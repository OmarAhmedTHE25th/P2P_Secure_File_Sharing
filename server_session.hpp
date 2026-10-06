#ifndef P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP
#define P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP

#include <iostream>
#include <memory>
#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/endian/conversion.hpp>
#include "protocol.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "file_streaming.hpp"
#include "validation.hpp"

using std::cout;
using std::cerr;
using std::string;
using std::shared_ptr;
using std::make_shared;
using std::enable_shared_from_this;
using std::move;
using std::size_t;

namespace net = boost::asio;
namespace fs = std::filesystem;
class ServerSession : public enable_shared_from_this<ServerSession> {
public:
    using SSLStream = net::ssl::stream<net::ip::tcp::socket>;
    ServerSession(shared_ptr<SSLStream> socket, fs::path save_dir)
     : socket_(std::move(socket)), 
       save_dir_(std::move(save_dir)),
       timer_(socket_->get_executor()) {}
    ~ServerSession() {
        timer_.cancel();
        if (part_file_.is_open()) part_file_.close();
        if (!temp_path_.empty() && !finished_) {
            std::error_code ec;
            fs::remove(temp_path_, ec);   // never leave half-received files behind
        }
    }
    void start () {
        start_timeout();
        read_header();
    }

private:
    void start_timeout() {
        timer_.expires_after(std::chrono::seconds(30));
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
            if (!ec) {
                std::cerr << "[SERVER] Session timed out\n";
                boost::system::error_code ignored_ec;
                self->socket_->lowest_layer().close(ignored_ec);
            }
        });
    }

    void reset_timeout() {
        timer_.expires_after(std::chrono::seconds(30));
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
            if (!ec) {
                std::cerr << "[SERVER] Session timed out\n";
                boost::system::error_code ignored_ec;
                self->socket_->lowest_layer().close(ignored_ec);
            }
        });
    }

    void read_header() {
        net::async_read(*socket_,net::buffer(&header_, sizeof(PacketHeader)),
                        [self = shared_from_this()](const boost::system::error_code& ec,size_t) {
                            if (ec) {
                                if (ec != net::error::operation_aborted)
                                    cerr << "[SERVER ERROR] failed to read header: " << ec.message() << "\n";
                                return;
                            }
                            self->reset_timeout();
                            self -> handle_header();
                        }
        );
    }
    void handle_header() {
        const AckStatus verdict = validation::check_metadata_header(header_);
        if (verdict != AckStatus::READY) {
            reject(verdict, describe(verdict));
            return;
        }
        file_size_ = boost::endian::big_to_native(header_.total_file_size);
        const uint16_t filename_len = boost::endian::big_to_native(header_.filename_len);

        cout << "[SERVER] Header OK. Filename length: " << filename_len
             << ", file size: " << file_size_ << " bytes" << "\n";
        raw_name_.resize(filename_len);
        read_filename();
    }

    void read_filename() {
        net::async_read(*socket_,net::buffer(raw_name_),
            [self = shared_from_this()](const boost::system::error_code& ec,size_t) {
                if (ec) {
                    if (ec != net::error::operation_aborted)
                        cerr << "[SERVER ERROR] Failed to read filename: " << ec.message() << "\n";
                    return;
                }
                self->reset_timeout();
                if (!validation::sanitize_file_name(self->raw_name_, self->safe_name_)) {
                    self->reject(AckStatus::UNSAFE_FILENAME, "Unsafe Filename");
                    return;
                }
                cout << "[SERVER] Incoming file: " << self->safe_name_ << "\n";
                self -> prepare_receive();
            }
        );
    }

    void prepare_receive() {
    std::error_code fs_ec;
    fs::create_directories(save_dir_, fs_ec);
    if (fs_ec) { reject(AckStatus::SERVER_ERROR, "Cannot create save folder"); return; }

    fs::path final_path = save_dir_ / safe_name_;
    fs::path temp_path  = save_dir_ / (safe_name_ + ".part");
    if (fs::exists(final_path, fs_ec) || fs::exists(temp_path, fs_ec)) {
        reject(AckStatus::ALREADY_EXISTS, "File already exists or is already being received");
        return;
    }

    part_file_.open(temp_path, std::ios::binary);
    if (!part_file_.is_open()) { reject(AckStatus::SERVER_ERROR, "Cannot open temp file"); return; }

    // Only claim these paths once we truly own the temp file
    final_path_ = final_path;
    temp_path_  = temp_path;

    if (!hash_ctx_ || EVP_DigestInit_ex(hash_ctx_.get(), EVP_sha256(), nullptr) != 1) {
        reject(AckStatus::SERVER_ERROR, "Hash init failed");
        return;
    }

    buffer_.resize(FileStreamer::CHUNK_SIZE);
    send_ack(AckStatus::READY, [self = shared_from_this()] { self->read_next_chunk(); });
}

    void read_next_chunk() {
        uint64_t remaining = file_size_ - bytes_received_;
        
        // Progress bar
        if (file_size_ > 0) {
            int progress = static_cast<int>((bytes_received_ * 100) / file_size_);
            static int last_progress = -1;
            if (progress != last_progress) {
                std::cout << "\r[SERVER] Progress: [" << std::string(progress / 2, '=') << std::string(50 - progress / 2, ' ') << "] " << progress << "%" << std::flush;
                if (progress == 100) std::cout << std::endl;
                last_progress = progress;
            }
        }

        if (remaining == 0) { read_eof_header(); return; }

        std::size_t to_read = static_cast<std::size_t>(std::min<uint64_t>(remaining, buffer_.size()));
        net::async_read(*socket_, net::buffer(buffer_.data(), to_read),
            [self = shared_from_this()](const boost::system::error_code& ec, std::size_t n) {
                if (ec) {
                    if (ec != net::error::operation_aborted)
                        std::cerr << "[SERVER ERROR] Connection lost mid-transfer: " << ec.message() << '\n';
                    return;
                }
                self->reset_timeout();
                self->handle_chunk(n);
            });
    }

    void handle_chunk(std::size_t n) {
        part_file_.write(buffer_.data(), static_cast<std::streamsize>(n));
        if (!part_file_) { reject(AckStatus::SERVER_ERROR, "Disk write failed"); return; }
        if (EVP_DigestUpdate(hash_ctx_.get(), buffer_.data(), n) != 1) { reject(AckStatus::SERVER_ERROR, "Hash update failed"); return; }
        bytes_received_ += n;
        read_next_chunk();
    }

    void read_eof_header() {
        net::async_read(*socket_, net::buffer(&eof_header_, sizeof(PacketHeader)),
            [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    if (ec != net::error::operation_aborted)
                        std::cerr << "[SERVER ERROR] Failed to read EOF packet: " << ec.message() << '\n';
                    return;
                }
                self->reset_timeout();
                self->finish_transfer();
            });
    }

    void finish_transfer() {
        if (eof_header_.msg_type != static_cast<uint8_t>(MessageType::END_OF_FILE)) {
            reject(AckStatus::BAD_REQUEST, "Expected END_OF_FILE packet");
            return;
        }

        part_file_.close();
        if (part_file_.fail()) {
            send_ack(AckStatus::SERVER_ERROR, [self = shared_from_this()] {
                self->shutdown_tls();
            });
            return;
        }

        std::array<uint8_t, 32> digest{};
        unsigned int digest_len = 0;
        if (EVP_DigestFinal_ex(hash_ctx_.get(), digest.data(), &digest_len) != 1) {
            send_ack(AckStatus::SERVER_ERROR, [self = shared_from_this()] {
                self->shutdown_tls();
            });
            return;
        }

        if (CRYPTO_memcmp(digest.data(), header_.file_hash, digest.size()) != 0) {
            std::cerr << "[SERVER] HASH MISMATCH. Discarding " << safe_name_ << '\n';
            send_ack(AckStatus::HASH_MISMATCH, [self = shared_from_this()] {
                self->shutdown_tls();
            });
            return;
        }

        std::error_code rename_ec;
        fs::rename(temp_path_, final_path_, rename_ec);
        if (rename_ec) {
            std::cerr << "[SERVER ERROR] Rename failed: " << rename_ec.message() << '\n';
            send_ack(AckStatus::SERVER_ERROR, [self = shared_from_this()] {
                self->shutdown_tls();
            });
            return;
        }

        finished_ = true;
        std::cout << "[SERVER] Verified and saved: " << final_path_.string() << '\n';
        send_ack(AckStatus::OK, [self = shared_from_this()] {
            self->shutdown_tls();
        });
    }
    void reject(AckStatus status, const std::string& reason) {
        std::cerr << "[SERVER] Rejected peer: " << reason << '\n';
        send_ack(status, [self = shared_from_this()] {
            self->shutdown_tls();
        });
    }

    void shutdown_tls() {
        timer_.cancel();
        socket_->async_shutdown(
            [self = shared_from_this()](const boost::system::error_code& ec) {
                boost::system::error_code ignored_ec;
                self->socket_->lowest_layer().shutdown(net::ip::tcp::socket::shutdown_both, ignored_ec);
                self->socket_->lowest_layer().close(ignored_ec);

                if (ec && ec != net::error::eof &&
                    ec != boost::asio::ssl::error::stream_truncated &&
                    ec != net::error::operation_aborted &&
                    ec != net::error::connection_reset
                    ) {
                    std::cerr << "[SERVER ERROR] TLS shutdown failed: " << ec.message() << '\n';
                }
            });
    }

    void send_ack(AckStatus status, std::function<void()> on_sent = nullptr) {
        std::memset(&ack_header_, 0, sizeof(PacketHeader));
        ack_header_.msg_type    = static_cast<uint8_t>(MessageType::ACK);
        ack_header_.payload_len = boost::endian::native_to_big(static_cast<uint32_t>(1));
        ack_status_             = static_cast<uint8_t>(status);

        std::array<net::const_buffer, 2> bufs{
            net::buffer(&ack_header_, sizeof(PacketHeader)),
            net::buffer(&ack_status_, 1)
        };
        net::async_write(*socket_, bufs,
            [self = shared_from_this(), on_sent = std::move(on_sent)](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    if (ec != net::error::operation_aborted)
                        std::cerr << "[SERVER ERROR] Failed to send ACK: " << ec.message() << '\n';
                    return;
                }
                self->reset_timeout();
                if (on_sent) on_sent();
            });
    }
    
    shared_ptr<SSLStream> socket_;
    net::steady_timer timer_;
    fs::path final_path_;
    fs::path temp_path_;
    std::ofstream part_file_;
    std::vector<char> buffer_;
    uint64_t bytes_received_ = 0;
    bool finished_ = false;
    FileStreamer::EVP_MD_CTX_ptr hash_ctx_{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
    PacketHeader eof_header_{};
    PacketHeader ack_header_{};
    uint8_t ack_status_ = 0;
    fs::path save_dir_;
    PacketHeader header_{};
    string raw_name_;
    string safe_name_;
    uint64_t file_size_ = 0;
};


#endif //P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP