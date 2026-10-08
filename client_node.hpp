#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/endian/conversion.hpp>
#include "protocol.hpp"
#include "file_streaming.hpp"
#include <filesystem>
using std::cout;
using std::cerr;
using std::string;
using std::vector;
using std::ifstream;
using std::ios;
using std::size_t;
using std::enable_shared_from_this;
using std::make_shared;
using std::memcpy;
using std::memset;
using std::exception;

namespace net = boost::asio;
using tcp = net::ip::tcp;

class ClientNode : public enable_shared_from_this<ClientNode> {
public:
    using SSLStream = net::ssl::stream<tcp::socket>;
    ClientNode(net::io_context& io_ctx,net::ssl::context& ssl_ctx)
        : resolver_(io_ctx), ssl_socket_(io_ctx,ssl_ctx), timer_(io_ctx) {};

    // True only if the receiver confirmed that the file was verified and saved
    bool succeeded() const { return succeeded_; }

    void send_file(const string& port,const string& host,const string& file_path) {
        file_path_ = file_path;
        start_timeout();
        resolver_.async_resolve(host,port,
            [self = shared_from_this()](const boost::system::error_code& ec,const tcp::resolver::results_type& endpoints) {
                if (!ec) {
                    self->reset_timeout();
                    self ->connect(endpoints);
                } else {
                    cerr << "[CLIENT ERROR]: Resolve Failed." << ec.message() << "\n";
                    self->finish();
                }
            });
    }

private:
    // Conversation is over: stop the watchdog and close, so the program can exit right away
    void finish() {
        timer_.cancel();
        boost::system::error_code ignored_ec;
        ssl_socket_.lowest_layer().close(ignored_ec);
    }

    // With TLS 1.3 our side of the handshake finishes BEFORE the receiver checks our identity.
    // So a receiver that does not trust us just hangs up on us a moment later, and all we see is
    // a closed connection. Say what that usually means.
    void hint_if_not_trusted(const boost::system::error_code& ec) {
        if (ec == net::error::broken_pipe || ec == net::error::connection_reset ||
            ec == net::error::eof || ec.category() == net::error::get_ssl_category()) {
            cerr << "[CLIENT] The receiver closed the connection. If this is the first time you send to it, "
                    "it may not trust you yet. Send it your fingerprint (P2P_Secure_File_Sharing fingerprint) "
                    "so it can add you with 'trust add'.\n";
        }
    }

    void start_timeout() {
        timer_.expires_after(std::chrono::seconds(30));
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
            if (!ec) {
                std::cerr << "[CLIENT] Operation timed out\n";
                boost::system::error_code ignored_ec;
                self->ssl_socket_.lowest_layer().close(ignored_ec);
            }
        });
    }

    void reset_timeout() {
        timer_.expires_after(std::chrono::seconds(30));
        timer_.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
            if (!ec) {
                std::cerr << "[CLIENT] Operation timed out\n";
                boost::system::error_code ignored_ec;
                self->ssl_socket_.lowest_layer().close(ignored_ec);
            }
        });
    }

    void handshake() {
        ssl_socket_.async_handshake(net::ssl::stream_base::client,
            [self = shared_from_this()](const boost::system::error_code& ec) {
                if (!ec) {
                    self->reset_timeout();
                    cout << "[CLIENT] TLS Handshake SUCCESS!!" << "\n";
                    self->prepare_and_send_header();
                } else {
                    if (ec != net::error::operation_aborted)
                        cerr << "[CLIENT ERROR] TLS Handshake failed: " << ec.message() << "\n";
                    self->finish();
                }
            }
            );
    }

    void connect(const tcp::resolver::results_type & endpoints) {
        net::async_connect(ssl_socket_.lowest_layer(),endpoints,
            [self = shared_from_this()](const boost::system::error_code& ec,const tcp::endpoint&) {
                if (!ec) {
                    self->reset_timeout();
                    cout << "[CLIENT] TCP Connected. Performing TLS 1.3 handshake..." << "\n";
                    self->handshake();
                } else {
                    if (ec != net::error::operation_aborted)
                        cerr << "[CLIENT ERROR] TCP Connect failed: " << ec.message() << "\n";
                    self->finish();
                }

            }
            );
    }

    void prepare_and_send_header() {
    try {
        uint64_t file_size = FileStreamer::get_file_size(file_path_);
        auto file_hash = FileStreamer::compute_sha256(file_path_);
        file_name_ = std::filesystem::path(file_path_).filename().string();

        header_.msg_type = static_cast<uint8_t>(MessageType::METADATA);
        header_.payload_len = boost::endian::native_to_big(static_cast<uint32_t>(file_name_.length()));
        header_.total_file_size = boost::endian::native_to_big(file_size);
        header_.filename_len = boost::endian::native_to_big(static_cast<uint16_t>(file_name_.length()));
        memcpy(header_.file_hash, file_hash.data(), 32);
        cout << "[CLIENT] Sending 47-byte PacketHeader...\n";

        net::async_write(ssl_socket_, net::buffer(&header_, sizeof(PacketHeader)),
            [self = shared_from_this()](const boost::system::error_code& ec, size_t) {
                if (!ec) {
                    self->reset_timeout();
                    self->send_filename_payload();
                } else {
                    if (ec != net::error::operation_aborted) {
                        cerr << "[CLIENT ERROR] Failed to send header: " << ec.message() << '\n';
                        self->hint_if_not_trusted(ec);
                    }
                    self->finish();
                }
            });
    } catch (const exception& e) {
        cerr << "[CLIENT ERROR] File prep failed: " << e.what() << '\n';
        finish();
    }
}



void send_end_of_file_signal() {
    std::memset(&eof_header_, 0, sizeof(PacketHeader));
    eof_header_.msg_type = static_cast<uint8_t>(MessageType::END_OF_FILE);

    net::async_write(ssl_socket_, net::buffer(&eof_header_, sizeof(PacketHeader)),
        [self = shared_from_this()](const boost::system::error_code& ec, size_t) {
            if (ec) {
                if (ec != net::error::operation_aborted)
                    cerr << "[CLIENT ERROR] Failed to send EOF packet: " << ec.message() << '\n';
                self->finish();
                return;
            }
            self->reset_timeout();
            cout << "[CLIENT] EOF packet delivered. Waiting for the receiver's verdict...\n";
            self->read_reply([self](AckStatus status) {
    if (status == AckStatus::OK) {
        self->succeeded_ = true;
        cout << "[CLIENT] Receiver confirmed: " << describe(status) << "!\n";
    } else {
        cerr << "[CLIENT] Transfer failed: " << describe(status) << '\n';
    }
    self->finish();
});
        });
}

void send_filename_payload() {
    net::async_write(ssl_socket_, net::buffer(file_name_),
        [self = shared_from_this()](const boost::system::error_code& ec, size_t) {
            if (ec) {
                if (ec != net::error::operation_aborted) {
                    cerr << "[CLIENT ERROR] Failed to send filename payload: " << ec.message() << '\n';
                    self->hint_if_not_trusted(ec);
                }
                self->finish();
                return;
            }
            self->reset_timeout();
            cout << "[CLIENT] Metadata sent. Waiting for the receiver to accept...\n";
            self->read_reply([self](AckStatus status) {
                if (status == AckStatus::READY) {
                    cout << "[CLIENT] Receiver accepted. Streaming file...\n";
                    self->open_file_and_stream();
                } else {
                    cerr << "[CLIENT] Receiver refused the transfer: " << describe(status) << '\n';
                    self->finish();
                }
            });
        });
}

// Reads one reply from the receiver (47-byte header + 1 status byte), then calls handler
    void read_reply(std::function<void(AckStatus)> handler) {
        cout << "[CLIENT] Waiting for ACK header...\n";

        net::async_read(ssl_socket_, net::buffer(&ack_header_, sizeof(PacketHeader)),
            [self = shared_from_this(), handler = std::move(handler)](const boost::system::error_code& ec, size_t bytes_read) mutable {
                if (ec) {
                    if (ec != net::error::operation_aborted) {
                        cerr << "[CLIENT ERROR] No reply from receiver after reading "
                             << bytes_read << " bytes: " << ec.message() << '\n';
                        self->hint_if_not_trusted(ec);
                    }
                    self->finish();
                    return;
                }
                self->reset_timeout();
                if (self->ack_header_.msg_type != static_cast<uint8_t>(MessageType::ACK) ||
                    boost::endian::big_to_native(self->ack_header_.payload_len) != 1) {
                    cerr << "[CLIENT ERROR] Malformed reply from receiver\n";
                    self->finish();
                    return;
                }

                cout << "[CLIENT] ACK header received. Waiting for ACK status...\n";

                net::async_read(self->ssl_socket_, net::buffer(&self->ack_status_, 1),
                    [self, handler = std::move(handler)](const boost::system::error_code& ec2, size_t bytes_read2) {
                        if (ec2) {
                            if (ec2 != net::error::operation_aborted) {
                                cerr << "[CLIENT ERROR] Failed to read reply status after reading "
                                     << bytes_read2 << " bytes: " << ec2.message() << '\n';
                            }
                            self->finish();
                            return;
                        }
                        self->reset_timeout();
                        handler(static_cast<AckStatus>(self->ack_status_));
                    });
            });
    }



    void stream_next_chunk() {
        // Progress bar
        try {
            uint64_t file_size = FileStreamer::get_file_size(file_path_);
            if (file_size > 0) {
                uint64_t pos = file_stream_.tellg();
                if (pos == (uint64_t)-1) pos = file_size; // End of file
                int progress = static_cast<int>((pos * 100) / file_size);
                static int last_progress = -1;
                if (progress != last_progress) {
                    std::cout << "\r[CLIENT] Progress: [" << std::string(progress / 2, '=') << std::string(50 - progress / 2, ' ') << "] " << progress << "%" << std::flush;
                    if (progress == 100) std::cout << std::endl;
                    last_progress = progress;
                }
            }
        } catch (...) {}

        if (!file_stream_.read(buffer_.data(), buffer_.size()) && file_stream_.gcount() == 0) {
            std::cout << "[CLIENT] File transfer complete!" << "\n";
            send_end_of_file_signal();
            return;
        }
        size_t bytes_read = file_stream_.gcount();

        net::async_write(ssl_socket_, net::buffer(buffer_.data(), bytes_read),
            [self = shared_from_this()](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    self->reset_timeout();
                    self->stream_next_chunk(); // Recursively stream the next chunk asynchronously
                } else {
                    if (ec != net::error::operation_aborted)
                        std::cerr << "[CLIENT ERROR] Stream write error: " << ec.message() << "\n";
                    self->finish();
                }
            }
        );
    }

    void open_file_and_stream() {
        file_stream_.open(file_path_, ios::binary);
        if (!file_stream_.is_open()) {
            cerr << "[CLIENT ERROR] Failed to open file for streaming!" << "\n";
            finish();
            return;
        }
        buffer_.resize(FileStreamer::CHUNK_SIZE);
        stream_next_chunk();
    }

    net::steady_timer timer_;
    string file_name_;
    bool succeeded_ = false;
    PacketHeader eof_header_{};
    PacketHeader ack_header_{};
    uint8_t ack_status_ = 0;
    tcp::resolver resolver_;
    SSLStream ssl_socket_;
    string file_path_;
    PacketHeader header_{};
    ifstream file_stream_ ;
    vector<char> buffer_;


};

#ifndef P2P_SECURE_FILE_SHARING_CLIENT_NODE_HPP
#define P2P_SECURE_FILE_SHARING_CLIENT_NODE_HPP

#endif //P2P_SECURE_FILE_SHARING_CLIENT_NODE_HPP