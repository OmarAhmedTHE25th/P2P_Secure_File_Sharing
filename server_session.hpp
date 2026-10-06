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
    static constexpr uint16_t MAX_FILE_LEN = 255;
    static constexpr uint64_t MAX_FILE_SIZE = 10ULL * 1024 * 1024 * 1024;
    explicit ServerSession(shared_ptr<SSLStream> socket) : socket_(std::move(socket)){}

    void start () {read_header();}

private:
    void read_header() {
        net::async_read(*socket_,net::buffer(&header_, sizeof(PacketHeader)),
                        [self = shared_from_this()](const boost::system::error_code& ec,size_t) {
                            if (ec) {
                                cerr << "[SEVER ERROR] failed to read header" << "\n";
                                return;
                            }
                            self -> handle_header();
                        }
        );
    }
    void handle_header() {
        if (header_.msg_type != static_cast<uint8_t> (MessageType::METADATA)) {
            cerr << "Unexpected Message type,";
            return;
        }
        const uint64_t payload_len = boost::endian::big_to_native(header_.payload_len);
        const uint32_t filename_len = boost::endian::big_to_native(header_.filename_len);
        file_size_ = boost::endian::big_to_native(header_.total_file_size);
        if (filename_len == 0 || filename_len > MAX_FILE_LEN || payload_len != filename_len) {
            cerr << "Invalid Filename Length";
            return;
        }
        if (file_size_ > MAX_FILE_SIZE) {
            reject("File too large");
            return;
        }
        cout << "[SERVER] Header OK. Filename length: " << filename_len
                  << ", file size: " << file_size_ << " bytes" << "\n";
        raw_name_.resize(filename_len);
        read_filename();
    }

    static bool sanitize_file_name(const string & raw_name, string& clean_name) {
        if (raw_name.find('\000' ) != string::npos) return false;
        clean_name = fs::path(raw_name).filename().string();
        return !clean_name.empty() && clean_name != "." && clean_name != ".." && clean_name == raw_name;
    }

    static void reject(const string& reason) {
        cerr << "[SERVER] Rejected peer: " << reason << "\n";
    }

    void read_filename() {
        net::async_read(*socket_,net::buffer(raw_name_),
            [self = shared_from_this()](const boost::system::error_code& ec,size_t) {
                if (ec) {
                    cerr << "[SERVER ERROR] Failed to read filename: " << ec.message() << "\n";
                    return;
                }
                if (!sanitize_file_name(self -> raw_name_,self -> safe_name_)) {
                    reject("Unsafe Filename");
                    return;
                }
                cout << "[SERVER] Incoming file: " << self->safe_name_ << "\n";
            }


        );
    }
    shared_ptr<SSLStream> socket_;
    PacketHeader header_{};
    string raw_name_;
    string safe_name_;
    uint64_t file_size_ = 0;
};


#endif //P2P_SECURE_FILE_SHARING_SERVER_SESSION_HPP