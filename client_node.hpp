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
    ClientNode(net::io_context& io_ctx,net::ssl::context& ssl_ctx): resolver_(io_ctx), ssl_socket_(io_ctx,ssl_ctx){};


    void send_file(const string& port,const string& host,const string& file_path) {
        file_path_ = file_path;
        ssl_socket_.set_verify_callback(net::ssl::host_name_verification(host));
        resolver_.async_resolve(host,port,
            [self = shared_from_this()](const boost::system::error_code& ec,const tcp::resolver::results_type& endpoints) {
                if (!ec) {
                    self ->connect(endpoints);
                } else {
                    cerr << "[CLIENT ERROR]: Resolve Failed." << ec.message() << "\n";
                }
            });
    }

private:


    void handshake() {
        ssl_socket_.async_handshake(net::ssl::stream_base::client,
            [self = shared_from_this()](const boost::system::error_code& ec) {
                if (!ec) {
                    cout << "[CLIENT] TLS Handshake SUCCESS!!" << "\n";
                    self->prepare_and_send_header();
                } else {
                    cerr << "[CLIENT ERROR] TLS Handshake failed: " << ec.message() << "\n";
                }
            }
            );
    }

    void connect(const tcp::resolver::results_type & endpoints) {
        net::async_connect(ssl_socket_.lowest_layer(),endpoints,
            [self = shared_from_this()](const boost::system::error_code& ec,const tcp::endpoint&) {
                if (!ec) {
                    cout << "[CLIENT] TCP Connected. Performing TLS 1.3 handshake..." << "\n";
                    self->handshake();
                } else {
                    cerr << "[CLIENT ERROR] TCP Connect failed: " << ec.message() << "\n";
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
                    self->send_filename_payload();
                } else {
                    cerr << "[CLIENT ERROR] Failed to send header: " << ec.message() << '\n';
                }
            });
    } catch (const exception& e) {
        cerr << "[CLIENT ERROR] File prep failed: " << e.what() << '\n';
    }
}

void send_filename_payload() {
    net::async_write(ssl_socket_, net::buffer(file_name_),
        [self = shared_from_this()](const boost::system::error_code& ec, size_t) {
            if (!ec) {
                cout << "[CLIENT] Header & metadata sent. Starting file payload stream...\n";
                self->open_file_and_stream();
            } else {
                cerr << "[CLIENT ERROR] Failed to send filename payload: " << ec.message() << '\n';
            }
        });
}

void send_end_of_file_signal() {
    std::memset(&eof_header_, 0, sizeof(PacketHeader));
    eof_header_.msg_type = static_cast<uint8_t>(MessageType::END_OF_FILE);

    net::async_write(ssl_socket_, net::buffer(&eof_header_, sizeof(PacketHeader)),
        [self = shared_from_this()](const boost::system::error_code& ec, size_t) {
            if (ec) {
                cerr << "[CLIENT ERROR] Failed to send EOF packet: " << ec.message() << '\n';
                return;
            }
            cout << "[CLIENT] EOF packet delivered. Waiting for the receiver's verdict...\n";
            self->read_ack();
        });
}

void read_ack() {
    net::async_read(ssl_socket_, net::buffer(&ack_header_, sizeof(PacketHeader)),
        [self = shared_from_this()](const boost::system::error_code& ec, size_t) {
            if (ec) {
                cerr << "[CLIENT ERROR] No ACK received: " << ec.message() << '\n';
                return;
            }
            if (self->ack_header_.msg_type != static_cast<uint8_t>(MessageType::ACK) ||
                boost::endian::big_to_native(self->ack_header_.payload_len) != 1) {
                cerr << "[CLIENT ERROR] Malformed ACK from receiver\n";
                return;
            }
            net::async_read(self->ssl_socket_, net::buffer(&self->ack_status_, 1),
                [self](const boost::system::error_code& ec2, size_t) {
                    if (ec2) {
                        cerr << "[CLIENT ERROR] Failed to read ACK status: " << ec2.message() << '\n';
                        return;
                    }
                    switch (static_cast<AckStatus>(self->ack_status_)) {
                        case AckStatus::OK:
                            cout << "[CLIENT] Receiver confirmed: file verified and saved!\n"; break;
                        case AckStatus::HASH_MISMATCH:
                            cerr << "[CLIENT] Receiver says the hash did NOT match. File discarded.\n"; break;
                        default:
                            cerr << "[CLIENT] Receiver hit an error and could not save the file.\n"; break;
                    }
                });
        });
}


    void stream_next_chunk() {
        if (!file_stream_.read(buffer_.data(), buffer_.size()) && file_stream_.gcount() == 0) {
            std::cout << "[CLIENT] File transfer complete!" << "\n";
            send_end_of_file_signal();
            return;
        }
        size_t bytes_read = file_stream_.gcount();

        net::async_write(ssl_socket_, net::buffer(buffer_.data(), bytes_read),
            [self = shared_from_this()](const boost::system::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    self->stream_next_chunk(); // Recursively stream the next chunk asynchronously
                } else {
                    std::cerr << "[CLIENT ERROR] Stream write error: " << ec.message() << "\n";
                }
            }
        );
    }

    void open_file_and_stream() {
        file_stream_.open(file_path_, ios::binary);
        if (!file_stream_.is_open()) {
            cerr << "[CLIENT ERROR] Failed to open file for streaming!" << "\n";
            return;
        }
        buffer_.resize(FileStreamer::CHUNK_SIZE);
        stream_next_chunk();
    }

    string file_name_;
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