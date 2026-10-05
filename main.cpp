#include "iostream"
#include "exception"
#include "boost/asio.hpp"
#include "boost/asio/ssl.hpp"
#include "protocol.hpp"
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_type;
using namespace std;

void configure_server_mode(boost::asio::ssl::context& ssl_ctx) {
ssl_ctx.set_options(
    boost::asio::ssl::context::default_workarounds |
    boost::asio::ssl::context::no_sslv2 |
    boost::asio::ssl::context::no_sslv3 |
    boost::asio::ssl::context::single_dh_use
    );
    ssl_ctx.use_certificate_chain_file("server.crt");
    ssl_ctx.use_private_key_file("server.key", boost::asio::ssl::context::pem);
}
int main() {
    try {
        boost::asio::io_context io_ctx;
        boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv13_server);
        configure_server_mode(ssl_ctx);

        boost::asio::ip::tcp::acceptor acceptor(
            io_ctx,
            boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),8080)
            );
        cout << "Listening on Port 8080 for an incoming peer ..." << endl;

        auto ssl_socket = make_shared<ssl_socket_type>(io_ctx,ssl_ctx);


        cout << "INITIATING ASYNC TLS HANDSHAKE: " << endl;
        acceptor.async_accept(
            ssl_socket->lowest_layer(),
            [ssl_socket](const boost::system::error_code& ec) {
                            if (!ec) {
                                cout << "[SERVER] TCP Connection accepted! Starting TLS handshake..." << endl;

                                // 4. Perform TLS handshake ONCE a peer connects
                                ssl_socket->async_handshake(
                                    boost::asio::ssl::stream_base::server,
                                    [ssl_socket](const boost::system::error_code& handshake_ec) {
                                        if (!handshake_ec) {
                                            cout << "TLS HANDSHAKE SUCCESS. CHANNEL IS SECURE" << endl;
                                            auto header = std::make_shared<PacketHeader>();
                                            boost::asio::async_read(
                                                *ssl_socket,
                                                boost::asio::buffer(header.get(), sizeof(PacketHeader)),
                                                [ssl_socket, header](const boost::system::error_code& ec, std::size_t bytes_transferred) {
                                                    if (!ec) {
                                                        std::cout << "[SERVER] Received 47-byte protocol header!" << std::endl;
                                                        std::cout << "[SERVER] Payload size to follow: " << ntohl(header->payload_len) << " bytes" << std::endl;
                                                        std::cout << "[SERVER] File total size: " << be64toh(header->total_file_size) << " bytes" << std::endl;
                                                    } else {
                                                        std::cerr << "[SERVER ERROR] Failed to read header: " << ec.message() << std::endl;
                                                    }
                                                }
                                            );

                                        } else {
                                            cerr << "[ERROR] Handshake failed: " << handshake_ec.message() << endl;
                                        }
                                    }
                                );
                            } else {
                                cerr << "[ERROR] Accept failed: " << ec.message() << endl;
                            }
                        }
                    );
        io_ctx.run();







    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}