#include "iostream"
#include "exception"
#include "boost/asio.hpp"
#include "boost/asio/ssl.hpp"

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
                                    [](const boost::system::error_code& handshake_ec) {
                                        if (!handshake_ec) {
                                            cout << "TLS HANDSHAKE SUCCESS. CHANNEL IS SECURE" << endl;
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