#include "iostream"
#include "exception"
#include "boost/asio.hpp"
#include "boost/asio/ssl.hpp"

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket_type;
using namespace std;
int main() {
    try {
        boost::asio::io_context io_ctx;
        boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv13_client);

        ssl_socket_type ssl_socket(io_ctx, ssl_ctx);


    }
    catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}