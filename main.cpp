#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "client_node.hpp"
#include "server_node.hpp"

namespace {

void configure_server_mode(net::ssl::context& ssl_ctx) {
    ssl_ctx.set_options(
        net::ssl::context::default_workarounds |
        net::ssl::context::no_sslv2 |
        net::ssl::context::no_sslv3 |
        net::ssl::context::single_dh_use
    );
    ssl_ctx.use_certificate_chain_file("server.crt");
    ssl_ctx.use_private_key_file("server.key", net::ssl::context::pem);
}

void configure_client_mode(net::ssl::context& ssl_ctx) {
    ssl_ctx.set_options(
        net::ssl::context::default_workarounds |
        net::ssl::context::no_sslv2 |
        net::ssl::context::no_sslv3
    );
    ssl_ctx.set_verify_mode(net::ssl::verify_peer);
    ssl_ctx.load_verify_file("server.crt");
}

uint16_t parse_port(const std::string& text) {
    int value = 0;
    try {
        std::size_t used = 0;
        value = std::stoi(text, &used);
        if (used != text.size()) throw std::invalid_argument("trailing characters");
    } catch (const std::exception&) {
        throw std::runtime_error("Invalid port: " + text);
    }
    if (value < 1 || value > 65535) {
        throw std::runtime_error("Port must be between 1 and 65535");
    }
    return static_cast<uint16_t>(value);
}

void print_usage(const char* program) {
    std::cerr << "Usage:\n"
              << "  " << program << " receive <port> [save_folder]\n"
              << "  " << program << " send <host> <port> <file>\n";
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) { print_usage(argv[0]); return 1; }
        const std::string mode = argv[1];
        net::io_context io_ctx;

        if (mode == "receive" && (argc == 3 || argc == 4)) {
            uint16_t port = parse_port(argv[2]);
            fs::path save_dir = (argc == 4) ? fs::path(argv[3]) : fs::path("received");

            net::ssl::context ssl_ctx(net::ssl::context::tlsv13_server);
            configure_server_mode(ssl_ctx);

            std::make_shared<ServerNode>(io_ctx, ssl_ctx, port, save_dir)->start();
            io_ctx.run();

        } else if (mode == "send" && argc == 5) {
            const std::string host = argv[2];
            const std::string port = std::to_string(parse_port(argv[3]));   // validates it
            const std::string file = argv[4];

            net::ssl::context ssl_ctx(net::ssl::context::tlsv13_client);
            configure_client_mode(ssl_ctx);

            // heads up: send_file takes (port, host, file), in that order
            std::make_shared<ClientNode>(io_ctx, ssl_ctx)->send_file(port, host, file);
            io_ctx.run();

        } else {
            print_usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << '\n';
        return 1;
    }
    return 0;
}