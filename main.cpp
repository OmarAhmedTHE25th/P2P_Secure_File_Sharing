#include <cstdio>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "client_node.hpp"
#include "server_node.hpp"
#include "cli_identity.hpp"
#include "tls_trust.hpp"

namespace {

// Every mode needs an identity of its own; an empty trust list is legal but means nobody gets in
void check_ready(const trust::TrustStore& store) {
    if (!fs::exists(identity::CERT_FILE) || !fs::exists(identity::KEY_FILE)) {
        throw std::runtime_error(std::string("No identity found in this folder. Create one with:  ") +
                                 "P2P_Secure_File_Sharing init");
    }
    if (store.list().empty()) {
        std::cerr << "[WARNING] Your trust list (" << identity::TRUST_FILE << ") is empty, so you will not "
                  << "accept anyone yet. Add a peer with:  P2P_Secure_File_Sharing trust add <fingerprint> <name>\n";
    }
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
              << "  " << program << " send <host> <port> <file>\n"
              << "  " << program << " p2p <port> [save_folder]\n";
    cli::print_identity_usage(program);
}

} // namespace

#include "p2p_node.hpp"
#include <thread>

int main(int argc, char* argv[]) {
#ifndef _WIN32
    // Write each log line immediately, even when output is redirected to a file or pipe
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
#endif
    try {
        if (argc < 2) { print_usage(argv[0]); return 1; }
        const std::string mode = argv[1];

        // init, fingerprint and trust: manage your identity and who you trust
        const int identity_result = cli::handle_identity_command(
            std::vector<std::string>(argv + 1, argv + argc), "P2P_Secure_File_Sharing");
        if (identity_result >= 0) return identity_result;
        net::io_context io_ctx;

        if (mode == "p2p" && argc >= 3) {
            uint16_t port = parse_port(argv[2]);
            fs::path save_dir = (argc >= 4) ? fs::path(argv[3]) : fs::path("received");

            auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
            check_ready(*trust_store);

            net::ssl::context server_ctx(net::ssl::context::tlsv13_server);
            tls_trust::configure_server(server_ctx, trust_store);

            net::ssl::context client_ctx(net::ssl::context::tlsv13_client);
            tls_trust::configure_client(client_ctx, trust_store);

            auto node = std::make_shared<P2PNode>(io_ctx, server_ctx, client_ctx, port, save_dir, trust_store);
            node->start();

            // Simple command loop for P2P interaction
            std::thread input_thread([&io_ctx, node]() {
                std::string cmd;
                while (true) {
                    std::cout << "> ";
                    if (!(std::cin >> cmd)) break;
                    if (cmd == "send") {
                        std::string host, port, file;
                        std::cin >> host >> port >> std::quoted(file);;
                        node->send_file_to_addr(host, port, file);
                    } else if (cmd == "add") {
                        std::string name, host, port;
                        std::cin >> name >> host >> port;
                        node->add_peer(name, host, port);
                    } else if (cmd == "send_to") {
                        std::string name, file;
                        std::cin >> name >> file;
                        node->send_file(name, file);
                    } else if (cmd == "exit") {
                        io_ctx.stop();
                        break;
                    } else {
                        std::cout << "Commands: send <host> <port> <file>, add <name> <host> <port>, send_to <name> <file>, exit\n";
                    }
                }
            });

            io_ctx.run();
            if (input_thread.joinable()) input_thread.join();

        } else if (mode == "receive" && (argc == 3 || argc == 4)) {
            uint16_t port = parse_port(argv[2]);
            fs::path save_dir = (argc == 4) ? fs::path(argv[3]) : fs::path("received");
            auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
            check_ready(*trust_store);

            net::ssl::context ssl_ctx(net::ssl::context::tlsv13_server);
            tls_trust::configure_server(ssl_ctx, trust_store);

            std::make_shared<ServerNode>(io_ctx, ssl_ctx, port, save_dir, trust_store)->start();
            io_ctx.run();

        } else if (mode == "send" && argc == 5) {
            const std::string host = argv[2];
            const std::string port = std::to_string(parse_port(argv[3]));   // validates it
            const std::string file = argv[4];

            auto trust_store = std::make_shared<trust::TrustStore>(identity::TRUST_FILE);
            check_ready(*trust_store);

            net::ssl::context ssl_ctx(net::ssl::context::tlsv13_client);
            tls_trust::configure_client(ssl_ctx, trust_store);

            // heads up: send_file takes (port, host, file), in that order
            auto node = std::make_shared<ClientNode>(io_ctx, ssl_ctx);
            node->send_file(port, host, file);
            io_ctx.run();
            return node->succeeded() ? 0 : 1;   // so scripts can tell whether the file really arrived

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