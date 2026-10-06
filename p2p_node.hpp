#ifndef P2P_SECURE_FILE_SHARING_P2P_NODE_HPP
#define P2P_SECURE_FILE_SHARING_P2P_NODE_HPP

#include "server_node.hpp"
#include "client_node.hpp"
#include <map>
#include <string>

class P2PNode {
public:
    P2PNode(net::io_context& io_ctx, net::ssl::context& server_ctx, net::ssl::context& client_ctx, uint16_t port, fs::path save_dir)
        : io_ctx_(io_ctx),
          server_node_(std::make_shared<ServerNode>(io_ctx, server_ctx, port, save_dir)),
          client_ctx_(client_ctx) {}

    void start() {
        server_node_->start();
    }

    void send_file(const std::string& peer_name, const std::string& file_path) {
        auto it = address_book_.find(peer_name);
        if (it == address_book_.end()) {
            std::cerr << "[P2P] Peer " << peer_name << " not found in address book.\n";
            return;
        }
        send_file_to_addr(it->second.host, it->second.port, file_path);
    }

    void send_file_to_addr(const std::string& host, const std::string& port, const std::string& file_path) {
        auto client = std::make_shared<ClientNode>(io_ctx_, client_ctx_);
        client->send_file(port, host, file_path);
        // client_node manages its own lifetime via shared_from_this in its async ops
    }

    void add_peer(const std::string& name, const std::string& host, const std::string& port) {
        address_book_[name] = {host, port};
    }

private:
    struct PeerInfo {
        std::string host;
        std::string port;
    };

    net::io_context& io_ctx_;
    std::shared_ptr<ServerNode> server_node_;
    net::ssl::context& client_ctx_;
    std::map<std::string, PeerInfo> address_book_;
};

#endif //P2P_SECURE_FILE_SHARING_P2P_NODE_HPP
