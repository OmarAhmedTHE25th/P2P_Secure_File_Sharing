#ifndef P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
#define P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
#include <cstdint>
#include <iostream>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "server_session.hpp"

class ServerNode : public std::enable_shared_from_this<ServerNode> {
public:
    using SSLStream = ServerSession::SSLStream;

    ServerNode(net::io_context& io_ctx, net::ssl::context& ssl_ctx, uint16_t port, fs::path save_dir)
        : io_ctx_(io_ctx),
          ssl_ctx_(ssl_ctx),
          acceptor_(io_ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), port)),
          save_dir_(std::move(save_dir)) {}

    void start() {
        std::cout << "[SERVER] Listening on port " << acceptor_.local_endpoint().port()
                  << ", saving files to: " << save_dir_.string() << '\n';
        accept_next();
    }

private:
    void accept_next() {
        auto socket = std::make_shared<SSLStream>(io_ctx_, ssl_ctx_);
        acceptor_.async_accept(socket->lowest_layer(),
            [self = shared_from_this(), socket](const boost::system::error_code& ec) {
                if (ec == net::error::operation_aborted) return;   // server is shutting down
                if (ec) {
                    std::cerr << "[SERVER ERROR] Accept failed: " << ec.message() << '\n';
                } else {
                    self->handshake(socket);
                }
                self->accept_next();   // always go back to waiting for the next peer
            });
    }

    void handshake(std::shared_ptr<SSLStream> socket) {
        socket->async_handshake(net::ssl::stream_base::server,
            [self = shared_from_this(), socket](const boost::system::error_code& ec) {
                if (ec) {
                    std::cerr << "[SERVER ERROR] Handshake failed: " << ec.message() << '\n';
                    return;
                }
                
                // Fingerprint verification
                X509* cert = SSL_get_peer_certificate(socket->native_handle());
                if (cert) {
                    unsigned char md[EVP_MAX_MD_SIZE];
                    unsigned int n;
                    if (X509_digest(cert, EVP_sha256(), md, &n)) {
                        std::cout << "[SERVER] Peer fingerprint: ";
                        for (unsigned int i = 0; i < n; i++) {
                            printf("%02X%c", md[i], (i == n - 1) ? '\n' : ':');
                        }
                    }
                    X509_free(cert);
                }

                std::cout << "[SERVER] TLS handshake OK. Channel is secure.\n";
                std::make_shared<ServerSession>(socket, self->save_dir_)->start();
            });
    }

    net::io_context& io_ctx_;
    net::ssl::context& ssl_ctx_;
    net::ip::tcp::acceptor acceptor_;
    fs::path save_dir_;
};
#endif //P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP