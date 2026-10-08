#ifndef P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
#define P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "disk_budget.hpp"
#include "server_session.hpp"

// A "seat" in the receiver. Creating one takes a seat, destroying it gives the seat back.
// Whoever holds the ConnectionSlot (first the handshake, then the session) keeps the seat taken,
// so the counter goes down exactly when the connection is really gone, whatever way it ended.
class ConnectionSlot {
public:
    explicit ConnectionSlot(std::shared_ptr<std::atomic<std::size_t>> counter)
        : counter_(std::move(counter)) { ++*counter_; }
    ConnectionSlot(const ConnectionSlot&) = delete;
    ConnectionSlot& operator=(const ConnectionSlot&) = delete;
    ~ConnectionSlot() { --*counter_; }
private:
    std::shared_ptr<std::atomic<std::size_t>> counter_;
};

class ServerNode : public std::enable_shared_from_this<ServerNode> {
public:
    using SSLStream = ServerSession::SSLStream;

    // How many peers may be connected (including ones still doing the TLS handshake) at once
    static constexpr std::size_t MAX_CONNECTIONS = 64;
    // How long a peer gets to finish the TLS handshake before we hang up on it
    static constexpr std::chrono::seconds HANDSHAKE_TIMEOUT{10};

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
                } else if (self->active_connections_->load() >= MAX_CONNECTIONS) {
                    // Full house: hang up right away (the socket closes when it goes out of scope)
                    std::cerr << "[SERVER] Too many connections (" << MAX_CONNECTIONS
                              << "), dropping a new peer\n";
                } else {
                    self->handshake(socket);
                }
                self->accept_next();   // always go back to waiting for the next peer
            });
    }

    void handshake(std::shared_ptr<SSLStream> socket) {
        auto slot = std::make_shared<ConnectionSlot>(active_connections_);

        // A peer that connects and then says nothing must not hold a seat forever
        auto timer = std::make_shared<net::steady_timer>(io_ctx_);
        timer->expires_after(HANDSHAKE_TIMEOUT);
        timer->async_wait([socket](const boost::system::error_code& ec) {
            if (ec) return;   // cancelled: the handshake finished in time
            std::cerr << "[SERVER] TLS handshake timed out, dropping peer\n";
            boost::system::error_code ignored_ec;
            socket->lowest_layer().close(ignored_ec);   // makes the pending handshake fail
        });

        socket->async_handshake(net::ssl::stream_base::server,
            [self = shared_from_this(), socket, timer, slot](const boost::system::error_code& ec) {
                timer->cancel();
                if (ec) {
                    if (ec != net::error::operation_aborted) {   // aborted = we closed it ourselves
                        std::cerr << "[SERVER ERROR] Handshake failed: " << ec.message() << '\n';
                    }
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
                // The session now holds the seat, so it is given back only when the session ends
                std::make_shared<ServerSession>(socket, self->save_dir_, slot, self->disk_budget_)->start();
            });
    }

    net::io_context& io_ctx_;
    net::ssl::context& ssl_ctx_;
    net::ip::tcp::acceptor acceptor_;
    fs::path save_dir_;
    std::shared_ptr<std::atomic<std::size_t>> active_connections_ =
        std::make_shared<std::atomic<std::size_t>>(0);
    // One budget shared by every upload, so parallel uploads cannot fill the disk together
    std::shared_ptr<DiskBudget> disk_budget_ = std::make_shared<DiskBudget>();
};
#endif //P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
