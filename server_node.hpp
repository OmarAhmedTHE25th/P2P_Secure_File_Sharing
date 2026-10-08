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
#include "identity.hpp"
#include "trust_store.hpp"
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

    // trust_store is only used to show the peer's name in the log; the handshake itself
    // (see tls_trust.hpp) already decided whether the peer is allowed in
    ServerNode(net::io_context& io_ctx, net::ssl::context& ssl_ctx, uint16_t port, fs::path save_dir,
               std::shared_ptr<trust::TrustStore> trust_store = nullptr)
        : io_ctx_(io_ctx),
          ssl_ctx_(ssl_ctx),
          acceptor_(io_ctx, net::ip::tcp::endpoint(net::ip::tcp::v4(), port)),
          save_dir_(std::move(save_dir)),
          trust_store_(std::move(trust_store)) {}

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

                // The handshake already proved this peer is on our trust list. Say who it is.
                X509* cert = SSL_get_peer_certificate(socket->native_handle());
                if (cert) {
                    try {
                        const std::string fingerprint = identity::fingerprint_of(cert);
                        std::string name = "unknown";
                        if (self->trust_store_) {
                            if (auto known = self->trust_store_->find_name(fingerprint)) name = *known;
                        }
                        std::cout << "[SERVER] Authenticated peer '" << name << "' ("
                                  << trust::display_fingerprint(fingerprint) << ")\n";
                    } catch (...) {}
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
    std::shared_ptr<trust::TrustStore> trust_store_;
};
#endif //P2P_SECURE_FILE_SHARING_SERVER_NODE_HPP
