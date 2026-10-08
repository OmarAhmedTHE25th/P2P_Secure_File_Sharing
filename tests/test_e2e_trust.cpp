#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <random>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "server_node.hpp"
#include "client_node.hpp"
#include "identity.hpp"
#include "trust_store.hpp"

namespace {
namespace fs = std::filesystem;
namespace net = boost::asio;

class E2ETestDir {
public:
    E2ETestDir(const std::string& prefix) {
        std::random_device rd;
        path_ = fs::temp_directory_path() / (prefix + "_" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path_);
    }
    ~E2ETestDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    fs::path path() const { return path_; }
    fs::path file(const std::string& name) const { return path_ / name; }
private:
    fs::path path_;
};

void create_identity(const fs::path& dir, const std::string& name) {
    auto old_path = fs::current_path();
    fs::current_path(dir);
    identity::generate(identity::CERT_FILE, identity::KEY_FILE, name);
    fs::current_path(old_path);
}

void configure_server_ctx(net::ssl::context& ctx, const fs::path& dir) {
    ctx.set_options(net::ssl::context::default_workarounds | net::ssl::context::no_sslv2 | net::ssl::context::no_sslv3);
    ctx.use_certificate_chain_file((dir / identity::CERT_FILE).string());
    ctx.use_private_key_file((dir / identity::KEY_FILE).string(), net::ssl::context::pem);
    ctx.set_verify_mode(net::ssl::verify_peer | net::ssl::verify_fail_if_no_peer_cert);
}

void configure_client_ctx(net::ssl::context& ctx, const fs::path& dir) {
    ctx.set_options(net::ssl::context::default_workarounds | net::ssl::context::no_sslv2 | net::ssl::context::no_sslv3);
    ctx.use_certificate_chain_file((dir / identity::CERT_FILE).string());
    ctx.use_private_key_file((dir / identity::KEY_FILE).string(), net::ssl::context::pem);
    ctx.set_verify_mode(net::ssl::verify_peer);
}

} // namespace

TEST(E2ETrust, FullTrustCycle) {
    E2ETestDir alice_dir("alice"), bob_dir("bob");
    create_identity(alice_dir.path(), "alice");
    create_identity(bob_dir.path(), "bob");

    const std::string alice_fp = identity::fingerprint_of_file(alice_dir.file(identity::CERT_FILE));
    const std::string bob_fp = identity::fingerprint_of_file(bob_dir.file(identity::CERT_FILE));

    net::io_context io_ctx;
    net::ssl::context alice_server_ctx(net::ssl::context::tlsv13_server);
    configure_server_ctx(alice_server_ctx, alice_dir.path());

    net::ssl::context bob_client_ctx(net::ssl::context::tlsv13_client);
    configure_client_ctx(bob_client_ctx, bob_dir.path());

    // Alice starts server
    auto old_path = fs::current_path();
    fs::current_path(alice_dir.path());
    auto server = std::make_shared<ServerNode>(io_ctx, alice_server_ctx, 0, alice_dir.path() / "received");
    server->start();
    uint16_t port = server->port();
    fs::current_path(old_path);

    auto test_file = bob_dir.file("hello.txt");
    {
        std::ofstream out(test_file);
        out << "Hello Alice, I am Bob.";
    }

    // 1. Bob tries to send to Alice. Alice does NOT trust Bob yet.
    // Expected: Handshake fails or connection dropped.
    {
        fs::current_path(bob_dir.path());
        // Bob needs to trust Alice to even connect as a client (since we check fingerprints on both sides)
        trust::TrustStore bob_store(bob_dir.file(identity::TRUST_FILE));
        bob_store.add(alice_fp, "alice");

        auto client = std::make_shared<ClientNode>(io_ctx, bob_client_ctx);
        client->send_file(std::to_string(port), "127.0.0.1", test_file.string());

        // Run until timeout or failure
        io_ctx.run_for(std::chrono::seconds(2));
        io_ctx.restart();

        // Alice's received dir should be empty
        EXPECT_FALSE(fs::exists(alice_dir.path() / "received" / "hello.txt"));
    }

    // 2. Alice trusts Bob. Bob sends again.
    // Expected: Success.
    {
        trust::TrustStore alice_store(alice_dir.file(identity::TRUST_FILE));
        alice_store.add(bob_fp, "bob");

        auto client = std::make_shared<ClientNode>(io_ctx, bob_client_ctx);
        client->send_file(std::to_string(port), "127.0.0.1", test_file.string());

        io_ctx.run_for(std::chrono::seconds(2));
        io_ctx.restart();

        EXPECT_TRUE(fs::exists(alice_dir.path() / "received" / "hello.txt"));
    }

    // 3. Alice removes Bob from trust list. Bob sends another file.
    // Expected: Failure without restarting Alice.
    {
        trust::TrustStore alice_store(alice_dir.file(identity::TRUST_FILE));
        alice_store.remove("bob");

        auto test_file2 = bob_dir.file("secret.txt");
        {
            std::ofstream out(test_file2);
            out << "I am no longer trusted.";
        }

        auto client = std::make_shared<ClientNode>(io_ctx, bob_client_ctx);
        client->send_file(std::to_string(port), "127.0.0.1", test_file2.string());

        io_ctx.run_for(std::chrono::seconds(2));
        io_ctx.restart();

        EXPECT_FALSE(fs::exists(alice_dir.path() / "received" / "secret.txt"));
    }
    
    fs::current_path(old_path);
}
