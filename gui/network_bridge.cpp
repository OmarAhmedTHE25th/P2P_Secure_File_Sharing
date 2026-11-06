#include "network_bridge.hpp"
#include "tls_trust.hpp"
#include "identity.hpp"
#include <QStandardPaths>
#include <QDir>
#include <filesystem>

namespace {
std::filesystem::path getIdentityDirectory() {
    QString qPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir dir(qPath);
    if (!dir.exists() && !dir.mkpath(".")) {
        throw std::runtime_error("cannot create identity directory: " + qPath.toStdString());
    }
#ifdef _WIN32
    return std::filesystem::path(qPath.toStdWString());
#else
    return std::filesystem::path(qPath.toStdString());
#endif
}
} // namespace

NetworkBridge::NetworkBridge(QObject* parent)
    : QObject(parent),
      work_guard_(boost::asio::make_work_guard(io_ctx_)),
      trust_store_(std::make_shared<trust::TrustStore>(getIdentityDirectory() / identity::TRUST_FILE)) {
    worker_thread_ = std::thread([this]() {
        io_ctx_.run();
    });
}

NetworkBridge::~NetworkBridge() {
    work_guard_.reset();
    io_ctx_.stop();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void NetworkBridge::setIdentityPassphrase(const QString& passphrase) {
    identity_passphrase_ = passphrase.toStdString();
}

void NetworkBridge::startServer(uint16_t port, const QString& saveDir) {
    boost::asio::post(io_ctx_, [this, port, saveDir]() {
        try {
            server_ssl_ctx_ = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv13_server);

            std::string cert_file = (getIdentityDirectory() / identity::CERT_FILE).string();
            std::string key_file  = (getIdentityDirectory() / identity::KEY_FILE).string();

            tls_trust::configure_server(*server_ssl_ctx_, trust_store_, cert_file, key_file, identity_passphrase_);

            std::filesystem::path save_path = saveDir.toStdString();
            server_node_ = std::make_shared<ServerNode>(io_ctx_, *server_ssl_ctx_, port, save_path, trust_store_);
            server_node_->start();

            emit logMessage(QString("[SERVER] Listening on port %1 (saving to %2)").arg(port).arg(saveDir));
        } catch (const std::exception& e) {
            emit logMessage(QString("[SERVER ERROR] %1").arg(e.what()));
        }
    });
}

void NetworkBridge::sendFile(const QString& host, uint16_t port, const QString& filePath) {
    boost::asio::post(io_ctx_, [this, host, port, filePath]() {
        try {
            client_ssl_ctx_ = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv13_client);

            std::string cert_file = (getIdentityDirectory() / identity::CERT_FILE).string();
            std::string key_file  = (getIdentityDirectory() / identity::KEY_FILE).string();

            tls_trust::configure_client(*client_ssl_ctx_, trust_store_, cert_file, key_file, identity_passphrase_);

            auto client = std::make_shared<ClientNode>(io_ctx_, *client_ssl_ctx_);
            emit logMessage(QString("[CLIENT] Connecting to %1:%2 to send %3...").arg(host).arg(port).arg(filePath));

            client->send_file(std::to_string(port), host.toStdString(), filePath.toStdString());
        } catch (const std::exception& e) {
            emit logMessage(QString("[CLIENT ERROR] %1").arg(e.what()));
            emit transferCompleted(false, QString::fromStdString(e.what()));
        }
    });
}