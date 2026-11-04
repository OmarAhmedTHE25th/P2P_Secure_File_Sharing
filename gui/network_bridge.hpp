#pragma once
#include <QObject>
#include <QString>
#include <thread>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "../trust_store.hpp"
#include "../server_node.hpp"
#include "../client_node.hpp"

class NetworkBridge : public QObject {
    Q_OBJECT
public:
    explicit NetworkBridge(QObject* parent = nullptr);
    ~NetworkBridge();

    void startServer(uint16_t port, const QString& saveDir);
    void sendFile(const QString& host, uint16_t port, const QString& filePath);

    signals:
        // Outbound notifications to the UI
        void logMessage(const QString& msg);
    void transferProgress(int percentage, quint64 bytesTransferred, quint64 totalBytes);
    void transferComplete(bool success, const QString& statusText);
    void peerAuthenticated(const QString& name, const QString& fingerprint);

private:
    boost::asio::io_context io_ctx_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::thread worker_thread_;

    std::shared_ptr<trust::TrustStore> trust_store_;
    std::unique_ptr<boost::asio::ssl::context> server_ssl_ctx_;
    std::unique_ptr<boost::asio::ssl::context> client_ssl_ctx_;
    std::shared_ptr<ServerNode> server_node_;
};