#pragma once

#include <QMainWindow>
#include <QLineEdit>
#include <QPushButton>
#include <QProgressBar>
#include <QTextEdit>
#include <QTableWidget>
#include <QLabel>
#include "network_bridge.hpp"

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void onBrowseFile();
    void onSendFile();
    void onStartServer();
    void onAddPeer();
    void onRemovePeer();
    void onLogMessage(const QString& msg);
    void onTransferProgress(int percentage, quint64 transferred, quint64 total);
    void refreshPeerList();

private:
    void setupUi();

    NetworkBridge* bridge_ = nullptr;

    // Identity widgets
    QLabel* fp_label_ = nullptr;

    // Sender widgets
    QLineEdit* host_input_ = nullptr;
    QLineEdit* port_input_ = nullptr;
    QLineEdit* file_path_input_ = nullptr;
    QPushButton* send_btn_ = nullptr;
    QProgressBar* progress_bar_ = nullptr;

    // Server widgets
    QLineEdit* server_port_input_ = nullptr;
    QLineEdit* save_dir_input_ = nullptr;
    QPushButton* server_toggle_btn_ = nullptr;

    // Peer management
    QTableWidget* peer_table_ = nullptr;
    QLineEdit* peer_name_input_ = nullptr;
    QLineEdit* peer_fp_input_ = nullptr;

    // Activity log
    QTextEdit* log_pane_ = nullptr;
};