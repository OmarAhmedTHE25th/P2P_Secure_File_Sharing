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

    NetworkBridge* bridge_;

    // Identity widgets
    QLabel* fp_label_;

    // Sender widgets
    QLineEdit* host_input_;
    QLineEdit* port_input_;
    QLineEdit* file_path_input_;
    QPushButton* send_btn_;
    QProgressBar* progress_bar_;

    // Server widgets
    QLineEdit* server_port_input_;
    QLineEdit* save_dir_input_;
    QPushButton* server_toggle_btn_;

    // Peer management
    QTableWidget* peer_table_;
    QLineEdit* peer_name_input_;
    QLineEdit* peer_fp_input_;

    // Activity log
    QTextEdit* log_pane_;
};