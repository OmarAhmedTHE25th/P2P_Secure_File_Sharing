#include "main_window.hpp"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QFileDialog>
#include <QHeaderView>
#include <QMessageBox>
#include "identity.hpp"
#include "trust_store.hpp"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), bridge_(new NetworkBridge(this)) {
    setupUi();

    connect(bridge_, &NetworkBridge::logMessage, this, &MainWindow::onLogMessage);
    connect(bridge_, &NetworkBridge::transferProgress, this, &MainWindow::onTransferProgress);

    refreshPeerList();
}

void MainWindow::setupUi() {
    setWindowTitle("P2P Secure File Transfer");
    resize(720, 540);

    auto* centralWidget = new QWidget(this);
    auto* mainLayout = new QVBoxLayout(centralWidget);

    // Identity Bar
    auto* idLayout = new QHBoxLayout();
    QString my_fp = "No Identity Found";
    try {
        my_fp = QString::fromStdString(trust::display_fingerprint(identity::fingerprint_of_file(identity::CERT_FILE)));
    } catch (...) {}
    fp_label_ = new QLabel(QString("<b>My Fingerprint:</b> %1").arg(my_fp), this);
    fp_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    idLayout->addWidget(fp_label_);
    mainLayout->addLayout(idLayout);

    // Tabs
    auto* tabs = new QTabWidget(this);

    // Tab 1: Send File
    auto* sendTab = new QWidget();
    auto* sendLayout = new QVBoxLayout(sendTab);

    auto* targetLayout = new QHBoxLayout();
    host_input_ = new QLineEdit("127.0.0.1", this);
    host_input_->setFixedHeight(36);
    port_input_ = new QLineEdit("8080", this);
    port_input_->setFixedHeight(36);
    targetLayout->addWidget(new QLabel("Host:"));
    targetLayout->addWidget(host_input_);
    targetLayout->addWidget(new QLabel("Port:"));
    targetLayout->addWidget(port_input_);
    sendLayout->addLayout(targetLayout);

    auto* fileLayout = new QHBoxLayout();
    file_path_input_ = new QLineEdit(this);
    file_path_input_->setFixedHeight(36);
    auto* browseBtn = new QPushButton("Browse...", this);
    connect(browseBtn, &QPushButton::clicked, this, &MainWindow::onBrowseFile);
    fileLayout->addWidget(new QLabel("File:"));
    fileLayout->addWidget(file_path_input_);
    fileLayout->addWidget(browseBtn);
    sendLayout->addLayout(fileLayout);

    send_btn_ = new QPushButton("Send File", this);
    send_btn_->setFixedHeight(38);
    connect(send_btn_, &QPushButton::clicked, this, &MainWindow::onSendFile);
    sendLayout->addWidget(send_btn_);

    progress_bar_ = new QProgressBar(this);
    progress_bar_->setValue(0);
    sendLayout->addWidget(progress_bar_);
    tabs->addTab(sendTab, "Send");

    // Tab 2: Receiver
    auto* recvTab = new QWidget();
    auto* recvLayout = new QVBoxLayout(recvTab);

    auto* srvConfigLayout = new QHBoxLayout();
    server_port_input_ = new QLineEdit("8080", this);
    server_port_input_->setFixedHeight(36);
    save_dir_input_ = new QLineEdit("received", this);
    save_dir_input_->setFixedHeight(36);
    server_toggle_btn_ = new QPushButton("Start Listening", this);
    server_toggle_btn_->setFixedHeight(38);
    connect(server_toggle_btn_, &QPushButton::clicked, this, &MainWindow::onStartServer);

    srvConfigLayout->addWidget(new QLabel("Listen Port:"));
    srvConfigLayout->addWidget(server_port_input_);
    srvConfigLayout->addWidget(new QLabel("Save Folder:"));
    srvConfigLayout->addWidget(save_dir_input_);
    srvConfigLayout->addWidget(server_toggle_btn_);
    recvLayout->addLayout(srvConfigLayout);
    tabs->addTab(recvTab, "Receive");

    // Tab 3: Trust List
    auto* trustTab = new QWidget();
    auto* trustLayout = new QVBoxLayout(trustTab);
    peer_table_ = new QTableWidget(0, 2, this);
    peer_table_->setHorizontalHeaderLabels({"Peer Name", "Fingerprint"});
    peer_table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    trustLayout->addWidget(peer_table_);

    auto* addPeerLayout = new QHBoxLayout();
    peer_name_input_ = new QLineEdit(this);
    peer_name_input_->setPlaceholderText("Peer Name");
    peer_fp_input_ = new QLineEdit(this);
    peer_fp_input_->setPlaceholderText("64-hex Fingerprint");
    auto* addPeerBtn = new QPushButton("Add Peer", this);
    auto* removePeerBtn = new QPushButton("Remove Selected", this);
    connect(addPeerBtn, &QPushButton::clicked, this, &MainWindow::onAddPeer);
    connect(removePeerBtn, &QPushButton::clicked, this, &MainWindow::onRemovePeer);

    addPeerLayout->addWidget(peer_name_input_);
    addPeerLayout->addWidget(peer_fp_input_);
    addPeerLayout->addWidget(addPeerBtn);
    addPeerLayout->addWidget(removePeerBtn);
    trustLayout->addLayout(addPeerLayout);
    tabs->addTab(trustTab, "Trusted Peers");

    mainLayout->addWidget(tabs);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(16);

    // Activity Log
    log_pane_ = new QTextEdit(this);
    log_pane_->setReadOnly(true);
    log_pane_->setMaximumHeight(150);
    mainLayout->addWidget(new QLabel("Activity Log:"));
    mainLayout->addWidget(log_pane_);

    setCentralWidget(centralWidget);
}

void MainWindow::onBrowseFile() {
    QString file = QFileDialog::getOpenFileName(this, "Select File to Transfer");
    if (!file.isEmpty()) {
        file_path_input_->setText(file);
    }
}

void MainWindow::onSendFile() {
    QString host = host_input_->text().trimmed();
    uint16_t port = port_input_->text().toUShort();
    QString path = file_path_input_->text().trimmed();

    if (host.isEmpty() || port == 0 || path.isEmpty()) {
        QMessageBox::warning(this, "Validation", "Please provide a valid Host, Port, and File path.");
        return;
    }
    progress_bar_->setValue(0);
    bridge_->sendFile(host, port, path);
}

void MainWindow::onStartServer() {
    uint16_t port = server_port_input_->text().toUShort();
    QString saveDir = save_dir_input_->text().trimmed();
    if (port == 0 || saveDir.isEmpty()) {
        QMessageBox::warning(this, "Validation", "Invalid server port or save directory.");
        return;
    }
    server_toggle_btn_->setEnabled(false);
    bridge_->startServer(port, saveDir);
}

void MainWindow::onAddPeer() {
    QString name = peer_name_input_->text().trimmed();
    QString fp = peer_fp_input_->text().trimmed();
    if (name.isEmpty() || fp.isEmpty()) return;

    trust::TrustStore store(identity::TRUST_FILE);
    std::string err = store.add(fp.toStdString(), name.toStdString());
    if (!err.empty()) {
        QMessageBox::critical(this, "Error", QString::fromStdString(err));
        return;
    }
    peer_name_input_->clear();
    peer_fp_input_->clear();
    refreshPeerList();
}

void MainWindow::onRemovePeer() {
    int row = peer_table_->currentRow();
    if (row < 0) return;
    QString name = peer_table_->item(row, 0)->text();

    trust::TrustStore store(identity::TRUST_FILE);
    store.remove(name.toStdString());
    refreshPeerList();
}

void MainWindow::refreshPeerList() {
    peer_table_->setRowCount(0);
    trust::TrustStore store(identity::TRUST_FILE);
    for (const auto& entry : store.list()) {
        int row = peer_table_->rowCount();
        peer_table_->insertRow(row);
        peer_table_->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry.name)));
        peer_table_->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(trust::display_fingerprint(entry.fingerprint))));
    }
}

void MainWindow::onLogMessage(const QString& msg) {
    log_pane_->append(msg);
}

void MainWindow::onTransferProgress(int percentage, quint64, quint64) {
    progress_bar_->setValue(percentage);
}