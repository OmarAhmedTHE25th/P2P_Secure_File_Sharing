#include "main_window.hpp"
#include <QVBoxLayout>
#include <QGridLayout>
#include <QFormLayout>
#include <QTabWidget>
#include <QFileDialog>
#include <QHeaderView>
#include <QMessageBox>
#include <QGuiApplication>
#include <QClipboard>
#include <QTimer>
#include <QFile>
#include <QStandardPaths>
#include <QDir>
#include <filesystem>
#include <openssl/pem.h>
#include "identity.hpp"
#include "trust_store.hpp"

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

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), bridge_(new NetworkBridge(this)) {
    setMinimumSize(940, 680);
    resize(980, 720);
    setupUi();
    if (!initializeIdentity()) {
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    connect(bridge_, &NetworkBridge::logMessage, this, &MainWindow::onLogMessage);
    connect(bridge_, &NetworkBridge::transferProgress, this, &MainWindow::onTransferProgress);
    connect(bridge_, &NetworkBridge::transferCompleted, this, &MainWindow::onTransferCompleted);

    refreshPeerList();
}

bool MainWindow::initializeIdentity() {
    const auto keyPath = getIdentityDirectory() / identity::KEY_FILE;
    const auto certPath = getIdentityDirectory() / identity::CERT_FILE;

    auto readPrivateKey = [&keyPath](const QString& passphrase) {
#ifdef _WIN32
        FILE* file = _wfopen(keyPath.wstring().c_str(), L"rb");
#else
        FILE* file = std::fopen(keyPath.string().c_str(), "rb");
#endif
        if (!file) return false;
        EVP_PKEY* key = PEM_read_PrivateKey(
            file, nullptr, nullptr,
            const_cast<char*>(passphrase.toUtf8().constData()));
        std::fclose(file);
        if (key) EVP_PKEY_free(key);
        return key != nullptr;
    };

    QString passphrase;
    if (!std::filesystem::exists(keyPath)) {
        QDialog dialog(this);
        dialog.setWindowTitle("Create Node Identity");
        dialog.setModal(true);

        auto* form = new QFormLayout(&dialog);
        auto* aliasInput = new QLineEdit(&dialog);
        auto* passInput = new QLineEdit(&dialog);
        auto* confirmInput = new QLineEdit(&dialog);
        passInput->setEchoMode(QLineEdit::Password);
        confirmInput->setEchoMode(QLineEdit::Password);
        aliasInput->setPlaceholderText("e.g. Alice");
        form->addRow("Node Alias / Display Name:", aliasInput);
        form->addRow("Passphrase:", passInput);
        form->addRow("Confirm Passphrase:", confirmInput);

        auto* generateButton = new QPushButton("Generate", &dialog);
        form->addRow(generateButton);
        connect(generateButton, &QPushButton::clicked, &dialog, [&]() {
            const QString alias = aliasInput->text().trimmed();
            const QString first = passInput->text();
            if (alias.isEmpty()) {
                QMessageBox::warning(&dialog, "Identity", "Please enter a node alias.");
                return;
            }
            if (first != confirmInput->text()) {
                QMessageBox::warning(&dialog, "Identity", "Passphrases do not match.");
                return;
            }
            try {
                identity::generate(certPath, keyPath, alias.toStdString(), first.toStdString());
                passphrase = first;
                dialog.accept();
            } catch (const std::exception& error) {
    char err_buf[256];
    unsigned long err = ERR_get_error();
    QString ssl_details;
    while (err != 0) {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        ssl_details += QString("\nOpenSSL Error: %1").arg(err_buf);
        err = ERR_get_error();
    }
    QMessageBox::critical(&dialog, "Identity Generation Failed",
                          QString("Error: %1%2").arg(error.what(), ssl_details));
}
        });

        if (dialog.exec() != QDialog::Accepted) return false;
    } else {
        if (!std::filesystem::exists(certPath)) {
            QMessageBox::critical(this, "Identity Error",
                                  "identity.key exists, but identity.crt is missing.");
            return false;
        }

        if (!readPrivateKey(QString())) {
            QDialog dialog(this);
            dialog.setWindowTitle("Unlock Identity");
            dialog.setModal(true);
            auto* form = new QFormLayout(&dialog);
            auto* passInput = new QLineEdit(&dialog);
            passInput->setEchoMode(QLineEdit::Password);
            form->addRow("Passphrase:", passInput);
            auto* unlockButton = new QPushButton("Unlock", &dialog);
            form->addRow(unlockButton);
            connect(unlockButton, &QPushButton::clicked, &dialog, [&]() {
                if (!readPrivateKey(passInput->text())) {
                    QMessageBox::warning(&dialog, "Unlock Failed",
                                         "The passphrase is incorrect or the private key is invalid.");
                    return;
                }
                passphrase = passInput->text();
                dialog.accept();
            });
            if (dialog.exec() != QDialog::Accepted) return false;
        }
    }

    try {
        raw_fingerprint_ = QString::fromStdString(
            identity::fingerprint_of_file(certPath));
        fp_label_->setText(QString::fromStdString(
            trust::display_fingerprint(raw_fingerprint_.toStdString())));
        bridge_->setIdentityPassphrase(passphrase);
        return true;
    } catch (const std::exception& error) {
        QMessageBox::critical(this, "Identity Error", error.what());
        return false;
    }
}

void MainWindow::setupUi() {
    setWindowTitle("P2P Secure File Sharing");

    auto* centralWidget = new QWidget(this);
    auto* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    // Identity Card Container
    auto* idCard = new QFrame(centralWidget);
    idCard->setObjectName("card");
    auto* idLayout = new QVBoxLayout(idCard);
    idLayout->setContentsMargins(22, 18, 22, 18);
    idLayout->setSpacing(12);

    auto* idHeaderLayout = new QHBoxLayout();
    auto* appTitle = new QLabel("P2P Secure File Sharing", centralWidget);
    appTitle->setObjectName("appTitle");
    auto* badge = new QLabel("TLS 1.3 Node", centralWidget);
    badge->setObjectName("badge");
    idHeaderLayout->addWidget(appTitle);
    idHeaderLayout->addStretch();
    idHeaderLayout->addWidget(badge);
    idLayout->addLayout(idHeaderLayout);

    QString my_fp = "No Identity Found";
    try {
        const auto certPath = getIdentityDirectory() / identity::CERT_FILE;
        raw_fingerprint_ = QString::fromStdString(identity::fingerprint_of_file(certPath));
        my_fp = QString::fromStdString(trust::display_fingerprint(raw_fingerprint_.toStdString()));
    } catch (...) {}

    auto* fpRowLayout = new QHBoxLayout();
    auto* fpTitle = new QLabel("My Fingerprint:", centralWidget);
    fpTitle->setObjectName("subheading");

    fp_label_ = new QLabel(my_fp, centralWidget);
    fp_label_->setObjectName("monoBox");
    fp_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    copy_fp_btn_ = new QPushButton("Copy", centralWidget);
    copy_fp_btn_->setObjectName("secondaryBtn");
    copy_fp_btn_->setToolTip("Copy raw SHA-256 fingerprint to clipboard");
    copy_fp_btn_->setFixedWidth(70);
    connect(copy_fp_btn_, &QPushButton::clicked, this, &MainWindow::onCopyFingerprint);

    fpRowLayout->addWidget(fpTitle);
    fpRowLayout->addWidget(fp_label_, 1);
    fpRowLayout->addWidget(copy_fp_btn_);
    idLayout->addLayout(fpRowLayout);

    mainLayout->addWidget(idCard);

    auto* columnsLayout = new QHBoxLayout();
    columnsLayout->setContentsMargins(0, 0, 0, 0);
    columnsLayout->setSpacing(12);

    // Left column: tab navigation and functional forms
    auto* tabs = new QTabWidget(centralWidget);
    tabs->addTab(createSendTab(), "Send File");
    tabs->addTab(createReceiveTab(), "Receive Files");
    tabs->addTab(createTrustTab(), "Trusted Peers");
    columnsLayout->addWidget(tabs, 55);

    // Right column: activity log
    auto* logCard = new QFrame(centralWidget);
    logCard->setObjectName("card");
    auto* logLayout = new QVBoxLayout(logCard);
    logLayout->setContentsMargins(22, 18, 22, 20);
    logLayout->setSpacing(12);

    auto* logHeaderLayout = new QHBoxLayout();
    auto* logTitle = new QLabel("Activity & Network Log", centralWidget);
    logTitle->setObjectName("cardTitle");
    auto* clearLogBtn = new QPushButton("Clear Log", centralWidget);
    clearLogBtn->setObjectName("secondaryBtn");
    clearLogBtn->setMinimumHeight(36);
    connect(clearLogBtn, &QPushButton::clicked, this, &MainWindow::onClearLog);
    logHeaderLayout->addWidget(logTitle);
    logHeaderLayout->addStretch();
    logHeaderLayout->addWidget(clearLogBtn);
    logLayout->addLayout(logHeaderLayout);

    log_pane_ = new QTextEdit(this);
    log_pane_->setReadOnly(true);
    log_pane_->setMinimumHeight(120);
    logLayout->addWidget(log_pane_, 1);

    columnsLayout->addWidget(logCard, 45);
    mainLayout->addLayout(columnsLayout, 1);

    setCentralWidget(centralWidget);
}

QWidget* MainWindow::createSendTab() {
    auto* sendTab = new QWidget();
    auto* layout = new QVBoxLayout(sendTab);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    // Target Node Card
    auto* targetCard = new QFrame(sendTab);
    targetCard->setObjectName("card");
    auto* targetLayout = new QVBoxLayout(targetCard);
    targetLayout->setContentsMargins(22, 20, 22, 20);
    targetLayout->setSpacing(14);

    auto* targetTitle = new QLabel("Target Peer Information", targetCard);
    targetTitle->setObjectName("cardTitle");
    targetLayout->addWidget(targetTitle);

    auto* targetFormLayout = new QGridLayout();
    targetFormLayout->setHorizontalSpacing(12);
    targetFormLayout->setVerticalSpacing(10);
    targetFormLayout->setColumnStretch(0, 1);

    auto* hostLabel = new QLabel("Host Address:", targetCard);
    hostLabel->setObjectName("inputLabel");
    host_input_ = new QLineEdit("127.0.0.1", targetCard);
    host_input_->setPlaceholderText("IP address or hostname (e.g. 192.168.1.10)");
    host_input_->setFixedHeight(36);

    auto* portLabel = new QLabel("Port:", targetCard);
    portLabel->setObjectName("inputLabel");
    port_input_ = new QLineEdit("8080", targetCard);
    port_input_->setPlaceholderText("8080");
    port_input_->setFixedWidth(96);
    port_input_->setFixedHeight(36);

    targetFormLayout->addWidget(hostLabel, 0, 0);
    targetFormLayout->addWidget(portLabel, 0, 1);
    targetFormLayout->addWidget(host_input_, 1, 0);
    targetFormLayout->addWidget(port_input_, 1, 1);
    targetLayout->addLayout(targetFormLayout);

    layout->addWidget(targetCard);

    // File Selection Card
    auto* fileCard = new QFrame(sendTab);
    fileCard->setObjectName("card");
    auto* fileLayout = new QVBoxLayout(fileCard);
    fileLayout->setContentsMargins(22, 20, 22, 20);
    fileLayout->setSpacing(14);

    auto* fileTitle = new QLabel("Payload Selection", fileCard);
    fileTitle->setObjectName("cardTitle");
    fileLayout->addWidget(fileTitle);

    auto* fileInputLayout = new QHBoxLayout();
    file_path_input_ = new QLineEdit(fileCard);
    file_path_input_->setPlaceholderText("Select a file to transfer securely...");
    file_path_input_->setFixedHeight(36);

    auto* browseBtn = new QPushButton("Browse...", fileCard);
    browseBtn->setObjectName("secondaryBtn");
    browseBtn->setFixedHeight(36);
    connect(browseBtn, &QPushButton::clicked, this, &MainWindow::onBrowseFile);

    fileInputLayout->addWidget(file_path_input_, 1);
    fileInputLayout->addWidget(browseBtn);
    fileLayout->addLayout(fileInputLayout);

    layout->addWidget(fileCard);

    // Transfer Action Card
    auto* actionCard = new QFrame(sendTab);
    actionCard->setObjectName("card");
    auto* actionLayout = new QVBoxLayout(actionCard);
    actionLayout->setContentsMargins(22, 20, 22, 20);
    actionLayout->setSpacing(14);

    send_btn_ = new QPushButton("Send File", actionCard);
    send_btn_->setObjectName("primaryBtn");
    send_btn_->setFixedHeight(40);
    send_btn_->setMaximumWidth(820);
    connect(send_btn_, &QPushButton::clicked, this, &MainWindow::onSendFile);
    actionLayout->addWidget(send_btn_, 0, Qt::AlignHCenter);

    progress_bar_ = new QProgressBar(actionCard);
    progress_bar_->setValue(0);
    progress_bar_->setFixedHeight(20);
    progress_bar_->setMaximumWidth(820);
    actionLayout->addWidget(progress_bar_, 0, Qt::AlignHCenter);

    transfer_status_lbl_ = new QLabel("Ready to initiate transfer", actionCard);
    transfer_status_lbl_->setObjectName("subheading");
    transfer_status_lbl_->setAlignment(Qt::AlignCenter);
    actionLayout->addWidget(transfer_status_lbl_);

    layout->addWidget(actionCard);
    layout->addStretch();

    return sendTab;
}

QWidget* MainWindow::createReceiveTab() {
    auto* recvTab = new QWidget();
    auto* layout = new QVBoxLayout(recvTab);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    // Listener Configuration Card
    auto* srvCard = new QFrame(recvTab);
    srvCard->setObjectName("card");
    auto* srvLayout = new QVBoxLayout(srvCard);
    srvLayout->setContentsMargins(22, 20, 22, 20);
    srvLayout->setSpacing(14);

    auto* srvTitle = new QLabel("Incoming Transfers Listener", srvCard);
    srvTitle->setObjectName("cardTitle");
    srvLayout->addWidget(srvTitle);

    auto* srvFormLayout = new QGridLayout();
    srvFormLayout->setHorizontalSpacing(16);
    srvFormLayout->setVerticalSpacing(8);

    auto* portLabel = new QLabel("Listening Port:", srvCard);
    portLabel->setObjectName("inputLabel");
    server_port_input_ = new QLineEdit("8080", srvCard);
    server_port_input_->setPlaceholderText("8080");
    server_port_input_->setFixedHeight(36);

    auto* dirLabel = new QLabel("Save Directory:", srvCard);
    dirLabel->setObjectName("inputLabel");

    auto* dirInputLayout = new QHBoxLayout();
    save_dir_input_ = new QLineEdit("received", srvCard);
    save_dir_input_->setFixedHeight(36);
    auto* browseDirBtn = new QPushButton("Browse...", srvCard);
    browseDirBtn->setObjectName("secondaryBtn");
    browseDirBtn->setFixedHeight(36);
    connect(browseDirBtn, &QPushButton::clicked, this, &MainWindow::onBrowseSaveDir);
    dirInputLayout->addWidget(save_dir_input_, 1);
    dirInputLayout->addWidget(browseDirBtn);

    srvFormLayout->addWidget(portLabel, 0, 0);
    srvFormLayout->addWidget(dirLabel, 0, 1);
    srvFormLayout->addWidget(server_port_input_, 1, 0);
    srvFormLayout->addLayout(dirInputLayout, 1, 1);
    srvLayout->addLayout(srvFormLayout);

    server_toggle_btn_ = new QPushButton("Start Listening", srvCard);
    server_toggle_btn_->setObjectName("primaryBtn");
    server_toggle_btn_->setFixedHeight(40);
    connect(server_toggle_btn_, &QPushButton::clicked, this, &MainWindow::onStartServer);
    srvLayout->addWidget(server_toggle_btn_);

    server_status_lbl_ = new QLabel("Listener inactive - start listening to receive files from trusted peers", srvCard);
    server_status_lbl_->setObjectName("subheading");
    server_status_lbl_->setAlignment(Qt::AlignCenter);
    srvLayout->addWidget(server_status_lbl_);

    layout->addWidget(srvCard);

    // Trust Notice Card
    auto* noticeCard = new QFrame(recvTab);
    noticeCard->setObjectName("card");
    auto* noticeLayout = new QVBoxLayout(noticeCard);
    noticeLayout->setContentsMargins(22, 18, 22, 18);
    noticeLayout->setSpacing(10);

    auto* noticeTitle = new QLabel("Security Notice", noticeCard);
    noticeTitle->setObjectName("cardTitle");
    auto* noticeText = new QLabel("Incoming connections are authenticated against your Trusted Peers store using mutual TLS 1.3 verification. Transfers from unknown fingerprints are rejected automatically.", noticeCard);
    noticeText->setWordWrap(true);
    noticeText->setObjectName("subheading");

    noticeLayout->addWidget(noticeTitle);
    noticeLayout->addWidget(noticeText);
    layout->addWidget(noticeCard);

    layout->addStretch();
    return recvTab;
}

QWidget* MainWindow::createTrustTab() {
    auto* trustTab = new QWidget();
    auto* layout = new QVBoxLayout(trustTab);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);

    // Authorized Peers Card
    auto* listCard = new QFrame(trustTab);
    listCard->setObjectName("card");
    auto* listLayout = new QVBoxLayout(listCard);
    listLayout->setContentsMargins(22, 20, 22, 20);
    listLayout->setSpacing(14);

    auto* headerLayout = new QHBoxLayout();
    auto* listTitle = new QLabel("Authorized Peers", listCard);
    listTitle->setObjectName("cardTitle");
    auto* removePeerBtn = new QPushButton("Remove Selected", listCard);
    removePeerBtn->setObjectName("dangerBtn");
    removePeerBtn->setFixedHeight(32);
    connect(removePeerBtn, &QPushButton::clicked, this, &MainWindow::onRemovePeer);

    headerLayout->addWidget(listTitle);
    headerLayout->addStretch();
    headerLayout->addWidget(removePeerBtn);
    listLayout->addLayout(headerLayout);

    peer_table_ = new QTableWidget(0, 2, listCard);
    peer_table_->setHorizontalHeaderLabels({"Peer Name", "Fingerprint (SHA-256)"});
    peer_table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    peer_table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    peer_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    peer_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    peer_table_->setAlternatingRowColors(true);
    peer_table_->setFixedHeight(160);
    listLayout->addWidget(peer_table_);

    layout->addWidget(listCard);

    // Add Peer Card
    auto* addCard = new QFrame(trustTab);
    addCard->setObjectName("card");
    auto* addLayout = new QVBoxLayout(addCard);
    addLayout->setContentsMargins(22, 20, 22, 20);
    addLayout->setSpacing(14);

    auto* addTitle = new QLabel("Add Trusted Peer", addCard);
    addTitle->setObjectName("cardTitle");
    addLayout->addWidget(addTitle);

    auto* addFormLayout = new QHBoxLayout();
    peer_name_input_ = new QLineEdit(addCard);
    peer_name_input_->setPlaceholderText("Peer Alias (e.g. Alice)");
    peer_name_input_->setFixedHeight(36);

    peer_fp_input_ = new QLineEdit(addCard);
    peer_fp_input_->setPlaceholderText("64-hex SHA-256 Fingerprint");
    peer_fp_input_->setFixedHeight(36);

    auto* addPeerBtn = new QPushButton("Add Peer", addCard);
    addPeerBtn->setObjectName("primaryBtn");
    addPeerBtn->setFixedHeight(36);
    connect(addPeerBtn, &QPushButton::clicked, this, &MainWindow::onAddPeer);

    addFormLayout->addWidget(peer_name_input_, 1);
    addFormLayout->addWidget(peer_fp_input_, 2);
    addFormLayout->addWidget(addPeerBtn);
    addLayout->addLayout(addFormLayout);

    layout->addWidget(addCard);
    layout->addStretch();

    return trustTab;
}

void MainWindow::onBrowseFile() {
    QString file = QFileDialog::getOpenFileName(this, "Select File to Transfer");
    if (!file.isEmpty()) {
        file_path_input_->setText(file);
    }
}

void MainWindow::onBrowseSaveDir() {
    QString dir = QFileDialog::getExistingDirectory(this, "Select Directory to Save Incoming Files");
    if (!dir.isEmpty()) {
        save_dir_input_->setText(dir);
    }
}

void MainWindow::onCopyFingerprint() {
    if (raw_fingerprint_.isEmpty()) {
        try {
            const auto certPath = getIdentityDirectory() / identity::CERT_FILE;
            raw_fingerprint_ = QString::fromStdString(identity::fingerprint_of_file(certPath));
        } catch (...) {}
    }

    if (!raw_fingerprint_.isEmpty()) {
        QGuiApplication::clipboard()->setText(raw_fingerprint_);
        copy_fp_btn_->setText("Copied!");
        QTimer::singleShot(2000, this, [this]() {
            if (copy_fp_btn_) copy_fp_btn_->setText("Copy");
        });
        onLogMessage("[INFO] Fingerprint copied to clipboard.");
    }
}

void MainWindow::onClearLog() const {
    log_pane_->clear();
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
    transfer_status_lbl_->setText(QString("Transferring %1 to %2:%3...").arg(path, host).arg(port));
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
    server_toggle_btn_->setText("Server Running");
    server_status_lbl_->setText(QString("Listening on port %1 (saving to '%2')").arg(port).arg(saveDir));
    bridge_->startServer(port, saveDir);
}

void MainWindow::onAddPeer() {
    QString name = peer_name_input_->text().trimmed();
    QString fp = peer_fp_input_->text().trimmed();
    if (name.isEmpty() || fp.isEmpty()) {
        QMessageBox::warning(this, "Validation", "Please provide both a peer name and fingerprint.");
        return;
    }

    const auto trustPath = getIdentityDirectory() / identity::TRUST_FILE;
    trust::TrustStore store(trustPath);
    std::string err = store.add(fp.toStdString(), name.toStdString());
    if (!err.empty()) {
        QMessageBox::critical(this, "Error", QString::fromStdString(err));
        return;
    }
    peer_name_input_->clear();
    peer_fp_input_->clear();
    refreshPeerList();
    onLogMessage(QString("[TRUST] Added peer '%1' to trust store.").arg(name));
}

void MainWindow::onRemovePeer() {
    int row = peer_table_->currentRow();
    if (row < 0) {
        QMessageBox::information(this, "Notice", "Please select a peer row to remove.");
        return;
    }
    QString name = peer_table_->item(row, 0)->text();

    const auto trustPath = getIdentityDirectory() / identity::TRUST_FILE;
    trust::TrustStore store(trustPath);
    store.remove(name.toStdString());
    refreshPeerList();
    onLogMessage(QString("[TRUST] Removed peer '%1' from trust store.").arg(name));
}

void MainWindow::refreshPeerList() const {
    peer_table_->setRowCount(0);
    const auto trustPath = getIdentityDirectory() / identity::TRUST_FILE;
    trust::TrustStore store(trustPath);
    for (const auto& entry : store.list()) {
        int row = peer_table_->rowCount();
        peer_table_->insertRow(row);
        auto* nameItem = new QTableWidgetItem(QString::fromStdString(entry.name));
        auto* fpItem = new QTableWidgetItem(QString::fromStdString(trust::display_fingerprint(entry.fingerprint)));
        nameItem->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        fpItem->setTextAlignment(Qt::AlignVCenter | Qt::AlignLeft);
        peer_table_->setItem(row, 0, nameItem);
        peer_table_->setItem(row, 1, fpItem);
    }
}

void MainWindow::onLogMessage(const QString& msg) const {
    log_pane_->append(msg);
}

void MainWindow::onTransferProgress(int percentage, quint64 transferred, quint64 total) const {
    progress_bar_->setValue(percentage);
    if (total > 0) {
        double transMb = static_cast<double>(transferred) / (1024.0 * 1024.0);
        double totalMb = static_cast<double>(total) / (1024.0 * 1024.0);
        transfer_status_lbl_->setText(QString("Progress: %1% (%2 MB / %3 MB)")
            .arg(percentage)
            .arg(transMb, 0, 'f', 2)
            .arg(totalMb, 0, 'f', 2));
    } else {
        transfer_status_lbl_->setText(QString("Progress: %1%").arg(percentage));
    }
}

void MainWindow::onTransferCompleted(bool success, const QString& status) const {
    if (success) {
        progress_bar_->setValue(100);
        transfer_status_lbl_->setText("Transfer completed successfully!");
    } else {
        transfer_status_lbl_->setText(QString("Transfer failed: %1").arg(status));
    }
}
