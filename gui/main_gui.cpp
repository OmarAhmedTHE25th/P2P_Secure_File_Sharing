#include <QApplication>
#include "main_window.hpp"
#include <QStyleFactory>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    if (auto* fusion = QStyleFactory::create("Fusion")) {
        QApplication::setStyle(fusion);
    }

    const QString modernStyle = R"(
    /* Global Base */
    QWidget {
        background-color: #F5F6FA;
        color: #0f172a; /* Slate 900 */
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        font-size: 13px;
    }

    /* Card Containers */
    QFrame#card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
    }

    /* Headings and Labels */
    QLabel#appTitle {
        font-size: 17px;
        font-weight: 800;
        color: #0f172a;
    }
    QLabel#cardTitle {
        font-size: 14px;
        font-weight: 700;
        color: #0f172a;
    }
    QLabel#subheading {
        color: #64748b;
        font-size: 12px;
    }
    QLabel#inputLabel {
        font-size: 12px;
        font-weight: 600;
        color: #334155;
    }
    QLabel#badge {
        background-color: #eff6ff;
        color: #2563eb;
        font-size: 11px;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 10px;
        border: 1px solid #bfdbfe;
    }
    QLabel#monoBox {
        background-color: #f8fafc;
        color: #0f172a;
        border: 1px solid #cbd5e1;
        border-radius: 6px;
        padding: 6px 12px;
        font-family: "SF Mono", "Fira Code", "Consolas", "Courier New", monospace;
        font-size: 12px;
        font-weight: 500;
    }

    /* Tab Widget & Bar */
    QTabWidget::pane {
        border: none;
        background: transparent;
    }
    QTabBar {
        background: transparent;
    }
    QTabBar::tab {
        background-color: #ffffff;
        color: #64748b;
        font-weight: 600;
        font-size: 13px;
        padding: 9px 22px;
        border-radius: 8px;
        margin-right: 8px;
        border: 1px solid #e2e8f0;
    }
    QTabBar::tab:selected {
        background-color: #2563eb;
        color: #ffffff;
        border: 1px solid #2563eb;
    }
    QTabBar::tab:hover:!selected {
        background-color: #f1f5f9;
        color: #0f172a;
        border-color: #cbd5e1;
    }

    /* Flat Modern Inputs */
    QLineEdit {
        background-color: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        padding: 6px 12px;
        color: #0f172a;
        font-size: 13px;
    }
    QLineEdit:focus {
        border: 2px solid #2563eb;
        background-color: #ffffff;
    }
    QLineEdit:disabled {
        background-color: #f1f5f9;
        color: #94a3b8;
        border-color: #e2e8f0;
    }

    /* Primary Action Buttons */
    QPushButton#primaryBtn {
        background-color: #2563eb;
        color: #ffffff;
        font-weight: 600;
        font-size: 13px;
        border-radius: 8px;
        padding: 8px 18px;
        border: none;
    }
    QPushButton#primaryBtn:hover {
        background-color: #1d4ed8;
    }
    QPushButton#primaryBtn:pressed {
        background-color: #1e40af;
    }
    QPushButton#primaryBtn:disabled {
        background-color: #e2e8f0;
        color: #94a3b8;
    }

    /* Secondary Neutral Buttons */
    QPushButton#secondaryBtn, QPushButton {
        background-color: #ffffff;
        color: #334155;
        font-weight: 600;
        font-size: 13px;
        border-radius: 8px;
        padding: 6px 14px;
        border: 1px solid #cbd5e1;
    }
    QPushButton#secondaryBtn:hover, QPushButton:hover {
        background-color: #f8fafc;
        border-color: #94a3b8;
        color: #0f172a;
    }
    QPushButton#secondaryBtn:pressed, QPushButton:pressed {
        background-color: #f1f5f9;
    }
    QPushButton#secondaryBtn:disabled, QPushButton:disabled {
        background-color: #f8fafc;
        color: #94a3b8;
        border-color: #e2e8f0;
    }

    /* Danger Action Buttons */
    QPushButton#dangerBtn {
        background-color: #fef2f2;
        color: #dc2626;
        font-weight: 600;
        font-size: 12px;
        border-radius: 8px;
        padding: 6px 14px;
        border: 1px solid #fecaca;
    }
    QPushButton#dangerBtn:hover {
        background-color: #fee2e2;
        border-color: #f87171;
        color: #b91c1c;
    }
    QPushButton#dangerBtn:pressed {
        background-color: #fca5a5;
    }
    QPushButton#dangerBtn:disabled {
        background-color: #f8fafc;
        color: #cbd5e1;
        border-color: #f1f5f9;
    }

    /* Progress Bar (Solid Modern Fill, No Gradients) */
    QProgressBar {
        background-color: #f1f5f9;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        text-align: center;
        color: #0f172a;
        font-size: 11px;
        font-weight: 700;
    }
    QProgressBar::chunk {
        background-color: #2563eb;
        border-radius: 7px;
    }

    /* Table Widget */
    QTableWidget {
        background-color: #ffffff;
        gridline-color: #f1f5f9;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        outline: none;
    }
    QTableWidget::item {
        padding: 6px 12px;
        color: #1e293b;
    }
    QTableWidget::item:selected {
        background-color: #eff6ff;
        color: #1d4ed8;
    }
    QTableWidget::item:alternate {
        background-color: #f8fafc;
    }
    QHeaderView::section {
        background-color: #f8fafc;
        color: #475569;
        padding: 8px 12px;
        border: none;
        border-bottom: 2px solid #e2e8f0;
        font-weight: 700;
        font-size: 12px;
    }

    /* Activity Log Pane */
    QTextEdit {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 10px;
        color: #334155;
        font-family: "SF Mono", "Fira Code", "Consolas", "Courier New", monospace;
        font-size: 12px;
        line-height: 1.4;
    }
    QTextEdit:focus {
        border: 1px solid #94a3b8;
    }

    /* Clean Scrollbars */
    QScrollBar:vertical {
        background: transparent;
        width: 8px;
        margin: 2px 0 2px 0;
    }
    QScrollBar::handle:vertical {
        background: #cbd5e1;
        min-height: 24px;
        border-radius: 4px;
    }
    QScrollBar::handle:vertical:hover {
        background: #94a3b8;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
        background: transparent;
    }
    )";

    app.setStyleSheet(modernStyle);

    MainWindow window;
    window.show();

    return QApplication::exec();
}