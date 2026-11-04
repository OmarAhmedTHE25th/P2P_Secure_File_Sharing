#include <QApplication>
#include "main_window.hpp"
#include <QStyleFactory>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    if (auto* fusion = QStyleFactory::create("Fusion")) {
        QApplication::setStyle(fusion);
    }

    const QString modernStyle = R"(
    QWidget {
        background-color: #0f172a; /* Slate 900 */
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 13px;
    }

    /* Clean Card Container */
    QTabWidget::pane {
        border: 1px solid #1e293b;
        background: #1e293b;
        border-radius: 8px;
        top: -1px;
    }

    /* Pill-Style Tab Bar */
    QTabBar::tab {
        background: transparent;
        color: #94a3b8;
        padding: 8px 18px;
        margin-right: 4px;
        border-radius: 6px;
        font-weight: 500;
    }
    QTabBar::tab:selected {
        background: #334155;
        color: #38bdf8;
    }
    QTabBar::tab:hover:!selected {
        background: #1e293b;
        color: #f1f5f9;
    }

    /* Modern Flat Inputs */
    QLineEdit, QTextEdit, QTableWidget {
        background-color: #0b1120;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 0 10px;
        color: #f8fafc;
    }
    QLineEdit:focus, QTextEdit:focus {
        border: 1px solid #38bdf8;
        background-color: #070d19;
    }

    /* Buttons */
    QPushButton {
        background-color: #2563eb;
        color: #ffffff;
        font-weight: 600;
        border-radius: 6px;
        padding: 8px 16px;
        border: none;
    }
    QPushButton:hover {
        background-color: #3b82f6;
    }
    QPushButton:pressed {
        background-color: #1d4ed8;
    }
    QPushButton:disabled {
        background-color: #1e293b;
        color: #64748b;
    }

    /* Progress Bar */
    QProgressBar {
        background-color: #0b1120;
        border: 1px solid #334155;
        border-radius: 6px;
        height: 18px;
        text-align: center;
        color: #f8fafc;
        font-size: 11px;
        font-weight: 600;
    }
    QProgressBar::chunk {
        background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #06b6d4, stop:1 #3b82f6);
        border-radius: 5px;
    }

    /* Table & Log */
    QTableWidget {
        gridline-color: #1e293b;
        border: 1px solid #334155;
    }
    QHeaderView::section {
        background-color: #1e293b;
        color: #94a3b8;
        padding: 6px;
        border: none;
        border-bottom: 1px solid #334155;
        font-weight: 600;
    }
)";

    app.setStyleSheet(modernStyle);

    MainWindow window;
    window.show();

    return QApplication::exec();
}