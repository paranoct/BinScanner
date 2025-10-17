import sys
import os
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QListWidget, QTextEdit, QLabel,
    QFileDialog, QMessageBox, QProgressBar, QFrame
)
from PySide6.QtGui import QFont, QIcon, QPalette, QColor, QTextDocument
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from scanner import scan_pe, format_report_html


# ---- Поток с session_id в сигналах ----
class ScanThread(QThread):
    progress = Signal(int, int)
    finished = Signal(int, list)
    error = Signal(int, str)

    def __init__(self, paths, session_id: int):
        super().__init__()
        self.orig_paths = list(paths)
        self.session_id = session_id
        self._stop_requested = False

    def expand_paths(self, paths):
        file_list = []
        for p in paths:
            if os.path.isfile(p):
                if p.lower().endswith(('.exe', '.dll')):
                    file_list.append(p)
            elif os.path.isdir(p):
                for root, _, files in os.walk(p):
                    for f in files:
                        if f.lower().endswith(('.exe', '.dll')):
                            file_list.append(os.path.join(root, f))
        seen = set()
        uniq = []
        for f in file_list:
            if f not in seen:
                seen.add(f)
                uniq.append(f)
        return uniq

    def run(self):
        try:
            files = self.expand_paths(self.orig_paths)
            total = len(files)
            results = []

            if total == 0:
                self.progress.emit(self.session_id, 0)
                self.finished.emit(self.session_id, results)
                return

            for i, fpath in enumerate(files):
                if self._stop_requested:
                    break
                try:
                    res = scan_pe(fpath)
                    results.append(res)
                except Exception as e:
                    results.append({
                        "path": fpath,
                        "ok": False,
                        "summary": {"High": 1, "Medium": 0, "Low": 0, "Info": 0},
                        "issues": [{
                            "severity": "High",
                            "title": "Ошибка анализа файла",
                            "description": str(e),
                            "evidence": [],
                            "recommendation": "Проверьте файл вручную.",
                            "location": "scanner"
                        }],
                        "metadata": {}
                    })
                pct = int((i + 1) / total * 100)
                self.progress.emit(self.session_id, pct)

            self.finished.emit(self.session_id, results)
        except Exception as e:
            self.error.emit(self.session_id, str(e))

    def stop(self):
        self._stop_requested = True


# ---- Главное окно ----
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BinScanner — Анализатор бинарников на уязвимости")
        self.resize(1100, 700)

        self.layout = QHBoxLayout(self)

        # left panel
        left = QVBoxLayout()
        title = QLabel("Файлы для анализа")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        title.setStyleSheet("color: #93c5fd; margin-bottom: 8px;")
        left.addWidget(title)

        self.listw = QListWidget()
        self.listw.setStyleSheet("""
            QListWidget {
                background-color: #1e293b;
                color: #e2e8f0;
                border-radius: 8px;
                padding: 6px;
            }
            QListWidget::item:selected {
                background-color: #334155;
                border-left: 4px solid #60a5fa;
            }
        """)
        left.addWidget(self.listw)

        # --- Buttons row ---
        btn_row = QHBoxLayout()
        self.add_btn = QPushButton("➕ Файл")
        self.add_folder_btn = QPushButton("📁 Папка")
        self.remove_btn = QPushButton("🗑 Удалить")
        self.scan_btn = QPushButton("🚀 Сканировать")
        self.stop_btn = QPushButton("🛑 Стоп")
        self.stop_btn.setEnabled(False)

        def style_primary(btn):
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #2563eb;
                    color: white;
                    border-radius: 8px;
                    padding: 6px 14px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background-color: #1d4ed8;
                }
            """)

        for b in [self.add_btn, self.add_folder_btn, self.remove_btn, self.scan_btn]:
            style_primary(b)

        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444;
                color: white;
                border-radius: 6px;
                padding: 4px 10px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #dc2626;
            }
        """)

        btn_row.addWidget(self.add_btn)
        btn_row.addWidget(self.add_folder_btn)
        btn_row.addWidget(self.remove_btn)
        btn_row.addWidget(self.scan_btn)
        btn_row.addWidget(self.stop_btn)
        left.addLayout(btn_row)

        # progress
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #334155;
                border-radius: 8px;
                text-align: center;
                color: #cbd5e1;
                background-color: #1e293b;
                height: 18px;
            }
            QProgressBar::chunk {
                background-color: #60a5fa;
                border-radius: 8px;
            }
        """)
        left.addWidget(self.progress)

        # right panel
        right = QVBoxLayout()
        header_row = QHBoxLayout()
        header = QLabel("Результаты анализа")
        header.setFont(QFont("Segoe UI", 12, QFont.Bold))
        header.setStyleSheet("color: #93c5fd; margin-bottom: 8px;")

        self.clear_btn = QPushButton("🧹 Очистить отчёт")
        self.clear_btn.setCursor(Qt.PointingHandCursor)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #475569;
                color: #e2e8f0;
                border-radius: 6px;
                padding: 4px 10px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #64748b;
            }
        """)

        header_row.addWidget(header)
        header_row.addStretch()
        header_row.addWidget(self.clear_btn)
        right.addLayout(header_row)

        self.report = QTextEdit()
        self.report.setReadOnly(True)
        self.report.setPlaceholderText("Отчёт появится здесь после анализа...")
        self.report.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #e2e8f0;
                border-radius: 8px;
                padding: 10px;
                font-family: Consolas, monospace;
            }
        """)
        right.addWidget(self.report)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #94a3b8; font-size: 12px; padding: 6px 0px;")
        right.addWidget(self.status_label)

        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setStyleSheet("color: #475569;")
        self.layout.addLayout(left, 1)
        self.layout.addWidget(line)
        self.layout.addLayout(right, 2)

        # signals
        self.add_btn.clicked.connect(self.add_file)
        self.add_folder_btn.clicked.connect(self.add_folder)
        self.remove_btn.clicked.connect(self.remove_selected)
        self.scan_btn.clicked.connect(self.do_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn.clicked.connect(self.clear_report)

        self.thread = None
        self._scan_session_id = 0
        self.scan_log = []

    # UI methods
    def add_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите PE-файл", "", "Файлы (*.exe *.dll)")
        if path:
            self.listw.addItem(path)

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку с файлами")
        if folder:
            self.listw.addItem(folder)

    def remove_selected(self):
        row = self.listw.currentRow()
        if row >= 0:
            self.listw.takeItem(row)
        else:
            QMessageBox.information(self, "Удаление", "Выберите элемент для удаления.")

    def do_scan(self):
        if self.thread and self.thread.isRunning():
            QMessageBox.warning(self, "Скан уже запущен", "Сканирование уже выполняется.")
            return

        paths = [self.listw.item(i).text() for i in range(self.listw.count())]
        if not paths:
            QMessageBox.warning(self, "Нет файлов", "Добавьте хотя бы один путь (файл или папка).")
            return

        self.report.clear()
        self._scan_session_id += 1
        sid = self._scan_session_id

        self.scan_log = []
        self.report.setPlainText("🔍 Сканирование запущено...\nПожалуйста, подождите.")
        self.progress.setValue(0)
        self.status_label.setText("")
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.thread = ScanThread(paths, sid)
        self.thread.progress.connect(self.on_progress)
        self.thread.finished.connect(self.scan_done)
        self.thread.error.connect(self.scan_error)
        self.thread.start()

    def on_progress(self, sid: int, pct: int):
        if sid == self._scan_session_id:
            self.progress.setValue(pct)

    def scan_done(self, sid: int, results):
        if sid != self._scan_session_id:
            return
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.thread = None

        if not results:
            self.report.setPlainText("Файлы .exe/.dll не найдены.")
            self.status_label.setText("Нет файлов для анализа.")
            return

        text_parts = [format_report_html(r) + "<hr>" for r in results]
        html = "".join(text_parts)
        self.scan_log = text_parts.copy()

        doc = QTextDocument()
        doc.setDefaultFont(QFont("Consolas", 10))
        doc.setHtml(html)
        self.report.setDocument(doc)

        high = sum(r.get("summary", {}).get("High", 0) for r in results)
        med = sum(r.get("summary", {}).get("Medium", 0) for r in results)
        low = sum(r.get("summary", {}).get("Low", 0) for r in results)

        self.progress.setValue(100)
        QMessageBox.information(
            self,
            "Сканирование завершено",
            f"✅ Анализ завершён!\n\n"
            f"Файлов обработано: {len(results)}\n"
            f"High: {high} | Medium: {med} | Low: {low}"
        )

    def scan_error(self, sid: int, msg: str):
        if sid != self._scan_session_id:
            return
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.thread = None
        QMessageBox.critical(self, "Ошибка анализа", msg)

    def stop_scan(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.stop_btn.setEnabled(False)
            self.scan_btn.setEnabled(True)
            self.status_label.setText("Остановка сканирования...")
        else:
            self.status_label.setText("Сканирование не выполняется.")

    def clear_report(self):
        self.report.clear()
        self.progress.setValue(0)
        self.status_label.setText("Отчёт очищен.")
        QTimer.singleShot(1400, lambda: self.status_label.setText(""))

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning():
            self.thread.stop()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    dark = QPalette()
    dark.setColor(QPalette.Window, QColor("#0f172a"))
    dark.setColor(QPalette.WindowText, QColor("#e2e8f0"))
    dark.setColor(QPalette.Base, QColor("#1e293b"))
    dark.setColor(QPalette.Text, QColor("#e2e8f0"))
    dark.setColor(QPalette.Button, QColor("#1e293b"))
    dark.setColor(QPalette.ButtonText, QColor("#e2e8f0"))
    app.setPalette(dark)
    app.setStyle("Fusion")

    w = MainWindow()
    w.show()
    sys.exit(app.exec())
