#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI-only installer for BinScanner using PySide6.
Build with PyInstaller using --noconsole (if you want a no-console exe).

This variant uses the same dark palette and styling as gui.py.
"""
from __future__ import annotations
import sys
import os
import shutil
import subprocess
import tempfile
import urllib.request
import time
import threading
from typing import Optional

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QCheckBox, QFileDialog, QMessageBox, QProgressBar
)
from PySide6.QtGui import QFont, QPalette, QColor
from PySide6.QtCore import Qt, QObject, Signal, QThread

# ---------- Config ----------
APP_NAME = "BinScanner"
DEFAULT_PY_VER = "3.12.6"
THIS_DIR = os.path.abspath(os.path.dirname(__file__))


def is_windows() -> bool:
    return sys.platform.startswith("win")


def is_admin() -> bool:
    if not is_windows():
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_cmd(cmd, check=True):
    return subprocess.run(cmd, check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def download_file(url: str, dest: str, progress_callback=None):
    with urllib.request.urlopen(url) as resp, open(dest, "wb") as out:
        total = resp.getheader('Content-Length')
        total = int(total) if total and total.isdigit() else None
        downloaded = 0
        block = 8192
        start = time.time()
        while True:
            chunk = resp.read(block)
            if not chunk:
                break
            out.write(chunk)
            downloaded += len(chunk)
            if total and progress_callback:
                pct = int(downloaded * 100 / total)
                progress_callback(pct)
        elapsed = time.time() - start
    return True


def python_in_venv(venv_path: str) -> str:
    if is_windows():
        return os.path.join(venv_path, "Scripts", "python.exe")
    else:
        return os.path.join(venv_path, "bin", "python")


# ---------- Worker ----------
class InstallerWorker(QObject):
    log = Signal(str)
    progress = Signal(int)
    finished = Signal(bool, str)

    def __init__(self, install_dir: str, install_python: bool, use_venv: bool, create_shortcuts_flag: bool):
        super().__init__()
        self.install_dir = install_dir
        self.install_python = install_python
        self.use_venv = use_venv
        self.create_shortcuts_flag = create_shortcuts_flag
        self._stop_requested = False

    def _emit(self, msg: str):
        self.log.emit(msg)

    def _emit_progress(self, v: int):
        self.progress.emit(v)

    def stop(self):
        self._stop_requested = True

    def copy_project_files(self):
        self._emit("Копирование файлов проекта...")
        os.makedirs(self.install_dir, exist_ok=True)
        names = ["dist", "assets", "templates", "static", "icon.ico", "requirements.txt"]
        total = len(names)
        done = 0
        for name in names:
            if self._stop_requested:
                return False
            src = os.path.join(THIS_DIR, name)
            dst = os.path.join(self.install_dir, os.path.basename(name))
            if os.path.exists(src):
                try:
                    if os.path.isdir(src):
                        if os.path.exists(dst):
                            shutil.rmtree(dst, ignore_errors=True)
                        shutil.copytree(src, dst)
                        self._emit(f"  Скопирована папка: {name}")
                    else:
                        shutil.copy2(src, dst)
                        self._emit(f"  Скопирован файл: {name}")
                except Exception as e:
                    self._emit(f"  Ошибка копирования {name}: {e}")
                    return False
            else:
                self._emit(f"  (не найдено) {name} — пропущено")
            done += 1
            self._emit_progress(int(done / total * 30))
        return True

    def install_system_python_windows(self) -> bool:
        if not is_windows():
            self._emit("Автоустановка системного Python поддерживается только в Windows.")
            return False
        try:
            out = run_cmd(["python", "--version"])
            self._emit(f"Python обнаружен: {out.stdout.strip()}")
            return True
        except Exception:
            pass
        if not is_admin():
            self._emit("Для установки системного Python требуются права администратора. Отмена.")
            return False
        self._emit("Скачивание установщика Python...")
        tmp_inst = os.path.join(tempfile.gettempdir(), f"python-{DEFAULT_PY_VER}-amd64.exe")
        url = f"https://www.python.org/ftp/python/{DEFAULT_PY_VER}/python-{DEFAULT_PY_VER}-amd64.exe"
        try:
            download_file(url, tmp_inst, progress_callback=lambda p: self._emit_progress(30 + int(p * 0.2)))
        except Exception as e:
            self._emit(f"Ошибка скачивания Python: {e}")
            return False
        args = [tmp_inst, "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_pip=1"]
        try:
            self._emit("Запуск инсталлятора Python (тихо)...")
            res = run_cmd(args)
            self._emit(res.stdout or "Установка Python завершена.")
            return True
        except Exception as e:
            self._emit(f"Ошибка установки Python: {e}")
            return False
        finally:
            try:
                if os.path.exists(tmp_inst):
                    os.remove(tmp_inst)
            except Exception:
                pass

    def make_venv(self, venv_path: str) -> Optional[str]:
        try:
            self._emit(f"Создание виртуального окружения: {venv_path}")
            import venv
            venv.EnvBuilder(with_pip=True).create(venv_path)
            py = python_in_venv(venv_path)
            self._emit(f"venv создан: {py}")
            return py
        except Exception as e:
            self._emit(f"Ошибка создания venv: {e}")
            return None

    def pip_install(self, requirements_path: str, python_exe: str) -> bool:
        if not os.path.exists(requirements_path):
            self._emit("requirements.txt не найден в папке установки.")
            return False
        try:
            self._emit("Обновление pip и установка зависимостей...")
            run_cmd([python_exe, "-m", "pip", "install", "--upgrade", "pip"])
            run_cmd([python_exe, "-m", "pip", "install", "-r", requirements_path])
            self._emit("Установка зависимостей завершена.")
            return True
        except Exception as e:
            self._emit(f"Ошибка установки зависимостей: {e}")
            return False

    def create_shortcuts_impl(self):
        if not is_windows():
            self._emit("Ярлыки поддерживаются только в Windows.")
            return
        desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop") or os.path.join(os.path.expanduser("~"), "Desktop")
        start_menu = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", APP_NAME)
        os.makedirs(start_menu, exist_ok=True)

        def make_vbs(target, shortcut):
            vbs = f'''
Set WshShell = WScript.CreateObject("WScript.Shell")
Set oShellLink = WshShell.CreateShortcut("{shortcut}")
oShellLink.TargetPath = "{target}"
oShellLink.WorkingDirectory = "{os.path.dirname(target)}"
oShellLink.Save
'''
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".vbs", mode="w", encoding="utf-8")
            tf.write(vbs); tf.flush(); tf.close()
            try:
                run_cmd(["cscript", "//nologo", tf.name])
                self._emit(f"  Ярлык создан: {os.path.basename(shortcut)}")
            except Exception as e:
                self._emit(f"  Ошибка создания ярлыка {shortcut}: {e}")
            finally:
                try:
                    os.remove(tf.name)
                except Exception:
                    pass

        gui_exe = os.path.join(self.install_dir, "gui.exe")
        web_exe = os.path.join(self.install_dir, "web_api.exe")
        if os.path.exists(gui_exe):
            make_vbs(gui_exe, os.path.join(desktop, f"{APP_NAME} GUI.lnk"))
            make_vbs(gui_exe, os.path.join(start_menu, f"{APP_NAME} GUI.lnk"))
        if os.path.exists(web_exe):
            make_vbs(web_exe, os.path.join(desktop, f"{APP_NAME} Web.lnk"))
            make_vbs(web_exe, os.path.join(start_menu, f"{APP_NAME} Web.lnk"))

    def write_uninstall(self):
        uninst = os.path.join(self.install_dir, "uninstall.bat")
        content = f"""@echo off
echo Удаление {APP_NAME}...
rd /s /q "{self.install_dir}" 2>nul
echo Готово.
pause
"""
        try:
            with open(uninst, "w", encoding="utf-8") as f:
                f.write(content)
            self._emit(f"Скрипт удаления записан: {uninst}")
        except Exception as e:
            self._emit(f"Ошибка записи uninstall.bat: {e}")

    # main run
    def run(self):
        try:
            self._emit("Начало установки...")
            self._emit_progress(5)

            # copy files
            ok = self.copy_project_files()
            if not ok:
                self.finished.emit(False, "Ошибка при копировании файлов.")
                return
            self._emit_progress(35)

            # optionally install system python (windows)
            if self.install_python and is_windows():
                ok = self.install_system_python_windows()
                if not ok:
                    self._emit("Внимание: автоматическая установка Python не удалась — продолжим, но установка зависимостей может не пройти.")
                self._emit_progress(50)

            # install dependencies
            req_path = os.path.join(self.install_dir, "requirements.txt")
            if self.use_venv:
                venv_path = os.path.join(self.install_dir, "venv")
                py = self.make_venv(venv_path)
                if not py:
                    self.finished.emit(False, "Не удалось создать venv.")
                    return
                ok = self.pip_install(req_path, py)
                if not ok:
                    self.finished.emit(False, "Установка зависимостей в venv не удалась.")
                    return
            else:
                python_exe = shutil.which("python") or sys.executable
                try:
                    ok = self.pip_install(req_path, python_exe)
                except Exception as e:
                    self._emit(f"Ошибка установки в системный Python: {e}")
                    ok = False
                if not ok:
                    # try fallback to venv
                    self._emit("Попытка fallback: создаём venv...")
                    venv_path = os.path.join(self.install_dir, "venv")
                    py = self.make_venv(venv_path)
                    if not py:
                        self.finished.emit(False, "Не удалось создать venv fallback.")
                        return
                    ok2 = self.pip_install(req_path, py)
                    if not ok2:
                        self.finished.emit(False, "Установка зависимостей не удалась (venv fallback).")
                        return

            self._emit_progress(85)

            # create shortcuts
            if self.create_shortcuts_flag:
                self.create_shortcuts_impl()
            self._emit_progress(90)

            # uninstall script
            self.write_uninstall()
            self._emit_progress(95)

            self._emit("Установка успешно завершена.")
            self._emit_progress(100)
            self.finished.emit(True, "Установка успешно завершена.")
        except Exception as e:
            self._emit(f"Ошибка установки: {e}")
            self.finished.emit(False, f"Ошибка: {e}")


# ---------- UI styling helpers (match gui.py) ----------
def apply_dark_palette(app: QApplication):
    dark = QPalette()
    dark.setColor(QPalette.ColorRole.Window, QColor("#0f172a"))
    dark.setColor(QPalette.ColorRole.WindowText, QColor("#e2e8f0"))
    dark.setColor(QPalette.ColorRole.Base, QColor("#1e293b"))
    dark.setColor(QPalette.ColorRole.Text, QColor("#e2e8f0"))
    dark.setColor(QPalette.ColorRole.Button, QColor("#1e293b"))
    dark.setColor(QPalette.ColorRole.ButtonText, QColor("#e2e8f0"))
    app.setPalette(dark)
    app.setStyle("Fusion")


def style_primary(btn: QPushButton):
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet("""
        QPushButton {
            background-color: #2563eb;
            color: white;
            border-radius: 8px;
            padding: 8px 14px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #1d4ed8;
        }
    """)


def style_secondary(btn: QPushButton):
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet("""
        QPushButton {
            background-color: #475569;
            color: #e2e8f0;
            border-radius: 6px;
            padding: 6px 10px;
            font-weight: 500;
        }
        QPushButton:hover {
            background-color: #64748b;
        }
    """)


def style_danger(btn: QPushButton):
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet("""
        QPushButton {
            background-color: #ef4444;
            color: white;
            border-radius: 6px;
            padding: 6px 10px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #dc2626;
        }
    """)


# ---------- GUI ----------
class InstallerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — Установщик")
        self.resize(780, 520)

        # overall font
        self.setFont(QFont("Segoe UI", 10))

        v = QVBoxLayout(self)
        header = QLabel(f"<b style='font-size:16pt'> {APP_NAME} — графический установщик</b>")
        header.setStyleSheet("color: #93c5fd; margin-bottom: 6px;")
        v.addWidget(header)

        hdir = QHBoxLayout()
        self.dir_edit = QLineEdit()
        self.dir_edit.setPlaceholderText("Папка установки (по умолчанию Program Files или ~/BinScanner)")
        btn_browse = QPushButton("Обзор...")
        style_secondary(btn_browse)
        btn_browse.clicked.connect(self.browse_dir)
        hdir.addWidget(self.dir_edit)
        hdir.addWidget(btn_browse)
        v.addLayout(hdir)

        opt_layout = QHBoxLayout()
        self.chk_install_python = QCheckBox("Авто-установить Python (Windows, требует админов)")
        self.chk_use_venv = QCheckBox("Установить зависимости в venv (по умолчанию OFF)")
        self.chk_create_shortcuts = QCheckBox("Создать ярлыки (Desktop и Пуск)")
        self.chk_create_shortcuts.setChecked(True)
        opt_layout.addWidget(self.chk_install_python)
        opt_layout.addWidget(self.chk_use_venv)
        opt_layout.addWidget(self.chk_create_shortcuts)
        v.addLayout(opt_layout)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Начать установку")
        self.cancel_btn = QPushButton("Закрыть")
        style_primary(self.start_btn)
        style_danger(self.cancel_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.cancel_btn)
        v.addLayout(btn_layout)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        # style log to match gui.py
        self.log.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #e2e8f0;
                border-radius: 8px;
                padding: 10px;
                font-family: Consolas, monospace;
            }
        """)
        v.addWidget(self.log, 1)

        self.progress = QProgressBar()
        # style progress bar to match gui.py
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
        self.progress.setValue(0)
        v.addWidget(self.progress)

        self.start_btn.clicked.connect(self.start_install)
        self.cancel_btn.clicked.connect(self.close)

        self._worker_thread: Optional[QThread] = None
        self._worker: Optional[InstallerWorker] = None

    def browse_dir(self):
        dirpath = QFileDialog.getExistingDirectory(self, "Выберите папку для установки", os.path.expanduser("~"))
        if dirpath:
            self.dir_edit.setText(dirpath)

    def append_log(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log.append(f"[{ts}] {text}")

    def set_progress(self, v: int):
        self.progress.setValue(v)

    def on_finished(self, success: bool, message: str):
        self.append_log(message)
        self.start_btn.setEnabled(True)
        if success:
            QMessageBox.information(self, "Установка", message)
        else:
            QMessageBox.critical(self, "Установка", message)

    def start_install(self):
        install_dir = self.dir_edit.text().strip()
        if not install_dir:
            if is_windows():
                pf = os.environ.get("ProgramFiles", r"C:\Program Files")
                install_dir = os.path.join(pf, APP_NAME)
            else:
                install_dir = os.path.join(os.path.expanduser("~"), APP_NAME)
            self.dir_edit.setText(install_dir)

        self.start_btn.setEnabled(False)
        self.log.clear()
        self.progress.setValue(0)

        install_python = self.chk_install_python.isChecked()
        use_venv = self.chk_use_venv.isChecked()
        create_shortcuts_flag = self.chk_create_shortcuts.isChecked()

        self._worker = InstallerWorker(install_dir, install_python, use_venv, create_shortcuts_flag)
        self._worker_thread = QThread()
        self._worker.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._worker.run)
        self._worker.log.connect(self.append_log)
        self._worker.progress.connect(self.set_progress)
        self._worker.finished.connect(self.on_finished)

        def cleanup(success, message):
            try:
                self._worker_thread.quit()
                self._worker_thread.wait(2000)
            finally:
                self._worker = None
                self._worker_thread = None

        self._worker.finished.connect(cleanup)
        self._worker_thread.start()


# ---------- entry ----------
def main():
    app = QApplication(sys.argv)
    apply_dark_palette(app)
    wnd = InstallerWindow()
    wnd.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
