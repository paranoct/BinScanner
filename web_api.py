# web_api.py
import sys
import os
import subprocess
import webbrowser
import tempfile
import shutil
import socket
import re
import html as _html
import uuid
import threading
import time
import argparse
from typing import List, Optional

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QMessageBox
)
from PySide6.QtGui import QFont, QPalette, QColor
from PySide6.QtCore import Qt, QTimer

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ---------------- Try to import scanner API from scanner.py ----------------
scan_files = None
scan_pe = None
format_report_html = None
format_report_human = None

try:
    from scanner import scan_files as _sf, scan_pe as _sp, format_report_html as _frh, format_report_human as _frh2
    scan_files = _sf if callable(_sf) else None
    scan_pe = _sp if callable(_sp) else None
    format_report_html = _frh if callable(_frh) else None
    format_report_human = _frh2 if callable(_frh2) else None
except Exception:
    # scanner missing or exports different names — upload will handle gracefully
    scan_files = None
    scan_pe = None
    format_report_html = None
    format_report_human = None

# ---------------- FastAPI app (definition only) ----------------
app = FastAPI(title="BinScanner Web")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATES_DIR)

SUPPORTED_EXTENSIONS = {".exe", ".dll"}

# ---------------- JOBS storage for background scans ----------------
JOBS = {}  # job_id -> dict: status, progress, result_html, result_text, error
JOBS_LOCK = threading.Lock()


def create_job_entry() -> str:
    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "pending",   # pending, running, done, error
            "progress": 0,
            "result_html": None,
            "result_text": None,
            "error": None,
            "tmp_dir": None,
            "done_event": None
        }
    return job_id


def update_job(job_id: str, **kwargs):
    with JOBS_LOCK:
        if job_id in JOBS:
            JOBS[job_id].update(kwargs)


def get_job(job_id: str):
    with JOBS_LOCK:
        return JOBS.get(job_id)


def remove_job(job_id: str):
    with JOBS_LOCK:
        JOBS.pop(job_id, None)


# ---------------- scanning worker ----------------
def scan_worker(job_id: str, path: str):
    """
    Worker runs in background thread. Uses scan_pe if available, else scan_files.
    While the scan runs, a progress feeder thread increments progress so UI is smooth.
    """
    update_job(job_id, status="running", progress=5)
    done_event = threading.Event()
    update_job(job_id, done_event=done_event)

    # progress feeder - increments progress while scan is running
    def feeder():
        while not done_event.is_set():
            with JOBS_LOCK:
                j = JOBS.get(job_id)
                if not j:
                    break
                p = j.get("progress", 0)
                # grow towards 85 slowly
                if p < 85:
                    p = min(85, p + (1 + (time.time() % 3)))
                else:
                    p = min(95, p + 0.5)
                j["progress"] = int(p)
            time.sleep(0.45)

    fthr = threading.Thread(target=feeder, daemon=True)
    fthr.start()

    try:
        # actual scan
        result = None
        if scan_pe:
            result = scan_pe(path)
        elif scan_files:
            # fallback - scan_files returns list
            res_list = scan_files([path])
            result = res_list[0] if isinstance(res_list, list) and res_list else None
        else:
            raise RuntimeError("scanner.py not available on server")

        # format HTML/text
        if format_report_html:
            try:
                report_html = format_report_html(result)
            except Exception as e:
                report_html = f"<pre>Ошибка format_report_html: {e}</pre>"
        else:
            report_html = None

        if format_report_human:
            try:
                report_text = format_report_human(result)
            except Exception as e:
                report_text = f"Ошибка format_report_human: {e}"
        else:
            # if no human formatter, convert HTML->text or JSON
            if report_html:
                t = re.sub(r'(?i)<br\s*/?>', '\n', report_html)
                t = re.sub(r'<[^>]+>', '', t)
                report_text = _html.unescape(t).strip()
            else:
                import json
                report_text = json.dumps(result or {}, ensure_ascii=False, indent=2)

        # save results
        update_job(job_id, result_html=report_html, result_text=report_text)
        done_event.set()
        update_job(job_id, progress=100, status="done")
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        update_job(job_id, error=str(e) + "\n" + tb, status="error", progress=0)
        done_event.set()
    finally:
        # cleanup tmp_dir if present
        j = get_job(job_id)
        if j:
            td = j.get("tmp_dir")
            if td:
                try:
                    shutil.rmtree(td, ignore_errors=True)
                except Exception:
                    pass


# ---------------- FastAPI endpoints ----------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/upload", response_class=HTMLResponse)
async def upload(request: Request, file: UploadFile = File(...)):
    """
    Legacy synchronous upload (keeps compatibility) — runs scan synchronously and returns full page.
    Recommended: client should use /start_scan for background scanning with progress.
    """
    filename = file.filename or "uploaded.bin"
    ext = os.path.splitext(filename)[1].lower()

    if ext not in SUPPORTED_EXTENSIONS:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "error": f"Выбранный файл '{filename}' не поддерживается. Загрузите .exe или .dll."},
        )

    tmp_dir = tempfile.mkdtemp()
    path = os.path.join(tmp_dir, filename)
    try:
        with open(path, "wb") as f:
            shutil.copyfileobj(file.file, f)

        # synchronous scan (same logic as background worker)
        if scan_pe:
            result = scan_pe(path)
        elif scan_files:
            rlist = scan_files([path])
            result = rlist[0] if rlist else {}
        else:
            result = {"note": "scanner not available"}

        if format_report_html:
            report_html = format_report_html(result)
        elif format_report_human:
            report_html = "<pre>" + format_report_human(result) + "</pre>"
        else:
            import json
            report_html = "<pre>" + json.dumps(result, ensure_ascii=False, indent=2) + "</pre>"

        report_text = format_report_human(result) if format_report_human else None
        if not report_text and report_html:
            t = re.sub(r'(?i)<br\s*/?>', '\n', report_html)
            t = re.sub(r'<[^>]+>', '', t)
            report_text = _html.unescape(t).strip()

        return templates.TemplateResponse("index.html", {"request": request, "filename": filename, "report_html": report_html, "report_text": report_text})
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.post("/start_scan")
async def start_scan(file: UploadFile = File(...)):
    """
    Start a background scan job. Returns job_id immediately.
    """
    filename = file.filename or "uploaded.bin"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return JSONResponse({"error": "Неверное расширение. Загрузите .exe или .dll."}, status_code=400)

    # save file in tmp dir per job
    tmp_dir = tempfile.mkdtemp()
    path = os.path.join(tmp_dir, filename)
    with open(path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    job_id = create_job_entry()
    update_job(job_id, status="queued", progress=1, tmp_dir=tmp_dir)
    # start background thread
    thr = threading.Thread(target=scan_worker, args=(job_id, path), daemon=True)
    thr.start()

    return {"job_id": job_id}


@app.get("/status/{job_id}")
async def status(job_id: str):
    j = get_job(job_id)
    if not j:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    # only return necessary fields
    return {
        "status": j.get("status"),
        "progress": int(j.get("progress", 0)),
        "result_html": j.get("result_html"),
        "result_text": j.get("result_text"),
        "error": j.get("error"),
    }


@app.get("/result/{job_id}", response_class=HTMLResponse)
async def result_html(job_id: str, request: Request):
    """
    Returns full template fragment for #reportArea (used if you prefer fetching whole fragment).
    """
    j = get_job(job_id)
    if not j:
        return HTMLResponse("<div class='error-box'>Job not found</div>", status_code=404)
    if j.get("status") != "done":
        return HTMLResponse("<div class='info-box'>Задача не завершена</div>", status_code=202)
    # build fragment similar to template: include HTML if available else text
    report_html = j.get("result_html")
    report_text = j.get("result_text")
    if report_html:
        fragment = f"<div id='content-html'>{report_html}</div>"
    else:
        fragment = f"<div id='content-text'><pre class='report'>{_html.escape(report_text or '')}</pre></div>"
    return HTMLResponse(fragment)


# ---------------- Utilities for server control (unchanged) ----------------
def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def find_pids_listening_on_port_windows(port: int) -> List[int]:
    if not sys.platform.startswith("win"):
        return []
    try:
        out = subprocess.check_output(["netstat", "-ano"], text=True, encoding="oem")
    except Exception:
        return []
    pids = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            local = parts[1]
            pid = parts[-1]
            if local.endswith(f":{port}"):
                try:
                    pids.add(int(pid))
                except Exception:
                    pass
    return sorted(pids)


def force_kill_pid_windows(pid: int) -> tuple[bool, str]:
    try:
        subprocess.check_output(["taskkill", "/PID", str(pid), "/F"], stderr=subprocess.STDOUT, text=True)
        return True, f"Процесс {pid} завершён."
    except subprocess.CalledProcessError as e:
        return False, f"Не удалось завершить PID {pid}: {e.output.strip()}"
    except Exception as e:
        return False, f"Ошибка: {e}"


# ---------------- GUI (PySide6) ----------------
class WebControl(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BinScanner Web Control")
        self.resize(520, 140)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignTop)

        title = QLabel("Управление Web сервером для BinScanner")
        title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        title.setStyleSheet("color: #93c5fd; margin-bottom: 12px;")
        layout.addWidget(title, alignment=Qt.AlignCenter)

        self.status_label = QLabel("🔴 Сервер остановлен")
        self.status_label.setFont(QFont("Segoe UI", 11))
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #f87171; font-weight: 500;")
        layout.addWidget(self.status_label)

        btns = QHBoxLayout()
        layout.addLayout(btns)

        self.start_btn = QPushButton("🚀 Запустить сервер")
        self.stop_btn = QPushButton("🛑 Остановить сервер")
        self.stop_btn.setEnabled(False)

        self._style_primary(self.start_btn)
        self._style_danger(self.stop_btn)

        btns.addStretch()
        btns.addWidget(self.start_btn)
        btns.addWidget(self.stop_btn)
        btns.addStretch()

        extra = QHBoxLayout()
        self.check_btn = QPushButton("Проверить порт")
        self.kill_btn = QPushButton("Принудительно убить PID")
        self.kill_btn.setEnabled(False)
        self._style_secondary(self.check_btn)
        self._style_secondary(self.kill_btn)
        extra.addWidget(self.check_btn)
        extra.addWidget(self.kill_btn)
        layout.addLayout(extra)

        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn.clicked.connect(self.stop_server)
        self.check_btn.clicked.connect(self.check_port)
        self.kill_btn.clicked.connect(self.kill_pid_prompt)

        self.uvicorn_proc: Optional[subprocess.Popen] = None
        self.uvicorn_thread = None  # reserved if needed in future
        self.uvicorn_server = None
        self._child_logf = None

        self.port = 8000
        self.url = f"http://127.0.0.1:{self.port}"
        self.found_pids_on_port: List[int] = []

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._check_server)
        self.status_timer.start(1500)

    def _style_primary(self, btn):
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #2563eb; color: white; border-radius: 8px;
                padding: 8px 14px; font-weight: 600;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)

    def _style_danger(self, btn):
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #ef4444; color: white; border-radius: 8px;
                padding: 8px 14px; font-weight: 600;
            }
            QPushButton:hover { background-color: #dc2626; }
        """)

    def _style_secondary(self, btn):
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #475569; color: #e2e8f0; border-radius: 8px;
                padding: 6px 10px; font-weight: 500;
            }
            QPushButton:hover { background-color: #64748b; }
        """)

    def start_server(self):
        # if already running, nothing to do
        if self.uvicorn_proc and self.uvicorn_proc.poll() is None:
            QMessageBox.information(self, "Инфо", "Сервер уже запущен.")
            return

        if is_port_in_use(self.port):
            self.found_pids_on_port = find_pids_listening_on_port_windows(self.port) if sys.platform.startswith("win") else []
            msg = f"Порт {self.port} занят."
            if self.found_pids_on_port:
                msg += f"\nНайденные PID: {', '.join(map(str, self.found_pids_on_port))}."
                msg += "\nМожно принудительно завершить их (кнопка «Принудительно убить PID»)."
                self.kill_btn.setEnabled(True)
            else:
                msg += "\nЗакройте приложение, использующее порт, и попробуйте снова."
            QMessageBox.warning(self, "Порт занят", msg)
            return

        # Лог дочернего процесса (stdout/stderr)
        log_path = os.path.join(BASE_DIR, "uvicorn_child.log")
        try:
            # Автовывод (line buffered), в Windows buffering=1 может быть игнорирован — всё равно будет лог
            self._child_logf = open(log_path, "a", buffering=1, encoding="utf-8")
        except Exception:
            self._child_logf = None

        # В замороженном exe запускаем просто sys.executable с флагами.
        # В dev-режиме (не frozen) запускаем python interpreter с текущим скриптом.
        is_frozen = getattr(sys, "frozen", False)
        if is_frozen:
            cmd = [sys.executable, "--uvicorn-child", "--port", str(self.port)]
        else:
            # Запуск через интерпретатор: передаём путь к исходному скрипту
            cmd = [sys.executable, sys.argv[0], "--uvicorn-child", "--port", str(self.port)]

        startupinfo = None
        creationflags = 0
        if sys.platform.startswith("win"):
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                creationflags = subprocess.CREATE_NO_WINDOW
            except Exception:
                startupinfo = None
                creationflags = 0

        try:
            self.uvicorn_proc = subprocess.Popen(
                cmd,
                cwd=BASE_DIR,
                stdout=self._child_logf or subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                startupinfo=startupinfo,
                creationflags=creationflags
            )
        except FileNotFoundError as e:
            QMessageBox.critical(self, "Ошибка запуска", f"Не найден исполняемый файл: {e}")
            try:
                if self._child_logf:
                    self._child_logf.close()
                    self._child_logf = None
            except Exception:
                pass
            return
        except Exception as e:
            QMessageBox.critical(self, "Ошибка запуска", str(e))
            try:
                if self._child_logf:
                    self._child_logf.close()
                    self._child_logf = None
            except Exception:
                pass
            return

        # update UI
        self.status_label.setText("🟢 Сервер запущен")
        self.status_label.setStyleSheet("color: #4ade80; font-weight: 500;")
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.kill_btn.setEnabled(False)

        # open browser shortly after
        QTimer.singleShot(800, lambda: webbrowser.open(self.url))

    def stop_server(self):
        if self.uvicorn_proc:
            try:
                if self.uvicorn_proc.poll() is None:
                    self.uvicorn_proc.terminate()
                    try:
                        self.uvicorn_proc.wait(timeout=3)
                    except Exception:
                        self.uvicorn_proc.kill()
                        self.uvicorn_proc.wait(timeout=2)
            except Exception:
                pass
            finally:
                self.uvicorn_proc = None

        # Закрываем файл лога дочернего процесса, если он был открыт
        if self._child_logf:
            try:
                self._child_logf.close()
            except Exception:
                pass
            finally:
                self._child_logf = None

        self._set_stopped_ui()

    def _set_stopped_ui(self):
        self.status_label.setText("🔴 Сервер остановлен")
        self.status_label.setStyleSheet("color: #f87171; font-weight: 500;")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.kill_btn.setEnabled(False)

    def _check_server(self):
        if self.uvicorn_proc:
            if self.uvicorn_proc.poll() is None:
                return
            else:
                # дочерний процесс завершён — закроем лог и обновим UI
                self.uvicorn_proc = None
                if self._child_logf:
                    try:
                        self._child_logf.close()
                    except Exception:
                        pass
                    self._child_logf = None
                self._set_stopped_ui()
                return

        # если сервер запускали внутри процесса (не используется в этой реализации) —
        # можно проверить uvicorn_thread/uvicorn_server; сейчас считаем остановленным
        self._set_stopped_ui()

    def check_port(self):
        busy = is_port_in_use(self.port)
        if busy:
            msg = f"Порт {self.port} занят."
            if sys.platform.startswith("win"):
                pids = find_pids_listening_on_port_windows(self.port)
                if pids:
                    msg += f"\nНайдены PID: {', '.join(map(str,pids))}."
                    self.found_pids_on_port = pids
                    self.kill_btn.setEnabled(True)
            QMessageBox.information(self, "Проверка порта", msg)
        else:
            QMessageBox.information(self, "Проверка порта", f"Порт {self.port} свободен.")

    def kill_pid_prompt(self):
        if not sys.platform.startswith("win"):
            QMessageBox.warning(self, "Невозможно", "Функция принудительного убийства реализована только для Windows.")
            return
        if not self.found_pids_on_port:
            QMessageBox.information(self, "Нет PID", "Не найдено PID для данного порта.")
            return

        pids = ", ".join(map(str, self.found_pids_on_port))
        ok = QMessageBox.question(self, "Принудительно завершить", f"Завершить процессы: {pids}?")
        if ok != QMessageBox.StandardButton.Yes:
            return

        results = []
        for pid in self.found_pids_on_port:
            ok_kill, msg = force_kill_pid_windows(pid)
            results.append(msg)

        QMessageBox.information(self, "Результат", "\n".join(results))
        self.found_pids_on_port = []
        self.kill_btn.setEnabled(False)

    def closeEvent(self, event):
        try:
            # при закрытии GUI корректно остановим дочерний процесс, если он запущен
            if self.uvicorn_proc and self.uvicorn_proc.poll() is None:
                self.uvicorn_proc.terminate()
                try:
                    self.uvicorn_proc.wait(timeout=2)
                except Exception:
                    self.uvicorn_proc.kill()
                    self.uvicorn_proc.wait(timeout=1)
            # закроем лог, если открыт
            if self._child_logf:
                try:
                    self._child_logf.close()
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            event.accept()


# ---------------- Child-mode runner for uvicorn ----------------
def run_uvicorn_child(port: int = 8000, host: str = "127.0.0.1"):
    """
    Режим запускается, когда exe запущен с флагом --uvicorn-child.
    Попытка импортировать uvicorn и запустить server.run(app,...).
    Логирует stdout/stderr в BASE_DIR/uvicorn_child.log.
    """
    log_path = os.path.join(BASE_DIR, "uvicorn_child.log")
    try:
        import uvicorn
    except Exception as e:
        # Если import не проходит, пишем в лог и завершаем с кодом >0
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} ERROR: uvicorn import failed: {e}\n")
        except Exception:
            pass
        sys.exit(2)

    # Перенаправим stdout/stderr в файл (чтобы логи uvicorn были доступны)
    logf = None
    try:
        logf = open(log_path, "a", encoding="utf-8")
        sys.stdout = logf
        sys.stderr = logf
    except Exception:
        logf = None

    try:
        # Запускаем встроенный сервер uvicorn в этом процессе
        uvicorn.run(app, host=host, port=port, log_level="info")
    except Exception as ex:
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                import traceback
                f.write(time.strftime("%Y-%m-%d %H:%M:%S") + " — Exception in uvicorn.run:\n")
                f.write(traceback.format_exc() + "\n")
        except Exception:
            pass
        sys.exit(1)
    finally:
        try:
            if logf:
                logf.close()
        except Exception:
            pass


# ---------------- Main ----------------
if __name__ == "__main__":
    # child-mode: если exe запущен с --uvicorn-child, запускаем только uvicorn и выходим.
    if "--uvicorn-child" in sys.argv:
        parser = argparse.ArgumentParser()
        parser.add_argument("--port", type=int, default=8000)
        parser.add_argument("--host", default="127.0.0.1")
        args, _ = parser.parse_known_args()
        run_uvicorn_child(port=args.port, host=args.host)
        sys.exit(0)

    # обычный GUI путь
    try:
        app_qt = QApplication(sys.argv)
        dark = QPalette()
        dark.setColor(QPalette.Window, QColor("#0f172a"))
        dark.setColor(QPalette.WindowText, QColor("#e2e8f0"))
        dark.setColor(QPalette.Base, QColor("#1e293b"))
        dark.setColor(QPalette.Text, QColor("#e2e8f0"))
        dark.setColor(QPalette.Button, QColor("#1e293b"))
        dark.setColor(QPalette.ButtonText, QColor("#e2e8f0"))
        app_qt.setPalette(dark)
        app_qt.setStyle("Fusion")

        w = WebControl()
        w.show()
        sys.exit(app_qt.exec())
    except Exception as e:
        print("Ошибка GUI:", e)
        raise
