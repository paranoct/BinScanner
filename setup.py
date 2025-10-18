#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.py — универсальный установщик для BinScanner.
Собирается в .exe (рекомендуется через pyinstaller --onefile setup.py)
и выполняется пользователем первым.

Основные возможности:
 - опциональная установка Python на Windows (скачивает официальный инсталлятор с python.org)
 - создание виртуального окружения (venv) в папке установки или установка глобально
 - установка зависимостей из requirements.txt
 - копирование файлов проекта в папку установки
 - создание ярлыков (desktop / startmenu) под Windows
"""
from __future__ import annotations
import sys
import os
import shutil
import subprocess
import argparse
import tempfile
import urllib.request
import time
import stat

# --- Конфиг по-умолчанию ---
DEFAULT_APP_NAME = "BinScanner"
DEFAULT_PY_VER = "3.12.6"  # можно изменить при необходимости
THIS_DIR = os.path.abspath(os.path.dirname(__file__))

def is_windows() -> bool:
    return sys.platform.startswith("win")

def is_admin() -> bool:
    if not is_windows():
        # on *nix, root check
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def download_file(url: str, dest: str):
    print(f"[+] Скачиваю {url} -> {dest}")
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
            if total:
                pct = downloaded * 100 // total
                print(f"\r    {pct}% ({downloaded // 1024}KB / {total // 1024}KB)", end='', flush=True)
        elapsed = time.time() - start
        print(f"\n    Завершено за {elapsed:.1f}s")

def run_subprocess(cmd, check=True, **kwargs):
    print(f"[CMD] {' '.join(map(str, cmd))}")
    try:
        res = subprocess.run(cmd, check=check, **kwargs)
        return res
    except subprocess.CalledProcessError as e:
        print(f"[!] Команда завершилась с кодом {e.returncode}")
        raise

def install_system_python_windows(version: str = DEFAULT_PY_VER, silent: bool = True) -> bool:
    """
    Загрузит и поставит Python для всех пользователей (если нужно).
    Возвращает True если успешно (либо уже есть python в PATH).
    """
    # Если python уже есть, пропускаем
    try:
        out = subprocess.check_output(["python", "--version"], text=True, stderr=subprocess.STDOUT)
        print("[*] Python обнаружен:", out.strip())
        return True
    except Exception:
        pass

    if not is_windows():
        print("[!] Автоматическая установка Python доступна только на Windows.")
        return False

    if not is_admin():
        print("[!] Для установки системного Python требуются права администратора.")
        return False

    arch = "amd64" if sys.maxsize > 2**32 else ""
    filename = f"python-{version}-amd64.exe" if arch else f"python-{version}.exe"
    url = f"https://www.python.org/ftp/python/{version}/python-{version}-amd64.exe"
    tmp = tempfile.gettempdir()
    installer = os.path.join(tmp, filename)
    try:
        download_file(url, installer)
    except Exception as e:
        print("[!] Ошибка скачивания Python:", e)
        return False

    args = [installer, "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_pip=1"]
    if not silent:
        args = [installer]

    try:
        run_subprocess(args, check=True)
        print("[+] Python успешно установлен.")
        return True
    except Exception as e:
        print("[!] Установка Python завершилась ошибкой:", e)
        return False
    finally:
        try:
            if os.path.exists(installer):
                os.remove(installer)
        except Exception:
            pass

def make_venv(venv_path: str):
    print(f"[+] Создаю виртуальное окружение в: {venv_path}")
    import venv
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_path)
    # return path to python inside venv
    py = python_in_venv(venv_path)
    print(f"    venv python: {py}")
    return py

def python_in_venv(venv_path: str) -> str:
    if is_windows():
        return os.path.join(venv_path, "Scripts", "python.exe")
    else:
        return os.path.join(venv_path, "bin", "python")

def pip_install(requirements_path: str, python_exe: str = None):
    if not os.path.exists(requirements_path):
        print(f"[!] requirements.txt не найден: {requirements_path}")
        return False
    if python_exe is None:
        python_exe = shutil.which("python") or sys.executable
    cmd = [python_exe, "-m", "pip", "install", "--upgrade", "pip"]
    run_subprocess(cmd)
    cmd = [python_exe, "-m", "pip", "install", "-r", requirements_path]
    run_subprocess(cmd)
    return True

def copy_tree(src: str, dst: str):
    if not os.path.exists(src):
        print(f"    Пропускаю (не найдено): {src}")
        return
    if os.path.isdir(src):
        destdir = os.path.join(dst, os.path.basename(src))
        print(f"[+] Копирую {src} -> {destdir}")
        if os.path.exists(destdir):
            shutil.rmtree(destdir, ignore_errors=True)
        shutil.copytree(src, destdir)
    else:
        shutil.copy2(src, dst)

def copy_project_files(install_dir: str, extras: list[str] = None):
    extras = extras or ["dist", "assets", "templates", "static", "icon.ico", "requirements.txt"]
    print("[+] Копирование файлов проекта...")
    os.makedirs(install_dir, exist_ok=True)
    for name in extras:
        src = os.path.join(THIS_DIR, name)
        if os.path.exists(src):
            if os.path.isdir(src):
                dst = os.path.join(install_dir, os.path.basename(src))
                print(f"    копируем папку {src} -> {dst}")
                if os.path.exists(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
            else:
                dst = os.path.join(install_dir, os.path.basename(src))
                print(f"    копируем файл {src} -> {dst}")
                shutil.copy2(src, dst)
        else:
            print(f"    (не найден) {src}")

def create_shortcut_windows(target: str, link_path: str, args: str = "", icon: str | None = None):
    """
    Создаёт .lnk ярлык через Windows Script Host (VBScript), чтобы не требовать pywin32.
    """
    vbs = f'''
Set WshShell = WScript.CreateObject("WScript.Shell")
Set oShellLink = WshShell.CreateShortcut("{link_path}")
oShellLink.TargetPath = "{target}"
oShellLink.Arguments = "{args}"
oShellLink.WorkingDirectory = "{os.path.dirname(target)}"
'''
    if icon:
        vbs += f'oShellLink.IconLocation = "{icon}"\n'
    vbs += '''
oShellLink.Save
'''
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".vbs", mode="w", encoding="utf-8")
    tf.write(vbs)
    tf.flush()
    tf.close()
    try:
        run_subprocess(["cscript", "//nologo", tf.name], check=True)
        print(f"[+] Ярлык создан: {link_path}")
    finally:
        try:
            os.remove(tf.name)
        except Exception:
            pass

def ensure_executable(path: str):
    if not is_windows():
        st = os.stat(path)
        os.chmod(path, st.st_mode | stat.S_IEXEC)

def create_shortcuts(install_dir: str, app_name: str = DEFAULT_APP_NAME):
    print("[+] Создание ярлыков...")
    if not is_windows():
        print("    ярлыки создаются только на Windows.")
        return
    # Desktop
    desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
    if not desktop:
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    start_menu = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Start Menu", "Programs", app_name)
    os.makedirs(start_menu, exist_ok=True)

    gui_exe = os.path.join(install_dir, "gui.exe")
    web_exe = os.path.join(install_dir, "web_api.exe")
    icon = os.path.join(install_dir, "icon.ico")
    if not os.path.exists(icon):
        icon = None

    if os.path.exists(gui_exe):
        create_shortcut_windows(gui_exe, os.path.join(desktop, f"{app_name} GUI.lnk"), icon=icon)
        create_shortcut_windows(gui_exe, os.path.join(start_menu, f"{app_name} GUI.lnk"), icon=icon)
    if os.path.exists(web_exe):
        create_shortcut_windows(web_exe, os.path.join(desktop, f"{app_name} Web.lnk"), icon=icon)
        create_shortcut_windows(web_exe, os.path.join(start_menu, f"{app_name} Web.lnk"), icon=icon)

def write_uninstall_script(install_dir: str):
    uninst = os.path.join(install_dir, "uninstall.bat")
    content = f"""@echo off
echo Удаление {DEFAULT_APP_NAME}...
rd /s /q "{install_dir}" 2>nul
echo Готово.
pause
"""
    with open(uninst, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Установщик оставил {uninst} для ручного удаления.")

def main():
    parser = argparse.ArgumentParser(description="Installer for BinScanner")
    parser.add_argument("--install-dir", default=None, help="Папка установки (по умолчанию Program Files для Windows или ~/BinScanner)")
    parser.add_argument("--venv", action="store_true", help="Создать venv в папке установки и ставить туда зависимости")
    parser.add_argument("--no-shortcuts", action="store_true", help="Не создавать ярлыки")
    parser.add_argument("--silent", action="store_true", help="Режим без диалогов (все по умолчанию)")
    parser.add_argument("--install-python", action="store_true", help="Если Windows и python не найден — скачать и установить системно")
    parser.add_argument("--mode", choices=("gui","web","both"), default="both", help="Что устанавливать (gui/web/both)")
    args = parser.parse_args()

    # determine default install dir
    if args.install_dir:
        install_dir = os.path.abspath(args.install_dir)
    else:
        if is_windows():
            pf = os.environ.get("ProgramFiles", r"C:\Program Files")
            install_dir = os.path.join(pf, DEFAULT_APP_NAME)
        else:
            install_dir = os.path.join(os.path.expanduser("~"), DEFAULT_APP_NAME)

    print(f"[i] Установка в: {install_dir}")
    if is_windows():
        if "Program Files" in install_dir and not is_admin():
            print("[!] Вы устанавливаете в Program Files — нужны права администратора.")
            if args.silent:
                print("[!] Silent mode: прерываем.")
                return
            resp = input("Продолжить установку в Program Files без прав (вероятно не получится)? (y/N): ").strip().lower()
            if resp != "y":
                print("Прерываю.")
                return

    # Optionally install system Python on Windows
    if args.install_python and is_windows():
        ok = install_system_python_windows()
        if not ok:
            print("[!] Не удалось установить системный Python автоматически.")
            if not args.silent:
                cont = input("Продолжить без установки Python? (may fail) (y/N): ").strip().lower()
                if cont != "y":
                    return

    # copy files
    copy_project_files(install_dir, extras=["dist", "assets", "templates", "static", "icon.ico", "requirements.txt"])

    # set up venv or system pip
    req_path = os.path.join(install_dir, "requirements.txt")
    if args.venv:
        venv_path = os.path.join(install_dir, "venv")
        python_exe = make_venv(venv_path)
        # ensure pip upgraded & install
        pip_install(req_path, python_exe)
    else:
        # attempt to use system python
        print("[+] Установка зависимостей в системный Python (или тот, который в PATH)")
        python_exe = shutil.which("python") or sys.executable
        try:
            pip_install(req_path, python_exe)
        except Exception as e:
            print("[!] Установка через системный Python не удалась:", e)
            if not args.silent:
                if input("Попробовать создать venv и установить туда? (y/N): ").strip().lower() == "y":
                    venv_path = os.path.join(install_dir, "venv")
                    python_exe = make_venv(venv_path)
                    pip_install(req_path, python_exe)
                else:
                    print("Остаётся без установленный зависимости. Вы сможете запустить dist/*.exe напрямую если они автономные.")

    # make executables runnable on *nix
    if not is_windows():
        for exe in ("gui", "web_api"):
            p = os.path.join(install_dir, exe)
            if os.path.exists(p):
                ensure_executable(p)

    # shortcuts & uninstall
    if is_windows() and not args.no_shortcuts:
        create_shortcuts(install_dir, DEFAULT_APP_NAME)
    write_uninstall_script(install_dir)

    print("\n[✓] Установка завершена.")
    print(f"    Папка установки: {install_dir}")
    if is_windows():
        print("    Ярлыки должны появиться на рабочем столе и в меню Пуск (если запускали с правами).")
    print("    Для запуска GUI: запустите gui.exe из папки установки.")
    print("    Для запуска Web: запустите web_api.exe (если хотите — использовать WebControl GUI).")

if __name__ == "__main__":
    main()
