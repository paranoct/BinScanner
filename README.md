# BinScanner

BinScanner — инструмент для разработчиков, который помогает быстро оценить **уязвимость/эксплуатируемость PE-приложений** (`.exe/.dll`) на Windows.

Это **не антивирус**: сканер фокусируется на защитных механизмах (mitigations), ошибках безопасного кодирования и признаках, которые повышают риск эксплуатации.

## Возможности

- Статический анализ PE: архитектура, точка входа, mitigations (ASLR/DEP/CFG/HighEntropyVA/CET,/GS, SafeSEH/NO_SEH для x86), RWX-секции, небезопасные CRT/WinAPI паттерны.
- Динамический анализ (опционально): реальный запуск с таймаутом, детект падений, crash‑probe переполнений (argv/stdin).
- Отчёт: цветной CLI‑отчёт + HTML‑отчёт.
- Web UI (FastAPI) + Desktop UI (PySide6).

## Установка

Требуется Python 3.10+ (Windows).

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Опционально (глубокие проверки .NET):

```powershell
pip install -r requirements-deep.txt
```

## Запуск

### Web UI

```powershell
python -m binscanner.webapp
```

Откройте `http://127.0.0.1:8000`.

### Desktop UI (PySide6)

```powershell
python -m binscanner.ui_pyside
```

### CLI

```powershell
python -m binscanner.scanner path\to\sample.exe --no-dynamic
python -m binscanner.scanner path\to\sample.exe --execute --timeout 10
python -m binscanner.scanner path\to\sample.exe --execute --overflow-probe
```

## Оценка

`Оценка защищённости` — это шкала **0..100**, где **100 = лучше**.
Чем меньше mitigations и чем больше проблем — тем ниже оценка и выше уровень уязвимости.

## Важно

`Реальный запуск` и `crash-probe` потенциально **опасны** — используйте только в изолированной среде (VM/песочница).

### Запуск от администратора (UAC)

Desktop (`binscanner.ui_pyside`) и Web (`binscanner.webapp`) при старте на Windows автоматически запрашивают повышение прав через UAC.
Чтобы отключить автоповышение: `BINSCANNER_SKIP_UAC=1`.

## Установщик (Windows)

Установщик собирается через Inno Setup 6+ и устанавливает готовую сборку `BinScanner.exe` (PyInstaller):

- копирует файлы из `build\\pyinstaller\\BinScanner\\` в `{app}`;
- по выбору создаёт ярлыки в меню «Пуск» и/или на рабочем столе;
- создаёт `{app}\uninstall.exe` (копия штатного деинсталлятора Inno Setup).

Сборка (скрипт сам сначала соберёт EXE, затем установщик):

```powershell
powershell -ExecutionPolicy Bypass -File installer\build_installer.ps1
```

Готовый установщик появится в `dist\BinScanner_Setup.exe`.

## База уязвимых зависимостей (CVE)

По умолчанию используется небольшая встроенная база (демо). Можно подключить свою JSON‑базу:

- Создайте файл, например `vuln_db.json`
- Укажите путь через переменную окружения:

```powershell
$env:BINSCANNER_VULN_DB="D:\path\to\vuln_db.json"
```

Формат:

```json
{
  "zlib1.dll": [
    {"cve":"CVE-2018-25032", "introduced":"0", "fixed":"1.2.12", "severity":"high", "note":"Обновите до 1.2.12+"}
  ]
}
```
