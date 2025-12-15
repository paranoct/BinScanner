# 🧩 BinScanner — статический сканер PE-файлов (.exe, .dll)

BinScanner — это инструмент для **статического анализа исполняемых файлов Windows**.  
Проект включает два интерфейса:
- **GUI-версия** (для локальной работы);
- **Web-версия** (через браузер, с локальным сервером).

---

## 🚀 Установка

> ⚠️ **Важно:** Устанавливайте программу **только через `setup.exe`**.  
> Не запускайте Python-скрипты вручную — всё необходимое уже собрано и настроено автоматически.

### Шаги установки:
1. Найдите файл `setup.exe` в корне проекта.  
2. Дважды щёлкните по нему — начнётся установка.
3. Дождитесь окончания установки (может занять несколько минут).
4. После завершения в системе появятся ярлыки и установленная программа **BinScanner**.

---

## 📂 Где находятся исполняемые файлы

После установки или сборки все `.exe` файлы располагаются в папке: **dist/**


Там вы найдёте:
- `gui.exe` — графическая версия сканера;
- `web_api.exe` — локальный веб-интерфейс для сканирования.

Вы также можете:
- найти их через **поиск Windows** (нажмите `Win` и введите `gui` или `web_api`);
- создать ярлык на рабочем столе (правый клик → «Создать ярлык»).

---

## 💻 Как пользоваться

1. Откройте папку `dist` или найдите `BinScanner` через поиск Windows.  
2. **Запустите `gui.exe`** — откроется основное окно сканера.
3. Добавьте файл или папку для проверки и нажмите **«Сканировать»**.
4. Результаты анализа появятся в правой панели (HTML-отчёт).

Если хотите использовать веб-интерфейс:
1. Запустите `web_api.exe`.  
2. Нажмите кнопку **«Запустить сервер»**.  
3. Откройте браузер по адресу `http://127.0.0.1:8000`.

---

## 🧠 Возможности

- Анализ PE-заголовков и секций (`.text`, `.data`, `.rdata` и др.).  
- Определение подозрительных признаков в бинарных файлах.  
- Поддержка как `.exe`, так и `.dll`.  
- Подробный HTML-отчёт с форматированием и цветовой разметкой.  
- Веб-интерфейс с загрузкой файлов и прогресс-баром.  
- Встроенный лог (`uvicorn_child.log`) для веб-версии.  

---

## ⚙️ Системные требования

- **Windows 10 / 11** (x64)
- **Python требуется** — установщик установит его, если его нет. Или же установить сами.
- **Минимальная версия Python:** 3.10
- **Рекомендуемая версия (указана в установщике):** 3.12.6
- **Минимум 100 МБ свободного места** на диске.
- При запуске может потребоваться разрешение **SmartScreen** *(нажмите «Подробнее» → «Всё равно выполнить»)*.

---

## 🧩 Иконка и ярлык

После установки иконка `BinScanner` появится:
- в панели задач при запуске;
- в списке установленных программ;
- в ярлыке на рабочем столе (создаётся автоматически).

Если иконка не отображается:
- кликните правой кнопкой по ярлыку → Свойства → Сменить значок → выберите `icon.ico` в папке программы.

---

## 🛠️ Логи и отчёты

- GUI-приложение выводит результат прямо в окне.
- WebControl создаёт файл `uvicorn_child.log` для журнала сервера.
- Отчёты можно сохранять вручную в HTML-формате.

---

## 🔒 Безопасность

BinScanner выполняет **только статический анализ**.  
Он **не запускает** проверяемые файлы и не изменяет их.  
Рекомендуется использовать программу в безопасной среде для анализа подозрительных бинарников.

# Модуль динамического анализа BinScanner

## Обзор

Модуль `dynamic_analysis.py` добавляет в BinScanner возможность динамического анализа PE файлов с фокусом на практическую полезность для разработчика:

- **Воспроизводимые доказательства** - каждый найденный дефект включает POC (Proof of Concept) файл
- **Конкретные рекомендации** - детальные шаги по исправлению проблем
- **Job-based API** - асинхронное выполнение с опросом статуса
- **Легкий фаззер** - мутационный фаззинг для поиска уязвимостей

## Использование

### Базовое использование (интегрировано в scanner.py)

```python
from scanner import scan_pe_with_dynamic

# Запуск статического + динамического анализа (синхронно)
report = scan_pe_with_dynamic(
    path='program.exe',
    dynamic_enabled=True,
    dynamic_timeout=30,  # секунд на один запуск
    dynamic_max_iterations=100,  # количество итераций фаззера
    wait_for_dynamic=True  # ждать завершения
)

# report содержит объединённые результаты статического и динамического анализа
```

### Асинхронное использование (job-based API)

```python
from dynamic_analysis import (
    create_dynamic_job,
    start_analysis,
    get_job_status,
    generate_developer_report,
    stop_job,
    cleanup_job
)

# 1. Создать задачу
job_id = create_dynamic_job(
    pe_path='program.exe',
    timeout=30,
    max_iterations=100,
    fuzzing_enabled=True
)

# 2. Запустить анализ (в фоне)
start_analysis(job_id)

# 3. Опрашивать статус
import time
while True:
    status = get_job_status(job_id)
    print(f"Progress: {status['progress']}%, Status: {status['status']}")
    if status['status'] in ('done', 'error'):
        break
    time.sleep(1)

# 4. Получить отчёт
if status['status'] == 'done':
    report = generate_developer_report(job_id)
    print(f"Found {len(report['findings'])} issues")
    print(f"POC files: {len(report['poc_files'])}")
    
    # 5. Очистить ресурсы (опционально)
    cleanup_job(job_id, keep_artifacts=False)
```

## Структура отчёта

Отчёт разработчика содержит:

```python
{
    'job_id': '...',
    'pe_path': 'program.exe',
    'status': 'done',
    'summary': {
        'High': 2,
        'Medium': 1,
        'Low': 0,
        'Info': 0
    },
    'findings': [
        {
            'severity': 'High',
            'title': 'Crash detected during fuzzing',
            'description': 'Program crashed with input of size 256 bytes',
            'evidence': ['returncode: -1', 'input_size: 256', 'poc_file: poc_0042.bin'],
            'recommendation': 'Fix buffer overflow or input validation issues...',
            'location': 'runtime',
            'poc': 'poc_0042.bin',  # имя файла в artifacts_dir
            'reproduction': 'Run: program.exe < poc_0042.bin'
        },
        ...
    ],
    'poc_files': [
        {
            'path': '/tmp/.../artifacts/poc_0042.bin',
            'size': 256,
            'hash': 'abc123...',
            'iteration': 42
        },
        ...
    ],
    'action_items': [
        'ПРИОРИТЕТ: Исследовать High-уровневые находки немедленно.',
        'Проверить 2 POC файлов в /tmp/.../artifacts',
        ...
    ],
    'bug_report_template': {
        'title': 'Security issue: Crash detected during fuzzing',
        'priority': 'High',
        'description': '...',
        'steps_to_reproduce': [...],
        'recommendations': '...',
        'attachments': ['poc_0042.bin']
    },
    'artifacts_dir': '/tmp/.../artifacts'
}
```

## Конфигурация

### Параметры по умолчанию

```python
DEFAULT_TIMEOUT = 30  # секунд на один запуск программы
DEFAULT_MAX_ITERATIONS = 100  # максимальное количество итераций фаззера
DEFAULT_MAX_FUZZ_TIME = 120  # максимум времени фаззинга (секунды)
DEFAULT_SEED_SIZE = 1024  # размер начальных семян
```

### Рекомендации по настройке

- **Для быстрого сканирования**: `timeout=10`, `max_iterations=50`
- **Для глубокого анализа**: `timeout=60`, `max_iterations=500`
- **Для CI/CD**: `timeout=30`, `max_iterations=100` (баланс скорости и покрытия)

## Что обнаруживает модуль

1. **Краши** - аварийное завершение программы при определённых входных данных
2. **Таймауты** - зависания или бесконечные циклы
3. **Высокое потребление памяти** - потенциальные утечки памяти
4. **Аномальное поведение** - отклонения от ожидаемого поведения

## Безопасность

⚠️ **ВАЖНО**: Динамический анализ запускает реальные исполняемые файлы!

- Модуль НЕ требует виртуальной машины по умолчанию
- Запускайте анализ только на **непродуктивных машинах**
- Все артефакты сохраняются в временной директории
- Используйте `cleanup_job()` для удаления артефактов после анализа

## Зависимости

### Обязательные
- Стандартная библиотека Python (subprocess, threading, tempfile, и т.д.)

### Опциональные (для расширенного мониторинга)
- `psutil` - для мониторинга потребления памяти

```bash
pip install psutil  # опционально
```

## Интеграция в CI/CD

Пример интеграции в пайплайн:

```python
from scanner import scan_pe_with_dynamic

def check_build(binary_path):
    report = scan_pe_with_dynamic(
        path=binary_path,
        dynamic_enabled=True,
        dynamic_timeout=30,
        dynamic_max_iterations=100,
        wait_for_dynamic=True
    )
    
    # Блокировать релиз при High-находках
    if report['summary'].get('High', 0) > 0:
        print(f"❌ Build failed: {report['summary']['High']} High severity issues found")
        return False
    
    print("✅ Build passed")
    return True
```

## Примеры использования

### Пример 1: Быстрое сканирование

```python
from scanner import scan_pe_with_dynamic

report = scan_pe_with_dynamic(
    'myapp.exe',
    dynamic_enabled=True,
    dynamic_timeout=10,
    dynamic_max_iterations=50,
    wait_for_dynamic=True
)

for finding in report.get('findings', []):
    if finding['severity'] == 'High':
        print(f"⚠️  {finding['title']}")
        print(f"   POC: {finding.get('poc', 'N/A')}")
```

### Пример 2: Асинхронное сканирование с GUI

```python
from dynamic_analysis import create_dynamic_job, start_analysis, get_job_status

job_id = create_dynamic_job('myapp.exe', timeout=60, max_iterations=200)
start_analysis(job_id)

# В отдельном потоке/GUI обновлять прогресс
def update_progress():
    status = get_job_status(job_id)
    progress_bar.setValue(status['progress'])
    if status['status'] == 'done':
        show_results(generate_developer_report(job_id))
```

## Ограничения

1. **Безопасность**: Запускает реальные исполняемые файлы - используйте только в изолированной среде
2. **Производительность**: Фаззинг может занимать много времени для больших программ
3. **Покрытие**: Легкий фаззер не покрывает все возможные сценарии (в отличие от полного символьного исполнения)
4. **Платформа**: В основном тестировалось на Windows; Linux/macOS требуют адаптации

## Дополнительные возможности (будущие улучшения)

- Сетевой мониторинг (перехват сетевых пакетов)
- API hooking (детекция опасных вызовов)
- Полный taint-tracking
- Интеграция с символами отладки (.pdb)
- Экспорт в SARIF для интеграции с IDE
