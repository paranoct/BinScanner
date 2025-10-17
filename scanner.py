# scanner.py
"""
Расширенный статический сканер PE (Windows .exe/.dll).
Зависимости: pefile

Выход: список отчётов в формате:
{
  "path": "...",
  "ok": bool,
  "summary": {"high":n, "medium":m, "low":l, "info":k},
  "issues": [
    {
      "severity": "High"|"Medium"|"Low"|"Info",
      "title": "Short title",
      "description": "Что это значит",
      "evidence": ["строка/импорт/section ..."],
      "recommendation": "Что сделать",
      "location": "imports/.rdata/.text/section X"
    }, ...
  ],
  "metadata": {... imports, security flags, sections ...}
}
"""
from __future__ import annotations
import pefile
import os
import math
import re
import json
from typing import List, Dict, Any

# ---- Конфигурация правил ----
DANGEROUS_FUNCS = {
    # classic unsafe C functions
    'strcpy','strcat','gets','scanf','sscanf','sprintf','vsprintf','strncpy','strncat',
    'memcpy','memmove','strncpy_s','sprintf_s','wscanf','swscanf'
}
FORMAT_FUNCS = {'printf','fprintf','vprintf','snprintf','vsnprintf','sprintf','vsprintf'}
EXEC_FUNCS = {'system','WinExec','CreateProcessA','CreateProcessW','ShellExecuteA','ShellExecuteW'}
NETWORK_FUNCS = {'socket','connect','send','recv','InternetOpenUrlA','InternetOpenA','URLDownloadToFileA'}
CRYPTO_WEAK = {'MD5','md5','SHA1','sha1','RC4','DES'}  # heuristic via strings
DEBUG_MARKERS = ('.pdb', 'MSFT', 'CodeView')
PACKER_MARKERS = ('UPX', 'ASPack', 'Themida', 'PECompact', '.upx')
HARD_SECRET_REGEXES = [
    re.compile(r'AKIA[0-9A-Z]{16}'),  # aws access key id
    re.compile(r'AIza[0-9A-Za-z-_]{35}'),  # google api key heuristic
    re.compile(r'-----BEGIN (RSA|PRIVATE) KEY-----'),  # private key
    re.compile(r'(?i)(password|passwd|pwd)[\s:=]{1,4}["\']?[\w\-\./@]{6,100}'),  # possible password leakage
    re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+')  # JWT-like
]

SEC_FLAGS = {
    'DYNAMIC_BASE': 0x40,   # ASLR
    'NX_COMPAT': 0x0100,    # NX / DEP
    'NO_SEH': 0x0400,       # No SEH
    'GUARD_CF': 0x4000      # Control Flow Guard (CFG)
}

# ---- Утилиты ----
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    ln = len(data)
    for v in freq.values():
        p = v / ln
        ent -= p * math.log2(p)
    return ent

def safe_decode(b: bytes) -> str:
    for enc in ('utf-8','latin-1','cp1251','ascii'):
        try:
            return b.decode(enc, errors='ignore')
        except Exception:
            continue
    return b.decode('latin-1', errors='ignore')

# ---- Правила обнаружения ----
def find_imports(pe: pefile.PE) -> List[str]:
    imports = []
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    name = None
                    if imp.name:
                        name = imp.name.decode(errors='ignore')
                    else:
                        name = f'ord{imp.ordinal}'
                    imports.append(name)
    except Exception:
        pass
    return imports

def find_strings(pe: pefile.PE, min_len=4) -> List[str]:
    # Получим данные всего файла (быстро) и вытащим ASCII/Unicode строки
    raw = pe.__data__  # полный бинарник как bytes
    res = set()
    # ASCII-like strings
    ascii_re = re.compile(br'[\x20-\x7E]{%d,}' % min_len)
    for m in ascii_re.finditer(raw):
        try:
            s = m.group().decode('ascii', errors='ignore')
            res.add(s)
        except Exception:
            continue
    # simple UTF-16-LE
    u16_re = re.compile((br'(?:[\x20-\x7E]\x00){%d,}' % min_len))
    for m in u16_re.finditer(raw):
        try:
            s = m.group().decode('utf-16le', errors='ignore')
            res.add(s)
        except Exception:
            continue
    return sorted(res)

def analyze_sections(pe: pefile.PE) -> List[Dict[str,Any]]:
    sections = []
    for sec in getattr(pe, 'sections', []):
        name = safe_decode(sec.Name).rstrip('\x00')
        data = sec.get_data() or b''
        ent = entropy(data)
        sections.append({
            'name': name,
            'vaddr': hex(sec.VirtualAddress),
            'size': len(data),
            'entropy': round(ent, 3)
        })
    return sections

# ---- Основной анализ одного PE ----
def scan_pe(path: str) -> Dict[str,Any]:
    out = {
        'path': path,
        'ok': True,
        'summary': {'High':0,'Medium':0,'Low':0,'Info':0},
        'issues': [],
        'metadata': {}
    }
    if not os.path.isfile(path):
        out['ok'] = False
        out['issues'].append({
            'severity':'High',
            'title':'File not found',
            'description':'Файл не найден по указанному пути.',
            'evidence':[path],
            'recommendation':'Проверьте путь к файлу.',
            'location':'filesystem'
        })
        out['summary']['High'] += 1
        return out

    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
        ])
    except Exception as e:
        out['ok'] = False
        out['issues'].append({
            'severity':'High',
            'title':'PE parse error',
            'description':'Не удалось распарсить PE-файл: ' + str(e),
            'evidence':[],
            'recommendation':'Файл может быть повреждён или защищён упаковщиком. Попробуйте открыть в дизассемблере/Hex-редакторе.',
            'location':'parsing'
        })
        out['summary']['High'] += 1
        return out

    # metadata
    imports = find_imports(pe)
    strings = find_strings(pe, min_len=6)
    secs = analyze_sections(pe)
    dllchars = getattr(pe, 'OPTIONAL_HEADER', None) and getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0) or 0

    out['metadata'] = {
        'imports': imports,
        'num_imports': len(imports),
        'sections': secs,
        'dll_characteristics': dllchars,
    }

    # ---- security flags checks ----
    sec_map = {}
    for k,flag in SEC_FLAGS.items():
        sec_map[k] = bool(dllchars & flag)
    out['metadata']['security'] = sec_map

    if not sec_map['DYNAMIC_BASE']:
        out['ok'] = False
        issue = {
            'severity':'Medium',
            'title':'ASLR (Dynamic Base) отключён',
            'description':'ASLR затрудняет эксплуатацию уязвимостей; рекомендуется включать.',
            'evidence':['DllCharacteristics missing DYNAMIC_BASE'],
            'recommendation':'Включить /DYNAMICBASE при линковке (MSVC) или соответствующие опции компоновки.',
            'location':'optional_header'
        }
        out['issues'].append(issue); out['summary']['Medium']+=1

    if not sec_map['NX_COMPAT']:
        out['ok'] = False
        issue = {
            'severity':'Medium',
            'title':'NX/DEP отключён',
            'description':'DEP/NX предотвращает исполнение данных в стеке/куче.',
            'evidence':['DllCharacteristics missing NX_COMPAT'],
            'recommendation':'Включить NX/DEP (NXCOMPAT).',
            'location':'optional_header'
        }
        out['issues'].append(issue); out['summary']['Medium']+=1

    if not sec_map['GUARD_CF']:
        # CFG не обязателен, но это современный защитный механизм
        out['issues'].append({
            'severity':'Low',
            'title':'Control Flow Guard (CFG) не включён',
            'description':'CFG усложняет многие классы эксплойтов (инструментальное средство защиты).',
            'evidence':['DllCharacteristics missing GUARD_CF'],
            'recommendation':'Включить CFG при сборке (если поддерживается).',
            'location':'optional_header'
        })
        out['summary']['Low'] += 1

    if not sec_map['NO_SEH']:
        # absence of NO_SEH means SEH present, on x86 could be risky
        out['issues'].append({
            'severity':'Info',
            'title':'SEH not disabled',
            'description':'Возможно использование SEH; проверьте необходимость и защиту.',
            'evidence':['DllCharacteristics NO_SEH flag not set'],
            'recommendation':'Если используется SEH, рассмотрите дополнительные меры защиты.',
            'location':'optional_header'
        })
        out['summary']['Info'] += 1

    # ---- imports based rules ----
    dangerous_used = sorted([f for f in imports if f in DANGEROUS_FUNCS])
    if dangerous_used:
        out['ok'] = False
        out['issues'].append({
            'severity':'High',
            'title':'Используются небезопасные C-функции',
            'description':'Найден импорт небезопасных строковых/буферных функций, что повышает риск переполнений.',
            'evidence':dangerous_used,
            'recommendation':'Заменить на безопасные аналоги (strncpy_s, snprintf) и добавить проверки длины.',
            'location':'imports'
        })
        out['summary']['High'] += 1

    format_used = sorted([f for f in imports if f in FORMAT_FUNCS])
    if format_used:
        out['issues'].append({
            'severity':'Medium',
            'title':'Форматированные функции (возможные format-string уязвимости)',
            'description':'Функции форматирования могут быть источником format-string уязвимостей при небезопасном использовании.',
            'evidence':format_used,
            'recommendation':'Проверить использование и экранировать/валидировать пользовательский ввод при передаче в форматтеры.',
            'location':'imports'
        })
        out['summary']['Medium'] += 1

    exec_used = sorted([f for f in imports if f in EXEC_FUNCS])
    if exec_used:
        out['ok'] = False
        out['issues'].append({
            'severity':'High',
            'title':'Вызов функций запуска процессов/команд',
            'description':'Использование system/WinExec/CreateProcess/ShellExecute может быть рискованным при передаче данных от пользователя.',
            'evidence':exec_used,
            'recommendation':'Проверять/валидировать все аргументы, использовать явные API с контролем прав.',
            'location':'imports'
        })
        out['summary']['High'] += 1

    net_used = sorted([f for f in imports if f in NETWORK_FUNCS])
    if net_used:
        out['issues'].append({
            'severity':'Medium',
            'title':'Сетевые функции присутствуют',
            'description':'Приложение устанавливает сетевые соединения — проверьте шифрование/аутентификацию и возможные эксплойты (hardcoded endpoints).',
            'evidence':net_used,
            'recommendation':'Проверить реализацию сетевого взаимодействия и хранение учётных данных.',
            'location':'imports'
        })
        out['summary']['Medium'] += 1

    # ---- strings / secrets / weak crypto / debug / packer heuristics ----
    # hardcoded secrets
    secrets_found = []
    for rx in HARD_SECRET_REGEXES:
        for s in strings:
            if rx.search(s):
                snippet = s.strip()
                if len(snippet) > 200:
                    snippet = snippet[:200] + '...'
                secrets_found.append(snippet)
    if secrets_found:
        out['ok'] = False
        out['issues'].append({
            'severity':'High',
            'title':'Возможные захардкоженные секреты',
            'description':'Найдены строки, похожие на ключи/пароли/приватные ключи — это серьёзный риск утечки.',
            'evidence':secrets_found[:10],
            'recommendation':'Удалить секреты из бинарника, использовать секрет-менеджер, вращать ключи и отозвать скомпрометированные.',
            'location':'rdata/.rdata/.data'
        })
        out['summary']['High'] += 1

    # weak crypto mention
    crypto_found = [s for s in strings if any(tok in s for tok in CRYPTO_WEAK)]
    if crypto_found:
        out['issues'].append({
            'severity':'Medium',
            'title':'Упоминание слабых криптопримитивов',
            'description':'Найдены упоминания MD5/SHA1/RC4/..., возможно используется устаревшая криптография.',
            'evidence':crypto_found[:10],
            'recommendation':'Перейти на современные алгоритмы (SHA256/AEAD), проверить использование криптографии экспертами.',
            'location':'strings'
        })
        out['summary']['Medium'] += 1

    # debug/pdb leaks
    pdb_hits = [s for s in strings if '.pdb' in s.lower() or s.lower().endswith('.pdb')]
    if pdb_hits:
        out['issues'].append({
            'severity':'Low',
            'title':'PDB/символы отладки обнаружены',
            'description':'Найден путь к файлу символов отладки (PDB) — потенциальный источник утечки внутренней структуры/информации.',
            'evidence':pdb_hits[:5],
            'recommendation':'Не включать пути к PDB в релизную сборку, strip/dontship symbols.',
            'location':'debug directory / strings'
        })
        out['summary']['Low'] += 1

    # packer / high entropy sections
    packer_hits = []
    for sec in out['metadata']['sections']:
        if any(pm.lower() in sec['name'].lower() for pm in PACKER_MARKERS) or sec['entropy'] > 7.5:
            packer_hits.append(sec['name'])
    if packer_hits:
        out['issues'].append({
            'severity':'Medium',
            'title':'Потенциальная упаковка / обфускация',
            'description':'Высокая энтропия секции или признаки UPX/других упаковщиков — статический анализ может быть затруднён.',
            'evidence':packer_hits,
            'recommendation':'Рассмотреть распаковку/динамический анализ в изолированной среде для дальнейшей проверки.',
            'location':'sections'
        })
        out['summary']['Medium'] += 1

    # general heuristic: too few imports (statically linked) may hide behavior
    if out['metadata']['num_imports'] < 5:
        out['issues'].append({
            'severity':'Info',
            'title':'Небольшое число импортов (возможно статическая линковка)',
            'description':'Малое количество импортов может означать статическую линковку/обфускацию — это усложняет анализ.',
            'evidence':[f'num_imports={out["metadata"]["num_imports"]}'],
            'recommendation':'Проверить файл в дизассемблере или динамически.',
            'location':'imports'
        })
        out['summary']['Info'] += 1

    # final ok determination
    if any(out['summary'][lvl] > 0 for lvl in ('High','Medium')):
        out['ok'] = False

    return out

# ---- Функция для сканирования папки/списка ----
def scan_files(paths: List[str]) -> List[Dict[str,Any]]:
    results = []
    for p in paths:
        if os.path.isdir(p):
            for root,_,files in os.walk(p):
                for f in files:
                    if f.lower().endswith(('.exe','.dll')):
                        results.append(scan_pe(os.path.join(root,f)))
        else:
            results.append(scan_pe(p))
    return results

def format_report_html(report: dict) -> str:
    """
    Форматирование отчёта в HTML для QTextEdit
    """
    html = []
    # Имя и путь файла жирным
    html.append(f"<b>=== {report['path']} ===</b><br>")
    
    if report.get('ok', True):
        html.append("<span style='color:green;'>Статус: не найдены критические проблемы (статический анализ).</span><br>")
    else:
        html.append("<span style='color:red;'>Статус: обнаружены потенциальные проблемы.</span><br>")

    html.append("<b>Сводка по уровням:</b><br>")
    for lvl in ('High','Medium','Low','Info'):
        html.append(f"{lvl}: {report['summary'].get(lvl,0)}<br>")

    html.append("<br>")
    if not report['issues']:
        html.append("Проблем не найдено.<br>")
    else:
        for i, iss in enumerate(report['issues'],1):
            html.append(f"<b>{i}. [{iss['severity']}] {iss['title']}</b><br>")
            html.append(f"<i>Описание:</i> {iss['description']}<br>")
            if iss.get('evidence'):
                ev_short = iss['evidence'][:5] if isinstance(iss['evidence'], list) else [iss['evidence']]
                html.append("<i>Доказательства:</i><br>")
                for e in ev_short:
                    s = str(e)
                    if len(s) > 200: s = s[:200] + "..."
                    html.append(f"&nbsp;&nbsp;- {s}<br>")
            if iss.get('recommendation'):
                html.append(f"<i>Рекомендация:</i> {iss['recommendation']}<br>")
            html.append("<br>")

    return "".join(html)

# ---- Удобный форматтер для человека (plain text) ----
def format_report_human(report: Dict[str,Any]) -> str:
    lines = []
    lines.append(f"=== {report['path']} ===")
    if report.get('ok', True):
        lines.append("Статус: Не найдены критические проблемы (статический анализ).")
    else:
        lines.append("Статус: Обнаружены потенциальные проблемы.")
    lines.append("Сводка по уровням:")
    for lvl in ('High','Medium','Low','Info'):
        lines.append(f"  {lvl}: {report['summary'].get(lvl,0)}")
    lines.append("")
    if not report['issues']:
        lines.append("Проблем не найдено.")
    else:
        for i,iss in enumerate(report['issues'],1):
            lines.append(f"{i}. [{iss['severity']}] {iss['title']}")
            lines.append(f"   Описание: {iss['description']}")
            if iss.get('evidence'):
                ev = iss['evidence']
                # короткие доказательства
                ev_short = (ev[:5] if isinstance(ev,list) else [ev])
                lines.append("   Доказательства: ")
                for e in ev_short:
                    # убираем длинные строки
                    s = str(e)
                    if len(s) > 200:
                        s = s[:200] + "..."
                    lines.append(f"     - {s}")
            if iss.get('recommendation'):
                lines.append(f"   Рекомендация: {iss['recommendation']}")
            lines.append("")
    # metadata кратко
    meta = report.get('metadata',{})
    lines.append("Мета: imports count = " + str(meta.get('num_imports','?')))
    # sections top entropies
    secs = meta.get('sections',[])
    if secs:
        lines.append("Top sections (name / size / entropy):")
        for s in sorted(secs, key=lambda x: -x.get('entropy',0))[:6]:
            lines.append(f"  - {s['name']} / {s['size']} / entropy={s['entropy']}")
    return "\n".join(lines)

# ---- CLI для быстрого теста ----
if __name__ == '__main__':
    import sys
    paths = sys.argv[1:] if len(sys.argv)>1 else ['.']
    res = scan_files(paths)
    # по умолчанию печатаем человеческий формат для каждой позиции
    for r in res:
        print(format_report_human(r))
        print("\n" + ("-"*80) + "\n")
