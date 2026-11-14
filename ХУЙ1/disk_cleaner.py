# -*- coding: utf-8 -*-
"""
Disk Cleaner - утилита для автоматической очистки дисков.

Два режима:
  GUI:  python disk_cleaner.py
  CLI:  python disk_cleaner.py --config rules.json [--dry-run | --execute [--yes]]

Пользователь сам выбирает пути и правила; ничего не удаляется без подтверждения
(или без явного --execute в CLI).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import time
import threading
import subprocess
import queue
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional, Any

# --- tkinter optional (в стандартной поставке Python есть почти всегда) ---
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    TK_AVAILABLE = True
except Exception:  # pragma: no cover
    TK_AVAILABLE = False

# --- send2trash optional: удаление в корзину ---
try:
    from send2trash import send2trash  # type: ignore
    TRASH_AVAILABLE = True
except Exception:
    TRASH_AVAILABLE = False

# --- встроенный антивирус (одноимённый модуль рядом со скриптом) ---
try:
    import antivirus as av
    AV_AVAILABLE = True
except Exception:
    av = None
    AV_AVAILABLE = False


# ---------------------------------------------------------------------------
# Защита системных зон
# ---------------------------------------------------------------------------

# Пути, которые по умолчанию нельзя удалять, пока не включён allow_protected.
PROTECTED_PREFIXES_WIN = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
    os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"),
]

PROTECTED_PREFIXES_POSIX = [
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
    "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var",
]


def protected_prefixes() -> list[str]:
    if os.name == "nt":
        return [os.path.normcase(p) for p in PROTECTED_PREFIXES_WIN]
    return PROTECTED_PREFIXES_POSIX


def is_protected(path: str) -> bool:
    norm = os.path.normcase(os.path.abspath(path))
    for pref in protected_prefixes():
        # сравниваем по границе пути, чтобы /usr не ловило /usr2
        if norm == pref or norm.startswith(pref.rstrip("/\\") + os.sep):
            return True
    return False


# ---------------------------------------------------------------------------
# Защита от самоуничтожения
# ---------------------------------------------------------------------------
# Файлы самой программы (скрипт/EXE и папка проекта) и Python-интерпретатор
# не удаляются НИКОГДА, пока явно не включён allow_self_delete. Эта защита
# НЕ отключается флагом allow_protected.

def app_root() -> str:
    """Каталог, где лежит сама программа (учитывает PyInstaller-сборку)."""
    if getattr(sys, "frozen", False):  # собрано в EXE через PyInstaller
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def self_protected_prefixes() -> list[str]:
    """Пути, удаление которых = самоуничтожение."""
    prefixes: set[str] = {os.path.normcase(app_root())}
    for p in (sys.executable, sys.prefix, getattr(sys, "base_prefix", sys.prefix)):
        try:
            prefixes.add(os.path.normcase(os.path.abspath(p)))
        except Exception:
            pass
    return list(prefixes)


def is_self(path: str) -> bool:
    """True, если путь относится к самой программе или интерпретатору."""
    norm = os.path.normcase(os.path.abspath(path))
    for pref in self_protected_prefixes():
        if norm == pref or norm.startswith(pref.rstrip("/\\") + os.sep):
            return True
    return False


# ---------------------------------------------------------------------------
# Защита интерпретатора Python (всех установок на системе)
# ---------------------------------------------------------------------------
# Отдельно от "файлов программы" защищаем САМ PYTHON: любой python.exe и его
# каталог установки, включая другие версии, conda и Microsoft Store.
# Иначе правило вида "*" на C:\ снесло бы интерпретатор, на котором работает
# сама утилита. Кэшируется один раз — проверка вызывается на каждом файле.

_PYTHON_ROOTS_CACHE: Optional[list[str]] = None


def _looks_like_python_root(directory: str) -> bool:
    """Каталог считается корнем/бин-папкой Python, если там есть исполняемый
    python.exe / pythonw.exe. Это покрывает и обычную установку (есть Lib),
    и conda, и новый python-manager (bin/ без Lib)."""
    try:
        if not os.path.isdir(directory):
            return False
        return (
            os.path.isfile(os.path.join(directory, "python.exe"))
            or os.path.isfile(os.path.join(directory, "python3.exe"))
            or os.path.isfile(os.path.join(directory, "pythonw.exe"))
        )
    except OSError:
        return False


def _in_windows_apps(norm_path: str) -> bool:
    """Пути в WindowsApps содержат десятки чужих UWP-приложений и шорткаты
    python.exe; целиком как 'корень Python' их помечать нельзя."""
    return os.sep + "windowsapps" + os.sep in (norm_path + os.sep).lower()


def _is_drive_root(path: str) -> bool:
    """True для корня тома (C:\\, D:\\ и т.п.) и слишком коротких путей."""
    norm = os.path.normcase(os.path.abspath(path))
    drive, tail = os.path.splitdrive(norm)
    if drive and tail in ("", os.sep, "/"):
        return True
    # любой путь короче 4 символов не может быть полноценной папкой Python
    if len(norm.rstrip("/\\")) < 4:
        return True
    return False


def python_install_roots() -> list[str]:
    """Собирает каталоги всех известных установок Python (кэшируется).

    Строго: добавляем только папки, которые либо являются текущим
    интерпретатором, либо явно похожи на корень Python (python.exe + Lib).
    Корень диска (C:\\) не добавляется НИКОГДА — иначе защита накрыла бы весь
    диск и сломала обычную очистку.
    """
    global _PYTHON_ROOTS_CACHE
    if _PYTHON_ROOTS_CACHE is not None:
        return _PYTHON_ROOTS_CACHE

    roots: set[str] = set()

    def add(candidate: str, *, force: bool = False) -> None:
        try:
            if not candidate:
                return
            norm = os.path.normcase(os.path.abspath(candidate))
            if _is_drive_root(norm):           # guard: никогда не C:\
                return
            if not force and _in_windows_apps(norm):
                return                         # не накрываем весь WindowsApps
            if force or _looks_like_python_root(norm):
                roots.add(norm)
        except Exception:
            pass

    # 1) Текущий интерпретатор и его base/prefix (доверяем безусловно).
    for p in (sys.executable, sys.prefix, getattr(sys, "base_prefix", sys.prefix)):
        add(os.path.dirname(os.path.abspath(p)), force=True)
        add(p, force=True)

    # 2) Переменные окружения, где обычно ставят Python.
    env_dirs = []
    for var in ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
                "ProgramFiles", "ProgramFiles(x86)", "USERPROFILE"):
        val = os.environ.get(var)
        if val:
            env_dirs.append(val)

    # Только конкретные места установок, НЕ сами base-каталоги.
    candidates: list[str] = []
    for base in env_dirs:
        candidates.append(os.path.join(base, "Programs", "Python"))
        # новый python-manager: %LOCALAPPDATA%\Python\bin и ...\Python
        candidates.append(os.path.join(base, "Python", "bin"))
        candidates.append(os.path.join(base, "Python"))
        for name in ("miniconda3", "anaconda3", "Miniconda3", "Anaconda3"):
            candidates.append(os.path.join(base, name))

    # Разворачиваем "Programs\Python\Python3xx" и conda-корни.
    for c in list(candidates):
        add(c)
        try:
            if os.path.isdir(c):
                for sub in os.listdir(c):
                    full = os.path.join(c, sub)
                    if os.path.isdir(full) and sub.lower().startswith("python"):
                        add(full)
        except OSError:
            pass

    # 3) Microsoft Store Python: WindowsApps\PythonSoftwareFoundation.*
    for base in env_dirs:
        apps = os.path.join(base, "Microsoft", "WindowsApps")
        try:
            if os.path.isdir(apps):
                for sub in os.listdir(apps):
                    if sub.lower().startswith("pythonsoftwarefoundation"):
                        add(os.path.join(apps, sub), force=True)
        except OSError:
            pass

    # 4) Корни из PATH, но только если это настоящий корень Python.
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if entry:
            add(entry)

    _PYTHON_ROOTS_CACHE = [r for r in roots if r]
    return _PYTHON_ROOTS_CACHE


def is_python(path: str) -> bool:
    """True, если путь лежит внутри какой-либо установки Python."""
    norm = os.path.normcase(os.path.abspath(path))
    for pref in python_install_roots():
        if norm == pref or norm.startswith(pref.rstrip("/\\") + os.sep):
            return True
    return False


def is_self_or_python(path: str) -> bool:
    """Единая проверка: файлы программы ИЛИ сам Python. Снимается только
    явным allow_self_delete."""
    return is_self(path) or is_python(path)


# ---------------------------------------------------------------------------
# Правила
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """Одно правило сканирования."""
    path: str                       # базовая папка
    patterns: list[str] = field(default_factory=lambda: ["*"])  # glob-маски имён
    extensions: list[str] = field(default_factory=list)         # ["log","tmp"] или [".log"]
    min_size_kb: int = 0            # минимальный размер файла, КБ
    max_size_kb: int = 0            # 0 = без ограничения
    older_than_days: int = 0        # 0 = не проверять возраст
    recursive: bool = True
    include_dirs: bool = False      # удалять и пустые папки (после чистки)
    enabled: bool = True

    def normalized_ext(self) -> list[str]:
        return ["." + e.lstrip(".").lower() for e in self.extensions if e.strip()]


@dataclass
class Profile:
    """Набор правил + настройки удаления. Сохраняется в JSON."""
    rules: list[Rule] = field(default_factory=list)
    use_recycle_bin: bool = True    # если send2trash доступен
    allow_protected: bool = False   # разрешить удаление из системных зон
    allow_self_delete: bool = False # РАЗРЕШИТЬ удаление файлов самой программы
    follow_symlinks: bool = False
    # --- антивирус ---
    antivirus_enabled: bool = True       # проверять найденные файлы
    quarantine_enabled: bool = True      # заражённые -> в карантин, а не удалять
    quarantine_dir: str = ""             # пусто = <папка программы>/quarantine
    allow_infected_delete: bool = False  # удалять заражённые вместо карантина
    signatures_file: str = ""            # доп. база сигнатур (пусто = virus_signatures.json рядом)

    def resolved_quarantine_dir(self) -> str:
        return self.quarantine_dir or os.path.join(app_root(), "quarantine")

    def resolved_signatures_file(self) -> str:
        if self.signatures_file:
            return self.signatures_file
        default = os.path.join(app_root(), "virus_signatures.json")
        return default if os.path.exists(default) else ""

    @classmethod
    def load(cls, path: str) -> "Profile":
        # utf-8-sig терпит и обычный UTF-8, и файл с BOM (Notepad/PowerShell)
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        rules = [Rule(**r) for r in data.get("rules", [])]
        return cls(
            rules=rules,
            use_recycle_bin=bool(data.get("use_recycle_bin", True)),
            allow_protected=bool(data.get("allow_protected", False)),
            allow_self_delete=bool(data.get("allow_self_delete", False)),
            follow_symlinks=bool(data.get("follow_symlinks", False)),
            antivirus_enabled=bool(data.get("antivirus_enabled", True)),
            quarantine_enabled=bool(data.get("quarantine_enabled", True)),
            quarantine_dir=str(data.get("quarantine_dir", "")),
            allow_infected_delete=bool(data.get("allow_infected_delete", False)),
            signatures_file=str(data.get("signatures_file", "")),
        )

    def save(self, path: str) -> None:
        data = {
            "rules": [asdict(r) for r in self.rules],
            "use_recycle_bin": self.use_recycle_bin,
            "allow_protected": self.allow_protected,
            "allow_self_delete": self.allow_self_delete,
            "follow_symlinks": self.follow_symlinks,
            "antivirus_enabled": self.antivirus_enabled,
            "quarantine_enabled": self.quarantine_enabled,
            "quarantine_dir": self.quarantine_dir,
            "allow_infected_delete": self.allow_infected_delete,
            "signatures_file": self.signatures_file,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Ядро: сканирование и удаление
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    path: str
    size: int
    mtime: float
    is_dir: bool
    rule_index: int
    threat: Any = None  # av.ThreatResult | None (Any, т.к. av — необязательный импорт)

    @property
    def is_infected(self) -> bool:
        return bool(self.threat and self.threat.infected)

    @property
    def threat_label(self) -> str:
        return self.threat.label if self.threat is not None else ""

    @property
    def size_h(self) -> str:
        return human_size(self.size)

    @property
    def mtime_h(self) -> str:
        try:
            return datetime.fromtimestamp(self.mtime).strftime("%Y-%m-%d %H:%M")
        except (OverflowError, OSError, ValueError):
            return "?"


def human_size(n: int) -> str:
    sign = "-" if n < 0 else ""
    n = abs(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            if unit == "B":
                return f"{sign}{int(n)} {unit}"
            return f"{sign}{n:.1f} {unit}"
        n /= 1024.0
    return f"{sign}{n:.1f} PB"


class Scanner:
    """Собирает файлы по правилам профиля."""

    def __init__(self, profile: Profile):
        self.profile = profile
        # Встроенный антивирус включается, если модуль доступен и опция профиля вкл.
        self.av_engine = None
        if AV_AVAILABLE and profile.antivirus_enabled:
            try:
                sig = profile.resolved_signatures_file()
                self.av_engine = av.AntivirusEngine(sig or None)
            except Exception:
                self.av_engine = None

    def scan(
        self,
        should_stop: Optional[threading.Event] = None,
        on_progress: Optional[callable] = None,
    ) -> tuple[list[FileEntry], list[str]]:
        results: list[FileEntry] = []
        errors: list[str] = []
        now = time.time()

        for idx, rule in enumerate(self.profile.rules):
            if not rule.enabled:
                continue
            base = Path(os.path.expandvars(os.path.expanduser(rule.path)))
            if not base.exists():
                errors.append(f"Путь не найден: {rule.path}")
                continue

            exts = rule.normalized_ext()
            min_b = rule.min_size_kb * 1024
            max_b = rule.max_size_kb * 1024 if rule.max_size_kb > 0 else 0
            age_cut = now - rule.older_than_days * 86400 if rule.older_than_days > 0 else 0

            if base.is_file():
                if self._match_file(base, rule, exts, min_b, max_b, age_cut):
                    results.append(self._entry(base, idx, True))
                continue

            walker_root = base
            if rule.recursive:
                walker = os.walk(walker_root, followlinks=self.profile.follow_symlinks)
            else:
                # только верхний уровень
                try:
                    entries = list(os.scandir(walker_root))
                except OSError as e:
                    errors.append(f"{walker_root}: {e}")
                    continue
                walker = iter([(str(walker_root), [], [e.name for e in entries if e.is_file(follow_symlinks=False)])])

            for root, dirs, files in walker:
                if should_stop is not None and should_stop.is_set():
                    return results, errors
                if not rule.recursive:
                    dirs[:] = []
                if not self.profile.allow_protected:
                    # не спускаемся в защищённые зоны
                    dirs[:] = [d for d in dirs if not is_protected(os.path.join(root, d))]
                if not self.profile.allow_self_delete:
                    # не спускаемся в папку самой программы и в папки Python
                    dirs[:] = [d for d in dirs if not is_self_or_python(os.path.join(root, d))]

                for fname in files:
                    full = os.path.join(root, fname)
                    p = Path(full)
                    if self._match_file(p, rule, exts, min_b, max_b, age_cut):
                        e = self._entry(p, idx, True)
                        if e is not None:
                            results.append(e)
                        if on_progress is not None:
                            on_progress(len(results))

                if rule.include_dirs:
                    for d in dirs:
                        full = os.path.join(root, d)
                        if self._match_dir(Path(full), rule):
                            e = self._entry(Path(full), idx, False)
                            if e is not None:
                                results.append(e)

        return results, errors

    def _entry(self, p: Path, rule_index: int, is_file: bool) -> Optional[FileEntry]:
        try:
            st = p.stat()
            entry = FileEntry(str(p), st.st_size if is_file else 0, st.st_mtime, not is_file, rule_index)
        except OSError:
            return None
        # Антивирусная проверка только файлов (папки не сканируем на сигнатуры).
        if is_file and self.av_engine is not None:
            try:
                entry.threat = self.av_engine.scan_file(str(p))
            except Exception:
                entry.threat = None
        return entry

    def _match_file(self, p: Path, rule: Rule, exts: list[str],
                    min_b: int, max_b: int, age_cut: float) -> bool:
        name = p.name.lower()
        if not any(fnmatch.fnmatch(name, pat.lower()) for pat in (rule.patterns or ["*"])):
            return False
        if exts and p.suffix.lower() not in exts:
            return False
        if not self.profile.allow_protected and is_protected(str(p)):
            return False
        if not self.profile.allow_self_delete and is_self_or_python(str(p)):
            return False
        try:
            st = p.stat()
        except OSError:
            return False
        if st.st_size < min_b:
            return False
        if max_b and st.st_size > max_b:
            return False
        if age_cut and st.st_mtime > age_cut:
            return False
        return True

    def _match_dir(self, p: Path, rule: Rule) -> bool:
        name = p.name.lower()
        if not any(fnmatch.fnmatch(name, pat.lower()) for pat in (rule.patterns or ["*"])):
            return False
        if not self.profile.allow_protected and is_protected(str(p)):
            return False
        if not self.profile.allow_self_delete and is_self_or_python(str(p)):
            return False
        return True


class Deleter:
    """Удаляет выбранные записи. Возвращает (removed, freed, quarantined, errors)."""

    def __init__(self, profile: Profile):
        self.profile = profile
        # Карантин создаём, если AV-модуль доступен и опция включена.
        self.quarantine = None
        if AV_AVAILABLE and profile.quarantine_enabled:
            try:
                self.quarantine = av.Quarantine(profile.resolved_quarantine_dir())
            except Exception:
                self.quarantine = None

    def delete(self, entries: Iterable[FileEntry]) -> tuple[int, int, int, list[str]]:
        removed = 0
        freed = 0
        quarantined = 0
        errors: list[str] = []
        use_bin = self.profile.use_recycle_bin and TRASH_AVAILABLE

        # Сначала файлы, потом папки (чтобы пустые папки удалились последними).
        ordered = sorted(entries, key=lambda e: (not e.is_dir, -len(e.path)))
        for e in ordered:
            if not self.profile.allow_protected and is_protected(e.path):
                errors.append(f"Пропущено (защищённая зона): {e.path}")
                continue
            if not self.profile.allow_self_delete and is_self_or_python(e.path):
                errors.append(f"Пропущено (защита программы/Python): {e.path}")
                continue

            # Заражённые файлы: карантин / удаление / пропуск — по настройкам.
            if e.is_infected:
                tname = e.threat.name if e.threat else "?"
                if self.quarantine is not None:
                    item = self.quarantine.put(e.path, e.threat)
                    if item is not None:
                        quarantined += 1
                    else:
                        errors.append(f"Карантин не удался: {e.path}")
                    continue
                if self.profile.allow_infected_delete:
                    errors.append(f"Удалено заражённое ({tname}): {e.path}")
                    # падаем вниз к обычному удалению
                else:
                    errors.append(
                        f"Заражено ({tname}) — ПРОПУЩЕНО (карантин выключен, "
                        f"удаление заражённого запрещено): {e.path}")
                    continue

            try:
                if use_bin and not e.is_dir:
                    send2trash(e.path)  # type: ignore
                elif use_bin and e.is_dir:
                    # в корзину папки тоже можно, ноsend2trash умеет и папки
                    send2trash(e.path)  # type: ignore
                else:
                    if e.is_dir:
                        # shutil.rmtree безопаснее os.remove для непустых
                        import shutil
                        shutil.rmtree(e.path)
                    else:
                        os.remove(e.path)
                removed += 1
                freed += e.size
            except OSError as ex:
                errors.append(f"{e.path}: {ex}")
        return removed, freed, quarantined, errors


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def run_gui() -> int:
    if not TK_AVAILABLE:
        print("tkinter недоступен. Запустите CLI-режим: python disk_cleaner.py --help")
        return 2

    root = tk.Tk()
    root.title("Disk Cleaner")
    root.geometry("1000x680")

    profile = Profile()
    entries: list[FileEntry] = []
    checked: set[int] = set()

    log_q: "queue.Queue[str]" = queue.Queue()
    stop_ev = threading.Event()

    def log(msg: str) -> None:
        log_q.put(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    # ---------- Редактор правил (верхняя панель) ----------
    left = ttk.Frame(root, padding=8)
    left.pack(side="left", fill="y")

    right = ttk.Frame(root, padding=8)
    right.pack(side="left", fill="both", expand=True)

    ttk.Label(left, text="Правила очистки", font=("", 11, "bold")).pack(anchor="w")

    form = ttk.Frame(left)
    form.pack(fill="x", pady=6)

    ttk.Label(form, text="Папка:").grid(row=0, column=0, sticky="w")
    path_var = tk.StringVar()
    ttk.Entry(form, textvariable=path_var, width=40).grid(row=0, column=1, sticky="ew")
    ttk.Button(form, text="...", width=3,
               command=lambda: path_var.set(
                   filedialog.askdirectory() or path_var.get()
               )).grid(row=0, column=2)

    ttk.Label(form, text="Маски имён:").grid(row=1, column=0, sticky="w")
    pat_var = tk.StringVar(value="*")
    ttk.Entry(form, textvariable=pat_var).grid(row=1, column=1, sticky="ew")

    ttk.Label(form, text="Расширения:").grid(row=2, column=0, sticky="w")
    ext_var = tk.StringVar()
    ttk.Entry(form, textvariable=ext_var).grid(row=2, column=1, sticky="ew")

    ttk.Label(form, text="Мин. размер, КБ:").grid(row=3, column=0, sticky="w")
    min_var = tk.StringVar(value="0")
    ttk.Entry(form, textvariable=min_var, width=10).grid(row=3, column=1, sticky="w")

    ttk.Label(form, text="Старше, дней:").grid(row=4, column=0, sticky="w")
    age_var = tk.StringVar(value="0")
    ttk.Entry(form, textvariable=age_var, width=10).grid(row=4, column=1, sticky="w")

    rec_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(form, text="Рекурсивно", variable=rec_var).grid(row=5, column=1, sticky="w")

    dir_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(form, text="Пустые папки (по маске)", variable=dir_var).grid(row=6, column=1, sticky="w")

    ttk.Button(form, text="Добавить правило", command=lambda: None).grid(row=7, column=1, sticky="ew", pady=(8, 0))

    rules_list = tk.Listbox(left, height=8, width=60, exportselection=False)
    rules_list.pack(fill="both", expand=True, pady=6)

    def add_rule():
        try:
            min_kb = int(min_var.get() or 0)
            age = int(age_var.get() or 0)
        except ValueError:
            messagebox.showerror("Ошибка", "Мин. размер и возраст — целые числа.")
            return
        if not path_var.get():
            messagebox.showerror("Ошибка", "Укажите папку.")
            return
        pats = [p.strip() for p in pat_var.get().split(",") if p.strip()] or ["*"]
        exts = [e.strip() for e in ext_var.get().split(",") if e.strip()]
        rule = Rule(
            path=path_var.get(),
            patterns=pats,
            extensions=exts,
            min_size_kb=min_kb,
            older_than_days=age,
            recursive=rec_var.get(),
            include_dirs=dir_var.get(),
        )
        profile.rules.append(rule)
        refresh_rules()

    # переопределяем кнопку после объявления add_rule
    for child in form.winfo_children():
        if isinstance(child, ttk.Button) and child.cget("text") == "Добавить правило":
            child.configure(command=add_rule)

    def refresh_rules():
        rules_list.delete(0, "end")
        for r in profile.rules:
            mark = "✓" if r.enabled else "✗"
            rules_list.insert(
                "end",
                f"{mark} {r.path} | {','.join(r.patterns)} | ext={','.join(r.extensions) or '-'} "
                f"| ≥{r.min_size_kb}КБ | >{r.older_than_days}д | {'рекурс' if r.recursive else 'top'}",
            )

    def del_rule():
        sel = list(rules_list.curselection())
        for i in reversed(sel):
            profile.rules.pop(i)
        refresh_rules()

    def toggle_rule():
        for i in rules_list.curselection():
            profile.rules[i].enabled = not profile.rules[i].enabled
        refresh_rules()

    btns = ttk.Frame(left)
    btns.pack(fill="x")
    ttk.Button(btns, text="Удалить правило", command=del_rule).pack(side="left", padx=2)
    ttk.Button(btns, text="Вкл/выкл", command=toggle_rule).pack(side="left", padx=2)

    # ---------- Опции профиля ----------
    opts = ttk.LabelFrame(left, text="Опции", padding=6)
    opts.pack(fill="x", pady=8)
    bin_var = tk.BooleanVar(value=profile.use_recycle_bin)
    ttk.Checkbutton(opts, text="В корзину (send2trash)" if TRASH_AVAILABLE
                    else "В корзину (send2trash НЕ установлен)",
                    variable=bin_var, state="normal" if TRASH_AVAILABLE else "disabled").pack(anchor="w")
    prot_var = tk.BooleanVar(value=profile.allow_protected)
    ttk.Checkbutton(opts, text="Разрешить системные зоны (осторожно!)",
                    variable=prot_var).pack(anchor="w")
    self_var = tk.BooleanVar(value=profile.allow_self_delete)

    def on_self_toggle():
        # При включении просим явное подтверждение; при отказе — откатываем галку.
        if self_var.get():
            ok = messagebox.askyesno(
                "ОПАСНО: самоуничтожение",
                "Вы разрешаете программе удалять СОБСТВЕННЫЕ файлы "
                "и файлы Python-интерпретатора.\n\n"
                "Программа может перестать работать и не сможет запуститься "
                "снова. Это действие необратимо.\n\n"
                "Вы уверены?",
                icon="warning",
            )
            if not ok:
                self_var.set(False)

    ttk.Checkbutton(opts, text="Разрешить удалить саму программу (самоуничтожение!)",
                    variable=self_var, command=on_self_toggle).pack(anchor="w")

    # ---------- Антивирус ----------
    av_var = tk.BooleanVar(value=profile.antivirus_enabled and AV_AVAILABLE)
    quarantine_var = tk.BooleanVar(value=profile.quarantine_enabled and AV_AVAILABLE)
    _av_state = "normal" if AV_AVAILABLE else "disabled"
    ttk.Checkbutton(
        opts,
        text="Антивирус: проверять файлы" if AV_AVAILABLE else "Антивирус (модуль antivirus недоступен)",
        variable=av_var, state=_av_state).pack(anchor="w")
    ttk.Checkbutton(opts, text="Заражённые -> в карантин (не удалять)",
                    variable=quarantine_var, state=_av_state).pack(anchor="w")
    ttk.Button(opts, text="Открыть папку карантина",
               command=lambda: open_quarantine()).pack(anchor="w", pady=(4, 0))

    def open_quarantine():
        qdir = profile.resolved_quarantine_dir()
        try:
            os.makedirs(qdir, exist_ok=True)
            if os.name == "nt":
                os.startfile(qdir)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", qdir])
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось открыть папку:\n{e}")

    # ---------- Профили ----------
    prof_frame = ttk.Frame(left)
    prof_frame.pack(fill="x", pady=4)
    ttk.Button(prof_frame, text="Сохранить профиль...",
               command=lambda: save_profile()).pack(side="left", padx=2)
    ttk.Button(prof_frame, text="Загрузить профиль...",
               command=lambda: load_profile()).pack(side="left", padx=2)

    def save_profile():
        p = filedialog.asksaveasfilename(defaultextension=".json",
                                         filetypes=[("JSON", "*.json")])
        if not p:
            return
        profile.use_recycle_bin = bin_var.get()
        profile.allow_protected = prot_var.get()
        profile.allow_self_delete = self_var.get()
        profile.antivirus_enabled = av_var.get()
        profile.quarantine_enabled = quarantine_var.get()
        profile.save(p)
        log(f"Профиль сохранён: {p}")

    def load_profile():
        p = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not p:
            return
        try:
            loaded = Profile.load(p)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить: {e}")
            return
        profile.rules = loaded.rules
        profile.use_recycle_bin = loaded.use_recycle_bin
        profile.allow_protected = loaded.allow_protected
        profile.allow_self_delete = loaded.allow_self_delete
        profile.antivirus_enabled = loaded.antivirus_enabled
        profile.quarantine_enabled = loaded.quarantine_enabled
        bin_var.set(loaded.use_recycle_bin)
        prot_var.set(loaded.allow_protected)
        self_var.set(loaded.allow_self_delete)
        av_var.set(loaded.antivirus_enabled and AV_AVAILABLE)
        quarantine_var.set(loaded.quarantine_enabled and AV_AVAILABLE)
        refresh_rules()
        log(f"Профиль загружен: {p}")

    # ---------- Правая часть: результаты ----------
    toolbar = ttk.Frame(right)
    toolbar.pack(fill="x")
    ttk.Button(toolbar, text="Сканировать", command=lambda: start_scan()).pack(side="left", padx=2)
    ttk.Button(toolbar, text="Остановить", command=lambda: stop_ev.set()).pack(side="left", padx=2)
    ttk.Button(toolbar, text="Выделить всё", command=lambda: check_all(True)).pack(side="left", padx=2)
    ttk.Button(toolbar, text="Снять всё", command=lambda: check_all(False)).pack(side="left", padx=2)
    del_btn = ttk.Button(toolbar, text="Удалить выбранное", command=lambda: do_delete())
    del_btn.pack(side="left", padx=2)
    ttk.Button(toolbar, text="Отметить заражённые", command=lambda: select_infected()).pack(side="left", padx=2)

    filter_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(toolbar, text="только угрозы", variable=filter_var,
                    command=lambda: render_rows()).pack(side="left", padx=6)

    status_var = tk.StringVar(value="Готово")
    ttk.Label(toolbar, textvariable=status_var).pack(side="right", padx=6)

    columns = ("sel", "size", "mtime", "threat", "path")
    tree = ttk.Treeview(right, columns=columns, show="headings", selectmode="extended")
    tree.heading("sel", text="✓")
    tree.heading("size", text="Размер")
    tree.heading("mtime", text="Изменён")
    tree.heading("threat", text="Угроза")
    tree.heading("path", text="Путь")
    tree.column("sel", width=40, anchor="center", stretch=False)
    tree.column("size", width=100, anchor="e", stretch=False)
    tree.column("mtime", width=130, anchor="w", stretch=False)
    tree.column("threat", width=170, anchor="w", stretch=False)
    tree.column("path", width=560, anchor="w")
    # Подсветка строк по уровню угрозы (цвета читаемы и на светлых, и на тёмных темах)
    tree.tag_configure("infected", background="#e06666")
    tree.tag_configure("suspicious", background="#f6c453")
    tree.pack(fill="both", expand=True, pady=6)

    vsb = ttk.Scrollbar(right, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)

    def row_id(i: int) -> str:
        return f"r{i}"

    def row_tags(e: FileEntry) -> tuple:
        if e.threat is not None and e.threat.infected:
            return ("infected",)
        if e.threat is not None and e.threat.severity == "SUSPICIOUS":
            return ("suspicious",)
        return ()

    def row_values(i: int) -> tuple:
        e = entries[i]
        mark = "☑" if i in checked else "☐"
        return (mark, e.size_h, e.mtime_h, e.threat_label, e.path)

    def render_rows():
        tree.delete(*tree.get_children())
        for i, e in enumerate(entries):
            if filter_var.get() and not e.threat_label:
                continue  # фильтр: показываем только угрозы/подозрительное
            tree.insert("", "end", iid=row_id(i), values=row_values(i), tags=row_tags(e))

    def toggle_row(_event):
        sel = tree.focus()
        if not sel.startswith("r"):
            return
        i = int(sel[1:])
        if i in checked:
            checked.discard(i)
        else:
            checked.add(i)
        tree.item(sel, values=row_values(i))

    tree.bind("<Button-1>", lambda ev: (root.after(20, toggle_row, ev)))

    def check_all(value: bool):
        if value:
            checked.update(range(len(entries)))
        else:
            checked.clear()
        render_rows()

    def select_infected():
        """Отметить только заражённые файлы (для изоляции в карантин)."""
        checked.clear()
        for i, e in enumerate(entries):
            if e.is_infected:
                checked.add(i)
        render_rows()

    # ---------- Лог ----------
    log_box = tk.Text(right, height=8, wrap="word")
    log_box.pack(fill="x")

    def pump_log():
        try:
            while True:
                log_box.insert("end", log_q.get_nowait() + "\n")
                log_box.see("end")
        except queue.Empty:
            pass
        root.after(200, pump_log)

    # ---------- Сканирование в потоке ----------
    def start_scan():
        if not profile.rules:
            messagebox.showinfo("Пусто", "Сначала добавьте хотя бы одно правило.")
            return
        profile.use_recycle_bin = bin_var.get()
        profile.allow_protected = prot_var.get()
        profile.allow_self_delete = self_var.get()
        profile.antivirus_enabled = av_var.get()
        profile.quarantine_enabled = quarantine_var.get()
        entries.clear()
        checked.clear()
        render_rows()
        stop_ev.clear()
        status_var.set("Сканирование...")
        del_btn.configure(state="disabled")

        def work():
            sc = Scanner(profile)
            res, errs = sc.scan(should_stop=stop_ev)
            root.after(0, lambda: finish_scan(res, errs))

        threading.Thread(target=work, daemon=True).start()

    def finish_scan(res: list[FileEntry], errs: list[str]):
        entries.extend(res)
        for e in errs:
            log("⚠ " + e)
        total = sum(e.size for e in entries)
        log(f"Найдено объектов: {len(entries)}  (всего {human_size(total)})")
        infected = sum(1 for e in entries if e.is_infected)
        susp = sum(1 for e in entries if e.threat and e.threat.severity == "SUSPICIOUS")
        if infected or susp:
            log(f"☣ Заражено: {infected}   ⚠ Подозрительных: {susp}")
            status_var.set(f"Найдено: {len(entries)} | ☣ {infected} | ⚠ {susp} | {human_size(total)}")
        else:
            status_var.set(f"Найдено: {len(entries)} | угроз нет | {human_size(total)}")
        render_rows()
        del_btn.configure(state="normal")

    # ---------- Удаление ----------
    def do_delete():
        chosen = [entries[i] for i in sorted(checked)]
        if not chosen:
            messagebox.showinfo("Ничего не выбрано", "Отметьте объекты в списке.")
            return
        total = sum(e.size for e in chosen)
        where = "корзину" if (profile.use_recycle_bin and TRASH_AVAILABLE) else "с диска БЕЗВОЗВРАТНО"
        infected = sum(1 for e in chosen if e.is_infected)
        msg = f"Удалить {len(chosen)} объект(ов) ({human_size(total)}) в {where}?"
        if infected:
            if self_quarantine_on():
                msg += f"\n\nЗаражённых файлов: {infected} — они будут помещены в КАРАНТИН (не удалены)."
            else:
                msg += f"\n\nВНИМАНИЕ: заражённых файлов: {infected}. Карантин выключен — они будут пропущены или удалены."
        msg += "\n\nДействие необратимо для режима 'безвозвратно'."
        if not messagebox.askyesno("Подтверждение удаления", msg, icon="warning"):
            return
        dl = Deleter(profile)
        status_var.set("Удаление...")
        del_btn.configure(state="disabled")

        def work():
            removed, freed, quarantined, errs = dl.delete(chosen)
            root.after(0, lambda: finish_delete(removed, freed, quarantined, errs))

        threading.Thread(target=work, daemon=True).start()

    def self_quarantine_on() -> bool:
        return bool(profile.quarantine_enabled and AV_AVAILABLE)

    def finish_delete(removed: int, freed: int, quarantined: int, errs: list[str]):
        log(f"Удалено: {removed}  Освобождено: {human_size(freed)}", )
        if quarantined:
            log(f"В карантин помещено: {quarantined}")
        for e in errs:
            log("⚠ " + e)
        status_var.set(f"Удалено: {removed} | Карантин: {quarantined} | {human_size(freed)}")
        # убираем удалённые/изолированные из списка (их уже нет на месте)
        new_entries = [e for e in entries if not os.path.exists(e.path)]
        entries.clear()
        entries.extend(new_entries)
        checked.clear()
        render_rows()
        del_btn.configure(state="normal")

    pump_log()
    root.mainloop()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_cli(args: argparse.Namespace) -> int:
    if not os.path.exists(args.config):
        print(f"Файл правил не найден: {args.config}", file=sys.stderr)
        return 2
    profile = Profile.load(args.config)
    # Флаги применяем и для предпросмотра, чтобы --list/--dry-run показывали
    # именно то, что будет удалено при --execute.
    profile.allow_protected = profile.allow_protected or args.allow_protected
    profile.allow_self_delete = profile.allow_self_delete or args.allow_self_delete
    if args.no_av:
        profile.antivirus_enabled = False
    if args.no_quarantine:
        profile.quarantine_enabled = False
    if args.delete_infected:
        profile.allow_infected_delete = True
    if profile.allow_self_delete:
        print("ВНИМАНИЕ: включено самоуничтожение — файлы самой программы и "
              "ВСЕ установки Python больше НЕ защищены от удаления.")
    if profile.antivirus_enabled and not AV_AVAILABLE:
        print("Антивирус запрошен, но модуль antivirus недоступен — проверка отключена.")
        profile.antivirus_enabled = False

    sc = Scanner(profile)
    print("Сканирование..." + (" (с антивирусом)" if sc.av_engine else " (без антивируса)"))
    entries, errs = sc.scan()
    for e in errs:
        print("⚠ " + e)
    total = sum(e.size for e in entries)
    infected = sum(1 for e in entries if e.is_infected)
    susp = sum(1 for e in entries if e.threat and e.threat.severity == av.SEV_SUSPICIOUS) if AV_AVAILABLE else 0
    print(f"Найдено объектов: {len(entries)}  Освободится: {human_size(total)}"
          + (f"  Заражено: {infected}  Подозрительно: {susp}" if sc.av_engine else ""))

    if args.list:
        for e in entries:
            tag = f"  [{e.threat.label}]" if e.threat_label else ""
            print(f"{e.size_h:>10}  {e.mtime_h}  {e.path}{tag}")

    if args.dry_run or not args.execute:
        print("Режим предпросмотра (--dry-run или без --execute). Ничего не удалено.")
        return 0

    if not args.yes:
        ans = input(f"Удалить {len(entries)} объектов в "
                    f"{'корзину' if profile.use_recycle_bin and TRASH_AVAILABLE else 'мусор'}? [y/N] ")
        if ans.strip().lower() not in ("y", "yes", "д", "да"):
            print("Отменено.")
            return 1

    dl = Deleter(profile)
    removed, freed, quarantined, derrs = dl.delete(entries)
    for e in derrs:
        print("⚠ " + e, file=sys.stderr)
    print(f"Удалено: {removed}  Освобождено: {human_size(freed)}  В карантине: {quarantined}")
    return 0 if not derrs else 1


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

EXAMPLE_PROFILE = {
    "rules": [
        {
            "path": "C:\\Users\\%USERNAME%\\Downloads",
            "patterns": ["*"],
            "extensions": ["tmp", "log", "~"],
            "min_size_kb": 1024,
            "max_size_kb": 0,
            "older_than_days": 30,
            "recursive": True,
            "include_dirs": False,
            "enabled": True,
        }
    ],
    "use_recycle_bin": True,
    "allow_protected": False,
    "allow_self_delete": False,
    "follow_symlinks": False,
    "antivirus_enabled": True,
    "quarantine_enabled": True,
    "quarantine_dir": "",
    "allow_infected_delete": False,
    "signatures_file": "",
}


def run_av_scan(args: argparse.Namespace) -> int:
    """Проверить указанный путь встроенным движком (+ опционально Windows Defender)."""
    if not AV_AVAILABLE:
        print("Модуль antivirus недоступен — проверка невозможна.", file=sys.stderr)
        return 2
    target = args.av_scan
    if not os.path.exists(target):
        print(f"Путь не найден: {target}", file=sys.stderr)
        return 2
    sig = args.signatures or (Profile().resolved_signatures_file() or None)
    eng = av.AntivirusEngine(sig)
    print(f"Встроенная сигнатурная проверка: {target}")
    found = 0
    if os.path.isfile(target):
        walk_files = [target]
    else:
        walk_files = [os.path.join(r, f) for r, _d, fs in os.walk(target) for f in fs]
    for p in walk_files:
        r = eng.scan_file(p)
        if r.infected or r.severity == av.SEV_SUSPICIOUS:
            found += 1
            print(f"  {r.label}  {p}")
    print(f"Всего помечено встроенным движком: {found}")
    if args.defender:
        print("Запуск внешнего скана Windows Defender (QuickScan)...")
        hits = av.defender_scan_paths([target])
        for h in hits:
            print("  DEFENDER:", h)
        print(f"Defender сообщений: {len(hits)}")
    return 0


def run_quarantine_cmd(args: argparse.Namespace) -> int:
    """Управление карантином: список / восстановление / удаление."""
    if not AV_AVAILABLE:
        print("Модуль antivirus недоступен — карантина нет.", file=sys.stderr)
        return 2
    qdir = args.quarantine_dir or Profile().resolved_quarantine_dir()
    q = av.Quarantine(qdir)
    if args.quarantine_list:
        items = q.list()
        if not items:
            print(f"Карантин пуст ({qdir}).")
            return 0
        for it in items:
            print(f"  {it['stored']}  [{it.get('threat','?')}]  "
                  f"из {it.get('original','?')}  {it.get('quarantined_at','')}")
        print(f"Всего в карантине: {len(items)}  (папка: {qdir})")
        return 0
    if args.restore is not None:
        ok, msg = q.restore(args.restore)
        print(("Восстановлено: " if ok else "Ошибка: ") + msg)
        return 0 if ok else 1
    if args.purge is not None:
        n = q.purge(args.purge or None)
        print(f"Безвозвратно удалено из карантина: {n}")
        return 0
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Disk Cleaner — очистка дисков по правилам пользователя."
    )
    parser.add_argument("--config", help="JSON с правилами (для CLI-режима).")
    parser.add_argument("--execute", action="store_true", help="Реально удалять.")
    parser.add_argument("--dry-run", action="store_true", help="Только показать что будет удалено.")
    parser.add_argument("--yes", action="store_true", help="Без подтверждения (для планировщика).")
    parser.add_argument("--list", action="store_true", help="Вывести найденные файлы.")
    parser.add_argument("--allow-protected", action="store_true",
                        help="Разрешить работу в системных зонах (опасно).")
    parser.add_argument("--allow-self-delete", action="store_true",
                        help="Разрешить удаление файлов самой программы (самоуничтожение, опасно).")
    parser.add_argument("--make-example", action="store_true",
                        help="Создать пример правил в --config и выйти.")
    # --- антивирус ---
    parser.add_argument("--no-av", action="store_true", help="Выключить антивирусную проверку.")
    parser.add_argument("--no-quarantine", action="store_true", help="Не помещать заражённые в карантин.")
    parser.add_argument("--delete-infected", action="store_true",
                        help="Удалять заражённые вместо карантина (опасно).")
    parser.add_argument("--signatures", help="Доп. файл базы сигнатур JSON.")
    parser.add_argument("--av-scan", metavar="PATH",
                        help="Проверить путь антивирусом и показать угрозы (без удаления).")
    parser.add_argument("--defender", action="store_true",
                        help="С --av-scan: дополнительно вызвать Windows Defender.")
    # --- карантин ---
    parser.add_argument("--quarantine-dir", help="Папка карантина (по умолчанию <программа>/quarantine).")
    parser.add_argument("--quarantine-list", action="store_true", help="Показать содержимое карантина.")
    parser.add_argument("--restore", metavar="NAME", help="Восстановить объект из карантина по имени.")
    parser.add_argument("--purge", nargs="?", const="", metavar="NAME", default=None,
                        help="Удалить из карантина безвозвратно (без NAME — всё).")
    args = parser.parse_args()

    # Команды антивируса/карантина работают независимо от --config.
    if args.quarantine_list or args.restore is not None or args.purge is not None:
        return run_quarantine_cmd(args)
    if args.av_scan:
        return run_av_scan(args)

    if args.make_example:
        if not args.config:
            print("Укажите --config путь.json", file=sys.stderr)
            return 2
        with open(args.config, "w", encoding="utf-8") as f:
            json.dump(EXAMPLE_PROFILE, f, ensure_ascii=False, indent=2)
        print(f"Пример правил: {args.config}")
        return 0

    if args.config:
        return run_cli(args)

    return run_gui()


if __name__ == "__main__":
    sys.exit(main())
