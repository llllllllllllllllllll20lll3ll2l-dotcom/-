# -*- coding: utf-8 -*-
"""
antivirus.py — встроенный антивирусный движок для Disk Cleaner.

Возможности:
  * Сигнатурный анализ: SHA-256 хеш-база + поиск байтовых сигнатур в теле файла.
  * Тест-сигнатура EICAR (официальный тест антивирусов) — для проверки работы.
  * Эвристика: двойные расширения (.pdf.exe), исполняемые файлы в подозрительных
    местах (Temp, скрытые в AppData), известные имена малвари.
  * Внешний движок: быстрый скан через Windows Defender (PowerShell, если доступен).
  * Карантин: безопасная изоляция заражённых файлов с manifest и восстановлением.

Движок НЕ исполняет проверяемые файлы и не требует интернета. База сигнатур
расширяется пользователем через virus_signatures.json (см. пример рядом).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Iterable, Optional

# Сколько байт из файла читаем для поиска сигнатур (чтобы не грузить RAM).
MAX_SCAN_BYTES = 4 * 1024 * 1024  # 4 МБ

# ---------------------------------------------------------------------------
# Результат проверки
# ---------------------------------------------------------------------------

# Уровни серьёзности
SEV_MALWARE = "MALWARE"      # подтверждённая сигнатура/хеш -> заражён
SEV_TEST = "TEST"            # тест-сигнатура (EICAR) -> заражён
SEV_SUSPICIOUS = "SUSPICIOUS"  # эвристика -> только предупреждение
SEV_CLEAN = "CLEAN"


@dataclass
class ThreatResult:
    infected: bool
    name: str = ""
    method: str = ""        # hash | signature | heuristic | external
    severity: str = SEV_CLEAN

    @property
    def label(self) -> str:
        if not self.infected and self.severity == SEV_CLEAN:
            return ""
        if self.severity == SEV_SUSPICIOUS:
            return f"⚠ {self.name}"
        return f"☣ {self.name}"


CLEAN = ThreatResult(infected=False, severity=SEV_CLEAN)


# ---------------------------------------------------------------------------
# Встроенные сигнатуры
# ---------------------------------------------------------------------------

# Официальный тест-файл EICAR (безопасен, используется для проверки AV).
EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

# SHA-256 известных образцов (EICAR + публичные тестовые хеши).
# Пользователь может расширить через virus_signatures.json -> "hashes".
DEFAULT_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
        "EICAR-Test-File",
}

# Байтовые сигнатуры: (имя, шаблон-байты). Ищем в теле файла.
DEFAULT_BYTE_SIGNATURES = [
    ("EICAR-Test-File", EICAR_BYTES),
    # Примеры публичных учебных маркеров (совпадения по строкам в теле файла):
    ("Worm.Generic.Marker", b"EICAR-STANDARD-ANTIVIRUS"),
]

# Двойные расширения, которыми часто маскируют малварь.
DOUBLE_EXT_RE = re.compile(
    r"\.(doc|docx|xls|xlsx|ppt|pdf|txt|jpg|jpeg|png|gif|mp3|mp4|csv|zip|htm|html)"
    r"\.(exe|scr|vbs|vbe|js|jse|bat|cmd|com|pif|msi|ps1|jar)$",
    re.IGNORECASE,
)

# Исполняемые расширения.
EXEC_EXT = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd",
    ".com", ".pif", ".msi", ".ps1", ".jar", ".hta",
}

# Подозрительные места, где легитимные файлы редко живут.
SUSPICIOUS_DIR_RE = re.compile(
    r"(\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\recycler|\\$recycle\.bin)",
    re.IGNORECASE,
)

# Известные имена малвари/вымогателей (имена файлов и расширения-маркеры).
KNOWN_BAD_NAMES_RE = re.compile(
    r"(wannacry|wantyou|encryptor_(exe|ledo)|readme_for_decrypt|"
    r"how_to_recover_files|decrypt_files|locked\.txt|recoveryfile)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Движок
# ---------------------------------------------------------------------------

class AntivirusEngine:
    def __init__(self, signatures_path: Optional[str] = None):
        self.hashes = dict(DEFAULT_HASHES)
        self.byte_sigs = list(DEFAULT_BYTE_SIGNATURES)
        self.bad_name_res = [KNOWN_BAD_NAMES_RE]
        if signatures_path and os.path.exists(signatures_path):
            self._load_signatures(signatures_path)

    def _load_signatures(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception:
            return
        for h, name in (data.get("hashes") or {}).items():
            self.hashes[h.lower()] = name
        for item in (data.get("signatures") or []):
            name = item.get("name")
            pat = item.get("pattern")
            if not name or not pat:
                continue
            try:
                # hex-строка -> bytes
                self.byte_sigs.append((name, bytes.fromhex(pat)))
            except ValueError:
                continue
        for pattern in (data.get("bad_names") or []):
            try:
                self.bad_name_res.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                continue

    # ---- публичное API ----

    def scan_file(self, path: str) -> ThreatResult:
        try:
            if os.path.isdir(path):
                return CLEAN
            size = os.path.getsize(path)
        except OSError:
            return CLEAN

        # 1) Хеш (только для файлов разумного размера).
        h = self._sha256(path)
        if h and h in self.hashes:
            return ThreatResult(True, self.hashes[h], "hash", SEV_TEST
                                if self.hashes[h].startswith("EICAR") else SEV_MALWARE)

        # 2) Байтовые сигнатуры в теле файла.
        chunk = self._read_head(path)
        if chunk:
            for name, pat in self.byte_sigs:
                if pat in chunk:
                    sev = SEV_TEST if name.startswith("EICAR") else SEV_MALWARE
                    return ThreatResult(True, name, "signature", sev)

        # 3) Эвристика по имени/расположению.
        susp = self._heuristic(path)
        if susp is not None:
            return susp

        return CLEAN

    def scan_bytes(self, data: bytes, name: str = "") -> ThreatResult:
        """Проверка содержимого прямо в памяти (без записи на диск)."""
        h = hashlib.sha256(data).hexdigest()
        if h in self.hashes:
            return ThreatResult(True, self.hashes[h], "hash", SEV_TEST
                                if self.hashes[h].startswith("EICAR") else SEV_MALWARE)
        for sname, pat in self.byte_sigs:
            if pat in data:
                sev = SEV_TEST if sname.startswith("EICAR") else SEV_MALWARE
                return ThreatResult(True, sname, "signature", sev)
        if name:
            susp = self._heuristic(name)
            if susp is not None:
                return susp
        return CLEAN

    # ---- внутреннее ----

    def _sha256(self, path: str) -> Optional[str]:
        try:
            if os.path.getsize(path) > MAX_SCAN_BYTES * 8:
                return None  # слишком большой — хеш не считаем ради скорости
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(65536), b""):
                    h.update(block)
            return h.hexdigest()
        except OSError:
            return None

    def _read_head(self, path: str) -> bytes:
        try:
            with open(path, "rb") as f:
                return f.read(MAX_SCAN_BYTES)
        except OSError:
            return b""

    def _heuristic(self, path: str) -> Optional[ThreatResult]:
        name = os.path.basename(path)
        low = path.replace("/", "\\").lower()
        ext = os.path.splitext(name)[1].lower()

        if DOUBLE_EXT_RE.search(name):
            return ThreatResult(False, "Двойное расширение", "heuristic", SEV_SUSPICIOUS)
        if any(r.search(name) for r in self.bad_name_res):
            return ThreatResult(True, "Известное имя малвари", "heuristic", SEV_MALWARE)
        if ext in EXEC_EXT and SUSPICIOUS_DIR_RE.search(low):
            return ThreatResult(False, "EXE в подозрительной папке", "heuristic", SEV_SUSPICIOUS)
        return None


# ---------------------------------------------------------------------------
# Внешний движок: Windows Defender (опционально)
# ---------------------------------------------------------------------------

def defender_available() -> bool:
    if os.name != "nt":
        return False
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-MpComputerStatus | Select -Expand AntivirusEnabled"],
            capture_output=True, text=True, timeout=20,
        )
        return out.stdout.strip().lower() == "true"
    except Exception:
        return False


def defender_scan_paths(paths: Iterable[str], timeout: int = 600) -> list[str]:
    """Быстрый скан Windows Defender по указанным путям.

    Возвращает список путей ресурсов, которые Defender пометил как угрозы.
    Требует прав; при недоступности возвращает пустой список.
    """
    if os.name != "nt":
        return []
    start = datetime.now()
    quoted = ";".join(f"'{p.replace(chr(39), chr(39)*2)}'" for p in paths)
    ps = f"""
$ErrorActionPreference='SilentlyContinue'
foreach ($p in @({quoted})) {{ if (Test-Path $p) {{ Invoke-MpScan -ScanPath $p -ScanType QuickScan }} }}
$since = [datetime]'{start.strftime('%Y-%m-%dT%H:%M:%S')}'
Get-MpThreatDetection | Where-Object {{ $_.InitialDetectionTime -gt $since }} | ForEach-Object {{ $_.Resources }}
"""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Invoke-MpScan -ScanPath NUL -ScanType QuickScan"],
            capture_output=True, text=True, timeout=5,
        )  # прогрев/проверка доступности
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=timeout,
        )
        found = [line.strip() for line in out.stdout.splitlines() if line.strip()]
        return found
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Карантин
# ---------------------------------------------------------------------------

class Quarantine:
    """Изоляция заражённых файлов: перенос в папку карантина + manifest.json.

    Файл физически перемещается и переименовывается в <sha16><расширение>,
    оригинальный путь сохраняется в манифесте для восстановления.
    """

    def __init__(self, directory: str):
        self.dir = os.path.abspath(directory)
        self.manifest_path = os.path.join(self.dir, "manifest.json")
        os.makedirs(self.dir, exist_ok=True)

    def _load(self) -> list[dict]:
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, "r", encoding="utf-8-sig") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save(self, items: list[dict]) -> None:
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)

    def put(self, path: str, threat: ThreatResult) -> Optional[dict]:
        try:
            abspath = os.path.abspath(path)
            ext = os.path.splitext(abspath)[1][:12]
            tag = hashlib.sha1(abspath.encode("utf-8")).hexdigest()[:16]
            stored = f"{tag}{ext}"
            dest = os.path.join(self.dir, stored)
            # не затираем существующий: добавляем счётчик
            i = 1
            while os.path.exists(dest):
                dest = os.path.join(self.dir, f"{tag}_{i}{ext}")
                i += 1
            shutil.move(abspath, dest)
            item = {
                "stored": os.path.basename(dest),
                "original": abspath,
                "threat": threat.name,
                "method": threat.method,
                "severity": threat.severity,
                "size": os.path.getsize(dest),
                "quarantined_at": datetime.now().isoformat(timespec="seconds"),
            }
            items = self._load()
            items.append(item)
            self._save(items)
            return item
        except OSError:
            return None

    def list(self) -> list[dict]:
        return self._load()

    def restore(self, stored_name: str) -> tuple[bool, str]:
        items = self._load()
        target = next((it for it in items if it["stored"] == stored_name), None)
        if target is None:
            return False, "Не найдено в карантине"
        src = os.path.join(self.dir, target["stored"])
        dst = target["original"]
        if not os.path.exists(src):
            return False, "Файл потерян в карантине"
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.exists(dst):
                base, ext = os.path.splitext(dst)
                dst = f"{base}.restored{ext}"
            shutil.move(src, dst)
            items.remove(target)
            self._save(items)
            return True, dst
        except OSError as e:
            return False, str(e)

    def purge(self, stored_name: Optional[str] = None) -> int:
        """Удалить из карантина (безвозвратно). None = всё."""
        items = self._load()
        if stored_name is None:
            targets = items
        else:
            targets = [it for it in items if it["stored"] == stored_name]
        removed = 0
        for it in list(targets):
            p = os.path.join(self.dir, it["stored"])
            try:
                if os.path.exists(p):
                    os.remove(p)
                items.remove(it)
                removed += 1
            except OSError:
                pass
        self._save(items)
        return removed
