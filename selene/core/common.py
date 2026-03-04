"""
selene/core/common.py
Utilitas bersama untuk semua tools Selene.
"""

import os
import sys
import platform
import socket
import json
import time
import threading
from datetime import datetime
from pathlib import Path

# ── Platform detection ────────────────────────────────────────────────────────
IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"
IS_MACOS   = platform.system() == "Darwin"
IS_ANDROID = "ANDROID_ROOT" in os.environ or os.path.exists("/data/data/com.termux")

if hasattr(os, "getuid"):
    IS_ROOT = os.getuid() == 0
else:
    try:
        import ctypes
        IS_ROOT = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        IS_ROOT = False

# ── Warna terminal ────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _Dummy()
    _HAS_COLOR = False

def c(text: str, color: str = "", bold: bool = False) -> str:
    """Beri warna pada teks terminal."""
    if not _HAS_COLOR:
        return str(text)
    bold_code = Style.BRIGHT if bold else ""
    return f"{bold_code}{color}{text}{Style.RESET_ALL}"

# ── Path constants ────────────────────────────────────────────────────────────
SELENE_DIR  = Path(__file__).resolve().parent.parent.parent
LOGS_DIR    = SELENE_DIR / "logs"
DATA_DIR    = SELENE_DIR / "data"
REPORTS_DIR = SELENE_DIR / "reports"
CONFIG_FILE = SELENE_DIR / "selene.config.json"

ALERTS_FILE      = LOGS_DIR / "alerts.jsonl"
HP_CAPTURES_FILE = LOGS_DIR / "honeypot_captures.jsonl"
HEALTH_FILE      = DATA_DIR / "health.json"

# Pastikan direktori runtime ada
for _d in (LOGS_DIR, DATA_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ── Logger ────────────────────────────────────────────────────────────────────
_LOG_META = {
    "OK":    (Fore.GREEN,   "✓"),
    "INFO":  (Fore.CYAN,    "ℹ"),
    "WARN":  (Fore.YELLOW,  "⚠"),
    "ERROR": (Fore.RED,     "✗"),
    "CRIT":  (Fore.RED,     "⛔"),
    "SCAN":  (Fore.MAGENTA, "◈"),
    "RUN":   (Fore.BLUE,    "▶"),
    "SKIP":  (Fore.WHITE,   "○"),
}

def log(level: str, msg: str, indent: int = 0) -> None:
    color, icon = _LOG_META.get(level, (Fore.WHITE, "·"))
    ts  = datetime.now().strftime("%H:%M:%S")
    pad = "  " * indent
    bold = level in ("CRIT", "ERROR")
    print(c(f"  {pad}[{ts}] {icon}  {msg}", color, bold=bold))

def log_section(title: str) -> None:
    print(c(f"\n  {'─' * 58}", Fore.BLUE))
    print(c(f"  ▶  {title}", Fore.YELLOW, bold=True))

def log_header(title: str, subtitle: str = "") -> None:
    W = 62
    print()
    print(c("╔" + "═" * W + "╗", Fore.CYAN))
    print(c("║" + title.center(W) + "║", Fore.CYAN, bold=True))
    if subtitle:
        print(c("║" + subtitle.center(W) + "║", Fore.CYAN))
    print(c("╚" + "═" * W + "╝", Fore.CYAN))
    print()

# ── Dependency helpers ────────────────────────────────────────────────────────
def require_root(tool: str) -> bool:
    if IS_ROOT:
        return True
    print(c(f"\n  ⚡ '{tool}' membutuhkan akses root/administrator.", Fore.YELLOW, bold=True))
    if IS_WINDOWS:
        print(c("     Jalankan Command Prompt sebagai Administrator.", Fore.WHITE))
    else:
        print(c(f"     Jalankan: sudo python scripts/{tool}", Fore.WHITE))
    return False

def check_dependency(module: str, pip_name: str = None, optional: bool = False) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        pkg = pip_name or module
        if optional:
            log("INFO", f"Module opsional '{module}' tidak tersedia.")
            return False
        print(c(f"\n  ✗  Dependency tidak ditemukan: {module}", Fore.RED, bold=True))
        print(c(f"     Install: pip install {pkg}", Fore.WHITE))
        return False

def check_binary(name: str, optional: bool = False) -> bool:
    import shutil
    if shutil.which(name):
        return True
    if optional:
        log("INFO", f"Binary opsional '{name}' tidak ditemukan.")
        return False
    print(c(f"\n  ✗  Binary tidak ditemukan: {name}", Fore.RED, bold=True))
    if IS_LINUX:
        print(c(f"     Install: sudo apt install {name}", Fore.WHITE))
    return False

# ── Input helpers ─────────────────────────────────────────────────────────────
def confirm(prompt_text: str, default: bool = True) -> bool:
    hint = "Ya/tidak" if default else "ya/Tidak"
    try:
        ans = input(c(f"  {prompt_text} [{hint}]: ", Fore.YELLOW)).strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if not ans:
        return default
    return ans in ("ya", "y", "yes", "1")

def prompt(text: str, default: str = "") -> str:
    hint = f" (default: {default})" if default else ""
    try:
        ans = input(c(f"  {text}{hint}: ", Fore.YELLOW)).strip()
    except (KeyboardInterrupt, EOFError):
        return default
    return ans if ans else default

def prompt_password(text: str) -> str:
    import getpass
    try:
        return getpass.getpass(c(f"  {text}: ", Fore.YELLOW))
    except (KeyboardInterrupt, EOFError):
        return ""

# ── Alert writer ──────────────────────────────────────────────────────────────
_alert_lock = threading.Lock()

def write_alert(level: str, message: str, details: dict = None, ip: str = None) -> None:
    entry = {
        "timestamp": datetime.now().isoformat(),
        "level":     level,
        "message":   message,
        "ip":        ip,
        "details":   details or {},
    }
    with _alert_lock:
        try:
            with open(ALERTS_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError:
            pass

def append_jsonl(path: Path, entry: dict) -> None:
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        pass

def read_jsonl(path: Path, last_n: int = None) -> list:
    entries = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        if last_n:
            lines = lines[-last_n:]
        for line in lines:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass
    return entries

# ── JSON helpers ──────────────────────────────────────────────────────────────
def save_json(path: Path, data: dict, indent: int = 2) -> bool:
    tmp = Path(str(path) + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, default=str, ensure_ascii=False)
        tmp.replace(path)
        return True
    except OSError as e:
        log("ERROR", f"Gagal simpan {Path(path).name}: {e}")
        try: tmp.unlink(missing_ok=True)
        except Exception: pass
        return False

def load_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default if default is not None else {}

# ── Format helpers ────────────────────────────────────────────────────────────
def fmt_bytes(n: int) -> str:
    for u in ("B","KB","MB","GB","TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {u}"
        n /= 1024.0
    return f"{n:.1f} PB"

def fmt_duration(s: float) -> str:
    if s < 60:   return f"{s:.0f} detik"
    if s < 3600: return f"{s/60:.0f} menit"
    return f"{s/3600:.1f} jam"

def risk_color(score: int) -> str:
    if score >= 70: return Fore.RED
    if score >= 40: return Fore.YELLOW
    if score >= 15: return Fore.CYAN
    return Fore.GREEN

def risk_label(score: int) -> str:
    if score >= 70: return "TINGGI"
    if score >= 40: return "SEDANG"
    if score >= 15: return "RENDAH"
    return "AMAN"

# ── Spinner ───────────────────────────────────────────────────────────────────
class Spinner:
    def __init__(self, msg: str = "Memproses..."):
        self.msg   = msg
        self._stop = threading.Event()
        self._t    = None

    def _spin(self):
        frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        i = 0
        while not self._stop.is_set():
            f = frames[i % len(frames)]
            print(c(f"\r  {f}  {self.msg}", Fore.CYAN), end="", flush=True)
            time.sleep(0.1)
            i += 1
        print("\r" + " " * (len(self.msg) + 8) + "\r", end="", flush=True)

    def __enter__(self):
        self._t = threading.Thread(target=self._spin, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._t: self._t.join(timeout=1)

# ── Network quick helpers ─────────────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"

def get_hostname() -> str:
    try:   return socket.gethostname()
    except Exception: return "unknown"

def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except (socket.error, OSError):
        return False

def is_port_available(port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.close()
        return True
    except OSError:
        return False
