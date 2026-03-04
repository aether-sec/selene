#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Hash Verifier v3.0                                ║
║   Pantau integritas file — deteksi modifikasi tidak sah.     ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/hash_verifier.py init       — buat baseline
  python scripts/hash_verifier.py check      — cek integritas
  python scripts/hash_verifier.py watch      — pantau terus (daemon)
  python scripts/hash_verifier.py diff       — lihat perubahan saja
  python scripts/hash_verifier.py update <file>  — update hash file tertentu

File baseline: data/fim_baseline.json
"""

import sys
import os
import json
import time
import hashlib
import argparse
import fnmatch
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, write_alert, save_json, load_json,
        Spinner, IS_LINUX, IS_WINDOWS, DATA_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

TOOL_VERSION  = "3.0.0"
BASELINE_FILE = DATA_DIR / "fim_baseline.json"
REPORT_FILE   = DATA_DIR / "fim_last_check.json"

# ── Default watch paths ───────────────────────────────────────────────────────
DEFAULT_WATCH_LINUX = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/ssh/authorized_keys",
    "/root/.ssh",
    "/etc/crontab",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
]

DEFAULT_WATCH_WINDOWS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\calc.exe",
]

DEFAULT_EXCLUDES = [
    "*.log", "*.tmp", "*.pid", "*.lock", "*.sock",
    "__pycache__", "*.pyc", ".git", "*.swp",
    "/proc/*", "/sys/*", "/dev/*", "/run/*",
]

MAX_FILE_SIZE  = 50 * 1024 * 1024  # 50 MB
MAX_WORKERS    = 8

# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_file(path: Path) -> Dict:
    """
    Hash satu file dengan SHA-256 + BLAKE2b.
    Returns dict dengan hash values, size, mtime, atau error info.
    """
    try:
        st = path.stat()

        if st.st_size > MAX_FILE_SIZE:
            return {
                "sha256":  None,
                "blake2b": None,
                "size":    st.st_size,
                "mtime":   st.st_mtime,
                "skipped": "too_large",
            }

        h1 = hashlib.sha256()
        h2 = hashlib.blake2b()

        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h1.update(chunk)
                h2.update(chunk)

        return {
            "sha256":  h1.hexdigest(),
            "blake2b": h2.hexdigest(),
            "size":    st.st_size,
            "mtime":   st.st_mtime,
        }

    except PermissionError:
        return {"error": "permission_denied", "size": 0, "mtime": 0}
    except FileNotFoundError:
        return {"error": "not_found", "size": 0, "mtime": 0}
    except OSError as e:
        return {"error": str(e)[:50], "size": 0, "mtime": 0}

def should_exclude(path: Path, excludes: List[str]) -> bool:
    """Apakah path ini harus dilewati."""
    if not excludes:
        return False
    path_str = str(path)
    name     = path.name
    for pattern in excludes:
        if fnmatch.fnmatch(name, pattern):
            return True
        if fnmatch.fnmatch(path_str, pattern):
            return True
    return False

def collect_files(watch_paths: List[str], excludes: List[str] = None) -> List[Path]:
    """Kumpulkan semua file yang akan dipantau."""
    files: Set[Path] = set()

    for wp in watch_paths:
        p = Path(wp)
        if not p.exists():
            continue
        if p.is_file():
            if not should_exclude(p, excludes):
                files.add(p)
        elif p.is_dir():
            try:
                for item in p.rglob("*"):
                    if item.is_file() and not should_exclude(item, excludes):
                        files.add(item)
            except (PermissionError, OSError):
                pass

    return sorted(files)

def build_baseline(files: List[Path]) -> Dict:
    """Hash semua file dan bangun baseline."""
    baseline = {}
    errors   = 0
    done     = 0
    total    = len(files)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {ex.submit(hash_file, f): f for f in files}
        for future in as_completed(future_map, timeout=120):
            fpath = future_map[future]
            done += 1
            try:
                result = future.result(timeout=10)
                baseline[str(fpath)] = result
                if "error" in result:
                    errors += 1
            except Exception as e:
                baseline[str(fpath)] = {"error": str(e), "size": 0, "mtime": 0}
                errors += 1

    return baseline

# ── Perbandingan ──────────────────────────────────────────────────────────────

ChangeType = str  # "modified" | "added" | "deleted" | "permission_error"

def compare_baselines(old: Dict, new: Dict) -> List[Dict]:
    """
    Bandingkan dua baseline dan kembalikan daftar perubahan.
    """
    changes = []

    old_paths = set(old.keys())
    new_paths = set(new.keys())

    # File yang dihapus
    for p in old_paths - new_paths:
        changes.append({
            "path":     p,
            "type":     "deleted",
            "severity": "TINGGI",
            "old":      old[p],
            "new":      None,
        })

    # File baru
    for p in new_paths - old_paths:
        info = new[p]
        if "error" not in info:
            changes.append({
                "path":     p,
                "type":     "added",
                "severity": "SEDANG",
                "old":      None,
                "new":      info,
            })

    # File yang mungkin berubah
    for p in old_paths & new_paths:
        old_info = old[p]
        new_info = new[p]

        # Lewati jika keduanya punya error
        if "error" in old_info and "error" in new_info:
            continue
        if "skipped" in old_info or "skipped" in new_info:
            continue

        # Bandingkan hash
        old_hash = old_info.get("sha256")
        new_hash = new_info.get("sha256")

        if old_hash and new_hash and old_hash != new_hash:
            # File kritis (sistem) → severity lebih tinggi
            severity = "KRITIS" if _is_critical_path(p) else "TINGGI"
            changes.append({
                "path":     p,
                "type":     "modified",
                "severity": severity,
                "old":      old_info,
                "new":      new_info,
            })

    return changes

def _is_critical_path(path_str: str) -> bool:
    """Apakah ini file sistem yang kritis."""
    CRITICAL = {
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/bin/bash", "/bin/sh", "/usr/bin/sudo",
        "/usr/bin/passwd",
    }
    return path_str in CRITICAL or any(path_str.endswith(c) for c in CRITICAL)

# ── Display ───────────────────────────────────────────────────────────────────

SEV_C = {
    "KRITIS": Fore.RED,
    "TINGGI": Fore.RED,
    "SEDANG": Fore.YELLOW,
    "INFO":   Fore.CYAN,
}

def print_changes(changes: List[Dict], verbose: bool = False) -> None:
    """Cetak daftar perubahan."""
    if not changes:
        print(c("\n  ✓  Tidak ada perubahan terdeteksi. Semua file utuh.",
                Fore.GREEN, bold=True))
        return

    type_label = {
        "modified": "DIMODIFIKASI",
        "added":    "DITAMBAHKAN",
        "deleted":  "DIHAPUS",
    }
    type_icon = {
        "modified": "✎",
        "added":    "+",
        "deleted":  "✗",
    }

    for ch in changes:
        sev   = ch["severity"]
        ctype = ch["type"]
        path  = ch["path"]
        col   = SEV_C.get(sev, Fore.WHITE)
        icon  = type_icon.get(ctype, "?")
        label = type_label.get(ctype, ctype.upper())

        print(c(f"\n  [{icon}] [{sev}] {label}", col, bold=(sev=="KRITIS")))
        print(c(f"      {path}", Fore.WHITE))

        if verbose and ctype == "modified":
            old = ch.get("old",{})
            new = ch.get("new",{})
            if old.get("mtime") and new.get("mtime"):
                old_time = datetime.fromtimestamp(old["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
                new_time = datetime.fromtimestamp(new["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
                print(c(f"      Waktu: {old_time}  →  {new_time}", Fore.WHITE))
            if old.get("sha256") and new.get("sha256"):
                print(c(f"      Hash lama: {old['sha256'][:20]}...", Fore.WHITE))
                print(c(f"      Hash baru: {new['sha256'][:20]}...", Fore.WHITE))

def print_summary_check(changes: List[Dict], total_files: int,
                         elapsed: float, check_time: str) -> None:
    """Cetak ringkasan hasil check."""
    log_section("RINGKASAN")

    kritis = [c for c in changes if c["severity"] == "KRITIS"]
    tinggi = [c for c in changes if c["severity"] == "TINGGI"]
    sedang = [c for c in changes if c["severity"] == "SEDANG"]
    modified = [c for c in changes if c["type"] == "modified"]
    added    = [c for c in changes if c["type"] == "added"]
    deleted  = [c for c in changes if c["type"] == "deleted"]

    print(c(f"\n  File dipantau : {total_files}", Fore.WHITE))
    print(c(f"  Dimodifikasi  : {len(modified)}",
            Fore.RED if modified else Fore.GREEN, bold=bool(modified)))
    print(c(f"  Ditambahkan   : {len(added)}",
            Fore.YELLOW if added else Fore.GREEN))
    print(c(f"  Dihapus       : {len(deleted)}",
            Fore.RED if deleted else Fore.GREEN))
    print(c(f"  Masalah kritis: {len(kritis)}",
            Fore.RED if kritis else Fore.GREEN, bold=bool(kritis)))
    print(c(f"  Waktu check   : {elapsed:.1f} detik", Fore.WHITE))
    print(c(f"  Diperiksa     : {check_time[:16]}", Fore.WHITE))

    if kritis:
        print(c(f"\n  ⛔ PERINGATAN: {len(kritis)} file kritis dimodifikasi!", Fore.RED, bold=True))
        print(c("     Bisa jadi tanda rootkit, backdoor, atau kompromi sistem.", Fore.RED))

# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_init(watch_paths: List[str], excludes: List[str],
             force: bool = False) -> bool:
    """Buat baseline baru."""
    if BASELINE_FILE.exists() and not force:
        print(c(f"\n  Baseline sudah ada ({BASELINE_FILE})", Fore.YELLOW))
        if not confirm("Timpa dengan baseline baru?", default=False):
            log("INFO", "Init dibatalkan.")
            return False

    log("SCAN", f"Mengumpulkan file dari {len(watch_paths)} path...")
    with Spinner("Mengumpulkan file..."):
        files = collect_files(watch_paths, excludes)

    if not files:
        log("WARN", "Tidak ada file yang ditemukan untuk dipantau.")
        return False

    log("INFO", f"{len(files)} file ditemukan, membangun baseline...")

    with Spinner(f"Menghash {len(files)} file..."):
        baseline = build_baseline(files)

    # Simpan baseline
    data = {
        "version":      TOOL_VERSION,
        "created_at":   datetime.now().isoformat(),
        "watch_paths":  watch_paths,
        "excludes":     excludes,
        "file_count":   len(files),
        "files":        baseline,
    }

    if save_json(BASELINE_FILE, data):
        errors = sum(1 for v in baseline.values() if "error" in v)
        log("OK", c(f"Baseline dibuat: {len(files)} file", Fore.GREEN, bold=True))
        if errors:
            log("INFO", f"{errors} file tidak bisa di-hash (permission error, normal)")
        return True

    log("ERROR", "Gagal menyimpan baseline.")
    return False

def cmd_check(verbose: bool = False) -> Tuple[bool, List[Dict]]:
    """Bandingkan kondisi saat ini dengan baseline."""
    if not BASELINE_FILE.exists():
        log("ERROR", "Baseline belum ada. Jalankan dulu: python scripts/hash_verifier.py init")
        return False, []

    baseline_data = load_json(BASELINE_FILE, {})
    if not baseline_data.get("files"):
        log("ERROR", "Baseline kosong atau korup.")
        return False, []

    old_baseline = baseline_data["files"]
    watch_paths  = baseline_data.get("watch_paths", [])
    excludes     = baseline_data.get("excludes", [])

    log("SCAN", f"Membangun snapshot saat ini ({len(old_baseline)} file)...")
    start = time.time()

    # Dapatkan file yang sama seperti saat baseline dibuat
    known_paths = [Path(p) for p in old_baseline.keys()]

    # Juga scan untuk file baru di watch paths
    current_files_on_disk = set(collect_files(watch_paths, excludes))
    all_paths = list(set(known_paths) | current_files_on_disk)

    with Spinner(f"Menghash {len(all_paths)} file..."):
        new_baseline = build_baseline(all_paths)

    changes = compare_baselines(old_baseline, new_baseline)
    elapsed = time.time() - start

    # Tampilkan perubahan
    print_changes(changes, verbose)
    check_time = datetime.now().isoformat()
    print_summary_check(changes, len(all_paths), elapsed, check_time)

    # Alert untuk perubahan kritis
    for ch in changes:
        if ch["severity"] in ("KRITIS", "TINGGI"):
            write_alert(
                "WARN" if ch["severity"] == "TINGGI" else "CRIT",
                f"FIM [{ch['type'].upper()}] {ch['path']}",
                details=ch,
            )

    # Simpan laporan
    save_json(REPORT_FILE, {
        "check_time": check_time,
        "total_files": len(all_paths),
        "changes":    changes,
        "elapsed":    elapsed,
    })

    return len(changes) == 0, changes

def cmd_watch(interval: int = 300, verbose: bool = False) -> None:
    """Pantau integritas file secara berkala."""
    log("INFO", c(f"Mode watch — cek setiap {interval} detik", Fore.CYAN))
    log("INFO", c("Tekan Ctrl+C untuk berhenti", Fore.WHITE))

    check_count = 0
    while True:
        try:
            check_count += 1
            ts = datetime.now().strftime("%H:%M:%S")
            print(c(f"\n  [{ts}] Cek ke-{check_count}...", Fore.BLUE))

            clean, changes = cmd_check(verbose=verbose)

            if not clean:
                crit = sum(1 for ch in changes if ch["severity"] == "KRITIS")
                if crit:
                    print(c(f"\n  ⛔ {crit} perubahan KRITIS terdeteksi!", Fore.RED, bold=True))

            next_ts = (datetime.now().timestamp() + interval)
            next_str = datetime.fromtimestamp(next_ts).strftime("%H:%M:%S")
            print(c(f"\n  Cek berikutnya: {next_str}", Fore.WHITE))
            time.sleep(interval)

        except KeyboardInterrupt:
            break

def cmd_update(file_path: str) -> bool:
    """Update hash satu file di baseline (setelah update yang sah)."""
    if not BASELINE_FILE.exists():
        log("ERROR", "Baseline belum ada.")
        return False

    fp = Path(file_path)
    if not fp.exists():
        log("ERROR", f"File tidak ditemukan: {file_path}")
        return False

    baseline_data = load_json(BASELINE_FILE, {})
    files         = baseline_data.get("files", {})
    path_str      = str(fp.resolve())

    if path_str in files:
        old = files[path_str]
        log("INFO", f"Hash lama: {old.get('sha256','?')[:20]}...")
    else:
        log("INFO", "File baru — menambahkan ke baseline")

    new_hash = hash_file(fp)
    files[path_str] = new_hash
    baseline_data["files"] = files
    baseline_data["updated_at"] = datetime.now().isoformat()

    if save_json(BASELINE_FILE, baseline_data):
        log("OK", c(f"Hash diperbarui: {fp.name}", Fore.GREEN))
        return True
    return False

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Hash Verifier — File Integrity Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/hash_verifier.py init
  python scripts/hash_verifier.py check
  python scripts/hash_verifier.py check --verbose
  python scripts/hash_verifier.py watch --interval 60
  python scripts/hash_verifier.py update /etc/hosts"""
    )
    parser.add_argument("command",
                        choices=["init","check","watch","diff","update"],
                        help="Perintah")
    parser.add_argument("path",     nargs="?",
                        help="Path file (untuk update)")
    parser.add_argument("--paths",  "-p",
                        help="Path yang dipantau, pisahkan koma")
    parser.add_argument("--interval", type=int, default=300, metavar="DETIK",
                        help="Interval watch (default: 300 detik)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Tampilkan detail hash")
    parser.add_argument("--force",  "-f", action="store_true",
                        help="Timpa baseline yang ada (untuk init)")
    args = parser.parse_args()

    log_header("Selene — Hash Verifier v3.0",
               "File Integrity Monitor — pantau perubahan file sistem")

    cfg = get_config()

    # Tentukan watch paths
    if args.paths:
        watch_paths = [p.strip() for p in args.paths.split(",")]
    else:
        configured = cfg.get("integrity","watch_paths", default=[])
        if configured:
            watch_paths = configured
        elif IS_LINUX:
            watch_paths = DEFAULT_WATCH_LINUX
        elif IS_WINDOWS:
            watch_paths = DEFAULT_WATCH_WINDOWS
        else:
            watch_paths = DEFAULT_WATCH_LINUX

    excludes = cfg.get("integrity","excludes", default=DEFAULT_EXCLUDES)

    # Filter yang ada
    existing_paths = [p for p in watch_paths if Path(p).exists()]
    if len(existing_paths) < len(watch_paths):
        missing = set(watch_paths) - set(existing_paths)
        log("INFO", f"{len(missing)} path tidak ditemukan: {list(missing)[:3]}")

    if args.command == "init":
        log("INFO", f"Memantau {len(existing_paths)} path")
        cmd_init(existing_paths, excludes, force=args.force)

    elif args.command in ("check", "diff"):
        verbose = args.verbose or args.command == "diff"
        clean, _ = cmd_check(verbose=verbose)
        sys.exit(0 if clean else 1)

    elif args.command == "watch":
        cmd_watch(args.interval, args.verbose)

    elif args.command == "update":
        if not args.path:
            log("ERROR", "Tentukan path file: hash_verifier.py update <file>")
            sys.exit(1)
        cmd_update(args.path)

    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(); log("INFO", "Dihentikan.")
    except Exception as e:
        log("ERROR", f"Error: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()
