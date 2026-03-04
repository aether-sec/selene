#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Privacy Audit v3.0                                ║
║   Temukan data sensitif, tracker, dan kebocoran privasi.     ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/privacy_audit.py
  python scripts/privacy_audit.py --dirs ~/Documents,~/Desktop
  python scripts/privacy_audit.py --browser
  python scripts/privacy_audit.py --network
  python scripts/privacy_audit.py --full
"""

import sys, os, re, json, subprocess, shutil, time, argparse, fnmatch
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, write_alert, save_json, Spinner,
        IS_LINUX, IS_WINDOWS, IS_ANDROID, IS_ROOT, IS_MACOS,
        fmt_bytes, REPORTS_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION = "3.0.0"

# ── Pola data sensitif ────────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    # Keuangan
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
     "Nomor Kartu Kredit", "KRITIS"),
    (r"\b\d{3}-\d{2}-\d{4}\b",
     "Social Security Number (SSN)", "KRITIS"),
    # Indonesia
    (r"\b[1-9][0-9]{15}\b",
     "Nomor KTP Indonesia (16 digit)", "TINGGI"),
    (r"\b(?:BCA|BNI|BRI|Mandiri|CIMB|Danamon)\s*[:\-]?\s*\d{10,16}\b",
     "Nomor Rekening Bank Indonesia", "TINGGI"),
    # Kata sandi & kunci
    (r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{6,})",
     "Password / API Key dalam file", "KRITIS"),
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}",
     "AWS Access Key ID", "KRITIS"),
    (r"(?i)(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}",
     "Stripe API Key", "KRITIS"),
    (r"ghp_[A-Za-z0-9]{36}",
     "GitHub Personal Access Token", "KRITIS"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
     "Private Key dalam file teks", "KRITIS"),
    # Email & identitas
    (r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
     "Alamat Email", "INFO"),
    # Nomor telepon Indonesia
    (r"\b(?:\+62|62|0)(?:8[1-9][0-9]|21|31)[0-9]{6,10}\b",
     "Nomor Telepon Indonesia", "RENDAH"),
]

# Ekstensi yang diperiksa untuk data sensitif
SENSITIVE_EXTENSIONS = {
    ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".env",
    ".conf", ".config", ".ini", ".properties", ".log",
    ".sql", ".db", ".bak", ".old", ".backup",
    ".py", ".js", ".php", ".sh", ".bash",
    ".doc", ".docx", ".xls", ".xlsx",
}

EXCLUDE_DIRS = {
    "__pycache__", ".git", "node_modules", ".venv", "venv",
    ".mypy_cache", ".tox", "dist", "build", ".cache",
    "site-packages", ".local/share/Trash",
}

MAX_FILE_SIZE = 5 * 1024 * 1024   # 5 MB per file
MAX_FINDINGS  = 500               # Maks findings total

# ── Tracker domains (untuk cek koneksi jaringan) ──────────────────────────────
TRACKER_DOMAINS = {
    # Iklan & tracking
    "doubleclick.net", "googlesyndication.com", "googletagmanager.com",
    "facebook.net", "fbcdn.net", "fbsbx.com",
    "amazon-adsystem.com", "ads.yahoo.com", "scorecardresearch.com",
    "outbrain.com", "taboola.com", "criteo.com", "quantserve.com",
    "adsafeprotected.com", "adform.net", "rubiconproject.com",
    # Analytics
    "hotjar.com", "mixpanel.com", "segment.com", "amplitude.com",
    "intercom.io", "fullstory.com", "logrocket.com",
    # Telemetry
    "telemetry.mozilla.org", "telemetry.microsoft.com",
    "vortex.data.microsoft.com", "settings-win.data.microsoft.com",
}

# ── File scanner ──────────────────────────────────────────────────────────────

def scan_file_for_sensitive_data(fpath: Path, max_findings: int = 5) -> List[Dict]:
    """Scan satu file untuk pola data sensitif."""
    findings = []
    try:
        content = fpath.read_text(errors="ignore")[:200_000]  # Maks 200KB teks
    except (PermissionError, OSError):
        return []

    lines = content.splitlines()
    for lineno, line in enumerate(lines[:5000], 1):
        if len(findings) >= max_findings:
            break
        for pattern, label, severity in SENSITIVE_PATTERNS:
            if severity == "INFO" and lineno > 50:
                continue  # Email hanya cek 50 baris pertama
            m = re.search(pattern, line)
            if m:
                # Sensor nilai sensitif
                value = m.group(0)
                if len(value) > 6:
                    value = value[:3] + "***" + value[-2:]
                findings.append({
                    "file":     str(fpath),
                    "line":     lineno,
                    "label":    label,
                    "severity": severity,
                    "snippet":  value,
                })
                break  # Satu temuan per baris

    return findings

def scan_directory_for_sensitive(directories: List[str]) -> List[Dict]:
    """Scan direktori untuk data sensitif."""
    all_findings = []
    scanned = 0

    for dir_str in directories:
        dp = Path(dir_str)
        if not dp.exists():
            continue
        try:
            for fpath in dp.rglob("*"):
                if len(all_findings) >= MAX_FINDINGS:
                    break
                if not fpath.is_file():
                    continue
                # Skip excluded dirs
                if any(ex in fpath.parts for ex in EXCLUDE_DIRS):
                    continue
                if fpath.suffix.lower() not in SENSITIVE_EXTENSIONS:
                    continue
                try:
                    if fpath.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                scanned += 1
                findings = scan_file_for_sensitive_data(fpath)
                all_findings.extend(findings)
        except (PermissionError, OSError):
            pass

    log("INFO", f"File dipindai: {scanned}  |  Temuan: {len(all_findings)}")
    return all_findings

# ── Browser audit ─────────────────────────────────────────────────────────────

def audit_browser_privacy() -> List[Dict]:
    """Periksa pengaturan privasi browser yang umum."""
    findings = []

    # Lokasi profil browser
    home = Path.home()
    BROWSER_DIRS = {}

    if IS_LINUX:
        BROWSER_DIRS = {
            "Chrome":  home / ".config/google-chrome",
            "Chromium":home / ".config/chromium",
            "Firefox": home / ".mozilla/firefox",
            "Brave":   home / ".config/BraveSoftware/Brave-Browser",
        }
    elif IS_WINDOWS:
        appdata = Path(os.environ.get("LOCALAPPDATA",""))
        BROWSER_DIRS = {
            "Chrome":  appdata / "Google/Chrome/User Data",
            "Edge":    appdata / "Microsoft/Edge/User Data",
            "Firefox": Path(os.environ.get("APPDATA","")) / "Mozilla/Firefox/Profiles",
        }

    for browser, browser_dir in BROWSER_DIRS.items():
        if not browser_dir.exists():
            continue

        # Cek apakah ada profil default
        findings.append({
            "type":     "browser_detected",
            "browser":  browser,
            "severity": "INFO",
            "desc":     f"Browser ditemukan: {browser} ({browser_dir})",
            "solution": f"Periksa pengaturan privasi {browser}",
        })

        # Cek history file (jika bisa dibaca)
        history_paths = list(browser_dir.rglob("History")) + list(browser_dir.rglob("places.sqlite"))
        for hp in history_paths[:1]:
            if hp.exists():
                size = hp.stat().st_size
                findings.append({
                    "type":     "browser_history",
                    "browser":  browser,
                    "severity": "RENDAH",
                    "path":     str(hp),
                    "size":     fmt_bytes(size),
                    "desc":     f"Browser history {browser}: {fmt_bytes(size)}",
                    "solution": "Atur browser untuk hapus history saat tutup",
                })

        # Cek saved passwords
        login_data = browser_dir / "Default/Login Data"
        if login_data.exists() and login_data.stat().st_size > 4096:
            findings.append({
                "type":     "browser_saved_passwords",
                "browser":  browser,
                "severity": "SEDANG",
                "desc":     f"Password tersimpan di browser {browser}",
                "solution": "Gunakan password manager eksternal (seperti Selene Vault), bukan browser",
            })

    # Chrome ekstension mencurigakan
    for browser, browser_dir in BROWSER_DIRS.items():
        ext_dir = browser_dir / "Default/Extensions"
        if not ext_dir.exists():
            continue
        extensions = [d for d in ext_dir.iterdir() if d.is_dir()]
        if len(extensions) > 20:
            findings.append({
                "type":     "too_many_extensions",
                "browser":  browser,
                "severity": "SEDANG",
                "desc":     f"{browser}: {len(extensions)} ekstensi terpasang — makin banyak makin besar risiko",
                "solution": "Hapus ekstensi yang tidak digunakan, audit izin ekstensi",
            })

    return findings

# ── Network privacy ───────────────────────────────────────────────────────────

def audit_network_privacy() -> List[Dict]:
    """Periksa koneksi jaringan untuk tracking dan telemetry."""
    findings = []
    if not HAS_PSUTIL:
        log("INFO", "psutil tidak ada — network audit dilewati")
        return findings

    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, Exception):
        log("INFO", "Tidak bisa akses koneksi jaringan (butuh izin lebih)")
        return findings

    tracker_conns = []
    for conn in conns:
        if not conn.raddr:
            continue
        rip = conn.raddr.ip

        # Resolve hostname
        import socket
        try:
            hostname = socket.gethostbyaddr(rip)[0]
        except Exception:
            hostname = ""

        # Cek tracker
        for tracker in TRACKER_DOMAINS:
            if tracker in hostname:
                proc_name = "?"
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass
                tracker_conns.append({
                    "ip":       rip,
                    "hostname": hostname,
                    "tracker":  tracker,
                    "process":  proc_name,
                    "pid":      conn.pid,
                })
                break

    if tracker_conns:
        for tc in tracker_conns:
            findings.append({
                "type":     "tracker_connection",
                "severity": "SEDANG",
                "desc":     f"Koneksi aktif ke tracker: {tc['hostname']} oleh {tc['process']}",
                "ip":       tc["ip"],
                "tracker":  tc["tracker"],
                "process":  tc["process"],
                "solution": "Gunakan DNS blocker (Pi-hole, AdGuard) atau hosts file blocking",
            })
    else:
        findings.append({
            "type":     "no_trackers",
            "severity": "INFO",
            "desc":     "Tidak ada koneksi ke tracker yang terdeteksi saat ini",
            "solution": "",
        })

    return findings

# ── System privacy ────────────────────────────────────────────────────────────

def audit_system_privacy() -> List[Dict]:
    """Cek pengaturan privasi sistem operasi."""
    findings = []

    if IS_LINUX:
        # Cek apakah telemetry aktif
        telemetry_indicators = [
            ("/var/lib/ubuntu-advantage/private/machine-token", "Ubuntu Pro/Advantage telemetry"),
            ("/etc/apport/crashdb.conf", "Ubuntu Apport crash reporter"),
            ("/usr/bin/ubuntu-report", "Ubuntu system report"),
        ]
        for path_str, label in telemetry_indicators:
            if Path(path_str).exists():
                findings.append({
                    "type":     "system_telemetry",
                    "severity": "RENDAH",
                    "desc":     f"Telemetry terdeteksi: {label}",
                    "solution": f"Nonaktifkan: ubuntu-report send no | apport-cli --disable",
                })

        # Cek .bash_history
        for hist_file in [Path.home() / ".bash_history",
                          Path.home() / ".zsh_history",
                          Path.home() / ".history"]:
            if hist_file.exists():
                size = hist_file.stat().st_size
                findings.append({
                    "type":     "shell_history",
                    "severity": "RENDAH",
                    "path":     str(hist_file),
                    "size":     fmt_bytes(size),
                    "desc":     f"Shell history tersimpan: {hist_file.name} ({fmt_bytes(size)})",
                    "solution": "Tambahkan: export HISTFILE=/dev/null di .bashrc untuk nonaktifkan",
                })

        # Cek SSH known_hosts
        known = Path.home() / ".ssh/known_hosts"
        if known.exists():
            lines = len(known.read_text(errors="ignore").splitlines())
            findings.append({
                "type":     "ssh_known_hosts",
                "severity": "INFO",
                "desc":     f"SSH known_hosts: {lines} entri (bisa mengungkap server yang pernah diakses)",
                "solution": "Pertimbangkan HashKnownHosts yes di ~/.ssh/config",
            })

        # Cek file .env di home
        env_files = list(Path.home().glob("**/.env"))[:5]
        for ef in env_files:
            if not any(ex in ef.parts for ex in EXCLUDE_DIRS):
                findings.append({
                    "type":     "exposed_env_file",
                    "severity": "TINGGI",
                    "path":     str(ef),
                    "desc":     f"File .env ditemukan: {ef} — mungkin mengandung secrets",
                    "solution": "Pastikan .env tidak di-commit ke git dan izin filenya 600",
                })

    elif IS_WINDOWS:
        # Windows Diagnostic Data
        findings.append({
            "type":     "windows_telemetry_note",
            "severity": "RENDAH",
            "desc":     "Windows mengirim diagnostic data ke Microsoft secara default",
            "solution": "Matikan di: Settings → Privacy → Diagnostics & feedback → Basic",
        })

    return findings

# ── Display ───────────────────────────────────────────────────────────────────
SEV_C = {
    "KRITIS": Fore.RED,
    "TINGGI": Fore.RED,
    "SEDANG": Fore.YELLOW,
    "RENDAH": Fore.CYAN,
    "INFO":   Fore.WHITE,
}

def print_findings_group(title: str, findings: List[Dict]) -> None:
    if not findings:
        log("OK", f"{title}: Bersih")
        return

    non_info = [f for f in findings if f.get("severity") != "INFO"]
    log("WARN" if non_info else "INFO",
        c(f"{title}: {len(non_info)} masalah", Fore.YELLOW if non_info else Fore.GREEN))

    for f in sorted(findings, key=lambda x: {"KRITIS":0,"TINGGI":1,"SEDANG":2,"RENDAH":3,"INFO":4}.get(x.get("severity","INFO"),4)):
        sev = f.get("severity","INFO")
        if sev == "INFO" and not f.get("desc"):
            continue
        col = SEV_C.get(sev, Fore.WHITE)
        print(c(f"\n    [{sev}] {f.get('desc','?')}", col, bold=(sev=="KRITIS")))
        if f.get("path"):
            print(c(f"      Path: {f['path']}", Fore.WHITE))
        if f.get("solution"):
            print(c(f"      → {f['solution']}", Fore.CYAN))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Privacy Audit — Temukan kebocoran data & tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/privacy_audit.py
  python scripts/privacy_audit.py --full
  python scripts/privacy_audit.py --dirs ~/Documents,~/Desktop
  python scripts/privacy_audit.py --browser
  python scripts/privacy_audit.py --network"""
    )
    parser.add_argument("--dirs",    "-d", help="Direktori yang diperiksa (pisahkan koma)")
    parser.add_argument("--browser", action="store_true", help="Hanya audit browser")
    parser.add_argument("--network", action="store_true", help="Hanya audit koneksi jaringan")
    parser.add_argument("--full",    action="store_true", help="Semua audit (lebih lambat)")
    parser.add_argument("--no-save", action="store_true")
    args = parser.parse_args()

    log_header("Selene — Privacy Audit v3.0",
               "Temukan data sensitif, tracker, dan kebocoran privasi")

    all_findings: Dict[str, List[Dict]] = {}

    # ── Data sensitif di file ─────────────────────────────────────────────────
    if args.full or args.dirs or (not args.browser and not args.network):
        if args.dirs:
            dirs = [d.strip() for d in args.dirs.split(",")]
        else:
            cfg  = get_config()
            dirs = cfg.get("backup","directories", default=[str(Path.home() / "Documents")])
            # Tambah direktori umum
            for common in ["~/Desktop", "~/Downloads"]:
                p = Path(common).expanduser()
                if p.exists() and str(p) not in dirs:
                    dirs.append(str(p))

        log_section("1 — SCAN DATA SENSITIF DI FILE")
        log("INFO", f"Direktori: {', '.join(dirs[:3])}")
        with Spinner("Memindai file..."):
            file_findings = scan_directory_for_sensitive(dirs)
        all_findings["Data Sensitif"] = file_findings
        print_findings_group("Data Sensitif", file_findings)

    # ── Browser audit ─────────────────────────────────────────────────────────
    if args.full or args.browser or (not args.dirs and not args.network):
        log_section("2 — AUDIT PRIVASI BROWSER")
        with Spinner("Memeriksa browser..."):
            browser_findings = audit_browser_privacy()
        all_findings["Browser"] = browser_findings
        print_findings_group("Browser", browser_findings)

    # ── System audit ──────────────────────────────────────────────────────────
    if args.full or (not args.browser and not args.network and not args.dirs):
        log_section("3 — AUDIT PRIVASI SISTEM")
        with Spinner("Memeriksa sistem..."):
            system_findings = audit_system_privacy()
        all_findings["Sistem"] = system_findings
        print_findings_group("Sistem", system_findings)

    # ── Network audit ─────────────────────────────────────────────────────────
    if args.full or args.network:
        log_section("4 — AUDIT KONEKSI JARINGAN")
        with Spinner("Memeriksa koneksi aktif..."):
            net_findings = audit_network_privacy()
        all_findings["Jaringan"] = net_findings
        print_findings_group("Jaringan", net_findings)

    # ── Ringkasan ─────────────────────────────────────────────────────────────
    log_section("RINGKASAN PRIVACY AUDIT")
    total    = sum(len(v) for v in all_findings.values())
    kritis   = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "KRITIS")
    tinggi   = sum(1 for v in all_findings.values() for f in v if f.get("severity") == "TINGGI")

    print(c(f"\n  Total temuan  : {total}", Fore.WHITE))
    print(c(f"  KRITIS        : {kritis}", Fore.RED if kritis else Fore.GREEN, bold=bool(kritis)))
    print(c(f"  TINGGI        : {tinggi}", Fore.RED if tinggi else Fore.GREEN))

    if kritis:
        print(c(f"\n  ⛔ Ada data sangat sensitif yang perlu segera diamankan!", Fore.RED, bold=True))
    elif tinggi:
        print(c(f"\n  ⚠  Beberapa data perlu diamankan.", Fore.YELLOW))
    else:
        print(c(f"\n  ✓  Tidak ada masalah privasi kritis yang ditemukan.", Fore.GREEN, bold=True))

    # Alert
    for v in all_findings.values():
        for f in v:
            if f.get("severity") == "KRITIS":
                write_alert("CRIT", f"Privacy: {f.get('desc','?')}", details=f)

    # Simpan
    if not args.no_save:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"privacy_{ts}.json"
        save_json(path, {"tool":"privacy_audit","version":TOOL_VERSION,
                         "scan_time":datetime.now().isoformat(),"findings":all_findings})
        log("OK", c(f"Laporan: reports/privacy_{ts}.json", Fore.GREEN))

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
