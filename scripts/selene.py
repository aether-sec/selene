#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene Security Suite v3.0                                 ║
║   Satu file untuk mengakses semua tools.                     ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/selene.py           — Menu interaktif
  python scripts/selene.py setup     — Setup wizard
  python scripts/selene.py scan      — Scan jaringan
  python scripts/selene.py profile   — Inventaris sistem
  python scripts/selene.py status    — Status semua tools
  python scripts/selene.py <tool>    — Jalankan tool apapun
"""

import sys
import os
import subprocess
import time
from pathlib import Path
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
SELENE_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(SELENE_ROOT))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore, Style,
        IS_ROOT, IS_LINUX, IS_WINDOWS, IS_ANDROID,
        get_local_ip, get_hostname, fmt_bytes,
        read_jsonl, LOGS_DIR, DATA_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] Gagal memuat Selene: {e}")
    print(f"  Pastikan berada di direktori root Selene.")
    print(f"  Jalankan: pip install -r requirements.txt\n")
    sys.exit(1)

SCRIPTS_DIR = SELENE_ROOT / "scripts"

# ── Definisi semua tools ──────────────────────────────────────────────────────
# Format: (key, nama tampil, file script, butuh_root, deskripsi_singkat)
TOOLS = [
    # Batch 1 — Kenali
    ("scan",     "Network Scanner",   "network_scanner.py",  False,
     "Peta semua perangkat di jaringanmu"),
    ("profile",  "System Profiler",   "system_profiler.py",  False,
     "Inventaris software & kerentanan sistem"),
    # Batch 2 — Cegah
    ("vuln",     "Vuln Scanner",      "vuln_scanner.py",     False,
     "Scan CVE & kerentanan jaringan lokal"),
    ("harden",   "Security Hardener", "security_hardener.py",True,
     "Bersihkan malware, tutup celah keamanan"),
    ("cred",     "Credential Checker","credential_checker.py",False,
     "Cek apakah email/password pernah bocor"),
    # Batch 3 — Deteksi
    ("monitor",  "Threat Monitor",    "threat_monitor.py",   True,
     "IDS real-time, auto-blokir ancaman"),
    ("honeypot", "Honeypot",          "honeypot.py",         False,
     "Jebak penyerang dengan layanan palsu"),
    ("wifi",     "WiFi Analyzer",     "wifi_analyzer.py",    True,
     "Deteksi rogue AP & ancaman WiFi"),
    # Batch 4 — Lindungi
    ("vault",    "Vault",             "vault.py",            False,
     "Simpan password dengan enkripsi AES-256"),
    ("backup",   "Secure Backup",     "secure_backup.py",    False,
     "Backup terenkripsi otomatis"),
    ("verify",   "Hash Verifier",     "hash_verifier.py",    False,
     "Pantau integritas file sistem"),
    ("privacy",  "Privacy Audit",     "privacy_audit.py",    False,
     "Cek DNS leak, metadata & privasi"),
    # Batch 5 — Investigasi & Pantau
    ("forensics","Log Forensics",     "log_forensics.py",    False,
     "Rekonstruksi timeline serangan"),
    ("intel",    "Threat Intel",      "threat_intel.py",     False,
     "Investigasi IP & domain mencurigakan"),
    ("incident", "Incident Response", "incident_response.py",True,
     "Panduan respons insiden step-by-step"),
    # Batch 5 — Kelola & Pantau
    ("port",     "Port Guardian",     "port_guardian.py",    False,
     "Pantau port terbuka & alert perubahan"),
    ("users",    "User Auditor",      "user_auditor.py",     False,
     "Audit akun, privilege, SSH keys, anomali"),
    ("dashboard","Dashboard",         "dashboard.py",        False,
     "Terminal security dashboard real-time"),
    ("health",   "Health Score",      "health_score.py",     False,
     "Skor keamanan sistem 0-100 dengan grade A-F"),
    ("report",   "Report Engine",     "report_engine.py",    False,
     "Laporan keamanan komprehensif (HTML/JSON/TXT)"),
    # Setup
    ("setup",    "Setup Wizard",      "setup_wizard.py",     False,
     "Konfigurasi awal Selene"),
]

# ── Status checker ────────────────────────────────────────────────────────────
def get_tool_status() -> dict:
    """Cek status setiap tool (tersedia/tidak)."""
    status = {}
    for key, name, fname, needs_root, _ in TOOLS:
        script = SCRIPTS_DIR / fname
        status[key] = {
            "name":        name,
            "file":        fname,
            "available":   script.exists(),
            "needs_root":  needs_root,
        }
    return status

def get_quick_stats() -> dict:
    """Dapatkan statistik cepat dari semua logs."""
    stats = {
        "alerts_24h": 0,
        "blocked_ips": 0,
        "last_scan":   None,
        "last_backup": None,
    }

    # Alerts 24 jam
    try:
        from datetime import timedelta
        entries = read_jsonl(LOGS_DIR / "alerts.jsonl", last_n=200)
        cutoff  = datetime.now() - timedelta(hours=24)
        stats["alerts_24h"] = sum(
            1 for e in entries
            if e.get("timestamp") and
               datetime.fromisoformat(e["timestamp"]) > cutoff
        )
    except Exception:
        pass

    # Last scan
    try:
        reports = sorted((SELENE_ROOT/"reports").glob("scan_*.json"), reverse=True)
        if reports:
            stats["last_scan"] = datetime.fromtimestamp(
                reports[0].stat().st_mtime
            ).strftime("%d/%m/%Y %H:%M")
    except Exception:
        pass

    # Last backup
    try:
        entries = read_jsonl(LOGS_DIR / "backup_log.jsonl", last_n=1)
        if entries:
            ts = entries[-1].get("timestamp","")
            if ts:
                stats["last_backup"] = ts[:16]
    except Exception:
        pass

    return stats

# ── Display helpers ───────────────────────────────────────────────────────────
def print_status_bar() -> None:
    """Tampilkan status bar di atas menu."""
    stats = get_quick_stats()
    cfg   = get_config()

    try:
        import psutil
        cpu   = psutil.cpu_percent(interval=0.3)
        mem   = psutil.virtual_memory().percent
        sysinfo = c(f"CPU: {cpu:.0f}%  RAM: {mem:.0f}%", Fore.WHITE)
    except ImportError:
        sysinfo = c("psutil tidak tersedia", Fore.WHITE)

    alert_color = Fore.RED if stats["alerts_24h"] > 0 else Fore.GREEN
    alert_str   = c(f"Alert 24h: {stats['alerts_24h']}", alert_color)
    setup_done  = cfg.is_setup_done()
    setup_str   = c("Terkonfigurasi", Fore.GREEN) if setup_done else c("Belum setup!", Fore.RED)

    print(c(f"\n  ╔{'═'*58}╗", Fore.BLUE))
    print(c(f"  ║  {get_hostname():<20}  {sysinfo}  {alert_str}", Fore.BLUE))
    print(c(f"  ║  IP: {get_local_ip():<18}  {setup_str}", Fore.BLUE))

    if stats["last_scan"]:
        print(c(f"  ║  Scan terakhir: {stats['last_scan']}", Fore.BLUE))
    if stats["last_backup"]:
        print(c(f"  ║  Backup terakhir: {stats['last_backup']}", Fore.BLUE))

    print(c(f"  ╚{'═'*58}╝", Fore.BLUE))

def print_menu(tool_status: dict) -> None:
    """Tampilkan menu tools."""
    categories = [
        ("KENALI",      ["scan", "profile"]),
        ("CEGAH",       ["vuln", "harden", "cred"]),
        ("DETEKSI",     ["monitor", "honeypot", "wifi"]),
        ("LINDUNGI",    ["vault", "backup", "verify", "privacy"]),
        ("INVESTIGASI", ["forensics", "intel", "incident"]),
        ("KELOLA",      ["port", "users"]),
        ("PANTAU",      ["dashboard", "health", "report"]),
        ("KONFIGURASI", ["setup"]),
    ]

    for cat_name, keys in categories:
        print(c(f"\n  {'─'*58}", Fore.BLUE))
        print(c(f"  {cat_name}", Fore.YELLOW, bold=True))

        for key in keys:
            ts = tool_status.get(key, {})
            if not ts:
                continue

            name      = ts["name"]
            available = ts["available"]
            needs_root= ts["needs_root"]

            # Warna dan status
            if not available:
                status_mark = c("[BELUM ADA]", Fore.WHITE)
                key_color   = Fore.WHITE
            elif needs_root and not IS_ROOT:
                status_mark = c("[BUTUH ROOT]", Fore.YELLOW)
                key_color   = Fore.YELLOW
            else:
                status_mark = c("[OK]", Fore.GREEN)
                key_color   = Fore.CYAN

            # Cari deskripsi
            desc = ""
            for t in TOOLS:
                if t[0] == key:
                    desc = t[4]
                    break

            print(c(f"    {key:<12}", key_color) +
                  c(f" {name:<22}", Fore.WHITE) +
                  c(f" {status_mark}", Fore.WHITE) +
                  c(f"  {desc}", Fore.WHITE))

    print(c(f"\n  {'─'*58}", Fore.BLUE))
    print(c("    q/exit        Keluar", Fore.WHITE))

# ── Tool runner ───────────────────────────────────────────────────────────────
def run_tool(key: str, extra_args: list = None) -> int:
    """Jalankan tool berdasarkan key."""
    # Cari tool
    tool_info = None
    for t in TOOLS:
        if t[0] == key:
            tool_info = t
            break

    if not tool_info:
        log("ERROR", f"Tool tidak dikenal: {key}")
        return 1

    _, name, fname, needs_root, _ = tool_info
    script = SCRIPTS_DIR / fname

    if not script.exists():
        print(c(f"\n  ⚠  Tool '{name}' belum tersedia.", Fore.YELLOW))
        print(c(f"     File yang diharapkan: scripts/{fname}", Fore.WHITE))
        print(c(f"     Tool ini akan tersedia di update berikutnya.", Fore.WHITE))
        return 1

    if needs_root and not IS_ROOT:
        print(c(f"\n  ⚡ '{name}' membutuhkan root/administrator.", Fore.YELLOW, bold=True))
        if IS_WINDOWS:
            print(c("     Jalankan Command Prompt sebagai Administrator.", Fore.WHITE))
        else:
            print(c(f"     Jalankan: sudo python scripts/{fname}", Fore.WHITE))
        return 1

    cmd = [sys.executable, str(script)] + (extra_args or [])
    print(c(f"\n  Menjalankan: {name}...\n", Fore.CYAN))

    try:
        result = subprocess.run(cmd)
        return result.returncode
    except KeyboardInterrupt:
        print()
        log("INFO", f"{name} dihentikan.")
        return 0
    except Exception as e:
        log("ERROR", f"Gagal menjalankan {name}: {e}")
        return 1

# ── Show status ───────────────────────────────────────────────────────────────
def show_status() -> None:
    """Tampilkan status semua tools."""
    log_header("Selene — Status Tools")

    tool_status = get_tool_status()
    available   = sum(1 for t in tool_status.values() if t["available"])
    total       = len(tool_status)

    print(c(f"\n  Tools tersedia: {available}/{total}", Fore.WHITE))

    if available < total:
        print(c(f"\n  Tools yang belum tersedia:", Fore.YELLOW))
        for key, ts in tool_status.items():
            if not ts["available"]:
                print(c(f"    • {ts['name']} (scripts/{ts['file']})", Fore.WHITE))

    print_menu(tool_status)

# ── Interactive menu ──────────────────────────────────────────────────────────
def interactive_menu() -> None:
    """Menu interaktif utama."""
    cfg        = get_config()
    tool_status = get_tool_status()

    # Cek setup
    if not cfg.is_setup_done():
        print(c("\n  Selene belum dikonfigurasi.", Fore.YELLOW, bold=True))
        print(c("  Disarankan untuk menjalankan setup wizard dulu.\n", Fore.WHITE))
        if confirm("Jalankan setup wizard sekarang?", default=True):
            run_tool("setup")
            return

    while True:
        log_header("Selene Security Suite v3.0", "🌙 Penjaga Keamananmu")
        print_status_bar()
        print_menu(tool_status)

        print()
        try:
            choice = input(c("  Pilih tool (ketik key): ", Fore.YELLOW)).strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if not choice:
            continue

        if choice in ("q", "quit", "exit", "keluar"):
            break

        if choice == "status":
            show_status()
            input(c("\n  Tekan Enter untuk kembali...", Fore.WHITE))
            continue

        # Cek apakah valid
        valid_keys = [t[0] for t in TOOLS]
        if choice not in valid_keys:
            log("WARN", f"Tool tidak dikenal: '{choice}'")
            time.sleep(1)
            continue

        # Jalankan
        run_tool(choice)
        print()
        try:
            input(c("  Tekan Enter untuk kembali ke menu...", Fore.WHITE))
        except (KeyboardInterrupt, EOFError):
            break

    print(c("\n  Terima kasih telah menggunakan Selene. Sampai jumpa!\n", Fore.CYAN))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Selene Security Suite — Entry Point",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/selene.py               # Menu interaktif
  python scripts/selene.py setup         # Setup wizard
  python scripts/selene.py scan          # Scan jaringan
  python scripts/selene.py scan --quick  # Scan cepat
  python scripts/selene.py status        # Status semua tools
  python scripts/selene.py monitor       # IDS (butuh sudo)"""
    )
    parser.add_argument("tool", nargs="?",
                        help="Nama tool yang ingin dijalankan")
    parser.add_argument("tool_args", nargs=argparse.REMAINDER,
                        help="Argumen untuk tool tersebut")
    parser.add_argument("--status", action="store_true",
                        help="Tampilkan status semua tools")
    args = parser.parse_args()

    if args.status:
        show_status()
        return

    if not args.tool:
        interactive_menu()
        return

    if args.tool == "status":
        show_status()
        return

    rc = run_tool(args.tool, args.tool_args)
    sys.exit(rc)

if __name__ == "__main__":
    main()
