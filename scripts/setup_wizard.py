#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Setup Wizard v3.0                                 ║
║   Konfigurasi Selene dengan panduan langkah demi langkah.    ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/setup_wizard.py
  python scripts/setup_wizard.py --reset   (mulai ulang konfigurasi)
"""

import sys
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore, Style,
        IS_LINUX, IS_WINDOWS, IS_ANDROID, IS_ROOT,
        confirm, prompt, prompt_password,
        check_binary, get_local_ip, get_hostname,
        save_json, SELENE_DIR,
    )
    from selene.core.network import (
        get_network_range, get_default_gateway, arp_scan,
        HAS_PSUTIL, HAS_SCAPY,
    )
    from selene.core.config import get_config
    from selene.core.crypto import HAS_CRYPTO
except ImportError as e:
    print(f"\n  [ERROR] Gagal memuat selene.core: {e}")
    print("  Pastikan kamu berada di direktori root Selene.")
    print("  Contoh: cd selene_v3 && python scripts/setup_wizard.py\n")
    sys.exit(1)

# ── Dependency check ──────────────────────────────────────────────────────────
REQUIRED_PKGS = {
    "colorama":    "colorama",
    "requests":    "requests",
    "psutil":      "psutil",
    "cryptography":"cryptography",
}

OPTIONAL_PKGS = {
    "scapy":       "scapy",
    "nmap":        None,  # binary, bukan pip
}

def check_all_deps() -> tuple:
    """
    Cek semua dependency. Returns (missing_required, missing_optional).
    """
    missing_req = []
    missing_opt = []

    for module, pkg in REQUIRED_PKGS.items():
        try:
            __import__(module)
        except ImportError:
            missing_req.append(pkg)

    # Scapy
    try:
        import scapy
    except ImportError:
        missing_opt.append("scapy")

    # nmap binary
    if not shutil.which("nmap"):
        missing_opt.append("nmap (binary)")

    return missing_req, missing_opt

def install_packages(packages: list) -> bool:
    """Install pip packages."""
    if not packages:
        return True

    print(c(f"\n  Menginstall: {', '.join(packages)}", Fore.CYAN))

    pip_packages = [p for p in packages if not p.endswith("(binary)")]
    if not pip_packages:
        return True

    try:
        cmd = [sys.executable, "-m", "pip", "install"] + pip_packages + ["-q"]
        if IS_LINUX and not IS_ANDROID:
            cmd.append("--break-system-packages")
        result = subprocess.run(cmd, timeout=120)
        if result.returncode == 0:
            log("OK", f"Berhasil install: {', '.join(pip_packages)}")
            return True
        else:
            log("WARN", f"Sebagian package gagal diinstall.")
            return False
    except subprocess.TimeoutExpired:
        log("WARN", "Timeout saat install package.")
        return False
    except Exception as e:
        log("WARN", f"Install gagal: {e}")
        return False

# ── Langkah-langkah wizard ────────────────────────────────────────────────────
def step_welcome() -> None:
    """Tampilkan selamat datang dan penjelasan singkat."""
    print(c("""
  Selamat datang di Selene Security Suite!

  Wizard ini akan memandu kamu mengatur Selene
  untuk pertama kalinya. Prosesnya tidak lama.

  Selene adalah defensive security toolkit yang
  membantu kamu:
    ✓  Memantau ancaman di jaringanmu
    ✓  Menyimpan password dengan aman
    ✓  Backup data terenkripsi otomatis
    ✓  Mendeteksi perubahan file penting
    ✓  Investigasi serangan dengan mudah
""", Fore.WHITE))

def step_check_deps() -> bool:
    """Langkah 1: Cek dan install dependency."""
    log_section("LANGKAH 1 — Cek Dependencies")

    missing_req, missing_opt = check_all_deps()

    # Dependency wajib
    if missing_req:
        print(c(f"\n  Dependency yang kurang: {', '.join(missing_req)}", Fore.YELLOW))
        if confirm("Install otomatis sekarang?", default=True):
            ok = install_packages(missing_req)
            if not ok:
                print(c("\n  Gagal install otomatis. Install manual:", Fore.RED))
                print(c(f"  pip install {' '.join(missing_req)}", Fore.WHITE))
                return False
        else:
            print(c(f"\n  Install manual: pip install {' '.join(missing_req)}", Fore.WHITE))
            return False
    else:
        log("OK", "Semua dependency wajib tersedia")

    # Dependency opsional
    if missing_opt:
        print(c(f"\n  Dependency opsional yang kurang: {', '.join(missing_opt)}", Fore.WHITE))
        print(c("""
  Catatan:
    • scapy  — untuk ARP scan lebih akurat (butuh root)
    • nmap   — untuk scan port lebih detail
  Tanpa keduanya, Selene tetap berfungsi dengan ping sweep.
""", Fore.WHITE))
        pip_opt = [p for p in missing_opt if not p.startswith("nmap")]
        if pip_opt and confirm(f"Install dependency opsional ({', '.join(pip_opt)})?",
                                default=False):
            install_packages(pip_opt)
    else:
        log("OK", "Semua dependency opsional juga tersedia")

    return True

def step_network_config(cfg) -> bool:
    """Langkah 2: Konfigurasi jaringan."""
    log_section("LANGKAH 2 — Konfigurasi Jaringan")

    local_ip = get_local_ip()
    hostname = get_hostname()
    gateway  = get_default_gateway()
    auto_range = get_network_range()

    print(c(f"""
  Informasi jaringan yang terdeteksi:
    IP Lokal  : {local_ip}
    Hostname  : {hostname}
    Gateway   : {gateway or "tidak terdeteksi"}
    Range LAN : {auto_range}
""", Fore.WHITE))

    # Konfirmasi range atau ubah manual
    use_auto = confirm(f"Gunakan range otomatis ({auto_range})?", default=True)
    if use_auto:
        scan_range = auto_range
    else:
        scan_range = prompt("Masukkan range CIDR", default=auto_range)

    cfg.set("network", "scan_range", scan_range)

    # Gateway
    if gateway:
        cfg.set("network", "gateway", gateway)
        # Otomatis tambah gateway ke trusted IPs
        trusted = cfg.get("network", "trusted_ips", default=[])
        if gateway not in trusted:
            trusted.append(gateway)
            cfg.set("network", "trusted_ips", trusted)

    # IP yang dipercaya (tambahan)
    print(c("""
  IP yang dipercaya tidak akan pernah diblokir oleh auto-block.
  Contoh: IP printer, NAS, CCTV milikmu sendiri.
""", Fore.WHITE))
    if confirm("Tambah IP terpercaya secara manual?", default=False):
        while True:
            ip_input = prompt("IP terpercaya (kosong untuk selesai)").strip()
            if not ip_input:
                break
            trusted = cfg.get("network", "trusted_ips", default=[])
            if ip_input not in trusted:
                trusted.append(ip_input)
                cfg.set("network", "trusted_ips", trusted)
                log("OK", f"Ditambahkan: {ip_input}")

    log("OK", f"Konfigurasi jaringan disimpan: {scan_range}")
    return True

def step_backup_config(cfg) -> bool:
    """Langkah 3: Konfigurasi backup."""
    log_section("LANGKAH 3 — Konfigurasi Backup")

    if not HAS_CRYPTO:
        log("WARN", "Library 'cryptography' tidak tersedia — backup dilewati.")
        return True

    print(c("""
  Backup terenkripsi menjaga data pentingmu aman.
  Bahkan jika komputermu diserang, backup tetap terlindungi.
""", Fore.WHITE))

    if not confirm("Konfigurasi backup sekarang?", default=True):
        log("INFO", "Backup dilewati — bisa dikonfigurasi nanti.")
        return True

    # Direktori yang di-backup
    default_dirs = []
    if IS_LINUX or IS_ANDROID:
        home = str(Path.home())
        default_dirs = [f"{home}/Documents", f"{home}/Desktop"]
    elif IS_WINDOWS:
        home = str(Path.home())
        default_dirs = [f"{home}\\Documents", f"{home}\\Desktop"]

    # Filter yang benar-benar ada
    existing_dirs = [d for d in default_dirs if Path(d).exists()]

    if existing_dirs:
        print(c(f"  Direktori default yang ditemukan:", Fore.WHITE))
        for d in existing_dirs:
            print(c(f"    • {d}", Fore.CYAN))
        use_default = confirm("Gunakan direktori ini?", default=True)
        dirs = existing_dirs if use_default else []
    else:
        dirs = []

    # Direktori tambahan
    if confirm("Tambah direktori lain untuk di-backup?", default=False):
        while True:
            d = prompt("Path direktori (kosong untuk selesai)").strip()
            if not d:
                break
            if Path(d).exists():
                dirs.append(d)
                log("OK", f"Ditambahkan: {d}")
            else:
                log("WARN", f"Direktori tidak ditemukan: {d}")

    if dirs:
        cfg.set("backup", "directories", dirs)

    # Destinasi backup
    default_dest = str(Path.home() / "selene_backups")
    dest = prompt("Direktori tujuan backup", default=default_dest)
    Path(dest).mkdir(parents=True, exist_ok=True)
    cfg.set("backup", "destination", dest)

    # Jadwal
    print(c("""
  Jadwal backup otomatis:
    [1] Setiap hari  (24 jam)
    [2] Setiap 2 hari
    [3] Setiap minggu
    [4] Nonaktif
""", Fore.WHITE))
    choice = prompt("Pilih jadwal", default="1")
    schedule_map = {"1": 24, "2": 48, "3": 168, "4": 0}
    hours = schedule_map.get(choice, 24)
    cfg.set("backup", "schedule_h", hours)

    log("OK", f"Backup: {len(dirs)} direktori → {dest}")
    return True

def step_notification_config(cfg) -> bool:
    """Langkah 4: Konfigurasi notifikasi."""
    log_section("LANGKAH 4 — Notifikasi (Opsional)")

    print(c("""
  Selene bisa mengirim alert langsung ke HP atau email kamu
  ketika mendeteksi ancaman — tanpa kamu harus pantau terus.
""", Fore.WHITE))

    if not confirm("Konfigurasi notifikasi?", default=True):
        log("INFO", "Notifikasi dilewati — bisa dikonfigurasi nanti.")
        return True

    enabled = []

    # Telegram
    print(c("\n  ── Telegram ──────────────────────────────────────", Fore.BLUE))
    print(c("""  Cara buat Telegram bot:
    1. Chat @BotFather di Telegram
    2. Ketik /newbot dan ikuti instruksi
    3. Salin token yang diberikan
    4. Chat bot kamu sekali, lalu dapatkan chat_id dari:
       https://api.telegram.org/bot<TOKEN>/getUpdates
""", Fore.WHITE))

    if confirm("Aktifkan notifikasi Telegram?", default=False):
        token = prompt("Bot token Telegram")
        chat_id = prompt("Chat ID kamu")
        if token and chat_id:
            cfg.set("notifications", "telegram_token", token)
            cfg.set("notifications", "telegram_chat_id", chat_id)
            enabled.append("telegram")

            # Test kirim pesan
            if confirm("Kirim pesan test sekarang?", default=True):
                _test_telegram(token, chat_id)

    # Discord
    print(c("\n  ── Discord ───────────────────────────────────────", Fore.BLUE))
    if confirm("Aktifkan notifikasi Discord webhook?", default=False):
        webhook = prompt("Discord webhook URL")
        if webhook:
            cfg.set("notifications", "discord_webhook", webhook)
            enabled.append("discord")

    cfg.set("notifications", "enabled", enabled)

    if enabled:
        log("OK", f"Notifikasi aktif: {', '.join(enabled)}")
    else:
        log("INFO", "Tidak ada notifikasi yang dikonfigurasi.")

    return True

def _test_telegram(token: str, chat_id: str) -> None:
    try:
        import requests
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id,
                  "text": "🌙 Selene Security Suite berhasil terhubung!"},
            timeout=5
        )
        if r.status_code == 200:
            log("OK", "Pesan test Telegram berhasil dikirim!")
        else:
            log("WARN", f"Telegram error: {r.status_code} — periksa token/chat_id")
    except Exception as e:
        log("WARN", f"Tidak bisa menghubungi Telegram: {e}")

def step_summary(cfg) -> None:
    """Tampilkan ringkasan konfigurasi."""
    log_section("RINGKASAN KONFIGURASI")

    scan_range  = cfg.get("network","scan_range",default="auto")
    trusted     = cfg.get("network","trusted_ips",default=[])
    backup_dirs = cfg.get("backup","directories",default=[])
    backup_dest = cfg.get("backup","destination",default="")
    notif       = cfg.get("notifications","enabled",default=[])

    print(c(f"""
  Jaringan:
    Range scan  : {scan_range}
    IP terpercaya : {len(trusted)} IP

  Backup:
    Direktori   : {len(backup_dirs)} folder
    Tujuan      : {backup_dest or 'belum dikonfigurasi'}
    Jadwal      : {cfg.get("backup","schedule_h",default=24)} jam

  Notifikasi:
    Aktif       : {', '.join(notif) if notif else 'tidak ada'}

  Tools siap digunakan:
    python scripts/selene.py          — Menu utama
    python scripts/network_scanner.py — Scan jaringan
    python scripts/system_profiler.py — Inventaris sistem
""", Fore.WHITE))

def print_next_steps() -> None:
    """Tampilkan panduan langkah selanjutnya."""
    print(c("""
╔══════════════════════════════════════════════════════════════╗
║              Setup selesai! Apa selanjutnya?                ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Mulai dari sini:                                            ║
║    python scripts/selene.py                                 ║
║    → Menu interaktif untuk semua tools                       ║
║                                                              ║
║  Atau langsung pakai tool tertentu:                          ║
║    python scripts/network_scanner.py   — Scan jaringan      ║
║    python scripts/system_profiler.py   — Cek sistem         ║
║                                                              ║
║  Butuh bantuan?                                              ║
║    python scripts/<nama_tool>.py --help                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""", Fore.CYAN))

# ── Main ──────────────────────────────────────────────────────────────────────
def run_wizard(reset: bool = False) -> bool:
    """Jalankan wizard dari awal sampai akhir."""
    cfg = get_config()

    if not reset and cfg.is_setup_done():
        print(c("\n  Setup sudah pernah dijalankan sebelumnya.", Fore.YELLOW))
        if not confirm("Jalankan ulang wizard?", default=False):
            log("INFO", "Setup dilewati. Gunakan --reset untuk konfigurasi ulang.")
            return True

    log_header("Selene — Setup Wizard v3.0", "Konfigurasi awal selene")
    step_welcome()

    # Langkah 1: Dependencies
    if not step_check_deps():
        print(c("\n  Setup dihentikan — install dependency yang kurang terlebih dahulu.", Fore.RED))
        return False

    # Langkah 2: Network
    step_network_config(cfg)

    # Langkah 3: Backup
    step_backup_config(cfg)

    # Langkah 4: Notifikasi
    step_notification_config(cfg)

    # Simpan konfigurasi
    cfg.save()
    cfg.mark_setup_done()

    # Ringkasan
    step_summary(cfg)
    print_next_steps()

    log("OK", c("Setup selesai! Selene siap digunakan.", Fore.GREEN, bold=True))
    return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Selene Setup Wizard")
    parser.add_argument("--reset", action="store_true",
                        help="Reset dan jalankan ulang konfigurasi dari awal")
    args = parser.parse_args()

    success = run_wizard(reset=args.reset)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("INFO", "Setup dibatalkan.")
        sys.exit(1)
