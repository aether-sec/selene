#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Security Hardener v3.0                            ║
║   Scan malware, tutup celah, dan perkuat sistem.             ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  sudo python scripts/security_hardener.py
  sudo python scripts/security_hardener.py --scan-only
  sudo python scripts/security_hardener.py --auto
  sudo python scripts/security_hardener.py --check-ssh

Catatan: Membutuhkan root untuk menerapkan perubahan.
         Mode --scan-only bisa dijalankan tanpa root.
"""

import sys
import os
import re
import subprocess
import shutil
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        require_root, confirm,
        write_alert, save_json, Spinner,
        IS_LINUX, IS_WINDOWS, IS_ANDROID, IS_ROOT,
        REPORTS_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION = "3.0.0"

# ── Warna severity ────────────────────────────────────────────────────────────
SEV = {
    "KRITIS": Fore.RED,
    "TINGGI": Fore.RED,
    "SEDANG": Fore.YELLOW,
    "INFO":   Fore.CYAN,
}

# ── Database pattern berbahaya ────────────────────────────────────────────────

# Nama proses mencurigakan (regex)
SUSPICIOUS_PROC_PATTERNS = [
    (r"^(xmrig|minerd|cpuminer|kworkerds|kswapd0|kdevtmpfsi)$",
     "Crypto miner terdeteksi"),
    (r"^(msfconsole|msfvenom|meterpreter|empire|cobalt)$",
     "Hacking tool terdeteksi"),
    (r"\.sh$",                        "Shell script berjalan sebagai proses"),
    (r"(python|perl|ruby)\d* -c ",   "Interpreter menjalankan kode inline"),
    (r"/tmp/\w{6,}$",                 "Proses berjalan dari /tmp"),
    (r"/dev/shm/\w+$",               "Proses berjalan dari /dev/shm"),
]

# Port yang mengindikasikan backdoor jika ada koneksi ke luar
BACKDOOR_PORTS = {4444, 4445, 31337, 12345, 1337, 6666, 8888, 9999, 1234}

# Pola webshell dalam file web
WEBSHELL_PATTERNS = [
    (rb"eval\s*\(\s*base64_decode",      "PHP eval+base64"),
    (rb"eval\s*\(\s*gzinflate",          "PHP eval+gzinflate"),
    (rb"eval\s*\(\s*str_rot13",          "PHP eval+rot13"),
    (rb"\$_(?:GET|POST|REQUEST)\s*\[.{1,30}\]\s*\(",  "PHP shell via GET/POST"),
    (rb"exec\s*\(\s*\$_(GET|POST)",      "PHP exec via input"),
    (rb"system\s*\(\s*\$_(GET|POST)",    "PHP system via input"),
    (rb"passthru\s*\(\s*\$_(GET|POST)",  "PHP passthru via input"),
    (rb"shell_exec\s*\(\s*\$_(GET|POST)","PHP shell_exec via input"),
    (rb"\$\{jndi:",                       "Log4Shell payload"),
    (rb"os\.system\s*\(\s*request\.",    "Python shell via request"),
    (rb"<\?php.*eval.*\$_(GET|POST)",    "PHP one-liner webshell"),
]

# Lokasi persistence yang dicek
PERSISTENCE_PATHS = [
    "/etc/cron.d", "/etc/cron.daily", "/etc/cron.weekly",
    "/var/spool/cron", "/etc/rc.local", "/etc/profile.d",
    "/root/.bashrc", "/root/.bash_profile", "/root/.profile",
    "/root/.ssh/authorized_keys", "/etc/ssh/authorized_keys",
]

# Setting SSH yang direkomendasikan
SSH_RECOMMENDED = {
    "PermitRootLogin":       "no",
    "PasswordAuthentication":"no",
    "MaxAuthTries":          "3",
    "LoginGraceTime":        "30",
    "AllowTcpForwarding":    "no",
    "X11Forwarding":         "no",
    "PermitEmptyPasswords":  "no",
}

# Perintah yang mencurigakan di file startup/cron
SUSPICIOUS_CMDS = [
    "curl ", "wget ", "nc ", "ncat ", "python3 -c",
    "bash -i", "sh -i", "/dev/tcp/", "/dev/udp/",
    "chmod 777", "chmod +x /tmp", "base64 -d",
]

# ── Scanner functions ─────────────────────────────────────────────────────────

def scan_processes() -> List[Dict]:
    """Scan proses berjalan untuk mendeteksi malware."""
    findings = []
    if not HAS_PSUTIL:
        log("INFO", "psutil tidak tersedia — scan proses dilewati")
        return findings

    try:
        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "username", "cpu_percent", "exe"]
        ):
            try:
                info    = proc.info
                name    = info.get("name") or ""
                cmdline = " ".join(info.get("cmdline") or [])
                exe     = info.get("exe") or ""
                user    = info.get("username") or ""

                # Cek nama proses
                for pattern, reason in SUSPICIOUS_PROC_PATTERNS:
                    if re.search(pattern, name, re.I) or re.search(pattern, cmdline, re.I):
                        findings.append({
                            "type":     "suspicious_process",
                            "severity": "TINGGI",
                            "pid":      info["pid"],
                            "name":     name,
                            "cmdline":  cmdline[:120],
                            "user":     user,
                            "reason":   reason,
                        })
                        break

                # CPU sangat tinggi → kemungkinan miner
                cpu = info.get("cpu_percent") or 0
                if cpu > 85 and name not in ("python3","python","java","node"):
                    findings.append({
                        "type":     "high_cpu",
                        "severity": "SEDANG",
                        "pid":      info["pid"],
                        "name":     name,
                        "cpu":      cpu,
                        "reason":   f"Penggunaan CPU sangat tinggi ({cpu:.0f}%) — kemungkinan miner",
                    })

                # Koneksi ke port backdoor
                try:
                    for conn in proc.net_connections():
                        if conn.raddr and conn.raddr.port in BACKDOOR_PORTS:
                            findings.append({
                                "type":       "backdoor_connection",
                                "severity":   "KRITIS",
                                "pid":        info["pid"],
                                "name":       name,
                                "remote":     f"{conn.raddr.ip}:{conn.raddr.port}",
                                "reason":     f"Koneksi aktif ke port backdoor {conn.raddr.port}",
                            })
                except (psutil.AccessDenied, AttributeError):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    except Exception as e:
        log("WARN", f"Scan proses sebagian: {e}")

    return findings


def scan_network_connections() -> List[Dict]:
    """Scan koneksi jaringan aktif."""
    findings = []
    if not HAS_PSUTIL:
        return findings

    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            rport = conn.raddr.port
            rip   = conn.raddr.ip

            if rport in BACKDOOR_PORTS:
                proc_name = "?"
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass
                findings.append({
                    "type":      "backdoor_conn",
                    "severity":  "KRITIS",
                    "remote_ip": rip,
                    "remote_port": rport,
                    "pid":       conn.pid,
                    "process":   proc_name,
                    "reason":    f"Koneksi ke port backdoor {rport} ({rip})",
                })
    except Exception:
        pass

    return findings


def scan_webshells(directories: List[str] = None) -> List[Dict]:
    """Scan file web untuk pola webshell."""
    findings = []
    if not IS_LINUX or IS_ANDROID:
        return findings

    if directories is None:
        directories = ["/var/www", "/srv/www", "/home", "/tmp", "/var/tmp"]

    WEB_EXT = {".php",".php3",".php4",".php5",".phtml",
                ".asp",".aspx",".jsp",".py"}
    scanned = 0

    for dir_str in directories:
        dp = Path(dir_str)
        if not dp.exists():
            continue
        try:
            for fpath in dp.rglob("*"):
                if not fpath.is_file():
                    continue
                if fpath.suffix.lower() not in WEB_EXT:
                    continue
                scanned += 1
                try:
                    content = fpath.read_bytes()[:10240]
                    for pattern, desc in WEBSHELL_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                            findings.append({
                                "type":     "webshell",
                                "severity": "KRITIS",
                                "path":     str(fpath),
                                "size":     fpath.stat().st_size,
                                "modified": datetime.fromtimestamp(
                                    fpath.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                                "reason":   f"Pola webshell: {desc}",
                            })
                            break
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    log("INFO", f"File web di-scan: {scanned}")
    return findings


def scan_persistence() -> List[Dict]:
    """Cek lokasi persistence untuk backdoor."""
    findings = []
    if not IS_LINUX:
        return findings

    for loc in PERSISTENCE_PATHS:
        p = Path(loc)
        if not p.exists():
            continue

        items = [p] if p.is_file() else list(p.iterdir())
        for item in items:
            if not item.is_file():
                continue
            try:
                content = item.read_text(errors="ignore")
                for cmd in SUSPICIOUS_CMDS:
                    if cmd in content:
                        findings.append({
                            "type":     "persistence_backdoor",
                            "severity": "TINGGI",
                            "path":     str(item),
                            "trigger":  cmd.strip(),
                            "reason":   f"Perintah mencurigakan '{cmd.strip()}' di lokasi persistence",
                        })
                        break
            except (PermissionError, OSError, UnicodeDecodeError):
                pass

    return findings


def audit_ssh() -> List[Dict]:
    """Audit konfigurasi SSH."""
    findings = []
    sshd = Path("/etc/ssh/sshd_config")
    if not sshd.exists():
        return findings

    try:
        content = sshd.read_text(errors="ignore")
    except (PermissionError, OSError):
        log("WARN", "Tidak bisa baca sshd_config (tidak ada izin)")
        return findings

    current = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            current[parts[0]] = parts[1]

    for setting, recommended in SSH_RECOMMENDED.items():
        actual = current.get(setting, "not_set")
        if actual.lower() != recommended.lower():
            sev = "TINGGI" if setting in ("PermitRootLogin","PermitEmptyPasswords") else "SEDANG"
            findings.append({
                "type":        "ssh_config",
                "severity":    sev,
                "setting":     setting,
                "current":     actual,
                "recommended": recommended,
                "reason":      f"SSH {setting}: '{actual}' → seharusnya '{recommended}'",
            })

    return findings


def check_suid_files() -> List[Dict]:
    """Cari file SUID yang tidak wajar (Linux)."""
    findings = []
    if not IS_LINUX or IS_ANDROID:
        return findings

    # SUID yang normal dan diizinkan
    NORMAL_SUID = {
        "/usr/bin/sudo","/usr/bin/passwd","/usr/bin/su",
        "/usr/bin/ping","/usr/bin/mount","/usr/bin/umount",
        "/usr/sbin/pppd","/bin/ping","/bin/su","/bin/mount",
        "/sbin/mount.nfs","/usr/bin/newgrp","/usr/bin/chfn",
        "/usr/bin/chsh","/usr/bin/gpasswd",
    }

    try:
        out = subprocess.check_output(
            ["find", "/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f"],
            stderr=subprocess.DEVNULL, timeout=15
        ).decode(errors="ignore")

        for path_str in out.splitlines():
            path_str = path_str.strip()
            if not path_str or path_str in NORMAL_SUID:
                continue
            findings.append({
                "type":     "suspicious_suid",
                "severity": "SEDANG",
                "path":     path_str,
                "reason":   f"File SUID tidak dikenal: {path_str}",
            })

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    except Exception as e:
        log("INFO", f"SUID scan: {e}")

    return findings


# ── Hardening actions ─────────────────────────────────────────────────────────

def _cmd(args: List[str], timeout: int = 10) -> bool:
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


def apply_ufw_rules() -> List[str]:
    """Aktifkan UFW firewall dengan aturan dasar."""
    applied = []
    if not IS_LINUX or IS_ANDROID or not shutil.which("ufw"):
        return applied

    if _cmd(["ufw", "--force", "enable"]):
        applied.append("UFW firewall diaktifkan")
    if _cmd(["ufw", "default", "deny", "incoming"]):
        applied.append("Default policy: tolak semua koneksi masuk")
    if _cmd(["ufw", "default", "allow", "outgoing"]):
        applied.append("Default policy: izinkan semua koneksi keluar")
    if _cmd(["ufw", "allow", "ssh"]):
        applied.append("SSH (port 22) diizinkan melalui firewall")

    # Blokir port berbahaya yang umum
    for port in [23, 135, 139]:
        if _cmd(["ufw", "deny", str(port)]):
            applied.append(f"Port {port} diblokir")

    return applied


def apply_iptables_rules() -> List[str]:
    """Terapkan aturan iptables dasar."""
    applied = []
    if not IS_ROOT or not shutil.which("iptables"):
        return applied

    # Blokir Telnet
    if _cmd(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "23", "-j", "DROP"]):
        applied.append("Telnet (port 23) diblokir via iptables")

    return applied


def harden_ssh_config() -> List[str]:
    """Terapkan konfigurasi SSH yang lebih aman."""
    applied  = []
    sshd_cfg = Path("/etc/ssh/sshd_config")

    if not sshd_cfg.exists() or not IS_ROOT:
        return applied

    # Backup dulu
    backup = Path("/etc/ssh/sshd_config.selene.bak")
    try:
        import shutil as sh
        sh.copy2(str(sshd_cfg), str(backup))
        applied.append(f"Backup dibuat: {backup}")
    except Exception:
        pass

    try:
        content = sshd_cfg.read_text(errors="ignore")
        for setting, value in SSH_RECOMMENDED.items():
            pattern = rf"^#?\s*{re.escape(setting)}\s+.*$"
            new_line = f"{setting} {value}"
            if re.search(pattern, content, re.MULTILINE):
                content = re.sub(pattern, new_line, content, flags=re.MULTILINE)
            else:
                content += f"\n{new_line}\n"
            applied.append(f"SSH: {setting} = {value}")

        sshd_cfg.write_text(content)

        # Restart SSH
        for svc in ("sshd", "ssh"):
            if _cmd(["systemctl", "restart", svc]):
                applied.append(f"SSH service ({svc}) di-restart")
                break

    except (PermissionError, OSError) as e:
        log("WARN", f"Gagal hardening SSH: {e}")

    return applied


def quarantine_file(path: str) -> bool:
    """Pindahkan file mencurigakan ke quarantine (tidak dihapus)."""
    quarantine_dir = Path("/tmp/selene_quarantine")
    quarantine_dir.mkdir(mode=0o700, exist_ok=True)

    src = Path(path)
    if not src.exists():
        return False
    try:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        dst = quarantine_dir / f"{ts}_{src.name}"
        src.rename(dst)
        log("OK", f"Dipindah ke quarantine: {dst}")
        return True
    except (PermissionError, OSError) as e:
        log("WARN", f"Gagal quarantine {path}: {e}")
        return False


def kill_process(pid: int) -> bool:
    """Hentikan proses berbahaya."""
    try:
        if HAS_PSUTIL:
            psutil.Process(pid).terminate()
            time.sleep(0.5)
            try:
                psutil.Process(pid).kill()
            except psutil.NoSuchProcess:
                pass
            return True
        else:
            os.kill(pid, 9)
            return True
    except Exception as e:
        log("WARN", f"Gagal hentikan PID {pid}: {e}")
        return False


# ── Display helpers ───────────────────────────────────────────────────────────

def print_findings_section(title: str, findings: List[Dict]) -> None:
    if not findings:
        log("OK", f"{title}: Bersih")
        return

    log("WARN", c(f"{title}: {len(findings)} temuan", Fore.YELLOW, bold=True))
    for f in findings:
        sev   = f.get("severity", "INFO")
        color = SEV.get(sev, Fore.WHITE)
        print(c(f"\n    [{sev}] {f.get('reason','?')}", color, bold=(sev == "KRITIS")))

        if "path" in f:
            print(c(f"      Path: {f['path']}", Fore.WHITE))
        if "pid" in f:
            print(c(f"      PID: {f['pid']}  Proses: {f.get('name','?')}", Fore.WHITE))
        if "remote" in f:
            print(c(f"      Remote: {f['remote']}", Fore.WHITE))
        if "setting" in f:
            print(c(f"      {f['setting']}: {f['current']} → {f['recommended']}", Fore.WHITE))


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Security Hardener — Scan malware & hardening sistem",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  sudo python scripts/security_hardener.py
  python scripts/security_hardener.py --scan-only
  sudo python scripts/security_hardener.py --auto
  sudo python scripts/security_hardener.py --check-ssh"""
    )
    parser.add_argument("--scan-only", action="store_true",
                        help="Hanya scan, tidak ubah apapun")
    parser.add_argument("--auto",      action="store_true",
                        help="Terapkan semua perbaikan otomatis tanpa konfirmasi")
    parser.add_argument("--check-ssh", action="store_true",
                        help="Hanya audit dan hardening SSH")
    parser.add_argument("--no-web",    action="store_true",
                        help="Skip scan webshell (lebih cepat)")
    args = parser.parse_args()

    log_header(
        "Selene — Security Hardener v3.0",
        "Scan malware, tutup celah, perkuat sistem"
    )

    can_fix = IS_ROOT and not args.scan_only
    if not IS_ROOT:
        log("INFO", "Berjalan tanpa root — hanya mode scan (tidak bisa terapkan perbaikan)")
        log("INFO", "Jalankan dengan sudo untuk perbaikan otomatis")

    all_findings: Dict[str, List[Dict]] = {}

    # ── Mode check-ssh saja ───────────────────────────────────────────────────
    if args.check_ssh:
        log_section("AUDIT SSH")
        ssh_findings = audit_ssh()
        all_findings["SSH"] = ssh_findings
        print_findings_section("Konfigurasi SSH", ssh_findings)

        if ssh_findings and can_fix:
            if args.auto or confirm("Terapkan hardening SSH?", default=True):
                log_section("HARDENING SSH")
                for action in harden_ssh_config():
                    log("OK", action)
        print(); return

    # ── Scan lengkap ──────────────────────────────────────────────────────────

    log_section("1 — SCAN PROSES")
    with Spinner("Memeriksa proses berjalan..."):
        proc_f = scan_processes()
    all_findings["Proses"] = proc_f
    print_findings_section("Proses", proc_f)

    log_section("2 — SCAN KONEKSI JARINGAN")
    with Spinner("Memeriksa koneksi aktif..."):
        conn_f = scan_network_connections()
    all_findings["Koneksi"] = conn_f
    print_findings_section("Koneksi", conn_f)

    if IS_LINUX and not IS_ANDROID and not args.no_web:
        log_section("3 — SCAN WEBSHELL")
        with Spinner("Mencari webshell di direktori web..."):
            shell_f = scan_webshells()
        all_findings["Webshell"] = shell_f
        print_findings_section("Webshell", shell_f)

    log_section("4 — SCAN PERSISTENCE")
    with Spinner("Memeriksa lokasi persistence..."):
        persist_f = scan_persistence()
    all_findings["Persistence"] = persist_f
    print_findings_section("Persistence", persist_f)

    if IS_LINUX and not IS_ANDROID:
        log_section("5 — AUDIT SSH")
        ssh_f = audit_ssh()
        all_findings["SSH"] = ssh_f
        print_findings_section("SSH", ssh_f)

        log_section("6 — SCAN FILE SUID")
        with Spinner("Mencari file SUID mencurigakan..."):
            suid_f = check_suid_files()
        all_findings["SUID"] = suid_f
        print_findings_section("File SUID", suid_f)

    # ── Ringkasan ─────────────────────────────────────────────────────────────
    log_section("RINGKASAN")

    total_f  = sum(len(v) for v in all_findings.values())
    kritis_f = sum(1 for v in all_findings.values()
                   for f in v if f.get("severity") == "KRITIS")
    tinggi_f = sum(1 for v in all_findings.values()
                   for f in v if f.get("severity") == "TINGGI")

    print(c(f"\n  Total temuan  : {total_f}",  Fore.WHITE))
    print(c(f"  KRITIS        : {kritis_f}",
            Fore.RED if kritis_f else Fore.GREEN, bold=bool(kritis_f)))
    print(c(f"  TINGGI        : {tinggi_f}",
            Fore.RED if tinggi_f else Fore.GREEN))

    if not total_f:
        log("OK", c("Sistem terlihat bersih! Tidak ada ancaman ditemukan.", Fore.GREEN, bold=True))

    # ── Terapkan perbaikan ────────────────────────────────────────────────────
    if total_f > 0 and can_fix:
        print()
        do_fix = args.auto or confirm("Terapkan perbaikan otomatis?", default=True)

        if do_fix:
            log_section("MENERAPKAN PERBAIKAN")
            all_actions = []

            # Firewall
            if shutil.which("ufw"):
                for a in apply_ufw_rules():
                    log("OK", a); all_actions.append(a)
            else:
                for a in apply_iptables_rules():
                    log("OK", a); all_actions.append(a)

            # Hardening SSH
            if all_findings.get("SSH"):
                if args.auto or confirm("Hardening konfigurasi SSH?", default=True):
                    for a in harden_ssh_config():
                        log("OK", a); all_actions.append(a)

            # Quarantine webshell
            for f in all_findings.get("Webshell", []):
                if args.auto or confirm(
                    f"Quarantine {Path(f['path']).name}?", default=True
                ):
                    if quarantine_file(f["path"]):
                        all_actions.append(f"Quarantine: {f['path']}")

            # Kill proses backdoor
            for f in all_findings.get("Proses", []):
                if f.get("severity") == "KRITIS" and f.get("pid"):
                    if args.auto or confirm(
                        f"Hentikan PID {f['pid']} ({f.get('name','?')})?", default=True
                    ):
                        if kill_process(f["pid"]):
                            all_actions.append(f"Proses dihentikan: PID {f['pid']}")

            log("OK", c(f"\n  {len(all_actions)} perbaikan diterapkan.", Fore.GREEN, bold=True))

    # ── Simpan laporan ────────────────────────────────────────────────────────
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"hardener_{ts}.json"
    save_json(path, {
        "tool":      "security_hardener",
        "version":   TOOL_VERSION,
        "scan_time": datetime.now().isoformat(),
        "findings":  {k: v for k, v in all_findings.items()},
        "total":     total_f,
    })
    log("OK", c(f"Laporan: reports/hardener_{ts}.json", Fore.GREEN))

    # Alert kritis
    for v in all_findings.values():
        for f in v:
            if f.get("severity") == "KRITIS":
                write_alert("CRIT", f"Hardener: {f['reason']}", details=f)

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
