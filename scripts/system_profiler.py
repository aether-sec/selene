#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — System Profiler v3.0                              ║
║   Inventaris sistem: OS, software, user, konfigurasi.        ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/system_profiler.py
  python scripts/system_profiler.py --full
  python scripts/system_profiler.py --export
"""

import sys
import os
import platform
import subprocess
import socket
import json
import getpass
import argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        fmt_bytes, save_json, Spinner,
        IS_LINUX, IS_WINDOWS, IS_ANDROID, IS_ROOT,
        get_local_ip, get_hostname, REPORTS_DIR,
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

def _run(cmd: list, timeout: int = 8) -> str:
    """Jalankan command, kembalikan output sebagai string."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="ignore"
        )
        return (r.stdout + r.stderr).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""

def _run_shell(cmd: str, timeout: int = 8) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout, errors="ignore"
        )
        return r.stdout.strip()
    except Exception:
        return ""

# ── Collectors ────────────────────────────────────────────────────────────────
def collect_system_info() -> dict:
    """Kumpulkan info OS dan hardware."""
    info = {
        "hostname":       get_hostname(),
        "platform":       platform.system(),
        "platform_version": platform.version(),
        "architecture":   platform.machine(),
        "python_version": platform.python_version(),
        "boot_time":      None,
        "uptime_h":       None,
    }

    if HAS_PSUTIL:
        try:
            boot   = psutil.boot_time()
            now    = datetime.now().timestamp()
            uptime = now - boot
            info["boot_time"] = datetime.fromtimestamp(boot).isoformat()
            info["uptime_h"]  = round(uptime / 3600, 1)
        except Exception:
            pass

    # Linux spesifik
    if IS_LINUX:
        # Distribusi
        try:
            for f in ("/etc/os-release", "/etc/lsb-release"):
                if Path(f).exists():
                    content = Path(f).read_text(errors="ignore")
                    for line in content.splitlines():
                        if line.startswith("PRETTY_NAME="):
                            info["distro"] = line.split("=",1)[1].strip('"')
                            break
                    if "distro" in info:
                        break
        except Exception:
            pass

        # Kernel
        info["kernel"] = _run(["uname","-r"])

    return info

def collect_hardware() -> dict:
    """Kumpulkan info hardware."""
    hw = {}

    if not HAS_PSUTIL:
        hw["note"] = "psutil tidak tersedia — install: pip install psutil"
        return hw

    try:
        # CPU
        cpu_freq = psutil.cpu_freq()
        hw["cpu"] = {
            "cores_physical": psutil.cpu_count(logical=False),
            "cores_logical":  psutil.cpu_count(logical=True),
            "usage_percent":  psutil.cpu_percent(interval=0.5),
            "freq_mhz":       round(cpu_freq.current) if cpu_freq else None,
        }

        # Memori
        mem = psutil.virtual_memory()
        hw["memory"] = {
            "total":        fmt_bytes(mem.total),
            "available":    fmt_bytes(mem.available),
            "used":         fmt_bytes(mem.used),
            "percent":      mem.percent,
        }

        # Disk
        disks = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device":    part.device,
                    "mountpoint":part.mountpoint,
                    "fstype":    part.fstype,
                    "total":     fmt_bytes(usage.total),
                    "used":      fmt_bytes(usage.used),
                    "free":      fmt_bytes(usage.free),
                    "percent":   usage.percent,
                })
            except (PermissionError, OSError):
                pass
        hw["disks"] = disks

    except Exception as e:
        hw["error"] = str(e)

    return hw

def collect_network_interfaces() -> list:
    """Kumpulkan semua network interface."""
    ifaces = []

    if not HAS_PSUTIL:
        # Fallback minimal
        try:
            ip = get_local_ip()
            ifaces.append({"name":"default","ip":ip})
        except Exception:
            pass
        return ifaces

    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        io    = psutil.net_io_counters(pernic=True)

        for name, addr_list in addrs.items():
            iface = {"name": name, "ipv4": None, "ipv6": None,
                     "mac": None, "is_up": False, "speed_mb": None}

            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    iface["ipv4"] = addr.address
                elif addr.family == socket.AF_INET6:
                    iface["ipv6"] = addr.address
                elif hasattr(socket, "AF_PACKET") and addr.family == socket.AF_PACKET:
                    iface["mac"] = addr.address

            if name in stats:
                st = stats[name]
                iface["is_up"]    = st.isup
                iface["speed_mb"] = st.speed if st.speed > 0 else None

            # Hanya tampilkan interface yang punya IP atau aktif
            if iface["ipv4"] or iface["is_up"]:
                ifaces.append(iface)

    except Exception:
        pass

    return ifaces

def collect_active_connections() -> list:
    """Kumpulkan koneksi jaringan aktif (hanya ESTABLISHED)."""
    conns = []

    if not HAS_PSUTIL:
        return conns

    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                entry = {
                    "local_port":  conn.laddr.port if conn.laddr else 0,
                    "remote_ip":   conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "pid":         conn.pid,
                    "process":     None,
                }
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        entry["process"] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                conns.append(entry)
    except (psutil.AccessDenied, Exception):
        pass

    return conns

def collect_users() -> list:
    """Kumpulkan daftar user di sistem."""
    users = []

    if IS_LINUX or IS_ANDROID:
        try:
            passwd = Path("/etc/passwd").read_text(errors="ignore")
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) < 7:
                    continue
                username = parts[0]
                uid      = int(parts[2]) if parts[2].isdigit() else -1
                shell    = parts[6].strip()
                home     = parts[5]

                # Hanya tampilkan user nyata (UID >= 1000 atau root)
                is_real = (uid == 0 or uid >= 1000)
                # Atau yang punya shell interaktif
                has_shell = shell in ("/bin/bash","/bin/sh","/bin/zsh",
                                      "/usr/bin/bash","/usr/bin/zsh")
                if is_real or has_shell:
                    users.append({
                        "username": username,
                        "uid":      uid,
                        "home":     home,
                        "shell":    shell,
                        "is_root":  uid == 0,
                    })
        except (PermissionError, OSError):
            pass

    elif IS_WINDOWS:
        out = _run(["net","user"])
        lines = out.splitlines()
        for line in lines[4:-3]:  # skip header/footer
            for uname in line.split():
                if uname:
                    users.append({"username": uname, "platform": "windows"})

    return users

def collect_installed_software() -> list:
    """Kumpulkan software yang terinstall."""
    software = []

    if IS_LINUX and not IS_ANDROID:
        # dpkg (Debian/Ubuntu)
        out = _run_shell("dpkg -l 2>/dev/null | awk '/^ii/{print $2,$3}' | head -100")
        if out:
            for line in out.splitlines()[:50]:
                parts = line.split(None, 1)
                if len(parts) >= 2:
                    software.append({"name": parts[0], "version": parts[1], "pm": "dpkg"})

        # pip packages
        out = _run([sys.executable, "-m", "pip", "list", "--format=columns"])
        if out:
            for line in out.splitlines()[2:30]:
                parts = line.split()
                if len(parts) >= 2:
                    software.append({"name": parts[0], "version": parts[1], "pm": "pip"})

    elif IS_ANDROID:
        out = _run(["pkg","list-installed"])
        for line in out.splitlines()[:30]:
            parts = line.split("/")
            software.append({"name": parts[0].strip(), "version": "?", "pm": "pkg"})

    elif IS_WINDOWS:
        out = _run_shell(
            'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall /s '
            '| findstr "DisplayName DisplayVersion" 2>nul'
        )
        if out:
            names = []
            for line in out.splitlines():
                if "DisplayName" in line:
                    val = line.split(None, 2)[-1].strip()
                    names.append(val)
            software = [{"name": n, "version": "?", "pm": "windows"} for n in names[:30]]

    return software

def collect_security_config() -> dict:
    """Kumpulkan informasi konfigurasi keamanan."""
    sec = {}

    if IS_LINUX and not IS_ANDROID:
        # SSH config
        sshd_conf = Path("/etc/ssh/sshd_config")
        if sshd_conf.exists():
            try:
                content = sshd_conf.read_text(errors="ignore")
                settings = {}
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        settings[parts[0]] = parts[1]

                sec["ssh"] = {
                    "permit_root_login":      settings.get("PermitRootLogin","?"),
                    "password_auth":          settings.get("PasswordAuthentication","?"),
                    "max_auth_tries":         settings.get("MaxAuthTries","?"),
                    "port":                   settings.get("Port","22"),
                    "x11_forwarding":         settings.get("X11Forwarding","?"),
                }
            except (PermissionError, OSError):
                sec["ssh"] = {"error": "tidak bisa baca sshd_config"}

        # Firewall
        ufw_out = _run(["ufw","status"])
        if "Status: active" in ufw_out:
            sec["firewall"] = {"type":"ufw","status":"aktif"}
        else:
            ipt_out = _run(["iptables","-L","-n","--line-numbers"])
            rules   = [l for l in ipt_out.splitlines() if "DROP" in l or "REJECT" in l]
            if rules:
                sec["firewall"] = {"type":"iptables","status":"aktif","rules":len(rules)}
            else:
                sec["firewall"] = {"type":"none","status":"tidak aktif"}

        # Fail2ban
        f2b = _run(["fail2ban-client","status"])
        sec["fail2ban"] = "aktif" if "Number of jail" in f2b else "tidak aktif/tidak terinstall"

        # SELinux / AppArmor
        selinux = _run(["getenforce"])
        if selinux:
            sec["selinux"] = selinux

        apparmor = _run_shell("systemctl is-active apparmor 2>/dev/null")
        if apparmor:
            sec["apparmor"] = apparmor

    elif IS_WINDOWS:
        # Defender
        defs = _run_shell('powershell -Command "Get-MpPreference | Select-Object DisableRealtimeMonitoring" 2>nul')
        if "False" in defs:
            sec["defender"] = "Real-time protection aktif"
        elif "True" in defs:
            sec["defender"] = "Real-time protection NONAKTIF"

    return sec

def check_sudo_permissions() -> list:
    """Cek konfigurasi sudo yang mungkin berbahaya."""
    issues = []

    if not IS_LINUX or IS_ANDROID:
        return issues

    sudoers_files = [Path("/etc/sudoers")]
    sudoers_dir   = Path("/etc/sudoers.d")
    if sudoers_dir.exists():
        sudoers_files += list(sudoers_dir.iterdir())

    for sf in sudoers_files:
        try:
            content = sf.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "NOPASSWD:ALL" in line or "NOPASSWD: ALL" in line:
                    issues.append(f"NOPASSWD:ALL ditemukan di {sf}: {line[:60]}")
                if "ALL=(ALL) ALL" in line and "root" not in line.lower():
                    issues.append(f"Akses sudo penuh untuk non-root: {line[:60]}")
        except (PermissionError, OSError):
            pass

    return issues

# ── Display ───────────────────────────────────────────────────────────────────
def print_profile(profile: dict, full: bool = False) -> None:
    """Cetak profil sistem ke terminal."""

    sys_info = profile.get("system",{})
    hw       = profile.get("hardware",{})
    ifaces   = profile.get("interfaces",[])
    users    = profile.get("users",[])
    conns    = profile.get("active_connections",[])
    sec      = profile.get("security",{})
    software = profile.get("software",[])
    issues   = profile.get("sudo_issues",[])

    # ── Sistem ──────────────────────────────────────────────────────────────
    log_section("INFORMASI SISTEM")
    print(c(f"\n  Hostname    : {sys_info.get('hostname','?')}", Fore.WHITE))
    print(c(f"  Platform    : {sys_info.get('platform','?')}", Fore.WHITE))
    if sys_info.get("distro"):
        print(c(f"  Distribusi  : {sys_info['distro']}", Fore.WHITE))
    if sys_info.get("kernel"):
        print(c(f"  Kernel      : {sys_info['kernel']}", Fore.WHITE))
    print(c(f"  Arsitektur  : {sys_info.get('architecture','?')}", Fore.WHITE))
    if sys_info.get("uptime_h"):
        print(c(f"  Uptime      : {sys_info['uptime_h']} jam", Fore.WHITE))

    # ── Hardware ─────────────────────────────────────────────────────────────
    if hw and "note" not in hw:
        log_section("HARDWARE")
        cpu = hw.get("cpu",{})
        mem = hw.get("memory",{})
        if cpu:
            print(c(f"\n  CPU   : {cpu.get('cores_logical','?')} core  "
                    f"Usage: {cpu.get('usage_percent','?')}%  "
                    f"Freq: {cpu.get('freq_mhz','?')} MHz", Fore.WHITE))
        if mem:
            mem_color = Fore.RED if mem.get("percent",0) > 85 else Fore.WHITE
            print(c(f"  Memori: {mem.get('used','?')} / {mem.get('total','?')}  "
                    f"({mem.get('percent','?')}%)", mem_color))
        for disk in hw.get("disks",[]):
            disk_color = Fore.RED if disk.get("percent",0) > 90 else Fore.WHITE
            print(c(f"  Disk  : {disk.get('mountpoint','?')}  "
                    f"{disk.get('used','?')} / {disk.get('total','?')}  "
                    f"({disk.get('percent','?')}%)", disk_color))

    # ── Network ──────────────────────────────────────────────────────────────
    log_section("JARINGAN")
    for iface in ifaces:
        if not iface.get("ipv4") and not iface.get("is_up"):
            continue
        status = "▲" if iface.get("is_up") else "▼"
        speed  = f"  {iface['speed_mb']} Mb/s" if iface.get("speed_mb") else ""
        print(c(f"\n  {status} {iface['name']:<12} "
                f"IPv4: {iface.get('ipv4') or '—':<18}"
                f"MAC: {iface.get('mac') or '—'}{speed}", Fore.WHITE))

    # Koneksi aktif
    if conns:
        print(c(f"\n  Koneksi aktif saat ini ({len(conns)}):", Fore.CYAN))
        for conn in conns[:8]:
            proc = conn.get("process","?") or "?"
            print(c(f"    {conn['remote_ip']:<18} :{conn['remote_port']}  "
                    f"← {proc}", Fore.WHITE))
        if len(conns) > 8:
            print(c(f"    ... +{len(conns)-8} lagi", Fore.WHITE))

    # ── Keamanan ─────────────────────────────────────────────────────────────
    log_section("KONFIGURASI KEAMANAN")

    firewall = sec.get("firewall",{})
    fw_status = firewall.get("status","?")
    fw_color  = Fore.GREEN if "aktif" in fw_status else Fore.RED
    print(c(f"\n  Firewall  : {firewall.get('type','?')} — {fw_status}", fw_color))

    if "ssh" in sec:
        ssh = sec["ssh"]
        print(c(f"  SSH Port  : {ssh.get('port','22')}", Fore.WHITE))
        root_login = ssh.get("permit_root_login","?")
        rl_color   = Fore.RED if root_login == "yes" else Fore.GREEN
        print(c(f"  Root Login: {root_login}", rl_color))
        pw_auth  = ssh.get("password_auth","?")
        pw_color = Fore.RED if pw_auth == "yes" else Fore.GREEN
        print(c(f"  Pass Auth : {pw_auth}", pw_color))

    if "fail2ban" in sec:
        fb_color = Fore.GREEN if "aktif" == sec["fail2ban"] else Fore.YELLOW
        print(c(f"  Fail2ban  : {sec['fail2ban']}", fb_color))

    if "defender" in sec:
        color = Fore.GREEN if "aktif" in sec["defender"] else Fore.RED
        print(c(f"  Defender  : {sec['defender']}", color))

    # ── Users ────────────────────────────────────────────────────────────────
    if users:
        log_section("USER SISTEM")
        root_users = [u for u in users if u.get("is_root")]
        if len(root_users) > 1:
            print(c(f"\n  ⚠  {len(root_users)} akun dengan akses root!", Fore.YELLOW))

        for u in users[:8]:
            root_flag = c(" [ROOT]", Fore.RED, bold=True) if u.get("is_root") else ""
            print(c(f"    {u['username']:<20} {u.get('shell','?')}{root_flag}", Fore.WHITE))

    # ── Sudo issues ──────────────────────────────────────────────────────────
    if issues:
        log_section("MASALAH SUDO")
        for issue in issues:
            print(c(f"\n  ⚠  {issue}", Fore.YELLOW))

    # ── Software (hanya jika --full) ─────────────────────────────────────────
    if full and software:
        log_section(f"SOFTWARE TERINSTALL ({len(software)})")
        for s in software[:30]:
            print(c(f"    {s['name']:<40} {s.get('version','?')}", Fore.WHITE))

    # ── Ringkasan ─────────────────────────────────────────────────────────────
    log_section("RINGKASAN")
    problems = []

    if firewall and "tidak aktif" in str(firewall.get("status","")):
        problems.append("Firewall tidak aktif")

    if "ssh" in sec and sec["ssh"].get("permit_root_login") == "yes":
        problems.append("SSH: Root login diizinkan (berbahaya)")

    if "ssh" in sec and sec["ssh"].get("password_auth","?").lower() not in ("no","?"):
        problems.append("SSH: Autentikasi password aktif (disarankan pakai key)")

    for issue in issues:
        problems.append(f"Sudo: {issue[:60]}")

    if problems:
        print(c(f"\n  ⚠  {len(problems)} masalah keamanan ditemukan:", Fore.YELLOW, bold=True))
        for p in problems:
            print(c(f"    • {p}", Fore.YELLOW))
        print(c(f"\n  💡 Jalankan security hardener untuk memperbaiki:", Fore.CYAN))
        print(c("     sudo python scripts/security_hardener.py", Fore.WHITE))
    else:
        print(c("\n  ✓  Konfigurasi keamanan terlihat baik.", Fore.GREEN, bold=True))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Selene System Profiler — Inventaris sistem"
    )
    parser.add_argument("--full",   action="store_true",
                        help="Tampilkan semua info termasuk software lengkap")
    parser.add_argument("--export", action="store_true",
                        help="Simpan laporan ke file JSON")
    args = parser.parse_args()

    log_header("Selene — System Profiler v3.0",
               "Inventaris lengkap sistem dan konfigurasi keamanan")

    if not HAS_PSUTIL:
        log("WARN", "psutil tidak tersedia — beberapa info hardware tidak tersedia.")
        log("INFO", "Install: pip install psutil")

    log("SCAN", "Mengumpulkan informasi sistem...")
    profile = {}

    with Spinner("Profiling sistem..."):
        profile["system"]             = collect_system_info()
        profile["hardware"]           = collect_hardware()
        profile["interfaces"]         = collect_network_interfaces()
        profile["active_connections"] = collect_active_connections()
        profile["users"]              = collect_users()
        profile["security"]           = collect_security_config()
        profile["software"]           = collect_installed_software()
        profile["sudo_issues"]        = check_sudo_permissions()
        profile["profiled_at"]        = datetime.now().isoformat()

    print_profile(profile, full=args.full)

    if args.export:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"profile_{ts}.json"
        if save_json(path, profile):
            log("OK", c(f"Laporan disimpan: reports/profile_{ts}.json", Fore.GREEN))

    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("INFO", "Dihentikan.")
    except Exception as e:
        log("ERROR", f"Error: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()
