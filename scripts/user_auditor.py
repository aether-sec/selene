#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — User Auditor v3.0                                 ║
║   Audit akun, privilege, SSH keys, dan anomali login.        ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/user_auditor.py
  sudo python scripts/user_auditor.py --full
  python scripts/user_auditor.py --user john
  python scripts/user_auditor.py --inactive
"""

import sys, os, re, subprocess, pwd as _pwd, grp, spwd, time, argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        write_alert, save_json, Spinner,
        IS_LINUX, IS_WINDOWS, IS_ROOT, IS_ANDROID,
        REPORTS_DIR,
    )
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

TOOL_VERSION = "3.0.0"

SYSTEM_USERS = {
    "root","daemon","bin","sys","sync","games","man","lp","mail","news",
    "uucp","proxy","www-data","backup","list","irc","gnats","nobody",
    "systemd-network","systemd-resolve","messagebus","syslog","_apt",
    "tss","uuidd","tcpdump","sshd","pollinate","landscape","fwupd-refresh",
    "usbmux","dnsmasq","avahi","cups-browsed","rtkit","whoopsie",
    "speech-dispatcher","kernoops","pulse","geoclue","gdm","sssd",
    "systemd-coredump","mysql","postgres","redis","mongodb","nginx","apache",
    "www","ftp","postfix","dovecot","openvpn","ntp","snmp","netdata",
}

def _run(cmd: List[str], timeout: int = 5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="ignore")
        return r.stdout.strip()
    except Exception:
        return ""

# ── User collectors ───────────────────────────────────────────────────────────

def get_all_users() -> List[Dict]:
    """Kumpulkan info semua user dari /etc/passwd."""
    users = []
    if not IS_LINUX and not IS_ANDROID:
        log("INFO", "User audit penuh hanya tersedia di Linux.")
        return users

    try:
        passwd_entries = _pwd.getpwall()
    except Exception:
        return users

    for entry in passwd_entries:
        name    = entry.pw_name
        uid     = entry.pw_uid
        gid     = entry.pw_gid
        home    = entry.pw_dir
        shell   = entry.pw_shell
        is_sys  = (uid < 1000 or name in SYSTEM_USERS)
        can_login= shell not in ("/bin/false","/usr/sbin/nologin","/sbin/nologin","")

        # Group membership
        groups = []
        try:
            for g in grp.getgrall():
                if name in g.gr_mem or g.gr_gid == gid:
                    groups.append(g.gr_name)
        except Exception:
            pass

        is_sudo  = "sudo" in groups or "wheel" in groups or "admin" in groups
        is_root  = uid == 0

        # Password info (butuh root untuk spwd)
        pw_status  = "?"
        pw_last    = None
        pw_expire  = None
        has_no_pass= False

        if IS_ROOT:
            try:
                sp = spwd.getspnam(name)
                has_no_pass = (sp.sp_pwdp in ("","!","!!","*"))
                pw_status   = ("LOCKED" if sp.sp_pwdp.startswith("!")
                               else ("NOLOGIN" if sp.sp_pwdp in ("*","!!") else "OK"))
                if sp.sp_lstchg and sp.sp_lstchg > 0:
                    pw_last = datetime(1970,1,1) + timedelta(days=sp.sp_lstchg)
                if sp.sp_expire and sp.sp_expire > 0:
                    pw_expire = datetime(1970,1,1) + timedelta(days=sp.sp_expire)
            except (KeyError, PermissionError):
                pass

        # SSH keys
        ssh_keys = []
        auth_keys = Path(home) / ".ssh/authorized_keys"
        if auth_keys.exists():
            try:
                lines = auth_keys.read_text(errors="ignore").splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Ambil komentar (biasanya user@host)
                        parts = line.split()
                        comment = parts[-1] if len(parts) >= 3 else "?"
                        key_type= parts[0] if parts else "?"
                        ssh_keys.append({"type": key_type, "comment": comment})
            except Exception:
                pass

        # Last login
        last_login = _run(["lastlog", "-u", name]).splitlines()
        last_login_str = ""
        if len(last_login) > 1:
            last_login_str = last_login[1]

        users.append({
            "name":       name,
            "uid":        uid,
            "gid":        gid,
            "home":       home,
            "shell":      shell,
            "groups":     groups,
            "is_system":  is_sys,
            "is_root":    is_root,
            "is_sudo":    is_sudo,
            "can_login":  can_login,
            "pw_status":  pw_status,
            "has_no_pass":has_no_pass,
            "pw_last":    pw_last.isoformat() if pw_last else None,
            "pw_expire":  pw_expire.isoformat() if pw_expire else None,
            "ssh_keys":   ssh_keys,
            "last_login": last_login_str,
        })

    return users

def get_sudo_rules() -> List[str]:
    """Baca aturan sudoers."""
    rules = []
    if not IS_ROOT:
        return rules

    sudoers_files = [Path("/etc/sudoers")]
    sudoers_d = Path("/etc/sudoers.d")
    if sudoers_d.exists():
        sudoers_files.extend(sudoers_d.iterdir())

    for sf in sudoers_files:
        try:
            content = sf.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("Default"):
                    if "ALL=(ALL" in line or "NOPASSWD" in line:
                        rules.append(f"{sf.name}: {line}")
        except Exception:
            pass
    return rules

def get_failed_logins() -> List[Dict]:
    """Ambil 20 failed login terbaru."""
    entries = []
    out = _run(["lastb", "-n", "30"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            entries.append({
                "user": parts[0],
                "tty":  parts[1],
                "ip":   parts[2] if re.match(r"\d+\.\d+", parts[2]) else "",
                "time": " ".join(parts[3:6]) if len(parts) > 5 else "",
            })
    return entries[:20]

# ── Risk analysis ─────────────────────────────────────────────────────────────

def analyze_user_risks(users: List[Dict]) -> List[Dict]:
    """Identifikasi risiko dari daftar user."""
    findings = []
    now = datetime.now()

    for u in users:
        if u["is_system"] and not u["can_login"]:
            continue  # Skip user sistem yang normal

        # Root bukan uid 0 (backdoor)
        if u["uid"] == 0 and u["name"] != "root":
            findings.append({
                "severity": "KRITIS",
                "user":     u["name"],
                "issue":    f"UID 0 pada user bukan root: '{u['name']}' — KEMUNGKINAN BACKDOOR!",
                "fix":      f"Hapus segera: userdel {u['name']}",
            })
            write_alert("CRIT", f"User Auditor: UID 0 pada '{u['name']}' — BACKDOOR?",
                        details=u)

        # User dengan no password
        if u["can_login"] and u["has_no_pass"]:
            findings.append({
                "severity": "KRITIS",
                "user":     u["name"],
                "issue":    f"User '{u['name']}' bisa login tanpa password!",
                "fix":      f"Set password: passwd {u['name']}",
            })

        # Password sangat lama (> 180 hari)
        if u["pw_last"] and u["can_login"]:
            try:
                last = datetime.fromisoformat(u["pw_last"])
                age  = (now - last).days
                if age > 180:
                    findings.append({
                        "severity": "SEDANG",
                        "user":     u["name"],
                        "issue":    f"Password '{u['name']}' tidak diganti {age} hari",
                        "fix":      f"Ganti password: passwd {u['name']}",
                    })
            except Exception:
                pass

        # User sudo dengan shell berbahaya
        if u["is_sudo"] and u["can_login"]:
            if u["shell"] in ("/bin/bash","/bin/sh","/bin/zsh"):
                pass  # Normal
            elif u["is_system"]:
                findings.append({
                    "severity": "TINGGI",
                    "user":     u["name"],
                    "issue":    f"User sistem '{u['name']}' punya sudo dan bisa login ({u['shell']})",
                    "fix":      f"Batasi akses: usermod -s /usr/sbin/nologin {u['name']}",
                })

        # SSH key dari host asing (heuristic: banyak key)
        if len(u["ssh_keys"]) > 5:
            findings.append({
                "severity": "SEDANG",
                "user":     u["name"],
                "issue":    f"Terlalu banyak SSH key ({len(u['ssh_keys'])}) di '{u['name']}'",
                "fix":      f"Audit: cat /home/{u['name']}/.ssh/authorized_keys",
            })

        # User tanpa home directory
        if u["can_login"] and not Path(u["home"]).exists() and not u["is_system"]:
            findings.append({
                "severity": "RENDAH",
                "user":     u["name"],
                "issue":    f"Home directory tidak ada: {u['home']}",
                "fix":      f"Buat home: mkhomedir {u['name']}",
            })

    return sorted(findings,
                  key=lambda x: {"KRITIS":0,"TINGGI":1,"SEDANG":2,"RENDAH":3}.get(x["severity"],4))

# ── Display ───────────────────────────────────────────────────────────────────

SEV_C = {
    "KRITIS": Fore.RED,
    "TINGGI": Fore.RED,
    "SEDANG": Fore.YELLOW,
    "RENDAH": Fore.CYAN,
}

def print_user_table(users: List[Dict], filter_system: bool = True) -> None:
    display = [u for u in users if not u["is_system"] or u["uid"] == 0] if filter_system else users

    print(c(f"\n  {'USER':<18} {'UID':<6} {'SUDO':<6} {'LOGIN':<7} {'PW STATUS':<10} {'SSH KEYS'}", Fore.CYAN))
    print(c(f"  {'─'*18} {'─'*6} {'─'*6} {'─'*7} {'─'*10} {'─'*10}", Fore.BLUE))

    for u in sorted(display, key=lambda x: x["uid"]):
        name   = u["name"][:17]
        uid    = u["uid"]
        sudo   = c("YES", Fore.RED, bold=True) if u["is_sudo"] else c("no", Fore.WHITE)
        login  = c("YES", Fore.YELLOW) if u["can_login"] else c("no", Fore.WHITE)
        pws    = u["pw_status"]
        pw_col = (Fore.RED if pws in ("NOLOGIN","") else
                  Fore.YELLOW if pws == "LOCKED" else Fore.GREEN)
        pw_str = c(pws, pw_col)
        keys   = len(u["ssh_keys"])
        key_str= c(f"{keys} key", Fore.YELLOW if keys > 0 else Fore.WHITE)

        root_mark = c(" [ROOT]", Fore.RED, bold=True) if u["uid"] == 0 else ""
        print(f"  {name:<18} {uid:<6} {sudo:<18} {login:<15} {pw_str:<18} {key_str}{root_mark}")

def print_findings(findings: List[Dict]) -> None:
    if not findings:
        print(c("\n  ✓  Tidak ada risiko user yang terdeteksi.", Fore.GREEN, bold=True))
        return

    for f in findings:
        sev = f["severity"]
        col = SEV_C.get(sev, Fore.WHITE)
        print(c(f"\n  [{sev}] {f['issue']}", col, bold=(sev=="KRITIS")))
        print(c(f"    → {f['fix']}", Fore.CYAN))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene User Auditor — Audit akun dan privilege",
    )
    parser.add_argument("--full",      action="store_true", help="Tampilkan semua user termasuk sistem")
    parser.add_argument("--user",      metavar="USER",      help="Fokus pada user tertentu")
    parser.add_argument("--inactive",  action="store_true", help="Tampilkan user yang tidak pernah login")
    parser.add_argument("--no-save",   action="store_true")
    args = parser.parse_args()

    log_header("Selene — User Auditor v3.0",
               "Audit akun, privilege, SSH keys, dan anomali login")

    if not IS_LINUX and not IS_ANDROID:
        log("WARN", "User Auditor penuh hanya mendukung Linux.")
        log("INFO", "Untuk Windows gunakan: net user / Get-LocalUser (PowerShell)")
        return

    if not IS_ROOT:
        log("WARN", "Beberapa info (password hash, shadow) hanya tersedia dengan sudo")

    log("SCAN", "Mengumpulkan informasi user...")
    with Spinner("Membaca /etc/passwd dan shadow..."):
        users = get_all_users()

    if args.user:
        users = [u for u in users if u["name"] == args.user]
        if not users:
            log("ERROR", f"User '{args.user}' tidak ditemukan")
            return

    # Tampilkan tabel
    log_section("DAFTAR USER")
    print_user_table(users, filter_system=not args.full)

    # Ringkasan
    total     = len(users)
    sudo_cnt  = sum(1 for u in users if u["is_sudo"])
    login_cnt = sum(1 for u in users if u["can_login"] and not u["is_system"])
    nopass    = sum(1 for u in users if u["has_no_pass"] and u["can_login"])

    print(c(f"\n  Total user  : {total}", Fore.WHITE))
    print(c(f"  Bisa login  : {login_cnt}", Fore.WHITE))
    print(c(f"  Punya sudo  : {sudo_cnt}", Fore.YELLOW if sudo_cnt > 2 else Fore.WHITE))
    print(c(f"  Tanpa pass  : {nopass}", Fore.RED if nopass else Fore.GREEN, bold=bool(nopass)))

    # Risk analysis
    log_section("ANALISIS RISIKO")
    findings = analyze_user_risks(users)
    print_findings(findings)

    # Sudo rules
    if IS_ROOT:
        sudo_rules = get_sudo_rules()
        if sudo_rules:
            log_section("ATURAN SUDO BERBAHAYA")
            for rule in sudo_rules:
                print(c(f"  {rule}", Fore.YELLOW))

    # Failed logins
    failed = get_failed_logins()
    if failed:
        log_section(f"LOGIN GAGAL TERBARU ({len(failed)})")
        print(c(f"\n  {'USER':<15} {'IP':<18} {'WAKTU'}", Fore.CYAN))
        print(c(f"  {'─'*15} {'─'*18} {'─'*20}", Fore.BLUE))
        for f in failed:
            print(c(f"  {f['user']:<15} {f['ip']:<18} {f['time']}", Fore.WHITE))

    # Inactive users
    if args.inactive:
        log_section("USER TIDAK AKTIF")
        inactive = [u for u in users if u["can_login"] and "Never logged in" in u["last_login"]]
        if inactive:
            for u in inactive:
                print(c(f"  {u['name']:<20} (UID {u['uid']}) — belum pernah login", Fore.YELLOW))
                log("INFO", f"Pertimbangkan nonaktifkan: usermod -L {u['name']}")
        else:
            log("OK", "Semua user yang bisa login sudah pernah login setidaknya sekali")

    # Simpan
    if not args.no_save:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"users_{ts}.json"
        save_json(path, {"tool":"user_auditor","version":TOOL_VERSION,
                         "scan_time":datetime.now().isoformat(),
                         "users":users,"findings":findings})
        log("OK", c(f"Laporan: reports/users_{ts}.json", Fore.GREEN))

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
