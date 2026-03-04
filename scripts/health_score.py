#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Health Score v3.0                                 ║
║   Nilai kesehatan keamanan sistem dari A+ hingga F.          ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/health_score.py
  python scripts/health_score.py --detail
  python scripts/health_score.py --history
  python scripts/health_score.py --watch      ← hitung ulang setiap jam

Kategori penilaian (total 100 poin):
  • Firewall & Network  (20 poin)
  • Update & Patch      (15 poin)
  • SSH & Auth          (15 poin)
  • Backup              (15 poin)
  • Monitoring          (10 poin)
  • Vulnerability       (10 poin)
  • Privacy             (10 poin)
  • Incident Response   ( 5 poin)
"""

import sys, os, subprocess, shutil, time, argparse, re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        read_jsonl, load_json, save_json, append_jsonl,
        IS_LINUX, IS_WINDOWS, IS_ROOT, IS_ANDROID,
        REPORTS_DIR, LOGS_DIR, DATA_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION = "3.0.0"
HEALTH_FILE  = DATA_DIR / "health.json"
HEALTH_LOG   = DATA_DIR / "health_history.jsonl"

# ── Kategori penilaian ────────────────────────────────────────────────────────
CATEGORIES = {
    "firewall":   {"label": "Firewall & Network",  "max": 20},
    "updates":    {"label": "Update & Patch",       "max": 15},
    "ssh_auth":   {"label": "SSH & Autentikasi",    "max": 15},
    "backup":     {"label": "Backup",               "max": 15},
    "monitoring": {"label": "Monitoring Aktif",     "max": 10},
    "vulns":      {"label": "Vulnerability",        "max": 10},
    "privacy":    {"label": "Privasi",              "max": 10},
    "incident":   {"label": "Incident Response",    "max":  5},
}

def grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"

def grade_color(g: str) -> str:
    return {
        "A+": Fore.GREEN, "A": Fore.GREEN,
        "B":  Fore.YELLOW,
        "C":  Fore.YELLOW,
        "D":  Fore.RED, "F": Fore.RED,
    }.get(g, Fore.WHITE)

def _run(cmd: List[str], timeout: int = 5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="ignore")
        return r.stdout + r.stderr
    except Exception:
        return ""

def _file_age_days(path: Path) -> Optional[float]:
    if not path.exists():
        return None
    return (datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)).total_seconds() / 86400

# ── Checker per kategori ──────────────────────────────────────────────────────

def check_firewall(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek firewall, network hardening, open ports."""
    score  = 0
    items  = []
    max_sc = CATEGORIES["firewall"]["max"]

    if IS_LINUX and not IS_ANDROID:
        # UFW aktif
        ufw_out = _run(["ufw", "status"])
        if "active" in ufw_out.lower():
            score += 7
            items.append({"ok": True, "msg": "UFW firewall aktif", "pts": 7})
        elif shutil.which("ufw"):
            items.append({"ok": False, "msg": "UFW terinstall tapi tidak aktif", "pts": 0,
                          "fix": "sudo ufw enable"})
        else:
            # Cek iptables
            ipt = _run(["iptables", "-L", "-n"])
            if "DROP" in ipt or "REJECT" in ipt:
                score += 5
                items.append({"ok": True, "msg": "iptables punya aturan DROP/REJECT", "pts": 5})
            else:
                items.append({"ok": False, "msg": "Tidak ada firewall aktif", "pts": 0,
                              "fix": "sudo apt install ufw && sudo ufw enable"})

        # fail2ban
        if shutil.which("fail2ban-client"):
            fb_out = _run(["fail2ban-client", "status"])
            if "Number of jail" in fb_out or "ssh" in fb_out.lower():
                score += 5
                items.append({"ok": True, "msg": "fail2ban aktif", "pts": 5})
            else:
                items.append({"ok": False, "msg": "fail2ban terinstall tapi tidak aktif", "pts": 0,
                              "fix": "sudo systemctl enable --now fail2ban"})
        else:
            items.append({"ok": False, "msg": "fail2ban tidak terinstall", "pts": 0,
                          "fix": "sudo apt install fail2ban"})

        # IPv6 disable (opsional, nilai kecil)
        sysctl = _run(["sysctl", "net.ipv6.conf.all.disable_ipv6"])
        if "= 1" in sysctl:
            score += 2
            items.append({"ok": True, "msg": "IPv6 dinonaktifkan", "pts": 2})

        # Port forwarding dinonaktifkan
        fwd = _run(["sysctl", "net.ipv4.ip_forward"])
        if "= 0" in fwd:
            score += 3
            items.append({"ok": True, "msg": "IP forwarding dinonaktifkan", "pts": 3})
        else:
            items.append({"ok": False, "msg": "IP forwarding aktif (berisiko jika bukan router)", "pts": 0,
                          "fix": "echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf && sysctl -p"})

        # Cek port berbahaya yang terbuka
        ss_out = _run(["ss", "-tlnp"])
        dangerous_open = []
        for port, svc in [(23,"Telnet"),(135,"RPC"),(445,"SMB"),(3389,"RDP")]:
            if f":{port}" in ss_out:
                dangerous_open.append(f"{svc}({port})")
        if dangerous_open:
            items.append({"ok": False, "msg": f"Port berbahaya terbuka: {', '.join(dangerous_open)}", "pts": 0,
                          "fix": f"Tutup port ini segera"})
        else:
            score += 3
            items.append({"ok": True, "msg": "Tidak ada port berbahaya terbuka", "pts": 3})

    elif IS_WINDOWS:
        fw = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if fw.count("ON") >= 2:
            score += 15
            items.append({"ok": True, "msg": "Windows Defender Firewall aktif", "pts": 15})
        else:
            items.append({"ok": False, "msg": "Windows Firewall tidak aktif di semua profil", "pts": 0,
                          "fix": "netsh advfirewall set allprofiles state on"})

    return min(score, max_sc), items


def check_updates(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek status update sistem."""
    score = 0
    items = []
    max_sc = CATEGORIES["updates"]["max"]

    if IS_LINUX and not IS_ANDROID:
        # apt: cek update tersedia
        if shutil.which("apt"):
            try:
                out = subprocess.run(
                    ["apt-get", "--simulate", "dist-upgrade"],
                    capture_output=True, text=True, timeout=20
                )
                upgradable = len([l for l in out.stdout.splitlines()
                                  if l.startswith("Inst ")])
                if upgradable == 0:
                    score += 10
                    items.append({"ok": True, "msg": "Semua paket sudah up-to-date", "pts": 10})
                elif upgradable < 10:
                    score += 6
                    items.append({"ok": False, "msg": f"{upgradable} paket perlu diupdate", "pts": 6,
                                  "fix": "sudo apt upgrade -y"})
                else:
                    score += 2
                    items.append({"ok": False, "msg": f"{upgradable} paket belum diupdate (banyak!)", "pts": 2,
                                  "fix": "sudo apt update && sudo apt upgrade -y"})
            except Exception:
                items.append({"ok": False, "msg": "Tidak bisa cek update apt", "pts": 0, "fix": ""})

        # unattended-upgrades
        ua_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if ua_conf.exists():
            content = ua_conf.read_text(errors="ignore")
            if '"1"' in content or '"true"' in content.lower():
                score += 5
                items.append({"ok": True, "msg": "Auto-update (unattended-upgrades) aktif", "pts": 5})
        if not any(i["ok"] and "Auto-update" in i["msg"] for i in items):
            items.append({"ok": False, "msg": "Auto-update tidak dikonfigurasi", "pts": 0,
                          "fix": "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"})

    elif IS_WINDOWS:
        # Cek Windows Update via registry/PowerShell
        try:
            out = subprocess.run(
                ["powershell", "-Command",
                 "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"],
                capture_output=True, text=True, timeout=15
            )
            pending = int(out.stdout.strip() or "99")
            if pending == 0:
                score += 15
                items.append({"ok": True, "msg": "Windows Update: tidak ada update tertunda", "pts": 15})
            else:
                score += 5
                items.append({"ok": False, "msg": f"Windows Update: {pending} update tertunda", "pts": 5,
                              "fix": "Buka Windows Update dan install semua update"})
        except Exception:
            items.append({"ok": False, "msg": "Tidak bisa cek Windows Update", "pts": 0, "fix": ""})

    return min(score, max_sc), items


def check_ssh_auth(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek konfigurasi SSH dan autentikasi."""
    score = 0
    items = []
    max_sc = CATEGORIES["ssh_auth"]["max"]

    sshd_cfg = Path("/etc/ssh/sshd_config")
    if not sshd_cfg.exists():
        items.append({"ok": True, "msg": "SSH tidak terinstall (tidak ada risiko SSH)", "pts": max_sc})
        return max_sc, items

    try:
        content = sshd_cfg.read_text(errors="ignore")
    except PermissionError:
        items.append({"ok": False, "msg": "Tidak bisa baca sshd_config (akses ditolak)", "pts": 0,
                      "fix": "Jalankan dengan sudo"})
        return 0, items

    def cfg_val(key: str) -> str:
        m = re.search(rf"^\s*{key}\s+(.+)$", content, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip().lower() if m else "default"

    checks = [
        ("PermitRootLogin",       "no",   5, "Login root via SSH dinonaktifkan",
         "sudo sed -i 's/^.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"),
        ("PasswordAuthentication","no",   4, "Autentikasi password SSH dinonaktifkan (hanya key)",
         "sudo sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"),
        ("PermitEmptyPasswords",  "no",   3, "Password kosong ditolak SSH",
         "sudo sed -i 's/^.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config"),
        ("MaxAuthTries",          "3",    2, "MaxAuthTries dibatasi",
         "Tambahkan: MaxAuthTries 3 di sshd_config"),
        ("X11Forwarding",         "no",   1, "X11 Forwarding dinonaktifkan",
         "sudo sed -i 's/^.*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"),
    ]

    for key, expected, pts, ok_msg, fix in checks:
        val = cfg_val(key)
        ok  = (val == expected or
               (expected == "3" and val.isdigit() and int(val) <= 3))
        if ok:
            score += pts
            items.append({"ok": True,  "msg": ok_msg, "pts": pts})
        else:
            items.append({"ok": False, "msg": f"SSH {key}={val} (seharusnya {expected})",
                          "pts": 0, "fix": fix})

    return min(score, max_sc), items


def check_backup(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek apakah backup dilakukan secara teratur."""
    score = 0
    items = []
    max_sc = CATEGORIES["backup"]["max"]

    # Cek log backup Selene
    backup_log = LOGS_DIR / "backup_log.jsonl"
    if backup_log.exists():
        entries = read_jsonl(backup_log, last_n=20)
        backups = [e for e in entries if e.get("action") == "backup"]
        if backups:
            last_backup = max(
                (datetime.fromisoformat(b["timestamp"]) for b in backups
                 if b.get("timestamp")),
                default=None
            )
            if last_backup:
                age_days = (datetime.now() - last_backup).days
                if age_days == 0:
                    score += 15
                    items.append({"ok": True, "msg": f"Backup terbaru: hari ini", "pts": 15})
                elif age_days <= 7:
                    score += 10
                    items.append({"ok": True, "msg": f"Backup terbaru: {age_days} hari lalu", "pts": 10})
                elif age_days <= 30:
                    score += 5
                    items.append({"ok": False, "msg": f"Backup terakhir {age_days} hari lalu (idealnya < 7 hari)", "pts": 5,
                                  "fix": "python scripts/secure_backup.py backup"})
                else:
                    score += 2
                    items.append({"ok": False, "msg": f"Backup terakhir {age_days} hari lalu (terlalu lama!)", "pts": 2,
                                  "fix": "python scripts/secure_backup.py backup"})
        else:
            items.append({"ok": False, "msg": "Belum ada backup yang tercatat", "pts": 0,
                          "fix": "python scripts/secure_backup.py backup"})
    else:
        items.append({"ok": False, "msg": "Backup belum pernah dilakukan via Selene", "pts": 0,
                      "fix": "python scripts/secure_backup.py backup --dirs ~/Documents"})

    # Cek direktori backup ada di konfigurasi
    cfg      = get_config()
    dest     = cfg.get("backup","destination", default="")
    dirs     = cfg.get("backup","directories", default=[])
    if dest and dirs:
        score += 3 if score < max_sc else 0
        items.append({"ok": True, "msg": "Backup dikonfigurasi di setup", "pts": 3})
    else:
        items.append({"ok": False, "msg": "Tujuan backup belum dikonfigurasi", "pts": 0,
                      "fix": "python scripts/setup_wizard.py"})

    return min(score, max_sc), items


def check_monitoring(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek apakah tools monitoring Selene aktif."""
    score = 0
    items = []
    max_sc = CATEGORIES["monitoring"]["max"]

    # Cek apakah ada alert dalam 7 hari (berarti threat_monitor pernah berjalan)
    alerts = read_jsonl(LOGS_DIR / "alerts.jsonl", last_n=100)
    cutoff = datetime.now() - timedelta(days=7)
    recent = [a for a in alerts if a.get("timestamp","") > cutoff.isoformat()]
    if recent:
        score += 4
        items.append({"ok": True, "msg": f"Monitoring aktif: {len(recent)} alert dalam 7 hari", "pts": 4})

    # Honeypot: ada capture?
    hp_caps = read_jsonl(LOGS_DIR / "honeypot_captures.jsonl", last_n=5)
    if hp_caps:
        score += 3
        items.append({"ok": True, "msg": "Honeypot pernah aktif dan menangkap koneksi", "pts": 3})
    else:
        items.append({"ok": False, "msg": "Honeypot belum pernah aktif atau belum menangkap", "pts": 0,
                      "fix": "python scripts/honeypot.py"})

    # FIM: baseline ada?
    fim_base = DATA_DIR / "fim_baseline.json"
    if fim_base.exists():
        age = _file_age_days(fim_base)
        if age is not None and age < 30:
            score += 3
            items.append({"ok": True, "msg": f"File Integrity Monitor: baseline ada ({int(age)} hari lalu)", "pts": 3})
        else:
            score += 1
            items.append({"ok": False, "msg": "FIM baseline ada tapi sudah lama (> 30 hari)", "pts": 1,
                          "fix": "python scripts/hash_verifier.py init"})
    else:
        items.append({"ok": False, "msg": "File Integrity Monitor belum diinisialisasi", "pts": 0,
                      "fix": "python scripts/hash_verifier.py init"})

    return min(score, max_sc), items


def check_vulnerabilities(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek hasil vuln scan terakhir."""
    score = 0
    items = []
    max_sc = CATEGORIES["vulns"]["max"]

    # Cari laporan vuln scan terbaru
    vuln_reports = sorted(REPORTS_DIR.glob("vuln_*.json"), reverse=True)
    if not vuln_reports:
        items.append({"ok": False, "msg": "Belum ada vuln scan yang dilakukan", "pts": 0,
                      "fix": "python scripts/vuln_scanner.py"})
        return 0, items

    latest = vuln_reports[0]
    age    = _file_age_days(latest)

    if age is None:
        return 0, items

    data = load_json(latest, {})
    hosts = data.get("hosts", []) if isinstance(data.get("hosts"), list) else []

    # Hitung findings
    kritis_count = sum(
        1 for h in hosts
        for f in h.get("findings", [])
        if f.get("severity") in ("KRITIS", "CRITICAL")
    )
    tinggi_count = sum(
        1 for h in hosts
        for f in h.get("findings", [])
        if f.get("severity") in ("TINGGI", "HIGH")
    )

    age_penalty = 0 if age < 7 else (3 if age < 30 else 5)

    if kritis_count == 0 and tinggi_count == 0:
        score = max_sc - age_penalty
        items.append({"ok": True, "msg": f"Tidak ada vuln KRITIS/TINGGI (scan {int(age)} hari lalu)", "pts": score})
    elif kritis_count > 0:
        score = max(0, 2 - age_penalty)
        items.append({"ok": False, "msg": f"{kritis_count} vuln KRITIS ditemukan — segera perbaiki!", "pts": score,
                      "fix": "sudo python scripts/security_hardener.py --auto"})
    else:
        score = max(0, 5 - age_penalty)
        items.append({"ok": False, "msg": f"{tinggi_count} vuln TINGGI ditemukan", "pts": score,
                      "fix": "Perbaiki vulnerability yang ditemukan"})

    if age > 14:
        items.append({"ok": False, "msg": f"Vuln scan terakhir {int(age)} hari lalu (idealnya tiap 7 hari)", "pts": 0,
                      "fix": "python scripts/vuln_scanner.py"})

    return min(score, max_sc), items


def check_privacy(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek hasil privacy audit terakhir."""
    score = 0
    items = []
    max_sc = CATEGORIES["privacy"]["max"]

    priv_reports = sorted(REPORTS_DIR.glob("privacy_*.json"), reverse=True)
    if not priv_reports:
        items.append({"ok": False, "msg": "Belum ada privacy audit", "pts": 0,
                      "fix": "python scripts/privacy_audit.py"})
        return 0, items

    latest = priv_reports[0]
    age    = _file_age_days(latest)
    data   = load_json(latest, {})
    all_f  = data.get("findings", {})

    kritis = sum(
        1 for cat_f in all_f.values()
        for f in (cat_f if isinstance(cat_f, list) else [])
        if f.get("severity") == "KRITIS"
    )
    tinggi = sum(
        1 for cat_f in all_f.values()
        for f in (cat_f if isinstance(cat_f, list) else [])
        if f.get("severity") == "TINGGI"
    )

    age_days = int(age or 0)
    if kritis == 0 and tinggi == 0:
        score = max_sc - (0 if age_days < 30 else 3)
        items.append({"ok": True, "msg": f"Tidak ada masalah privasi kritis (audit {age_days} hari lalu)", "pts": score})
    else:
        score = max(0, max_sc - kritis * 3 - tinggi)
        items.append({"ok": False, "msg": f"Privacy: {kritis} KRITIS, {tinggi} TINGGI ditemukan", "pts": score,
                      "fix": "Baca laporan privacy dan tindak lanjuti"})

    return min(score, max_sc), items


def check_incident_response(detail: bool) -> Tuple[int, List[Dict]]:
    """Cek kesiapan incident response."""
    score = 0
    items = []
    max_sc = CATEGORIES["incident"]["max"]

    # Apakah pernah ada IR case?
    ir_cases_dir = REPORTS_DIR / "ir_cases"
    if ir_cases_dir.exists():
        cases = list(ir_cases_dir.glob("IR-*.json"))
        if cases:
            score += 3
            items.append({"ok": True, "msg": f"IR cases ada: {len(cases)} kasus pernah ditangani", "pts": 3})

    # Apakah config ada?
    cfg = get_config()
    notif = cfg.get("notifications","enabled", default=False)
    if notif:
        score += 2
        items.append({"ok": True, "msg": "Notifikasi (Telegram/Discord) dikonfigurasi", "pts": 2})
    else:
        items.append({"ok": False, "msg": "Notifikasi belum dikonfigurasi", "pts": 0,
                      "fix": "python scripts/setup_wizard.py → langkah notifikasi"})

    return min(score, max_sc), items

# ── Agregat dan tampilan ──────────────────────────────────────────────────────

def run_all_checks(detail: bool) -> Dict:
    """Jalankan semua cek dan kembalikan hasil lengkap."""
    checkers = {
        "firewall":   check_firewall,
        "updates":    check_updates,
        "ssh_auth":   check_ssh_auth,
        "backup":     check_backup,
        "monitoring": check_monitoring,
        "vulns":      check_vulnerabilities,
        "privacy":    check_privacy,
        "incident":   check_incident_response,
    }

    results   = {}
    total_pts = 0
    total_max = sum(c["max"] for c in CATEGORIES.values())

    for key, checker_fn in checkers.items():
        cat   = CATEGORIES[key]
        pts, items = checker_fn(detail)
        results[key] = {
            "label":  cat["label"],
            "score":  pts,
            "max":    cat["max"],
            "pct":    int(pts * 100 / cat["max"]) if cat["max"] else 0,
            "items":  items,
        }
        total_pts += pts

    final_score = int(total_pts * 100 / total_max) if total_max else 0
    g           = grade(final_score)

    return {
        "score":      final_score,
        "grade":      g,
        "total_pts":  total_pts,
        "total_max":  total_max,
        "categories": results,
        "generated":  datetime.now().isoformat(),
    }

def print_results(data: Dict, detail: bool) -> None:
    """Tampilkan hasil health score dengan visual yang jelas."""
    score  = data["score"]
    g      = data["grade"]
    g_col  = grade_color(g)
    cats   = data["categories"]

    # ── Header score ──────────────────────────────────────────────────────────
    print(c(f"\n  {'═'*56}", Fore.CYAN))
    print(c(f"  SELENE SECURITY HEALTH SCORE", Fore.CYAN, bold=True))
    print(c(f"  {'═'*56}", Fore.CYAN))

    # Big score display
    score_bar_w = 40
    filled = int(score_bar_w * score / 100)
    bar_col= Fore.GREEN if score >= 75 else (Fore.YELLOW if score >= 50 else Fore.RED)
    bar    = c("█" * filled, bar_col, bold=True) + c("░" * (score_bar_w - filled), Fore.WHITE)

    print(f"\n  {bar}  {c(str(score), bar_col, bold=True)}/100")
    print(c(f"\n  Grade: {g}  —  ", Fore.WHITE) +
          c(f"{'Sangat Aman' if score>=85 else 'Cukup Aman' if score>=65 else 'Perlu Perhatian' if score>=50 else 'BERISIKO TINGGI'}",
            g_col, bold=True))

    # ── Per kategori ──────────────────────────────────────────────────────────
    print(c(f"\n  {'─'*56}", Fore.BLUE))
    print(c(f"  {'KATEGORI':<28} {'SKOR':>5}  {'BAR':<20}", Fore.CYAN))
    print(c(f"  {'─'*56}", Fore.BLUE))

    for key, cat in cats.items():
        pts  = cat["score"]
        mx   = cat["max"]
        pct  = cat["pct"]
        label= cat["label"]

        bar_w  = 16
        filled = int(bar_w * pct / 100)
        col    = Fore.GREEN if pct >= 75 else (Fore.YELLOW if pct >= 50 else Fore.RED)
        mini_bar = c("█" * filled, col) + c("░" * (bar_w - filled), Fore.WHITE)
        pts_str  = c(f"{pts}/{mx}", col)

        print(f"  {label:<28} {pts_str:<8}  {mini_bar}  {c(str(pct)+'%', col)}")

        if detail:
            for item in cat["items"]:
                icon = c("✓", Fore.GREEN) if item["ok"] else c("✗", Fore.RED)
                msg  = item["msg"]
                print(c(f"    {icon} {msg}", Fore.WHITE if item["ok"] else Fore.YELLOW))
                if not item["ok"] and item.get("fix"):
                    print(c(f"      → {item['fix']}", Fore.CYAN))

    print(c(f"\n  {'─'*56}", Fore.BLUE))
    print(c(f"  Total: {data['total_pts']}/{data['total_max']} poin  |  "
            f"Grade: {g}  |  {data['generated'][:16]}", Fore.WHITE))

    # ── Rekomendasi prioritas ──────────────────────────────────────────────────
    print(c(f"\n  TOP PRIORITAS:", Fore.YELLOW, bold=True))
    todos = []
    for key, cat in cats.items():
        for item in cat["items"]:
            if not item["ok"] and item.get("fix"):
                deficit = cat["max"] - cat["score"]
                todos.append((deficit, cat["label"], item["msg"], item["fix"]))

    todos.sort(reverse=True)
    for i, (deficit, label, msg, fix) in enumerate(todos[:5], 1):
        print(c(f"  {i}. [{label}] {msg}", Fore.WHITE))
        print(c(f"     → {fix}", Fore.CYAN))

def save_health(data: Dict) -> None:
    """Simpan hasil ke file dan history."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    save_json(HEALTH_FILE, data)
    append_jsonl(HEALTH_LOG, {
        "timestamp": data["generated"],
        "score":     data["score"],
        "grade":     data["grade"],
        "categories":{k: v["score"] for k,v in data["categories"].items()},
    })

def show_history() -> None:
    """Tampilkan riwayat health score."""
    entries = read_jsonl(HEALTH_LOG, last_n=30)
    if not entries:
        log("INFO", "Belum ada riwayat health score.")
        log("INFO", "Jalankan: python scripts/health_score.py")
        return

    log_section(f"RIWAYAT HEALTH SCORE ({len(entries)} entri)")
    print(c(f"\n  {'TANGGAL':<20} {'SKOR':>5}  {'GRADE'}  {'BAR'}", Fore.CYAN))
    print(c(f"  {'─'*55}", Fore.BLUE))

    for e in reversed(entries):
        ts    = e.get("timestamp","?")[:16].replace("T"," ")
        sc    = e.get("score", 0)
        g     = e.get("grade","?")
        g_col = grade_color(g)
        w     = 20
        filled= int(w * sc / 100)
        col   = Fore.GREEN if sc >= 75 else (Fore.YELLOW if sc >= 50 else Fore.RED)
        bar   = c("█"*filled, col) + c("░"*(w-filled), Fore.WHITE)
        print(f"  {ts:<20} {c(str(sc), col):>7}  {c(g, g_col)}  {bar}")

    # Trend
    if len(entries) >= 2:
        first = entries[0]["score"]
        last  = entries[-1]["score"]
        delta = last - first
        if delta > 0:
            print(c(f"\n  Trend: +{delta} poin sejak pertama (↑ membaik)", Fore.GREEN))
        elif delta < 0:
            print(c(f"\n  Trend: {delta} poin sejak pertama (↓ menurun)", Fore.RED))
        else:
            print(c(f"\n  Trend: Tidak berubah", Fore.WHITE))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Health Score — Nilai kesehatan keamanan sistem",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--detail",  "-d", action="store_true",
                        help="Tampilkan semua temuan per kategori")
    parser.add_argument("--history", action="store_true",
                        help="Tampilkan riwayat health score")
    parser.add_argument("--watch",   action="store_true",
                        help="Hitung ulang setiap jam (mode daemon)")
    parser.add_argument("--no-save", action="store_true",
                        help="Jangan simpan hasil")
    args = parser.parse_args()

    log_header("Selene — Health Score v3.0",
               "Nilai kesehatan keamanan sistem dari A+ hingga F")

    if args.history:
        show_history()
        print()
        return

    if args.watch:
        log("INFO", c("Mode watch — hitung ulang setiap jam. Ctrl+C untuk berhenti.", Fore.CYAN))
        while True:
            try:
                data = run_all_checks(False)
                print_results(data, False)
                if not args.no_save:
                    save_health(data)
                log("INFO", f"Berikutnya: {(datetime.now() + timedelta(hours=1)).strftime('%H:%M')}")
                time.sleep(3600)
            except KeyboardInterrupt:
                break
        print()
        return

    log("SCAN", "Menjalankan semua cek keamanan...")
    print()

    data = run_all_checks(args.detail)
    print_results(data, args.detail)

    if not args.no_save:
        save_health(data)
        log("OK", c(f"Health score disimpan. Grade: {data['grade']} ({data['score']}/100)", Fore.GREEN, bold=True))

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
