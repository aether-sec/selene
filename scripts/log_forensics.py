#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Log Forensics v3.0                                ║
║   Analisis log & rekonstruksi timeline serangan.             ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/log_forensics.py
  python scripts/log_forensics.py --ip 10.0.0.5
  python scripts/log_forensics.py --since "2024-01-01"
  python scripts/log_forensics.py --export html
  python scripts/log_forensics.py --source ssh

Sumber log yang dianalisis:
  • /var/log/auth.log      (SSH, sudo, login gagal)
  • /var/log/syslog        (system events)
  • Nginx / Apache logs    (HTTP attacks)
  • Selene alerts.jsonl    (ancaman yang dicatat Selene)
  • Selene honeypot logs   (interaksi honeypot)
"""

import sys
import os
import re
import gzip
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        read_jsonl, save_json, LOGS_DIR, REPORTS_DIR,
        IS_LINUX,
    )
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

TOOL_VERSION = "3.0.0"

# ── Pola regex untuk parsing log ─────────────────────────────────────────────

# Auth.log SSH patterns
RE_SSH_FAIL = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"sshd\[.*\]:\s+Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)
RE_SSH_ACCEPT = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"sshd\[.*\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)
RE_SSH_INVALID = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"sshd\[.*\]:\s+Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)
RE_SUDO_FAIL = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"sudo\[.*\]:\s+(?P<user>\S+).*FAILED"
)
RE_PAM_FAIL = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*"
    r"pam_unix.*:\s+authentication failure.*rhost=(?P<ip>[\d.]+)?"
    r"(?:.*user=(?P<user>\S+))?"
)

# HTTP log (nginx/apache combined log format)
RE_HTTP = re.compile(
    r'(?P<ip>[\d.]+) - .* \[(?P<dt>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>[^\s"]+)[^"]*" (?P<status>\d+) (?P<size>\d+)'
)

# HTTP attack patterns
HTTP_ATTACKS = [
    (re.compile(r"(?:union\s+select|drop\s+table|insert\s+into"
                r"|'\s*or\s*'1'\s*=|'\s*or\s*1\s*=\s*1"
                r"|\bor\s+1\s*=\s*1\b|--(?:\s|$)|/\*.*?\*/)", re.I), "SQL Injection"),
    (re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(", re.I), "XSS"),
    (re.compile(r"\.\./|etc/passwd|etc/shadow|proc/self", re.I), "Path Traversal"),
    (re.compile(r"(?:;|&&|\|\|)\s*(?:cat|ls|id|whoami|wget|curl|bash|nc)\b", re.I), "Command Injection"),
    (re.compile(r"\$\{jndi:", re.I), "Log4Shell"),
    (re.compile(r"(?:masscan|nmap|nikto|sqlmap|hydra|acunetix|nessus|burp)", re.I), "Scanner"),
    (re.compile(r"(?:/wp-admin|/phpmyadmin|/.env|/.git/config|/xmlrpc)", re.I), "Sensitive Path Probe"),
    (re.compile(r"(?:cmd\.exe|/bin/sh|/bin/bash|powershell)", re.I), "Shell Probe"),
]

# ── Timestamp parsing ─────────────────────────────────────────────────────────
MONTH_MAP = {
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
    "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12,
    "Jan":1,"Feb":2,"Mar":3,"Apr":4,"Mei":5,"Jun":6,
    "Jul":7,"Agu":8,"Sep":9,"Okt":10,"Nov":11,"Des":12,
}

def parse_syslog_ts(month: str, day: str, time_str: str,
                    year: int = None) -> Optional[datetime]:
    """Parse timestamp format syslog: Jan  5 10:23:45"""
    try:
        y = year or datetime.now().year
        m = MONTH_MAP.get(month[:3].capitalize(), 1)
        d = int(day)
        h, mn, s = (int(x) for x in time_str.split(":"))
        dt = datetime(y, m, d, h, mn, s)
        # Jika lebih dari 6 bulan di masa depan, kemungkinan tahun lalu
        if (dt - datetime.now()).days > 180:
            dt = datetime(y-1, m, d, h, mn, s)
        return dt
    except Exception:
        return None

def parse_http_ts(ts_str: str) -> Optional[datetime]:
    """Parse HTTP log timestamp: 01/Jan/2024:10:23:45 +0700"""
    try:
        return datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None

# ── Log readers ───────────────────────────────────────────────────────────────

def read_log_file(path: Path) -> List[str]:
    """Baca file log, support .gz."""
    try:
        if path.suffix == ".gz":
            with gzip.open(str(path), "rt", errors="ignore") as f:
                return f.readlines()
        else:
            return path.read_text(errors="ignore").splitlines()
    except (OSError, PermissionError):
        return []

def parse_auth_log(since: Optional[datetime] = None,
                   filter_ip: Optional[str] = None) -> List[Dict]:
    """Parse /var/log/auth.log untuk event SSH dan autentikasi."""
    events = []

    LOG_PATHS = [
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
        # Rotated logs
        Path("/var/log/auth.log.1"),
        Path("/var/log/auth.log.2.gz"),
    ]

    year = datetime.now().year

    for log_path in LOG_PATHS:
        if not log_path.exists():
            continue

        lines = read_log_file(log_path)
        for line in lines:
            event = None

            # SSH failed
            m = RE_SSH_FAIL.search(line)
            if m:
                ts = parse_syslog_ts(m.group("month"), m.group("day"),
                                     m.group("time"), year)
                event = {
                    "timestamp": ts.isoformat() if ts else "?",
                    "type":      "ssh_fail",
                    "category":  "Authentication",
                    "severity":  "WARN",
                    "ip":        m.group("ip"),
                    "user":      m.group("user"),
                    "message":   f"SSH login gagal: user '{m.group('user')}' dari {m.group('ip')}",
                    "source":    str(log_path),
                }

            # SSH accepted
            elif (m := RE_SSH_ACCEPT.search(line)):
                ts = parse_syslog_ts(m.group("month"), m.group("day"),
                                     m.group("time"), year)
                event = {
                    "timestamp": ts.isoformat() if ts else "?",
                    "type":      "ssh_accept",
                    "category":  "Authentication",
                    "severity":  "INFO",
                    "ip":        m.group("ip"),
                    "user":      m.group("user"),
                    "message":   f"SSH login berhasil: user '{m.group('user')}' dari {m.group('ip')}",
                    "source":    str(log_path),
                }

            # Invalid user
            elif (m := RE_SSH_INVALID.search(line)):
                ts = parse_syslog_ts(m.group("month"), m.group("day"),
                                     m.group("time"), year)
                event = {
                    "timestamp": ts.isoformat() if ts else "?",
                    "type":      "ssh_invalid_user",
                    "category":  "Authentication",
                    "severity":  "WARN",
                    "ip":        m.group("ip"),
                    "user":      m.group("user"),
                    "message":   f"Invalid user '{m.group('user')}' dari {m.group('ip')}",
                    "source":    str(log_path),
                }

            if not event:
                continue

            # Filter
            if since and event["timestamp"] != "?":
                try:
                    if datetime.fromisoformat(event["timestamp"]) < since:
                        continue
                except (ValueError, TypeError):
                    pass
            if filter_ip and event.get("ip") != filter_ip:
                continue

            events.append(event)

    return events

def parse_http_logs(since: Optional[datetime] = None,
                    filter_ip: Optional[str] = None) -> List[Dict]:
    """Parse Nginx / Apache access logs."""
    events = []

    LOG_DIRS = [
        Path("/var/log/nginx"),
        Path("/var/log/apache2"),
        Path("/var/log/httpd"),
    ]

    for log_dir in LOG_DIRS:
        if not log_dir.exists():
            continue
        for log_file in log_dir.glob("access*.log*"):
            lines = read_log_file(log_file)
            for line in lines:
                m = RE_HTTP.match(line)
                if not m:
                    continue

                ip     = m.group("ip")
                ts     = parse_http_ts(m.group("dt"))
                method = m.group("method")
                path   = m.group("path")
                status = int(m.group("status"))

                if filter_ip and ip != filter_ip:
                    continue
                if since and ts and ts < since:
                    continue

                # Deteksi pola serangan di URL
                attacks = []
                for pattern, name in HTTP_ATTACKS:
                    if pattern.search(path):
                        attacks.append(name)

                if attacks or status in (400, 401, 403, 404, 500):
                    event = {
                        "timestamp": ts.isoformat() if ts else "?",
                        "type":      "http_attack" if attacks else "http_error",
                        "category":  "Web",
                        "severity":  "WARN" if attacks else "INFO",
                        "ip":        ip,
                        "method":    method,
                        "path":      path[:120],
                        "status":    status,
                        "attacks":   attacks,
                        "message":   f"HTTP {method} {path[:60]} [{status}]"
                                     + (f" — {', '.join(attacks)}" if attacks else ""),
                        "source":    str(log_file),
                    }
                    events.append(event)

    return events

def parse_selene_logs(since: Optional[datetime] = None,
                      filter_ip: Optional[str] = None) -> List[Dict]:
    """Parse log Selene sendiri (alerts + honeypot)."""
    events = []

    # Alerts
    for entry in read_jsonl(LOGS_DIR / "alerts.jsonl"):
        ts = entry.get("timestamp","")
        ip = entry.get("ip","")
        if filter_ip and ip != filter_ip:
            continue
        if since and ts:
            try:
                if datetime.fromisoformat(ts) < since:
                    continue
            except (ValueError, TypeError):
                pass
        events.append({
            "timestamp": ts,
            "type":      f"selene_{entry.get('level','?').lower()}",
            "category":  "Selene Alert",
            "severity":  entry.get("level","INFO"),
            "ip":        ip,
            "message":   entry.get("message","?"),
            "source":    "alerts.jsonl",
        })

    # Honeypot
    for entry in read_jsonl(LOGS_DIR / "honeypot_captures.jsonl"):
        ts = entry.get("timestamp","")
        ip = entry.get("client_ip","")
        if filter_ip and ip != filter_ip:
            continue
        if since and ts:
            try:
                if datetime.fromisoformat(ts) < since:
                    continue
            except (ValueError, TypeError):
                pass
        attacks = entry.get("attacks",[])
        events.append({
            "timestamp": ts,
            "type":      "honeypot",
            "category":  "Honeypot",
            "severity":  "WARN" if attacks else "INFO",
            "ip":        ip,
            "service":   entry.get("service","?"),
            "attacks":   attacks,
            "message":   f"Honeypot [{entry.get('service','?')}]"
                         + (f": {', '.join(attacks)}" if attacks else " — koneksi masuk"),
            "source":    "honeypot_captures.jsonl",
        })

    return events

# ── Attacker profiling ────────────────────────────────────────────────────────

def build_attacker_profiles(events: List[Dict]) -> List[Dict]:
    """Bangun profil setiap IP yang terlihat berbahaya."""
    ip_data: Dict[str, Dict] = defaultdict(lambda: {
        "ip":           "",
        "events":       [],
        "ssh_fails":    0,
        "ssh_success":  0,
        "http_attacks": 0,
        "honeypot":     0,
        "first_seen":   None,
        "last_seen":    None,
        "users_tried":  set(),
        "attack_types": set(),
    })

    for ev in events:
        ip = ev.get("ip","")
        if not ip or ip == "?":
            continue

        d = ip_data[ip]
        d["ip"] = ip
        d["events"].append(ev)

        ts = ev.get("timestamp","")
        if ts:
            try:
                dt = datetime.fromisoformat(ts)
                if not d["first_seen"] or dt < d["first_seen"]:
                    d["first_seen"] = dt
                if not d["last_seen"] or dt > d["last_seen"]:
                    d["last_seen"] = dt
            except (ValueError, TypeError):
                pass

        etype = ev.get("type","")
        if "ssh_fail" in etype or "ssh_invalid" in etype:
            d["ssh_fails"] += 1
        if "ssh_accept" in etype:
            d["ssh_success"] += 1
        if "http" in etype and ev.get("attacks"):
            d["http_attacks"] += 1
        if etype == "honeypot":
            d["honeypot"] += 1

        if ev.get("user"):
            d["users_tried"].add(ev["user"])
        for atk in ev.get("attacks",[]):
            d["attack_types"].add(atk)

    # Konversi ke list, hitung skor risiko
    profiles = []
    for ip, d in ip_data.items():
        score = 0
        score += min(d["ssh_fails"] * 2, 40)
        score += min(d["http_attacks"] * 5, 30)
        score += d["honeypot"] * 10
        if d["ssh_success"] > 0:
            score += 50   # Login berhasil setelah banyak fail → sangat mencurigakan
        score = min(score, 100)

        profiles.append({
            "ip":           ip,
            "risk_score":   score,
            "ssh_fails":    d["ssh_fails"],
            "ssh_success":  d["ssh_success"],
            "http_attacks": d["http_attacks"],
            "honeypot_hits":d["honeypot"],
            "total_events": len(d["events"]),
            "first_seen":   d["first_seen"].isoformat() if d["first_seen"] else "?",
            "last_seen":    d["last_seen"].isoformat()  if d["last_seen"]  else "?",
            "users_tried":  sorted(d["users_tried"])[:10],
            "attack_types": sorted(d["attack_types"]),
        })

    return sorted(profiles, key=lambda x: x["risk_score"], reverse=True)

# ── Display ───────────────────────────────────────────────────────────────────

def print_timeline(events: List[Dict], max_events: int = 50) -> None:
    """Cetak timeline event secara kronologis."""

    def _ts_sort_key(ev):
        ts = ev.get("timestamp","")
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return datetime.min

    sorted_events = sorted(events, key=_ts_sort_key, reverse=True)[:max_events]

    if not sorted_events:
        log("INFO", "Tidak ada event yang ditemukan.")
        return

    for ev in sorted_events:
        ts      = ev.get("timestamp","?")[:16]
        msg     = ev.get("message","?")
        ip      = ev.get("ip","")
        sev     = ev.get("severity","INFO")
        attacks = ev.get("attacks",[])

        if sev in ("CRIT","KRITIS") or attacks:
            col = Fore.RED
        elif sev == "WARN":
            col = Fore.YELLOW
        else:
            col = Fore.WHITE

        print(c(f"\n  [{ts}]  {msg}", col))
        if ip:
            print(c(f"            IP: {ip}", Fore.WHITE))
        if attacks:
            print(c(f"            Serangan: {', '.join(attacks)}", Fore.RED))

def print_attacker_profiles(profiles: List[Dict], top_n: int = 10) -> None:
    """Cetak profil penyerang teratas."""
    if not profiles:
        log("INFO", "Tidak ada IP mencurigakan yang terdeteksi.")
        return

    for p in profiles[:top_n]:
        score = p["risk_score"]
        ip    = p["ip"]

        if score >= 70:   col = Fore.RED
        elif score >= 40: col = Fore.YELLOW
        else:             col = Fore.WHITE

        print(c(f"\n  {ip}", col, bold=(score >= 70)))
        print(c(f"    Skor risiko  : {score}/100", col))
        print(c(f"    SSH gagal    : {p['ssh_fails']}", Fore.WHITE))
        if p["ssh_success"] > 0:
            print(c(f"    SSH BERHASIL : {p['ssh_success']} ← PERHATIAN!", Fore.RED, bold=True))
        print(c(f"    HTTP attack  : {p['http_attacks']}", Fore.WHITE))
        print(c(f"    Honeypot     : {p['honeypot_hits']}", Fore.WHITE))
        print(c(f"    Total events : {p['total_events']}", Fore.WHITE))
        print(c(f"    Pertama      : {p['first_seen'][:16]}", Fore.WHITE))
        print(c(f"    Terakhir     : {p['last_seen'][:16]}", Fore.WHITE))
        if p["users_tried"]:
            print(c(f"    User dicoba  : {', '.join(p['users_tried'][:5])}", Fore.WHITE))
        if p["attack_types"]:
            print(c(f"    Jenis serangan: {', '.join(p['attack_types'])}", Fore.RED))

# ── HTML export ───────────────────────────────────────────────────────────────

def export_html(events: List[Dict], profiles: List[Dict], outpath: Path) -> None:
    """Export laporan sebagai HTML interaktif."""
    total  = len(events)
    warns  = sum(1 for e in events if e.get("severity") in ("WARN","CRIT"))
    kritis = sum(1 for e in events if e.get("severity") == "CRIT")
    now    = datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = ""
    for ev in sorted(events, key=lambda e: e.get("timestamp",""), reverse=True)[:500]:
        ts      = ev.get("timestamp","")[:16]
        msg     = ev.get("message","?").replace("<","&lt;").replace(">","&gt;")
        ip      = ev.get("ip","—")
        sev     = ev.get("severity","INFO")
        attacks = ", ".join(ev.get("attacks",[]))
        cat     = ev.get("category","?")

        row_class = "critical" if sev == "CRIT" else ("warn" if sev == "WARN" else "info")
        rows += (
            f"<tr class='{row_class}'>"
            f"<td>{ts}</td><td>{ip}</td><td>{cat}</td>"
            f"<td>{msg}</td><td>{attacks or '—'}</td>"
            f"</tr>\n"
        )

    profile_rows = ""
    for p in profiles[:20]:
        score = p["risk_score"]
        cls   = "critical" if score >= 70 else ("warn" if score >= 40 else "")
        profile_rows += (
            f"<tr class='{cls}'>"
            f"<td>{p['ip']}</td><td>{score}</td>"
            f"<td>{p['ssh_fails']}</td><td>{p['ssh_success']}</td>"
            f"<td>{p['http_attacks']}</td><td>{p['last_seen'][:16]}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>Selene Log Forensics — {now}</title>
<style>
  body {{font-family:monospace;background:#0d1117;color:#e6edf3;padding:2em}}
  h1,h2 {{color:#58a6ff}} h3 {{color:#f78166}}
  .stats {{display:flex;gap:2em;margin:1em 0}}
  .stat  {{background:#161b22;padding:1em 2em;border-radius:8px;text-align:center}}
  .stat .num {{font-size:2em;font-weight:bold;color:#58a6ff}}
  .stat .lbl {{color:#8b949e;font-size:0.8em}}
  table  {{width:100%;border-collapse:collapse;margin:1em 0;font-size:0.85em}}
  th     {{background:#21262d;color:#f0f6fc;padding:8px;text-align:left;position:sticky;top:0}}
  td     {{padding:6px 8px;border-bottom:1px solid #21262d;word-break:break-all}}
  .critical td {{color:#ff7b72;background:#1a0000}}
  .warn     td {{color:#d29922}}
  .info     td {{color:#8b949e}}
  tr:hover  td {{background:#1f2937}}
</style>
</head>
<body>
<h1>🌙 Selene — Log Forensics Report</h1>
<p style="color:#8b949e">Dibuat: {now}</p>
<div class="stats">
  <div class="stat"><div class="num">{total}</div><div class="lbl">Total Events</div></div>
  <div class="stat"><div class="num" style="color:#d29922">{warns}</div><div class="lbl">Peringatan</div></div>
  <div class="stat"><div class="num" style="color:#ff7b72">{kritis}</div><div class="lbl">Kritis</div></div>
  <div class="stat"><div class="num">{len(profiles)}</div><div class="lbl">IP Unik</div></div>
</div>
<h2>📋 Timeline Event</h2>
<table>
<tr><th>Waktu</th><th>IP</th><th>Kategori</th><th>Pesan</th><th>Serangan</th></tr>
{rows}
</table>
<h2>🎯 Profil Penyerang</h2>
<table>
<tr><th>IP</th><th>Skor</th><th>SSH Gagal</th><th>SSH Sukses</th><th>HTTP Attack</th><th>Terakhir</th></tr>
{profile_rows}
</table>
</body>
</html>"""

    outpath.write_text(html, encoding="utf-8")
    log("OK", c(f"HTML report: {outpath}", Fore.GREEN))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Log Forensics — Analisis log & rekonstruksi timeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/log_forensics.py
  python scripts/log_forensics.py --ip 10.0.0.5
  python scripts/log_forensics.py --since 2024-01-01
  python scripts/log_forensics.py --source ssh
  python scripts/log_forensics.py --export html"""
    )
    parser.add_argument("--ip",     help="Filter berdasarkan IP")
    parser.add_argument("--since",  help="Event sejak tanggal (YYYY-MM-DD atau YYYY-MM-DDTHH:MM)")
    parser.add_argument("--source", choices=["ssh","http","selene","all"], default="all",
                        help="Sumber log yang dianalisis")
    parser.add_argument("--export", choices=["html","json"], default=None,
                        help="Export laporan")
    parser.add_argument("--top",    type=int, default=50, metavar="N",
                        help="Tampilkan N event terbaru (default: 50)")
    parser.add_argument("--no-profile", action="store_true",
                        help="Skip profiling penyerang")
    args = parser.parse_args()

    log_header("Selene — Log Forensics v3.0",
               "Analisis log & rekonstruksi timeline serangan")

    # Parse --since
    since = None
    if args.since:
        try:
            if "T" in args.since or " " in args.since:
                since = datetime.fromisoformat(args.since.replace(" ","T"))
            else:
                since = datetime.strptime(args.since, "%Y-%m-%d")
        except ValueError:
            log("ERROR", f"Format tanggal tidak valid: {args.since}")
            log("INFO",  "Gunakan format: YYYY-MM-DD atau YYYY-MM-DDTHH:MM")
            sys.exit(1)

    # Kumpulkan events
    log("SCAN", "Menganalisis log...")
    all_events = []

    if args.source in ("ssh","all") and IS_LINUX:
        ssh_events = parse_auth_log(since, args.ip)
        log("INFO", c(f"SSH/Auth : {len(ssh_events)} event", Fore.WHITE))
        all_events.extend(ssh_events)

    if args.source in ("http","all") and IS_LINUX:
        http_events = parse_http_logs(since, args.ip)
        log("INFO", c(f"HTTP     : {len(http_events)} event", Fore.WHITE))
        all_events.extend(http_events)

    if args.source in ("selene","all"):
        selene_events = parse_selene_logs(since, args.ip)
        log("INFO", c(f"Selene   : {len(selene_events)} event", Fore.WHITE))
        all_events.extend(selene_events)

    if not all_events:
        if not IS_LINUX:
            log("INFO", "Analisis SSH dan HTTP hanya tersedia di Linux.")
            log("INFO", "Log Selene (alerts, honeypot) masih dianalisis.")
        log("INFO", "Tidak ada event yang ditemukan.")
        return

    log("OK", c(f"Total: {len(all_events)} event", Fore.GREEN, bold=True))

    # Timeline
    log_section(f"TIMELINE ({min(args.top, len(all_events))} event terbaru)")
    print_timeline(all_events, max_events=args.top)

    # Profil penyerang
    if not args.no_profile:
        profiles = build_attacker_profiles(all_events)
        log_section(f"PROFIL PENYERANG ({len(profiles)} IP unik)")
        print_attacker_profiles(profiles, top_n=10)
    else:
        profiles = []

    # Ringkasan
    log_section("RINGKASAN")
    warns  = sum(1 for e in all_events if e.get("severity") == "WARN")
    crits  = sum(1 for e in all_events if e.get("severity") == "CRIT")
    ips    = len({e.get("ip") for e in all_events if e.get("ip")})
    attacks= sum(len(e.get("attacks",[])) for e in all_events)

    print(c(f"\n  Total event   : {len(all_events)}", Fore.WHITE))
    print(c(f"  Peringatan    : {warns}",
            Fore.YELLOW if warns else Fore.GREEN))
    print(c(f"  Kritis        : {crits}",
            Fore.RED if crits else Fore.GREEN, bold=bool(crits)))
    print(c(f"  IP unik       : {ips}", Fore.WHITE))
    print(c(f"  Total serangan: {attacks}",
            Fore.RED if attacks else Fore.GREEN))

    # Export
    if args.export == "html":
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"forensics_{ts}.html"
        export_html(all_events, profiles, path)

    elif args.export == "json":
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"forensics_{ts}.json"
        save_json(path, {
            "tool":      "log_forensics",
            "version":   TOOL_VERSION,
            "generated": datetime.now().isoformat(),
            "events":    all_events,
            "profiles":  profiles,
        })
        log("OK", c(f"JSON report: {path}", Fore.GREEN))

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
