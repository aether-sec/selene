#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Dashboard v3.0                                    ║
║   Web security dashboard — buka di browser, live update.    ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/dashboard.py              ← buka di http://localhost:7331
  python scripts/dashboard.py --port 8080
  python scripts/dashboard.py --no-browser ← jangan buka browser otomatis
  python scripts/dashboard.py --terminal   ← mode terminal klasik (fallback)
  python scripts/dashboard.py --once       ← terminal sekali lalu keluar
"""

import sys, os, time, argparse, json, shutil, socket, threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        c, Fore, log, log_header,
        read_jsonl, load_json,
        IS_LINUX, IS_WINDOWS,
        get_local_ip, get_hostname,
        LOGS_DIR, REPORTS_DIR, DATA_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION = "3.0.0"
DEFAULT_PORT  = 7331

# ════════════════════════════════════════════════════════════════
#  DATA COLLECTORS
# ════════════════════════════════════════════════════════════════

def _fmt_bytes(n: int) -> str:
    for u in ["B","KB","MB","GB","TB"]:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def _fmt_uptime(sec: float) -> str:
    d, r = divmod(int(sec), 86400)
    h, r = divmod(r, 3600)
    m    = r // 60
    if d:  return f"{d}d {h}h {m}m"
    if h:  return f"{h}h {m}m"
    return f"{m}m"

def get_system_stats() -> Dict:
    s = {"cpu":0.0,"ram_pct":0.0,"ram_used":0,"ram_total":0,
         "disk_pct":0.0,"disk_used":0,"disk_total":0,
         "uptime_sec":0,"procs":0,"net_sent":0,"net_recv":0,"load":[0.0,0.0,0.0]}
    if not HAS_PSUTIL: return s
    try:
        s["cpu"]        = psutil.cpu_percent(interval=0.3)
        m               = psutil.virtual_memory()
        s["ram_pct"]    = m.percent
        s["ram_used"]   = m.used
        s["ram_total"]  = m.total
        d               = psutil.disk_usage("/")
        s["disk_pct"]   = d.percent
        s["disk_used"]  = d.used
        s["disk_total"] = d.total
        s["uptime_sec"] = time.time() - psutil.boot_time()
        s["procs"]      = len(psutil.pids())
        n               = psutil.net_io_counters()
        s["net_sent"]   = n.bytes_sent
        s["net_recv"]   = n.bytes_recv
        if IS_LINUX:
            s["load"]   = list(os.getloadavg())
    except Exception:
        pass
    return s

def get_alert_stats() -> Dict:
    now  = datetime.now()
    cuts = {"1h": now-timedelta(hours=1), "24h": now-timedelta(hours=24), "7d": now-timedelta(days=7)}
    cnt  = {k: 0 for k in cuts}
    crit = 0
    by_day: Dict[str,int] = {}
    top_ips: Dict[str,int] = {}
    alerts = read_jsonl(LOGS_DIR / "alerts.jsonl", last_n=1000)

    for a in alerts:
        ts_str = a.get("timestamp","")
        try:
            ts  = datetime.fromisoformat(ts_str)
            day = ts.strftime("%m/%d")
            by_day[day] = by_day.get(day, 0) + 1
            for k, cut in cuts.items():
                if ts > cut: cnt[k] += 1
            if ts > cuts["24h"] and a.get("level") in ("CRIT","KRITIS"):
                crit += 1
        except Exception:
            pass
        ip = a.get("ip","")
        if ip: top_ips[ip] = top_ips.get(ip, 0) + 1

    recent = sorted(alerts, key=lambda x: x.get("timestamp",""), reverse=True)[:10]
    return {
        **cnt, "total": len(alerts), "crit_24h": crit,
        "by_day": by_day,
        "top_ips": sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5],
        "recent": recent,
    }

def get_honeypot_stats() -> Dict:
    caps  = read_jsonl(LOGS_DIR / "honeypot_captures.jsonl", last_n=500)
    h24   = datetime.now() - timedelta(hours=24)
    today = 0; attacks = 0
    by_svc: Dict[str,int] = {}
    top_ips: Dict[str,int] = {}
    for cap in caps:
        try:
            ts = datetime.fromisoformat(cap.get("timestamp",""))
            if ts > h24:
                today += 1
                svc    = cap.get("service","?")
                by_svc[svc] = by_svc.get(svc, 0) + 1
                if cap.get("attacks"): attacks += 1
                ip = cap.get("client_ip","")
                if ip: top_ips[ip] = top_ips.get(ip, 0) + 1
        except Exception:
            pass
    return {
        "today": today, "attacks_24h": attacks, "total": len(caps),
        "by_service": sorted(by_svc.items(), key=lambda x: x[1], reverse=True)[:5],
        "top_ips":    sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:5],
    }

def get_health() -> Dict:
    h = load_json(DATA_DIR / "health.json", {})
    return h if h else {"score": None, "grade": "?", "generated": "",
                        "categories": {}}

def get_last_scans() -> List[Dict]:
    scans = []
    if not REPORTS_DIR.exists(): return scans
    for prefix, label in [
        ("scan_","Network Scan"), ("vuln_","Vuln Scan"),
        ("hardener_","Hardener"), ("wifi_","WiFi"),
        ("privacy_","Privacy"), ("forensics_","Forensics"),
        ("report_","Report"),
    ]:
        files = sorted(REPORTS_DIR.glob(f"{prefix}*.json"), reverse=True)
        if files:
            f   = files[0]
            mt  = datetime.fromtimestamp(f.stat().st_mtime)
            age = datetime.now() - mt
            scans.append({
                "label": label, "file": f.name,
                "age_h": round(age.total_seconds() / 3600, 1),
                "mtime": mt.strftime("%Y-%m-%d %H:%M"),
            })
    return sorted(scans, key=lambda x: x["age_h"])[:8]

def get_connections() -> List[Dict]:
    if not HAS_PSUTIL: return []
    conns = []
    BAD   = {4444, 31337, 1337, 6666, 9999, 12345}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                proc = "?"
                try:
                    if conn.pid: proc = psutil.Process(conn.pid).name()[:16]
                except Exception: pass
                conns.append({
                    "proc": proc, "rip": conn.raddr.ip, "rport": conn.raddr.port,
                    "suspicious": conn.raddr.port in BAD,
                })
    except Exception: pass
    return conns[:8]

def get_blocked_ips() -> int:
    if not IS_LINUX or not shutil.which("iptables"): return 0
    try:
        import subprocess
        r = subprocess.run(["iptables","-L","INPUT","-n"],
                           capture_output=True, text=True, timeout=3)
        return r.stdout.count("DROP")
    except Exception: return 0

def get_health_history() -> List[Dict]:
    hist = read_jsonl(DATA_DIR / "health_history.jsonl", last_n=14)
    result = []
    for h in hist:
        ts = h.get("timestamp","")[:10]
        if ts: result.append({"date": ts, "score": h.get("score", 0)})
    return result

def get_backup_log() -> List[Dict]:
    entries = read_jsonl(LOGS_DIR / "backup_log.jsonl", last_n=5)
    return [e for e in entries if e.get("action") == "backup"]

def collect_all() -> Dict:
    sys_s = get_system_stats()
    return {
        "meta": {
            "hostname":  get_hostname(),
            "ip":        get_local_ip(),
            "timestamp": datetime.now().isoformat(),
            "version":   TOOL_VERSION,
        },
        "system": {
            **sys_s,
            "uptime_str":     _fmt_uptime(sys_s["uptime_sec"]),
            "ram_used_str":   _fmt_bytes(sys_s["ram_used"]),
            "ram_total_str":  _fmt_bytes(sys_s["ram_total"]),
            "disk_used_str":  _fmt_bytes(sys_s["disk_used"]),
            "disk_total_str": _fmt_bytes(sys_s["disk_total"]),
            "net_sent_str":   _fmt_bytes(sys_s["net_sent"]),
            "net_recv_str":   _fmt_bytes(sys_s["net_recv"]),
        },
        "alerts":          get_alert_stats(),
        "honeypot":        get_honeypot_stats(),
        "health":          get_health(),
        "health_history":  get_health_history(),
        "scans":           get_last_scans(),
        "connections":     get_connections(),
        "blocked_ips":     get_blocked_ips(),
        "backups":         get_backup_log(),
    }


# ════════════════════════════════════════════════════════════════
#  HTML PAGE (served once — JS fetches /api/data every 10s)
# ════════════════════════════════════════════════════════════════

HTML_PAGE = """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Selene Security Dashboard</title>
<style>
:root{
  --bg:#070b10; --bg2:#0c1520; --bg3:#111e2e; --border:#182840;
  --accent:#00d4ff; --accent2:#7b5ea7; --green:#00e676;
  --yellow:#ffb300; --red:#ff3d57; --text:#c8daf0; --muted:#3a5570;
  --glow:0 0 24px rgba(0,212,255,.12);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'JetBrains Mono','Fira Code','Cascadia Code','Consolas','Courier New',monospace;background:var(--bg);color:var(--text);min-height:100vh;
  background-image:radial-gradient(ellipse at 15% 8%,rgba(0,212,255,.04) 0%,transparent 55%),
                   radial-gradient(ellipse at 88% 92%,rgba(123,94,167,.04) 0%,transparent 55%),
                   url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60'%3E%3Ccircle cx='1' cy='1' r='.5' fill='%23ffffff06'/%3E%3C/svg%3E");}
/* Header */
header{background:rgba(12,21,32,.96);border-bottom:1px solid var(--border);padding:.7rem 1.5rem;
  display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;
  backdrop-filter:blur(12px);}
.logo{display:flex;align-items:center;gap:.7rem}
.logo-moon{font-size:1.6rem;filter:drop-shadow(0 0 10px rgba(0,212,255,.6));animation:moonpulse 4s ease-in-out infinite}
@keyframes moonpulse{0%,100%{filter:drop-shadow(0 0 10px rgba(0,212,255,.5))}50%{filter:drop-shadow(0 0 18px rgba(0,212,255,.9))}}
.logo h1{font-size:.95rem;font-weight:800;letter-spacing:.22em;text-transform:uppercase;color:var(--accent)}
.logo p{font-size:.58rem;color:var(--muted);letter-spacing:.12em;margin-top:1px}
.hdr-meta{display:flex;align-items:center;gap:1.2rem;font-size:.7rem}
.hdr-host .name{color:var(--accent);font-weight:700;font-size:.82rem}
.hdr-host .ip{color:var(--muted)}
.hdr-time .t{color:var(--text);font-weight:700;font-size:.85rem;letter-spacing:.04em}
.hdr-time .d{color:var(--muted)}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);
  box-shadow:0 0 8px var(--green);animation:blink 2.2s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
/* Tabs */
.tabs{display:flex;gap:3px}
.tab{background:transparent;border:1px solid transparent;color:var(--muted);
  padding:3px 12px;border-radius:5px;font-size:.62rem;cursor:pointer;font-family:inherit;
  letter-spacing:.1em;transition:all .15s}
.tab.active{background:rgba(0,212,255,.1);border-color:rgba(0,212,255,.35);color:var(--accent)}
/* Layout */
.wrap{max-width:1380px;margin:0 auto;padding:1rem 1.5rem 2rem}
.section-label{font-size:.58rem;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);
  margin:1.2rem 0 .6rem;display:flex;align-items:center;gap:.6rem}
.section-label::after{content:'';flex:1;height:1px;background:var(--border)}
/* Grids */
.g4{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:.7rem;margin-bottom:.7rem}
.g3{display:grid;grid-template-columns:1fr 1.5fr 1fr;gap:.7rem;margin-bottom:.7rem}
.g2{display:grid;grid-template-columns:1.6fr 1fr;gap:.7rem;margin-bottom:.7rem}
@media(max-width:1100px){.g4,.g3{grid-template-columns:repeat(2,1fr)}.g2{grid-template-columns:1fr}}
@media(max-width:640px){.g4,.g3{grid-template-columns:1fr}}
/* Card */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:9px;
  padding:1rem 1.1rem;position:relative;overflow:hidden;
  transition:border-color .2s,box-shadow .2s;animation:fadeUp .4s ease both}
.card:hover{border-color:rgba(0,212,255,.25);box-shadow:var(--glow)}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:0;transition:opacity .2s}
.card:hover::before{opacity:1}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.card-title{font-size:.58rem;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);
  margin-bottom:.7rem;display:flex;align-items:center;gap:5px}
.card-title .ic{font-size:.9rem}
/* Stat */
.stat-num{font-size:2.2rem;font-weight:800;line-height:1;letter-spacing:-.02em;margin-bottom:.25rem}
.stat-lbl{font-size:.62rem;color:var(--muted)}
.g{color:var(--green)}.y{color:var(--yellow)}.r{color:var(--red)}.a{color:var(--accent)}.m{color:var(--muted)}
/* Health ring */
.health-wrap{display:flex;align-items:center;gap:1.2rem}
.ring-info .grade-label{font-size:.72rem;font-weight:700;margin-bottom:.2rem}
.ring-info .desc{font-size:.62rem;color:var(--muted)}
/* Progress bars */
.res-row{display:flex;align-items:center;gap:.6rem;margin-bottom:.45rem}
.res-lbl{font-size:.6rem;color:var(--muted);width:2.8rem;flex-shrink:0}
.res-bar{flex:1;height:5px;background:var(--bg3);border-radius:3px;overflow:hidden}
.res-fill{height:100%;border-radius:3px;transition:width .7s ease;box-shadow:0 0 5px currentColor}
.res-val{font-size:.65rem;width:4.5rem;text-align:right;flex-shrink:0}
/* Alert items */
.al-item{display:flex;gap:.5rem;align-items:flex-start;padding:.38rem 0;
  border-bottom:1px solid rgba(24,40,64,.5)}
.al-item:last-child{border-bottom:none}
.al-ts{color:var(--muted);font-size:.6rem;white-space:nowrap;padding-top:2px;width:2.8rem;flex-shrink:0}
.al-msg{font-size:.7rem;color:var(--text);flex:1}
.al-ip{font-size:.62rem;color:var(--red);margin-top:2px}
/* Badge */
.bdg{display:inline-block;padding:1px 5px;border-radius:3px;font-size:.58rem;font-weight:700;letter-spacing:.04em}
.bdg-r{background:rgba(255,61,87,.15);color:var(--red)}
.bdg-y{background:rgba(255,179,0,.15);color:var(--yellow)}
.bdg-b{background:rgba(0,212,255,.12);color:var(--accent)}
.bdg-g{background:rgba(0,230,118,.12);color:var(--green)}
/* Tables */
.mt{width:100%;border-collapse:collapse;font-size:.68rem;margin-top:.4rem}
.mt th{text-align:left;color:var(--muted);font-size:.57rem;letter-spacing:.1em;
  padding:.25rem .4rem;border-bottom:1px solid var(--border)}
.mt td{padding:.3rem .4rem;border-bottom:1px solid rgba(24,40,64,.4)}
.mt tr:last-child td{border-bottom:none}
.mt tr:hover td{background:rgba(0,212,255,.03)}
/* Connection rows */
.conn{display:flex;justify-content:space-between;padding:.28rem 0;
  border-bottom:1px solid rgba(24,40,64,.4);font-size:.68rem}
.conn:last-child{border-bottom:none}
/* Spark */
.spark{display:flex;align-items:flex-end;gap:2px;height:34px;margin-top:.5rem}
.sp-bar{flex:1;min-height:2px;border-radius:2px 2px 0 0;opacity:.75;transition:opacity .2s}
.sp-bar:hover{opacity:1}
/* Scan grid */
.scan-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:5px;margin-top:.3rem}
.scan-item{padding:4px 7px;background:rgba(0,0,0,.3);border:1px solid var(--border);
  border-radius:5px;display:flex;justify-content:space-between;font-size:.65rem}
/* Recommendations */
.rec{padding:.55rem .7rem;border-left:2px solid var(--accent);margin-bottom:.45rem;
  background:rgba(0,0,0,.3);border-radius:0 5px 5px 0}
.rec-title{font-size:.7rem;font-weight:700;margin-bottom:.2rem}
.rec-cmd{font-size:.6rem;color:var(--muted);font-family:monospace;
  background:rgba(0,0,0,.5);padding:2px 5px;border-radius:3px;display:inline-block;margin-top:2px}
/* Cat bars */
.cat-row{display:flex;align-items:center;gap:.5rem;margin-bottom:.35rem}
.cat-name{font-size:.6rem;color:var(--muted);width:5.5rem;flex-shrink:0}
.cat-bar{flex:1;height:4px;background:var(--bg3);border-radius:2px;overflow:hidden}
.cat-fill{height:100%;border-radius:2px;box-shadow:0 0 4px currentColor}
.cat-val{font-size:.6rem;width:2.2rem;text-align:right;flex-shrink:0}
/* Health ring SVG */
.ring-num{font:800 1.9rem/1 'JetBrains Mono','Fira Code','Consolas',monospace}
.ring-grade{font:700 1rem/1 'JetBrains Mono','Fira Code','Consolas',monospace}
/* Footer */
footer{border-top:1px solid var(--border);padding:.6rem 1.5rem;
  display:flex;justify-content:space-between;font-size:.6rem;color:var(--muted);
  background:rgba(12,21,32,.7)}
.last-upd{position:fixed;bottom:.8rem;right:.8rem;background:var(--bg2);
  border:1px solid var(--border);padding:.25rem .55rem;border-radius:5px;font-size:.58rem;color:var(--muted)}
/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--accent2)}
/* Warning banner */
.warn-banner{background:rgba(255,61,87,.08);border:1px solid rgba(255,61,87,.25);
  border-radius:7px;padding:.6rem 1rem;margin-bottom:.7rem;font-size:.72rem;color:var(--red);
  display:flex;align-items:center;gap:.6rem}
</style>
</head>
<body>

<header>
  <div class="logo">
    <span class="logo-moon">🌙</span>
    <div><h1>Selene</h1><p>Security Dashboard &bull; v3.0</p></div>
  </div>
  <div class="tabs">
    <button class="tab active" onclick="setTab('overview')">⌘ Overview</button>
    <button class="tab" onclick="setTab('threats')">⚠ Ancaman</button>
    <button class="tab" onclick="setTab('system')">🖥 Sistem</button>
  </div>
  <div class="hdr-meta">
    <div class="hdr-host"><div class="name" id="hdr-host">—</div><div class="ip" id="hdr-ip">—</div></div>
    <div class="hdr-time"><div class="t" id="hdr-time">—</div><div class="d" id="hdr-date">—</div></div>
    <div class="live-dot" title="Live — auto-refresh 10 detik"></div>
  </div>
</header>

<div class="wrap" id="tab-overview">

  <!-- Critical banner (hidden by default) -->
  <div class="warn-banner" id="crit-banner" style="display:none">
    ⛔ <strong>Alert KRITIS aktif!</strong> &nbsp;Cek segera:
    <code style="background:rgba(0,0,0,.4);padding:1px 6px;border-radius:3px">
      python scripts/log_forensics.py
    </code>
  </div>

  <!-- ── Baris 1: Health + Alert + Honeypot + Blocked -->
  <div class="section-label"><span>⚡ Status Keamanan</span></div>
  <div class="g4">

    <!-- Health Score -->
    <div class="card">
      <div class="card-title"><span class="ic">💚</span> Security Health Score</div>
      <div class="health-wrap">
        <svg id="health-ring" width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="50" fill="none" stroke="#182840" stroke-width="10"/>
          <circle id="ring-bg-glow" cx="60" cy="60" r="50" fill="none" stroke="#00d4ff" stroke-width="10" stroke-opacity=".08"/>
          <circle id="ring-arc" cx="60" cy="60" r="50" fill="none" stroke="#00d4ff" stroke-width="10"
            stroke-linecap="round" stroke-dasharray="314" stroke-dashoffset="314"
            transform="rotate(-90 60 60)" style="transition:stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1);filter:drop-shadow(0 0 5px #00d4ff)"/>
          <text id="ring-num" x="60" y="55" text-anchor="middle" fill="#00d4ff"
            style="font:800 1.7rem/1 'JetBrains Mono',monospace">?</text>
          <text id="ring-grade" x="60" y="76" text-anchor="middle" fill="#00d4ff"
            style="font:700 .95rem/1 'JetBrains Mono',monospace">?</text>
        </svg>
        <div class="ring-info">
          <div class="grade-label" id="grade-label" style="color:#00d4ff">Belum dihitung</div>
          <div class="desc">dari 100 poin<br><span id="health-ts" style="color:#3a5570">—</span></div>
          <div style="margin-top:.6rem">
            <div id="h-progress" style="height:5px;background:#182840;border-radius:3px;overflow:hidden;width:120px">
              <div id="h-progress-fill" style="height:100%;width:0%;border-radius:3px;background:#00d4ff;
                box-shadow:0 0 6px #00d4ff;transition:width 1s ease"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Alerts -->
    <div class="card">
      <div class="card-title"><span class="ic">⚠️</span> Alerts</div>
      <div class="stat-num a" id="a-24h">—</div>
      <div class="stat-lbl">24 jam terakhir</div>
      <div style="margin-top:.6rem;font-size:.68rem;display:flex;gap:.8rem;flex-wrap:wrap">
        <div><span class="m">1j </span><strong id="a-1h">—</strong></div>
        <div><span class="m">7h </span><strong id="a-7d">—</strong></div>
        <div><strong class="r" id="a-crit">0 KRITIS</strong></div>
      </div>
      <div style="margin-top:.5rem;font-size:.62rem;color:var(--muted)">
        Total: <span id="a-total">—</span>
      </div>
    </div>

    <!-- Honeypot -->
    <div class="card">
      <div class="card-title"><span class="ic">🎣</span> Honeypot</div>
      <div class="stat-num" id="hp-today" style="color:var(--yellow)">—</div>
      <div class="stat-lbl">koneksi masuk 24 jam</div>
      <div style="margin-top:.6rem;font-size:.68rem;display:flex;gap:.8rem">
        <div><span class="m">serangan </span><strong class="r" id="hp-atk">—</strong></div>
        <div><span class="m">total </span><strong id="hp-total">—</strong></div>
      </div>
    </div>

    <!-- Blocked -->
    <div class="card">
      <div class="card-title"><span class="ic">🛡️</span> IP Diblokir</div>
      <div class="stat-num r" id="blk">—</div>
      <div class="stat-lbl">via iptables / threat monitor</div>
      <div style="margin-top:.5rem;font-size:.62rem;color:var(--muted)">auto-block aktif</div>
    </div>
  </div>

  <!-- ── Baris 2: Resources + Health Cats + Koneksi -->
  <div class="section-label"><span>🖥️ Sistem & Jaringan</span></div>
  <div class="g3">

    <!-- Resources -->
    <div class="card">
      <div class="card-title"><span class="ic">📊</span> Resource Real-time</div>
      <div class="res-row">
        <span class="res-lbl">CPU</span>
        <div class="res-bar"><div class="res-fill" id="r-cpu" style="width:0%;color:var(--accent);background:var(--accent)"></div></div>
        <span class="res-val a" id="r-cpu-v">—</span>
      </div>
      <div class="res-row">
        <span class="res-lbl">RAM</span>
        <div class="res-bar"><div class="res-fill" id="r-ram" style="width:0%;color:var(--accent2);background:var(--accent2)"></div></div>
        <span class="res-val" id="r-ram-v" style="color:var(--accent2)">—</span>
      </div>
      <div class="res-row">
        <span class="res-lbl">Disk</span>
        <div class="res-bar"><div class="res-fill" id="r-disk" style="width:0%;color:var(--green);background:var(--green)"></div></div>
        <span class="res-val g" id="r-disk-v">—</span>
      </div>
      <div style="margin-top:.7rem;font-size:.65rem;color:var(--muted);display:flex;gap:1rem;flex-wrap:wrap">
        <div>↑ Uptime <span class="a" id="sys-up">—</span></div>
        <div>Proses <span class="a" id="sys-pr">—</span></div>
        <div>↓ <span id="sys-recv">—</span></div>
        <div>↑ <span id="sys-sent">—</span></div>
      </div>
    </div>

    <!-- Health categories + spark -->
    <div class="card">
      <div class="card-title"><span class="ic">📈</span> Health per Kategori</div>
      <div id="cat-bars"><span class="m" style="font-size:.68rem">Belum ada data — jalankan health_score.py</span></div>
      <div style="margin-top:.7rem">
        <div style="font-size:.57rem;letter-spacing:.12em;color:var(--muted);margin-bottom:3px">TREN 14 HARI</div>
        <div class="spark" id="spark"></div>
      </div>
    </div>

    <!-- Active connections -->
    <div class="card">
      <div class="card-title"><span class="ic">🔗</span> Koneksi Aktif</div>
      <div id="conn-list"><span class="m" style="font-size:.68rem">Memuat...</span></div>
      <div id="conn-warn" style="display:none;margin-top:.6rem;padding:.35rem .55rem;
        background:rgba(255,61,87,.1);border:1px solid rgba(255,61,87,.2);
        border-radius:5px;font-size:.62rem;color:#ff7093">
        ⚠ Koneksi ke port mencurigakan terdeteksi!
      </div>
    </div>
  </div>

  <!-- ── Baris 3: Alert list + Honeypot detail -->
  <div class="section-label"><span>🔍 Detail Ancaman</span></div>
  <div class="g2">

    <!-- Recent alerts -->
    <div class="card">
      <div class="card-title"><span class="ic">📋</span> Alert Terbaru</div>
      <div id="alert-list"><span class="m" style="font-size:.68rem">Belum ada alert</span></div>
    </div>

    <!-- Honeypot breakdown + top IPs -->
    <div class="card">
      <div class="card-title"><span class="ic">🎯</span> Honeypot &amp; Top Penyerang</div>
      <div id="hp-detail"><span class="m" style="font-size:.68rem">Honeypot belum aktif</span></div>
    </div>
  </div>

  <!-- ── Baris 4: Scans + Rekomendasi -->
  <div class="section-label"><span>📂 Scan &amp; Rekomendasi</span></div>
  <div class="g2">
    <div class="card">
      <div class="card-title"><span class="ic">🔬</span> Scan Terakhir</div>
      <div class="scan-grid" id="scan-list"><span class="m" style="font-size:.68rem">Belum ada scan</span></div>
    </div>
    <div class="card">
      <div class="card-title"><span class="ic">💡</span> Rekomendasi Aksi</div>
      <div id="recs"></div>
    </div>
  </div>

</div><!-- /tab-overview -->

<footer>
  <div>🌙 Selene Security Suite v3.0</div>
  <div style="color:#182840;letter-spacing:.08em">⟳ live · auto-refresh 10s</div>
  <div>Laporan: <code style="color:var(--accent)">python scripts/report_engine.py</code></div>
</footer>

<div class="last-upd">⟳ <span id="lupd">—</span></div>

<script>
const $=id=>document.getElementById(id);
const scoreColor=s=>!s?'#3a5570':s>=80?'#00e676':s>=60?'#ffb300':s>=40?'#ff7043':'#ff3d57';
const pColor=p=>p>=80?'#ff3d57':p>=60?'#ffb300':'#00d4ff';
const gradeLabel=g=>({'A+':'Sangat Aman','A':'Sangat Aman','B':'Cukup Aman',
  'C':'Perlu Perhatian','D':'Berisiko','F':'Berisiko Tinggi'}[g]||'Belum dihitung');
const fmtTs=ts=>{try{return new Date(ts.replace(' ','T')).toLocaleTimeString('id-ID',{hour:'2-digit',minute:'2-digit'})}catch{return ts.slice(11,16)||'?'}};

function badge(txt,cls){return`<span class="bdg bdg-${cls}">${txt}</span>`}
function alertBadge(lvl){
  if(lvl==='CRIT'||lvl==='KRITIS') return badge(lvl,'r');
  if(lvl==='WARN') return badge(lvl,'y');
  if(lvl==='OK')   return badge(lvl,'g');
  return badge(lvl,'b');
}

function setTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  event.target.classList.add('active');
}

function renderHealth(h){
  const s=h.score,g=h.grade||'?';
  const col=scoreColor(s);
  $('ring-num').textContent=s??'?'; $('ring-num').setAttribute('fill',col);
  $('ring-grade').textContent=g; $('ring-grade').setAttribute('fill',col);
  $('ring-arc').style.stroke=col; $('ring-arc').style.filter=`drop-shadow(0 0 5px ${col})`;
  $('ring-bg-glow').style.stroke=col;
  const off=314*(1-(s||0)/100);
  $('ring-arc').style.strokeDashoffset=off;
  $('grade-label').textContent=gradeLabel(g); $('grade-label').style.color=col;
  if(h.generated) $('health-ts').textContent='Update: '+h.generated.slice(0,16).replace('T',' ');
  $('h-progress-fill').style.width=(s||0)+'%';
  $('h-progress-fill').style.background=col;
  $('h-progress-fill').style.boxShadow=`0 0 6px ${col}`;
}

function renderSystem(s){
  const pc=(v,el,cls)=>{
    $(el).style.width=v+'%'; $(el).style.color=pColor(v); $(el).style.background=pColor(v);
  };
  pc(s.cpu,'r-cpu'); $('r-cpu-v').textContent=s.cpu.toFixed(1)+'%';
  $('r-cpu-v').style.color=pColor(s.cpu);
  pc(s.ram_pct,'r-ram'); $('r-ram-v').textContent=s.ram_used_str+'/'+s.ram_total_str;
  pc(s.disk_pct,'r-disk'); $('r-disk-v').textContent=s.disk_pct.toFixed(0)+'%';
  $('sys-up').textContent=s.uptime_str||'—';
  $('sys-pr').textContent=s.procs||'—';
  $('sys-recv').textContent='↓ '+s.net_recv_str;
  $('sys-sent').textContent='↑ '+s.net_sent_str;
}

function renderAlerts(a){
  const v24=a['24h']||0,vc=a.crit_24h||0;
  $('a-24h').textContent=v24;
  $('a-24h').style.color=v24>5?'#ff3d57':v24>0?'#ffb300':'#00e676';
  $('a-1h').textContent=a['1h']||0;
  $('a-7d').textContent=a['7d']||0;
  $('a-crit').textContent=vc+' KRITIS';
  $('a-crit').style.color=vc>0?'#ff3d57':'#3a5570';
  $('a-total').textContent=a.total||0;
  $('crit-banner').style.display=vc>0?'flex':'none';

  const list=(a.recent||[]).slice(0,8);
  if(!list.length){$('alert-list').innerHTML='<span class="m" style="font-size:.68rem">✓ Tidak ada alert</span>';return}
  $('alert-list').innerHTML=list.map(al=>`
    <div class="al-item">
      <div class="al-ts">${fmtTs(al.timestamp||'')}</div>
      ${alertBadge(al.level||'INFO')}
      <div><div class="al-msg">${(al.message||'?').slice(0,65)}</div>
        ${al.ip?`<div class="al-ip">${al.ip}</div>`:''}</div>
    </div>`).join('');
}

function renderHoneypot(hp){
  $('hp-today').textContent=hp.today||0;
  $('hp-today').style.color=hp.today>0?'#ffb300':'#00e676';
  $('hp-atk').textContent=hp.attacks_24h||0;
  $('hp-total').textContent=hp.total||0;

  let html='';
  const svcs=hp.by_service||[],ips=hp.top_ips||[];
  if(!svcs.length&&!ips.length){
    $('hp-detail').innerHTML='<span class="m" style="font-size:.68rem">🎣 Honeypot belum aktif atau belum ada koneksi.<br>Jalankan: python scripts/honeypot.py</span>';
    return;
  }
  if(svcs.length){
    html+=`<div style="font-size:.57rem;letter-spacing:.1em;color:var(--muted);margin-bottom:.3rem">PER LAYANAN</div>
      <table class="mt"><thead><tr><th>Service</th><th>Koneksi</th></tr></thead><tbody>
      ${svcs.map(([s,n])=>`<tr><td class="a">${s}</td><td>${n}</td></tr>`).join('')}
      </tbody></table>`;
  }
  if(ips.length){
    html+=`<div style="font-size:.57rem;letter-spacing:.1em;color:var(--muted);margin:.7rem 0 .3rem">TOP PENYERANG</div>
      <table class="mt"><thead><tr><th>IP</th><th>Hit</th><th></th></tr></thead><tbody>
      ${ips.map(([ip,n])=>`<tr><td class="r">${ip}</td><td>${n}</td><td>${n>5?badge('HIGH','r'):badge('LOW','y')}</td></tr>`).join('')}
      </tbody></table>`;
  }
  $('hp-detail').innerHTML=html;
}

function renderConnections(conns){
  if(!conns.length){
    $('conn-list').innerHTML='<span class="m" style="font-size:.68rem">Tidak ada koneksi ESTABLISHED</span>';
    $('conn-warn').style.display='none'; return;
  }
  const hasBad=conns.some(c=>c.suspicious);
  $('conn-warn').style.display=hasBad?'block':'none';
  $('conn-list').innerHTML=conns.map(c=>`
    <div class="conn">
      <span style="color:${c.suspicious?'#ff3d57':'#00d4ff'};font-weight:600">${c.proc}</span>
      <span style="color:${c.suspicious?'#ff7093':'#3a5570'}">${c.rip}:${c.rport}${c.suspicious?' ⚠':''}</span>
    </div>`).join('');
}

function renderCatBars(cats){
  if(!cats||!Object.keys(cats).length){
    $('cat-bars').innerHTML='<span class="m" style="font-size:.68rem">Jalankan: python scripts/health_score.py</span>';
    return;
  }
  const entries=typeof cats==='object'&&!Array.isArray(cats)?Object.values(cats):cats;
  $('cat-bars').innerHTML=entries.map(c=>{
    const pct=c.max?Math.round(c.score*100/c.max):0;
    const col=pct>=75?'#00e676':pct>=50?'#ffb300':'#ff3d57';
    return`<div class="cat-row">
      <div class="cat-name">${c.label||c.name||'?'}</div>
      <div class="cat-bar"><div class="cat-fill" style="width:${pct}%;background:${col};color:${col}"></div></div>
      <div class="cat-val" style="color:${col}">${c.score||0}/${c.max||0}</div>
    </div>`;
  }).join('');
}

function renderSpark(hist){
  if(!hist||!hist.length){$('spark').innerHTML='';return}
  const vals=hist.map(h=>h.score||0);
  const mx=Math.max(...vals,1);
  $('spark').innerHTML=vals.map((v,i)=>{
    const h=Math.max(3,Math.round(34*v/mx));
    const col=v>=80?'#00e676':v>=60?'#ffb300':'#ff7043';
    const isLast=i===vals.length-1;
    return`<div class="sp-bar" title="${hist[i]?.date||i}: ${v}"
      style="height:${h}px;background:${col};${isLast?'box-shadow:0 0 6px '+col+';opacity:1':''}"></div>`;
  }).join('');
}

function renderScans(scans){
  if(!scans.length){$('scan-list').innerHTML='<span class="m" style="font-size:.68rem">Belum ada scan</span>';return}
  $('scan-list').innerHTML=scans.map(s=>{
    const col=s.age_h<2?'#00e676':s.age_h<24?'#ffb300':'#ff3d57';
    const ageStr=s.age_h<1?Math.round(s.age_h*60)+'m':s.age_h<24?s.age_h.toFixed(1)+'j':(s.age_h/24).toFixed(1)+'h';
    return`<div class="scan-item"><span class="m">${s.label}</span><span style="color:${col}">${ageStr}</span></div>`;
  }).join('');
}

function renderRecs(d){
  const recs=[];
  const h=d.health||{},a=d.alerts||{},hp=d.honeypot||{},s=d.system||{};

  if((a.crit_24h||0)>0)
    recs.push(['#ff3d57','⛔ Alert KRITIS aktif','python scripts/log_forensics.py --since 1d']);
  if(!h.score)
    recs.push(['#00d4ff','📊 Hitung Security Health Score','python scripts/health_score.py']);
  else if(h.score<50)
    recs.push(['#ff3d57','🔧 Health Score sangat rendah ('+h.score+'/100)','sudo python scripts/security_hardener.py']);
  else if(h.score<75)
    recs.push(['#ffb300','💡 Health Score bisa ditingkatkan ('+h.score+'/100)','python scripts/health_score.py --detail']);
  if(!hp.today)
    recs.push(['#00d4ff','🎣 Aktifkan Honeypot','python scripts/honeypot.py']);
  if((d.scans||[]).length===0)
    recs.push(['#ffb300','🔍 Lakukan scan pertama','python scripts/network_scanner.py']);
  if((s.cpu||0)>85)
    recs.push(['#ff3d57','🔥 CPU sangat tinggi ('+s.cpu.toFixed(0)+'%)','ps aux --sort=-%cpu | head -10']);
  if(!recs.length)
    recs.push(['#00e676','✅ Semua terlihat aman!','Tetap lakukan scan berkala']);

  $('recs').innerHTML=recs.map(([col,title,cmd])=>`
    <div class="rec" style="border-left-color:${col}">
      <div class="rec-title" style="color:${col}">${title}</div>
      <code class="rec-cmd">${cmd}</code>
    </div>`).join('');
}

// ── Main fetch & render
async function refresh(){
  try{
    const res=await fetch('/api/data');
    const d=await res.json();
    const m=d.meta||{};
    $('hdr-host').textContent=m.hostname||'—';
    $('hdr-ip').textContent=m.ip||'—';
    const now=new Date();
    $('hdr-time').textContent=now.toLocaleTimeString('id-ID');
    $('hdr-date').textContent=now.toLocaleDateString('id-ID',{weekday:'short',day:'numeric',month:'short'});
    $('lupd').textContent=now.toLocaleTimeString('id-ID');

    renderHealth(d.health||{});
    renderSystem(d.system||{});
    renderAlerts(d.alerts||{});
    renderHoneypot(d.honeypot||{});
    renderConnections(d.connections||[]);
    renderCatBars((d.health||{}).categories||{});
    renderSpark(d.health_history||[]);
    renderScans(d.scans||[]);
    renderRecs(d);

    $('blk').textContent=d.blocked_ips||0;
    $('blk').style.color=(d.blocked_ips||0)>0?'#ff3d57':'#00e676';

  }catch(e){$('lupd').textContent='Error: '+e.message}
}

refresh();
setInterval(refresh,10000);
</script>
</body>
</html>"""


# ════════════════════════════════════════════════════════════════
#  HTTP REQUEST HANDLER
# ════════════════════════════════════════════════════════════════

class DashboardHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # suppress default request logs

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8",
                       HTML_PAGE.encode("utf-8"))

        elif path == "/api/data":
            try:
                data    = collect_all()
                payload = json.dumps(data, ensure_ascii=False,
                                     default=str).encode("utf-8")
                self._send(200, "application/json", payload)
            except Exception as e:
                err = json.dumps({"error": str(e)}).encode()
                self._send(500, "application/json", err)

        elif path == "/api/ping":
            self._send(200, "application/json", b'{"status":"ok"}')

        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code: int, ct: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(body))
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def find_free_port(start: int = DEFAULT_PORT) -> int:
    for port in range(start, start + 30):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("", port))
                return port
        except OSError:
            continue
    return start

# ════════════════════════════════════════════════════════════════
#  TERMINAL FALLBACK
# ════════════════════════════════════════════════════════════════

def render_terminal(compact: bool = False):
    W   = shutil.get_terminal_size((80, 24)).columns
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    d   = collect_all()
    s   = d["system"]; a = d["alerts"]; hp = d["honeypot"]
    h   = d["health"]; bl= d["blocked_ips"]

    def bbar(pct, w=12):
        f   = int(w * min(pct, 100) / 100)
        col = Fore.RED if pct >= 80 else (Fore.YELLOW if pct >= 60 else Fore.GREEN)
        return c("█" * f, col) + c("░" * (w - f), Fore.WHITE)

    def div(title=""):
        if title:
            pad = max(0, (W - len(title) - 4) // 2)
            return c(f"  {'─'*pad} {title} {'─'*pad}", Fore.BLUE)
        return c("  " + "─" * max(0, W - 4), Fore.BLUE)

    os.system("cls" if IS_WINDOWS else "clear")

    # Header
    print(c("  ╔" + "═"*(W-4) + "╗", Fore.CYAN))
    title = "🌙  SELENE SECURITY DASHBOARD  v3.0"
    pad   = max(0, (W - 4 - len(title)) // 2)
    print(c(f"  ║{' '*pad}{title}{' '*(max(0,W-4-pad-len(title)))}║", Fore.CYAN, bold=True))
    info  = f"  {get_hostname()}  |  {get_local_ip()}  |  {now}  "
    print(c(f"  ║{info}{' '*max(0,W-4-len(info))}║", Fore.CYAN))
    print(c("  ╚" + "═"*(W-4) + "╝", Fore.CYAN))

    if not compact:
        print(div("SISTEM"))
        cpu = s["cpu"]; ram = s["ram_pct"]; disk = s["disk_pct"]
        print(f"  CPU  {bbar(cpu ,14)}  {cpu :>5.1f}%   "
              f"RAM  {bbar(ram ,14)}  {ram :>5.1f}%  "
              f"({s['ram_used_str']}/{s['ram_total_str']})")
        print(f"  Disk {bbar(disk,14)}  {disk:>5.1f}%   "
              f"Uptime: {c(s['uptime_str'], Fore.WHITE)}   "
              f"Proses: {c(str(s['procs']), Fore.WHITE)}")
        if IS_LINUX and s["load"][0] > 0:
            la = s["load"]
            lc = Fore.RED if la[0] > 4 else (Fore.YELLOW if la[0] > 2 else Fore.GREEN)
            print(f"  Load avg: {c(f'{la[0]:.2f}  {la[1]:.2f}  {la[2]:.2f}', lc)}")

    print(div("KEAMANAN"))

    # Health Score
    hs    = h.get("score"); grade = h.get("grade", "?")
    gcol  = (Fore.GREEN if grade in ("A","A+") else
             Fore.YELLOW if grade in ("B","C") else Fore.RED)
    print(f"\n  Health Score: ", end="")
    if hs is not None:
        filled = int(20 * hs / 100)
        print(c("█"*filled, gcol, bold=True) + c("░"*(20-filled), Fore.WHITE)
              + c(f"  {hs}/100  [{grade}]", gcol, bold=True))
    else:
        print(c("─"*20 + "  Belum dihitung — jalankan: python scripts/health_score.py", Fore.CYAN))

    # Alerts
    a24 = a.get("24h", 0); acrit = a.get("crit_24h", 0)
    a24c = Fore.RED if a24 > 5 else (Fore.YELLOW if a24 > 0 else Fore.GREEN)
    print(f"\n  Alerts  1j: {c(str(a.get('1h',0)), Fore.YELLOW if a.get('1h') else Fore.GREEN)}"
          f"  24j: {c(str(a24), a24c)}"
          f"  KRITIS: {c(str(acrit), Fore.RED if acrit else Fore.GREEN, bold=bool(acrit))}"
          f"  Total: {a.get('total', 0)}")

    # Honeypot
    hp24 = hp.get("today", 0); hpatk = hp.get("attacks_24h", 0)
    print(f"  Honeypot 24j: {c(str(hp24), Fore.RED if hp24 else Fore.GREEN)} koneksi  "
          f"({c(str(hpatk), Fore.RED if hpatk else Fore.GREEN)} serangan)  "
          f"IP Diblokir: {c(str(bl), Fore.RED if bl else Fore.GREEN)}")

    if not compact:
        conns = d["connections"]
        if conns:
            print(div("KONEKSI AKTIF"))
            for conn in conns[:5]:
                col = Fore.RED if conn["suspicious"] else Fore.WHITE
                flag = c(" ⚠ PORT MENCURIGAKAN!", Fore.RED, bold=True) if conn["suspicious"] else ""
                print(f"  {conn['proc']:<16} → "
                      f"{c(conn['rip'], col)}:{c(str(conn['rport']), col)}{flag}")

        scans = d["scans"]
        if scans:
            print(div("SCAN TERAKHIR"))
            for sc in scans[:6]:
                age_col = (Fore.GREEN  if sc["age_h"] < 2
                           else Fore.YELLOW if sc["age_h"] < 24
                           else Fore.RED)
                age_str = (f"{sc['age_h']:.1f}j" if sc["age_h"] < 24
                           else f"{sc['age_h']/24:.1f}h")
                print(f"  {sc['label']:<18} {c(age_str+' lalu', age_col):<20}")

    print(div())

    # Tips
    if acrit > 0:
        print(c("  ⛔ Alert KRITIS! → python scripts/log_forensics.py", Fore.RED, bold=True))
    elif not hs:
        print(c("  💡 Hitung health score → python scripts/health_score.py", Fore.CYAN))
    elif hs < 60:
        print(c(f"  ⚠  Health {hs}/100 → sudo python scripts/security_hardener.py", Fore.YELLOW))
    elif hp24 == 0:
        print(c("  🎣 Aktifkan honeypot → python scripts/honeypot.py", Fore.WHITE))
    else:
        print(c("  ✓  Sistem terlihat aman. Tetap waspada!", Fore.GREEN))

    print(c(f"\n  💡 Tip: jalankan tanpa --terminal untuk web dashboard yang lebih lengkap", Fore.CYAN))
    print(c(f"     python scripts/dashboard.py  →  http://localhost:{DEFAULT_PORT}\n", Fore.WHITE))

# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Selene Dashboard — Web security dashboard real-time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Contoh:
  python scripts/dashboard.py                    ← web di http://localhost:{DEFAULT_PORT}
  python scripts/dashboard.py --port 8080        ← ganti port
  python scripts/dashboard.py --no-browser       ← tanpa buka browser
  python scripts/dashboard.py --terminal         ← mode terminal klasik
  python scripts/dashboard.py --once             ← terminal sekali lalu keluar"""
    )
    parser.add_argument("--port",       type=int, default=DEFAULT_PORT,
                        help=f"Port HTTP (default: {DEFAULT_PORT})")
    parser.add_argument("--no-browser", action="store_true",
                        help="Jangan buka browser otomatis")
    parser.add_argument("--terminal",   action="store_true",
                        help="Mode terminal (tanpa web server)")
    parser.add_argument("--once",       action="store_true",
                        help="Terminal mode — tampil sekali lalu keluar")
    parser.add_argument("--compact",    action="store_true",
                        help="Terminal mode ringkas")
    parser.add_argument("--refresh",    type=int, default=10,
                        help="Interval refresh terminal detik (default: 10)")
    args = parser.parse_args()

    # ── Mode terminal (fallback / --terminal / --once)
    if args.terminal or args.once:
        if not HAS_PSUTIL:
            log("WARN", "psutil tidak ada — statistik sistem terbatas (pip install psutil)")
        if args.once:
            render_terminal(args.compact)
            return
        try:
            while True:
                render_terminal(args.compact)
                time.sleep(args.refresh)
        except KeyboardInterrupt:
            os.system("clear")
            print(c("\n  Dashboard dihentikan.\n", Fore.CYAN))
        return

    # ── Mode web server
    log_header("Selene — Dashboard v3.0",
               "Web security dashboard — real-time di browser")

    port = find_free_port(args.port)
    url  = f"http://localhost:{port}"

    print()
    log("OK",   c(f"Dashboard:  {url}", Fore.GREEN, bold=True))
    log("INFO", f"API data:   {url}/api/data")
    log("INFO", c("Tekan Ctrl+C untuk menghentikan server", Fore.WHITE))
    print()

    # Buka browser otomatis setelah 1.2 detik
    if not args.no_browser:
        def _open_browser():
            time.sleep(1.2)
            try:
                import webbrowser
                webbrowser.open(url)
                log("OK", c(f"Browser dibuka: {url}", Fore.GREEN))
            except Exception:
                pass
        threading.Thread(target=_open_browser, daemon=True).start()

    # Jalankan HTTP server
    try:
        server = HTTPServer(("", port), DashboardHandler)
        log("INFO", c(f"HTTP server berjalan di port {port}...", Fore.CYAN))
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        log("INFO", "Dashboard dihentikan.")
        server.server_close()
    except OSError as e:
        log("ERROR", f"Tidak bisa bind port {port}: {e}")
        log("INFO",  f"Coba: python scripts/dashboard.py --port {port + 1}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n  [ERROR] {e}")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
