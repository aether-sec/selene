#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Report Engine v3.0                                ║
║   Buat laporan keamanan komprehensif (HTML / JSON / TXT).    ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/report_engine.py               — laporan HTML lengkap
  python scripts/report_engine.py --format json
  python scripts/report_engine.py --format txt
  python scripts/report_engine.py --since 7d    — 7 hari terakhir
  python scripts/report_engine.py --type weekly — template mingguan
  python scripts/report_engine.py --type monthly
"""

import sys, os, json, time, argparse, re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        read_jsonl, load_json, save_json, Spinner,
        fmt_bytes, IS_LINUX, REPORTS_DIR, LOGS_DIR, DATA_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

TOOL_VERSION = "3.0.0"

# ── Data collector ────────────────────────────────────────────────────────────

def collect_period_data(since: datetime) -> Dict:
    """Kumpulkan semua data dari berbagai sumber dalam rentang waktu."""

    def _ts(entry: Dict) -> Optional[datetime]:
        ts = entry.get("timestamp","")
        try:
            return datetime.fromisoformat(ts)
        except Exception:
            return None

    # Alerts
    raw_alerts = read_jsonl(LOGS_DIR / "alerts.jsonl", last_n=2000)
    alerts = [a for a in raw_alerts if (_ts(a) or datetime.min) >= since]

    # Honeypot captures
    raw_hp = read_jsonl(LOGS_DIR / "honeypot_captures.jsonl", last_n=2000)
    hp_caps = [h for h in raw_hp if (_ts(h) or datetime.min) >= since]

    # Health history
    health_history = read_jsonl(DATA_DIR / "health_history.jsonl", last_n=50)
    health_in_period = [h for h in health_history if (_ts(h) or datetime.min) >= since]

    # Backup log
    backup_log = read_jsonl(LOGS_DIR / "backup_log.jsonl", last_n=100)
    backups = [b for b in backup_log if (_ts(b) or datetime.min) >= since]

    # Latest reports dari setiap tool
    def latest_report(prefix: str) -> Optional[Dict]:
        files = sorted(REPORTS_DIR.glob(f"{prefix}*.json"), reverse=True)
        return load_json(files[0], {}) if files else None

    return {
        "period_start":  since.isoformat(),
        "period_end":    datetime.now().isoformat(),
        "alerts":        alerts,
        "hp_captures":   hp_caps,
        "health_history":health_in_period,
        "backups":       backups,
        "latest_scan":   latest_report("scan_"),
        "latest_vuln":   latest_report("vuln_"),
        "latest_health": load_json(DATA_DIR / "health.json", {}),
        "latest_privacy":latest_report("privacy_"),
        "latest_hardener":latest_report("hardener_"),
    }

def build_summary(data: Dict) -> Dict:
    """Hitung statistik ringkasan dari data yang dikumpulkan."""
    alerts   = data["alerts"]
    hp_caps  = data["hp_captures"]
    backups  = data["backups"]
    health   = data["latest_health"]
    health_h = data["health_history"]

    # Alert breakdown
    alert_by_level: Dict[str, int] = defaultdict(int)
    alert_by_day:   Dict[str, int] = defaultdict(int)
    top_ips:        Dict[str, int] = defaultdict(int)

    for a in alerts:
        level = a.get("level","INFO")
        alert_by_level[level] += 1
        ts = a.get("timestamp","")[:10]
        if ts:
            alert_by_day[ts] += 1
        ip = a.get("ip","")
        if ip:
            top_ips[ip] += 1

    # Honeypot breakdown
    hp_by_service: Dict[str, int] = defaultdict(int)
    hp_attacks:    List[str] = []
    unique_hp_ips: set = set()

    for cap in hp_caps:
        svc = cap.get("service","?")
        hp_by_service[svc] += 1
        hp_attacks.extend(cap.get("attacks",[]))
        ip = cap.get("client_ip","")
        if ip:
            unique_hp_ips.add(ip)

    # Health trend
    health_trend = []
    for h in health_h:
        health_trend.append({
            "date":  h.get("timestamp","")[:10],
            "score": h.get("score", 0),
            "grade": h.get("grade","?"),
        })

    # Backup stats
    successful_backups = [b for b in backups if b.get("action") == "backup"]
    total_backup_size  = sum(b.get("backup_size", 0) for b in successful_backups)

    return {
        "alerts_total":     len(alerts),
        "alerts_crit":      alert_by_level.get("CRIT", 0),
        "alerts_warn":      alert_by_level.get("WARN", 0),
        "alerts_by_day":    dict(sorted(alert_by_day.items())),
        "top_attacker_ips": dict(sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
        "hp_total":         len(hp_caps),
        "hp_attacks":       len([a for a in hp_attacks if a]),
        "hp_unique_ips":    len(unique_hp_ips),
        "hp_by_service":    dict(hp_by_service),
        "health_score":     health.get("score"),
        "health_grade":     health.get("grade","?"),
        "health_trend":     health_trend,
        "backups_done":     len(successful_backups),
        "backup_total_size":total_backup_size,
    }

# ── HTML Report Generator ─────────────────────────────────────────────────────

CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, 'Segoe UI', sans-serif; background: #0d1117;
       color: #c9d1d9; line-height: 1.6; }
.container { max-width: 1100px; margin: 0 auto; padding: 2rem; }
h1 { color: #58a6ff; font-size: 1.8rem; margin-bottom: 0.3rem; }
h2 { color: #58a6ff; font-size: 1.2rem; border-bottom: 1px solid #21262d;
     padding-bottom: 0.4rem; margin: 2rem 0 1rem; }
h3 { color: #8b949e; font-size: 1rem; margin: 1rem 0 0.5rem; }
.subtitle { color: #8b949e; margin-bottom: 2rem; font-size: 0.9rem; }
/* Score card */
.score-card { background: #161b22; border-radius: 12px; padding: 2rem;
              display: flex; align-items: center; gap: 2rem; margin-bottom: 2rem;
              border: 1px solid #21262d; }
.score-big  { font-size: 4rem; font-weight: 900; line-height: 1; }
.grade      { font-size: 2rem; font-weight: 700; margin-left: 0.5rem; }
.score-bar-wrap { flex: 1; }
.score-bar  { height: 20px; background: #21262d; border-radius: 10px; overflow: hidden; }
.score-fill { height: 100%; border-radius: 10px; transition: width 0.5s; }
.score-lbl  { font-size: 0.85rem; color: #8b949e; margin-top: 0.4rem; }
/* Stat grid */
.stat-grid  { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
              gap: 1rem; margin-bottom: 2rem; }
.stat-card  { background: #161b22; border: 1px solid #21262d; border-radius: 10px;
              padding: 1.2rem; text-align: center; }
.stat-num   { font-size: 2.2rem; font-weight: 700; }
.stat-lbl   { font-size: 0.8rem; color: #8b949e; margin-top: 0.2rem; }
.red  { color: #f85149; } .yellow { color: #d29922; }
.green{ color: #3fb950; } .blue   { color: #58a6ff; }
.gray { color: #8b949e; }
/* Table */
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th  { background: #161b22; padding: 0.6rem 1rem; text-align: left; color: #8b949e;
      font-weight: 600; position: sticky; top: 0; }
td  { padding: 0.55rem 1rem; border-bottom: 1px solid #21262d; word-break: break-all; }
tr:hover td { background: #161b22; }
.crit-row td { color: #f85149; }
.warn-row td { color: #d29922; }
/* Badges */
.badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
         font-size: 0.75rem; font-weight: 600; }
.badge-red    { background: rgba(248,81,73,.2); color: #f85149; }
.badge-yellow { background: rgba(210,153,34,.2); color: #d29922; }
.badge-green  { background: rgba(63,185,80,.2);  color: #3fb950; }
.badge-blue   { background: rgba(88,166,255,.2); color: #58a6ff; }
/* Section box */
.box { background: #161b22; border: 1px solid #21262d; border-radius: 10px;
       padding: 1.5rem; margin-bottom: 1.5rem; }
/* Timeline mini-chart */
.chart-row { display: flex; align-items: flex-end; gap: 3px; height: 60px; }
.chart-bar { flex: 1; background: #58a6ff; border-radius: 2px 2px 0 0; min-height: 2px;
             position: relative; cursor: default; }
.chart-bar:hover::after { content: attr(data-tip); position: absolute; bottom: 105%;
  left: 50%; transform: translateX(-50%); background: #21262d; color: #c9d1d9;
  padding: 2px 6px; border-radius: 4px; font-size: 0.7rem; white-space: nowrap; }
/* Category table */
.cat-bar-wrap { display: inline-block; width: 120px; background: #21262d;
                border-radius: 4px; overflow: hidden; vertical-align: middle; }
.cat-bar-fill { height: 10px; border-radius: 4px; }
footer { text-align: center; color: #8b949e; font-size: 0.8rem; margin-top: 3rem;
         padding-top: 1rem; border-top: 1px solid #21262d; }
"""

def _score_color(score: Optional[int]) -> str:
    if score is None: return "#8b949e"
    if score >= 80:   return "#3fb950"
    if score >= 60:   return "#d29922"
    return "#f85149"

def _badge(text: str, typ: str = "blue") -> str:
    return f'<span class="badge badge-{typ}">{text}</span>'

def _alert_badge(level: str) -> str:
    m = {"CRIT":"red","WARN":"yellow","INFO":"blue","OK":"green"}
    return _badge(level, m.get(level,"blue"))

def generate_html(data: Dict, summary: Dict, title: str, period_label: str) -> str:
    """Generate laporan HTML lengkap."""

    now_str  = datetime.now().strftime("%d %B %Y, %H:%M")
    hs       = summary["health_score"]
    hg       = summary["health_grade"]
    hs_color = _score_color(hs)
    hs_pct   = hs or 0
    hs_label = ("Sangat Aman" if hs and hs >= 85 else
                "Cukup Aman"  if hs and hs >= 65 else
                "Perlu Perhatian" if hs and hs >= 50 else
                "Berisiko Tinggi" if hs else "Belum dihitung")

    # ── Score Card ─────────────────────────────────────────────────────────────
    score_card = f"""
<div class="score-card">
  <div>
    <span class="score-big" style="color:{hs_color}">{hs if hs is not None else '?'}</span>
    <span class="grade" style="color:{hs_color}">{hg}</span>
  </div>
  <div class="score-bar-wrap">
    <div style="font-size:1.1rem;font-weight:600;margin-bottom:0.5rem">Health Score — {hs_label}</div>
    <div class="score-bar">
      <div class="score-fill" style="width:{hs_pct}%;background:{hs_color}"></div>
    </div>
    <div class="score-lbl">Dibuat: {now_str} | Periode: {period_label}</div>
  </div>
</div>"""

    # ── Stat Grid ─────────────────────────────────────────────────────────────
    ac  = summary["alerts_crit"]
    aw  = summary["alerts_warn"]
    at  = summary["alerts_total"]
    ht  = summary["hp_total"]
    haa = summary["hp_attacks"]
    bd  = summary["backups_done"]

    def stat(num, lbl, color="blue"):
        return f'<div class="stat-card"><div class="stat-num {color}">{num}</div><div class="stat-lbl">{lbl}</div></div>'

    stat_grid = f"""
<div class="stat-grid">
  {stat(at, "Total Alerts", "blue")}
  {stat(ac, "Alert Kritis", "red" if ac else "green")}
  {stat(aw, "Alert Warning", "yellow" if aw else "green")}
  {stat(ht, "Honeypot Hits", "blue")}
  {stat(haa, "Serangan Terdeteksi", "red" if haa else "green")}
  {stat(bd, "Backup Berhasil", "green" if bd else "yellow")}
</div>"""

    # ── Alert Timeline Chart ───────────────────────────────────────────────────
    alert_days = summary.get("alerts_by_day", {})
    max_alerts = max(alert_days.values(), default=1)
    chart_bars = ""
    for day, cnt in sorted(alert_days.items())[-14:]:   # 14 hari terakhir
        h = max(2, int(60 * cnt / max_alerts))
        chart_bars += f'<div class="chart-bar" style="height:{h}px" data-tip="{day}: {cnt}"></div>'
    chart_section = f"""
<div class="box">
  <h3>Alert per Hari (14 hari terakhir)</h3>
  <div class="chart-row">{chart_bars}</div>
</div>""" if chart_bars else ""

    # ── Top Attacker IPs ──────────────────────────────────────────────────────
    top_ip_rows = ""
    for ip, cnt in list(summary["top_attacker_ips"].items())[:10]:
        badge = _badge("HIGH", "red") if cnt > 20 else _badge("MED", "yellow")
        top_ip_rows += f"<tr><td>{ip}</td><td>{cnt}</td><td>{badge}</td></tr>"
    top_ip_table = f"""
<h2>🎯 Top Penyerang</h2>
<div class="box">
<table>
  <tr><th>IP Address</th><th>Jumlah Alert</th><th>Risiko</th></tr>
  {top_ip_rows or '<tr><td colspan="3" style="color:#8b949e">Tidak ada</td></tr>'}
</table>
</div>""" if summary["top_attacker_ips"] else ""

    # ── Honeypot breakdown ────────────────────────────────────────────────────
    hp_svc_rows = ""
    for svc, cnt in sorted(summary["hp_by_service"].items(), key=lambda x: x[1], reverse=True):
        hp_svc_rows += f"<tr><td>{svc}</td><td>{cnt}</td></tr>"
    hp_section = f"""
<h2>🎣 Honeypot</h2>
<div class="box">
  <div class="stat-grid" style="margin-bottom:1rem">
    {stat(summary['hp_total'], 'Total Koneksi', 'blue')}
    {stat(summary['hp_attacks'], 'Serangan Aktif', 'red' if summary['hp_attacks'] else 'green')}
    {stat(summary['hp_unique_ips'], 'IP Unik', 'yellow')}
  </div>
  <table>
    <tr><th>Layanan</th><th>Koneksi</th></tr>
    {hp_svc_rows or '<tr><td colspan="2" style="color:#8b949e">Tidak ada capture</td></tr>'}
  </table>
</div>""" if summary["hp_total"] > 0 else ""

    # ── Alert table (terbaru) ─────────────────────────────────────────────────
    alert_rows = ""
    for a in sorted(data["alerts"], key=lambda x: x.get("timestamp",""), reverse=True)[:50]:
        ts  = a.get("timestamp","")[:16].replace("T"," ")
        lvl = a.get("level","?")
        msg = a.get("message","?")[:80]
        ip  = a.get("ip","—")
        row_cls = "crit-row" if lvl == "CRIT" else ("warn-row" if lvl == "WARN" else "")
        alert_rows += f'<tr class="{row_cls}"><td>{ts}</td><td>{_alert_badge(lvl)}</td><td>{ip}</td><td>{msg}</td></tr>'

    alert_table = f"""
<h2>⚠ Alert Log</h2>
<div class="box">
<table>
  <tr><th>Waktu</th><th>Level</th><th>IP</th><th>Pesan</th></tr>
  {alert_rows or '<tr><td colspan="4" style="color:#8b949e">Tidak ada alert</td></tr>'}
</table>
</div>"""

    # ── Health per kategori ───────────────────────────────────────────────────
    health_data = data.get("latest_health", {})
    cat_rows = ""
    if health_data and health_data.get("categories"):
        for key, cat in health_data["categories"].items():
            pts  = cat.get("score", 0)
            mx   = cat.get("max", 1)
            pct  = int(pts * 100 / mx) if mx else 0
            lbl  = cat.get("label", key)
            col  = "#3fb950" if pct >= 75 else ("#d29922" if pct >= 50 else "#f85149")
            bar  = f'<div class="cat-bar-wrap"><div class="cat-bar-fill" style="width:{pct}%;background:{col};height:10px"></div></div>'
            cat_rows += f"<tr><td>{lbl}</td><td>{pts}/{mx}</td><td>{bar} {pct}%</td></tr>"

    health_table = f"""
<h2>💚 Security Health per Kategori</h2>
<div class="box">
<table>
  <tr><th>Kategori</th><th>Skor</th><th>Progress</th></tr>
  {cat_rows or '<tr><td colspan="3" style="color:#8b949e">Jalankan health_score.py terlebih dahulu</td></tr>'}
</table>
</div>"""

    # ── Backup history ────────────────────────────────────────────────────────
    bkp_rows = ""
    for b in sorted(data["backups"], key=lambda x: x.get("timestamp",""), reverse=True)[:10]:
        if b.get("action") != "backup":
            continue
        ts   = b.get("timestamp","")[:16].replace("T"," ")
        fc   = b.get("file_count", 0)
        bsz  = fmt_bytes(b.get("backup_size", 0))
        bkp_rows += f"<tr><td>{ts}</td><td>{fc} file</td><td>{bsz}</td><td>{_badge('OK','green')}</td></tr>"

    backup_section = f"""
<h2>💾 Riwayat Backup</h2>
<div class="box">
<table>
  <tr><th>Waktu</th><th>File</th><th>Ukuran</th><th>Status</th></tr>
  {bkp_rows or '<tr><td colspan="4" style="color:#8b949e">Belum ada backup</td></tr>'}
</table>
</div>"""

    # ── Health trend chart ────────────────────────────────────────────────────
    ht_bars = ""
    for h in data["health_history"][-14:]:
        sc   = h.get("score", 0)
        dt   = h.get("timestamp","")[:10]
        fill_h = max(2, int(60 * sc / 100))
        col  = "#3fb950" if sc >= 75 else ("#d29922" if sc >= 50 else "#f85149")
        ht_bars += f'<div class="chart-bar" style="height:{fill_h}px;background:{col}" data-tip="{dt}: {sc}"></div>'

    health_trend_section = f"""
<div class="box">
  <h3>Trend Health Score</h3>
  <div class="chart-row">{ht_bars}</div>
</div>""" if ht_bars else ""

    # ── Rekomendasi ───────────────────────────────────────────────────────────
    recs = []
    if ac > 0:
        recs.append(("Tindaklanjuti alert KRITIS", f"{ac} alert kritis memerlukan perhatian segera", "red"))
    if summary["backups_done"] == 0:
        recs.append(("Lakukan backup", "Tidak ada backup dalam periode ini", "yellow"))
    if hs is not None and hs < 60:
        recs.append(("Tingkatkan keamanan", f"Health score {hs}/100 — jalankan security_hardener.py", "red"))
    if summary["hp_total"] == 0:
        recs.append(("Aktifkan honeypot", "Honeypot belum berjalan — tambah layer deteksi", "blue"))

    _color_map = {"red": "f85149", "yellow": "d29922", "blue": "58a6ff"}
    def _rec_div(rec_item):
        rtitle, rdesc, rcolor = rec_item
        hex_c = _color_map.get(rcolor, "58a6ff")
        return (
            f'<div style="padding:0.8rem;border-left:3px solid #{hex_c};'
            f'margin-bottom:0.7rem;background:rgba(0,0,0,0.2);">'
            f'<strong>{rtitle}</strong><br>'
            f'<span style="color:#8b949e;font-size:0.88rem">{rdesc}</span></div>'
        )
    rec_html = "".join(_rec_div(r) for r in recs) \
               or '<p style="color:#3fb950">✓ Tidak ada rekomendasi mendesak.</p>'

    rec_section = f"""
<h2>📋 Rekomendasi</h2>
<div class="box">{rec_html}</div>"""

    return f"""<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>{CSS}</style>
</head>
<body>
<div class="container">
  <h1>🌙 {title}</h1>
  <p class="subtitle">Selene Security Suite v{TOOL_VERSION} · Dibuat: {now_str} · Periode: {period_label}</p>
  {score_card}
  {stat_grid}
  {chart_section}
  {health_trend_section}
  {health_table}
  {top_ip_table}
  {hp_section}
  {alert_table}
  {backup_section}
  {rec_section}
  <footer>Selene Security Suite v{TOOL_VERSION} · Laporan ini RAHASIA — jangan dibagikan sembarangan</footer>
</div>
</body>
</html>"""

# ── Text Report Generator ─────────────────────────────────────────────────────

def generate_txt(data: Dict, summary: Dict, title: str, period_label: str) -> str:
    """Generate laporan teks sederhana."""
    lines = []
    sep   = "═" * 60

    lines.append(f"\n  {sep}")
    lines.append(f"  {title}")
    lines.append(f"  Periode: {period_label}")
    lines.append(f"  Dibuat: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"  {sep}\n")

    hs = summary["health_score"]
    hg = summary["health_grade"]
    lines.append(f"  HEALTH SCORE: {hs or '?'}/100  [{hg}]")
    lines.append(f"  {'─'*40}")
    lines.append(f"  Alert total : {summary['alerts_total']}")
    lines.append(f"  Alert KRITIS: {summary['alerts_crit']}")
    lines.append(f"  Alert WARN  : {summary['alerts_warn']}")
    lines.append(f"  Honeypot    : {summary['hp_total']} koneksi ({summary['hp_attacks']} serangan)")
    lines.append(f"  Backup      : {summary['backups_done']} kali")
    lines.append("")

    if summary["top_attacker_ips"]:
        lines.append(f"  TOP PENYERANG:")
        for ip, cnt in list(summary["top_attacker_ips"].items())[:5]:
            lines.append(f"    {ip:<22}  {cnt} alert")
        lines.append("")

    lines.append(f"  ALERT TERBARU:")
    for a in sorted(data["alerts"], key=lambda x: x.get("timestamp",""), reverse=True)[:15]:
        ts  = a.get("timestamp","")[:16].replace("T"," ")
        lvl = a.get("level","?")
        msg = a.get("message","?")[:60]
        lines.append(f"    [{ts}] [{lvl}] {msg}")

    lines.append(f"\n  {sep}")
    lines.append(f"  Selene Security Suite v{TOOL_VERSION}")
    lines.append(f"  {sep}\n")

    return "\n".join(lines)

# ── JSON Report ───────────────────────────────────────────────────────────────

def generate_json(data: Dict, summary: Dict, title: str, period_label: str) -> Dict:
    return {
        "meta": {
            "tool":         "report_engine",
            "version":      TOOL_VERSION,
            "title":        title,
            "period_label": period_label,
            "generated":    datetime.now().isoformat(),
            "period_start": data["period_start"],
            "period_end":   data["period_end"],
        },
        "summary": summary,
        "alerts":  data["alerts"][:200],
        "honeypot_captures": data["hp_captures"][:100],
        "health":  data.get("latest_health", {}),
        "backups": data["backups"],
    }

# ── Main ──────────────────────────────────────────────────────────────────────

def parse_since(arg: str) -> datetime:
    """Parse '7d', '30d', '1w', '1m', atau tanggal YYYY-MM-DD."""
    now = datetime.now()
    m   = re.match(r"^(\d+)([dhwm])$", arg.lower().strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        deltas  = {"d": timedelta(days=n), "h": timedelta(hours=n),
                   "w": timedelta(weeks=n), "m": timedelta(days=n*30)}
        return now - deltas[unit]
    try:
        return datetime.strptime(arg, "%Y-%m-%d")
    except ValueError:
        pass
    # Default: 7 hari
    return now - timedelta(days=7)

def main():
    parser = argparse.ArgumentParser(
        description="Selene Report Engine — Buat laporan keamanan komprehensif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/report_engine.py
  python scripts/report_engine.py --format json
  python scripts/report_engine.py --format txt
  python scripts/report_engine.py --since 30d
  python scripts/report_engine.py --type weekly
  python scripts/report_engine.py --type monthly --format html"""
    )
    parser.add_argument("--format", "-f", choices=["html","json","txt"], default="html",
                        help="Format output (default: html)")
    parser.add_argument("--since",  "-s", default="7d", metavar="PERIODE",
                        help="Periode data: 7d, 30d, 1w, 1m, atau YYYY-MM-DD (default: 7d)")
    parser.add_argument("--type",   "-t", choices=["custom","weekly","monthly","daily"],
                        default="custom", help="Template laporan")
    parser.add_argument("--out",    "-o", metavar="FILE",
                        help="Nama file output (opsional)")
    parser.add_argument("--open",   action="store_true",
                        help="Buka laporan HTML di browser setelah dibuat")
    args = parser.parse_args()

    log_header("Selene — Report Engine v3.0",
               "Generate laporan keamanan komprehensif")

    # Tentukan periode
    type_periods = {
        "daily":   ("1d", "Harian"),
        "weekly":  ("7d", "Mingguan"),
        "monthly": ("30d", "Bulanan"),
        "custom":  (args.since, f"Kustom ({args.since})"),
    }
    since_str, period_label = type_periods.get(args.type, ("7d","7 hari terakhir"))
    since = parse_since(since_str)

    log("INFO", f"Periode  : {period_label} ({since.strftime('%Y-%m-%d')} s/d sekarang)")
    log("INFO", f"Format   : {args.format.upper()}")

    # Kumpulkan data
    with Spinner("Mengumpulkan data dari semua sumber..."):
        data    = collect_period_data(since)
        summary = build_summary(data)

    log("OK", c(f"Data: {summary['alerts_total']} alert, {summary['hp_total']} honeypot captures", Fore.GREEN))

    # Generate laporan
    title = f"Selene Security Report — {period_label}"
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.format == "html":
        with Spinner("Membuat laporan HTML..."):
            content = generate_html(data, summary, title, period_label)
        ext  = "html"
        mode = "w"
    elif args.format == "json":
        content = json.dumps(generate_json(data, summary, title, period_label),
                             ensure_ascii=False, indent=2)
        ext  = "json"
        mode = "w"
    else:
        content = generate_txt(data, summary, title, period_label)
        ext  = "txt"
        mode = "w"

    # Simpan
    fname   = args.out or f"report_{args.type}_{ts}.{ext}"
    outpath = REPORTS_DIR / fname
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    outpath.write_text(content, encoding="utf-8")

    log("OK", c(f"Laporan disimpan: {outpath}", Fore.GREEN, bold=True))
    log("INFO", f"Ukuran: {fmt_bytes(outpath.stat().st_size)}")

    # Buka di browser
    if args.open and args.format == "html":
        import webbrowser
        webbrowser.open(f"file://{outpath.resolve()}")
        log("OK", "Laporan dibuka di browser")

    # Ringkasan singkat di terminal
    log_section("RINGKASAN")
    hs = summary["health_score"]
    ac = summary["alerts_crit"]
    print(c(f"\n  Health Score : {hs or '?'}/100  [{summary['health_grade']}]",
            Fore.GREEN if hs and hs >= 75 else Fore.YELLOW))
    print(c(f"  Alert Kritis : {ac}",
            Fore.RED if ac else Fore.GREEN, bold=bool(ac)))
    print(c(f"  Honeypot     : {summary['hp_total']} koneksi", Fore.WHITE))
    print(c(f"  Backup       : {summary['backups_done']} kali", Fore.WHITE))
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
