#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Port Guardian v3.0                                ║
║   Pantau port terbuka & alert jika ada yang berubah.         ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/port_guardian.py               — scan & tampilkan
  python scripts/port_guardian.py --watch       — pantau terus, alert perubahan
  python scripts/port_guardian.py --baseline    — simpan baseline port
  python scripts/port_guardian.py --diff        — bandingkan dengan baseline
  python scripts/port_guardian.py --kill 4444   — kill proses di port tsb
"""

import sys, os, subprocess, shutil, time, argparse, socket
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, write_alert, save_json, load_json,
        IS_LINUX, IS_WINDOWS, IS_ROOT, IS_ANDROID,
        DATA_DIR, REPORTS_DIR,
    )
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION   = "3.0.0"
BASELINE_FILE  = DATA_DIR / "port_baseline.json"

# Port yang dianggap berbahaya jika terbuka
DANGEROUS_PORTS = {
    21: "FTP",    22: "SSH",    23: "Telnet",  25: "SMTP",
    53: "DNS",    80: "HTTP",   110: "POP3",   135: "RPC",
    137: "NetBIOS",138: "NetBIOS",139: "NetBIOS",143: "IMAP",
    443: "HTTPS", 445: "SMB",   1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL",3389: "RDP",  4444: "Metasploit",
    5432: "PostgreSQL",5900: "VNC",
    6379: "Redis",8080: "HTTP-Alt",8443: "HTTPS-Alt",
    9200: "Elasticsearch",27017: "MongoDB",
    31337: "BackOrifice",4445:"MeterpreterHTTPS",
}

ALWAYS_SUSPICIOUS = {4444, 31337, 1337, 9999, 6666, 12345, 54321, 31338}

# ── Port collectors ───────────────────────────────────────────────────────────

def get_open_ports_psutil() -> List[Dict]:
    """Dapatkan semua port yang mendengarkan via psutil."""
    ports = []
    if not HAS_PSUTIL:
        return ports
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("LISTEN","",None):
                continue
            if not conn.laddr:
                continue

            port  = conn.laddr.port
            proto = "TCP"
            proc_name = pid = ""
            try:
                if conn.pid:
                    pid = conn.pid
                    proc_name = psutil.Process(conn.pid).name()
            except Exception:
                pass

            ports.append({
                "port":    port,
                "proto":   proto,
                "address": conn.laddr.ip,
                "process": proc_name,
                "pid":     pid,
                "service": DANGEROUS_PORTS.get(port, ""),
                "suspicious": port in ALWAYS_SUSPICIOUS,
            })
    except Exception:
        pass
    return sorted(ports, key=lambda x: x["port"])

def get_open_ports_ss() -> List[Dict]:
    """Fallback: gunakan `ss` atau `netstat`."""
    ports = []
    cmd   = ["ss","-tlnp"] if shutil.which("ss") else ["netstat","-tlnp"]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=8,
                                      stderr=subprocess.DEVNULL)
    except Exception:
        return ports

    for line in out.splitlines()[1:]:
        parts = line.split()
        if not parts:
            continue
        # ss format: State Recv-Q Send-Q Local Peer Process
        try:
            addr = parts[3] if len(parts) > 3 else ""
            if ":" not in addr:
                continue
            port = int(addr.rsplit(":", 1)[-1])
            proc = parts[-1] if "pid=" in line else ""
            pid  = ""
            m    = __import__("re").search(r"pid=(\d+)", line)
            if m:
                pid = int(m.group(1))
            ports.append({
                "port":      port,
                "proto":     "TCP",
                "address":   addr.rsplit(":",1)[0],
                "process":   proc,
                "pid":       pid,
                "service":   DANGEROUS_PORTS.get(port, ""),
                "suspicious":port in ALWAYS_SUSPICIOUS,
            })
        except (ValueError, IndexError):
            pass
    return sorted(ports, key=lambda x: x["port"])

def get_open_ports() -> List[Dict]:
    ports = get_open_ports_psutil() if HAS_PSUTIL else get_open_ports_ss()
    # Deduplicate by port
    seen = {}
    for p in ports:
        if p["port"] not in seen:
            seen[p["port"]] = p
    return sorted(seen.values(), key=lambda x: x["port"])

# ── Display ───────────────────────────────────────────────────────────────────

def print_port_table(ports: List[Dict], title: str = "PORT TERBUKA") -> None:
    log_section(title)
    if not ports:
        log("OK", "Tidak ada port yang mendengarkan")
        return

    sus_count  = sum(1 for p in ports if p["suspicious"])
    dang_count = sum(1 for p in ports if p.get("service") and not p["suspicious"])

    print(c(f"\n  Total: {len(ports)} port  |  "
            f"Berbahaya: {sus_count}  |  Perhatian: {dang_count}\n", Fore.WHITE))
    print(c(f"  {'PORT':<7} {'PROTO':<6} {'ADDRESS':<20} {'SERVICE':<18} {'PROSES'}", Fore.CYAN))
    print(c(f"  {'─'*7} {'─'*6} {'─'*20} {'─'*18} {'─'*20}", Fore.BLUE))

    for p in ports:
        port    = p["port"]
        proto   = p["proto"]
        addr    = p["address"] or "*"
        svc     = p["service"]
        proc    = str(p["process"])[:20]

        if p["suspicious"]:
            col  = Fore.RED
            flag = " ⛔"
        elif svc:
            col  = Fore.YELLOW
            flag = " ⚠"
        else:
            col  = Fore.WHITE
            flag = ""

        print(c(f"  {port:<7} {proto:<6} {addr:<20} {(svc or '—'):<18} {proc}{flag}", col))

# ── Baseline & diff ───────────────────────────────────────────────────────────

def save_baseline(ports: List[Dict]) -> None:
    port_set = {p["port"]: p for p in ports}
    save_json(BASELINE_FILE, {
        "created_at": datetime.now().isoformat(),
        "ports": port_set,
    })
    log("OK", c(f"Baseline disimpan: {len(port_set)} port", Fore.GREEN, bold=True))

def load_baseline() -> Optional[Dict]:
    if not BASELINE_FILE.exists():
        return None
    return load_json(BASELINE_FILE, {})

def diff_ports(old_ports: Dict, new_ports: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Return (opened, closed) ports dibandingkan baseline."""
    old_set = set(int(k) for k in old_ports.keys())
    new_set = {p["port"] for p in new_ports}

    opened = [p for p in new_ports if p["port"] not in old_set]
    closed = [{"port": p} for p in old_set if p not in new_set]
    return opened, closed

def print_diff(opened: List[Dict], closed: List[Dict]) -> None:
    changed = len(opened) + len(closed)
    if changed == 0:
        log("OK", c("Tidak ada perubahan port sejak baseline.", Fore.GREEN, bold=True))
        return

    if opened:
        print(c(f"\n  PORT BARU TERBUKA ({len(opened)}):", Fore.RED, bold=True))
        for p in opened:
            svc = p.get("service","?")
            sus = p.get("suspicious", False)
            col = Fore.RED if sus or svc else Fore.YELLOW
            flag= " ⛔ BERBAHAYA!" if sus else (" ⚠" if svc else "")
            print(c(f"    + Port {p['port']:<6} {svc or '—':<16} {str(p.get('process',''))}{flag}", col))
            write_alert("WARN" if not sus else "CRIT",
                        f"Port guardian: port baru terbuka {p['port']} ({svc or 'unknown'})",
                        details=p)

    if closed:
        print(c(f"\n  PORT DITUTUP ({len(closed)}):", Fore.CYAN))
        for p in closed:
            print(c(f"    - Port {p['port']}", Fore.CYAN))

# ── Watch mode ────────────────────────────────────────────────────────────────

def watch_mode(interval: int = 30) -> None:
    log("INFO", c(f"Mode watch aktif — cek setiap {interval} detik", Fore.CYAN))
    log("INFO", c("Tekan Ctrl+C untuk berhenti", Fore.WHITE))

    prev_ports: Set[int] = set()
    first      = True

    while True:
        try:
            current = get_open_ports()
            cur_set = {p["port"] for p in current}

            if first:
                prev_ports = cur_set
                first      = False
                log("OK", c(f"Baseline sesi: {len(prev_ports)} port", Fore.GREEN))
            else:
                new_open  = cur_set - prev_ports
                new_close = prev_ports - cur_set

                for port in new_open:
                    p    = next((x for x in current if x["port"] == port), {})
                    svc  = p.get("service","")
                    sus  = port in ALWAYS_SUSPICIOUS
                    col  = Fore.RED if sus else Fore.YELLOW
                    ts   = datetime.now().strftime("%H:%M:%S")
                    print(c(f"\n  [{ts}] 🔓 Port baru terbuka: {port} ({svc or '?'})  "
                            f"{str(p.get('process',''))}", col, bold=sus))
                    write_alert("CRIT" if sus else "WARN",
                                f"Port guardian: port {port} terbuka tiba-tiba",
                                details=p)

                for port in new_close:
                    ts = datetime.now().strftime("%H:%M:%S")
                    svc = DANGEROUS_PORTS.get(port,"")
                    print(c(f"  [{ts}] 🔒 Port ditutup: {port} ({svc or '?'})", Fore.CYAN))

                prev_ports = cur_set

            time.sleep(interval)
        except KeyboardInterrupt:
            break

# ── Kill process ──────────────────────────────────────────────────────────────

def kill_port_process(port: int) -> bool:
    if not HAS_PSUTIL:
        log("ERROR", "psutil diperlukan untuk kill proses")
        return False

    target = None
    for conn in psutil.net_connections(kind="inet"):
        if conn.laddr and conn.laddr.port == port and conn.pid:
            target = conn.pid
            break

    if target is None:
        log("ERROR", f"Tidak ada proses di port {port}")
        return False

    try:
        proc = psutil.Process(target)
        name = proc.name()
        print(c(f"\n  Proses di port {port}: {name} (PID {target})", Fore.YELLOW))
        if confirm(f"Kill proses '{name}' (PID {target})?", default=False):
            proc.terminate()
            time.sleep(1)
            if proc.is_running():
                proc.kill()
            log("OK", c(f"Proses {name} (PID {target}) dihentikan", Fore.GREEN))
            return True
    except Exception as e:
        log("ERROR", f"Gagal kill proses: {e}")
    return False

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Port Guardian — Pantau port terbuka",
    )
    parser.add_argument("--watch",    action="store_true", help="Pantau terus-menerus")
    parser.add_argument("--baseline", action="store_true", help="Simpan port saat ini sebagai baseline")
    parser.add_argument("--diff",     action="store_true", help="Bandingkan dengan baseline")
    parser.add_argument("--kill",     type=int, metavar="PORT", help="Kill proses di port ini")
    parser.add_argument("--interval", type=int, default=30, help="Interval watch (detik, default: 30)")
    parser.add_argument("--no-save",  action="store_true")
    args = parser.parse_args()

    log_header("Selene — Port Guardian v3.0",
               "Pantau port terbuka & alert jika ada yang berubah")

    if args.kill:
        kill_port_process(args.kill)
        return

    if args.watch:
        watch_mode(args.interval)
        return

    # Scan port
    with __import__("selene.core", fromlist=["Spinner"]).Spinner("Memindai port terbuka..."):
        ports = get_open_ports()

    print_port_table(ports)

    if args.baseline:
        save_baseline(ports)
    elif args.diff:
        base = load_baseline()
        if base:
            log("INFO", f"Baseline dari: {base.get('created_at','?')[:16]}")
            opened, closed = diff_ports(base.get("ports",{}), ports)
            print_diff(opened, closed)
        else:
            log("WARN", "Belum ada baseline — jalankan: port_guardian.py --baseline")

    if not args.no_save and not args.baseline and not args.diff:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"ports_{ts}.json"
        save_json(path, {"tool":"port_guardian","version":TOOL_VERSION,
                         "scan_time":datetime.now().isoformat(),"ports":ports})
        log("OK", c(f"Disimpan: reports/ports_{ts}.json", Fore.GREEN))

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
