#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Threat Monitor v3.0                               ║
║   IDS real-time: deteksi & blokir ancaman otomatis.          ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  sudo python scripts/threat_monitor.py           ← mode penuh (Scapy)
  python  scripts/threat_monitor.py               ← mode fallback (psutil)
  python  scripts/threat_monitor.py --no-block    ← hanya deteksi, tanpa blokir
  python  scripts/threat_monitor.py --status      ← tampilkan statistik
"""

import sys
import os
import time
import socket
import json
import threading
import subprocess
import shutil
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Set, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        write_alert, read_jsonl,
        IS_LINUX, IS_WINDOWS, IS_ROOT,
        get_local_ip, LOGS_DIR,
    )
    from selene.core.config import get_config
    from selene.core.network import get_default_gateway, is_private_ip
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2  import ARP, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION = "3.0.0"

# ── Ambang deteksi ────────────────────────────────────────────────────────────
TH_PORTSCAN_PORTS   = 15    # port unik dalam 10 detik → port scan
TH_PORTSCAN_WIN     = 10    # detik window
TH_BRUTEFORCE_TRIES = 5     # percobaan login dalam 30 detik → brute force
TH_BRUTEFORCE_WIN   = 30
TH_DDOS_PPS         = 500   # paket/detik → DDoS
TH_DDOS_WIN         = 3

BRUTEFORCE_PORTS = {22, 21, 3389, 3306, 5432, 23, 110, 143}

# ── State thread-safe ─────────────────────────────────────────────────────────
class MonitorState:
    def __init__(self, trusted_ips: Set[str]):
        self._lock         = threading.Lock()
        self.trusted_ips   = trusted_ips
        self.blocked_ips: Dict[str, datetime] = {}
        self.threat_scores: Dict[str, int]    = {}
        self.port_history:  Dict[str, Dict[str, Set]] = defaultdict(
            lambda: defaultdict(set))     # ip → window_key → set(ports)
        self.login_attempts: Dict[str, List[float]]   = defaultdict(list)
        self.pkt_counts:     Dict[str, List[float]]   = defaultdict(list)
        self.arp_table:      Dict[str, str]            = {}
        self.event_count    = 0
        self.alert_count    = 0
        self.start_time     = datetime.now()

    def add_score(self, ip: str, score: int) -> int:
        with self._lock:
            self.threat_scores[ip] = self.threat_scores.get(ip, 0) + score
            return self.threat_scores[ip]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            if ip not in self.blocked_ips:
                return False
            if datetime.now() > self.blocked_ips[ip]:
                del self.blocked_ips[ip]
                return False
            return True

    def block_ip(self, ip: str, minutes: int) -> None:
        with self._lock:
            self.blocked_ips[ip] = datetime.now() + timedelta(minutes=minutes)

    def is_trusted(self, ip: str) -> bool:
        return ip in self.trusted_ips or ip.startswith("127.")

    def tick_event(self):
        with self._lock:
            self.event_count += 1

    def tick_alert(self):
        with self._lock:
            self.alert_count += 1

# ── Auto-blocker ──────────────────────────────────────────────────────────────
def block_ip(ip: str, minutes: int, state: MonitorState) -> bool:
    """Blokir IP menggunakan iptables (Linux) atau netsh (Windows)."""
    if state.is_trusted(ip) or state.is_blocked(ip):
        return False

    state.block_ip(ip, minutes)

    if IS_LINUX and IS_ROOT and shutil.which("iptables"):
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                timeout=5, capture_output=True
            )
            log("OK", c(f"  IP diblokir via iptables: {ip} ({minutes} menit)",
                        Fore.RED, bold=True))
            return True
        except Exception as e:
            log("WARN", f"iptables gagal: {e}")

    elif IS_WINDOWS and IS_ROOT:
        try:
            rule_name = f"Selene_Block_{ip.replace('.','_')}"
            subprocess.run(
                ["netsh","advfirewall","firewall","add","rule",
                 f"name={rule_name}","dir=in","action=block",
                 f"remoteip={ip}"],
                timeout=5, capture_output=True
            )
            return True
        except Exception:
            pass

    # Tanpa root: hanya catat di state
    log("INFO", c(f"  IP ditandai berbahaya (no root, tidak bisa iptables): {ip}",
                  Fore.YELLOW))
    return False

def unblock_ip(ip: str) -> bool:
    """Lepas blokir IP."""
    if IS_LINUX and shutil.which("iptables"):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                timeout=5, capture_output=True
            )
            return True
        except Exception:
            pass
    return False

# ── Deteksi ancaman ───────────────────────────────────────────────────────────
def detect_port_scan(ip: str, dport: int, state: MonitorState) -> Optional[str]:
    """Deteksi port scan (banyak port dalam waktu singkat)."""
    now     = time.time()
    win_key = str(int(now / TH_PORTSCAN_WIN))

    with state._lock:
        state.port_history[ip][win_key].add(dport)
        count = len(state.port_history[ip][win_key])
        # Bersihkan window lama
        old_keys = [k for k in state.port_history[ip] if k != win_key]
        for k in old_keys:
            del state.port_history[ip][k]

    if count >= TH_PORTSCAN_PORTS:
        return f"Port scan: {count} port unik dalam {TH_PORTSCAN_WIN} detik"
    return None

def detect_bruteforce(ip: str, dport: int, state: MonitorState) -> Optional[str]:
    """Deteksi brute force pada port login."""
    if dport not in BRUTEFORCE_PORTS:
        return None

    now = time.time()
    key = f"{ip}:{dport}"

    with state._lock:
        state.login_attempts[key].append(now)
        cutoff = now - TH_BRUTEFORCE_WIN
        state.login_attempts[key] = [
            t for t in state.login_attempts[key] if t > cutoff
        ]
        count = len(state.login_attempts[key])

    if count >= TH_BRUTEFORCE_TRIES:
        svc = {22:"SSH",21:"FTP",3389:"RDP",3306:"MySQL",
               5432:"PostgreSQL",23:"Telnet",110:"POP3",143:"IMAP"
               }.get(dport, str(dport))
        return f"Brute force {svc}: {count} percobaan dalam {TH_BRUTEFORCE_WIN} detik"
    return None

def detect_ddos(ip: str, state: MonitorState) -> Optional[str]:
    """Deteksi DDoS (volume paket sangat tinggi)."""
    now = time.time()

    with state._lock:
        state.pkt_counts[ip].append(now)
        cutoff = now - TH_DDOS_WIN
        state.pkt_counts[ip] = [t for t in state.pkt_counts[ip] if t > cutoff]
        count = len(state.pkt_counts[ip])

    if count >= TH_DDOS_PPS * TH_DDOS_WIN:
        return f"DDoS: {count} paket dalam {TH_DDOS_WIN} detik"
    return None

def detect_arp_spoof(ip: str, mac: str, state: MonitorState) -> Optional[str]:
    """Deteksi ARP spoofing (MAC berubah)."""
    with state._lock:
        prev_mac = state.arp_table.get(ip)
        state.arp_table[ip] = mac

    if prev_mac and prev_mac != mac:
        return f"ARP spoofing: {ip} MAC berubah {prev_mac} → {mac}"
    return None

# ── Alert handler ─────────────────────────────────────────────────────────────
def handle_threat(ip: str, threat_type: str, description: str,
                  score: int, state: MonitorState, cfg,
                  auto_block: bool) -> None:
    """Proses ancaman yang terdeteksi."""
    if state.is_trusted(ip):
        return

    total_score = state.add_score(ip, score)
    state.tick_alert()

    ts = datetime.now().strftime("%H:%M:%S")
    print(c(f"\n  [{ts}] ⚠  {threat_type}", Fore.RED, bold=True))
    print(c(f"         IP: {ip}  Skor: {total_score}/100", Fore.RED))
    print(c(f"         {description}", Fore.YELLOW))

    write_alert("WARN", f"{threat_type}: {description}",
                details={"threat_type": threat_type, "score": total_score},
                ip=ip)

    # Auto blokir jika skor cukup tinggi
    block_threshold = cfg.get("monitor","alert_threshold", default=70)
    block_minutes   = cfg.get("monitor","block_minutes",   default=30)

    if auto_block and total_score >= block_threshold:
        block_ip(ip, block_minutes, state)

# ── Mode Scapy (root, real-time) ──────────────────────────────────────────────
def start_scapy_monitor(state: MonitorState, cfg, auto_block: bool) -> None:
    """Monitor paket real-time menggunakan Scapy."""

    def process_packet(pkt):
        state.tick_event()

        # ── ARP spoofing ──────────────────────────────────────────────────────
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
            src_ip  = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            reason  = detect_arp_spoof(src_ip, src_mac, state)
            if reason:
                handle_threat(src_ip, "ARP Spoofing", reason, 60,
                              state, cfg, auto_block)
            return

        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        if state.is_trusted(src_ip) or state.is_blocked(src_ip):
            return

        # ── DDoS ──────────────────────────────────────────────────────────────
        reason = detect_ddos(src_ip, state)
        if reason:
            handle_threat(src_ip, "DDoS", reason, 50, state, cfg, auto_block)
            return

        # ── TCP ───────────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags

            # SYN scan (tanpa ACK)
            if flags == 0x02:  # SYN
                reason = detect_port_scan(src_ip, dport, state)
                if reason:
                    handle_threat(src_ip, "Port Scan", reason, 35,
                                  state, cfg, auto_block)

                reason = detect_bruteforce(src_ip, dport, state)
                if reason:
                    handle_threat(src_ip, "Brute Force", reason, 45,
                                  state, cfg, auto_block)

    log("INFO", "Mode Scapy aktif — menangkap semua paket jaringan")
    log("INFO", c("Tekan Ctrl+C untuk berhenti", Fore.WHITE))

    scapy.sniff(
        prn     = process_packet,
        store   = False,
        filter  = "ip or arp",
        stop_filter = lambda _: False,
    )

# ── Mode psutil (tanpa root, polling) ────────────────────────────────────────
def start_psutil_monitor(state: MonitorState, cfg,
                         auto_block: bool, interval: int = 5) -> None:
    """Monitor koneksi via psutil (tanpa root, interval-based)."""
    log("INFO", "Mode psutil aktif — cek koneksi setiap " +
        c(f"{interval} detik", Fore.CYAN))
    log("INFO", c("Tekan Ctrl+C untuk berhenti", Fore.WHITE))

    seen_connections: Set[Tuple] = set()
    login_track: Dict[str, List[float]] = defaultdict(list)

    while True:
        try:
            current_connections = set()
            try:
                conns = psutil.net_connections(kind="inet")
            except psutil.AccessDenied:
                log("WARN", "AccessDenied untuk net_connections — jalankan dengan sudo")
                time.sleep(interval)
                continue

            for conn in conns:
                if not conn.raddr:
                    continue

                rip   = conn.raddr.ip
                rport = conn.raddr.port
                lport = conn.laddr.port if conn.laddr else 0
                key   = (rip, rport, lport)

                current_connections.add(key)
                state.tick_event()

                if key in seen_connections or state.is_trusted(rip):
                    continue

                # Cek brute force pada port login
                if lport in BRUTEFORCE_PORTS:
                    now = time.time()
                    track_key = f"{rip}:{lport}"
                    login_track[track_key].append(now)
                    cutoff = now - TH_BRUTEFORCE_WIN
                    login_track[track_key] = [
                        t for t in login_track[track_key] if t > cutoff
                    ]
                    count = len(login_track[track_key])
                    if count >= TH_BRUTEFORCE_TRIES:
                        svc = {22:"SSH",21:"FTP",3389:"RDP",
                               3306:"MySQL"}.get(lport, str(lport))
                        handle_threat(
                            rip, "Brute Force",
                            f"Brute force {svc}: {count} koneksi baru",
                            45, state, cfg, auto_block
                        )

                # Koneksi ke port backdoor
                if rport in {4444, 31337, 1337, 9999, 6666}:
                    handle_threat(
                        rip, "Backdoor Connection",
                        f"Koneksi aktif ke port backdoor {rport}",
                        70, state, cfg, auto_block
                    )

            seen_connections = current_connections
            time.sleep(interval)

        except KeyboardInterrupt:
            break
        except Exception as e:
            log("WARN", f"Monitor error: {e}")
            time.sleep(interval)

# ── Status reporter ───────────────────────────────────────────────────────────
def status_reporter(state: MonitorState, interval_sec: int = 300) -> None:
    """Cetak status ringkasan secara berkala."""
    while True:
        time.sleep(interval_sec)
        uptime = datetime.now() - state.start_time
        h, rem = divmod(int(uptime.total_seconds()), 3600)
        m, s   = divmod(rem, 60)

        with state._lock:
            blocked  = len(state.blocked_ips)
            alerts   = state.alert_count
            events   = state.event_count
            top_ips  = sorted(state.threat_scores.items(),
                              key=lambda x: x[1], reverse=True)[:3]

        ts = datetime.now().strftime("%H:%M:%S")
        print(c(f"\n  [{ts}] ─── Status Monitor ─────────────────────", Fore.BLUE))
        print(c(f"         Uptime: {h}j {m}m  "
                f"Events: {events}  "
                f"Alerts: {alerts}  "
                f"Blocked: {blocked}", Fore.WHITE))
        if top_ips:
            print(c("         Top threats:", Fore.WHITE))
            for ip, score in top_ips:
                print(c(f"           {ip:<18}  skor {score}", Fore.YELLOW))

# ── Show status (non-monitor mode) ────────────────────────────────────────────
def show_status() -> None:
    """Tampilkan statistik dari log alerts."""
    log_header("Selene — Threat Monitor Status")

    alerts = read_jsonl(LOGS_DIR / "alerts.jsonl", last_n=200)
    if not alerts:
        log("INFO", "Belum ada alert yang tercatat.")
        return

    cutoff_24h  = datetime.now() - timedelta(hours=24)
    cutoff_week = datetime.now() - timedelta(days=7)

    last_24h  = []
    last_week = []
    for a in alerts:
        try:
            ts = datetime.fromisoformat(a.get("timestamp",""))
            if ts > cutoff_24h:
                last_24h.append(a)
            if ts > cutoff_week:
                last_week.append(a)
        except (ValueError, TypeError):
            pass

    log_section("RINGKASAN ALERT")
    print(c(f"\n  24 jam terakhir : {len(last_24h)} alert", Fore.WHITE))
    print(c(f"  7 hari terakhir : {len(last_week)} alert", Fore.WHITE))
    print(c(f"  Total di log    : {len(alerts)} alert", Fore.WHITE))

    if last_24h:
        log_section("ALERT 24 JAM TERAKHIR")
        ip_counts: Dict[str, int] = defaultdict(int)
        for a in last_24h:
            ip = a.get("ip","?")
            if ip:
                ip_counts[ip] += 1

        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(c(f"  {ip:<20}  {count} alert", Fore.YELLOW))

    log_section("5 ALERT TERBARU")
    for a in reversed(alerts[-5:]):
        ts  = a.get("timestamp","?")[:16]
        lvl = a.get("level","?")
        msg = a.get("message","?")
        ip  = a.get("ip") or ""
        col = Fore.RED if lvl in ("CRIT","WARN") else Fore.CYAN
        print(c(f"\n  [{ts}] {msg}", col))
        if ip:
            print(c(f"  IP: {ip}", Fore.WHITE))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Selene Threat Monitor — IDS real-time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  sudo python scripts/threat_monitor.py
  python scripts/threat_monitor.py --no-block
  python scripts/threat_monitor.py --status
  python scripts/threat_monitor.py --interval 10"""
    )
    parser.add_argument("--no-block", action="store_true",
                        help="Deteksi saja, jangan blokir IP apapun")
    parser.add_argument("--status",   action="store_true",
                        help="Tampilkan statistik dari log, lalu keluar")
    parser.add_argument("--interval", type=int, default=5, metavar="DETIK",
                        help="Interval cek koneksi untuk mode psutil (default: 5)")
    args = parser.parse_args()

    if args.status:
        show_status(); return

    log_header("Selene — Threat Monitor v3.0",
               "IDS real-time: deteksi & blokir ancaman otomatis")

    cfg = get_config()

    # Kumpulkan IP terpercaya
    trusted: Set[str] = set()
    trusted.add(get_local_ip())
    gw = get_default_gateway()
    if gw:
        trusted.add(gw)
    for ip in cfg.get("network","trusted_ips",default=[]):
        trusted.add(ip)

    auto_block = cfg.get("monitor","auto_block",default=True) and not args.no_block

    state = MonitorState(trusted_ips=trusted)

    log_section("KONFIGURASI")
    log("INFO", f"IP terpercaya : {', '.join(sorted(trusted))}")
    log("INFO", f"Auto-blokir   : {'Ya' if auto_block else 'Tidak (--no-block)'}")
    log("INFO", f"Mode          : {'Scapy (real-time)' if HAS_SCAPY and IS_ROOT else 'psutil (polling)'}")
    if not IS_ROOT:
        log("WARN", "Berjalan tanpa root — mode psutil, beberapa deteksi tidak tersedia")
        log("INFO", "Jalankan dengan sudo untuk deteksi penuh")

    # Thread status reporter
    reporter = threading.Thread(
        target=status_reporter,
        args=(state, 300),
        daemon=True
    )
    reporter.start()

    log_section("MONITORING AKTIF")
    print(c("  Menunggu ancaman...\n", Fore.GREEN))

    try:
        if HAS_SCAPY and IS_ROOT:
            start_scapy_monitor(state, cfg, auto_block)
        elif HAS_PSUTIL:
            start_psutil_monitor(state, cfg, auto_block, args.interval)
        else:
            log("ERROR", "Dibutuhkan psutil atau scapy.")
            log("INFO",  "Install: pip install psutil")
            sys.exit(1)

    except KeyboardInterrupt:
        pass

    # Ringkasan sesi
    uptime = datetime.now() - state.start_time
    log_section("RINGKASAN SESI")
    print(c(f"\n  Durasi    : {str(uptime).split('.')[0]}", Fore.WHITE))
    print(c(f"  Events    : {state.event_count}", Fore.WHITE))
    print(c(f"  Alerts    : {state.alert_count}", Fore.WHITE))
    print(c(f"  Diblokir  : {len(state.blocked_ips)} IP", Fore.WHITE))
    if state.threat_scores:
        print(c("\n  IP dengan skor tertinggi:", Fore.YELLOW))
        for ip, score in sorted(state.threat_scores.items(),
                                key=lambda x: x[1], reverse=True)[:5]:
            print(c(f"    {ip:<20}  skor {score}", Fore.YELLOW))

    # Unblock semua IP saat selesai
    if state.blocked_ips and IS_ROOT:
        print()
        for ip in list(state.blocked_ips.keys()):
            if unblock_ip(ip):
                log("OK", f"IP dilepas blokir: {ip}")

    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(); log("INFO", "Monitor dihentikan.")
    except Exception as e:
        log("ERROR", f"Error: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()
