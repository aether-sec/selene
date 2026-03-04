#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Network Scanner v3.0                              ║
║   Temukan semua perangkat, port, dan ancaman di jaringan.    ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/network_scanner.py
  python scripts/network_scanner.py --quick
  python scripts/network_scanner.py --range 192.168.1.0/24
  python scripts/network_scanner.py --target 192.168.1.5
"""

import sys
import os
import time
import socket
import json
import argparse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        get_local_ip, get_hostname,
        write_alert, save_json, Spinner,
        IS_ROOT, REPORTS_DIR,
    )
    from selene.core.network import (
        get_network_range, arp_scan, scan_ports, grab_banner,
        fingerprint_os, get_vendor,
        COMMON_PORTS, QUICK_PORTS, PORT_NAMES, DANGEROUS_PORTS,
        is_private_ip,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}")
    print("  Jalankan dari direktori root Selene.")
    sys.exit(1)

TOOL_VERSION = "3.0.0"

# ── Risk scoring ──────────────────────────────────────────────────────────────
def score_device(open_ports: list) -> tuple:
    """
    Hitung skor risiko perangkat (0-100).
    Returns: (skor, [alasan])
    """
    score   = 0
    reasons = []
    port_set = set(open_ports)

    # Port berbahaya
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            score += 18
            reasons.append(f"Port {port} ({PORT_NAMES.get(port,'?')}) terbuka — {DANGEROUS_PORTS[port]}")

    # Banyak port terbuka
    if len(open_ports) > 12:
        score += 12
        reasons.append(f"Banyak port terbuka ({len(open_ports)}) — kemungkinan server yang tidak diamankan")
    elif len(open_ports) > 6:
        score += 5

    # Port backdoor klasik
    backdoors = {4444, 31337, 12345, 1337, 6666, 9999, 7777}
    found = backdoors & port_set
    if found:
        score += 40
        reasons.append(f"Port backdoor terdeteksi: {sorted(found)}")

    # Telnet
    if 23 in port_set:
        score += 12
        reasons.append("Telnet aktif — protokol tidak terenkripsi, ganti dengan SSH")

    return min(score, 100), reasons

# ── Single device scan ────────────────────────────────────────────────────────
def scan_device(ip: str, quick: bool = False) -> dict:
    """Scan lengkap satu perangkat. Semua operasi punya timeout."""

    # Hostname lookup (non-blocking dengan timeout)
    hostname = "?"
    try:
        socket.setdefaulttimeout(1.5)
        hostname = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(None)
    except Exception:
        socket.setdefaulttimeout(None)

    # Port scan
    ports_to_scan = QUICK_PORTS if quick else COMMON_PORTS
    open_ports    = scan_ports(ip, ports_to_scan, timeout=0.8)

    # Banner grab (maks 4 port, timeout ketat)
    banners = {}
    for port in open_ports[:4]:
        b = grab_banner(ip, port, timeout=1.5)
        if b:
            banners[port] = b[:100]

    # OS fingerprint
    os_guess = fingerprint_os(ip, open_ports)

    # Risk score
    risk_score, risk_reasons = score_device(open_ports)

    return {
        "ip":          ip,
        "hostname":    hostname,
        "mac":         "?",     # diisi caller
        "vendor":      "?",     # diisi caller
        "os_guess":    os_guess,
        "open_ports":  open_ports,
        "port_names":  {str(p): PORT_NAMES.get(p,"?") for p in open_ports},
        "banners":     {str(k): v for k,v in banners.items()},
        "risk_score":  risk_score,
        "risk_reasons":risk_reasons,
        "scanned_at":  datetime.now().isoformat(),
    }

# ── Print helpers ─────────────────────────────────────────────────────────────
def print_device_card(device: dict, index: int) -> None:
    """Cetak kartu informasi satu perangkat."""
    score    = device.get("risk_score", 0)
    ip       = device["ip"]
    hostname = device.get("hostname","?")
    vendor   = device.get("vendor","?")
    os_guess = device.get("os_guess","?")
    ports    = device.get("open_ports", [])

    if score >= 70:
        header_color = Fore.RED
    elif score >= 40:
        header_color = Fore.YELLOW
    else:
        header_color = Fore.CYAN

    # Header
    h_extra = f"  ({hostname})" if hostname not in ("?","") else ""
    print(c(f"\n  [{index:02d}] {ip}{h_extra}", header_color, bold=True))

    # Info baris
    print(c(f"       MAC/Vendor : {device.get('mac','?')}  /  {vendor}", Fore.WHITE))
    print(c(f"       OS (estimasi): {os_guess}", Fore.WHITE))

    # Port
    if ports:
        labeled = [f"{p}({PORT_NAMES.get(p,'?')})" for p in ports[:6]]
        extra   = f" +{len(ports)-6} lagi" if len(ports) > 6 else ""
        print(c(f"       Port terbuka  : {', '.join(labeled)}{extra}", Fore.WHITE))

        # Highlight port berbahaya
        dangerous_found = [p for p in ports if p in DANGEROUS_PORTS]
        if dangerous_found:
            for dp in dangerous_found:
                print(c(f"       ⚠  {dp} ({PORT_NAMES.get(dp,'?')}) — {DANGEROUS_PORTS[dp]}",
                         Fore.YELLOW))
    else:
        print(c(f"       Port terbuka  : tidak ada", Fore.GREEN))

    # Risk score
    from selene.core.common import risk_color, risk_label
    rc = risk_color(score)
    rl = risk_label(score)
    print(c(f"       Skor risiko   : ", Fore.WHITE), end="")
    print(c(f"{score}/100 — {rl}", rc, bold=(score >= 40)))

    # Alasan
    for reason in device.get("risk_reasons", [])[:2]:
        print(c(f"         → {reason}", Fore.YELLOW))

def print_scan_summary(devices: list, elapsed: float) -> None:
    """Cetak ringkasan akhir scan."""
    log_section("RINGKASAN SCAN")

    total     = len(devices)
    high      = [d for d in devices if d.get("risk_score",0) >= 70]
    med       = [d for d in devices if 40 <= d.get("risk_score",0) < 70]
    dangerous_devs = [d for d in devices
                      if any(p in DANGEROUS_PORTS for p in d.get("open_ports",[]))]

    print(c(f"\n  Perangkat ditemukan  : {total}", Fore.WHITE))
    print(c(f"  Risiko TINGGI        : {len(high)}",
            Fore.RED if high else Fore.GREEN, bold=bool(high)))
    print(c(f"  Risiko SEDANG        : {len(med)}",
            Fore.YELLOW if med else Fore.GREEN))
    print(c(f"  Port berbahaya       : {len(dangerous_devs)} perangkat",
            Fore.YELLOW if dangerous_devs else Fore.GREEN))
    print(c(f"  Waktu scan           : {elapsed:.1f} detik", Fore.WHITE))

    # Perangkat risiko tinggi
    if high:
        print(c(f"\n  ⛔ Perhatian — Perangkat risiko TINGGI:", Fore.RED, bold=True))
        for d in high:
            print(c(f"     • {d['ip']} — skor {d['risk_score']}", Fore.RED))
            for r in d.get("risk_reasons",[])[:1]:
                print(c(f"       {r}", Fore.YELLOW))

    # Rekomendasi umum
    print(c(f"\n  💡 Rekomendasi:", Fore.CYAN, bold=True))
    telnet  = [d for d in devices if 23 in d.get("open_ports",[])]
    rdp     = [d for d in devices if 3389 in d.get("open_ports",[])]
    vnc     = [d for d in devices if 5900 in d.get("open_ports",[])]

    if telnet:
        print(c(f"  • Nonaktifkan Telnet di {len(telnet)} perangkat — ganti dengan SSH", Fore.YELLOW))
    if rdp:
        print(c(f"  • {len(rdp)} perangkat membuka RDP — batasi dengan firewall atau VPN", Fore.YELLOW))
    if vnc:
        print(c(f"  • {len(vnc)} perangkat membuka VNC — pastikan ada password kuat", Fore.YELLOW))
    if not high and not med:
        print(c(f"  • Tidak ada masalah serius. Lakukan scan rutin setiap minggu.", Fore.GREEN))

# ── Main scan ─────────────────────────────────────────────────────────────────
def run_scan(target_range: str = None, quick: bool = False,
             single_ip: str = None) -> list:
    """Fungsi scan utama. Kembali: list of device dicts."""
    cfg     = get_config()
    devices = []

    # Mode: satu host
    if single_ip:
        log_section(f"SCAN SATU HOST: {single_ip}")
        log("SCAN", f"Memindai {single_ip}...")
        device = scan_device(single_ip, quick)
        print_device_card(device, 1)
        return [device]

    # Mode: jaringan penuh
    scan_range = target_range or cfg.get("network","scan_range",default="auto")
    if not scan_range or scan_range == "auto":
        scan_range = get_network_range()

    log_section("FASE 1 — TEMUKAN PERANGKAT")
    log("INFO", f"Range: {scan_range}")
    log("INFO", f"Mode: {'Quick' if quick else 'Lengkap'}")
    log("INFO", f"IP lokal: {get_local_ip()}  Hostname: {get_hostname()}")
    log("INFO", "ARP scan" if IS_ROOT else "Ping sweep (tanpa root)")

    start = time.time()

    with Spinner("Mencari perangkat aktif..."):
        hosts = arp_scan(scan_range, timeout=2.0)

    if not hosts:
        log("WARN", "Tidak ada perangkat ditemukan.")
        log("INFO", "Pastikan kamu terhubung ke jaringan.")
        return []

    log("OK", c(f"Ditemukan {len(hosts)} perangkat aktif", Fore.GREEN, bold=True))

    mac_map = {h["ip"]: h["mac"] for h in hosts}
    ip_list = [h["ip"] for h in hosts]

    # Fase 2: Detail scan
    log_section("FASE 2 — SCAN DETAIL")
    mode_label = "quick scan" if quick else f"{len(COMMON_PORTS)} port"
    log("SCAN", f"Memindai {len(ip_list)} perangkat ({mode_label})...")

    done    = 0
    total   = len(ip_list)
    workers = min(4, total)  # Batasi agar tidak overload jaringan

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {
            ex.submit(scan_device, ip, quick): ip
            for ip in ip_list
        }
        for future in as_completed(future_map, timeout=total * 15 + 30):
            ip = future_map[future]
            done += 1
            try:
                device = future.result(timeout=25)
                device["mac"]    = mac_map.get(ip,"?")
                device["vendor"] = get_vendor(device["mac"])
                devices.append(device)

                print_device_card(device, done)
                log("INFO", c(f"  [{done}/{total}] {ip} — selesai", Fore.WHITE))

                # Alert otomatis jika risiko tinggi
                if device["risk_score"] >= 70:
                    write_alert(
                        "WARN",
                        f"Perangkat risiko tinggi: {ip} (skor {device['risk_score']})",
                        details={"ip": ip, "ports": device["open_ports"]},
                        ip=ip,
                    )
            except Exception as e:
                log("WARN", f"  [{done}/{total}] {ip} — error: {e}")
                devices.append({
                    "ip": ip, "mac": mac_map.get(ip,"?"),
                    "open_ports": [], "risk_score": 0,
                    "error": str(e),
                })

    elapsed = time.time() - start
    print_scan_summary(devices, elapsed)
    return devices

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Selene Network Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/network_scanner.py
  python scripts/network_scanner.py --quick
  python scripts/network_scanner.py --range 10.0.0.0/24
  python scripts/network_scanner.py --target 192.168.1.100"""
    )
    parser.add_argument("--range",  "-r", help="Range CIDR (contoh: 192.168.1.0/24)")
    parser.add_argument("--target", "-t", help="Scan satu IP saja")
    parser.add_argument("--quick",  "-q", action="store_true",
                        help="Scan cepat — hanya port umum")
    parser.add_argument("--no-save", action="store_true",
                        help="Jangan simpan laporan")
    args = parser.parse_args()

    log_header("Selene — Network Scanner v3.0",
               "Temukan semua perangkat dan ancaman di jaringan")

    try:
        devices = run_scan(
            target_range = args.range,
            quick        = args.quick,
            single_ip    = args.target,
        )

        if devices and not args.no_save:
            ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
            rpath = REPORTS_DIR / f"scan_{ts}.json"
            save_json(rpath, {
                "tool":         "network_scanner",
                "version":      TOOL_VERSION,
                "scan_time":    datetime.now().isoformat(),
                "range":        args.range or get_network_range(),
                "device_count": len(devices),
                "devices":      devices,
            })
            log("OK", c(f"Laporan disimpan: reports/scan_{ts}.json", Fore.GREEN))

    except KeyboardInterrupt:
        print()
        log("INFO", "Scan dihentikan.")
    except Exception as e:
        log("ERROR", f"Error tidak terduga: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()

    print()

if __name__ == "__main__":
    main()
