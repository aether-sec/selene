#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — WiFi Analyzer v3.0                                ║
║   Deteksi rogue AP, enkripsi lemah, dan ancaman WiFi.        ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/wifi_analyzer.py
  python scripts/wifi_analyzer.py --iface wlan0
  python scripts/wifi_analyzer.py --monitor     ← pantau terus-menerus
  sudo python scripts/wifi_analyzer.py --deep   ← scan mendalam (Scapy)

Catatan:
  Mode dasar: hanya butuh python + psutil/nmcli.
  Mode mendalam (--deep): butuh scapy + root.
"""

import sys
import os
import re
import subprocess
import shutil
import time
import json
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        write_alert, save_json, Spinner,
        IS_LINUX, IS_WINDOWS, IS_ANDROID, IS_ROOT,
        REPORTS_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import scapy.all as scapy
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

TOOL_VERSION = "3.0.0"

# ── Enkripsi yang lemah ───────────────────────────────────────────────────────
WEAK_ENCRYPTIONS = {"WEP", "OPEN", "NONE", ""}
MEDIUM_ENCRYPTIONS = {"WPA"}
STRONG_ENCRYPTIONS = {"WPA2", "WPA3", "WPA2-PSK", "WPA3-SAE"}

# Kanal yang valid (2.4GHz dan 5GHz)
VALID_CHANNELS_24G = set(range(1, 15))
VALID_CHANNELS_5G  = {36,40,44,48,52,56,60,64,100,104,108,112,
                       116,120,124,128,132,136,140,144,149,153,
                       157,161,165}

# SSID yang umum dijadikan rogue AP
COMMON_HONEYPOT_SSIDS = {
    "free wifi", "free internet", "airport wifi", "hotel wifi",
    "starbucks", "mcdonalds wifi", "guest", "public", "hotspot",
    "wifi free", "internet gratis", "wifi gratis",
}

# ── Network interface helper ──────────────────────────────────────────────────
def get_wifi_interface() -> Optional[str]:
    """Temukan network interface WiFi yang aktif."""
    if IS_LINUX or IS_ANDROID:
        candidates = []

        # Cek /proc/net/wireless
        try:
            content = Path("/proc/net/wireless").read_text(errors="ignore")
            for line in content.splitlines()[2:]:
                iface = line.split(":")[0].strip()
                if iface:
                    candidates.append(iface)
        except OSError:
            pass

        # Fallback: cari dari psutil
        if not candidates and HAS_PSUTIL:
            for iface in psutil.net_if_stats():
                if any(x in iface.lower() for x in ["wlan","wifi","wlp","wlx"]):
                    candidates.append(iface)

        # Fallback: cari dari /sys
        if not candidates:
            sys_net = Path("/sys/class/net")
            if sys_net.exists():
                for d in sys_net.iterdir():
                    if (d / "wireless").exists() or (d / "phy80211").exists():
                        candidates.append(d.name)

        return candidates[0] if candidates else None

    elif IS_WINDOWS:
        # Windows: cari dari netsh
        out = _run(["netsh","wlan","show","interfaces"])
        m   = re.search(r"Name\s*:\s*(.+)", out)
        return m.group(1).strip() if m else None

    return None

def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="ignore")
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""

def _run_shell(cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout, errors="ignore")
        return r.stdout.strip()
    except Exception:
        return ""

# ── Scanner menggunakan nmcli/iwlist/netsh ────────────────────────────────────
def scan_with_nmcli() -> List[Dict]:
    """Scan jaringan WiFi menggunakan nmcli (NetworkManager)."""
    networks = []

    # Refresh dulu
    _run(["nmcli","dev","wifi","rescan"], timeout=5)
    time.sleep(2)

    out = _run(["nmcli","--fields",
                "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY",
                "-t", "dev","wifi","list"])
    if not out:
        return networks

    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 8:
            continue
        try:
            ssid     = parts[0].strip()
            bssid    = ":".join(parts[1:7]).strip() if len(parts) > 7 else parts[1].strip()
            security = parts[-1].strip() if parts[-1].strip() else "OPEN"
            signal   = int(parts[-2]) if parts[-2].strip().isdigit() else 0
            channel  = parts[3].strip()

            networks.append({
                "ssid":     ssid or "<hidden>",
                "bssid":    bssid.upper(),
                "security": security.upper().replace("--","OPEN"),
                "signal":   signal,
                "channel":  channel,
                "source":   "nmcli",
            })
        except (IndexError, ValueError):
            pass

    return networks

def scan_with_iwlist(iface: str) -> List[Dict]:
    """Scan menggunakan iwlist (lebih luas tersedia)."""
    networks = []
    out      = _run(["iwlist", iface, "scan"], timeout=15)
    if not out:
        return networks

    # Parse blok per AP
    blocks = re.split(r"Cell \d+ -", out)
    for block in blocks[1:]:  # Skip header
        net = {}

        m = re.search(r"ESSID:\"([^\"]*?)\"", block)
        net["ssid"]     = m.group(1) if m else "<hidden>"

        m = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", block)
        net["bssid"]    = m.group(1).upper() if m else "?"

        m = re.search(r"Channel:(\d+)", block)
        net["channel"]  = m.group(1) if m else "?"

        m = re.search(r"Quality=(\d+)/(\d+)", block)
        if m:
            net["signal"] = int(int(m.group(1)) * 100 / int(m.group(2)))
        else:
            net["signal"] = 0

        # Enkripsi
        if "Encryption key:on" in block:
            if "WPA2" in block:
                net["security"] = "WPA2"
            elif "WPA" in block:
                net["security"] = "WPA"
            else:
                net["security"] = "WEP"
        else:
            net["security"] = "OPEN"

        net["source"] = "iwlist"
        networks.append(net)

    return networks

def scan_with_windows_netsh() -> List[Dict]:
    """Scan WiFi di Windows menggunakan netsh."""
    networks = []
    out      = _run(["netsh","wlan","show","networks","mode=Bssid"])
    if not out:
        return networks

    blocks = re.split(r"SSID \d+ :", out)
    for block in blocks[1:]:
        net = {}
        lines = block.strip().splitlines()

        net["ssid"]     = lines[0].strip() if lines else "<hidden>"

        m = re.search(r"Authentication\s*:\s*(.+)", block)
        net["security"] = m.group(1).strip().upper() if m else "?"

        m = re.search(r"Signal\s*:\s*(\d+)%", block)
        net["signal"]   = int(m.group(1)) if m else 0

        m = re.search(r"Channel\s*:\s*(\d+)", block)
        net["channel"]  = m.group(1) if m else "?"

        m = re.search(r"BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", block)
        net["bssid"]    = m.group(1).upper() if m else "?"

        net["source"] = "netsh"
        networks.append(net)

    return networks

# ── Scapy deep scan ───────────────────────────────────────────────────────────
_scapy_networks: Dict[str, Dict] = {}
_scapy_lock = threading.Lock()

def _scapy_packet_handler(pkt):
    """Handler paket untuk mode deep scan Scapy."""
    try:
        if not pkt.haslayer(Dot11Beacon):
            return
        if not pkt.haslayer(Dot11):
            return

        bssid = pkt[Dot11].addr2
        if not bssid:
            return

        bssid = bssid.upper()

        # SSID
        ssid = "?"
        try:
            ssid_elt = pkt[Dot11Elt]
            if ssid_elt.ID == 0:
                ssid = ssid_elt.info.decode(errors="replace").strip() or "<hidden>"
        except Exception:
            pass

        # Signal
        signal = 0
        if pkt.haslayer(RadioTap):
            try:
                signal = pkt[RadioTap].dBm_AntSignal
            except AttributeError:
                pass

        # Channel
        channel = "?"
        try:
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 3:  # DS Parameter (channel)
                    channel = str(elt.info[0])
                    break
                elt = elt.payload if hasattr(elt, "payload") else None
        except Exception:
            pass

        # Security
        security = "OPEN"
        stats = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        if "privacy" in stats.lower():
            security = "WPA2"  # Asumsi, perlu cek lebih detail

        with _scapy_lock:
            _scapy_networks[bssid] = {
                "ssid":     ssid,
                "bssid":    bssid,
                "security": security,
                "signal":   signal,
                "channel":  str(channel),
                "source":   "scapy",
            }
    except Exception:
        pass

def scan_with_scapy(iface: str, duration: int = 10) -> List[Dict]:
    """Deep scan menggunakan Scapy."""
    if not HAS_SCAPY or not IS_ROOT:
        return []

    log("INFO", f"Scapy deep scan pada {iface} selama {duration} detik...")
    _scapy_networks.clear()

    try:
        scapy.sniff(
            iface  = iface,
            prn    = _scapy_packet_handler,
            timeout= duration,
            store  = False,
            monitor= True,
        )
    except Exception as e:
        log("WARN", f"Scapy scan error: {e}")

    with _scapy_lock:
        return list(_scapy_networks.values())

# ── Analisis keamanan ─────────────────────────────────────────────────────────
def get_connected_ssid() -> Optional[str]:
    """Dapatkan SSID yang sedang terhubung."""
    if IS_LINUX:
        for cmd in (
            ["nmcli","-t","-f","ACTIVE,SSID","dev","wifi"],
            ["iwgetid","-r"],
        ):
            out = _run(cmd)
            if out:
                # nmcli format: yes:SSID
                if "yes:" in out:
                    return out.split("yes:")[1].strip()
                return out.strip()
    elif IS_WINDOWS:
        out = _run(["netsh","wlan","show","interfaces"])
        m   = re.search(r"SSID\s+:\s+(.+)", out)
        return m.group(1).strip() if m else None
    return None

def analyze_network_security(network: Dict,
                              all_networks: List[Dict],
                              connected_ssid: Optional[str]) -> List[Dict]:
    """
    Analisis satu jaringan untuk temuan keamanan.
    Returns: list of findings
    """
    findings = []
    ssid     = network.get("ssid","?")
    bssid    = network.get("bssid","?")
    security = network.get("security","?").upper()
    signal   = network.get("signal", 0)
    channel  = str(network.get("channel","?"))

    # 1. Enkripsi lemah / terbuka
    if security in WEAK_ENCRYPTIONS:
        findings.append({
            "severity": "TINGGI",
            "type":     "open_network",
            "title":    f"Jaringan terbuka: '{ssid}'",
            "desc":     "Tidak ada enkripsi — semua traffic bisa disadap",
            "solution": "Aktifkan WPA2 atau WPA3 pada access point",
        })
    elif security in MEDIUM_ENCRYPTIONS:
        findings.append({
            "severity": "SEDANG",
            "type":     "weak_encryption",
            "title":    f"Enkripsi lemah (WPA): '{ssid}'",
            "desc":     "WPA rentan terhadap serangan TKIP dan dictionary attack",
            "solution": "Upgrade ke WPA2-AES atau WPA3",
        })
    elif security == "WEP":
        findings.append({
            "severity": "KRITIS",
            "type":     "wep_encryption",
            "title":    f"WEP terdeteksi: '{ssid}'",
            "desc":     "WEP sudah sepenuhnya retak sejak 2001 — tidak aman sama sekali",
            "solution": "Ganti ke WPA2 atau WPA3 segera",
        })

    # 2. SSID honeypot / rogue AP (nama umum)
    ssid_lower = ssid.lower().strip()
    if ssid_lower in COMMON_HONEYPOT_SSIDS:
        findings.append({
            "severity": "TINGGI",
            "type":     "suspicious_ssid",
            "title":    f"SSID mencurigakan: '{ssid}'",
            "desc":     "Nama ini sering digunakan untuk honeypot / evil twin attack",
            "solution": "Jangan terhubung ke jaringan ini",
        })

    # 3. Evil twin: SSID sama tapi BSSID berbeda
    duplicates = [
        n for n in all_networks
        if n.get("ssid","?").lower() == ssid_lower
        and n.get("bssid","?") != bssid
        and n.get("bssid","?") != "?"
    ]
    if duplicates:
        findings.append({
            "severity": "KRITIS",
            "type":     "evil_twin",
            "title":    f"Evil twin terdeteksi: '{ssid}'",
            "desc":     f"Ada {1+len(duplicates)} AP dengan SSID yang sama tapi MAC berbeda",
            "solution": "Waspadai — salah satu mungkin penyerang yang meniru AP asli",
        })

    # 4. Sinyal sangat kuat (kemungkinan AP palsu dekat)
    # AP asli biasanya -40 sampai -80 dBm atau 40-80%
    if signal > 95 and ssid_lower in COMMON_HONEYPOT_SSIDS:
        findings.append({
            "severity": "SEDANG",
            "type":     "strong_signal_suspicious",
            "title":    f"Sinyal sangat kuat dari AP mencurigakan: '{ssid}'",
            "desc":     "AP palsu yang ditempatkan dekat korban biasanya punya sinyal sangat kuat",
            "solution": "Verifikasi BSSID dengan admin jaringan asli",
        })

    # 5. Kanal tidak valid (tanda AP tidak dikonfigurasi dengan benar atau palsu)
    if channel.isdigit():
        ch = int(channel)
        if ch not in VALID_CHANNELS_24G | VALID_CHANNELS_5G:
            findings.append({
                "severity": "RENDAH",
                "type":     "invalid_channel",
                "title":    f"Kanal tidak valid: {channel}",
                "desc":     "AP dikonfigurasi pada kanal yang tidak standar",
                "solution": "Periksa konfigurasi AP",
            })

    # 6. AP yang sedang terhubung tapi tidak aman
    if connected_ssid and ssid == connected_ssid and security in WEAK_ENCRYPTIONS:
        findings.append({
            "severity": "KRITIS",
            "type":     "connected_to_open",
            "title":    "Kamu sedang terhubung ke jaringan TERBUKA!",
            "desc":     "Semua data yang kamu kirim bisa disadap siapapun",
            "solution": "Putuskan koneksi dan gunakan VPN atau cari jaringan aman",
        })

    return findings

# ── Display ───────────────────────────────────────────────────────────────────
SEV_COLOR = {
    "KRITIS": Fore.RED,
    "TINGGI": Fore.RED,
    "SEDANG": Fore.YELLOW,
    "RENDAH": Fore.CYAN,
}

def print_network_card(network: Dict, findings: List[Dict],
                       index: int, is_connected: bool) -> None:
    """Cetak kartu satu jaringan WiFi."""
    ssid     = network.get("ssid","?")
    bssid    = network.get("bssid","?")
    security = network.get("security","?")
    signal   = network.get("signal", 0)
    channel  = network.get("channel","?")

    # Bar sinyal
    bars = int(signal / 25)  # 0-4 bar
    bar  = "▓" * bars + "░" * (4-bars)

    # Warna berdasarkan keamanan
    if security in WEAK_ENCRYPTIONS:
        sec_color = Fore.RED
    elif security in MEDIUM_ENCRYPTIONS:
        sec_color = Fore.YELLOW
    else:
        sec_color = Fore.GREEN

    conn_mark = c(" [TERHUBUNG]", Fore.GREEN, bold=True) if is_connected else ""
    print(c(f"\n  [{index:02d}] {ssid}", Fore.WHITE, bold=True) + conn_mark)
    print(c(f"       BSSID   : {bssid}", Fore.WHITE))
    print(c(f"       Kanal   : {channel}   Sinyal: {signal}% [{bar}]", Fore.WHITE))
    print(c(f"       Keamanan: {security}", sec_color, bold=(security in WEAK_ENCRYPTIONS)))

    if findings:
        for f in findings:
            col = SEV_COLOR.get(f["severity"], Fore.WHITE)
            print(c(f"       ⚠  [{f['severity']}] {f['title']}", col, bold=(f['severity']=="KRITIS")))
            print(c(f"              Solusi: {f['solution']}", Fore.CYAN))

def print_summary(all_findings: List[Dict], networks: List[Dict],
                  elapsed: float) -> None:
    """Cetak ringkasan scan WiFi."""
    log_section("RINGKASAN")

    total  = len(networks)
    open_n = sum(1 for n in networks if n.get("security","") in WEAK_ENCRYPTIONS)
    wpa_n  = sum(1 for n in networks if n.get("security","") in MEDIUM_ENCRYPTIONS)
    wpa2_n = sum(1 for n in networks if n.get("security","") in STRONG_ENCRYPTIONS)
    kritis = [f for f in all_findings if f.get("severity") == "KRITIS"]
    evil   = [f for f in all_findings if f.get("type") == "evil_twin"]

    print(c(f"\n  Jaringan ditemukan   : {total}", Fore.WHITE))
    print(c(f"  Terbuka / tidak aman : {open_n}",
            Fore.RED if open_n else Fore.GREEN))
    print(c(f"  WPA (lemah)          : {wpa_n}",
            Fore.YELLOW if wpa_n else Fore.GREEN))
    print(c(f"  WPA2/WPA3 (aman)     : {wpa2_n}", Fore.GREEN))
    print(c(f"  Evil twin terdeteksi : {len(evil)}",
            Fore.RED if evil else Fore.GREEN, bold=bool(evil)))
    print(c(f"  Total masalah kritis : {len(kritis)}",
            Fore.RED if kritis else Fore.GREEN, bold=bool(kritis)))
    print(c(f"  Waktu scan           : {elapsed:.1f} detik", Fore.WHITE))

    if evil:
        print(c(f"\n  ⛔ EVIL TWIN ATTACK terdeteksi!", Fore.RED, bold=True))
        print(c("     Jangan terhubung ke jaringan tersebut!", Fore.RED))

    if not all_findings:
        print(c("\n  ✓  Tidak ada ancaman WiFi yang terdeteksi.", Fore.GREEN, bold=True))
    elif not kritis:
        print(c(f"\n  ℹ  {len(all_findings)} masalah ditemukan tapi tidak ada yang kritis.",
                Fore.YELLOW))

# ── Monitor mode ──────────────────────────────────────────────────────────────
def monitor_mode(iface: Optional[str], interval: int = 30) -> None:
    """Pantau jaringan WiFi terus-menerus, alert jika ada perubahan."""
    log("INFO", f"Mode monitor aktif — interval {interval} detik")
    log("INFO", c("Tekan Ctrl+C untuk berhenti", Fore.WHITE))

    known_bssids: Set[str] = set()
    known_findings_keys: Set[str] = set()

    while True:
        try:
            networks = collect_networks(iface)
            if not networks:
                time.sleep(interval)
                continue

            current_bssids = {n.get("bssid","?") for n in networks}
            connected      = get_connected_ssid()
            all_findings   = []

            # Cek evil twin dan masalah kritis
            for net in networks:
                findings = analyze_network_security(net, networks, connected)
                all_findings.extend(findings)

                # Alert untuk yang baru
                for f in findings:
                    key = f"{net.get('bssid','?')}_{f['type']}"
                    if key not in known_findings_keys:
                        known_findings_keys.add(key)
                        if f["severity"] in ("KRITIS","TINGGI"):
                            ts = datetime.now().strftime("%H:%M:%S")
                            print(c(f"\n  [{ts}] ⚠  WiFi: {f['title']}", Fore.RED, bold=True))
                            print(c(f"         {f['desc']}", Fore.YELLOW))
                            write_alert("WARN", f"WiFi: {f['title']}",
                                        details={**f, "bssid": net.get("bssid")})

            # AP baru muncul
            new_aps = current_bssids - known_bssids
            for bssid in new_aps:
                net    = next((n for n in networks if n.get("bssid") == bssid), {})
                ssid   = net.get("ssid","?")
                ts     = datetime.now().strftime("%H:%M:%S")
                security = net.get("security","?")
                col    = Fore.RED if security in WEAK_ENCRYPTIONS else Fore.CYAN
                print(c(f"\n  [{ts}] 📡 AP baru terdeteksi: '{ssid}' ({bssid}) [{security}]",
                        col))

            known_bssids = current_bssids
            time.sleep(interval)

        except KeyboardInterrupt:
            break
        except Exception as e:
            log("WARN", f"Monitor error: {e}")
            time.sleep(interval)

# ── Kumpulkan jaringan ────────────────────────────────────────────────────────
def collect_networks(iface: Optional[str]) -> List[Dict]:
    """Kumpulkan daftar jaringan WiFi dengan berbagai metode."""
    networks = []

    if IS_LINUX and not IS_ANDROID:
        # Coba nmcli dulu (paling lengkap)
        if shutil.which("nmcli"):
            networks = scan_with_nmcli()
        # Fallback ke iwlist
        if not networks and iface and shutil.which("iwlist"):
            networks = scan_with_iwlist(iface)

    elif IS_ANDROID:
        # Termux: coba iwlist jika tersedia
        if iface and shutil.which("iwlist"):
            networks = scan_with_iwlist(iface)

    elif IS_WINDOWS:
        networks = scan_with_windows_netsh()

    return networks

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Selene WiFi Analyzer — Deteksi ancaman WiFi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/wifi_analyzer.py
  python scripts/wifi_analyzer.py --iface wlan0
  python scripts/wifi_analyzer.py --monitor
  sudo python scripts/wifi_analyzer.py --deep"""
    )
    parser.add_argument("--iface",   "-i", help="Interface WiFi (contoh: wlan0)")
    parser.add_argument("--monitor", "-m", action="store_true",
                        help="Mode monitor — pantau terus-menerus")
    parser.add_argument("--deep",    action="store_true",
                        help="Deep scan dengan Scapy (butuh root + monitor mode)")
    parser.add_argument("--interval",type=int, default=30, metavar="DETIK",
                        help="Interval monitor mode (default: 30 detik)")
    parser.add_argument("--no-save", action="store_true",
                        help="Jangan simpan laporan")
    args = parser.parse_args()

    log_header("Selene — WiFi Analyzer v3.0",
               "Deteksi rogue AP, enkripsi lemah, dan ancaman WiFi")

    # Temukan interface
    iface = args.iface or get_wifi_interface()
    if iface:
        log("INFO", f"Interface WiFi: {iface}")
    else:
        log("INFO", "Interface WiFi tidak terdeteksi — akan gunakan nmcli/netsh")

    # Mode monitor
    if args.monitor:
        log_section("MODE MONITOR")
        monitor_mode(iface, args.interval)
        return

    # Mode deep scan
    if args.deep:
        if not HAS_SCAPY:
            log("ERROR", "Scapy tidak tersedia. Install: pip install scapy")
            sys.exit(1)
        if not IS_ROOT:
            log("ERROR", "Deep scan membutuhkan root.")
            sys.exit(1)
        if not iface:
            log("ERROR", "Tentukan interface: --iface wlan0")
            sys.exit(1)
        log_section("DEEP SCAN (Scapy)")
        with Spinner("Menangkap beacon frame..."):
            networks = scan_with_scapy(iface, duration=10)
    else:
        # Mode standar
        log_section("SCAN JARINGAN WIFI")
        with Spinner("Memindai jaringan WiFi..."):
            networks = collect_networks(iface)

    if not networks:
        log("WARN", "Tidak ada jaringan WiFi yang ditemukan.")
        if IS_LINUX:
            log("INFO", "Pastikan WiFi aktif: nmcli radio wifi on")
        elif IS_WINDOWS:
            log("INFO", "Pastikan WiFi adapter aktif")
        return

    log("OK", c(f"Ditemukan {len(networks)} jaringan WiFi", Fore.GREEN, bold=True))

    start        = time.time()
    connected    = get_connected_ssid()
    all_findings = []

    # Analisis setiap jaringan
    log_section("ANALISIS KEAMANAN")
    for i, network in enumerate(networks, 1):
        ssid         = network.get("ssid","?")
        is_connected = (connected and connected == ssid)
        findings     = analyze_network_security(network, networks, connected)
        all_findings.extend(findings)
        print_network_card(network, findings, i, is_connected)

        # Alert kritis
        for f in findings:
            if f["severity"] in ("KRITIS","TINGGI"):
                write_alert("WARN", f"WiFi: {f['title']}",
                            details={**f, "bssid": network.get("bssid","?")})

    elapsed = time.time() - start
    print_summary(all_findings, networks, elapsed)

    # Simpan laporan
    if not args.no_save:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"wifi_{ts}.json"
        save_json(path, {
            "tool":       "wifi_analyzer",
            "version":    TOOL_VERSION,
            "scan_time":  datetime.now().isoformat(),
            "interface":  iface,
            "networks":   networks,
            "findings":   all_findings,
        })
        log("OK", c(f"Laporan: reports/wifi_{ts}.json", Fore.GREEN))

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
