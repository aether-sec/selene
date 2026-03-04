"""
selene/core/network.py
Utilitas jaringan bersama. Semua operasi punya timeout eksplisit.
"""

import os
import socket
import struct
import platform
import subprocess
import ipaddress
import threading
import re
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from selene.core.common import (
    log, IS_LINUX, IS_WINDOWS, IS_ANDROID, IS_ROOT, get_local_ip
)

# ── Capability detection ──────────────────────────────────────────────────────
try:
    import scapy.all as scapy
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# ── Interface & gateway ───────────────────────────────────────────────────────
def get_default_gateway() -> Optional[str]:
    try:
        if IS_LINUX or IS_ANDROID:
            with open("/proc/net/route") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        return socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
        elif IS_WINDOWS:
            out = subprocess.check_output(["route","print","0.0.0.0"],
                                          stderr=subprocess.DEVNULL, timeout=5
                                          ).decode(errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0":
                    try:
                        candidate = parts[2]
                        ipaddress.ip_address(candidate)
                        if candidate != "0.0.0.0":
                            return candidate
                    except ValueError:
                        pass
    except Exception:
        pass
    local = get_local_ip()
    parts = local.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.1" if len(parts) == 4 else None

def get_network_range() -> str:
    local = get_local_ip()
    parts = local.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "192.168.1.0/24"

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ── ARP table ─────────────────────────────────────────────────────────────────
def get_arp_table() -> Dict[str, str]:
    table = {}
    try:
        if IS_LINUX or IS_ANDROID:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        table[parts[0]] = parts[3].lower()
        elif IS_WINDOWS:
            out = subprocess.check_output(["arp","-a"],
                                          stderr=subprocess.DEVNULL, timeout=5
                                          ).decode(errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    table[parts[0]] = parts[1].replace("-",":").lower()
    except Exception:
        pass
    return table

# ── Host discovery ────────────────────────────────────────────────────────────
def ping_host(ip: str, timeout: float = 1.0) -> bool:
    try:
        if IS_WINDOWS:
            cmd = ["ping","-n","1","-w",str(int(timeout*1000)), ip]
        else:
            cmd = ["ping","-c","1","-W",str(int(timeout)), ip]
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return r.returncode == 0
    except Exception:
        return False

def arp_scan(network_range: str, timeout: float = 2.0) -> List[Dict]:
    """ARP scan. Fallback ke ping sweep jika scapy tidak ada."""
    if HAS_SCAPY and IS_ROOT:
        return _scapy_arp_scan(network_range, timeout)
    return _ping_sweep(network_range)

def _scapy_arp_scan(network_range: str, timeout: float) -> List[Dict]:
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range)
        answered, _ = scapy.srp(pkt, timeout=timeout, verbose=False, retry=1)
        return [{"ip": r.psrc, "mac": r.hwsrc.lower()} for _, r in answered]
    except Exception as e:
        log("WARN", f"Scapy ARP gagal: {e} — beralih ke ping sweep")
        return _ping_sweep(network_range)

def _ping_sweep(network_range: str) -> List[Dict]:
    try:
        hosts = [str(ip) for ip in ipaddress.ip_network(network_range, strict=False).hosts()]
    except ValueError:
        return []

    alive = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(ping_host, ip, 0.7): ip for ip in hosts}
        for f in as_completed(futures, timeout=len(hosts)*0.04 + 15):
            try:
                if f.result():
                    alive.append(futures[f])
            except Exception:
                pass

    arp = get_arp_table()
    return [{"ip": ip, "mac": arp.get(ip, "unknown")} for ip in alive]

# ── Port scanning ─────────────────────────────────────────────────────────────
COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,
                993,995,1433,1521,3306,3389,5432,5900,6379,
                8080,8443,9200,27017]
QUICK_PORTS  = [22,80,443,445,3306,3389,6379,8080]

PORT_NAMES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 135:"RPC", 139:"NetBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 1521:"Oracle", 3306:"MySQL", 3389:"RDP",
    5432:"PostgreSQL", 5900:"VNC", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 9200:"Elasticsearch",
    27017:"MongoDB",
}

DANGEROUS_PORTS = {
    23:"Telnet — tidak terenkripsi",
    445:"SMB — rentan EternalBlue",
    3389:"RDP — sering brute force",
    5900:"VNC — sering tanpa auth",
    6379:"Redis — sering tanpa auth",
    9200:"Elasticsearch — sering tanpa auth",
    27017:"MongoDB — sering tanpa auth",
    4444:"Backdoor/Metasploit",
    31337:"Backdoor umum",
    1337:"Backdoor umum",
}

from selene.core.common import is_port_open

def scan_ports(ip: str, ports: List[int] = None,
               timeout: float = 0.8, workers: int = 30) -> List[int]:
    ports     = ports or COMMON_PORTS
    open_ports = []
    lock      = threading.Lock()

    def check(port):
        if is_port_open(ip, port, timeout):
            with lock:
                open_ports.append(port)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(check, p) for p in ports]
        for f in as_completed(futures, timeout=timeout * 4 + 5):
            try: f.result()
            except Exception: pass

    return sorted(open_ports)

# ── Banner grabbing ───────────────────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    _PROBES = {
        80:   b"HEAD / HTTP/1.0\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        25:   b"EHLO selene\r\n",
        6379: b"PING\r\n",
        9200: b"GET / HTTP/1.0\r\n\r\n",
    }
    if port in (443, 8443):
        return _https_banner(ip, port, timeout)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        probe = _PROBES.get(port)
        if probe: s.send(probe)
        s.settimeout(timeout)
        try:    banner = s.recv(1024).decode(errors="ignore").strip()
        except socket.timeout: banner = ""
        s.close()
        return banner[:300]
    except (socket.error, OSError):
        return ""

def _https_banner(ip: str, port: int, timeout: float) -> str:
    import ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                try:    return s.recv(512).decode(errors="ignore").strip()[:300]
                except socket.timeout: return ""
    except Exception:
        return ""

# ── OS fingerprint ────────────────────────────────────────────────────────────
def fingerprint_os(ip: str, open_ports: List[int]) -> str:
    ttl = _get_ttl(ip)
    if ttl:
        if ttl <= 64:   guess = "Linux/Android"
        elif ttl <= 128: guess = "Windows"
        else:            guess = "Router/Cisco"
    else:
        guess = "Unknown"

    p = set(open_ports)
    if 3389 in p:        return "Windows (RDP aktif)"
    if {135,139,445} <= p: return "Windows"
    if 22 in p and 3389 not in p and "Windows" not in guess:
        return "Linux/Unix"
    return guess

def _get_ttl(ip: str) -> Optional[int]:
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["ping","-n","1",ip],
                                          stderr=subprocess.DEVNULL, timeout=3
                                          ).decode(errors="ignore")
        else:
            out = subprocess.check_output(["ping","-c","1","-W","2",ip],
                                          stderr=subprocess.DEVNULL, timeout=3
                                          ).decode(errors="ignore")
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None

# ── MAC vendor ────────────────────────────────────────────────────────────────
MAC_VENDORS = {
    "00:50:56":"VMware","00:0c:29":"VMware","08:00:27":"VirtualBox",
    "52:54:00":"QEMU/KVM","b8:27:eb":"Raspberry Pi","dc:a6:32":"Raspberry Pi",
    "e4:5f:01":"Raspberry Pi","a4:c3:f0":"Apple","3c:22:fb":"Apple",
    "00:17:f2":"Apple","1c:bd:b9":"Asus","10:bf:48":"TP-Link",
    "50:d4:f7":"TP-Link","c8:3a:35":"Tenda","00:00:0c":"Cisco",
    "fc:fb:fb":"Cisco","00:1b:21":"Intel","8c:8d:28":"Intel",
}

def get_vendor(mac: str) -> str:
    if not mac or mac in ("unknown","?"):
        return "Unknown"
    return MAC_VENDORS.get(mac[:8].lower(), "Unknown")

# ── Geolocation ───────────────────────────────────────────────────────────────
def get_geo(ip: str, timeout: float = 3.0) -> Dict:
    if is_private_ip(ip):
        return {"country":"Private","city":"LAN","org":"Local"}
    try:
        import requests
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=timeout,
                         headers={"User-Agent":"Selene/3.0"})
        if r.status_code == 200:
            d = r.json()
            return {
                "country": d.get("country","?"),
                "city":    d.get("city","?"),
                "org":     d.get("org","?"),
            }
    except Exception:
        pass
    return {"country":"?","city":"?","org":"?"}
