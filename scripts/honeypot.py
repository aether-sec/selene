#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Honeypot v3.0                                     ║
║   Jebak penyerang dengan layanan palsu yang terlihat nyata.  ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/honeypot.py
  python scripts/honeypot.py --ports 2222,8080,2121,9200
  python scripts/honeypot.py --analyze
  sudo python scripts/honeypot.py --real-ports   ← port standar (butuh root)
"""

import sys
import os
import re
import socket
import threading
import time
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        write_alert, append_jsonl, read_jsonl,
        IS_ROOT, IS_LINUX, LOGS_DIR,
        is_port_available,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

TOOL_VERSION = "3.0.0"

# ── Konfigurasi layanan palsu ─────────────────────────────────────────────────
SERVICES = {
    "ssh": {
        "default_port": 2222,
        "real_port":    22,
        "banner": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
        "prompt": b"login as: ",
        "description": "SSH Server",
    },
    "ftp": {
        "default_port": 2121,
        "real_port":    21,
        "banner": b"220 ProFTPD 1.3.5 Server (FTP Server) [192.168.1.1]\r\n",
        "prompt": b"Name: ",
        "description": "FTP Server",
    },
    "http": {
        "default_port": 8080,
        "real_port":    80,
        "banner": None,  # HTTP tidak kirim banner, tunggu request
        "description": "HTTP Web Server",
    },
    "mysql": {
        "default_port": 13306,
        "real_port":    3306,
        # MySQL greeting packet (fake)
        "banner": (
            b"\x4a\x00\x00\x00\x0a"                         # pkt len + seq + protocol
            b"5.7.38-log\x00"                                # server version
            b"\x08\x00\x00\x00"                              # connection ID
            b"HoneypotX\x00"                                 # auth plugin data
            b"\xff\xf7"                                      # capabilities
            b"\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00"    # more flags
            b"HoneypotXX12\x00"                              # auth plugin data 2
            b"mysql_native_password\x00"                     # plugin name
        ),
        "description": "MySQL Database",
    },
    "elasticsearch": {
        "default_port": 9200,
        "real_port":    9200,
        "banner": None,
        "description": "Elasticsearch",
    },
    "redis": {
        "default_port": 16379,
        "real_port":    6379,
        "banner": b"+OK\r\n",
        "description": "Redis Cache",
    },
}

# ── Pola serangan ─────────────────────────────────────────────────────────────
ATTACK_PATTERNS = [
    # SQL injection
    (rb"(?:union\s+select|drop\s+table|insert\s+into|'\s*or\s*'1'\s*=\s*'1|--\s*$|/\*.*\*/)",
     "SQL Injection"),
    # XSS
    (rb"<\s*script[^>]*>|javascript\s*:|onerror\s*=|onload\s*=",
     "XSS"),
    # Path traversal / LFI
    (rb"\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self",
     "Path Traversal / LFI"),
    # Command injection
    (rb";\s*(?:cat|ls|id|whoami|uname|wget|curl|bash|sh)\s",
     "Command Injection"),
    # Log4Shell
    (rb"\$\{jndi:",
     "Log4Shell (CVE-2021-44228)"),
    # Scanner signatures
    (rb"(?i)(?:masscan|zmap|nmap|nikto|sqlmap|hydra|medusa|burpsuite|metasploit|msfconsole|empire|cobalt.strike)",
     "Scanner/Tool terdeteksi"),
    # Kredensial umum yang dicoba
    (rb"(?i)(?:root|admin|administrator|test|guest|user|password|123456|qwerty)",
     "Kredensial umum dicoba"),
    # ShellShock
    (rb"\(\s*\)\s*\{",
     "ShellShock (CVE-2014-6271)"),
]

# HTTP responses palsu yang meyakinkan
HTTP_RESPONSES = {
    "login": (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.51 (Ubuntu)\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"X-Powered-By: PHP/7.4.3\r\n"
        b"\r\n"
        b"<html><head><title>Admin Login</title></head>"
        b"<body><form method='post'>"
        b"<input type='text' name='user' placeholder='Username'>"
        b"<input type='password' name='pass' placeholder='Password'>"
        b"<input type='submit' value='Login'></form></body></html>"
    ),
    "error": (
        b"HTTP/1.1 404 Not Found\r\n"
        b"Server: Apache/2.4.51 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n"
        b"\r\n"
        b"<html><body><h1>404 Not Found</h1></body></html>"
    ),
    "ok": (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.51 (Ubuntu)\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"status":"ok","version":"2.3.1"}'
    ),
    "elasticsearch": (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b'{"name":"node-1","cluster_name":"production","version":{"number":"7.17.0"},"tagline":"You Know, for Search"}'
    ),
}

# ── Logger capture ────────────────────────────────────────────────────────────
_log_lock = threading.Lock()

def log_capture(service: str, port: int, client_ip: str, client_port: int,
                data: bytes, attacks: List[str], extra: dict = None) -> None:
    """Catat interaksi dengan honeypot."""
    entry = {
        "timestamp":   datetime.now().isoformat(),
        "service":     service,
        "port":        port,
        "client_ip":   client_ip,
        "client_port": client_port,
        "data_hex":    data[:512].hex() if data else "",
        "data_text":   data[:512].decode(errors="replace") if data else "",
        "attacks":     attacks,
        "extra":       extra or {},
    }
    with _log_lock:
        append_jsonl(LOGS_DIR / "honeypot_captures.jsonl", entry)

    # Print real-time
    ts = datetime.now().strftime("%H:%M:%S")
    atk_str = c(f"  [{', '.join(attacks)}]", Fore.RED, bold=True) if attacks else ""
    print(c(f"\n  [{ts}] 🎣 {service}:{port}  ←  {client_ip}:{client_port}",
            Fore.YELLOW, bold=True) + atk_str)
    if data and len(data) > 1:
        preview = data[:120].decode(errors="replace").replace("\n"," ").replace("\r","")
        print(c(f"         Data: {preview[:80]}", Fore.WHITE))

    if attacks:
        for atk in attacks:
            print(c(f"         ⚠  Serangan terdeteksi: {atk}", Fore.RED))
        write_alert("WARN", f"Honeypot [{service}]: {', '.join(attacks)}",
                    details=entry, ip=client_ip)

def detect_attacks(data: bytes) -> List[str]:
    """Cek data untuk pola serangan."""
    found = []
    for pattern, name in ATTACK_PATTERNS:
        if re.search(pattern, data, re.IGNORECASE):
            found.append(name)
    return found

# ── Handler per-service ───────────────────────────────────────────────────────
def handle_ssh(conn: socket.socket, addr: tuple, port: int) -> None:
    svc = SERVICES["ssh"]
    cip, cport = addr
    recv_data  = b""
    try:
        conn.settimeout(30)
        conn.send(svc["banner"])

        # Baca response client (biasanya SSH client banner)
        try:
            recv_data = conn.recv(1024)
        except socket.timeout:
            pass

        # Kirim prompt login
        conn.send(svc["prompt"])
        try:
            username = conn.recv(256)
        except socket.timeout:
            username = b""

        conn.send(b"Password: ")
        try:
            password = conn.recv(256)
        except socket.timeout:
            password = b""

        all_data = recv_data + b" " + username + b" " + password
        attacks  = detect_attacks(all_data)

        # Selalu tolak
        conn.send(b"Permission denied (publickey,password).\r\n")
        log_capture("SSH", port, cip, cport, all_data, attacks,
                    extra={"username": username.decode(errors="replace").strip(),
                           "has_password": len(password) > 1})

    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def handle_ftp(conn: socket.socket, addr: tuple, port: int) -> None:
    svc = SERVICES["ftp"]
    cip, cport = addr
    all_data = b""
    try:
        conn.settimeout(30)
        conn.send(svc["banner"])

        for _ in range(5):  # Maks 5 pertukaran
            try:
                data = conn.recv(512)
                if not data:
                    break
                all_data += data
                cmd = data.strip().upper()

                if cmd.startswith(b"USER"):
                    conn.send(b"331 Password required for user.\r\n")
                elif cmd.startswith(b"PASS"):
                    conn.send(b"530 Login incorrect.\r\n")
                    break
                elif cmd.startswith(b"QUIT"):
                    conn.send(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.send(b"530 Please login with USER and PASS.\r\n")
            except socket.timeout:
                break

        attacks = detect_attacks(all_data)
        log_capture("FTP", port, cip, cport, all_data, attacks)

    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def handle_http(conn: socket.socket, addr: tuple,
                port: int, service_name: str = "HTTP") -> None:
    cip, cport = addr
    try:
        conn.settimeout(10)
        data = b""
        try:
            data = conn.recv(4096)
        except socket.timeout:
            pass

        if not data:
            return

        attacks = detect_attacks(data)

        # Routing berdasarkan path
        path = b""
        m = re.search(rb"(?:GET|POST|HEAD|PUT|DELETE)\s+([^\s]+)", data)
        if m:
            path = m.group(1)

        # Response berdasarkan service dan path
        if service_name == "Elasticsearch":
            response = HTTP_RESPONSES["elasticsearch"]
        elif b"login" in path.lower() or b"admin" in path.lower():
            response = HTTP_RESPONSES["login"]
        elif b"api" in path.lower() or b"json" in path.lower():
            response = HTTP_RESPONSES["ok"]
        else:
            response = HTTP_RESPONSES["error"]

        conn.send(response)

        extra = {"method": "", "path": path.decode(errors="replace")[:100]}
        if m:
            method_m = re.search(rb"(GET|POST|HEAD|PUT|DELETE)", data)
            if method_m:
                extra["method"] = method_m.group(1).decode()

        log_capture(service_name, port, cip, cport, data, attacks, extra=extra)

    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def handle_mysql(conn: socket.socket, addr: tuple, port: int) -> None:
    cip, cport = addr
    try:
        conn.settimeout(15)
        # Kirim MySQL server greeting
        conn.send(SERVICES["mysql"]["banner"])

        data = b""
        try:
            data = conn.recv(1024)
        except socket.timeout:
            pass

        # Tolak koneksi
        error_pkt = (
            b"\x24\x00\x00\x02"      # pkt len + seq
            b"\xff"                   # error marker
            b"\x15\x04"              # error code 1045
            b"#28000"                # SQL state
            b"Access denied for user 'root'@'"
            + cip.encode() +
            b"'"
        )
        conn.send(error_pkt)

        attacks = detect_attacks(data)
        log_capture("MySQL", port, cip, cport, data, attacks)

    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def handle_redis(conn: socket.socket, addr: tuple, port: int) -> None:
    cip, cport = addr
    all_data = b""
    try:
        conn.settimeout(15)
        # Redis tidak kirim banner dulu, tunggu command
        for _ in range(4):
            try:
                data = conn.recv(512)
                if not data:
                    break
                all_data += data
                cmd = data.strip().upper()

                if cmd.startswith(b"PING") or b"PING" in cmd:
                    conn.send(b"+PONG\r\n")
                elif cmd.startswith(b"INFO"):
                    conn.send(b"$-1\r\n")  # nil reply
                elif cmd.startswith(b"CONFIG"):
                    conn.send(b"-ERR unknown command 'config'\r\n")
                elif b"FLUSHALL" in cmd or b"FLUSHDB" in cmd or b"CONFIG" in cmd:
                    conn.send(b"-NOAUTH Authentication required.\r\n")
                else:
                    conn.send(b"-ERR operation not permitted\r\n")
            except socket.timeout:
                break

        attacks = detect_attacks(all_data)
        log_capture("Redis", port, cip, cport, all_data, attacks)

    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def handle_generic(conn: socket.socket, addr: tuple,
                   port: int, banner: bytes = b"") -> None:
    """Handler generik untuk port apapun."""
    cip, cport = addr
    try:
        conn.settimeout(10)
        if banner:
            conn.send(banner)
        data = b""
        try:
            data = conn.recv(1024)
        except socket.timeout:
            pass
        attacks = detect_attacks(data)
        log_capture(f"Generic:{port}", port, cip, cport, data, attacks)
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

# ── Listener per-port ─────────────────────────────────────────────────────────
def start_listener(service_name: str, port: int, use_real_ports: bool) -> Optional[threading.Thread]:
    """
    Buat listener socket untuk satu port.
    Returns thread jika berhasil, None jika port tidak tersedia.
    """
    # Cek ketersediaan port
    if not is_port_available(port):
        log("WARN", f"Port {port} sudah digunakan — {service_name} dilewati")
        return None

    # Pilih handler
    svc_lower = service_name.lower()
    if "ssh" in svc_lower:
        handler = lambda conn, addr: handle_ssh(conn, addr, port)
    elif "ftp" in svc_lower:
        handler = lambda conn, addr: handle_ftp(conn, addr, port)
    elif "http" in svc_lower or "web" in svc_lower:
        handler = lambda conn, addr: handle_http(conn, addr, port)
    elif "elasticsearch" in svc_lower or "elastic" in svc_lower:
        handler = lambda conn, addr: handle_http(conn, addr, port, "Elasticsearch")
    elif "mysql" in svc_lower:
        handler = lambda conn, addr: handle_mysql(conn, addr, port)
    elif "redis" in svc_lower:
        handler = lambda conn, addr: handle_redis(conn, addr, port)
    else:
        svc_cfg = next((s for s in SERVICES.values()
                        if s.get("default_port") == port or s.get("real_port") == port), {})
        banner = svc_cfg.get("banner", b"")
        handler = lambda conn, addr, b=banner: handle_generic(conn, addr, port, b)

    def listen_loop():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(10)
            srv.settimeout(1.0)  # timeout agar bisa dicek stop_event
        except OSError as e:
            log("ERROR", f"Gagal bind port {port}: {e}")
            return

        log("OK", c(f"  {service_name:<22} mendengarkan di port {port}", Fore.GREEN))

        while not _stop_event.is_set():
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

        try: srv.close()
        except Exception: pass

    t = threading.Thread(target=listen_loop, daemon=True)
    t.start()
    return t

_stop_event = threading.Event()

# ── Analyzer ──────────────────────────────────────────────────────────────────
def analyze_captures() -> None:
    """Analisis hasil tangkapan honeypot."""
    log_header("Selene — Honeypot Analyzer")

    captures = read_jsonl(LOGS_DIR / "honeypot_captures.jsonl")
    if not captures:
        log("INFO", "Belum ada capture. Jalankan honeypot terlebih dahulu.")
        return

    log_section(f"STATISTIK ({len(captures)} capture)")

    # Top attacker IPs
    ip_count: Dict[str, int] = {}
    attack_count: Dict[str, int] = {}
    service_count: Dict[str, int] = {}
    all_attacks: List[str] = []

    for cap in captures:
        ip  = cap.get("client_ip","?")
        svc = cap.get("service","?")
        atk = cap.get("attacks",[])

        ip_count[ip]   = ip_count.get(ip,0) + 1
        service_count[svc] = service_count.get(svc,0) + 1
        for a in atk:
            attack_count[a] = attack_count.get(a,0) + 1
            all_attacks.append(a)

    print(c(f"\n  Total koneksi : {len(captures)}", Fore.WHITE))
    print(c(f"  Unique IP     : {len(ip_count)}", Fore.WHITE))
    print(c(f"  Serangan      : {len(all_attacks)}", Fore.RED if all_attacks else Fore.GREEN))

    # Top 10 IP penyerang
    log_section("TOP 10 PENYERANG")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(c(f"  {ip:<20}  {count:>4} koneksi", Fore.YELLOW))

    # Jenis serangan
    if attack_count:
        log_section("JENIS SERANGAN")
        for atk, count in sorted(attack_count.items(), key=lambda x: x[1], reverse=True):
            print(c(f"  {count:>4}x  {atk}", Fore.RED))

    # Per-service
    log_section("KONEKSI PER LAYANAN")
    for svc, count in sorted(service_count.items(), key=lambda x: x[1], reverse=True):
        print(c(f"  {svc:<25}  {count:>4} koneksi", Fore.WHITE))

    # 5 capture terbaru
    log_section("5 TANGKAPAN TERBARU")
    for cap in reversed(captures[-5:]):
        ts   = cap.get("timestamp","?")[:16]
        svc  = cap.get("service","?")
        ip   = cap.get("client_ip","?")
        atk  = cap.get("attacks",[])
        col  = Fore.RED if atk else Fore.CYAN
        print(c(f"\n  [{ts}] {svc}  ←  {ip}", col))
        if atk:
            print(c(f"    Serangan: {', '.join(atk)}", Fore.RED))
        preview = cap.get("data_text","")[:60].replace("\n"," ")
        if preview:
            print(c(f"    Data: {preview}", Fore.WHITE))

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Selene Honeypot — Jebak penyerang dengan layanan palsu",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/honeypot.py
  python scripts/honeypot.py --ports 2222,8080,2121
  python scripts/honeypot.py --analyze
  sudo python scripts/honeypot.py --real-ports"""
    )
    parser.add_argument("--ports",      "-p", metavar="PORT,PORT,...",
                        help="Port yang digunakan (default dari konfigurasi)")
    parser.add_argument("--real-ports", action="store_true",
                        help="Gunakan port standar (22,80,21,3306) — butuh root")
    parser.add_argument("--analyze",    "-a", action="store_true",
                        help="Analisis tangkapan, lalu keluar")
    args = parser.parse_args()

    if args.analyze:
        analyze_captures(); return

    log_header("Selene — Honeypot v3.0",
               "Jebak penyerang dengan layanan palsu yang terlihat nyata")

    cfg = get_config()

    # Tentukan port
    if args.ports:
        try:
            port_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            log("ERROR", "Format port tidak valid. Contoh: --ports 2222,8080,2121")
            sys.exit(1)
        # Mapping port ke service name
        port_service_map = {}
        for svc_name, svc_cfg in SERVICES.items():
            port_service_map[svc_cfg["default_port"]] = svc_name.upper()
            port_service_map[svc_cfg["real_port"]]    = svc_name.upper()
        service_map = {p: port_service_map.get(p, f"Generic:{p}") for p in port_list}

    elif args.real_ports:
        if not IS_ROOT:
            log("ERROR", "Port standar (< 1024) membutuhkan root.")
            log("INFO",  "Jalankan: sudo python scripts/honeypot.py --real-ports")
            sys.exit(1)
        service_map = {
            svc_cfg["real_port"]: svc_name.upper()
            for svc_name, svc_cfg in SERVICES.items()
        }
    else:
        # Default: port alternatif dari konfigurasi
        default_ports = cfg.get("honeypot","ports", default=[2222,8080,2121,13306,9200,16379])
        default_service_names = {
            2222:"SSH", 2121:"FTP", 8080:"HTTP",
            13306:"MySQL", 9200:"Elasticsearch", 16379:"Redis",
        }
        service_map = {
            p: default_service_names.get(p, f"Generic:{p}")
            for p in default_ports
        }

    log_section("MEMULAI LAYANAN HONEYPOT")
    log("INFO", f"Capture disimpan di: {LOGS_DIR}/honeypot_captures.jsonl")
    print()

    # Start listeners
    threads = []
    active_ports = []
    for port, svc_name in service_map.items():
        t = start_listener(svc_name, port, args.real_ports)
        if t:
            threads.append(t)
            active_ports.append(port)

    if not threads:
        log("ERROR", "Tidak ada port yang berhasil di-bind!")
        log("INFO",  "Semua port mungkin sudah digunakan proses lain.")
        sys.exit(1)

    print()
    log("OK", c(f"{len(threads)} layanan honeypot aktif di port: "
                f"{', '.join(map(str,active_ports))}", Fore.GREEN, bold=True))
    log("INFO", c("Tekan Ctrl+C untuk berhenti dan lihat ringkasan", Fore.WHITE))
    print()

    # Tunggu Ctrl+C
    total_captures = 0
    try:
        while True:
            time.sleep(5)
            # Hitung capture baru
            captures = read_jsonl(LOGS_DIR / "honeypot_captures.jsonl")
            new_total = len(captures)
            if new_total > total_captures:
                diff = new_total - total_captures
                total_captures = new_total
    except KeyboardInterrupt:
        pass

    _stop_event.set()
    print()
    log_section("RINGKASAN SESI")

    # Tampilkan ringkasan
    captures = read_jsonl(LOGS_DIR / "honeypot_captures.jsonl")
    if captures:
        attacks = [c for cap in captures for c in cap.get("attacks",[])]
        ips     = {cap.get("client_ip") for cap in captures}
        print(c(f"\n  Total koneksi : {len(captures)}", Fore.WHITE))
        print(c(f"  Unique IP     : {len(ips)}", Fore.WHITE))
        print(c(f"  Serangan      : {len(attacks)}", Fore.RED if attacks else Fore.GREEN))
        print(c("\n  Gunakan --analyze untuk laporan lengkap.", Fore.CYAN))
    else:
        print(c("\n  Tidak ada koneksi yang masuk.", Fore.WHITE))

    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _stop_event.set()
        print(); log("INFO", "Honeypot dihentikan.")
    except Exception as e:
        log("ERROR", f"Error: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()
