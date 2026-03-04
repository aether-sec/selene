#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Vulnerability Scanner v3.0                        ║
║   Temukan celah keamanan sebelum penyerang menemukannya.     ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/vuln_scanner.py
  python scripts/vuln_scanner.py --target 192.168.1.1
  python scripts/vuln_scanner.py --range 192.168.1.0/24
  python scripts/vuln_scanner.py --from-scan reports/scan_xxx.json

Catatan:
  Tidak membutuhkan root. Semua pengecekan dilakukan secara
  pasif dan aktif tapi aman — tidak mengeksploitasi apapun.
"""

import sys
import os
import json
import time
import socket
import ssl
import re
import subprocess
import shutil
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        get_local_ip, write_alert, save_json, load_json,
        Spinner, IS_LINUX, IS_WINDOWS, IS_ROOT, REPORTS_DIR,
    )
    from selene.core.network import (
        get_network_range, arp_scan, scan_ports, grab_banner,
        COMMON_PORTS, PORT_NAMES, DANGEROUS_PORTS,
        is_private_ip,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

TOOL_VERSION = "3.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# Database kerentanan lokal
# Berisi pola banner → CVE yang diketahui
# Format: (pola_regex, CVE, deskripsi, severity, solusi)
# ─────────────────────────────────────────────────────────────────────────────
BANNER_VULNS = [
    # OpenSSH versi lama
    (r"SSH-2\.0-OpenSSH_([0-4]\.|5\.[0-8]|6\.[0-6]|7\.[0-3])",
     "CVE-2016-6210", "OpenSSH username enumeration",
     "SEDANG", "Update OpenSSH ke versi 7.4 atau lebih baru"),

    (r"SSH-2\.0-OpenSSH_([4-6]\.|7\.[0-6])",
     "CVE-2018-15473", "OpenSSH username enumeration via timing",
     "SEDANG", "Update OpenSSH ke versi 7.7 atau lebih baru"),

    # Apache versi lama
    (r"Apache/([01]\.|2\.[0-3]\.|2\.4\.[0-4][0-9]\b)",
     "CVE-2021-41773", "Apache path traversal & RCE",
     "KRITIS", "Update Apache ke versi 2.4.51 atau lebih baru"),

    (r"Apache/2\.4\.([0-3][0-9]|4[0-8])\b",
     "CVE-2021-41773", "Apache path traversal (mod_cgi RCE)",
     "KRITIS", "Update Apache ke versi terbaru"),

    # Nginx versi lama
    (r"nginx/([0-9]\.[0-9]\.[0-9]|1\.[0-9]\.[0-9]|1\.1[0-5]\.)",
     "CVE-2019-20372", "Nginx HTTP Request Smuggling",
     "SEDANG", "Update Nginx ke versi 1.16.1 / 1.17.7 atau lebih baru"),

    # PHP versi lama
    (r"PHP/([45]\.|7\.[0-3]\.)",
     "CVE-2019-11043", "PHP-FPM Remote Code Execution",
     "KRITIS", "Update PHP ke versi 7.4 atau lebih baru"),

    # OpenSSL lama (lewat banner HTTP)
    (r"OpenSSL/([01]\.|1\.0\.[01]|1\.0\.2[a-s])\b",
     "CVE-2016-2107", "OpenSSL DROWN / padding oracle",
     "TINGGI", "Update OpenSSL ke versi 1.1.1 atau lebih baru"),

    # Telnet terbuka
    (r"telnet|Telnet|TELNET|\x00\xff\xfb",
     "INSECURE-TELNET", "Telnet tidak terenkripsi",
     "TINGGI", "Nonaktifkan Telnet, gunakan SSH"),

    # FTP anonymous
    (r"220.*FTP|ProFTPD|vsftpd|Pure-FTPd",
     "CHECK-FTP-ANON", "FTP server aktif — periksa anonymous login",
     "INFO", "Nonaktifkan FTP anonymous, gunakan SFTP"),

    # Redis tanpa auth
    (r"\+PONG|\+OK",
     "CVE-2022-0543", "Redis tanpa autentikasi — potensi RCE",
     "KRITIS", "Aktifkan password Redis: requirepass <password>"),

    # Elasticsearch tanpa auth
    (r'"cluster_name"|"cluster_uuid"',
     "CVE-2015-1427", "Elasticsearch tanpa autentikasi",
     "KRITIS", "Aktifkan X-Pack security atau firewall port 9200"),

    # MongoDB tanpa auth
    (r"MongoDB|\"errmsg\"",
     "CHECK-MONGO-AUTH", "MongoDB mungkin tanpa autentikasi",
     "TINGGI", "Aktifkan authentication di MongoDB"),

    # SMBv1 / EternalBlue
    (r"SMBv1|NT LM 0\.12",
     "CVE-2017-0144", "SMBv1 aktif — rentan EternalBlue (WannaCry)",
     "KRITIS", "Nonaktifkan SMBv1, update Windows"),
]

# Pemeriksaan berbasis port (tanpa banner)
PORT_CHECKS = [
    # (port, nama_check, deskripsi, severity, solusi)
    (23,    "Telnet Aktif",
     "Telnet mengirim semua data tanpa enkripsi termasuk password",
     "TINGGI", "Ganti dengan SSH (port 22)"),

    (445,   "SMB Terbuka ke Publik",
     "Port SMB tidak boleh terbuka ke internet — rentan ransomware",
     "KRITIS", "Blokir port 445 di firewall untuk akses publik"),

    (135,   "RPC Endpoint Mapper",
     "Port RPC sering dieksploitasi di Windows lama",
     "SEDANG", "Blokir di firewall jika tidak dibutuhkan"),

    (3389,  "RDP Terbuka",
     "RDP langsung ke internet — target utama brute force",
     "TINGGI", "Gunakan VPN atau batasi akses ke IP tertentu"),

    (5900,  "VNC Terbuka",
     "VNC sering tidak memiliki autentikasi atau password lemah",
     "TINGGI", "Aktifkan enkripsi VNC dan gunakan password kuat"),

    (6379,  "Redis Terbuka",
     "Redis biasanya tidak butuh akses publik",
     "KRITIS", "Bind Redis ke 127.0.0.1 saja, aktifkan password"),

    (9200,  "Elasticsearch Terbuka",
     "Banyak data bocor karena Elasticsearch tanpa auth",
     "KRITIS", "Aktifkan X-Pack security, jangan expose ke publik"),

    (27017, "MongoDB Terbuka",
     "MongoDB sering dikonfigurasi tanpa autentikasi",
     "KRITIS", "Aktifkan autentikasi MongoDB, bind ke 127.0.0.1"),

    (11211, "Memcached Terbuka",
     "Memcached tanpa autentikasi, sering dipakai untuk DDoS amplification",
     "TINGGI", "Bind ke 127.0.0.1, aktifkan SASL auth"),

    (2375,  "Docker API Terbuka",
     "Docker API tanpa TLS memungkinkan kontrol penuh server",
     "KRITIS", "Nonaktifkan Docker API publik atau aktifkan TLS"),

    (2376,  "Docker API (TLS) Terbuka",
     "Docker API TLS harus diamankan dengan certificate yang valid",
     "SEDANG", "Verifikasi konfigurasi TLS Docker"),

    (1433,  "MSSQL Terbuka",
     "Database SQL Server tidak boleh terbuka ke internet",
     "TINGGI", "Gunakan firewall, batasi akses ke IP tertentu"),

    (3306,  "MySQL/MariaDB Terbuka",
     "Database MySQL tidak boleh terbuka ke internet",
     "TINGGI", "Bind MySQL ke 127.0.0.1 atau gunakan VPN"),

    (5432,  "PostgreSQL Terbuka",
     "PostgreSQL tidak boleh terbuka ke internet",
     "TINGGI", "Konfigurasi pg_hba.conf dengan IP yang diizinkan"),
]

# Severity color map
SEV_COLORS = {
    "KRITIS": Fore.RED,
    "TINGGI": Fore.RED,
    "SEDANG": Fore.YELLOW,
    "RENDAH": Fore.CYAN,
    "INFO":   Fore.WHITE,
}

SEV_SCORE = {
    "KRITIS": 40,
    "TINGGI": 25,
    "SEDANG": 15,
    "RENDAH": 5,
    "INFO":   2,
}

# ─────────────────────────────────────────────────────────────────────────────
# Pengecekan individual
# ─────────────────────────────────────────────────────────────────────────────

def check_ssl_cert(ip: str, port: int) -> List[Dict]:
    """
    Cek sertifikat SSL/TLS.
    Deteksi: expired, self-signed, weak cipher, versi lama.
    """
    findings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                cert    = s.getpeercert()
                version = s.version()
                cipher  = s.cipher()

                # Cek versi TLS lama
                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append({
                        "type":     "weak_tls",
                        "cve":      "CVE-2014-3566",
                        "title":    f"Versi TLS lama: {version}",
                        "desc":     f"TLS {version} rentan terhadap POODLE dan serangan downgrade",
                        "severity": "TINGGI",
                        "solution": "Nonaktifkan TLS 1.0/1.1, gunakan TLS 1.2 atau 1.3",
                        "ip":       ip,
                        "port":     port,
                    })

                # Cek cipher lemah
                if cipher:
                    cipher_name = cipher[0] if cipher else ""
                    weak = ["RC4","DES","3DES","EXPORT","NULL","anon"]
                    for w in weak:
                        if w.lower() in cipher_name.lower():
                            findings.append({
                                "type":     "weak_cipher",
                                "cve":      "CVE-2015-2808",
                                "title":    f"Cipher lemah: {cipher_name}",
                                "desc":     "Cipher ini mudah didekripsi oleh penyerang",
                                "severity": "SEDANG",
                                "solution": "Konfigurasi server untuk menggunakan cipher kuat (AES-GCM, ChaCha20)",
                                "ip":       ip,
                                "port":     port,
                            })
                            break

                # Cek expiry sertifikat
                if cert:
                    not_after = cert.get("notAfter","")
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - datetime.utcnow()).days
                            if days_left < 0:
                                findings.append({
                                    "type":     "expired_cert",
                                    "cve":      "CONFIG-SSL",
                                    "title":    "Sertifikat SSL sudah kadaluarsa",
                                    "desc":     f"Kadaluarsa: {not_after}",
                                    "severity": "TINGGI",
                                    "solution": "Perbarui sertifikat SSL secepatnya",
                                    "ip":       ip,
                                    "port":     port,
                                })
                            elif days_left < 30:
                                findings.append({
                                    "type":     "expiring_cert",
                                    "cve":      "CONFIG-SSL",
                                    "title":    f"Sertifikat SSL akan kadaluarsa dalam {days_left} hari",
                                    "desc":     f"Kadaluarsa: {not_after}",
                                    "severity": "SEDANG",
                                    "solution": "Perbarui sertifikat SSL segera",
                                    "ip":       ip,
                                    "port":     port,
                                })
                        except ValueError:
                            pass

                    # Cek self-signed
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    if issuer.get("organizationName") == subject.get("organizationName"):
                        findings.append({
                            "type":     "self_signed",
                            "cve":      "CONFIG-SSL",
                            "title":    "Sertifikat SSL self-signed",
                            "desc":     "Sertifikat tidak diverifikasi oleh CA terpercaya",
                            "severity": "RENDAH",
                            "solution": "Gunakan sertifikat dari CA terpercaya (Let's Encrypt gratis)",
                            "ip":       ip,
                            "port":     port,
                        })

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # Port tidak terbuka / timeout — bukan error
    except ssl.SSLError:
        pass
    except Exception:
        pass

    return findings


def check_banner_vulns(ip: str, port: int, banner: str) -> List[Dict]:
    """Cocokkan banner dengan database kerentanan."""
    findings = []
    if not banner:
        return findings

    for pattern, cve, title, severity, solution in BANNER_VULNS:
        if re.search(pattern, banner, re.IGNORECASE):
            findings.append({
                "type":     "banner_vuln",
                "cve":      cve,
                "title":    title,
                "desc":     f"Banner: {banner[:80]}",
                "severity": severity,
                "solution": solution,
                "ip":       ip,
                "port":     port,
            })
    return findings


def check_port_vulns(ip: str, open_ports: List[int]) -> List[Dict]:
    """Cek kerentanan berdasarkan port yang terbuka."""
    findings = []
    port_set = set(open_ports)

    for port, title, desc, severity, solution in PORT_CHECKS:
        if port in port_set:
            findings.append({
                "type":     "port_vuln",
                "cve":      f"PORT-{port}",
                "title":    title,
                "desc":     desc,
                "severity": severity,
                "solution": solution,
                "ip":       ip,
                "port":     port,
            })

    return findings


def check_ftp_anonymous(ip: str) -> Optional[Dict]:
    """Cek apakah FTP mengizinkan anonymous login."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 21))
        banner = s.recv(256).decode(errors="ignore")

        # Kirim: USER anonymous
        s.send(b"USER anonymous\r\n")
        resp1 = s.recv(256).decode(errors="ignore")

        # Kirim: PASS test@test.com
        s.send(b"PASS selene@test.com\r\n")
        resp2 = s.recv(256).decode(errors="ignore")
        s.close()

        if "230" in resp2:  # 230 = Login successful
            return {
                "type":     "ftp_anonymous",
                "cve":      "CONFIG-FTP",
                "title":    "FTP Anonymous Login AKTIF",
                "desc":     "Siapapun bisa login ke FTP tanpa password",
                "severity": "TINGGI",
                "solution": "Nonaktifkan anonymous FTP di konfigurasi server",
                "ip":       ip,
                "port":     21,
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def check_smtp_open_relay(ip: str) -> Optional[Dict]:
    """Cek apakah SMTP adalah open relay."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, 25))
        banner = s.recv(256).decode(errors="ignore")

        s.send(b"EHLO selene.test\r\n")
        resp1 = s.recv(512).decode(errors="ignore")

        # Coba relay ke domain eksternal
        s.send(b"MAIL FROM:<test@test.com>\r\n")
        resp2 = s.recv(256).decode(errors="ignore")

        s.send(b"RCPT TO:<test@gmail.com>\r\n")
        resp3 = s.recv(256).decode(errors="ignore")
        s.close()

        # 250 = accepted, relay mungkin terbuka
        if resp3.startswith("250"):
            return {
                "type":     "smtp_relay",
                "cve":      "CONFIG-SMTP",
                "title":    "SMTP Open Relay kemungkinan aktif",
                "desc":     "Server menerima email untuk domain eksternal — bisa dipakai spam",
                "severity": "TINGGI",
                "solution": "Konfigurasi SMTP hanya relay untuk domain/IP yang diizinkan",
                "ip":       ip,
                "port":     25,
            }
    except Exception:
        pass
    return None


def check_ssh_weak_config(ip: str) -> List[Dict]:
    """
    Cek kelemahan konfigurasi SSH via banner dan koneksi.
    Tidak melakukan brute force — hanya cek banner dan negoisasi awal.
    """
    findings = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, 22))
        banner = s.recv(256).decode(errors="ignore").strip()
        s.close()

        if not banner:
            return findings

        # Cek versi SSH lama
        if "SSH-1." in banner:
            findings.append({
                "type":     "ssh_v1",
                "cve":      "CVE-2001-0816",
                "title":    "SSH versi 1 aktif",
                "desc":     f"SSHv1 sangat rentan, sudah tidak aman sejak 2001. Banner: {banner[:60]}",
                "severity": "KRITIS",
                "solution": "Nonaktifkan SSHv1 di sshd_config: Protocol 2",
                "ip":       ip,
                "port":     22,
            })

        # Cek versi OpenSSH sangat lama
        m = re.search(r"OpenSSH_(\d+)\.(\d+)", banner)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if major < 7 or (major == 7 and minor < 4):
                findings.append({
                    "type":     "old_openssh",
                    "cve":      "CVE-2018-15473",
                    "title":    f"OpenSSH versi lama: {m.group(0)}",
                    "desc":     "Versi OpenSSH ini mengandung beberapa kerentanan yang sudah dipatch",
                    "severity": "SEDANG",
                    "solution": "Update OpenSSH ke versi 8.x atau lebih baru",
                    "ip":       ip,
                    "port":     22,
                })

    except Exception:
        pass

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Scanner per-host
# ─────────────────────────────────────────────────────────────────────────────

def scan_host(ip: str, open_ports: List[int] = None) -> Dict:
    """
    Scan kerentanan satu host.
    Returns: dict dengan semua findings dan skor risiko.
    """
    all_findings = []

    # Scan port jika belum ada
    if open_ports is None:
        open_ports = scan_ports(ip, COMMON_PORTS, timeout=0.8)

    if not open_ports:
        return {
            "ip":          ip,
            "open_ports":  [],
            "findings":    [],
            "risk_score":  0,
            "scanned_at":  datetime.now().isoformat(),
        }

    # 1. Cek kerentanan berdasarkan port
    all_findings += check_port_vulns(ip, open_ports)

    # 2. Banner grab + cek versi
    ssl_ports = {443, 8443, 993, 995, 465}
    for port in open_ports:
        banner = grab_banner(ip, port, timeout=2.0)

        # Cek banner vs CVE database
        if banner:
            all_findings += check_banner_vulns(ip, port, banner)

        # Cek SSL cert
        if port in ssl_ports:
            all_findings += check_ssl_cert(ip, port)

    # 3. Cek spesifik per protokol
    if 21 in open_ports:
        ftp_finding = check_ftp_anonymous(ip)
        if ftp_finding:
            all_findings.append(ftp_finding)

    if 25 in open_ports:
        smtp_finding = check_smtp_open_relay(ip)
        if smtp_finding:
            all_findings.append(smtp_finding)

    if 22 in open_ports:
        all_findings += check_ssh_weak_config(ip)

    # Hapus duplikat berdasarkan (cve, port)
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f.get("cve",""), f.get("port",""))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Hitung skor risiko
    risk_score = 0
    for f in unique_findings:
        risk_score += SEV_SCORE.get(f.get("severity","INFO"), 2)
    risk_score = min(risk_score, 100)

    return {
        "ip":         ip,
        "open_ports": open_ports,
        "findings":   unique_findings,
        "risk_score": risk_score,
        "scanned_at": datetime.now().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

def print_host_result(result: Dict) -> None:
    """Cetak hasil scan satu host."""
    ip       = result["ip"]
    findings = result.get("findings", [])
    score    = result.get("risk_score", 0)

    from selene.core.common import risk_color, risk_label
    rc = risk_color(score)
    rl = risk_label(score)

    if not findings:
        print(c(f"\n  {ip}  ✓  Tidak ada kerentanan terdeteksi", Fore.GREEN))
        return

    print(c(f"\n  ┌─ {ip}  —  {len(findings)} temuan  —  skor {score}/100 ({rl})",
            rc, bold=True))

    # Grup per severity
    for sev in ("KRITIS", "TINGGI", "SEDANG", "RENDAH", "INFO"):
        sev_findings = [f for f in findings if f.get("severity") == sev]
        if not sev_findings:
            continue
        color = SEV_COLORS.get(sev, Fore.WHITE)
        for f in sev_findings:
            print(c(f"  │ [{sev:<7}] {f.get('title','?')}", color, bold=(sev == "KRITIS")))
            print(c(f"  │           {f.get('desc','')[:70]}", Fore.WHITE))
            print(c(f"  │  ✎ Solusi: {f.get('solution','?')}", Fore.CYAN))
            print(c(f"  │           CVE: {f.get('cve','?')}  Port: {f.get('port','?')}", Fore.WHITE))
            print(c(f"  │", Fore.BLUE))

    print(c(f"  └{'─'*52}", Fore.BLUE))


def print_final_summary(results: List[Dict], elapsed: float) -> None:
    """Cetak ringkasan akhir."""
    log_section("RINGKASAN VULNERABILITY SCAN")

    total     = len(results)
    has_vuln  = [r for r in results if r.get("findings")]
    kritis    = sum(1 for r in results
                    for f in r.get("findings",[])
                    if f.get("severity") == "KRITIS")
    tinggi    = sum(1 for r in results
                    for f in r.get("findings",[])
                    if f.get("severity") == "TINGGI")
    total_cve = sum(len(r.get("findings",[])) for r in results)

    print(c(f"\n  Host di-scan            : {total}", Fore.WHITE))
    print(c(f"  Host dengan kerentanan  : {len(has_vuln)}",
            Fore.RED if has_vuln else Fore.GREEN))
    print(c(f"  Total temuan            : {total_cve}",
            Fore.RED if total_cve else Fore.GREEN))
    print(c(f"  Temuan KRITIS           : {kritis}",
            Fore.RED if kritis else Fore.GREEN, bold=bool(kritis)))
    print(c(f"  Temuan TINGGI           : {tinggi}",
            Fore.RED if tinggi else Fore.GREEN))
    print(c(f"  Waktu scan              : {elapsed:.1f} detik", Fore.WHITE))

    if kritis > 0:
        print(c(f"\n  ⛔ ADA {kritis} KERENTANAN KRITIS — Perbaiki segera!", Fore.RED, bold=True))
    elif tinggi > 0:
        print(c(f"\n  ⚠  Ada {tinggi} kerentanan tinggi — Segera tindak lanjuti.", Fore.YELLOW))
    elif has_vuln:
        print(c(f"\n  ℹ  Beberapa kerentanan ditemukan — Perbaiki saat ada waktu.", Fore.CYAN))
    else:
        print(c(f"\n  ✓  Tidak ada kerentanan yang terdeteksi. Sistem terlihat aman.", Fore.GREEN, bold=True))

    # Top 3 masalah paling mendesak
    all_findings = [(r["ip"], f) for r in results for f in r.get("findings",[])]
    all_findings.sort(key=lambda x: SEV_SCORE.get(x[1].get("severity","INFO"), 0), reverse=True)
    if all_findings[:3]:
        print(c(f"\n  🔥 Prioritas utama yang harus diperbaiki:", Fore.YELLOW, bold=True))
        for ip, f in all_findings[:3]:
            color = SEV_COLORS.get(f.get("severity",""), Fore.WHITE)
            print(c(f"     [{f['severity']}] {ip}:{f.get('port','?')}  {f.get('title','?')}",
                    color))
            print(c(f"      → {f.get('solution','?')}", Fore.WHITE))


# ─────────────────────────────────────────────────────────────────────────────
# Scan runners
# ─────────────────────────────────────────────────────────────────────────────

def run_from_scan_report(report_path: str) -> List[Dict]:
    """
    Jalankan vuln scan menggunakan data port dari hasil network_scanner.
    Efisien karena tidak perlu scan port ulang.
    """
    data = load_json(Path(report_path), {})
    devices = data.get("devices", [])

    if not devices:
        log("WARN", f"Tidak ada data perangkat di {report_path}")
        return []

    log("INFO", f"Memuat {len(devices)} perangkat dari laporan scan")
    results = []

    for i, device in enumerate(devices, 1):
        ip         = device.get("ip","")
        open_ports = device.get("open_ports", [])
        if not ip:
            continue

        log("SCAN", c(f"[{i}/{len(devices)}] {ip} ({len(open_ports)} port terbuka)", Fore.WHITE))
        result = scan_host(ip, open_ports)
        results.append(result)
        print_host_result(result)

    return results


def run_network_scan(target_range: str = None, quick: bool = False) -> List[Dict]:
    """Scan vuln untuk seluruh jaringan (termasuk port scan)."""
    scan_range = target_range or get_network_range()
    log_section(f"TEMUKAN HOST: {scan_range}")

    with Spinner("Mencari perangkat aktif..."):
        hosts = arp_scan(scan_range, timeout=2.0)

    if not hosts:
        log("WARN", "Tidak ada host ditemukan.")
        return []

    log("OK", c(f"{len(hosts)} host ditemukan", Fore.GREEN, bold=True))
    ip_list = [h["ip"] for h in hosts]

    log_section("SCAN KERENTANAN")
    log("SCAN", f"Memindai {len(ip_list)} host...")

    results = []
    workers = min(3, len(ip_list))

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(scan_host, ip): ip for ip in ip_list}
        done = 0
        for future in as_completed(future_map, timeout=len(ip_list)*30 + 30):
            ip   = future_map[future]
            done += 1
            try:
                result = future.result(timeout=30)
                results.append(result)
                log("INFO", c(f"  [{done}/{len(ip_list)}] {ip} — "
                              f"{len(result.get('findings',[]))} temuan", Fore.WHITE))
                print_host_result(result)
            except Exception as e:
                log("WARN", f"  [{done}/{len(ip_list)}] {ip} — error: {e}")

    return results


def run_single_target(ip: str) -> List[Dict]:
    """Scan satu target spesifik."""
    log_section(f"SCAN TARGET: {ip}")
    log("SCAN", "Menemukan port terbuka...")

    with Spinner(f"Scanning port {ip}..."):
        open_ports = scan_ports(ip, COMMON_PORTS, timeout=0.8)

    if not open_ports:
        log("INFO", f"Tidak ada port terbuka di {ip}")
        return [{"ip": ip, "open_ports": [], "findings": [], "risk_score": 0}]

    log("OK", f"Port terbuka: {open_ports}")
    log("SCAN", "Memeriksa kerentanan...")

    result = scan_host(ip, open_ports)
    print_host_result(result)
    return [result]


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/vuln_scanner.py
  python scripts/vuln_scanner.py --target 192.168.1.1
  python scripts/vuln_scanner.py --range 192.168.1.0/24
  python scripts/vuln_scanner.py --from-scan reports/scan_20240101_120000.json"""
    )
    parser.add_argument("--target",    "-t", help="Scan satu IP")
    parser.add_argument("--range",     "-r", help="Scan range CIDR")
    parser.add_argument("--from-scan", "-f", metavar="FILE",
                        help="Gunakan hasil network_scanner.py (lebih cepat)")
    parser.add_argument("--no-save",   action="store_true",
                        help="Jangan simpan laporan")
    args = parser.parse_args()

    log_header(
        "Selene — Vulnerability Scanner v3.0",
        "Temukan celah keamanan sebelum penyerang menemukannya"
    )

    start   = time.time()
    results = []

    try:
        if args.from_scan:
            # Mode tercepat: pakai hasil scan yang ada
            if not Path(args.from_scan).exists():
                log("ERROR", f"File tidak ditemukan: {args.from_scan}")
                sys.exit(1)
            log("INFO", f"Mode: menggunakan laporan scan dari {args.from_scan}")
            results = run_from_scan_report(args.from_scan)

        elif args.target:
            log("INFO", f"Mode: satu target — {args.target}")
            results = run_single_target(args.target)

        else:
            cfg        = get_config()
            scan_range = args.range or cfg.get("network","scan_range",default="auto")
            if not scan_range or scan_range == "auto":
                scan_range = get_network_range()
            log("INFO", f"Mode: jaringan — {scan_range}")
            results = run_network_scan(scan_range)

    except KeyboardInterrupt:
        print()
        log("INFO", "Scan dihentikan.")
        if not results:
            sys.exit(0)

    elapsed = time.time() - start
    print_final_summary(results, elapsed)

    # Simpan laporan
    if results and not args.no_save:
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        rpath = REPORTS_DIR / f"vuln_{ts}.json"
        save_json(rpath, {
            "tool":        "vuln_scanner",
            "version":     TOOL_VERSION,
            "scan_time":   datetime.now().isoformat(),
            "host_count":  len(results),
            "results":     results,
        })
        log("OK", c(f"Laporan disimpan: reports/vuln_{ts}.json", Fore.GREEN))

        # Alert untuk temuan kritis
        for result in results:
            for finding in result.get("findings", []):
                if finding.get("severity") == "KRITIS":
                    write_alert(
                        "CRIT",
                        f"Kerentanan kritis: {finding['title']} di {result['ip']}:{finding.get('port','')}",
                        details=finding,
                        ip=result["ip"],
                    )

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        log("INFO", "Dihentikan.")
    except Exception as e:
        log("ERROR", f"Error tidak terduga: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()
