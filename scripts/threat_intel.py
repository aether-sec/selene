#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Threat Intel v3.0                                 ║
║   Investigasi IP, domain, dan hash lewat OSINT publik.       ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/threat_intel.py --ip 1.2.3.4
  python scripts/threat_intel.py --domain evil.com
  python scripts/threat_intel.py --hash d41d8cd98f00b204e9800998ecf8427e
  python scripts/threat_intel.py --batch ips.txt
  python scripts/threat_intel.py --from-alerts     ← investigasi IP dari alerts Selene

Sumber OSINT (semua gratis, tanpa registrasi):
  • ipwho.is           — geolokasi + ASN (unlimited, tanpa API key)
  • ip-api.com         — proxy/VPN/hosting detection (1k/menit, tanpa key)
  • OTX AlienVault     — threat feeds global (gratis, tanpa key)
  • AbuseIPDB          — reputasi IP (opsional, gratis 1k/hari setelah daftar)
  • VirusTotal         — reputasi domain/hash (opsional, gratis 4req/menit)
"""

import sys
import os
import re
import json
import time
import socket
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        read_jsonl, save_json, Spinner, LOGS_DIR, REPORTS_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

TOOL_VERSION  = "3.0.0"
REQUEST_TO    = 8   # timeout detik per request

# Cache sederhana (in-memory) untuk hindari query berulang
_cache: Dict[str, Dict] = {}

# ── Validator ─────────────────────────────────────────────────────────────────

def is_valid_ip(value: str) -> bool:
    try:
        parts = value.strip().split(".")
        return (len(parts) == 4 and
                all(0 <= int(p) <= 255 for p in parts))
    except Exception:
        return False

def is_valid_domain(value: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value.strip()))

def is_valid_hash(value: str) -> Optional[str]:
    """Returns hash type (md5/sha1/sha256) atau None."""
    v = value.strip().lower()
    if re.match(r"^[0-9a-f]{32}$", v):  return "md5"
    if re.match(r"^[0-9a-f]{40}$", v):  return "sha1"
    if re.match(r"^[0-9a-f]{64}$", v):  return "sha256"
    return None

def is_private_ip_str(ip: str) -> bool:
    """Cek apakah IP adalah private/loopback."""
    try:
        parts = [int(p) for p in ip.split(".")]
        return (
            parts[0] == 10 or
            parts[0] == 127 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168)
        )
    except Exception:
        return False

# ── API callers ───────────────────────────────────────────────────────────────

def _get(url: str, headers: dict = None, params: dict = None,
         cache_key: str = None) -> Optional[Dict]:
    """HTTP GET dengan cache dan error handling."""
    if cache_key and cache_key in _cache:
        return _cache[cache_key]

    if not HAS_REQUESTS:
        return None

    try:
        r = requests.get(
            url,
            headers=headers or {"User-Agent": "Selene-Security-Suite/3.0"},
            params=params,
            timeout=REQUEST_TO,
        )
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                data = {"raw": r.text[:500]}
            if cache_key:
                _cache[cache_key] = data
            return data
        elif r.status_code == 429:
            log("WARN", "Rate limit — tunggu sebentar lalu coba lagi")
            return None
        return None
    except requests.Timeout:
        return None
    except Exception:
        return None

def query_ipinfo(ip: str) -> Dict:
    """
    Query ipwho.is — geolokasi, ASN, org.
    100% gratis, unlimited, tanpa API key, tanpa registrasi.
    """
    data = _get(f"https://ipwho.is/{ip}",
                cache_key=f"ipwho_{ip}") or {}
    if not data.get("success", True) is False and data:
        return {
            "country":  data.get("country", "?"),
            "region":   data.get("region", "?"),
            "city":     data.get("city", "?"),
            "org":      data.get("connection", {}).get("org", "?"),
            "asn":      str(data.get("connection", {}).get("asn", "?")),
            "hostname": data.get("hostname", "?"),
            "timezone": data.get("timezone", {}).get("id", "?"),
            "loc":      f"{data.get('latitude','?')},{data.get('longitude','?')}",
            "source":   "ipwho.is",
        }
    return {"country":"?","region":"?","city":"?","org":"?","asn":"?",
            "hostname":"?","timezone":"?","loc":"?","source":"ipwho.is"}

def query_ip_api(ip: str) -> Dict:
    """
    Query ip-api.com — proxy/VPN/hosting detection.
    Gratis 45 request/menit tanpa API key.
    """
    data = _get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,"
                f"isp,org,as,proxy,hosting,query",
                cache_key=f"ipapi_{ip}") or {}

    if data.get("status") != "success":
        return {}

    return {
        "country":   data.get("country","?"),
        "region":    data.get("regionName","?"),
        "city":      data.get("city","?"),
        "isp":       data.get("isp","?"),
        "org":       data.get("org","?"),
        "is_proxy":  data.get("proxy", False),
        "is_hosting":data.get("hosting", False),
        "source":    "ip-api.com",
    }

def query_abuseipdb(ip: str, api_key: str = "") -> Dict:
    """
    Query AbuseIPDB — berapa kali IP dilaporkan berbahaya.
    Butuh API key gratis: https://www.abuseipdb.com/register
    """
    if not api_key:
        return {"error": "no_api_key"}

    data = _get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={
            "Key":    api_key,
            "Accept": "application/json",
            "User-Agent": "Selene-Security-Suite/3.0",
        },
        params={"ipAddress": ip, "maxAgeInDays": 90},
        cache_key=f"abuseipdb_{ip}",
    )

    if not data or "data" not in data:
        return {}

    d = data["data"]
    return {
        "abuse_score":      d.get("abuseConfidenceScore", 0),
        "total_reports":    d.get("totalReports", 0),
        "last_reported":    d.get("lastReportedAt","?"),
        "is_whitelisted":   d.get("isWhitelisted", False),
        "isp":              d.get("isp","?"),
        "usage_type":       d.get("usageType","?"),
        "country":          d.get("countryCode","?"),
        "source":           "AbuseIPDB",
    }

def query_virustotal_ip(ip: str, api_key: str = "") -> Dict:
    """Query VirusTotal untuk reputasi IP."""
    if not api_key:
        return {"error": "no_api_key"}

    data = _get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key, "User-Agent": "Selene/3.0"},
        cache_key=f"vt_ip_{ip}",
    )
    if not data:
        return {}

    stats = (data.get("data",{}).get("attributes",{})
             .get("last_analysis_stats",{}))
    return {
        "malicious":   stats.get("malicious", 0),
        "suspicious":  stats.get("suspicious", 0),
        "harmless":    stats.get("harmless", 0),
        "undetected":  stats.get("undetected", 0),
        "source":      "VirusTotal",
    }

def query_virustotal_domain(domain: str, api_key: str = "") -> Dict:
    """Query VirusTotal untuk reputasi domain."""
    if not api_key:
        return {"error": "no_api_key"}

    data = _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": api_key, "User-Agent": "Selene/3.0"},
        cache_key=f"vt_domain_{domain}",
    )
    if not data:
        return {}

    attrs = data.get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    return {
        "malicious":    stats.get("malicious", 0),
        "suspicious":   stats.get("suspicious", 0),
        "harmless":     stats.get("harmless", 0),
        "categories":   attrs.get("categories",{}),
        "creation_date":attrs.get("creation_date","?"),
        "reputation":   attrs.get("reputation", 0),
        "source":       "VirusTotal",
    }

def query_virustotal_hash(hash_val: str, api_key: str = "") -> Dict:
    """Query VirusTotal untuk analisis file hash."""
    if not api_key:
        return {"error": "no_api_key"}

    data = _get(
        f"https://www.virustotal.com/api/v3/files/{hash_val}",
        headers={"x-apikey": api_key, "User-Agent": "Selene/3.0"},
        cache_key=f"vt_hash_{hash_val}",
    )
    if not data:
        return {}

    attrs = data.get("data",{}).get("attributes",{})
    stats = attrs.get("last_analysis_stats",{})
    return {
        "name":         attrs.get("meaningful_name","?"),
        "size":         attrs.get("size", 0),
        "type":         attrs.get("type_description","?"),
        "malicious":    stats.get("malicious", 0),
        "suspicious":   stats.get("suspicious", 0),
        "harmless":     stats.get("harmless", 0),
        "undetected":   stats.get("undetected", 0),
        "first_seen":   attrs.get("first_submission_date","?"),
        "tags":         attrs.get("tags",[]),
        "source":       "VirusTotal",
    }

# ── OTX AlienVault — gratis, tanpa API key ───────────────────────────────────
def query_otx_ip(ip: str) -> Dict:
    """
    Query OTX AlienVault untuk reputasi IP.
    100% gratis, tanpa API key, tanpa registrasi.
    """
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        cache_key=f"otx_ip_{ip}",
    )
    if not data:
        return {}
    pulses = data.get("pulse_info", {})
    return {
        "pulse_count": pulses.get("count", 0),
        "is_malicious": pulses.get("count", 0) > 0,
        "tags":         pulses.get("tags", [])[:5],
        "source":       "OTX AlienVault",
    }

def query_otx_domain(domain: str) -> Dict:
    """Query OTX AlienVault untuk reputasi domain — gratis tanpa key."""
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        cache_key=f"otx_domain_{domain}",
    )
    if not data:
        return {}
    pulses = data.get("pulse_info", {})
    return {
        "pulse_count": pulses.get("count", 0),
        "is_malicious": pulses.get("count", 0) > 0,
        "tags":         pulses.get("tags", [])[:5],
        "source":       "OTX AlienVault",
    }

def query_otx_hash(hash_val: str) -> Dict:
    """Query OTX AlienVault untuk analisis hash — gratis tanpa key."""
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/file/{hash_val}/general",
        cache_key=f"otx_hash_{hash_val}",
    )
    if not data:
        return {}
    pulses = data.get("pulse_info", {})
    return {
        "pulse_count":  pulses.get("count", 0),
        "is_malicious": pulses.get("count", 0) > 0,
        "tags":         pulses.get("tags", [])[:5],
        "source":       "OTX AlienVault",
    }

def dns_lookup(domain: str) -> Dict:
    """Resolusi DNS dasar — gratis, tanpa API."""
    result = {"ips": [], "error": None}
    try:
        infos = socket.getaddrinfo(domain, None)
        ips   = list({info[4][0] for info in infos})
        result["ips"] = ips[:5]
    except socket.gaierror as e:
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)
    return result

def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "?"

# ── Risk scoring ──────────────────────────────────────────────────────────────

def calculate_ip_risk(results: Dict) -> Tuple[int, List[str]]:
    """
    Hitung skor risiko IP berdasarkan semua hasil query.
    Returns: (score 0-100, [alasan])
    """
    score   = 0
    reasons = []

    # AbuseIPDB
    abuse = results.get("abuseipdb",{})
    if not abuse.get("error"):
        abuse_score = abuse.get("abuse_score", 0)
        reports     = abuse.get("total_reports", 0)
        if abuse_score >= 80:
            score   += 40
            reasons.append(f"AbuseIPDB: skor {abuse_score}% — sangat berbahaya")
        elif abuse_score >= 50:
            score   += 25
            reasons.append(f"AbuseIPDB: skor {abuse_score}% — mencurigakan")
        elif abuse_score >= 20:
            score   += 10
            reasons.append(f"AbuseIPDB: skor {abuse_score}% ({reports} laporan)")

    # VirusTotal
    vt = results.get("virustotal",{})
    if not vt.get("error"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        if mal >= 5:
            score   += 35
            reasons.append(f"VirusTotal: {mal} engine mendeteksi berbahaya")
        elif mal >= 1:
            score   += 20
            reasons.append(f"VirusTotal: {mal} engine mendeteksi berbahaya")
        if sus >= 3:
            score   += 10
            reasons.append(f"VirusTotal: {sus} engine mendeteksi mencurigakan")

    # ip-api: proxy/hosting
    ipapi = results.get("ip_api",{})
    if ipapi.get("is_proxy"):
        score   += 15
        reasons.append("IP Proxy/VPN terdeteksi")
    if ipapi.get("is_hosting"):
        score   += 5
        reasons.append("IP hosting/datacenter")

    # Private IP
    ip = results.get("ip","")
    if is_private_ip_str(ip):
        score = 0
        reasons = ["IP private/loopback — tidak relevan"]

    score = min(score, 100)
    return score, reasons

def calculate_hash_risk(vt: Dict) -> Tuple[int, str]:
    """Hitung skor risiko file dari hasil VT."""
    if vt.get("error"):
        return 0, "Tidak ada data (butuh VT API key)"

    mal = vt.get("malicious", 0)
    sus = vt.get("suspicious", 0)

    if mal >= 10:   return 100, "MALWARE DIKONFIRMASI"
    if mal >= 5:    return 80,  "Sangat mencurigakan"
    if mal >= 1:    return 60,  "Kemungkinan malware"
    if sus >= 3:    return 40,  "Mencurigakan"
    if sus >= 1:    return 20,  "Sedikit mencurigakan"
    return 0, "Bersih"

# ── Display ───────────────────────────────────────────────────────────────────

def print_ip_report(ip: str, results: Dict, score: int, reasons: List[str]) -> None:
    """Cetak laporan lengkap satu IP."""
    if score >= 70:     col = Fore.RED
    elif score >= 40:   col = Fore.YELLOW
    else:               col = Fore.GREEN

    print(c(f"\n  ╔══ {ip} ════════════════════════════════════", col, bold=True))
    print(c(f"  ║  Skor risiko: {score}/100", col, bold=True))

    # Geolokasi
    geo = results.get("ipinfo") or results.get("ip_api",{})
    if geo and not geo.get("error"):
        country = geo.get("country","?")
        city    = geo.get("city","?")
        org     = geo.get("org") or geo.get("isp","?")
        print(c(f"  ║  Lokasi   : {city}, {country}", Fore.WHITE))
        print(c(f"  ║  ISP/Org  : {org[:60]}", Fore.WHITE))

    ipinfo = results.get("ipinfo",{})
    if ipinfo.get("hostname") and ipinfo["hostname"] != "?":
        print(c(f"  ║  Hostname : {ipinfo['hostname']}", Fore.WHITE))

    ipapi = results.get("ip_api",{})
    if ipapi.get("is_proxy"):
        print(c(f"  ║  ⚠  Proxy/VPN terdeteksi", Fore.YELLOW))
    if ipapi.get("is_hosting"):
        print(c(f"  ║  ℹ  IP Hosting/Datacenter", Fore.CYAN))

    # AbuseIPDB
    abuse = results.get("abuseipdb",{})
    if not abuse.get("error") and abuse:
        ascore  = abuse.get("abuse_score", 0)
        reports = abuse.get("total_reports", 0)
        last    = (abuse.get("last_reported","?") or "?")[:10]
        acol    = Fore.RED if ascore >= 50 else (Fore.YELLOW if ascore >= 20 else Fore.GREEN)
        print(c(f"  ║  AbuseIPDB: {ascore}% ({reports} laporan, terakhir: {last})", acol))

    # VirusTotal
    vt = results.get("virustotal",{})
    if not vt.get("error") and vt:
        mal = vt.get("malicious",0)
        sus = vt.get("suspicious",0)
        har = vt.get("harmless",0)
        vtcol = Fore.RED if mal >= 1 else Fore.GREEN
        print(c(f"  ║  VirusTotal: {mal} berbahaya, {sus} mencurigakan, {har} aman", vtcol))

    # Alasan
    if reasons:
        for r in reasons:
            rcol = Fore.RED if "berbahaya" in r.lower() or "sangat" in r.lower() else Fore.YELLOW
            print(c(f"  ║  ⚠  {r}", rcol))

    # Reverse DNS
    rdns = results.get("reverse_dns","?")
    if rdns and rdns != "?":
        print(c(f"  ║  rDNS     : {rdns}", Fore.WHITE))

    print(c(f"  ╚{'═'*48}", col))

def print_domain_report(domain: str, dns: Dict, vt: Dict) -> None:
    """Cetak laporan domain."""
    print(c(f"\n  ╔══ {domain} ════════════════════════════════", Fore.CYAN, bold=True))

    # DNS
    ips = dns.get("ips",[])
    if ips:
        print(c(f"  ║  DNS → {', '.join(ips)}", Fore.WHITE))
    elif dns.get("error"):
        print(c(f"  ║  DNS error: {dns['error']}", Fore.RED))
    else:
        print(c(f"  ║  DNS: tidak ada record A", Fore.YELLOW))

    # VirusTotal
    if not vt.get("error") and vt:
        mal  = vt.get("malicious",0)
        sus  = vt.get("suspicious",0)
        har  = vt.get("harmless",0)
        rep  = vt.get("reputation",0)
        cats = vt.get("categories",{})

        vtcol = Fore.RED if mal >= 1 else (Fore.YELLOW if sus >= 1 else Fore.GREEN)
        print(c(f"  ║  VirusTotal: {mal} berbahaya, {sus} mencurigakan, {har} aman", vtcol))
        print(c(f"  ║  Reputasi  : {rep}", Fore.WHITE))
        if cats:
            cat_str = ", ".join(list(set(cats.values()))[:3])
            print(c(f"  ║  Kategori  : {cat_str}", Fore.WHITE))

        cdate = vt.get("creation_date","?")
        if cdate and cdate != "?":
            try:
                dt = datetime.utcfromtimestamp(int(cdate)).strftime("%Y-%m-%d")
                print(c(f"  ║  Dibuat    : {dt}", Fore.WHITE))
            except Exception:
                pass
    elif not vt.get("error"):
        print(c("  ║  VirusTotal: butuh API key (gratis di virustotal.com)", Fore.CYAN))

    print(c(f"  ╚{'═'*48}", Fore.CYAN))

def print_hash_report(hash_val: str, hash_type: str, vt: Dict) -> None:
    """Cetak laporan file hash."""
    score, verdict = calculate_hash_risk(vt)

    if score >= 60:     col = Fore.RED
    elif score >= 20:   col = Fore.YELLOW
    else:               col = Fore.GREEN

    print(c(f"\n  ╔══ Hash ({hash_type.upper()}) ══════════════════════════════════", col, bold=True))
    print(c(f"  ║  {hash_val}", Fore.WHITE))
    print(c(f"  ║  Verdict : {verdict}", col, bold=(score >= 60)))

    if not vt.get("error") and vt:
        name = vt.get("name","?")
        ftype= vt.get("type","?")
        size = vt.get("size",0)
        mal  = vt.get("malicious",0)
        sus  = vt.get("suspicious",0)
        har  = vt.get("harmless",0)
        tags = vt.get("tags",[])

        if name and name != "?":
            print(c(f"  ║  Nama file: {name}", Fore.WHITE))
        print(c(f"  ║  Tipe     : {ftype}  ({size:,} bytes)", Fore.WHITE))
        print(c(f"  ║  Detection: {mal} berbahaya, {sus} mencurigakan, {har} aman",
                Fore.RED if mal >= 1 else Fore.GREEN))
        if tags:
            print(c(f"  ║  Tags     : {', '.join(tags[:5])}", Fore.WHITE))
    elif vt.get("error") == "no_api_key":
        print(c("  ║  VirusTotal: butuh API key — daftar gratis di virustotal.com", Fore.CYAN))

    print(c(f"  ╚{'═'*48}", col))

# ── Bulk investigasi ──────────────────────────────────────────────────────────

def investigate_ip(ip: str, apis: Dict) -> Dict:
    """Investigasi satu IP dengan semua sumber yang tersedia."""
    if not is_valid_ip(ip):
        return {"ip": ip, "error": "invalid_ip"}

    if is_private_ip_str(ip):
        return {
            "ip":    ip,
            "error": "private_ip",
            "note":  "IP private/loopback tidak perlu investigasi eksternal",
        }

    results = {"ip": ip}

    # Query paralel — OTX gratis tanpa key, dipakai selalu
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {
            ex.submit(query_ipinfo, ip):   "ipinfo",    # ipwho.is — gratis unlimited
            ex.submit(query_ip_api, ip):   "ip_api",    # ip-api.com — gratis 1k/menit
            ex.submit(reverse_dns,  ip):   "reverse_dns",
            ex.submit(query_otx_ip, ip):   "otx",       # OTX AlienVault — gratis tanpa key
        }
        if apis.get("abuseipdb"):
            futures[ex.submit(query_abuseipdb, ip, apis["abuseipdb"])] = "abuseipdb"
        if apis.get("virustotal"):
            futures[ex.submit(query_virustotal_ip, ip, apis["virustotal"])] = "virustotal"

        for future in as_completed(futures, timeout=15):
            key = futures[future]
            try:
                results[key] = future.result(timeout=10)
            except Exception:
                results[key] = {}

    score, reasons = calculate_ip_risk(results)
    results["risk_score"]      = score
    results["risk_reasons"]    = reasons
    results["investigated_at"] = datetime.now().isoformat()

    return results

def investigate_from_alerts(apis: Dict) -> List[Dict]:
    """Investigasi semua IP unik dari log alerts Selene."""
    alerts = read_jsonl(LOGS_DIR / "alerts.jsonl", last_n=500)
    if not alerts:
        log("INFO", "Log alerts Selene kosong — belum ada ancaman yang dicatat")
        return []

    # Kumpulkan IP unik
    unique_ips = list({
        a.get("ip","") for a in alerts
        if a.get("ip") and is_valid_ip(a.get("ip",""))
        and not is_private_ip_str(a.get("ip",""))
    })

    if not unique_ips:
        log("INFO", "Tidak ada IP publik yang valid di log alerts")
        return []

    log("INFO", f"Investigasi {len(unique_ips)} IP unik dari alerts Selene...")
    results = []

    for i, ip in enumerate(unique_ips[:20], 1):  # Max 20 IP
        log("SCAN", c(f"  [{i}/{min(len(unique_ips),20)}] Investigasi {ip}...", Fore.WHITE))
        result = investigate_ip(ip, apis)
        results.append(result)
        if result.get("risk_score",0) >= 40:
            score   = result["risk_score"]
            reasons = result.get("risk_reasons",[])
            print_ip_report(ip, result, score, reasons)
        else:
            log("OK", c(f"  {ip} — skor {result.get('risk_score',0)}/100 (aman)", Fore.GREEN))

        # Rate limiting antar request
        if i < min(len(unique_ips), 20):
            time.sleep(0.5)

    return results

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Threat Intel — Investigasi IP, domain, dan hash",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/threat_intel.py --ip 185.220.101.1
  python scripts/threat_intel.py --domain malware-site.ru
  python scripts/threat_intel.py --hash d41d8cd98f00b204e9800998ecf8427e
  python scripts/threat_intel.py --batch ips.txt
  python scripts/threat_intel.py --from-alerts

API keys (opsional, gratis):
  AbuseIPDB  : https://www.abuseipdb.com/register
  VirusTotal : https://www.virustotal.com/gui/join-us
  Set env var: ABUSEIPDB_KEY=xxx  VIRUSTOTAL_KEY=xxx"""
    )
    parser.add_argument("--ip",         help="Investigasi satu IP")
    parser.add_argument("--domain",     help="Investigasi satu domain")
    parser.add_argument("--hash",       help="Investigasi file hash (MD5/SHA1/SHA256)")
    parser.add_argument("--batch",      metavar="FILE",
                        help="Investigasi daftar IP dari file (satu IP per baris)")
    parser.add_argument("--from-alerts",action="store_true",
                        help="Investigasi IP dari log alerts Selene")
    parser.add_argument("--no-save",    action="store_true",
                        help="Jangan simpan laporan")
    parser.add_argument("--abuseipdb",  metavar="KEY",
                        help="AbuseIPDB API key")
    parser.add_argument("--virustotal", metavar="KEY",
                        help="VirusTotal API key")
    args = parser.parse_args()

    log_header("Selene — Threat Intel v3.0",
               "Investigasi IP, domain, dan hash lewat OSINT publik")

    if not HAS_REQUESTS:
        log("ERROR", "Library 'requests' tidak tersedia.")
        log("INFO",  "Install: pip install requests")
        sys.exit(1)

    # Kumpulkan API keys
    cfg = get_config()
    apis = {
        "abuseipdb":  (args.abuseipdb
                       or os.environ.get("ABUSEIPDB_KEY","")
                       or cfg.get("threat_intel","abuseipdb_key", default="")),
        "virustotal": (args.virustotal
                       or os.environ.get("VIRUSTOTAL_KEY","")
                       or cfg.get("threat_intel","virustotal_key", default="")),
    }

    if not any(apis.values()):
        log("INFO", c("Mode dasar — ipwho.is + ip-api.com + OTX AlienVault (semua gratis, tanpa API key)",
                      Fore.CYAN))
        log("INFO", c("Tambahkan API key untuk deteksi lebih lengkap:", Fore.WHITE))
        log("INFO",  "  ABUSEIPDB_KEY=xxx  VIRUSTOTAL_KEY=xxx python scripts/threat_intel.py ...")
    else:
        active = [k for k,v in apis.items() if v]
        log("INFO", c(f"API aktif: {', '.join(active)}", Fore.GREEN))

    all_results = []

    # ── IP tunggal ────────────────────────────────────────────────────────────
    if args.ip:
        ip = args.ip.strip()
        if not is_valid_ip(ip):
            log("ERROR", f"Format IP tidak valid: {ip}")
            sys.exit(1)
        if is_private_ip_str(ip):
            log("INFO", f"{ip} adalah IP private — tidak perlu investigasi eksternal")
            return

        log_section(f"INVESTIGASI IP: {ip}")
        with Spinner(f"Mengumpulkan data untuk {ip}..."):
            result = investigate_ip(ip, apis)

        score   = result.get("risk_score", 0)
        reasons = result.get("risk_reasons",[])
        print_ip_report(ip, result, score, reasons)
        all_results.append(result)

    # ── Domain ────────────────────────────────────────────────────────────────
    elif args.domain:
        domain = args.domain.strip().lstrip("http://").lstrip("https://").split("/")[0]
        if not is_valid_domain(domain):
            log("ERROR", f"Format domain tidak valid: {domain}")
            sys.exit(1)

        log_section(f"INVESTIGASI DOMAIN: {domain}")
        with Spinner(f"Mengumpulkan data untuk {domain}..."):
            dns = dns_lookup(domain)
            otx = query_otx_domain(domain)   # gratis tanpa key
            vt  = (query_virustotal_domain(domain, apis["virustotal"])
                   if apis.get("virustotal") else {"error":"no_api_key"})

        # Tampilkan hasil OTX jika ada
        if otx.get("pulse_count",0) > 0:
            log("WARN", c(f"OTX AlienVault: {otx['pulse_count']} laporan ancaman untuk domain ini!",
                          Fore.RED, bold=True))
        else:
            log("OK", c("OTX AlienVault: tidak ditemukan dalam threat feeds", Fore.GREEN))

        print_domain_report(domain, dns, vt)

        if dns.get("ips") and not is_private_ip_str(dns["ips"][0]):
            for ip in dns["ips"][:2]:
                log("SCAN", f"Investigasi IP {ip} dari {domain}...")
                with Spinner(f"IP {ip}..."):
                    ip_result = investigate_ip(ip, apis)
                score   = ip_result.get("risk_score",0)
                reasons = ip_result.get("risk_reasons",[])
                print_ip_report(ip, ip_result, score, reasons)
                all_results.append(ip_result)

    # ── Hash ──────────────────────────────────────────────────────────────────
    elif args.hash:
        hash_val  = args.hash.strip().lower()
        hash_type = is_valid_hash(hash_val)
        if not hash_type:
            log("ERROR", "Format hash tidak valid. Gunakan MD5, SHA-1, atau SHA-256.")
            sys.exit(1)

        log_section(f"INVESTIGASI HASH ({hash_type.upper()})")
        with Spinner(f"Query OTX + VirusTotal untuk {hash_val[:16]}..."):
            otx = query_otx_hash(hash_val)   # gratis tanpa key
            vt  = (query_virustotal_hash(hash_val, apis["virustotal"])
                   if apis.get("virustotal") else {"error":"no_api_key"})

        # OTX result
        if otx.get("pulse_count",0) > 0:
            log("WARN", c(f"OTX: {otx['pulse_count']} laporan — hash ini dikenal berbahaya!",
                          Fore.RED, bold=True))
        elif not otx.get("error"):
            log("OK", c("OTX AlienVault: hash tidak ditemukan dalam threat feeds", Fore.GREEN))

        if not apis.get("virustotal"):
            log("INFO", c("VirusTotal: tambahkan API key untuk analisis lebih detail (gratis di virustotal.com)",
                          Fore.CYAN))

        print_hash_report(hash_val, hash_type, vt)

    # ── Batch ─────────────────────────────────────────────────────────────────
    elif args.batch:
        fp = Path(args.batch)
        if not fp.exists():
            log("ERROR", f"File tidak ditemukan: {args.batch}")
            sys.exit(1)

        ips = [
            line.strip() for line in fp.read_text(errors="ignore").splitlines()
            if line.strip() and not line.startswith("#") and is_valid_ip(line.strip())
        ]

        if not ips:
            log("ERROR", "Tidak ada IP valid di file tersebut")
            sys.exit(1)

        log_section(f"BATCH INVESTIGASI: {len(ips)} IP")
        for i, ip in enumerate(ips, 1):
            log("SCAN", c(f"  [{i}/{len(ips)}] {ip}", Fore.WHITE))
            result  = investigate_ip(ip, apis)
            score   = result.get("risk_score",0)
            reasons = result.get("risk_reasons",[])
            print_ip_report(ip, result, score, reasons)
            all_results.append(result)
            if i < len(ips):
                time.sleep(0.5)

    # ── From alerts ───────────────────────────────────────────────────────────
    elif args.from_alerts:
        log_section("INVESTIGASI IP DARI ALERTS SELENE")
        all_results = investigate_from_alerts(apis)

    # ── Tidak ada input ───────────────────────────────────────────────────────
    else:
        parser.print_help()
        return

    # Ringkasan
    if all_results:
        log_section("RINGKASAN")
        high_risk = [r for r in all_results if r.get("risk_score",0) >= 70]
        med_risk  = [r for r in all_results if 40 <= r.get("risk_score",0) < 70]
        print(c(f"\n  IP diperiksa  : {len(all_results)}", Fore.WHITE))
        print(c(f"  Risiko tinggi : {len(high_risk)}",
                Fore.RED if high_risk else Fore.GREEN, bold=bool(high_risk)))
        print(c(f"  Risiko sedang : {len(med_risk)}",
                Fore.YELLOW if med_risk else Fore.GREEN))

        if high_risk:
            print(c("\n  IP paling berbahaya:", Fore.RED, bold=True))
            for r in sorted(high_risk, key=lambda x: x.get("risk_score",0), reverse=True)[:3]:
                print(c(f"    {r['ip']:<20}  skor {r['risk_score']}/100", Fore.RED))

    # Simpan laporan
    if all_results and not args.no_save:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = REPORTS_DIR / f"threat_intel_{ts}.json"
        save_json(path, {
            "tool":      "threat_intel",
            "version":   TOOL_VERSION,
            "scan_time": datetime.now().isoformat(),
            "results":   all_results,
        })
        log("OK", c(f"Laporan: reports/threat_intel_{ts}.json", Fore.GREEN))

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
