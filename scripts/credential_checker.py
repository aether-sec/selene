#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Credential Checker v3.0                           ║
║   Cek apakah email atau password kamu pernah bocor.          ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/credential_checker.py
  python scripts/credential_checker.py --email kamu@gmail.com
  python scripts/credential_checker.py --password
  python scripts/credential_checker.py --batch emails.txt

Privasi:
  - Email: dikirim ke HaveIBeenPwned (API resmi, enkripsi HTTPS)
  - Password: TIDAK pernah dikirim ke mana-mana.
    Hanya 5 karakter pertama hash SHA-1 yang dikirim (k-Anonymity).
    Sisa hash dibandingkan secara lokal.
"""

import sys
import os
import hashlib
import time
import argparse
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, prompt, prompt_password,
        save_json, REPORTS_DIR,
    )
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

TOOL_VERSION = "3.0.1"

# ── API Endpoints — 100% gratis, tanpa registrasi ────────────────────────────
HIBP_RANGE_URL  = "https://api.pwnedpasswords.com/range/{}"   # password k-anonymity: GRATIS PENUH
EMAILREP_URL    = "https://emailrep.io/{}"                     # reputasi email: gratis 100/hari
LEAKCHECK_URL   = "https://leakcheck.io/api/public?check={}"  # breach check: gratis tanpa key

HEADERS = {
    "User-Agent": "Selene-Security-Suite/3.0",
}

REQUEST_TIMEOUT = 10

# ── Validasi ──────────────────────────────────────────────────────────────────
def is_valid_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email.strip()))

# ── Password check (k-Anonymity) ──────────────────────────────────────────────
def check_password(password: str) -> Tuple[bool, int]:
    """
    Cek apakah password pernah bocor menggunakan k-Anonymity.

    Cara kerja:
    1. Hash password dengan SHA-1
    2. Kirim HANYA 5 karakter pertama ke server
    3. Server kembalikan semua hash yang dimulai 5 karakter itu
    4. Kita cocokkan sisa hash SECARA LOKAL

    Password TIDAK PERNAH dikirim ke server.

    Returns: (ditemukan: bool, jumlah_bocor: int)
    """
    if not HAS_REQUESTS:
        log("ERROR", "requests tidak tersedia — install: pip install requests")
        return False, 0

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix    = sha1_hash[:5]
    suffix    = sha1_hash[5:]

    try:
        r = requests.get(
            HIBP_RANGE_URL.format(prefix),
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": HEADERS["User-Agent"]},
        )
        if r.status_code != 200:
            log("WARN", f"HIBP API error: {r.status_code}")
            return False, 0

        # Cari suffix yang cocok dalam response
        for line in r.text.splitlines():
            if ":" in line:
                hash_suffix, count_str = line.split(":", 1)
                if hash_suffix.strip() == suffix:
                    count = int(count_str.strip())
                    return True, count

        return False, 0

    except requests.Timeout:
        log("WARN", "Timeout — tidak bisa terhubung ke HIBP")
        return False, 0
    except Exception as e:
        log("WARN", f"Error check password: {e}")
        return False, 0

def rate_password_strength(password: str) -> Tuple[int, str, List[str]]:
    """
    Nilai kekuatan password secara lokal.
    Returns: (skor 0-100, label, [saran])
    """
    score   = 0
    issues  = []

    # Panjang
    if len(password) >= 20:    score += 30
    elif len(password) >= 14:  score += 20
    elif len(password) >= 10:  score += 10
    elif len(password) >= 8:   score += 5
    else:
        issues.append(f"Terlalu pendek ({len(password)} karakter) — minimal 12")

    # Variasi karakter
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_sym   = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)

    if has_upper: score += 10
    else: issues.append("Tambah huruf besar (A-Z)")
    if has_lower: score += 10
    else: issues.append("Tambah huruf kecil (a-z)")
    if has_digit: score += 10
    else: issues.append("Tambah angka (0-9)")
    if has_sym:   score += 20
    else: issues.append("Tambah simbol (!@#$...)")

    # Cek pola buruk
    COMMON_PATTERNS = [
        r"^(.)\1{3,}$",            # karakter berulang (aaaa, 1111)
        r"(012|123|234|345|456|567|678|789|890)",  # urutan angka
        r"(abc|bcd|cde|def|efg)",  # urutan huruf
        r"(qwerty|asdfgh|zxcvbn)", # keyboard walk
    ]
    COMMON_PASSWORDS = {
        "password","123456","password123","admin","letmein",
        "qwerty","monkey","dragon","sunshine","princess",
        "welcome","login","master","abc123","iloveyou",
    }

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        issues.insert(0, "Password ini sangat umum dan ada di semua daftar bocor!")

    for pattern in COMMON_PATTERNS:
        if re.search(pattern, password, re.IGNORECASE):
            score -= 15
            issues.append("Mengandung pola yang mudah ditebak")
            break

    score = max(0, min(100, score))

    if score >= 80:    label = "Sangat Kuat"
    elif score >= 60:  label = "Kuat"
    elif score >= 40:  label = "Sedang"
    elif score >= 20:  label = "Lemah"
    else:              label = "Sangat Lemah"

    return score, label, issues

# ── Email check — gratis, tanpa API key ──────────────────────────────────────
def check_email_leakcheck(email: str) -> Optional[List[Dict]]:
    """
    Cek email di LeakCheck.io — gratis tanpa API key.
    Returns list bocoran atau [] jika aman, None jika error.
    """
    if not HAS_REQUESTS:
        return None
    try:
        r = requests.get(
            LEAKCHECK_URL.format(email.strip()),
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            # LeakCheck public API: {"success":true,"found":3,"sources":[...]}
            if not data.get("success"):
                return []
            sources = data.get("sources", [])
            result  = []
            for s in sources:
                result.append({
                    "name":        s.get("name", "?"),
                    "date":        s.get("date", "?"),
                    "source":      "leakcheck.io",
                })
            return result
        elif r.status_code == 404:
            return []   # Tidak ada di database bocoran
        elif r.status_code == 429:
            log("WARN", "Rate limit LeakCheck — tunggu sebentar")
            return None
        return None
    except Exception as e:
        log("WARN", f"LeakCheck error: {e}")
        return None

def check_email_reputation(email: str) -> Dict:
    """
    Cek reputasi email via emailrep.io — gratis 100 request/hari.
    Memberikan info: apakah disposable, apakah ada di breach, dll.
    """
    if not HAS_REQUESTS:
        return {}
    try:
        r = requests.get(
            EMAILREP_URL.format(email.strip()),
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            rep = d.get("details", {})
            return {
                "is_disposable":   rep.get("disposable", False),
                "is_free":         rep.get("free_provider", False),
                "credentials_leaked": rep.get("credentials_leaked", False),
                "malicious_activity": rep.get("malicious_activity", False),
                "suspicious_tld":  rep.get("suspicious_tld", False),
                "spam":            rep.get("spam", False),
                "reputation":      d.get("reputation", "unknown"),
                "source":          "emailrep.io",
            }
        return {}
    except Exception:
        return {}

def check_email(email: str, api_key: str = "") -> Optional[List[Dict]]:
    """
    Cek apakah email ada di database bocor.
    Menggunakan LeakCheck.io (gratis, tanpa API key).
    api_key diabaikan — parameter dipertahankan untuk kompatibilitas.
    """
    if not HAS_REQUESTS:
        log("ERROR", "requests tidak tersedia")
        return None
    if not is_valid_email(email):
        log("ERROR", f"Format email tidak valid: {email}")
        return None

    # Coba LeakCheck gratis dulu
    result = check_email_leakcheck(email)

    # Tambah info reputasi dari emailrep.io
    rep = check_email_reputation(email)
    if rep.get("credentials_leaked") and result == []:
        # emailrep tahu ada kebocoran tapi leakcheck tidak punya detailnya
        result = result or []
        result.append({
            "name":   "Tidak diketahui (terdeteksi emailrep.io)",
            "date":   "?",
            "source": "emailrep.io",
        })

    return result

# ── Display helpers ───────────────────────────────────────────────────────────
def print_email_result(email: str, breaches: Optional[List[Dict]]) -> None:
    """Cetak hasil cek email."""
    if breaches is None:
        print(c(f"\n  {email} — Tidak bisa dicek (mungkin offline atau rate limit)", Fore.YELLOW))
        return

    if not breaches:
        print(c(f"\n  ✓  {email}", Fore.GREEN, bold=True))
        print(c("     Tidak ditemukan dalam database kebocoran data.", Fore.GREEN))
        return

    print(c(f"\n  ⚠  {email}", Fore.RED, bold=True))
    print(c(f"     Ditemukan dalam {len(breaches)} kebocoran data!", Fore.RED))
    print()

    breaches_sorted = sorted(breaches, key=lambda b: b.get("date",""), reverse=True)

    for b in breaches_sorted[:5]:
        name   = b.get("name", "?")
        date   = b.get("date", "?")
        source = b.get("source", "")
        print(c(f"     ⚠  {name}", Fore.YELLOW, bold=True) +
              c(f"  (tanggal: {date})", Fore.WHITE))

    if len(breaches) > 5:
        print(c(f"     ... +{len(breaches)-5} kebocoran lainnya", Fore.WHITE))

    print()
    print(c("     💡 Yang harus kamu lakukan:", Fore.CYAN))
    print(c("        1. Ganti password di semua layanan yang bocor", Fore.WHITE))
    print(c("        2. Aktifkan two-factor authentication (2FA)", Fore.WHITE))
    print(c("        3. Gunakan password unik berbeda untuk setiap layanan", Fore.WHITE))
    print(c("        4. Pertimbangkan menggunakan password manager (vault.py)", Fore.WHITE))

def print_password_result(found: bool, count: int,
                           strength_score: int, strength_label: str,
                           issues: List[str]) -> None:
    """Cetak hasil cek password."""
    print()

    # Status bocor
    if found:
        print(c(f"  ⛔ Password ini ditemukan {count:,}x dalam database kebocoran!",
                Fore.RED, bold=True))
        print(c("     JANGAN gunakan password ini — sudah diketahui penyerang.", Fore.RED))
    else:
        print(c("  ✓  Password ini TIDAK ditemukan dalam database kebocoran.",
                Fore.GREEN, bold=True))

    # Kekuatan password
    strength_color = (
        Fore.GREEN if strength_score >= 60
        else Fore.YELLOW if strength_score >= 40
        else Fore.RED
    )
    print()
    print(c(f"  Kekuatan password: ", Fore.WHITE), end="")
    print(c(f"{strength_score}/100 — {strength_label}", strength_color, bold=True))

    # Progress bar sederhana
    filled = int(strength_score / 5)
    bar    = "█" * filled + "░" * (20 - filled)
    print(c(f"  [{bar}]", strength_color))

    if issues:
        print(c("\n  Saran perbaikan:", Fore.CYAN))
        for issue in issues:
            print(c(f"    • {issue}", Fore.WHITE))

# ── Batch processing ──────────────────────────────────────────────────────────
def check_email_batch(file_path: str) -> List[Dict]:
    """Cek daftar email dari file."""
    fp = Path(file_path)
    if not fp.exists():
        log("ERROR", f"File tidak ditemukan: {file_path}")
        return []
    emails = [l.strip() for l in fp.read_text(errors="ignore").splitlines()
              if l.strip() and not l.startswith("#")]
    valid   = [e for e in emails if is_valid_email(e)]
    invalid = len(emails) - len(valid)
    if invalid:
        log("INFO", f"{invalid} email tidak valid dilewati")
    log("INFO", f"Memeriksa {len(valid)} email...")
    results = []
    for i, email in enumerate(valid, 1):
        log("SCAN", c(f"  [{i}/{len(valid)}] {email}", Fore.WHITE))
        breaches = check_email(email)
        results.append({
            "email":        email,
            "breaches":     breaches or [],
            "breach_count": len(breaches) if breaches else 0,
            "status":       "bocor" if breaches else ("aman" if breaches == [] else "error"),
        })
        print_email_result(email, breaches)
        if i < len(valid):
            time.sleep(1.2)   # hindari rate limit
    return results

def interactive_mode() -> None:
    """Mode interaktif untuk cek email atau password."""
    while True:
        print(c("""
  Apa yang ingin kamu periksa?
  [1] Email — cek apakah ada dalam database kebocoran
  [2] Password — cek apakah pernah bocor + nilai kekuatan
  [3] Keluar
""", Fore.WHITE))

        choice = input(c("  Pilih [1/2/3]: ", Fore.YELLOW)).strip()

        if choice == "3" or not choice:
            break

        elif choice == "1":
            email = prompt("Masukkan email")
            if not email:
                continue
            if not is_valid_email(email):
                log("ERROR", "Format email tidak valid.")
                continue
            log("SCAN", f"Memeriksa {email}...")
            breaches = check_email(email)
            print_email_result(email, breaches)

        elif choice == "2":
            password = prompt_password("Masukkan password (tidak akan ditampilkan)")
            if not password:
                continue

            print(c("\n  Memeriksa...", Fore.CYAN))
            strength_score, strength_label, issues = rate_password_strength(password)
            found, count = check_password(password)
            print_password_result(found, count, strength_score, strength_label, issues)
        else:
            log("WARN", f"Pilihan tidak valid: {choice}")

        print()

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Selene Credential Checker — Cek email & password yang bocor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/credential_checker.py
  python scripts/credential_checker.py --email kamu@gmail.com
  python scripts/credential_checker.py --password
  python scripts/credential_checker.py --batch emails.txt

Privasi:
  Password TIDAK pernah dikirim ke server.
  Hanya 5 karakter pertama hash SHA-1 yang dikirim (k-Anonymity).
  Sumber: https://haveibeenpwned.com/Passwords"""
    )
    parser.add_argument("--email",    "-e", help="Cek satu email")
    parser.add_argument("--password", "-p", action="store_true",
                        help="Cek password (akan diminta secara aman)")
    parser.add_argument("--batch",    "-b", metavar="FILE",
                        help="Cek banyak email dari file (satu per baris)")
    parser.add_argument("--no-save",  action="store_true",
                        help="Jangan simpan laporan")
    args = parser.parse_args()

    log_header(
        "Selene — Credential Checker v3.0",
        "Cek apakah akun atau password kamu pernah bocor"
    )

    if not HAS_REQUESTS:
        log("ERROR", "Library 'requests' diperlukan.")
        log("INFO",  "Install: pip install requests")
        sys.exit(1)

    results = []

    # ── Mode email tunggal
    if args.email:
        if not is_valid_email(args.email):
            log("ERROR", "Format email tidak valid.")
            sys.exit(1)
        log("SCAN", f"Memeriksa: {args.email}")
        breaches = check_email(args.email)
        print_email_result(args.email, breaches)
        results = [{"email": args.email, "breaches": breaches or [],
                    "breach_count": len(breaches) if breaches else 0}]

    elif args.password:
        print(c("""
  Catatan privasi:
  Password TIDAK dikirim ke server. Hanya 5 karakter pertama
  dari hash SHA-1 yang dikirim. Sisa perbandingan dilakukan
  secara lokal di komputermu.
""", Fore.WHITE))
        password = prompt_password("Masukkan password")
        if not password:
            log("ERROR", "Password tidak boleh kosong.")
            sys.exit(1)
        log("SCAN", "Memeriksa kekuatan dan kebocoran...")
        strength_score, strength_label, issues = rate_password_strength(password)
        found, count = check_password(password)
        print_password_result(found, count, strength_score, strength_label, issues)

    elif args.batch:
        results = check_email_batch(args.batch)
        if results:
            bocor = [r for r in results if r["status"] == "bocor"]
            log_section("RINGKASAN BATCH")
            print(c(f"\n  Total email diperiksa  : {len(results)}", Fore.WHITE))
            print(c(f"  Email yang bocor       : {len(bocor)}",
                    Fore.RED if bocor else Fore.GREEN, bold=bool(bocor)))
            print(c(f"  Email yang aman        : {len(results)-len(bocor)}", Fore.GREEN))

    else:
        interactive_mode()

    # Simpan laporan
    if results and not args.no_save:
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        rpath = REPORTS_DIR / f"credentials_{ts}.json"
        save_json(rpath, {
            "tool":       "credential_checker",
            "version":    TOOL_VERSION,
            "check_time": datetime.now().isoformat(),
            "results":    results,
        })
        log("OK", c(f"Laporan: reports/credentials_{ts}.json", Fore.GREEN))

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
