#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Vault v3.0                                        ║
║   Password manager terenkripsi AES-256-GCM.                  ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/vault.py                   — menu interaktif
  python scripts/vault.py add               — tambah password
  python scripts/vault.py get <nama>        — ambil password
  python scripts/vault.py list              — daftar semua
  python scripts/vault.py delete <nama>     — hapus entri
  python scripts/vault.py generate          — buat password kuat
  python scripts/vault.py check             — cek kesehatan vault

Keamanan:
  • AES-256-GCM authenticated encryption
  • PBKDF2-SHA256 dengan 480.000 iterasi
  • Master password TIDAK pernah disimpan
  • Auto-lock setelah 5 menit tidak aktif
"""

import sys
import os
import json
import time
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, prompt, prompt_password,
        SELENE_DIR,
    )
    from selene.core.crypto import (
        encrypt, decrypt, secure_random_password, HAS_CRYPTO
    )
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

TOOL_VERSION  = "3.0.0"
VAULT_FILE    = SELENE_DIR / "vault.enc"
AUDIT_FILE    = SELENE_DIR / "logs" / "vault_audit.jsonl"
AUTO_LOCK_SEC = 300   # 5 menit

# ── Vault core ────────────────────────────────────────────────────────────────

def _load_vault(master: str) -> Optional[Dict]:
    """Muat dan dekripsi vault. Returns None jika gagal."""
    if not VAULT_FILE.exists():
        return {}
    try:
        raw  = VAULT_FILE.read_bytes()
        data = decrypt(raw, master)
        return json.loads(data.decode("utf-8"))
    except ValueError as e:
        log("ERROR", str(e))
        return None
    except Exception as e:
        log("ERROR", f"Gagal buka vault: {e}")
        return None

def _save_vault(data: Dict, master: str) -> bool:
    """Enkripsi dan simpan vault secara atomic."""
    try:
        raw = encrypt(json.dumps(data, ensure_ascii=False).encode("utf-8"), master)
        tmp = Path(str(VAULT_FILE) + ".tmp")
        tmp.write_bytes(raw)
        tmp.replace(VAULT_FILE)
        # Pastikan permission ketat
        try:
            VAULT_FILE.chmod(0o600)
        except Exception:
            pass
        return True
    except Exception as e:
        log("ERROR", f"Gagal simpan vault: {e}")
        return False

def _audit(action: str, name: str = "") -> None:
    """Catat semua aksi vault ke audit log."""
    entry = {
        "timestamp": datetime.now().isoformat(),
        "action":    action,
        "entry":     name,
    }
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass

# ── Copy to clipboard ─────────────────────────────────────────────────────────

def copy_to_clipboard(text: str) -> bool:
    """Coba copy ke clipboard. Returns True jika berhasil."""
    import subprocess, shutil
    tools = []
    if shutil.which("xclip"):
        tools.append(["xclip", "-selection", "clipboard"])
    elif shutil.which("xsel"):
        tools.append(["xsel", "--clipboard", "--input"])
    elif shutil.which("pbcopy"):
        tools.append(["pbcopy"])
    elif shutil.which("clip"):
        tools.append(["clip"])

    for tool in tools:
        try:
            p = subprocess.Popen(tool, stdin=subprocess.PIPE)
            p.communicate(input=text.encode())
            if p.returncode == 0:
                return True
        except Exception:
            pass
    return False

def clear_clipboard_after(seconds: int = 30) -> None:
    """Bersihkan clipboard setelah delay."""
    def _clear():
        time.sleep(seconds)
        copy_to_clipboard("")
    threading.Thread(target=_clear, daemon=True).start()

# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_add(vault: Dict, master: str) -> bool:
    """Tambah entri baru ke vault."""
    print(c("\n  Tambah entri baru\n", Fore.CYAN, bold=True))

    name = prompt("Nama entri (contoh: gmail, ssh-server)").strip()
    if not name:
        log("ERROR", "Nama tidak boleh kosong.")
        return False
    if name in vault:
        log("WARN", f"Entri '{name}' sudah ada.")
        if not confirm("Timpa entri yang ada?", default=False):
            return False

    username = prompt("Username / email (kosong untuk skip)").strip()

    print(c("\n  Pilih sumber password:", Fore.WHITE))
    print(c("  [1] Ketik sendiri", Fore.WHITE))
    print(c("  [2] Generate otomatis (disarankan)", Fore.WHITE))
    choice = input(c("  Pilih [1/2]: ", Fore.YELLOW)).strip()

    if choice == "2":
        length_str = prompt("Panjang password", default="20")
        try:
            length = max(12, min(64, int(length_str)))
        except ValueError:
            length = 20
        use_symbols = confirm("Sertakan simbol (!@#...)?", default=True)
        password = secure_random_password(length, use_symbols)
        print(c(f"\n  Password dibuat: ", Fore.WHITE), end="")
        print(c(password, Fore.GREEN, bold=True))
        if copy_to_clipboard(password):
            print(c("  ✓ Tersalin ke clipboard (akan dihapus dalam 30 detik)",
                    Fore.CYAN))
            clear_clipboard_after(30)
    else:
        password = prompt_password("Password")
        if not password:
            log("ERROR", "Password tidak boleh kosong.")
            return False
        verify = prompt_password("Ulangi password")
        if password != verify:
            log("ERROR", "Password tidak cocok.")
            return False

    url   = prompt("URL / host (kosong untuk skip)").strip()
    notes = prompt("Catatan (kosong untuk skip)").strip()

    vault[name] = {
        "username":   username,
        "password":   password,
        "url":        url,
        "notes":      notes,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "accessed_at": None,
    }

    if _save_vault(vault, master):
        _audit("add", name)
        log("OK", c(f"Entri '{name}' berhasil disimpan.", Fore.GREEN, bold=True))
        return True
    return False

def cmd_get(vault: Dict, master: str, name: str) -> bool:
    """Ambil dan tampilkan entri."""
    if name not in vault:
        # Coba fuzzy search
        matches = [k for k in vault if name.lower() in k.lower()]
        if not matches:
            log("ERROR", f"Entri '{name}' tidak ditemukan.")
            return False
        if len(matches) == 1:
            name = matches[0]
            log("INFO", f"Ditemukan: '{name}'")
        else:
            print(c(f"\n  Maksud kamu:", Fore.YELLOW))
            for i, m in enumerate(matches[:8], 1):
                print(c(f"  [{i}] {m}", Fore.WHITE))
            choice = input(c("  Pilih nomor: ", Fore.YELLOW)).strip()
            try:
                name = matches[int(choice) - 1]
            except (ValueError, IndexError):
                return False

    entry = vault[name]

    # Update accessed_at
    entry["accessed_at"] = datetime.now().isoformat()
    _save_vault(vault, master)
    _audit("get", name)

    print(c(f"\n  ── {name} ───────────────────────────────────────", Fore.CYAN))
    print(c(f"  Username : {entry.get('username','—')}", Fore.WHITE))
    print(c(f"  Password : ", Fore.WHITE), end="")
    print(c(entry.get('password','?'), Fore.GREEN, bold=True))
    if entry.get("url"):
        print(c(f"  URL      : {entry['url']}", Fore.WHITE))
    if entry.get("notes"):
        print(c(f"  Catatan  : {entry['notes']}", Fore.WHITE))
    print(c(f"  Dibuat   : {entry.get('created_at','?')[:16]}", Fore.WHITE))

    # Tawarkan copy ke clipboard
    if confirm("\n  Copy password ke clipboard?", default=True):
        if copy_to_clipboard(entry.get("password","")):
            log("OK", "Password tersalin ke clipboard (akan dihapus dalam 30 detik)")
            clear_clipboard_after(30)
        else:
            log("INFO", "Clipboard tidak tersedia (xclip/xsel/pbcopy tidak terinstall)")

    return True

def cmd_list(vault: Dict) -> None:
    """Tampilkan daftar semua entri."""
    if not vault:
        print(c("\n  Vault kosong. Gunakan 'add' untuk menambah entri.", Fore.YELLOW))
        return

    print(c(f"\n  {len(vault)} entri tersimpan:\n", Fore.WHITE))
    print(c(f"  {'NAMA':<25} {'USERNAME':<28} {'TERAKHIR DIBUAT'}", Fore.CYAN))
    print(c(f"  {'─'*25} {'─'*28} {'─'*16}", Fore.BLUE))

    for name in sorted(vault.keys()):
        entry    = vault[name]
        username = entry.get("username","—")[:27]
        created  = entry.get("created_at","?")[:10]
        print(c(f"  {name:<25} {username:<28} {created}", Fore.WHITE))

def cmd_delete(vault: Dict, master: str, name: str) -> bool:
    """Hapus entri dari vault."""
    if name not in vault:
        log("ERROR", f"Entri '{name}' tidak ditemukan.")
        return False

    print(c(f"\n  Akan menghapus: {name}", Fore.YELLOW))
    if not confirm("Yakin?", default=False):
        log("INFO", "Batal.")
        return False

    del vault[name]
    if _save_vault(vault, master):
        _audit("delete", name)
        log("OK", f"Entri '{name}' dihapus.")
        return True
    return False

def cmd_generate() -> None:
    """Generate password kuat secara mandiri."""
    print(c("\n  Generate Password Kuat\n", Fore.CYAN, bold=True))
    length_str  = prompt("Panjang (8-64)", default="20")
    use_symbols = confirm("Sertakan simbol (!@#...)?", default=True)
    count_str   = prompt("Berapa password yang dibuat?", default="1")

    try:
        length = max(8, min(64, int(length_str)))
        count  = max(1, min(20, int(count_str)))
    except ValueError:
        length, count = 20, 1

    print(c(f"\n  {count} password kuat:\n", Fore.WHITE))
    for i in range(count):
        pwd = secure_random_password(length, use_symbols)
        print(c(f"  {i+1:>2}. {pwd}", Fore.GREEN, bold=True))

    if count == 1 and confirm("\n  Copy ke clipboard?", default=True):
        pwd = secure_random_password(length, use_symbols)
        if copy_to_clipboard(pwd):
            log("OK", "Tersalin ke clipboard")
        else:
            log("INFO", "xclip/xsel tidak tersedia")

def cmd_check(vault: Dict) -> None:
    """Cek kesehatan vault: password lemah, duplikat, dll."""
    if not vault:
        log("INFO", "Vault kosong.")
        return

    print(c(f"\n  Memeriksa {len(vault)} entri...\n", Fore.CYAN))

    issues = []
    passwords: Dict[str, List[str]] = {}  # password → list of names

    COMMON_PASSWORDS = {
        "password","123456","password123","admin","letmein",
        "qwerty","monkey","welcome","login","test123",
        "abc123","111111","000000","iloveyou","sunshine",
    }

    for name, entry in vault.items():
        pwd = entry.get("password","")

        # Kumpulkan untuk deteksi duplikat
        if pwd:
            passwords.setdefault(pwd, []).append(name)

        # Password terlalu pendek
        if len(pwd) < 8:
            issues.append(("KRITIS", name, "Password terlalu pendek (< 8 karakter)"))
        elif len(pwd) < 12:
            issues.append(("SEDANG", name, "Password pendek (< 12 karakter)"))

        # Password umum
        if pwd.lower() in COMMON_PASSWORDS:
            issues.append(("KRITIS", name, "Password sangat umum dan mudah ditebak"))

        # Tidak ada variasi karakter
        if pwd and pwd.isdigit():
            issues.append(("TINGGI", name, "Password hanya angka"))
        if pwd and pwd.isalpha() and pwd == pwd.lower():
            issues.append(("SEDANG", name, "Password hanya huruf kecil"))

        # Placeholder
        if pwd.lower() in ("password","pass","12345","test","change_me","todo"):
            issues.append(("TINGGI", name, f"Password placeholder: '{pwd}'"))

        # Entri sangat lama (> 1 tahun tidak diperbarui)
        created = entry.get("created_at","")
        if created:
            try:
                age_days = (datetime.now() - datetime.fromisoformat(created)).days
                if age_days > 365:
                    issues.append(("INFO", name,
                        f"Password berumur {age_days} hari — pertimbangkan untuk ganti"))
            except (ValueError, TypeError):
                pass

    # Duplikat
    for pwd, names in passwords.items():
        if len(names) > 1:
            for name in names:
                issues.append(("TINGGI", name,
                    f"Password duplikat dipakai di: {', '.join(names)}"))

    # Tampilkan hasil
    if not issues:
        print(c("  ✓  Semua password terlihat baik!", Fore.GREEN, bold=True))
        return

    sev_order = {"KRITIS": 0, "TINGGI": 1, "SEDANG": 2, "INFO": 3}
    issues.sort(key=lambda x: sev_order.get(x[0], 4))

    SEV_C = {"KRITIS": Fore.RED, "TINGGI": Fore.RED,
              "SEDANG": Fore.YELLOW, "INFO": Fore.WHITE}
    kritis = sum(1 for s,_,_ in issues if s == "KRITIS")
    tinggi = sum(1 for s,_,_ in issues if s == "TINGGI")

    print(c(f"  Ditemukan {len(issues)} masalah:", Fore.YELLOW, bold=True))
    print(c(f"  KRITIS: {kritis}  TINGGI: {tinggi}\n", Fore.WHITE))

    for sev, name, desc in issues:
        col = SEV_C.get(sev, Fore.WHITE)
        print(c(f"  [{sev:<7}] {name:<25}  {desc}", col))

    print(c(f"\n  💡 Gunakan 'generate' untuk buat password kuat baru,", Fore.CYAN))
    print(c(  "     lalu 'add' untuk update entri yang bermasalah.", Fore.CYAN))

# ── Session dengan auto-lock ──────────────────────────────────────────────────

class VaultSession:
    """Session vault dengan auto-lock setelah idle."""

    def __init__(self, master: str, vault: Dict):
        self.master      = master
        self.vault       = vault
        self._last_use   = time.time()
        self._lock       = threading.Lock()
        self._locked     = False
        self._timer      = threading.Thread(target=self._auto_lock, daemon=True)
        self._timer.start()

    def _auto_lock(self):
        while not self._locked:
            time.sleep(10)
            with self._lock:
                if time.time() - self._last_use > AUTO_LOCK_SEC:
                    self._locked = True
                    print(c("\n\n  🔒 Vault otomatis dikunci setelah 5 menit tidak aktif.",
                            Fore.YELLOW))
                    sys.exit(0)

    def touch(self):
        with self._lock:
            self._last_use = time.time()

# ── Interactive menu ──────────────────────────────────────────────────────────

def interactive_mode(vault: Dict, master: str) -> None:
    """Mode interaktif vault."""
    session = VaultSession(master, vault)

    MENU = """
  Pilih aksi:
  [a] add      — tambah password baru
  [g] get      — ambil password
  [l] list     — lihat semua entri
  [d] delete   — hapus entri
  [n] generate — buat password kuat
  [c] check    — cek kesehatan vault
  [q] quit     — keluar & kunci vault
"""
    while True:
        session.touch()
        print(c(MENU, Fore.WHITE))
        try:
            choice = input(c("  Pilih [a/g/l/d/n/c/q]: ", Fore.YELLOW)).strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        session.touch()

        if not choice or choice == "q":
            break
        elif choice in ("a","add"):
            cmd_add(vault, master)
        elif choice in ("g","get"):
            name = prompt("Nama entri").strip()
            if name:
                cmd_get(vault, master, name)
        elif choice in ("l","list"):
            cmd_list(vault)
        elif choice in ("d","delete"):
            name = prompt("Nama entri yang akan dihapus").strip()
            if name:
                cmd_delete(vault, master, name)
        elif choice in ("n","generate"):
            cmd_generate()
        elif choice in ("c","check"):
            cmd_check(vault)
        else:
            log("WARN", f"Pilihan tidak dikenal: '{choice}'")

    print(c("\n  🔒 Vault dikunci. Sampai jumpa!\n", Fore.CYAN))

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Vault — Password manager terenkripsi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/vault.py
  python scripts/vault.py add
  python scripts/vault.py get gmail
  python scripts/vault.py list
  python scripts/vault.py delete github
  python scripts/vault.py generate
  python scripts/vault.py check"""
    )
    parser.add_argument("command",  nargs="?",
                        choices=["add","get","list","delete","generate","check"],
                        help="Perintah langsung (opsional)")
    parser.add_argument("name",     nargs="?", help="Nama entri (untuk get/delete)")
    args = parser.parse_args()

    log_header("Selene — Vault v3.0",
               "Password manager terenkripsi AES-256-GCM")

    if not HAS_CRYPTO:
        log("ERROR", "Library 'cryptography' tidak tersedia.")
        log("INFO",  "Install: pip install cryptography")
        sys.exit(1)

    # Minta master password
    is_new = not VAULT_FILE.exists()
    if is_new:
        print(c("""
  Selamat datang di Selene Vault!

  Vault belum ada — kamu akan membuat vault baru.
  Master password adalah SATU-SATUNYA kunci vault kamu.
  Jika lupa, data TIDAK BISA dipulihkan.
""", Fore.WHITE))
        master = prompt_password("Buat master password")
        if not master:
            log("ERROR", "Master password tidak boleh kosong.")
            sys.exit(1)
        if len(master) < 8:
            log("WARN", "Master password sangat pendek (< 8 karakter) — risiko rendah")
        verify = prompt_password("Ulangi master password")
        if master != verify:
            log("ERROR", "Password tidak cocok.")
            sys.exit(1)
        vault = {}
        _save_vault(vault, master)
        _audit("vault_created")
        log("OK", c("Vault baru berhasil dibuat!", Fore.GREEN, bold=True))
    else:
        master = prompt_password("Master password")
        if not master:
            log("ERROR", "Master password tidak boleh kosong.")
            sys.exit(1)
        vault = _load_vault(master)
        if vault is None:
            log("ERROR", "Master password salah atau vault korup.")
            sys.exit(1)
        _audit("vault_opened")
        log("OK", c(f"Vault terbuka. {len(vault)} entri tersimpan.", Fore.GREEN))

    # Dispatch command
    if args.command == "add" or (not args.command and not VAULT_FILE.exists()):
        cmd_add(vault, master)
    elif args.command == "get":
        if args.name:
            cmd_get(vault, master, args.name)
        else:
            log("ERROR", "Tentukan nama entri: vault.py get <nama>")
    elif args.command == "list":
        cmd_list(vault)
    elif args.command == "delete":
        if args.name:
            cmd_delete(vault, master, args.name)
        else:
            log("ERROR", "Tentukan nama entri: vault.py delete <nama>")
    elif args.command == "generate":
        cmd_generate()
    elif args.command == "check":
        cmd_check(vault)
    else:
        interactive_mode(vault, master)

    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print(c("\n  🔒 Vault dikunci.\n", Fore.CYAN))
    except Exception as e:
        log("ERROR", f"Error: {e}")
        if "--debug" in sys.argv:
            import traceback; traceback.print_exc()
