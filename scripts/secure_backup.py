#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Secure Backup v3.0                                ║
║   Backup terenkripsi AES-256-GCM + kompresi gzip.            ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/secure_backup.py backup              — backup sekarang
  python scripts/secure_backup.py restore <file>      — restore dari backup
  python scripts/secure_backup.py list                — daftar backup
  python scripts/secure_backup.py verify <file>       — verifikasi integritas
  python scripts/secure_backup.py schedule            — jadwal otomatis
  python scripts/secure_backup.py cleanup             — hapus backup lama

File backup: <timestamp>_<hostname>.ngbk
"""

import sys
import os
import io
import tarfile
import time
import argparse
import platform
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional, Dict

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, prompt, prompt_password,
        append_jsonl, read_jsonl, fmt_bytes, Spinner,
        LOGS_DIR,
    )
    from selene.core.crypto import encrypt, decrypt, HAS_CRYPTO
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n")
    sys.exit(1)

TOOL_VERSION  = "3.0.0"
BACKUP_EXT    = ".ngbk"
BACKUP_LOG    = LOGS_DIR / "backup_log.jsonl"
MAGIC_HEADER  = b"SLNE_BACKUP_V3\n"

# ── Backup ────────────────────────────────────────────────────────────────────

def create_backup(directories: List[str], destination: str,
                  password: str, label: str = "",
                  max_file_mb: int = 100,
                  excludes: List[str] = None) -> Optional[Path]:
    """
    Buat backup terenkripsi dari daftar direktori.

    Proses:
    1. Buat tar archive dalam memori (untuk keamanan, tidak ke disk)
    2. Compress dengan gzip
    3. Encrypt dengan AES-256-GCM
    4. Simpan ke file .ngbk

    Returns: Path file backup jika berhasil, None jika gagal.
    """
    if not HAS_CRYPTO:
        log("ERROR", "Library 'cryptography' diperlukan. Install: pip install cryptography")
        return None

    dest_dir = Path(destination)
    dest_dir.mkdir(parents=True, exist_ok=True)

    exclude_set = set(excludes or [])
    exclude_set.update(["*.pyc","__pycache__","*.log","*.tmp",".git",".DS_Store"])

    def _should_exclude(path: Path) -> bool:
        import fnmatch
        for pattern in exclude_set:
            if fnmatch.fnmatch(path.name, pattern):
                return True
            if fnmatch.fnmatch(str(path), pattern):
                return True
        return False

    max_bytes = max_file_mb * 1024 * 1024

    # Buat tar di memori
    log("SCAN", "Membuat archive...")
    buf = io.BytesIO()
    total_files = 0
    total_size  = 0
    skipped     = 0
    errors      = []

    try:
        with tarfile.open(fileobj=buf, mode="w:gz",
                          compresslevel=6) as tar:
            for dir_str in directories:
                dp = Path(dir_str)
                if not dp.exists():
                    log("WARN", f"Direktori tidak ditemukan: {dir_str}")
                    continue

                for item in dp.rglob("*"):
                    if not item.is_file():
                        continue
                    if _should_exclude(item):
                        skipped += 1
                        continue

                    # Lewati file terlalu besar
                    try:
                        size = item.stat().st_size
                    except OSError:
                        continue

                    if size > max_bytes:
                        log("INFO", f"  Dilewati (terlalu besar {fmt_bytes(size)}): {item.name}")
                        skipped += 1
                        continue

                    # Gunakan relative path dalam archive
                    arcname = str(item.relative_to(dp.parent))
                    try:
                        tar.add(str(item), arcname=arcname)
                        total_files += 1
                        total_size  += size
                    except (PermissionError, OSError) as e:
                        errors.append(str(item))
                        skipped += 1
                    except Exception as e:
                        errors.append(f"{item}: {e}")

    except Exception as e:
        log("ERROR", f"Gagal membuat archive: {e}")
        return None

    if total_files == 0:
        log("WARN", "Tidak ada file yang di-backup.")
        return None

    log("INFO", f"  {total_files} file  |  {fmt_bytes(total_size)} sebelum kompresi")
    log("INFO", f"  {skipped} file dilewati")

    # Siapkan data untuk enkripsi
    raw_data = buf.getvalue()
    log("INFO", f"  Archive: {fmt_bytes(len(raw_data))} (setelah kompresi)")

    # Tambahkan metadata header
    meta = {
        "version":    TOOL_VERSION,
        "created_at": datetime.now().isoformat(),
        "hostname":   platform.node(),
        "directories":directories,
        "file_count": total_files,
        "raw_size":   total_size,
        "label":      label,
    }
    import json
    meta_bytes = json.dumps(meta, ensure_ascii=False).encode("utf-8")

    # Format: MAGIC(15) + meta_len(4) + meta + tar_gz_data
    import struct
    payload = (
        MAGIC_HEADER
        + struct.pack(">I", len(meta_bytes))
        + meta_bytes
        + raw_data
    )

    # Enkripsi
    log("SCAN", "Mengenkripsi...")
    try:
        encrypted = encrypt(payload, password, compress=False)
    except Exception as e:
        log("ERROR", f"Enkripsi gagal: {e}")
        return None

    # Simpan file
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = platform.node().replace(" ","_")
    filename = f"{ts}_{hostname}{BACKUP_EXT}"
    outpath  = dest_dir / filename

    tmp = Path(str(outpath) + ".tmp")
    try:
        tmp.write_bytes(encrypted)
        tmp.replace(outpath)
        try:
            outpath.chmod(0o600)
        except Exception:
            pass
    except OSError as e:
        log("ERROR", f"Gagal menyimpan backup: {e}")
        return None

    final_size = outpath.stat().st_size
    ratio      = (1 - final_size / max(total_size, 1)) * 100

    log("OK", c(f"Backup berhasil: {outpath.name}", Fore.GREEN, bold=True))
    log("INFO", f"  Ukuran: {fmt_bytes(final_size)} (kompresi {ratio:.0f}%)")

    # Catat ke log
    append_jsonl(BACKUP_LOG, {
        "timestamp":   datetime.now().isoformat(),
        "action":      "backup",
        "file":        str(outpath),
        "file_count":  total_files,
        "raw_size":    total_size,
        "backup_size": final_size,
        "directories": directories,
        "errors":      len(errors),
    })

    if errors:
        log("WARN", f"{len(errors)} file tidak bisa di-backup (permission error)")

    return outpath

def restore_backup(backup_file: str, destination: str,
                   password: str) -> bool:
    """
    Restore backup dari file .ngbk.

    Returns True jika berhasil.
    """
    bpath = Path(backup_file)
    if not bpath.exists():
        log("ERROR", f"File tidak ditemukan: {backup_file}")
        return False

    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)

    log("SCAN", f"Membaca {bpath.name}...")

    # Baca dan dekripsi
    try:
        encrypted = bpath.read_bytes()
    except OSError as e:
        log("ERROR", f"Tidak bisa membaca file: {e}")
        return False

    log("SCAN", "Mendekripsi...")
    try:
        payload = decrypt(encrypted, password)
    except ValueError as e:
        log("ERROR", str(e))
        return False
    except Exception as e:
        log("ERROR", f"Dekripsi gagal: {e}")
        return False

    # Parse header
    import struct, json
    try:
        if not payload.startswith(MAGIC_HEADER):
            log("ERROR", "Bukan file backup Selene yang valid.")
            return False

        off      = len(MAGIC_HEADER)
        meta_len = struct.unpack(">I", payload[off:off+4])[0]
        off     += 4
        meta     = json.loads(payload[off:off+meta_len].decode("utf-8"))
        off     += meta_len
        tar_data = payload[off:]
    except Exception as e:
        log("ERROR", f"Format backup tidak valid: {e}")
        return False

    # Tampilkan info backup
    log("INFO", f"  Dibuat   : {meta.get('created_at','?')[:16]}")
    log("INFO", f"  Hostname : {meta.get('hostname','?')}")
    log("INFO", f"  File     : {meta.get('file_count','?')}")
    log("INFO", f"  Label    : {meta.get('label','—')}")
    dirs = meta.get("directories",[])
    log("INFO", f"  Direktori: {', '.join(dirs[:3])}")

    # Konfirmasi
    print(c(f"\n  Restore ke: {dest}", Fore.YELLOW))
    if not confirm("Lanjutkan restore?", default=True):
        log("INFO", "Restore dibatalkan.")
        return False

    # Extract tar
    log("SCAN", "Mengekstrak file...")
    try:
        buf = io.BytesIO(tar_data)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            # Safety check: tidak ada absolute path atau ../
            safe_members = []
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    log("WARN", f"Path tidak aman dilewati: {member.name}")
                    continue
                safe_members.append(member)

            tar.extractall(path=str(dest), members=safe_members)
            count = len(safe_members)
    except Exception as e:
        log("ERROR", f"Ekstrak gagal: {e}")
        return False

    log("OK", c(f"Restore selesai! {count} file diekstrak ke {dest}",
                Fore.GREEN, bold=True))

    append_jsonl(BACKUP_LOG, {
        "timestamp":   datetime.now().isoformat(),
        "action":      "restore",
        "source_file": backup_file,
        "destination": str(dest),
        "file_count":  count,
    })
    return True

def verify_backup(backup_file: str, password: str) -> bool:
    """Verifikasi integritas file backup tanpa mengekstrak."""
    bpath = Path(backup_file)
    if not bpath.exists():
        log("ERROR", f"File tidak ditemukan: {backup_file}")
        return False

    log("SCAN", f"Memverifikasi {bpath.name}...")

    try:
        encrypted = bpath.read_bytes()
    except OSError as e:
        log("ERROR", f"Tidak bisa membaca: {e}")
        return False

    try:
        payload = decrypt(encrypted, password)
        if not payload.startswith(MAGIC_HEADER):
            log("ERROR", "Magic header tidak valid.")
            return False

        import struct, json
        off      = len(MAGIC_HEADER)
        meta_len = struct.unpack(">I", payload[off:off+4])[0]
        off     += 4
        meta     = json.loads(payload[off:off+meta_len].decode("utf-8"))

        log("OK", c("Verifikasi berhasil! File backup valid.", Fore.GREEN, bold=True))
        log("INFO", f"  Dibuat   : {meta.get('created_at','?')[:16]}")
        log("INFO", f"  Hostname : {meta.get('hostname','?')}")
        log("INFO", f"  File     : {meta.get('file_count','?')}")
        return True

    except ValueError as e:
        log("ERROR", f"Verifikasi GAGAL: {e}")
        return False
    except Exception as e:
        log("ERROR", f"Error: {e}")
        return False

def list_backups(destination: str) -> List[Path]:
    """Tampilkan daftar file backup."""
    dest = Path(destination)
    if not dest.exists():
        log("WARN", f"Direktori tidak ditemukan: {destination}")
        return []

    backups = sorted(dest.glob(f"*{BACKUP_EXT}"), reverse=True)
    if not backups:
        log("INFO", "Tidak ada backup ditemukan.")
        return []

    total_size = sum(b.stat().st_size for b in backups)
    print(c(f"\n  {len(backups)} backup  |  Total: {fmt_bytes(total_size)}\n",
            Fore.WHITE))
    print(c(f"  {'NAMA FILE':<45} {'UKURAN':>10}  {'TANGGAL'}", Fore.CYAN))
    print(c(f"  {'─'*45} {'─'*10}  {'─'*16}", Fore.BLUE))

    for bp in backups:
        st   = bp.stat()
        size = fmt_bytes(st.st_size)
        mtime= datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
        print(c(f"  {bp.name:<45} {size:>10}  {mtime}", Fore.WHITE))

    return backups

def cleanup_old_backups(destination: str, keep_days: int = 30,
                         dry_run: bool = False) -> int:
    """Hapus backup yang lebih lama dari keep_days."""
    dest = Path(destination)
    if not dest.exists():
        return 0

    cutoff  = datetime.now() - timedelta(days=keep_days)
    backups = list(dest.glob(f"*{BACKUP_EXT}"))
    removed = 0

    for bp in backups:
        mtime = datetime.fromtimestamp(bp.stat().st_mtime)
        if mtime < cutoff:
            age = (datetime.now() - mtime).days
            if dry_run:
                log("INFO", f"Akan dihapus ({age} hari): {bp.name}")
            else:
                try:
                    bp.unlink()
                    log("OK", f"Dihapus ({age} hari): {bp.name}")
                    removed += 1
                except OSError as e:
                    log("WARN", f"Gagal hapus {bp.name}: {e}")

    if removed == 0 and not dry_run:
        log("OK", "Tidak ada backup lama yang perlu dihapus.")

    return removed

def schedule_backup(cfg) -> None:
    """Jalankan backup secara terjadwal (loop)."""
    interval_h = cfg.get("backup","schedule_h", default=24)
    if interval_h <= 0:
        log("ERROR", "Jadwal dinonaktifkan di konfigurasi (schedule_h = 0)")
        return

    log("INFO", c(f"Backup terjadwal setiap {interval_h} jam", Fore.CYAN))
    log("INFO", c("Tekan Ctrl+C untuk berhenti", Fore.WHITE))

    while True:
        log("SCAN", "Memulai backup terjadwal...")
        dirs = cfg.get("backup","directories", default=[])
        dest = cfg.get("backup","destination",  default="")

        if not dirs or not dest:
            log("WARN", "Direktori atau tujuan backup belum dikonfigurasi.")
            log("INFO", "Jalankan: python scripts/setup_wizard.py")
        else:
            password = prompt_password("Master password untuk enkripsi backup")
            if password:
                with Spinner("Membuat backup..."):
                    outpath = create_backup(dirs, dest, password,
                                            label="scheduled")
                if outpath:
                    log("OK", f"Backup selesai: {outpath.name}")
                    # Cleanup otomatis
                    keep_days = cfg.get("backup","keep_days", default=30)
                    removed   = cleanup_old_backups(dest, keep_days)
                    if removed:
                        log("OK", f"{removed} backup lama dihapus")
            else:
                log("WARN", "Password kosong — backup dilewati")

        next_run = datetime.now() + timedelta(hours=interval_h)
        log("INFO", f"Backup berikutnya: {next_run.strftime('%Y-%m-%d %H:%M')}")
        time.sleep(interval_h * 3600)

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Secure Backup — Backup terenkripsi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/secure_backup.py backup
  python scripts/secure_backup.py backup --dirs ~/Documents,~/Desktop
  python scripts/secure_backup.py restore backup.ngbk
  python scripts/secure_backup.py list
  python scripts/secure_backup.py verify backup.ngbk
  python scripts/secure_backup.py cleanup"""
    )
    parser.add_argument("command",
                        choices=["backup","restore","list","verify","cleanup","schedule"],
                        help="Perintah yang dijalankan")
    parser.add_argument("file",     nargs="?",
                        help="File backup (untuk restore/verify)")
    parser.add_argument("--dirs",   "-d",
                        help="Direktori yang di-backup, pisahkan dengan koma")
    parser.add_argument("--dest",   "-o",
                        help="Direktori tujuan backup")
    parser.add_argument("--label",  "-l", default="",
                        help="Label / deskripsi backup ini")
    parser.add_argument("--restore-to", metavar="DIR", default=".",
                        help="Direktori tujuan restore (default: direktori sekarang)")
    parser.add_argument("--keep-days",  type=int, default=None,
                        help="Hapus backup lebih tua dari N hari (untuk cleanup)")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Tampilkan apa yang akan dilakukan tanpa benar-benar melakukannya")
    args = parser.parse_args()

    log_header("Selene — Secure Backup v3.0",
               "Backup terenkripsi AES-256-GCM + kompresi gzip")

    if not HAS_CRYPTO:
        log("ERROR", "Library 'cryptography' tidak tersedia.")
        log("INFO",  "Install: pip install cryptography")
        sys.exit(1)

    cfg = get_config()

    # ── backup ────────────────────────────────────────────────────────────────
    if args.command == "backup":
        dirs = (
            [d.strip() for d in args.dirs.split(",")]
            if args.dirs
            else cfg.get("backup","directories", default=[])
        )
        dest = args.dest or cfg.get("backup","destination", default="")

        if not dirs:
            log("ERROR", "Tentukan direktori: --dirs ~/Documents,~/Desktop")
            log("INFO",  "Atau konfigurasi melalui: python scripts/setup_wizard.py")
            sys.exit(1)
        if not dest:
            dest = str(Path.home() / "selene_backups")
            log("INFO", f"Tujuan default: {dest}")

        # Filter direktori yang ada
        valid_dirs = [d for d in dirs if Path(d).exists()]
        invalid    = set(dirs) - set(valid_dirs)
        if invalid:
            log("WARN", f"Direktori tidak ditemukan: {', '.join(invalid)}")
        if not valid_dirs:
            log("ERROR", "Tidak ada direktori yang valid untuk di-backup.")
            sys.exit(1)

        log_section("MEMULAI BACKUP")
        log("INFO", f"Direktori: {', '.join(valid_dirs)}")
        log("INFO", f"Tujuan   : {dest}")

        password = prompt_password("Password enkripsi backup")
        if not password:
            log("ERROR", "Password tidak boleh kosong.")
            sys.exit(1)
        verify = prompt_password("Ulangi password")
        if password != verify:
            log("ERROR", "Password tidak cocok.")
            sys.exit(1)

        max_mb    = cfg.get("backup","max_file_mb", default=100)
        excludes  = cfg.get("backup","excludes",    default=[])
        with Spinner("Membuat backup terenkripsi..."):
            outpath = create_backup(valid_dirs, dest, password,
                                    label=args.label, max_file_mb=max_mb,
                                    excludes=excludes)
        if not outpath:
            sys.exit(1)

        # Cleanup otomatis
        keep_days = (args.keep_days
                     or cfg.get("backup","keep_days", default=30))
        if keep_days and keep_days > 0:
            removed = cleanup_old_backups(dest, keep_days, args.dry_run)
            if removed > 0:
                log("OK", f"{removed} backup lama dihapus (> {keep_days} hari)")

    # ── restore ───────────────────────────────────────────────────────────────
    elif args.command == "restore":
        if not args.file:
            log("ERROR", "Tentukan file backup: restore <file.ngbk>")
            sys.exit(1)
        password = prompt_password("Password dekripsi backup")
        if not password:
            log("ERROR", "Password tidak boleh kosong.")
            sys.exit(1)
        success = restore_backup(args.file, args.restore_to, password)
        if not success:
            sys.exit(1)

    # ── list ──────────────────────────────────────────────────────────────────
    elif args.command == "list":
        dest = args.dest or cfg.get("backup","destination", default="")
        if not dest:
            dest = str(Path.home() / "selene_backups")
        log_section(f"DAFTAR BACKUP: {dest}")
        list_backups(dest)

    # ── verify ────────────────────────────────────────────────────────────────
    elif args.command == "verify":
        if not args.file:
            log("ERROR", "Tentukan file: verify <file.ngbk>")
            sys.exit(1)
        password = prompt_password("Password backup")
        if not password:
            sys.exit(1)
        ok = verify_backup(args.file, password)
        sys.exit(0 if ok else 1)

    # ── cleanup ───────────────────────────────────────────────────────────────
    elif args.command == "cleanup":
        dest = args.dest or cfg.get("backup","destination", default="")
        if not dest:
            log("ERROR", "Tentukan direktori: --dest <dir>")
            sys.exit(1)
        keep = args.keep_days or cfg.get("backup","keep_days", default=30)
        log("INFO", f"Menghapus backup lebih tua dari {keep} hari dari {dest}")
        if args.dry_run:
            log("INFO", "MODE DRY-RUN — tidak ada yang dihapus")
        removed = cleanup_old_backups(dest, keep, args.dry_run)
        if not args.dry_run:
            log("OK", f"{removed} backup dihapus.")

    # ── schedule ──────────────────────────────────────────────────────────────
    elif args.command == "schedule":
        try:
            schedule_backup(cfg)
        except KeyboardInterrupt:
            print()
            log("INFO", "Jadwal dihentikan.")

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
