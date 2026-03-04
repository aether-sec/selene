#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════════╗
║   Selene — Incident Response v3.0                            ║
║   Otomasi dan panduan respons insiden keamanan.              ║
╚════════════════════════════════════════════════════════════════╝

Cara pakai:
  python scripts/incident_response.py
  sudo python scripts/incident_response.py --contain --ip 10.0.0.5
  python scripts/incident_response.py --collect
  python scripts/incident_response.py --report
  python scripts/incident_response.py --playbook brute_force
"""

import sys, os, re, subprocess, shutil, time, argparse, json, tarfile, io
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from selene.core import (
        log, log_section, log_header, c, Fore,
        confirm, write_alert, save_json, load_json,
        append_jsonl, read_jsonl, Spinner,
        IS_LINUX, IS_WINDOWS, IS_ROOT, IS_ANDROID,
        get_local_ip, REPORTS_DIR, LOGS_DIR,
    )
    from selene.core.config import get_config
except ImportError as e:
    print(f"\n  [ERROR] {e}\n  Jalankan dari direktori root Selene.\n"); sys.exit(1)

try:
    import psutil; HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

TOOL_VERSION  = "3.0.0"
IR_LOG        = LOGS_DIR / "incident_response.jsonl"
IR_CASES_DIR  = REPORTS_DIR / "ir_cases"

SEVERITY_LEVELS = ["KRITIS","TINGGI","SEDANG","RENDAH"]

# ── Playbook database ─────────────────────────────────────────────────────────
PLAYBOOKS = {
    "brute_force": {
        "name":        "Brute Force / Password Attack",
        "indicators":  ["Banyak login gagal dalam waktu singkat","IP asing mencoba akses SSH/RDP/FTP"],
        "severity":    "TINGGI",
        "steps": [
            ("DETEKSI",  "Cek log auth: grep 'Failed' /var/log/auth.log | tail -50"),
            ("DETEKSI",  "Identifikasi IP penyerang: grep 'Failed' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20"),
            ("KONTAINMEN","Blokir IP: sudo iptables -I INPUT -s <IP> -j DROP"),
            ("KONTAINMEN","Aktifkan fail2ban jika belum: sudo systemctl enable --now fail2ban"),
            ("KONTAINMEN","Tambah MaxAuthTries 3 di /etc/ssh/sshd_config"),
            ("ERADIKASI", "Ganti password semua akun jika ada login yang berhasil"),
            ("ERADIKASI", "Cek apakah ada akun baru dibuat: cat /etc/passwd | grep -v nologin"),
            ("RECOVERY",  "Restart SSH: sudo systemctl restart sshd"),
            ("RECOVERY",  "Monitor log selama 24 jam ke depan"),
            ("LAPORAN",   "Dokumentasikan: waktu serangan, IP, user yang diserang, tindakan"),
        ],
    },
    "malware": {
        "name":        "Malware / Ransomware",
        "indicators":  ["File berubah massal","Proses tidak dikenal menggunakan CPU tinggi",
                        "Koneksi ke IP asing yang tidak dikenal","File dienkripsi"],
        "severity":    "KRITIS",
        "steps": [
            ("DETEKSI",   "Isolasi mesin dari jaringan SEGERA: cabut kabel LAN / matikan WiFi"),
            ("DETEKSI",   "Jangan restart mesin — ransomware mungkin menghapus jejak saat boot"),
            ("DETEKSI",   "Ambil screenshot/foto layar sebagai bukti awal"),
            ("KONTAINMEN","Identifikasi proses: ps aux | sort -k3 -rn | head -20"),
            ("KONTAINMEN","Cek koneksi keluar: ss -tunap atau netstat -tunap"),
            ("KONTAINMEN","Kill proses mencurigakan: sudo kill -9 <PID>"),
            ("ERADIKASI", "Boot dari live USB untuk scan malware tanpa menjalankan OS"),
            ("ERADIKASI", "Scan dengan ClamAV: sudo clamscan -r /home --bell -i"),
            ("ERADIKASI", "Cek file yang berubah dalam 24 jam: find / -newer /tmp -type f 2>/dev/null"),
            ("RECOVERY",  "Restore dari backup SETELAH memastikan sistem bersih"),
            ("RECOVERY",  "Ganti semua password setelah mesin bersih"),
            ("LAPORAN",   "Laporkan ke BSSN (Indonesia) jika menyangkut infrastruktur kritis"),
        ],
    },
    "data_breach": {
        "name":        "Kebocoran Data / Data Breach",
        "indicators":  ["Data sensitif ditemukan di internet","Akses tidak sah ke database",
                        "Notifikasi dari pihak ketiga tentang kebocoran data"],
        "severity":    "KRITIS",
        "steps": [
            ("DETEKSI",   "Konfirmasi kebocoran: verifikasi data yang diduga bocor"),
            ("DETEKSI",   "Tentukan scope: data apa yang bocor, berapa banyak, milik siapa"),
            ("DETEKSI",   "Cek log akses database: lihat query tidak normal"),
            ("KONTAINMEN","Ubah semua kredensial yang terdampak segera"),
            ("KONTAINMEN","Revoke API key / token yang mungkin bocor"),
            ("KONTAINMEN","Block IP yang mengakses data tanpa izin"),
            ("ERADIKASI", "Patch vulnerability yang menyebabkan kebocoran"),
            ("ERADIKASI", "Audit semua akses ke data sensitif"),
            ("RECOVERY",  "Notifikasi pengguna yang terdampak dalam 72 jam (GDPR/UU PDP)"),
            ("RECOVERY",  "Implementasi enkripsi data at-rest jika belum ada"),
            ("LAPORAN",   "Buat laporan insiden untuk regulasi jika diperlukan"),
            ("LAPORAN",   "Review dan perbarui kebijakan keamanan data"),
        ],
    },
    "unauthorized_access": {
        "name":        "Akses Tidak Sah / Unauthorized Access",
        "indicators":  ["Login berhasil dari IP/lokasi tidak biasa","Akun admin digunakan di luar jam kerja",
                        "Perubahan konfigurasi tanpa izin"],
        "severity":    "TINGGI",
        "steps": [
            ("DETEKSI",   "Identifikasi sesi aktif: who -a atau query-session (Windows)"),
            ("DETEKSI",   "Cek login sukses dari IP asing: grep 'Accepted' /var/log/auth.log"),
            ("KONTAINMEN","Terminate sesi tidak sah: pkill -u <username> atau logoff /server"),
            ("KONTAINMEN","Lock akun yang dikompromikan: sudo passwd -l <username>"),
            ("KONTAINMEN","Ganti password segera: sudo passwd <username>"),
            ("ERADIKASI", "Cek perubahan yang dibuat: cari file baru, user baru, cron baru"),
            ("ERADIKASI", "Review dan revoke SSH authorized_keys"),
            ("RECOVERY",  "Aktifkan MFA untuk semua akun"),
            ("RECOVERY",  "Review dan perketat kebijakan password"),
            ("LAPORAN",   "Dokumentasikan akses: dari mana, kapan, apa yang dilakukan"),
        ],
    },
    "ddos": {
        "name":        "DDoS / Serangan Volume Tinggi",
        "indicators":  ["Server tidak bisa diakses","Traffic sangat tinggi dari banyak IP",
                        "CPU/RAM/Bandwidth habis"],
        "severity":    "TINGGI",
        "steps": [
            ("DETEKSI",   "Konfirmasi DDoS: mtr <IP_SERVER> atau ping untuk cek konektivitas"),
            ("DETEKSI",   "Identifikasi traffic: tcpdump -nn -i eth0 | head -100"),
            ("DETEKSI",   "Cek IP sumber: netstat -ntu | awk '{print $5}' | sort | uniq -c | sort -rn"),
            ("KONTAINMEN","Aktifkan rate limiting: iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT"),
            ("KONTAINMEN","Block IP sumber: for ip in $(netstat -ntu | ...); do iptables -A INPUT -s $ip -j DROP; done"),
            ("KONTAINMEN","Hubungi ISP/datacenter untuk null routing jika serangan sangat besar"),
            ("ERADIKASI", "Aktifkan CDN/WAF seperti Cloudflare jika belum"),
            ("RECOVERY",  "Monitor traffic setelah serangan mereda"),
            ("LAPORAN",   "Dokumentasikan durasi, sumber, dampak, tindakan"),
        ],
    },
    "insider_threat": {
        "name":        "Insider Threat / Ancaman Orang Dalam",
        "indicators":  ["Karyawan/ex-karyawan mengakses data di luar tugasnya",
                        "Download data dalam jumlah besar","Akses di luar jam kerja"],
        "severity":    "TINGGI",
        "steps": [
            ("DETEKSI",   "Identifikasi akun dan akses yang mencurigakan"),
            ("DETEKSI",   "Review log akses: siapa yang mengakses data apa dan kapan"),
            ("KONTAINMEN","Suspend akun yang dicurigai: sudo passwd -l <user>"),
            ("KONTAINMEN","Preserve semua bukti digital sebelum menghubungi yang bersangkutan"),
            ("KONTAINMEN","Jangan hapus log — ini bukti hukum"),
            ("ERADIKASI", "Revoke semua akses: password, API key, SSH key, VPN"),
            ("ERADIKASI", "Audit: apakah data sudah di-exfiltrate?"),
            ("RECOVERY",  "Review dan perketat access control / least privilege"),
            ("LAPORAN",   "Konsultasikan dengan legal sebelum tindakan formal"),
            ("LAPORAN",   "Laporkan ke kepolisian jika ada indikasi tindak pidana"),
        ],
    },
}

# ── Evidence collection ───────────────────────────────────────────────────────

def collect_evidence(case_id: str) -> Optional[Path]:
    """
    Kumpulkan bukti digital: proses, koneksi, log, file mencurigakan.
    Simpan ke tarball terenkompres untuk analisis forensik.
    """
    case_dir = IR_CASES_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    evidence_files = []

    def _run_save(cmd: List[str], outname: str, shell: bool = False):
        try:
            r = subprocess.run(
                cmd if not shell else " ".join(cmd),
                capture_output=True, text=True, timeout=10,
                shell=shell, errors="ignore"
            )
            out = r.stdout + r.stderr
            if out.strip():
                fpath = case_dir / outname
                fpath.write_text(out)
                evidence_files.append(fpath)
        except Exception as e:
            (case_dir / f"{outname}.error").write_text(str(e))

    log("SCAN", "Mengumpulkan bukti digital...")

    # Timestamp pengumpulan
    (case_dir / "collection_time.txt").write_text(
        f"Waktu pengumpulan: {datetime.now().isoformat()}\n"
        f"Hostname: {os.uname().nodename if IS_LINUX else os.environ.get('COMPUTERNAME','?')}\n"
        f"IP lokal: {get_local_ip()}\n"
    )

    if IS_LINUX:
        _run_save(["ps", "auxf"],                           "processes.txt")
        _run_save(["ss", "-tunap"],                         "connections.txt")
        _run_save(["netstat", "-rn"],                       "routing.txt")
        _run_save(["who", "-a"],                            "logged_in_users.txt")
        _run_save(["last", "-n", "50"],                     "recent_logins.txt")
        _run_save(["lastb", "-n", "50"],                    "failed_logins.txt")
        _run_save(["cat", "/etc/passwd"],                   "users.txt")
        _run_save(["crontab", "-l"],                        "crontab_root.txt")
        _run_save(["systemctl", "list-units", "--failed"],  "failed_services.txt")
        _run_save(["dmesg", "-T"],                          "dmesg.txt")
        _run_save(["iptables", "-L", "-n", "-v"],           "firewall_rules.txt")
        _run_save(["find", "/tmp", "-type", "f",
                   "-newer", "/proc/1"],                    "new_tmp_files.txt")
        _run_save(["find", "/root/.ssh",
                   "-type", "f"],                           "root_ssh_files.txt")

        # Copy log penting
        for log_file in ["/var/log/auth.log", "/var/log/syslog",
                          "/var/log/kern.log"]:
            src = Path(log_file)
            if src.exists():
                try:
                    dst = case_dir / src.name
                    import shutil as sh
                    sh.copy2(str(src), str(dst))
                    evidence_files.append(dst)
                except Exception:
                    pass

    elif IS_WINDOWS:
        _run_save(["tasklist", "/v"],               "processes.txt")
        _run_save(["netstat", "-ano"],              "connections.txt")
        _run_save(["net", "user"],                  "users.txt")
        _run_save(["systeminfo"],                   "sysinfo.txt")
        _run_save(["ipconfig", "/all"],             "ipconfig.txt")

    # Selene logs
    for selene_log in [LOGS_DIR / "alerts.jsonl",
                        LOGS_DIR / "honeypot_captures.jsonl"]:
        if selene_log.exists():
            try:
                import shutil as sh
                sh.copy2(str(selene_log), str(case_dir / selene_log.name))
                evidence_files.append(case_dir / selene_log.name)
            except Exception:
                pass

    # Buat tarball
    tar_path = IR_CASES_DIR / f"{case_id}_evidence.tar.gz"
    try:
        with tarfile.open(str(tar_path), "w:gz") as tar:
            for ef in evidence_files + [case_dir / "collection_time.txt"]:
                if ef.exists():
                    tar.add(str(ef), arcname=ef.name)
        log("OK", c(f"Bukti dikumpulkan: {tar_path.name}", Fore.GREEN, bold=True))
        return tar_path
    except Exception as e:
        log("ERROR", f"Gagal membuat tarball: {e}")
        return case_dir

def contain_ip(ip: str) -> bool:
    """Blokir IP segera menggunakan iptables / netsh."""
    if not IS_ROOT:
        log("ERROR", "Kontainmen butuh root/admin.")
        return False

    log("SCAN", c(f"Memblokir IP: {ip}", Fore.RED, bold=True))

    if IS_LINUX and shutil.which("iptables"):
        try:
            for chain in ["INPUT", "OUTPUT", "FORWARD"]:
                subprocess.run(
                    ["iptables", "-I", chain, "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=5
                )
            log("OK", c(f"IP {ip} diblokir di semua chain iptables", Fore.GREEN))
            # Simpan aturan jika tersedia
            if shutil.which("iptables-save"):
                out = subprocess.run(["iptables-save"], capture_output=True, text=True)
                Path("/etc/iptables/rules.v4").write_text(out.stdout)
            write_alert("CRIT", f"IR: IP {ip} dikontain/diblokir")
            return True
        except Exception as e:
            log("ERROR", f"iptables gagal: {e}")
            return False

    elif IS_WINDOWS:
        rule_name = f"Selene_IR_Block_{ip.replace('.','_')}"
        try:
            subprocess.run(
                ["netsh","advfirewall","firewall","add","rule",
                 f"name={rule_name}","dir=in","action=block",
                 f"remoteip={ip}","enable=yes"],
                capture_output=True, timeout=10
            )
            log("OK", c(f"IP {ip} diblokir via Windows Firewall", Fore.GREEN))
            return True
        except Exception as e:
            log("ERROR", f"netsh gagal: {e}")
            return False

    log("WARN", "Tidak bisa blokir IP — iptables/netsh tidak tersedia")
    return False

# ── Playbook runner ───────────────────────────────────────────────────────────

def run_playbook(playbook_key: str, context: Dict = None) -> None:
    """Tampilkan dan jalankan playbook interaktif."""
    pb = PLAYBOOKS.get(playbook_key)
    if not pb:
        log("ERROR", f"Playbook '{playbook_key}' tidak ditemukan.")
        log("INFO",  f"Tersedia: {', '.join(PLAYBOOKS.keys())}")
        return

    print(c(f"\n  ╔══ PLAYBOOK: {pb['name']} ══════════════════════════", Fore.CYAN, bold=True))
    print(c(f"  ║  Severity: {pb['severity']}", Fore.RED if pb['severity']=="KRITIS" else Fore.YELLOW))
    print(c(f"  ╠══ INDIKATOR ──────────────────────────────────────", Fore.CYAN))
    for ind in pb["indicators"]:
        print(c(f"  ║  • {ind}", Fore.WHITE))
    print(c(f"  ╚══════════════════════════════════════════════════", Fore.CYAN))

    # Langkah per fase
    phases = {}
    for phase, step in pb["steps"]:
        phases.setdefault(phase, []).append(step)

    phase_colors = {
        "DETEKSI":    Fore.CYAN,
        "KONTAINMEN": Fore.YELLOW,
        "ERADIKASI":  Fore.MAGENTA,
        "RECOVERY":   Fore.GREEN,
        "LAPORAN":    Fore.WHITE,
    }

    step_num = 0
    for phase, steps in phases.items():
        col = phase_colors.get(phase, Fore.WHITE)
        print(c(f"\n  [{phase}]", col, bold=True))
        for step in steps:
            step_num += 1
            # Replace placeholder
            if context:
                for k, v in context.items():
                    step = step.replace(f"<{k}>", v)
            print(c(f"  {step_num:>2}. {step}", col))

    print(c(f"\n  Total: {step_num} langkah dalam {len(phases)} fase", Fore.WHITE))

# ── Active incident: new case ─────────────────────────────────────────────────

def create_incident_case(title: str, severity: str,
                          description: str, tags: List[str] = None) -> str:
    """Buat kasus insiden baru."""
    IR_CASES_DIR.mkdir(parents=True, exist_ok=True)
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    case_id = f"IR-{ts}"

    case = {
        "case_id":     case_id,
        "title":       title,
        "severity":    severity,
        "description": description,
        "tags":        tags or [],
        "status":      "OPEN",
        "created_at":  datetime.now().isoformat(),
        "updated_at":  datetime.now().isoformat(),
        "timeline":    [{
            "time":   datetime.now().isoformat(),
            "actor":  "system",
            "action": "Kasus dibuka",
        }],
        "containment_actions": [],
        "affected_ips":        [],
    }

    case_file = IR_CASES_DIR / f"{case_id}.json"
    save_json(case_file, case)
    append_jsonl(IR_LOG, {"timestamp": datetime.now().isoformat(),
                           "event": "case_created", "case_id": case_id})

    log("OK", c(f"Kasus baru dibuat: {case_id}", Fore.GREEN, bold=True))
    write_alert("CRIT" if severity == "KRITIS" else "WARN",
                f"Insiden baru: [{severity}] {title}", details=case)
    return case_id

def generate_ir_report() -> Optional[Path]:
    """Generate laporan ringkasan semua kasus insiden."""
    if not IR_CASES_DIR.exists():
        log("INFO", "Belum ada kasus insiden.")
        return None

    cases = []
    for f in IR_CASES_DIR.glob("IR-*.json"):
        data = load_json(f, {})
        if data:
            cases.append(data)

    if not cases:
        log("INFO", "Tidak ada kasus yang ditemukan.")
        return None

    cases.sort(key=lambda c: c.get("created_at",""), reverse=True)

    log_section(f"LAPORAN INSIDEN ({len(cases)} kasus)")
    for case in cases:
        sev = case.get("severity","?")
        col = Fore.RED if sev == "KRITIS" else Fore.YELLOW
        status = case.get("status","?")
        print(c(f"\n  [{case['case_id']}]", col, bold=True))
        print(c(f"    [{sev}] {case.get('title','?')}", col))
        print(c(f"    Status  : {status}", Fore.GREEN if status == "CLOSED" else Fore.YELLOW))
        print(c(f"    Dibuat  : {case.get('created_at','?')[:16]}", Fore.WHITE))
        print(c(f"    Tags    : {', '.join(case.get('tags',[]))}", Fore.WHITE))

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"ir_report_{ts}.json"
    save_json(path, {"tool":"incident_response","version":TOOL_VERSION,
                     "generated":datetime.now().isoformat(),"cases":cases})
    log("OK", c(f"Laporan IR: reports/ir_report_{ts}.json", Fore.GREEN))
    return path

# ── Interactive mode ──────────────────────────────────────────────────────────

def interactive_mode() -> None:
    """Mode interaktif untuk manajemen insiden."""
    while True:
        print(c("""
  ┌─ Incident Response ──────────────────────────────┐
  │  [1] Buat kasus insiden baru                     │
  │  [2] Jalankan playbook                            │
  │  [3] Kumpulkan bukti digital                      │
  │  [4] Blokir IP (kontainmen)                      │
  │  [5] Lihat semua kasus                            │
  │  [6] Keluar                                       │
  └──────────────────────────────────────────────────┘
""", Fore.WHITE))
        choice = input(c("  Pilih [1-6]: ", Fore.YELLOW)).strip()

        if choice == "6" or not choice:
            break

        elif choice == "1":
            print(c("\n  Buat Kasus Insiden Baru\n", Fore.CYAN, bold=True))
            from selene.core import prompt
            title   = prompt("Judul insiden")
            sev     = input(c("  Severity [KRITIS/TINGGI/SEDANG/RENDAH]: ", Fore.YELLOW)).strip().upper()
            if sev not in SEVERITY_LEVELS:
                sev = "TINGGI"
            desc    = prompt("Deskripsi singkat")
            tags    = [t.strip() for t in input(c("  Tags (pisahkan koma): ", Fore.YELLOW)).split(",")]
            case_id = create_incident_case(title, sev, desc, tags)
            print(c(f"\n  Kasus dibuat: {case_id}", Fore.GREEN, bold=True))

        elif choice == "2":
            print(c("\n  Playbook tersedia:", Fore.CYAN))
            for key, pb in PLAYBOOKS.items():
                print(c(f"    {key:<22}  {pb['name']}", Fore.WHITE))
            key = input(c("\n  Masukkan nama playbook: ", Fore.YELLOW)).strip().lower()
            if key:
                run_playbook(key)

        elif choice == "3":
            from selene.core import prompt
            case_id = prompt("Case ID (contoh: IR-20240101_120000)")
            if case_id:
                with Spinner("Mengumpulkan bukti..."):
                    result = collect_evidence(case_id)
                if result:
                    print(c(f"\n  Bukti: {result}", Fore.GREEN))

        elif choice == "4":
            ip = input(c("  IP yang akan diblokir: ", Fore.YELLOW)).strip()
            if ip:
                if confirm(c(f"Blokir {ip} sekarang?", Fore.RED), default=False):
                    contain_ip(ip)

        elif choice == "5":
            generate_ir_report()
        else:
            log("WARN", "Pilihan tidak valid")

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Selene Incident Response — Respons insiden keamanan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python scripts/incident_response.py
  python scripts/incident_response.py --playbook brute_force
  python scripts/incident_response.py --playbook malware
  sudo python scripts/incident_response.py --contain --ip 10.0.0.5
  python scripts/incident_response.py --collect --case IR-20240101
  python scripts/incident_response.py --report"""
    )
    parser.add_argument("--playbook", metavar="NAMA", help=f"Jalankan playbook ({', '.join(PLAYBOOKS)})")
    parser.add_argument("--contain",  action="store_true", help="Mode kontainmen")
    parser.add_argument("--ip",       help="IP yang dikontain (untuk --contain)")
    parser.add_argument("--collect",  action="store_true", help="Kumpulkan bukti digital")
    parser.add_argument("--case",     help="Case ID untuk pengumpulan bukti")
    parser.add_argument("--report",   action="store_true", help="Tampilkan semua kasus insiden")
    parser.add_argument("--new",      action="store_true", help="Buat kasus insiden baru")
    args = parser.parse_args()

    log_header("Selene — Incident Response v3.0",
               "Deteksi, kontain, eradikasi, dan pulihkan dari insiden keamanan")

    if args.playbook:
        run_playbook(args.playbook, {"IP": args.ip or "<IP_PENYERANG>"})
    elif args.contain:
        if not args.ip:
            log("ERROR", "Tentukan IP: --contain --ip <IP>")
            sys.exit(1)
        contain_ip(args.ip)
    elif args.collect:
        case_id = args.case or f"IR-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        with Spinner("Mengumpulkan bukti..."):
            result = collect_evidence(case_id)
        if result:
            log("OK", c(f"Bukti tersimpan di: {result}", Fore.GREEN))
    elif args.report:
        generate_ir_report()
    elif args.new:
        from selene.core import prompt
        title   = prompt("Judul insiden")
        desc    = prompt("Deskripsi")
        sev     = "TINGGI"
        case_id = create_incident_case(title, sev, desc)
        log("OK", f"Kasus dibuat: {case_id}")
    else:
        interactive_mode()

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
