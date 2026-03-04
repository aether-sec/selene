<div align="center">

# 🌙 Selene Security Suite

**Toolkit keamanan sistem berbasis terminal — 22 tools, satu perintah.**

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-GPL%20v3-green?style=flat-square)](LICENSE)
[![Tools](https://img.shields.io/badge/Tools-22-cyan?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)]()

*Dirancang untuk developer dan sysadmin yang ingin melindungi server mereka — tanpa harus jadi pakar security.*

</div>

---

## Apa itu Selene?

Selene adalah kumpulan 22 tools security yang bekerja bersama dalam satu sistem terpadu. Mulai dari memantau ancaman secara real-time, mengaudit keamanan sistem, menyimpan password dengan enkripsi, hingga merespons insiden secara terstruktur — semua bisa dijalankan dari terminal dengan satu menu interaktif.

**Selene cocok untuk:**
- Developer yang punya VPS atau server dan ingin tahu kondisi keamanannya
- Sysadmin yang butuh tools monitoring tanpa setup yang rumit
- Siapapun yang ingin belajar security melalui tools yang bisa langsung dipakai

---

## Instalasi Cepat

**Persyaratan:** Python 3.8+, pip

```bash
# Clone repo
git clone https://github.com/aether-sec/selene.git
cd selene

# Install dependencies
pip install -r requirements.txt

# Setup awal (hanya perlu sekali)
python scripts/setup_wizard.py

# Jalankan menu utama
python scripts/selene.py
```

---

## 22 Tools dalam Satu Suite

### 🔍 KENALI — Pahami sistemmu
| Tool | Fungsi |
|------|--------|
| `network_scanner.py` | Scan jaringan lokal, temukan device dan port terbuka |
| `system_profiler.py` | Profil lengkap sistem: OS, hardware, service, user |

### 🛡️ CEGAH — Sebelum diserang
| Tool | Fungsi |
|------|--------|
| `vuln_scanner.py` | Deteksi kerentanan: SSH lemah, permission salah, CVE umum |
| `security_hardener.py` | Auto-hardening Linux berdasarkan best practice |
| `credential_checker.py` | Cek password bocor via HaveIBeenPwned |

### 👁️ DETEKSI — Tangkap serangan aktif
| Tool | Fungsi |
|------|--------|
| `threat_monitor.py` | IDS real-time: deteksi brute force, port scan, anomali |
| `honeypot.py` | SSH/HTTP/FTP/MySQL palsu untuk jebak penyerang |
| `wifi_analyzer.py` | Deteksi rogue access point dan enkripsi lemah |

### 🔒 LINDUNGI — Amankan data penting
| Tool | Fungsi |
|------|--------|
| `vault.py` | Password manager terenkripsi AES-256-GCM |
| `secure_backup.py` | Backup terenkripsi dengan verifikasi integritas |
| `hash_verifier.py` | Pantau perubahan file penting (FIM) |
| `privacy_audit.py` | Deteksi data sensitif yang tidak sengaja tersimpan |

### 🔬 INVESTIGASI — Analisis pasca insiden
| Tool | Fungsi |
|------|--------|
| `log_forensics.py` | Rekonstruksi timeline serangan dari log sistem |
| `threat_intel.py` | OSINT: cek reputasi IP, domain, dan file hash |
| `incident_response.py` | 6 playbook respons insiden (brute force, malware, DDoS, dll) |

### 📋 KELOLA — Kontrol akses dan port
| Tool | Fungsi |
|------|--------|
| `port_guardian.py` | Pantau port terbuka, deteksi perubahan dari baseline |
| `user_auditor.py` | Audit akun user, sudo privilege, password lemah |

### 📊 PANTAU — Dashboard dan laporan
| Tool | Fungsi |
|------|--------|
| `dashboard.py` | Web dashboard real-time di browser (`http://localhost:7331`) |
| `health_score.py` | Skor keamanan 0–100 dengan rekomendasi prioritas |
| `report_engine.py` | Generate laporan HTML/JSON/TXT otomatis |

### ⚙️ KONFIGURASI
| Tool | Fungsi |
|------|--------|
| `setup_wizard.py` | Setup awal interaktif |

---

## Penggunaan Dasar

```bash
# Menu interaktif (pilih tool dari daftar)
python scripts/selene.py

# Langsung jalankan tool tertentu
python scripts/health_score.py               # Hitung skor keamanan
python scripts/dashboard.py                  # Buka web dashboard
python scripts/threat_monitor.py             # Mulai monitoring real-time
python scripts/vuln_scanner.py               # Scan kerentanan
python scripts/vault.py --add                # Tambah password baru

# Dashboard web (buka browser otomatis)
python scripts/dashboard.py
# → http://localhost:7331
```

---

## Web Dashboard

Jalankan `python scripts/dashboard.py` untuk membuka dashboard di browser:

- **Health Score** — Gauge animasi dengan grade A+ hingga F
- **Alert real-time** — Langsung dari log sistem, update tiap 10 detik  
- **Resource monitor** — CPU, RAM, Disk dengan progress bar live
- **Koneksi aktif** — Port mencurigakan otomatis ditandai merah
- **Rekomendasi** — Aksi prioritas berdasarkan kondisi sistem

---

## Health Score

```bash
python scripts/health_score.py
```

Menilai keamanan sistem dari 8 kategori:

```
  Firewall & Network   ████████████████░░░░  14/20
  SSH & Authentication ████████████████████  15/15
  Update & Patch       ██████████████░░░░░░  10/15
  Backup               ████████████████░░░░  12/15
  Monitoring           ████████████████░░░░   8/10
  Vulnerability        ████████████░░░░░░░░   6/10
  Privacy              ████████████████░░░░   8/10
  Incident Response    ░░░░░░░░░░░░░░░░░░░░   0/ 5

  Skor: 73/100  [B]  Cukup Aman
```

---

## Struktur Proyek

```
selene/
├── scripts/          # 22 tools Python
├── selene/
│   └── core/         # Modul inti (crypto, network, config, common)
├── data/             # File runtime (tidak di-commit)
├── logs/             # Log sistem (tidak di-commit)
├── reports/          # Output laporan (tidak di-commit)
├── requirements.txt
└── README.md
```

---

## Dependencies

```
colorama>=0.4.6    # Warna terminal
requests>=2.28.0   # HTTP client
psutil>=5.9.0      # System metrics
cryptography>=41.0.0  # Enkripsi AES-256
```

Install opsional untuk fitur lengkap:
```bash
pip install scapy   # ARP scan akurat (butuh root)
```

---

## Lisensi

Selene dirilis di bawah [GNU General Public License v3.0](LICENSE).

Bebas digunakan, dimodifikasi, dan didistribusikan — selama tetap open source dengan lisensi yang sama.

---

<div align="center">

**Dibuat oleh [aether-sec](https://github.com/aether-sec)**

*"Keamanan bukan tentang menjadi tidak terlihat — tapi tentang tahu siapa yang melihat."*

</div>
