# Changelog

Semua perubahan penting pada Selene Security Suite akan dicatat di sini.

Format: `[vX.Y.Z] - YYYY-MM-DD`

---

## [v3.0.0] - 2026-03-04

### Ditambahkan
- 22 tools security dalam satu suite terpadu
- Web dashboard real-time (`dashboard.py`) — buka di browser, auto-refresh 10 detik
- Health score system dengan 8 kategori dan grade A+ hingga F
- Report engine — generate laporan HTML, JSON, dan TXT
- Port guardian — monitor port dengan deteksi perubahan dari baseline
- User auditor — audit akun, sudo privilege, dan password
- Privacy audit — deteksi data sensitif yang tidak sengaja tersimpan
- Incident response — 6 playbook terstruktur (brute force, malware, DDoS, dll)

### Diperbaiki
- `hash_verifier.py`: fungsi `collect_files()` dan `should_exclude()` sekarang bisa dipanggil tanpa argumen `excludes` (default `None`)
- `report_engine.py`: fixed NameError di HTML generation untuk nested f-string

### Teknis
- 12.725+ baris kode Python
- 27/27 test check lulus (22 import + 5 integration)
- 0 syntax error di seluruh codebase
- Dashboard: 26.652 bytes HTML, API `/api/data` dan `/api/ping`

---

## [v2.0.0] - sebelumnya

- 15 tools (batch 1–3): selene, setup_wizard, network_scanner, system_profiler,
  vuln_scanner, security_hardener, credential_checker, threat_monitor, honeypot,
  wifi_analyzer, vault, secure_backup, hash_verifier, log_forensics, threat_intel
