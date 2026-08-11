# SOC Log Analyzer v0.2.0

Tool/automation untuk analisa log dari berbagai sumber (multi log source) di stack
Elastic + Wazuh.

Fitur: parse → normalize → correlate → detect → executive summary (3 level output)
+ False Positive heuristik (100% offline, no API).

## Cara Pakai (Usage)

### Instalasi

```bash
# Butuh Python 3.10+ dan pip
pip install -r requirements.txt
# atau kalau pakai Ubuntu/Debian:
sudo apt install python3-yaml   # pyyaml via apt
```

### 1. Coba dengan data sample (testing)

```bash
# Generate sample data untuk ketiga source
python3 main.py sample

# Hasilnya:
#   data/sample-wazuh-alerts.json    (29 event, 3 insiden)
#   data/sample-fortigate-fw.log     (17 event)
#   data/sample-windows-security.json (12 event)
```

### 2. Analisa log per source

```bash
# Wazuh HIDS — export alerts.json dari Elastic
python3 main.py analyze -s wazuh -f data/sample-wazuh-alerts.json

# FortiGate — syslog key=value (export firewall log dari Elastic)
python3 main.py analyze -s fortigate -f data/sample-fortigate-fw.log

# Windows EventLog — format Wazuh JSONL ATAU winlogbeat generic
python3 main.py analyze -s windows -f data/sample-windows-security.json
```

Ganti `data/sample-*.json` dengan file log asli hasil export Elastic.
Format file yang didukung:

| Source | Format file | Nama file yang dikenali auto-detect |
|--------|------------|--------------------------------------|
| wazuh | JSONL (satu JSON per baris) | `*.json` (default), `*wazuh*`, `*alert*` |
| fortigate | syslog key=value per baris | `*fortigate*`, `*forti*`, `*fw.log*` |
| windows | JSONL (Wazuh/winlogbeat) | `*windows*`, `*security*`, `*sysmon*` |

### 3. Level output (kedalaman analisa)

```bash
# Level 1 — Executive Summary (default): ringkasan insiden + verdict FP/TP
python3 main.py analyze -s wazuh -f file.json

# Level 2 — Detail: timeline, metrik, reasoning FP, sample raw event per insiden
python3 main.py analyze -s wazuh -f file.json --detail

# Level 3 — Verbose: semua event per insiden (forensik / cross-check)
python3 main.py analyze -s wazuh -f file.json --verbose

# Lihat detail 1 insiden tertentu aja
python3 main.py analyze -s wazuh -f file.json --incident 1 --verbose
```

### 4. Analisa multi-source sekaligus

```bash
# Auto-detect semua file di folder (campur source bebas)
python3 main.py analyze --dir exports/

# Contoh folder yang bisa diproses sekaligus:
#   exports/wazuh-alerts.json
#   exports/fortigate-fw.log
#   exports/windows-security.json

# Simpan output ke file
python3 main.py analyze --dir exports/ --output report.txt
```

Korelasi cross-source otomatis: event dari source berbeda yang
melibatkan (src_ip, dst_host) yang sama dalam window waktu akan
digabung jadi 1 insiden — dan dapat bonus skor cross-source
confirmation di FP detection.

### 5. Cuma parse + normalize (tanpa analisa)

```bash
# Output JSON terstruktur (buat dipakai tool lain / Excel)
python3 main.py parse -s wazuh -f file.json
python3 main.py parse -s fortigate -f fw.log --output parsed.json
python3 main.py parse -s windows -f security.json --output parsed.json
```

### 6. Konfigurasi

```bash
# Bikin template config (kalau belum ada)
python3 main.py init
```

Edit `config/trusted_hosts.yaml` — ini KUNCI akurasi FP detection.
Isi IP scanner, monitoring, dan host internal yang dikenal aman:

```yaml
known_scanners:      # vulnerability scanner & tools otomatis
  ips:
    - 10.0.1.50      # SIEM-NESSUS (daily scheduled scan)
  subnets:
    - 10.0.3.0/24    # SecOps lab subnet

trusted_hosts:       # host internal yang di-trust
  ips:
    - 10.0.2.10      # MONITOR-PRTG (network monitoring)
  subnets:
    - 10.0.0.0/8     # All internal networks
```

Makin lengkap config ini, makin jarang false alarm dari aktivitas
internal yang sah (scan berkala, maintenance, monitoring).

## Arsitektur

```
                           ┌─────────────────────┐
  alerts.json ──────────→  │ WazuhParser         │
  (JSONL)                  │ (src/parsers/wazuh) │
                           └────────┬────────────┘
                                    │ raw dict
                                    ▼
                           ┌─────────────────────┐
                           │ Normalizer          │
                           │ (src/normalizer.py) │
                           └────────┬────────────┘
                                    │ CommonEvent
                                    ▼
                           ┌─────────────────────┐
                           │ Correlation Engine  │
                           │ (src/correlation.py)│
                           └────────┬────────────┘
                                    │ Incidents
                                    ▼
                           ┌─────────────────────┐
                           │ Detection Engine    │  ← config/rules/detection.yaml
                           │ (src/detection.py)  │  ← config/trusted_hosts.yaml
                           │ · detect_pattern()  │
                           │ · fp_scoring()      │  (100% OFFLINE)
                           │ · get_verdict()     │
                           └────────┬────────────┘
                                    │
                                    ▼
                           ┌─────────────────────┐
                           │ Reporter            │
                           │ (src/reporter.py)   │
                           │ · Level 1: Summary  │
                           │ · Level 2: Detail   │
                           │ · Level 3: Verbose  │
                           └─────────────────────┘
```

## False Positive Detection (offline)

Verdict dihitung dari 20+ indikator heuristik yang semuanya
berjalan lokal (tidak ada API call ke internet).

Indikator True Positive:  IP eksternal · port sensitif · user beragam ·
  user admin · di luar jam kerja · jumlah besar · durasi panjang ·
  severity escalation · persistent failures · cross-source confirmation

Indikator False Positive: IP internal + trusted host · jam kerja ·
  user-agent scanner (Nessus/Qualys/etc) · pola predictable/cron ·
  one-hit wonder · process maintenance · rule description update/backup

Score 0-100 → VERDICT:
  ≥75 CONFIRMED | 50-74 LIKELY_TRUE | 26-49 LIKELY_FP | ≤25 FALSE_POSITIVE

## Struktur project

```
soc-log-analyzer/
├── main.py              # entry point CLI
├── src/
│   ├── schema.py        # CommonEvent & Incident dataclass
│   ├── normalizer.py    # raw event → CommonEvent
│   ├── correlation.py   # event grouping engine
│   ├── detection.py     # pattern detection + FP scoring
│   ├── reporter.py      # output formatter (3 level)
│   ├── sample_data.py   # sample Wazuh alert generator
│   └── parsers/
│       ├── base.py      # abstract parser interface
│       └── wazuh.py     # Wazuh alerts.json parser
├── config/
│   ├── .env.example
│   ├── trusted_hosts.yaml
│   └── rules/detection.yaml
├── data/               # gitignored — sample log, output
└── requirements.txt
```

## Log source (roadmap)

| Source | Format | Status |
|--------|--------|--------|
| Wazuh HIDS | JSONL (alerts.json) | ✅ v0.2.0 |
| FortiGate | syslog (key=value) | ✅ v0.2.1 |
| Windows EventLog | Wazuh JSONL / Elastic JSON | ✅ v0.2.1 |
| Linux auth/syslog | syslog | planned |
| CyberArk PAM | JSON / syslog | planned |

## Keamanan

- Repo ini PUBLIC — kode bisa dilihat siapa saja. Hati-hati dengan yang di-commit.
- JANGAN commit log asli / IP internal / username / data produksi.
- Semua secret lewat `.env` — jangan hardcode.
- Sample data harus di-sanitasi. `data/` di-gitignore.
