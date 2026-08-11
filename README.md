# SOC Log Analyzer v0.2.0

Tool/automation untuk analisa log dari berbagai sumber (multi log source) di stack
Elastic + Wazuh.

Fitur: parse → normalize → correlate → detect → executive summary (3 level output)
+ False Positive heuristik (100% offline, no API).

## Quickstart

```bash
# Generate sample data untuk testing
python3 main.py sample

# Analisa command:
python3 main.py analyze --source wazuh --file data/sample-wazuh-alerts.json
python3 main.py analyze --source wazuh --file data/alerts.json --detail
python3 main.py analyze --source wazuh --file data/alerts.json --verbose

# Auto-detect semua file di folder + export
python3 main.py analyze --dir exports/ --output report.csv

# Cuma parse + normalize (output JSON)
python3 main.py parse --source wazuh --file data/alerts.json

# Bikin config template
python3 main.py init
```

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
| FortiGate | syslog | planned |
| Windows EventLog | EVTX / JSON | planned |
| Linux auth/syslog | syslog | planned |
| CyberArk PAM | JSON / syslog | planned |

## Keamanan

- Repo ini PUBLIC — kode bisa dilihat siapa saja. Hati-hati dengan yang di-commit.
- JANGAN commit log asli / IP internal / username / data produksi.
- Semua secret lewat `.env` — jangan hardcode.
- Sample data harus di-sanitasi. `data/` di-gitignore.
