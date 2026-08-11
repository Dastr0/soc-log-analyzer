# SOC Log Analyzer

Tool/automation untuk analisa log dari berbagai sumber (multi log source) di stack Elastic + Wazuh.

## Tujuan

Satu tempat untuk parsing, normalisasi, dan triage log dari berbagai source, biar analisa alert lebih cepat dan konsisten.

## Log source yang didukung (roadmap)

| Source | Format | Status |
|--------|--------|--------|
| Wazuh HIDS (alerts.json) | JSON | planned |
| FortiGate (firewall) | syslog / CSV | planned |
| CyberArk PAM | JSON / syslog | planned |
| ... | | |

## Struktur project

```
soc-log-analyzer/
├── main.py          # entry point CLI
├── parsers/         # parser per log source
│   ├── wazuh.py     # (soon)
│   ├── fortigate.py # (soon)
│   └── cyberark.py  # (soon)
├── config/          # config per source (contoh .env.example)
├── data/            # sample log (JANGAN commit data produksi/sensitif!)
└── requirements.txt
```

## Cara pakai (nanti)

```
python3 main.py --source wazuh --file data/alerts.json
python3 main.py --source fortigate --file data/fw.log
```

## Keamanan

- Repo ini PRIVATE.
- JANGAN pernah commit: log asli, IP internal, username, atau data produksi lain.
- Semua secret (API key Elastic/Wazuh, token) lewat `.env` — jangan hardcode.
- Sample data harus di-sanitasi dulu sebelum masuk `data/`.
