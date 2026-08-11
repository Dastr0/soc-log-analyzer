#!/usr/bin/env python3
"""
SOC Log Analyzer v0.2.0 — Multi-source log analysis untuk SOC.

Usage:
  python3 main.py analyze --source wazuh --file alerts.json
  python3 main.py analyze --dir exports/
  python3 main.py parse --source wazuh --file alerts.json
  python3 main.py init
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Tuple

from src.schema import CommonEvent, Incident
from src.parsers.wazuh import WazuhParser
from src.parsers.fortigate import FortiGateParser
from src.parsers.windows import WindowsParser
from src.parsers.csv_elastic import CsvElasticParser
from src.normalizer import normalize_wazuh, normalize_fortigate, normalize_windows
from src.correlation import correlate
from src.detection import detect
from src.reporter import report


# ─── Parser Registry ───────────────────────────────────────────────
# Nambah source baru: tinggal daftarin di sini + buat parser class-nya.

PARSER_MAP = {
    "wazuh": WazuhParser,
    "fortigate": FortiGateParser,
    "windows": WindowsParser,
}

NORMALIZER_MAP = {
    "wazuh": normalize_wazuh,
    "fortigate": normalize_fortigate,
    "windows": normalize_windows,
}

SUPPORTED_SOURCES = sorted(PARSER_MAP.keys())


# ─── Main Commands ─────────────────────────────────────────────────

def cmd_analyze(args: argparse.Namespace) -> None:
    """Command: analyze — full pipeline parse → correlate → detect → report."""
    start_time = time.time()

    # --- Collect file:source pairs ---
    pairs: List[Tuple[str, str]] = []
    if args.file and args.source:
        pairs.append((args.source, args.file))
    elif args.dir:
        dir_path = Path(args.dir)
        if not dir_path.is_dir():
            print(f"[!] Error: '{args.dir}' bukan direktori.")
            sys.exit(1)
        for f in sorted(dir_path.iterdir()):
            if f.is_file():
                source = _detect_source(f.name)
                if source:
                    pairs.append((source, str(f)))
                else:
                    print(f"[!] Skip: '{f.name}' — format nggak dikenali (coba --source manual).")
    else:
        print("[!] Error: harus kasih --file + --source ATAU --dir")
        sys.exit(1)

    if not pairs:
        print("[!] Error: nggak ada file log yang ditemukan.")
        sys.exit(1)

    # --- Parse + Normalize ---
    all_events: List[CommonEvent] = []
    total_raw = 0
    total_skipped = 0

    for source, filepath in pairs:
        parser_cls = PARSER_MAP.get(source)
        normalizer_fn = NORMALIZER_MAP.get(source)

        is_csv = filepath.lower().endswith(".csv")

        if is_csv:
            # ── CSV path: auto-detect source dari kolom ──
            print(f"\n[⏳] Parsing CSV: {filepath} (auto-detect source...)")
            csv_parser = CsvElasticParser(filepath, source_hint=source)
            raw_events = list(csv_parser.parse())
            detected = csv_parser.detected_source or "unknown"
            parsed = csv_parser.parsed
            skipped = csv_parser.skipped
            total_raw += parsed
            total_skipped += skipped

            print(f"[✓] CSVParsed: {parsed:,} events ({skipped} skipped) "
                  f"→ detected source: {detected}")

            # Pilih normalizer dari source terdeteksi
            if detected not in NORMALIZER_MAP:
                print(f"[!] Source terdeteksi '{detected}' belum ada normalizernya. Skip.")
                continue

            normalizer_fn = NORMALIZER_MAP[detected]
            print(f"[⏳] Normalizing as: {detected}...")
            source_events = []
            for raw in raw_events:
                try:
                    event = normalizer_fn(raw)
                    source_events.append(event)
                except Exception:
                    total_skipped += 1

            all_events.extend(source_events)
            print(f"[✓] Normalized: {len(source_events):,} common events")

        else:
            # ── Native path (JSONL / syslog) ──
            if not parser_cls or not normalizer_fn:
                print(f"[!] Parser untuk source '{source}' belum tersedia.")
                continue

            print(f"\n[⏳] Parsing: {filepath} ({source})")
            parser = parser_cls(filepath)

            raw_events = list(parser.parse())
            parsed = parser.parsed
            skipped = parser.skipped
            total_raw += parsed
            total_skipped += skipped

            print(f"[✓] Parsed: {parsed:,} events ({skipped} skipped) "
                  f"dari {Path(filepath).name}")

            # Normalize
            print(f"[⏳] Normalizing...")
            source_events = []
            for raw in raw_events:
                try:
                    event = normalizer_fn(raw)
                    source_events.append(event)
                except Exception:
                    total_skipped += 1

            all_events.extend(source_events)
            print(f"[✓] Normalized: {len(source_events):,} common events")

    if not all_events:
        print("[!] Nggak ada event yang berhasil diparse dari semua file.")
        sys.exit(1)

    print(f"\n{'─' * 50}")
    print(f"[i] Total: {total_raw:,} raw events → {len(all_events):,} common events "
          f"({total_skipped} skipped/corrupt)")

    # --- Correlation ---
    print(f"\n[⏳] Correlating events into incidents...")
    incidents = correlate(all_events)
    print(f"[✓] Correlation: {len(incidents)} incidents found "
          f"({sum(i.event_count for i in incidents):,} events grouped)")

    # --- Detection ---
    print(f"\n[⏳] Running detection engine...")
    trusted_config = _load_trusted_config()
    detect(incidents, all_events, trusted_config)

    n_confirmed = sum(1 for i in incidents if i.verdict == "CONFIRMED")
    n_likely_true = sum(1 for i in incidents if i.verdict == "LIKELY_TRUE")
    n_likely_fp = sum(1 for i in incidents if i.verdict == "LIKELY_FP")
    n_fp = sum(1 for i in incidents if i.verdict == "FALSE_POSITIVE")

    print(f"[✓] Detection: {n_confirmed} CONFIRMED, "
          f"{n_likely_true} LIKELY_TRUE, "
          f"{n_likely_fp} LIKELY_FP, "
          f"{n_fp} FALSE_POSITIVE")

    elapsed = time.time() - start_time
    print(f"\n[i] Analysis completed in {elapsed:.1f}s")

    # --- Report ---
    output_file = args.output if hasattr(args, 'output') and args.output else None

    # Filter per-insiden kalau --incident dipakai
    if hasattr(args, 'incident') and args.incident:
        target = [i for i in incidents if i.id == args.incident]
        if not target:
            print(f"[!] Insiden #{args.incident} tidak ditemukan. "
                  f"Insiden yang ada: {', '.join(str(i.id) for i in incidents)}")
            sys.exit(1)
        incidents = target

    report(incidents, all_events, detail=args.detail, verbose=args.verbose,
           output_file=output_file)

    if output_file:
        print(f"\n[✓] Output disimpan ke: {output_file}")


def cmd_parse(args: argparse.Namespace) -> None:
    """Command: parse — cuma parse + normalize, output JSON."""
    if not args.file or not args.source:
        print("[!] Error: butuh --file dan --source.")
        sys.exit(1)

    is_csv = args.file.lower().endswith(".csv")

    if is_csv:
        # CSV → auto-detect source → normalize
        sys.stderr.write(f"[⏳] Parsing CSV: {args.file} (auto-detect)...\n")
        csv_parser = CsvElasticParser(args.file, source_hint=args.source)
        raw_events = list(csv_parser.parse())
        detected = csv_parser.detected_source or "unknown"
        sys.stderr.write(f"[✓] Parsed: {len(raw_events)} events → {detected}\n")

        if detected not in NORMALIZER_MAP:
            print(f"[!] Source '{detected}' belum ada normalizer. "
                  f"Support: {', '.join(NORMALIZER_MAP)}")
            sys.exit(1)
        normalizer_fn = NORMALIZER_MAP[detected]
    else:
        # Native JSONL/syslog
        parser_cls = PARSER_MAP.get(args.source)
        normalizer_fn = NORMALIZER_MAP.get(args.source)

        if not parser_cls or not normalizer_fn:
            print(f"[!] Parser untuk '{args.source}' belum tersedia. "
                  f"Support: {', '.join(SUPPORTED_SOURCES)}")
            sys.exit(1)

        sys.stderr.write(f"[⏳] Parsing: {args.file}\n")
        parser = parser_cls(args.file)
        raw_events = list(parser.parse())
        sys.stderr.write(f"[✓] Parsed: {len(raw_events)} events\n")

    sys.stderr.write(f"[⏳] Normalizing...\n")
    events = []
    for raw in raw_events:
        try:
            event = normalizer_fn(raw)
            events.append({
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "dst_host": event.dst_host,
                "dst_port": event.dst_port,
                "user": event.user,
                "action": event.action,
                "severity": event.severity,
            })
        except Exception:
            pass

    output = json.dumps(events, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        sys.stderr.write(f"[✓] Output saved: {args.output}\n")
    else:
        print(output)


def cmd_init(args: argparse.Namespace) -> None:
    """Command: init — bikin file konfigurasi template."""
    import os.path

    # trusted_hosts.yaml
    trusted_path = Path("config/trusted_hosts.yaml")
    if not trusted_path.exists():
        trusted_content = """# Trusted Hosts — IP/host yang dikenal aman.
# Isi dengan IP scanner, subnet admin, atau host internal yg nggak mencurigakan.

# Host yang sudah dikenal aman (vuln scanner, monitoring, dll)
known_scanners:
  ips: []
  #  - 10.0.1.50   # SIEM-NESSUS
  subnets: []
  #  - 10.0.3.0/24 # SEC-TEAM-SUBNET

# Host internal yang di-trust (admin, monitoring, SIEM sendiri)
trusted_hosts:
  ips: []
  #  - 10.0.2.10    # MONITOR-PRTG
  subnets: []
  #  - 10.0.0.0/8   # Internal network
"""
        trusted_path.parent.mkdir(parents=True, exist_ok=True)
        trusted_path.write_text(trusted_content)
        print(f"[✓] Created: {trusted_path}")
    else:
        print(f"[i] Already exists: {trusted_path}")

    # detection rules (placeholder)
    rules_path = Path("config/rules/detection.yaml")
    if not rules_path.exists():
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_content = """# Detection Rules v0.2.0
# Nambah rules baru: tinggal tambah entry. Nggak perlu ubah kode.

patterns:
  - name: brute_force
    description: "Brute force attack (multiple login failures)"
    action: login_failed
    min_events: 10
    window_minutes: 15

  - name: port_scan
    description: "Port scan / reconnaissance"
    min_unique_ports: 10
    window_minutes: 5

  - name: suspicious_process
    description: "Suspicious process execution"
    process_keywords:
      - powershell -enc
      - wmic
      - rundll32
      - certutil
      - schtasks
    window_minutes: 60

  - name: priv_escalation
    description: "Privilege escalation"
    action: priv_escalation
    min_severity: 3
    window_minutes: 60
"""
        rules_path.write_text(rules_content)
        print(f"[✓] Created: {rules_path}")
    else:
        print(f"[i] Already exists: {rules_path}")


def cmd_sample(args: argparse.Namespace) -> None:
    """Command: sample — generate sample alerts untuk testing."""
    from src.sample_data import generate_sample, generate_sample_fortigate, generate_sample_windows

    sources = args.source or ["wazuh", "fortigate", "windows"]

    for source in sources:
        if source == "wazuh":
            out = args.output or "data/sample-wazuh-alerts.json"
            generate_sample(out)
            print(f"[✓] Wazuh sample: {out}")
        elif source == "fortigate":
            out = "data/sample-fortigate-fw.log"
            generate_sample_fortigate(out)
            print(f"[✓] FortiGate sample: {out}")
        elif source == "windows":
            out = "data/sample-windows-security.json"
            generate_sample_windows(out)
            print(f"[✓] Windows sample: {out}")

    print(f"\n[i] Run:")
    if "wazuh" in sources:
        print(f"    python3 main.py analyze -s wazuh -f data/sample-wazuh-alerts.json [--detail]")
    if "fortigate" in sources:
        print(f"    python3 main.py analyze -s fortigate -f data/sample-fortigate-fw.log [--detail]")
    if "windows" in sources:
        print(f"    python3 main.py analyze -s windows -f data/sample-windows-security.json [--detail]")


# ─── Helpers ────────────────────────────────────────────────────────

def _detect_source(filename: str) -> str:
    """Auto-detect source type dari nama file."""
    f = filename.lower()
    if "wazuh" in f or "alert" in f and f.endswith(".json"):
        return "wazuh"
    if "fortigate" in f or "fg-" in f or "fw.log" in f or "forti" in f:
        return "fortigate"
    if "windows" in f or "win" in f or "security" in f or "sysmon" in f:
        return "windows"
    if "cyberark" in f or "pam" in f:
        return "cyberark"
    if f.endswith(".json") and not any(k in f for k in ["wazuh", "forti", "win", "cyber"]):
        return "wazuh"  # default: assume Wazuh JSONL
    return ""


def _load_trusted_config() -> dict:
    """Load config/trusted_hosts.yaml kalau ada."""
    import yaml
    config_path = Path("config/trusted_hosts.yaml")
    if config_path.exists():
        try:
            return yaml.safe_load(config_path.read_text()) or {}
        except Exception:
            pass
    return {}


# ─── CLI Setup ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="soc-log-analyzer",
        description="Analisa log multi-source untuk SOC (Elastic + Wazuh).",
    )
    sub = parser.add_subparsers(dest="command", help="Sub-command")

    # --- analyze ---
    a = sub.add_parser("analyze", help="Parse, correlate, detect, and report")
    a.add_argument("-s", "--source", choices=SUPPORTED_SOURCES, help="Tipe log source")
    a.add_argument("-f", "--file", help="Path ke file log")
    a.add_argument("--dir", help="Path ke direktori berisi file log (auto-detect source)")
    a.add_argument("--detail", action="store_true",
                   help="Tampilkan detail per insiden (Level 2)")
    a.add_argument("--verbose", action="store_true",
                   help="Tampilkan semua event per insiden (Level 3)")
    a.add_argument("--incident", type=int,
                   help="Hanya tampilkan insiden dengan ID ini (cek --detail dulu)")
    a.add_argument("--output", help="Simpan output ke file")

    # --- parse ---
    p = sub.add_parser("parse", help="Hanya parse + normalize, output JSON")
    p.add_argument("-s", "--source", choices=SUPPORTED_SOURCES, required=True)
    p.add_argument("-f", "--file", required=True)
    p.add_argument("-o", "--output", help="Simpan ke file (default: stdout)")

    # --- init ---
    sub.add_parser("init", help="Buat file konfigurasi template")

    # --- sample ---
    s = sub.add_parser("sample", help="Generate sample data Wazuh untuk testing")
    s.add_argument("--source", choices=SUPPORTED_SOURCES, nargs="+",
                   help="Source yang mau digenerate (default: semua)")
    s.add_argument("--output", help="Path output (hanya untuk --source wazuh)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "parse":
        cmd_parse(args)
    elif args.command == "init":
        cmd_init(args)
    elif args.command == "sample":
        cmd_sample(args)


if __name__ == "__main__":
    main()
