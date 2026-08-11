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
from src.normalizer import normalize_wazuh
from src.correlation import correlate
from src.detection import detect
from src.reporter import report


# ─── Parser Registry ───────────────────────────────────────────────
# Nambah source baru: tinggal daftarin di sini + buat parser class-nya.

PARSER_MAP = {
    "wazuh": WazuhParser,
}

NORMALIZER_MAP = {
    "wazuh": normalize_wazuh,
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

        if not parser_cls or not normalizer_fn:
            print(f"[!] Parser untuk source '{source}' belum tersedia.")
            continue

        print(f"\n[⏳] Parsing: {filepath} ({source})")
        parser = parser_cls(filepath)

        raw_events = list(parser.parse())  # konsumsi generator
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
            except Exception as exc:
                skipped += 1
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
    report(incidents, all_events, detail=args.detail, verbose=args.verbose,
           output_file=output_file)

    if output_file:
        print(f"\n[✓] Output disimpan ke: {output_file}")


def cmd_parse(args: argparse.Namespace) -> None:
    """Command: parse — cuma parse + normalize, output JSON."""
    if not args.file or not args.source:
        print("[!] Error: butuh --file dan --source.")
        sys.exit(1)

    parser_cls = PARSER_MAP.get(args.source)
    normalizer_fn = NORMALIZER_MAP.get(args.source)

    if not parser_cls or not normalizer_fn:
        print(f"[!] Parser untuk '{args.source}' belum tersedia. "
              f"Support: {', '.join(SUPPORTED_SOURCES)}")
        sys.exit(1)

    print(f"[⏳] Parsing: {args.file}")
    parser = parser_cls(args.file)
    raw_events = list(parser.parse())
    print(f"[✓] Parsed: {len(raw_events)} events")

    print(f"[⏳] Normalizing...")
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
        print(f"[✓] Output: {args.output}")
    else:
        print(output[:5000])
        if len(output) > 5000:
            print("... (truncated for display, use --output to save full result)")


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
    """Command: sample — generate sample Wazuh alerts buat testing."""
    from src.sample_data import generate_sample
    output_path = args.output or "data/sample-wazuh-alerts.json"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    generate_sample(output_path)
    print(f"[✓] Sample data: {output_path}")
    print(f"[i] Jalankan: python3 main.py analyze --source wazuh --file {output_path}")


# ─── Helpers ────────────────────────────────────────────────────────

def _detect_source(filename: str) -> str:
    """Auto-detect source type dari nama file."""
    f = filename.lower()
    if "wazuh" in f or "alert" in f and f.endswith(".json"):
        return "wazuh"
    # Placeholder untuk parser future
    # if "fortigate" in f or "fw.log" in f:
    #     return "fortigate"
    # if "cyberark" in f or "pam" in f:
    #     return "cyberark"
    return ""  # nggak dikenali


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
    a.add_argument("--source", choices=SUPPORTED_SOURCES, help="Tipe log source")
    a.add_argument("--file", help="Path ke file log")
    a.add_argument("--dir", help="Path ke direktori berisi file log (auto-detect source)")
    a.add_argument("--detail", action="store_true",
                   help="Tampilkan detail per insiden (Level 2)")
    a.add_argument("--verbose", action="store_true",
                   help="Tampilkan semua event per insiden (Level 3)")
    a.add_argument("--output", help="Simpan output ke file")

    # --- parse ---
    p = sub.add_parser("parse", help="Hanya parse + normalize, output JSON")
    p.add_argument("--source", choices=SUPPORTED_SOURCES, required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--output", help="Simpan ke file (default: stdout)")

    # --- init ---
    sub.add_parser("init", help="Buat file konfigurasi template")

    # --- sample ---
    s = sub.add_parser("sample", help="Generate sample data Wazuh untuk testing")
    s.add_argument("--output", help="Path output (default: data/sample-wazuh-alerts.json)")

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
