#!/usr/bin/env python3
"""
CSV Field Inspector — analisa struktur CSV export Elastic Discover.

Gunakan:
  python3 csv_inspect.py export.csv

Output:
  - Nama kolom (mapping: ada di YAML/built-in atau nggak?)
  - Sample 3 baris pertama (buat liat nilai real)
  - Proyeksi: berapa banyak baris yang bakal lolos ke normalizer?
  - Statistik: baris kosong, baris tanpa timestamp, dll

Biar lu nggak nebak-nebak kenapa event hilang.
"""

import csv
import sys
from pathlib import Path
from collections import Counter


# Add project root to path
PROJ = str(Path(__file__).resolve().parent / "src")
if PROJ not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.parsers.csv_elastic import CsvElasticParser


def inspect(filepath: str, max_sample: int = 5):
    """Analisa struktur CSV dan laporin potensi masalah."""

    parser = CsvElasticParser(filepath)
    detected = parser._detect_source  # will be None until parse()
    # Pre-load first few rows for inspection
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        sample_rows = []
        for i, row in enumerate(reader):
            if i < max_sample:
                sample_rows.append(row)
            else:
                break

    total_lines = parser._count_lines()

    # Detect source from column names
    detected_source = parser._detect_source(fieldnames)
    print(f"File  : {filepath}")
    print(f"Lines : {total_lines:,} (incl. header)")
    print(f"Source terdeteksi: {detected_source}")
    print()

    # Load YAML mappings
    try:
        yaml_mappings = CsvElasticParser._load_yaml_mappings()
        source_map = yaml_mappings.get(detected_source, {})
        global_map = yaml_mappings.get("global", {})
    except Exception:
        source_map = {}
        global_map = {}

    # Column mapping analysis
    print(f"{'─' * 70}")
    print(f"{'KOLOM CSV':35s} {'→ MAPPING':35s} {'STATUS'}")
    print(f"{'─' * 70}")

    mapped_count = 0
    unmapped_count = 0
    for col in fieldnames:
        col_lower = col.lower().strip()
        mapped_to = (
            source_map.get(col_lower)
            or global_map.get(col_lower)
        )
        if mapped_to:
            mapped_count += 1
            status = "✓ mapped"
        else:
            mapped_to = col  # pass-through
            unmapped_count += 1
            status = "• passthrough (tidak dikenal)"

        print(f"  {col:33s} → {mapped_to:33s} {status}")

    print(f"{'─' * 70}")
    print(f"  Total kolom: {len(fieldnames)} | "
          f"{mapped_count} mapped, {unmapped_count} passthrough")
    print()

    # Critical fields check (PAKE MAPPED TARGET, bukan raw column name)
    critical_targets = {
        "wazuh": ["rule.id", "agent.name", "rule.level"],
        "fortigate": ["srcip", "action", "dstport"],
        "windows": ["event_id", "dstuser"],
    }
    needed = critical_targets.get(detected_source, ["timestamp"])
    # Build set of mapped target fields
    mapped_targets = set()
    for col in fieldnames:
        t = source_map.get(col.lower().strip()) or global_map.get(col.lower().strip()) or col
        mapped_targets.add(t)
    missing = [f for f in needed if f not in mapped_targets]

    if missing:
        print(f"⚠ KOLOM KRITIS HILANG (event bakal di-skip):")
        for m in missing:
            print(f"    - '{m}' tidak ditemukan di CSV")
        print(f"    → TAMBAHIN mapping manual di config/csv_mappings.yaml")
        print(f"    → atau pastiin export Elastic lu include kolom ini")
    else:
        print(f"✓ Semua kolom kritis ada")

    print()

    # ── Auto-mapping suggestion ──
    unknown_cols = []
    for col in fieldnames:
        col_lower = col.lower().strip()
        if not (source_map.get(col_lower) or global_map.get(col_lower)):
            # Ambil sample values buat hint
            sample_vals = []
            for row in sample_rows:
                v = (row.get(col, "") or "").strip()
                if v:
                    sample_vals.append(v)
            sample_str = ", ".join(sample_vals[:3])[:50] if sample_vals else "?"
            unknown_cols.append((col, sample_str))

    if unknown_cols:
        print(f"{'─' * 70}")
        print(f"  AUTO-MAPPING SUGGESTION — copy-paste ke config/csv_mappings.yaml:")
        print(f"{'─' * 70}")
        print(f"  {detected_source}:")
        for col, sample in unknown_cols:
            print(f"    # {col:30s} sample: {sample}")
            print(f"    {col}: TARGET_FIELD_HERE")
        print()
        print(f"  Ganti TARGET_FIELD_HERE dengan field standar, contoh:")
        if detected_source == "wazuh":
            print(f"    rule.description / agent.ip / data.srcport / location / full_log")
        elif detected_source == "fortigate":
            print(f"    devname / dstip / service / policyid / sentbyte / proto")
        elif detected_source == "windows":
            print(f"    event_data.IpAddress / event_data.TargetUserName / host.name")
        print(f"  Atau bikin prefix path: data.custom_field / extra.metadata")
        print(f"{'─' * 70}")

    print()

    # Sample values
    if sample_rows:
        print(f"{'─' * 70}")
        print(f"  SAMPLE {len(sample_rows)} BARIS PERTAMA:")
        print(f"{'─' * 70}")
        for col in fieldnames:
            values = [row.get(col, "")[:60] for row in sample_rows]
            unique_vals = set(values)
            if len(unique_vals) == 1:
                v = values[0] if values[0] else "(kosong)"
                print(f"  {col:30s} = {v}")
            else:
                print(f"  {col:30s} = {values[0]}  ... ({len(unique_vals)} nilai beda)")
        print()

    # Full scan: statistik event yang bakal diparse
    print(f"{'─' * 70}")
    print(f"  SCAN LENGKAP — estimasi event yang lolos ke normalizer:")
    print(f"{'─' * 70}")

    parser = CsvElasticParser(filepath)
    events = list(parser.parse())
    parsed = parser.parsed
    skipped = parser.skipped

    print(f"  Baris total    : {total_lines:,}")
    print(f"  Diparse        : {parsed:,} (berhasil)")
    print(f"  Di-skip        : {skipped:,} (gagal/field kosong)")
    print(f"  Persentase     : {parsed / max(total_lines - 1, 1) * 100:.1f}%")

    if skipped > 0:
        print(f"\n  ⚠ {skipped:,} baris DI-SKIP. Kemungkinan penyebab:")
        print(f"     - Baris kosong")
        print(f"     - Semua kolom bernilai kosong/''")
        print(f"     - JSON/format corrupt (kalau bukan CSV)")
        print(f"     - Run: python3 csv_inspect.py {filepath} --verbose untuk detail")

    # Normalizer stage: berapa yang jadi CommonEvent?
    if events and detected_source:
        normalizer_map = {
            "wazuh": "src.normalizer.normalize_wazuh",
            "fortigate": "src.normalizer.normalize_fortigate",
            "windows": "src.normalizer.normalize_windows",
        }
        fail_count = 0
        for e in events[:100]:  # sample 100 aja
            try:
                if detected_source == "wazuh":
                    from src.normalizer import normalize_wazuh; normalize_wazuh(e)
                elif detected_source == "fortigate":
                    from src.normalizer import normalize_fortigate; normalize_fortigate(e)
                elif detected_source == "windows":
                    from src.normalizer import normalize_windows; normalize_windows(e)
            except Exception:
                fail_count += 1
        if fail_count > 0:
            print(f"\n  ⚠ Normalizer gagal pada {fail_count}/{min(100, parsed)} event sample")
            print(f"     → Mungkin ada field yang formatnya beda (cek nilai di atas)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 csv_inspect.py <file.csv>")
        sys.exit(1)

    inspect(sys.argv[1])
