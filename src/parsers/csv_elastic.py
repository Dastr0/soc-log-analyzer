"""
CSV ElasticDiscover Parser — parse export CSV dari menu Discover Elastic.

Elastic mengekspor field nested dengan dot-notation:
  rule.id, rule.level, agent.name, data.srcip, ...

Parser ini membalikkan jadi struktur nested dict (sama dengan format
yang dihasilkan parser asli), lalu auto-detect source type dari nama
kolom. Output bisa langsung masuk ke normalizer yang sudah ada.

Custom mapping: tambahin kolom CSV lu sendiri di config/csv_mappings.yaml.
"""

import csv
import json
import sys
from pathlib import Path
from typing import Iterator, Optional

import yaml

from src.parsers.base import BaseParser


class CsvElasticParser(BaseParser):
    """
    Parser universal untuk CSV export dari Elastic Discover.

    Auto-detect source type dari nama kolom CSV.
    Column mapping: merge config/csv_mappings.yaml + built-in aliases.
    Lu bisa nambah mapping sendiri di file YAML tanpa ubah kode Python.
    """

    # Cache YAML mappings (load sekali)
    _yaml_cache: Optional[dict] = None
    _yaml_loaded: bool = False

    def __init__(self, filepath: str, source_hint: Optional[str] = None,
                 source_hint_authoritative: bool = False):
        super().__init__(filepath)
        self.source_hint = source_hint
        self.source_hint_authoritative = source_hint_authoritative
        self._detected_source: Optional[str] = None

    def parse(self) -> Iterator[dict]:
        """Baca CSV, konversi tiap baris jadi nested dict."""
        self.total_lines = self._count_lines()

        with open(self.filepath, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return

            # Deteksi source
            detected = self._detect_source(reader.fieldnames)
            if self.source_hint_authoritative:
                self._detected_source = self.source_hint or detected or "unknown"
            else:
                self._detected_source = detected or self.source_hint or "unknown"
            self.source_type = self._detected_source

            processed = 0
            for row in reader:
                processed += 1
                try:
                    event = self._row_to_nested(row)
                    if event:
                        event["_source"] = self._detected_source
                        self.parsed += 1
                        yield event
                    else:
                        self.skipped += 1
                except Exception:
                    self.skipped += 1

                if processed % 1000 == 0 and self.total_lines:
                    pct = int(processed / self.total_lines * 100)
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    sys.stderr.write(
                        f"\r  [{bar}] {processed:,}/{self.total_lines:,} "
                        f"CSV ({self._detected_source}) ({pct}%)"
                    )
                    sys.stderr.flush()

        if self.total_lines and processed:
            sys.stderr.write(
                f"\r  [{'█' * 20}] {processed:,}/{self.total_lines:,} "
                f"CSV ({self._detected_source}) (100%)\n"
            )

    # ── Source Detection ──────────────────────────────────────────

    def _detect_source(self, fieldnames: list) -> str:
        """Deteksi source type dari nama-nama kolom CSV."""
        fields = set(f.lower() for f in fieldnames)

        # Windows/Winlogbeat: use its distinctive namespaces before generic ECS
        # fields such as agent.name, which are shared by many Elastic sources.
        if (any(f.startswith("winlog.") for f in fields)
                or "event.code" in fields
                or any(f.startswith("data.win.") for f in fields)):
            return "windows"
        if {"event_id", "eventid", "winlog_event_id"} & fields:
            return "windows"

        # FortiGate: require a device/log marker plus network traffic fields.
        traffic_fields = {"srcip", "sourceip", "source_ip", "dstip", "destip", "dest_ip"}
        device_fields = {"devname", "device_name", "logid", "policyid", "subtype"}
        if fields & traffic_fields and fields & device_fields:
            return "fortigate"
        if "type" in fields and "srcip" in fields:
            return "fortigate"
        if "action" in fields and {"srcip", "sourceip", "destip", "dstip"} & fields:
            if not {"rule.id", "agent.name", "event_id"} & fields:
                return "fortigate"

        if (("rule.id" in fields or "rule_id" in fields)
                and ({"rule.level", "rule_level", "rule.description",
                      "agent.name", "agent_name", "manager.name"} & fields)):
            return "wazuh"

        return "unknown"

    # ── Row Conversion ───────────────────────────────────────────

    def _row_to_nested(self, row: dict) -> Optional[dict]:
        """Konversi CSV row (flat dict, dot-notation) → nested dict."""
        result: dict = {}
        has_content = False

        for key, value in row.items():
            key = key.strip()
            value = (value or "").strip()
            # Skip empty & Elastic null placeholders
            if not key or value == "" or value == "-":
                continue
            has_content = True

            key_norm = self._normalize_key(key)
            parts = key_norm.split(".")

            target = result
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                elif not isinstance(target[part], dict):
                    target[part] = {"_value": target[part]}
                target = target[part]

            target[parts[-1]] = _coerce_csv_value(value)

        return result if has_content else None

    # ── YAML Mapping ─────────────────────────────────────────────

    @classmethod
    def _load_yaml_mappings(cls) -> dict:
        """Load column mappings dari config/csv_mappings.yaml. Cache sekali.
        Keys di-lowercase-kan otomatis untuk case-insensitive lookup."""
        if cls._yaml_loaded:
            return cls._yaml_cache or {}

        cls._yaml_loaded = True
        project_config = Path(__file__).resolve().parents[2] / "config" / "csv_mappings.yaml"
        paths = [
            project_config,
            Path("config/csv_mappings.yaml"),
            Path.home() / ".hermes" / "soc-log-analyzer" / "csv_mappings.yaml",
        ]
        for p in paths:
            if p.exists():
                try:
                    raw = yaml.safe_load(p.read_text()) or {}
                    # Lowercase-kan semua key (nested)
                    cls._yaml_cache = _deep_lowercase_keys(raw)
                    break
                except Exception:
                    pass
        return cls._yaml_cache or {}

    def _normalize_key(self, key: str) -> str:
        """
        Normalisasi nama kolom CSV → field standar.
        Prioritas: YAML (source-specific) > YAML (global) > built-in > original.
        """
        key_lower = key.lower()
        yaml_map = self._load_yaml_mappings()
        source = self._detected_source or self.source_hint or ""

        # 1. YAML: mapping spesifik source
        if source in yaml_map and isinstance(yaml_map[source], dict):
            if key_lower in yaml_map[source]:
                return yaml_map[source][key_lower]

        # 2. YAML: mapping global
        global_map = yaml_map.get("global", {})
        if isinstance(global_map, dict) and key_lower in global_map:
            return global_map[key_lower]

        # 3. Built-in hardcoded aliases (fallback)
        builtin = {
            "@timestamp": "timestamp", "ts": "timestamp",
            "rule_id": "rule.id", "rule_level": "rule.level",
            "rule_description": "rule.description", "rule_groups": "rule.groups",
            "agent_id": "agent.id", "agent_name": "agent.name", "agent_ip": "agent.ip",
            "data_srcip": "data.srcip", "src_ip": "data.srcip",
            "data_srcport": "data.srcport", "srcport": "data.srcport",
            "data_srcuser": "data.srcuser", "data_dstuser": "data.dstuser",
            "data_dstip": "data.dstip", "dst_ip": "data.dstip",
            "data_dstport": "data.dstport", "dstport": "data.dstport",
            "data_proto": "data.proto", "data_command": "data.command",
            "location": "location", "full_log": "full_log", "data_id": "data.id",
            "srcip": "srcip", "dstip": "dstip", "proto": "proto",
            "action": "action", "devname": "devname", "service": "service",
            "type": "type", "subtype": "subtype",
            "policyid": "policyid", "sentbyte": "sentbyte", "rcvdbyte": "rcvdbyte",
            "winlog_event_id": "winlog.event_id", "event_code": "winlog.event_id",
            "event_id": "event_id", "host_name": "host.name", "host_ip": "host.ip",
            "target_user_name": "winlog.event_data.TargetUserName",
            "targetusername": "winlog.event_data.TargetUserName",
            "ip_address": "winlog.event_data.IpAddress",
            "ipaddress": "winlog.event_data.IpAddress",
            "computer_name": "computer_name", "message": "full_log",
        }
        if key_lower in builtin:
            return builtin[key_lower]

        # 4. Pass-through (nama kolom tidak dimodifikasi)
        return key

    @property
    def detected_source(self) -> Optional[str]:
        return self._detected_source


# ── Module-level helpers ─────────────────────────────────────────

def _deep_lowercase_keys(obj):
    """Rekursif lowercase semua key di dict (top-level aja untuk 1-level nest)."""
    if isinstance(obj, dict):
        return {k.lower(): _deep_lowercase_keys(v) for k, v in obj.items()}
    return obj


def _coerce_csv_value(value: str):
    """Restore JSON arrays/objects exported by Elastic without changing IDs."""
    if value and value[0] in "[{" and value[-1] in "]}":
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
    return value
