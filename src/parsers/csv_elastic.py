"""
CSV ElasticDiscover Parser — parse export CSV dari menu Discover Elastic.

Elastic mengekspor field nested dengan dot-notation:
  rule.id, rule.level, agent.name, data.srcip, ...

Parser ini membalikkan jadi struktur nested dict (sama dengan format
yang dihasilkan parser asli), lalu auto-detect source type dari nama
kolom. Output bisa langsung masuk ke normalizer yang sudah ada.

Dengan parser ini, lu bisa langsung analyze file CSV hasil export
Elastic tanpa harus convert ke JSONL dulu.
"""

import csv
import sys
from typing import Iterator, Optional

from src.parsers.base import BaseParser


class CsvElasticParser(BaseParser):
    """
    Parser universal untuk CSV export dari Elastic Discover.

    Auto-detect source type dari nama kolom CSV (rule.id → wazuh,
    devname → fortigate, winlog.event_id → windows).

    Output: dict nested yang kompatibel dengan normalizer yang sudah ada.
    """

    def __init__(self, filepath: str, source_hint: Optional[str] = None):
        super().__init__(filepath)
        self.source_hint = source_hint
        self._detected_source: Optional[str] = None

    def parse(self) -> Iterator[dict]:
        """Baca CSV, konversi tiap baris jadi nested dict."""
        self.total_lines = self._count_lines()

        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return

            # Deteksi source dari kolom
            self._detected_source = (
                self._detect_source(reader.fieldnames)
                or self.source_hint
                or "unknown"
            )
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

    def _detect_source(self, fieldnames: list) -> str:
        """Deteksi source type dari nama-nama kolom CSV."""
        fields = set(f.lower() for f in fieldnames)

        # Wazuh: ada rule.id, agent.name
        if {"rule.id", "agent.name"} & fields or {"rule_id", "agent_name"} & fields:
            return "wazuh"

        # FortiGate: ada devname atau type=traffic
        if "devname" in fields or ("type" in fields and "srcip" in fields):
            return "fortigate"

        # Windows: ada winlog.event_id, event_id, dstuser + windows context
        if {"winlog.event_id", "event_id", "event.code"} & fields:
            return "windows"

        # Windows fallback: ada dstuser + source srcip (Wazuh Windows agent)
        if "dstuser" in fields and "srcip" in fields:
            # Masih ambigu: cek lokasi Security → Windows
            if any(
                "security" in str(f).lower() or "windows" in str(f).lower()
                for f in fieldnames
            ):
                return "windows"

        # Wazuh fallback: ada rule.level dan agent.ip
        if "rule.level" in fields or "rule_id" in fields:
            return "wazuh"

        return "unknown"

    def _row_to_nested(self, row: dict) -> Optional[dict]:
        """
        Konversi CSV row (flat dict dengan dot-notation keys) → nested dict.

        Contoh:
          Input:  {"rule.id": "5710", "agent.name": "DC01", "data.srcip": "1.2.3.4"}
          Output: {"rule": {"id": "5710"}, "agent": {"name": "DC01"}, "data": {"srcip": "1.2.3.4"}}
        """
        result: dict = {}
        has_content = False

        for key, value in row.items():
            key = key.strip()
            value = (value or "").strip()

            # Skip kolom kosong
            if not key or value == "":
                continue

            has_content = True

            # Normalisasi nama kolom yang umum di Elastic
            key_norm = self._normalize_key(key)

            # Pecah berdasarkan dot: "rule.id" → ["rule", "id"]
            parts = key_norm.split(".")

            # Sisipkan ke nested dict
            target = result
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                elif not isinstance(target[part], dict):
                    # Conflict: key sudah ada sebagai nilai non-dict
                    # Wrap dalam dict dengan key "_value"
                    target[part] = {"_value": target[part]}
                target = target[part]

            target[parts[-1]] = self._cast_value(value)

        return result if has_content else None

    def _normalize_key(self, key: str) -> str:
        """Normalisasi nama kolom dari berbagai format Elastic."""
        # Mapping alias kolom yang sering muncul beda-beda
        aliases = {
            # Stempel waktu
            "@timestamp": "timestamp",
            "ts": "timestamp",
            # Wazuh nested
            "rule_id": "rule.id",
            "rule_level": "rule.level",
            "rule_description": "rule.description",
            "rule_groups": "rule.groups",
            "agent_id": "agent.id",
            "agent_name": "agent.name",
            "agent_ip": "agent.ip",
            "data_srcip": "data.srcip",
            "src_ip": "data.srcip",
            "data_srcport": "data.srcport",
            "srcport": "data.srcport",
            "data_srcuser": "data.dstuser",
            "data_dstuser": "data.dstuser",
            "data_dstip": "data.dstip",
            "dst_ip": "data.dstip",
            "data_dstport": "data.dstport",
            "dstport": "data.dstport",
            "data_proto": "data.proto",
            "data_command": "data.command",
            "location": "location",
            "full_log": "full_log",
            "data_id": "data.id",
            # FortiGate
            "srcip": "srcip",
            "dstip": "dstip",
            "proto": "proto",
            "action": "action",
            "devname": "devname",
            "service": "service",
            "type": "type",
            "subtype": "subtype",
            "policyid": "policyid",
            "sentbyte": "sentbyte",
            "rcvdbyte": "rcvdbyte",
            # Windows
            "winlog_event_id": "winlog.event_id",
            "event_code": "winlog.event_id",
            "event_id": "event_id",
            "host_name": "host.name",
            "host_ip": "host.ip",
            "target_user_name": "event_data.TargetUserName",
            "targetusername": "event_data.TargetUserName",
            "ip_address": "event_data.IpAddress",
            "ipaddress": "event_data.IpAddress",
            "computer_name": "computer_name",
            "message": "full_log",
        }

        key_lower = key.lower()
        if key_lower in aliases:
            return aliases[key_lower]

        return key

    def _cast_value(self, value: str):
        """Coba convert string ke int/float kalau bisa."""
        value = value.strip()

        # Angka
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        # Boolean
        if value.lower() in ("true", "false"):
            return value.lower() == "true"

        return value

    @property
    def detected_source(self) -> Optional[str]:
        return self._detected_source
