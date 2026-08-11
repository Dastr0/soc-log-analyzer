"""
FortiGate firewall syslog parser.

Format: key=value pairs per baris, dipisah spasi.
  date=2026-08-10 time=08:33:17 devname=FG-01 logid=0000000013
  type=traffic subtype=forward level=notice srcip=203.0.113.5
  srcport=55987 dstip=10.0.0.5 dstport=3389 proto=6 service="RDP"
  action=accept policyid=3 duration=120 sentbyte=2048

Beberapa tipe log FortiGate:
  - traffic: forward/deny koneksi (yang paling penting buat SOC)
  - event: system events, admin login, config changes
  - utm: UTM security events (IPS, AV, web filter, dll)
"""

import re
from typing import Iterator, Optional

from src.parsers.base import BaseParser


class FortiGateParser(BaseParser):
    """Parser untuk syslog FortiGate."""

    # Regex: key=value atau key="value" atau key='value'
    _KV_RE = re.compile(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)')

    def __init__(self, filepath: str):
        super().__init__(filepath)
        self.source_type = "fortigate"

    def parse(self) -> Iterator[dict]:
        """Baca file syslog, parse tiap baris jadi dict key=value."""
        self.total_lines = self._count_lines()
        processed = 0

        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                processed += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    event = self._parse_line(line)
                    if event:
                        self.parsed += 1
                        yield event
                    else:
                        self.skipped += 1
                except Exception:
                    self.skipped += 1

                if processed % 1000 == 0 and self.total_lines:
                    pct = int(processed / self.total_lines * 100)
                    import sys
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    sys.stderr.write(f"\r  [{bar}] {processed:,}/{self.total_lines:,} "
                                     f"FortiGate events ({pct}%)")
                    sys.stderr.flush()

        if self.total_lines and processed:
            import sys
            sys.stderr.write(f"\r  [{'█' * 20}] {processed:,}/{self.total_lines:,} "
                             f"FortiGate events (100%)\n")

    def _parse_line(self, line: str) -> Optional[dict]:
        """
        Parse satu baris syslog FortiGate → dict.

        Return None kalau bukan format FortiGate yang dikenal.
        """
        # Cek apakah ini log FortiGate (harus ada devname atau type=)
        if "devname=" not in line and "type=" not in line:
            return None

        # Ekstrak semua key=value pairs
        event = {}
        for m in self._KV_RE.finditer(line):
            key = m.group(1)
            value = m.group(2)
            # Strip quotes
            if value.startswith('"') or value.startswith("'"):
                value = value[1:-1]
            event[key] = value

        # Minimal harus punya type
        if "type" not in event:
            return None

        # Ambil timestamp dari date + time
        if "date" in event and "time" in event:
            event["_timestamp"] = f"{event['date']}T{event['time']}"

        # Parse numeric fields
        for field in ["proto", "srcport", "dstport", "duration",
                       "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt",
                       "policyid", "cpu", "mem", "disk"]:
            if field in event:
                try:
                    event[f"_{field}_int"] = int(event[field])
                except (ValueError, TypeError):
                    pass

        return event

    # ── Field extractors (helpers buat normalizer) ──

    def extract_src_ip(self, event: dict) -> Optional[str]:
        return event.get("srcip")

    def extract_dst_ip(self, event: dict) -> Optional[str]:
        return event.get("dstip")

    def extract_dst_port(self, event: dict) -> Optional[int]:
        return event.get("_dstport_int")

    def extract_src_port(self, event: dict) -> Optional[int]:
        return event.get("_srcport_int")

    def extract_protocol(self, event: dict) -> Optional[int]:
        return event.get("_proto_int")

    def extract_action(self, event: dict) -> Optional[str]:
        """Map FortiGate action → common label."""
        action = event.get("action", "").lower()
        if action == "accept":
            return "connection_allowed"
        elif action == "deny":
            return "connection_blocked"
        elif action == "close":
            return "connection_closed"
        elif action in ("drop", "block"):
            return "connection_blocked"
        return action or None

    def extract_device(self, event: dict) -> Optional[str]:
        return event.get("devname")

    def extract_service(self, event: dict) -> Optional[str]:
        return event.get("service")

    def extract_log_type(self, event: dict) -> Optional[str]:
        """Tipe log: traffic / event / utm."""
        return event.get("type")

    def extract_subtype(self, event: dict) -> Optional[str]:
        return event.get("subtype")

    def extract_bytes(self, event: dict) -> tuple:
        """Return (sent, rcvd) bytes."""
        return (
            event.get("_sentbyte_int"),
            event.get("_rcvdbyte_int"),
        )
