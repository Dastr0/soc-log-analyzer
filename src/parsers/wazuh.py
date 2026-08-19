"""
Wazuh HIDS alerts.json parser.

Format: JSONL (satu JSON object per baris).
Membaca file yang diexport dari Elastic (atau dump langsung dari Wazuh).
"""

import json
import sys
from typing import Iterator, Optional

from src.parsers.base import BaseParser


class WazuhParser(BaseParser):
    """
    Parser untuk alerts.json Wazuh.

    Struktur alert Wazuh (JSONL):
      {
        "timestamp": "2026-08-10T08:33:17.523+0000",
        "rule": {"level": 5, "description": "sshd: brute force attack", "id": "5710", ...},
        "agent": {"name": "DC01", "ip": "10.0.0.5", "id": "001"},
        "manager": {"name": "wazuh-manager"},
        "data": {"srcip": "203.0.113.5", "srcport": "55987", "dstuser": "Administrator", ...},
        "predecoder": {"program_name": "sshd", "hostname": "DC01", "timestamp": "..."},
        "decoder": {"name": "sshd"},
        "full_log": "Aug 10 08:33:17 DC01 sshd[12345]: Failed password ...",
        "location": "/var/log/auth.log",
        "id": "1723277297.17143763"
      }
    """

    def __init__(self, filepath: str):
        super().__init__(filepath)
        self.source_type = "wazuh"

    def parse(self) -> Iterator[dict]:
        """
        Baca file JSONL, yield tiap alert sebagai dict.
        Baris yang corrupt JSON-nya di-skip (counter self.skipped).
        """
        self.total_lines = self._count_lines()
        processed = 0

        with open(self.filepath, "r", encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                processed += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    if isinstance(event, dict) and isinstance(event.get("_source"), dict):
                        event = event["_source"]
                    # pastiin ini alert Wazuh valid (minimal punya timestamp & rule)
                    if self._is_valid_alert(event):
                        self.parsed += 1
                        yield event
                    else:
                        self.skipped += 1
                except json.JSONDecodeError:
                    self.skipped += 1

                # progress tiap 1000 baris
                if processed % 1000 == 0 and self.total_lines:
                    pct = int(processed / self.total_lines * 100)
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    sys.stderr.write(f"\r  [{bar}] {processed:,}/{self.total_lines:,} Wazuh alerts ({pct}%)")
                    sys.stderr.flush()

        if self.total_lines and processed:
            sys.stderr.write(f"\r  [{'█' * 20}] {processed:,}/{self.total_lines:,} Wazuh alerts (100%)\n")

    def _is_valid_alert(self, event: dict) -> bool:
        """Validasi minimal: harus punya timestamp & rule object."""
        if not isinstance(event, dict):
            return False
        if "timestamp" not in event:
            return False
        if "rule" not in event:
            return False
        return True

    def extract_src_ip(self, event: dict) -> Optional[str]:
        """Ambil IP sumber dari berbagai field Wazuh."""
        # data.srcip paling umum
        data = event.get("data", {})
        if isinstance(data, dict) and data.get("srcip"):
            return data["srcip"]
        # predecoder.srcip
        predecoder = event.get("predecoder", {})
        if isinstance(predecoder, dict) and predecoder.get("srcip"):
            return predecoder["srcip"]
        return None

    def extract_dst_ip(self, event: dict) -> Optional[str]:
        """Ambil IP tujuan — biasanya agent.ip."""
        data = event.get("data", {})
        if isinstance(data, dict) and data.get("dstip"):
            return data["dstip"]
        return None

    def extract_user(self, event: dict) -> Optional[str]:
        """Ambil username dari data.srcuser atau data.dstuser."""
        data = event.get("data", {})
        if not isinstance(data, dict):
            return None
        return data.get("srcuser") or data.get("dstuser")

    def extract_agent_name(self, event: dict) -> Optional[str]:
        """Ambil nama host dari agent.name atau predecoder.hostname."""
        agent = event.get("agent", {})
        if isinstance(agent, dict) and agent.get("name"):
            return agent["name"]
        predecoder = event.get("predecoder", {})
        if isinstance(predecoder, dict) and predecoder.get("hostname"):
            return predecoder["hostname"]
        return None

    def extract_agent_ip(self, event: dict) -> Optional[str]:
        """Ambil IP agent (host yang dimonitor)."""
        agent = event.get("agent", {})
        if isinstance(agent, dict) and agent.get("ip"):
            return agent["ip"]
        return None
