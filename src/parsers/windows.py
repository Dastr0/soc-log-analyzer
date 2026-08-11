"""
Windows EventLog parser (format Wazuh/Elastic).

Dua mode input:
  1. Wazuh JSONL — alert Wazuh dari agent Windows
     Format: sama persis dengan alerts.json Wazuh, tapi rule.id spesifik Windows
     (60106, 60122, 60204, 61603, 61609, dll)

  2. Generic JSON — export langsung dari Elastic/winlogbeat
     Format: {"@timestamp": "...", "winlog": {"event_id": 4625, ...}, ...}

Prioritas: Wazuh parser dulu (karena lu export dari Elastic yang ada Wazuh-nya).
Kalau format nggak cocok, fallback ke generic Windows JSON.
"""

import json
import sys
from typing import Iterator, Optional

from src.parsers.base import BaseParser


# ─── Windows EventID → Action mapping ─────────────────────────────
_EVENTID_ACTION_MAP = {
    # Logon
    "4624": "login_success",
    "4625": "login_failed",
    "4634": "logout",
    "4647": "logout",
    "4648": "explicit_logon",
    "4776": "credential_validation",
    "4771": "kerberos_preauth_failed",
    # Account management
    "4720": "user_created",
    "4722": "user_enabled",
    "4725": "user_disabled",
    "4726": "user_deleted",
    "4728": "user_added_to_group",
    "4732": "user_added_to_local_group",
    "4738": "user_changed",
    # Process
    "4688": "process_create",
    "4689": "process_terminated",
    # Service
    "7045": "service_installed",
    "7034": "service_crashed",
    "7036": "service_state_changed",
    # Share / file
    "5140": "share_access",
    "5145": "share_object_access",
    "4663": "file_accessed",
    # Audit
    "1102": "audit_log_cleared",
    "4719": "audit_policy_changed",
    # Special logon
    "4672": "special_privilege_assigned",
    # RDP
    "21": "rdp_session_start",   # TerminalServices-LocalSessionManager
    "24": "rdp_session_reconnect",
    "25": "rdp_session_reconnect",
    "40": "rdp_session_disconnect",
    # Sysmon (via Wazuh rule.id, not EventID)
    "1": "sysmon_process_create",
    "3": "sysmon_network_connect",
    "7": "sysmon_image_load",
    "8": "sysmon_create_remote_thread",
    "11": "sysmon_file_create",
}

# Wazuh rule.id → EventID mapping (Windows agent)
_WAZUH_RULE_EVENTID = {
    # Windows logon
    "60106": "4625",   # Windows logon failure
    "60122": "4624",   # Windows logon success
    "60204": "4720",   # Windows: A user account was created
    "60207": "4726",   # Windows: A user account was deleted
    "60202": "4732",   # Windows: User added to local group
    "60225": "4648",   # Windows: Explicit credentials logon
    # Sysmon
    "61603": "1",      # Sysmon: Process creation
    "61609": "3",      # Sysmon: Network connection
    "61613": "8",      # Sysmon: CreateRemoteThread
    "61614": "11",     # Sysmon: File creation
    # Other
    "18101": "4625",   # Windows: Multiple failed logins
    "18102": "4625",
    "18103": "4625",
    "18107": "4625",
    "91816": None,     # PowerShell encoded command (dicek dari data)
}


class WindowsParser(BaseParser):
    """
    Parser untuk Windows EventLog dari export Elastic/Wazuh.

    Mode auto-detect:
      - JSONL dengan agent.name + rule.id → mode Wazuh
      - JSON dengan winlog.event_id → mode generic Elastic
    """

    EVENTID_ACTION = _EVENTID_ACTION_MAP

    def __init__(self, filepath: str):
        super().__init__(filepath)
        self.source_type = "windows"
        self._mode: Optional[str] = None  # "wazuh" or "generic"

    def parse(self) -> Iterator[dict]:
        """Baca file, auto-detect format per baris pertama."""
        self.total_lines = self._count_lines()
        processed = 0

        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                processed += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    self.skipped += 1
                    continue

                if not isinstance(event, dict):
                    self.skipped += 1
                    continue

                # Auto-detect mode dari event pertama
                if self._mode is None:
                    self._mode = self._detect_mode(event)

                if self._is_valid(event):
                    self.parsed += 1
                    # Inject source marker buat normalizer
                    event["_parser_mode"] = self._mode
                    yield event
                else:
                    self.skipped += 1

                if processed % 1000 == 0 and self.total_lines:
                    pct = int(processed / self.total_lines * 100)
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    sys.stderr.write(f"\r  [{bar}] {processed:,}/{self.total_lines:,} "
                                     f"Windows events ({pct}%)")
                    sys.stderr.flush()

        if self.total_lines and processed:
            sys.stderr.write(f"\r  [{'█' * 20}] {processed:,}/{self.total_lines:,} "
                             f"Windows events (100%)\n")

    def _detect_mode(self, event: dict) -> str:
        """Deteksi format: 'wazuh' atau 'generic'."""
        # Mode Wazuh: ada agent.name + rule.id
        if "agent" in event and "rule" in event:
            return "wazuh"
        # Mode generic: ada winlog atau event.code
        if "winlog" in event or "event" in event:
            return "generic"
        # Heuristic: punya event_id
        if "event_id" in event or "EventID" in event:
            return "generic"
        return "generic"

    def _is_valid(self, event: dict) -> bool:
        """Minimal: harus punya timestamp & bisa diekstrak field-nya."""
        if self._mode == "wazuh":
            return "timestamp" in event and "rule" in event
        # Generic mode: cukup punya @timestamp atau timestamp
        return "@timestamp" in event or "timestamp" in event

    # ── Field extractors (mode-aware) ──

    def extract_event_id(self, event: dict) -> Optional[str]:
        """Ambil EventID dari berbagai format."""
        mode = event.get("_parser_mode") or self._mode

        if mode == "wazuh":
            # Coba dari Wazuh rule.id → EventID mapping
            rule = event.get("rule", {})
            if isinstance(rule, dict):
                wazuh_id = str(rule.get("id", ""))
                return _WAZUH_RULE_EVENTID.get(wazuh_id, wazuh_id)

        # Generic: winlog.event_id atau event_id langsung
        winlog = event.get("winlog", {})
        if isinstance(winlog, dict) and "event_id" in winlog:
            return str(winlog["event_id"])

        for key in ("event_id", "EventID", "event.code"):
            if key in event:
                return str(event[key])

        return None

    def extract_action(self, event: dict) -> Optional[str]:
        """Map EventID → common action label."""
        eid = self.extract_event_id(event)
        if eid and eid in _EVENTID_ACTION_MAP:
            return _EVENTID_ACTION_MAP[eid]

        # Fallback: cek rule.description untuk keyword Windows
        mode = event.get("_parser_mode") or self._mode
        if mode == "wazuh":
            rule = event.get("rule", {})
            desc = (rule.get("description", "") if isinstance(rule, dict) else "").lower()
            for keyword, action in _DESC_ACTION_MAP:
                if keyword in desc:
                    return action

        return "windows_event"


_DESC_ACTION_MAP = [
    ("logon failure", "login_failed"),
    ("logon success", "login_success"),
    ("special logon", "login_success"),
    ("account was created", "user_created"),
    ("account was deleted", "user_deleted"),
    ("added to", "user_added_to_group"),
    ("process creation", "process_create"),
    ("powershell", "suspicious_process"),
    ("encoded command", "suspicious_process"),
    ("service installed", "service_installed"),
    ("audit log was cleared", "audit_log_cleared"),
]
