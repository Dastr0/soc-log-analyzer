"""
Normalizer: konversi raw event per-source → CommonEvent universal.

Mapping field-by-field dari setiap source ke CommonEvent schema.
"""

from datetime import datetime, timezone
from typing import Optional

from src.schema import CommonEvent


# Severity normalization table: Wazuh rule.level → CommonEvent severity
# Wazuh levels: 0-4=LOW, 5-7=MED, 8-12=HIGH, 13-15=CRITICAL
def _severity_wazuh(level: int) -> int:
    if level >= 13:
        return 4   # CRITICAL
    elif level >= 8:
        return 3   # HIGH
    elif level >= 5:
        return 2   # MEDIUM
    return 1       # LOW


# Action mapping: dari rule.description → common action label
def _action_from_wazuh_rule(event: dict) -> Optional[str]:
    description = event.get("rule", {}).get("description", "").lower()
    rule_id = str(event.get("rule", {}).get("id", ""))

    # Pattern matching sederhana dari description
    for keyword, action in _ACTION_PATTERNS:
        if keyword in description:
            return action

    # Fallback ke generic
    groups = event.get("rule", {}).get("groups", [])
    if isinstance(groups, list):
        for g in groups:
            if g in _GROUP_ACTION_MAP:
                return _GROUP_ACTION_MAP[g]

    return None


_ACTION_PATTERNS = [
    ("brute force", "login_failed"),
    ("multiple failed", "login_failed"),
    ("attempt to login using a non-existent user", "login_failed"),
    ("failed password", "login_failed"),
    ("authentication failure", "login_failed"),
    ("multiple authentication failure", "login_failed"),
    ("authentication success", "login_success"),
    ("successful login", "login_success"),
    ("new user", "user_created"),
    ("user deleted", "user_deleted"),
    ("user added to group", "user_added_to_group"),
    ("privilege escalation", "priv_escalation"),
    ("command execution by user", "process_create"),
    ("integrity checking", "file_integrity"),
    ("port scan", "port_scan"),
    ("web server attack", "web_attack"),
    ("sql injection", "web_attack"),
    ("ossec: alert", "generic_alert"),
]

_GROUP_ACTION_MAP = {
    "authentication_failed": "login_failed",
    "authentication_success": "login_success",
    "syslog": "syslog_event",
    "windows": "windows_event",
}


def normalize_wazuh(raw: dict) -> CommonEvent:
    """Konversi raw Wazuh alert → CommonEvent."""

    # --- TIMESTAMP ---
    ts_str = raw.get("timestamp", "")
    try:
        # Format ISO 8601 dengan timezone (+0000)
        ts_str = ts_str.replace("+0000", "+00:00")
        timestamp = datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    # --- RULE ---
    rule = raw.get("rule", {})
    level = rule.get("level", 0) if isinstance(rule, dict) else 0
    description = rule.get("description", "") if isinstance(rule, dict) else ""

    # --- AGENT ---
    agent = raw.get("agent", {}) if isinstance(raw.get("agent"), dict) else {}
    agent_name = agent.get("name")
    agent_ip = agent.get("ip")

    # --- DATA ---
    data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}

    # --- PRE-DECODER ---
    predecoder = raw.get("predecoder", {}) if isinstance(raw.get("predecoder"), dict) else {}

    # --- FIELD EXTRACTION ---
    src_ip = data.get("srcip") or predecoder.get("srcip")
    dst_ip = agent_ip
    dst_host = agent_name or predecoder.get("hostname")
    src_port = data.get("srcport")
    dst_port = data.get("dstport")
    if isinstance(dst_port, str) and dst_port.isdigit():
        dst_port = int(dst_port)

    user = data.get("srcuser") or data.get("dstuser")
    process = data.get("command") or data.get("cmdline")
    if not process:
        full_log = raw.get("full_log", "")
        if "powershell -enc" in str(full_log).lower():
            process = full_log  # simpen full_log sebagai process buat analisa

    action = _action_from_wazuh_rule(raw)
    result = "failure" if "fail" in description.lower() or action == "login_failed" else None
    result = "success" if action == "login_success" else result
    protocol = data.get("proto")

    # --- SEVERITY ---
    severity = _severity_wazuh(level)

    # --- MITRE ATT&CK (dari rule.mitre) ---
    mitre = rule.get("mitre", {}) if isinstance(rule, dict) else {}

    return CommonEvent(
        timestamp=timestamp,
        source="wazuh",
        src_host=None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_host=dst_host,
        dst_port=dst_port,
        user=user,
        process=process,
        action=action,
        result=result,
        protocol=protocol,
        severity=severity,
        raw_event=raw,
        extra={
            "rule_id": rule.get("id", "") if isinstance(rule, dict) else "",
            "rule_level": level,
            "rule_description": description,
            "rule_groups": rule.get("groups", []) if isinstance(rule, dict) else [],
            "mitre": mitre,
            "location": raw.get("location", ""),
            "full_log": raw.get("full_log", ""),
            "agent_id": agent.get("id", ""),
            "manager": raw.get("manager", {}).get("name", ""),
            "program": predecoder.get("program_name", ""),
        },
    )
