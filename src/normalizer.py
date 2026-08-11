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
    level = _to_int(rule.get("level", 0)) if isinstance(rule, dict) else 0
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
    source_ns = raw.get("source", {}) if isinstance(raw.get("source"), dict) else {}
    dest_ns = raw.get("destination", {}) if isinstance(raw.get("destination"), dict) else {}
    src_ip = (data.get("srcip") or source_ns.get("ip")
              or predecoder.get("srcip") or predecoder.get("source.ip"))
    dst_ip = (data.get("dstip") or dest_ns.get("ip")
              or predecoder.get("dstip") or predecoder.get("destination.ip")
              or agent_ip)
    dst_host = agent_name or predecoder.get("hostname")
    port_raw = (data.get("dstport") or dest_ns.get("port") or source_ns.get("port")
                or data.get("srcport")
                or data.get("suricata.eve.dest_port"))
    dst_port = None
    if isinstance(port_raw, str) and port_raw.isdigit():
        dst_port = int(port_raw)
    elif isinstance(port_raw, int):
        dst_port = port_raw

    user = (data.get("srcuser") or data.get("dstuser")
            or data.get("suricata.eve.user"))
    process = data.get("command") or data.get("cmdline")
    protocol = data.get("proto") or data.get("suricata.eve.proto")
    action = _action_from_wazuh_rule(raw)  # default dari rule
    # Override action from data.action (FortiGate: pass/deny/close)
    if data.get("action") and data["action"] in ("pass", "deny", "close", "accept", "drop", "block"):
        da = data["action"].lower()
        if da in ("deny", "drop", "block"):
            action = "connection_blocked"
        elif da in ("pass", "accept"):
            action = "connection_allowed"
        elif da == "close":
            action = "connection_closed"
    severity = _severity_wazuh(level)

    full_log_text = raw.get("full_log", "")

    # ── Wazuh archives: structured fields kosong → parse full_log ──
    is_archive = (not src_ip and not user and not process and not protocol
                  and level == 0 and full_log_text)
    if is_archive and full_log_text:
        fallback = _extract_from_full_log(full_log_text)
        src_ip = fallback.get("srcip") or src_ip
        dst_ip = fallback.get("dstip") or dst_ip
        if not dst_port:
            p = fallback.get("dstport")
            if p: dst_port = _safe_int(p)
        if not user:
            user = fallback.get("user")
        if not protocol:
            protocol = fallback.get("proto")
        # Action from full_log pattern
        if not action or action == "generic_alert":
            fb_action = fallback.get("action")
            if fb_action:
                action = fb_action
        # Severity: traffic deny=HIGH, archive=MED default
        if level == 0 and severity == 1:
            sev = fallback.get("severity")
            if sev:
                severity = sev

    if not process:
        if "powershell -enc" in str(full_log_text).lower():
            process = full_log_text

    result = "failure" if "fail" in description.lower() or action == "login_failed" else None
    result = "success" if action == "login_success" else result

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


# ═══════════════════════════════════════════════════════════════════
# FortiGate Normalizer
# ═══════════════════════════════════════════════════════════════════


def _proto_name(proto_int: Optional[int]) -> Optional[str]:
    """Convert proto number → common name."""
    if proto_int is None:
        return None
    _map = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 50: "ESP", 51: "AH"}
    return _map.get(proto_int, str(proto_int))


def normalize_fortigate(raw: dict) -> CommonEvent:
    """Konversi raw FortiGate syslog event → CommonEvent.
    Support native syslog parser (dg _timestamp, _dstport_int, dll)
    maupun CSV parser (dg timestamp, dstport string, dll).
    """

    # Timestamp: coba _timestamp (native parser) → timestamp (CSV) → date+time
    ts_str = (raw.get("_timestamp")
              or raw.get("timestamp")
              or f"{raw.get('date', '')}T{raw.get('time', '')}")
    try:
        timestamp = _parse_fortigate_time(ts_str)
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    # Fields: _*_int (native parser) dengan fallback ke string (CSV)
    src_ip = raw.get("srcip")
    dst_ip = raw.get("dstip")
    dst_port = (_safe_int(raw.get("_dstport_int"))
                or _safe_int(raw.get("dstport")))
    src_host = raw.get("devname")
    proto_int = (_safe_int(raw.get("_proto_int"))
                 or _safe_int(raw.get("proto")))

    action = raw.get("action", "").lower()
    log_type = raw.get("type", "")
    subtype = raw.get("subtype", "")

    # Map action → common label
    if action == "accept":
        common_action = "connection_allowed"
        result = "allowed"
    elif action in ("deny", "drop", "block"):
        common_action = "connection_blocked"
        result = "blocked"
    elif action == "close":
        common_action = "connection_closed"
        result = "closed"
    elif action in ("timeout", "reset"):
        common_action = "connection_terminated"
        result = "terminated"
    else:
        common_action = f"fortigate_{action}" if action else None
        result = action

    # Severity dari level + action
    severity = 2  # default MEDIUM
    if action == "deny" and dst_port and int(dst_port) in {22, 3389, 445, 5985}:
        severity = 3  # HIGH — blocked access to sensitive port
    if action == "accept" and dst_ip and not _is_ip_internal(dst_ip):
        severity = 2  # outbound external — could be exfil

    # Extra info
    sent_bytes = (_safe_int(raw.get("_sentbyte_int"))
                  or _safe_int(raw.get("sentbyte")))
    rcvd_bytes = (_safe_int(raw.get("_rcvdbyte_int"))
                  or _safe_int(raw.get("rcvdbyte")))
    duration = (_safe_int(raw.get("_duration_int"))
                or _safe_int(raw.get("duration")))

    return CommonEvent(
        timestamp=timestamp,
        source="fortigate",
        src_host=src_host,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_host=None,
        dst_port=dst_port,
        user=None,
        process=None,
        action=common_action,
        result=result,
        protocol=_proto_name(proto_int),
        severity=severity,
        raw_event=raw,
        extra={
            "log_type": log_type,
            "subtype": subtype,
            "service": raw.get("service", ""),
            "policy_id": raw.get("policyid", ""),
            "sent_bytes": sent_bytes,
            "rcvd_bytes": rcvd_bytes,
            "duration": duration,
            "log_id": raw.get("logid", ""),
        },
    )


def _parse_fortigate_time(ts: str) -> datetime:
    """Parse timestamp FortiGate: 2026-08-10T08:33:17."""
    from datetime import datetime as dt
    # Coba ISO lengkap dulu
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return dt.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════
# Windows EventLog Normalizer
# ═══════════════════════════════════════════════════════════════════


def normalize_windows(raw: dict) -> CommonEvent:
    """Konversi raw Windows event → CommonEvent. Auto-detect mode."""
    mode = raw.get("_parser_mode", "generic")

    if mode == "wazuh":
        return _normalize_windows_wazuh(raw)
    else:
        return _normalize_windows_generic(raw)


def _normalize_windows_wazuh(raw: dict) -> CommonEvent:
    """Windows event dari Wazuh JSONL (format mirip alerts.json)."""

    # Timestamp
    ts_str = raw.get("timestamp", "")
    try:
        ts_str = ts_str.replace("+0000", "+00:00")
        timestamp = datetime.fromisoformat(ts_str)
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    # Rule
    rule = raw.get("rule", {}) if isinstance(raw.get("rule"), dict) else {}
    level = _to_int(rule.get("level", 0))

    # Agent (host yang dimonitor — biasanya target Windows host)
    agent = raw.get("agent", {}) if isinstance(raw.get("agent"), dict) else {}
    agent_name = agent.get("name")
    agent_ip = agent.get("ip")

    # Data fields (spesifik Windows, lebih kaya dari Wazuh Linux)
    data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}

    # Windows-specific extraction
    user = (data.get("dstuser") or data.get("srcuser") or
            data.get("TargetUserName") or data.get("target_user"))
    src_ip = (data.get("srcip") or data.get("SourceIp") or
              data.get("IpAddress") or data.get("source_ip"))
    process = (data.get("command") or data.get("CommandLine") or
               data.get("cmd") or data.get("process"))
    dst_port = data.get("dstport") or data.get("DestPort") or data.get("dest_port")
    if isinstance(dst_port, str) and dst_port.isdigit():
        dst_port = int(dst_port)

    # Event ID → action
    from src.parsers.windows import WindowsParser
    wp = WindowsParser.__new__(WindowsParser)
    event_id = wp.extract_event_id(raw)
    action = wp.extract_action(raw)

    result = "failure" if action == "login_failed" else (
        "success" if action == "login_success" else None)

    severity = _severity_wazuh(level)

    return CommonEvent(
        timestamp=timestamp,
        source="windows",
        src_host=None,
        src_ip=src_ip,
        dst_ip=agent_ip,          # agent.ip = host yang dimonitor
        dst_host=agent_name,
        dst_port=dst_port,
        user=user,
        process=process,
        action=action,
        result=result,
        protocol=None,
        severity=severity,
        raw_event=raw,
        extra={
            "event_id": event_id,
            "rule_id": rule.get("id", "") if isinstance(rule, dict) else "",
            "rule_description": rule.get("description", "") if isinstance(rule, dict) else "",
            "location": raw.get("location", ""),
            "full_log": raw.get("full_log", ""),
            "agent_id": agent.get("id", ""),
        },
    )


def _normalize_windows_generic(raw: dict) -> CommonEvent:
    """Windows event dari format generic Elastic/winlogbeat."""

    # Timestamp
    ts_str = raw.get("@timestamp") or raw.get("timestamp", "")
    try:
        timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        timestamp = datetime.now(timezone.utc)

    # Winlog fields
    winlog = raw.get("winlog", {})
    if not isinstance(winlog, dict):
        winlog = {}

    event_id = str(winlog.get("event_id") or raw.get("event_id", ""))
    action = _EVENTID_ACTION_MAP.get(event_id, "windows_event")

    # Host
    host = raw.get("host", {}).get("name") or raw.get("computer_name", "")
    agent_ip = raw.get("host", {}).get("ip") or raw.get("agent", {}).get("ip", "")

    # Event data
    event_data = raw.get("event_data", {})
    if not isinstance(event_data, dict):
        event_data = raw.get("EventData", {}) if isinstance(raw.get("EventData"), dict) else {}

    user = (event_data.get("TargetUserName") or
            raw.get("user", {}).get("name") or
            raw.get("user_name"))

    src_ip = (event_data.get("IpAddress") or
              event_data.get("SourceNetworkAddress"))
    process = (event_data.get("NewProcessName") or
               event_data.get("CommandLine") or
               event_data.get("ProcessName"))

    result = "failure" if action == "login_failed" else (
        "success" if action == "login_success" else None)

    return CommonEvent(
        timestamp=timestamp,
        source="windows",
        src_ip=src_ip,
        dst_host=host,
        dst_ip=agent_ip,
        user=user,
        process=process,
        action=action,
        result=result,
        severity=2,  # default MEDIUM
        raw_event=raw,
        extra={
            "event_id": event_id,
            "log_name": winlog.get("channel") or winlog.get("log_name", ""),
            "provider": winlog.get("provider_name", ""),
            "keywords": winlog.get("keywords", ""),
            "task": winlog.get("task", ""),
        },
    )


def _is_ip_internal(ip: str) -> bool:
    """Check RFC1918."""
    import re
    for pattern in [
        re.compile(r"^10\..*"),
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\..*"),
        re.compile(r"^192\.168\..*"),
    ]:
        if pattern.match(ip):
            return True
    return False


def _safe_int(value, default=None):
    """Safe int conversion — return None kalau gagal."""
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _extract_from_full_log(full_log: str) -> dict:
    """
    Parse full_log text untuk extract fields (fallback saat structured data kosong).

    Format yang dikenali:
      - FortiGate syslog: key=value pairs
      - SSH auth: "Failed password for user from IP port 22"
      - Generic: ambil IP pertama, port pertama
    """
    import re
    result: dict = {}
    if not full_log:
        return result

    # ── FortiGate syslog: date=... time=... devname=... srcip=... ──
    ftg_match = re.findall(r'(\w+)=("[^"]*"|\S+)', full_log)
    if len(ftg_match) >= 5:
        for k, v in ftg_match:
            v = v.strip('"').strip("'")
            k_lower = k.lower()
            if k_lower == "srcip":
                result["srcip"] = v
            elif k_lower == "dstip":
                result["dstip"] = v
            elif k_lower in ("dstport", "srcport"):
                result[k_lower] = v
            elif k_lower == "proto":
                result["proto"] = v
            elif k_lower == "action" and v.lower() in ("accept", "deny", "drop", "block"):
                result["action"] = "connection_allowed" if v.lower() == "accept" else "connection_blocked"
                result["severity"] = 3 if v.lower() in ("deny", "block") else 2
            elif k_lower == "devname":
                result["devname"] = v

    # ── SSH: Failed password for <user> from <ip> port <port> ──
    ssh_match = re.match(
        r".*[Ff]ailed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)",
        full_log
    )
    if ssh_match:
        result["user"] = ssh_match.group(1)
        result["srcip"] = result.get("srcip") or ssh_match.group(2)
        result["dstport"] = result.get("dstport") or ssh_match.group(3)
        result["action"] = "login_failed"
        result["severity"] = result.get("severity") or 3

    # ── Generic IP extraction (last resort) ──
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    ips = re.findall(ip_pattern, full_log)
    # Filter out known non-routable artifacts (0.x, 127.x, etc.)
    real_ips = [ip for ip in ips if not ip.startswith(("0.", "127.", "255."))]
    if real_ips:
        if not result.get("srcip"):
            result["srcip"] = real_ips[0]
        if len(real_ips) > 1 and not result.get("dstip"):
            result["dstip"] = real_ips[-1]

    return result


def _to_int(value, default=0):
    """Convert string/int ke int, fallback ke default."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
