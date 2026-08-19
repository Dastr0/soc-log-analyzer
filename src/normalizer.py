"""
Normalizer: konversi raw event per-source → CommonEvent universal.

Mapping field-by-field dari setiap source ke CommonEvent schema.
"""

import ipaddress
from datetime import datetime, timezone
from typing import Optional

from src.schema import CommonEvent
from src.parsers.windows import EVENTID_ACTION_MAP, WindowsParser


def _parse_iso_timestamp(value: object, field_name: str = "timestamp") -> datetime:
    """Parse an ISO-8601 timestamp and fail explicitly when it is invalid."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing {field_name}")

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Wazuh commonly emits offsets as +0000 instead of +00:00.
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid {field_name}: {value!r}") from exc

    # Preserve the historical UTC assumption only when the source has no zone.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _first_scalar(value: object):
    """ECS fields such as host.ip may be arrays; select the first value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


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
        # Specific outcome groups must win over generic groups like "windows".
        for specific in ("authentication_failed", "authentication_success"):
            if specific in groups:
                return _GROUP_ACTION_MAP[specific]
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
    ("logon failure", "login_failed"),
    ("authentication success", "login_success"),
    ("successful login", "login_success"),
    ("logon success", "login_success"),
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
    timestamp = _parse_iso_timestamp(
        raw.get("timestamp") or raw.get("@timestamp"), "Wazuh timestamp"
    )

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
    # Strip Elastic null placeholders from data fields
    data = {k: v for k, v in data.items() if v and str(v).strip() != "-"}

    # --- PRE-DECODER ---
    predecoder = raw.get("predecoder", {}) if isinstance(raw.get("predecoder"), dict) else {}

    # --- FIELD EXTRACTION ---
    source_ns = raw.get("source", {}) if isinstance(raw.get("source"), dict) else {}
    dest_ns = raw.get("destination", {}) if isinstance(raw.get("destination"), dict) else {}
    win = _as_dict(data.get("win"))
    win_system = _as_dict(win.get("system"))
    win_eventdata = _as_dict(win.get("eventdata"))
    src_ip = (data.get("srcip") or data.get("ip")
              or win_eventdata.get("ipAddress")
              or win_eventdata.get("sourceNetworkAddress")
              or source_ns.get("ip")
              or predecoder.get("srcip") or predecoder.get("source.ip"))
    dst_ip = (data.get("dstip") or dest_ns.get("ip")
              or predecoder.get("dstip") or predecoder.get("destination.ip")
              or agent_ip)
    src_ip = _first_scalar(src_ip)
    dst_ip = _first_scalar(dst_ip)
    dst_host = agent_name or win_system.get("computer") or predecoder.get("hostname")
    port_raw = (data.get("dstport") or dest_ns.get("port") or source_ns.get("port")
                or win_eventdata.get("destinationPort")
                or data.get("srcport")
                or data.get("suricata.eve.dest_port"))
    dst_port = None
    if isinstance(port_raw, str) and port_raw.isdigit():
        dst_port = int(port_raw)
    elif isinstance(port_raw, int):
        dst_port = port_raw

    user = (data.get("srcuser") or data.get("dstuser")
            or win_eventdata.get("targetUserName")
            or win_eventdata.get("subjectUserName")
            or data.get("suricata.eve.user"))
    process = (data.get("command") or data.get("cmdline")
               or win_eventdata.get("commandLine")
               or win_eventdata.get("newProcessName")
               or win_eventdata.get("processName"))
    protocol = (data.get("proto") or win_eventdata.get("protocol")
                or data.get("suricata.eve.proto"))
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

    # prefer log.original/host > full_log > message (longest first)
    candidates = [
        raw.get("log.original", ""),
        raw.get("host", ""),
        raw.get("full_log", ""),
        raw.get("message", ""),
    ]
    full_log_text = max(
        (c for c in candidates if c and len(c) > 50),
        key=len, default=""
    )

    # ── Wazuh archives: structured fields kosong → parse full_log ──
    is_archive = (not src_ip and not user and not process and not protocol
                  and level == 0 and full_log_text)
    # Also: if structured fields exist but are clearly invalid (non-IP strings)
    src_invalid = src_ip and not _looks_like_ip(src_ip)
    dst_invalid = dst_ip and not _looks_like_ip(dst_ip)
    needs_fallback = is_archive or src_invalid or dst_invalid

    if needs_fallback and full_log_text:
        fallback = _extract_from_full_log(full_log_text)
        if src_invalid or not src_ip:
            src_ip = fallback.get("srcip") or src_ip
        if dst_invalid or not dst_ip:
            dst_ip = fallback.get("dstip") or dst_ip
        if not dst_port:
            p = fallback.get("dstport")
            if p: dst_port = _safe_int(p)
        if not user or user in ("N/A", "?"):
            user = fallback.get("user")
        if not protocol:
            protocol = fallback.get("proto")
        if not action or action == "generic_alert":
            fb_action = fallback.get("action")
            if fb_action:
                action = fb_action
        if level == 0 and severity == 1:
            sev = fallback.get("severity")
            if sev:
                severity = sev

    # Post-normalize cleanup: strip obviously invalid values
    if src_ip and not _looks_like_ip(src_ip):
        src_ip = None
    if dst_ip and not _looks_like_ip(dst_ip):
        dst_ip = None
    if user and (user == "N/A" or len(user) > 30 or ":" in user
                 or _looks_like_uuid(user)):
        user = None  # UUID/MAC/N/A → None

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
            "event_id": (win_system.get("eventID") or win_system.get("eventId")
                         or data.get("id") or ""),
            "logon_type": win_eventdata.get("logonType", ""),
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

    # eventtime is authoritative; date/time + tz is the fallback.
    timestamp = _parse_fortigate_time(raw)

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
    if action in ("accept", "pass", "start"):
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


def _parse_fortigate_time(raw: dict) -> datetime:
    """Parse FortiGate eventtime or local date/time with its tz offset."""
    eventtime = raw.get("eventtime")
    if eventtime not in (None, ""):
        try:
            epoch = int(str(eventtime).strip())
            magnitude = abs(epoch)
            if magnitude >= 10**17:      # nanoseconds
                seconds = epoch / 1_000_000_000
            elif magnitude >= 10**14:    # microseconds
                seconds = epoch / 1_000_000
            elif magnitude >= 10**11:    # milliseconds
                seconds = epoch / 1_000
            else:                        # seconds
                seconds = epoch
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (ValueError, TypeError, OSError, OverflowError):
            # Some exports contain a damaged eventtime but a valid date/time.
            pass

    explicit = raw.get("timestamp")
    if explicit:
        return _parse_iso_timestamp(explicit, "FortiGate timestamp")

    date_value = raw.get("date")
    time_value = raw.get("time")
    if not date_value or not time_value:
        raise ValueError("missing FortiGate eventtime and date/time")

    zone = str(raw.get("tz") or "").strip()
    if zone and zone not in ("Z", "UTC"):
        if len(zone) == 5 and zone[0] in "+-" and zone[1:].isdigit():
            zone = zone[:3] + ":" + zone[3:]
    elif zone in ("Z", "UTC"):
        zone = "+00:00"

    return _parse_iso_timestamp(
        f"{date_value}T{time_value}{zone}", "FortiGate date/time"
    )


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

    timestamp = _parse_iso_timestamp(
        raw.get("timestamp") or raw.get("@timestamp"), "Windows/Wazuh timestamp"
    )

    # Rule
    rule = raw.get("rule", {}) if isinstance(raw.get("rule"), dict) else {}
    level = _to_int(rule.get("level", 0))

    # Agent (host yang dimonitor — biasanya target Windows host)
    agent = raw.get("agent", {}) if isinstance(raw.get("agent"), dict) else {}
    agent_name = agent.get("name")
    agent_ip = agent.get("ip")

    # Data fields (spesifik Windows, lebih kaya dari Wazuh Linux)
    data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}
    # Strip Elastic null placeholders from data fields
    data = {k: v for k, v in data.items() if v and str(v).strip() != "-"}
    win = _as_dict(data.get("win"))
    win_system = _as_dict(win.get("system"))
    win_eventdata = _as_dict(win.get("eventdata"))

    # Windows-specific extraction
    user = (data.get("dstuser") or data.get("srcuser") or
            data.get("TargetUserName") or data.get("target_user") or
            win_eventdata.get("targetUserName") or
            win_eventdata.get("subjectUserName"))
    src_ip = (data.get("srcip") or data.get("SourceIp") or
              data.get("IpAddress") or data.get("source_ip") or
              win_eventdata.get("ipAddress") or
              win_eventdata.get("sourceNetworkAddress"))
    process = (data.get("command") or data.get("CommandLine") or
               data.get("cmd") or data.get("process") or
               win_eventdata.get("commandLine") or
               win_eventdata.get("newProcessName") or
               win_eventdata.get("processName"))
    dst_port = _safe_int(
        data.get("dstport") or data.get("DestPort") or data.get("dest_port") or
        win_eventdata.get("destinationPort")
    )
    src_ip = _first_scalar(src_ip)

    # Event ID → action
    wp = WindowsParser.__new__(WindowsParser)
    wp._mode = "wazuh"
    event_id = wp.extract_event_id(raw)
    action = wp.extract_action(raw)

    result = "failure" if action == "login_failed" else (
        "success" if action == "login_success" else None)

    severity = _severity_wazuh(level)

    return CommonEvent(
        timestamp=timestamp,
        source="windows",
        src_host=win_eventdata.get("workstationName"),
        src_ip=src_ip,
        dst_ip=agent_ip,          # agent.ip = host yang dimonitor
        dst_host=agent_name or win_system.get("computer"),
        dst_port=dst_port,
        user=user,
        process=process,
        action=action,
        result=result,
        protocol=win_eventdata.get("protocol"),
        severity=severity,
        raw_event=raw,
        extra={
            "event_id": event_id,
            "logon_type": (win_eventdata.get("logonType") or
                           data.get("logon_type") or data.get("LogonType") or ""),
            "status": win_eventdata.get("status", ""),
            "sub_status": win_eventdata.get("subStatus", ""),
            "rule_id": rule.get("id", "") if isinstance(rule, dict) else "",
            "rule_description": rule.get("description", "") if isinstance(rule, dict) else "",
            "location": raw.get("location", ""),
            "full_log": raw.get("full_log", ""),
            "agent_id": agent.get("id", ""),
        },
    )


def _normalize_windows_generic(raw: dict) -> CommonEvent:
    """Windows event dari format generic Elastic/winlogbeat."""

    timestamp = _parse_iso_timestamp(
        raw.get("@timestamp") or raw.get("timestamp"), "Winlogbeat timestamp"
    )

    # Winlog fields
    winlog = raw.get("winlog", {})
    if not isinstance(winlog, dict):
        winlog = {}

    event_ns = _as_dict(raw.get("event"))
    event_id_raw = (winlog.get("event_id") or event_ns.get("code") or
                    raw.get("event_id") or raw.get("EventID") or
                    raw.get("event.code"))
    event_id = str(event_id_raw) if event_id_raw not in (None, "") else ""
    action = EVENTID_ACTION_MAP.get(event_id, "windows_event")

    # Host
    host_ns = _as_dict(raw.get("host"))
    agent_ns = _as_dict(raw.get("agent"))
    host = (winlog.get("computer_name") or host_ns.get("name") or
            raw.get("computer_name", ""))
    agent_ip = _first_scalar(host_ns.get("ip") or agent_ns.get("ip"))

    # Event data
    event_data = _as_dict(winlog.get("event_data"))
    if not event_data:
        event_data = _as_dict(raw.get("event_data")) or _as_dict(raw.get("EventData"))

    user = (event_data.get("TargetUserName") or
            event_data.get("targetUserName") or
            _as_dict(raw.get("user")).get("name") or
            raw.get("user_name"))

    src_ip = (event_data.get("IpAddress") or
              event_data.get("ipAddress") or
              event_data.get("SourceNetworkAddress") or
              _as_dict(raw.get("source")).get("ip"))
    src_ip = _first_scalar(src_ip)
    process = (event_data.get("CommandLine") or
               event_data.get("commandLine") or
               event_data.get("NewProcessName") or
               event_data.get("ProcessName"))
    dst_port = _safe_int(event_data.get("DestinationPort") or
                         event_data.get("DestPort"))
    protocol = event_data.get("Protocol") or event_data.get("protocol")

    result = "failure" if action == "login_failed" else (
        "success" if action == "login_success" else None)

    return CommonEvent(
        timestamp=timestamp,
        source="windows",
        src_host=(event_data.get("WorkstationName") or
                  event_data.get("workstationName")),
        src_ip=src_ip,
        dst_host=host,
        dst_ip=agent_ip,
        dst_port=dst_port,
        user=user,
        process=process,
        action=action,
        result=result,
        protocol=protocol,
        severity=2,  # default MEDIUM
        raw_event=raw,
        extra={
            "event_id": event_id,
            "log_name": winlog.get("channel") or winlog.get("log_name", ""),
            "provider": winlog.get("provider_name", ""),
            "keywords": winlog.get("keywords", ""),
            "task": winlog.get("task", ""),
            "logon_type": (event_data.get("LogonType") or
                           event_data.get("logonType") or ""),
            "status": event_data.get("Status", ""),
            "sub_status": event_data.get("SubStatus", ""),
        },
    )


def _is_ip_internal(ip: str) -> bool:
    """Check private, loopback, or link-local IPv4/IPv6 addresses."""
    try:
        parsed = ipaddress.ip_address(str(ip).split("%", 1)[0])
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local
    except ValueError:
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


def _looks_like_uuid(s: str) -> bool:
    """Detect UUID format: 8-4-4-4-12 hex digits with hyphens."""
    if not s or "-" not in s or len(s) < 14:
        return False
    parts = s.split("-")
    # UUID v4: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (or shorter variants)
    return len(parts) >= 3 and all(
        all(c.lower() in "0123456789abcdef" for c in p)
        for p in parts[:5]
    )


def _looks_like_ip(s: str) -> bool:
    """Validate IPv4 or IPv6 without accepting arbitrary dotted strings."""
    if not isinstance(s, str) or not s.strip():
        return False
    try:
        ipaddress.ip_address(s.strip().split("%", 1)[0])
        return True
    except ValueError:
        return False
