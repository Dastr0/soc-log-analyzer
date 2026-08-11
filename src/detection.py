"""
Detection Engine — deteksi pola serangan + False Positive scoring.

Dua fungsi utama:
  1. detect_pattern() — menentukan insiden ini BRUTE_FORCE / PORT_SCAN / dll
  2. fp_scoring() — scoring heuristik lokal (NO INTERNET) untuk verdict TP/FP

Semua logic 100% offline — gak ada API call.
"""

import re
from datetime import datetime
from typing import List, Tuple

from src.schema import CommonEvent, Incident


# ─── IP Helpers ────────────────────────────────────────────────────

_RFC1918 = [
    re.compile(r"^10\..*"),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\..*"),
    re.compile(r"^192\.168\..*"),
]


def _is_internal_ip(ip: str) -> bool:
    """Cek apakah IP termasuk private/trusted (RFC1918)."""
    for pattern in _RFC1918:
        if pattern.match(ip):
            return True
    return False


def _is_sensitive_port(port: int) -> bool:
    return port in {22, 23, 3389, 445, 5985, 5986, 1433, 3306, 6379, 27017}


def _is_office_hours(ts: datetime) -> bool:
    """Cek apakah timestamp dalam jam kerja (08-18 WIB, UTC+7)."""
    hour = (ts.hour + 7) % 24  # approx UTC+7
    return 8 <= hour < 18


# ─── Pattern Detection ─────────────────────────────────────────────

def detect_pattern(incident: Incident) -> str:
    """
    Deteksi pola serangan dari karakteristik inciden.

    Returns:
        String: BRUTE_FORCE | PORT_SCAN | SUSPICIOUS_PROC | PRIV_ESCALATION |
                LATERAL_MOVEMENT | DATA_EXFIL | IOC_MATCH | UNKNOWN
    """
    events = incident.events
    n = len(events)
    if n == 0:
        return "UNKNOWN"

    # Kumpulkan statistik
    actions = [e.action for e in events if e.action]
    users = incident.unique_users
    n_users = len(users)
    dst_ports = set(e.dst_port for e in events if e.dst_port)
    n_ports = len(dst_ports)
    hosts = set(e.dst_host for e in events if e.dst_host)
    n_hosts = len(hosts)
    processes = [e.process for e in events if e.process]
    severities = [e.severity for e in events]

    # Hitung durasi
    if incident.start_time and incident.end_time:
        duration_min = (incident.end_time - incident.start_time).total_seconds() / 60.0
    else:
        duration_min = 0

    # --- BRUTE FORCE ---
    # >10 login_failed dari (src_ip, dst_host) yg sama
    failed = [a for a in actions if a == "login_failed"]
    if len(failed) >= 10 and len(incident.unique_ips) >= 1:
        return "BRUTE_FORCE"

    # --- PORT SCAN ---
    # 1 src_ip → >10 port beda dalam <10 menit
    if n_ports >= 10 and len(incident.unique_ips) <= 3 and duration_min < 10:
        return "PORT_SCAN"

    # --- SUSPICIOUS PROCESS ---
    suspicious_keywords = ["powershell -enc", "powershell -e ", "wmic ", "rundll32 ",
                           "certutil ", "regsvr32", "schtasks", "base64", "iex(",
                           "invoke-expression", "encodedcommand", "downloadstring",
                           "frombase64string", "start-process -windowstyle hidden"]
    for proc in processes:
        proc_lower = str(proc).lower()
        for kw in suspicious_keywords:
            if kw in proc_lower:
                return "SUSPICIOUS_PROC"

    # --- PRIVILEGE ESCALATION ---
    if "priv_escalation" in actions or "user_added_to_group" in actions:
        if max(severities) >= 3:
            return "PRIV_ESCALATION"

    # --- LATERAL MOVEMENT ---
    # Internal IP → >2 host internal beda pada port sensitif
    if n_hosts >= 3:
        has_internal = any(_is_internal_ip(ip) for ip in incident.unique_ips
                           if ip and _is_internal_ip(ip))
        has_sensitive = any(_is_sensitive_port(p) for p in dst_ports if p)
        if has_internal and has_sensitive:
            return "LATERAL_MOVEMENT"

    # --- DATA EXFIL ---
    # Many outbound connections (>50) dalam 1 jam
    if n >= 50 and duration_min < 60:
        return "DATA_EXFIL"

    return "UNKNOWN"


# ─── False Positive Scoring ────────────────────────────────────────

def fp_scoring(incident: Incident, trusted_config: dict = None) -> float:
    """
    Hitung confidence score: 0-100.
    > 75: CONFIRMED (serangan beneran)
    50-74: LIKELY_TRUE
    26-49: LIKELY_FP
    < 25: FALSE_POSITIVE

    Args:
        incident: Incident yang mau di-score.
        trusted_config: dict dari config/trusted_hosts.yaml (opsional).

    Returns:
        confidence score (0-100), makin tinggi = makin yakin ini serangan.
    """
    if trusted_config is None:
        trusted_config = {}

    score = 50.0  # start netral (UNCLEAR)
    reasoning: List[str] = []
    events = incident.events

    # ── INDIKATOR TRUE POSITIVE (tambah skor) ──

    # TP1: IP eksternal (+15)
    external_ips = [ip for ip in incident.unique_ips if ip and not _is_internal_ip(ip)]
    if external_ips:
        score += 15
        reasoning.append(f"[+15] IP eksternal: {', '.join(list(external_ips)[:3])}")

    # TP2: Port sensitif (+5)
    ports = set(e.dst_port for e in events if e.dst_port)
    sensitive = [p for p in ports if _is_sensitive_port(p)]
    if sensitive:
        score += 5
        reasoning.append(f"[+5] Port sensitif: {sensitive}")

    # TP3: User beragam (≥3) (+12)
    if len(incident.unique_users) >= 3:
        score += 12
        reasoning.append(f"[+12] {len(incident.unique_users)} user berbeda")

    # TP4: User admin (+8)
    admin_users = {"administrator", "admin", "root", "sa", "sqlserver", "postgres"}
    if incident.unique_users & admin_users:
        score += 8
        reasoning.append(f"[+8] Ada user administrator/root")

    # TP5: Di luar jam kerja (+10)
    if incident.start_time and not _is_office_hours(incident.start_time):
        score += 10
        reasoning.append(f"[+10] Di luar jam kerja ({incident.start_time.strftime('%H:%M')})")

    # TP6: Jumlah event besar (>100) (+10)
    if incident.event_count >= 100:
        score += 10
        reasoning.append(f"[+10] Jumlah besar: {incident.event_count:,} event")

    # TP7: Durasi panjang (>30 menit) (+8)
    if incident.start_time and incident.end_time:
        dur = (incident.end_time - incident.start_time).total_seconds() / 60.0
        if dur > 30:
            score += 8
            reasoning.append(f"[+8] Durasi panjang: {int(dur)} menit")

    # TP8: Severity escalation (+12) — check if severity increases over time
    sev_list = [e.severity for e in events if e.severity]
    if len(sev_list) >= 5:
        first_half = sev_list[:len(sev_list) // 2]
        second_half = sev_list[len(sev_list) // 2:]
        if max(second_half) >= max(first_half) and max(second_half) >= 3:
            score += 12
            reasoning.append("[+12] Severity meningkat (escalation)")

    # TP9: Persisten — action=failed tapi terus dilanjut (+15)
    failed_events = [e for e in events if e.result == "failure"]
    if len(failed_events) >= 20:
        score += 15
        reasoning.append(f"[+15] Persisten: {len(failed_events):,} kegagalan tetap coba")

    # TP10: Cross-source confirmation (+15)
    if len(incident.sources) >= 2:
        score += 15
        reasoning.append(f"[+15] Cross-source: {', '.join(sorted(incident.sources))}")

    # ── INDIKATOR FALSE POSITIVE (kurangi skor) ──

    # FP1: IP internal + trusted_hosts (-25)
    internal_ips = [ip for ip in incident.unique_ips if ip and _is_internal_ip(ip)]
    trusted_ips = _get_trusted_ips(trusted_config)
    matched_trusted = [ip for ip in internal_ips if ip in trusted_ips or
                       any(ip.startswith(subnet.replace("0/", "")) for subnet in trusted_ips)]
    if matched_trusted:
        score -= 25
        reasoning.append(f"[-25] IP trusted internal: {matched_trusted}")

    # FP2: Internal + jam kerja (-10)
    if internal_ips and incident.start_time and _is_office_hours(incident.start_time):
        score -= 10
        reasoning.append("[-10] IP internal + jam kerja")

    # FP3: User-agent scanner (-40)
    for event in events:
        raw = event.raw_event or {}
        full_log = str(raw.get("full_log", "")).lower()
        agent = str(raw.get("user_agent", "")).lower()
        combined = full_log + " " + agent
        for scanner in ["nessus", "qualys", "nmap", "openvas", "burp suite", "zap",
                        "rapid7", "acunetix", "nikto", "owasp"]:
            if scanner in combined:
                score -= 40
                reasoning.append(f"[-40] User-agent: {scanner} (vuln scanner)")
                break
        else:
            continue
        break

    # FP4: Prediksi — frekuensi teratur (-30)
    # Simpel: cek apakah event terjadi di jam yang sama setiap hari
    # Untuk v0.2.0: cek variance antar gap event
    if len(events) >= 3:
        gaps = []
        for i in range(1, len(events)):
            gap = (events[i].timestamp - events[i - 1].timestamp).total_seconds()
            gaps.append(gap)
        if gaps:
            mean_gap = sum(gaps) / len(gaps)
            # Cek apakah event benar² teratur (variance rendah)
            variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            if variance < 1.0 and mean_gap > 300:  # variance <1s + interval >5 menit
                score -= 30
                reasoning.append("[-30] Pola predictable (kemungkinan cron/scheduler)")

    # FP5: One-hit wonder (-15)
    if incident.event_count <= 2:
        score -= 15
        reasoning.append("[-15] <3 event (one-hit wonder)")

    # FP6: Process tool maintenance (-20)
    maintenance_procs = {"taskeng.exe", "cron", "schtasks.exe", "wmiadap.exe",
                         "mrt.exe", "mscorsvw.exe"}
    for event in events:
        if event.process:
            pl = str(event.process).lower()
            for mp in maintenance_procs:
                if mp.lower() in pl:
                    score -= 20
                    reasoning.append(f"[-20] Process maintenance: {mp}")
                    break

    # FP7: Rule description contains known false-positive patterns (-20)
    known_fp_desc = ["update", "patch", "scheduled", "backup", "health check",
                     "monitoring"]
    for event in events:
        extra = event.extra
        desc = str(extra.get("rule_description", "")).lower()
        for fp_word in known_fp_desc:
            if fp_word in desc:
                score -= 20
                reasoning.append(f"[-20] Rule description: '{fp_word}'")
                break
        else:
            continue
        break

    # Clamp score 0-100
    score = max(0.0, min(100.0, score))
    incident.confidence = round(score, 1)
    incident.reasoning = reasoning

    return score


def get_verdict(confidence: float) -> str:
    """Konversi confidence score → label verdict."""
    if confidence >= 75:
        return "CONFIRMED"
    elif confidence >= 50:
        return "LIKELY_TRUE"
    elif confidence >= 26:
        return "LIKELY_FP"
    else:
        return "FALSE_POSITIVE"


def _get_trusted_ips(config: dict) -> List[str]:
    """Extract trusted IP list dari config."""
    if not config:
        return []
    ips = set()
    known_scanners = config.get("known_scanners", {})
    trusted_hosts = config.get("trusted_hosts", {})

    for section in [known_scanners, trusted_hosts]:
        for ip in section.get("ips", []):
            if isinstance(ip, str):
                ips.add(ip)
        for subnet in section.get("subnets", []):
            if isinstance(subnet, str):
                # Simplifikasi: ambil prefix subnet
                # e.g. "10.0.3.0/24" → semua IP di 10.0.3.x di-trust
                ips.add(subnet)

    return list(ips)


def detect(incidents: List[Incident], all_events: List[CommonEvent],
           trusted_config: dict = None) -> List[Incident]:
    """
    Full detection pipeline: pattern detection + FP scoring + verdict.

    Args:
        incidents: List Incident dari correlation engine.
        all_events: Semua CommonEvent (untuk cross-reference).
        trusted_config: Config dari config/trusted_hosts.yaml.

    Returns:
        List Incident dengan field pattern, confidence, verdict terisi.
    """
    for incident in incidents:
        # Step 1: Deteksi pola serangan
        incident.pattern = detect_pattern(incident)

        # Step 2: False Positive scoring
        fp_scoring(incident, trusted_config)

        # Step 3: Verdict
        incident.verdict = get_verdict(incident.confidence)

    return incidents
