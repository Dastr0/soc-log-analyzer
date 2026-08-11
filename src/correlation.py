"""
Correlation Engine — mengelompokkan event individual menjadi insiden.

Cara kerja:
  1. Semua CommonEvent diurutkan berdasarkan timestamp.
  2. Untuk setiap correlation key (misal: (src_ip, dst_host)),
     event yang match kunci + dalam window waktu → 1 grup.
  3. Grup yang melebihi threshold min_events → Incident.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List, Optional

from src.schema import CommonEvent, Incident


# ─── Correlation Rules ─────────────────────────────────────────────
# Tiap rule: key_fields utk grouping, window, min_events.
# Kunci ini menentukan "kejadian mana yang saling terkait?"

CORRELATION_RULES = [
    {
        "name": "src_ip->dst_host",
        "key_fields": ["src_ip", "dst_host"],
        "window_minutes": 15,
        "min_events": 3,
    },
    {
        "name": "src_ip->dst_host (long window)",
        "key_fields": ["src_ip", "dst_host"],
        "window_minutes": 60,
        "min_events": 10,
    },
    {
        "name": "src_ip (firewall/blocked)",
        "key_fields": ["src_ip"],
        "window_minutes": 15,
        "min_events": 5,
    },
    {
        "name": "src_ip + dst_port",
        "key_fields": ["src_ip", "dst_port"],
        "window_minutes": 15,
        "min_events": 3,
    },
    {
        "name": "src_ip + dst_ip",
        "key_fields": ["src_ip", "dst_ip"],
        "window_minutes": 15,
        "min_events": 3,
    },
    {
        "name": "src_host + process",
        "key_fields": ["src_host", "process"],
        "window_minutes": 60,
        "min_events": 1,
    },
    {
        "name": "dst_ip + dst_port",
        "key_fields": ["dst_ip", "dst_port"],
        "window_minutes": 15,
        "min_events": 5,
    },
]


def _make_key(event: CommonEvent, key_fields: List[str]) -> Optional[tuple]:
    """
    Buat tuple key dari CommonEvent berdasarkan field yang diminta.
    Contoh: key_fields=["src_ip","dst_host"] → ("203.0.113.5","DC01")
    Return None jika ada field wajib yang kosong.
    """
    parts = []
    for field in key_fields:
        val = getattr(event, field, None)
        if val is None:
            return None  # key nggak lengkap → nggak ikut grouping ini
        parts.append(str(val))
    return tuple(parts)


def correlate(events: List[CommonEvent]) -> List[Incident]:
    """
    Kelompokkan event menjadi insiden.

    Args:
        events: List CommonEvent, diurutkan by timestamp.

    Returns:
        List Incident, sudah terurut by severity+count (paling penting dulu).
    """
    if not events:
        return []

    # urutkan by timestamp (seharusnya sudah terurut dari file, tapi amankan)
    events.sort(key=lambda e: e.timestamp)

    incidents: List[Incident] = []
    incident_id = 0

    # Untuk tiap correlation rule
    for rule in CORRELATION_RULES:
        window = timedelta(minutes=rule["window_minutes"])
        min_events = rule["min_events"]

        # Kumpulkan event per key
        groups: dict[tuple, List[CommonEvent]] = defaultdict(list)
        for event in events:
            key = _make_key(event, rule["key_fields"])
            if key:
                groups[key].append(event)

        # Untuk tiap grup, bikin Incident kalau memenuhi threshold
        for key, group_events in groups.items():
            if len(group_events) < min_events:
                continue

            # Pecah grup menjadi sub-grup berdasarkan window sliding
            sub_groups = _split_by_window(group_events, window)

            for sub_events in sub_groups:
                if len(sub_events) < min_events:
                    continue

                incident_id += 1
                incident = Incident(
                    id=incident_id,
                    events=sub_events,
                    start_time=sub_events[0].timestamp,
                    end_time=sub_events[-1].timestamp,
                    event_count=len(sub_events),
                    unique_ips=_extract_unique_ips(sub_events),
                    unique_users=_extract_unique_users(sub_events),
                    sources=_extract_sources(sub_events),
                )
                incidents.append(incident)

    # Deduplicate: incident yang overlap kejadiannya (bisa dari beda rule)
    incidents = _deduplicate(incidents)

    # Urutkan: severity tertinggi + count terbanyak → paling atas
    incidents.sort(key=lambda i: (i.event_count, len(i.unique_ips)), reverse=True)

    return incidents


def _split_by_window(events: List[CommonEvent], window: timedelta) -> List[List[CommonEvent]]:
    """
    Pecah list event jadi sub-grup berdasarkan sliding window.
    Setiap sub-grup: event pertama → terakhir ≤ window.
    """
    if not events:
        return []

    groups: List[List[CommonEvent]] = []
    current_group: List[CommonEvent] = []

    for event in events:
        if not current_group:
            current_group = [event]
        elif event.timestamp - current_group[0].timestamp <= window:
            current_group.append(event)
        else:
            groups.append(current_group)
            current_group = [event]

    if current_group:
        groups.append(current_group)

    return groups


def _extract_unique_ips(events: List[CommonEvent]) -> set:
    ips = set()
    for e in events:
        if e.src_ip:
            ips.add(e.src_ip)
        if e.dst_ip:
            ips.add(e.dst_ip)
    return ips


def _extract_unique_users(events: List[CommonEvent]) -> set:
    users = set()
    for e in events:
        if e.user:
            users.add(e.user)
    return users


def _extract_sources(events: List[CommonEvent]) -> set:
    return set(e.source for e in events if e.source)


def _deduplicate(incidents: List[Incident]) -> List[Incident]:
    """
    Gabung insiden yang overlap event-nya (>50% event sama).
    """
    if len(incidents) <= 1:
        return incidents

    # Sederhana: sort by size descending, lalu merge overlap
    incidents.sort(key=lambda i: i.event_count, reverse=True)
    merged: List[Incident] = []
    seen_events: set = set()  # id() dari CommonEvent

    for inc in incidents:
        # Berapa event yang udah kena di insiden sebelumnya?
        event_ids = set(id(e) for e in inc.events)
        overlap = event_ids & seen_events

        if len(overlap) > len(event_ids) * 0.5:
            # >50% overlap → merge (tambah source ke insiden yg udah ada)
            continue

        seen_events.update(event_ids)
        merged.append(inc)

    return merged
