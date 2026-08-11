"""
Common data structures untuk SOC Log Analyzer.

CommonEvent: format universal dari semua log source.
Incident: kumpulan event yang saling terkait (hasil korelasi).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Set


@dataclass
class CommonEvent:
    """Representasi universal satu event dari log source manapun."""
    timestamp: datetime
    source: str                                        # wazuh | windows | linux | fortigate | cyberark
    src_host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_host: Optional[str] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    process: Optional[str] = None
    action: Optional[str] = None                       # login_failed, connection_blocked, priv_escalation, ...
    result: Optional[str] = None                       # success | failure | blocked | allowed
    protocol: Optional[str] = None
    severity: int = 1                                  # 1=LOW 2=MED 3=HIGH 4=CRIT (dinormalisasi)
    raw_event: Optional[dict] = None                   # data asli buat referensi balik
    extra: dict = field(default_factory=dict)          # data tambahan spesifik source


@dataclass
class Incident:
    """Satu insiden: kumpulan CommonEvent yang saling terkait."""
    id: int
    events: List[CommonEvent] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    event_count: int = 0
    unique_ips: Set[str] = field(default_factory=set)
    unique_users: Set[str] = field(default_factory=set)
    sources: Set[str] = field(default_factory=set)     # cross-source confirmation
    pattern: str = "UNKNOWN"                           # BRUTE_FORCE | PORT_SCAN | ...
    verdict: str = "UNCLEAR"                           # CONFIRMED | LIKELY_TRUE | LIKELY_FP | FALSE_POSITIVE
    confidence: float = 50.0                           # 0-100
    reasoning: List[str] = field(default_factory=list)  # langkah reasoning FP check
