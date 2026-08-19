import csv
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.normalizer import normalize_fortigate, normalize_wazuh, normalize_windows
from src.parsers.csv_elastic import CsvElasticParser
from src.parsers.fortigate import FortiGateParser
from src.parsers.windows import WindowsParser
from src.parsers.wazuh import WazuhParser


ROOT = Path(__file__).resolve().parents[1]


class TempFileTestCase(unittest.TestCase):
    def setUp(self):
        self._tempdir = tempfile.TemporaryDirectory()
        self.tempdir = Path(self._tempdir.name)

    def tearDown(self):
        self._tempdir.cleanup()

    def write_text(self, name, text):
        path = self.tempdir / name
        path.write_text(text, encoding="utf-8")
        return path

    def write_csv(self, name, fieldnames, row):
        path = self.tempdir / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(row)
        return path


class WindowsParsingTests(TempFileTestCase):
    def test_generic_winlogbeat_event_is_fully_normalized(self):
        raw = {
            "@timestamp": "2026-08-10T08:30:00.000Z",
            "agent": {"name": "winlogbeat"},
            "host": {"name": "DC01", "ip": ["10.0.0.5"]},
            "event": {"code": "4625"},
            "winlog": {
                "event_id": 4625,
                "channel": "Security",
                "computer_name": "DC01.corp.local",
                "event_data": {
                    "TargetUserName": "alice",
                    "IpAddress": "203.0.113.9",
                    "LogonType": "3",
                    "WorkstationName": "CLIENT01",
                },
            },
        }
        path = self.write_text("winlogbeat.json", json.dumps(raw) + "\n")

        parsed = list(WindowsParser(str(path)).parse())
        event = normalize_windows(parsed[0])

        self.assertEqual(event.action, "login_failed")
        self.assertEqual(event.result, "failure")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.src_ip, "203.0.113.9")
        self.assertEqual(event.src_host, "CLIENT01")
        self.assertEqual(event.dst_ip, "10.0.0.5")
        self.assertEqual(event.dst_host, "DC01.corp.local")
        self.assertEqual(event.extra["event_id"], "4625")
        self.assertEqual(event.extra["logon_type"], "3")

    def test_wazuh_eventchannel_uses_actual_event_id_and_nested_fields(self):
        raw = {
            "timestamp": "2026-08-10T08:30:00.000+0000",
            "rule": {
                "id": "60122",
                "level": 5,
                "description": "Logon Failure - Unknown user or bad password",
            },
            "agent": {"id": "001", "name": "DC01", "ip": "10.0.0.5"},
            "data": {
                "win": {
                    "system": {"eventID": "4625", "computer": "DC01"},
                    "eventdata": {
                        "targetUserName": "alice",
                        "ipAddress": "2001:db8::9",
                        "logonType": "10",
                    },
                }
            },
            "location": "EventChannel",
        }
        path = self.write_text("wazuh-windows.json", json.dumps(raw) + "\n")

        parsed = list(WindowsParser(str(path)).parse())
        event = normalize_windows(parsed[0])

        self.assertEqual(event.action, "login_failed")
        self.assertEqual(event.result, "failure")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.src_ip, "2001:db8::9")
        self.assertEqual(event.extra["event_id"], "4625")

    def test_wazuh_rule_fallback_maps_success_and_failure_correctly(self):
        parser = WindowsParser.__new__(WindowsParser)
        parser._mode = "wazuh"

        success = {"_parser_mode": "wazuh", "rule": {"id": "60106"}, "data": {}}
        failure = {"_parser_mode": "wazuh", "rule": {"id": "60122"}, "data": {}}

        self.assertEqual(parser.extract_event_id(success), "4624")
        self.assertEqual(parser.extract_action(success), "login_success")
        self.assertEqual(parser.extract_event_id(failure), "4625")
        self.assertEqual(parser.extract_action(failure), "login_failed")


class CsvParsingTests(TempFileTestCase):
    def setUp(self):
        super().setUp()
        CsvElasticParser._yaml_cache = None
        CsvElasticParser._yaml_loaded = False

    def test_windows_csv_with_agent_name_is_not_misclassified(self):
        fields = [
            "@timestamp", "agent.name", "winlog.event_id",
            "winlog.event_data.TargetUserName",
            "winlog.event_data.IpAddress", "host.name", "host.ip",
        ]
        path = self.write_csv("windows.csv", fields, {
            "@timestamp": "2026-08-10T08:30:00.000Z",
            "agent.name": "winlogbeat",
            "winlog.event_id": "4625",
            "winlog.event_data.TargetUserName": "alice",
            "winlog.event_data.IpAddress": "203.0.113.9",
            "host.name": "DC01",
            "host.ip": "10.0.0.5",
        })

        # Directory analysis may provide a filename-based fallback hint; the
        # distinctive columns must still win when the hint is not explicit.
        parser = CsvElasticParser(str(path), source_hint="wazuh")
        parsed = list(parser.parse())
        event = normalize_windows(parsed[0])

        self.assertEqual(parser.detected_source, "windows")
        self.assertEqual(event.action, "login_failed")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.src_ip, "203.0.113.9")

    def test_explicit_source_hint_overrides_detection(self):
        path = self.write_csv("ambiguous.csv", ["agent.name", "rule.id"], {
            "agent.name": "DC01", "rule.id": "60122",
        })
        parser = CsvElasticParser(
            str(path), source_hint="windows", source_hint_authoritative=True
        )
        list(parser.parse())
        self.assertEqual(parser.detected_source, "windows")

    def test_wazuh_rule_level_mapping_preserves_id_and_severity(self):
        fields = [
            "timestamp", "rule.id", "rule.level", "rule.description",
            "rule.groups", "agent.name", "data.srcip", "data.dstuser",
        ]
        path = self.write_csv("wazuh.csv", fields, {
            "timestamp": "2026-08-10T08:30:00.000Z",
            "rule.id": "60122",
            "rule.level": "5",
            "rule.description": "Logon failure - Unknown user or bad password",
            "rule.groups": json.dumps(["windows", "authentication_failed"]),
            "agent.name": "DC01",
            "data.srcip": "203.0.113.9",
            "data.dstuser": "alice",
        })

        parser = CsvElasticParser(str(path), source_hint="wazuh")
        parsed = list(parser.parse())
        event = normalize_wazuh(parsed[0])

        self.assertEqual(parsed[0]["rule"]["id"], "60122")
        self.assertEqual(parsed[0]["rule"]["level"], "5")
        self.assertEqual(parsed[0]["rule"]["groups"], ["windows", "authentication_failed"])
        self.assertEqual(event.severity, 2)
        self.assertEqual(event.action, "login_failed")


class FortiGateParsingTests(TempFileTestCase):
    def test_timezone_is_applied_to_local_date_time(self):
        line = (
            'date=2026-08-10 time=08:30:00 tz="+0700" devname="FG-01" '
            'logid="0000000013" type="traffic" subtype="forward" '
            'srcip=203.0.113.9 dstip=10.0.0.5 dstport=3389 proto=6 action=deny'
        )
        path = self.write_text("fortigate.log", line + "\n")
        raw = list(FortiGateParser(str(path)).parse())[0]
        event = normalize_fortigate(raw)

        self.assertEqual(event.timestamp, datetime(2026, 8, 10, 1, 30, tzinfo=timezone.utc))
        self.assertEqual(event.action, "connection_blocked")

    def test_nanosecond_eventtime_is_authoritative(self):
        expected = datetime(2026, 8, 10, 1, 30, tzinfo=timezone.utc)
        eventtime = int(expected.timestamp() * 1_000_000_000)
        raw = {
            "eventtime": str(eventtime),
            "date": "1999-01-01",
            "time": "00:00:00",
            "tz": "+0700",
            "type": "traffic",
            "action": "start",
            "srcip": "10.0.0.1",
            "dstip": "203.0.113.10",
        }

        event = normalize_fortigate(raw)
        self.assertEqual(event.timestamp, expected)
        self.assertEqual(event.action, "connection_allowed")
        self.assertEqual(event.result, "allowed")


class ResilienceAndCliTests(TempFileTestCase):
    def test_wazuh_parser_accepts_bom_and_elastic_source_wrapper(self):
        alert = {
            "timestamp": "2026-08-10T08:30:00.000Z",
            "rule": {"id": "5710", "level": 5, "description": "failed password"},
        }
        path = self.tempdir / "wrapped.json"
        path.write_text(json.dumps({"_source": alert}) + "\n", encoding="utf-8-sig")

        parsed = list(WazuhParser(str(path)).parse())
        self.assertEqual(parsed, [alert])

    def test_invalid_timestamp_is_rejected_instead_of_fabricated(self):
        raw = {
            "timestamp": "not-a-timestamp",
            "rule": {"id": "5710", "level": 5, "description": "failed password"},
        }
        with self.assertRaisesRegex(ValueError, "invalid Wazuh timestamp"):
            normalize_wazuh(raw)

    def test_parse_cli_outputs_complete_contract(self):
        raw = {
            "@timestamp": "2026-08-10T08:30:00.000Z",
            "host": {"name": "DC01", "ip": "10.0.0.5"},
            "winlog": {
                "event_id": 4625,
                "event_data": {"TargetUserName": "alice", "IpAddress": "203.0.113.9"},
            },
        }
        path = self.write_text("cli-windows.json", json.dumps(raw) + "\n")
        result = subprocess.run(
            [sys.executable, "main.py", "parse", "-s", "windows", "-f", str(path)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(len(output), 1)
        self.assertEqual(output[0]["result"], "failure")
        self.assertEqual(output[0]["extra"]["event_id"], "4625")
        self.assertIn("raw_event", output[0])
        self.assertIn("process", output[0])
        self.assertIn("protocol", output[0])

    def test_parse_cli_fails_when_every_record_has_bad_timestamp(self):
        raw = {
            "@timestamp": "bad-time",
            "winlog": {"event_id": 4625, "event_data": {}},
        }
        path = self.write_text("bad-time.json", json.dumps(raw) + "\n")
        result = subprocess.run(
            [sys.executable, "main.py", "parse", "-s", "windows", "-f", str(path)],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Normalize error", result.stderr)
        self.assertIn("failed normalization", result.stderr)


if __name__ == "__main__":
    unittest.main()
