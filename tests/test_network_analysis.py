from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from cat_app import analyzer
from cat_app.analyzer import analyze_events
from cat_app.models import EventRecord, ParseResult
from cat_app.reporting import generate_rule_report


SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


class NetworkAnalysisTests(unittest.TestCase):
    def test_process_dns_and_connection_are_correlated_by_process_guid(self) -> None:
        start = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
        guid = "{11111111-2222-3333-4444-555555555555}"
        process = _event(
            "1",
            start,
            record_id="1",
            data={
                "ProcessGuid": guid,
                "ProcessId": "4242",
                "Image": r"C:\Users\alice\AppData\Local\Temp\payload.exe",
                "CommandLine": "payload.exe --connect",
                "ParentImage": r"C:\Windows\System32\cmd.exe",
                "ParentCommandLine": "cmd.exe /c payload.exe --connect",
                "Hashes": "SHA256=0123456789abcdef",
                "User": r"LAB\alice",
            },
        )
        dns = _event(
            "22",
            start + timedelta(seconds=10),
            record_id="2",
            data={
                "ProcessGuid": guid,
                "ProcessId": "4242",
                "Image": r"C:\Users\alice\AppData\Local\Temp\payload.exe",
                "QueryName": "control.example.test",
                "QueryResults": "8.8.8.8",
                "User": r"LAB\alice",
            },
        )
        connection = _event(
            "3",
            start + timedelta(seconds=12),
            record_id="3",
            data={
                "ProcessGuid": guid,
                "ProcessId": "4242",
                "Image": r"C:\Users\alice\AppData\Local\Temp\payload.exe",
                "User": r"LAB\alice",
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": "10.0.0.5",
                "SourcePort": "50123",
                "DestinationIp": "8.8.8.8",
                "DestinationHostname": "control.example.test",
                "DestinationPort": "4444",
            },
        )

        analysis = analyze_events(_result([connection, dns, process]), None, None)

        finding = _finding(analysis, "suspicious_network_connection")
        self.assertEqual(
            {item["event_id"] for item in finding["evidence"]},
            {"1", "3", "22"},
        )
        context = finding["network_context"]
        self.assertEqual(context["destination_ip"], "8.8.8.8")
        self.assertEqual(context["destination_port"], 4444)
        self.assertEqual(context["dns_queries"], ["control.example.test"])
        self.assertTrue(any("ProcessGuid" in value for value in context["correlation_reasons"]))
        process_evidence = next(
            item for item in finding["evidence"] if item["event_id"] == "1"
        )
        self.assertEqual(
            process_evidence["fields"]["ParentImage"],
            r"C:\Windows\System32\cmd.exe",
        )
        self.assertEqual(
            process_evidence["fields"]["Hashes"],
            "SHA256=0123456789abcdef",
        )

        network_event = next(
            item
            for item in analysis["suspicious_events"]
            if item["event_id"] == "3"
        )
        self.assertEqual(network_event["source_ip"], "10.0.0.5")
        self.assertEqual(network_event["source_port"], 50123)
        self.assertEqual(network_event["destination_ip"], "8.8.8.8")
        self.assertEqual(network_event["destination_port"], 4444)
        self.assertEqual(network_event["destination_hostname"], "control.example.test")
        self.assertEqual(network_event["protocol"], "tcp")
        self.assertIs(network_event["initiated"], True)
        self.assertEqual(network_event["network_direction"], "outbound")
        self.assertEqual(network_event["process_guid"], guid.casefold())
        self.assertEqual(network_event["fields"]["DestinationIp"], "8.8.8.8")

        dns_event = next(
            item
            for item in analysis["suspicious_events"]
            if item["event_id"] == "22"
        )
        self.assertEqual(dns_event["query_name"], "control.example.test")
        self.assertEqual(dns_event["fields"]["QueryResults"], "8.8.8.8")

        report, status = generate_rule_report(analysis)
        self.assertEqual(status["backend"], "rule")
        self.assertIn("dst=control.example.test (8.8.8.8):4444", report)
        self.assertIn(f"ProcessGuid={guid.casefold()}", report)
        self.assertIn("### 상위 목적지 IP", report)

    def test_sysmon_provider_and_channel_must_match_exactly(self) -> None:
        time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        collisions = [
            _event(
                "3",
                time,
                provider="Collision-Sysmon",
                data={"DestinationIp": "8.8.8.8", "DestinationPort": "4444"},
            ),
            _event(
                "3",
                time,
                channel="Application",
                data={"DestinationIp": "8.8.8.8", "DestinationPort": "4444"},
            ),
            _event(
                "22",
                time,
                provider="Collision-Sysmon",
                data={"QueryName": "bad.example"},
            ),
        ]

        analysis = analyze_events(_result(collisions), None, None)

        self.assertEqual(analysis["network_activity"]["connection_event_count"], 0)
        self.assertEqual(analysis["network_activity"]["dns_query_event_count"], 0)
        self.assertFalse(
            any(
                str(item["rule_id"]).startswith(("suspicious_network", "possible_network"))
                for item in analysis["findings"]
            )
        )

    def test_pid_fallback_requires_same_host_image_and_tight_time_window(self) -> None:
        start = datetime(2026, 2, 3, tzinfo=timezone.utc)
        unrelated_process = _event(
            "1",
            start,
            record_id="1",
            host="HOST-A",
            data={
                "ProcessId": "31337",
                "Image": r"C:\Users\alice\AppData\Local\Temp\unrelated.exe",
            },
        )
        connection = _event(
            "3",
            start + timedelta(minutes=2),
            record_id="2",
            host="HOST-A",
            data={
                "ProcessId": "31337",
                "Image": r"C:\Windows\System32\svchost.exe",
                "Initiated": "true",
                "DestinationIp": "1.1.1.1",
                "DestinationPort": "4444",
            },
        )

        analysis = analyze_events(_result([unrelated_process, connection]), None, None)

        finding = _finding(analysis, "suspicious_network_connection")
        evidence_ids = [item["event_id"] for item in finding["evidence"]]
        self.assertEqual(evidence_ids, ["3"])
        self.assertFalse(
            any("PID" in value for value in finding["network_context"]["correlation_reasons"])
        )

    def test_pid_fallback_correlates_matching_image(self) -> None:
        start = datetime(2026, 2, 3, tzinfo=timezone.utc)
        process = _event(
            "1",
            start,
            record_id="1",
            data={
                "ProcessId": "31337",
                "Image": r"C:\Users\alice\Downloads\agent.exe",
            },
        )
        connection = _event(
            "3",
            start + timedelta(minutes=2),
            record_id="2",
            data={
                "ProcessId": "31337",
                "Image": r"C:\Users\alice\Downloads\agent.exe",
                "Initiated": "true",
                "DestinationIp": "1.1.1.1",
                "DestinationPort": "443",
            },
        )

        analysis = analyze_events(_result([process, connection]), None, None)

        finding = _finding(analysis, "suspicious_network_connection")
        self.assertEqual(
            {item["event_id"] for item in finding["evidence"]},
            {"1", "3"},
        )
        self.assertTrue(
            any("PID" in value for value in finding["network_context"]["correlation_reasons"])
        )

    def test_regular_connections_create_possible_beacon_finding(self) -> None:
        start = datetime(2026, 3, 4, tzinfo=timezone.utc)
        events = [
            _event(
                "3",
                start + timedelta(seconds=60 * index),
                record_id=str(index + 1),
                data={
                    "ProcessGuid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
                    "ProcessId": "777",
                    "Image": r"C:\Windows\System32\svchost.exe",
                    "Initiated": "true",
                    "Protocol": "tcp",
                    "DestinationIp": "8.8.4.4",
                    "DestinationPort": "443",
                },
            )
            for index in range(8)
        ]

        analysis = analyze_events(_result(events), None, None)

        finding = _finding(analysis, "possible_network_beacon")
        self.assertEqual(finding["network_context"]["connection_count"], 8)
        self.assertTrue(finding["network_context"]["possible_beacon"])
        self.assertIn("중앙 간격 60.0초", " ".join(finding["network_context"]["anomaly_signals"]))

    def test_normal_browser_https_does_not_become_finding(self) -> None:
        start = datetime(2026, 4, 5, tzinfo=timezone.utc)
        events = [
            _event(
                "3",
                start + timedelta(seconds=offset),
                record_id=str(index + 1),
                data={
                    "ProcessGuid": "{bbbbbbbb-cccc-dddd-eeee-ffffffffffff}",
                    "ProcessId": "1000",
                    "Image": r"C:\Users\alice\AppData\Local\Google\Chrome\chrome.exe",
                    "Initiated": "true",
                    "Protocol": "tcp",
                    "DestinationIp": "8.8.8.8",
                    "DestinationHostname": "www.example.com",
                    "DestinationPort": "443",
                },
            )
            for index, offset in enumerate((0, 2, 11, 47, 180))
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(analysis["findings"], [])
        self.assertEqual(analysis["network_activity"]["external_connection_count"], 5)
        connection = analysis["network_activity"]["connections"][0]
        self.assertFalse(connection["suspicious"])
        self.assertIn("외부/비로컬 목적지", connection["anomaly_signals"])

    def test_security_5156_preserves_network_fields_and_tunnel_process(self) -> None:
        start = datetime(2026, 5, 6, tzinfo=timezone.utc)
        process = _event(
            "4688",
            start,
            record_id="1",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "NewProcessId": "0x1234",
                "NewProcessName": r"C:\Tools\plink.exe",
                "CommandLine": "plink.exe -R 3389:127.0.0.1:3389",
            },
        )
        event = _event(
            "5156",
            start + timedelta(milliseconds=30),
            record_id="2",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "ProcessID": "0x1234",
                "Application": r"\device\harddiskvolume3\tools\plink.exe",
                "Direction": "%%14593",
                "SourceAddress": "192.168.1.20",
                "SourcePort": "53000",
                "DestAddress": "192.168.1.10",
                "DestPort": "3389",
                "Protocol": "6",
            },
        )

        analysis = analyze_events(_result([process, event]), None, None)

        finding = _finding(analysis, "suspicious_network_connection")
        self.assertIn("터널링 도구", " ".join(finding["network_context"]["anomaly_signals"]))
        self.assertEqual(
            {item["event_id"] for item in finding["evidence"]},
            {"4688", "5156"},
        )
        self.assertTrue(
            any(
                "파일명(경로 표기 상이)" in value
                for value in finding["network_context"]["correlation_reasons"]
            )
        )
        suspicious = next(
            item
            for item in analysis["suspicious_events"]
            if item["event_id"] == "5156"
        )
        self.assertEqual(suspicious["destination_ip"], "192.168.1.10")
        self.assertEqual(suspicious["destination_port"], 3389)
        self.assertEqual(suspicious["source_port"], 53000)
        self.assertEqual(suspicious["protocol"], "tcp")
        self.assertEqual(suspicious["network_direction"], "outbound")
        self.assertEqual(suspicious["process_id"], "4660")

    def test_w3wp_sensitive_loopback_connection_is_tunnel_candidate(self) -> None:
        event = _event(
            "3",
            datetime(2026, 6, 7, tzinfo=timezone.utc),
            data={
                "ProcessGuid": "{12345678-1234-1234-1234-123456789abc}",
                "ProcessId": "9000",
                "Image": r"C:\Windows\System32\inetsrv\w3wp.exe",
                "Initiated": "true",
                "DestinationIp": "127.0.0.1",
                "DestinationPort": "3389",
                "Protocol": "tcp",
            },
        )

        analysis = analyze_events(_result([event]), None, None)

        finding = _finding(analysis, "suspicious_network_connection")
        self.assertTrue(finding["network_context"]["sensitive_loopback"])
        self.assertFalse(finding["network_context"]["external_destination"])

    def test_network_activity_marks_representative_group_limitation(self) -> None:
        start = datetime(2026, 7, 8, tzinfo=timezone.utc)
        events = [
            _event(
                "3",
                start + timedelta(seconds=index),
                record_id=str(index),
                data={
                    "ProcessId": str(1000 + index),
                    "Image": r"C:\Windows\System32\svchost.exe",
                    "Initiated": "true",
                    "DestinationIp": f"8.8.{index // 250}.{index % 250 + 1}",
                    "DestinationPort": "443",
                },
            )
            for index in range(70)
        ]

        analysis = analyze_events(_result(events), None, None)

        activity = analysis["network_activity"]
        self.assertEqual(activity["group_count"], 70)
        self.assertEqual(activity["included_group_count"], 64)
        self.assertTrue(activity["truncated"])
        self.assertIn("대표 64개", activity["limitation"])

    def test_dense_dns_correlation_examines_a_bounded_candidate_set(self) -> None:
        start = datetime(2026, 8, 9, tzinfo=timezone.utc)
        guid = "{cccccccc-dddd-eeee-ffff-000000000001}"
        dns_events = [
            _event(
                "22",
                start + timedelta(seconds=index),
                record_id=f"dns-{index}",
                data={
                    "ProcessGuid": guid,
                    "ProcessId": "2222",
                    "Image": r"C:\Windows\System32\svchost.exe",
                    "QueryName": "same.example",
                },
            )
            for index in range(200)
        ]
        connections = [
            _event(
                "3",
                start + timedelta(seconds=100 + index),
                record_id=f"net-{index}",
                data={
                    "ProcessGuid": guid,
                    "ProcessId": "2222",
                    "Image": r"C:\Windows\System32\svchost.exe",
                    "Initiated": "true",
                    "DestinationIp": "8.8.8.8",
                    "DestinationHostname": "same.example",
                    "DestinationPort": "443",
                },
            )
            for index in range(50)
        ]

        with patch.object(
            analyzer,
            "_event_time_delta_seconds",
            wraps=analyzer._event_time_delta_seconds,
        ) as delta:
            analysis = analyze_events(
                _result([*dns_events, *connections]),
                None,
                None,
            )

        self.assertEqual(analysis["network_activity"]["connection_event_count"], 50)
        self.assertLessEqual(delta.call_count, 50 * 32)


def _event(
    event_id: str,
    time: datetime,
    *,
    record_id: str = "1",
    provider: str = SYSMON_PROVIDER,
    channel: str = SYSMON_CHANNEL,
    host: str = "HOST-A",
    data: dict[str, str] | None = None,
) -> EventRecord:
    return EventRecord(
        source_file="network.evtx",
        event_id=event_id,
        provider=provider,
        channel=channel,
        computer=host,
        time_created=time,
        record_id=record_id,
        event_data=data or {},
    )


def _result(events: list[EventRecord]) -> ParseResult:
    return ParseResult(
        records=events,
        files=[],
        errors=[],
        total_seen=len(events),
        total_in_range=len(events),
    )


def _finding(analysis: dict[str, object], rule_id: str) -> dict[str, object]:
    findings = analysis["findings"]
    assert isinstance(findings, list)
    for finding in findings:
        if isinstance(finding, dict) and finding.get("rule_id") == rule_id:
            return finding
    raise AssertionError(f"finding not found: {rule_id}; got {findings}")


if __name__ == "__main__":
    unittest.main()
