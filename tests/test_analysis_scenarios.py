from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from cat_app.models import EventRecord, ParseResult
from cat_app.reporting import generate_rule_report


ROOT = Path(__file__).resolve().parents[1]


class AnalysisScenarioTests(unittest.TestCase):
    def test_sample_produces_addressable_events_and_correlated_scenario(self) -> None:
        parsed = parse_event_files(
            [ROOT / "tests" / "sample_events.xml"],
            start_utc=None,
            end_utc=None,
            max_records=1000,
        )

        analysis = analyze_events(parsed, None, None)

        suspicious = analysis["suspicious_events"]
        self.assertEqual(len(suspicious), 3)
        self.assertEqual([item["event_ref"] for item in suspicious], ["EVT-0001", "EVT-0002", "EVT-0003"])
        self.assertEqual({item["event_id"] for item in suspicious}, {"1102", "7045", "4688"})
        self.assertTrue(all(item["provider"] and item["channel"] for item in suspicious))

        scenarios = analysis["scenario_candidates"]
        self.assertEqual(len(scenarios), 1)
        scenario = scenarios[0]
        self.assertEqual(scenario["scenario_id"], "SCN-001")
        self.assertEqual(scenario["event_refs"], ["EVT-0001", "EVT-0002", "EVT-0003"])
        self.assertEqual([stage["event_ref"] for stage in scenario["stages"]], scenario["event_refs"])
        self.assertEqual([stage["order"] for stage in scenario["stages"]], [1, 2, 3])
        self.assertEqual(scenario["confidence"], "medium")
        self.assertTrue(scenario["link_reasons"])
        self.assertIn("가설", scenario["hypothesis"])

        report, status = generate_rule_report(analysis)
        self.assertEqual(status["backend"], "rule")
        self.assertIn("## 3. 의심 이벤트 목록", report)
        self.assertIn("`EVT-0001`", report)
        self.assertIn("## 6. 이벤트 기반 공격 시나리오", report)
        self.assertIn("SCN-001", report)
        self.assertIn("침해 확정이 아닌", report)

    def test_same_event_matched_by_multiple_rules_is_not_duplicated(self) -> None:
        event = _record(
            event_id="4688",
            minute=0,
            command_line="powershell.exe -enc AAAA schtasks /create /tn bad /tr calc.exe",
        )
        analysis = analyze_events(_result([event]), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 1)
        suspicious = analysis["suspicious_events"][0]
        self.assertGreaterEqual(len(suspicious["rule_ids"]), 2)
        self.assertEqual(analysis["scenario_candidates"], [])
        report, _ = generate_rule_report(analysis)
        self.assertIn("시나리오 없음", report)
        self.assertIn("억지로 맞추지 않았습니다", report)

    def test_unrelated_hosts_outside_window_remain_separate(self) -> None:
        first = _record("7045", minute=0, host="WIN-A", service_name="SvcA")
        second = _record("7045", minute=180, host="WIN-B", service_name="SvcB")
        analysis = analyze_events(_result([first, second]), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 2)
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_every_scenario_reference_resolves_to_suspicious_event(self) -> None:
        events = [
            _record("7045", minute=0, host="WIN-A", service_name="SvcA"),
            _record("4688", minute=5, host="WIN-A", command_line="certutil -urlcache https://example.invalid/a"),
            _record("4698", minute=8, host="WIN-A", task_name="Updater"),
        ]
        analysis = analyze_events(_result(events), None, None)
        known_refs = {item["event_ref"] for item in analysis["suspicious_events"]}

        for scenario in analysis["scenario_candidates"]:
            self.assertTrue(set(scenario["event_refs"]).issubset(known_refs))
            self.assertTrue({stage["event_ref"] for stage in scenario["stages"]}.issubset(known_refs))

    def test_provider_collisions_do_not_create_suspicious_events(self) -> None:
        events = [
            EventRecord(
                source_file="collision.evtx",
                event_id=event_id,
                provider="Example-Provider",
                channel="Application",
                computer="WIN-A",
                time_created=datetime(2026, 7, 5, 10, index, tzinfo=timezone.utc),
                record_id=str(index),
                event_data=data,
            )
            for index, (event_id, data) in enumerate(
                [
                    ("7045", {"ServiceName": "NotAServiceEvent"}),
                    ("4688", {"CommandLine": "powershell.exe -enc AAAA"}),
                    ("4104", {"ScriptBlockText": "Invoke-WebRequest https://example.invalid"}),
                ],
                start=1,
            )
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(analysis["suspicious_events"], [])
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_canonical_channel_without_canonical_provider_is_rejected(self) -> None:
        events = [
            EventRecord(
                source_file="collision.evtx",
                event_id=event_id,
                provider="Example-Provider",
                channel=channel,
                computer="WIN-A",
                time_created=datetime(
                    2026,
                    7,
                    5,
                    11,
                    index,
                    tzinfo=timezone.utc,
                ),
                record_id=str(3000 + index),
                event_data=data,
            )
            for index, (event_id, channel, data) in enumerate(
                [
                    ("4720", "Security", {"TargetUserName": "new-admin"}),
                    (
                        "4688",
                        "Security",
                        {"CommandLine": "powershell.exe -enc AAAA"},
                    ),
                    ("7045", "System", {"ServiceName": "FakeSvc"}),
                    (
                        "106",
                        "Microsoft-Windows-TaskScheduler/Operational",
                        {"TaskName": r"\Fake"},
                    ),
                    (
                        "1",
                        "Microsoft-Windows-Sysmon/Operational",
                        {"CommandLine": "certutil -urlcache example.invalid/a"},
                    ),
                    (
                        "4104",
                        "Microsoft-Windows-PowerShell/Operational",
                        {"ScriptBlockText": "Invoke-WebRequest example.invalid/a"},
                    ),
                    (
                        "1116",
                        "Microsoft-Windows-Windows Defender/Operational",
                        {"ThreatName": "Fake"},
                    ),
                    (
                        "5857",
                        "Microsoft-Windows-WMI-Activity/Operational",
                        {"Operation": "Started"},
                    ),
                ],
                start=1,
            )
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(analysis["suspicious_events"], [])
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_provider_names_containing_canonical_substrings_are_rejected(self) -> None:
        events = [
            EventRecord(
                source_file="spoofed-provider.evtx",
                event_id=event_id,
                provider=provider,
                channel=channel,
                computer="WIN-A",
                time_created=datetime(
                    2026,
                    7,
                    5,
                    12,
                    index,
                    tzinfo=timezone.utc,
                ),
                record_id=str(4500 + index),
                event_data=data,
            )
            for index, (event_id, provider, channel, data) in enumerate(
                [
                    (
                        "4688",
                        "Contoso-Microsoft-Windows-Security-Auditing-Proxy",
                        "Security",
                        {"CommandLine": "powershell.exe -enc AAAA"},
                    ),
                    (
                        "7045",
                        "Fake Service Control Manager Adapter",
                        "System",
                        {"ServiceName": "FakeSvc"},
                    ),
                    (
                        "104",
                        "Contoso-Microsoft-Windows-Eventlog-Adapter",
                        "System",
                        {},
                    ),
                    (
                        "1116",
                        "Contoso-Microsoft-Windows-Windows Defender-Adapter",
                        "Microsoft-Windows-Windows Defender/Operational",
                        {"ThreatName": "Fake"},
                    ),
                ],
                start=1,
            )
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(analysis["suspicious_events"], [])
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_canonical_provider_on_wrong_channel_is_rejected(self) -> None:
        events = [
            EventRecord(
                source_file="collision.evtx",
                event_id=event_id,
                provider=provider,
                channel="Application",
                computer="WIN-A",
                time_created=datetime(
                    2026,
                    7,
                    5,
                    12,
                    index,
                    tzinfo=timezone.utc,
                ),
                record_id=str(4000 + index),
                event_data=data,
            )
            for index, (event_id, provider, data) in enumerate(
                [
                    (
                        "4688",
                        "Microsoft-Windows-Security-Auditing",
                        {"CommandLine": "powershell.exe -enc AAAA"},
                    ),
                    (
                        "7045",
                        "Service Control Manager",
                        {"ServiceName": "FakeSvc"},
                    ),
                    (
                        "4104",
                        "Microsoft-Windows-PowerShell",
                        {"ScriptBlockText": "Invoke-WebRequest example.invalid/a"},
                    ),
                    (
                        "1116",
                        "Microsoft-Windows-Windows Defender",
                        {"ThreatName": "Fake"},
                    ),
                    (
                        "5857",
                        "Microsoft-Windows-WMI-Activity",
                        {"Operation": "Started"},
                    ),
                ],
                start=1,
            )
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(analysis["suspicious_events"], [])
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_cross_host_shared_account_process_and_logon_id_do_not_correlate(self) -> None:
        first = EventRecord(
            source_file="cross-host.evtx",
            event_id="7045",
            provider="Service Control Manager",
            channel="System",
            computer="WIN-A",
            time_created=datetime(2026, 7, 5, 13, 0, tzinfo=timezone.utc),
            record_id="5001",
            event_data={
                "ServiceName": "Updater",
                "SubjectUserName": "analyst",
                "SubjectDomainName": "CATLAB",
                "SubjectLogonId": "0x123456",
                "NewProcessName": r"C:\Tools\shared.exe",
            },
        )
        second = EventRecord(
            source_file="cross-host.evtx",
            event_id="4688",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            computer="WIN-B",
            time_created=datetime(2026, 7, 5, 13, 5, tzinfo=timezone.utc),
            record_id="5002",
            event_data={
                "SubjectUserName": "analyst",
                "SubjectDomainName": "CATLAB",
                "SubjectLogonId": "0x123456",
                "NewProcessName": r"C:\Tools\shared.exe",
                "CommandLine": "certutil -urlcache example.invalid/a",
            },
        )

        analysis = analyze_events(_result([first, second]), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 2)
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_explicit_target_server_can_correlate_cross_host_events(self) -> None:
        explicit_credentials = EventRecord(
            source_file="lateral.evtx",
            event_id="4648",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            computer="WIN-A",
            time_created=datetime(2026, 7, 5, 13, 0, tzinfo=timezone.utc),
            record_id="5501",
            event_data={
                "SubjectUserName": "analyst",
                "SubjectDomainName": "CATLAB",
                "TargetServerName": "WIN-B",
            },
        )
        execution = EventRecord(
            source_file="lateral.evtx",
            event_id="4688",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            computer="WIN-B",
            time_created=datetime(2026, 7, 5, 13, 5, tzinfo=timezone.utc),
            record_id="5502",
            event_data={
                "SubjectUserName": "analyst",
                "SubjectDomainName": "CATLAB",
                "NewProcessName": r"C:\Windows\System32\certutil.exe",
                "CommandLine": "certutil -urlcache example.invalid/a",
            },
        )

        analysis = analyze_events(
            _result([explicit_credentials, execution]),
            None,
            None,
        )

        self.assertEqual(len(analysis["scenario_candidates"]), 1)
        scenario = analysis["scenario_candidates"][0]
        self.assertEqual(scenario["event_refs"], ["EVT-0001", "EVT-0002"])
        self.assertTrue(
            any("TargetServerName" in reason for reason in scenario["link_reasons"])
        )
        self.assertTrue(
            any("서로 다른 호스트" in reason for reason in scenario["link_reasons"])
        )
        self.assertTrue(
            any(
                "원격 관리·배포 활동" in alternative
                for alternative in scenario["alternative_explanations"]
            )
        )
        self.assertFalse(
            any(
                "공통 호스트" in alternative
                for alternative in scenario["alternative_explanations"]
            )
        )

    def test_well_known_system_logon_id_does_not_link_persistence_events(self) -> None:
        service = EventRecord(
            source_file="system-session.evtx",
            event_id="7045",
            provider="Service Control Manager",
            channel="System",
            computer="WIN-A",
            time_created=datetime(2026, 7, 5, 14, 0, tzinfo=timezone.utc),
            record_id="6001",
            event_data={
                "ServiceName": "Updater",
                "SubjectUserName": "SYSTEM",
                "SubjectLogonId": "0x3e7",
            },
        )
        task = EventRecord(
            source_file="system-session.evtx",
            event_id="4698",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            computer="WIN-A",
            time_created=datetime(2026, 7, 5, 14, 5, tzinfo=timezone.utc),
            record_id="6002",
            event_data={
                "TaskName": r"\Updater",
                "SubjectUserName": "SYSTEM",
                "SubjectLogonId": "0x3e7",
            },
        )

        analysis = analyze_events(_result([service, task]), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 2)
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_large_findings_keep_time_balanced_representative_evidence(self) -> None:
        events = [
            _record(
                "7045",
                minute=minute,
                service_name=f"Svc{minute}",
            )
            for minute in range(120)
        ]

        analysis = analyze_events(_result(events), None, None)
        finding = next(
            item
            for item in analysis["findings"]
            if item["rule_id"] == "service_installed"
        )
        record_ids = [item["record_id"] for item in finding["evidence"]]

        self.assertEqual(finding["event_count"], 120)
        self.assertEqual(len(finding["evidence"]), 96)
        self.assertEqual(record_ids[0], "1000")
        self.assertEqual(record_ids[-1], "1119")
        self.assertEqual(
            analysis["suspicious_event_scope"]["per_finding_evidence_limit"],
            96,
        )
        self.assertTrue(analysis["suspicious_event_scope"]["evidence_truncated"])

    def test_events_within_evidence_limit_remain_available_for_scenario(self) -> None:
        services = [
            _record(
                "7045",
                minute=minute,
                host="WIN-B",
                service_name=f"UnrelatedSvc{minute}",
            )
            for minute in range(24)
        ]
        correlated_service = _record(
            "7045",
            minute=30,
            host="WIN-A",
            service_name="CorrelatedSvc",
        )
        process = _record(
            "4688",
            minute=31,
            host="WIN-A",
            command_line="certutil -urlcache https://example.invalid/payload",
        )

        analysis = analyze_events(
            _result([*services, correlated_service, process]),
            None,
            None,
        )

        self.assertEqual(len(analysis["suspicious_events"]), 26)
        self.assertEqual(len(analysis["scenario_candidates"]), 1)
        scenario_refs = analysis["scenario_candidates"][0]["event_refs"]
        event_by_ref = {
            event["event_ref"]: event
            for event in analysis["suspicious_events"]
        }
        self.assertEqual(
            [event_by_ref[ref]["event_id"] for ref in scenario_refs],
            ["7045", "4688"],
        )
        self.assertEqual(
            [event_by_ref[ref]["host"] for ref in scenario_refs],
            ["WIN-A", "WIN-A"],
        )

    def test_failed_logon_burst_requires_five_events_in_ten_minutes(self) -> None:
        events = [
            _failed_logon(minute=minute)
            for minute in (0, 20, 40, 60, 80)
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertFalse(
            any(
                finding["rule_id"] == "failed_logon_burst"
                for finding in analysis["findings"]
            )
        )

        compact_analysis = analyze_events(
            _result([_failed_logon(minute=minute) for minute in range(5)]),
            None,
            None,
        )
        burst = next(
            finding
            for finding in compact_analysis["findings"]
            if finding["rule_id"] == "failed_logon_burst"
        )
        self.assertEqual(burst["event_count"], 5)
        self.assertEqual(len(burst["evidence"]), 5)

    def test_auth_failure_burst_requires_ten_events_in_ten_minutes(self) -> None:
        events = [
            _auth_failure(minute=minute * 20)
            for minute in range(10)
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertFalse(
            any(
                finding["rule_id"] == "auth_failure_burst"
                for finding in analysis["findings"]
            )
        )

        compact_analysis = analyze_events(
            _result([_auth_failure(minute=minute) for minute in range(10)]),
            None,
            None,
        )
        burst = next(
            finding
            for finding in compact_analysis["findings"]
            if finding["rule_id"] == "auth_failure_burst"
        )
        self.assertEqual(burst["event_count"], 10)

    def test_missing_event_time_does_not_break_aware_datetime_sorting(self) -> None:
        timed = _record(
            "4688",
            minute=0,
            command_line="powershell.exe -enc AAAA",
        )
        missing_time = _record(
            "7045",
            minute=1,
            service_name="NoTimestampSvc",
        )
        missing_time.time_created = None

        analysis = analyze_events(_result([missing_time, timed]), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 2)
        self.assertEqual(analysis["suspicious_events"][0]["event_id"], "4688")
        self.assertEqual(analysis["suspicious_events"][1]["event_id"], "7045")
        self.assertIsNone(analysis["suspicious_events"][1]["time"])

    def test_transition_reason_respects_observed_event_order(self) -> None:
        rdp = EventRecord(
            source_file="ordered.evtx",
            event_id="4624",
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            computer="WIN-A",
            time_created=datetime(2026, 7, 5, 15, 0, tzinfo=timezone.utc),
            record_id="7000",
            event_data={
                "TargetUserName": "analyst",
                "TargetDomainName": "CATLAB",
                "IpAddress": "10.0.0.20",
                "LogonType": "10",
            },
        )
        failures = [
            EventRecord(
                source_file="ordered.evtx",
                event_id="4625",
                provider="Microsoft-Windows-Security-Auditing",
                channel="Security",
                computer="WIN-A",
                time_created=datetime(
                    2026,
                    7,
                    5,
                    15,
                    minute,
                    tzinfo=timezone.utc,
                ),
                record_id=str(7000 + minute),
                event_data={
                    "TargetUserName": "analyst",
                    "TargetDomainName": "CATLAB",
                    "IpAddress": "10.0.0.20",
                },
            )
            for minute in range(1, 6)
        ]

        analysis = analyze_events(_result([rdp, *failures]), None, None)
        reasons = analysis["scenario_candidates"][0]["link_reasons"]

        self.assertTrue(
            any("원격 로그인 징후 후 인증 실패 반복" in reason for reason in reasons)
        )
        self.assertFalse(
            any("인증 실패 반복 후 원격 로그인" in reason for reason in reasons)
        )

    def test_time_and_host_alone_do_not_create_scenario(self) -> None:
        events = [
            EventRecord(
                source_file="same-host.evtx",
                event_id="7045",
                provider="Service Control Manager",
                channel="System",
                computer="WIN-A",
                time_created=datetime(2026, 7, 5, 10, minute, tzinfo=timezone.utc),
                record_id=str(2000 + minute),
                event_data={"ServiceName": f"Svc{minute}", "AccountName": "LocalSystem"},
            )
            for minute in (0, 5)
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 2)
        self.assertEqual(analysis["scenario_candidates"], [])

    def test_repeated_same_rule_with_same_account_is_not_a_multistage_scenario(self) -> None:
        events = [
            _record(
                "7045",
                minute=minute,
                service_name=f"Svc{minute}",
            )
            for minute in (0, 5)
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertEqual(len(analysis["suspicious_events"]), 2)
        self.assertEqual(analysis["scenario_candidates"], [])


def _record(
    event_id: str,
    minute: int,
    host: str = "WIN-CLIENT01",
    command_line: str | None = None,
    service_name: str | None = None,
    task_name: str | None = None,
) -> EventRecord:
    data = {"SubjectUserName": "analyst", "SubjectDomainName": "CATLAB"}
    if command_line:
        data.update(
            {
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": command_line,
            }
        )
    if service_name:
        data["ServiceName"] = service_name
    if task_name:
        data["TaskName"] = task_name
    provider = "Service Control Manager" if event_id == "7045" else "Microsoft-Windows-Security-Auditing"
    channel = "System" if event_id == "7045" else "Security"
    return EventRecord(
        source_file="scenario.evtx",
        event_id=event_id,
        provider=provider,
        channel=channel,
        computer=host,
        time_created=datetime(2026, 7, 5, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=minute),
        record_id=str(1000 + minute),
        event_data=data,
    )


def _failed_logon(minute: int) -> EventRecord:
    return EventRecord(
        source_file="authentication.evtx",
        event_id="4625",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="WIN-A",
        time_created=datetime(2026, 7, 5, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minute),
        record_id=str(3000 + minute),
        event_data={
            "TargetUserName": "analyst",
            "TargetDomainName": "CATLAB",
            "IpAddress": "10.0.0.20",
        },
    )


def _auth_failure(minute: int) -> EventRecord:
    return EventRecord(
        source_file="authentication.evtx",
        event_id="4771",
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="DC01",
        time_created=datetime(2026, 7, 5, 10, 0, tzinfo=timezone.utc)
        + timedelta(minutes=minute),
        record_id=str(4000 + minute),
        event_data={
            "TargetUserName": "analyst",
            "TargetDomainName": "CATLAB",
            "IpAddress": "10.0.0.20",
        },
    )


def _result(events: list[EventRecord]) -> ParseResult:
    return ParseResult(
        records=events,
        files=[],
        errors=[],
        total_seen=len(events),
        total_in_range=len(events),
    )


if __name__ == "__main__":
    unittest.main()
