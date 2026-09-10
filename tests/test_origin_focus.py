from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from cat_app import analyzer
from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from test_origin_trace import event, process, result


class OriginFocusTests(unittest.TestCase):
    def test_earliest_supported_component_precedes_later_high_volume_activity(self) -> None:
        first = process(10, r"C:\Windows\System32\regsvr32.exe", "{first}")
        later = [process(i, r"C:\Windows\System32\rundll32.exe", f"{{later-{i}}}", "{later-20}")
                 for i in range(20, 30)]
        chain = analyze_events(result([first, *later]), None, None)["intrusion_chain"]
        self.assertEqual(chain["observed_trigger_process"]["process_guid"], "{first}")

    def test_seed_identity_preserves_incident_amid_earlier_unrelated_findings(self) -> None:
        original = process(100, r"C:\Windows\System32\regsvr32.exe", "{seed}", "{parent}")
        seed = analyze_events(result([original]), None, None)["intrusion_chain"]["observed_trigger_process"]
        unrelated = process(1, r"C:\Windows\System32\rundll32.exe", "{unrelated}")
        parent = process(2, r"C:\Users\alice\Downloads\invoice.exe", "{parent}")
        chain = analyze_events(result([unrelated, parent, original]), None, None,
                               focus_anchors=[seed])["intrusion_chain"]
        self.assertEqual(chain["origin_process"]["process_guid"], "{parent}")
        self.assertEqual(chain["observed_trigger_process"]["process_guid"], "{seed}")
        self.assertTrue(chain["source"]["focus_preserved"])
        self.assertNotIn("{unrelated}", {p["process_guid"] for p in chain["processes"]})

    def test_wrong_host_or_reused_pid_cannot_restore_a_missing_seed(self) -> None:
        original = process(10, r"C:\Windows\System32\regsvr32.exe", "{seed}")
        seed = analyze_events(result([original]), None, None)["intrusion_chain"]["origin_process"]
        wrong_host = replace(original, computer="OTHER")
        chain = analyze_events(result([wrong_host]), None, None, focus_anchors=[seed])["intrusion_chain"]
        self.assertIsNone(chain["origin_process"])
        self.assertTrue(chain["source"]["focus_unresolved"])
        reused = replace(original, time_created=original.time_created + timedelta(hours=2), record_id="11",
                         event_data={**original.event_data, "ProcessGuid": ""})
        pid_anchor = {**seed, "process_guid": None, "source_ref": None}
        chain = analyze_events(result([reused]), None, None, focus_anchors=[pid_anchor])["intrusion_chain"]
        self.assertIsNone(chain["origin_process"])

    def test_raw_related_module_and_injection_preserve_actor_target_roles(self) -> None:
        source = process(1, r"C:\Users\alice\Downloads\invoice.exe", "{source}")
        child = process(2, r"C:\Windows\System32\regsvr32.exe", "{child}", "{source}")
        dll = event(3, "7", ProcessGuid="{source}", Image=source.event_data["Image"],
                    ImageLoaded=r"C:\Users\alice\AppData\Local\helper.dll", Signed="false")
        injection = event(4, "8", SourceProcessGUID="{outside}", SourceImage=r"C:\Tools\writer.exe",
                          TargetProcessGUID="{child}", TargetImage=child.event_data["Image"],
                          NewThreadId="501", StartAddress="0x1000")
        bad_host = replace(injection, computer="OTHER", record_id="5")
        bad_provider = replace(dll, provider="Fake-Sysmon", record_id="6")
        too_early = replace(dll, time_created=source.time_created - timedelta(seconds=1), record_id="7")
        chain = analyze_events(result([source, child, dll, injection, bad_host, bad_provider, too_early]),
                               None, None)["intrusion_chain"]
        rows = {e["record_id"]: e for e in chain["related_events"]}
        self.assertEqual(set(rows), {"1", "2", "3", "4"})
        self.assertEqual(rows["3"]["fields"]["ImageLoaded"], dll.event_data["ImageLoaded"])
        self.assertEqual(rows["4"]["process"], r"C:\Tools\writer.exe")
        self.assertEqual(rows["4"]["related_process_roles"], ["target"])
        self.assertEqual(rows["4"]["fields"]["NewThreadId"], "501")
        self.assertTrue(rows["4"]["review_reason"])

    def test_related_event_budget_preserves_origin_and_reports_omissions(self) -> None:
        origin = process(1, r"C:\Windows\System32\regsvr32.exe", "{origin}")
        loads = [event(i, "7", ProcessGuid="{origin}", Image=origin.event_data["Image"],
                       ImageLoaded=f"C:\\Modules\\m{i}.dll") for i in range(2, 30)]
        with patch.object(analyzer, "INTRUSION_RELATED_EVENT_LIMIT", 3):
            chain = analyze_events(result([*loads, origin]), None, None)["intrusion_chain"]
        self.assertEqual(len(chain["related_events"]), 3)
        self.assertEqual(chain["related_events"][0]["record_id"], "1")
        scope = chain["related_event_scope"]
        self.assertEqual(scope["omitted_event_count"], 26)
        self.assertTrue(scope["truncated"])
        with patch.object(analyzer, "INTRUSION_RELATED_CHAR_LIMIT", 3000):
            chain = analyze_events(result([origin, *loads]), None, None)["intrusion_chain"]
        self.assertLessEqual(len(json.dumps(chain["related_events"], ensure_ascii=False, separators=(",", ":"))), 3000)

    def test_file_provenance_reference_collision_does_not_include_another_host(self) -> None:
        write = event(1, "11", ProcessGuid="{unknown-creator}", TargetFilename=r"C:\Temp\helper.dll")
        other_host = replace(write, computer="OTHER")
        run = process(2, r"C:\Windows\System32\regsvr32.exe", "{run}",
                      command=r"regsvr32.exe /s C:\Temp\helper.dll")
        chain = analyze_events(result([write, other_host, run]), None, None)["intrusion_chain"]
        writes = [row for row in chain["related_events"] if row["event_id"] == "11"]
        self.assertEqual([row["host"] for row in writes], ["PC01"])

    def test_related_fields_survive_general_record_limit_via_spool(self) -> None:
        origin = process(1, r"C:\Windows\System32\regsvr32.exe", "{origin}")
        records = [origin,
            event(2, "7", ProcessGuid="{origin}", ImageLoaded=r"C:\Temp\module.dll"),
            event(3, "8", SourceProcessGUID="{origin}", TargetProcessGUID="{other}", StartAddress="0x1000"),
            event(4, "10", SourceProcessGUID="{other}", TargetProcessGUID="{origin}", GrantedAccess="0x1fffff")]
        parts = []
        for row in records:
            fields = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in row.event_data.items())
            parts.append(f'<Event><System><Provider Name="{row.provider}"/><EventID>{row.event_id}</EventID>'
                         f'<Channel>{row.channel}</Channel><Computer>{row.computer}</Computer>'
                         f'<EventRecordID>{row.record_id}</EventRecordID><TimeCreated SystemTime="{row.time_created.isoformat()}"/>'
                         f'</System><EventData>{fields}</EventData></Event>')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "related.xml"
            path.write_text("<Events>" + "".join(parts) + "</Events>", encoding="utf-8")
            parsed = parse_event_files([path], None, None, max_records=1)
            try:
                chain = analyze_events(parsed, None, None)["intrusion_chain"]
                self.assertEqual(parsed.network_records_spooled, 4)
            finally:
                parsed.close()
        self.assertEqual({row["event_id"] for row in chain["related_events"]}, {"1", "7", "8", "10"})


if __name__ == "__main__":
    unittest.main()
