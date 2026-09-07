from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import unittest
from unittest.mock import patch

from cat_app import report_evidence
from cat_app.models import EventRecord
from cat_app.timeutil import isoformat_utc


def _events(count: int, source: str = "test.evtx") -> list[EventRecord]:
    return [EventRecord(
        source_file=source, event_id="1", provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational", computer="TEST",
        record_id=str(i + 1),
        time_created=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
        event_data={"CommandLine": f"powershell.exe -File script-{i}.ps1"},
    ) for i in range(count)]


def _evidence(event: EventRecord) -> dict:
    return {
        "time": isoformat_utc(event.time_created), "source_file": event.source_file,
        "record_id": event.record_id, "event_id": event.event_id,
        "provider": event.provider, "channel": event.channel, "host": event.computer,
        "command_line": event.event_data["CommandLine"],
    }


def _record(events: list[EventRecord], rule: str = "rule-one", count: int | None = None) -> None:
    report_evidence.record_finding_evidence(
        events, rule_id=rule, title=rule, severity="high", confidence="medium",
        description="test observation", evidence_factory=_evidence, event_count=count,
    )


class ReportEvidenceTests(unittest.TestCase):
    def test_retains_events_beyond_finding_sample_and_keeps_original_refs(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze(events):
            _record(events)
            _record(events[:1], "rule-two")
            return {"suspicious_events": [{**_evidence(events[0]), "event_ref": "EVT-0001"}]}

        data = analyze(_events(350))
        self.assertEqual(len(data["report_evidence"]), 350)
        self.assertEqual(data["report_evidence"][0]["event_ref"], "EVT-0001")
        self.assertEqual(data["report_evidence"][0]["rule_ids"], ["rule-one", "rule-two"])
        self.assertEqual(data["report_evidence"][-1]["record_id"], "350")
        self.assertFalse(data["report_evidence_scope"]["truncated"])

    def test_bound_preserves_rule_time_boundaries_and_reports_omissions(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze():
            _record(_events(300))
            return {}

        with patch.object(report_evidence, "REPORT_EVIDENCE_MAX_EVENTS", 32):
            data = analyze()
        self.assertEqual(len(data["report_evidence"]), 32)
        self.assertEqual(data["report_evidence"][0]["record_id"], "1")
        self.assertEqual(data["report_evidence"][-1]["record_id"], "300")
        self.assertEqual(data["report_evidence_scope"]["omitted_event_references"], 268)
        self.assertTrue(data["report_evidence_scope"]["limitations"])

    def test_char_budget_includes_final_refs_and_retains_separate_match_limits(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze():
            events = _events(60)
            for event in events:
                event.event_data["CommandLine"] = "X" * 3000
            _record(events, count=100)
            return {"scope": {"record_limit_reached": True}}

        with patch.object(report_evidence, "REPORT_EVIDENCE_MAX_CHARS", 16000):
            data = analyze()
        serialized = json.dumps(data["report_evidence"], ensure_ascii=False, separators=(",", ":"))
        self.assertLessEqual(len(serialized), 16000)
        scope = data["report_evidence_scope"]
        self.assertEqual(scope["upstream_omitted_event_references"], 40)
        self.assertTrue(scope["input_scan_limited"])
        self.assertTrue(scope["truncated"])

    def test_concurrent_analyses_and_failed_analysis_cannot_share_evidence(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze(source):
            _record(_events(4, source))
            if source == "failure":
                raise ValueError("expected")
            return {}

        with self.assertRaises(ValueError):
            analyze("failure")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(analyze, ["one.evtx", "two.evtx"]))
        for result, source in zip(results, ["one.evtx", "two.evtx"]):
            self.assertEqual({e["source_file"] for e in result["report_evidence"]}, {source})
        self.assertIsNone(report_evidence._CURRENT.get())

    def test_missing_record_ids_do_not_merge_distinct_simultaneous_commands(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze():
            events = _events(2)
            for event in events:
                event.record_id = None
                event.time_created = events[0].time_created
            _record(events)
            return {"suspicious_events": [{**_evidence(events[0]), "event_ref": "EVT-AMBIGUOUS"}]}

        result = analyze()
        evidence = result["report_evidence"]
        self.assertEqual(len(evidence), 2)
        self.assertEqual(len({item["event_ref"] for item in evidence}), 2)
        self.assertNotIn("EVT-AMBIGUOUS", {item["event_ref"] for item in evidence})

    def test_same_record_number_from_distinct_hosts_and_channels_stays_distinct(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze():
            events = [_events(1)[0] for _ in range(3)]
            events[1].computer = "OTHER-HOST"
            events[2].provider = "Microsoft-Windows-Security-Auditing"
            events[2].channel = "Security"
            _record(events)
            return {}

        result = analyze()
        self.assertEqual(len(result["report_evidence"]), 3)
        self.assertEqual(len({item["event_ref"] for item in result["report_evidence"]}), 3)

    def test_nested_analysis_failure_restores_outer_collector(self) -> None:
        @report_evidence.capture_report_evidence
        def inner():
            _record(_events(1, "inner.evtx"))
            raise ValueError("inner failed")

        @report_evidence.capture_report_evidence
        def outer():
            _record(_events(1, "before.evtx"))
            with self.assertRaises(ValueError):
                inner()
            _record(_events(1, "after.evtx"))
            return {}

        result = outer()
        self.assertEqual({item["source_file"] for item in result["report_evidence"]}, {"before.evtx", "after.evtx"})
        self.assertIsNone(report_evidence._CURRENT.get())

    def test_one_oversized_event_is_omitted_and_reported_without_exceeding_budget(self) -> None:
        @report_evidence.capture_report_evidence
        def analyze():
            events = _events(1)
            events[0].event_data["CommandLine"] = "X" * 5000
            _record(events)
            return {}

        with patch.object(report_evidence, "REPORT_EVIDENCE_MAX_CHARS", 1000):
            result = analyze()
        self.assertEqual(result["report_evidence"], [])
        self.assertEqual(result["report_evidence_scope"]["omitted_event_references"], 1)
        self.assertTrue(result["report_evidence_scope"]["truncated"])


if __name__ == "__main__":
    unittest.main()
