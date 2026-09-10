from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from cat_app import reporting


def _origin_analysis() -> dict:
    root = {
        "process": r"C:\Users\analyst\Downloads\invoice.exe", "host": "PC01",
        "process_id": "100", "process_guid": "{invoice}",
        "start_time": "2026-09-01T09:00:00Z", "source_ref": "case.evtx#1",
        "creation_event_observed": True,
    }
    base = {
        "source_file": "case.evtx", "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational", "host": "PC01",
        "process": root["process"], "process_guid": root["process_guid"],
        "related_process_instance_id": "guid:pc01|{invoice}",
        "related_process_role": "origin_candidate",
        "relationship_basis": "동일 호스트 ProcessGuid로 원인 후보에 연결",
    }
    related = [
        {**base, "record_id": "1", "event_id": "1", "source_ref": "case.evtx#1",
         "time": root["start_time"], "review_priority": 0, "review_reason": "원인 후보 생성 근거",
         "command_line": r'"C:\Users\analyst\Downloads\invoice.exe" --open'},
        {**base, "record_id": "2", "event_id": "7", "source_ref": "case.evtx#2",
         "time": "2026-09-01T09:00:01Z", "review_priority": 3, "review_reason": "원인 후보의 DLL 로드 검토",
         "fields": {"ImageLoaded": r"C:\Users\analyst\Temp\helper.dll", "Signed": "false"}},
        {**base, "record_id": "3", "event_id": "8", "source_ref": "case.evtx#3",
         "time": "2026-09-01T09:00:02Z", "review_priority": 2, "review_reason": "원격 스레드 생성 주체·대상 검토",
         "fields": {"SourceProcessGUID": "{invoice}", "SourceImage": root["process"],
                    "TargetProcessGUID": "{target}", "TargetImage": r"C:\Windows\System32\rundll32.exe",
                    "StartAddress": "0x1000", "NewThreadId": "201"}},
    ]
    return {
        "scope": {}, "parser": {}, "summary": {}, "findings": [], "timeline": [],
        "suspicious_events": [],
        "intrusion_chain": {
            "origin_process": root,
            "observed_trigger_process": {**root, "process": r"C:\Windows\System32\rundll32.exe",
                                         "process_guid": "{target}", "process_id": "200"},
            "origin_assessment": {"status": "upstream_source_candidate_identified",
                                  "malware_confirmed": False, "initial_compromise_confirmed": False,
                                  "assessment": "상위 실행 주체의 침해 연관성을 추가 확인할 필요가 있습니다.",
                                  "missing_evidence": ["실행 파일 해시와 최초 유입 경로"]},
            "related_events": related,
            "related_event_scope": {"included_event_count": 3, "matched_event_count": 5,
                                    "omitted_event_count": 2, "truncated": True,
                                    "input_scan_limited": False,
                                    "limitations": ["관련 이벤트 2건은 보관 상한으로 제외되었습니다."]},
            "steps": [],
        },
    }


class OriginPriorityReportingTests(unittest.TestCase):
    def test_rule_report_starts_with_causal_review_and_preserves_related_raw_rows(self) -> None:
        analysis = _origin_analysis()
        duplicate = dict(analysis["intrusion_chain"]["related_events"][0])
        duplicate.pop("review_reason")
        duplicate["event_ref"] = "EVT-0001"
        analysis["report_evidence"] = [duplicate]
        report, metadata = reporting.generate_rule_report(analysis)
        self.assertLess(report.index("## 최초 비정상"), report.index("## 1. 분석 범위"))
        self.assertIn("invoice.exe", report.split("## 1. 분석 범위")[0])
        self.assertEqual(metadata["report_evidence_count"], 3)
        self.assertEqual(report.count("- 원본 참조:"), 3)
        self.assertEqual(metadata["related_event_scope"]["omitted_event_count"], 2)
        for value in ("ImageLoaded", "helper.dll", "SourceProcessGUID", "TargetProcessGUID", "{target}", "StartAddress"):
            self.assertIn(value, report)
        rows = reporting._report_evidence_events(analysis)
        self.assertEqual({row["record_id"] for row in rows}, {"1", "2", "3"})
        self.assertEqual(rows[0]["event_ref"], "EVT-0001")
        self.assertEqual(rows[0]["review_reason"], "원인 후보 생성 근거")

    def test_causal_rows_survive_hierarchical_source_cap(self) -> None:
        analysis = _origin_analysis()
        analysis["suspicious_events"] = [
            {"event_ref": f"EVT-{i}", "event_id": "3", "process": f"unrelated-{i}.exe",
             "severity": "critical", "time": "2026-09-01T10:00:00Z"}
            for i in range(100)
        ]
        with patch.object(reporting, "MAX_LM_HIERARCHICAL_SOURCE_EVENTS", 3):
            evidence, metadata = reporting._hierarchical_evidence(analysis)
        self.assertTrue(metadata["hierarchical_source_limit_reached"])
        self.assertEqual({item["record_id"] for item in evidence}, {"1", "2", "3"})
        self.assertEqual(next(item for item in evidence if item["record_id"] == "3")["fields"]["TargetProcessGUID"], "{target}")

    def test_causal_rows_precede_generic_boundary_rows_in_crowded_chunk(self) -> None:
        related = _origin_analysis()["intrusion_chain"]["related_events"]
        window = [
            {"event_id": "3", "process": "unrelated.exe", "severity": "critical",
             "time": "2026-09-01T08:00:00Z"},
            related[0], related[2],
            {"event_id": "3", "process": "unrelated.exe", "severity": "critical",
             "time": "2026-09-01T10:00:00Z"},
        ]
        selected = reporting._select_hierarchical_window(window, max_events=2, max_chars=4096)
        self.assertEqual([item["record_id"] for item in selected], ["1", "3"])
        self.assertLessEqual(len(json.dumps(selected, ensure_ascii=False, separators=(",", ":"))), 4096)

    def test_distinct_injection_targets_are_not_treated_as_repetition(self) -> None:
        source = _origin_analysis()["intrusion_chain"]["related_events"][2]
        rows = []
        for index in range(8):
            row = copy.deepcopy(source)
            row["record_id"] = str(index + 10)
            row["fields"]["TargetProcessGUID"] = f"{{target-{index}}}"
            rows.append(reporting._hierarchical_evidence_item(row, source_kind="intrusion_related_event"))
        reduced, omitted = reporting._reduce_hierarchical_repetitions(rows)
        self.assertEqual(omitted, 0)
        self.assertEqual(len(reduced), 8)

    def test_small_prompt_keeps_root_identity_and_obeys_total_budget_in_both_modes(self) -> None:
        analysis = _origin_analysis()
        analysis["scope"] = {"records_in_range": 5000}
        analysis["suspicious_events"] = [
            {"event_ref": f"EVT-{index:04d}", "event_id": "3", "host": "PC01",
             "time": "2026-09-01T10:00:00Z", "process": f"unrelated-{index}.exe",
             "command_line": "argument " * 200, "severity": "high", "confidence": "medium"}
            for index in range(100)
        ]
        for strict in (False, True):
            with self.subTest(strict=strict), patch.object(reporting, "DEFAULT_LM_MAX_INPUT_CHARS", 8192):
                messages, metadata = reporting._build_agent_messages_with_metadata(analysis, strict_validation=strict)
            self.assertLessEqual(sum(len(item["content"]) for item in messages), 8192)
            compact = json.loads(messages[1]["content"].split("CAT_ANALYSIS_JSON:\n", 1)[1])
            root = compact["intrusion_chain"]["origin_process"]
            self.assertEqual(root["process_guid"], "{invoice}")
            self.assertEqual(root["source_ref"], "case.evtx#1")
            self.assertTrue(metadata["input_truncated"])

    def test_compact_context_keeps_source_fields_for_loaded_and_injected_targets(self) -> None:
        chain = _origin_analysis()["intrusion_chain"]
        compact = reporting._compact_intrusion_context(chain)
        self.assertLessEqual(len(json.dumps(compact, ensure_ascii=False, separators=(",", ":"))), 4096)
        rows = {row["event_id"]: row for row in compact["related_events"]}
        self.assertIn("helper.dll", str(rows["7"]["fields"]))
        self.assertEqual(rows["8"]["fields"]["TargetProcessGUID"], "{target}")
        self.assertFalse(compact["origin_assessment"]["malware_confirmed"])

    def test_small_deterministic_context_keeps_structured_root_not_json_string(self) -> None:
        analysis = _origin_analysis()
        analysis["adaptive_time_range"] = {"reasons": ["R" * 8000] * 100}
        with patch.object(reporting, "DEFAULT_LM_MAX_INPUT_CHARS", 8192):
            context = reporting._hierarchical_deterministic_context(analysis)
        self.assertLessEqual(len(json.dumps(context, ensure_ascii=False, separators=(",", ":"))), 1024)
        self.assertEqual(context["intrusion_chain"]["origin_process"]["process_guid"], "{invoice}")

    def test_tiny_context_never_shortens_real_process_guid_or_source_reference(self) -> None:
        chain = _origin_analysis()["intrusion_chain"]
        origin = chain["origin_process"]
        origin.update(process_guid="{747f3d96-d8e3-5f8a-0000-001029a37200}",
                      source_ref="Microsoft-Windows-Sysmon-Operational.evtx#417071",
                      process="C:\\" + "LongDirectory\\" * 20 + "invoice.exe",
                      parent_process="C:\\" + "LongParent\\" * 20 + "parent.exe",
                      parent_link_basis="관측 " * 300)
        compact = reporting._compact_intrusion_context(chain, maximum=384)
        self.assertLessEqual(len(json.dumps(compact, ensure_ascii=False, separators=(",", ":"))), 384)
        root = compact["origin_process"]
        self.assertEqual(root["process_guid"], origin["process_guid"])
        self.assertEqual(root["source_ref"], origin["source_ref"])


if __name__ == "__main__":
    unittest.main()
