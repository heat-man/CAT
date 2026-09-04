from __future__ import annotations

from datetime import datetime, timezone
import unittest
from unittest import mock

from cat_app import server
from cat_app.adaptive_range import recommend_expanded_range
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
                "auto_expand_time_range": "true",
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


class AdaptiveRangeTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
