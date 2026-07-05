from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from cat_app.models import EventRecord, ParseResult
from cat_app.reporting import generate_report, generate_rule_report


def main() -> None:
    sample = ROOT / "tests" / "sample_events.xml"
    parse_result = parse_event_files([sample], start_utc=None, end_utc=None, max_records=1000)
    assert parse_result.total_seen == 3
    assert parse_result.total_in_range == 3
    assert not parse_result.errors

    analysis = analyze_events(parse_result, start_utc=None, end_utc=None)
    rule_ids = {finding["rule_id"] for finding in analysis["findings"]}
    assert "log_cleared" in rule_ids
    assert "service_installed" in rule_ids
    assert "suspicious_process_encoded_powershell" in rule_ids

    collision_result = ParseResult(
        records=[
            _record("104", "Microsoft-Windows-Kernel-Cache", "Microsoft-Windows-Kernel-Cache/Operational"),
            _record("1117", "Microsoft-Windows-PushNotifications-Platform", "Microsoft-Windows-PushNotifications-Platform/Operational"),
            _record("5858", "Example-Provider", "Application"),
        ],
        files=[],
        errors=[],
        total_seen=3,
        total_in_range=3,
    )
    collision_rules = {finding["rule_id"] for finding in analyze_events(collision_result, None, None)["findings"]}
    assert "log_cleared" not in collision_rules
    assert "defender_detection_or_tamper" not in collision_rules
    assert "wmi_activity" not in collision_rules

    contextual_result = ParseResult(
        records=[
            _record("104", "Microsoft-Windows-Eventlog", "System"),
            _record("5007", "Microsoft-Windows-Windows Defender", "Microsoft-Windows-Windows Defender/Operational"),
            _record("5858", "Microsoft-Windows-WMI-Activity", "Microsoft-Windows-WMI-Activity/Operational"),
        ],
        files=[],
        errors=[],
        total_seen=3,
        total_in_range=3,
    )
    contextual_rules = {finding["rule_id"] for finding in analyze_events(contextual_result, None, None)["findings"]}
    assert "log_cleared" in contextual_rules
    assert "defender_detection_or_tamper" in contextual_rules
    assert "wmi_activity" in contextual_rules

    report, llm = generate_report(analysis, use_llm=False, lm_url=None, model=None)
    assert "CAT 규칙 기반 침해 로그 분석 보고서" in report
    assert llm["used"] is False
    rule_report, rule_status = generate_rule_report(analysis)
    assert "보고서 방식: CAT 내장 규칙 엔진 기반" in rule_report
    assert rule_status["backend"] == "rule"
    assert rule_status["used"] is True
    print("CAT smoke test passed")


def _record(event_id: str, provider: str, channel: str) -> EventRecord:
    return EventRecord(
        source_file="synthetic.evtx",
        event_id=event_id,
        provider=provider,
        channel=channel,
        computer="WIN-CLIENT01",
        time_created=datetime(2026, 7, 5, 10, 0, 0, tzinfo=timezone.utc),
        record_id=f"synthetic-{event_id}",
    )


if __name__ == "__main__":
    main()
