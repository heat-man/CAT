from __future__ import annotations

from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

from Evtx.Evtx import Evtx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from cat_app.models import EventRecord, ParseResult
from cat_app.reporting import (
    REQUIRED_REPORT_SECTIONS,
    generate_report,
    generate_rule_report,
)
from cat_app.timeutil import get_timezone, parse_user_datetime


def main() -> None:
    _require(version("hexdump") == "3.3", "hexdump version mismatch")
    _require(version("python-evtx") == "0.8.1", "python-evtx version mismatch")
    _require(version("tzdata") == "2026.3", "tzdata version mismatch")

    for relative in (
        "images/cat.jpg",
        "images/cat_down.jpg",
        "images/cat_dress.jpg",
        "images/cat_sleep.jpg",
        "images/cat_sleep2.jpg",
    ):
        _require((ROOT / relative).is_file(), f"cat image missing: {relative}")

    _require(get_timezone("UTC") is timezone.utc, "UTC timezone fallback failed")
    seoul = get_timezone("Asia/Seoul")
    _require(isinstance(seoul, ZoneInfo), "Asia/Seoul did not resolve with ZoneInfo")
    _require(
        seoul.utcoffset(datetime(2026, 7, 5, 10, 0, 0)) == timedelta(hours=9),
        "Asia/Seoul UTC offset mismatch",
    )
    _require(
        parse_user_datetime("2026-07-05 10:00:00", seoul)
        == datetime(2026, 7, 5, 1, 0, 0, tzinfo=timezone.utc),
        "Asia/Seoul to UTC conversion failed",
    )

    evtx_sample = ROOT / "tests" / "fixtures" / "issue_38.evtx"
    with Evtx(str(evtx_sample)) as event_log:
        raw_xml_records = [record.xml() for record in event_log.records()]
    _require(len(raw_xml_records) == 1, "real EVTX record count mismatch")
    _require(raw_xml_records[0].startswith("<Event "), "real EVTX XML conversion failed")

    evtx_result = parse_event_files([evtx_sample], start_utc=None, end_utc=None, max_records=1000)
    _require(evtx_result.total_seen == 1, "real EVTX total_seen mismatch")
    _require(evtx_result.total_in_range == 1, "real EVTX total_in_range mismatch")
    _require(not evtx_result.errors, f"real EVTX parse errors: {evtx_result.errors}")
    _require(evtx_result.records[0].event_id == "4672", "real EVTX event ID mismatch")
    _require(
        evtx_result.records[0].provider == "Microsoft-Windows-Security-Auditing",
        "real EVTX provider mismatch",
    )
    _require(evtx_result.records[0].channel == "Security", "real EVTX channel mismatch")

    sample = ROOT / "tests" / "sample_events.xml"
    parse_result = parse_event_files([sample], start_utc=None, end_utc=None, max_records=1000)
    _require(parse_result.total_seen == 3, "sample XML total_seen mismatch")
    _require(parse_result.total_in_range == 3, "sample XML total_in_range mismatch")
    _require(not parse_result.errors, f"sample XML parse errors: {parse_result.errors}")

    analysis = analyze_events(parse_result, start_utc=None, end_utc=None)
    rule_ids = {finding["rule_id"] for finding in analysis["findings"]}
    _require("log_cleared" in rule_ids, "log clear rule did not trigger")
    _require("service_installed" in rule_ids, "service install rule did not trigger")
    _require(
        "suspicious_process_encoded_powershell" in rule_ids,
        "encoded PowerShell rule did not trigger",
    )
    suspicious_events = analysis["suspicious_events"]
    _require(
        [event["event_ref"] for event in suspicious_events]
        == ["EVT-0001", "EVT-0002", "EVT-0003"],
        "canonical suspicious event references mismatch",
    )
    known_refs = {event["event_ref"] for event in suspicious_events}
    _require(
        {event["event_id"] for event in suspicious_events}
        == {"1102", "7045", "4688"},
        "suspicious event IDs mismatch",
    )
    scenarios = analysis["scenario_candidates"]
    _require(len(scenarios) == 1, "expected one correlated scenario candidate")
    scenario = scenarios[0]
    _require(scenario["scenario_id"] == "SCN-001", "scenario ID mismatch")
    _require(
        scenario["event_refs"] == ["EVT-0001", "EVT-0002", "EVT-0003"],
        "scenario event reference order mismatch",
    )
    _require(
        set(scenario["event_refs"]).issubset(known_refs),
        "scenario contains an unresolved event reference",
    )
    _require(
        [stage["order"] for stage in scenario["stages"]] == [1, 2, 3],
        "scenario stage ordering mismatch",
    )
    _require(
        [stage["event_ref"] for stage in scenario["stages"]]
        == scenario["event_refs"],
        "scenario stage references mismatch",
    )

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
    _require("log_cleared" not in collision_rules, "event ID collision triggered log clear")
    _require(
        "defender_detection_or_tamper" not in collision_rules,
        "event ID collision triggered Defender",
    )
    _require("wmi_activity" not in collision_rules, "event ID collision triggered WMI")

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
    _require("log_cleared" in contextual_rules, "contextual log clear rule did not trigger")
    _require(
        "defender_detection_or_tamper" in contextual_rules,
        "contextual Defender rule did not trigger",
    )
    _require("wmi_activity" in contextual_rules, "contextual WMI rule did not trigger")

    app_source = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    for contract_marker in (
        "analysis.suspicious_events",
        "analysis.suspicious_event_scope",
        "analysis.scenario_candidates",
        "analysis.attack_scenarios",
        "analysis.findings",
        "의심 이벤트",
        "공격 시나리오 후보",
    ):
        _require(
            contract_marker in app_source,
            f"UI structured analysis contract missing: {contract_marker}",
        )

    report, llm = generate_report(analysis, use_llm=False, lm_url=None, model=None)
    _require("CAT 규칙 기반 침해 로그 분석 보고서" in report, "fallback report missing")
    _require(llm["used"] is False, "fallback report unexpectedly used an LLM")
    rule_report, rule_status = generate_rule_report(analysis)
    _require("보고서 방식: CAT 내장 규칙 엔진 기반" in rule_report, "rule report missing")
    for section in REQUIRED_REPORT_SECTIONS:
        _require(section in rule_report, f"rule report section missing: {section}")
    _require("SCN-001" in rule_report, "rule report scenario missing")
    _require("EVT-0001" in rule_report, "rule report suspicious event missing")
    _require(rule_status["backend"] == "rule", "rule backend status mismatch")
    _require(rule_status["used"] is True, "rule backend was not marked used")
    print("CAT smoke test passed")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"CAT smoke test failed: {message}")


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
