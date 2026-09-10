from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import isfinite
import ntpath
import os
from typing import Any

from .models import ParseResult
from .timeutil import isoformat_utc, parse_event_time


def _env_seconds(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    if not isfinite(value):
        return default
    return max(minimum, min(maximum, value))


DEFAULT_AUTO_EXPAND_EDGE_SECONDS = _env_seconds(
    "CAT_AUTO_EXPAND_EDGE_SECONDS",
    15 * 60,
    minimum=60,
    maximum=60 * 60,
)
DEFAULT_AUTO_EXPAND_WINDOW_SECONDS = _env_seconds(
    "CAT_AUTO_EXPAND_WINDOW_SECONDS",
    60 * 60,
    minimum=5 * 60,
    maximum=24 * 60 * 60,
)
DEFAULT_AUTO_EXPAND_MAX_ROUNDS = int(_env_seconds(
    "CAT_AUTO_EXPAND_MAX_ROUNDS", 4, minimum=1, maximum=8,
))
DEFAULT_AUTO_EXPAND_MAX_LOOKBACK_SECONDS = _env_seconds(
    "CAT_AUTO_EXPAND_MAX_LOOKBACK_SECONDS", 24 * 60 * 60,
    minimum=5 * 60, maximum=7 * 24 * 60 * 60,
)
DEFAULT_AUTO_EXPAND_BUDGET_SECONDS = _env_seconds(
    "CAT_AUTO_EXPAND_BUDGET_SECONDS", 600, minimum=30, maximum=7200,
)


@dataclass(frozen=True)
class AdaptiveRangeDecision:
    start_utc: datetime | None
    end_utc: datetime | None
    reasons: tuple[str, ...] = ()

    @property
    def expanded(self) -> bool:
        return bool(self.reasons)

    def metadata(
        self,
        *,
        enabled: bool,
        requested_start_utc: datetime | None,
        requested_end_utc: datetime | None,
        parse_result: ParseResult,
    ) -> dict[str, Any]:
        return {
            "enabled": enabled,
            "expanded": self.expanded,
            "requested_start_utc": isoformat_utc(requested_start_utc),
            "requested_end_utc": isoformat_utc(requested_end_utc),
            "effective_start_utc": isoformat_utc(self.start_utc),
            "effective_end_utc": isoformat_utc(self.end_utc),
            "reasons": list(self.reasons),
            "available_events_before_requested_range": (
                parse_result.events_before_range
            ),
            "available_events_after_requested_range": (
                parse_result.events_after_range
            ),
        }


def recommend_expanded_range(
    analysis: dict[str, Any],
    parse_result: ParseResult,
    start_utc: datetime | None,
    end_utc: datetime | None,
    *,
    enabled: bool,
    edge_seconds: float = DEFAULT_AUTO_EXPAND_EDGE_SECONDS,
    window_seconds: float = DEFAULT_AUTO_EXPAND_WINDOW_SECONDS,
    round_index: int = 0,
    requested_start_utc: datetime | None = None,
    max_lookback_seconds: float = DEFAULT_AUTO_EXPAND_MAX_LOOKBACK_SECONDS,
    allow_end_expansion: bool = True,
) -> AdaptiveRangeDecision:
    """Extend a selected incident's causal context within uploaded evidence.

    Missing parent/creator identities justify earlier investigation even when
    the suspicious child is far from the selected boundary. Free-text model
    recommendations never provide dates or expansion authority.
    """
    if not enabled or (start_utc is None and end_utc is None):
        return AdaptiveRangeDecision(start_utc, end_utc)

    signal_times = _analysis_signal_times(analysis)
    trace_gaps = root_trace_gaps(analysis)
    if not signal_times and not trace_gaps:
        return AdaptiveRangeDecision(start_utc, end_utc)

    effective_start = start_utc
    effective_end = end_utc
    reasons: list[str] = []
    earliest_signal = min(signal_times) if signal_times else None
    latest_signal = max(signal_times) if signal_times else None
    expansion = timedelta(seconds=min(
        window_seconds * (2 ** min(max(round_index, 0), 8)), max_lookback_seconds,
    ))
    near_start = bool(start_utc is not None and earliest_signal is not None
                      and 0 <= (earliest_signal - start_utc).total_seconds() <= edge_seconds)

    if (
        start_utc is not None
        and parse_result.events_before_range > 0
        and (near_start or trace_gaps)
    ):
        candidate = start_utc - expansion
        minimum_start = (requested_start_utc or start_utc) - timedelta(seconds=max_lookback_seconds)
        candidate = max(candidate, minimum_start)
        if (
            parse_result.earliest_event_time is not None
            and candidate < parse_result.earliest_event_time
        ):
            candidate = parse_result.earliest_event_time
        if candidate < start_utc:
            effective_start = candidate
            reasons.append(
                "침해 후보의 부모·파일 생성자 등 선행 증거가 누락되어 최초 원인 프로세스를 추적하기 위해 이전 로그를 포함했습니다."
                if trace_gaps else
                "선택 범위 시작 경계 인근에서 침해 후보가 발견되어 선행 프로세스·행위 확인을 위해 이전 로그를 포함했습니다."
            )

    if (
        allow_end_expansion
        and end_utc is not None
        and parse_result.events_after_range > 0
        and latest_signal is not None
        and 0 <= (end_utc - latest_signal).total_seconds() <= edge_seconds
    ):
        candidate = end_utc + timedelta(seconds=window_seconds)
        if (
            parse_result.latest_event_time is not None
            and candidate > parse_result.latest_event_time
        ):
            candidate = parse_result.latest_event_time
        if candidate > end_utc:
            effective_end = candidate
            reasons.append(
                "선택 범위 종료 경계 인근에서 침해 후보가 발견되어 후속 통신·행위 확인을 위해 이후 로그를 포함했습니다."
            )

    return AdaptiveRangeDecision(effective_start, effective_end, tuple(reasons))


def incident_focus_anchors(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    chain = analysis.get("intrusion_chain")
    if not isinstance(chain, dict):
        return []
    anchors: list[dict[str, Any]] = []
    for key in ("observed_trigger_process", "origin_process"):
        process = chain.get(key)
        if not isinstance(process, dict):
            continue
        if not (process.get("host") and (
            process.get("source_ref") or process.get("process_guid")
            or (process.get("process_id") and process.get("start_time"))
        )):
            continue
        anchor = {key: process.get(key) for key in (
            "host", "process_guid", "process_id", "start_time", "source_ref", "process",
        )}
        if anchor not in anchors:
            anchors.append(anchor)
    return anchors


def root_trace_gaps(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Return bounded deterministic lookup targets, not a malware verdict."""
    chain = analysis.get("intrusion_chain")
    if not isinstance(chain, dict):
        return []
    processes = [chain.get(key) for key in (
        "origin_process", "observed_trigger_process", "initiating_process_candidate",
    )]
    processes.extend(chain.get("upstream_process_context") or [])
    gaps: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for process in processes:
        if not isinstance(process, dict) or not (
            process.get("source_ref") or process.get("event_refs")
        ):
            continue
        # Routine OS ancestry alone is not a reason to keep widening a case.
        if (process.get("role") == "upstream_context" and ntpath.basename(
            str(process.get("process") or "")
        ).casefold() in {"explorer.exe", "services.exe", "svchost.exe", "winlogon.exe",
                         "userinit.exe", "smss.exe", "csrss.exe", "system"}):
            continue
        missing_parent = not process.get("parent_process_instance_id") and (
            process.get("parent_process_guid") or process.get("parent_process_id")
        )
        missing_creation = not process.get("creation_event_observed") and (
            process.get("process_guid") or process.get("process_id")
        )
        if not missing_parent and not missing_creation:
            continue
        identity = (process.get("host"), process.get("source_ref"), process.get("process_guid"),
                    process.get("process_id"), process.get("start_time"))
        if identity in seen:
            continue
        seen.add(identity)
        gaps.append({
            "kind": "parent_creation" if missing_parent else "process_creation",
            "host": process.get("host"), "source_ref": process.get("source_ref"),
            "process": process.get("process"), "observed_time": process.get("start_time"),
            "process_guid": process.get("parent_process_guid") if missing_parent else process.get("process_guid"),
            "process_id": process.get("parent_process_id") if missing_parent else process.get("process_id"),
            "reason": "관측된 의심 계보의 부모 생성 이벤트가 없습니다." if missing_parent
                      else "관측된 의심 프로세스의 생성 이벤트가 없습니다.",
        })
    for link in chain.get("file_provenance") or []:
        if (isinstance(link, dict) and link.get("source_refs")
                and not link.get("creator_process_instance_id")
                and (link.get("creator_process_guid") or link.get("creator_process_id"))):
            gaps.append({
                "kind": "file_creator_creation", "source_refs": link.get("source_refs"),
                "process_guid": link.get("creator_process_guid"),
                "process_id": link.get("creator_process_id"),
                "process": link.get("creator_process"), "observed_time": link.get("time"),
                "target_filename": link.get("target_filename"),
                "reason": "실행 대상 파일을 생성한 프로세스의 생성 이벤트가 없습니다.",
            })
    for artifact in chain.get("payload_artifacts") or []:
        if (isinstance(artifact, dict) and artifact.get("source_ref")
                and artifact.get("reference_kind") == "command_line_literal"
                and artifact.get("referenced_path") and not artifact.get("creation_source_refs")):
            gaps.append({
                "kind": "payload_file_creation", "source_ref": artifact.get("source_ref"),
                "target_filename": artifact.get("referenced_path"),
                "reason": "의심 실행 명령에서 참조한 파일의 생성 경위를 확인해야 합니다.",
            })
    return gaps[:16]


def _analysis_signal_times(analysis: dict[str, Any]) -> list[datetime]:
    values: list[Any] = []
    suspicious_events = analysis.get("suspicious_events")
    if isinstance(suspicious_events, list):
        values.extend(
            event.get("time")
            for event in suspicious_events
            if isinstance(event, dict)
        )
    findings = analysis.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "").casefold()
            if severity not in {"critical", "high", "medium"}:
                continue
            values.extend((finding.get("first_seen"), finding.get("last_seen")))

    chain = analysis.get("intrusion_chain")
    if isinstance(chain, dict) and chain.get("origin_process"):
        # Use actual observed starts in the evidence-linked causal chain. A
        # free-text hypothesis or arbitrary requested date must not expand it.
        for key in ("origin_process", "initiating_process_candidate", "observed_trigger_process"):
            process = chain.get(key)
            if isinstance(process, dict) and process.get("creation_event_observed"):
                values.append(process.get("start_time"))
        for link in chain.get("file_provenance") or []:
            if isinstance(link, dict) and link.get("source_refs"):
                values.append(link.get("time"))

    parsed: list[datetime] = []
    for value in values:
        if isinstance(value, datetime):
            parsed.append(value)
            continue
        timestamp = parse_event_time(str(value)) if value else None
        if timestamp is not None:
            parsed.append(timestamp)
    return parsed
