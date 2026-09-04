from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import isfinite
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
) -> AdaptiveRangeDecision:
    """Recommend one bounded context expansion inside the uploaded logs.

    CAT only expands around a selected-range boundary when actionable evidence
    is close to that boundary and the parser observed timestamped events beyond
    it.  This avoids silently replacing the investigator's range with the
    entire file while still recovering likely parent/precursor and follow-on
    evidence.
    """
    if not enabled or (start_utc is None and end_utc is None):
        return AdaptiveRangeDecision(start_utc, end_utc)

    signal_times = _analysis_signal_times(analysis)
    if not signal_times:
        return AdaptiveRangeDecision(start_utc, end_utc)

    effective_start = start_utc
    effective_end = end_utc
    reasons: list[str] = []
    earliest_signal = min(signal_times)
    latest_signal = max(signal_times)
    expansion = timedelta(seconds=window_seconds)

    if (
        start_utc is not None
        and parse_result.events_before_range > 0
        and 0 <= (earliest_signal - start_utc).total_seconds() <= edge_seconds
    ):
        candidate = start_utc - expansion
        if (
            parse_result.earliest_event_time is not None
            and candidate < parse_result.earliest_event_time
        ):
            candidate = parse_result.earliest_event_time
        if candidate < start_utc:
            effective_start = candidate
            reasons.append(
                "선택 범위 시작 경계 인근에서 침해 후보가 발견되어 선행 프로세스·행위 확인을 위해 이전 로그를 포함했습니다."
            )

    if (
        end_utc is not None
        and parse_result.events_after_range > 0
        and 0 <= (end_utc - latest_signal).total_seconds() <= edge_seconds
    ):
        candidate = end_utc + expansion
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

    parsed: list[datetime] = []
    for value in values:
        if isinstance(value, datetime):
            parsed.append(value)
            continue
        timestamp = parse_event_time(str(value)) if value else None
        if timestamp is not None:
            parsed.append(timestamp)
    return parsed
