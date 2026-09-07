"""Bounded report evidence, collected before per-finding LM/UI sampling.

The context is local to one analysis (including concurrent callers). Records
remain data; neither original commands nor decoded scripts are ever executed.
"""
from __future__ import annotations

from contextvars import ContextVar
from functools import wraps
import hashlib
import heapq
import json
import os
from typing import Any, Callable

from .models import EventRecord
from .timeutil import isoformat_utc


def _limit(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


REPORT_EVIDENCE_MAX_EVENTS = _limit("CAT_REPORT_EVIDENCE_MAX_EVENTS", 4096, 32, 20000)
REPORT_EVIDENCE_MAX_CHARS = _limit(
    "CAT_REPORT_EVIDENCE_MAX_CHARS", 8 * 1024 * 1024, 64 * 1024, 32 * 1024 * 1024
)
_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
_CONFIDENCE = {"high": 3, "medium": 2, "low": 1}
_CURRENT: ContextVar[_EvidenceCollector | None] = ContextVar("cat_report_evidence", default=None)


def _identity(value: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(value.get(key) or "") for key in (
        "source_file", "record_id", "time", "event_id", "provider", "channel", "host"
    ))


def _record_identity(event: EventRecord) -> tuple[str, ...]:
    key = (
        event.source_file, str(event.record_id or ""), isoformat_utc(event.time_created) or "",
        str(event.event_id or ""), event.provider or "", event.channel or "", event.computer or "",
    )
    if not event.record_id:
        raw_fields = json.dumps([event.event_data, event.user_data], ensure_ascii=False, sort_keys=True)
        return (*key, hashlib.sha256(raw_fields.encode()).hexdigest())
    return key


class _EvidenceCollector:
    def __init__(self) -> None:
        self.entries: dict[tuple[str, ...], dict[str, Any]] = {}
        self.priorities: dict[tuple[str, ...], tuple[int, int, int]] = {}
        self.sizes: dict[tuple[str, ...], int] = {}
        self.heap: list[tuple[tuple[int, int, int], tuple[str, ...]]] = []
        self.chars = 0
        self.matches = 0
        self.omitted = 0
        self.upstream_omitted = 0

    def _lowest(self) -> tuple[tuple[int, int, int], tuple[str, ...]]:
        while self.heap and self.priorities.get(self.heap[0][1]) != self.heap[0][0]:
            heapq.heappop(self.heap)
        return self.heap[0]

    def _set(self, key: tuple[str, ...], entry: dict[str, Any], priority: tuple[int, int, int]) -> None:
        # Reserve room for final event_ref and JSON list separators.
        size = len(json.dumps(entry, ensure_ascii=False, separators=(",", ":"))) + 128
        self.chars += size - self.sizes.get(key, 0)
        self.entries[key], self.priorities[key], self.sizes[key] = entry, priority, size
        heapq.heappush(self.heap, (priority, key))
        # Repeated multi-rule matches cannot grow a stale priority heap forever.
        if len(self.heap) > max(64, 3 * len(self.entries)):
            self.heap = [(value, item) for item, value in self.priorities.items()]
            heapq.heapify(self.heap)
        while self.entries and (
            len(self.entries) > REPORT_EVIDENCE_MAX_EVENTS or self.chars > REPORT_EVIDENCE_MAX_CHARS
        ):
            _, removed = self._lowest()
            heapq.heappop(self.heap)
            self.omitted += len(self.entries[removed].get("rule_ids") or [])
            self.chars -= self.sizes.pop(removed)
            del self.entries[removed], self.priorities[removed]

    def add(
        self, events: list[EventRecord], *, rule_id: str, title: str, severity: str,
        confidence: str, description: str, evidence_factory: Callable[[EventRecord], dict[str, Any]],
        event_count: int | None,
    ) -> None:
        self.matches += len(events)
        self.upstream_omitted += max(0, int(event_count or 0) - len(events))
        for index, event in enumerate(events):
            key = _record_identity(event)
            # Per-rule time boundaries outrank uniform, deterministic samples.
            digest = int.from_bytes(hashlib.sha256(repr(key).encode()).digest()[:8], "big")
            priority = (int(index in (0, len(events) - 1)), _SEVERITY.get(severity, 0), digest)
            previous = self.entries.get(key)
            if previous is None:
                if (len(self.entries) >= REPORT_EVIDENCE_MAX_EVENTS and self.heap
                        and priority <= self._lowest()[0]):
                    self.omitted += 1
                    continue
                entry = dict(evidence_factory(event))
                entry.update(severity=severity, confidence=confidence, rule_ids=[], reasons=[])
            else:
                entry = dict(previous)
                entry["rule_ids"] = list(previous["rule_ids"])
                entry["reasons"] = list(previous["reasons"])
                priority = max(priority, self.priorities[key])
                if _SEVERITY.get(severity, 0) > _SEVERITY.get(str(entry.get("severity")), 0):
                    entry["severity"] = severity
                if _CONFIDENCE.get(confidence, 0) > _CONFIDENCE.get(str(entry.get("confidence")), 0):
                    entry["confidence"] = confidence
            if rule_id not in entry["rule_ids"]:
                entry["rule_ids"].append(rule_id)
                entry["reasons"].append({"rule_id": rule_id, "title": title, "description": description})
            self._set(key, entry, priority)

    def attach(self, analysis: dict[str, Any]) -> None:
        existing = {
            _identity(item): item.get("event_ref")
            for item in analysis.get("suspicious_events") or []
            if isinstance(item, dict) and item.get("record_id")
        }
        entries = sorted(self.entries.values(), key=lambda item: (
            item.get("time") is None, str(item.get("time") or ""),
            str(item.get("source_file") or ""), str(item.get("record_id") or ""),
        ))
        for index, entry in enumerate(entries, 1):
            entry["event_ref"] = existing.get(_identity(entry)) or f"RPT-{index:05d}"
        scope = analysis.get("scope") or {}
        endpoint_scope = analysis.get("endpoint_rule_scope") or {}
        limitations = []
        if self.omitted:
            limitations.append(
                f"보고서 근거 보관 상한으로 규칙 매칭 참조 {self.omitted}건이 생략되었습니다. "
                "같은 이벤트의 다중 규칙 매칭이 포함될 수 있으며 고유 이벤트 수가 아닙니다."
            )
        if self.upstream_omitted:
            limitations.append(
                f"네트워크 등 선행 집계에서 원본 상세 대신 횟수로 전달된 규칙 매칭 참조가 "
                f"{self.upstream_omitted}건 있습니다. 대표 근거만 수록됩니다."
            )
        if scope.get("truncated") or scope.get("record_limit_reached"):
            limitations.append("입력/일반 보관 상한이 적용되어 모든 원본 이벤트에 대한 규칙 탐지를 보장하지 않습니다.")
        if endpoint_scope.get("omitted_matching_records"):
            limitations.append(
                f"추가 프로세스/PowerShell 규칙 입력 상한으로 의심 후보 "
                f"{endpoint_scope['omitted_matching_records']}건을 상세 분석하지 못했습니다."
            )
        analysis["report_evidence"] = entries
        analysis["report_evidence_scope"] = {
            "included_event_count": len(entries),
            "matched_event_references": self.matches,
            "omitted_event_references": self.omitted,
            "upstream_omitted_event_references": self.upstream_omitted,
            "max_events": REPORT_EVIDENCE_MAX_EVENTS,
            "max_chars": REPORT_EVIDENCE_MAX_CHARS,
            "serialized_chars": len(json.dumps(entries, ensure_ascii=False, separators=(",", ":"))),
            "truncated": bool(self.omitted or self.upstream_omitted),
            "input_scan_limited": bool(scope.get("truncated") or scope.get("record_limit_reached")),
            "limitations": limitations,
            "note": "LM 입력 선별과 독립적으로 로컬 규칙 매칭 근거를 시간순 보존합니다. 탐지되지 않은 원본 로그 전체는 아닙니다.",
        }


def record_finding_evidence(
    events: list[EventRecord], *, rule_id: str, title: str, severity: str,
    confidence: str, description: str, evidence_factory: Callable[[EventRecord], dict[str, Any]],
    event_count: int | None = None,
) -> None:
    collector = _CURRENT.get()
    if collector is not None:
        collector.add(events, rule_id=rule_id, title=title, severity=severity,
                      confidence=confidence, description=description,
                      evidence_factory=evidence_factory, event_count=event_count)


def capture_report_evidence(function: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> dict[str, Any]:
        collector = _EvidenceCollector()
        token = _CURRENT.set(collector)
        try:
            analysis = function(*args, **kwargs)
            collector.attach(analysis)
            return analysis
        finally:
            _CURRENT.reset(token)
    return wrapped
