from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import Any, Iterator, TextIO

from .timeutil import isoformat_utc, parse_event_time


@dataclass
class EventRecord:
    source_file: str
    event_id: str | None
    provider: str | None
    channel: str | None
    computer: str | None
    time_created: datetime | None
    record_id: str | None = None
    level: str | None = None
    task: str | None = None
    opcode: str | None = None
    keywords: str | None = None
    event_data: dict[str, str] = field(default_factory=dict)
    user_data: dict[str, str] = field(default_factory=dict)
    raw_xml: str = ""

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source_file": self.source_file,
            "event_id": self.event_id,
            "provider": self.provider,
            "channel": self.channel,
            "computer": self.computer,
            "time_created": isoformat_utc(self.time_created),
            "record_id": self.record_id,
            "level": self.level,
            "task": self.task,
            "opcode": self.opcode,
            "keywords": self.keywords,
            "event_data": self.event_data,
            "user_data": self.user_data,
        }
        if include_raw:
            data["raw_xml"] = self.raw_xml
        return data

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EventRecord":
        """Restore a compact, CAT-produced event record from an analysis spool."""
        event_data = value.get("event_data")
        user_data = value.get("user_data")
        return cls(
            source_file=str(value.get("source_file") or ""),
            event_id=_optional_text(value.get("event_id")),
            provider=_optional_text(value.get("provider")),
            channel=_optional_text(value.get("channel")),
            computer=_optional_text(value.get("computer")),
            time_created=parse_event_time(_optional_text(value.get("time_created"))),
            record_id=_optional_text(value.get("record_id")),
            level=_optional_text(value.get("level")),
            task=_optional_text(value.get("task")),
            opcode=_optional_text(value.get("opcode")),
            keywords=_optional_text(value.get("keywords")),
            event_data={
                str(key): str(item)
                for key, item in event_data.items()
                if key is not None and item is not None
            }
            if isinstance(event_data, dict)
            else {},
            user_data={
                str(key): str(item)
                for key, item in user_data.items()
                if key is not None and item is not None
            }
            if isinstance(user_data, dict)
            else {},
        )


@dataclass
class ParseResult:
    records: list[EventRecord]
    files: list[dict[str, Any]]
    errors: list[str]
    total_seen: int
    total_in_range: int
    truncated: bool = False
    record_limit_reached: bool = False
    retention_limit_reached: bool = False
    network_records_seen: int = 0
    network_records_spooled: int = 0
    network_spool_bytes: int = 0
    network_spool_limit_reached: bool = False
    network_scan_complete: bool = True
    earliest_event_time: datetime | None = None
    latest_event_time: datetime | None = None
    events_before_range: int = 0
    events_after_range: int = 0
    _network_record_spool: TextIO | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "errors": self.errors,
            "total_seen": self.total_seen,
            "total_in_range": self.total_in_range,
            "truncated": self.truncated,
            "record_limit_reached": self.record_limit_reached,
            "retention_limit_reached": self.retention_limit_reached,
            "records_retained": len(self.records),
            "network_records_seen": self.network_records_seen,
            "network_records_spooled": self.network_records_spooled,
            "network_spool_bytes": self.network_spool_bytes,
            "network_spool_limit_reached": self.network_spool_limit_reached,
            "network_scan_complete": self.network_scan_complete,
            "earliest_event_time": isoformat_utc(self.earliest_event_time),
            "latest_event_time": isoformat_utc(self.latest_event_time),
            "events_before_range": self.events_before_range,
            "events_after_range": self.events_after_range,
        }

    def iter_network_records(self) -> Iterator[EventRecord]:
        """Yield every in-range record retained for endpoint network analysis.

        Normal ``ParseResult`` instances constructed by callers and tests have
        no spool, so their in-memory records remain the backwards-compatible
        source. File parsing installs a rewindable spool containing all
        relevant events, including those beyond the general retention limit.
        """
        spool = self._network_record_spool
        if spool is None:
            yield from self.records
            return
        spool.seek(0)
        for line in spool:
            value = json.loads(line)
            if isinstance(value, dict):
                yield EventRecord.from_dict(value)

    @property
    def has_network_record_spool(self) -> bool:
        return self._network_record_spool is not None

    def close(self) -> None:
        spool, self._network_record_spool = self._network_record_spool, None
        if spool is not None:
            spool.close()

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup.
        try:
            self.close()
        except Exception:
            pass


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None
