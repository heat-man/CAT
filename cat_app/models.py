from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .timeutil import isoformat_utc


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


@dataclass
class ParseResult:
    records: list[EventRecord]
    files: list[dict[str, Any]]
    errors: list[str]
    total_seen: int
    total_in_range: int
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "errors": self.errors,
            "total_seen": self.total_seen,
            "total_in_range": self.total_in_range,
            "truncated": self.truncated,
        }
