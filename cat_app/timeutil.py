from __future__ import annotations

from datetime import datetime, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def get_timezone(name: str | None) -> tzinfo:
    key = (name or "UTC").strip()
    if key.upper() in {"UTC", "Z"}:
        return timezone.utc
    try:
        return ZoneInfo(key)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(
            f"지원하지 않거나 시간대 데이터가 없는 IANA 시간대입니다: {key}. "
            "Windows 독립망 설치에서는 vendor/wheels의 tzdata 패키지를 확인하세요."
        ) from exc


def parse_user_datetime(value: str | None, default_tz: tzinfo) -> datetime | None:
    if not value or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz)
    return dt.astimezone(timezone.utc)


def parse_event_time(value: str | None) -> datetime | None:
    if not value or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def isoformat_utc(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
