from __future__ import annotations

from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

from .models import EventRecord, ParseResult
from .timeutil import parse_event_time

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

try:
    from Evtx.Evtx import Evtx
except Exception:  # pragma: no cover - depends on optional runtime package.
    Evtx = None  # type: ignore[assignment]


class EvtxDependencyError(RuntimeError):
    pass


def parse_event_files(
    paths: list[Path],
    start_utc: datetime | None,
    end_utc: datetime | None,
    max_records: int,
) -> ParseResult:
    records: list[EventRecord] = []
    files: list[dict[str, object]] = []
    errors: list[str] = []
    total_seen = 0
    total_in_range = 0
    truncated = False

    for path in paths:
        before_seen = total_seen
        before_range = total_in_range
        file_error: str | None = None
        try:
            iterator = _parse_xml_file(path) if path.suffix.lower() == ".xml" else _parse_evtx_file(path)
            for record in iterator:
                total_seen += 1
                if _in_range(record.time_created, start_utc, end_utc):
                    total_in_range += 1
                    if len(records) < max_records:
                        records.append(record)
                    else:
                        truncated = True
        except EvtxDependencyError as exc:
            file_error = str(exc)
            errors.append(f"{path.name}: {exc}")
        except Exception as exc:
            file_error = f"{type(exc).__name__}: {exc}"
            errors.append(f"{path.name}: {file_error}")

        files.append(
            {
                "name": path.name,
                "events_seen": total_seen - before_seen,
                "events_in_range": total_in_range - before_range,
                "error": file_error,
            }
        )

    return ParseResult(
        records=records,
        files=files,
        errors=errors,
        total_seen=total_seen,
        total_in_range=total_in_range,
        truncated=truncated,
    )


def _parse_evtx_file(path: Path):
    if Evtx is None:
        raise EvtxDependencyError(
            "EVTX 파싱 모듈이 설치되어 있지 않습니다. `python3 -m pip install -r requirements.txt`로 python-evtx를 설치하세요."
        )
    with Evtx(str(path)) as event_log:
        for record in event_log.records():
            yield parse_event_xml(record.xml(), path.name)


def _parse_xml_file(path: Path):
    root = ET.parse(path).getroot()
    if _local_name(root.tag) == "Event":
        yield parse_event_xml(ET.tostring(root, encoding="unicode"), path.name)
        return
    for event in root.iter():
        if _local_name(event.tag) == "Event":
            yield parse_event_xml(ET.tostring(event, encoding="unicode"), path.name)


def parse_event_xml(xml_text: str, source_file: str) -> EventRecord:
    root = ET.fromstring(xml_text)
    system = _first_child(root, "System")
    event_data = _extract_event_data(root)
    user_data = _extract_user_data(root)

    provider = None
    event_id = None
    channel = None
    computer = None
    time_created = None
    record_id = None
    level = None
    task = None
    opcode = None
    keywords = None

    if system is not None:
        provider_node = _first_child(system, "Provider")
        if provider_node is not None:
            provider = provider_node.attrib.get("Name") or provider_node.attrib.get("Guid")
        event_id = _child_text(system, "EventID")
        channel = _child_text(system, "Channel")
        computer = _child_text(system, "Computer")
        record_id = _child_text(system, "EventRecordID")
        level = _child_text(system, "Level")
        task = _child_text(system, "Task")
        opcode = _child_text(system, "Opcode")
        keywords = _child_text(system, "Keywords")
        time_node = _first_child(system, "TimeCreated")
        if time_node is not None:
            time_created = parse_event_time(time_node.attrib.get("SystemTime"))

    return EventRecord(
        source_file=source_file,
        event_id=event_id,
        provider=provider,
        channel=channel,
        computer=computer,
        time_created=time_created,
        record_id=record_id,
        level=level,
        task=task,
        opcode=opcode,
        keywords=keywords,
        event_data=event_data,
        user_data=user_data,
        raw_xml=xml_text,
    )


def _extract_event_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    event_data = _first_child(root, "EventData")
    if event_data is None:
        return data
    unnamed_count = 0
    for node in list(event_data):
        key = node.attrib.get("Name")
        if not key:
            unnamed_count += 1
            key = f"Data{unnamed_count}"
        _set_unique(data, key, _node_text(node))
    return data


def _extract_user_data(root: ET.Element) -> dict[str, str]:
    data: dict[str, str] = {}
    user_data = _first_child(root, "UserData")
    if user_data is None:
        return data
    for node in list(user_data):
        _flatten(node, _local_name(node.tag), data)
    return data


def _flatten(node: ET.Element, prefix: str, data: dict[str, str]) -> None:
    children = list(node)
    if not children:
        _set_unique(data, prefix, _node_text(node))
        return
    for child in children:
        name = f"{prefix}.{_local_name(child.tag)}"
        _flatten(child, name, data)


def _set_unique(data: dict[str, str], key: str, value: str) -> None:
    clean_value = value.strip()
    if key not in data:
        data[key] = clean_value
        return
    index = 2
    while f"{key}_{index}" in data:
        index += 1
    data[f"{key}_{index}"] = clean_value


def _node_text(node: ET.Element) -> str:
    return " ".join(part.strip() for part in node.itertext() if part and part.strip())


def _child_text(node: ET.Element, child_name: str) -> str | None:
    child = _first_child(node, child_name)
    if child is None:
        return None
    text = _node_text(child)
    return text or None


def _first_child(node: ET.Element, child_name: str) -> ET.Element | None:
    for child in list(node):
        if _local_name(child.tag) == child_name:
            return child
    return None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _in_range(value: datetime | None, start_utc: datetime | None, end_utc: datetime | None) -> bool:
    if value is None:
        return True
    if start_utc and value < start_utc:
        return False
    if end_utc and value > end_utc:
        return False
    return True
