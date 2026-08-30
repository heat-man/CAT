from __future__ import annotations

from datetime import datetime
from math import isfinite
import os
from pathlib import Path
import time
import xml.etree.ElementTree as ET
import xml.parsers.expat as expat

from .models import EventRecord, ParseResult
from .timeutil import parse_event_time

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    if not isfinite(value):
        return default
    return max(minimum, min(maximum, value))


XML_READ_CHUNK_BYTES = 64 * 1024
MAX_XML_FILE_BYTES = _env_int(
    "CAT_XML_MAX_FILE_BYTES", 128 * 1024 * 1024, minimum=1024, maximum=512 * 1024 * 1024
)
MAX_XML_EVENT_BYTES = _env_int(
    "CAT_XML_MAX_EVENT_BYTES", 4 * 1024 * 1024, minimum=1024, maximum=32 * 1024 * 1024
)
MAX_XML_EVENT_TEXT_CHARS = _env_int(
    "CAT_XML_MAX_EVENT_TEXT_CHARS", 512 * 1024, minimum=1024, maximum=8 * 1024 * 1024
)
MAX_XML_RAW_CHARS = _env_int(
    "CAT_XML_MAX_RAW_CHARS", 1024 * 1024, minimum=1024, maximum=8 * 1024 * 1024
)
MAX_XML_TOKEN_BYTES = _env_int(
    "CAT_XML_MAX_TOKEN_BYTES", 256 * 1024, minimum=1024, maximum=1024 * 1024
)
MAX_XML_NAME_CHARS = _env_int(
    "CAT_XML_MAX_NAME_CHARS", 1024, minimum=64, maximum=8192
)
MAX_XML_ATTRIBUTE_CHARS = _env_int(
    "CAT_XML_MAX_ATTRIBUTE_CHARS", 64 * 1024, minimum=1024, maximum=1024 * 1024
)
MAX_XML_NAMESPACE_CHARS = _env_int(
    "CAT_XML_MAX_NAMESPACE_CHARS", 256, minimum=64, maximum=4096
)
MAX_XML_ATTRIBUTES_PER_ELEMENT = _env_int(
    "CAT_XML_MAX_ATTRIBUTES_PER_ELEMENT", 256, minimum=8, maximum=4096
)
MAX_XML_IN_SCOPE_NAMESPACES = _env_int(
    "CAT_XML_MAX_IN_SCOPE_NAMESPACES", 64, minimum=1, maximum=256
)
MAX_XML_FIELD_KEY_CHARS = _env_int(
    "CAT_XML_MAX_FIELD_KEY_CHARS", 1024, minimum=64, maximum=8192
)
MAX_XML_EXTRACTED_FIELDS_PER_EVENT = _env_int(
    "CAT_XML_MAX_EXTRACTED_FIELDS_PER_EVENT", 4096, minimum=16, maximum=20000
)
MAX_XML_EXTRACTED_CHARS_PER_EVENT = _env_int(
    "CAT_XML_MAX_EXTRACTED_CHARS_PER_EVENT",
    1024 * 1024,
    minimum=4096,
    maximum=16 * 1024 * 1024,
)
MAX_XML_RETAINED_CHARS_PER_ANALYSIS = _env_int(
    "CAT_XML_MAX_RETAINED_CHARS_PER_ANALYSIS",
    64 * 1024 * 1024,
    minimum=64 * 1024,
    maximum=512 * 1024 * 1024,
)
MAX_XML_RETAINED_FIELDS_PER_ANALYSIS = _env_int(
    "CAT_XML_MAX_RETAINED_FIELDS_PER_ANALYSIS",
    262_144,
    minimum=4096,
    maximum=2_000_000,
)
MAX_XML_EXPANDED_CHARS_PER_EVENT = _env_int(
    "CAT_XML_MAX_EXPANDED_CHARS_PER_EVENT",
    2 * 1024 * 1024,
    minimum=4096,
    maximum=16 * 1024 * 1024,
)
MAX_XML_EXPANDED_CHARS_PER_FILE = _env_int(
    "CAT_XML_MAX_EXPANDED_CHARS_PER_FILE",
    32 * 1024 * 1024,
    minimum=64 * 1024,
    maximum=256 * 1024 * 1024,
)
MAX_XML_ELEMENTS_PER_EVENT = _env_int(
    "CAT_XML_MAX_ELEMENTS_PER_EVENT", 20000, minimum=100, maximum=200000
)
MAX_XML_ELEMENTS_PER_FILE = _env_int(
    "CAT_XML_MAX_ELEMENTS_PER_FILE", 5_000_000, minimum=1000, maximum=20_000_000
)
MAX_XML_DEPTH = _env_int("CAT_XML_MAX_DEPTH", 128, minimum=16, maximum=1024)
XML_PARSE_TIMEOUT_SECONDS = _env_float(
    "CAT_XML_PARSE_TIMEOUT_SECONDS", 60.0, minimum=1.0, maximum=1800.0
)


class XMLLimitError(ValueError):
    pass


class _ExtractionBudget:
    def __init__(self) -> None:
        self.fields = 0
        self.chars = 0

    def reserve(self, key: str, value: str) -> None:
        if len(key) > MAX_XML_FIELD_KEY_CHARS:
            raise XMLLimitError(
                "XML flattened field key exceeds "
                f"{MAX_XML_FIELD_KEY_CHARS} characters"
            )
        self.fields += 1
        if self.fields > MAX_XML_EXTRACTED_FIELDS_PER_EVENT:
            raise XMLLimitError(
                "XML extracted field count exceeds "
                f"{MAX_XML_EXTRACTED_FIELDS_PER_EVENT} per event"
            )
        self.chars += len(key) + len(value)
        if self.chars > MAX_XML_EXTRACTED_CHARS_PER_EVENT:
            raise XMLLimitError(
                "XML extracted fields exceed "
                f"{MAX_XML_EXTRACTED_CHARS_PER_EVENT} characters per event"
            )


class _RetentionBudget:
    """Bound the records that remain live for the rest of an analysis."""

    def __init__(self) -> None:
        self.fields = 0
        self.chars = 0

    def reserve(self, record: EventRecord) -> None:
        field_count = len(record.event_data) + len(record.user_data)
        char_count = len(record.raw_xml)
        for value in (
            record.source_file,
            record.event_id,
            record.provider,
            record.channel,
            record.computer,
            record.record_id,
            record.level,
            record.task,
            record.opcode,
            record.keywords,
        ):
            if value is not None:
                char_count += len(value)
        for values in (record.event_data, record.user_data):
            char_count += sum(len(key) + len(value) for key, value in values.items())

        next_fields = self.fields + field_count
        if next_fields > MAX_XML_RETAINED_FIELDS_PER_ANALYSIS:
            raise XMLLimitError(
                "XML retained field count exceeds "
                f"{MAX_XML_RETAINED_FIELDS_PER_ANALYSIS} per analysis"
            )
        next_chars = self.chars + char_count
        if next_chars > MAX_XML_RETAINED_CHARS_PER_ANALYSIS:
            raise XMLLimitError(
                "XML retained records exceed "
                f"{MAX_XML_RETAINED_CHARS_PER_ANALYSIS} characters per analysis"
            )
        self.fields = next_fields
        self.chars = next_chars


class _BoundedXMLParser:
    """Incremental parser that avoids ElementTree namespace amplification.

    Namespace-aware ElementTree materializes ``{uri}name`` for every tag and
    attribute before TreeBuilder.start runs. A long URI combined with many
    short names can therefore amplify a small start tag into hundreds of MiB.
    Expat with namespace processing disabled keeps raw QNames so declarations
    and attribute counts can be rejected before any expanded names exist.
    """

    def __init__(self, target: "_StreamingEventTarget") -> None:
        self.target = target
        self.namespace_bindings: dict[str, str] = {}
        self.namespace_restore_stack: list[list[tuple[str, bool, str | None]]] = []
        parser = expat.ParserCreate(namespace_separator=None)
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        parser.CharacterDataHandler = target.data
        parser.CommentHandler = target.comment
        parser.ProcessingInstructionHandler = target.pi
        parser.StartDoctypeDeclHandler = self._reject_doctype
        parser.EntityDeclHandler = self._reject_entity
        parser.ExternalEntityRefHandler = self._reject_external_entity
        parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
        self.parser = parser

    def _start(self, tag: str, attrs: dict[str, str]) -> None:
        if len(attrs) > MAX_XML_ATTRIBUTES_PER_ELEMENT:
            raise XMLLimitError(
                "XML element attribute count exceeds "
                f"{MAX_XML_ATTRIBUTES_PER_ELEMENT}"
            )
        namespace_changes: list[tuple[str, bool, str | None]] = []
        for key, value in attrs.items():
            if (key == "xmlns" or key.startswith("xmlns:")) and len(value) > (
                MAX_XML_NAMESPACE_CHARS
            ):
                raise XMLLimitError(
                    "XML namespace URI exceeds "
                    f"{MAX_XML_NAMESPACE_CHARS} characters"
                )
            if key == "xmlns" or key.startswith("xmlns:"):
                namespace_changes.append(
                    (key, key in self.namespace_bindings, self.namespace_bindings.get(key))
                )
                self.namespace_bindings[key] = value
        if len(self.namespace_bindings) > MAX_XML_IN_SCOPE_NAMESPACES:
            raise XMLLimitError(
                "XML in-scope namespace count exceeds "
                f"{MAX_XML_IN_SCOPE_NAMESPACES}"
            )

        retained_attrs = attrs
        if _local_name(tag) == "Event" and self.namespace_bindings:
            retained_attrs = dict(attrs)
            for key, value in self.namespace_bindings.items():
                retained_attrs.setdefault(key, value)
            if len(retained_attrs) > MAX_XML_ATTRIBUTES_PER_ELEMENT:
                raise XMLLimitError(
                    "XML element attribute count exceeds "
                    f"{MAX_XML_ATTRIBUTES_PER_ELEMENT}"
                )
        self.namespace_restore_stack.append(namespace_changes)
        self.target.start(tag, retained_attrs)

    def _end(self, tag: str) -> ET.Element:
        element = self.target.end(tag)
        changes = self.namespace_restore_stack.pop()
        for key, existed, previous in reversed(changes):
            if existed and previous is not None:
                self.namespace_bindings[key] = previous
            else:
                self.namespace_bindings.pop(key, None)
        return element

    @staticmethod
    def _reject_doctype(*_args: object) -> None:
        raise XMLLimitError("XML DTD is not allowed")

    @staticmethod
    def _reject_entity(*_args: object) -> None:
        raise XMLLimitError("XML entity declarations are not allowed")

    @staticmethod
    def _reject_external_entity(*_args: object) -> int:
        raise XMLLimitError("XML external entities are not allowed")

    def feed(self, data: bytes) -> None:
        self.parser.Parse(data, False)

    def close(self) -> ET.Element:
        self.parser.Parse(b"", True)
        return self.target.close()


class _StreamingEventTarget(ET.TreeBuilder):
    """TreeBuilder that releases completed Event nodes from their container."""

    def __init__(self, deadline: float):
        super().__init__()
        self.deadline = deadline
        self.stack: list[ET.Element] = []
        self.completed: list[ET.Element] = []
        self.event_depth: int | None = None
        self.event_start_bytes = 0
        self.event_text_chars = 0
        self.event_elements = 0
        self.total_elements = 0
        self.total_expanded_chars = 0
        self.event_expanded_chars = 0
        self.feed_start_bytes = 0
        self.callback_serial = 0

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.callback_serial += 1
        self._check_deadline()
        if len(tag) > MAX_XML_NAME_CHARS:
            raise XMLLimitError(
                f"XML expanded name exceeds {MAX_XML_NAME_CHARS} characters"
            )
        expanded_chars = len(tag)
        for key, value in attrs.items():
            if len(key) > MAX_XML_NAME_CHARS:
                raise XMLLimitError(
                    f"XML expanded name exceeds {MAX_XML_NAME_CHARS} characters"
                )
            if len(value) > MAX_XML_ATTRIBUTE_CHARS:
                raise XMLLimitError(
                    "XML attribute value exceeds "
                    f"{MAX_XML_ATTRIBUTE_CHARS} characters"
                )
            expanded_chars += len(key) + len(value)
        self.total_expanded_chars += expanded_chars
        if self.total_expanded_chars > MAX_XML_EXPANDED_CHARS_PER_FILE:
            raise XMLLimitError(
                "XML expanded names and attributes exceed "
                f"{MAX_XML_EXPANDED_CHARS_PER_FILE} characters per file"
            )
        if len(self.stack) >= MAX_XML_DEPTH:
            raise XMLLimitError(f"XML nesting depth exceeds {MAX_XML_DEPTH}")
        self.total_elements += 1
        if self.total_elements > MAX_XML_ELEMENTS_PER_FILE:
            raise XMLLimitError(
                f"XML file element count exceeds {MAX_XML_ELEMENTS_PER_FILE}"
            )
        element = super().start(tag, attrs)
        self.stack.append(element)
        if self.event_depth is None and _local_name(tag) == "Event":
            self.event_depth = len(self.stack)
            self.event_expanded_chars = expanded_chars
            self.event_start_bytes = self.feed_start_bytes
            self.event_text_chars = 0
            self.event_elements = 1
        elif self.event_depth is not None:
            self.event_expanded_chars += expanded_chars
            if self.event_expanded_chars > MAX_XML_EXPANDED_CHARS_PER_EVENT:
                raise XMLLimitError(
                    "XML expanded names and attributes exceed "
                    f"{MAX_XML_EXPANDED_CHARS_PER_EVENT} characters per event"
                )
            self.event_elements += 1
            if self.event_elements > MAX_XML_ELEMENTS_PER_EVENT:
                raise XMLLimitError(
                    f"XML event element count exceeds {MAX_XML_ELEMENTS_PER_EVENT}"
                )
        return element

    def data(self, data: str) -> None:
        self.callback_serial += 1
        if self.event_depth is None:
            # Container indentation and other text are not part of an Event and
            # need not be retained. This also prevents wrapper-text memory abuse.
            return
        self.event_text_chars += len(data)
        if self.event_text_chars > MAX_XML_EVENT_TEXT_CHARS:
            raise XMLLimitError(
                f"XML event text exceeds {MAX_XML_EVENT_TEXT_CHARS} characters"
            )
        super().data(data)

    def end(self, tag: str) -> ET.Element:
        self.callback_serial += 1
        self._check_deadline()
        if not self.stack:
            raise XMLLimitError("invalid XML element stack")
        element = super().end(tag)
        parent = self.stack[-2] if len(self.stack) > 1 else None
        self.stack.pop()
        if self.event_depth == len(self.stack) + 1 and _local_name(tag) == "Event":
            if parent is not None:
                parent.remove(element)
            self.completed.append(element)
            self.event_depth = None
            self.event_text_chars = 0
            self.event_elements = 0
            self.event_expanded_chars = 0
        elif self.event_depth is None and parent is not None:
            # Irrelevant container subtrees must not accumulate under the root.
            parent.remove(element)
            element.clear()
        return element

    def comment(self, text: str) -> None:
        self.callback_serial += 1
        self._check_deadline()

    def pi(self, target: str, text: str | None = None) -> None:
        self.callback_serial += 1
        self._check_deadline()

    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise XMLLimitError("XML DTD is not allowed")

    def check_event_bytes(self, bytes_read: int) -> None:
        if (
            self.event_depth is not None
            and bytes_read - self.event_start_bytes > MAX_XML_EVENT_BYTES + XML_READ_CHUNK_BYTES
        ):
            raise XMLLimitError(f"XML event exceeds {MAX_XML_EVENT_BYTES} bytes")

    def pop_completed(self) -> list[ET.Element]:
        completed, self.completed = self.completed, []
        return completed

    def _check_deadline(self) -> None:
        _check_xml_deadline(self.deadline)


def _check_xml_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise TimeoutError(
            f"XML parsing exceeded {XML_PARSE_TIMEOUT_SECONDS:g} seconds"
        )

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
    stop_after_limit = False
    parse_deadline = time.monotonic() + XML_PARSE_TIMEOUT_SECONDS
    retention_budget = _RetentionBudget()

    for path in paths:
        before_seen = total_seen
        before_range = total_in_range
        file_error: str | None = None
        try:
            iterator = (
                _parse_xml_file(path, deadline=parse_deadline)
                if path.suffix.lower() == ".xml"
                else _parse_evtx_file(path, deadline=parse_deadline)
            )
            for record in iterator:
                total_seen += 1
                if _in_range(record.time_created, start_utc, end_utc):
                    total_in_range += 1
                    if len(records) < max_records:
                        retention_budget.reserve(record)
                        records.append(record)
                    else:
                        truncated = True
                        stop_after_limit = True
                        break
        except EvtxDependencyError as exc:
            file_error = str(exc)
            errors.append(f"{path.name}: {exc}")
        except Exception as exc:
            file_error = f"{type(exc).__name__}: {exc}"
            errors.append(f"{path.name}: {file_error}")
            # Preserve successfully parsed records, but make it explicit that
            # the input ended early because of a parser limit, timeout, or
            # malformed tail. Reports surface parser errors alongside this
            # truncation flag instead of silently presenting a complete scope.
            truncated = True

        files.append(
            {
                "name": path.name,
                "events_seen": total_seen - before_seen,
                "events_in_range": total_in_range - before_range,
                "error": file_error,
            }
        )
        if stop_after_limit:
            break

    return ParseResult(
        records=records,
        files=files,
        errors=errors,
        total_seen=total_seen,
        total_in_range=total_in_range,
        truncated=truncated,
    )


def _parse_evtx_file(path: Path, deadline: float | None = None):
    if Evtx is None:
        raise EvtxDependencyError(
            "EVTX 파싱 모듈이 설치되어 있지 않습니다. `python3 -m pip install -r requirements.txt`로 python-evtx를 설치하세요."
        )
    if deadline is None:
        deadline = time.monotonic() + XML_PARSE_TIMEOUT_SECONDS
    with Evtx(str(path)) as event_log:
        for record in event_log.records():
            _check_xml_deadline(deadline)
            xml_text = record.xml()
            _check_xml_deadline(deadline)
            yield parse_event_xml(xml_text, path.name, deadline=deadline)


def _parse_xml_file(path: Path, deadline: float | None = None):
    file_size = path.stat().st_size
    if file_size > MAX_XML_FILE_BYTES:
        raise XMLLimitError(f"XML file exceeds {MAX_XML_FILE_BYTES} bytes")

    if deadline is None:
        deadline = time.monotonic() + XML_PARSE_TIMEOUT_SECONDS
    target = _StreamingEventTarget(deadline)
    parser = _BoundedXMLParser(target)
    bytes_read = 0
    callback_serial = target.callback_serial
    bytes_without_callback = 0
    read_chunk_bytes = min(
        XML_READ_CHUNK_BYTES,
        max(64, MAX_XML_TOKEN_BYTES // 16),
    )
    with path.open("rb") as stream:
        while True:
            target._check_deadline()
            chunk = stream.read(read_chunk_bytes)
            if not chunk:
                break
            target.feed_start_bytes = bytes_read
            bytes_read += len(chunk)
            if bytes_read > MAX_XML_FILE_BYTES:
                raise XMLLimitError(f"XML file exceeds {MAX_XML_FILE_BYTES} bytes")
            # A callback can occur near either edge of a feed, so its exact
            # byte offset is unavailable. Conservatively treat the complete
            # callback-containing chunk as the possible start of the next XML
            # token, and reject before Expat can buffer beyond the hard cap.
            if bytes_without_callback + len(chunk) > MAX_XML_TOKEN_BYTES:
                raise XMLLimitError(
                    f"XML token exceeds {MAX_XML_TOKEN_BYTES} bytes"
                )
            try:
                parser.feed(chunk)
            except Exception:
                # Expat may complete one or more Event elements and then hit a
                # malformed/limited later event in the same feed. Yield those
                # completed records before surfacing the tail error so callers
                # can mark the result partial rather than losing valid prefix
                # evidence.
                for event in target.pop_completed():
                    record = _parse_event_element(
                        event,
                        path.name,
                        deadline=deadline,
                    )
                    event.clear()
                    yield record
                raise
            if target.callback_serial == callback_serial:
                bytes_without_callback += len(chunk)
            else:
                callback_serial = target.callback_serial
                bytes_without_callback = len(chunk)
            target.check_event_bytes(bytes_read)
            for event in target.pop_completed():
                record = _parse_event_element(event, path.name, deadline=deadline)
                event.clear()
                yield record
        parser.close()
        for event in target.pop_completed():
            record = _parse_event_element(event, path.name, deadline=deadline)
            event.clear()
            yield record


def parse_event_xml(
    xml_text: str,
    source_file: str,
    deadline: float | None = None,
) -> EventRecord:
    if deadline is None:
        deadline = time.monotonic() + XML_PARSE_TIMEOUT_SECONDS
    _check_xml_deadline(deadline)
    if len(xml_text) > MAX_XML_EVENT_BYTES:
        raise XMLLimitError(f"XML event exceeds {MAX_XML_EVENT_BYTES} bytes")
    encoded = xml_text.encode("utf-8", errors="replace")
    if len(encoded) > MAX_XML_EVENT_BYTES:
        raise XMLLimitError(f"XML event exceeds {MAX_XML_EVENT_BYTES} bytes")
    target = _StreamingEventTarget(deadline)
    parser = _BoundedXMLParser(target)
    bytes_read = 0
    callback_serial = target.callback_serial
    bytes_without_callback = 0
    read_chunk_bytes = min(
        XML_READ_CHUNK_BYTES,
        max(64, MAX_XML_TOKEN_BYTES // 16),
    )
    for offset in range(0, len(encoded), read_chunk_bytes):
        target._check_deadline()
        chunk = encoded[offset : offset + read_chunk_bytes]
        target.feed_start_bytes = bytes_read
        bytes_read += len(chunk)
        if bytes_without_callback + len(chunk) > MAX_XML_TOKEN_BYTES:
            raise XMLLimitError(
                f"XML token exceeds {MAX_XML_TOKEN_BYTES} bytes"
            )
        parser.feed(chunk)
        if target.callback_serial == callback_serial:
            bytes_without_callback += len(chunk)
        else:
            callback_serial = target.callback_serial
            bytes_without_callback = len(chunk)
        target.check_event_bytes(bytes_read)
    root = parser.close()
    return _parse_event_element(
        root,
        source_file,
        raw_xml=xml_text,
        deadline=deadline,
    )


def _parse_event_element(
    root: ET.Element,
    source_file: str,
    raw_xml: str | None = None,
    deadline: float | None = None,
) -> EventRecord:
    if deadline is None:
        deadline = time.monotonic() + XML_PARSE_TIMEOUT_SECONDS
    _check_xml_deadline(deadline)
    text_chars = 0
    for index, part in enumerate(root.itertext()):
        if index % 256 == 0:
            _check_xml_deadline(deadline)
        if part:
            text_chars += len(part)
    if text_chars > MAX_XML_EVENT_TEXT_CHARS:
        raise XMLLimitError(
            f"XML event text exceeds {MAX_XML_EVENT_TEXT_CHARS} characters"
        )
    if raw_xml is None:
        _check_xml_deadline(deadline)
        raw_bytes = ET.tostring(root, encoding="utf-8")
        _check_xml_deadline(deadline)
        if len(raw_bytes) > MAX_XML_EVENT_BYTES:
            raise XMLLimitError(f"XML event exceeds {MAX_XML_EVENT_BYTES} bytes")
        raw_xml = raw_bytes.decode("utf-8", errors="replace")
    raw_xml = _truncate_raw_xml(raw_xml)
    _check_xml_deadline(deadline)
    system = _first_child(root, "System")
    extraction_budget = _ExtractionBudget()
    event_data = _extract_event_data(root, deadline, extraction_budget)
    user_data = _extract_user_data(root, deadline, extraction_budget)

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
        event_id = _child_text(system, "EventID", deadline)
        channel = _child_text(system, "Channel", deadline)
        computer = _child_text(system, "Computer", deadline)
        record_id = _child_text(system, "EventRecordID", deadline)
        level = _child_text(system, "Level", deadline)
        task = _child_text(system, "Task", deadline)
        opcode = _child_text(system, "Opcode", deadline)
        keywords = _child_text(system, "Keywords", deadline)
        time_node = _first_child(system, "TimeCreated")
        if time_node is not None:
            time_created = parse_event_time(time_node.attrib.get("SystemTime"))

    _check_xml_deadline(deadline)
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
        raw_xml=raw_xml,
    )


def _truncate_raw_xml(xml_text: str) -> str:
    if len(xml_text) <= MAX_XML_RAW_CHARS:
        return xml_text
    marker = "\n<!-- CAT: raw XML truncated -->"
    keep = max(0, MAX_XML_RAW_CHARS - len(marker))
    return xml_text[:keep] + marker


def _extract_event_data(
    root: ET.Element,
    deadline: float,
    budget: _ExtractionBudget,
) -> dict[str, str]:
    data: dict[str, str] = {}
    next_indices: dict[str, int] = {}
    event_data = _first_child(root, "EventData")
    if event_data is None:
        return data
    unnamed_count = 0
    for index, node in enumerate(event_data):
        if index % 256 == 0:
            _check_xml_deadline(deadline)
        key = node.attrib.get("Name")
        if not key:
            unnamed_count += 1
            key = f"Data{unnamed_count}"
        _set_unique(
            data,
            key,
            _node_text(node, deadline),
            next_indices,
            budget,
        )
    return data


def _extract_user_data(
    root: ET.Element,
    deadline: float,
    budget: _ExtractionBudget,
) -> dict[str, str]:
    data: dict[str, str] = {}
    next_indices: dict[str, int] = {}
    user_data = _first_child(root, "UserData")
    if user_data is None:
        return data
    for node in list(user_data):
        _flatten(
            node,
            _local_name(node.tag),
            data,
            next_indices,
            deadline,
            budget,
        )
    return data


def _flatten(
    node: ET.Element,
    prefix: str,
    data: dict[str, str],
    next_indices: dict[str, int],
    deadline: float,
    budget: _ExtractionBudget,
) -> None:
    stack = [(node, prefix)]
    while stack:
        _check_xml_deadline(deadline)
        current, current_prefix = stack.pop()
        children = list(current)
        if not children:
            _set_unique(
                data,
                current_prefix,
                _node_text(current, deadline),
                next_indices,
                budget,
            )
            continue
        for child in reversed(children):
            child_prefix = f"{current_prefix}.{_local_name(child.tag)}"
            if len(child_prefix) > MAX_XML_FIELD_KEY_CHARS:
                raise XMLLimitError(
                    "XML flattened field key exceeds "
                    f"{MAX_XML_FIELD_KEY_CHARS} characters"
                )
            stack.append((child, child_prefix))


def _set_unique(
    data: dict[str, str],
    key: str,
    value: str,
    next_indices: dict[str, int],
    budget: _ExtractionBudget,
) -> None:
    clean_value = value.strip()
    if key not in data:
        budget.reserve(key, clean_value)
        data[key] = clean_value
        next_indices.setdefault(key, 2)
        return
    index = next_indices.get(key, 2)
    while f"{key}_{index}" in data:
        index += 1
    unique_key = f"{key}_{index}"
    budget.reserve(unique_key, clean_value)
    data[unique_key] = clean_value
    next_indices[key] = index + 1


def _node_text(node: ET.Element, deadline: float) -> str:
    parts: list[str] = []
    for index, part in enumerate(node.itertext()):
        if index % 256 == 0:
            _check_xml_deadline(deadline)
        if part and part.strip():
            parts.append(part.strip())
    return " ".join(parts)


def _child_text(
    node: ET.Element,
    child_name: str,
    deadline: float,
) -> str | None:
    child = _first_child(node, child_name)
    if child is None:
        return None
    text = _node_text(child, deadline)
    return text or None


def _first_child(node: ET.Element, child_name: str) -> ET.Element | None:
    for child in list(node):
        if _local_name(child.tag) == child_name:
            return child
    return None


def _local_name(tag: str) -> str:
    if "}" in tag:
        tag = tag.rsplit("}", 1)[1]
    return tag.rsplit(":", 1)[-1]


def _in_range(value: datetime | None, start_utc: datetime | None, end_utc: datetime | None) -> bool:
    if value is None:
        return True
    if start_utc and value < start_utc:
        return False
    if end_utc and value > end_utc:
        return False
    return True
