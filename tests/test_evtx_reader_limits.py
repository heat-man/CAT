from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cat_app import evtx_reader


def _event(record_id: int, text: str = "ok") -> str:
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Test"/><EventID>4688</EventID><EventRecordID>{record_id}</EventRecordID>
  </System>
  <EventData><Data Name="CommandLine">{text}</Data></EventData>
</Event>"""


class XMLReaderLimitTests(unittest.TestCase):
    def _write(self, directory: str, content: str) -> Path:
        path = Path(directory) / "events.xml"
        path.write_text(content, encoding="utf-8")
        return path

    def test_xml_parse_timeout_default_override_and_maximum(self) -> None:
        self.assertEqual(evtx_reader.DEFAULT_XML_PARSE_TIMEOUT_SECONDS, 300.0)
        self.assertEqual(evtx_reader.MAX_XML_PARSE_TIMEOUT_SECONDS, 1800.0)
        with mock.patch.dict(
            os.environ,
            {"CAT_XML_PARSE_TIMEOUT_SECONDS": "900"},
        ):
            self.assertEqual(evtx_reader._xml_parse_timeout_seconds(), 900.0)
        with mock.patch.dict(
            os.environ,
            {"CAT_XML_PARSE_TIMEOUT_SECONDS": "9999"},
        ):
            self.assertEqual(evtx_reader._xml_parse_timeout_seconds(), 1800.0)

    def test_xml_stream_does_not_reparse_serialized_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{_event(1)}</Events>")
            with mock.patch.object(
                evtx_reader.ET,
                "fromstring",
                side_effect=AssertionError("XML events must not be reparsed"),
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual([record.record_id for record in result.records], ["1"])
        self.assertEqual(result.errors, [])

    def test_record_limit_stops_before_malformed_tail(self) -> None:
        valid = "".join(_event(index) for index in range(1, 4))
        content = f"<Events>{valid}{' ' * 512}<broken"
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(evtx_reader, "XML_READ_CHUNK_BYTES", 64):
                result = evtx_reader.parse_event_files([path], None, None, 2)

        self.assertEqual(len(result.records), 2)
        self.assertEqual(result.total_seen, 3)
        self.assertEqual(result.total_in_range, 3)
        self.assertTrue(result.truncated)
        self.assertEqual(result.errors, [])

    def test_partial_xml_error_marks_result_truncated(self) -> None:
        content = f"<Events>{_event(1)}{_event(2, 'A' * 2000)}</Events>"
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(evtx_reader, "MAX_XML_EVENT_TEXT_CHARS", 1000):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(len(result.records), 1)
        self.assertTrue(result.truncated)
        self.assertIn("XML event text exceeds 1000 characters", result.errors[0])

    def test_event_text_budget_rejects_oversized_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{_event(1, 'A' * 200)}</Events>")
            with mock.patch.object(evtx_reader, "MAX_XML_EVENT_TEXT_CHARS", 64):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML event text exceeds 64 characters", result.errors[0])

    def test_event_byte_budget_rejects_oversized_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{_event(1, 'A' * 500)}</Events>")
            with mock.patch.object(evtx_reader, "MAX_XML_EVENT_BYTES", 256):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML event exceeds 256 bytes", result.errors[0])

    def test_raw_xml_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{_event(1, 'A' * 200)}</Events>")
            with mock.patch.object(evtx_reader, "MAX_XML_RAW_CHARS", 96):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(len(result.records[0].raw_xml), 96)
        self.assertTrue(result.records[0].raw_xml.endswith("<!-- CAT: raw XML truncated -->"))

    def test_file_size_budget_is_checked_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{_event(1)}</Events>")
            with mock.patch.object(evtx_reader, "MAX_XML_FILE_BYTES", 32):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML file exceeds 32 bytes", result.errors[0])

    def test_irrelevant_element_budget_rejects_wrapper_node_flood(self) -> None:
        content = "<Events>" + ("<Ignored/>" * 20) + "</Events>"
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(evtx_reader, "MAX_XML_ELEMENTS_PER_FILE", 10):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML file element count exceeds 10", result.errors[0])

    def test_giant_wrapper_attribute_is_stopped_before_expat_buffers_file(self) -> None:
        content = f'<Events Padding="{"A" * 4096}"></Events>'
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with (
                mock.patch.object(evtx_reader, "XML_READ_CHUNK_BYTES", 64),
                mock.patch.object(evtx_reader, "MAX_XML_TOKEN_BYTES", 256),
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML token exceeds 256 bytes", result.errors[0])

    def test_token_cap_counts_callback_chunks_and_small_config(self) -> None:
        content = (
            '<Events><Ignored/><Other Padding="'
            + ("A" * (64 * 1024))
            + '"/></Events>'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(evtx_reader, "MAX_XML_TOKEN_BYTES", 1024):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML token exceeds 1024 bytes", result.errors[0])

    def test_expanded_namespace_names_have_individual_and_total_budgets(self) -> None:
        namespace = "urn:" + ("u" * 256)
        content = (
            "<Events><Event><Ignored xmlns=\""
            + namespace
            + "\"><A/><B/></Ignored></Event></Events>"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(evtx_reader, "MAX_XML_NAME_CHARS", 128):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertTrue(result.truncated)
        self.assertIn("XML namespace URI exceeds 256 characters", result.errors[0])

        small_namespace = "urn:" + ("u" * 32)
        repeated = "".join(f"<N{index}/>" for index in range(20))
        content = (
            f'<Events><Event><Ignored xmlns="{small_namespace}">'
            f"{repeated}</Ignored></Event></Events>"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(
                evtx_reader,
                "MAX_XML_EXPANDED_CHARS_PER_EVENT",
                64,
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("characters per event", result.errors[0])

    def test_many_prefixed_attributes_are_rejected_without_namespace_expansion(self) -> None:
        attributes = " ".join(f'p:a{index}=""' for index in range(300))
        content = (
            '<Events><Event xmlns:p="urn:short" '
            + attributes
            + "/></Events>"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertTrue(result.truncated)
        self.assertIn("attribute count exceeds 256", result.errors[0])

    def test_inherited_namespace_is_preserved_on_detached_raw_event(self) -> None:
        content = (
            '<Root xmlns:e="urn:event"><e:Event><e:System>'
            "<e:EventID>1</e:EventID><e:EventRecordID>7</e:EventRecordID>"
            "</e:System></e:Event></Root>"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.errors, [])
        self.assertEqual(result.records[0].event_id, "1")
        self.assertEqual(result.records[0].record_id, "7")
        reparsed = evtx_reader.ET.fromstring(result.records[0].raw_xml)
        self.assertEqual(evtx_reader._local_name(reparsed.tag), "Event")

    def test_dtd_is_rejected(self) -> None:
        content = '<!DOCTYPE Events [<!ENTITY x "expanded">]><Events>&x;</Events>'
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML DTD is not allowed", result.errors[0])

    def test_duplicate_event_data_keys_are_numbered_linearly(self) -> None:
        repeated = "".join('<Data Name="X">value</Data>' for _ in range(1000))
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                f"<Events>{_event(1).replace('</EventData>', repeated + '</EventData>')}</Events>",
            )
            result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.errors, [])
        self.assertEqual(result.records[0].event_data["X_1000"], "value")

    def test_deadline_is_checked_during_event_extraction(self) -> None:
        root = evtx_reader.ET.fromstring(_event(1))
        with (
            mock.patch.object(evtx_reader, "XML_PARSE_TIMEOUT_SECONDS", 1.0),
            mock.patch.object(evtx_reader.time, "monotonic", return_value=2.0),
            self.assertRaisesRegex(TimeoutError, "XML parsing exceeded 1 seconds"),
        ):
            evtx_reader._parse_event_element(root, "events.xml", deadline=1.0)

    def test_evtx_records_share_the_absolute_parse_deadline(self) -> None:
        clock = [0.0]

        class FakeRecord:
            def __init__(self, record_id: int) -> None:
                self.record_id = record_id

            def xml(self) -> str:
                clock[0] += 0.03
                return _event(self.record_id)

        class FakeEvtx:
            def __init__(self, _path: str) -> None:
                pass

            def __enter__(self) -> "FakeEvtx":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def records(self) -> list[FakeRecord]:
                return [FakeRecord(index) for index in range(1, 6)]

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(evtx_reader, "Evtx", FakeEvtx),
            mock.patch.object(evtx_reader, "XML_PARSE_TIMEOUT_SECONDS", 0.05),
            mock.patch.object(evtx_reader.time, "monotonic", side_effect=lambda: clock[0]),
            self.assertLogs(evtx_reader.LOGGER, level="WARNING"),
        ):
            path = Path(directory) / "events.evtx"
            path.write_bytes(b"evtx")
            result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.total_seen, 1)
        self.assertTrue(result.truncated)
        self.assertIn("XML parsing exceeded 0.05 seconds", result.errors[0])
        self.assertIn("file_size_bytes=4", result.errors[0])
        self.assertIn("parsed_events=1", result.errors[0])
        self.assertIn("in_range_events=1", result.errors[0])
        self.assertIn("retained_events=1", result.errors[0])
        self.assertIn("elapsed_seconds=0.060", result.errors[0])

    def test_deep_user_data_is_flattened_without_python_recursion(self) -> None:
        nested = "value"
        for index in range(300):
            nested = f"<N{index}>{nested}</N{index}>"
        content = _event(1).replace(
            "</Event>",
            f"<UserData>{nested}</UserData></Event>",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{content}</Events>")
            with (
                mock.patch.object(evtx_reader, "MAX_XML_DEPTH", 512),
                mock.patch.object(evtx_reader, "MAX_XML_FIELD_KEY_CHARS", 8192),
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.errors, [])
        self.assertIn("value", result.records[0].user_data.values())

    def test_flattened_user_data_key_and_output_are_bounded(self) -> None:
        nested = "value"
        for index in range(20):
            nested = f"<Node{index}>{nested}</Node{index}>"
        content = _event(1).replace(
            "</Event>",
            f"<UserData>{nested}</UserData></Event>",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{content}</Events>")
            with mock.patch.object(evtx_reader, "MAX_XML_FIELD_KEY_CHARS", 64):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertTrue(result.truncated)
        self.assertIn("flattened field key exceeds 64", result.errors[0])

        leaves = "".join(f"<N{index}>{'A' * 50}</N{index}>" for index in range(20))
        content = _event(1).replace(
            "</Event>",
            f"<UserData><Root>{leaves}</Root></UserData></Event>",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{content}</Events>")
            with mock.patch.object(
                evtx_reader,
                "MAX_XML_EXTRACTED_CHARS_PER_EVENT",
                512,
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("extracted fields exceed 512", result.errors[0])

    def test_retained_character_budget_is_shared_across_events(self) -> None:
        content = f"<Events>{_event(1, 'A' * 100)}{_event(2, 'A' * 100)}</Events>"
        with tempfile.TemporaryDirectory() as directory:
            single_path = Path(directory) / "single.xml"
            single_path.write_text(f"<Events>{_event(1, 'A' * 100)}</Events>", encoding="utf-8")
            first = evtx_reader.parse_event_files([single_path], None, None, 10).records[0]
            budget = evtx_reader._RetentionBudget()
            budget.reserve(first)
            exact_first_cost = budget.chars
            path = self._write(directory, content)
            with mock.patch.object(
                evtx_reader,
                "MAX_XML_RETAINED_CHARS_PER_ANALYSIS",
                exact_first_cost,
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual([record.record_id for record in result.records], ["1"])
        self.assertTrue(result.truncated)
        self.assertIn("retained records exceed", result.errors[0])

    def test_retained_field_budget_is_shared_across_events(self) -> None:
        content = f"<Events>{_event(1)}{_event(2)}</Events>"
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, content)
            with mock.patch.object(
                evtx_reader,
                "MAX_XML_RETAINED_FIELDS_PER_ANALYSIS",
                1,
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual([record.record_id for record in result.records], ["1"])
        self.assertTrue(result.truncated)
        self.assertIn("retained field count exceeds", result.errors[0])

    def test_xml_deadline_is_absolute_across_parse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, f"<Events>{_event(1)}</Events>")
            file_size = path.stat().st_size
            with (
                mock.patch.object(evtx_reader, "XML_PARSE_TIMEOUT_SECONDS", 1.0),
                mock.patch.object(evtx_reader.time, "monotonic", side_effect=[0.0, 2.0]),
                self.assertLogs(evtx_reader.LOGGER, level="WARNING") as captured,
            ):
                result = evtx_reader.parse_event_files([path], None, None, 10)

        self.assertEqual(result.records, [])
        self.assertIn("XML parsing exceeded 1 seconds", result.errors[0])
        self.assertIn(f"file_size_bytes={file_size}", result.errors[0])
        self.assertIn("parsed_events=0", result.errors[0])
        self.assertIn("in_range_events=0", result.errors[0])
        self.assertIn("retained_events=0", result.errors[0])
        self.assertIn("elapsed_seconds=2.000", result.errors[0])
        self.assertIn("XML parsing timeout file=events.xml", captured.output[0])


if __name__ == "__main__":
    unittest.main()
