from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class _HistoryUiParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: dict[str, dict[str, str | None]] = {}
        self.id_counts: dict[str, int] = {}
        self.auto_expand: dict[str, str | None] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.elements[str(values["id"])] = values
            self.id_counts[str(values["id"])] = self.id_counts.get(str(values["id"]), 0) + 1
        if tag == "input" and values.get("name") == "auto_expand_time_range":
            self.auto_expand = values


class AnalysisHistoryUiTests(unittest.TestCase):
    def test_history_dialog_and_controls_are_accessible(self) -> None:
        source = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        parser = _HistoryUiParser()
        parser.feed(source)

        self.assertEqual(parser.elements["historyButton"].get("type"), "button")
        self.assertEqual(parser.elements["historyButton"].get("aria-haspopup"), "dialog")
        self.assertEqual(parser.elements["historyButton"].get("aria-controls"), "historyDialog")
        self.assertEqual(parser.elements["historyDialog"].get("aria-labelledby"), "historyTitle")
        self.assertEqual(parser.elements["historyDialog"].get("aria-describedby"), "historyDescription")
        self.assertIn("historyDescription", parser.elements)
        self.assertEqual(parser.elements["closeHistoryButton"].get("type"), "button")
        self.assertEqual(parser.elements["clearHistoryButton"].get("type"), "button")
        self.assertEqual(parser.elements["historyList"].get("role"), "list")
        self.assertIn("업로드한 원본 파일과 API 키는 저장하지 않습니다", source)
        self.assertTrue(all(count == 1 for count in parser.id_counts.values()))

    def test_auto_time_expansion_is_checked_and_submitted_with_form(self) -> None:
        source = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        parser = _HistoryUiParser()
        parser.feed(source)

        self.assertIsNotNone(parser.auto_expand)
        assert parser.auto_expand is not None
        self.assertEqual(parser.auto_expand.get("type"), "checkbox")
        self.assertEqual(parser.auto_expand.get("value"), "true")
        self.assertEqual(parser.auto_expand.get("id"), "autoExpandTimeRange")
        self.assertEqual(parser.auto_expand.get("aria-describedby"), "autoExpandTimeRangeHelp")
        self.assertIn("autoExpandTimeRangeHelp", parser.elements)
        self.assertIn("checked", parser.auto_expand)
        self.assertIn("업로드한 파일 안에서 분석 시간대를 자동 확장", source)
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn('formData.delete("auto_expand_time_range")', app)
        self.assertIn('formData.set(\n    "auto_expand_time_range"', app)
        self.assertIn('autoExpandTimeRange?.checked === true ? "true" : "false"', app)
        self.assertIn("data.adaptive_time_range?.default_enabled", app)
        self.assertIn("function renderAdaptiveTimeRange(adaptiveRange)", app)
        self.assertIn("실제 적용 범위", app)
        self.assertIn("확장 근거", app)

    def test_history_is_bounded_and_sanitized_before_local_storage(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn('const ANALYSIS_HISTORY_KEY = "cat.analysis_history.v1"', app)
        self.assertRegex(app, r"ANALYSIS_HISTORY_MAX_ENTRIES\s*=\s*10")
        self.assertIn("ANALYSIS_HISTORY_MAX_TOTAL_CHARS", app)
        self.assertIn("ANALYSIS_HISTORY_MAX_ENTRY_CHARS", app)
        self.assertIn("HISTORY_FORBIDDEN_KEYS", app)
        self.assertIn("private_?key|authorization|token|access_?token", app)
        self.assertIn("auth_?token|bearer_?token|id_?token|session_?token", app)
        self.assertIn("function historySafeClone(", app)
        self.assertIn("if (HISTORY_FORBIDDEN_KEYS.test(normalizedKey)) continue", app)
        self.assertIn("function historyLmMetadata(", app)
        self.assertNotIn('"api_key",', app.split("const allowedKeys = [", 1)[1].split("];", 1)[0])
        self.assertIn("saveAnalysisHistory(lastReport, lastAnalysis, data.llm)", app)
        self.assertIn("while (bounded.length &&", app)
        self.assertIn("JSON.stringify(entry).length <= ANALYSIS_HISTORY_MAX_ENTRY_CHARS", app)
        self.assertIn("entries.slice(0, limits.objectLimit)", app)
        self.assertIn("window.localStorage.setItem(ANALYSIS_HISTORY_KEY", app)
        self.assertIn("intrusion_chain: source.intrusion_chain", app)
        self.assertIn('"hierarchical_analysis_used"', app)
        self.assertIn('"hierarchical_chunks_completed"', app)
        self.assertIn('"hierarchical_evidence_omitted"', app)
        self.assertIn('"hierarchical_validation_warnings"', app)
        self.assertIn('"input_hierarchical_context"', app)
        self.assertIn("function minimalHistoryAnalysis(analysis)", app)
        self.assertIn("analysis: minimalHistoryAnalysis(analysis)", app)
        self.assertIn("origin_process: origin", app)
        self.assertIn("steps: asList(chain.steps).slice(0, 8)", app)

    def test_history_list_exposes_chain_origin_and_chunk_completion(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("origin_process: displayValue(originProcess.process)", app)
        self.assertIn("최초 침해 프로세스 후보:", app)
        self.assertIn("storedLlm.hierarchical_analysis_used === true", app)
        self.assertIn("분할 분석 ${Number(storedLlm.hierarchical_chunks_completed", app)
        self.assertIn('class="history-item" role="listitem"', app)

    def test_history_can_restore_delete_and_clear_with_confirmation(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function restoreAnalysisHistoryEntry(entry)", app)
        self.assertIn("renderReport(lastReport, entry.llm || {}, lastAnalysis)", app)
        self.assertIn("renderFindings(lastAnalysis)", app)
        self.assertIn("renderSummary(lastAnalysis)", app)
        self.assertIn("저장된 분석 이력을 복원하지 못했습니다", app)
        self.assertIn("저장된 탐지 결과 렌더링 경고", app)
        self.assertIn('button.dataset.historyAction === "delete"', app)
        self.assertGreaterEqual(app.count("window.confirm("), 2)
        self.assertIn("window.localStorage.removeItem(ANALYSIS_HISTORY_KEY)", app)

    def test_history_styles_are_responsive_and_excluded_from_print(self) -> None:
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn(".history-dialog::backdrop", styles)
        self.assertIn(".history-list", styles)
        self.assertIn(".history-item-actions", styles)
        print_styles = styles.split("@media print", 1)[1]
        self.assertRegex(
            print_styles,
            re.compile(r"\.history-dialog,\s*#findingsView", re.MULTILINE),
        )


if __name__ == "__main__":
    unittest.main()
