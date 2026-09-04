from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class _PdfButtonParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.attributes: dict[str, str | None] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        if tag == "button" and values.get("id") == "savePdfButton":
            self.attributes = values


class PdfExportUiTests(unittest.TestCase):
    def test_pdf_button_is_safe_and_disabled_until_a_report_exists(self) -> None:
        parser = _PdfButtonParser()
        parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))

        self.assertIsNotNone(parser.attributes)
        assert parser.attributes is not None
        self.assertEqual(parser.attributes.get("type"), "button")
        self.assertIn("disabled", parser.attributes)

    def test_pdf_export_uses_current_page_printing_and_restores_title(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function saveReportAsPdf()", app)
        self.assertIn('savePdfButton?.addEventListener("click", saveReportAsPdf)', app)
        self.assertIn('!String(lastReport || "").trim()', app)
        self.assertIn("window.print()", app)
        self.assertIn('window.addEventListener("afterprint", restoreTitle)', app)
        self.assertIn("document.title = originalTitle", app)
        self.assertIn("CAT-report-${date}-${time}", app)
        self.assertNotIn("document.write", app)
        self.assertNotIn("window.open", app)

    def test_pdf_includes_local_network_appendix_without_mutating_report_text(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("function renderPrintNetworkAppendix(analysis)", app)
        self.assertIn("NETWORK_FINDING_RULE_IDS", app)
        self.assertIn("renderPrintNetworkAppendix(analysis)", app)
        self.assertIn("process_fanout_candidates", app)
        self.assertIn("function renderProcessFanoutCandidate(candidate)", app)
        self.assertIn("CAT 로컬 C2/네트워크 탐지 근거", app)
        self.assertIn("hasNetworkActivity", app)
        self.assertIn("분석 범위와 한계", app)
        self.assertRegex(styles, r"\.print-only\s*\{\s*display:\s*none;")
        print_styles = styles.split("@media print", 1)[1]
        self.assertRegex(
            print_styles,
            r"#reportView \.print-only\s*\{\s*display:\s*block\s*!important;",
        )
        self.assertNotIn("lastReport +=", app)

    def test_pdf_includes_summary_intrusion_activity_and_evidence_limits(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("function renderPrintAnalysisAppendix(analysis, llm)", app)
        self.assertIn("renderPrintAnalysisAppendix(analysis, llm)", app)
        self.assertIn("CAT 분석 데이터 부록", app)
        self.assertIn("CAT 요약 내용", app)
        self.assertIn("침해행위 및 탐지 결과", app)
        self.assertIn("function renderIntrusionChain(chain)", app)
        self.assertIn("최초 침해 프로세스와 후속 흐름", app)
        self.assertIn("renderIntrusionChain(safeAnalysis.intrusion_chain)", app)
        self.assertIn("증거 및 분석 한계", app)
        self.assertIn("renderSummaryContents(safeAnalysis, false)", app)
        self.assertIn("collectPrintEvidenceLimitations", app)
        self.assertIn("intrusionChain.limitations", app)
        self.assertIn("llm?.hierarchical_validation_warnings", app)
        self.assertIn("llm?.hierarchical_chunks_failed", app)
        self.assertIn("llm?.hierarchical_evidence_omitted", app)
        self.assertIn("llm?.hierarchical_repetition_omitted", app)
        self.assertIn("llm?.hierarchical_source_limit_reached", app)
        self.assertIn("최초 침해 프로세스와 후속 흐름은 분석 상한", app)
        print_styles = styles.split("@media print", 1)[1]
        self.assertIn("#reportView .print-analysis-appendix", print_styles)

    def test_ui_displays_hierarchical_chunk_status_and_warning_count(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("function renderHierarchicalLmStatus(llm)", app)
        self.assertIn("renderHierarchicalLmStatus(llm)", app)
        self.assertIn("계층형 분할 분석:", app)
        self.assertIn("hierarchical_chunks_completed", app)
        self.assertIn("hierarchical_chunks_failed", app)
        self.assertIn("hierarchical_skip_reason", app)
        self.assertIn("관련 경고 ${warningCount}건", app)
        self.assertIn("반복 근거 축약 ${repetitionsOmitted}건", app)
        self.assertIn(".lm-hierarchical-status", styles)
        self.assertIn(".lm-hierarchical-status.has-warning", styles)

    def test_ui_supports_fourth_level_markdown_headings_and_fanout_counts(self) -> None:
        app = (ROOT / "static" / "app.js").read_text(encoding="utf-8")

        fourth = app.index('line.startsWith("#### ")')
        third = app.index('line.startsWith("### ")')
        self.assertLess(fourth, third)
        self.assertIn("<h4>${inlineMarkdown(line.slice(5))}</h4>", app)
        self.assertIn("C2 통신 후보 합계", app)
        self.assertIn("프로세스 fan-out 후보", app)
        self.assertIn("candidate_destinations", app)
        self.assertIn("candidate_ports", app)
        self.assertIn("input_source_network_groups", app)
        self.assertIn("function boundedCountLabel", app)
        self.assertIn("이상 (하한)", app)
        self.assertIn("network_spool_limit_reached", app)
        self.assertIn("network_records_spooled", app)

    def test_print_styles_include_only_the_report_view(self) -> None:
        styles = (ROOT / "static" / "styles.css").read_text(encoding="utf-8")
        print_styles = styles.split("@media print", 1)[1]

        self.assertIn("@page", styles)
        self.assertIn("size: A4", styles)
        self.assertIn("@media print", styles)
        self.assertRegex(
            print_styles,
            re.compile(
                r"\.app-header,\s*\.input-panel,\s*\.tabs,\s*\.loading,\s*"
                r"\.error-box,\s*\.history-dialog,\s*#findingsView,\s*#summaryView\s*\{\s*"
                r"display:\s*none\s*!important;",
                re.MULTILINE,
            ),
        )
        self.assertIn("#reportView details:not([open]) > table", print_styles)
        self.assertIn("display: table !important", print_styles)
        self.assertRegex(
            print_styles,
            re.compile(
                r"#reportView\s*\{[^}]*display:\s*block\s*!important;"
                r"[^}]*height:\s*auto;[^}]*overflow:\s*visible;",
                re.MULTILINE,
            ),
        )

    def test_readme_documents_browser_pdf_flow_and_evidence_sensitivity(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("### 7. 보고서를 PDF로 저장", readme)
        self.assertIn("CAT-report-YYYYMMDD-HHMMSS.pdf", readme)
        self.assertIn("민감한 조사 증거", readme)


if __name__ == "__main__":
    unittest.main()
