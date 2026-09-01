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
                r"\.error-box,\s*#findingsView,\s*#summaryView\s*\{\s*"
                r"display:\s*none\s*!important;",
                re.MULTILINE,
            ),
        )
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
