from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXED_FIELDS = ("agent_backend", "lm_url", "lm_model", "use_llm")


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.fields: dict[str, str] = {}
        self.field_attributes: dict[str, dict[str, str | None]] = {}
        self.elements: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.elements.add(str(values["id"]))
        if tag in {"input", "select", "textarea"} and values.get("name"):
            self.fields[str(values["name"])] = values.get("value") or ""
            self.field_attributes[str(values["name"])] = values


class FixedConfigurationUiTests(unittest.TestCase):
    def test_configuration_controls_are_removed_not_merely_hidden(self) -> None:
        parser = _FormParser()
        parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        self.assertTrue({"files", "start_time", "end_time", "timezone"} <= parser.fields.keys())
        for field in (*FIXED_FIELDS, "auto_expand_time_range"):
            self.assertNotIn(field, parser.fields)
        for element in ("agentBackend", "lmUrl", "lmModel", "autoExpandTimeRange"):
            self.assertNotIn(element, parser.elements)

    def test_time_range_is_visibly_required_and_enforced_by_html(self) -> None:
        source = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
        parser = _FormParser()
        parser.feed(source)
        for name in ("start_time", "end_time"):
            with self.subTest(field=name):
                self.assertEqual(parser.field_attributes[name]["type"], "datetime-local")
                self.assertIn("required", parser.field_attributes[name])
        range_section = re.search(
            r'<fieldset\b[^>]*class="[^"]*\btime-range-fields\b[^"]*"[^>]*>(.*?)</fieldset>',
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(range_section)
        assert range_section is not None
        self.assertIn("필수", range_section[1])
        self.assertNotIn("비워두면", range_section[1])
        self.assertNotIn("선택 사항", range_section[1])

    def _submit_form(
        self,
        *,
        health: str = "pending",
        form_overrides: dict[str, str] | None = None,
        file_size: int = 64,
        health_limit: int = 1024,
    ) -> dict:
        if not shutil.which("node"):
            self.skipTest("Node.js is required for form behavior tests")
        parser = _FormParser()
        parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
        fields = {
            **parser.fields,
            "start_time": "2026-09-10T09:00",
            "end_time": "2026-09-10T10:00",
            **(form_overrides or {}),
        }
        program = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const options = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = fs.readFileSync('static/app.js', 'utf8');
const storage = new Map([
  ['cat.lm_url', 'http://stale.invalid:1234/v1'],
  ['cat.lm_model', 'obsolete-model'],
  ['cat.agent_backend', 'codex_dev'],
  ['cat.auto_expand_time_range', 'false'],
]);
const storageReads = [];
const nodes = {};
const coreIds = [
  'analysisForm', 'evtxFiles', 'fileDrop', 'fileSummary', 'analyzeButton',
  'loading', 'errorBox', 'reportView', 'findingsView', 'summaryView',
  'healthStatus', 'progressFill', 'progressCat', 'loadingText',
];
for (const id of coreIds) {
  nodes[id] = {
    listeners: {}, textContent: '', innerHTML: '', dataset: {}, style: {},
    classList: {add() {}, remove() {}, toggle() {}},
    addEventListener(name, callback) { this.listeners[name] = callback; },
  };
}
nodes.analysisForm.fields = options.fields;
nodes.evtxFiles.files = [{name: 'sample.evtx', size: options.fileSize}];
class FormDataStub {
  constructor(form) { this.items = Object.entries(form.fields); }
  get(key) { return this.items.find(([name]) => name === key)?.[1] ?? null; }
  delete(key) { this.items = this.items.filter(([name]) => name !== key); }
  set(key, value) { this.delete(key); this.items.push([key, value]); }
  append(key, value) { this.items.push([key, value]); }
}
const requests = [];
const sandbox = {
  document: {
    querySelector: selector => selector.startsWith('#') ? nodes[selector.slice(1)] || null : null,
    querySelectorAll: () => [],
  },
  window: {
    localStorage: {
      getItem: key => { storageReads.push(key); return storage.get(key) || null; },
      setItem: (key, value) => storage.set(key, value),
      removeItem: key => storage.delete(key),
    },
  },
  FormData: FormDataStub,
  setInterval: () => 1, clearInterval() {}, setTimeout: () => 1,
  fetch: async (url, init) => {
    if (url === '/api/health') {
      if (options.health === 'pending') return new Promise(() => {});
      if (options.health === 'failed') throw Error('Health endpoint unavailable');
      return {json: async () => ({
        ok: true, max_upload_bytes: options.healthLimit,
        default_agent_backend: 'lmstudio', lm_studio_url: 'http://configured.invalid:1234',
        default_model: 'configured-model', allow_custom_lm_url: true,
        adaptive_time_range: {default_enabled: false},
      })};
    }
    if (url !== '/api/analyze') throw Error(`Unexpected request: ${url}`);
    requests.push({url, method: init.method, fields: init.body.items});
    return {ok: true, status: 200, text: async () => JSON.stringify({
      ok: true, report_markdown: '# Test report', analysis: {}, llm: {backend: 'rule'},
    })};
  },
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
(async () => {
  // Let health finish when available, without ever awaiting a stalled health request.
  await new Promise(resolve => setImmediate(resolve));
  await nodes.analysisForm.listeners.submit({preventDefault() {}});
  process.stdout.write(JSON.stringify({
    requests, storageReads, error: nodes.errorBox.textContent,
    report: nodes.reportView.innerHTML, busy: nodes.analyzeButton.disabled,
    health: nodes.healthStatus.textContent,
  }));
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        result = subprocess.run(
            ["node", "-e", program],
            input=json.dumps({
                "fields": fields,
                "health": health,
                "fileSize": file_size,
                "healthLimit": health_limit,
            }),
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=10,
            check=True,
        )
        return json.loads(result.stdout)

    def _assert_fixed_submission(self, result: dict) -> None:
        self.assertEqual(result["error"], "")
        self.assertFalse(result["busy"])
        self.assertIn("Test report", result["report"])
        self.assertEqual(len(result["requests"]), 1)
        request = result["requests"][0]
        self.assertEqual(request["url"], "/api/analyze")
        self.assertEqual(request["method"], "POST")
        fields = dict(request["fields"])
        self.assertEqual(fields["auto_expand_time_range"], "true")
        self.assertEqual(fields["files"]["name"], "sample.evtx")
        self.assertEqual(fields["start_time"], "2026-09-10T09:00")
        self.assertEqual(fields["end_time"], "2026-09-10T10:00")
        for field in FIXED_FIELDS:
            self.assertNotIn(field, fields)
        self.assertFalse(set(result["storageReads"]) & {
            "cat.lm_url", "cat.lm_model", "cat.agent_backend", "cat.auto_expand_time_range",
        })

    def test_submit_works_before_health_arrives_without_configuration_controls(self) -> None:
        self._assert_fixed_submission(self._submit_form(health="pending"))

    def test_submit_works_when_health_fails_and_ignores_stale_lm_preferences(self) -> None:
        result = self._submit_form(health="failed")
        self._assert_fixed_submission(result)
        self.assertEqual(result["health"], "서버 연결 실패")

    def test_health_configuration_cannot_disable_automatic_expansion(self) -> None:
        result = self._submit_form(health="ready")
        self._assert_fixed_submission(result)
        self.assertEqual(result["health"], "서버 연결됨")

    def test_stale_form_fields_cannot_override_fixed_server_configuration(self) -> None:
        result = self._submit_form(form_overrides={
            "agent_backend": "rule",
            "lm_url": "http://stale.invalid:1234",
            "lm_model": "obsolete-model",
            "use_llm": "false",
            "auto_expand_time_range": "false",
        })
        self._assert_fixed_submission(result)

    def test_time_range_validation_is_preserved(self) -> None:
        for missing_field in ("start_time", "end_time"):
            with self.subTest(field=missing_field):
                result = self._submit_form(form_overrides={missing_field: ""})
                self.assertEqual(result["requests"], [])
                self.assertIn("시작 시간과 종료 시간", result["error"])

    def test_upload_limit_from_health_is_still_enforced(self) -> None:
        result = self._submit_form(health="ready", file_size=2048, health_limit=1024)
        self.assertEqual(result["requests"], [])
        self.assertIn("업로드 제한을 초과", result["error"])


if __name__ == "__main__":
    unittest.main()
