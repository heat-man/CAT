from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AnalysisProgressUiTests(unittest.TestCase):
    def _run_progress(self, *, health: str = "pending", outcome: str = "success", repeat: bool = False) -> dict:
        if not shutil.which("node"):
            self.skipTest("Node.js is required for progress behavior tests")
        program = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const options = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = fs.readFileSync('static/app.js', 'utf8');
let now = 100000;
let timerId = 0;
const intervals = new Map();
const timeouts = new Map();
const requests = [];
const storage = new Map();
const nodes = {};
for (const id of [
  'analysisForm', 'evtxFiles', 'fileDrop', 'fileSummary', 'analyzeButton',
  'loading', 'errorBox', 'reportView', 'findingsView', 'summaryView',
  'healthStatus', 'progressFill', 'progressCat', 'loadingText',
]) {
  nodes[id] = {
    listeners: {}, textContent: '', innerHTML: '', dataset: {}, style: {},
    classList: {add() {}, remove() {}, toggle() {}},
    addEventListener(name, callback) { this.listeners[name] = callback; },
  };
}
nodes.analysisForm.fields = {
  start_time: '2026-09-10T09:00', end_time: '2026-09-10T10:00', timezone: 'UTC',
};
nodes.evtxFiles.files = [{name: 'sample.evtx', size: 64}];
class FormDataStub {
  constructor(form) { this.items = Object.entries(form.fields); }
  get(key) { return this.items.find(([name]) => name === key)?.[1] ?? null; }
  delete(key) { this.items = this.items.filter(([name]) => name !== key); }
  set(key, value) { this.delete(key); this.items.push([key, value]); }
  append(key, value) { this.items.push([key, value]); }
}
class FakeDate extends Date {
  static now() { return now; }
}
const sandbox = {
  Date: FakeDate,
  document: {
    querySelector: selector => selector.startsWith('#') ? nodes[selector.slice(1)] || null : null,
    querySelectorAll: () => [],
  },
  window: {localStorage: {
    getItem: key => storage.get(key) || null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
  }},
  FormData: FormDataStub,
  setInterval(callback) { const id = ++timerId; intervals.set(id, callback); return id; },
  clearInterval(id) { intervals.delete(id); },
  setTimeout(callback) { const id = ++timerId; timeouts.set(id, callback); return id; },
  fetch: async (url, init) => {
    if (url === '/api/health') {
      if (options.health === 'failed') throw Error('Health endpoint unavailable');
      return new Promise(() => {});
    }
    if (url !== '/api/analyze') throw Error(`Unexpected request: ${url}`);
    return new Promise((resolve, reject) => requests.push({resolve, reject, fields: init.body.items}));
  },
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
function snapshot() {
  return {
    text: nodes.loadingText.textContent, width: nodes.progressFill.style.width,
    busy: nodes.analyzeButton.disabled, intervals: intervals.size,
    error: nodes.errorBox.textContent, report: nodes.reportView.innerHTML,
  };
}
function tick(seconds) {
  now += seconds * 1000;
  for (const callback of [...intervals.values()]) callback();
  return snapshot();
}
function flushTimeouts() {
  const callbacks = [...timeouts.values()];
  timeouts.clear();
  for (const callback of callbacks) callback();
}
function finish(request, outcome) {
  if (outcome === 'network_error') { request.reject(Error('Connection lost')); return; }
  const ok = outcome === 'success';
  request.resolve({
    ok, status: ok ? 200 : 500,
    text: async () => JSON.stringify(ok ? {
      ok: true, report_markdown: '# Completed report', analysis: {}, llm: {backend: 'rule'},
    } : {ok: false, error: 'Analysis failed'}),
  });
}
(async () => {
  await new Promise(resolve => setImmediate(resolve));
  const submission = nodes.analysisForm.listeners.submit({preventDefault() {}});
  const initial = snapshot();
  const waiting = [tick(20), tick(1), tick(39), tick(840)];
  finish(requests[0], options.outcome);
  await submission;
  const completed = snapshot();
  let restarted = null;
  let afterOldTimeout = null;
  let secondWaiting = null;
  if (options.repeat) {
    const secondSubmission = nodes.analysisForm.listeners.submit({preventDefault() {}});
    restarted = snapshot();
    flushTimeouts();
    afterOldTimeout = snapshot();
    secondWaiting = tick(21);
    finish(requests[1], 'success');
    await secondSubmission;
  }
  flushTimeouts();
  process.stdout.write(JSON.stringify({
    initial, waiting, completed, restarted, afterOldTimeout, secondWaiting,
    settled: snapshot(), requestCount: requests.length,
  }));
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
        result = subprocess.run(
            ["node", "-e", program],
            input=json.dumps({"health": health, "outcome": outcome, "repeat": repeat}),
            text=True,
            capture_output=True,
            cwd=ROOT,
            timeout=10,
            check=True,
        )
        return json.loads(result.stdout)

    def test_pending_request_updates_after_twenty_seconds_without_removed_controls_or_health(self) -> None:
        result = self._run_progress()
        self.assertIn("(0초)", result["initial"]["text"])
        for elapsed, state in zip((20, 21, 60, 900), result["waiting"]):
            with self.subTest(elapsed=elapsed):
                self.assertIn(f"({elapsed}초)", state["text"])
                self.assertTrue(state["busy"])
                self.assertEqual(state["intervals"], 1)
                self.assertNotIn("파싱", state["text"])
                self.assertNotIn("보고서 생성 중", state["text"])
        self.assertIn("서버 응답을 기다리는 중", result["waiting"][1]["text"])
        self.assertIn("시간이 걸릴 수 있습니다", result["waiting"][2]["text"])
        widths = [float(state["width"].rstrip("%")) for state in result["waiting"]]
        self.assertEqual(widths, sorted(widths))
        self.assertTrue(all(0 < width < 100 for width in widths))

    def test_progress_does_not_depend_on_health_request_success(self) -> None:
        result = self._run_progress(health="failed")
        self.assertIn("(900초)", result["waiting"][-1]["text"])
        self.assertIn("Completed report", result["completed"]["report"])

    def test_success_clears_interval_and_resets_indicator(self) -> None:
        result = self._run_progress()
        self.assertFalse(result["completed"]["busy"])
        self.assertEqual(result["completed"]["intervals"], 0)
        self.assertIn("Completed report", result["completed"]["report"])
        self.assertEqual(result["settled"]["text"], "분석 준비 중")
        self.assertEqual(result["settled"]["width"], "0%")

    def test_server_and_network_errors_clear_interval(self) -> None:
        for outcome, message in (("server_error", "Analysis failed"), ("network_error", "Connection lost")):
            with self.subTest(outcome=outcome):
                result = self._run_progress(outcome=outcome)
                self.assertFalse(result["completed"]["busy"])
                self.assertEqual(result["completed"]["intervals"], 0)
                self.assertEqual(result["completed"]["error"], message)
                self.assertEqual(result["settled"]["text"], "분석 준비 중")

    def test_next_request_resets_elapsed_time_and_ignores_old_cleanup_timeout(self) -> None:
        result = self._run_progress(repeat=True)
        self.assertEqual(result["requestCount"], 2)
        self.assertIn("(0초)", result["restarted"]["text"])
        self.assertEqual(result["restarted"]["width"], "5%")
        self.assertEqual(result["restarted"], result["afterOldTimeout"])
        self.assertIn("(21초)", result["secondWaiting"]["text"])
        self.assertEqual(result["secondWaiting"]["intervals"], 1)
        self.assertFalse(result["settled"]["busy"])
        self.assertEqual(result["settled"]["intervals"], 0)


if __name__ == "__main__":
    unittest.main()
