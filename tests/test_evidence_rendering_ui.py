from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"), "Node.js is required for UI execution tests")
class EvidenceRenderingUiTests(unittest.TestCase):
    def render(self, expression: str, value: object) -> str:
        # Run the actual renderer functions with data, without DOM or network.
        program = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('static/app.js', 'utf8');
const args = JSON.parse(fs.readFileSync(0, 'utf8'));
const sandbox = {input: args.value};
vm.createContext(sandbox);
vm.runInContext(source.slice(source.indexOf('function renderReport('), source.indexOf('function startProgress(')), sandbox);
process.stdout.write(String(vm.runInContext(args.expression, sandbox)));
"""
        return subprocess.run(
            ["node", "-e", program], input=json.dumps({"expression": expression, "value": value}),
            capture_output=True, text=True, check=True, cwd=ROOT, timeout=10,
        ).stdout

    def test_decoded_script_is_literal_escaped_text_with_limitations(self) -> None:
        value = {
            "status": "partial", "decoded_scripts": [{
                "source": "command_line", "method": "EncodedCommand", "encoding": "utf-16-le",
                "depth": 1, "text": '<script>alert("x")</script>\n# Not a report heading',
                "text_truncated": True, "signals": ["검토 필요"],
            }], "warnings": ["입력 일부 생략"],
        }
        html = self.render("renderDecodedPowershell(input)", value)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("# Not a report heading", html)
        self.assertIn("입력 일부 생략", html)
        self.assertIn("정적 분석 신호", html)
        self.assertIn("실행 없이", html)

    def test_code_fences_preserve_newlines_and_do_not_turn_script_into_headings(self) -> None:
        content = '# Report\n\n````powershell\n# Script comment\n```\n<img src=x onerror=alert(1)>\n````\n\n## Next'
        html = self.render("markdownToHtml(input)", content)
        self.assertIn("<h1>Report</h1>", html)
        self.assertIn("<h2>Next</h2>", html)
        self.assertIn("<pre><code># Script comment\n```\n&lt;img", html)
        self.assertNotIn("<h1>Script", html)
        self.assertNotIn("<img", html)

    def test_chain_keeps_steps_after_96_and_displays_origin_and_trigger(self) -> None:
        data = {
            "origin_process": {"process": "untrusted-download.exe", "process_id": "42"},
            "origin_assessment": "생성·실행 근거로 연결됨. 악성 여부 미확정",
            "observed_trigger_process": {"process": "regsvr32.exe", "process_id": "44"},
            "upstream_process_context": [{"process": "untrusted-download.exe", "source_ref": "sample.evtx#3"}],
            "payload_artifacts": [{"process": "regsvr32.exe", "referenced_path": "C:\\Temp\\payload.dll",
                                   "source_ref": "sample.evtx#4", "creation_source_refs": ["sample.evtx#2"],
                                   "limitation": "실행 성공 미확인"}],
            "steps": [{"order": i, "time": f"2026-01-01T00:00:{i:03d}Z", "process": f"process-{i}",
                       "command_line": f"command-{i}", "source_refs": [f"sample.evtx#{i}"]}
                      for i in range(1, 111)],
        }
        html = self.render("renderIntrusionChain(input)", data)
        self.assertIn("process-110", html)
        self.assertIn("command-110", html)
        self.assertIn("sample.evtx#110", html)
        self.assertIn("regsvr32.exe", html)
        self.assertIn("untrusted-download.exe", html)
        self.assertIn("악성 여부 미확정", html)
        self.assertIn("C:\\Temp\\payload.dll", html)
        self.assertIn("실행 성공 미확인", html)

    def test_chunk_status_distinguishes_model_results_from_local_recovery(self) -> None:
        html = self.render("renderHierarchicalLmStatus(input)", {
            "hierarchical_analysis_used": True, "hierarchical_chunk_count": 5,
            "hierarchical_chunks_completed": 3, "hierarchical_chunks_failed": 2,
            "hierarchical_chunks_recovered": 2,
        })
        self.assertIn("LM 완료 3개", html)
        self.assertIn("로컬 근거 보완 2개", html)
        self.assertNotIn("미복구", html)


if __name__ == "__main__":
    unittest.main()
