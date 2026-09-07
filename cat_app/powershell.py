"""Bounded, static decoding of PowerShell evidence; never execute its contents."""

from __future__ import annotations

import base64
import binascii
from collections import deque
import hashlib
import re
from typing import Any


MAX_POWERSHELL_INPUT_CHARS = 131_072
MAX_ENCODED_TOKEN_CHARS = 65_536
MAX_DECODED_BYTES = 49_152
MAX_TOTAL_DECODED_BYTES = 98_304
MAX_DECODED_SCRIPT_CHARS = 12_000
MAX_TOTAL_DECODED_SCRIPT_CHARS = 32_768
MAX_DECODE_DEPTH = 3
MAX_DECODED_SCRIPTS = 8
MAX_DECODE_ATTEMPTS = 16

_POWERSHELL_HOST = re.compile(
    r"(?:^|[\\/\s\"'])(?:powershell|pwsh)(?:\.exe)?(?=$|[\s\"'])", re.I
)
_ENCODED_SWITCHES = "|".join(
    ["encodedcommand"[:length] for length in range(14, 0, -1)] + ["ec"]
)
_ENCODED_ARGUMENT = re.compile(
    r"(?<![\w-])-(?:" + _ENCODED_SWITCHES + r")(?=$|[\s:=])"
    r"(?:\s+|[:=]\s*)(?:\"([^\"]*)\"|'([^']*)'|([^\s;|&<>]+))",
    re.I,
)
_ENCODED_SWITCH = re.compile(
    r"(?<![\w-])-(?:" + _ENCODED_SWITCHES + r")(?=$|[\s:=])", re.I
)
_BASE64_LITERAL = re.compile(
    r"\[(?:system\.)?convert\]\s*::\s*frombase64string\s*\(\s*"
    r"(?:\"([^\"]*)\"|'([^']*)')\s*\)",
    re.I,
)
_BASE64_CALL = re.compile(r"\[(?:system\.)?convert\]\s*::\s*frombase64string\s*\(", re.I)
_QUOTED_LITERAL = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"`]|`.)*\"", re.S)
_LEADING_EXECUTABLE = re.compile(r'''^\s*(?:"([^"]+)"|'([^']+)'|([^\s]+))(.*)$''', re.S)
_COMMENT = re.compile(r"<#.*?#>|\#[^\r\n]*", re.S)
_COMMAND_BOUNDARY = r"(?:^|[;|&({\s])"
_DOWNLOAD = re.compile(
    r"\.\s*(?:downloadstring|downloadfile|downloaddata)\s*\("
    r"|" + _COMMAND_BOUNDARY + r"(?:invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer)\b",
    re.I,
)
_DYNAMIC_EXECUTION = re.compile(
    _COMMAND_BOUNDARY + r"(?:iex|invoke-expression)\b", re.I
)
_SECURITY_SETTING = re.compile(
    _COMMAND_BOUNDARY + r"(?:set-mppreference|add-mppreference)\b", re.I
)


def analyze_powershell_content(
    command_line: str = "", script_block: str = ""
) -> dict[str, Any]:
    """Decode literal arguments and inspect text, without evaluating PowerShell.

    Callers retain the original event fields alongside this result. A decoded
    string or a static signal alone does not establish execution or compromise.
    Variable resolution, decompression and arbitrary expression evaluation are
    intentionally unsupported. Only literal Base64 inputs are decoded.
    """
    result: dict[str, Any] = {
        "status": "not_encoded",
        "decoded_scripts": [],
        "signals": [],
        "warnings": [],
        "truncated": False,
        "input_truncated": False,
        "decoding_only_is_not_malicious": True,
        "signal_limitations": (
            "정적 디코딩 결과이며 스크립트를 실행하지 않았습니다. 문자열·명령 참조는 "
            "실행이나 악성을 입증하지 않으며 원본 이벤트·프로세스·통신 근거와 대조해야 합니다."
        ),
    }
    queue: deque[tuple[str, str, int, int | None]] = deque()
    remaining_input = MAX_POWERSHELL_INPUT_CHARS
    for source, value in (("command_line", command_line), ("script_block", script_block)):
        if not isinstance(value, str) or not value:
            continue
        text = value[:remaining_input]
        if len(text) < len(value):
            result["input_truncated"] = result["truncated"] = True
            _warn(result, "원본 입력이 정적 디코딩 검사 크기 제한을 초과하여 일부만 검사했습니다.")
        remaining_input -= len(text)
        if text:
            queue.append((source, text, 1, None))

    seen: set[tuple[str, str]] = set()
    attempts = 0
    total_bytes = 0
    total_chars = 0
    encoded_seen = False
    failed = False
    while queue:
        source, text, depth, parent_index = queue.popleft()
        candidates, unresolved = _literal_candidates(
            text, script_context=source == "script_block" or depth > 1
        )
        encoded_seen = encoded_seen or bool(candidates) or unresolved
        if unresolved:
            failed = True
            _warn(result, "Base64 인수가 누락되었거나 상수가 아니어서 해당 식을 평가하지 않았습니다.")
        if depth > MAX_DECODE_DEPTH and candidates:
            result["truncated"] = True
            _warn(result, "중첩 디코딩 깊이 제한에 도달하여 나머지 계층은 검사하지 않았습니다.")
            continue
        for method, encoded in candidates:
            if attempts >= MAX_DECODE_ATTEMPTS or len(result["decoded_scripts"]) >= MAX_DECODED_SCRIPTS:
                result["truncated"] = True
                _warn(result, "디코딩 항목 수 제한에 도달하여 일부 인수를 검사하지 않았습니다.")
                queue.clear()
                break
            attempts += 1
            if len(encoded) > MAX_ENCODED_TOKEN_CHARS:
                result["truncated"] = True
                failed = True
                _warn(result, "Base64 인수가 크기 제한을 초과하여 디코딩하지 않았습니다.")
                continue
            # Whitespace is legal in .NET FromBase64String literal arguments.
            compact = re.sub(r"\s+", "", encoded)
            key = (source, compact)
            if key in seen:
                continue
            seen.add(key)
            try:
                raw = _decode_base64(compact)
            except (ValueError, binascii.Error):
                failed = True
                _warn(result, "유효하지 않은 Base64 인수는 디코딩하지 못했습니다.")
                continue
            if len(raw) > MAX_DECODED_BYTES or total_bytes + len(raw) > MAX_TOTAL_DECODED_BYTES:
                result["truncated"] = True
                failed = True
                _warn(result, "디코딩 바이트 제한에 도달하여 일부 내용을 검사하지 않았습니다.")
                continue
            total_bytes += len(raw)
            decoded, encoding = _decode_text(raw)
            if decoded is None:
                failed = True
                _warn(result, "디코딩 값이 텍스트로 확인되지 않아 바이너리·압축 데이터를 처리하지 않았습니다.")
                continue
            available_chars = min(
                MAX_DECODED_SCRIPT_CHARS, MAX_TOTAL_DECODED_SCRIPT_CHARS - total_chars
            )
            if available_chars <= 0:
                result["truncated"] = True
                _warn(result, "디코딩 텍스트 보존 제한에 도달하여 일부 내용을 보존하지 못했습니다.")
                queue.clear()
                break
            visible = decoded[:available_chars]
            item_truncated = len(visible) < len(decoded)
            total_chars += len(visible)
            result["truncated"] = result["truncated"] or item_truncated
            if item_truncated:
                _warn(result, "디코딩 텍스트가 보존 제한을 초과했습니다. 원본 인수를 추가로 확인해야 합니다.")
            signals = _static_signals(visible)
            item = {
                "source": source,
                "method": method,
                "depth": depth,
                "parent_index": parent_index,
                "encoding": encoding,
                "text": visible,
                "text_truncated": item_truncated,
                "encoded_chars": len(compact),
                "decoded_bytes": len(raw),
                "encoded_sha256": hashlib.sha256(compact.encode("ascii")).hexdigest(),
                "decoded_sha256": hashlib.sha256(raw).hexdigest(),
                "signals": signals,
            }
            result["decoded_scripts"].append(item)
            for signal in signals:
                if signal not in result["signals"]:
                    result["signals"].append(signal)
            queue.append((source, visible, depth + 1, len(result["decoded_scripts"]) - 1))
    if result["decoded_scripts"]:
        result["status"] = "partial" if failed or result["truncated"] else "decoded"
    elif encoded_seen:
        result["status"] = "failed"
    elif result["input_truncated"]:
        # Absence in the inspected prefix says nothing about uninspected data.
        result["status"] = "partial"
    return result


def _literal_candidates(text: str, *, script_context: bool) -> tuple[list[tuple[str, str]], bool]:
    candidates: list[tuple[str, str]] = []
    unresolved = False
    if not script_context:
        command = _powershell_command_text(text)
        if command is None:
            return candidates, unresolved
        text = command
    masked = _mask_literals_and_comments(text)
    has_host = not script_context or bool(_POWERSHELL_HOST.search(masked))
    if script_context and not has_host:
        has_host = any(
            re.search(r"(?:^|[;(\s])&\s*$", text[:match.start()])
            for match in _POWERSHELL_HOST.finditer(text)
        )
    if has_host:
        # Cap discovery as well as decoding, even for input containing thousands
        # of tiny arguments. One extra item records that the limit was reached.
        for match in _ENCODED_ARGUMENT.finditer(text):
            if script_context and masked[match.start()] != "-":
                continue
            candidates.append(("encoded_command", next(value for value in match.groups() if value is not None)))
            if len(candidates) > MAX_DECODE_ATTEMPTS:
                break
        switch_text = masked if script_context else text
        unresolved = sum(1 for _ in _ENCODED_SWITCH.finditer(switch_text)) > len(candidates)
    literal_count = 0
    for match in _BASE64_LITERAL.finditer(text):
        if script_context and masked[match.start()] != "[":
            continue
        literal_count += 1
        candidates.append(("from_base64_string", next(value for value in match.groups() if value is not None)))
        if len(candidates) > MAX_DECODE_ATTEMPTS:
            break
    call_text = masked if script_context else text
    unresolved = unresolved or sum(1 for _ in _BASE64_CALL.finditer(call_text)) > literal_count
    return candidates, unresolved


def _powershell_command_text(text: str, depth: int = 0) -> str | None:
    """Recognize an actual host, not a host name mentioned in another app's data."""
    match = _LEADING_EXECUTABLE.match(text)
    if not match:
        return None
    executable = next(value for value in match.groups()[:3] if value is not None)
    basename = executable.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if basename in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        return text
    if basename not in {"cmd", "cmd.exe"} or depth >= 2:
        return None
    wrapper = re.match(r"\s*(?:(?:/d|/s)\s+)*(?:/c|/k)\s+(.+)$", match.group(4), re.I | re.S)
    if not wrapper:
        return None
    nested = wrapper.group(1).strip()
    command = _powershell_command_text(nested, depth + 1)
    if command is not None:
        return command
    if nested.startswith('"') and nested.endswith('"'):
        return _powershell_command_text(nested[1:-1], depth + 1)
    return None


def _mask_literals_and_comments(text: str) -> str:
    masked = _QUOTED_LITERAL.sub(lambda match: " " * len(match.group()), text)
    return _COMMENT.sub(lambda match: " " * len(match.group()), masked)


def powershell_code_text(text: str) -> str:
    """Return bounded text with quoted data/comments masked for static rules.

    This is a conservative textual view, not an AST or evidence of execution.
    Original and decoded text must remain available separately as evidence.
    """
    if not isinstance(text, str):
        return ""
    return _mask_literals_and_comments(text[:MAX_POWERSHELL_INPUT_CHARS])


def _decode_base64(encoded: str) -> bytes:
    if not encoded or len(encoded) % 4 != 0:
        raise ValueError("Empty or invalid Base64 length")
    return base64.b64decode(encoded, validate=True)


def _decode_text(raw: bytes) -> tuple[str | None, str | None]:
    if not raw:
        return None, None
    if raw.startswith(b"\xff\xfe"):
        encodings = [("utf-16", "utf-16le")]
    elif raw.startswith(b"\xfe\xff"):
        encodings = [("utf-16", "utf-16be")]
    elif raw.startswith(b"\xef\xbb\xbf"):
        encodings = [("utf-8-sig", "utf-8")]
    elif b"\x00" in raw:
        if raw[0::2].count(0) > raw[1::2].count(0):
            encodings = [("utf-16be", "utf-16be")]
        else:
            encodings = [("utf-16le", "utf-16le")]
    else:
        encodings = [("utf-8", "utf-8"), ("utf-16le", "utf-16le")]
    for codec, label in encodings:
        try:
            text = raw.decode(codec)
        except UnicodeError:
            continue
        if not text or "\x00" in text:
            continue
        printable = sum(char.isprintable() or char in "\r\n\t" for char in text)
        if printable / len(text) < 0.95:
            continue
        # Arbitrary binary can coincidentally look like UTF-16 CJK text. Require
        # script syntax when neither a BOM nor NUL bytes indicate UTF-16.
        if label == "utf-16le" and b"\x00" not in raw and not raw.startswith(b"\xff\xfe"):
            if not re.search(r"[A-Za-z_$'\";{}()]", text):
                continue
        return text, label
    return None, None


def _static_signals(text: str) -> list[str]:
    # Mask string literals to avoid treating e.g. Write-Output 'IEX' as a call.
    # This is a conservative textual inspection, not a PowerShell AST parser.
    commands = powershell_code_text(text)
    signals = []
    if _DOWNLOAD.search(commands):
        signals.append("network_transfer_command")
    if _DYNAMIC_EXECUTION.search(commands):
        signals.append("dynamic_code_execution")
    if "network_transfer_command" in signals and "dynamic_code_execution" in signals:
        signals.append("download_and_execute_pattern")
    if _SECURITY_SETTING.search(commands) and re.search(
        r"-(?:disablerealtimemonitoring|disablebehaviormonitoring)\s+\$true\b", commands, re.I
    ):
        signals.append("security_monitoring_disable_command")
    return signals


def _warn(result: dict[str, Any], message: str) -> None:
    if message not in result["warnings"]:
        result["warnings"].append(message)
