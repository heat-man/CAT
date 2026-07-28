from __future__ import annotations

import argparse
import json
from math import isfinite
from pathlib import Path
import sys
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cat_app import reporting  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check LM Studio models and perform a real Chat Completions probe."
    )
    parser.add_argument("--base-url", default=reporting.DEFAULT_LM_STUDIO_URL)
    parser.add_argument("--model", default=reporting.DEFAULT_MODEL)
    parser.add_argument(
        "--timeout",
        type=float,
        default=reporting.DEFAULT_LM_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--models-only",
        action="store_true",
        help="Only call /v1/models; skip the real chat completion probe.",
    )
    args = parser.parse_args(argv)

    try:
        if not isfinite(args.timeout):
            raise ValueError("timeout must be a finite number")
        timeout = max(1.0, min(3600.0, args.timeout))
        model = args.model.strip()
        if not model:
            raise ValueError("LM Studio model ID is empty")
        headers = _headers()

        models_url = reporting.models_endpoint(args.base_url)
        payload = _request_json(models_url, headers=headers, timeout=timeout)
        models = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(models, list):
            raise RuntimeError("LM Studio /v1/models response has no data list")

        print(f"LM Studio reachable: {models_url}")
        model_ids = [
            model_id.strip()
            for item in models
            if isinstance(item, dict)
            and isinstance((model_id := item.get("id")), str)
            and model_id.strip()
        ]
        if not model_ids:
            raise RuntimeError("LM Studio /v1/models returned no usable model IDs")
        for model_id in model_ids:
            print(f"- {model_id}")

        if args.models_only:
            return 0
        if model not in model_ids:
            raise RuntimeError(
                f"configured model ID {model!r} is not present in /v1/models; "
                "use the exact listed and approved model ID"
            )

        chat_url = reporting.normalize_chat_endpoint(args.base_url)
        report, status = reporting.generate_report(
            _probe_analysis(),
            use_llm=True,
            lm_url=chat_url,
            model=model,
            timeout_seconds=timeout,
        )
        if not status.get("used"):
            raise RuntimeError(
                "production structured scenario probe failed: "
                f"{status.get('error') or 'Qwen response was rejected'}"
            )
        if not status.get("structured_report_validated"):
            raise RuntimeError(
                "production structured scenario probe was not schema-validated"
            )
        if status.get("suspicious_event_count") != 2:
            raise RuntimeError(
                "production structured scenario probe did not preserve both suspicious events"
            )
        if status.get("attack_scenario_count") != 1:
            raise RuntimeError(
                "production structured scenario probe did not return the required scenario"
            )
        missing_sections = [
            section
            for section in reporting.REQUIRED_REPORT_SECTIONS
            if section not in report
        ]
        if missing_sections:
            raise RuntimeError(
                "production structured scenario probe is missing report sections: "
                f"{', '.join(missing_sections)}"
            )
        if "EVT-0001" not in report or "EVT-0002" not in report:
            raise RuntimeError(
                "production structured scenario probe lost an expected event reference"
            )
        finish_reason = status.get("finish_reason")
        print(
            f"LM Studio production structured scenario probe passed: model={model} "
            f"finish_reason={finish_reason or 'unspecified'}"
        )
        return 0
    except (RuntimeError, ValueError) as exc:
        print(f"LM Studio check failed: {exc}", file=sys.stderr)
        return 1


def _headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if reporting.DEFAULT_LM_API_KEY:
        headers["Authorization"] = f"Bearer {reporting.DEFAULT_LM_API_KEY}"
    return headers


def _probe_analysis() -> dict[str, Any]:
    event_refs = ["EVT-0001", "EVT-0002"]
    return {
        "analysis_schema_version": 2,
        "scope": {
            "start_utc": "2026-07-28T01:00:00Z",
            "end_utc": "2026-07-28T01:02:00Z",
            "records_loaded": 2,
            "records_in_range": 2,
            "records_seen": 2,
            "truncated": False,
        },
        "parser": {
            "files": [],
            "errors": [],
            "total_seen": 2,
            "total_in_range": 2,
            "truncated": False,
        },
        "summary": {
            "first_seen": "2026-07-28T01:00:00Z",
            "last_seen": "2026-07-28T01:02:00Z",
        },
        "findings": [],
        "suspicious_events": [
            {
                "event_ref": "EVT-0001",
                "time": "2026-07-28T01:00:00Z",
                "source_file": "Security.evtx",
                "record_id": "1001",
                "event_id": "4624",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "host": "WIN-PROBE",
                "account": r"CATLAB\analyst",
                "source_ip": "10.255.255.10",
                "process": None,
                "command_line": None,
                "fields": {"LogonType": "10", "TargetLogonId": "0x123456"},
                "severity": "medium",
                "confidence": "medium",
                "rule_ids": ["rdp_logon"],
                "reasons": [
                    {
                        "rule_id": "rdp_logon",
                        "title": "RDP 원격 대화형 로그온",
                        "description": "원격 대화형 로그온이 관측됨",
                    }
                ],
            },
            {
                "event_ref": "EVT-0002",
                "time": "2026-07-28T01:02:00Z",
                "source_file": "Security.evtx",
                "record_id": "1002",
                "event_id": "4688",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "host": "WIN-PROBE",
                "account": r"CATLAB\analyst",
                "source_ip": None,
                "process": (
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                ),
                "command_line": "powershell.exe -NoProfile -EncodedCommand QUJD",
                "fields": {
                    "SubjectLogonId": "0x123456",
                    "ParentProcessName": r"C:\Windows\explorer.exe",
                },
                "severity": "high",
                "confidence": "medium",
                "rule_ids": [
                    "suspicious_process_encoded_powershell",
                    "suspicious_powershell",
                ],
                "reasons": [
                    {
                        "rule_id": "suspicious_process_encoded_powershell",
                        "title": "의심 프로세스 실행: encoded powershell",
                        "description": "EncodedCommand가 포함된 프로세스 생성",
                    }
                ],
            },
        ],
        "suspicious_event_scope": {
            "included_count": 2,
            "finding_event_count": 2,
            "evidence_truncated": False,
        },
        "scenario_candidates": [
            {
                "scenario_id": "SCN-001",
                "title": "RDP 로그온 후 의심 PowerShell 실행 가설",
                "confidence": "medium",
                "event_refs": event_refs,
                "stages": [
                    {
                        "order": 1,
                        "phase": "원격 접근 또는 측면 이동",
                        "event_ref": "EVT-0001",
                        "description": "RDP 원격 대화형 로그온",
                    },
                    {
                        "order": 2,
                        "phase": "실행",
                        "event_ref": "EVT-0002",
                        "description": "Encoded PowerShell 실행",
                    },
                ],
                "link_reasons": [
                    "동일 호스트 WIN-PROBE에서 2분 이내 발생",
                    r"동일 계정 CATLAB\analyst 사용",
                    "동일 Logon ID 0x123456 공유",
                ],
                "hypothesis": (
                    "RDP 세션 이후 동일 세션에서 의심 PowerShell이 실행됐을 가능성"
                ),
                "alternative_explanations": [
                    "승인된 원격 관리 작업일 수 있음",
                ],
                "evidence_gaps": [
                    "EDR 프로세스 계보와 네트워크 로그 추가 확인 필요",
                ],
            }
        ],
        "timeline": [],
    }


def _request_json(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    body: dict[str, Any] | None = None,
) -> Any:
    request_headers = dict(headers)
    data = None
    method = "GET"
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
        method = "POST"
    req = request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with reporting.open_lm_request(req, timeout=timeout) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise RuntimeError("LM Studio response is larger than 8 MiB")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("LM Studio returned invalid JSON") from exc
    except HTTPError as exc:
        detail = exc.read(500).decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise RuntimeError(f"connection timed out after {timeout:g} seconds") from exc
        raise RuntimeError(f"connection failed: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError(f"connection timed out after {timeout:g} seconds") from exc


if __name__ == "__main__":
    raise SystemExit(main())
