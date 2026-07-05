from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from time import perf_counter
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError

DEFAULT_LM_STUDIO_URL = os.getenv("LM_STUDIO_URL", "http://172.16.100.51:1234/v1/chat/completions")
DEFAULT_MODEL = os.getenv("LM_STUDIO_MODEL", "qwen")
DEFAULT_CODEX_TIMEOUT_SECONDS = int(os.getenv("CAT_CODEX_TIMEOUT_SECONDS", "300"))
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def generate_report(
    analysis: dict[str, Any],
    use_llm: bool,
    lm_url: str | None,
    model: str | None,
) -> tuple[str, dict[str, Any]]:
    llm_status = {"used": False, "url": _chat_endpoint(lm_url or DEFAULT_LM_STUDIO_URL), "model": model or DEFAULT_MODEL, "error": None}
    if use_llm:
        try:
            report = _generate_lm_report(analysis, llm_status["url"], llm_status["model"])
            llm_status["used"] = True
            return report, llm_status
        except Exception as exc:
            llm_status["error"] = f"{type(exc).__name__}: {exc}"

    return _fallback_report(analysis, llm_status["error"]), llm_status


def generate_codex_dev_report(analysis: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    status: dict[str, Any] = {
        "used": False,
        "backend": "codex_dev",
        "url": "codex exec",
        "model": os.getenv("CAT_CODEX_MODEL", "codex-default"),
        "error": None,
        "codex_review_required": False,
        "duration_seconds": None,
    }
    codex_bin = shutil.which("codex")
    if not codex_bin:
        status["error"] = "codex CLI를 PATH에서 찾지 못했습니다."
        return _fallback_report(analysis, status["error"]), status

    prompt = _codex_development_prompt(analysis)
    command = [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--color",
        "never",
        "-C",
        str(PROJECT_ROOT),
    ]
    if model := os.getenv("CAT_CODEX_MODEL"):
        command.extend(["--model", model])

    start = perf_counter()
    with tempfile.TemporaryDirectory(prefix="cat-codex-") as temp_dir:
        output_path = Path(temp_dir) / "codex-review.md"
        command.extend(["-o", str(output_path)])
        command.append("-")
        try:
            completed = subprocess.run(
                command,
                input=prompt,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=DEFAULT_CODEX_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            status["duration_seconds"] = perf_counter() - start
            status["error"] = f"codex exec가 {DEFAULT_CODEX_TIMEOUT_SECONDS}초 제한을 초과했습니다."
            return _fallback_report(analysis, status["error"]), status

        status["duration_seconds"] = perf_counter() - start
        output_text = output_path.read_text(encoding="utf-8") if output_path.exists() else ""
        if completed.returncode != 0:
            tail = (completed.stdout or "").strip()[-1200:]
            status["error"] = f"codex exec 실패(returncode={completed.returncode}): {tail}"
            return _fallback_report(analysis, status["error"]), status
        if not output_text.strip():
            tail = (completed.stdout or "").strip()[-1200:]
            status["error"] = f"codex exec 결과 파일이 비어 있습니다. 출력: {tail}"
            return _fallback_report(analysis, status["error"]), status

    status["used"] = True
    return output_text.strip(), status


def _generate_lm_report(analysis: dict[str, Any], endpoint: str, model: str) -> str:
    messages = build_agent_messages(analysis)
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 4096,
    }
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        endpoint,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"LM Studio HTTP {exc.code}: {detail[:500]}") from exc
    except URLError as exc:
        raise RuntimeError(f"LM Studio 연결 실패: {exc.reason}") from exc

    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"LM Studio 응답 형식이 예상과 다릅니다: {str(data)[:500]}") from exc


def build_agent_messages(analysis: dict[str, Any]) -> list[dict[str, str]]:
    compact = _compact_for_llm(analysis)
    return [
        {
            "role": "system",
            "content": (
                "너는 Windows DFIR 침해사고 조사 분석가다. Qwen 계열 로컬 LLM에서도 안정적으로 "
                "수행되도록 간결하고 근거 중심으로 답한다. 제공된 JSON 근거 안에서만 판단하고, "
                "추정은 반드시 '가설'로 표시한다. 이벤트 ID, 시간, 호스트, 계정, 원본 IP, 명령줄 등 "
                "근거를 명확히 인용하며 한국어 보고서를 작성한다. 악성 의심 로그는 발생 원인 후보와 "
                "관측 행위를 분리해 설명하고, 네트워크 연결, 파일/레지스트리/데이터 변조, 계정 변경 등 "
                "근거가 없는 행위는 확인 불가로 명시한다."
            ),
        },
        {
            "role": "user",
            "content": (
                "다음 CAT 분석 결과를 바탕으로 조사 보고서를 작성하라.\n\n"
                "요구 형식:\n"
                "1. 분석 범위\n"
                "2. 핵심 요약\n"
                "3. 주요 이상 활동 상세 분석\n"
                "4. 시간순 타임라인\n"
                "5. 관련 계정/호스트/IP/프로세스\n"
                "6. 침해 가설과 확인 필요 사항\n"
                "7. 추가 수집 및 대응 권고\n\n"
                "작성 규칙:\n"
                "- 증거가 부족한 내용은 단정하지 말고 가설로 표시한다.\n"
                "- 각 주요 판단에는 근거 이벤트를 붙인다.\n"
                "- 각 이상 활동은 판정, 발생 원인 후보, 관측된 행위, 확인되지 않은 행위/증거 한계, 후속 확인으로 나누어 쓴다.\n"
                "- Event ID가 같아도 provider/channel이 다르면 다른 이벤트로 취급한다. 예: 로그 삭제는 Security 1102 또는 Microsoft-Windows-Eventlog/System 104를 우선 근거로 삼고, Kernel-Cache 104는 로그 삭제로 단정하지 않는다.\n"
                "- Defender 1116/1117/5007 등은 Microsoft-Windows-Windows Defender provider/channel일 때만 Defender 근거로 삼는다.\n"
                "- WMI 5857-5861은 Microsoft-Windows-WMI-Activity provider/channel 또는 명시적 WMI 명령 근거가 있을 때만 WMI 활동으로 판단한다.\n"
                "- 이벤트 수가 많으면 우선순위가 높은 이상 활동부터 정리한다.\n"
                "- 보안 담당자가 바로 후속 조사를 수행할 수 있게 확인 명령이나 확인 대상을 구체화한다.\n\n"
                f"CAT_ANALYSIS_JSON:\n{json.dumps(compact, ensure_ascii=False, indent=2)}"
            ),
        },
    ]


def build_agent_prompt_markdown(analysis: dict[str, Any]) -> str:
    messages = build_agent_messages(analysis)
    lines = [
        "# CAT Agent Prompt",
        "",
        "이 파일은 개발 환경에서 Codex를 보고서 작성/품질 검증 에이전트로 사용할 때 전달하는 프롬프트입니다.",
        "독립망 운영 환경에서는 동일한 메시지가 LM Studio의 Qwen 모델로 전송됩니다.",
        "",
    ]
    for message in messages:
        lines.extend([f"## {message['role']}", "", message["content"], ""])
    return "\n".join(lines).rstrip() + "\n"


def _codex_development_prompt(analysis: dict[str, Any]) -> str:
    return (
        f"{build_agent_prompt_markdown(analysis)}\n\n"
        "# Codex Development Agent Task\n\n"
        "위 CAT 분석 결과를 기준으로 침해사고 조사 보고서를 작성하고, 개발 성능 검증 관점에서 "
        "다음 항목도 함께 평가하라.\n\n"
        "- 분석 결과가 근거 이벤트에 충실한지\n"
        "- 주요 이상 활동의 우선순위가 타당한지\n"
        "- 악성 의심 로그의 발생 원인과 관측 행위를 근거 범위 안에서 충분히 분리했는지\n"
        "- 누락 가능성이 있는 추가 확인 이벤트가 있는지\n"
        "- 실제 Qwen 운영 환경에 넘기기 전에 프롬프트나 요약을 줄여야 할 부분이 있는지\n"
    )


def _chat_endpoint(value: str) -> str:
    url = value.rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    if url.endswith("/v1"):
        return f"{url}/chat/completions"
    return f"{url}/v1/chat/completions"


def _compact_for_llm(analysis: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for finding in analysis.get("findings", [])[:20]:
        compact_finding = dict(finding)
        compact_finding["evidence"] = finding.get("evidence", [])[:6]
        findings.append(compact_finding)
    return {
        "scope": analysis.get("scope"),
        "parser": analysis.get("parser"),
        "summary": analysis.get("summary"),
        "findings": findings,
        "timeline": analysis.get("timeline", [])[:80],
    }


def _fallback_report(analysis: dict[str, Any], llm_error: str | None) -> str:
    scope = analysis.get("scope", {})
    summary = analysis.get("summary", {})
    findings = analysis.get("findings", [])
    parser = analysis.get("parser", {})

    lines = [
        "# CAT 침해 로그 분석 보고서",
        "",
        "## 1. 분석 범위",
        f"- 시작(UTC): {scope.get('start_utc') or '미지정'}",
        f"- 종료(UTC): {scope.get('end_utc') or '미지정'}",
        f"- 로드 이벤트: {scope.get('records_loaded', 0)}건 / 범위 내 이벤트: {scope.get('records_in_range', 0)}건 / 전체 확인: {scope.get('records_seen', 0)}건",
        f"- 레코드 제한 초과: {'예' if scope.get('truncated') else '아니오'}",
        "",
    ]
    if parser.get("errors"):
        lines.extend(["## 파서 경고", *[f"- {error}" for error in parser["errors"]], ""])
    if llm_error:
        lines.extend(["## LM Studio 보고서 생성 상태", f"- LLM 호출 실패로 규칙 기반 보고서를 생성했습니다: `{llm_error}`", ""])

    lines.extend(
        [
            "## 2. 핵심 요약",
            f"- 탐지된 이상 활동: {len(findings)}건",
            f"- 최초 이벤트: {summary.get('first_seen') or '확인 불가'}",
            f"- 최종 이벤트: {summary.get('last_seen') or '확인 불가'}",
            "",
            "### 상위 이벤트 ID",
            *_format_counter(summary.get("top_event_ids", [])),
            "",
            "### 상위 호스트",
            *_format_counter(summary.get("top_hosts", [])),
            "",
            "### 상위 계정",
            *_format_counter(summary.get("top_accounts", [])),
            "",
            "### 상위 원본 IP",
            *_format_counter(summary.get("top_source_ips", [])),
            "",
            "## 3. 주요 이상 활동 상세 분석",
        ]
    )

    if not findings:
        lines.extend(
            [
                "- 현재 룰 기준으로 주요 이상 활동은 탐지되지 않았습니다.",
                "- 단, 로그 종류와 감사 정책에 따라 탐지 공백이 있을 수 있으므로 원본 로그 보존, 시간 동기화, 보안 제품 이벤트를 함께 확인해야 합니다.",
                "",
            ]
        )
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend(_format_finding(index, finding))

    lines.extend(["## 4. 시간순 타임라인"])
    timeline = analysis.get("timeline", [])[:30]
    if timeline:
        for item in timeline:
            lines.append(
                f"- {item.get('time') or '시간 없음'} | {item.get('severity')} | {item.get('title')} | "
                f"host={item.get('host') or '-'} account={item.get('account') or '-'} src={item.get('source_ip') or '-'} event={item.get('event_id') or '-'}"
            )
    else:
        lines.append("- 타임라인을 구성할 이벤트가 없습니다.")

    lines.extend(
        [
            "",
            "## 5. 추가 수집 및 대응 권고",
            "- 탐지 항목의 계정, 호스트, 원본 IP를 기준으로 EDR, 방화벽, VPN, 프록시, AD 로그를 같은 시간대에서 교차 확인하세요.",
            "- 4624/4625/4648/4672/4688/7045/4698/1102 이벤트 간 시간적 연결을 우선적으로 확인하세요.",
            "- 의심 명령줄에 포함된 파일 경로, 해시, 서비스명, 작업명을 IOC 후보로 정리하고 전사 검색하세요.",
        ]
    )
    return "\n".join(lines)


def _format_counter(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["- 없음"]
    return [f"- {item.get('value')}: {item.get('count')}건" for item in items[:10]]


def _format_finding(index: int, finding: dict[str, Any]) -> list[str]:
    lines = [
        f"### {index}. {finding.get('title')}",
        f"- 심각도: {finding.get('severity')} / 신뢰도: {finding.get('confidence')} / 이벤트: {finding.get('event_count')}건",
        f"- 기간: {finding.get('first_seen') or '확인 불가'} ~ {finding.get('last_seen') or '확인 불가'}",
        f"- 설명: {finding.get('description')}",
    ]
    entities = finding.get("entities", {})
    entity_parts = []
    for label, key in [("계정", "accounts"), ("호스트", "hosts"), ("원본 IP", "source_ips"), ("프로세스", "processes"), ("서비스", "services"), ("작업", "tasks")]:
        values = entities.get(key) or []
        if values:
            entity_parts.append(f"{label}={', '.join(values[:5])}")
    if entity_parts:
        lines.append(f"- 관련 엔티티: {' / '.join(entity_parts)}")
    guidance = finding.get("analysis_guidance") or {}
    if guidance:
        lines.append("- 원인/행위 분석:")
        if guidance.get("cause_focus"):
            lines.append(f"  - 발생 원인 후보: {guidance['cause_focus']}")
        if guidance.get("observed_behavior"):
            lines.append(f"  - 관측된 행위: {guidance['observed_behavior']}")
        if guidance.get("not_proven"):
            lines.append(f"  - 확인되지 않은 행위: {guidance['not_proven']}")
        if guidance.get("correlation_targets"):
            lines.append(f"  - 연계 확인: {', '.join(guidance['correlation_targets'][:6])}")
    lines.append("- 근거 이벤트:")
    for evidence in finding.get("evidence", [])[:6]:
        lines.append(
            f"  - {evidence.get('time') or '시간 없음'} | event={evidence.get('event_id')} | "
            f"host={evidence.get('host') or '-'} | account={evidence.get('account') or '-'} | "
            f"src={evidence.get('source_ip') or '-'} | process={evidence.get('process') or '-'}"
        )
        if evidence.get("command_line"):
            lines.append(f"    - command: `{evidence['command_line']}`")
    steps = finding.get("recommended_next_steps") or []
    if steps:
        lines.append("- 확인 사항:")
        lines.extend(f"  - {step}" for step in steps)
    lines.append("")
    return lines
