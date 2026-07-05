from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Codex CLI as CAT development AI agent")
    parser.add_argument("prompt", type=Path, help="CAT agent prompt markdown")
    parser.add_argument("--output", type=Path, default=None, help="Path for Codex final response")
    parser.add_argument("--model", default=None, help="Optional Codex model override")
    args = parser.parse_args()

    codex_bin = shutil.which("codex")
    if not codex_bin:
        raise SystemExit("codex CLI not found in PATH")
    if not args.prompt.exists():
        raise SystemExit(f"prompt file not found: {args.prompt}")

    output = args.output
    if output is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = ROOT / "reports" / f"cat-{stamp}.codex-review.md"
    output.parent.mkdir(parents=True, exist_ok=True)

    prompt = args.prompt.read_text(encoding="utf-8")
    dev_prompt = (
        f"{prompt}\n\n"
        "# Codex Development Agent Task\n\n"
        "위 CAT 분석 결과를 기준으로 침해사고 조사 보고서를 작성하고, 개발 성능 검증 관점에서 "
        "다음 항목도 함께 평가하라.\n\n"
        "- 분석 결과가 근거 이벤트에 충실한지\n"
        "- 주요 이상 활동의 우선순위가 타당한지\n"
        "- 누락 가능성이 있는 추가 확인 이벤트가 있는지\n"
        "- 실제 Qwen 운영 환경에 넘기기 전에 프롬프트나 요약을 줄여야 할 부분이 있는지\n"
    )

    command = [
        codex_bin,
        "exec",
        "--skip-git-repo-check",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "-C",
        str(ROOT),
        "-o",
        str(output),
    ]
    if args.model:
        command.extend(["--model", args.model])
    command.append("-")

    completed = subprocess.run(command, input=dev_prompt, text=True)
    if completed.returncode != 0:
        return completed.returncode
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
