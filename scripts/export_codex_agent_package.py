from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from cat_app.reporting import build_agent_prompt_markdown, generate_report
from cat_app.timeutil import get_timezone, parse_user_datetime


def main() -> int:
    parser = argparse.ArgumentParser(description="Export CAT analysis artifacts for Codex agent review")
    parser.add_argument("files", nargs="+", type=Path, help="EVTX or XML files")
    parser.add_argument("--start-time", default=None)
    parser.add_argument("--end-time", default=None)
    parser.add_argument("--timezone", default="Asia/Seoul")
    parser.add_argument("--max-records", type=int, default=20000)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "reports")
    args = parser.parse_args()

    tz = get_timezone(args.timezone)
    start_utc = parse_user_datetime(args.start_time, tz)
    end_utc = parse_user_datetime(args.end_time, tz)
    if start_utc and end_utc and start_utc > end_utc:
        raise SystemExit("start time must be earlier than end time")

    missing = [str(path) for path in args.files if not path.exists()]
    if missing:
        raise SystemExit(f"missing input files: {', '.join(missing)}")

    parse_result = parse_event_files(args.files, start_utc, end_utc, args.max_records)
    analysis = analyze_events(parse_result, start_utc, end_utc)
    fallback_report, llm_status = generate_report(analysis, use_llm=False, lm_url=None, model=None)
    agent_prompt = build_agent_prompt_markdown(analysis)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    prefix = args.output_dir / f"cat-{stamp}"

    analysis_path = prefix.with_suffix(".analysis.json")
    report_path = prefix.with_suffix(".fallback-report.md")
    prompt_path = prefix.with_suffix(".agent-prompt.md")

    analysis_path.write_text(json.dumps({"analysis": analysis, "llm": llm_status}, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(fallback_report, encoding="utf-8")
    prompt_path.write_text(agent_prompt, encoding="utf-8")

    print(f"analysis={analysis_path}")
    print(f"fallback_report={report_path}")
    print(f"agent_prompt={prompt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
