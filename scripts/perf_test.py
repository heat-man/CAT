from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cat_app.analyzer import analyze_events
from cat_app.evtx_reader import parse_event_files
from cat_app.reporting import build_agent_prompt_markdown, generate_report
from cat_app.timeutil import get_timezone, parse_user_datetime


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure CAT local parsing and analysis performance")
    parser.add_argument("files", nargs="+", type=Path, help="EVTX or XML files")
    parser.add_argument("--start-time", default=None)
    parser.add_argument("--end-time", default=None)
    parser.add_argument("--timezone", default="Asia/Seoul")
    parser.add_argument("--max-records", type=int, default=20000)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    tz = get_timezone(args.timezone)
    start_utc = parse_user_datetime(args.start_time, tz)
    end_utc = parse_user_datetime(args.end_time, tz)
    missing = [str(path) for path in args.files if not path.exists()]
    if missing:
        raise SystemExit(f"missing input files: {', '.join(missing)}")

    runs = []
    for _ in range(max(1, args.iterations)):
        parse_start = perf_counter()
        parse_result = parse_event_files(args.files, start_utc, end_utc, args.max_records)
        parse_seconds = perf_counter() - parse_start

        analyze_start = perf_counter()
        analysis = analyze_events(parse_result, start_utc, end_utc)
        analyze_seconds = perf_counter() - analyze_start

        report_start = perf_counter()
        fallback_report, _ = generate_report(analysis, use_llm=False, lm_url=None, model=None)
        prompt = build_agent_prompt_markdown(analysis)
        report_seconds = perf_counter() - report_start

        runs.append(
            {
                "parse_seconds": parse_seconds,
                "analyze_seconds": analyze_seconds,
                "report_prompt_seconds": report_seconds,
                "total_seconds": parse_seconds + analyze_seconds + report_seconds,
                "records_seen": parse_result.total_seen,
                "records_in_range": parse_result.total_in_range,
                "records_loaded": len(parse_result.records),
                "findings": len(analysis.get("findings", [])),
                "fallback_report_chars": len(fallback_report),
                "agent_prompt_chars": len(prompt),
            }
        )

    result = {
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": [str(path) for path in args.files],
        "iterations": len(runs),
        "runs": runs,
        "summary": _summary(runs),
    }

    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text, encoding="utf-8")
        print(args.json_out)
    else:
        print(text)
    return 0


def _summary(runs: list[dict[str, float]]) -> dict[str, float]:
    keys = ["parse_seconds", "analyze_seconds", "report_prompt_seconds", "total_seconds"]
    summary = {}
    for key in keys:
        values = [run[key] for run in runs]
        summary[f"{key}_avg"] = statistics.fmean(values)
        summary[f"{key}_max"] = max(values)
    return summary


if __name__ == "__main__":
    raise SystemExit(main())
