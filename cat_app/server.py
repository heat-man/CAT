from __future__ import annotations

from email import policy
from email.parser import BytesParser
import argparse
import json
import mimetypes
import os
import shutil
from time import perf_counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import tempfile
import threading
import uuid
from typing import Any

from .analyzer import analyze_events
from .evtx_reader import parse_event_files
from .reporting import (
    DEFAULT_LM_STUDIO_URL,
    DEFAULT_MODEL,
    generate_codex_dev_report,
    generate_report,
)
from .timeutil import get_timezone, parse_user_datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_ROOT = PROJECT_ROOT / "static"
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
DEFAULT_AGENT_BACKEND = os.getenv("CAT_AGENT_BACKEND", "lmstudio")
ANALYSIS_LOCK = threading.Lock()


class CATRequestHandler(BaseHTTPRequestHandler):
    server_version = "CAT/0.1"

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self._serve_static(STATIC_ROOT / "index.html")
            return
        if self.path == "/api/health":
            self._json(
                {
                    "ok": True,
                    "name": "CAT",
                    "lm_studio_url": DEFAULT_LM_STUDIO_URL,
                    "default_model": DEFAULT_MODEL,
                    "default_agent_backend": DEFAULT_AGENT_BACKEND,
                    "max_upload_bytes": MAX_UPLOAD_BYTES,
                }
            )
            return
        if self.path.split("?", 1)[0] == "/asset/cat.jpg":
            self._serve_static(PROJECT_ROOT / "cat.jpg")
            return
        if self.path.split("?", 1)[0] in {"/asset/nyan_cat.gif", "/asset/nyan-cat.gif"}:
            self._serve_static(_existing_asset("nyan_cat.gif", "nyan-cat.gif"))
            return
        if self.path.startswith("/static/"):
            relative = self.path.removeprefix("/static/").split("?", 1)[0]
            target = (STATIC_ROOT / relative).resolve()
            if STATIC_ROOT.resolve() not in target.parents and target != STATIC_ROOT.resolve():
                self._error(HTTPStatus.FORBIDDEN, "잘못된 정적 파일 경로입니다.")
                return
            self._serve_static(target)
            return
        self._error(HTTPStatus.NOT_FOUND, "요청한 경로를 찾을 수 없습니다.")

    def do_POST(self) -> None:
        if self.path != "/api/analyze":
            self._error(HTTPStatus.NOT_FOUND, "요청한 경로를 찾을 수 없습니다.")
            return
        if not ANALYSIS_LOCK.acquire(blocking=False):
            self._error(HTTPStatus.TOO_MANY_REQUESTS, "다른 분석이 진행 중입니다. 현재 분석을 종료하거나 완료 후 다시 실행하세요.")
            return
        request_id = uuid.uuid4().hex[:8]
        request_start = perf_counter()
        checkpoint = request_start
        timings: dict[str, float] = {}
        try:
            _stage_log(request_id, request_start, "request_start")
            fields, files = self._parse_multipart()
            checkpoint = _mark_stage(request_id, request_start, checkpoint, timings, "multipart")
            if not files:
                self._error(HTTPStatus.BAD_REQUEST, "EVTX 또는 XML 파일을 하나 이상 업로드하세요.")
                return

            timezone_name = fields.get("timezone", "Asia/Seoul")
            tz = get_timezone(timezone_name)
            if not fields.get("start_time") or not fields.get("end_time"):
                self._error(HTTPStatus.BAD_REQUEST, "분석 제한: 시작 시간과 종료 시간을 모두 입력하세요.")
                return
            start_utc = parse_user_datetime(fields.get("start_time"), tz)
            end_utc = parse_user_datetime(fields.get("end_time"), tz)
            if start_utc and end_utc and start_utc > end_utc:
                self._error(HTTPStatus.BAD_REQUEST, "분석 시작 시간이 종료 시간보다 늦습니다.")
                return

            max_records = _bounded_int(fields.get("max_records"), default=20000, minimum=100, maximum=200000)
            agent_backend = _agent_backend(fields)
            use_llm = agent_backend == "lmstudio"

            upload_temp = tempfile.TemporaryDirectory(prefix="cat-upload-")
            temp_dir_path = Path(upload_temp.name)
            try:
                saved_paths = []
                for index, item in enumerate(files, start=1):
                    filename = _safe_filename(item["filename"])
                    path = temp_dir_path / f"{index:04d}_{filename}"
                    path.write_bytes(item["content"])
                    saved_paths.append(path)
                total_upload_bytes = sum(len(item["content"]) for item in files)
                files.clear()
                checkpoint = _mark_stage(
                    request_id,
                    request_start,
                    checkpoint,
                    timings,
                    "save_uploads",
                    files=len(saved_paths),
                    bytes=total_upload_bytes,
                )

                parse_result = parse_event_files(saved_paths, start_utc, end_utc, max_records)
                checkpoint = _mark_stage(
                    request_id,
                    request_start,
                    checkpoint,
                    timings,
                    "parse",
                    records_loaded=len(parse_result.records),
                    records_seen=parse_result.total_seen,
                    records_in_range=parse_result.total_in_range,
                    errors=len(parse_result.errors),
                    truncated=parse_result.truncated,
                )
                if not parse_result.records and parse_result.errors:
                    self._json(
                        {
                            "ok": False,
                            "error": "분석 가능한 이벤트를 읽지 못했습니다.",
                            "parser": parse_result.to_dict(),
                            "timings": _rounded_timings(timings, request_start),
                        },
                        status=HTTPStatus.UNPROCESSABLE_ENTITY,
                    )
                    return

                analysis = analyze_events(parse_result, start_utc, end_utc)
                checkpoint = _mark_stage(
                    request_id,
                    request_start,
                    checkpoint,
                    timings,
                    "analyze",
                    findings=len(analysis.get("findings", [])),
                )
                if agent_backend == "codex_dev":
                    report, llm_status = generate_codex_dev_report(analysis)
                else:
                    report, llm_status = generate_report(
                        analysis,
                        use_llm=use_llm,
                        lm_url=fields.get("lm_url"),
                        model=fields.get("lm_model"),
                    )
                    llm_status["backend"] = agent_backend
                    llm_status["codex_review_required"] = False
                _mark_stage(
                    request_id,
                    request_start,
                    checkpoint,
                    timings,
                    "report",
                    backend=agent_backend,
                    llm_used=llm_status.get("used"),
                    llm_error=bool(llm_status.get("error")),
                )
            finally:
                _cleanup_temp_context(request_id, request_start, upload_temp, temp_dir_path, "cleanup_uploads")

            self._json(
                {
                    "ok": True,
                    "report_markdown": report,
                    "analysis": analysis,
                    "llm": llm_status,
                    "timings": _rounded_timings(timings, request_start),
                }
            )
            _stage_log(request_id, request_start, "response_sent")
        except ValueError as exc:
            _stage_log(request_id, request_start, "bad_request", error=str(exc))
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            _stage_log(request_id, request_start, "server_error", error=f"{type(exc).__name__}: {exc}")
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")
        finally:
            ANALYSIS_LOCK.release()

    def _parse_multipart(self) -> tuple[dict[str, str], list[dict[str, Any]]]:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("multipart/form-data 요청만 지원합니다.")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("요청 본문이 비어 있습니다.")
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("업로드 크기가 512MB 제한을 초과했습니다.")

        body = self.rfile.read(length)
        message_bytes = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
        )
        message = BytesParser(policy=policy.default).parsebytes(message_bytes)

        fields: dict[str, str] = {}
        files: list[dict[str, Any]] = []
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            filename = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if not name:
                continue
            if filename:
                files.append({"field": name, "filename": filename, "content": payload})
            else:
                charset = part.get_content_charset() or "utf-8"
                fields[name] = payload.decode(charset, errors="replace")
        return fields, files

    def _serve_static(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self._error(HTTPStatus.NOT_FOUND, "정적 파일을 찾을 수 없습니다.")
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json({"ok": False, "error": message}, status=status)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[CAT] {self.address_string()} - {format % args}")


class CATHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    _cleanup_stale_temp_dirs("startup")
    httpd = CATHTTPServer((host, port), CATRequestHandler)
    print(f"CAT web interface: http://{host}:{port}")
    httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="CAT - Cyber Activity Tracker")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run(args.host, args.port)


def _safe_filename(value: str) -> str:
    name = Path(value).name.strip() or "upload.evtx"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def _bounded_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    if not value:
        return default
    number = int(value)
    if number < minimum:
        return minimum
    if number > maximum:
        return maximum
    return number


def _mark_stage(
    request_id: str,
    request_start: float,
    checkpoint: float,
    timings: dict[str, float],
    stage: str,
    **fields: Any,
) -> float:
    now = perf_counter()
    timings[f"{stage}_seconds"] = now - checkpoint
    _stage_log(request_id, request_start, stage, phase_seconds=timings[f"{stage}_seconds"], **fields)
    return now


def _stage_log(request_id: str, request_start: float, stage: str, **fields: Any) -> None:
    elapsed = perf_counter() - request_start
    details = " ".join(f"{key}={value}" for key, value in fields.items())
    suffix = f" {details}" if details else ""
    print(f"[CAT][{request_id}] {stage} elapsed={elapsed:.1f}s{suffix}", flush=True)


def _rounded_timings(timings: dict[str, float], request_start: float) -> dict[str, float]:
    data = {key: round(value, 3) for key, value in timings.items()}
    data["total_seconds"] = round(perf_counter() - request_start, 3)
    return data


def _cleanup_temp_context(
    request_id: str,
    request_start: float,
    temp_context: tempfile.TemporaryDirectory[str],
    temp_path: Path,
    stage: str,
) -> None:
    try:
        temp_context.cleanup()
        _stage_log(request_id, request_start, stage, temp_dir=temp_path.name, removed=not temp_path.exists())
    except Exception as exc:
        _stage_log(request_id, request_start, stage, temp_dir=temp_path.name, error=f"{type(exc).__name__}: {exc}")


def _cleanup_stale_temp_dirs(reason: str) -> None:
    temp_root = Path(tempfile.gettempdir())
    removed = 0
    for pattern in ("cat-upload-*", "cat-codex-*"):
        for path in temp_root.glob(pattern):
            if path.is_symlink() or not path.is_dir():
                continue
            try:
                shutil.rmtree(path)
                removed += 1
                print(f"[CAT] cleanup_stale_temp reason={reason} path={path}", flush=True)
            except Exception as exc:
                print(f"[CAT] cleanup_stale_temp_failed reason={reason} path={path} error={type(exc).__name__}: {exc}", flush=True)
    if removed:
        print(f"[CAT] cleanup_stale_temp_done reason={reason} removed={removed}", flush=True)


def _agent_backend(fields: dict[str, str]) -> str:
    backend = fields.get("agent_backend")
    if not backend:
        legacy_use_llm = fields.get("use_llm")
        if legacy_use_llm is not None:
            backend = "lmstudio" if legacy_use_llm.lower() in {"1", "true", "yes", "on"} else "rule"
        else:
            backend = DEFAULT_AGENT_BACKEND
    if backend in {"codex_dev", "lmstudio", "rule"}:
        return backend
    if DEFAULT_AGENT_BACKEND in {"codex_dev", "lmstudio", "rule"}:
        return DEFAULT_AGENT_BACKEND
    return "lmstudio"


def _existing_asset(*names: str) -> Path:
    for name in names:
        path = PROJECT_ROOT / name
        if path.exists() and path.is_file():
            return path
    return PROJECT_ROOT / names[0]


if __name__ == "__main__":
    main()
