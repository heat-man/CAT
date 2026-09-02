from __future__ import annotations

from email import policy
from email.parser import BytesParser
import argparse
import ipaddress
import json
from math import isfinite
import mimetypes
import os
import socket
from time import perf_counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import tempfile
import threading
import uuid
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .analyzer import analyze_events
from .evtx_reader import XML_PARSE_TIMEOUT_SECONDS, parse_event_files
from .reporting import (
    DEFAULT_LM_MAX_FIELD_CHARS,
    DEFAULT_LM_MAX_INPUT_CHARS,
    DEFAULT_LM_MAX_RESPONSE_BYTES,
    DEFAULT_LM_MAX_TOKENS,
    DEFAULT_LM_STUDIO_URL,
    DEFAULT_LM_STRICT_VALIDATION,
    DEFAULT_LM_TIMEOUT_SECONDS,
    DEFAULT_MODEL,
    MAX_LM_EVIDENCE_PER_FINDING,
    MAX_LM_FINDINGS,
    MAX_LM_SCENARIO_CANDIDATES,
    MAX_LM_SUSPICIOUS_EVENTS,
    MAX_LM_TIMELINE_EVENTS,
    MAX_LM_TIMEOUT_SECONDS,
    generate_codex_dev_report,
    generate_report,
    generate_rule_report,
    normalize_chat_endpoint,
)
from .timeutil import get_timezone, parse_user_datetime


def _env_bounded_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        return default
    if not isfinite(value):
        return default
    return max(minimum, min(maximum, value))


def _env_bounded_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def _env_allowed_origins(name: str) -> set[tuple[str, str, int]]:
    origins: set[tuple[str, str, int]] = set()
    for item in os.getenv(name, "").split(","):
        value = item.strip()
        if not value:
            continue
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise RuntimeError(
                f"{name} origin은 http:// 또는 https://로 시작해야 합니다: {value!r}"
            )
        if not parsed.hostname:
            raise RuntimeError(f"{name} origin에 호스트가 없습니다: {value!r}")
        if parsed.username is not None or parsed.password is not None:
            raise RuntimeError(f"{name} origin에 사용자 정보를 포함할 수 없습니다: {value!r}")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise RuntimeError(
                f"{name}에는 경로가 없는 정확한 origin만 지정하세요: {value!r}"
            )
        try:
            port = parsed.port
        except ValueError as exc:
            raise RuntimeError(f"{name} origin 포트가 올바르지 않습니다: {value!r}") from exc
        if port is None:
            port = 80 if parsed.scheme.lower() == "http" else 443
        origins.add((parsed.scheme.lower(), parsed.hostname.lower(), port))
    return origins


PROJECT_ROOT = Path(__file__).resolve().parent.parent
STATIC_ROOT = PROJECT_ROOT / "static"
CAT_IMAGE_ROOT = PROJECT_ROOT / "images"
CAT_IMAGE_ASSETS = {
    "/asset/cat.jpg": CAT_IMAGE_ROOT / "cat.jpg",
    "/asset/cat_down.jpg": CAT_IMAGE_ROOT / "cat_down.jpg",
    "/asset/cat_dress.jpg": CAT_IMAGE_ROOT / "cat_dress.jpg",
    "/asset/cat_sleep.jpg": CAT_IMAGE_ROOT / "cat_sleep.jpg",
    "/asset/cat_sleep2.jpg": CAT_IMAGE_ROOT / "cat_sleep2.jpg",
}
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
MAX_FORM_FIELD_BYTES = 1024 * 1024
MAX_TOTAL_FORM_FIELD_BYTES = 2 * 1024 * 1024
MAX_MULTIPART_HEADER_BYTES = 64 * 1024
MAX_MULTIPART_PARTS = 300
MAX_UPLOAD_FILES = 256
DEFAULT_UPLOAD_TIMEOUT_SECONDS = _env_bounded_float(
    "CAT_UPLOAD_TIMEOUT_SECONDS",
    900.0,
    minimum=10.0,
    maximum=7200.0,
)
DEFAULT_HTTP_HEADER_TIMEOUT_SECONDS = _env_bounded_float(
    "CAT_HTTP_HEADER_TIMEOUT_SECONDS",
    15.0,
    minimum=1.0,
    maximum=120.0,
)
DEFAULT_RESPONSE_WRITE_TIMEOUT_SECONDS = _env_bounded_float(
    "CAT_RESPONSE_WRITE_TIMEOUT_SECONDS",
    60.0,
    minimum=1.0,
    maximum=600.0,
)
DEFAULT_MAX_CONNECTIONS = _env_bounded_int(
    "CAT_MAX_CONNECTIONS",
    32,
    minimum=1,
    maximum=1024,
)
DEFAULT_MAX_LARGE_RESPONSES = _env_bounded_int(
    "CAT_MAX_LARGE_RESPONSES",
    2,
    minimum=1,
    maximum=32,
)
DEFAULT_BIND_HOST = (
    (os.getenv("CAT_HOST") or os.getenv("HOST") or "0.0.0.0").strip()
    or "0.0.0.0"
)
DEFAULT_AGENT_BACKEND = os.getenv("CAT_AGENT_BACKEND", "lmstudio")
ALLOW_CUSTOM_LM_URL = os.getenv("CAT_ALLOW_CUSTOM_LM_URL", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
CUSTOM_LM_ALLOWED_ORIGINS = _env_allowed_origins("CAT_LM_ALLOWED_ORIGINS")
BROWSER_ALLOWED_ORIGINS = _env_allowed_origins("CAT_BROWSER_ALLOWED_ORIGINS")
CODEX_DEV_ENABLED = os.getenv("CAT_ENABLE_CODEX_DEV", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ANALYSIS_LOCK = threading.Lock()
UPLOAD_LOCK = threading.Lock()
LARGE_RESPONSE_SLOTS = threading.BoundedSemaphore(DEFAULT_MAX_LARGE_RESPONSES)


class RequestBodyTimeout(ValueError):
    pass


class CATRequestHandler(BaseHTTPRequestHandler):
    server_version = f"CAT/{__version__}"

    def setup(self) -> None:
        super().setup()
        self._header_timer_lock = threading.Lock()
        self._header_timer: threading.Timer | None = None
        self._reading_headers = False
        self._header_generation = 0

    def handle_one_request(self) -> None:
        self._begin_header_deadline()
        try:
            super().handle_one_request()
        finally:
            self._end_header_deadline()

    def parse_request(self) -> bool:
        try:
            return super().parse_request()
        finally:
            # The request line and all headers have now either been parsed or
            # rejected.  Upload bodies use their own absolute deadline.
            self._end_header_deadline()

    def _begin_header_deadline(self) -> None:
        with self._header_timer_lock:
            self._header_generation += 1
            generation = self._header_generation
            self._reading_headers = True
            timer = threading.Timer(
                DEFAULT_HTTP_HEADER_TIMEOUT_SECONDS,
                self._expire_header_read,
                args=(generation,),
            )
            timer.daemon = True
            self._header_timer = timer
        timer.start()

    def _end_header_deadline(self) -> None:
        timer: threading.Timer | None = None
        with self._header_timer_lock:
            if self._reading_headers:
                self._reading_headers = False
                timer = self._header_timer
                self._header_timer = None
        if timer is not None:
            timer.cancel()

    def _expire_header_read(self, generation: int) -> None:
        with self._header_timer_lock:
            if (
                not self._reading_headers
                or generation != self._header_generation
            ):
                return
            self._reading_headers = False
            self._header_timer = None
        self.close_connection = True
        try:
            # settimeout alone is a per-recv timeout and can be defeated by a
            # header drip.  Shutting down the read side from this absolute
            # deadline timer unblocks BufferedReader.readline immediately.
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self._serve_static(STATIC_ROOT / "index.html")
            return
        if self.path == "/api/health":
            self._json(
                {
                    "ok": True,
                    "name": "CAT",
                    "version": __version__,
                    "lm_studio_url": _configured_lm_endpoint(),
                    "default_model": DEFAULT_MODEL,
                    "default_agent_backend": _default_agent_backend(),
                    "available_agent_backends": _available_agent_backends(),
                    "allow_custom_lm_url": ALLOW_CUSTOM_LM_URL,
                    "custom_lm_allowed_origins": sorted(
                        _origin_text(origin) for origin in CUSTOM_LM_ALLOWED_ORIGINS
                    ),
                    "browser_allowed_origins": sorted(
                        _origin_text(origin) for origin in BROWSER_ALLOWED_ORIGINS
                    ),
                    "lm_strict_validation": DEFAULT_LM_STRICT_VALIDATION,
                    "lm_limits": {
                        "timeout_seconds": DEFAULT_LM_TIMEOUT_SECONDS,
                        "max_timeout_seconds": MAX_LM_TIMEOUT_SECONDS,
                        "max_tokens": DEFAULT_LM_MAX_TOKENS,
                        "max_response_bytes": DEFAULT_LM_MAX_RESPONSE_BYTES,
                        "max_input_chars": DEFAULT_LM_MAX_INPUT_CHARS,
                        "max_field_chars": DEFAULT_LM_MAX_FIELD_CHARS,
                        "max_findings": MAX_LM_FINDINGS,
                        "max_evidence_per_finding": MAX_LM_EVIDENCE_PER_FINDING,
                        "max_suspicious_events": MAX_LM_SUSPICIOUS_EVENTS,
                        "max_scenario_candidates": MAX_LM_SCENARIO_CANDIDATES,
                        "max_timeline_events": MAX_LM_TIMELINE_EVENTS,
                    },
                    "codex_dev_enabled": CODEX_DEV_ENABLED,
                    "max_upload_bytes": MAX_UPLOAD_BYTES,
                    "upload_timeout_seconds": DEFAULT_UPLOAD_TIMEOUT_SECONDS,
                    "xml_parse_timeout_seconds": XML_PARSE_TIMEOUT_SECONDS,
                    "http_header_timeout_seconds": DEFAULT_HTTP_HEADER_TIMEOUT_SECONDS,
                    "response_write_timeout_seconds": DEFAULT_RESPONSE_WRITE_TIMEOUT_SECONDS,
                    "max_connections": DEFAULT_MAX_CONNECTIONS,
                    "max_large_responses": DEFAULT_MAX_LARGE_RESPONSES,
                }
            )
            return
        asset_path = CAT_IMAGE_ASSETS.get(self.path.split("?", 1)[0])
        if asset_path is not None:
            self._serve_static(asset_path)
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
        if not _browser_request_origin_allowed(self.headers):
            self._error(
                HTTPStatus.FORBIDDEN,
                "다른 웹사이트에서 시작된 분석 요청은 허용되지 않습니다.",
            )
            return
        request_id = uuid.uuid4().hex[:8]
        request_start = perf_counter()
        checkpoint = request_start
        timings: dict[str, float] = {}
        analysis_lock_acquired = False
        large_response_slot_acquired = False
        upload_temp: tempfile.TemporaryDirectory[str] | None = None
        temp_dir_path: Path | None = None
        try:
            _stage_log(request_id, request_start, "request_start")
            if not LARGE_RESPONSE_SLOTS.acquire(blocking=False):
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "이전 대용량 분석 응답을 전송 중입니다. 잠시 후 다시 시도하세요.",
                )
                return
            large_response_slot_acquired = True
            # Reject before accepting a second potentially 512 MiB spool while
            # an existing upload is already being analyzed.
            if ANALYSIS_LOCK.locked():
                self._error(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "다른 분석이 진행 중입니다. 현재 분석을 종료하거나 완료 후 다시 실행하세요.",
                )
                return
            if not UPLOAD_LOCK.acquire(blocking=False):
                self.close_connection = True
                self._error(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "다른 업로드를 수신 중입니다. 완료 후 다시 실행하세요.",
                )
                return
            try:
                # Close the small race between the early check and acquiring
                # UPLOAD_LOCK.
                if ANALYSIS_LOCK.locked():
                    self._error(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        "다른 분석이 진행 중입니다. 현재 분석을 종료하거나 완료 후 다시 실행하세요.",
                    )
                    return
                upload_temp = tempfile.TemporaryDirectory(prefix="cat-upload-")
                temp_dir_path = Path(upload_temp.name)
                fields, files = self._parse_multipart(temp_dir_path)
                if files and not ANALYSIS_LOCK.acquire(blocking=False):
                    self._error(
                        HTTPStatus.TOO_MANY_REQUESTS,
                        "다른 분석이 진행 중입니다. 현재 분석을 종료하거나 완료 후 다시 실행하세요.",
                    )
                    return
                analysis_lock_acquired = bool(files)
            finally:
                UPLOAD_LOCK.release()
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
            lm_url = _resolve_lm_url(fields) if use_llm else None
            lm_model = _resolve_lm_model(fields) if use_llm else None

            saved_paths = [Path(item["path"]) for item in files]
            total_upload_bytes = sum(int(item["size"]) for item in files)
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
            elif agent_backend == "rule":
                report, llm_status = generate_rule_report(analysis)
            else:
                report, llm_status = generate_report(
                    analysis,
                    use_llm=use_llm,
                    lm_url=lm_url,
                    model=lm_model,
                )
                llm_status["backend"] = agent_backend
                llm_status["codex_review_required"] = False
            report_log_fields: dict[str, Any] = {
                "backend": agent_backend,
                "llm_used": llm_status.get("used"),
                "llm_error": bool(llm_status.get("error")),
            }
            if llm_status.get("timed_out") is True:
                # Log only the bounded diagnostics created by the LM timeout
                # path. Never serialize the request body, evidence, HTTP error
                # response, Authorization header, or API key.
                report_log_fields.update(
                    {
                        "lm_timed_out": True,
                        "lm_model": _safe_log_text(llm_status.get("timeout_model")),
                        "lm_input_chars": llm_status.get("timeout_input_chars"),
                        "lm_elapsed_seconds": llm_status.get("timeout_elapsed_seconds"),
                        "lm_endpoint": _safe_log_text(llm_status.get("timeout_endpoint")),
                    }
                )
            _mark_stage(
                request_id,
                request_start,
                checkpoint,
                timings,
                "report",
                **report_log_fields,
            )

            _cleanup_temp_context(
                request_id,
                request_start,
                upload_temp,
                temp_dir_path,
                "cleanup_uploads",
            )
            upload_temp = None
            temp_dir_path = None
            # Parsing, analysis and LM generation are complete.  Do not keep
            # the single-analysis lock while serializing or writing a possibly
            # large response to a slow/disconnected browser.
            ANALYSIS_LOCK.release()
            analysis_lock_acquired = False

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
        except RequestBodyTimeout as exc:
            self.close_connection = True
            _stage_log(request_id, request_start, "request_timeout", error=str(exc))
            self._error(HTTPStatus.REQUEST_TIMEOUT, str(exc))
        except ValueError as exc:
            _stage_log(request_id, request_start, "bad_request", error=str(exc))
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            _stage_log(request_id, request_start, "server_error", error=f"{type(exc).__name__}: {exc}")
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(exc).__name__}: {exc}")
        finally:
            if upload_temp is not None and temp_dir_path is not None:
                _cleanup_temp_context(
                    request_id,
                    request_start,
                    upload_temp,
                    temp_dir_path,
                    "cleanup_uploads",
                )
            if analysis_lock_acquired:
                ANALYSIS_LOCK.release()
            if large_response_slot_acquired:
                LARGE_RESPONSE_SLOTS.release()

    def _parse_multipart(
        self,
        temp_dir_path: Path,
    ) -> tuple[dict[str, str], list[dict[str, Any]]]:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("multipart/form-data 요청만 지원합니다.")
        content_headers = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\n\r\n".encode(
                "latin-1",
                errors="replace",
            )
        )
        boundary = content_headers.get_boundary()
        if not boundary:
            raise ValueError("multipart boundary가 없습니다.")
        try:
            boundary_bytes = boundary.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("multipart boundary가 올바르지 않습니다.") from exc
        if not boundary_bytes or len(boundary_bytes) > 200 or any(
            byte in boundary_bytes for byte in b"\r\n"
        ):
            raise ValueError("multipart boundary가 올바르지 않습니다.")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Content-Length가 올바르지 않습니다.") from exc
        if length <= 0:
            raise ValueError("요청 본문이 비어 있습니다.")
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("업로드 크기가 512MB 제한을 초과했습니다.")

        upload_deadline = perf_counter() + DEFAULT_UPLOAD_TIMEOUT_SECONDS
        raw_path = temp_dir_path / "request.multipart"
        with raw_path.open("wb") as destination:
            self._receive_request_body(
                length,
                destination,
                deadline=upload_deadline,
            )
        try:
            return _parse_multipart_file(
                raw_path,
                boundary_bytes,
                temp_dir_path,
                deadline=upload_deadline,
            )
        finally:
            raw_path.unlink(missing_ok=True)

    def _receive_request_body(
        self,
        length: int,
        destination: Any,
        *,
        deadline: float | None = None,
    ) -> None:
        request_deadline = (
            perf_counter() + DEFAULT_UPLOAD_TIMEOUT_SECONDS
            if deadline is None
            else deadline
        )
        remaining_bytes = length
        previous_timeout = self.connection.gettimeout()
        read_once = getattr(self.rfile, "read1", self.rfile.read)
        try:
            while remaining_bytes:
                remaining_seconds = request_deadline - perf_counter()
                if remaining_seconds <= 0:
                    raise RequestBodyTimeout(
                        "업로드가 전체 수신 시간 제한을 초과했습니다"
                        f"({DEFAULT_UPLOAD_TIMEOUT_SECONDS:g}초)."
                    )
                self.connection.settimeout(remaining_seconds)
                try:
                    chunk = read_once(min(64 * 1024, remaining_bytes))
                except (TimeoutError, socket.timeout) as exc:
                    raise RequestBodyTimeout(
                        "업로드가 전체 수신 시간 제한을 초과했습니다"
                        f"({DEFAULT_UPLOAD_TIMEOUT_SECONDS:g}초)."
                    ) from exc
                if not chunk:
                    raise ValueError(
                        "요청 본문이 Content-Length보다 짧게 전송되었습니다."
                    )
                destination.write(chunk)
                remaining_bytes -= len(chunk)
        finally:
            try:
                self.connection.settimeout(previous_timeout)
            except OSError:
                pass

    def _serve_static(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self._error(HTTPStatus.NOT_FOUND, "정적 파일을 찾을 수 없습니다.")
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        data = path.read_bytes()
        self._send_bytes(
            data,
            status=HTTPStatus.OK,
            content_type=content_type,
            extra_headers={"Cache-Control": "no-store"},
        )

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = _json_bytes(payload)
        self._send_bytes(
            data,
            status=status,
            content_type="application/json; charset=utf-8",
        )

    def _send_bytes(
        self,
        data: bytes,
        *,
        status: HTTPStatus,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> bool:
        previous_timeout = self.connection.gettimeout()
        try:
            # SocketWriter.write uses sendall; its socket timeout bounds the
            # complete send operation, preventing slow readers from retaining
            # arbitrarily many response threads and large serialized bodies.
            self.connection.settimeout(DEFAULT_RESPONSE_WRITE_TIMEOUT_SECONDS)
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)
            return True
        except OSError as exc:
            self.close_connection = True
            print(
                f"[CAT] response write aborted: {type(exc).__name__}: {exc}",
                flush=True,
            )
            return False
        finally:
            try:
                self.connection.settimeout(previous_timeout)
            except OSError:
                pass

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json({"ok": False, "error": message}, status=status)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[CAT] {self.address_string()} - {format % args}")


class CATHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._connection_slots = threading.BoundedSemaphore(DEFAULT_MAX_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


def _parse_multipart_file(
    raw_path: Path,
    boundary: bytes,
    temp_dir_path: Path,
    *,
    deadline: float | None = None,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    delimiter = b"--" + boundary
    fields: dict[str, str] = {}
    files: list[dict[str, Any]] = []
    total_field_bytes = 0
    with raw_path.open("rb") as source:
        if source.readline(MAX_MULTIPART_HEADER_BYTES + 1) not in {
            delimiter + b"\r\n",
            delimiter + b"\n",
        }:
            raise ValueError("multipart 시작 boundary가 올바르지 않습니다.")

        part_index = 0
        while True:
            part_index += 1
            if part_index > MAX_MULTIPART_PARTS:
                raise ValueError(
                    f"multipart part가 {MAX_MULTIPART_PARTS}개 제한을 초과했습니다."
                )
            _check_upload_deadline(deadline)
            part_headers = _read_multipart_headers(source)
            name = part_headers.get_param("name", header="content-disposition")
            filename = part_headers.get_filename()
            if part_headers.get_content_disposition() != "form-data" or not name:
                raise ValueError(
                    "multipart part의 Content-Disposition이 올바르지 않습니다."
                )

            if filename is not None:
                if len(files) >= MAX_UPLOAD_FILES:
                    raise ValueError(
                        f"업로드 파일이 {MAX_UPLOAD_FILES}개 제한을 초과했습니다."
                    )
                safe_name = _safe_filename(filename)
                part_path = temp_dir_path / f"{part_index:04d}_{safe_name}"
                with part_path.open("wb") as part_file:
                    part_size, final_boundary = _copy_multipart_part(
                        source,
                        delimiter,
                        part_file.write,
                        deadline=deadline,
                    )
                files.append(
                    {
                        "field": name,
                        "filename": filename,
                        "path": part_path,
                        "size": part_size,
                    }
                )
            else:
                field_data = bytearray()

                def append_field(chunk: bytes) -> int:
                    if len(field_data) + len(chunk) > MAX_FORM_FIELD_BYTES:
                        raise ValueError(
                            "multipart 텍스트 필드가 1MB 제한을 초과했습니다."
                        )
                    field_data.extend(chunk)
                    return len(chunk)

                _, final_boundary = _copy_multipart_part(
                    source,
                    delimiter,
                    append_field,
                    deadline=deadline,
                )
                total_field_bytes += len(field_data)
                if total_field_bytes > MAX_TOTAL_FORM_FIELD_BYTES:
                    raise ValueError(
                        "multipart 텍스트 필드 총량이 2MB 제한을 초과했습니다."
                    )
                charset = part_headers.get_content_charset() or "utf-8"
                fields[name] = bytes(field_data).decode(charset, errors="replace")

            if final_boundary:
                break
    return fields, files


def _read_multipart_headers(source: Any) -> Any:
    lines: list[bytes] = []
    total = 0
    while True:
        line = source.readline(MAX_MULTIPART_HEADER_BYTES + 1)
        if not line:
            raise ValueError("multipart header가 끝나기 전에 본문이 종료되었습니다.")
        total += len(line)
        if total > MAX_MULTIPART_HEADER_BYTES:
            raise ValueError("multipart header가 64KB 제한을 초과했습니다.")
        if line in {b"\r\n", b"\n"}:
            break
        lines.append(line)
    return BytesParser(policy=policy.default).parsebytes(b"".join(lines) + b"\r\n")


def _copy_multipart_part(
    source: Any,
    delimiter: bytes,
    write_chunk: Any,
    *,
    deadline: float | None = None,
) -> tuple[int, bool]:
    normal_boundaries = {delimiter + b"\r\n", delimiter + b"\n"}
    final_boundaries = {
        delimiter + b"--",
        delimiter + b"--\r\n",
        delimiter + b"--\n",
    }
    pending: bytes | None = None
    written = 0
    while True:
        _check_upload_deadline(deadline)
        line = source.readline(64 * 1024)
        if not line:
            raise ValueError("multipart part가 끝나기 전에 본문이 종료되었습니다.")
        # A size-limited readline can split the separator CRLF into a trailing
        # CR and a one-byte LF read.  Keep both pending until we know whether
        # the following line is the MIME boundary; otherwise the CR would be
        # incorrectly appended to an exact-size file payload.
        if pending is not None and pending.endswith(b"\r") and line == b"\n":
            pending += line
            continue
        is_normal = line in normal_boundaries
        is_final = line in final_boundaries
        if is_normal or is_final:
            if pending is not None:
                if pending.endswith(b"\r\n"):
                    pending = pending[:-2]
                elif pending.endswith(b"\n"):
                    pending = pending[:-1]
                write_chunk(pending)
                written += len(pending)
            return written, is_final
        if pending is not None:
            write_chunk(pending)
            written += len(pending)
        pending = line


def _check_upload_deadline(deadline: float | None) -> None:
    if deadline is not None and perf_counter() >= deadline:
        raise RequestBodyTimeout(
            "업로드 수신 및 multipart 처리가 전체 시간 제한을 초과했습니다"
            f"({DEFAULT_UPLOAD_TIMEOUT_SECONDS:g}초)."
        )


def _json_bytes(payload: dict[str, Any]) -> bytes:
    # Escaping non-ASCII also makes otherwise valid JSON strings containing a
    # lone UTF-16 surrogate safe to send over UTF-8. Browsers decode the JSON
    # escapes back to their original Unicode values.  Non-finite numbers are
    # normalized to null because browser JSON.parse rejects JavaScript's bare
    # NaN/Infinity spellings.
    return json.dumps(
        _json_safe_value(payload),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, float) and not isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe_value(item) for item in value]
    return value


def _browser_request_origin_allowed(headers: Any) -> bool:
    fetch_site = str(headers.get("Sec-Fetch-Site") or "").strip().lower()
    if fetch_site == "cross-site":
        return False

    origin = str(headers.get("Origin") or "").strip()
    if not origin:
        # Preserve CLI/API clients that do not identify a browser origin.
        return True
    if origin == "null":
        return False

    host_header = str(headers.get("Host") or "").strip()
    if not host_header:
        return False
    try:
        origin_parts = urlsplit(origin)
        host_parts = urlsplit(f"//{host_header}")
        origin_port = origin_parts.port
        host_port = host_parts.port
    except ValueError:
        return False
    if (
        origin_parts.scheme.lower() not in {"http", "https"}
        or not origin_parts.hostname
        or not host_parts.hostname
        or origin_parts.username is not None
        or origin_parts.password is not None
        or host_parts.username is not None
        or host_parts.password is not None
        or origin_parts.path not in {"", "/"}
        or origin_parts.query
        or origin_parts.fragment
    ):
        return False
    origin_effective_port = origin_port or (
        80 if origin_parts.scheme.lower() == "http" else 443
    )
    origin_key = (
        origin_parts.scheme.lower(),
        origin_parts.hostname.lower(),
        origin_effective_port,
    )
    if BROWSER_ALLOWED_ORIGINS:
        # A TLS-terminating reverse proxy must opt in to its exact public
        # origin. Once configured, do not fall back to Host-derived matching.
        return origin_key in BROWSER_ALLOWED_ORIGINS
    if origin_parts.scheme.lower() != "http":
        # CAT's built-in server is HTTP. HTTPS origins are valid only through
        # an explicitly configured reverse-proxy public origin above.
        return False
    if origin_parts.hostname.lower() != host_parts.hostname.lower():
        return False
    host_effective_port = host_port or 80
    return origin_effective_port == host_effective_port


def run(host: str = DEFAULT_BIND_HOST, port: int = 8000) -> None:
    httpd = CATHTTPServer((host, port), CATRequestHandler)
    if host in {"0.0.0.0", ""}:
        print(f"CAT web interface (local): http://127.0.0.1:{port}")
        print(f"CAT web interface (VM/LAN): http://192.168.100.1:{port}")
        print("CAT is listening on all IPv4 interfaces (0.0.0.0).", flush=True)
    else:
        print(f"CAT web interface: http://{host}:{port}", flush=True)
    httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="CAT - Cyber Activity Tracker")
    parser.add_argument("--host", default=DEFAULT_BIND_HOST)
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


def _safe_log_text(value: Any, maximum: int = 512) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "")[:maximum]
    # JSON quoting keeps control characters from creating forged log lines.
    return json.dumps(text, ensure_ascii=False)


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


def _agent_backend(fields: dict[str, str]) -> str:
    backend = fields.get("agent_backend")
    if not backend:
        legacy_use_llm = fields.get("use_llm")
        if legacy_use_llm is not None:
            backend = "lmstudio" if legacy_use_llm.lower() in {"1", "true", "yes", "on"} else "rule"
        else:
            backend = _default_agent_backend()
    if backend == "codex_dev":
        if not CODEX_DEV_ENABLED:
            raise ValueError(
                "Codex 개발 검증 backend는 운영 모드에서 비활성화되어 있습니다. "
                "개발 환경에서만 CAT_ENABLE_CODEX_DEV=true로 허용하세요."
            )
        return backend
    if backend in {"lmstudio", "rule"}:
        return backend
    return _default_agent_backend()


def _available_agent_backends() -> list[str]:
    backends = ["lmstudio", "rule"]
    if CODEX_DEV_ENABLED:
        backends.insert(1, "codex_dev")
    return backends


def _default_agent_backend() -> str:
    if DEFAULT_AGENT_BACKEND == "codex_dev":
        return "codex_dev" if CODEX_DEV_ENABLED else "lmstudio"
    if DEFAULT_AGENT_BACKEND in {"lmstudio", "rule"}:
        return DEFAULT_AGENT_BACKEND
    return "lmstudio"


def _configured_lm_endpoint() -> str:
    return normalize_chat_endpoint(DEFAULT_LM_STUDIO_URL)


def _resolve_lm_url(fields: dict[str, str]) -> str:
    configured = _configured_lm_endpoint()
    submitted = fields.get("lm_url", "").strip()
    if not submitted:
        return configured

    requested = normalize_chat_endpoint(submitted)
    if not ALLOW_CUSTOM_LM_URL and _canonical_endpoint(requested) != _canonical_endpoint(configured):
        raise ValueError(
            "운영 모드에서는 서버에 설정된 LM Studio URL만 사용할 수 있습니다. "
            "주소 변경이 필요하면 CAT_ALLOW_CUSTOM_LM_URL=true로 설정하세요."
        )
    requested_origin = _endpoint_origin(requested)
    if (
        _canonical_endpoint(requested) != _canonical_endpoint(configured)
        and not _custom_lm_origin_allowed(requested_origin)
    ):
        raise ValueError(
            "사용자 지정 LM Studio endpoint는 포트 1234의 loopback 주소 또는 "
            "CAT_LM_ALLOWED_ORIGINS에 지정한 정확한 origin이어야 합니다: "
            f"{_origin_text(requested_origin)}"
        )
    return requested


def _custom_lm_origin_allowed(origin: tuple[str, str, int]) -> bool:
    if origin in CUSTOM_LM_ALLOWED_ORIGINS:
        return True
    _, host, port = origin
    if port != 1234:
        return False
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Classify IPv4-mapped IPv6 by its embedded IPv4 address.  Otherwise
    # ipaddress considers ::ffff:169.254.169.254 private even though the target
    # is the link-local metadata range that CAT explicitly blocks.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_link_local or address.is_multicast or address.is_unspecified:
        return False
    # The configured LM_STUDIO_URL is always accepted by _resolve_lm_url.
    # Additional destinations require an exact scheme/host/port origin so an
    # unauthenticated LAN browser cannot combine separately trusted hosts and
    # ports into a new private-network probe target.
    return address.is_loopback


def _endpoint_origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme.lower() == "http" else 443
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _origin_text(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    display_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{display_host}:{port}"


def _resolve_lm_model(fields: dict[str, str]) -> str:
    model = (fields.get("lm_model") or DEFAULT_MODEL).strip()
    if not model:
        raise ValueError("LM Studio 모델 ID가 비어 있습니다.")
    if len(model) > 256 or any(ord(character) < 32 for character in model):
        raise ValueError("LM Studio 모델 ID가 올바르지 않습니다.")
    return model


def _canonical_endpoint(value: str) -> tuple[str, str, int | None, str]:
    parsed = urlsplit(normalize_chat_endpoint(value))
    port = parsed.port
    if port is None:
        port = 80 if parsed.scheme == "http" else 443
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port, parsed.path


def _existing_asset(*names: str) -> Path:
    for name in names:
        path = PROJECT_ROOT / name
        if path.exists() and path.is_file():
            return path
    return PROJECT_ROOT / names[0]


if __name__ == "__main__":
    main()
