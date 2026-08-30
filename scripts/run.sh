#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIND_HOST="${CAT_HOST:-${HOST:-0.0.0.0}}"
PORT="${PORT:-8000}"
VENV_DIR="${VENV_DIR:-"$ROOT_DIR/.venv"}"
export CAT_AGENT_BACKEND="${CAT_AGENT_BACKEND:-lmstudio}"

RUNTIME_PROBE='
import sys
from importlib.metadata import version
from zoneinfo import ZoneInfo
from Evtx.Evtx import Evtx
import tzdata

if sys.version_info < (3, 9):
    raise SystemExit(1)
if version("hexdump") != "3.3":
    raise SystemExit(1)
if version("python-evtx") != "0.8.1":
    raise SystemExit(1)
if version("tzdata") != "2026.3":
    raise SystemExit(1)
ZoneInfo("Asia/Seoul")
'
if [[ ! -x "$VENV_DIR/bin/python" ]] \
  || ! "$VENV_DIR/bin/python" -c "$RUNTIME_PROBE" >/dev/null 2>&1; then
  VENV_DIR="$VENV_DIR" "$ROOT_DIR/scripts/bootstrap_offline.sh"
fi

exec "$VENV_DIR/bin/python" "$ROOT_DIR/run.py" --host "$BIND_HOST" --port "$PORT"
