#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
VENV_DIR="${VENV_DIR:-"$ROOT_DIR/.venv"}"
export CAT_AGENT_BACKEND="${CAT_AGENT_BACKEND:-lmstudio}"

if [[ ! -x "$VENV_DIR/bin/python" ]] || ! "$VENV_DIR/bin/python" -c "import Evtx" >/dev/null 2>&1; then
  "$ROOT_DIR/scripts/bootstrap_offline.sh"
fi

exec "$VENV_DIR/bin/python" "$ROOT_DIR/run.py" --host "$HOST" --port "$PORT"
