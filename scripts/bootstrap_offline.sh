#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-"$ROOT_DIR/.venv"}"
WHEELHOUSE="$ROOT_DIR/vendor/wheels"

if [[ ! -d "$WHEELHOUSE" ]]; then
  echo "Missing wheelhouse: $WHEELHOUSE" >&2
  exit 1
fi

if [[ -f "$WHEELHOUSE/SHA256SUMS" ]]; then
  (cd "$WHEELHOUSE" && sha256sum -c SHA256SUMS)
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --no-index --find-links "$WHEELHOUSE" -r "$ROOT_DIR/requirements.offline.txt"
"$VENV_DIR/bin/python" "$ROOT_DIR/tests/smoke_test.py"

echo "Offline bootstrap complete: $VENV_DIR"
