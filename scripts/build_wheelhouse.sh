#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
WHEELHOUSE="$ROOT_DIR/vendor/wheels"

mkdir -p "$WHEELHOUSE"
"$PYTHON_BIN" -m pip wheel --wheel-dir "$WHEELHOUSE" -r "$ROOT_DIR/requirements.offline.txt"
(cd "$WHEELHOUSE" && sha256sum *.whl > SHA256SUMS)

echo "Wheelhouse updated: $WHEELHOUSE"
