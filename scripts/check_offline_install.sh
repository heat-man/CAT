#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PYTHONTZPATH="" \
PIP_NO_INDEX=1 \
VENV_DIR="$TMP_DIR/cat-offline-venv" \
  "$ROOT_DIR/scripts/bootstrap_offline.sh"

(
  cd "$ROOT_DIR"
  PYTHONTZPATH="" \
  PIP_NO_INDEX=1 \
  PYTHONDONTWRITEBYTECODE=1 \
    "$TMP_DIR/cat-offline-venv/bin/python" -m unittest discover -s tests -p "test_*.py"
)

echo "Offline install check passed"
