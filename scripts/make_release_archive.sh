#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-$(date +%Y%m%d%H%M%S)}"
OUT_DIR="$ROOT_DIR/dist"
OUT_FILE="$OUT_DIR/cat-$VERSION.tar.gz"

mkdir -p "$OUT_DIR"
tar \
  --exclude=".venv" \
  --exclude="__pycache__" \
  --exclude=".pytest_cache" \
  --exclude=".ruff_cache" \
  --exclude=".mypy_cache" \
  --exclude="dist" \
  --exclude=".git" \
  -czf "$OUT_FILE" \
  -C "$ROOT_DIR" .

echo "$OUT_FILE"
