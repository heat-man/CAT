#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

VENV_DIR="$TMP_DIR/cat-offline-venv" "$ROOT_DIR/scripts/bootstrap_offline.sh"

echo "Offline install check passed"
