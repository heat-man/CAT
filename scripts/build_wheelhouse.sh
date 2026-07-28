#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
WHEELHOUSE="$ROOT_DIR/vendor/wheels"
DOWNLOAD_DIR="$(mktemp -d)"
trap 'rm -rf "$DOWNLOAD_DIR"' EXIT

mkdir -p "$WHEELHOUSE"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 \
  "$PYTHON_BIN" -m pip download \
  --only-binary=:all: \
  --dest "$DOWNLOAD_DIR" \
  -r "$ROOT_DIR/requirements.offline.txt"

downloaded_wheels=("$DOWNLOAD_DIR"/*.whl)
if [[ ! -e "${downloaded_wheels[0]}" ]]; then
  echo "No binary wheels were downloaded." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$DOWNLOAD_DIR" && LC_ALL=C sha256sum *.whl > SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$DOWNLOAD_DIR" && LC_ALL=C shasum -a 256 *.whl > SHA256SUMS)
else
  echo "Neither sha256sum nor shasum is available to create SHA256SUMS." >&2
  exit 1
fi

# Download and hash the complete replacement set before touching the existing
# wheelhouse so removed requirements cannot leave stale wheels in a release.
existing_wheels=("$WHEELHOUSE"/*.whl)
if [[ -e "${existing_wheels[0]}" ]]; then
  for existing_wheel in "${existing_wheels[@]}"; do
    rm -f -- "$existing_wheel"
  done
fi
cp "${downloaded_wheels[@]}" "$WHEELHOUSE/"
cp "$DOWNLOAD_DIR/SHA256SUMS" "$WHEELHOUSE/SHA256SUMS"

echo "Wheelhouse updated: $WHEELHOUSE"
