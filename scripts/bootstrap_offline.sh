#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-"$ROOT_DIR/.venv"}"
WHEELHOUSE="$ROOT_DIR/vendor/wheels"
REQUIREMENTS="$ROOT_DIR/requirements.offline.txt"
SHA_FILE="$WHEELHOUSE/SHA256SUMS"

for required in "$WHEELHOUSE" "$REQUIREMENTS" "$SHA_FILE"; do
  if [[ ! -e "$required" ]]; then
    echo "Missing offline installation input: $required" >&2
    exit 1
  fi
done

while read -r expected_hash file_name trailing; do
  if [[ -z "$expected_hash" ]]; then
    continue
  fi
  if [[ ! "$expected_hash" =~ ^[0-9A-Fa-f]{64}$ ]] \
    || [[ -z "$file_name" ]] \
    || [[ "$file_name" == */* ]] \
    || [[ "$file_name" != *.whl ]] \
    || [[ -n "${trailing:-}" ]]; then
    echo "Invalid wheel checksum entry: $expected_hash ${file_name:-} ${trailing:-}" >&2
    exit 1
  fi
done < "$SHA_FILE"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$WHEELHOUSE" && sha256sum -c SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$WHEELHOUSE" && shasum -a 256 -c SHA256SUMS)
else
  echo "Neither sha256sum nor shasum is available for wheel verification." >&2
  exit 1
fi

wheel_files=("$WHEELHOUSE"/*.whl)
if [[ ! -e "${wheel_files[0]}" ]]; then
  echo "No wheel files were found in: $WHEELHOUSE" >&2
  exit 1
fi
for wheel_path in "${wheel_files[@]}"; do
  wheel_name="$(basename "$wheel_path")"
  if ! awk 'NF {print $2}' "$SHA_FILE" | grep -Fqx -- "$wheel_name"; then
    echo "Wheel is not covered by SHA256SUMS: $wheel_name" >&2
    exit 1
  fi
done

"$PYTHON_BIN" -c 'import sys; sys.exit("Python 3.9 or newer is required.") if sys.version_info < (3, 9) else None'
"$PYTHON_BIN" -m venv "$VENV_DIR"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_NO_INDEX=1 \
  "$VENV_DIR/bin/python" -m pip install --no-index --find-links "$WHEELHOUSE" -r "$REQUIREMENTS"
PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PIP_NO_INDEX=1 \
  "$VENV_DIR/bin/python" -m pip check
"$VENV_DIR/bin/python" -I "$ROOT_DIR/tests/smoke_test.py"

echo "Offline bootstrap complete: $VENV_DIR"
