#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OUT_DIR="${OUT_DIR:-"$ROOT_DIR/dist"}"
REQUIRE_CLEAN="${REQUIRE_CLEAN:-0}"

"$PYTHON_BIN" -c \
  'import sys; sys.exit("Python 3.9 or newer is required to build a release.") if sys.version_info < (3, 9) else None'

APP_VERSION="$(
  PYTHONPATH="$ROOT_DIR" "$PYTHON_BIN" -c \
    'from cat_app import __version__; print(__version__)'
)"
VERSION="${VERSION:-$APP_VERSION}"
if [[ ! "$APP_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "cat_app.__version__ contains unsafe release characters: $APP_VERSION" >&2
  exit 1
fi
if [[ ! "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  echo "VERSION must contain only letters, digits, dot, underscore, and hyphen: $VERSION" >&2
  exit 1
fi

REQUESTED_GIT_COMMIT="${GIT_COMMIT:-}"
GIT_COMMIT="unavailable"
GIT_DIRTY="unknown"
if command -v git >/dev/null 2>&1 && git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  GIT_COMMIT="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  if [[ -n "$REQUESTED_GIT_COMMIT" && "$REQUESTED_GIT_COMMIT" != "$GIT_COMMIT" ]]; then
    echo "GIT_COMMIT override does not match the current Git HEAD." >&2
    exit 1
  fi
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=normal)" ]]; then
    GIT_DIRTY="true"
  else
    GIT_DIRTY="false"
  fi
elif [[ -n "$REQUESTED_GIT_COMMIT" ]]; then
  GIT_COMMIT="$REQUESTED_GIT_COMMIT"
fi
if [[ "$GIT_COMMIT" != "unavailable" && ! "$GIT_COMMIT" =~ ^[0-9A-Fa-f]{40}$ && ! "$GIT_COMMIT" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  echo "GIT_COMMIT must be unavailable or a full 40/64-character hexadecimal commit ID." >&2
  exit 1
fi
if [[ "$GIT_COMMIT" != "unavailable" ]]; then
  GIT_COMMIT="$(printf '%s' "$GIT_COMMIT" | tr '[:upper:]' '[:lower:]')"
fi
if [[ "$REQUIRE_CLEAN" == "1" && "$GIT_DIRTY" != "false" ]]; then
  echo "A clean Git worktree is required when REQUIRE_CLEAN=1 (git_dirty=$GIT_DIRTY)." >&2
  exit 1
fi
if [[ "$GIT_DIRTY" == "true" || "$GIT_DIRTY" == "false" ]]; then
  GIT_DIRTY_JSON="$GIT_DIRTY"
else
  GIT_DIRTY_JSON="null"
fi

SHORT_COMMIT="${GIT_COMMIT:0:12}"
if [[ "$GIT_COMMIT" == "unavailable" ]]; then
  SHORT_COMMIT="nogit"
fi
RELEASE_TAG="$VERSION-$SHORT_COMMIT"
if [[ "$GIT_DIRTY" != "false" ]]; then
  RELEASE_TAG="$RELEASE_TAG-dirty"
fi
PACKAGE_ROOT="cat-$RELEASE_TAG"

CREATED_UTC="$(
  "$PYTHON_BIN" -c \
    'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))'
)"

if command -v sha256sum >/dev/null 2>&1; then
  HASH_COMMAND=(sha256sum)
elif command -v shasum >/dev/null 2>&1; then
  HASH_COMMAND=(shasum -a 256)
else
  echo "Neither sha256sum nor shasum is available." >&2
  exit 1
fi

hash_file() {
  "${HASH_COMMAND[@]}" "$1" | awk '{print tolower($1)}'
}

WHEELHOUSE="$ROOT_DIR/vendor/wheels"
WHEEL_MANIFEST="$WHEELHOUSE/SHA256SUMS"
if [[ ! -f "$WHEEL_MANIFEST" ]]; then
  echo "Missing required wheel manifest: $WHEEL_MANIFEST" >&2
  exit 1
fi
if [[ "${HASH_COMMAND[0]}" == "sha256sum" ]]; then
  (cd "$WHEELHOUSE" && sha256sum -c SHA256SUMS)
else
  (cd "$WHEELHOUSE" && shasum -a 256 -c SHA256SUMS)
fi

mkdir -p "$OUT_DIR"
BUILD_DIR="$(mktemp -d "$OUT_DIR/.cat-release-build.XXXXXX")"
trap 'rm -rf "$BUILD_DIR"' EXIT
STAGE_ROOT="$BUILD_DIR/stage"
PACKAGE_DIR="$STAGE_ROOT/$PACKAGE_ROOT"
mkdir -p "$PACKAGE_DIR"

RELEASE_FILES=(
  "README.md"
  "cat_app/__init__.py"
  "cat_app/analyzer.py"
  "cat_app/evtx_reader.py"
  "cat_app/models.py"
  "cat_app/reporting.py"
  "cat_app/server.py"
  "cat_app/timeutil.py"
  "docs/AGENT_BACKEND.md"
  "docs/AIRGAP.md"
  "images/cat.jpg"
  "images/cat_down.jpg"
  "images/cat_dress.jpg"
  "images/cat_sleep.jpg"
  "images/cat_sleep2.jpg"
  "nyan-cat.gif"
  "requirements.offline.txt"
  "requirements.txt"
  "run.py"
  "scripts/bootstrap_offline.ps1"
  "scripts/bootstrap_offline.sh"
  "scripts/check_lmstudio.py"
  "scripts/run.ps1"
  "scripts/run.sh"
  "scripts/verify_release_package.py"
  "static/app.js"
  "static/index.html"
  "static/styles.css"
  "tests/fixtures/README.md"
  "tests/fixtures/issue_38.evtx"
  "tests/sample_events.xml"
  "tests/smoke_test.py"
  "vendor/wheels/SHA256SUMS"
  "vendor/wheels/hexdump-3.3-py3-none-any.whl"
  "vendor/wheels/python_evtx-0.8.1-py3-none-any.whl"
  "vendor/wheels/tzdata-2026.3-py2.py3-none-any.whl"
)

FILES_LIST="$BUILD_DIR/release-files.txt"
for relative in "${RELEASE_FILES[@]}"; do
  source="$ROOT_DIR/$relative"
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "Missing or non-regular required release file: $relative" >&2
    exit 1
  fi
  case "/$relative/" in
    */.agents/*|*/.codex/*|*/.git/*|*/.venv/*|*/__pycache__/*|*/dist/*|*/reports/*)
      echo "Banned path matched the release allowlist: $relative" >&2
      exit 1
      ;;
  esac
  lower_relative="$(printf '%s' "$relative" | tr '[:upper:]' '[:lower:]')"
  if [[ "$relative" == *:* || "$lower_relative" == *zone.identifier* ]]; then
    echo "Windows-incompatible path matched the release allowlist: $relative" >&2
    exit 1
  fi
  printf '%s\n' "$relative"
done > "$FILES_LIST"

ACTUAL_WHEELS="$BUILD_DIR/actual-wheels.txt"
MANIFEST_WHEELS="$BUILD_DIR/manifest-wheels.txt"
PACKAGED_WHEELS="$BUILD_DIR/packaged-wheels.txt"
for wheel_path in "$WHEELHOUSE"/*.whl; do
  if [[ -f "$wheel_path" ]]; then
    basename "$wheel_path"
  fi
done | LC_ALL=C sort -u > "$ACTUAL_WHEELS"
awk 'NF {print $2}' "$WHEEL_MANIFEST" | LC_ALL=C sort -u > "$MANIFEST_WHEELS"
if ! cmp -s "$ACTUAL_WHEELS" "$MANIFEST_WHEELS"; then
  echo "vendor/wheels/SHA256SUMS must list every and only source wheel:" >&2
  diff -u "$MANIFEST_WHEELS" "$ACTUAL_WHEELS" >&2 || true
  exit 1
fi
for relative in "${RELEASE_FILES[@]}"; do
  case "$relative" in
    vendor/wheels/*.whl)
      basename "$relative"
      ;;
  esac
done | LC_ALL=C sort -u > "$PACKAGED_WHEELS"
if ! cmp -s "$PACKAGED_WHEELS" "$MANIFEST_WHEELS"; then
  echo "Release allowlist must package every and only checksummed wheel:" >&2
  diff -u "$MANIFEST_WHEELS" "$PACKAGED_WHEELS" >&2 || true
  exit 1
fi

for relative in "${RELEASE_FILES[@]}"; do
  destination="$PACKAGE_DIR/$relative"
  mkdir -p "$(dirname "$destination")"
  cp -p "$ROOT_DIR/$relative" "$destination"
done

CHECKSUMMED_FILE_COUNT=$(("${#RELEASE_FILES[@]}" + 1))
{
  printf '{\n'
  printf '  "schema_version": 1,\n'
  printf '  "app_name": "CAT - Cyber Activity Tracker",\n'
  printf '  "app_version": "%s",\n' "$APP_VERSION"
  printf '  "release_version": "%s",\n' "$VERSION"
  printf '  "package_root": "%s",\n' "$PACKAGE_ROOT"
  printf '  "git_commit": "%s",\n' "$GIT_COMMIT"
  printf '  "git_dirty": %s,\n' "$GIT_DIRTY_JSON"
  printf '  "created_utc": "%s",\n' "$CREATED_UTC"
  printf '  "python_requirement": ">=3.9",\n'
  printf '  "runtime_agent_api": "OpenAI-compatible Chat Completions",\n'
  printf '  "payload_file_count": %d,\n' "${#RELEASE_FILES[@]}"
  printf '  "checksummed_file_count": %d\n' "$CHECKSUMMED_FILE_COUNT"
  printf '}\n'
} > "$PACKAGE_DIR/RELEASE-MANIFEST.json"

{
  digest="$(hash_file "$PACKAGE_DIR/RELEASE-MANIFEST.json")"
  printf '%s  %s\n' "$digest" "RELEASE-MANIFEST.json"
  for relative in "${RELEASE_FILES[@]}"; do
    digest="$(hash_file "$PACKAGE_DIR/$relative")"
    printf '%s  %s\n' "$digest" "$relative"
  done
} > "$PACKAGE_DIR/SHA256SUMS"

ZIP_NAME="$PACKAGE_ROOT.zip"
TAR_NAME="$PACKAGE_ROOT.tar.gz"
ARCHIVE_SUMS_NAME="$PACKAGE_ROOT.archive-SHA256SUMS"
ZIP_TARGET="$OUT_DIR/$ZIP_NAME"
TAR_TARGET="$OUT_DIR/$TAR_NAME"
ARCHIVE_SUMS_TARGET="$OUT_DIR/$ARCHIVE_SUMS_NAME"
for target in "$ZIP_TARGET" "$TAR_TARGET" "$ARCHIVE_SUMS_TARGET"; do
  if [[ -e "$target" ]]; then
    echo "Refusing to overwrite existing release artifact: $target" >&2
    exit 1
  fi
done

ZIP_BUILD="$BUILD_DIR/$ZIP_NAME"
TAR_BUILD="$BUILD_DIR/$TAR_NAME"
ARCHIVE_SUMS_BUILD="$BUILD_DIR/$ARCHIVE_SUMS_NAME"
(
  cd "$STAGE_ROOT"
  "$PYTHON_BIN" -m zipfile -c "$ZIP_BUILD" "$PACKAGE_ROOT"
  tar -czf "$TAR_BUILD" "$PACKAGE_ROOT"
)

"$PYTHON_BIN" "$ROOT_DIR/scripts/verify_release_package.py" "$ZIP_BUILD" "$TAR_BUILD"
{
  printf '%s  %s\n' "$(hash_file "$ZIP_BUILD")" "$ZIP_NAME"
  printf '%s  %s\n' "$(hash_file "$TAR_BUILD")" "$TAR_NAME"
} > "$ARCHIVE_SUMS_BUILD"

mv "$ZIP_BUILD" "$ZIP_TARGET"
mv "$TAR_BUILD" "$TAR_TARGET"
mv "$ARCHIVE_SUMS_BUILD" "$ARCHIVE_SUMS_TARGET"

printf 'ZIP=%s\n' "$ZIP_TARGET"
printf 'TAR_GZ=%s\n' "$TAR_TARGET"
printf 'ARCHIVE_SHA256=%s\n' "$ARCHIVE_SUMS_TARGET"
