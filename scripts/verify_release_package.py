from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Callable
import zipfile


MANIFEST_NAME = "RELEASE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS"
WHEEL_CHECKSUMS_PATH = "vendor/wheels/SHA256SUMS"
REQUIRED_RUNTIME_FILES = {
    "README.md",
    "cat.jpg",
    "cat_app/__init__.py",
    "cat_app/analyzer.py",
    "cat_app/evtx_reader.py",
    "cat_app/models.py",
    "cat_app/reporting.py",
    "cat_app/server.py",
    "cat_app/timeutil.py",
    "nyan-cat.gif",
    "requirements.offline.txt",
    "requirements.txt",
    "run.py",
    "scripts/bootstrap_offline.ps1",
    "scripts/bootstrap_offline.sh",
    "scripts/check_lmstudio.py",
    "scripts/run.ps1",
    "scripts/run.sh",
    "scripts/verify_release_package.py",
    "static/app.js",
    "static/index.html",
    "static/styles.css",
    "tests/fixtures/issue_38.evtx",
    "tests/sample_events.xml",
    "tests/smoke_test.py",
    "vendor/wheels/SHA256SUMS",
    "vendor/wheels/hexdump-3.3-py3-none-any.whl",
    "vendor/wheels/python_evtx-0.8.1-py3-none-any.whl",
    "vendor/wheels/tzdata-2026.3-py2.py3-none-any.whl",
}
BANNED_COMPONENTS = {
    ".agents",
    ".codex",
    ".git",
    ".venv",
    "__pycache__",
    "dist",
    "reports",
}
WINDOWS_RESERVED_NAMES = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
WINDOWS_INVALID_CHARACTERS = set('<>"|?*')
SHA256_LINE = re.compile(r"^([0-9a-fA-F]{64})  (.+)$")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate a CAT release ZIP or tar.gz without extracting it."
    )
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()

    for archive in args.archives:
        result = validate_archive(archive)
        print(
            f"{archive}: OK "
            f"(root={result['package_root']}, files={result['regular_file_count']})"
        )
    return 0


def validate_archive(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ValueError(f"release archive not found: {path}")
    lower_name = path.name.lower()
    if lower_name.endswith(".zip"):
        return _validate_zip(path)
    if lower_name.endswith((".tar.gz", ".tgz")):
        return _validate_tar(path)
    raise ValueError(f"unsupported release archive type: {path}")


def _validate_zip(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        _reject_duplicates([info.filename for info in infos], path)
        files: dict[str, zipfile.ZipInfo] = {}
        for info in infos:
            _validate_member_name(info.filename, path)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"{path}: symbolic link is not allowed: {info.filename}")
            if info.is_dir():
                continue
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG}:
                raise ValueError(f"{path}: special file is not allowed: {info.filename}")
            files[info.filename] = info

        return _validate_regular_files(
            path,
            list(files),
            lambda name: archive.read(files[name]),
        )


def _validate_tar(path: Path) -> dict[str, object]:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        _reject_duplicates([member.name for member in members], path)
        files: dict[str, tarfile.TarInfo] = {}
        for member in members:
            _validate_member_name(member.name, path)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"{path}: non-regular member is not allowed: {member.name}")
            files[member.name] = member

        def read_member(name: str) -> bytes:
            stream = archive.extractfile(files[name])
            if stream is None:
                raise ValueError(f"{path}: could not read archive member: {name}")
            return stream.read()

        return _validate_regular_files(path, list(files), read_member)


def _validate_regular_files(
    archive_path: Path,
    member_names: list[str],
    read_member: Callable[[str], bytes],
) -> dict[str, object]:
    if not member_names:
        raise ValueError(f"{archive_path}: archive contains no regular files")

    roots = {PurePosixPath(name).parts[0] for name in member_names}
    if len(roots) != 1:
        raise ValueError(f"{archive_path}: archive must contain exactly one top-level directory")
    package_root = roots.pop()

    relative_to_member: dict[str, str] = {}
    windows_paths: dict[str, str] = {}
    for name in member_names:
        parts = PurePosixPath(name).parts
        if len(parts) < 2:
            raise ValueError(f"{archive_path}: files at archive root are not allowed: {name}")
        relative = PurePosixPath(*parts[1:]).as_posix()
        if relative in relative_to_member:
            raise ValueError(f"{archive_path}: duplicate relative path: {relative}")
        relative_to_member[relative] = name
        windows_key = relative.casefold()
        if windows_key in windows_paths:
            raise ValueError(
                f"{archive_path}: Windows case-insensitive path collision: "
                f"{windows_paths[windows_key]} and {relative}"
            )
        windows_paths[windows_key] = relative

    required = {MANIFEST_NAME, CHECKSUMS_NAME}
    missing_required = required - relative_to_member.keys()
    if missing_required:
        missing = ", ".join(sorted(missing_required))
        raise ValueError(f"{archive_path}: required release metadata missing: {missing}")
    missing_runtime = REQUIRED_RUNTIME_FILES - relative_to_member.keys()
    if missing_runtime:
        missing = ", ".join(sorted(missing_runtime))
        raise ValueError(f"{archive_path}: required runtime files missing: {missing}")

    manifest = _load_manifest(
        archive_path,
        read_member(relative_to_member[MANIFEST_NAME]),
    )
    if manifest.get("package_root") != package_root:
        raise ValueError(
            f"{archive_path}: manifest package_root does not match archive root "
            f"({manifest.get('package_root')!r} != {package_root!r})"
        )

    checksums = _load_checksums(
        archive_path,
        read_member(relative_to_member[CHECKSUMS_NAME]),
    )
    expected_paths = set(relative_to_member) - {CHECKSUMS_NAME}
    if set(checksums) != expected_paths:
        missing = sorted(expected_paths - checksums.keys())
        extra = sorted(checksums.keys() - expected_paths)
        raise ValueError(
            f"{archive_path}: SHA256SUMS member mismatch; missing={missing}, extra={extra}"
        )

    for relative, expected in sorted(checksums.items()):
        actual = hashlib.sha256(read_member(relative_to_member[relative])).hexdigest()
        if actual != expected:
            raise ValueError(
                f"{archive_path}: SHA-256 mismatch for {relative}: "
                f"expected {expected}, got {actual}"
            )

    _validate_wheelhouse(
        archive_path,
        relative_to_member,
        read_member,
    )

    checksum_count = manifest.get("checksummed_file_count")
    if checksum_count != len(checksums):
        raise ValueError(
            f"{archive_path}: manifest checksummed_file_count mismatch "
            f"({checksum_count!r} != {len(checksums)})"
        )
    payload_count = manifest.get("payload_file_count")
    expected_payload_count = len(relative_to_member) - 2
    if payload_count != expected_payload_count:
        raise ValueError(
            f"{archive_path}: manifest payload_file_count mismatch "
            f"({payload_count!r} != {expected_payload_count})"
        )
    for field in ("app_version", "release_version", "git_commit", "created_utc"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            raise ValueError(f"{archive_path}: manifest field is missing or empty: {field}")

    return {
        "package_root": package_root,
        "regular_file_count": len(relative_to_member),
        "manifest": manifest,
    }


def _validate_wheelhouse(
    archive_path: Path,
    relative_to_member: dict[str, str],
    read_member: Callable[[str], bytes],
) -> None:
    wheel_checksums = _load_checksums(
        archive_path,
        read_member(relative_to_member[WHEEL_CHECKSUMS_PATH]),
    )
    wheel_members: dict[str, str] = {}
    for relative in relative_to_member:
        wheel_path = PurePosixPath(relative)
        if not relative.endswith(".whl"):
            continue
        if wheel_path.parent.as_posix() != "vendor/wheels":
            raise ValueError(
                f"{archive_path}: wheel must be directly under vendor/wheels: {relative}"
            )
        if wheel_path.name in wheel_members:
            raise ValueError(
                f"{archive_path}: duplicate wheel file name: {wheel_path.name}"
            )
        wheel_members[wheel_path.name] = relative
    if set(wheel_checksums) != set(wheel_members):
        missing = sorted(wheel_members.keys() - wheel_checksums.keys())
        extra = sorted(wheel_checksums.keys() - wheel_members.keys())
        raise ValueError(
            f"{archive_path}: wheel SHA256SUMS member mismatch; "
            f"missing={missing}, extra={extra}"
        )
    for wheel_name, expected in sorted(wheel_checksums.items()):
        actual = hashlib.sha256(
            read_member(relative_to_member[wheel_members[wheel_name]])
        ).hexdigest()
        if actual != expected:
            raise ValueError(
                f"{archive_path}: wheel SHA-256 mismatch for {wheel_name}: "
                f"expected {expected}, got {actual}"
            )


def _load_manifest(path: Path, data: bytes) -> dict[str, object]:
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: invalid {MANIFEST_NAME}: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError(f"{path}: unsupported or missing release manifest schema")
    return manifest


def _load_checksums(path: Path, data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: {CHECKSUMS_NAME} is not UTF-8") from exc

    checksums: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        match = SHA256_LINE.fullmatch(line)
        if not match:
            raise ValueError(
                f"{path}: invalid {CHECKSUMS_NAME} line {line_number}: {line!r}"
            )
        digest, relative = match.groups()
        _validate_relative_manifest_path(relative, path)
        if relative in checksums:
            raise ValueError(f"{path}: duplicate checksum path: {relative}")
        checksums[relative] = digest.lower()
    if not checksums:
        raise ValueError(f"{path}: {CHECKSUMS_NAME} is empty")
    return checksums


def _validate_member_name(name: str, archive_path: Path) -> None:
    if not name:
        raise ValueError(f"{archive_path}: empty archive member name")
    if "\\" in name:
        raise ValueError(f"{archive_path}: backslash is not allowed in member name: {name}")
    trimmed = name[:-1] if name.endswith("/") else name
    _validate_relative_manifest_path(trimmed, archive_path)


def _validate_relative_manifest_path(name: str, archive_path: Path) -> None:
    if not name or name.startswith("/"):
        raise ValueError(f"{archive_path}: absolute or empty path is not allowed: {name!r}")
    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{archive_path}: unsafe path component: {name}")
    if any(part.endswith((" ", ".")) for part in parts):
        raise ValueError(f"{archive_path}: Windows trailing dot/space is not allowed: {name}")
    if any(
        any(ord(character) < 32 or character in WINDOWS_INVALID_CHARACTERS for character in part)
        for part in parts
    ):
        raise ValueError(f"{archive_path}: Windows-invalid character in path: {name}")
    if any(":" in part for part in parts):
        raise ValueError(f"{archive_path}: colon/ADS path is not allowed: {name}")
    for part in parts:
        device_name = part.split(".", 1)[0].casefold()
        if device_name in WINDOWS_RESERVED_NAMES:
            raise ValueError(f"{archive_path}: Windows reserved path name is not allowed: {name}")
    lowered = {part.casefold() for part in parts}
    banned = lowered & BANNED_COMPONENTS
    if banned:
        raise ValueError(
            f"{archive_path}: banned release path component {sorted(banned)} in {name}"
        )
    if parts[-1].casefold().endswith("zone.identifier"):
        raise ValueError(f"{archive_path}: Zone.Identifier is not allowed: {name}")


def _reject_duplicates(names: list[str], path: Path) -> None:
    seen: set[str] = set()
    windows_seen: dict[str, str] = {}
    for name in names:
        normalized = name.rstrip("/")
        if normalized in seen:
            raise ValueError(f"{path}: duplicate archive member: {name}")
        seen.add(normalized)
        windows_key = normalized.casefold()
        if windows_key in windows_seen and windows_seen[windows_key] != normalized:
            raise ValueError(
                f"{path}: Windows case-insensitive archive member collision: "
                f"{windows_seen[windows_key]} and {normalized}"
            )
        windows_seen[windows_key] = normalized


if __name__ == "__main__":
    raise SystemExit(main())
