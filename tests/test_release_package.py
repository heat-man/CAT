from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify_release_package.py"
SPEC = importlib.util.spec_from_file_location("verify_release_package", VERIFIER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load release verifier: {VERIFIER_PATH}")
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


class ReleasePackageTests(unittest.TestCase):
    def test_current_tree_builds_safe_zip_and_tar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            output_dir = Path(temp_dir)
            env = os.environ.copy()
            env.update(
                {
                    "OUT_DIR": str(output_dir),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "VERSION": "0.2.0-test",
                }
            )
            subprocess.run(
                [str(ROOT / "scripts" / "make_release_archive.sh")],
                cwd=ROOT,
                env=env,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            zip_path = _only(output_dir.glob("*.zip"))
            tar_path = _only(output_dir.glob("*.tar.gz"))
            sums_path = _only(output_dir.glob("*.archive-SHA256SUMS"))
            zip_result = VERIFIER.validate_archive(zip_path)
            tar_result = VERIFIER.validate_archive(tar_path)

            self.assertEqual(zip_result["package_root"], tar_result["package_root"])
            self.assertEqual(
                zip_result["regular_file_count"],
                tar_result["regular_file_count"],
            )
            sums = sums_path.read_text(encoding="utf-8")
            self.assertIn(zip_path.name, sums)
            self.assertIn(tar_path.name, sums)

            with zipfile.ZipFile(zip_path) as archive:
                names = {info.filename for info in archive.infolist()}
            forbidden = (
                "reports/",
                ".agents/",
                ".codex/",
                "Zone.Identifier",
                "scripts/build_wheelhouse.sh",
                "scripts/export_codex_agent_package.py",
                "scripts/perf_test.py",
                "scripts/run_codex_agent_review.py",
            )
            for value in forbidden:
                self.assertFalse(
                    any(value in name for name in names),
                    f"forbidden release member found: {value}",
                )

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "traversal.zip"
            _write_valid_zip(archive, extra={"cat-test/../escape.txt": b"escape"})
            with self.assertRaisesRegex(ValueError, "unsafe path component"):
                VERIFIER.validate_archive(archive)

    def test_rejects_reports_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "reports.zip"
            _write_valid_zip(archive, extra={"cat-test/reports/result.json": b"{}"})
            with self.assertRaisesRegex(ValueError, "banned release path"):
                VERIFIER.validate_archive(archive)

    def test_rejects_zone_identifier(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "zone.zip"
            _write_valid_zip(
                archive,
                extra={"cat-test/nyan-cat.gif:Zone.Identifier": b"zone"},
            )
            with self.assertRaisesRegex(ValueError, "colon/ADS path"):
                VERIFIER.validate_archive(archive)

    def test_rejects_checksum_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "tampered.zip"
            _write_valid_zip(archive, tamper_payload=True)
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                VERIFIER.validate_archive(archive)

    def test_rejects_missing_required_runtime_file(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "missing-runtime.zip"
            _write_valid_zip(archive, omit={"scripts/run.ps1"})
            with self.assertRaisesRegex(ValueError, "required runtime files missing"):
                VERIFIER.validate_archive(archive)

    def test_rejects_windows_casefold_collision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "casefold.zip"
            _write_valid_zip(archive, extra={"cat-test/README.MD": b"collision"})
            with self.assertRaisesRegex(ValueError, "case-insensitive"):
                VERIFIER.validate_archive(archive)

    def test_rejects_windows_reserved_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "reserved.zip"
            _write_valid_zip(archive, extra={"cat-test/CON.txt": b"reserved"})
            with self.assertRaisesRegex(ValueError, "Windows reserved"):
                VERIFIER.validate_archive(archive)

    def test_rejects_windows_trailing_dot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "trailing-dot.zip"
            _write_valid_zip(archive, extra={"cat-test/file.": b"trailing"})
            with self.assertRaisesRegex(ValueError, "trailing dot/space"):
                VERIFIER.validate_archive(archive)

    def test_rejects_manifest_payload_count_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "payload-count.zip"
            _write_valid_zip(archive, payload_count_delta=1)
            with self.assertRaisesRegex(ValueError, "payload_file_count mismatch"):
                VERIFIER.validate_archive(archive)

    def test_rejects_wheel_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cat-release-test-") as temp_dir:
            archive = Path(temp_dir) / "wheel-manifest.zip"
            _write_valid_zip(archive, tamper_wheel_manifest=True)
            with self.assertRaisesRegex(ValueError, "wheel SHA-256 mismatch"):
                VERIFIER.validate_archive(archive)


def _only(paths: object) -> Path:
    values = list(paths)  # type: ignore[arg-type]
    if len(values) != 1:
        raise AssertionError(f"expected exactly one path, got: {values}")
    return values[0]


def _write_valid_zip(
    path: Path,
    *,
    extra: dict[str, bytes] | None = None,
    tamper_payload: bool = False,
    omit: set[str] | None = None,
    payload_count_delta: int = 0,
    tamper_wheel_manifest: bool = False,
) -> None:
    package_root = "cat-test"
    payload_files = {
        relative: f"fixture for {relative}\n".encode("utf-8")
        for relative in VERIFIER.REQUIRED_RUNTIME_FILES
        if relative not in (omit or set())
    }
    payload_files["payload.txt"] = b"expected payload"
    wheel_paths = sorted(
        relative
        for relative in payload_files
        if relative.startswith("vendor/wheels/") and relative.endswith(".whl")
    )
    wheel_manifest_lines = []
    for index, relative in enumerate(wheel_paths):
        digest = hashlib.sha256(payload_files[relative]).hexdigest()
        if tamper_wheel_manifest and index == 0:
            digest = "0" * 64
        wheel_manifest_lines.append(f"{digest}  {Path(relative).name}")
    payload_files["vendor/wheels/SHA256SUMS"] = (
        "\n".join(wheel_manifest_lines) + "\n"
    ).encode("utf-8")
    manifest = {
        "schema_version": 1,
        "app_name": "CAT - Cyber Activity Tracker",
        "app_version": "0.2.0",
        "release_version": "test",
        "package_root": package_root,
        "git_commit": "0" * 40,
        "git_dirty": False,
        "created_utc": "2026-07-28T00:00:00Z",
        "python_requirement": ">=3.9",
        "runtime_agent_api": "OpenAI-compatible Chat Completions",
        "payload_file_count": len(payload_files) + payload_count_delta,
        "checksummed_file_count": len(payload_files) + 1,
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    checksum_lines = [
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  RELEASE-MANIFEST.json"
    ]
    checksum_lines.extend(
        f"{hashlib.sha256(data).hexdigest()}  {relative}"
        for relative, data in sorted(payload_files.items())
    )
    checksum_bytes = ("\n".join(checksum_lines) + "\n").encode("utf-8")

    with zipfile.ZipFile(path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{package_root}/RELEASE-MANIFEST.json", manifest_bytes)
        archive.writestr(f"{package_root}/SHA256SUMS", checksum_bytes)
        for relative, data in sorted(payload_files.items()):
            if relative == "payload.txt" and tamper_payload:
                data = b"tampered payload"
            archive.writestr(f"{package_root}/{relative}", data)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)


if __name__ == "__main__":
    unittest.main()
