from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WindowsScriptTests(unittest.TestCase):
    def test_multiline_python_is_passed_over_stdin(self) -> None:
        bootstrap = (ROOT / "scripts" / "bootstrap_offline.ps1").read_text(
            encoding="utf-8"
        )
        run = (ROOT / "scripts" / "run.ps1").read_text(encoding="utf-8")

        self.assertIn(
            "Invoke-SelectedPythonScript -Script $PythonValidation",
            bootstrap,
        )
        self.assertIn(
            "Invoke-CheckedPythonScript -Command $VenvPython "
            "-Script $PythonValidation",
            bootstrap,
        )
        self.assertNotIn('@("-c", $PythonValidation)', bootstrap)
        self.assertIn("$RuntimeProbe | & $VenvPython -", run)
        self.assertNotIn("& $VenvPython -c $RuntimeProbe", run)


if __name__ == "__main__":
    unittest.main()
