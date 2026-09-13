"""Run the installed scripts against a different repository, never this checkout."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Literal

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "tmforge"
SKILL = PLUGIN / "skills" / "threat-modeling"


class ChangedPackagesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tmforge-plugin-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.root = self.directory / "reviewed repo"
        self.root.mkdir()
        self.state = self.directory / "session state"
        self.scripts = SKILL / "scripts"
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        # Do not inherit a caller's Git context into the disposable fixture.
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
            self.environment.pop(name, None)

    def run_script(
        self, name: str, *arguments: str | Path, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(self.scripts / name), *map(str, arguments)],
            cwd=cwd or self.directory,
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def changed(
        self,
        command: str,
        *arguments: str | Path,
        root: Path | Literal[False] | None = None,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        options: list[str | Path] = ["--state-dir", self.state, *arguments]
        if root is not False:
            options.extend(["--root", root or self.root])
        return self.run_script(
            "validate_changed_packages.py", command, *options, cwd=cwd
        )

    def assert_ok(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def package(self, root: Path | None = None) -> Path:
        package = (root or self.root) / "threat-models" / "example"
        package.mkdir(parents=True)
        document = json.loads((SKILL / "assets" / "analysis.example.json").read_text())
        document["scope"]["mode"] = "verify"
        document["scope"]["ownershipDecision"] = {
            "action": "verify-only",
            "modelReference": "existing-model.tm7",
            "rationale": "Exercise local report consistency without a CLI dependency.",
        }
        ledger = package / "analysis.json"
        ledger.write_text(json.dumps(document), encoding="utf-8")
        self.assert_ok(self.run_script("render_analysis.py", ledger))
        self.assert_ok(self.run_script("validate_package.py", package, "--json"))
        return package

    def test_explicit_non_git_root_uses_sibling_validator(self):
        self.assert_ok(self.changed("snapshot"))
        self.package()
        result = self.changed("verify")
        self.assert_ok(result)
        self.assertIn("Validated 1", result.stdout)
        self.assertEqual(list(self.state.glob("*.json")), [])

    def test_git_root_discovery_from_subdirectory(self):
        result = subprocess.run(
            ["git", "init", "--quiet", str(self.root)],
            env=self.environment, capture_output=True, text=True, check=False,
        )
        self.assert_ok(result)
        self.package()
        nested = self.root / "src" / "nested"
        nested.mkdir(parents=True)
        self.assert_ok(self.changed("snapshot", root=False, cwd=nested))
        state = json.loads(next(self.state.glob("*.json")).read_text())
        self.assertEqual(state["root"], str(self.root))
        self.assertEqual(list(state["files"]), ["threat-models/example"])
        self.assert_ok(self.changed("verify", "--all", root=False, cwd=nested))

    def test_missing_git_root_requires_explicit_root(self):
        result = self.changed("snapshot", root=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--root", result.stderr)
        self.assertFalse(self.state.exists())

    def test_invalid_explicit_root_is_rejected(self):
        result = self.changed("snapshot", root=self.directory / "missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("directory", result.stderr)
        self.assertFalse(self.state.exists())

    def test_document_only_edit_fails_and_preserves_baseline(self):
        package = self.package()
        self.assert_ok(self.changed("snapshot"))
        report = package / "threat-model.md"
        original = report.read_bytes()
        report.write_bytes(original + b"\nHand-edited report.\n")
        result = self.changed("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stale generated document", result.stderr)
        self.assertEqual(len(list(self.state.glob("*.json"))), 1)
        report.write_bytes(original)
        self.assert_ok(self.changed("verify"))
        self.assertEqual(list(self.state.glob("*.json")), [])

    def test_invalid_score_fails_through_real_sibling_validator(self):
        package = self.package()
        self.assert_ok(self.changed("snapshot"))
        ledger = package / "analysis.json"
        document = json.loads(ledger.read_text())
        document["threats"][0]["score"] = 25
        ledger.write_text(json.dumps(document), encoding="utf-8")
        result = self.changed("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("score must equal", result.stderr)

    def test_missing_baseline_is_not_success(self):
        result = self.changed("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No baseline", result.stderr)

    def test_keep_and_all_preserve_baseline(self):
        self.assert_ok(self.changed("snapshot"))
        self.package()
        self.assert_ok(self.changed("verify", "--keep"))
        self.assertEqual(len(list(self.state.glob("*.json"))), 1)
        self.assert_ok(self.changed("verify", "--all"))
        self.assertEqual(len(list(self.state.glob("*.json"))), 1)
        self.assert_ok(self.changed("verify"))
        self.assertEqual(list(self.state.glob("*.json")), [])

    def test_baselines_are_isolated_by_target_root(self):
        other = self.directory / "other repo"
        other.mkdir()
        self.assert_ok(self.changed("snapshot"))
        self.assert_ok(self.changed("snapshot", root=other))
        self.assertEqual(len(list(self.state.glob("*.json"))), 2)
        self.assert_ok(self.changed("verify"))
        self.assertEqual(len(list(self.state.glob("*.json"))), 1)
        self.assert_ok(self.changed("verify", root=other))
        self.assertEqual(list(self.state.glob("*.json")), [])

    def test_caches_are_not_discovered_as_packages(self):
        for name in ("__pycache__", ".mypy_cache", ".pytest_cache", ".venv"):
            cache = self.root / name
            cache.mkdir()
            (cache / "analysis.json").write_text("invalid", encoding="utf-8")
        self.assert_ok(self.changed("snapshot"))
        state = json.loads(next(self.state.glob("*.json")).read_text())
        self.assertEqual(state["files"], {})

    def test_removed_ledger_cannot_hide_retained_package(self):
        package = self.package()
        self.assert_ok(self.changed("snapshot"))
        (package / "analysis.json").unlink()
        result = self.changed("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing canonical ledger", result.stderr)

    def test_corrupt_baseline_is_rejected(self):
        self.assert_ok(self.changed("snapshot"))
        state = next(self.state.glob("*.json"))
        state.write_text('{"files": {}}', encoding="utf-8")
        result = self.changed("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("baseline", result.stderr.lower())
        self.assertTrue(state.exists())

    def test_relocated_plugin_self_test_does_not_need_repository(self):
        installed = self.directory / "external plugins" / "tmforge"
        shutil.copytree(PLUGIN, installed, ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".mypy_cache"
        ))
        self.scripts = installed / "skills" / "threat-modeling" / "scripts"
        self.assert_ok(self.run_script("validate_changed_packages.py", "self-test"))
        self.assert_ok(self.changed("snapshot"))
        self.package()
        self.assert_ok(self.changed("verify"))


if __name__ == "__main__":
    unittest.main()
