"""Run the installed scripts against a different repository, never this checkout."""

import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal
from unittest.mock import patch

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "tmforge"
SKILL = PLUGIN / "skills" / "threat-modeling"


SCRIPTS = SKILL / "scripts"


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
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
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
        for name in (
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".venv",
            ".vscode-test",
            ".vscode-test-web",
        ):
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
        shutil.copytree(
            PLUGIN,
            installed,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".mypy_cache"),
        )
        self.scripts = installed / "skills" / "threat-modeling" / "scripts"
        self.assert_ok(self.run_script("validate_changed_packages.py", "self-test"))
        self.assert_ok(self.changed("snapshot"))
        self.package()
        self.assert_ok(self.changed("verify"))


class PackageDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "package_discovery", SCRIPTS / "validate_changed_packages.py"
        )
        assert spec is not None and spec.loader is not None
        self.checker = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
            spec.loader.exec_module(self.checker)
        temporary = tempfile.TemporaryDirectory(prefix="tmforge-package-discovery-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / "repository"
        self.state = self.root.parent / "state"
        self.package = self.root / "packages" / "example"
        self.package.mkdir(parents=True)
        self.ledger = self.package / "analysis.json"
        document = json.loads(
            (SCRIPTS.parent / "assets" / "analysis.example.json").read_text(
                encoding="utf-8"
            )
        )
        document["scope"]["mode"] = "verify"
        document["scope"]["ownershipDecision"] = {
            "action": "verify-only",
            "modelReference": "existing-model.tm7",
            "rationale": "Exercise package discovery without requiring tmforge.",
        }
        self.ledger_content = json.dumps(document)
        self.ledger.write_text(self.ledger_content, encoding="utf-8")
        rendered = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPTS / "render_analysis.py"),
                str(self.ledger),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(rendered.returncode, 0, rendered.stdout + rendered.stderr)
        self.baseline = self.checker.state_path(self.root, self.state)

    def snapshot(self) -> None:
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.checker.snapshot(self.root, self.state), 0)

    def test_vscode_runtime_links_do_not_block_repository_discovery(self) -> None:
        cache = self.root / "src" / "extension" / ".vscode-test"
        cache.mkdir(parents=True)
        outside = self.root.parent / "downloaded-runtime"
        outside.mkdir()
        (outside / "analysis.json").write_text("not a package", encoding="utf-8")
        try:
            (cache / "Electron Framework").symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable: {exc}")
        self.snapshot()
        self.assertEqual(
            list(self.checker.read_state(self.baseline)["files"]), ["packages/example"]
        )
        self.assertEqual(self.verify(check_all=True)[0], 0)

    def verify(self, check_all: bool = False) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = self.checker.verify(self.root, check_all, False, self.state)
        return result, output.getvalue()

    def test_invalid_baseline_shapes_are_rejected_and_preserved(self) -> None:
        invalid: tuple[object, ...] = (
            None,
            [],
            {},
            {"root": str(self.root)},
            {"root": str(self.root), "files": None},
            {"root": str(self.root), "files": []},
            {"root": str(self.root), "files": "corrupt"},
            {"root": str(self.root), "files": {}, "unexpected": True},
            {"root": str(self.root.parent), "files": {}},
        )
        self.state.mkdir(mode=0o700)
        for populated in (True, False):
            if not populated:
                shutil.rmtree(self.package)
            for value in invalid:
                with self.subTest(populated=populated, value=value):
                    self.baseline.write_text(json.dumps(value), encoding="utf-8")
                    self.baseline.chmod(0o600)
                    original = self.baseline.read_bytes()
                    with patch.object(self.checker, "validate_paths") as validate:
                        with self.assertRaisesRegex(ValueError, "baseline"):
                            self.verify()
                    validate.assert_not_called()
                    self.assertEqual(self.baseline.read_bytes(), original)

    def test_baseline_keys_and_digests_are_validated_before_comparison(self) -> None:
        invalid_keys = (
            "",
            "/outside",
            "../outside",
            "package/../other",
            "package//child",
            "./package",
            "package/",
            "C:/outside",
            "C:relative",
            "package\\child",
            "bad\0name",
        )
        invalid_digests: tuple[object, ...] = (
            None,
            {},
            123,
            True,
            "",
            "g" * 64,
            "A" * 64,
            "a" * 63,
        )
        cases: list[tuple[str, object]] = [(name, "a" * 64) for name in invalid_keys]
        cases.extend(("packages/example", digest) for digest in invalid_digests)
        for name, digest in cases:
            with self.subTest(name=name, digest=digest):
                self.checker.write_state(
                    self.baseline, {"root": str(self.root), "files": {name: digest}}
                )
                original = self.baseline.read_bytes()
                with patch.object(self.checker, "validate_paths") as validate:
                    with self.assertRaisesRegex(ValueError, "invalid baseline"):
                        self.verify()
                validate.assert_not_called()
                self.assertEqual(self.baseline.read_bytes(), original)
        for files in ({}, {".": "a" * 64}, {"packages/example": "b" * 64}):
            self.assertEqual(
                self.checker.baseline_files(
                    {"root": str(self.root), "files": files}, self.root
                ),
                files,
            )

    def test_invalid_baseline_cli_fails_without_removing_state(self) -> None:
        self.checker.write_state(self.baseline, {"root": str(self.root), "files": []})
        before = self.baseline.read_bytes()
        errors = io.StringIO()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "validate_changed_packages.py",
                    "verify",
                    "--root",
                    str(self.root),
                    "--state-dir",
                    str(self.state),
                ],
            ),
            redirect_stderr(errors),
        ):
            self.assertEqual(self.checker.main(), 1)
        self.assertIn("files must be an object", errors.getvalue())
        self.assertEqual(self.baseline.read_bytes(), before)

    def test_link_substitution_is_rejected_without_changing_baseline(self) -> None:
        for name in (
            "analysis.json",
            "data-flow.md",
            "threat-model.md",
            "model.tm7",
            "model.tm.json",
            "model.tm.suppressions.json",
            "model.tm.evidence.json",
        ):
            with self.subTest(name=name):
                artifact = self.package / name
                previous = artifact.read_bytes() if artifact.exists() else None
                content = previous if previous is not None else b"fixture"
                artifact.write_bytes(content)
                self.snapshot()
                baseline = self.baseline.read_bytes()
                outside = self.root.parent / "external-artifact"
                outside.write_bytes(content)
                artifact.unlink()
                try:
                    try:
                        artifact.symlink_to(outside)
                    except OSError as exc:
                        self.skipTest(f"symlinks are unavailable: {exc}")
                    with self.assertRaisesRegex(ValueError, "symlink"):
                        self.checker.file_digest(artifact)
                    for check_all in (False, True):
                        with self.assertRaisesRegex(ValueError, "symlink"):
                            self.verify(check_all)
                    with patch.object(self.checker.subprocess, "run") as run:
                        failures = self.checker.validate_paths(
                            self.root, ["packages/example"]
                        )
                    self.assertTrue(failures)
                    run.assert_not_called()
                    self.assertEqual(self.baseline.read_bytes(), baseline)
                    self.assertEqual(outside.read_bytes(), content)
                finally:
                    artifact.unlink(missing_ok=True)
                    if previous is not None:
                        artifact.write_bytes(previous)

    def test_dangling_artifact_and_linked_package_directories_fail(self) -> None:
        linked = self.package / "dangling.tm7"
        try:
            linked.symlink_to(self.root.parent / "missing")
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.checker.snapshot_packages(self.root)
        linked.unlink()
        original = self.root.parent / "moved-package"
        self.package.rename(original)
        self.package.symlink_to(original, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.checker.snapshot_packages(self.root)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.checker.package_files(self.package)

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow file open")
    def test_hash_reader_rejects_file_swapped_to_symlink(self) -> None:
        outside = self.root.parent / "external-artifact"
        outside.write_bytes(b"external bytes")
        original_open = os.open

        def swap(path, flags, *args, **kwargs):
            if path == "analysis.json":
                self.ledger.unlink()
                self.ledger.symlink_to(outside)
            return original_open(path, flags, *args, **kwargs)

        with patch.object(self.checker.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                self.checker.file_digest(self.ledger)

    def test_deleted_or_renamed_ledger_fails_until_restored(self) -> None:
        for operation in ("delete", "rename"):
            with self.subTest(operation=operation):
                self.snapshot()
                renamed = self.ledger.with_name("renamed-analysis.json")
                if operation == "rename":
                    self.ledger.rename(renamed)
                else:
                    self.ledger.unlink()
                for check_all in (False, True):
                    code, output = self.verify(check_all)
                    self.assertEqual(code, 0 if check_all else 1, output)
                    if not check_all:
                        self.assertIn("missing canonical ledger", output)
                    self.assertTrue(self.baseline.is_file())
                self.ledger.write_text(self.ledger_content, encoding="utf-8")
                renamed.unlink(missing_ok=True)
                code, output = self.verify()
                self.assertEqual(code, 0, output)
                self.assertFalse(self.baseline.exists())

    def test_new_orphan_fails_session_verify_but_is_not_an_all_target(self) -> None:
        self.snapshot()
        orphan = self.root / "orphan"
        orphan.mkdir()
        (orphan / "model.tm.evidence.json").write_text("{}", encoding="utf-8")
        for check_all in (False, True):
            code, output = self.verify(check_all)
            self.assertEqual(code, 0 if check_all else 1, output)
            if not check_all:
                self.assertIn("missing canonical ledger", output)
            self.assertTrue(self.baseline.is_file())

    def test_all_requires_a_ledger_without_a_baseline(self) -> None:
        self.ledger.unlink()
        with patch.object(self.checker, "validate_paths") as validate:
            code, output = self.verify(check_all=True)
        self.assertEqual(code, 0, output)
        validate.assert_not_called()

    def test_all_does_not_hash_or_validate_standalone_model_artifacts(self) -> None:
        for index in range(18):
            directory = (
                self.root / ("out", "test/Fixtures", "examples")[index % 3] / str(index)
            )
            directory.mkdir(parents=True)
            (directory / "fixture.tm7").write_bytes(b"not a retained package")
        with (
            patch.object(self.checker, "validate_paths", return_value=[]) as validate,
            patch.object(
                self.checker, "file_digest", wraps=self.checker.file_digest
            ) as digest,
        ):
            code, output = self.verify(check_all=True)
        self.assertEqual(code, 0, output)
        validate.assert_called_once_with(self.root, ["packages/example"], None, 300)
        self.assertTrue(digest.called)
        self.assertTrue(
            all(
                call.args[0].is_relative_to(self.package)
                for call in digest.call_args_list
            )
        )

    def test_all_still_rejects_an_invalid_canonical_ledger(self) -> None:
        self.ledger.write_text("{}", encoding="utf-8")
        code, output = self.verify(check_all=True)
        self.assertEqual(code, 1, output)
        self.assertIn("missing top-level fields", output)

    def test_each_companion_can_identify_an_orphan(self) -> None:
        orphan = self.root / "orphan"
        orphan.mkdir()
        for name in (
            "data-flow.md",
            "threat-model.md",
            "model.tm7",
            "model.tm.json",
            "model.tm.evidence.json",
            "model.tm.suppressions.json",
        ):
            with self.subTest(name=name):
                artifact = orphan / name
                artifact.write_text("fixture", encoding="utf-8")
                self.assertEqual(
                    list(self.checker.snapshot_packages(self.root)),
                    ["orphan", "packages/example"],
                )
                artifact.unlink()

    def test_complete_package_removal_is_allowed(self) -> None:
        self.snapshot()
        shutil.rmtree(self.package)
        for check_all in (False, True):
            code, output = self.verify(check_all)
            self.assertEqual(code, 0, output)
        self.assertFalse(self.baseline.exists())

    def test_nested_suppression_add_edit_and_remove_trigger_verification(self) -> None:
        directory = self.package / "diagrams"
        directory.mkdir()
        sidecar = directory / "model.tm.suppressions.json"
        for content in ("{}", '{"files": []}', None):
            with self.subTest(content=content):
                self.snapshot()
                if content is None:
                    sidecar.unlink()
                else:
                    sidecar.write_text(content, encoding="utf-8")
                with patch.object(
                    self.checker, "validate_paths", return_value=[]
                ) as validate:
                    code, output = self.verify()
                self.assertEqual(code, 0, output)
                validate.assert_called_once_with(
                    self.root, ["packages/example"], None, 300
                )
                self.assertEqual(
                    list(self.checker.snapshot_packages(self.root)),
                    ["packages/example"],
                )

    def test_package_deadline_scales_with_all_subprocesses(self) -> None:
        for name in ("first.tm7", "second.tm7", "first.tm.suppressions.json"):
            (self.package / name).write_text("fixture", encoding="utf-8")
        with patch.object(
            self.checker.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, "{}", ""),
        ) as run:
            self.assertEqual(
                self.checker.validate_paths(
                    self.root, ["packages/example"], "wrapper --", timeout=90
                ),
                [],
            )
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--timeout") + 1], "90")
        self.assertEqual(command[command.index("--tmforge") + 1], "wrapper --")
        self.assertEqual(run.call_args.kwargs["timeout"], 30 + 90 * (1 + 2 * (9 + 1)))

    def test_timeout_cli_is_forwarded_and_must_be_positive(self) -> None:
        arguments = [
            "validate_changed_packages.py",
            "verify",
            "--root",
            str(self.root),
            "--all",
            "--timeout",
        ]
        with (
            patch.object(sys, "argv", [*arguments, "91"]),
            patch.object(self.checker, "validate_paths", return_value=[]) as validate,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self.checker.main(), 0)
        self.assertEqual(validate.call_args.args[-1], 91)
        with (
            patch.object(sys, "argv", [*arguments, "0"]),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as error:
                self.checker.main()
        self.assertEqual(error.exception.code, 2)

    def test_removing_all_artifacts_leaves_no_package(self) -> None:
        self.snapshot()
        for artifact in self.checker.package_files(self.package):
            artifact.unlink()
        (self.package / "notes.txt").write_text(
            "retained unrelated notes", encoding="utf-8"
        )
        code, output = self.verify()
        self.assertEqual(code, 0, output)
        self.assertFalse(self.baseline.exists())

    def test_nested_models_belong_to_the_existing_package(self) -> None:
        nested = self.package / "diagrams"
        nested.mkdir()
        for name in ("model.tm7", "model.tm.json"):
            (nested / name).write_text("fixture", encoding="utf-8")
        before = self.checker.snapshot_packages(self.root)
        self.assertEqual(list(before), ["packages/example"])
        (nested / "model.tm.json").write_text("changed", encoding="utf-8")
        after = self.checker.snapshot_packages(self.root)
        self.assertEqual(
            self.checker.changed_packages(before, after), ["packages/example"]
        )

    def test_removed_nested_ledger_retains_its_baseline_target(self) -> None:
        nested = self.package / "nested-package"
        nested.mkdir()
        ledger = nested / "analysis.json"
        ledger.write_text(self.ledger_content, encoding="utf-8")
        (nested / "model.tm.json").write_text("{}", encoding="utf-8")
        self.snapshot()
        ledger.unlink()
        code, output = self.verify()
        self.assertEqual(code, 1, output)
        self.assertIn("missing canonical ledger", output)
        self.assertIn("nested-package", output)
        self.assertTrue(self.baseline.is_file())

    def test_unrelated_and_excluded_files_do_not_create_packages(self) -> None:
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        (unrelated / "README.md").write_text("# Notes", encoding="utf-8")
        for excluded in self.checker.SKIP_DIRECTORIES:
            directory = self.root / excluded
            directory.mkdir()
            (directory / "model.tm7").write_text("fixture", encoding="utf-8")
        self.assertEqual(
            list(self.checker.snapshot_packages(self.root)), ["packages/example"]
        )


class BaselineStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "baseline_storage", SCRIPTS / "validate_changed_packages.py"
        )
        assert spec is not None and spec.loader is not None
        self.checker = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
            spec.loader.exec_module(self.checker)
        temporary = tempfile.TemporaryDirectory(prefix="tmforge-baseline-security-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.state = self.root / "state"
        self.baseline = self.checker.state_path(self.repository, self.state)
        self.target = self.root / "outside.json"
        self.target.write_text("preserve", encoding="utf-8")

    def link(self, path: Path, target: Path, directory: bool = False) -> None:
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable: {exc}")

    def snapshot(self) -> None:
        with redirect_stdout(io.StringIO()):
            self.assertEqual(self.checker.snapshot(self.repository, self.state), 0)

    def test_baseline_reader_api_validates_private_state(self) -> None:
        document = {"root": str(self.repository), "files": {".": "a" * 64}}
        self.checker.write_state(self.baseline, document)
        self.assertEqual(
            self.checker.read_baseline(self.baseline, self.repository),
            document["files"],
        )
        document["files"] = {".": "not-a-sha256"}
        self.checker.write_state(self.baseline, document)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.checker.read_baseline(self.baseline, self.repository)
        self.assertTrue(self.baseline.exists())

    def test_private_storage_supports_repeated_snapshot_and_verify(self) -> None:
        self.snapshot()
        self.snapshot()
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(self.baseline.stat().st_mode), 0o600)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                self.checker.verify(self.repository, False, True, self.state), 0
            )
            self.assertTrue(self.baseline.exists())
            self.assertEqual(
                self.checker.verify(self.repository, False, False, self.state), 0
            )
        self.assertFalse(self.baseline.exists())

    def test_baseline_links_are_rejected_for_read_and_write(self) -> None:
        self.state.mkdir(mode=0o700)
        for target in (self.target, self.root / "missing.json"):
            with self.subTest(target=target.name):
                self.link(self.baseline, target)
                with self.assertRaisesRegex(ValueError, "not links"):
                    self.snapshot()
                with self.assertRaisesRegex(ValueError, "not links"):
                    self.checker.verify(self.repository, False, False, self.state)
                self.assertEqual(self.target.read_text(), "preserve")
                self.assertFalse((self.root / "missing.json").exists())
                self.baseline.unlink()

    def test_state_directory_symlink_is_rejected(self) -> None:
        outside = self.root / "outside-directory"
        outside.mkdir(mode=0o700)
        self.link(self.state, outside, directory=True)
        with self.assertRaisesRegex(ValueError, "not links|symlink or reparse point"):
            self.snapshot()
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(sys.platform == "darwin", "macOS system directory aliases")
    def test_system_temp_aliases_allow_private_state_without_following_user_links(
        self,
    ) -> None:
        for prefix in ("/var/tmp", "/tmp"):
            with (
                self.subTest(prefix=prefix),
                tempfile.TemporaryDirectory(dir=prefix) as temporary,
            ):
                self.state = Path(temporary) / "state"
                self.baseline = self.checker.state_path(self.repository, self.state)
                self.snapshot()
                self.assertEqual(
                    self.checker.read_state(self.baseline)["root"], str(self.repository)
                )
                outside = Path(temporary) / "outside"
                outside.mkdir(mode=0o700)
                linked = Path(temporary) / "linked-state"
                self.link(linked, outside, directory=True)
                with self.assertRaisesRegex(ValueError, "not links"):
                    self.checker.write_state(linked / "baseline.json", {})
                self.assertEqual(list(outside.iterdir()), [])

    def test_intermediate_state_links_are_rejected_before_read_or_create(self) -> None:
        outside = self.root / "outside-directory"
        outside.mkdir(mode=0o700)
        link = self.root / "linked-parent"
        self.link(link, outside, directory=True)
        for state in (link / "new-state", link / ".." / "new-state"):
            with self.subTest(state=state), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(
                    ValueError, "not links|symlink or reparse point"
                ):
                    self.checker.snapshot(self.repository, state)
                with self.assertRaisesRegex(
                    ValueError, "not links|symlink or reparse point"
                ):
                    self.checker.read_state(
                        self.checker.state_path(self.repository, state)
                    )
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / "new-state").exists())

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptors")
    def test_swapped_ancestor_cannot_redirect_directory_creation(self) -> None:
        parent = self.root / "parent"
        parent.mkdir(mode=0o700)
        original = self.root / "original-parent"
        outside = self.root / "outside-directory"
        outside.mkdir(mode=0o700)
        open_directory = os.open

        def swap(
            path: str | Path,
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if path == parent.name:
                parent.rename(original)
                parent.symlink_to(outside, target_is_directory=True)
            return open_directory(path, flags, mode, dir_fd=dir_fd)

        with patch.object(self.checker.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                self.checker.write_state(parent / "new-state" / "baseline.json", {})
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list(original.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_nested_state_is_private_and_writable_ancestors_are_rejected(self) -> None:
        self.state = self.root / "parent" / "nested" / "state"
        self.baseline = self.checker.state_path(self.repository, self.state)
        self.snapshot()
        self.assertEqual(
            self.checker.read_state(self.baseline)["root"], str(self.repository)
        )
        for directory in (self.state, self.state.parent, self.state.parent.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.state.parent.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "ancestors"):
            self.checker.read_state(self.baseline)
        with self.assertRaisesRegex(ValueError, "ancestors"):
            self.snapshot()
        self.assertEqual(stat.S_IMODE(self.state.parent.stat().st_mode), 0o777)

    def test_cli_does_not_resolve_away_state_symlink(self) -> None:
        outside = self.root / "outside-directory"
        outside.mkdir(mode=0o700)
        self.link(self.state, outside, directory=True)
        arguments = [
            "validate_changed_packages.py",
            "snapshot",
            "--root",
            str(self.repository),
            "--state-dir",
            str(self.state),
        ]
        with patch.object(sys, "argv", arguments), redirect_stderr(io.StringIO()):
            self.assertEqual(self.checker.main(), 1)
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_nonprivate_directory_is_rejected_without_changing_permissions(
        self,
    ) -> None:
        self.state.mkdir(mode=0o755)
        self.state.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.snapshot()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)
        self.assertEqual(list(self.state.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX ownership")
    def test_foreign_owned_directory_is_rejected(self) -> None:
        self.state.mkdir(mode=0o700)
        with patch.object(self.checker.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "owned"):
                self.snapshot()

    def test_hard_link_is_rejected(self) -> None:
        self.state.mkdir(mode=0o700)
        try:
            os.link(self.target, self.baseline)
        except OSError as exc:
            self.skipTest(f"hard links are unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "hard-linked"):
            self.snapshot()
        self.assertEqual(self.target.read_text(), "preserve")

    def test_atomic_replace_does_not_follow_swapped_destination(self) -> None:
        replace = os.replace

        def swap(
            source: str | Path, destination: str | Path, **kwargs: int | None
        ) -> None:
            self.link(self.baseline, self.target)
            replace(source, destination, **kwargs)

        with patch.object(self.checker.os, "replace", side_effect=swap):
            self.snapshot()
        self.assertEqual(self.target.read_text(), "preserve")
        self.assertFalse(self.baseline.is_symlink())
        self.assertEqual(
            self.checker.read_state(self.baseline)["root"], str(self.repository)
        )

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptors")
    def test_replaced_directory_cannot_redirect_write(self) -> None:
        outside = self.root / "outside-directory"
        outside.mkdir(mode=0o700)
        original = self.root / "original-state"
        replace = os.replace

        def swap(
            source: str | Path, destination: str | Path, **kwargs: int | None
        ) -> None:
            self.state.rename(original)
            self.link(self.state, outside, directory=True)
            replace(source, destination, **kwargs)

        with patch.object(self.checker.os, "replace", side_effect=swap):
            self.snapshot()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue((original / self.baseline.name).is_file())
        self.assertEqual(len(list(original.iterdir())), 1)

    def test_failed_replace_preserves_baseline_and_cleans_temporary(self) -> None:
        self.snapshot()
        previous = self.baseline.read_bytes()
        with patch.object(self.checker.os, "replace", side_effect=OSError("blocked")):
            with self.assertRaises(OSError):
                self.snapshot()
        self.assertEqual(self.baseline.read_bytes(), previous)
        self.assertEqual(list(self.state.iterdir()), [self.baseline])

    def test_windows_checks_ancestors_before_creating_state(self) -> None:
        def permissions(path: Path, private: bool = True) -> None:
            if path == self.root:
                raise ValueError("untrusted write access")

        with (
            patch.object(self.checker.sys, "platform", "win32"),
            patch.object(
                self.checker.windows_permissions_module(),
                "windows_directory_handle",
                return_value=nullcontext(),
            ),
            patch.object(
                self.checker, "windows_state_permissions", side_effect=permissions
            ),
            self.assertRaisesRegex(ValueError, "write access"),
        ):
            self.snapshot()
        self.assertFalse(self.state.exists())

    def test_windows_rejects_unsafe_state_directory_and_file(self) -> None:
        self.snapshot()
        previous = self.baseline.read_bytes()
        current_user = "S-1-5-21-1-2-3-1001"
        other_user = "S-1-5-21-1-2-3-1002"
        policy = self.checker.windows_permissions_module().validate_windows_acl
        for unsafe_path in (self.state, self.baseline):
            for owner, entries in (
                (other_user, []),
                (current_user, [(0, 0, 2, other_user)]),
            ):

                def permissions(path: Path, private: bool = True) -> None:
                    if path == unsafe_path:
                        policy(owner, current_user, entries, private)

                with (
                    self.subTest(path=unsafe_path.name, owner=owner),
                    patch.object(self.checker.sys, "platform", "win32"),
                    patch.object(
                        self.checker.windows_permissions_module(),
                        "windows_directory_handle",
                        return_value=nullcontext(),
                    ),
                    patch.object(
                        self.checker,
                        "windows_state_permissions",
                        side_effect=permissions,
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, "owner|write access"):
                        self.checker.read_state(self.baseline)
                    with self.assertRaisesRegex(ValueError, "owner|write access"):
                        self.snapshot()
                    self.assertEqual(self.baseline.read_bytes(), previous)
                    self.assertEqual(list(self.state.iterdir()), [self.baseline])

    def test_windows_checks_new_state_before_publication(self) -> None:
        self.snapshot()
        previous = self.baseline.read_bytes()

        def permissions(path: Path, private: bool = True) -> None:
            if path.suffix == ".tmp":
                raise ValueError("untrusted write access")

        with (
            patch.object(self.checker.sys, "platform", "win32"),
            patch.object(
                self.checker.windows_permissions_module(),
                "windows_directory_handle",
                return_value=nullcontext(),
            ),
            patch.object(
                self.checker, "windows_state_permissions", side_effect=permissions
            ),
            self.assertRaisesRegex(ValueError, "write access"),
        ):
            self.snapshot()
        self.assertEqual(self.baseline.read_bytes(), previous)
        self.assertEqual(list(self.state.iterdir()), [self.baseline])

    def test_windows_private_state_can_be_written_and_read(self) -> None:
        with (
            patch.object(self.checker.sys, "platform", "win32"),
            patch.object(
                self.checker.windows_permissions_module(),
                "windows_directory_handle",
                return_value=nullcontext(),
            ),
            patch.object(self.checker, "windows_state_permissions") as permissions,
        ):
            self.snapshot()
            self.assertEqual(
                self.checker.read_state(self.baseline)["root"], str(self.repository)
            )
        permissions.assert_any_call(self.root, private=False)
        permissions.assert_any_call(self.state, private=True)
        permissions.assert_any_call(self.baseline)
        self.assertTrue(
            any(call.args[0].suffix == ".tmp" for call in permissions.call_args_list)
        )

    def test_windows_state_handles_span_all_operations_and_failure_cleanup(
        self,
    ) -> None:
        active: list[Path] = []
        expected = [*reversed(self.state.parents), self.state]
        state_os = SimpleNamespace(**vars(os))

        @contextmanager
        def hold(path: Path):
            self.assertEqual(active, [*reversed(path.parents)])
            active.append(path)
            try:
                yield
            finally:
                self.assertEqual(active.pop(), path)

        def guarded(function):
            def operation(*args, **kwargs):
                self.assertEqual(active, expected)
                return function(*args, **kwargs)

            return operation

        def reject(*args, **kwargs):
            self.assertEqual(active, expected)
            raise OSError("publication failed")

        with (
            patch.object(self.checker.sys, "platform", "win32"),
            patch.object(self.checker, "os", state_os),
            patch.object(self.checker, "windows_state_permissions"),
            patch.object(
                self.checker.windows_permissions_module(),
                "windows_directory_handle",
                side_effect=hold,
            ),
            patch.object(state_os, "open", side_effect=guarded(os.open)),
            patch.object(state_os, "replace", side_effect=guarded(os.replace)),
            patch.object(state_os, "unlink", side_effect=guarded(os.unlink)),
        ):
            self.checker.write_state(self.baseline, {"original": True})
            self.assertEqual(active, [])
            self.assertEqual(self.checker.read_state(self.baseline), {"original": True})
            self.assertEqual(active, [])
            with patch.object(state_os, "replace", side_effect=reject):
                with self.assertRaisesRegex(OSError, "publication failed"):
                    self.checker.write_state(self.baseline, {"changed": True})
            self.assertEqual(active, [])
            self.assertEqual(self.checker.read_state(self.baseline), {"original": True})
            self.checker.remove_state(self.baseline)
            self.assertEqual(active, [])
        self.assertEqual(list(self.state.iterdir()), [])

    @unittest.skipUnless(sys.platform == "win32", "native Windows directory handles")
    def test_windows_state_operations_block_directory_replacement(self) -> None:
        state_os = SimpleNamespace(**vars(os))

        def guarded(function):
            def operation(*args, **kwargs):
                for path in (self.state, self.root):
                    with self.assertRaises(OSError):
                        path.rename(path.with_name(path.name + "-replacement"))
                return function(*args, **kwargs)

            return operation

        with (
            patch.object(self.checker, "os", state_os),
            patch.object(state_os, "open", side_effect=guarded(os.open)),
            patch.object(state_os, "replace", side_effect=guarded(os.replace)),
            patch.object(state_os, "unlink", side_effect=guarded(os.unlink)),
        ):
            self.checker.write_state(self.baseline, {"held": True})
            self.assertEqual(self.checker.read_state(self.baseline), {"held": True})
            self.checker.remove_state(self.baseline)
        self.state.rename(self.root / "released-state")

    @unittest.skipUnless(os.name == "nt", "native Windows DACLs")
    def test_windows_rejects_shared_state_dacl(self) -> None:
        self.snapshot()
        previous = self.baseline.read_bytes()
        result = subprocess.run(
            ["icacls", str(self.state), "/grant", "*S-1-1-0:(OI)(CI)M"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with self.assertRaisesRegex(ValueError, "write access"):
            self.snapshot()
        with self.assertRaisesRegex(ValueError, "write access"):
            self.checker.read_state(self.baseline)
        self.assertEqual(self.baseline.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
