"""Dependency-free packaging and bundled-validator checks for the public plugin."""

from __future__ import annotations

import ast
import copy
import importlib.util
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from urllib.parse import SplitResult, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "tmforge"
SKILL = PLUGIN / "skills" / "threat-modeling"
SCRIPTS = SKILL / "scripts"

layout_spec = importlib.util.spec_from_file_location(
    "plugin_layout_checks", SCRIPTS / "check_layout.py"
)
assert layout_spec is not None and layout_spec.loader is not None
check_layout = importlib.util.module_from_spec(layout_spec)
with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
    layout_spec.loader.exec_module(check_layout)


class PluginTests(unittest.TestCase):
    def test_managed_cli_version_matches_plugin_manifest(self):
        manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
        launcher = PLUGIN / "skills/threat-modeling-tmforge/scripts/tmforge.py"
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory).resolve() / "cache"
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(launcher),
                    "--cache-dir",
                    str(cache),
                    "--status",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["version"], manifest["version"])
            self.assertFalse(cache.exists())

    def test_manifest_matches_agent_plugins_and_product_version(self):
        manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        )
        self.assertEqual(manifest["name"], PLUGIN.name)
        self.assertTrue(
            set(manifest)
            <= {
                "$schema",
                "name",
                "version",
                "description",
                "author",
                "homepage",
                "repository",
                "license",
                "keywords",
                "extensions",
            }
        )
        self.assertTrue(manifest["description"])
        self.assertTrue(manifest["author"]["name"])
        self.assertEqual(manifest["license"], "MIT")
        self.assertEqual(
            manifest["repository"], "https://github.com/Hacks4Snacks/tmforge"
        )
        self.assertRegex(manifest["version"], r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
        for keyword in manifest["keywords"]:
            self.assertRegex(keyword, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        version = ET.parse(ROOT / "Directory.Build.props").findtext(".//VersionPrefix")
        self.assertEqual(manifest["version"], version)
        release = json.loads((ROOT / "release-please-config.json").read_text())
        self.assertIn(
            {
                "type": "json",
                "path": "plugins/tmforge/plugin.json",
                "jsonpath": "$.version",
            },
            release["packages"]["."]["extra-files"],
        )

    def test_repository_marketplace_matches_plugin_and_release_updater(self):
        catalog = json.loads(
            (ROOT / ".github/plugin/marketplace.json").read_text(encoding="utf-8")
        )
        manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["name"], "tmforge")
        self.assertEqual(catalog["owner"]["name"], manifest["author"]["name"])
        self.assertEqual(len(catalog["plugins"]), 1)
        entry = catalog["plugins"][0]
        for field in ("name", "description", "version"):
            self.assertEqual(entry[field], manifest[field])
        self.assertEqual(entry["source"], "./plugins/tmforge")
        self.assertEqual((ROOT / entry["source"]).resolve(), PLUGIN.resolve())
        release = json.loads(
            (ROOT / "release-please-config.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            {
                "type": "json",
                "path": ".github/plugin/marketplace.json",
                "jsonpath": "$.plugins[0].version",
            },
            release["packages"]["."]["extra-files"],
        )

    def test_plugin_license_matches_repository(self):
        self.assertEqual(
            (PLUGIN / "LICENSE.md").read_bytes(), (ROOT / "LICENSE.md").read_bytes()
        )

    def test_agent_and_skills_are_discoverable(self):
        agents = list((PLUGIN / "com.github.copilot" / "agents").glob("*.agent.md"))
        self.assertEqual([path.name for path in agents], ["strider.agent.md"])
        agent = agents[0].read_text(encoding="utf-8")
        frontmatter = agent.split("---", 2)[1]
        self.assertIn("name: Strider\n", frontmatter)
        self.assertNotRegex(frontmatter, r"(?m)^(target|id|skills):")
        self.assertIn("tools: [read, search, execute, edit, todo]", frontmatter)
        skills = sorted((PLUGIN / "skills").glob("*/SKILL.md"))
        self.assertEqual(
            [path.parent.name for path in skills],
            ["threat-modeling", "threat-modeling-tmforge"],
        )
        for path in [*agents, *skills]:
            with self.subTest(path=path.relative_to(PLUGIN)):
                text = path.read_text(encoding="utf-8")
                self.assertTrue(text.startswith("---\n"))
                header = text.split("---", 2)[1]
                description = re.search(r"(?m)^description: '([^\n]+)'$", header)
                self.assertIsNotNone(description)
                if description is not None:
                    self.assertGreaterEqual(len(description[1]), 10)
                    self.assertLessEqual(len(description[1]), 1024)
                if path.name == "SKILL.md":
                    self.assertIn(f"name: {path.parent.name}\n", header)
                    self.assertLess(len(text.splitlines()), 500)

    def test_local_links_stay_inside_plugin_or_owning_skill(self):
        skill_roots = [
            path.parent.resolve() for path in (PLUGIN / "skills").glob("*/SKILL.md")
        ]
        for path in PLUGIN.rglob("*.md"):
            # A skill's assets must be self-contained, not merely inside the plugin.
            link_root = next(
                (root for root in skill_roots if path.resolve().is_relative_to(root)),
                PLUGIN.resolve(),
            )
            text = path.read_text(encoding="utf-8")
            # Examples are not resource declarations.
            text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
            for link in re.findall(r"\[[^\]]+\]\(([^\s)]+)\)", text):
                parsed: SplitResult = urlsplit(link)
                if parsed.scheme or not parsed.path:
                    continue
                with self.subTest(path=path.relative_to(PLUGIN), link=link):
                    target = (path.parent / unquote(parsed.path)).resolve()
                    self.assertTrue(
                        target.is_relative_to(link_root),
                        f"{link} leaves its resource root: {link_root}",
                    )
                    self.assertTrue(target.exists(), str(target))

    def test_payload_has_no_binaries_caches_or_symlinks(self):
        forbidden = {
            "__pycache__",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".venv",
        }
        for path in PLUGIN.rglob("*"):
            with self.subTest(path=path.relative_to(PLUGIN)):
                self.assertFalse(path.is_symlink())
                self.assertNotIn(path.name, forbidden)
                if path.is_file():
                    self.assertIn(path.suffix, {".md", ".json", ".py"})
                    self.assertLess(path.stat().st_size, 5 * 1024 * 1024)
        self.assertTrue((SCRIPTS / "validate_changed_packages.py").is_file())
        self.assertFalse((SCRIPTS / "validate_change_packages.py").exists())
        self.assertFalse((PLUGIN / "mcp.json").exists())
        self.assertFalse((PLUGIN / "com.github.copilot" / "hooks").exists())

    def test_scripts_use_stdlib_and_python310_syntax(self):
        for path in PLUGIN.rglob("*.py"):
            siblings = {sibling.stem for sibling in path.parent.glob("*.py")}
            with self.subTest(path=path.relative_to(PLUGIN)):
                tree = ast.parse(
                    path.read_text(encoding="utf-8"), feature_version=(3, 10)
                )
                for node in ast.walk(tree):
                    modules: list[str] = []
                    if isinstance(node, ast.Import):
                        modules = [alias.name.split(".")[0] for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        modules = [node.module.split(".")[0]]
                    for module in modules:
                        self.assertIn(module, sys.stdlib_module_names | siblings)

    def test_bundled_self_tests(self):
        cases = [
            ("validate_analysis.py", "--self-test"),
            ("render_analysis.py", "--self-test"),
            ("validate_package.py", "--self-test"),
            ("generate_suppressions.py", "--self-test"),
            ("validate_changed_packages.py", "self-test"),
        ]
        with tempfile.TemporaryDirectory(prefix="tmforge-self-tests-") as directory:
            for script, option in cases:
                with self.subTest(script=script):
                    result = subprocess.run(
                        [sys.executable, "-B", str(SCRIPTS / script), option],
                        cwd=directory,
                        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )

    def test_standalone_report_has_no_companion_dependency(self):
        with tempfile.TemporaryDirectory(prefix="tmforge-markdown-") as directory:
            report = Path(directory).resolve() / "report.md"
            command = [
                sys.executable,
                "-B",
                str(SCRIPTS / "render_analysis.py"),
                str(SKILL / "assets" / "analysis.example.json"),
                "--standalone-report",
                str(report),
            ]
            for options in ([], ["--check"]):
                result = subprocess.run(
                    [*command, *options],
                    cwd=directory,
                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PATH=""),
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                [path.name for path in Path(directory).iterdir()], ["report.md"]
            )
            self.assertNotIn(
                "analysis.example.json", report.read_text(encoding="utf-8")
            )
            self.assertNotIn("data-flow.md", report.read_text(encoding="utf-8"))


class SidecarWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "suppression_writer", SCRIPTS / "generate_suppressions.py"
        )
        assert spec is not None and spec.loader is not None
        self.writer = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
            spec.loader.exec_module(self.writer)
            render_spec = importlib.util.spec_from_file_location(
                "output_renderer", SCRIPTS / "render_analysis.py"
            )
            assert render_spec is not None and render_spec.loader is not None
            self.renderer = importlib.util.module_from_spec(render_spec)
            render_spec.loader.exec_module(self.renderer)
        temporary = tempfile.TemporaryDirectory(prefix="tmforge-sidecar-write-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.package = self.root / "package"
        self.package.mkdir()
        self.sidecar = self.package / "model.tm.suppressions.json"
        self.target = self.root / "outside.txt"
        self.target.write_text("preserve", encoding="utf-8")
        self.document: dict[str, object] = {"files": []}

    def link(self, path: Path, target: Path, directory: bool = False) -> None:
        try:
            path.symlink_to(target, target_is_directory=directory)
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable: {exc}")

    def test_windows_output_handles_span_reads_writes_and_failure_cleanup(self) -> None:
        active: list[Path] = []
        expected = [*reversed(self.package.parents), self.package]
        windows_os = SimpleNamespace(**{**vars(os), "name": "nt"})
        replace = os.replace

        @contextmanager
        def hold(path: Path):
            self.assertEqual(active, [*reversed(path.parents)])
            active.append(path)
            try:
                yield
            finally:
                self.assertEqual(active.pop(), path)

        def publish(*args, **kwargs):
            self.assertEqual(active, expected)
            return replace(*args, **kwargs)

        def reject(path: Path) -> int:
            self.assertEqual(active, expected)
            raise OSError("verification failed")

        with (
            patch.object(self.writer, "os", windows_os),
            patch.object(self.writer, "windows_directory_handle", side_effect=hold),
            patch.object(windows_os, "replace", side_effect=publish),
        ):
            self.writer.write_sidecar(self.sidecar, self.document)
            self.assertEqual(active, [])
            with self.writer.artifact_stream(self.sidecar) as stream:
                self.assertEqual(active, expected)
                self.assertEqual(json.load(stream), self.document)
            self.assertEqual(active, [])
            with self.assertRaisesRegex(OSError, "verification failed"):
                self.writer.write_sidecar(self.sidecar, self.document, verify=reject)
            self.assertEqual(active, [])
            with self.writer.output_directory(self.package / "nested", create=True):
                self.assertEqual(active, [*expected, self.package / "nested"])
            self.assertEqual(active, [])
        self.assertEqual(json.loads(self.sidecar.read_text()), self.document)
        self.assertEqual(list(self.package.glob("*.tmp.json")), [])

    @unittest.skipUnless(sys.platform == "win32", "native Windows directory handles")
    def test_windows_artifact_operations_block_directory_replacement(self) -> None:
        def assert_pinned() -> None:
            for path in (self.package, self.root):
                with self.assertRaises(OSError):
                    path.rename(path.with_name(path.name + "-replacement"))

        def verify(path: Path) -> int:
            assert_pinned()
            return 0

        self.writer.write_sidecar(self.sidecar, self.document, verify=verify)
        with self.writer.artifact_stream(self.sidecar) as stream:
            assert_pinned()
            self.assertEqual(json.load(stream), self.document)
        replacement = self.package.with_name("released-package")
        self.package.rename(replacement)
        replacement.rename(self.package)

    def test_output_writers_reject_linked_parent_components(self) -> None:
        linked = self.root / "linked"
        self.link(linked, self.package, directory=True)
        for parent in (linked, linked / "nested", linked / ".." / "sibling"):
            for writer in (self.writer.write_sidecar, self.renderer.atomic_write):
                with self.subTest(parent=parent, writer=writer.__name__):
                    content = (
                        self.document
                        if writer == self.writer.write_sidecar
                        else "rendered"
                    )
                    with self.assertRaisesRegex(ValueError, "symlink"):
                        writer(parent / "output.json", content)
                    self.assertEqual(list(self.package.iterdir()), [])
                    self.assertFalse((self.root / "sibling").exists())

    def test_renderer_rejects_linked_file_even_when_contents_match(self) -> None:
        self.link(self.sidecar, self.target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.renderer.atomic_write(self.sidecar, "preserve")
        self.assertEqual(self.target.read_text(), "preserve")

    def test_renderer_creates_parents_and_preserves_unchanged_file(self) -> None:
        output = self.package / "nested" / "documents" / "data-flow.md"
        self.assertTrue(self.renderer.atomic_write(output, "rendered"))
        before = output.stat()
        self.assertFalse(self.renderer.atomic_write(output, "rendered"))
        self.assertEqual(output.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(list(output.parent.iterdir()), [output])

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptors")
    def test_renderer_parent_swap_cannot_redirect_publication(self) -> None:
        original = self.root / "original-package"
        outside = self.root / "outside-directory"
        outside.mkdir()
        replace = os.replace

        def swap(source: str | Path, destination: str | Path, **kwargs: Any) -> None:
            self.package.rename(original)
            self.package.symlink_to(outside, target_is_directory=True)
            replace(source, destination, **kwargs)

        with patch.object(self.renderer.os, "replace", side_effect=swap):
            self.renderer.atomic_write(self.sidecar, "rendered")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual((original / self.sidecar.name).read_text(), "rendered")
        self.assertEqual(len(list(original.iterdir())), 1)

    def test_regular_sidecar_is_replaced(self) -> None:
        self.sidecar.write_text("old", encoding="utf-8")
        self.writer.write_sidecar(self.sidecar, self.document)
        self.assertEqual(json.loads(self.sidecar.read_text()), self.document)
        self.assertEqual(list(self.package.iterdir()), [self.sidecar])

    def test_findings_preserve_spaces_and_drive_letters_in_filenames(self) -> None:
        target = "DS1: Snapshot volume (Generic Data Store) ID=ba30dd09-8f8f-5d2e-aa29-fb85377fb829"
        for filename in (
            "model.tm7",
            "checkout model.tm7",
            r"C:\model files\checkout model.tm7",
        ):
            for description in (
                f"Data store [{target}] stores sensitive data.",
                f"The {target} declares encryption.",
            ):
                with self.subTest(filename=filename, description=description):
                    text = f"{filename}: Warning TM1014: Diagram 1: {description}\n"
                    self.assertEqual(
                        self.writer.parse_findings(text),
                        [{"rule": "TM1014", "model": "Diagram 1", "target": target}],
                    )

    def test_unparsed_diagnostics_are_not_dropped_from_mixed_output(self) -> None:
        known = (
            "model.tm7: Warning TM1014: Diagram 1: Data store "
            "[DS1: Snapshot volume (Generic Data Store) "
            "ID=ba30dd09-8f8f-5d2e-aa29-fb85377fb829] stores sensitive data.\n"
        )
        unknown = (
            "model.tm7: Warning TM1014: Diagram 1: Unsupported target descriptor.\n"
        )
        self.assertEqual(
            self.writer.parse_findings("model.tm7: note: unrelated output\n"), []
        )
        for output in (unknown, known + unknown, unknown + known):
            with self.subTest(output=output):
                with self.assertRaisesRegex(
                    ValueError, "unparsed analyzer diagnostic.*TM1014"
                ):
                    self.writer.parse_findings(output)

    def test_suppressions_accept_alias_separators_named_pages_and_stencils(
        self,
    ) -> None:
        for separator in (": ", " "):
            for page in ("Diagram 1", "Storage", "Storage: private plane"):
                for stencil in ("Generic Data Store", "Azure Key Vault"):
                    with self.subTest(separator=separator, page=page, stencil=stencil):
                        target = f"DS1{separator}Snapshot volume ({stencil}) ID=ba30dd09-8f8f-5d2e-aa29-fb85377fb829"
                        for description in (
                            f"Data store [{target}] stores data.",
                            f"The {target} declares encryption.",
                        ):
                            findings = self.writer.parse_findings(
                                f"model.tm7: Warning TM1014: {page}: {description}"
                            )
                            self.assertEqual(len(findings), 1)
                            document, missing = self.writer.build_document(
                                findings,
                                {"TM1014": {"Snapshot volume": "Evidenced posture."}},
                                "model.tm7",
                            )
                            self.assertEqual(missing, [])
                            suppression = document["files"][0]["suppressions"][0]
                            self.assertEqual(suppression["target"], target)
                            self.assertEqual(suppression["model"], page)

    def test_suppression_naming_error_explains_the_expected_diagram_id(self) -> None:
        findings = [
            {
                "rule": "TM1014",
                "model": "Storage",
                "target": "Snapshot volume (Generic Data Store) ID=ba30dd09-8f8f-5d2e-aa29-fb85377fb829",
            }
        ]
        document, missing = self.writer.build_document(findings, {}, "model.tm7")
        self.assertEqual(document["files"][0]["suppressions"], [])
        self.assertEqual(len(missing), 1)
        self.assertIn("diagram ID", missing[0])
        self.assertIn("ID: Name", missing[0])
        self.assertIn("ID Name", missing[0])
        self.assertNotIn("unparsed", missing[0])

    def test_unparsed_diagnostics_never_publish_a_sidecar(self) -> None:
        diagnostic = (
            "model.tm7: Warning TM1014: Diagram 1: Unsupported target descriptor.\n"
        )
        saved_arguments = self.verification_arguments()
        analyzer = Path(saved_arguments[saved_arguments.index("--analyzer-output") + 1])
        for phase in ("analysis", "saved", "verification"):
            for existing in (False, True):
                for channel in ("stdout", "stderr"):
                    with self.subTest(phase=phase, existing=existing, channel=channel):
                        self.sidecar.unlink(missing_ok=True)
                        if existing:
                            self.sidecar.write_bytes(b"previous verified sidecar\n")
                        analyzer.write_text(
                            diagnostic if phase == "saved" else "", encoding="utf-8"
                        )
                        arguments = saved_arguments[:3] + ["--tmforge", "mock-tmforge"]
                        if phase != "analysis":
                            arguments += ["--analyzer-output", str(analyzer)]
                        if phase != "saved":
                            arguments.append("--verify")
                        output, errors = io.StringIO(), io.StringIO()
                        response = subprocess.CompletedProcess(
                            [],
                            2,
                            diagnostic if channel == "stdout" else "",
                            diagnostic if channel == "stderr" else "",
                        )
                        with (
                            patch.object(sys, "argv", arguments),
                            patch.object(
                                self.writer.subprocess, "run", return_value=response
                            ) as run,
                            redirect_stdout(output),
                            redirect_stderr(errors),
                        ):
                            self.assertEqual(self.writer.main(), 2)
                        self.assertEqual(run.call_count, 0 if phase == "saved" else 1)
                        self.assertIn(diagnostic.strip(), errors.getvalue())
                        self.assertEqual(output.getvalue(), "")
                        if existing:
                            self.assertEqual(
                                self.sidecar.read_bytes(),
                                b"previous verified sidecar\n",
                            )
                        else:
                            self.assertFalse(self.sidecar.exists())
                        self.assertEqual(list(self.package.glob(".*.tmp.json")), [])

    def test_symlink_and_dangling_symlink_are_rejected(self) -> None:
        for target in (self.target, self.root / "missing.txt"):
            with self.subTest(target=target.name):
                self.link(self.sidecar, target)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    self.writer.write_sidecar(self.sidecar, self.document)
                self.assertEqual(self.target.read_text(), "preserve")
                self.assertFalse((self.root / "missing.txt").exists())
                self.sidecar.unlink()

    def test_destination_swap_does_not_follow_symlink(self) -> None:
        replace = os.replace

        def swap(
            source: str | Path, destination: str | Path, **kwargs: int | None
        ) -> None:
            self.link(self.sidecar, self.target)
            replace(source, destination, **kwargs)

        with patch.object(self.writer.os, "replace", side_effect=swap):
            self.writer.write_sidecar(self.sidecar, self.document)
        self.assertFalse(self.sidecar.is_symlink())
        self.assertEqual(self.target.read_text(), "preserve")
        self.assertEqual(json.loads(self.sidecar.read_text()), self.document)

    @unittest.skipUnless(os.name == "posix", "POSIX directory descriptors")
    def test_parent_swap_does_not_redirect_sidecar_write(self) -> None:
        original = self.root / "original-package"
        outside = self.root / "outside-directory"
        outside.mkdir()
        replace = os.replace

        def swap(
            source: str | Path, destination: str | Path, **kwargs: int | None
        ) -> None:
            self.package.rename(original)
            self.package.symlink_to(outside, target_is_directory=True)
            replace(source, destination, **kwargs)

        with patch.object(self.writer.os, "replace", side_effect=swap):
            self.writer.write_sidecar(self.sidecar, self.document)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(
            json.loads((original / self.sidecar.name).read_text()), self.document
        )
        self.assertEqual(len(list(original.iterdir())), 1)

    def test_failed_replace_preserves_original_and_cleans_temporary(self) -> None:
        self.sidecar.write_text("old", encoding="utf-8")
        with patch.object(self.writer.os, "replace", side_effect=OSError("blocked")):
            with self.assertRaises(OSError):
                self.writer.write_sidecar(self.sidecar, self.document)
        self.assertEqual(self.sidecar.read_text(), "old")
        self.assertEqual(list(self.package.iterdir()), [self.sidecar])

    def test_verify_rejects_link_without_overwriting_target(self) -> None:
        model = self.package / "model.tm7"
        model.write_text("fixture", encoding="utf-8")
        justifications = self.package / "justifications.json"
        justifications.write_text("{}", encoding="utf-8")
        analyzer = self.root / "analyzer.txt"
        analyzer.write_text("", encoding="utf-8")
        self.link(self.sidecar, self.target)
        arguments = [
            "generate_suppressions.py",
            str(model),
            str(justifications),
            "--analyzer-output",
            str(analyzer),
            "--tmforge",
            "mock-tmforge",
            "--verify",
        ]
        with (
            patch.object(sys, "argv", arguments),
            patch.object(self.writer, "run_analyze") as analyze,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(self.writer.main(), 2)
        analyze.assert_not_called()
        self.assertEqual(self.target.read_text(), "preserve")

    def verification_arguments(self) -> list[str]:
        model = self.package / "model.tm7"
        model.write_text("fixture", encoding="utf-8")
        justifications = self.package / "justifications.json"
        justifications.write_text("{}", encoding="utf-8")
        analyzer = self.root / "analyzer.txt"
        analyzer.write_text("", encoding="utf-8")
        return [
            "generate_suppressions.py",
            str(model),
            str(justifications),
            "--analyzer-output",
            str(analyzer),
            "--verify",
        ]

    def test_suppression_outputs_never_replace_inputs(self) -> None:
        contents = {
            "model.tm7": b"original model",
            "justifications.json": b"{}\n",
            "analyzer.txt": b"",
        }
        for name, content in contents.items():
            (self.package / name).write_bytes(content)
        for name in contents:
            for verify in (False, True):
                for output in (
                    self.package / name,
                    self.package / ".." / self.package.name / name,
                ):
                    with self.subTest(name=name, verify=verify, output=output):
                        arguments = [
                            "generate_suppressions.py",
                            str(self.package / "model.tm7"),
                            str(self.package / "justifications.json"),
                            "--analyzer-output",
                            str(self.package / "analyzer.txt"),
                            "--out",
                            str(output),
                            "--tmforge",
                            "mock-tmforge",
                        ]
                        if verify:
                            arguments.append("--verify")
                        errors = io.StringIO()
                        with (
                            patch.object(sys, "argv", arguments),
                            patch.object(self.writer, "run_analyze") as analyze,
                            patch.object(self.writer, "write_sidecar") as write,
                            redirect_stderr(errors),
                        ):
                            self.assertEqual(self.writer.main(), 2)
                        self.assertIn("must be distinct", errors.getvalue())
                        analyze.assert_not_called()
                        write.assert_not_called()
                        self.assertEqual(
                            {
                                name: (self.package / name).read_bytes()
                                for name in contents
                            },
                            contents,
                        )

    def test_output_file_aliases_are_rejected(self) -> None:
        alias = self.package / "alias.json"
        for kind in ("hardlink", "symlink"):
            with self.subTest(kind=kind):
                if kind == "hardlink":
                    os.link(self.target, alias)
                else:
                    self.link(alias, self.target)
                try:
                    for output, source in ((alias, self.target), (self.target, alias)):
                        with self.assertRaisesRegex(ValueError, "must be distinct"):
                            self.writer.require_distinct_output(output, (source, None))
                    self.assertEqual(self.target.read_text(), "preserve")
                finally:
                    alias.unlink()

    def test_renderer_outputs_never_replace_the_ledger(self) -> None:
        fixture = (SCRIPTS.parent / "assets/analysis.example.json").read_bytes()
        for name in ("analysis.json", "data-flow.md", "threat-model.md"):
            ledger = self.package / name
            ledger.write_bytes(fixture)
            options = [
                ["--standalone-report", str(ledger)],
                [
                    "--standalone-report",
                    str(self.package / ".." / self.package.name / name),
                ],
            ]
            if name in self.renderer.DOCUMENT_NAMES:
                options.append([])
            for extra in options:
                with self.subTest(name=name, options=extra):
                    errors = io.StringIO()
                    with (
                        patch.object(
                            sys, "argv", ["render_analysis.py", str(ledger), *extra]
                        ),
                        patch.object(self.renderer, "atomic_write") as write,
                        redirect_stderr(errors),
                    ):
                        self.assertEqual(self.renderer.main(), 1)
                    self.assertIn("must be distinct", errors.getvalue())
                    write.assert_not_called()
                    self.assertEqual(ledger.read_bytes(), fixture)
            ledger.unlink()

    def test_distinct_standalone_report_preserves_ledger(self) -> None:
        ledger = self.package / "analysis.json"
        fixture = (SCRIPTS.parent / "assets/analysis.example.json").read_bytes()
        ledger.write_bytes(fixture)
        report = self.package / "report.md"
        with (
            patch.object(
                sys,
                "argv",
                ["render_analysis.py", str(ledger), "--standalone-report", str(report)],
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(self.renderer.main(), 0)
        self.assertEqual(ledger.read_bytes(), fixture)
        self.assertIn("## Threat Register", report.read_text())

    def test_verification_failures_never_publish_a_sidecar(self) -> None:
        finding = (
            "model.tm7: Warning TM1014: Diagram 1: Data store "
            "[DS1: Snapshot volume (Generic Data Store) "
            "ID=ba30dd09-8f8f-5d2e-aa29-fb85377fb829] stores sensitive data.\n"
        )
        cases = (
            ("missing tool", None, ("", None), 2),
            ("failed analyzer", ["mock-tmforge"], ("", "fixture failure"), 2),
            ("remaining finding", ["mock-tmforge"], (finding, None), 1),
            (
                "spaced filename",
                ["mock-tmforge"],
                (finding.replace("model.tm7", "checkout model.tm7"), None),
                1,
            ),
            (
                "Windows path",
                ["mock-tmforge"],
                (
                    finding.replace("model.tm7", r"C:\model files\checkout model.tm7"),
                    None,
                ),
                1,
            ),
            ("skipped suppression", ["mock-tmforge"], ("TM0001: skipped", None), 1),
        )
        arguments = self.verification_arguments()
        for existing in (False, True):
            for label, invocation, analysis, expected in cases:
                self.sidecar.unlink(missing_ok=True)
                if existing:
                    self.sidecar.write_bytes(b"previous verified sidecar\n")
                output = io.StringIO()
                with (
                    self.subTest(existing=existing, failure=label),
                    patch.object(sys, "argv", arguments),
                    patch.object(
                        self.writer, "resolve_invocation", return_value=invocation
                    ),
                    patch.object(
                        self.writer, "run_analyze", return_value=analysis
                    ) as analyze,
                    redirect_stdout(output),
                    redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(self.writer.main(), expected)
                    self.assertEqual(output.getvalue(), "")
                    if invocation is None:
                        analyze.assert_not_called()
                    else:
                        analyze.assert_called_once()
                    if existing:
                        self.assertEqual(
                            self.sidecar.read_bytes(), b"previous verified sidecar\n"
                        )
                    else:
                        self.assertFalse(self.sidecar.exists())
                    self.assertEqual(list(self.package.glob(".*.tmp.json")), [])

    def test_verified_candidate_is_published_only_after_success(self) -> None:
        arguments = self.verification_arguments()
        self.sidecar.write_text("previous", encoding="utf-8")
        candidates: list[Path] = []

        def analyze(
            invocation: list[str], model: Path, candidate: Path
        ) -> tuple[str, None]:
            self.assertEqual(invocation, ["mock-tmforge"])
            self.assertEqual(model.parent, self.package)
            self.assertEqual(candidate.parent, self.package)
            self.assertNotEqual(candidate, self.sidecar)
            self.assertEqual(self.sidecar.read_text(), "previous")
            self.assertEqual(
                json.loads(candidate.read_text())["files"][0]["file"], model.name
            )
            candidates.append(candidate)
            return "", None

        output = io.StringIO()
        with (
            patch.object(sys, "argv", arguments),
            patch.object(
                self.writer, "resolve_invocation", return_value=["mock-tmforge"]
            ),
            patch.object(self.writer, "run_analyze", side_effect=analyze),
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(self.writer.main(), 0)
        self.assertEqual(len(candidates), 1)
        self.assertFalse(candidates[0].exists())
        report = json.loads(output.getvalue())
        self.assertTrue(report["verified"])
        self.assertEqual(report["sidecar"], str(self.sidecar))
        self.assertEqual(
            json.loads(self.sidecar.read_text())["files"][0]["file"], "model.tm7"
        )


class NestedBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.geometry: dict[str, Any] = {
            "boundaries": {
                "outer": {"left": 0, "top": 0, "width": 600, "height": 600},
                "middle": {"left": 60, "top": 60, "width": 480, "height": 480},
                "inner": {"left": 120, "top": 120, "width": 360, "height": 360},
            },
            "elements": {
                "worker": {"left": 180, "top": 180, "width": 120, "height": 60},
            },
            "connectors": [],
        }
        self.ledger: dict[str, Any] = {
            "boundaries": [
                {"id": "outer", "axis": "network"},
                {"id": "middle", "axis": "network", "parentId": "outer"},
                {"id": "inner", "axis": "network", "parentId": "middle"},
            ],
            "elements": [
                {"id": "worker", "boundaryIds": ["inner", "middle", "outer"]},
            ],
        }

    def check(self):
        with (
            patch.object(check_layout, "read_geometry", return_value=self.geometry),
            patch.object(
                check_layout,
                "artifact_stream",
                return_value=io.BytesIO(json.dumps(self.ledger).encode()),
            ),
        ):
            return check_layout.check(Path("model.tm7"), Path("analysis.json"))

    def test_three_level_nesting_is_valid(self) -> None:
        report = self.check()
        self.assertTrue(report["ok"], report["failures"])

    def test_native_pages_have_independent_coordinate_systems(self) -> None:
        root = ET.Element(check_layout.MODEL + "ThreatModel")
        surfaces = ET.SubElement(root, check_layout.MODEL + "DrawingSurfaceList")
        for index in (1, 2):
            surface = ET.SubElement(
                surfaces, check_layout.MODEL + "DrawingSurfaceModel"
            )
            ET.SubElement(surface, check_layout.MODEL + "Header").text = f"Page {index}"
            borders = ET.SubElement(surface, check_layout.MODEL + "Borders")
            entry = ET.SubElement(
                borders, check_layout.ARRAYS + "KeyValueOfguidanyType"
            )
            shape = ET.SubElement(
                entry,
                check_layout.ARRAYS + "Value",
                {check_layout.XSI_TYPE: "StencilRectangle"},
            )
            for name, value in {
                "Guid": f"element-{index}",
                "Left": 40,
                "Top": 40,
                "Width": 190,
                "Height": 70,
            }.items():
                ET.SubElement(shape, check_layout.ABSTRACTS + name).text = str(value)
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory).resolve() / "model.tm7"
            ET.ElementTree(root).write(model, encoding="utf-8")
            geometry = check_layout.read_geometry(model)
            self.assertEqual(len(geometry["pages"]), 2)
            report = check_layout.check(model, None)
            self.assertTrue(report["ok"], report["failures"])
            self.assertEqual(report["elements"], 2)
            self.assertEqual(
                [page["page"] for page in report["pages"]], ["Page 1", "Page 2"]
            )
            first = geometry["pages"][0]["elements"]
            first["overlapping"] = dict(first["element-1"])
            with patch.object(check_layout, "read_geometry", return_value=geometry):
                report = check_layout.check(model, None)
            self.assertFalse(report["ok"])
            self.assertTrue(
                any(
                    message.startswith("Page 1:") and "overlap" in message
                    for message in report["failures"]
                )
            )

    def test_unrelated_boundary_overlap_is_rejected(self) -> None:
        self.geometry["boundaries"]["unrelated"] = {
            "left": 160,
            "top": 160,
            "width": 200,
            "height": 200,
        }
        failures = self.check()["failures"]
        self.assertIn("boundaries inner and unrelated overlap", failures)
        self.assertIn(
            "element worker overlaps boundary unrelated it does not belong to",
            failures,
        )

    def test_sibling_boundary_overlap_is_rejected(self) -> None:
        self.geometry["boundaries"]["sibling"] = {
            "left": 160,
            "top": 160,
            "width": 200,
            "height": 200,
        }
        self.ledger["boundaries"].append(
            {"id": "sibling", "axis": "network", "parentId": "middle"}
        )
        self.assertIn("boundaries inner and sibling overlap", self.check()["failures"])

    def test_element_outside_home_boundary_is_rejected(self) -> None:
        self.geometry["elements"]["worker"]["left"] = 80
        self.assertTrue(
            any(
                "drawn outside its boundary inner" in failure
                for failure in self.check()["failures"]
            )
        )

    def test_child_outside_ancestor_is_rejected(self) -> None:
        self.geometry["boundaries"]["inner"]["width"] = 500
        failures = self.check()["failures"]
        self.assertIn("boundary inner is drawn outside its ancestor middle", failures)
        self.assertIn("boundary inner is drawn outside its ancestor outer", failures)

    def test_indirect_parent_cycle_is_rejected(self) -> None:
        self.ledger["boundaries"][0]["parentId"] = "inner"
        self.assertIn(
            "boundary inner has a cyclic parent hierarchy", self.check()["failures"]
        )

    def test_connector_coordinate_limits_are_separate_from_shape_limits(self) -> None:
        connector = {
            "name": "F1: request",
            "sourceX": 800.0,
            "sourceY": 800.0,
            "targetX": 1000.0,
            "targetY": 1000.0,
            "handleX": 900.0,
            "handleY": 900.0,
        }
        for point in ("source", "target", "handle"):
            for axis, limit in (("X", 1990.0), ("Y", 2190.0)):
                coordinate = f"{point}{axis}"
                for value in (limit, limit + 1, float("inf"), float("nan")):
                    with self.subTest(coordinate=coordinate, value=value):
                        self.geometry["connectors"] = [{**connector, coordinate: value}]
                        report = self.check()
                        self.assertEqual(
                            report["ok"], value == limit, report["failures"]
                        )
                        if value != limit:
                            self.assertTrue(
                                any(
                                    coordinate in failure
                                    for failure in report["failures"]
                                )
                            )
        for handle_value in (None, 0):
            self.geometry["connectors"] = [
                {**connector, "handleX": handle_value, "handleY": handle_value}
            ]
            self.assertTrue(self.check()["ok"])

    def test_connector_limits_fail_cli_in_text_and_json_modes(self) -> None:
        self.geometry["connectors"] = [
            {
                "name": "F1",
                "sourceX": 800,
                "sourceY": 800,
                "targetX": 1000,
                "targetY": 1000,
                "handleX": 1991,
                "handleY": 900,
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "model.tm7"
            model.write_text("mock geometry, not a serialized model", encoding="utf-8")
            for options in ([], ["--json"]):
                with self.subTest(options=options):
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        patch.object(
                            sys, "argv", ["check_layout.py", str(model), *options]
                        ),
                        patch.object(
                            check_layout, "read_geometry", return_value=self.geometry
                        ),
                        redirect_stdout(output),
                        redirect_stderr(errors),
                    ):
                        self.assertEqual(check_layout.main(), 1)
                    if options:
                        self.assertFalse(json.loads(output.getvalue())["ok"])
                    self.assertIn("handleX", output.getvalue() + errors.getvalue())

    def test_direct_parent_cycle_is_rejected(self) -> None:
        self.ledger["boundaries"][2]["parentId"] = "inner"
        self.assertIn(
            "boundary inner has a cyclic parent hierarchy", self.check()["failures"]
        )


class PackageContractTests(unittest.TestCase):
    def setUp(self) -> None:
        with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
            spec = importlib.util.spec_from_file_location(
                "package_contract", SCRIPTS / "validate_package.py"
            )
            assert spec is not None and spec.loader is not None
            self.verifier = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.verifier)
        self.document = json.loads(
            (SCRIPTS.parent / "assets/analysis.example.json").read_text(
                encoding="utf-8"
            )
        )
        self.outputs: dict[str, Any] = {}
        for kind, ledger_kind in (
            ("boundaries", "boundaries"),
            ("components", "elements"),
            ("flows", "flows"),
        ):
            items = [
                {
                    "ID": item["id"].lower(),
                    "Name": f"{item['id']}: {item['name']}",
                    "DiagramHeader": "Diagram 1",
                    "SourceComponentID": str(item.get("sourceId", "")).lower(),
                    "TargetComponentID": str(item.get("targetId", "")).lower(),
                }
                for item in self.document[ledger_kind]
            ]
            self.outputs[kind] = {"items": items, "count": len(items)}
        self.outputs["diagrams"] = {
            "items": [
                {
                    "id": "diagram-id",
                    "header": "Diagram 1",
                    "componentCount": 2,
                    "connectorCount": 1,
                    "trustBoundaryCount": 1,
                }
            ],
            "count": 1,
        }

    def check(self) -> dict[str, Any]:
        return self.verifier.model_inventory_check(
            self.document, {"model.tm7": self.outputs}
        )

    def use_local_flow_numbers(self) -> None:
        self.document["pages"] = [
            {"id": "PG1", "name": "Runtime"},
            {"id": "PG2", "name": "Build"},
        ]
        for item in self.document["boundaries"] + self.document["elements"]:
            item["pageId"] = "PG1"
        for kind in ("boundaries", "components", "flows"):
            for item in self.outputs[kind]["items"]:
                item["DiagramHeader"] = "Runtime"
        self.outputs["diagrams"]["items"][0]["header"] = "Runtime"
        for alias, name in (("X2", "Build sender"), ("X3", "Build receiver")):
            self.document["elements"].append(
                {
                    "id": alias, "name": name, "kind": "external",
                    "boundaryIds": [], "pageId": "PG2",
                    "material": False, "evidenceIds": ["E001"],
                }
            )
            self.outputs["components"]["items"].append(
                {"ID": alias.lower(), "Name": f"{alias}: {name}",
                 "DiagramHeader": "Build"}
            )
        self.outputs["components"]["count"] += 2
        self.document["flows"][0]["displayId"] = "F1"
        self.document["flows"].append(
            {
                **self.document["flows"][0],
                "id": "F9", "displayId": "F1", "name": "Build records",
                "sourceId": "X2", "targetId": "X3",
                "crossesTrustBoundary": False, "material": False,
            }
        )
        self.outputs["flows"]["items"].append(
            {
                "ID": "f9", "Name": "F1: Build records", "DiagramHeader": "Build",
                "SourceComponentID": "x2", "TargetComponentID": "x3",
            }
        )
        self.outputs["flows"]["count"] += 1
        self.outputs["flow-aliases"] = {"f1": "F1", "f9": "F9"}
        self.outputs["diagrams"]["items"].append(
            {
                "id": "build-page", "header": "Build", "componentCount": 2,
                "connectorCount": 1, "trustBoundaryCount": 0,
            }
        )
        self.outputs["diagrams"]["count"] += 1

    def test_page_local_labels_preserve_stable_references_and_render_mapping(self) -> None:
        baseline = copy.deepcopy(self.document)
        self.use_local_flow_numbers()
        original = copy.deepcopy(self.document)
        self.assertEqual(self.verifier.validate_document(self.document), [])
        validator = sys.modules[self.verifier.validate_document.__module__]
        errors: list[str] = []
        validator.check_id_stability(self.document, baseline, errors.append)
        self.assertEqual(errors, [])
        rendered = self.verifier.render_documents(self.document)
        data_flow = rendered["data-flow.md"]
        self.assertIn('N_X2 -->|"F1: Build records"| N_X3', data_flow)
        self.assertIn("N_X2->>N_X3: F1 - Build records", data_flow)
        self.assertNotIn("F9: Build records", data_flow)
        self.assertRegex(
            data_flow, r"\|\s*PG2\s*\|\s*F1\s*\|\s*F9\s*\|\s*Build records\s*\|"
        )
        self.assertIn("stable IDs", rendered["threat-model.md"])
        renderer = sys.modules[self.verifier.render_documents.__module__]
        standalone = renderer.render_threat_model(
            self.document, "analysis.json", standalone=True
        )
        self.assertNotIn("data-flow.md", standalone)
        self.assertRegex(
            standalone, r"\|\s*PG2\s*\|\s*F1\s*\|\s*F9\s*\|\s*Build records\s*\|"
        )
        self.assertEqual(self.document, original)
        self.assertEqual(self.verifier.render_documents(self.document), rendered)
        self.assertEqual(self.document["coverage"], baseline["coverage"])
        self.assertEqual(self.document["threats"], baseline["threats"])

    def test_local_numbering_requires_pages_and_complete_contiguous_labels(self) -> None:
        self.document["flows"][0]["displayId"] = "F1"
        self.assertIn(
            "flows.F1: displayId requires a pages declaration",
            self.verifier.validate_document(self.document),
        )
        self.use_local_flow_numbers()
        second = {**self.document["flows"][1], "id": "F10", "name": "Build result",
                  "displayId": "F2"}
        self.document["flows"].append(second)
        self.assertEqual(self.verifier.validate_document(self.document), [])
        for value in ("F1", "F3", "F0", "F01", "1", None):
            with self.subTest(value=value):
                second["displayId"] = value
                self.assertTrue(self.verifier.validate_document(self.document))
        del second["displayId"]
        self.assertTrue(
            any("number every flow" in error
                for error in self.verifier.validate_document(self.document))
        )
        self.document["flows"].pop()
        del self.document["flows"][0]["displayId"]
        self.assertEqual(self.verifier.validate_document(self.document), [])
        self.document["flows"][1]["name"] = "F1: Build records"
        self.assertTrue(
            any("bare phrase" in error
                for error in self.verifier.validate_document(self.document))
        )

    def test_native_aliases_disambiguate_repeated_flow_labels(self) -> None:
        self.use_local_flow_numbers()
        self.assertEqual(self.check()["status"], "pass", self.check())
        baseline = copy.deepcopy(self.outputs)
        for aliases in ({}, {"f1": "F1", "f9": "F1"},
                        {"f1": "F9", "f9": "F1"}):
            with self.subTest(aliases=aliases):
                self.outputs["flow-aliases"] = aliases
                self.assertEqual(self.check()["status"], "fail")
        self.outputs = copy.deepcopy(baseline)
        self.outputs["flows"]["items"][1]["Name"] = "F9: Build records"
        self.assertIn("F9 name differs", self.check()["detail"])
        self.outputs = copy.deepcopy(baseline)
        self.outputs["flows"]["items"][1]["SourceComponentID"] = "x3"
        self.assertIn("F9 sourceId differs", self.check()["detail"])
        self.outputs = copy.deepcopy(baseline)
        self.outputs["flows"]["items"][1]["DiagramHeader"] = "Runtime"
        self.assertIn("F9 page differs", self.check()["detail"])

    def test_native_flow_alias_readback_rejects_missing_or_mismatched_objects(self) -> None:
        flow = self.outputs["flows"]["items"][0]
        detail = {
            "id": flow["ID"], "name": flow["Name"],
            "properties": {"Alias": "F1"},
        }
        with patch.object(
            self.verifier, "run_process",
            return_value=(json.dumps({"data": detail}), None),
        ) as run:
            aliases, errors = self.verifier.native_flow_aliases(
                Path("model.tm7"), self.outputs["flows"], ["mock-tmforge"], 60
            )
        self.assertEqual((aliases, errors), ({"f1": "F1"}, []))
        run.assert_called_once_with(
            ["mock-tmforge", "show", "model.tm7", "--id", "f1", "--json"], {0}, 60
        )
        invalid = [
            (json.dumps({"data": {**detail, "id": "wrong"}}), None),
            (json.dumps({"data": {**detail, "name": "wrong"}}), None),
            (json.dumps({"data": {**detail, "properties": {}}}), None),
            ("invalid json", None),
            (None, "readback failed"),
        ]
        for response in invalid:
            with self.subTest(response=response), patch.object(
                self.verifier, "run_process", return_value=response
            ):
                aliases, errors = self.verifier.native_flow_aliases(
                    Path("model.tm7"), self.outputs["flows"], ["mock-tmforge"], 60
                )
                self.assertEqual(aliases, {})
                self.assertTrue(errors)
        for inventory in ({}, {"items": "invalid"}, {"items": [{}]}):
            with self.subTest(inventory=inventory), patch.object(
                self.verifier, "run_process"
            ) as run:
                aliases, errors = self.verifier.native_flow_aliases(
                    Path("model.tm7"), inventory, ["mock-tmforge"], 60
                )
                self.assertEqual(aliases, {})
                self.assertTrue(errors)
                run.assert_not_called()

    def test_verified_lifecycle_requires_baseline_not_embedded_approval(self) -> None:
        self.document["scope"]["lifecycle"] = "verified"
        self.document["scope"].pop("baseline", None)
        self.assertIn(
            "verified lifecycle requires baseline.revision",
            self.verifier.validate_document(self.document),
        )
        self.document["scope"]["baseline"] = {
            "revision": "fixture-revision",
            "date": "2026-09-23",
        }
        self.assertEqual(self.verifier.validate_document(self.document), [])
        report = self.verifier.render_documents(self.document)["threat-model.md"]
        self.assertRegex(report, r"(?m)^\|\s*Revision\s*\|\s*Date\s*\|$")
        self.assertIn("fixture-revision", report)
        self.assertNotIn("Approved By", report)
        self.document["scope"]["baseline"]["approvedBy"] = "invented approver"
        self.assertIn(
            "scope.baseline: unknown fields: ['approvedBy']",
            self.verifier.validate_document(self.document),
        )

    def test_ledger_names_are_bare_phrases_not_display_labels(self) -> None:
        for kind in ("boundaries", "elements", "flows"):
            for separator in (": ", " "):
                with self.subTest(kind=kind, separator=separator):
                    document = copy.deepcopy(self.document)
                    item = document[kind][0]
                    item["name"] = f"{item['id']}{separator}{item['name']}"
                    errors = self.verifier.validate_document(document)
                    self.assertTrue(
                        any("bare phrase" in error for error in errors), errors
                    )

    def test_optional_pages_preserve_single_page_ledgers(self) -> None:
        self.assertEqual(self.verifier.validate_document(self.document), [])
        self.document["pages"] = [
            {"id": "PG1", "name": "Runtime"},
            {"id": "PG2", "name": "Distribution"},
        ]
        for item in self.document["boundaries"] + self.document["elements"]:
            item["pageId"] = "PG1"
        self.assertEqual(self.verifier.validate_document(self.document), [])
        for kind in ("boundaries", "elements"):
            for invalid in (None, "PG9"):
                with self.subTest(kind=kind, invalid=invalid):
                    document = copy.deepcopy(self.document)
                    if invalid is None:
                        del document[kind][0]["pageId"]
                    else:
                        document[kind][0]["pageId"] = invalid
                    self.assertTrue(
                        any(
                            "pageId" in error
                            for error in self.verifier.validate_document(document)
                        )
                    )

    def test_page_ids_survive_reordering_and_cannot_be_renumbered(self) -> None:
        validator = sys.modules[self.verifier.validate_document.__module__]
        baseline = {
            "pages": [{"id": "PG1", "name": "Runtime"}, {"id": "PG2", "name": "Build"}]
        }
        current = {"pages": list(reversed(copy.deepcopy(baseline["pages"])))}
        errors: list[str] = []
        validator.check_id_stability(current, baseline, errors.append)
        self.assertEqual(errors, [])
        current["pages"][0]["id"] = "PG3"
        validator.check_id_stability(current, baseline, errors.append)
        self.assertTrue(
            any("pages: existing entries were renumbered" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any(
                "pages: ids present in the baseline were removed" in error
                for error in errors
            ),
            errors,
        )

    def test_pages_reject_ambiguous_names_and_cross_page_references(self) -> None:
        self.document["pages"] = [
            {"id": "PG1", "name": "Runtime"},
            {"id": "PG2", "name": "Distribution"},
        ]
        for item in self.document["boundaries"] + self.document["elements"]:
            item["pageId"] = "PG1"
        duplicate = copy.deepcopy(self.document)
        duplicate["pages"][1]["name"] = "Runtime"
        self.assertIn(
            "duplicate page name: 'Runtime'", self.verifier.validate_document(duplicate)
        )
        duplicate["pages"][1]["id"] = "PG1"
        self.assertIn(
            "duplicate page id: PG1", self.verifier.validate_document(duplicate)
        )
        self.document["elements"][0]["pageId"] = "PG2"
        errors = self.verifier.validate_document(self.document)
        self.assertTrue(
            any("endpoints are on different pages" in error for error in errors), errors
        )
        self.document["boundaries"][0]["pageId"] = "PG2"
        errors = self.verifier.validate_document(self.document)
        self.assertTrue(
            any("boundary TB1 is on another page" in error for error in errors), errors
        )

    def test_unknown_nested_fields_fail_the_ledger_contract(self) -> None:
        self.document["pages"] = [{"id": "PG1", "name": "Runtime"}]
        for item in self.document["boundaries"] + self.document["elements"]:
            item["pageId"] = "PG1"
        paths: tuple[tuple[str | int, ...], ...] = (
            ("pages", 0),
            ("scope",),
            ("scope", "inputs", 0),
            ("scope", "ownershipDecision"),
            ("evidence", 0),
            ("boundaries", 0),
            ("elements", 0),
            ("flows", 0),
            ("assets", 0),
            ("threatActors", 0),
            ("coverage", 0),
            ("threats", 0),
            ("threats", 0, "currentControls", 0),
            ("threats", 0, "triage", 0),
            ("assumptions", 0),
            ("summary",),
            ("summary", "riskCounts"),
        )
        self.assertEqual(self.verifier.validate_document(self.document), [])
        for path in paths:
            with self.subTest(path=path):
                document = copy.deepcopy(self.document)
                target: Any = document
                location = ""
                for segment in path:
                    target = target[segment]
                    location += (
                        f"[{segment}]"
                        if isinstance(segment, int)
                        else ("." if location else "") + segment
                    )
                target["unexpectedReviewField"] = "must not be silently ignored"
                self.assertIn(
                    f"{location}: unknown fields: ['unexpectedReviewField']",
                    self.verifier.validate_document(document),
                )

    def test_page_membership_and_missing_empty_pages_are_checked(self) -> None:
        self.document["pages"] = [
            {"id": "PG1", "name": "Runtime"},
            {"id": "PG2", "name": "Build"},
        ]
        for item in self.document["boundaries"] + self.document["elements"]:
            item["pageId"] = "PG1"
        for kind in ("boundaries", "components", "flows"):
            for item in self.outputs[kind]["items"]:
                item["DiagramHeader"] = "Runtime"
        self.outputs["diagrams"]["items"][0]["header"] = "Runtime"
        self.assertIn("missing ledger pages: Build", self.check()["detail"])
        self.outputs["diagrams"]["items"].append(
            {
                "id": "page-two",
                "header": "Build",
                "componentCount": 0,
                "connectorCount": 0,
                "trustBoundaryCount": 0,
            }
        )
        self.outputs["diagrams"]["count"] = 2
        self.assertEqual(self.check()["status"], "pass", self.check())
        self.outputs["flows"]["items"][0]["DiagramHeader"] = "Build"
        self.outputs["diagrams"]["items"][0]["connectorCount"] = 0
        self.outputs["diagrams"]["items"][1]["connectorCount"] = 1
        self.assertIn("page differs from ledger", self.check()["detail"])

    def test_rendered_diagrams_do_not_join_objects_from_different_pages(self) -> None:
        self.document["pages"] = [
            {"id": "PG1", "name": "Runtime"},
            {"id": "PG2", "name": "Build"},
        ]
        for item in self.document["boundaries"] + self.document["elements"]:
            item["pageId"] = "PG1"
        self.document["elements"].append(
            {
                "id": "X99",
                "name": "Build worker",
                "kind": "external",
                "boundaryIds": [],
                "material": False,
                "evidenceIds": ["E001"],
                "pageId": "PG2",
            }
        )
        original = copy.deepcopy(self.document)
        rendered = self.verifier.render_documents(self.document)["data-flow.md"]
        diagrams = re.findall(
            r"```mermaid\nflowchart LR\n(.*?)```", rendered, re.DOTALL
        )
        self.assertEqual(len(diagrams), 2)
        self.assertNotIn("N_X99", diagrams[0])
        self.assertIn("N_X99", diagrams[1])
        self.assertNotIn("-->", diagrams[1])
        self.assertEqual(rendered.count("sequenceDiagram"), 2)
        self.assertIn("## Diagram Pages", rendered)
        self.assertEqual(self.document, original)
        self.assertEqual(
            self.verifier.render_documents(self.document)["data-flow.md"], rendered
        )

    @unittest.skipUnless(
        os.environ.get("TMFORGE_PLUGIN_TEST_CLI"), "opt-in real CLI round trip"
    )
    def test_multi_page_layout_round_trip_through_real_tmforge(self) -> None:
        self.check_multi_page_round_trip(local_numbering=False)

    @unittest.skipUnless(
        os.environ.get("TMFORGE_PLUGIN_TEST_CLI"), "opt-in real CLI round trip"
    )
    def test_local_flow_labels_round_trip_through_real_tmforge(self) -> None:
        self.check_multi_page_round_trip(local_numbering=True)

    def check_multi_page_round_trip(self, local_numbering: bool) -> None:
        invocation = shlex.split(os.environ["TMFORGE_PLUGIN_TEST_CLI"])
        if local_numbering:
            self.use_local_flow_numbers()
        else:
            self.document["pages"] = [
                {"id": "PG1", "name": "Runtime"},
                {"id": "PG2", "name": "Build"},
            ]
            for item in self.document["boundaries"] + self.document["elements"]:
                item["pageId"] = "PG1"
            self.document["elements"].append(
                {
                    "id": "X99",
                    "name": "Build worker",
                    "kind": "external",
                    "boundaryIds": [],
                    "material": False,
                    "evidenceIds": ["E001"],
                    "pageId": "PG2",
                }
            )
        forward = self.document["flows"][0]
        self.document["flows"].append(
            {
                **forward,
                "id": "F2",
                "name": "Return",
                "sourceId": forward["targetId"],
                "targetId": forward["sourceId"],
                "material": False,
                **({"displayId": "F2"} if local_numbering else {}),
            }
        )
        self.document["flows"].sort(key=lambda item: int(item["id"][1:]))
        self.assertEqual(self.verifier.validate_document(self.document), [])
        controls = {
            "data-store": "Encrypted",
            "process": "AuthenticationScheme",
            "external": "AuthenticatesItself",
            "actor": "AuthenticatesItself",
        }
        manifest = {
            "schema": "tmforge-manifest",
            "version": 1,
            "name": "Multi-page layout regression",
            "boundaries": [
                {"alias": item["id"], "name": f"{item['id']}: {item['name']}"}
                for item in self.document["boundaries"]
            ],
            "elements": [
                {
                    "alias": item["id"],
                    "name": f"{item['id']}: {item['name']}",
                    "kind": {"data-store": "store", "actor": "external"}.get(
                        item["kind"], item["kind"]
                    ),
                    **(
                        {"boundary": item["boundaryIds"][0]}
                        if item["boundaryIds"]
                        else {}
                    ),
                    "props": {controls[item["kind"]]: "Unknown"},
                }
                for item in self.document["elements"]
            ],
            "flows": [
                {
                    "alias": item["id"],
                    "name": f"{item.get('displayId', item['id'])}: {item['name']}",
                    "from": item["sourceId"],
                    "to": item["targetId"],
                    "props": {"Protocol": "Unknown"},
                }
                for item in self.document["flows"]
            ],
        }

        def run(command: list[str]) -> None:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        with tempfile.TemporaryDirectory(prefix="tmforge-plugin-pages-") as directory:
            package = Path(directory).resolve()
            ledger, source, candidate, model, exported = [
                package / name
                for name in (
                    "analysis.json",
                    "source.tm.json",
                    "candidate.tm.json",
                    "model.tm7",
                    "exported.tm.json",
                )
            ]
            ledger.write_text(json.dumps(self.document), encoding="utf-8")
            source.write_text(json.dumps(manifest), encoding="utf-8")
            run(
                [
                    sys.executable,
                    "-B",
                    str(SCRIPTS / "layout.py"),
                    str(ledger),
                    "--manifest",
                    str(source),
                    "--out",
                    str(candidate),
                ]
            )
            run([*invocation, "apply", str(candidate), "--out", str(model)])
            inventories: dict[str, Any] = {}
            checks = self.verifier.tmforge_model_checks(
                model, package, invocation, 60, inventories,
                flow_display_ids=local_numbering,
            )
            self.assertTrue(all(check["status"] == "pass" for check in checks), checks)
            parity = self.verifier.model_inventory_check(self.document, inventories)
            self.assertEqual(parity["status"], "pass", parity)
            geometry = check_layout.check(model, ledger)
            self.assertTrue(geometry["ok"], geometry)
            self.assertEqual(len(geometry["pages"]), 2)
            self.assertEqual(geometry["obstructedLabels"], 0, geometry)
            run(
                [
                    *invocation,
                    "export",
                    "--geometry",
                    "--out",
                    str(exported),
                    str(model),
                ]
            )
            actual = json.loads(exported.read_text(encoding="utf-8"))
            for kind in ("elements", "flows"):
                restored = {item["alias"]: item for item in actual[kind]}
                for original in manifest[kind]:
                    self.assertEqual(
                        restored[original["alias"]]["name"], original["name"]
                    )
                    for property_name, value in original["props"].items():
                        self.assertEqual(
                            restored[original["alias"]]["props"][property_name], value
                        )
            self.assertEqual(json.loads(source.read_text()), manifest)

    def test_optional_nested_objects_use_schema_field_names(self) -> None:
        document = copy.deepcopy(self.document)
        document["scope"]["baseline"] = {
            "revision": "a" * 40,
            "date": "2026-09-22",
        }
        document["scope"]["inputs"][0]["provider"] = "manual"
        document["assets"][0]["owner"] = "service-owner"
        document["flows"][0]["crossingExemptions"] = []
        self.assertEqual(self.verifier.validate_document(document), [])
        document["scope"]["baseline"]["unexpectedReviewField"] = True
        self.assertIn(
            "scope.baseline: unknown fields: ['unexpectedReviewField']",
            self.verifier.validate_document(document),
        )
        document["flows"][0]["crossingExemptions"] = [
            {
                "boundaryId": "TB1",
                "rationale": "Fixture exemption",
                "evidenceIds": ["E001"],
                "unexpectedReviewField": True,
            }
        ]
        self.assertIn(
            "flows[0].crossingExemptions[0]: unknown fields: ['unexpectedReviewField']",
            self.verifier.validate_document(document),
        )

    def test_unknown_field_errors_are_deterministic_and_do_not_mutate_input(
        self,
    ) -> None:
        self.document["scope"]["zUnknown"] = True
        self.document["scope"]["aUnknown"] = True
        self.document["unexpectedTopLevel"] = True
        original = copy.deepcopy(self.document)
        expected = [
            "unknown top-level fields: ['unexpectedTopLevel']",
            "scope: unknown fields: ['aUnknown', 'zUnknown']",
        ]
        self.assertEqual(self.verifier.validate_document(self.document), expected)
        self.assertEqual(self.verifier.validate_document(self.document), expected)
        self.assertEqual(self.document, original)

    def test_missing_material_cannot_remove_required_coverage(self) -> None:
        for collection in ("elements", "flows"):
            for item in self.document[collection]:
                del item["material"]
        self.document["coverage"] = []
        errors = self.verifier.validate_document(self.document)
        self.assertIn("elements[0]: missing required fields: ['material']", errors)
        self.assertIn("flows[0]: missing required fields: ['material']", errors)

    def test_material_flags_require_actual_booleans(self) -> None:
        invalid_values: tuple[object, ...] = (None, 0, 1, "true", [], {})
        for collection, field in (
            ("elements", "material"),
            ("flows", "material"),
            ("flows", "crossesTrustBoundary"),
        ):
            for value in invalid_values:
                with self.subTest(collection=collection, field=field, value=value):
                    document = copy.deepcopy(self.document)
                    document[collection][0][field] = value
                    document["coverage"] = []
                    self.assertIn(
                        f"{collection}[0].{field}: must be boolean",
                        self.verifier.validate_document(document),
                    )

    def test_missing_item_fields_and_wrong_nested_types_are_rejected(self) -> None:
        for collection, field in (
            ("elements", "kind"),
            ("elements", "name"),
            ("flows", "crossesTrustBoundary"),
            ("evidence", "reference"),
        ):
            with self.subTest(collection=collection, field=field):
                document = copy.deepcopy(self.document)
                del document[collection][0][field]
                self.assertIn(
                    f"{collection}[0]: missing required fields: ['{field}']",
                    self.verifier.validate_document(document),
                )
        self.document["elements"][0]["kind"] = []
        self.document["flows"][0]["sourceId"] = {}
        self.document["threats"][0]["likelihood"] = True
        errors = self.verifier.validate_document(self.document)
        self.assertTrue(
            any("elements[0].kind: must be one of" in error for error in errors)
        )
        self.assertIn("flows[0].sourceId: must be string", errors)
        self.assertIn("threats[0].likelihood: must be integer", errors)

    def test_schema_size_uniqueness_pattern_and_bounds_are_enforced(self) -> None:
        cases: tuple[tuple[tuple[str | int, ...], object, str], ...] = (
            (("threatActors",), [], "threatActors: must have at least 1 items"),
            (
                ("boundaries", 0, "name"),
                "",
                "boundaries[0].name: must have at least 1 characters",
            ),
            (
                ("elements", 1, "boundaryIds"),
                ["TB1", "TB1"],
                "elements[1].boundaryIds: items must be unique",
            ),
            (
                ("flows", 0, "assetIds"),
                ["AS1", "AS1"],
                "flows[0].assetIds: items must be unique",
            ),
            (("scope", "slug"), "Not a slug", "scope.slug: must match pattern"),
            (
                ("threats", 0, "confidence"),
                -0.1,
                "threats[0].confidence: violates minimum 0",
            ),
            (
                ("threats", 0, "likelihood"),
                6,
                "threats[0].likelihood: violates maximum 5",
            ),
            (
                ("threats", 0, "confidence"),
                float("nan"),
                "threats[0].confidence: must be finite",
            ),
            (("schemaVersion",), 2, "schemaVersion: must equal 1"),
        )
        for path, replacement, expected in cases:
            with self.subTest(path=path, replacement=replacement):
                document = copy.deepcopy(self.document)
                target: Any = document
                for segment in path[:-1]:
                    target = target[segment]
                target[path[-1]] = replacement
                errors = self.verifier.validate_document(document)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_schema_dates_and_conditional_requirements_are_enforced(self) -> None:
        validator = sys.modules[self.verifier.validate_document.__module__]
        for value in ("not-a-date", "2026-02-30", "20260922"):
            with self.subTest(date=value):
                document = copy.deepcopy(self.document)
                document["scope"]["baseline"] = {"revision": "abc", "date": value}
                self.assertIn(
                    "scope.baseline.date: must be a real calendar date in YYYY-MM-DD format",
                    validator.schema_field_errors(document),
                )
        for decision, field, required_value in (
            ("duplicate", "relatedThreatIds", [self.document["threats"][0]["id"]]),
            ("disputed", "reference", "review-thread"),
            ("resolved", "evidenceIds", ["E001"]),
        ):
            with self.subTest(decision=decision):
                document = copy.deepcopy(self.document)
                entry = document["threats"][0]["triage"][0]
                entry["decision"] = decision
                entry.pop(field, None)
                self.assertIn(
                    f"threats[0].triage[0]: missing required fields: ['{field}']",
                    validator.schema_field_errors(document),
                )
                entry[field] = required_value
                self.assertEqual(validator.schema_field_errors(document), [])
        for status in ("implemented", "partial", "unknown"):
            with self.subTest(status=status):
                document = copy.deepcopy(self.document)
                control = document["threats"][0]["currentControls"][0]
                control["implementationStatus"] = status
                control.pop("gap", None)
                self.assertEqual(
                    validator.schema_field_errors(document),
                    (
                        []
                        if status == "implemented"
                        else [
                            "threats[0].currentControls[0]: missing required fields: ['gap']"
                        ]
                    ),
                )

    def test_schema_boundary_values_pass_without_mutation(self) -> None:
        validator = sys.modules[self.verifier.validate_document.__module__]
        for confidence in (0, 1, 0.5):
            for score in (1, 25):
                document = copy.deepcopy(self.document)
                document["scope"]["baseline"] = {"revision": "a", "date": "2024-02-29"}
                document["boundaries"][0]["name"] = "x"
                document["threats"][0]["confidence"] = confidence
                document["threats"][0]["score"] = score
                before = copy.deepcopy(document)
                self.assertEqual(validator.schema_field_errors(document), [])
                self.assertEqual(document, before)

    def test_unsupported_schema_keywords_fail_even_for_absent_optional_fields(
        self,
    ) -> None:
        validator = sys.modules[self.verifier.validate_document.__module__]
        schema = copy.deepcopy(validator.analysis_schema())
        schema["properties"]["scope"]["properties"]["baseline"]["maxProperties"] = 3
        validator.analysis_schema.cache_clear()
        try:
            with patch.object(validator, "load_document", return_value=schema):
                with self.assertRaisesRegex(
                    ValueError, "unsupported analysis schema keywords.*maxProperties"
                ):
                    self.verifier.validate_document(self.document)
        finally:
            validator.analysis_schema.cache_clear()

    def disposition_document(self, status: str) -> dict[str, Any]:
        document = copy.deepcopy(self.document)
        document["evidence"][1]["type"] = "source"
        document["evidence"].extend(
            [
                {
                    "id": "E003",
                    "type": "test",
                    "reference": "test-run/42",
                    "claim": "The mitigation verification passed.",
                },
                {
                    "id": "E004",
                    "type": "change-record",
                    "reference": "risk-review/42",
                    "claim": "The decision owner approved this disposition.",
                },
                {
                    "id": "E005",
                    "type": "contract",
                    "reference": "transfer/42",
                    "claim": "The receiving service carries this risk.",
                },
            ]
        )
        threat = document["threats"][0]
        threat["status"] = status
        control = threat["currentControls"][0]
        control["implementationStatus"] = "implemented"
        control.pop("gap", None)
        threat["triage"].append(
            {
                "date": "2026-09-22",
                "reviewer": "decision-owner@example.com",
                "decision": "confirmed" if status == "accepted" else "resolved",
                "status": status,
                "rationale": "The cited records support this disposition.",
                "reference": "review/42",
                "evidenceIds": (
                    ["E002", "E003"]
                    if status == "mitigated"
                    else ["E004" if status == "accepted" else "E005"]
                ),
            }
        )
        return document

    def test_closed_statuses_require_explicit_latest_dispositions(self) -> None:
        for status in ("mitigated", "accepted", "transferred"):
            with self.subTest(status=status):
                document = copy.deepcopy(self.document)
                document["threats"][0]["status"] = status
                self.assertTrue(
                    any(
                        "latest triage entry" in error
                        for error in self.verifier.validate_document(document)
                    )
                )
                document = self.disposition_document(status)
                self.assertEqual(self.verifier.validate_document(document), [])
                report = self.verifier.render_documents(document)["threat-model.md"]
                self.assertIn("decision-owner@example.com", report)
                self.assertIn(
                    status,
                    report.partition("#### Review Disposition")[2].partition(
                        "#### Current Controls"
                    )[0],
                )
                document["threats"][0]["triage"].append(
                    {
                        "date": "2026-09-23",
                        "reviewer": "reviewer@example.com",
                        "decision": "disputed",
                        "rationale": "Closure needs more evidence.",
                        "reference": "review/43",
                    }
                )
                self.assertTrue(
                    any(
                        "latest triage entry" in error
                        for error in self.verifier.validate_document(document)
                    )
                )
        for status in ("open", "unknown"):
            document = copy.deepcopy(self.document)
            document["threats"][0]["status"] = status
            document["threats"][0]["mitigationOwner"] = "unassigned"
            self.assertEqual(self.verifier.validate_document(document), [])

    def test_mitigated_status_requires_implementation_and_verification(self) -> None:
        for label in (
            "partial control",
            "no control",
            "documentation only",
            "no implementation",
            "no verification",
            "unknown evidence",
        ):
            with self.subTest(case=label):
                document = self.disposition_document("mitigated")
                threat = document["threats"][0]
                if label == "partial control":
                    threat["currentControls"][0].update(
                        implementationStatus="partial", gap="Not deployed"
                    )
                elif label == "no control":
                    threat["currentControls"] = []
                elif label == "documentation only":
                    for evidence in document["evidence"]:
                        evidence["type"] = "documentation"
                else:
                    threat["triage"][-1]["evidenceIds"] = {
                        "no implementation": ["E003"],
                        "no verification": ["E002"],
                        "unknown evidence": ["E999"],
                    }[label]
                self.assertTrue(self.verifier.validate_document(document))

    def test_disposition_requires_recorded_decisions_and_named_owners(self) -> None:
        for status in ("mitigated", "accepted", "transferred"):
            for field, value in (
                ("reviewer", "unassigned"),
                ("decision", "deferred"),
                ("reference", " "),
                ("status", "unknown"),
            ):
                with self.subTest(status=status, field=field):
                    document = self.disposition_document(status)
                    document["threats"][0]["triage"][-1][field] = value
                    self.assertTrue(self.verifier.validate_document(document))
            if status != "transferred":
                document = self.disposition_document(status)
                document["threats"][0]["mitigationOwner"] = "unassigned"
                self.assertTrue(
                    any(
                        "named mitigationOwner" in error
                        for error in self.verifier.validate_document(document)
                    )
                )
        for status in ("accepted", "transferred"):
            document = self.disposition_document(status)
            document["threats"][0]["triage"][-1]["evidenceIds"] = ["E001"]
            self.assertTrue(
                any(
                    "change-record or contract" in error
                    for error in self.verifier.validate_document(document)
                )
            )

    def test_transfer_requires_named_owner_or_cited_contract(self) -> None:
        document = self.disposition_document("transferred")
        threat = document["threats"][0]
        threat["mitigationOwner"] = "unassigned"
        self.assertEqual(self.verifier.validate_document(document), [])
        threat["triage"][-1]["evidenceIds"] = ["E004"]
        self.assertTrue(
            any(
                "named mitigationOwner" in error
                for error in self.verifier.validate_document(document)
            )
        )
        threat["mitigationOwner"] = "Receiving service owner"
        self.assertEqual(self.verifier.validate_document(document), [])

    def test_explicit_historical_resolution_allows_reopening(self) -> None:
        document = self.disposition_document("mitigated")
        threat = document["threats"][0]
        threat["status"] = "open"
        threat["triage"].append(
            {
                "date": "2026-09-23",
                "reviewer": "reviewer@example.com",
                "decision": "corrected",
                "status": "open",
                "rationale": "A new deployment reintroduced the risk.",
            }
        )
        self.assertEqual(self.verifier.validate_document(document), [])

    def test_matching_inventory_and_case_insensitive_fields_pass(self) -> None:
        self.assertEqual(self.check()["status"], "pass")

    def test_unrelated_or_renamed_model_is_rejected(self) -> None:
        for name in (
            "P99: Unrelated process",
            "P1: Different process",
            "Request handler",
        ):
            with self.subTest(name=name):
                self.outputs["components"]["items"][1]["Name"] = name
                self.assertEqual(self.check()["status"], "fail")

    def test_missing_extra_duplicate_and_inconsistent_counts_fail(self) -> None:
        original = copy.deepcopy(self.outputs["components"])
        for items, count in (
            (original["items"][:1], 1),
            (original["items"] * 2, 4),
            (original["items"], 99),
            (None, 0),
        ):
            with self.subTest(items=items, count=count):
                self.outputs["components"] = {"items": items, "count": count}
                self.assertEqual(self.check()["status"], "fail")

    def test_reversed_flow_and_unknown_diagram_fail(self) -> None:
        self.outputs["flows"]["items"][0]["SourceComponentID"] = "p1"
        self.assertIn("F1 sourceId differs", self.check()["detail"])
        self.outputs["components"]["items"][0]["DiagramHeader"] = "Unrelated diagram"
        self.assertIn("unknown diagram", self.check()["detail"])

    def test_formal_package_requires_matching_lifecycle_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            self.assertEqual(
                self.verifier.lifecycle_check(self.document, package)["status"], "fail"
            )
            sidecar = package / "model.tm.evidence.json"
            sidecar.write_text(json.dumps({"state": "draft"}), encoding="utf-8")
            self.assertEqual(
                self.verifier.lifecycle_check(self.document, package)["status"], "pass"
            )
            sidecar.write_text(json.dumps({"state": "verified"}), encoding="utf-8")
            self.assertEqual(
                self.verifier.lifecycle_check(self.document, package)["status"], "fail"
            )
            sidecar.unlink()
            self.document["scope"]["mode"] = "verify"
            self.assertEqual(
                self.verifier.lifecycle_check(self.document, package)["status"],
                "skipped",
            )

    def test_linked_artifacts_fail_before_any_tmforge_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = root / "package"
            package.mkdir()
            outside = root / "external"
            outside.write_bytes(b"fixture")
            for name in (
                "analysis.json",
                "data-flow.md",
                "threat-model.md",
                "model.tm7",
                "model.tm.json",
                "model.tm.suppressions.json",
                "model.tm.evidence.json",
            ):
                for target in (outside, package / "internal-target", root / "missing"):
                    with self.subTest(name=name, target=target.name):
                        (package / "internal-target").write_bytes(b"fixture")
                        artifact = package / name
                        try:
                            artifact.symlink_to(target)
                        except OSError as exc:
                            self.skipTest(f"symlinks are unavailable: {exc}")
                        try:
                            with patch.object(self.verifier, "run_process") as run:
                                result = self.verifier.verify_package(
                                    package, ["mock-tmforge"]
                                )
                            self.assertFalse(result["valid"])
                            self.assertEqual(
                                result["checks"][0]["name"], "artifacts.paths"
                            )
                            self.assertIn("symlink", result["checks"][0]["detail"])
                            run.assert_not_called()
                        finally:
                            artifact.unlink()

    def test_model_reparse_attribute_fails_before_tmforge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            model = package / "model.tm7"
            model.write_bytes(b"fixture")
            original_stat = os.stat

            def reparse(path, *args, **kwargs):
                if (
                    path in (model.name, model)
                    and kwargs.get("follow_symlinks") is False
                ):
                    return SimpleNamespace(
                        st_mode=stat.S_IFREG,
                        st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                    )
                return original_stat(path, *args, **kwargs)

            with (
                patch.object(os, "stat", side_effect=reparse),
                patch.object(self.verifier, "run_process") as run,
            ):
                result = self.verifier.verify_package(package, ["mock-tmforge"])
            self.assertFalse(result["valid"])
            self.assertIn("reparse", result["checks"][0]["detail"])
            run.assert_not_called()

    def test_linked_package_and_direct_readers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package = root / "package"
            package.mkdir()
            model = package / "model.tm7"
            outside = root / "model.tm7"
            outside.write_bytes(b"fixture")
            linked = root / "linked"
            try:
                linked.symlink_to(package, target_is_directory=True)
                model.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlinks are unavailable: {exc}")
            self.assertFalse(self.verifier.verify_package(linked)["valid"])
            for reader in (
                self.verifier.file_sha256,
                self.verifier.load_document,
                check_layout.read_geometry,
            ):
                with (
                    self.subTest(reader=reader.__name__),
                    self.assertRaisesRegex(ValueError, "symlink"),
                ):
                    reader(model)
            with patch.object(self.verifier, "run_process") as run:
                checks = self.verifier.tmforge_model_checks(
                    model, package, ["mock-tmforge"], 1
                )
            self.assertEqual(checks[0]["status"], "fail")
            run.assert_not_called()

    def test_package_verdict_includes_model_parity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            (package / "analysis.json").write_text(
                json.dumps(self.document), encoding="utf-8"
            )
            (package / "model.tm7").write_text("mock model, not XML", encoding="utf-8")
            (package / "model.tm.evidence.json").write_text(
                json.dumps({"state": "draft"}), encoding="utf-8"
            )
            self.verifier.write_documents(
                self.verifier.render_documents(self.document), package
            )

            def run(
                command: list[str], allowed: set[int], timeout: int
            ) -> tuple[str, None]:
                if command[1] in {"--version", "render"}:
                    return "fixture", None
                data = (
                    self.outputs.get(command[2], {"items": []})
                    if command[1] == "list"
                    else {"threats": []}
                )
                return json.dumps({"data": data}), None

            with patch.object(self.verifier, "run_process", side_effect=run):
                self.assertTrue(
                    self.verifier.verify_package(package, ["mock-tmforge"])["valid"]
                )
                self.outputs["components"]["items"][1][
                    "Name"
                ] = "P99: Unrelated process"
                report = self.verifier.verify_package(package, ["mock-tmforge"])
                self.assertFalse(report["valid"])
                self.assertTrue(
                    any(
                        check["name"] == "models.parity" and check["status"] == "fail"
                        for check in report["checks"]
                    )
                )

    def test_inventories_cover_the_ledger_across_multiple_models(self) -> None:
        self.document["elements"].append({"id": "X1", "name": "Other system"})
        other = {
            "boundaries": {"items": [], "count": 0},
            "flows": {"items": [], "count": 0},
            "components": {
                "items": [
                    {
                        "id": "other-id",
                        "name": "X1: Other system",
                        "diagramHeader": "Other diagram",
                    }
                ],
                "count": 1,
            },
            "diagrams": {
                "items": [
                    {
                        "id": "other-diagram-id",
                        "header": "Other diagram",
                        "componentCount": 1,
                        "connectorCount": 0,
                        "trustBoundaryCount": 0,
                    }
                ],
                "count": 1,
            },
        }
        models = {"model.tm7": self.outputs, "other.tm7": other}
        self.assertEqual(
            self.verifier.model_inventory_check(self.document, models)["status"], "pass"
        )
        models["duplicate.tm7"] = other
        self.assertIn(
            "duplicate components alias X1",
            self.verifier.model_inventory_check(self.document, models)["detail"],
        )

    def test_suppression_contract_and_analyzer_failures_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            model = package / "checkout model.tm7"
            model.write_text("fixture", encoding="utf-8")
            sidecar = package / "model.tm.suppressions.json"
            valid = {
                "files": [
                    {
                        "file": model.name,
                        "suppressions": [
                            {
                                "rule": "TM1014",
                                "model": "Diagram 1",
                                "target": "fixture descriptor",
                                "justification": "Reviewed and accepted",
                            }
                        ],
                    }
                ]
            }
            for contents in (
                "{invalid",
                "{}",
                json.dumps({"files": []}),
                json.dumps({"files": [{"file": "../escape.tm7", "suppressions": []}]}),
                json.dumps(
                    {
                        "files": [
                            {"file": model.name, "suppressions": [{"rule": "TM1014"}]}
                        ]
                    }
                ),
            ):
                sidecar.write_text(contents, encoding="utf-8")
                with (
                    self.subTest(contents=contents),
                    patch.object(self.verifier, "run_process") as run,
                ):
                    self.assertEqual(
                        self.verifier.suppression_checks(package, ["mock-tmforge"], 90)[
                            0
                        ]["status"],
                        "fail",
                    )
                    run.assert_not_called()
            sidecar.write_text(json.dumps(valid), encoding="utf-8")
            with patch.object(
                self.verifier,
                "run_process",
                return_value=(json.dumps({"data": {"ruleReports": []}}), None),
            ) as run:
                self.assertEqual(
                    self.verifier.suppression_checks(package, ["mock-tmforge"], 90)[0][
                        "status"
                    ],
                    "pass",
                )
                self.assertEqual(run.call_args.args[1:], ({0}, 90))
                self.assertIn(str(sidecar), run.call_args.args[0])
            for failure in (
                "exit 2: TM0001 skipped suppression",
                "exit 2: remaining finding",
                "timed out",
            ):
                with (
                    self.subTest(failure=failure),
                    patch.object(
                        self.verifier, "run_process", return_value=(None, failure)
                    ),
                ):
                    check = self.verifier.suppression_checks(
                        package, ["mock-tmforge"], 90
                    )[0]
                    self.assertEqual(check["status"], "fail")
                    self.assertIn(failure, check["detail"])
            self.assertEqual(
                self.verifier.suppression_checks(package, None, 90)[0]["status"], "fail"
            )


class FlowLabelSpacingTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "label_spacing", SCRIPTS / "layout.py"
        )
        assert spec is not None and spec.loader is not None
        self.layout = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
            spec.loader.exec_module(self.layout)
        self.members = {"left": ["P1"], "middle": ["P2"], "right": ["P3"]}
        self.columns = [["left"], ["middle"], ["right"]]
        self.elements: list[dict[str, Any]] = [
            {"id": alias, "boundaryIds": [group]}
            for group, aliases in self.members.items()
            for alias in aliases
        ]
        self.flow = {"id": "F1", "name": "x" * 150, "sourceId": "P1", "targetId": "P3"}

    def test_nonadjacent_label_increases_all_spanned_gaps(self) -> None:
        gaps = self.layout.column_gaps(self.members, self.columns, [self.flow])
        self.assertEqual(gaps, [384.0, 384.0])
        boxes, _ = self.layout.compute(self.elements, [self.flow], columns=self.columns)
        clear_span = boxes["P3"][0] - (boxes["P1"][0] + boxes["P1"][2])
        self.assertGreaterEqual(clear_span, self.layout._label_width(self.flow))

    def test_reverse_flow_uses_the_same_gaps(self) -> None:
        reverse = {**self.flow, "sourceId": "P3", "targetId": "P1"}
        self.assertEqual(
            self.layout.column_gaps(self.members, self.columns, [reverse]),
            self.layout.column_gaps(self.members, self.columns, [self.flow]),
        )

    def test_label_width_uses_the_display_id_without_changing_identity(self) -> None:
        flow = {**self.flow, "id": "F12345", "displayId": "F1"}
        original = copy.deepcopy(flow)
        self.assertEqual(
            self.layout._label_width(flow), self.layout._label_width(self.flow)
        )
        self.assertEqual(flow, original)

    def test_adjacent_and_overlapping_flows_remain_order_independent(self) -> None:
        adjacent = {**self.flow, "targetId": "P2", "name": "x" * 50}
        self.assertEqual(
            self.layout.column_gaps(self.members, self.columns, [adjacent]),
            [318.0, 110.0],
        )
        self.assertEqual(
            self.layout.column_gaps(self.members, self.columns, [adjacent, self.flow]),
            self.layout.column_gaps(self.members, self.columns, [self.flow, adjacent]),
        )

    def test_short_same_column_and_unknown_flows_preserve_minimum_gaps(self) -> None:
        flows = [
            {**self.flow, "name": "short"},
            {**self.flow, "targetId": "P1"},
            {**self.flow, "targetId": "missing"},
        ]
        self.assertEqual(
            self.layout.column_gaps(self.members, self.columns, flows), [110.0, 110.0]
        )

    def test_gap_cap_is_preserved_for_oversized_labels(self) -> None:
        huge = {**self.flow, "name": "x" * 1000}
        self.assertEqual(
            self.layout.column_gaps(self.members, self.columns, [huge]), [420.0, 420.0]
        )

    def test_six_columns_wrap_without_dropping_shapes_or_memberships(self) -> None:
        elements = [
            {"id": f"P{index}", "boundaryIds": [f"TB{index}"]} for index in range(1, 7)
        ]
        flows = [
            {
                "id": f"F{index}",
                "name": "request",
                "sourceId": f"P{index}",
                "targetId": f"P{index + 1}",
            }
            for index in range(1, 6)
        ]
        original = copy.deepcopy((elements, flows))
        boxes, score = self.layout.compute(elements, flows)
        self.assertEqual(len(boxes), 12)
        self.assertLessEqual(
            max(box[0] + box[2] for box in boxes.values()), self.layout.MAX_CANVAS_X
        )
        self.assertLessEqual(
            max(box[1] + box[3] for box in boxes.values()), self.layout.MAX_CANVAS_Y
        )
        self.assertGreater(boxes["TB6"][1], boxes["TB1"][1] + boxes["TB1"][3])
        for element in elements:
            child = boxes[element["id"]]
            parent = boxes[element["boundaryIds"][0]]
            self.assertGreaterEqual(child[0], parent[0])
            self.assertGreaterEqual(child[1], parent[1])
            self.assertLessEqual(child[0] + child[2], parent[0] + parent[2])
            self.assertLessEqual(child[1] + child[3], parent[1] + parent[3])
        self.assertEqual((elements, flows), original)
        self.assertEqual(self.layout.compute(elements, flows), (boxes, score))

    def test_slot_permutation_prefers_clear_labels_over_shorter_edges(self) -> None:
        members = {"left": ["P1", "P2"], "middle": ["P3", "P4"], "right": ["P5", "P6"]}
        elements = [
            {"id": alias, "boundaryIds": [group]}
            for group, aliases in members.items()
            for alias in aliases
        ]
        flows = [{"id": "F1", "name": "request", "sourceId": "P1", "targetId": "P5"}]
        columns = [[group] for group in members]
        before = self.layout._place(members, members, columns)
        self.assertTrue(self.layout.label_obstructions(elements, flows, before))
        boxes, score = self.layout.compute(elements, flows, columns=columns)
        self.assertEqual(self.layout.label_obstructions(elements, flows, boxes), [])
        self.assertEqual(score[0], 0)
        self.assertEqual(
            self.layout.compute(elements, flows, columns=columns), (boxes, score)
        )

    def test_seeded_restarts_explore_cycle_layerings_without_mutating_topology(
        self,
    ) -> None:
        elements = [
            {"id": f"P{index}", "boundaryIds": [f"TB{index}"]} for index in range(1, 5)
        ]
        flows = [
            {
                "id": f"F{index}",
                "name": "hop",
                "sourceId": f"P{index}",
                "targetId": f"P{index % 4 + 1}",
            }
            for index in range(1, 5)
        ]
        original = copy.deepcopy((elements, flows))
        derive = self.layout.derive_columns
        visited: list[list[list[str]]] = []

        def record(*args, **kwargs):
            columns = derive(*args, **kwargs)
            visited.append(columns)
            return columns

        with patch.object(self.layout, "derive_columns", side_effect=record):
            result = self.layout.compute(elements, flows, restarts=8, seed=7)
        self.assertEqual(len(visited), 9)
        self.assertGreater(
            len({tuple(tuple(column) for column in columns) for columns in visited}), 1
        )
        self.assertEqual(
            self.layout.compute(elements, flows, restarts=8, seed=7), result
        )
        self.assertEqual((elements, flows), original)
        columns = [[f"TB{index}"] for index in range(1, 5)]
        with patch.object(self.layout, "derive_columns") as derive_fixed:
            fixed = self.layout.compute(
                elements, flows, columns=columns, restarts=8, seed=7
            )
        derive_fixed.assert_not_called()
        self.assertEqual(fixed, self.layout.compute(elements, flows, columns=columns))

    def test_restarts_improve_a_fixed_layering_local_minimum(self) -> None:
        elements = [
            {"id": f"P{index}", "boundaryIds": [f"TB{index}"]} for index in range(1, 6)
        ]
        pairs = [(1, 2), (1, 4), (2, 3), (2, 5), (5, 1), (5, 2), (5, 4)]
        flows = [
            {
                "id": f"F{index}",
                "name": "hop",
                "sourceId": f"P{source}",
                "targetId": f"P{target}",
            }
            for index, (source, target) in enumerate(pairs, start=1)
        ]
        original = copy.deepcopy((elements, flows))
        baseline, baseline_score = self.layout.compute(elements, flows)
        self.assertEqual(baseline_score[0], 1)
        self.assertEqual(self.layout.label_obstructions(elements, flows, baseline), [])
        previous = (0, *baseline_score)
        for restarts in (1, 4, 8):
            with self.subTest(restarts=restarts):
                boxes, score = self.layout.compute(
                    elements, flows, restarts=restarts, seed=0
                )
                current = (
                    len(self.layout.label_obstructions(elements, flows, boxes)),
                    *score,
                )
                self.assertLessEqual(current, previous)
                self.assertEqual(
                    self.layout.compute(elements, flows, restarts=restarts, seed=0),
                    (boxes, score),
                )
                previous = current
        self.assertEqual(previous[:2], (0, 0))
        self.assertEqual((elements, flows), original)

    def test_intermediate_shape_obstruction_is_reported(self) -> None:
        boxes, _ = self.layout.compute(self.elements, [self.flow], columns=self.columns)
        failures = self.layout.label_obstructions(self.elements, [self.flow], boxes)
        self.assertTrue(any("overlaps P2" in failure for failure in failures), failures)
        self.assertFalse(
            any(
                "overlaps P1" in failure or "overlaps P3" in failure
                for failure in failures
            ),
            failures,
        )

    def test_page_layouts_are_independent_and_selectable(self) -> None:
        document = {
            "pages": [{"id": "PG1", "name": "Runtime"}, {"id": "PG2", "name": "Build"}],
            "boundaries": [],
            "elements": [{"id": "P1", "pageId": "PG1"}, {"id": "P2", "pageId": "PG2"}],
            "flows": [],
        }
        original = copy.deepcopy(document)
        layouts = self.layout.compute_pages(document)
        self.assertEqual([layout["id"] for layout in layouts], ["PG1", "PG2"])
        self.assertEqual(set(layouts[0]["boxes"]), {"P1"})
        self.assertEqual(set(layouts[1]["boxes"]), {"P2"})
        self.assertEqual(layouts[0]["boxes"]["P1"], layouts[1]["boxes"]["P2"])
        for selector in ("PG2", "Build", "2"):
            self.assertEqual(
                self.layout.compute_pages(document, page=selector), [layouts[1]]
            )
        with self.assertRaisesRegex(ValueError, "unknown or ambiguous page"):
            self.layout.compute_pages(document, page="missing")
        self.assertEqual(document, original)
        document["flows"] = [{"id": "F1", "sourceId": "P1", "targetId": "P2"}]
        with self.assertRaisesRegex(ValueError, "different pages"):
            self.layout.compute_pages(document)
        document["flows"][0]["targetId"] = "missing"
        with self.assertRaisesRegex(ValueError, "declared elements"):
            self.layout.compute_pages(document)

    def test_cli_page_json_and_input_errors(self) -> None:
        document = {
            "pages": [{"id": "PG1", "name": "Runtime"}],
            "elements": [{"id": "P1", "pageId": "PG1"}],
            "flows": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "analysis.json"
            ledger.write_text(json.dumps(document), encoding="utf-8")
            output, errors = io.StringIO(), io.StringIO()
            with (
                patch.object(
                    sys,
                    "argv",
                    ["layout.py", str(ledger), "--json", "--page", "Runtime"],
                ),
                redirect_stdout(output),
                redirect_stderr(errors),
            ):
                self.assertEqual(self.layout.main(), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["pages"][0]["id"], "PG1")
            self.assertEqual(set(result["pages"][0]["boxes"]), {"P1"})
            for content in ("invalid json", "[]", '{"pages": []}'):
                with self.subTest(content=content):
                    ledger.write_text(content, encoding="utf-8")
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        patch.object(sys, "argv", ["layout.py", str(ledger), "--json"]),
                        redirect_stdout(output),
                        redirect_stderr(errors),
                    ):
                        self.assertEqual(self.layout.main(), 2)
                    self.assertEqual(output.getvalue(), "")
                    self.assertIn("ERROR:", errors.getvalue())

    def test_manifest_refresh_preserves_controls_stencils_and_direction(self) -> None:
        document = {
            "pages": [{"id": "PG1", "name": "Runtime"}, {"id": "PG2", "name": "Build"}],
            "boundaries": [],
            "elements": [
                {"id": "P1", "name": "Sender", "boundaryIds": [], "pageId": "PG1"},
                {"id": "P2", "name": "Receiver", "boundaryIds": [], "pageId": "PG1"},
            ],
            "flows": [
                {"id": "F1", "name": "request", "sourceId": "P1", "targetId": "P2"}
            ],
        }
        manifest = {
            "schema": "tmforge-manifest",
            "version": 1,
            "name": "Preserved model",
            "elements": [
                {
                    "alias": item["id"],
                    "name": f"{item['id']}: {item['name']}",
                    "kind": "process",
                    "stencil": "web-application",
                    "props": {"AuthenticationScheme": "Unknown"},
                }
                for item in document["elements"]
            ],
            "flows": [
                {
                    "alias": "F1",
                    "from": "P1",
                    "to": "P2",
                    "name": "F1: request",
                    "props": {"Protocol": "Unknown"},
                }
            ],
        }
        original = copy.deepcopy(manifest)
        layouts = self.layout.compute_pages(document)
        result = self.layout.manifest_with_layout(document, manifest, layouts)
        self.assertEqual(manifest, original)
        self.assertEqual(result["flows"], manifest["flows"])
        self.assertEqual(
            result["pages"],
            [{"alias": "PG1", "name": "Runtime"}, {"alias": "PG2", "name": "Build"}],
        )
        for item, before in zip(result["elements"], manifest["elements"]):
            self.assertEqual(item["props"], before["props"])
            self.assertEqual(item["stencil"], before["stencil"])
            self.assertEqual(item["page"], "PG1")
            self.assertTrue(
                all(type(item[field]) is int for field in ("x", "y", "width", "height"))
            )
        self.assertEqual(
            self.layout.manifest_with_layout(document, result, layouts), result
        )
        for field, value in (("from", "P2"), ("alias", "F99"), ("name", "wrong")):
            broken = copy.deepcopy(manifest)
            broken["flows"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.layout.manifest_with_layout(document, broken, layouts)
        with tempfile.TemporaryDirectory() as directory:
            ledger, template, destination = [
                Path(directory) / name
                for name in ("analysis.json", "model.tm.json", "candidate.tm.json")
            ]
            ledger.write_text(json.dumps(document), encoding="utf-8")
            template.write_text(json.dumps(manifest), encoding="utf-8")
            arguments = [
                "layout.py",
                str(ledger),
                "--manifest",
                str(template),
                "--out",
                str(destination),
            ]
            with (
                patch.object(sys, "argv", arguments),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(self.layout.main(), 0)
            self.assertEqual(json.loads(destination.read_text()), result)
            self.assertEqual(json.loads(template.read_text()), original)
            with (
                patch.object(sys, "argv", [*arguments[:-1], str(ledger)]),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(self.layout.main(), 2)
            self.assertEqual(json.loads(ledger.read_text()), document)
            destination.write_text("previous candidate", encoding="utf-8")
            warned = copy.deepcopy(layouts)
            warned[0]["warnings"] = ["fixture collision"]
            with (
                patch.object(sys, "argv", [*arguments, "--strict"]),
                patch.object(self.layout, "compute_pages", return_value=warned),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(self.layout.main(), 1)
            self.assertEqual(destination.read_text(), "previous candidate")

            restarted_layouts = copy.deepcopy(layouts)
            box = restarted_layouts[0]["boxes"]["P1"]
            restarted_layouts[0]["boxes"]["P1"] = (box[0] + 20, *box[1:])
            native_arguments = [
                *arguments,
                "--restarts",
                "1",
                "--tmforge",
                "selected-cli --",
            ]
            baseline_report = {
                "failures": [],
                "crossings": 6,
                "obstructedLabels": 0,
                "canvas": {"width": 1695, "height": 1082},
            }
            restarted_report = {
                **baseline_report,
                "crossings": 8,
                "canvas": {"width": 1695, "height": 1312},
            }
            with (
                patch.object(sys, "argv", native_arguments),
                patch.object(
                    self.layout,
                    "compute_pages",
                    side_effect=[restarted_layouts, layouts],
                ),
                patch.object(
                    self.layout,
                    "native_layout_report",
                    side_effect=[baseline_report, restarted_report],
                ) as native,
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(self.layout.main(), 0)
            self.assertEqual(json.loads(destination.read_text()), result)
            self.assertNotEqual(
                native.call_args_list[0].args[0], native.call_args_list[1].args[0]
            )
            self.assertEqual(native.call_args_list[0].args[-1], ["selected-cli", "--"])
            destination.write_text("previous candidate", encoding="utf-8")
            with (
                patch.object(sys, "argv", native_arguments),
                patch.object(
                    self.layout,
                    "native_layout_report",
                    side_effect=ValueError("native apply failed"),
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(self.layout.main(), 2)
            self.assertEqual(destination.read_text(), "previous candidate")

    def test_native_layout_selection_rejects_preview_winners_that_regress(self) -> None:
        baseline = {"name": "unseeded"}
        restarted = {"name": "preview winner"}

        def report(crossings=6, labels=0, height=1082, failures=None):
            return {
                "crossings": crossings,
                "obstructedLabels": labels,
                "failures": failures or [],
                "canvas": {"width": 1695, "height": height},
            }

        cases = [
            (report(crossings=8, height=1312), False),
            (report(crossings=5, height=1312), False),
            (report(crossings=5, labels=1), False),
            (report(crossings=5, failures=["outside boundary"]), False),
            (report(), False),
            (report(crossings=5), True),
            (report(height=1000), True),
        ]
        for candidate_report, expected in cases:
            with (
                self.subTest(candidate=candidate_report),
                patch.object(
                    self.layout,
                    "native_layout_report",
                    side_effect=[report(), candidate_report],
                ) as evaluate,
            ):
                selected, result = self.layout.select_native_layout(
                    baseline, restarted, Path("analysis.json"), ["chosen", "--"]
                )
            self.assertEqual(selected, expected)
            self.assertEqual(
                result["selected"], "restarted" if expected else "unseeded"
            )
            self.assertEqual(
                evaluate.call_args_list[0].args,
                (baseline, Path("analysis.json"), ["chosen", "--"]),
            )
        with patch.object(
            self.layout, "native_layout_report", return_value=report()
        ) as evaluate:
            self.assertFalse(
                self.layout.select_native_layout(
                    baseline, baseline, Path("analysis.json"), ["chosen"]
                )[0]
            )
            self.assertEqual(evaluate.call_count, 1)
        with patch.object(
            self.layout,
            "native_layout_report",
            side_effect=[
                report(failures=["bad baseline"]),
                report(failures=["bad candidate"]),
            ],
        ):
            with self.assertRaisesRegex(ValueError, "native layout check failed"):
                self.layout.select_native_layout(
                    baseline, restarted, Path("analysis.json"), ["chosen"]
                )

    def test_restarted_manifest_requires_native_validation_before_writing(self) -> None:
        arguments = [
            "layout.py",
            "missing-analysis.json",
            "--manifest",
            "missing-manifest.json",
            "--out",
            "output.json",
            "--restarts",
            "64",
        ]
        with (
            patch.object(sys, "argv", arguments),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            self.layout.main()
        self.assertEqual(raised.exception.code, 2)

    def test_native_evaluation_keeps_cli_and_writes_only_temporary_artifacts(
        self,
    ) -> None:
        selected = [sys.executable, "/chosen cli/launcher.py", "--"]
        captured: list[Path] = []

        def apply(command, **kwargs):
            self.assertEqual(command[: len(selected)], selected)
            self.assertEqual(command[len(selected)], "apply")
            self.assertEqual(kwargs["timeout"], 300)
            source = Path(command[len(selected) + 1])
            captured.append(source.parent)
            self.assertEqual(json.loads(source.read_text()), {"name": "candidate"})
            self.assertEqual(Path(command[-1]).parent, source.parent)
            return subprocess.CompletedProcess(command, 0, "", "")

        with (
            patch.object(self.layout.subprocess, "run", side_effect=apply),
            patch.object(
                self.layout.check_layout, "check", return_value={"ok": True}
            ) as inspect,
        ):
            self.assertEqual(
                self.layout.native_layout_report(
                    {"name": "candidate"}, Path("analysis.json"), selected
                ),
                {"ok": True},
            )
        self.assertEqual(inspect.call_args.args[1], Path("analysis.json"))
        self.assertFalse(captured[0].exists())
        for error in (OSError("missing CLI"), subprocess.TimeoutExpired(selected, 300)):
            with (
                self.subTest(error=error),
                patch.object(self.layout.subprocess, "run", side_effect=error),
            ):
                with self.assertRaisesRegex(
                    ValueError, "native layout evaluation failed"
                ):
                    self.layout.native_layout_report(
                        {}, Path("analysis.json"), selected
                    )
        with patch.object(
            self.layout.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                selected, 1, "", "invalid manifest"
            ),
        ):
            with self.assertRaisesRegex(
                ValueError, "native layout apply failed.*invalid manifest"
            ):
                self.layout.native_layout_report({}, Path("analysis.json"), selected)

    def test_cli_reports_obstruction_in_text_and_json_modes(self) -> None:
        flows = [
            {"id": "F2", "name": "hop", "sourceId": "P1", "targetId": "P2"},
            {"id": "F3", "name": "hop", "sourceId": "P2", "targetId": "P3"},
            self.flow,
        ]
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "analysis.json"
            ledger.write_text(
                json.dumps({"elements": self.elements, "flows": flows}),
                encoding="utf-8",
            )
            for options in ([], ["--json"], ["--strict"], ["--json", "--strict"]):
                with self.subTest(options=options):
                    output, errors = io.StringIO(), io.StringIO()
                    with (
                        patch.object(sys, "argv", ["layout.py", str(ledger), *options]),
                        redirect_stdout(output),
                        redirect_stderr(errors),
                    ):
                        self.assertEqual(
                            self.layout.main(), 1 if "--strict" in options else 0
                        )
                    self.assertIn("overlaps P2", errors.getvalue())
                    if "--json" in options:
                        self.assertIn("P1", json.loads(output.getvalue()))

    def test_cli_still_accepts_a_clear_adjacent_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory) / "analysis.json"
            ledger.write_text(
                json.dumps(
                    {
                        "elements": self.elements[:2],
                        "flows": [{**self.flow, "name": "short", "targetId": "P2"}],
                    }
                ),
                encoding="utf-8",
            )
            with (
                patch.object(sys, "argv", ["layout.py", str(ledger)]),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(self.layout.main(), 0)


if __name__ == "__main__":
    unittest.main()
