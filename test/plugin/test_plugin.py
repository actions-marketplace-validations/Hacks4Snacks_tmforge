"""Dependency-free packaging and bundled-validator checks for the public plugin."""

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import SplitResult, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "tmforge"
SKILL = PLUGIN / "skills" / "threat-modeling"
SCRIPTS = SKILL / "scripts"


class PluginTests(unittest.TestCase):
    def test_manifest_matches_agent_plugins_and_product_version(self):
        manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["$schema"],
                         "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json")
        self.assertEqual(manifest["name"], PLUGIN.name)
        self.assertTrue(set(manifest) <= {
            "$schema", "name", "version", "description", "author", "homepage",
            "repository", "license", "keywords", "extensions",
        })
        self.assertTrue(manifest["description"])
        self.assertTrue(manifest["author"]["name"])
        self.assertEqual(manifest["license"], "MIT")
        self.assertEqual(manifest["repository"], "https://github.com/Hacks4Snacks/tmforge")
        self.assertRegex(manifest["version"], r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
        for keyword in manifest["keywords"]:
            self.assertRegex(keyword, r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
        version = ET.parse(ROOT / "Directory.Build.props").findtext(".//VersionPrefix")
        self.assertEqual(manifest["version"], version)
        release = json.loads((ROOT / "release-please-config.json").read_text())
        self.assertIn({
            "type": "json", "path": "plugins/tmforge/plugin.json", "jsonpath": "$.version",
        }, release["packages"]["."]["extra-files"])

    def test_repository_marketplace_matches_plugin_and_release_updater(self):
        catalog = json.loads((ROOT / ".github/plugin/marketplace.json").read_text(encoding="utf-8"))
        manifest = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["name"], "tmforge")
        self.assertEqual(catalog["owner"]["name"], manifest["author"]["name"])
        self.assertEqual(len(catalog["plugins"]), 1)
        entry = catalog["plugins"][0]
        for field in ("name", "description", "version"):
            self.assertEqual(entry[field], manifest[field])
        self.assertEqual(entry["source"], "./plugins/tmforge")
        self.assertEqual((ROOT / entry["source"]).resolve(), PLUGIN.resolve())
        release = json.loads((ROOT / "release-please-config.json").read_text(encoding="utf-8"))
        self.assertIn({
            "type": "json", "path": ".github/plugin/marketplace.json",
            "jsonpath": "$.plugins[0].version",
        }, release["packages"]["."]["extra-files"])

    def test_plugin_license_matches_repository(self):
        self.assertEqual((PLUGIN / "LICENSE.md").read_bytes(),
                         (ROOT / "LICENSE.md").read_bytes())

    def test_agent_and_skills_are_discoverable(self):
        agents = list((PLUGIN / "com.github.copilot" / "agents").glob("*.agent.md"))
        self.assertEqual([path.name for path in agents], ["strider.agent.md"])
        agent = agents[0].read_text(encoding="utf-8")
        frontmatter = agent.split("---", 2)[1]
        self.assertIn("name: Strider\n", frontmatter)
        self.assertNotRegex(frontmatter, r"(?m)^(target|id|skills):")
        self.assertIn("tools: [read, search, execute, edit, todo]", frontmatter)
        skills = sorted((PLUGIN / "skills").glob("*/SKILL.md"))
        self.assertEqual([path.parent.name for path in skills],
                         ["threat-modeling", "threat-modeling-tmforge"])
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
        forbidden = {"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv"}
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
                tree = ast.parse(path.read_text(encoding="utf-8"), feature_version=(3, 10))
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
                        capture_output=True, text=True, timeout=60, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_standalone_report_has_no_companion_dependency(self):
        with tempfile.TemporaryDirectory(prefix="tmforge-markdown-") as directory:
            report = Path(directory) / "report.md"
            command = [
                sys.executable, "-B", str(SCRIPTS / "render_analysis.py"),
                str(SKILL / "assets" / "analysis.example.json"),
                "--standalone-report", str(report),
            ]
            for options in ([], ["--check"]):
                result = subprocess.run(
                    [*command, *options], cwd=directory,
                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PATH=""),
                    capture_output=True, text=True, timeout=30, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual([path.name for path in Path(directory).iterdir()], ["report.md"])
            self.assertNotIn("analysis.example.json", report.read_text(encoding="utf-8"))
            self.assertNotIn("data-flow.md", report.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
