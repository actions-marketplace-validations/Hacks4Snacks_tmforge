"""Offline tests for managed downloads; no real executable is downloaded or installed."""

import copy
import hashlib
import importlib.util
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import patch

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "tmforge"
SCRIPT = PLUGIN / "skills" / "threat-modeling-tmforge" / "scripts" / "tmforge.py"


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = load_script("tmforge_plugin_launcher", SCRIPT)


class BinaryLauncherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="tmforge-launcher-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.cache = self.directory / "private cache"
        self.version = "0.10.0"
        self.payload = b"test executable payload; never execute this fixture\n"

    def archive(self, rid: str, kind: str = "regular", extra_member: bool = False) -> Path:
        windows = rid.startswith("win-")
        path = self.directory / ("fixture.zip" if windows else "fixture.tar.gz")
        member_name = f"tmforge-{self.version}-{rid}/" + ("tmforge.exe" if windows else "tmforge")
        if windows:
            with zipfile.ZipFile(path, "w") as archive:
                entry = zipfile.ZipInfo(member_name)
                entry.create_system = 3
                entry.external_attr = ((stat.S_IFLNK if kind == "symlink" else stat.S_IFREG) | 0o755) << 16
                archive.writestr(entry, self.payload)
                if extra_member:
                    archive.writestr("../../escape", b"not extracted")
        else:
            with tarfile.open(path, "w:gz") as archive:
                entry = tarfile.TarInfo(member_name)
                if kind == "symlink":
                    entry.type, entry.linkname = tarfile.SYMTYPE, "../../escape"
                    archive.addfile(entry)
                else:
                    entry.size = len(self.payload)
                    archive.addfile(entry, io.BytesIO(self.payload))
                if extra_member:
                    extra = tarfile.TarInfo("../../escape")
                    extra.size = 1
                    archive.addfile(extra, io.BytesIO(b"x"))
        return path

    def metadata(self, rid: str, archive: Path) -> dict[str, object]:
        extension = "zip" if rid.startswith("win-") else "tar.gz"
        return {
            "version": self.version, "tag": f"v{self.version}",
            "artifacts": [{"rid": rid, "file": f"tmforge-{self.version}-{rid}.{extension}",
                           "size": archive.stat().st_size,
                           "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}],
        }

    def install_fixture(self, rid: str, corrupt: bool = False) -> Path:
        archive = self.archive(rid, extra_member=True)
        metadata = self.metadata(rid, archive)
        base = f"{launcher.RELEASES}/v{self.version}"

        def download(url: str, destination: Path, limit: int) -> None:
            if destination.name == "release-metadata.json":
                self.assertEqual(url, f"{base}/release-metadata.json")
                destination.write_text(json.dumps(metadata), encoding="utf-8")
            else:
                self.assertEqual(url, f"{base}/{destination.name}")
                self.assertEqual(limit, archive.stat().st_size)
                data = archive.read_bytes()
                destination.write_bytes(b"x" * len(data) if corrupt else data)

        with patch.object(launcher, "download", side_effect=download) as downloader:
            binary = launcher.install(self.cache, self.version, rid)
            self.assertEqual(downloader.call_count, 2)
        return binary

    def test_maps_all_six_platforms(self):
        for system, machine, expected in (
            ("Darwin", "x86_64", "osx-x64"), ("Darwin", "arm64", "osx-arm64"),
            ("Linux", "AMD64", "linux-x64"), ("Linux", "aarch64", "linux-arm64"),
            ("Windows", "AMD64", "win-x64"), ("Windows", "ARM64", "win-arm64"),
        ):
            with self.subTest(rid=expected), patch.object(launcher.platform, "libc_ver", return_value=("glibc", "2.39")):
                self.assertEqual(launcher.runtime_id(system, machine), expected)
        with self.assertRaisesRegex(ValueError, "No published"):
            launcher.runtime_id("Linux", "riscv64")
        with patch.object(launcher.platform, "libc_ver", return_value=("musl", "1.2")):
            with self.assertRaisesRegex(ValueError, "glibc"):
                launcher.runtime_id("Linux", "x86_64")

    def test_version_pin_comes_from_installed_manifest(self):
        installed = self.directory / "plugin"
        installed.mkdir()
        manifest = installed / "plugin.json"
        with patch.object(launcher, "PLUGIN_ROOT", installed):
            manifest.write_text('{"name":"tmforge","version":"1.2.3-rc.1"}')
            self.assertEqual(launcher.plugin_version(), "1.2.3-rc.1")
            for invalid in ("latest", "main", "../escape", "1.2", "1.2.3/extra"):
                manifest.write_text(json.dumps({"name": "tmforge", "version": invalid}))
                with self.assertRaises(ValueError):
                    launcher.plugin_version()

    def test_verified_tar_and_zip_are_cached_and_reused_offline(self):
        for rid in ("osx-arm64", "win-x64"):
            with self.subTest(rid=rid):
                binary = self.install_fixture(rid)
                self.assertEqual(binary.read_bytes(), self.payload)
                self.assertFalse((self.directory / "escape").exists())
                self.assertEqual(launcher.cached_binary(self.cache, self.version, rid), binary)
                with patch.object(launcher, "download", side_effect=AssertionError("Unexpected network access")):
                    self.assertEqual(launcher.install(self.cache, self.version, rid), binary)

    def test_checksum_failure_does_not_publish_a_binary(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.install_fixture("linux-x64", corrupt=True)
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, "linux-x64"))
        self.assertFalse(launcher.binary_path(self.cache, self.version, "linux-x64").exists())
        self.assertEqual(list(self.cache.rglob(".install-*")), [])

    def test_tampered_and_incomplete_cache_entries_are_rejected(self):
        binary = self.install_fixture("osx-arm64")
        binary.write_bytes(b"tampered")
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, "osx-arm64"))
        binary.write_bytes(self.payload)
        receipt = binary.parent / "receipt.json"
        original = receipt.read_bytes()
        receipt.write_text("not json")
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, "osx-arm64"))
        receipt.write_bytes(original)
        self.assertIsNotNone(launcher.cached_binary(self.cache, self.version, "osx-arm64"))
        receipt.unlink()
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, "osx-arm64"))
        self.assertIsNone(launcher.cached_binary(self.cache, "0.11.0", "osx-arm64"))

    def test_archive_links_are_rejected_in_both_formats(self):
        for rid in ("linux-x64", "win-arm64"):
            with self.subTest(rid=rid):
                archive = self.archive(rid, kind="symlink")
                name = "tmforge.exe" if rid.startswith("win-") else "tmforge"
                with self.assertRaisesRegex(ValueError, "regular file"):
                    launcher.unpack_binary(archive, f"tmforge-{self.version}-{rid}/{name}", self.directory / "binary")

    def test_untrusted_metadata_cannot_choose_version_or_asset_path(self):
        metadata = self.metadata("linux-x64", self.archive("linux-x64"))
        cases: list[dict[str, object]] = []
        changes: tuple[tuple[str, object], ...] = (("version", "latest"), ("tag", "main"), ("artifacts", []))
        for field, value in changes:
            invalid = copy.deepcopy(metadata)
            invalid[field] = value
            cases.append(invalid)
        for field, value in (("file", "../../binary"), ("sha256", "bad"), ("size", True),
                             ("size", launcher.MAX_ARCHIVE_BYTES + 1), ("rid", "osx-x64")):
            invalid = copy.deepcopy(metadata)
            artifacts = cast(list[dict[str, object]], invalid["artifacts"])
            artifacts[0][field] = value
            cases.append(invalid)
        for invalid in cases:
            with self.subTest(metadata=invalid), self.assertRaises(ValueError):
                launcher.release_asset(invalid, self.version, "linux-x64")

    def test_actual_bytes_are_bounded(self):
        output = io.BytesIO()
        self.assertEqual(launcher.copy_limited(io.BytesIO(b"abcd"), output, 4), 4)
        with self.assertRaisesRegex(ValueError, "limit"):
            launcher.copy_limited(io.BytesIO(b"abcde"), io.BytesIO(), 4)

    def test_download_refuses_non_github_or_plaintext_urls(self):
        with patch.object(launcher.urllib.request, "urlopen") as request:
            for url in ("http://github.com/file", "https://example.com/file", "file:///tmp/file"):
                with self.subTest(url=url), self.assertRaisesRegex(ValueError, "HTTPS GitHub"):
                    launcher.download(url, self.directory / "file", 100)
            request.assert_not_called()
            response = request.return_value.__enter__.return_value
            response.geturl.return_value = "http://github.com/downgraded"
            with self.assertRaisesRegex(ValueError, "redirected"):
                launcher.download("https://github.com/file", self.directory / "file", 100)

    def test_status_and_missing_binary_never_download(self):
        with patch.object(launcher, "download") as download, patch.object(launcher, "subprocess") as process:
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(launcher.main(["--cache-dir", str(self.cache), "--status"]), 0)
            self.assertFalse(json.loads(output.getvalue())["installed"])
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(launcher.main(["--cache-dir", str(self.cache), "--", "--version"]), 1)
            self.assertIn("After approval", errors.getvalue())
            self.assertFalse(self.cache.exists())
            download.assert_not_called()
            process.run.assert_not_called()

    def test_execution_preserves_arguments_and_exit_code(self):
        binary = self.directory / "binary with spaces"
        output = io.StringIO()
        with patch.object(launcher, "cached_binary", return_value=binary), \
             patch.object(launcher.subprocess, "run", return_value=subprocess.CompletedProcess([], 2)) as run, \
             patch.object(launcher, "download") as download, redirect_stdout(output):
            result = launcher.main(["--cache-dir", str(self.cache), "--", "analyze", "model with spaces.tm7", "--json"])
        self.assertEqual(result, 2)
        run.assert_called_once_with([str(binary), "analyze", "model with spaces.tm7", "--json"], check=False)
        self.assertEqual(output.getvalue(), "")
        download.assert_not_called()

    def test_cache_must_stay_outside_plugin_and_cannot_escape_root(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            launcher.cache_root(PLUGIN / "binary-cache")
        if os.name != "nt":
            self.cache.mkdir()
            (self.cache / self.version).symlink_to(self.directory, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "escapes"):
                launcher.binary_path(self.cache, self.version, "linux-x64")

    def test_relocated_launcher_reads_its_own_pin(self):
        installed = self.directory / "installed plugin"
        shutil.copytree(PLUGIN, installed, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".mypy_cache"))
        path = installed / SCRIPT.relative_to(PLUGIN)
        result = subprocess.run(
            [sys.executable, "-B", str(path), "--cache-dir", str(self.cache), "--status"],
            cwd=self.directory, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["version"], launcher.plugin_version())
        self.assertFalse(self.cache.exists())


class WrapperIntegrationTests(unittest.TestCase):
    def test_suppression_generator_preserves_quoted_launcher(self):
        script = PLUGIN / "skills" / "threat-modeling" / "scripts" / "generate_suppressions.py"
        generator = load_script("plugin_suppression_wrapper_test", script)
        command = [sys.executable, "/installed plugins/tmforge/launcher.py", "--"]
        self.assertEqual(generator.resolve_invocation(shlex.join(command)), command)

    def test_rebuild_keeps_launcher_and_checks_newly_generated_artifacts(self):
        script = PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        rebuild = load_script("plugin_rebuild_wrapper_test", script)
        wrapper = [sys.executable, "/installed plugins/tmforge/launcher.py", "--"]
        generator = [sys.executable, "/author scripts/build manifest.py"]
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            calls: list[list[str]] = []

            def record(command: list[str], cwd: Path | None = None) -> tuple[int, str]:
                calls.append(command)
                if command == generator:
                    self.assertEqual(cwd, package)
                    (package / "threat-model.tm.json").write_text("{}")
                if command[:len(wrapper)] == wrapper:
                    (package / "threat-model.tm7").write_bytes(b"test fixture, not a real model")
                return 0, "{}"

            arguments = [str(script), str(package), "--manifest-command", shlex.join(generator),
                         "--tmforge", shlex.join(wrapper), "--justifications", str(package / "justifications.json"), "--json"]
            output = io.StringIO()
            with patch.object(sys, "argv", arguments), patch.object(rebuild, "run", side_effect=record), redirect_stdout(output):
                self.assertEqual(rebuild.main(), 0)
            report = json.loads(output.getvalue())
            self.assertEqual([step["step"] for step in report["steps"]],
                             ["manifest", "ledger", "apply", "layout", "suppressions", "render", "package"])
            self.assertEqual(calls[0], generator)
            self.assertEqual(calls[2][:len(wrapper)], wrapper)
            for command in (calls[4], calls[-1]):
                self.assertIn("--tmforge", command)
                self.assertEqual(shlex.split(command[command.index("--tmforge") + 1]), wrapper)


if __name__ == "__main__":
    unittest.main()
