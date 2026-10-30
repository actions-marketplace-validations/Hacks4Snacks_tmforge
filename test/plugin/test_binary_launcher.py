"""Offline tests for managed downloads; no real executable is downloaded or installed."""

import copy
import ctypes
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, patch

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "tmforge"
SCRIPT = PLUGIN / "skills" / "threat-modeling-tmforge" / "scripts" / "tmforge.py"


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent), *sys.path]):
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
        self.installed_plugin = self.directory / "plugin"
        self.installed_plugin.mkdir()
        (self.installed_plugin / "plugin.json").write_text(
            json.dumps({"name": "tmforge", "version": self.version}), encoding="utf-8"
        )
        root_patch = patch.object(launcher, "PLUGIN_ROOT", self.installed_plugin)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def archive(
        self, rid: str, kind: str = "regular", extra_member: bool = False
    ) -> Path:
        windows = rid.startswith("win-")
        path = self.directory / ("fixture.zip" if windows else "fixture.tar.gz")
        member_name = f"tmforge-{self.version}-{rid}/" + (
            "tmforge.exe" if windows else "tmforge"
        )
        if windows:
            with zipfile.ZipFile(path, "w") as zip_archive:
                zip_entry = zipfile.ZipInfo(member_name)
                zip_entry.create_system = 3
                zip_entry.external_attr = (
                    (stat.S_IFLNK if kind == "symlink" else stat.S_IFREG) | 0o755
                ) << 16
                zip_archive.writestr(zip_entry, self.payload)
                if extra_member:
                    zip_archive.writestr("../../escape", b"not extracted")
        else:
            with tarfile.open(path, "w:gz") as tar_archive:
                tar_entry = tarfile.TarInfo(member_name)
                if kind == "symlink":
                    tar_entry.type, tar_entry.linkname = tarfile.SYMTYPE, "../../escape"
                    tar_archive.addfile(tar_entry)
                else:
                    tar_entry.size = len(self.payload)
                    tar_archive.addfile(tar_entry, io.BytesIO(self.payload))
                if extra_member:
                    extra = tarfile.TarInfo("../../escape")
                    extra.size = 1
                    tar_archive.addfile(extra, io.BytesIO(b"x"))
        return path

    def metadata(self, rid: str, archive: Path) -> dict[str, object]:
        extension = "zip" if rid.startswith("win-") else "tar.gz"
        return {
            "version": self.version,
            "tag": f"v{self.version}",
            "artifacts": [
                {
                    "rid": rid,
                    "file": f"tmforge-{self.version}-{rid}.{extension}",
                    "size": archive.stat().st_size,
                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                }
            ],
        }

    def install_fixture(
        self, rid: str, corrupt: bool = False, quarantine: str | None = None
    ) -> Path:
        archive = self.archive(rid, extra_member=True)
        metadata_bytes = json.dumps(self.metadata(rid, archive)).encode("utf-8")
        base = f"{launcher.RELEASES}/v{self.version}"

        def download(
            url: str, destination: Path, limit: int, directory: int | None = None
        ) -> None:
            if destination.name == "release-metadata.json":
                self.assertEqual(url, f"{base}/release-metadata.json")
                with launcher.cache_output(destination, directory) as output:
                    output.write(metadata_bytes)
            else:
                self.assertEqual(url, f"{base}/{destination.name}")
                self.assertEqual(limit, archive.stat().st_size)
                data = archive.read_bytes()
                with launcher.cache_output(destination, directory) as output:
                    output.write(b"x" * len(data) if corrupt else data)
                if quarantine is not None:
                    subprocess.run(
                        [
                            "/usr/bin/xattr",
                            "-w",
                            "com.apple.quarantine",
                            quarantine,
                            str(destination),
                        ],
                        check=True,
                        capture_output=True,
                    )

        with patch.object(launcher, "download", side_effect=download) as downloader:
            binary = launcher.install(self.cache, self.version, rid)
            self.assertEqual(downloader.call_count, 2)
        return binary

    def test_maps_all_six_platforms(self):
        for system, machine, expected in (
            ("Darwin", "x86_64", "osx-x64"),
            ("Darwin", "arm64", "osx-arm64"),
            ("Linux", "AMD64", "linux-x64"),
            ("Linux", "aarch64", "linux-arm64"),
            ("Windows", "AMD64", "win-x64"),
            ("Windows", "ARM64", "win-arm64"),
        ):
            with (
                self.subTest(rid=expected),
                patch.object(
                    launcher.platform, "libc_ver", return_value=("glibc", "2.39")
                ),
            ):
                self.assertEqual(launcher.runtime_id(system, machine), expected)
        with self.assertRaisesRegex(ValueError, "No published"):
            launcher.runtime_id("Linux", "riscv64")
        with patch.object(launcher.platform, "libc_ver", return_value=("musl", "1.2")):
            with self.assertRaisesRegex(ValueError, "glibc"):
                launcher.runtime_id("Linux", "x86_64")

    def test_version_pin_comes_from_installed_manifest(self):
        installed = self.directory / "version plugin"
        installed.mkdir()
        manifest = installed / "plugin.json"
        with patch.object(launcher, "PLUGIN_ROOT", installed):
            manifest.write_text('{"name":"tmforge","version":"1.2.3-rc.1"}')
            self.assertEqual(launcher.plugin_version(), "1.2.3-rc.1")
            for invalid in ("latest", "main", "../escape", "1.2", "1.2.3/extra"):
                manifest.write_text(json.dumps({"name": "tmforge", "version": invalid}))
                with self.assertRaises(ValueError):
                    launcher.plugin_version()

    def test_plugin_update_selects_matching_cli_release(self):
        (self.installed_plugin / "plugin.json").write_text(
            json.dumps({"name": "tmforge", "version": "99.0.0"})
        )
        output = io.StringIO()
        with patch.object(launcher, "download") as download, redirect_stdout(output):
            self.assertEqual(
                launcher.main(["--cache-dir", str(self.cache), "--status"]), 0
            )
        status = json.loads(output.getvalue())
        self.assertEqual(status["version"], "99.0.0")
        self.assertEqual(
            Path(status["binary"]),
            launcher.binary_path(self.cache, "99.0.0", status["rid"]),
        )
        download.assert_not_called()

    def test_plugin_update_installs_only_the_matching_release(self):
        (self.installed_plugin / "plugin.json").write_text(
            json.dumps({"name": "tmforge", "version": "99.0.0"})
        )
        binary = launcher.binary_path(self.cache, "99.0.0", "linux-x64")
        with (
            patch.object(launcher, "runtime_id", return_value="linux-x64"),
            patch.object(launcher, "install", return_value=binary) as install,
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                launcher.main(["--cache-dir", str(self.cache), "--install"]), 0
            )
        install.assert_called_once_with(self.cache, "99.0.0", "linux-x64")

    def test_unavailable_matching_release_never_falls_back_to_older_cache(self):
        older = self.install_fixture("osx-arm64")
        (self.installed_plugin / "plugin.json").write_text(
            json.dumps({"name": "tmforge", "version": "99.0.0"})
        )
        with (
            patch.object(launcher, "runtime_id", return_value="osx-arm64"),
            patch.object(
                launcher, "download", side_effect=OSError("release unavailable")
            ) as download,
            patch.object(launcher.subprocess, "run") as run,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(
                launcher.main(["--cache-dir", str(self.cache), "--install"]), 1
            )
            self.assertEqual(
                launcher.main(["--cache-dir", str(self.cache), "--", "--version"]), 1
            )
        self.assertEqual(download.call_count, 1)
        self.assertIn("/v99.0.0/", download.call_args.args[0])
        run.assert_not_called()
        self.assertEqual(older.read_bytes(), self.payload)

    def test_verified_tar_and_zip_are_cached_and_reused_offline(self):
        for rid in ("osx-arm64", "win-x64"):
            with self.subTest(rid=rid):
                binary = self.install_fixture(rid)
                self.assertEqual(binary.read_bytes(), self.payload)
                self.assertFalse((self.directory / "escape").exists())
                self.assertEqual(
                    launcher.cached_binary(self.cache, self.version, rid), binary
                )
                with patch.object(
                    launcher,
                    "download",
                    side_effect=AssertionError("Unexpected network access"),
                ):
                    self.assertEqual(
                        launcher.install(self.cache, self.version, rid), binary
                    )

    @unittest.skipUnless(os.name == "posix", "POSIX directory substitution")
    def test_install_publication_cannot_follow_a_replaced_cache_directory(self):
        rid = "osx-arm64"
        phases = ("create", "stage", "metadata", "archive", "extract", "publish")
        for target in ("cache", "runtime", "staging"):
            for phase in phases:
                if (phase == "create" and target != "cache") or (
                    phase == "stage" and target == "staging"
                ):
                    continue
                with self.subTest(target=target, phase=phase):
                    scope = self.directory / f"{target}-{phase}"
                    scope.mkdir(mode=0o700)
                    cache = scope / "cache"
                    parent = cache / self.version / rid
                    moved, outside = scope / "original", scope / "outside"
                    staged_path = None
                    before = {}
                    failure = None
                    original_mkdir, original_replace = os.mkdir, os.replace
                    original_output, original_unpack = (
                        launcher.cache_output,
                        launcher.unpack_binary,
                    )

                    def contents():
                        return {
                            str(path.relative_to(outside)): (
                                None if path.is_dir() else path.read_bytes()
                            )
                            for path in outside.rglob("*")
                        }

                    def swap():
                        if moved.exists():
                            return
                        selected = {
                            "cache": cache,
                            "runtime": parent,
                            "staging": staged_path,
                        }[target]
                        assert selected is not None
                        selected.rename(moved)
                        shutil.copytree(moved, outside)
                        before.update(contents())
                        selected.symlink_to(outside, target_is_directory=True)

                    def mkdir(path, mode=0o777, *, dir_fd=None):
                        nonlocal staged_path
                        name = Path(path).name
                        if name.startswith(".install-"):
                            staged_path = parent / name
                        if (phase == "create" and name == self.version) or (
                            phase == "stage" and name.startswith(".install-")
                        ):
                            self.assertIsNotNone(dir_fd)
                            swap()
                        return original_mkdir(path, mode, dir_fd=dir_fd)

                    def output(path, directory):
                        if (
                            phase == "metadata" and path.name == "release-metadata.json"
                        ) or (phase == "archive" and path.name.endswith(".tar.gz")):
                            self.assertIsNotNone(directory)
                            swap()
                        return original_output(path, directory)

                    def unpack(*arguments, **options):
                        if phase == "extract":
                            swap()
                        return original_unpack(*arguments, **options)

                    def replace(source, destination, **options):
                        if phase == "publish":
                            self.assertIsNotNone(options["src_dir_fd"])
                            self.assertIsNotNone(options["dst_dir_fd"])
                            swap()
                        return original_replace(source, destination, **options)

                    with (
                        patch.object(self, "cache", cache),
                        patch.object(launcher.os, "mkdir", side_effect=mkdir),
                        patch.object(launcher.os, "replace", side_effect=replace),
                        patch.object(launcher, "cache_output", side_effect=output),
                        patch.object(launcher, "unpack_binary", side_effect=unpack),
                    ):
                        try:
                            self.install_fixture(rid)
                        except (OSError, ValueError) as exc:
                            failure = exc
                    self.assertTrue(moved.is_dir())
                    self.assertEqual(contents(), before)
                    self.assertIsNotNone(failure)
                    self.assertEqual(list(moved.rglob(".install-*")), [])

    @unittest.skipUnless(sys.platform == "win32", "native Windows installation handles")
    def test_windows_install_retains_directory_handles_through_download(self):
        original_output = launcher.cache_output
        checked = []

        def output(path, directory):
            if path.name == "release-metadata.json":
                for selected in (self.cache, path.parent.parent, path.parent):
                    with self.assertRaises(OSError):
                        selected.rename(self.directory / "replacement")
                    checked.append(selected)
            return original_output(path, directory)

        with patch.object(launcher, "cache_output", side_effect=output):
            self.assertEqual(self.install_fixture("win-x64").read_bytes(), self.payload)
        self.assertEqual(len(checked), 3)

    def test_checksum_failure_does_not_publish_a_binary(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.install_fixture("linux-x64", corrupt=True)
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, "linux-x64"))
        self.assertFalse(
            launcher.binary_path(self.cache, self.version, "linux-x64").exists()
        )
        self.assertEqual(list(self.cache.rglob(".install-*")), [])

    def test_foreign_release_metadata_is_rejected_before_archive_download(self):
        rid = "linux-x64"
        metadata = self.metadata(rid, self.archive(rid))
        for field, value in (("version", "9.0.0"), ("tag", "v9.0.0")):
            replacement = json.dumps({**metadata, field: value}).encode("utf-8")

            def download(
                url: str, destination: Path, limit: int, directory: int | None = None
            ) -> None:
                self.assertEqual(destination.name, "release-metadata.json")
                with launcher.cache_output(destination, directory) as output:
                    output.write(replacement)

            with (
                self.subTest(field=field),
                patch.object(launcher, "download", side_effect=download) as downloader,
            ):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    launcher.install(self.cache, self.version, rid)
            self.assertEqual(downloader.call_count, 1)
            self.assertFalse(
                launcher.binary_path(self.cache, self.version, rid).exists()
            )
            self.assertEqual(list(self.cache.rglob(".install-*")), [])

    def test_malformed_or_oversized_metadata_stops_before_archive_download(self):
        for content in (b"not JSON", b"[]", b"x" * (launcher.MAX_METADATA_BYTES + 1)):

            def download(
                url: str, destination: Path, limit: int, directory: int | None = None
            ) -> None:
                self.assertEqual(limit, launcher.MAX_METADATA_BYTES)
                with launcher.cache_output(destination, directory) as output:
                    output.write(content)

            with (
                self.subTest(size=len(content)),
                patch.object(launcher, "download", side_effect=download) as downloader,
            ):
                with self.assertRaises(ValueError):
                    launcher.install(self.cache, self.version, "linux-x64")
            self.assertEqual(downloader.call_count, 1)
            self.assertFalse(
                launcher.binary_path(self.cache, self.version, "linux-x64").exists()
            )
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
        self.assertIsNotNone(
            launcher.cached_binary(self.cache, self.version, "osx-arm64")
        )
        receipt.unlink()
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, "osx-arm64"))
        self.assertIsNone(launcher.cached_binary(self.cache, "0.11.0", "osx-arm64"))

    def test_legacy_cache_requires_explicit_reinstallation(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        receipt = binary.parent / "receipt.json"
        data = json.loads(receipt.read_text(encoding="utf-8"))
        del data["releaseMetadataSha256"]
        receipt.write_text(json.dumps(data), encoding="utf-8")
        self.assertIsNone(launcher.cached_binary(self.cache, self.version, rid))
        with (
            patch.object(launcher, "runtime_id", return_value=rid),
            patch.object(launcher, "download") as download,
            patch.object(launcher.subprocess, "run") as process,
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    launcher.main(["--cache-dir", str(self.cache), "--status"]), 0
                )
            self.assertFalse(json.loads(output.getvalue())["installed"])
            with redirect_stderr(io.StringIO()):
                self.assertEqual(
                    launcher.main(["--cache-dir", str(self.cache), "--", "--version"]),
                    1,
                )
            download.assert_not_called()
            process.assert_not_called()
        self.install_fixture(rid)
        self.assertEqual(launcher.cached_binary(self.cache, self.version, rid), binary)

    def test_foreign_release_and_invalid_receipt_provenance_are_rejected(self):
        binary = self.install_fixture("osx-arm64")
        receipt = binary.parent / "receipt.json"
        original = json.loads(receipt.read_text())
        for field, value in (
            ("source", "https://example.com/tmforge"),
            ("source", original["source"].replace(f"/v{self.version}/", "/v9.0.0/")),
            ("version", "9.0.0"),
            ("rid", "linux-x64"),
            ("releaseMetadataSha256", None),
            ("releaseMetadataSha256", "invalid"),
            ("archiveSha256", None),
            ("archiveSha256", "invalid"),
        ):
            with self.subTest(field=field, value=value):
                receipt.write_text(json.dumps({**original, field: value}))
                self.assertIsNone(
                    launcher.cached_binary(self.cache, self.version, "osx-arm64")
                )
        receipt.write_text(json.dumps(original))
        self.assertEqual(
            launcher.cached_binary(self.cache, self.version, "osx-arm64"), binary
        )

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_writable_cache_is_rejected_before_any_action(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        binary.write_bytes(b"replacement fixture; never execute\n")
        receipt = binary.parent / "receipt.json"
        data = json.loads(receipt.read_text(encoding="utf-8"))
        data["binarySha256"] = launcher.sha256(binary)
        receipt.write_text(json.dumps(data), encoding="utf-8")
        for directory in (self.cache, self.cache / self.version, binary.parent):
            original_mode = stat.S_IMODE(directory.stat().st_mode)
            directory.chmod(0o777)
            try:
                for action in (["--status"], ["--install"], ["--", "--version"]):
                    with (
                        self.subTest(directory=directory.name, action=action),
                        patch.object(launcher, "runtime_id", return_value=rid),
                        patch.object(launcher, "download") as download,
                        patch.object(launcher.subprocess, "run") as process,
                        redirect_stdout(io.StringIO()),
                        redirect_stderr(io.StringIO()),
                    ):
                        self.assertEqual(
                            launcher.main(["--cache-dir", str(self.cache), *action]),
                            1,
                        )
                        download.assert_not_called()
                        process.assert_not_called()
                        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o777)
            finally:
                directory.chmod(original_mode)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_shared_readable_cache_files_are_rejected_before_any_action(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        for path in (binary, binary.parent / "receipt.json"):
            original_mode = stat.S_IMODE(path.stat().st_mode)
            original_bytes = path.read_bytes()
            try:
                for extra_bits in (0o040, 0o010, 0o004, 0o001, 0o055):
                    mode = original_mode | extra_bits
                    path.chmod(mode)
                    for action in (["--status"], ["--install"], ["--", "--version"]):
                        errors = io.StringIO()
                        with (
                            self.subTest(path=path.name, mode=oct(mode), action=action),
                            patch.object(launcher, "runtime_id", return_value=rid),
                            patch.object(launcher, "download") as download,
                            patch.object(launcher.subprocess, "run") as process,
                            redirect_stdout(io.StringIO()),
                            redirect_stderr(errors),
                        ):
                            self.assertEqual(
                                launcher.main(
                                    ["--cache-dir", str(self.cache), *action]
                                ),
                                1,
                            )
                            self.assertIn(
                                "Unsafe cache ownership or permissions",
                                errors.getvalue(),
                            )
                            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                            self.assertEqual(path.read_bytes(), original_bytes)
                            download.assert_not_called()
                            process.assert_not_called()
            finally:
                path.chmod(original_mode)
        self.assertEqual(launcher.cached_binary(self.cache, self.version, rid), binary)

    def test_redirected_cache_directories_are_rejected(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        for index, directory in enumerate(
            (self.cache, self.cache / self.version, binary.parent)
        ):
            saved = self.directory / f"saved-directory-{index}"
            directory.rename(saved)
            try:
                try:
                    directory.symlink_to(saved, target_is_directory=True)
                except OSError as exc:
                    self.skipTest(f"symlinks are unavailable: {exc}")
                with (
                    self.subTest(directory=directory.name),
                    patch.object(launcher, "download") as download,
                ):
                    with self.assertRaisesRegex(ValueError, "symlink|reparse"):
                        launcher.cached_binary(self.cache, self.version, rid)
                    with self.assertRaisesRegex(ValueError, "symlink|reparse"):
                        launcher.install(self.cache, self.version, rid)
                    download.assert_not_called()
            finally:
                if directory.is_symlink():
                    directory.unlink()
                saved.rename(directory)

    def test_intermediate_cache_links_are_rejected_before_any_action(self):
        target = self.directory / "redirected-target"
        target.mkdir(mode=0o700)
        link = self.directory / "intermediate-link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlinks are unavailable: {exc}")
        for cache in (link / "copilot", link / ".." / "copilot"):
            for action in (["--status"], ["--install"], ["--", "--version"]):
                errors = io.StringIO()
                with (
                    self.subTest(cache=cache, action=action),
                    patch.object(launcher, "runtime_id", return_value="win-x64"),
                    patch.object(launcher, "download") as download,
                    patch.object(launcher.subprocess, "run") as process,
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(errors),
                ):
                    self.assertEqual(
                        launcher.main(["--cache-dir", str(cache), *action]), 1
                    )
                    self.assertIn("symlink", errors.getvalue())
                    download.assert_not_called()
                    process.assert_not_called()
        self.assertEqual(list(target.iterdir()), [])
        self.assertFalse((self.directory / "copilot").exists())

    def test_reparse_directories_are_rejected_before_permission_checks(self):
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_file_attributes=0x400)
        with patch.object(Path, "lstat", return_value=info):
            with self.assertRaisesRegex(ValueError, "reparse"):
                launcher.validate_cache_entry(self.cache, private=True)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership")
    def test_foreign_owned_cache_is_rejected(self):
        self.install_fixture("osx-arm64")
        with patch.object(launcher.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "ownership"):
                launcher.cached_binary(self.cache, self.version, "osx-arm64")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_writable_cache_ancestor_is_rejected_before_creation(self):
        self.directory.chmod(0o777)
        try:
            with patch.object(launcher, "download") as download:
                with self.assertRaisesRegex(ValueError, "permissions"):
                    launcher.install(self.cache, self.version, "osx-arm64")
                download.assert_not_called()
            self.assertFalse(self.cache.exists())
        finally:
            self.directory.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_cache_files_must_not_be_writable_by_others(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        for path in (binary, binary.parent / "receipt.json"):
            original = stat.S_IMODE(path.stat().st_mode)
            path.chmod(original | 0o022)
            try:
                with (
                    self.subTest(path=path.name),
                    self.assertRaisesRegex(ValueError, "permissions"),
                ):
                    launcher.cached_binary(self.cache, self.version, rid)
            finally:
                path.chmod(original)

    def test_hardlinked_cache_files_are_rejected(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        linked = self.directory / "linked-file"
        for path in (binary, binary.parent / "receipt.json"):
            try:
                os.link(path, linked)
            except OSError as exc:
                self.skipTest(f"hard links are unavailable: {exc}")
            try:
                with (
                    self.subTest(path=path.name),
                    self.assertRaisesRegex(ValueError, "single-link"),
                ):
                    launcher.cached_binary(self.cache, self.version, rid)
            finally:
                linked.unlink()

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_new_cache_entries_have_private_permissions(self):
        binary = self.install_fixture("osx-arm64")
        for directory in (self.cache, self.cache / self.version, binary.parent):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o700)
        self.assertEqual(
            stat.S_IMODE((binary.parent / "receipt.json").stat().st_mode), 0o600
        )

    def test_windows_cache_acl_rejects_untrusted_owners_and_writers(self):
        current_user = "S-1-5-21-1-2-3-1001"
        other_user = "S-1-5-21-1-2-3-1002"
        entries = [
            (0, 0, 0x1F01FF, trustee)
            for trustee in (current_user, "S-1-5-18", "S-1-5-32-544")
        ]
        launcher.validate_windows_cache_acl(current_user, current_user, entries, True)
        for mask in (
            2,
            4,
            0x10,
            0x40,
            0x100,
            0x10000,
            0x40000,
            0x80000,
            0x10000000,
            0x40000000,
        ):
            for trustee in (other_user, "S-1-1-0", "S-1-5-32-545"):
                with (
                    self.subTest(mask=mask, trustee=trustee),
                    self.assertRaisesRegex(ValueError, "write access"),
                ):
                    launcher.validate_windows_cache_acl(
                        current_user,
                        current_user,
                        [*entries, (0, 0, mask, trustee)],
                        True,
                    )
        with self.assertRaisesRegex(ValueError, "owner"):
            launcher.validate_windows_cache_acl(other_user, current_user, entries, True)
        with self.assertRaisesRegex(ValueError, "ACL entry"):
            launcher.validate_windows_cache_acl(
                current_user, current_user, [(5, 0, 2, other_user)], True
            )

    def test_windows_cache_acl_accepts_trusted_owners_and_owner_rights(self):
        current_user = "S-1-5-21-1-2-3-1001"
        entries = [
            (0, 0x03, 0x1F01FF, trustee)
            for trustee in ("S-1-5-18", "S-1-5-32-544", "S-1-3-4")
        ]
        for private in (False, True):
            for owner in (current_user, "S-1-5-18", "S-1-5-32-544"):
                with self.subTest(owner=owner, private=private):
                    launcher.validate_windows_cache_acl(
                        owner, current_user, entries, private
                    )
            for owner in ("S-1-5-21-1-2-3-1002", "S-1-1-0", "S-1-3-4"):
                with (
                    self.subTest(owner=owner, private=private),
                    self.assertRaisesRegex(ValueError, "owner"),
                ):
                    launcher.validate_windows_cache_acl(
                        owner, current_user, entries, private
                    )
        for trustee in ("S-1-5-21-1-2-3-1002", "S-1-1-0", "S-1-5-32-545"):
            with (
                self.subTest(trustee=trustee),
                self.assertRaisesRegex(ValueError, "write access"),
            ):
                launcher.validate_windows_cache_acl(
                    current_user,
                    current_user,
                    [*entries, (0, 0, 0x1F01FF, trustee)],
                    True,
                )

    def test_windows_directory_handles_request_read_access(self):
        permissions = launcher.windows_permissions_module()
        kernel = Mock()
        kernel.CreateFileW.return_value = 123

        def file_information(
            handle: int, kind: int, attributes: Any, size: int
        ) -> bool:
            self.assertEqual(handle, 123)
            self.assertEqual(kind, 9)
            self.assertEqual(size, ctypes.sizeof(attributes._obj))
            attributes._obj[0] = 0x10
            return True

        kernel.GetFileInformationByHandleEx.side_effect = file_information
        for opener, options in (
            (permissions.windows_directory_handle, {}),
            (launcher.windows_cache_handle, {"directory": True}),
        ):
            kernel.reset_mock()
            with (
                self.subTest(opener=opener.__name__),
                patch.object(permissions.sys, "platform", "win32"),
                patch.object(ctypes, "WinDLL", return_value=kernel, create=True),
                patch.dict(sys.modules, {"msvcrt": Mock()}),
            ):
                with opener(self.directory, **options):
                    kernel.CreateFileW.assert_called_once_with(
                        str(self.directory), 0x81, 3, None, 3, 0x02200000, None
                    )
                    kernel.CloseHandle.assert_not_called()
            kernel.CloseHandle.assert_called_once_with(123)

    def test_windows_cache_creation_does_not_recreate_existing_ancestors(self):
        original_mkdir = Path.mkdir
        created: list[Path] = []

        def mkdir(
            path: Path,
            mode: int = 0o777,
            parents: bool = False,
            exist_ok: bool = False,
        ) -> None:
            if path.exists():
                raise PermissionError("cannot recreate an existing Windows root")
            created.append(path)
            return original_mkdir(path, mode, parents, exist_ok)

        with (
            patch.object(launcher, "os", SimpleNamespace(name="nt")),
            patch.object(Path, "mkdir", mkdir),
            patch.object(
                launcher, "windows_cache_handle", return_value=nullcontext(123)
            ) as handles,
            patch.object(launcher, "validate_cache_entry") as validate,
        ):
            with launcher.cache_directory(self.cache, self.cache, create=True):
                self.assertTrue(self.cache.is_dir())
        expected = [*reversed(self.cache.parents), self.cache]
        self.assertEqual(created, [self.cache])
        self.assertEqual([entry.args[0] for entry in handles.call_args_list], expected)
        self.assertEqual([entry.args[0] for entry in validate.call_args_list], expected)
        validate.assert_called_with(self.cache, private=True)

    def test_windows_token_user_passes_sid_pointer_to_conversion(self):
        import struct
        from ctypes import wintypes

        permissions = launcher.windows_permissions_module()
        security, kernel = Mock(), Mock()
        current_user = "S-1-5-21-1-2-3-1001"
        other_user = "S-1-5-21-1-2-3-1002"
        sid_storage = ctypes.create_string_buffer(b"fixture SID")
        sid_pointer = ctypes.c_void_p(ctypes.addressof(sid_storage))
        acl_storage = ctypes.create_string_buffer(struct.pack("<BBHHH", 2, 0, 8, 0, 0))
        ace_storage = ctypes.create_string_buffer(16)
        converted = []
        pointer_value = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)(
            lambda value: value
        )

        def token_information(token, kind, buffer, size, needed):
            needed._obj.value = ctypes.sizeof(sid_pointer) + ctypes.sizeof(
                wintypes.DWORD
            )
            if buffer is None:
                return False
            ctypes.memmove(
                buffer, ctypes.byref(sid_pointer), ctypes.sizeof(sid_pointer)
            )
            return True

        def convert(sid, text):
            address = pointer_value(sid)
            converted.append(address)
            text._obj.value = (
                current_user if address == sid_pointer.value else other_user
            )
            return True

        def get_ace(acl, index, address):
            self.assertEqual(index, 0)
            address._obj.value = ctypes.addressof(ace_storage)
            return True

        def security_information(
            path, kind, flags, owner, group, acl, sacl, descriptor
        ):
            owner._obj.value = sid_pointer.value
            acl._obj.value = ctypes.addressof(acl_storage)
            descriptor._obj.value = ctypes.addressof(acl_storage)
            return 0

        security.GetTokenInformation.side_effect = token_information
        security.ConvertSidToStringSidW.side_effect = convert
        security.GetNamedSecurityInfoW.side_effect = security_information
        security.GetAce.side_effect = get_ace
        flags_to_check = (None, 0, 0x10, 0x13, 0x08, 0x18)
        for flags in flags_to_check:
            converted.clear()
            acl_storage = ctypes.create_string_buffer(
                struct.pack("<BBHHH", 2, 0, 8, int(flags is not None), 0)
            )
            ace_storage = ctypes.create_string_buffer(
                struct.pack("<BBHI", 0, flags or 0, 16, 2) + b"\0" * 8
            )
            effective = flags is not None and not flags & 0x08
            with (
                self.subTest(flags=flags),
                patch.object(permissions.sys, "platform", "win32"),
                patch.object(
                    ctypes, "WinDLL", side_effect=[security, kernel], create=True
                ),
            ):
                if effective:
                    with self.assertRaisesRegex(ValueError, "write access"):
                        permissions.windows_permissions(self.cache, private=True)
                else:
                    permissions.windows_permissions(self.cache, private=True)
            expected = [sid_pointer.value]
            if effective:
                expected.append(ctypes.addressof(ace_storage) + 8)
            self.assertEqual(converted, [*expected, sid_pointer.value])
        self.assertEqual(kernel.CloseHandle.call_count, len(flags_to_check))

    def test_windows_ancestor_creation_does_not_allow_private_writes_or_replacement(
        self,
    ):
        current_user = "S-1-5-21-1-2-3-1001"
        other_user = "S-1-5-21-1-2-3-1002"
        for mask in (0x2, 0x4, 0x6):
            entries = [(0, 0, mask, other_user)]
            launcher.validate_windows_cache_acl(
                current_user, current_user, entries, False
            )
            with (
                self.subTest(mask=mask),
                self.assertRaisesRegex(ValueError, "write access"),
            ):
                launcher.validate_windows_cache_acl(
                    current_user, current_user, entries, True
                )
        for mask in (
            0x10,
            0x40,
            0x100,
            0x10000,
            0x40000,
            0x80000,
            0x10000000,
            0x40000000,
        ):
            with (
                self.subTest(mask=mask),
                self.assertRaisesRegex(ValueError, "write access"),
            ):
                launcher.validate_windows_cache_acl(
                    current_user, current_user, [(0, 0, mask, other_user)], False
                )
        with self.assertRaisesRegex(ValueError, "owner"):
            launcher.validate_windows_cache_acl(
                other_user, current_user, [(0, 0, 0x6, other_user)], False
            )

    def test_windows_cache_acl_accepts_read_only_and_creator_owner_entries(self):
        current_user = "S-1-5-21-1-2-3-1001"
        entries = [(0, 0, 0x1200A9, "S-1-5-32-545"), (0, 0x0B, 0x10000000, "S-1-3-0")]
        launcher.validate_windows_cache_acl(current_user, current_user, entries, True)
        ancestor_entries = [*entries, (0, 0, 4, "S-1-5-11")]
        launcher.validate_windows_cache_acl(
            "S-1-5-32-544", current_user, ancestor_entries, False
        )
        installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        launcher.validate_windows_cache_acl(
            installer, current_user, ancestor_entries, False
        )
        with self.assertRaisesRegex(ValueError, "write access"):
            launcher.validate_windows_cache_acl(
                current_user, current_user, ancestor_entries, True
            )

    def test_archive_links_are_rejected_in_both_formats(self):
        for rid in ("linux-x64", "win-arm64"):
            with self.subTest(rid=rid):
                archive = self.archive(rid, kind="symlink")
                name = "tmforge.exe" if rid.startswith("win-") else "tmforge"
                with self.assertRaisesRegex(ValueError, "regular file"):
                    launcher.unpack_binary(
                        archive,
                        f"tmforge-{self.version}-{rid}/{name}",
                        self.directory / "binary",
                    )

    def test_untrusted_metadata_cannot_choose_version_or_asset_path(self):
        metadata = self.metadata("linux-x64", self.archive("linux-x64"))
        cases: list[dict[str, object]] = []
        changes: tuple[tuple[str, object], ...] = (
            ("version", "latest"),
            ("tag", "main"),
            ("artifacts", []),
        )
        for field, value in changes:
            invalid = copy.deepcopy(metadata)
            invalid[field] = value
            cases.append(invalid)
        for field, value in (
            ("file", "../../binary"),
            ("sha256", "bad"),
            ("size", True),
            ("size", launcher.MAX_ARCHIVE_BYTES + 1),
            ("rid", "osx-x64"),
        ):
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
            for url in (
                "http://github.com/file",
                "https://example.com/file",
                "file:///tmp/file",
            ):
                with (
                    self.subTest(url=url),
                    self.assertRaisesRegex(ValueError, "HTTPS GitHub"),
                ):
                    launcher.download(url, self.directory / "file", 100)
            request.assert_not_called()
            response = request.return_value.__enter__.return_value
            response.geturl.return_value = "http://github.com/downgraded"
            with self.assertRaisesRegex(ValueError, "redirected"):
                launcher.download(
                    "https://github.com/file", self.directory / "file", 100
                )

    def test_status_and_missing_binary_never_download(self):
        with (
            patch.object(launcher, "download") as download,
            patch.object(launcher, "subprocess") as process,
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    launcher.main(["--cache-dir", str(self.cache), "--status"]), 0
                )
            self.assertFalse(json.loads(output.getvalue())["installed"])
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(
                    launcher.main(["--cache-dir", str(self.cache), "--", "--version"]),
                    1,
                )
            self.assertIn("After approval", errors.getvalue())
            self.assertFalse(self.cache.exists())
            download.assert_not_called()
            process.run.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX no-follow cache file open")
    def test_cache_swaps_before_open_are_rejected(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        receipt = binary.parent / "receipt.json"
        original_open = os.open
        for path in (binary, receipt):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                mode = stat.S_IMODE(path.stat().st_mode)
                target = self.directory / "replacement"
                target.write_bytes(original)

                def swap(name, flags, *args, **kwargs):
                    if name == path.name:
                        path.unlink()
                        path.symlink_to(target)
                    return original_open(name, flags, *args, **kwargs)

                try:
                    with (
                        patch.object(os, "open", side_effect=swap),
                        self.assertRaises(OSError),
                    ):
                        launcher.cached_binary(self.cache, self.version, rid)
                finally:
                    path.unlink()
                    path.write_bytes(original)
                    path.chmod(mode)

    @unittest.skipUnless(os.name == "posix", "POSIX held cache descriptor")
    def test_verified_cache_retains_the_hashed_file_after_path_swap(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        replacement = self.directory / "replacement"
        replacement.write_bytes(b"not the verified payload")
        with launcher.verified_cache(self.cache, self.version, rid) as verified:
            self.assertIsNotNone(verified)
            path, stream, digest = verified
            binary.unlink()
            binary.symlink_to(replacement)
            self.assertEqual(path, binary)
            self.assertEqual(stream.read(), self.payload)
            self.assertEqual(digest, hashlib.sha256(self.payload).hexdigest())
        self.assertTrue(stream.closed)

    def test_execution_preserves_arguments_and_exit_code(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        output = io.StringIO()

        def execute(verified, arguments):
            self.assertEqual(verified[0], binary)
            self.assertEqual(verified[1].read(), self.payload)
            self.assertEqual(arguments, ["analyze", "model with spaces.tm7", "--json"])
            return 2

        with (
            patch.object(launcher, "runtime_id", return_value=rid),
            patch.object(launcher, "execute_verified", side_effect=execute) as run,
            patch.object(launcher, "download") as download,
            redirect_stdout(output),
        ):
            result = launcher.main(
                [
                    "--cache-dir",
                    str(self.cache),
                    "--",
                    "analyze",
                    "model with spaces.tm7",
                    "--json",
                ]
            )
        self.assertEqual(result, 2)
        run.assert_called_once()
        self.assertEqual(output.getvalue(), "")
        download.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX retained file identity")
    def test_cache_replacement_after_hash_cannot_change_execution_bytes(self):
        rid = "osx-arm64"
        binary = self.install_fixture(rid)
        replacement = self.directory / "replacement"
        replacement.write_bytes(b"replacement must never execute")
        original_hash = launcher.stream_sha256
        swapped = False
        launched: list[Path] = []

        def swap_after_hash(stream):
            nonlocal swapped
            digest = original_hash(stream)
            if not swapped:
                binary.unlink()
                binary.symlink_to(replacement)
                swapped = True
            return digest

        def execute(command, **kwargs):
            selected = Path(kwargs.get("executable", command[0]))
            self.assertNotEqual(selected, binary)
            self.assertEqual(selected.read_bytes(), self.payload)
            self.assertEqual(command[1:], ["--version"])
            launched.append(selected)
            return subprocess.CompletedProcess(command, 0)

        with (
            patch.object(launcher, "runtime_id", return_value=rid),
            patch.object(launcher, "stream_sha256", side_effect=swap_after_hash),
            patch.object(launcher.subprocess, "run", side_effect=execute),
        ):
            self.assertEqual(
                launcher.main(["--cache-dir", str(self.cache), "--", "--version"]), 0
            )
        self.assertEqual(len(launched), 1)
        self.assertFalse(launched[0].exists())
        self.assertEqual(replacement.read_bytes(), b"replacement must never execute")

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine")
    def test_macos_install_preserves_archive_quarantine_through_execution_copy(self):
        quarantine = "0081;00000000;tmforge-fixture;"
        for rid in ("osx-arm64", "win-x64"):
            with self.subTest(rid=rid):
                binary = self.install_fixture(rid, quarantine=quarantine)
                with (
                    binary.open("rb") as source,
                    launcher.macos_execution_copy(
                        source, hashlib.sha256(self.payload).hexdigest()
                    ) as executable,
                ):
                    for current in (binary, executable):
                        result = subprocess.run(
                            [
                                "/usr/bin/xattr",
                                "-p",
                                "com.apple.quarantine",
                                str(current),
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(result.stdout.strip(), quarantine)
                        self.assertEqual(current.read_bytes(), self.payload)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine")
    def test_macos_install_accepts_archives_without_quarantine(self):
        binary = self.install_fixture("osx-arm64")
        result = subprocess.run(
            ["/usr/bin/xattr", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertNotIn("com.apple.quarantine", result.stdout.splitlines())
        self.assertEqual(binary.read_bytes(), self.payload)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS quarantine")
    def test_macos_install_does_not_publish_when_quarantine_copy_fails(self):
        with patch.object(
            launcher, "macos_copy_quarantine", side_effect=OSError("quarantine denied")
        ):
            with self.assertRaisesRegex(OSError, "quarantine denied"):
                self.install_fixture("osx-arm64")
        binary = launcher.binary_path(self.cache, self.version, "osx-arm64")
        self.assertFalse(binary.exists())
        self.assertFalse((binary.parent / "receipt.json").exists())
        self.assertEqual(list(binary.parent.iterdir()), [])

    @unittest.skipUnless(sys.platform == "darwin", "native macOS copyfile")
    def test_macos_execution_copy_preserves_quarantine_and_attributes(self):
        binary = self.install_fixture("osx-arm64")
        attributes = {
            "com.apple.quarantine": "0081;00000000;tmforge-fixture;",
            "org.tmforge.fixture": "preserve",
        }
        for name, value in attributes.items():
            subprocess.run(
                ["/usr/bin/xattr", "-w", name, value, str(binary)],
                check=True,
                capture_output=True,
            )
        with binary.open("rb") as stream:
            with launcher.macos_execution_copy(
                stream, hashlib.sha256(self.payload).hexdigest()
            ) as executable:
                self.assertEqual(executable.read_bytes(), self.payload)
                self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(executable.parent.stat().st_mode), 0o700)
                for name, value in attributes.items():
                    result = subprocess.run(
                        ["/usr/bin/xattr", "-p", name, str(executable)],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.stdout.strip(), value)
        self.assertFalse(executable.exists())

    @unittest.skipUnless(sys.platform == "darwin", "native macOS executable copy")
    def test_macos_executes_verified_native_fixture(self):
        self.payload = Path("/usr/bin/true").read_bytes()
        binary = self.install_fixture("osx-arm64")
        with patch.object(launcher, "runtime_id", return_value="osx-arm64"):
            self.assertEqual(launcher.main(["--cache-dir", str(self.cache), "--"]), 0)
        self.assertEqual(binary.read_bytes(), self.payload)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS execution copy")
    def test_macos_copy_rejects_in_place_changes_after_hash(self):
        binary = self.install_fixture("osx-arm64")
        with launcher.verified_cache(self.cache, self.version, "osx-arm64") as verified:
            binary.write_bytes(b"changed after validation")
            with patch.object(launcher.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                    launcher.execute_verified(verified, [])
            run.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "native Windows cache handles")
    def test_windows_verified_handles_block_replacement_and_writes(self):
        binary = self.install_fixture("win-x64")
        with launcher.verified_cache(self.cache, self.version, "win-x64") as verified:
            self.assertIsNotNone(verified)
            for path in (binary, binary.parent / "receipt.json"):
                with self.assertRaises(OSError):
                    path.unlink()
                with self.assertRaises(OSError):
                    path.write_bytes(b"must be denied")
            with self.assertRaises(OSError):
                binary.parent.rename(self.directory / "moved-cache")
        self.assertEqual(binary.read_bytes(), self.payload)

    @unittest.skipUnless(
        sys.platform.startswith("linux"), "native Linux descriptor execution"
    )
    def test_linux_executes_verified_native_fixture(self):
        self.payload = Path("/usr/bin/true").read_bytes()
        self.install_fixture("linux-x64")
        with patch.object(launcher, "runtime_id", return_value="linux-x64"):
            self.assertEqual(launcher.main(["--cache-dir", str(self.cache), "--"]), 0)

    def test_cache_must_stay_outside_plugin_and_cannot_escape_root(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            launcher.cache_root(self.installed_plugin / "binary-cache")
        if os.name != "nt":
            self.cache.mkdir()
            (self.cache / self.version).symlink_to(
                self.directory, target_is_directory=True
            )
            with self.assertRaisesRegex(ValueError, "escapes"):
                launcher.binary_path(self.cache, self.version, "linux-x64")

    def test_relocated_launcher_reads_its_own_pin(self):
        installed = self.directory / "relocated plugin"
        shutil.copytree(
            PLUGIN,
            installed,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".mypy_cache"),
        )
        path = installed / SCRIPT.relative_to(PLUGIN)
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(path),
                "--cache-dir",
                str(self.cache),
                "--status",
            ],
            cwd=self.directory,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        version = json.loads((PLUGIN / "plugin.json").read_text(encoding="utf-8"))[
            "version"
        ]
        self.assertEqual(json.loads(result.stdout)["version"], version)
        self.assertFalse(self.cache.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX cache permissions")
    def test_writable_cache_is_rejected_before_reuse(self):
        binary = self.install_fixture("osx-arm64")
        binary.parent.chmod(0o777)
        try:
            with self.assertRaisesRegex(ValueError, "permissions"):
                launcher.cached_binary(self.cache, self.version, "osx-arm64")
        finally:
            binary.parent.chmod(0o700)


class WrapperIntegrationTests(unittest.TestCase):
    def test_documented_nested_cli_quoting_survives_rebuild_parsing(self):
        reference = PLUGIN / "skills/threat-modeling-tmforge/references/cli-workflow.md"
        examples = re.findall(
            r"```bash\n(.*?)\n```", reference.read_text(encoding="utf-8"), re.DOTALL
        )
        example = next(block for block in examples if block.startswith("TMF="))
        assignment, command_text = example.split("\n", 1)
        invocation = shlex.split(assignment)[0].split("=", 1)[1]
        shell_arguments = [
            argument.replace("$TMF", invocation)
            for argument in shlex.split(command_text.replace("\\\n", ""))
        ]
        selected_cli = ["dotnet", "/absolute/tools path/tmforge.dll"]
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_nested_cli_documentation_test", script)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            (package / "analysis.json").write_text("{}", encoding="utf-8")
            (package / "model.tm.json").write_text("{}", encoding="utf-8")
            calls: list[list[str]] = []

            def run(command, cwd=None, descriptor=None):
                calls.append(command)
                if command[:2] == ["python3", "/path/to/layout.py"]:
                    self.assertEqual(command[-2:], ["--tmforge", invocation])
                    self.assertEqual(shlex.split(command[-1]), selected_cli)
                    (cwd / "model.tm.json").write_text(
                        '{"name":"regenerated"}', encoding="utf-8"
                    )
                if command[:3] == [*selected_cli, "apply"]:
                    (cwd / "model.tm7").write_bytes(b"candidate model")
                return 0, "{}"

            arguments = [str(script), str(package), *shell_arguments[3:], "--json"]
            with (
                patch.object(sys, "argv", arguments),
                patch.object(rebuild, "run", side_effect=run),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(rebuild.main(), 0)
            self.assertEqual(calls[0], [*selected_cli, "--version"])
            self.assertTrue(
                any(command[:3] == [*selected_cli, "apply"] for command in calls)
            )

    def test_manifest_command_must_refresh_its_staged_output(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_manifest_refresh_test", script)
        for operation in (
            "unchanged",
            "identical-write",
            "missing",
            "changed",
            "new",
            "allowed-noop",
        ):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as directory,
            ):
                package = Path(directory).resolve()
                (package / "analysis.json").write_text("{}", encoding="utf-8")
                (package / "model.tm7").write_bytes(b"owned model")
                if operation != "new":
                    (package / "model.tm.json").write_bytes(b"{}")
                before = {path.name: path.read_bytes() for path in package.iterdir()}
                calls: list[list[str]] = []

                def run(command, cwd=None, descriptor=None):
                    calls.append(command)
                    if command == ["mock-generator"]:
                        self.assertNotEqual(cwd, package)
                        manifest = cwd / "model.tm.json"
                        if operation == "identical-write":
                            manifest.write_bytes(b"{}")
                        elif operation == "missing":
                            manifest.unlink()
                        elif operation in {"changed", "new"}:
                            manifest.write_bytes(b'{"name":"regenerated"}')
                    return 0, "{}"

                arguments = [
                    str(script),
                    str(package),
                    "--manifest-command",
                    "mock-generator",
                    "--tmforge",
                    "mock-tmforge",
                    "--json",
                ]
                if operation == "allowed-noop":
                    arguments.append("--allow-unchanged-manifest")
                output = io.StringIO()
                expected_success = operation in {"changed", "new", "allowed-noop"}
                with (
                    patch.object(sys, "argv", arguments),
                    patch.object(rebuild, "run", side_effect=run),
                    redirect_stdout(output),
                ):
                    self.assertEqual(rebuild.main(), 0 if expected_success else 1)
                report = json.loads(output.getvalue())
                manifest_step = next(
                    step for step in report["steps"] if step["step"] == "manifest"
                )
                self.assertEqual(
                    manifest_step["status"], "pass" if expected_success else "fail"
                )
                self.assertNotEqual(manifest_step["cwd"], str(package))
                if operation in {"unchanged", "identical-write", "allowed-noop"}:
                    self.assertEqual(
                        manifest_step["beforeSha256"], manifest_step["afterSha256"]
                    )
                    self.assertFalse(manifest_step["changed"])
                if not expected_success:
                    self.assertEqual(report["failedStep"], "manifest")
                    self.assertIn("candidate cwd", manifest_step["detail"])
                    self.assertFalse(
                        any(
                            command[:2] == ["mock-tmforge", "apply"]
                            for command in calls
                        )
                    )
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in package.iterdir()},
                        before,
                    )

    def test_manifest_command_cannot_regenerate_the_staged_ledger(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_manifest_ledger_guard_test", script)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            (package / "analysis.json").write_bytes(b"{}")
            (package / "model.tm.json").write_bytes(b"{}")
            before = {path.name: path.read_bytes() for path in package.iterdir()}

            def run(command, cwd=None, descriptor=None):
                if command == ["mock-generator"]:
                    (cwd / "analysis.json").write_bytes(b'{"regenerated":true}')
                    (cwd / "model.tm.json").write_bytes(b'{"name":"changed"}')
                self.assertNotEqual(command[:2], ["mock-tmforge", "apply"])
                return 0, "{}"

            arguments = [
                str(script),
                str(package),
                "--manifest-command",
                "mock-generator",
                "--tmforge",
                "mock-tmforge",
                "--json",
            ]
            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch.object(rebuild, "run", side_effect=run),
                redirect_stdout(output),
            ):
                self.assertEqual(rebuild.main(), 1)
            report = json.loads(output.getvalue())
            self.assertEqual(report["failedStep"], "manifest")
            self.assertIn("Regenerate the ledger before", report["steps"][1]["detail"])
            self.assertEqual(
                {path.name: path.read_bytes() for path in package.iterdir()}, before
            )

    def test_rebuild_custom_names_and_formal_missing_defaults_are_explicit(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_custom_names_test", script)
        for supplied in (True, False):
            with (
                self.subTest(supplied=supplied),
                tempfile.TemporaryDirectory() as directory,
            ):
                package = Path(directory).resolve()
                (package / "analysis.json").write_text(
                    '{"scope":{"mode":"formal-package"}}', encoding="utf-8"
                )
                (package / "threat-model.tm.json").write_text("{}", encoding="utf-8")
                before = {path.name: path.read_bytes() for path in package.iterdir()}
                arguments = [
                    str(script),
                    str(package),
                    "--tmforge",
                    "mock-tmforge",
                    "--json",
                ]
                if supplied:
                    arguments += [
                        "--model",
                        "threat-model.tm7",
                        "--manifest",
                        "threat-model.tm.json",
                    ]
                calls: list[list[str]] = []

                def run(command, cwd=None, descriptor=None):
                    calls.append(command)
                    if command[:2] == ["mock-tmforge", "apply"]:
                        self.assertEqual(
                            command[2:],
                            ["threat-model.tm.json", "--out", "threat-model.tm7"],
                        )
                        (cwd / "threat-model.tm7").write_bytes(b"rebuilt candidate")
                    return 0, "{}"

                output = io.StringIO()
                with (
                    patch.object(sys, "argv", arguments),
                    patch.object(rebuild, "run", side_effect=run),
                    redirect_stdout(output),
                ):
                    self.assertEqual(rebuild.main(), 0 if supplied else 1)
                report = json.loads(output.getvalue())
                if supplied:
                    self.assertEqual(
                        (package / "threat-model.tm7").read_bytes(),
                        b"rebuilt candidate",
                    )
                    self.assertIsNone(report["failedStep"])
                else:
                    self.assertEqual(report["failedStep"], "apply")
                    self.assertFalse(
                        any(
                            command[:2] == ["mock-tmforge", "apply"]
                            for command in calls
                        )
                    )
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in package.iterdir()},
                        before,
                    )

    def test_rebuild_missing_artifact_fails_at_its_consumer(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_missing_input_test", script)
        for step, missing, option in (
            ("apply", "model.tm.json", "--manifest"),
            ("layout", "model.tm7", "--model"),
        ):
            with self.subTest(step=step), tempfile.TemporaryDirectory() as directory:
                package = Path(directory).resolve()
                (package / "analysis.json").write_text("{}", encoding="utf-8")
                present = "model.tm7" if step == "apply" else "model.tm.json"
                (package / present).write_bytes(b"owned artifact")
                before = {path.name: path.read_bytes() for path in package.iterdir()}
                output = io.StringIO()
                with (
                    patch.object(
                        sys,
                        "argv",
                        [
                            str(script),
                            str(package),
                            "--tmforge",
                            "mock-tmforge",
                            "--json",
                        ],
                    ),
                    patch.object(rebuild, "run", return_value=(0, "{}")),
                    redirect_stdout(output),
                ):
                    self.assertEqual(rebuild.main(), 1)
                report = json.loads(output.getvalue())
                self.assertEqual(report["failedStep"], step)
                failure = next(item for item in report["steps"] if item["step"] == step)
                self.assertEqual(failure["status"], "fail")
                self.assertIn(missing, failure["detail"])
                self.assertIn(option, failure["detail"])
                self.assertEqual(report["steps"][-1]["status"], "not-run")
                self.assertEqual(
                    {path.name: path.read_bytes() for path in package.iterdir()}, before
                )

    def test_explicit_empty_or_malformed_invocations_are_usage_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            model, justifications = (
                package / "model.tm7",
                package / "justifications.json",
            )
            model.write_bytes(b"fixture model")
            justifications.write_text("{}")
            for name in ("rebuild_package.py", "generate_suppressions.py"):
                script = PLUGIN / "skills/threat-modeling/scripts" / name
                module = load_script("invalid_invocation_" + script.stem, script)
                arguments = (
                    [str(package)]
                    if name == "rebuild_package.py"
                    else [str(model), str(justifications)]
                )
                flags = (
                    ("--tmforge", "--manifest-command")
                    if name == "rebuild_package.py"
                    else ("--tmforge",)
                )
                for flag in flags:
                    for value in ("", " ", "'unterminated"):
                        with (
                            self.subTest(script=name, flag=flag, value=value),
                            patch.object(
                                sys, "argv", [str(script), *arguments, flag, value]
                            ),
                            redirect_stderr(io.StringIO()),
                            self.assertRaises(SystemExit) as exit_status,
                        ):
                            module.main()
                        self.assertEqual(exit_status.exception.code, 2)

    def test_suppression_generator_preserves_quoted_launcher(self):
        script = (
            PLUGIN
            / "skills"
            / "threat-modeling"
            / "scripts"
            / "generate_suppressions.py"
        )
        generator = load_script("plugin_suppression_wrapper_test", script)
        command = [sys.executable, "/installed plugins/tmforge/launcher.py", "--"]
        self.assertEqual(generator.resolve_invocation(shlex.join(command)), command)

    def test_rebuild_keeps_launcher_and_checks_newly_generated_artifacts(self):
        script = (
            PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        )
        rebuild = load_script("plugin_rebuild_wrapper_test", script)
        wrapper = [sys.executable, "/installed plugins/tmforge/launcher.py", "--"]
        generator = [sys.executable, "/author scripts/build manifest.py"]
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            calls: list[list[str]] = []
            candidates: list[Path] = []

            def record(
                command: list[str],
                cwd: Path | None = None,
                descriptor: int | None = None,
            ) -> tuple[int, str]:
                calls.append(command)
                if command == generator:
                    assert cwd is not None
                    self.assertNotEqual(cwd, package)
                    self.assertEqual(cwd.parent, package.parent)
                    candidates.append(cwd)
                    (cwd / "model.tm.json").write_text("{}")
                if command[: len(wrapper) + 1] == [*wrapper, "apply"]:
                    self.assertEqual(cwd, candidates[0])
                    (candidates[0] / "model.tm7").write_bytes(
                        b"test fixture, not a real model"
                    )
                self.assertFalse((package / "model.tm7").exists())
                return 0, "{}"

            arguments = [
                str(script),
                str(package),
                "--manifest-command",
                shlex.join(generator),
                "--tmforge",
                shlex.join(wrapper),
                "--justifications",
                str(package / "justifications.json"),
                "--json",
            ]
            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch.object(rebuild, "run", side_effect=record),
                redirect_stdout(output),
            ):
                self.assertEqual(rebuild.main(), 0)
            report = json.loads(output.getvalue())
            self.assertEqual(
                [step["step"] for step in report["steps"]],
                [
                    "tmforge",
                    "manifest",
                    "ledger",
                    "apply",
                    "layout",
                    "suppressions",
                    "render",
                    "package",
                ],
            )
            self.assertEqual(calls[0], [*wrapper, "--version"])
            self.assertEqual(calls[1], generator)
            self.assertEqual(calls[3][: len(wrapper)], wrapper)
            self.assertEqual(
                (package / "model.tm7").read_bytes(),
                b"test fixture, not a real model",
            )
            self.assertTrue((package / "model.tm.json").is_file())
            self.assertFalse(candidates[0].exists())
            for command in (calls[5], calls[-1]):
                self.assertIn("--tmforge", command)
                self.assertEqual(
                    shlex.split(command[command.index("--tmforge") + 1]), wrapper
                )

    def test_generated_manifests_are_checked_before_apply(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_generated_manifest_test", script)
        for existing in (False, True):
            for kind in ("symlink", "dangling", "directory", "reparse"):
                with (
                    self.subTest(existing=existing, kind=kind),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory).resolve()
                    package = root / "package"
                    package.mkdir()
                    before = {
                        "analysis.json": b"original ledger",
                        "model.tm7": b"original model",
                        "threat-model.md": b"original report",
                    }
                    if existing:
                        before["model.tm.json"] = b"original manifest"
                    for name, content in before.items():
                        (package / name).write_bytes(content)
                    external = root / "external.json"
                    external.write_bytes(b"external manifest")
                    calls: list[list[str]] = []
                    candidates: list[Path] = []
                    reparse_paths: list[Path] = []
                    original_info = rebuild.BoundDirectory.info

                    def inspect(
                        directory, name: str
                    ) -> os.stat_result | SimpleNamespace:
                        if directory.path / name in reparse_paths:
                            return SimpleNamespace(
                                st_mode=stat.S_IFREG,
                                st_file_attributes=getattr(
                                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
                                ),
                            )
                        return original_info(directory, name)

                    def run(
                        command: list[str],
                        cwd: Path | None = None,
                        descriptor: int | None = None,
                    ) -> tuple[int, str]:
                        calls.append(command)
                        if command == ["mock-generator"]:
                            assert cwd is not None
                            candidates.append(cwd)
                            manifest = cwd / "model.tm.json"
                            manifest.unlink(missing_ok=True)
                            if kind == "directory":
                                manifest.mkdir()
                            elif kind == "reparse":
                                manifest.write_bytes(b"fixture manifest")
                                reparse_paths.append(manifest)
                            else:
                                try:
                                    manifest.symlink_to(
                                        external
                                        if kind == "symlink"
                                        else root / "missing.json"
                                    )
                                except OSError as exc:
                                    self.skipTest(f"symlinks are unavailable: {exc}")
                        return 0, "{}"

                    output = io.StringIO()
                    with (
                        patch.object(
                            sys,
                            "argv",
                            [
                                str(script),
                                str(package),
                                "--manifest-command",
                                "mock-generator",
                                "--tmforge",
                                "mock-tmforge",
                                "--json",
                            ],
                        ),
                        patch.object(rebuild, "run", side_effect=run),
                        patch.object(
                            rebuild.BoundDirectory,
                            "info",
                            autospec=True,
                            side_effect=inspect,
                        ),
                        redirect_stdout(output),
                    ):
                        self.assertEqual(rebuild.main(), 1)
                    report = json.loads(output.getvalue())
                    self.assertFalse(report["valid"])
                    self.assertEqual(report["failedStep"], "candidate")
                    self.assertIn("regular files", report["steps"][-1]["detail"])
                    self.assertFalse(
                        any(
                            command[:2] == ["mock-tmforge", "apply"]
                            for command in calls
                        )
                    )
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in package.iterdir()},
                        before,
                    )
                    self.assertEqual(external.read_bytes(), b"external manifest")
                    self.assertEqual(len(candidates), 1)
                    self.assertFalse(candidates[0].exists())

    def test_failed_layout_preserves_owned_model(self):
        script = (
            PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        )
        rebuild = load_script("plugin_rebuild_candidate_test", script)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            model = package / "model.tm7"
            model.write_bytes(b"previous model")
            (package / "model.tm.json").write_text("{}", encoding="utf-8")

            def run(
                command: list[str],
                cwd: Path | None = None,
                descriptor: int | None = None,
            ) -> tuple[int, str]:
                if command[:2] == ["mock-tmforge", "apply"]:
                    assert cwd is not None
                    destination = cwd / command[command.index("--out") + 1]
                    destination.write_bytes(b"candidate with invalid layout")
                if len(command) > 1 and Path(command[1]).name == "check_layout.py":
                    return 1, "element lies outside its boundary"
                return 0, "{}"

            output = io.StringIO()
            with (
                patch.object(
                    sys,
                    "argv",
                    [str(script), str(package), "--tmforge", "mock-tmforge", "--json"],
                ),
                patch.object(rebuild, "run", side_effect=run),
                redirect_stdout(output),
            ):
                self.assertEqual(rebuild.main(), 1)
            self.assertEqual(json.loads(output.getvalue())["failedStep"], "layout")
            self.assertEqual(model.read_bytes(), b"previous model")

    def test_late_rebuild_failures_preserve_all_outputs(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_late_failure_test", script)
        for failed_step in ("apply", "suppressions", "render", "package"):
            with (
                self.subTest(step=failed_step),
                tempfile.TemporaryDirectory() as directory,
            ):
                package = Path(directory).resolve()
                files = (
                    "analysis.json",
                    "model.tm.json",
                    "model.tm7",
                    "model.tm.suppressions.json",
                    "data-flow.md",
                    "threat-model.md",
                )
                for name in files:
                    (package / name).write_bytes(f"original {name}".encode())
                before = {name: (package / name).read_bytes() for name in files}
                candidates: list[Path] = []

                def run(
                    command: list[str],
                    cwd: Path | None = None,
                    descriptor: int | None = None,
                ) -> tuple[int, str]:
                    if command[:2] == ["mock-tmforge", "apply"]:
                        assert cwd is not None
                        candidates.append(cwd)
                        (cwd / "model.tm7").write_bytes(b"new model")
                        return (
                            (1, "apply failed") if failed_step == "apply" else (0, "{}")
                        )
                    step = {
                        "generate_suppressions.py": "suppressions",
                        "render_analysis.py": "render",
                        "validate_package.py": "package",
                    }.get(Path(command[1]).name)
                    if step and candidates:
                        for name in files[3:]:
                            (candidates[0] / name).write_bytes(b"new candidate output")
                    return (1, f"{step} failed") if step == failed_step else (0, "{}")

                output = io.StringIO()
                with (
                    patch.object(
                        sys,
                        "argv",
                        [
                            str(script),
                            str(package),
                            "--tmforge",
                            "mock-tmforge",
                            "--justifications",
                            str(package / "justifications.json"),
                            "--json",
                        ],
                    ),
                    patch.object(rebuild, "run", side_effect=run),
                    redirect_stdout(output),
                ):
                    self.assertEqual(rebuild.main(), 1)
                self.assertEqual(
                    json.loads(output.getvalue())["failedStep"], failed_step
                )
                self.assertEqual(
                    before, {name: (package / name).read_bytes() for name in files}
                )
                self.assertFalse(candidates[0].exists())

    def test_promotion_removes_outputs_missing_from_the_candidate(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_promotion_removal_test", script)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package, candidate = root / "package", root / "candidate"
            package.mkdir()
            candidate.mkdir()
            before = dict.fromkeys(
                ("model.tm7", "model.tm.json", "model.tm.suppressions.json"),
                b"old artifact",
            )
            for name, content in before.items():
                (package / name).write_bytes(content)
            with rebuild.package_lock(package):
                rebuild.promote_outputs(package, candidate, before)
            self.assertEqual(list(package.iterdir()), [])
            self.assertEqual(
                sorted(path.name for path in root.iterdir()), ["candidate", "package"]
            )

    def test_promotion_failures_restore_existing_and_remove_new_outputs(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_promotion_rollback_test", script)
        for failure in (OSError, KeyboardInterrupt):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                package, candidate = root / "package", root / "candidate"
                package.mkdir()
                candidate.mkdir()
                before: dict[str, bytes | None] = {
                    "model.tm.suppressions.json": b"original sidecar",
                    "analysis.json": b"original ledger",
                    "data-flow.md": None,
                    "model.tm7": b"original model",
                }
                for name, content in before.items():
                    if content is not None:
                        (package / name).write_bytes(content)
                    if name != "model.tm.suppressions.json":
                        (candidate / name).write_bytes(b"new candidate")
                replace = rebuild.BoundDirectory.replace_from

                def fail(destination, source, name):
                    if source.path == candidate and name == "model.tm7":
                        raise failure("injected promotion failure")
                    replace(destination, source, name)

                with (
                    rebuild.package_lock(package),
                    patch.object(
                        rebuild.BoundDirectory,
                        "replace_from",
                        autospec=True,
                        side_effect=fail,
                    ),
                    self.assertRaises(failure),
                ):
                    rebuild.promote_outputs(package, candidate, before)
                self.assertEqual(
                    {name: rebuild.artifact_bytes(package / name) for name in before},
                    before,
                )
                self.assertEqual(
                    sorted(path.name for path in root.iterdir()),
                    ["candidate", "package"],
                )

    def test_promotion_rechecks_outputs_and_preserves_concurrent_edits(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_promotion_concurrency_test", script)
        for edited_name in ("analysis.json", "model.tm7"):
            with (
                self.subTest(edited_name=edited_name),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                package, candidate = root / "package", root / "candidate"
                package.mkdir()
                candidate.mkdir()
                before = {
                    "analysis.json": b"old ledger",
                    "model.tm7": b"old model",
                }
                for name, content in before.items():
                    (package / name).write_bytes(content)
                    (candidate / name).write_bytes(b"new candidate")
                replace = rebuild.BoundDirectory.replace_from

                def edit(destination, source, name):
                    replace(destination, source, name)
                    if source.path == candidate and name == "analysis.json":
                        (package / edited_name).write_bytes(b"concurrent edit")

                with (
                    rebuild.package_lock(package),
                    patch.object(
                        rebuild.BoundDirectory,
                        "replace_from",
                        autospec=True,
                        side_effect=edit,
                    ),
                    self.assertRaisesRegex(ValueError, "changed during promotion"),
                ):
                    rebuild.promote_outputs(package, candidate, before)
                self.assertEqual(
                    (package / edited_name).read_bytes(), b"concurrent edit"
                )
                other_name = next(name for name in before if name != edited_name)
                self.assertEqual(
                    (package / other_name).read_bytes(), before[other_name]
                )
                recovery = list(root.glob(".package.rollback-*"))
                if edited_name == "analysis.json":
                    self.assertEqual(len(recovery), 1)
                    self.assertEqual(
                        (recovery[0] / edited_name).read_bytes(), before[edited_name]
                    )
                else:
                    self.assertEqual(recovery, [])

    def test_rollback_preserves_concurrently_recreated_deleted_output(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_promotion_recreation_test", script)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package, candidate = root / "package", root / "candidate"
            package.mkdir()
            candidate.mkdir()
            before = {
                "model.tm.suppressions.json": b"old sidecar",
                "analysis.json": b"old ledger",
            }
            for name, content in before.items():
                (package / name).write_bytes(content)
            (candidate / "analysis.json").write_bytes(b"new ledger")

            def recreate(destination, source, name):
                self.assertFalse((package / "model.tm.suppressions.json").exists())
                (package / "model.tm.suppressions.json").write_bytes(b"concurrent edit")
                raise OSError("injected failure after deletion")

            with (
                rebuild.package_lock(package),
                patch.object(
                    rebuild.BoundDirectory,
                    "replace_from",
                    autospec=True,
                    side_effect=recreate,
                ),
                self.assertRaisesRegex(ValueError, "rollback incomplete"),
            ):
                rebuild.promote_outputs(package, candidate, before)
            self.assertEqual(
                (package / "model.tm.suppressions.json").read_bytes(),
                b"concurrent edit",
            )
            self.assertEqual(
                (package / "analysis.json").read_bytes(), before["analysis.json"]
            )
            recovery = list(root.glob(".package.rollback-*"))
            self.assertEqual(len(recovery), 1)
            self.assertEqual(
                (recovery[0] / "model.tm.suppressions.json").read_bytes(),
                b"old sidecar",
            )

    def test_package_lock_excludes_other_processes_and_releases(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_lock_test", script)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve() / "package"
            package.mkdir()
            code = (
                "import importlib.util, sys\n"
                "from pathlib import Path\n"
                "sys.path.insert(0, str(Path(sys.argv[1]).parent))\n"
                "spec = importlib.util.spec_from_file_location('rebuild', sys.argv[1])\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "spec.loader.exec_module(module)\n"
                "with module.package_lock(Path(sys.argv[2])):\n"
                "    pass\n"
            )
            with rebuild.package_lock(package):
                result = subprocess.run(
                    [sys.executable, "-B", "-S", "-c", code, str(script), str(package)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("another rebuild holds", result.stderr)
            with rebuild.package_lock(package):
                pass
            self.assertEqual(list(package.parent.iterdir()), [package])

    def test_missing_tmforge_blocks_before_any_package_changes(self):
        script = (
            PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        )
        rebuild = load_script("plugin_rebuild_missing_tool_test", script)
        for source in ("manifest", "model", "generator"):
            with (
                self.subTest(source=source),
                tempfile.TemporaryDirectory() as directory,
            ):
                package = Path(directory).resolve()
                arguments = [str(script), str(package), "--json"]
                if source == "manifest":
                    (package / "model.tm.json").write_text("{}", encoding="utf-8")
                elif source == "model":
                    (package / "model.tm7").write_bytes(b"existing model")
                else:
                    arguments += ["--manifest-command", "generate-manifest"]
                (package / "threat-model.md").write_bytes(b"existing report")
                before = {path.name: path.read_bytes() for path in package.iterdir()}
                output = io.StringIO()
                with (
                    patch.object(sys, "argv", arguments),
                    patch.object(rebuild.shutil, "which", return_value=None),
                    patch.object(rebuild, "run") as run,
                    redirect_stdout(output),
                ):
                    self.assertEqual(rebuild.main(), 1)
                run.assert_not_called()
                report = json.loads(output.getvalue())
                self.assertFalse(report["valid"])
                self.assertEqual(report["failedStep"], "tmforge")
                self.assertTrue(
                    all(step["status"] == "not-run" for step in report["steps"][1:])
                )
                self.assertEqual(
                    before, {path.name: path.read_bytes() for path in package.iterdir()}
                )

    def test_unavailable_wrapper_blocks_before_manifest_generation(self):
        script = (
            PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        )
        rebuild = load_script("plugin_rebuild_unavailable_wrapper_test", script)
        wrapper = [sys.executable, "/installed plugins/tmforge/launcher.py", "--"]
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            arguments = [
                str(script),
                str(package),
                "--manifest-command",
                "generate-manifest",
                "--tmforge",
                shlex.join(wrapper),
                "--json",
            ]
            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch.object(
                    rebuild, "run", return_value=(1, "Approved installation required")
                ) as run,
                redirect_stdout(output),
            ):
                self.assertEqual(rebuild.main(), 1)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args, ([*wrapper, "--version"], package))
            self.assertEqual(json.loads(output.getvalue())["failedStep"], "tmforge")
            self.assertEqual(list(package.iterdir()), [])

    @unittest.skipUnless(os.name == "posix", "POSIX directory substitution")
    def test_rebuild_directory_swaps_never_modify_the_substituted_tree(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_directory_race_test", script)
        example = json.loads(
            (PLUGIN / "skills/threat-modeling/assets/analysis.example.json").read_text()
        )
        example["scope"]["mode"] = "verify"
        example["scope"]["ownershipDecision"] = {
            "action": "verify-only",
            "modelReference": "existing.tm7",
            "rationale": "Exercise descriptor-bound publication without a binary.",
        }
        for target in ("package", "parent"):
            for phase in ("create", "copy", "promote", "replace", "rollback"):
                with (
                    self.subTest(target=target, phase=phase),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory).resolve()
                    parent, outside = root / "reviewed", root / "outside"
                    package = parent / "package"
                    package.mkdir(parents=True)
                    before = {
                        "analysis.json": json.dumps(example).encode(),
                        "data-flow.md": b"old data flow",
                        "threat-model.md": b"old report",
                    }
                    for name, content in before.items():
                        (package / name).write_bytes(content)
                    shutil.copytree(package if target == "package" else parent, outside)
                    moved = root / "original"
                    swapped = False
                    original_mkdir, original_copy = os.mkdir, rebuild.copy_tree
                    original_promote = rebuild.promote_outputs
                    original_replace = rebuild.BoundDirectory.replace_from

                    def swap():
                        nonlocal swapped
                        if not swapped:
                            selected = package if target == "package" else parent
                            selected.rename(moved)
                            selected.symlink_to(outside, target_is_directory=True)
                            swapped = True

                    def mkdir(path, mode=0o777, *, dir_fd=None):
                        if phase == "create" and ".rebuild-" in str(path):
                            swap()
                            self.assertIsNotNone(dir_fd)
                        return original_mkdir(path, mode, dir_fd=dir_fd)

                    def copy(source, destination):
                        if phase == "copy":
                            swap()
                        return original_copy(source, destination)

                    def promote(*args, **kwargs):
                        if phase == "promote":
                            swap()
                        return original_promote(*args, **kwargs)

                    def replace(destination, source, name):
                        if phase == "replace":
                            swap()
                        if phase == "rollback":
                            if (
                                ".rebuild-" in source.path.name
                                and name == "threat-model.md"
                            ):
                                raise OSError("injected promotion failure")
                            if ".rollback-" in source.path.name:
                                swap()
                        self.assertIsNotNone(destination.descriptor)
                        self.assertIsNotNone(source.descriptor)
                        return original_replace(destination, source, name)

                    output = io.StringIO()
                    with (
                        patch.object(
                            sys, "argv", [str(script), str(package), "--json"]
                        ),
                        patch.object(rebuild.shutil, "which", return_value=None),
                        patch.object(os, "mkdir", side_effect=mkdir),
                        patch.object(rebuild, "copy_tree", side_effect=copy),
                        patch.object(rebuild, "promote_outputs", side_effect=promote),
                        patch.object(
                            rebuild.BoundDirectory,
                            "replace_from",
                            autospec=True,
                            side_effect=replace,
                        ),
                        redirect_stdout(output),
                    ):
                        self.assertEqual(rebuild.main(), 1)
                    self.assertFalse(json.loads(output.getvalue())["valid"])
                    self.assertTrue(swapped)
                    external_package = (
                        outside if target == "package" else outside / "package"
                    )
                    original_package = (
                        moved if target == "package" else moved / "package"
                    )
                    for current in (external_package, original_package):
                        self.assertEqual(
                            {
                                path.name: path.read_bytes()
                                for path in current.iterdir()
                            },
                            before,
                        )
                    if target == "parent":
                        self.assertEqual(list(outside.iterdir()), [external_package])
                        self.assertEqual(list(moved.iterdir()), [original_package])
                    else:
                        self.assertEqual(list(parent.iterdir()), [package])

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor-bound cwd")
    def test_candidate_command_uses_held_directory_after_rename(self):
        rebuild = load_script(
            "plugin_rebuild_cwd_race_test",
            PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            candidate, outside, moved = (
                root / "candidate",
                root / "outside",
                root / "original",
            )
            candidate.mkdir()
            outside.mkdir()
            with rebuild.bound_directory(candidate) as bound:
                candidate.rename(moved)
                candidate.symlink_to(outside, target_is_directory=True)
                code, output = rebuild.run(
                    [
                        sys.executable,
                        "-B",
                        "-S",
                        "-c",
                        "from pathlib import Path; Path('marker').write_text('bound')",
                    ],
                    cwd=candidate,
                    descriptor=bound.descriptor,
                )
            self.assertEqual(code, 0, output)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual((moved / "marker").read_text(), "bound")

    @unittest.skipUnless(sys.platform == "win32", "native Windows directory handles")
    def test_windows_rebuild_directories_cannot_be_substituted(self):
        rebuild = load_script(
            "plugin_rebuild_windows_pin_test",
            PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parent = root / "parent"
            package = parent / "package"
            package.mkdir(parents=True)
            with (
                rebuild.bound_directory(parent) as bound_parent,
                rebuild.bound_directory(package, bound_parent),
            ):
                for current in (package, parent):
                    with self.assertRaises(OSError):
                        current.rename(root / "substituted")
            self.assertTrue(package.is_dir())

    def test_recovery_open_failure_preserves_original_error_and_artifacts(self):
        rebuild = load_script(
            "plugin_rebuild_recovery_open_test",
            PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            package, candidate = root / "package", root / "candidate"
            package.mkdir()
            candidate.mkdir()
            (package / "analysis.json").write_bytes(b"original")
            (candidate / "analysis.json").write_bytes(b"replacement")
            original = rebuild.bound_directory
            denied = False

            def bind(path, parent=None):
                nonlocal denied
                if ".rollback-" in path.name and not denied:
                    denied = True
                    raise OSError("recovery open denied")
                return original(path, parent)

            with patch.object(rebuild, "bound_directory", side_effect=bind):
                with self.assertRaisesRegex(OSError, "recovery open denied"):
                    rebuild.promote_outputs(
                        package, candidate, {"analysis.json": b"original"}
                    )
            self.assertTrue(denied)
            self.assertEqual((package / "analysis.json").read_bytes(), b"original")
            self.assertEqual((candidate / "analysis.json").read_bytes(), b"replacement")

    def test_linked_package_paths_fail_before_any_rebuild_work(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_package_link_test", script)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            outside = root / "outside"
            package = outside / "package"
            package.mkdir(parents=True)
            ledger = package / "analysis.json"
            ledger.write_bytes(b"preserve external ledger")
            linked_package, linked_parent = (
                root / "linked-package",
                root / "linked-parent",
            )
            try:
                linked_package.symlink_to(package, target_is_directory=True)
                linked_parent.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks are unavailable: {exc}")
            for supplied in (
                linked_package,
                linked_parent / "package",
                linked_package / ".." / "package",
            ):
                with self.subTest(path=supplied):
                    errors = io.StringIO()
                    with (
                        patch.object(
                            sys,
                            "argv",
                            [
                                str(script),
                                str(supplied),
                                "--manifest-command",
                                "mock-generator",
                                "--tmforge",
                                "mock-tmforge",
                            ],
                        ),
                        patch.object(rebuild, "run") as run,
                        patch.object(rebuild, "package_lock") as lock,
                        redirect_stderr(errors),
                    ):
                        self.assertEqual(rebuild.main(), 2)
                    self.assertIn("symlink", errors.getvalue())
                    run.assert_not_called()
                    lock.assert_not_called()
                    self.assertEqual(ledger.read_bytes(), b"preserve external ledger")
                    self.assertEqual(list(outside.iterdir()), [package])
                    self.assertEqual(list(package.iterdir()), [ledger])

    def test_reparse_package_directory_fails_before_rebuild(self):
        script = PLUGIN / "skills/threat-modeling/scripts/rebuild_package.py"
        rebuild = load_script("plugin_rebuild_package_reparse_test", script)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            original_stat = os.stat
            original_lstat = Path.lstat

            def reparse(path, *args, **kwargs):
                if (
                    path in (package.name, package)
                    and kwargs.get("follow_symlinks") is False
                ):
                    return SimpleNamespace(
                        st_mode=stat.S_IFDIR, st_file_attributes=0x400
                    )
                return original_stat(path, *args, **kwargs)

            def reparse_lstat(path: Path) -> os.stat_result | SimpleNamespace:
                if path == package:
                    return SimpleNamespace(
                        st_mode=stat.S_IFDIR, st_file_attributes=0x400
                    )
                return original_lstat(path)

            errors = io.StringIO()
            with (
                patch.object(sys, "argv", [str(script), str(package)]),
                patch.object(os, "stat", side_effect=reparse),
                patch.object(Path, "lstat", reparse_lstat),
                patch.object(rebuild, "run") as run,
                redirect_stderr(errors),
            ):
                self.assertEqual(rebuild.main(), 2)
            run.assert_not_called()
            self.assertIn("reparse", errors.getvalue())
            self.assertEqual(list(package.iterdir()), [])

    def test_markdown_only_rebuild_does_not_require_tmforge(self):
        script = (
            PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        )
        rebuild = load_script("plugin_rebuild_markdown_test", script)
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory).resolve()
            example = PLUGIN / "skills/threat-modeling/assets/analysis.example.json"
            document = json.loads(example.read_text(encoding="utf-8"))
            document["scope"]["mode"] = "verify"
            document["scope"]["ownershipDecision"] = {
                "action": "verify-only",
                "modelReference": "existing-model.tm7",
                "rationale": "Exercise the Markdown-only rebuild without a binary.",
            }
            (package / "analysis.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
            arguments = [str(script), str(package), "--json"]
            output = io.StringIO()
            with (
                patch.object(sys, "argv", arguments),
                patch.object(rebuild.shutil, "which", return_value=None),
                patch.object(rebuild, "run", wraps=rebuild.run) as run,
                redirect_stdout(output),
            ):
                self.assertEqual(rebuild.main(), 0)
            report = json.loads(output.getvalue())
            self.assertTrue(report["valid"])
            self.assertEqual(run.call_count, 3)
            self.assertNotIn("tmforge", [step["step"] for step in report["steps"]])
            self.assertTrue((package / "data-flow.md").is_file())
            self.assertTrue((package / "threat-model.md").is_file())

    def test_empty_wrapper_is_rejected(self):
        script = (
            PLUGIN / "skills" / "threat-modeling" / "scripts" / "rebuild_package.py"
        )
        rebuild = load_script("plugin_rebuild_empty_wrapper_test", script)
        with tempfile.TemporaryDirectory() as directory:
            for invocation in ("", " ", "\t"):
                with (
                    self.subTest(invocation=invocation),
                    patch.object(
                        sys,
                        "argv",
                        [
                            str(script),
                            str(Path(directory).resolve()),
                            "--tmforge",
                            invocation,
                        ],
                    ),
                    redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        rebuild.main()
                    self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
