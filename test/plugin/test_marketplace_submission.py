"""Offline guards for preparing, but never publishing, a pinned external plugin submission."""

import copy
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_plugin_submission", ROOT / "build/prepare-plugin-submission.py")
assert SPEC is not None and SPEC.loader is not None
submission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(submission)


class MarketplaceSubmissionTests(unittest.TestCase):
    def setUp(self):
        self.tag = "v1.2.3"
        self.sha = "a" * 40
        self.manifest = json.loads((ROOT / "plugins/tmforge/plugin.json").read_text(encoding="utf-8"))
        self.manifest["version"] = self.tag[1:]
        names = ["release-metadata.json", "checksums.txt"]
        for rid in ("linux-x64", "linux-arm64", "osx-x64", "osx-arm64", "win-x64", "win-arm64"):
            extension = "zip" if rid.startswith("win-") else "tar.gz"
            names.append(f"tmforge-{self.tag[1:]}-{rid}.{extension}")
        self.release: dict[str, object] = {
            "tag_name": self.tag, "draft": False, "immutable": True,
            "published_at": "2026-09-04T00:00:00Z", "assets": [{"name": name} for name in names],
        }

    def test_rejects_branch_floating_and_unsafe_locators_before_any_command(self):
        for tag in ("main", "refs/heads/main", "v0.11", "latest", "--help", "../v1.2.3"):
            with self.subTest(tag=tag), patch.object(submission, "run_read") as command:
                with self.assertRaisesRegex(ValueError, "exact release tag"):
                    submission.pinned_manifest(ROOT, tag)
                command.assert_not_called()

    def test_reads_manifest_from_peeled_tag_commit_not_working_tree(self):
        with patch.object(submission, "run_read", side_effect=[self.sha, json.dumps(self.manifest)]) as command:
            sha, manifest = submission.pinned_manifest(ROOT, self.tag)
        self.assertEqual(sha, self.sha)
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(command.call_args_list[0].args[0],
                         ["git", "rev-parse", "--verify", f"refs/tags/{self.tag}^{{commit}}"])
        self.assertEqual(command.call_args_list[1].args[0],
                         ["git", "show", f"{self.sha}:plugins/tmforge/plugin.json"])

    def test_release_without_plugin_is_not_replaced_by_working_copy(self):
        with patch.object(submission, "run_read", side_effect=[self.sha, ValueError("missing plugin")]):
            with self.assertRaisesRegex(ValueError, "does not contain the plugin"):
                submission.pinned_manifest(ROOT, self.tag)

    def test_missing_tag_requires_fetch_not_branch_fallback(self):
        with patch.object(submission, "run_read", side_effect=ValueError("missing tag")):
            with self.assertRaisesRegex(ValueError, "fetch that published tag"):
                submission.pinned_manifest(ROOT, self.tag)

    def test_manifest_version_must_match_tag(self):
        self.manifest["version"] = "1.2.2"
        with self.assertRaisesRegex(ValueError, "name/version"):
            submission.build_entry(self.manifest, self.tag, self.sha)

    def test_listing_uses_ten_keywords_without_mutating_plugin(self):
        original = copy.deepcopy(self.manifest)
        entry = submission.build_entry(self.manifest, self.tag, self.sha)
        self.assertEqual(self.manifest, original)
        self.assertEqual(len(entry["keywords"]), 10)
        self.assertEqual(len(set(entry["keywords"])), 10)
        for keyword in entry["keywords"]:
            self.assertIn(keyword, original["keywords"])
            self.assertLessEqual(len(keyword), 30)
            self.assertRegex(keyword, r"^[a-z0-9-]+$")
        self.assertNotIn("$schema", entry)
        self.assertEqual(entry["source"], {
            "source": "github", "repo": "Hacks4Snacks/tmforge", "path": "plugins/tmforge",
            "ref": self.tag, "sha": self.sha,
        })

    def test_only_published_immutable_complete_releases_are_accepted(self):
        submission.verify_published_release(self.release, self.tag)
        changes: dict[str, object] = {"draft": True, "immutable": False, "published_at": None,
                          "tag_name": "v1.2.2", "assets": []}
        for name, value in changes.items():
            invalid = dict(self.release, **{name: value})
            with self.subTest(field=name), self.assertRaises(ValueError):
                submission.verify_published_release(invalid, self.tag)

    def test_public_and_local_tag_sha_must_agree(self):
        replies = [{"private": False}, self.release, {"sha": "b" * 40}]
        with patch.object(submission, "pinned_manifest", return_value=(self.sha, self.manifest)), \
             patch.object(submission, "github_read", side_effect=replies):
            with self.assertRaisesRegex(ValueError, "different commits"):
                submission.prepare(ROOT, self.tag)

    def test_private_repository_is_not_a_public_submission(self):
        with patch.object(submission, "pinned_manifest", return_value=(self.sha, self.manifest)), \
             patch.object(submission, "github_read", return_value={"private": True}):
            with self.assertRaisesRegex(ValueError, "public GitHub"):
                submission.prepare(ROOT, self.tag)

    def test_intake_outputs_share_pins_and_leave_attestations_to_human(self):
        with patch.object(submission, "pinned_manifest", return_value=(self.sha, self.manifest)), \
             patch.object(submission, "github_read", side_effect=[{"private": False}, self.release, {"sha": self.sha}]):
            entry = submission.prepare(ROOT, self.tag)
        files = submission.submission_files(entry)
        external = json.loads(files["external-plugin.json"])
        marketplace = json.loads(files["marketplace.json"])
        self.assertEqual(marketplace["plugins"], [external])
        self.assertEqual(marketplace["name"], "tmforge-review")
        body = files["issue.md"]
        self.assertIn("<!-- external-plugin-submission -->", body)
        self.assertIn(f"### Ref to review\n\n{self.tag}", body)
        self.assertIn(f"### Commit SHA to review\n\n{self.sha}", body)
        self.assertEqual(body.count("- [ ]"), 4)
        self.assertNotIn("- [x]", body)

    def test_failed_preflight_writes_no_draft_artifacts(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "submission"
            with patch.object(submission, "prepare", side_effect=ValueError("release not ready")), redirect_stderr(io.StringIO()):
                self.assertEqual(submission.main(["--tag", self.tag, "--output-dir", str(output)]), 1)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
