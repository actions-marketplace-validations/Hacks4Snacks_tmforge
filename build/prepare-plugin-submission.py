#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "Hacks4Snacks/tmforge"
PLUGIN_PATH = "plugins/tmforge"
# The external catalog permits at most ten tags. The plugin itself can retain more.
LISTING_KEYWORDS = [
    "data-flow-diagrams",
    "risk-assessment",
    "security-review",
    "stride",
    "strider",
    "threat-modeling",
    "threat-modeling-as-code",
    "tm7",
    "tmforge",
    "trust-boundaries",
]
REVIEW_NOTES = (
    "Agent Plugins 1.0 package with Strider and two skills. The workflow adds an "
    "evidence ledger, stable identities, complete STRIDE coverage checks, deterministic "
    "report rendering, and candidate validation for tmforge models. Python scripts use "
    "the standard library only. No hooks, bundled MCP servers, or embedded CLI binaries. "
    "A launcher downloads a version-pinned, checksum-verified CLI only after explicit "
    "user approval; normal use never downloads or changes global PATH. Markdown-only "
    "analysis requires no CLI download. The reviewed source is the nested plugin directory."
)
JsonObject = dict[str, object]


def object_from_json(text: str) -> JsonObject:
    value: object = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return cast(JsonObject, value)


def run_read(command: list[str], root: Path) -> str:
    result = subprocess.run(
        command, cwd=root, capture_output=True, text=True, timeout=60, check=False,
    )
    if result.returncode != 0:
        raise ValueError((result.stderr or result.stdout or "Read command failed").strip())
    return result.stdout


def github_read(resource: str, root: Path) -> JsonObject:
    # Every call is a GET. Do not add issue creation, release creation, or tag mutation here.
    return object_from_json(run_read(["gh", "api", resource], root))


def pinned_manifest(root: Path, tag: str) -> tuple[str, JsonObject]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", tag):
        raise ValueError("--tag must be an exact release tag such as v0.11.0, not a branch or floating tag")
    try:
        sha = run_read(["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], root).strip()
    except ValueError as exc:
        raise ValueError(f"Release tag {tag} is unavailable locally; fetch that published tag first") from exc
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Release tag did not resolve to a full 40-character commit SHA")
    try:
        text = run_read(["git", "show", f"{sha}:{PLUGIN_PATH}/plugin.json"], root)
    except ValueError as exc:
        raise ValueError(f"Release {tag} does not contain the plugin; publish a new release containing it") from exc
    return sha, object_from_json(text)


def build_entry(manifest: JsonObject, tag: str, sha: str) -> JsonObject:
    if manifest.get("$schema") != "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json":
        raise ValueError("Released plugin is not an Agent Plugins 1.0 manifest")
    if manifest.get("name") != "tmforge" or manifest.get("version") != tag[1:]:
        raise ValueError("Released plugin name/version does not match the selected tmforge release")
    if manifest.get("repository") != f"https://github.com/{REPOSITORY}":
        raise ValueError("Released plugin does not point to the expected public repository")
    fields = ("name", "description", "version", "author", "homepage", "repository", "license")
    if any(field not in manifest for field in fields):
        raise ValueError("Released manifest is missing intake metadata")
    author = manifest["author"]
    if not isinstance(author, dict) or not cast(JsonObject, author).get("name"):
        raise ValueError("Released manifest is missing author.name")
    keywords = manifest.get("keywords")
    if not isinstance(keywords, list) or not set(LISTING_KEYWORDS).issubset(cast(list[str], keywords)):
        raise ValueError("Review the listing keyword selection against the released manifest")
    entry = {field: manifest[field] for field in fields}
    entry["keywords"] = LISTING_KEYWORDS.copy()
    entry["source"] = {
        "source": "github", "repo": REPOSITORY, "path": PLUGIN_PATH,
        "ref": tag, "sha": sha,
    }
    return entry


def verify_published_release(release: JsonObject, tag: str) -> None:
    if release.get("tag_name") != tag or release.get("draft") is not False or not release.get("published_at"):
        raise ValueError("The selected release must be published, not a draft")
    if release.get("immutable") is not True:
        raise ValueError("The selected release must have immutable assets for the managed binary download")
    assets = release.get("assets")
    names: set[str] = set()
    if isinstance(assets, list):
        for value in cast(list[object], assets):
            if isinstance(value, dict):
                name = cast(JsonObject, value).get("name")
                if isinstance(name, str):
                    names.add(name)
    version = tag[1:]
    required = {"release-metadata.json", "checksums.txt"}
    for rid in ("linux-x64", "linux-arm64", "osx-x64", "osx-arm64", "win-x64", "win-arm64"):
        extension = "zip" if rid.startswith("win-") else "tar.gz"
        required.add(f"tmforge-{version}-{rid}.{extension}")
    if missing := required - names:
        raise ValueError("Release is missing managed-download assets: " + ", ".join(sorted(missing)))


def prepare(root: Path, tag: str) -> JsonObject:
    sha, manifest = pinned_manifest(root, tag)
    entry = build_entry(manifest, tag, sha)
    repo = github_read(f"repos/{REPOSITORY}", root)
    if repo.get("private") is not False:
        raise ValueError("Public intake requires a public GitHub repository")
    release = github_read(f"repos/{REPOSITORY}/releases/tags/{tag}", root)
    verify_published_release(release, tag)
    commit = github_read(f"repos/{REPOSITORY}/commits/{tag}", root)
    if commit.get("sha") != sha:
        raise ValueError("The public release tag and local tag resolve to different commits")
    return entry


def render_issue(entry: JsonObject) -> str:
    source = cast(JsonObject, entry["source"])
    author = cast(JsonObject, entry["author"])
    fields = [
        ("Plugin name", entry["name"]),
        ("Short description", entry["description"]),
        ("GitHub repository", source["repo"]),
        ("Plugin path inside the repository", source["path"]),
        ("Ref to review", source["ref"]),
        ("Commit SHA to review", source["sha"]),
        ("Version", entry["version"]),
        ("License identifier", entry["license"]),
        ("Author name", author["name"]),
        ("Author URL", author.get("url", "")),
        ("Homepage URL", entry["homepage"]),
        ("Keywords", ", ".join(cast(list[str], entry["keywords"]))),
        ("Additional notes for reviewers", REVIEW_NOTES),
    ]
    body = "<!-- external-plugin-submission -->\n\n"
    body += "\n\n".join(f"### {label}\n\n{value}" for label, value in fields)
    # These are human attestations. Never assert approval/rights on the submitter's behalf.
    body += (
        "\n\n### Submission checklist\n\n"
        "- [ ] The plugin lives in a public GitHub repository.\n"
        "- [ ] The ref and/or sha I provided is immutable (release tag and/or full 40-character commit SHA), not a branch.\n"
        "- [ ] This submission follows this repository's contribution, security, and responsible AI policies.\n"
        "- [ ] This plugin is not already listed in the Awesome Copilot marketplace.\n"
    )
    return body


def submission_files(entry: JsonObject) -> dict[str, str]:
    marketplace: JsonObject = {
        "name": "tmforge-review",
        "owner": {"name": "tmforge maintainers"},
        "metadata": {"description": "Local smoke test of the pinned Awesome Copilot submission."},
        "plugins": [entry],
    }
    return {
        "external-plugin.json": json.dumps(entry, indent=2) + "\n",
        "marketplace.json": json.dumps(marketplace, indent=2) + "\n",
        "issue.md": render_issue(entry),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Published exact release tag containing the plugin")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts" / "plugin-submission")
    args = parser.parse_args(argv)
    try:
        entry = prepare(ROOT, args.tag)
        output = args.output_dir.resolve()
        output.mkdir(parents=True, exist_ok=True)
        for name, text in submission_files(entry).items():
            (output / name).write_text(text, encoding="utf-8")
        source = cast(JsonObject, entry["source"])
        print(f"Prepared {source['ref']} at {source['sha']} in {output}")
        print("Review the issue draft and attestations. Nothing was published or submitted.")
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"Plugin submission not ready: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
