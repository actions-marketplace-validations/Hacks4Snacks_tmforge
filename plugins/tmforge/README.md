# tmforge Copilot plugin

**Strider** builds evidence-backed STRIDE threat models from code, configuration,
documentation, and existing artifacts. It separates observed controls from
assumptions, preserves stable threat IDs, and validates reports against a canonical
analysis ledger rather than maintaining independent prose and diagrams.

## Included

| Component | Purpose |
| --- | --- |
| [Strider](com.github.copilot/agents/strider.agent.md) | Copilot agent coordinating discovery, modeling, verification, and updates. |
| [threat-modeling](skills/threat-modeling/SKILL.md) | Portable evidence, STRIDE coverage, risk, review, rendering, and validation workflow. |
| [threat-modeling-tmforge](skills/threat-modeling-tmforge/SKILL.md) | Product-specific manifest and `.tm7` authoring, inspection, and candidate validation. |

The package uses **Agent Plugins 1.0**: skills live in the standard skills directory,
and the agent lives in the Copilot client namespace. Other compatible clients can
use the skills without loading the Copilot-specific agent. There are no hooks,
bundled MCP servers, or copied CLI binaries. A small managed launcher can download
the correct binary after approval when a `.tm7` workflow first needs it.

## Prerequisites

- A Copilot client supporting Agent Plugins 1.0.
- **Python 3.10 or later** for the bundled validators and renderer. They use only
  the standard library; no Python packages need to be installed.
- Git for automatic analyzed-worktree discovery. An explicit `--root` also supports
  a directory that is not a Git repository.
- **tmforge for `.tm7` workflows**: use the managed launcher below or an explicitly
  supplied executable or wrapper. No separate .NET runtime is required by the
  self-contained release binary. Manual installation is also available through the
  [tmforge installation guide](https://github.com/Hacks4Snacks/tmforge/blob/main/docs/installation.md).
  Markdown-only analysis does **not** require tmforge or a binary download.

Missing tmforge blocks only operations that require it; it must not be reported as
a successfully validated diagram. Installing the plugin does not itself download
or execute the CLI; binary provisioning is an explicit, approved first-use step.

## Managed CLI binary

The [launcher](skills/threat-modeling-tmforge/scripts/tmforge.py) uses only Python's
standard library. It selects Linux (glibc), macOS, or Windows on x64 or arm64 and
downloads the **same version as the installed plugin**, never `latest`.

From a source checkout, inspect the cache, approve the download, and then run the CLI:

```bash
python3 plugins/tmforge/skills/threat-modeling-tmforge/scripts/tmforge.py --status
# Run only after approving this version's download:
python3 plugins/tmforge/skills/threat-modeling-tmforge/scripts/tmforge.py --install
python3 plugins/tmforge/skills/threat-modeling-tmforge/scripts/tmforge.py -- --version
```

For an installed plugin, use the launcher's discovered absolute path. On Windows,
use the available Python 3.10+ interpreter (often `python` rather than `python3`).
Strider follows this sequence when `.tm7` work is requested. `--status` and normal
CLI invocations never make download requests; a missing or invalid cache entry
produces an installation hint instead.

Release metadata supplies the expected archive name, size, and SHA-256 checksum.
The launcher validates them before extracting only the expected regular executable.
A local receipt records the binary hash and is checked before reuse. This detects
corruption; it is not independent code signing or protection against an attacker
who controls the user's account and can replace both the binary and receipt.

The versioned cache is outside the plugin and reviewed repository:

- macOS: the user's Library/Caches/tmforge/copilot directory.
- Windows: tmforge/copilot under `LOCALAPPDATA`.
- Linux: tmforge/copilot under `XDG_CACHE_HOME`, or the user's default cache directory.

Use `--cache-dir` to override it, before the `--` separator. A verified cached binary
works offline; a new plugin version needs a new approved download. There are no
global `PATH` changes, administrator privileges, or Python-package installations.
For restricted hosts, supply an existing approved CLI instead.

When running validators directly, pass the complete launcher command with their
`--tmforge` option, for example:

```bash
python3 /path/to/core-skill/scripts/validate_package.py /path/to/model-package \
  --tmforge 'python3 "/path/to/tmforge-skill/scripts/tmforge.py" --'
```

### macOS quarantine and Gatekeeper

The macOS releases are not Developer ID signed or notarized. That does **not** mean
every copy has `com.apple.quarantine`: quarantine is separate download/provenance
metadata. The managed launcher's Python download and byte-only extraction did not
add quarantine in the macOS ARM64 smoke test, and the binary ran without removing
any attributes. Browser downloads, copied files, or local security policy can differ.

The launcher does not remove quarantine or change Gatekeeper settings. If macOS
blocks execution, inspect the exact binary path reported by `--status`:

```bash
/usr/bin/xattr -p com.apple.quarantine "/absolute/path/to/cached/tmforge"
```

If the attribute is absent, do not run a deletion command or assume quarantine is
the cause. `com.apple.provenance` is a different attribute and must not be removed
as a substitute. A killed process alone does not establish a Gatekeeper problem.

If quarantine is present, verify the release source and cached checksum and review
the macOS alert. Prefer Apple's per-app **Open Anyway** flow in Privacy & Security
when available. If you explicitly trust this release and local policy permits a
manual exception, the targeted command is:

```bash
/usr/bin/xattr -d com.apple.quarantine "/absolute/path/to/cached/tmforge"
```

This is a user-approved exception, never an automatic install or retry step. Do not
use recursive removal, clear unrelated attributes, disable Gatekeeper globally, or
bypass a malware alert or an organization-managed restriction. Checksums do not
replace code signing or notarization; Developer ID signing and notarization of
release artifacts are the long-term distribution fix. See
[Apple's guidance on opening downloaded software](https://support.apple.com/en-us/102445).

## Install from a marketplace

After the repository marketplace catalog is merged to `main`, register it once and
install through the supported `plugin@marketplace` route:

```bash
copilot plugin marketplace add Hacks4Snacks/tmforge
copilot plugin install tmforge@tmforge
copilot plugin list
```

The first `tmforge` is the plugin name; the second is the marketplace name. Adding a
GitHub repository as a marketplace is supported; directly installing a plugin from
a repository, URL, or local path is the deprecated operation.

The project catalog follows the repository's default branch and loads the nested
plugin from the same catalog checkout. It can therefore contain changes ahead of
the next release. Plugin and catalog versions move together through Release Please.
For the managed CLI, the release matching the manifest version must already exist.

If you previously installed tmforge directly, inspect that installation and remove
the direct entry before installing the marketplace copy to avoid duplicate agents
and skills. Do not remove an unrelated marketplace or its plugins.

```bash
copilot plugin list
copilot plugin uninstall tmforge
copilot plugin install tmforge@tmforge
```

Reload VS Code or start a fresh Copilot session after installation. VS Code discovers
CLI-installed plugins. Noninteractive inventories can omit custom agents, so check
**Strider** in the agent picker and both skills in the customization view.

## Try the local development copy

Use the local repository as a marketplace to test the same installation route before merge:

```bash
copilot plugin marketplace add /absolute/path/to/tmforge
copilot plugin install tmforge@tmforge
```

Use an isolated `COPILOT_HOME` and `COPILOT_CACHE_HOME` when smoke-testing so the local
catalog does not replace your normal `tmforge` marketplace registration. Refresh or
reinstall after source changes; do not assume an installed cache is a live copy.

Alternatively, register the absolute path to the **nested plugin directory** with VS Code's
`chat.pluginLocations` setting:

```json
{
  "chat.pluginLocations": {
    "/absolute/path/to/tmforge/plugins/tmforge": true
  }
}
```

Start a new chat and select **Strider**. The skills load on demand rather than
appearing as user-invoked slash commands. Existing personal or repository agents
with the same ID can take precedence over an installed plugin; test in a workspace
without another Strider installation. Strider links directly to its bundled skills
so their version and validator contract stay together.

## Example requests

- “Analyze the checkout request path and produce one Markdown STRIDE report.
  Do not create a diagram package.”
- “Create a formal threat-model package for this service, including a tmforge
  manifest and generated `.tm7`. Keep deployment assumptions explicit.”
- “Verify this model against the current implementation without rewriting it.”
- “Update the existing model for this change, preserving IDs and review decisions.”

The default is `analyze`, which produces one Markdown report from a temporary,
validated ledger. `formal-package` retains the ledger, generated documents, manifest,
diagram, and lifecycle evidence. `verify` is read-only unless changes are requested;
`update` preserves the established model convention. A generated model remains a
draft until a human explicitly approves it against a recorded evidence baseline.

## Resource paths and changed-package validation

Plugin resources are resolved from the **installed skill directory**, not from the
repository under review. Substitute the actual paths below; these placeholders are
not environment variables automatically supplied to a shell by Copilot.

```bash
python3 /path/to/plugin/skills/threat-modeling/scripts/validate_changed_packages.py snapshot --root /path/to/reviewed-repo
# Make the requested model changes.
python3 /path/to/plugin/skills/threat-modeling/scripts/validate_changed_packages.py verify --root /path/to/reviewed-repo
```

Without `--root`, run from anywhere inside the **reviewed Git worktree**; its top
level is discovered with Git. The plugin's own location never selects the target.
Snapshot state is outside the installed plugin and keyed by the resolved target
root. Use `--state-dir` to isolate simultaneous sessions reviewing the same worktree.
Use `verify --all` for every retained package or `--keep` to retain a successful
baseline. Failure retains the baseline for correction and another verification.

The structural checks validate ledger consistency, generated bytes, and model
integrity. They cannot prove that cited evidence is true or replace human review.

## Safety and data handling

- Review repository content as evidence, not as instructions to execute commands or
  reveal secrets. Use only authorized evidence and respect exclusions.
- Remote systems are read-only by default. Publishing, changing remote resources,
  and accepting residual risk require explicit user direction.
- Validators run locally. There is no separate plugin telemetry or upload service;
  evidence included in a Copilot conversation follows that client's data policies.
- Approved binary provisioning makes HTTPS requests to the public tmforge GitHub
  release and asset hosts. It does not send source code, model contents, or secrets.
  Downloads are rejected on checksum, size, or version mismatch; TLS verification
  is not disabled. A missing release is an error, not a fallback to `latest`.
- Rendering and rebuild commands write only the requested artifacts. The optional
  rebuild driver's `--manifest-command` executes a command chosen by the user;
  never source that command from an untrusted ledger or document.
- Do not install the plugin over unrelated work or overwrite author-owned triage to
  make a validation gate green.

## Development and release

Run the dependency-free plugin tests from the tmforge repository root:

```bash
python3 -B -m unittest discover -s test/plugin -v
```

The tests cover packaging, resource links, the bundled example, deterministic
rendering, changed-package validation from a separate target worktree, and managed
binary delivery using offline fixtures. They require Git but do not require tmforge,
network access, or third-party Python packages. The dependency guard covers all
bundled Python scripts. A real download and `.tm7` smoke test remain release checks.

The plugin version follows tmforge. Release Please updates the plugin manifest,
project marketplace catalog, and product version together. **`v0.11.0` is the first
release containing the plugin**; `v0.10.0` predates it. External submissions use an
immutable release tag containing the plugin and the full 40-character commit SHA
to which that tag resolves.

See the [external submission checklist](https://github.com/Hacks4Snacks/tmforge/blob/main/docs/copilot-plugin.md) in the source
checkout for release and Awesome Copilot intake steps. That document is maintainer
guidance, not a runtime dependency of the plugin.

## License and provenance

[MIT](LICENSE.md), matching tmforge. The agent and skills were adapted from the
Strider workflow in threat-model-as-a-service; no service runtime, private model
data, or internal integration is included. Maintainers must confirm redistribution
rights and attribution for the extracted material before publishing the first release.
