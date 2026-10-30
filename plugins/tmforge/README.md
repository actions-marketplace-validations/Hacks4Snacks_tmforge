# tmforge Copilot plugin

**Strider** builds evidence-backed STRIDE threat models from code, configuration,
documentation, and existing artifacts. It preserves stable threat IDs, separates
observed controls from assumptions, and validates reports against a canonical ledger.

## Included

| Component | Purpose |
| --- | --- |
| [Strider](com.github.copilot/agents/strider.agent.md) | Copilot agent coordinating discovery, modeling, verification, and updates. |
| [threat-modeling](skills/threat-modeling/SKILL.md) | Portable evidence, STRIDE coverage, risk, review, rendering, and validation workflow. |
| [threat-modeling-tmforge](skills/threat-modeling-tmforge/SKILL.md) | Product-specific manifest and `.tm7` authoring, inspection, and candidate validation. |

The package uses **Agent Plugins 1.0**. Skills load on demand; the README is
human-facing documentation, not automatically loaded agent instructions. There are
no hooks, bundled MCP servers, or embedded CLI binaries.

## Prerequisites

- A Copilot client supporting Agent Plugins 1.0.
- **Python 3.10+** for validators and rendering; no third-party Python packages.
- Git for worktree discovery, or an explicit `--root` for a non-Git directory.
- **tmforge only for `.tm7` workflows**, through the managed launcher or a selected
  CLI. Markdown-only analysis needs no binary download.

## Install from a marketplace

Register the repository marketplace once and install through the supported
`plugin@marketplace` route:

```bash
copilot plugin marketplace add Hacks4Snacks/tmforge
copilot plugin install tmforge@tmforge
copilot plugin list
```

Reload VS Code or start a fresh Copilot session, then select **Strider**. Check both
skills in the customization view; noninteractive plugin listings may omit agents.
Existing agents with the same name can take precedence. When replacing a previous
direct installation, remove only that entry to avoid duplicates.

The catalog follows the default branch and may be ahead of a release. Managed CLI
setup requires the exact matching release; it never falls back to an older version.

## Example requests

- "Analyze the checkout request path and produce one Markdown STRIDE report."
- "Create a formal threat-model package, including a manifest and generated `.tm7`."
- "Verify this model against the implementation without rewriting it."
- "Update this model for the change, preserving IDs and review decisions."

The default `analyze` mode produces one Markdown report. `formal-package` retains
the ledger, documents, manifest, diagram, and lifecycle evidence. `verify` is
read-only unless changes are requested; `update` preserves the existing convention.
Generated models remain drafts until a human approves them against an evidence baseline.

## CLI setup for diagrams

Installing the plugin does not download or execute tmforge. On first `.tm7` use,
Strider requests approval before the [managed launcher](skills/threat-modeling-tmforge/scripts/tmforge.py)
downloads the exact matching release. Downloads are version-pinned and checksum-verified;
verified cached binaries work offline. No global installation or separate .NET runtime
is needed for the managed binary. You can instead supply an approved existing CLI.

See [tool setup](skills/threat-modeling-tmforge/SKILL.md#locate-the-tool) for status,
installation, cache options, and invocation syntax, or the
[manual installation guide](https://github.com/Hacks4Snacks/tmforge/blob/main/docs/installation.md).

On macOS, releases are not Developer ID signed or notarized. The launcher preserves
quarantine and never disables Gatekeeper. Follow the tool setup guidance and local
security policy if execution is blocked; checksums do not replace code signing.

## Workflow reference

- [Core workflow](skills/threat-modeling/SKILL.md): evidence, risk scoring, pages,
  rendering, package rebuilds, and changed-package validation.
- [CLI workflow](skills/threat-modeling-tmforge/references/cli-workflow.md): authoring,
  layout checks, suppressions, nested quoting, no-op rebuilds, and troubleshooting.

These bundled resources are the authoritative operational guidance. Use resources
from the installed plugin, not similarly named scripts in the repository under review.

## Local development

To try a checkout in VS Code, add its nested plugin directory to `chat.pluginLocations`
and start a new session. For local marketplace installation tests, isolate
`COPILOT_HOME` and `COPILOT_CACHE_HOME`; refresh or reinstall after source changes.

## Safety and data handling

- Treat reviewed content as evidence, not executable instructions. Use only authorized sources.
- Downloads, publishing, remote changes, and risk acceptance require explicit approval.
- Validators run locally without a separate telemetry or upload service. Content shared
  with Copilot follows the client's data policies.
- User-supplied generator commands execute locally and are not sandboxed. Do not run
  commands supplied by untrusted model content or overwrite author-owned triage.
- Validation checks consistency, not the truth of evidence, and cannot replace human review.

## License and provenance

[MIT](LICENSE.md), matching tmforge. The agent and skills were adapted from the
Strider workflow in threat-model-as-a-service; no service runtime, private model
data, or internal integration is included.
