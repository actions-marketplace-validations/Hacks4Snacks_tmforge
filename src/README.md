# `src/`: Threat Model Forge projects

This directory holds the shipping libraries, the `tmforge` CLI, the engine API, and the
Studio front end, plus the VS Code extension. The .NET build is driven by [`dirs.proj`](dirs.proj)
(`Microsoft.Build.Traversal`); every project is also listed in
[`ThreatModelForge.slnx`](../ThreatModelForge.slnx) for IDE users.

The canonical in-memory model is the `.tm7`-shaped object graph in `ThreatModelForge.Core`.
Everything else layers on top of it: formats read/write it, analysis inspects it, reporting
renders it, editing mutates it, and the CLI and API expose it.

## Libraries

| Project | Role |
| --- | --- |
| [`ThreatModelForge.Core`](ThreatModelForge.Core) | The `ThreatModel` object graph and native `.tm7`/`.tb7` serialization (`DataContractSerializer`), knowledge-base types, and shared serialization abstractions. See [fidelity guarantees](../docs/formats.md#fidelity). |
| [`ThreatModelForge.Formats`](ThreatModelForge.Formats) | Pluggable readers/writers for native, canonical JSON, draw.io, Visio, and bounded Threat Dragon v2; import-only Mermaid and DOT. |
| [`ThreatModelForge.Analysis`](ThreatModelForge.Analysis) | The analysis object model: the base rule types that rule sets derive from, plus the machinery `tmforge analyze` uses to evaluate a model. |
| [`ThreatModelForge.Analysis.Rules`](ThreatModelForge.Analysis.Rules) | The built-in rule set: completeness/hygiene checks and security-property checks. |
| [`ThreatModelForge.Analysis.Reporting`](ThreatModelForge.Analysis.Reporting) | Report writers for analysis *findings*: SARIF (for CI/code-scanning) and self-contained HTML. |
| [`ThreatModelForge.Reporting`](ThreatModelForge.Reporting) | Renders the threat *model itself* to a self-contained HTML report with inline SVG diagrams (no native graphics libraries). |
| [`ThreatModelForge.Editing`](ThreatModelForge.Editing) | UI-agnostic editing operations (add/move/rename/delete, connectors, layout) with snapshot undo/redo, so a web UI, the CLI, or tests can drive edits identically. |
| [`ThreatModelForge.Engine`](ThreatModelForge.Engine) | Shared model/analysis facade, canonical DTOs, preserving native saves, comparison, and layout validation. |

## Applications

| Project | Role |
| --- | --- |
| [`ThreatModelForge.Cli`](ThreatModelForge.Cli) | The `tmforge` command-line tool: inspect, author, lint, report, and convert threat models, with `--json` for machine-readable output. |
| [`ThreatModelForge.Api`](ThreatModelForge.Api) | The engine API host: a versioned `/v1` HTTP surface over the engine, and the host that serves the Studio SPA from `wwwroot`. |
| [`ThreatModelForge.Studio`](ThreatModelForge.Studio) | React + TypeScript/React Flow editor over `IEngineClient`, with HTTP, browser WASM, and VS Code worker transports. |
| [`ThreatModelForge.Wasm`](ThreatModelForge.Wasm) | Opt-in browser/worker build exposing the same .NET engine without a server. |
| [`ThreatModelForge.Vscode`](ThreatModelForge.Vscode) | The desktop VS Code extension: Studio editing for native TM7 and canonical JSON, open/save findings, and JSON schema hints, using a bundled WebAssembly engine. |

## Tests

Tests live in [`../test`](../test), one `*.Tests` project per shipping library and
application. Build and run the .NET suite from the repo root (Node.js 22.12+ is also required for
the default Studio build):

```bash
dotnet build dirs.proj
dotnet test  dirs.proj --no-build
```

Studio has a separate `npm test` suite; WASM and extension builds are opt-in and covered separately
in CI. `-p:BuildStudio=false` skips the SPA build for a .NET-only loop.

## VS Code Extension Development

The extension's [README](ThreatModelForge.Vscode/README.md) covers installation and usage.
Contributors need Node.js 22.12+, the repository's .NET SDK, and `wasm-tools` / `wasm-experimental`.
From the repository root:

```bash
dotnet publish src/ThreatModelForge.Wasm/ThreatModelForge.Wasm.csproj -c Release -o artifacts/vscode-wasm
npm --prefix src/ThreatModelForge.Studio ci
npm --prefix src/ThreatModelForge.Vscode ci
node src/ThreatModelForge.Vscode/scripts/stage-engine.mjs
npm --prefix src/ThreatModelForge.Vscode test
npm --prefix src/ThreatModelForge.Vscode run test:extension
npm --prefix src/ThreatModelForge.Vscode run package
```

`stage-engine.mjs` optionally accepts the path to an already-published `_framework` directory.
Generated runtime assets and VSIX files are ignored by Git. Packaging refuses to proceed if required
runtime assets or schemas are missing. Tests use an isolated VS Code profile; set
`VSCODE_EXECUTABLE_PATH` to reuse a specific installation, otherwise the test runner can download
VS Code. `VSCODE_TEST_VERSION` selects a version when no executable override is supplied. On Linux,
run extension-host tests under `xvfb-run -a` when no display is available.

CI builds a VSIX artifact; Marketplace publication is a separate, deliberate release step.

Packaging generates the extension changelog from root release notes filtered by the referenced
commits' changed files. It requires full Git history (`git fetch --unshallow` for a shallow clone);
missing history or a version mismatch fails packaging. Extension, Studio, and shared-engine changes
are included, while plugin-only, CLI-only, API-only, and docs-only changes are excluded.

Packaging builds the shared Studio UI through `npm run build:extension` into the extension's ignored
`media/studio/` directory. `EditorHost` supplies the document, engine, and host actions; the standalone
browser path remains unchanged. `WasmEngineClient` shares result decoding across local and asynchronous
worker transports.

Both formats use `CustomTextEditorProvider`: versioned canvas deltas become `WorkspaceEdit`s,
preserving unrepresented JSON fields or patching native XML through `SaveTm7`. The current text
document is the native baseline for each edit, including after undo or external changes; native
state does not depend on a webview-only copy. VS Code owns save, dirty state, undo/redo, and recovery.
Each open Studio document has an isolated engine/rule session shared by its views. The webview loads
only packaged assets; CSP blocks network access and arbitrary scripts. Inline styles are needed by
React Flow. File reads/writes use VS Code dialogs and workspace APIs, not arbitrary webview paths.

Native `.tm7` opens directly in Studio without conversion. The canvas uses the engine projection,
while saves retain the native source. Hidden line boundaries are reported as a persistent warning.
Native export reads the current document after queued edits; other formats use explicit conversion
review. Exports never overwrite the currently edited document. Read-only preview registrations,
commands, and assets have been removed.

Inspection limits are 8 MiB input, 32 pages, 1,024 elements, 2,048 lines, one million element/line pairs,
16 MiB results, and 30 seconds per queued inspection. A timeout stops the worker; retry restarts it.
Native WebAssembly memory is not covered by Node's JavaScript heap limit.

### Copilot Integration

The extension owns a [tmforge-vscode skill](ThreatModelForge.Vscode/copilot/skills/tmforge-vscode/SKILL.md),
contributed directly through `chatSkills` with `user-invocable: true`. Copilot's normal agent can load it
on demand or through `/tmforge-vscode`; no custom agent is bundled. Keep it independent of
`plugins/tmforge`: Strider's CLI workflow must not acquire editor-specific branches or dependencies.
No resources are copied into the user's workspace or profile, and the CLI plugin is not bundled in the VSIX.

Four `languageModelTools` use the existing worker and document lifecycle: catalog, create, inspect,
and update. Catalogs come from the bundled engine/schema; creation preflights and applies a manifest
before opening a separate draft. Inspection uses current open-document text. Updates require an
opaque version/content token and pass through Studio's queued, validating `WorkspaceEdit` path.
Cancellation is checked before mutation. Tool inputs are capped at 8 MiB and chat results at 1 MiB.
No Copilot extension dependency, proposed API, model request, shell command, or new runtime dependency
is needed. `tmforge.copilot.enabled` controls contributions and is also checked at invocation.
The skill's instruction to use tmforge tools is behavioral guidance, not a tool allowlist. The current
agent retains its other tools; only tmforge tool calls receive these validation and revision checks.

The supported host minimum is 1.138.0. A 1.109.5 trial exposed untitled custom-editor dirty/render
failures even though its contribution APIs exist; do not lower the minimum based on API availability
alone. The release matrix reads the declared minimum from the manifest.

The existing extension-host suite invokes the actual registered tools in an isolated profile, without
a signed-in Copilot session or CLI plugin. Set `TMFORGE_TEST_COPILOT=1` for the focused tool checks.
This verifies deterministic tool behavior, not an LLM's adherence or discovery in a signed-in chat.
Before publishing, also verify the `/tmforge-vscode` entry, automatic skill loading, confirmation UI,
and a synthetic create/inspect/update conversation in a clean Copilot-enabled profile. Do not use
confidential input.
