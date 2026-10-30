# Threat Model Forge documentation

Welcome to the user documentation for **Threat Model Forge** (`tmforge`), a cross-platform
toolkit for authoring, validating, and reporting on `.tm7`-compatible threat models: in the
browser, in VS Code, in the terminal, and in CI. It is an open, automatable successor to the Windows-only
Microsoft Threat Modeling Tool (MTMT).

## Start here

| If you want to | Read |
| --- | --- |
| Try it right now, no install (runs in your browser) | [Live demo](https://hacks4snacks.github.io/tmforge/) |
| Understand what the platform is and its features | [Overview & features](overview.md) |
| Get running in a few minutes | [Quick start](quickstart.md) |
| Install the CLI, container, or global tool | [Installation](installation.md) |

## Guides

| Guide | What it covers |
| --- | --- |
| [Overview & features](overview.md) | Concepts, CLI/MCP, browser Studio, API, VS Code, formats, and rules at a glance. |
| [Quick start](quickstart.md) | Author, analyze, and report on your first model. |
| [Installation](installation.md) | Prebuilt binaries, container images, the .NET global tool, and building from source. |
| [CLI reference](cli-reference.md) | Every `tmforge` command, its options, exit codes, and JSON output. |
| [Studio guide](studio-guide.md) | Browser-based diagram authoring with the React Studio SPA. |
| [VS Code extension](../src/ThreatModelForge.Vscode/README.md) | Studio editing for native TM7 and JSON models, local analysis, Problems diagnostics, and JSON schemas. |
| [Engine API reference](api-reference.md) | The versioned `/v1` HTTP surface and its endpoints. |
| [Formats & interoperability](formats.md) | Native saves, JSON/diagram conversions, bounded Threat Dragon import/export, and Mermaid/DOT import. |
| [Analysis rules & CI](analysis-rules.md) | The built-in rule set, rule packs, suppressions, and gating a build. |
| [Deployment](deployment.md) | API security posture, containers, static WASM, Kubernetes, and CI/CD. |

## The surfaces

Threat Model Forge shares its engine across command-line, browser, HTTP, and editor integrations.

- **CLI** (`tmforge`): headless, scriptable authoring, validation, reporting, and conversion.
- **Studio**: a React single-page app using an HTTP engine or running locally with browser WASM.
- **Engine API** (`/v1`): a versioned HTTP surface that hosts Studio and exposes the engine to
  any client.
- **VS Code extension**: Studio editing for `.tm7` and `.tmforge.json`, with local
  analysis integrated with VS Code's document and Problems workflows.

## Reference material

- Project [README](../README.md): build, test, and contribution entry point.
