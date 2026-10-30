# Threat Model Forge (`tmforge`)

**The open, cross-platform successor to the Microsoft Threat Modeling Tool: threat modeling as
code, in your browser, your terminal, and your CI pipeline.**

![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)
![platforms: Linux · macOS · Windows](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-2b90d9)
![arch: x64 · arm64](https://img.shields.io/badge/arch-x64%20%C2%B7%20arm64-2b90d9)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE.md)

The Microsoft Threat Modeling Tool (MTMT) is Windows-only, GUI-only, and can't run in a pipeline.
Threat Model Forge keeps its file format, reading and writing `.tm7` files **byte-for-byte
unchanged for native no-op saves**, while preserving unrelated native content when editing. Author
models in browser or VS Code Studio or a headless CLI,
diff and merge them like source code, analyze them against **built-in security and hygiene
rules**, and gate a build on the result. No Windows, no GUI required.

**Try it now, no install:** the full editor and validation engine run client-side (WebAssembly) at
**[hacks4snacks.github.io/tmforge](https://hacks4snacks.github.io/tmforge/)**. Model processing stays
in your browser; saving, exporting, or sharing a model is an explicit action.

## Why tmforge

- **Keep native models native.** Open and edit `.tm7` without converting it to another format.
  No-op native saves retain the source bytes; edited saves preserve unrelated native content but
  may change XML formatting. [Fidelity and limits](docs/formats.md) are documented per format.
- **Threat modeling as code.** Models live in git like everything else: semantic `diff`, a
  three-way `merge` driver, declarative `apply`/`export` manifests, and `--json` output with a
  stable, versioned envelope on supported model commands for scripts, pipelines, and AI agents.
- **CI-grade validation.** Rule packs for core hygiene, STRIDE completeness, input validation,
  data protection, transport security, and identity & access, with SARIF + HTML reports and a
  distinct exit code for "found issues" you can gate a build on.
- **One engine across tools.** Browser **Studio**, **VS Code**, a scriptable **CLI** with MCP tools,
  and a versioned **HTTP API** share the same .NET engine.
- **Multi-format.** Import/export **draw.io** and **Visio** (`.vsdx`) alongside `.tm7` and a
  canonical JSON wire format; import bounded subsets of Threat Dragon, Mermaid, and Graphviz DOT.
- **Zero-runtime install.** Self-contained, single-file binaries for six platforms, or one
  container for the API + Studio.

## Try it

**In the browser (no install):** open
**[hacks4snacks.github.io/tmforge](https://hacks4snacks.github.io/tmforge/)** and start drawing.

**Self-hosted:** run the published engine API + Studio image (or
[build it yourself](#containers)):

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hacks4snacks/tmforge  # http://localhost:8080/
```

The API has no built-in authentication. Read the [security posture](docs/deployment.md#security-posture)
before exposing it to other users.

**In VS Code:** install **Threat Model Forge** (`hacks4snacks.tmforge`), or install the release VSIX,
then open a `.tm7` or `.tmforge.json` file. See the [extension guide](src/ThreatModelForge.Vscode/README.md).

**In the terminal:** with `tmforge` on your `PATH` (see [Install](#install)):

```bash
tmforge new payments.tm7 --name "Payments"
tmforge add process payments.tm7 --name "Checkout API"
tmforge add store payments.tm7 --name "Orders DB"
tmforge add boundary payments.tm7 --name "Azure VNet"
tmforge analyze payments.tm7 --max-severity warning  # exits 2 on warning/error findings
tmforge report payments.tm7 --out payments.html
```

New here? Start with the [Quick start](docs/quickstart.md). Coming from MTMT? Your `.tm7` files
open as-is; see [Formats & interoperability](docs/formats.md).

## What it does

- **Author & edit** data-flow diagrams in the browser (the React **Studio** SPA): add
  processes, external entities, data stores, and trust boundaries; draw data flows; resize and
  bend connectors; organize a model across multiple pages.
- **Author headlessly** from the CLI (`new`, `add`, `connect`, `set`, ...) or the API, so agents
  and pipelines build models with no GUI.
- **Preserve native `.tm7` data**, including templates and unaffected threat decisions during native editing.
- **Version like code**: semantic `diff`, three-way `merge`, and `git-setup` to wire both into
  your repo, plus declarative `apply`/`export` manifests for reproducible models.
- **Convert** between `.tm7`, `tmforge-json`, draw.io, and Visio.
- **Import Mermaid flowcharts and Graphviz DOT** as starter models with explicit mapping assumptions.
- **Import and export OWASP Threat Dragon v2 JSON** with stable imported identities and authored threats.
  The [bounded subset](docs/formats.md#threat-dragon-owasp-threat-dragon-v2) supports rectangular
  boundaries and directed flows; unsupported content is refused with a specific reason.
- **Report** to self-contained HTML (with inline SVG diagrams), or `render` the diagram right
  in your terminal.
- **Analyze in CI** with the `tmforge` CLI (`tmforge analyze`), gating builds on SARIF-reported
  findings.
- **Model with Copilot** using the [Strider plugin](plugins/tmforge/README.md): evidence-backed
  STRIDE analysis, deterministic reports, and optional `.tm7` authoring. Install through the
  [tmforge marketplace](plugins/tmforge/README.md#install-from-a-marketplace);
  Markdown-only analysis does not require the CLI.

## Documentation

Full user documentation lives in [`docs/`](docs/README.md):

- [Overview & features](docs/overview.md) · [Quick start](docs/quickstart.md) ·
  [Installation](docs/installation.md)
- [CLI reference](docs/cli-reference.md) · [Studio guide](docs/studio-guide.md) ·
  [Engine API reference](docs/api-reference.md)
- [Formats & interoperability](docs/formats.md) · [Analysis rules & CI](docs/analysis-rules.md) ·
  [Deployment](docs/deployment.md)

## Install

Prebuilt, **self-contained** `tmforge` binaries (no .NET runtime required on the host) are
attached to each GitHub Release for six platforms:

| OS      | x64                              | arm64                              |
|---------|----------------------------------|------------------------------------|
| Linux   | `tmforge-<ver>-linux-x64.tar.gz` | `tmforge-<ver>-linux-arm64.tar.gz` |
| macOS   | `tmforge-<ver>-osx-x64.tar.gz`   | `tmforge-<ver>-osx-arm64.tar.gz`   |
| Windows | `tmforge-<ver>-win-x64.zip`      | `tmforge-<ver>-win-arm64.zip`      |

```bash
# Linux example; select the version and RID for your platform.
base=https://github.com/hacks4snacks/tmforge/releases/download/v0.12.0
curl -fsSLO "$base/tmforge-0.12.0-linux-x64.tar.gz" &&
curl -fsSLO "$base/checksums.txt" &&
grep -F '  tmforge-0.12.0-linux-x64.tar.gz' checksums.txt | sha256sum -c - &&
tar -xzf tmforge-0.12.0-linux-x64.tar.gz &&
./tmforge-0.12.0-linux-x64/tmforge --version
```

Each release also ships `checksums.txt` (SHA-256) and `release-metadata.json`.
[Verify the downloaded archive before extracting or executing it](docs/installation.md#verify-the-download).

**Platform notes.** Linux binaries target a **glibc** baseline (not musl/Alpine). macOS binaries
are **not code-signed or notarized**. Follow the [platform notes](docs/installation.md#platform-notes)
if macOS blocks a verified download; changing Gatekeeper policy is not a prerequisite.

Prefer a runtime-present install? Use the [container image](#containers) or the RID-agnostic
global tool (`dotnet pack -p:PackTools=true`).

## Build & test

Requires the .NET SDK pinned in [`global.json`](global.json) and Node.js 22.12+ with npm for Studio.
Use `-p:BuildStudio=false` for a .NET-only build/test loop; that does not build the browser UI.

```bash
dotnet build dirs.proj
dotnet test  dirs.proj --no-build
```

The build system is MSBuild + `Microsoft.Build.Traversal`; central package versions live in
[`Directory.Packages.props`](Directory.Packages.props); shared build settings in
[`Directory.Build.props`](Directory.Build.props). Output goes to `out/<Config>-<Platform>/`.

## Containers

Pull the published multi-arch images from GitHub Container Registry:

```bash
# Engine API + Studio SPA (React): the /v1 API serves the SPA at /
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hacks4snacks/tmforge  # http://localhost:8080/

# CLI tool
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli analyze model.tm7
```

Published tags include `latest`, the release version (e.g. `0.12.0`), `0.12`, and `edge` (latest
`main`). Prefer to build locally?

```bash
docker build -f build/Dockerfile.api -t tmforge .        # API + Studio
docker build -f build/Dockerfile -t tmforge-cli .        # CLI
```

Both Dockerfiles build from the repo root and target the real `src/` layout.

## Repository layout

```text
docs/              Project documentation
build/             Dockerfile (CLI) + Dockerfile.api (engine API + Studio SPA)
src/               shared libraries, CLI/MCP, engine API, browser Studio, and VS Code extension
test/              one *.Tests project per shipping library
```

`ThreatModelForge.slnx` lists every project for IDE users; the build is driven by `dirs.proj`
(`Microsoft.Build.Traversal`), which fans out to `src/dirs.proj` and `test/dirs.proj`.

## Security

Report vulnerabilities privately using the [security policy](SECURITY.md). For shared hosting,
read the [API security posture](docs/deployment.md#security-posture).

## License

[MIT](LICENSE.md).
