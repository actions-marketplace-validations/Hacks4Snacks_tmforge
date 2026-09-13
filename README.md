# Threat Model Forge (`tmforge`)

**The open, cross-platform successor to the Microsoft Threat Modeling Tool: threat modeling as
code, in your browser, your terminal, and your CI pipeline.**

![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)
![platforms: Linux · macOS · Windows](https://img.shields.io/badge/platforms-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-2b90d9)
![arch: x64 · arm64](https://img.shields.io/badge/arch-x64%20%C2%B7%20arm64-2b90d9)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE.md)

The Microsoft Threat Modeling Tool (MTMT) is Windows-only, GUI-only, and can't run in a pipeline.
Threat Model Forge keeps its file format, reading and writing `.tm7` files **byte-for-byte
losslessly**, and removes everything else: author models in a browser Studio or a headless CLI,
diff and merge them like source code, analyze them against **built-in security and hygiene
rules**, and gate a build on the result. No Windows, no GUI required.

**Try it now, no install:** the full editor and validation engine run client-side (WebAssembly) at
**[hacks4snacks.github.io/tmforge](https://hacks4snacks.github.io/tmforge/)**. Your model never
leaves the page.

## Why tmforge

- **Your existing models just work.** Lossless, byte-for-byte `.tm7` compatibility means models
  move between tmforge and MTMT with zero drift; migration is opening the file.
- **Threat modeling as code.** Models live in git like everything else: semantic `diff`, a
  three-way `merge` driver, declarative `apply`/`export` manifests, and `--json` output with a
  stable, versioned envelope on every command for scripts, pipelines, and AI agents.
- **CI-grade validation.** Rule packs for core hygiene, STRIDE completeness, input validation,
  data protection, transport security, and identity & access, with SARIF + HTML reports and a
  distinct exit code for "found issues" you can gate a build on.
- **Three ways to drive one engine.** A React browser **Studio**, a scriptable **CLI**, and a
  versioned **HTTP API**, all over the same canonical `.tm7`-shaped model.
- **Multi-format.** Import/export **draw.io** and **Visio** (`.vsdx`) alongside `.tm7` and a
  canonical JSON wire format.
- **Zero-runtime install.** Self-contained, single-file binaries for six platforms, or one
  container for the API + Studio.

## Try it

**In the browser (no install):** open
**[hacks4snacks.github.io/tmforge](https://hacks4snacks.github.io/tmforge/)** and start drawing.

**Self-hosted:** run the published engine API + Studio image (or
[build it yourself](#containers)):

```bash
docker run --rm -p 8080:8080 ghcr.io/hacks4snacks/tmforge     # then open http://localhost:8080/
```

**In the terminal:** with `tmforge` on your `PATH` (see [Install](#install)):

```bash
tmforge new payments.tm7 --name "Payments"
tmforge add process payments.tm7 --name "Checkout API"
tmforge add store payments.tm7 --name "Orders DB"
tmforge add boundary payments.tm7 --name "Azure VNet"
tmforge analyze payments.tm7                    # analyze: exits 2 on findings, CI-ready
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
- **Read & write `.tm7` losslessly**, byte-for-byte compatible with MTMT.
- **Version like code**: semantic `diff`, three-way `merge`, and `git-setup` to wire both into
  your repo, plus declarative `apply`/`export` manifests for reproducible models.
- **Convert** between `.tm7`, `tmforge-json`, draw.io, and Visio.
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
- [Formats & interoperability](docs/formats.md) · [Validation rules & CI](docs/validation-rules.md) ·
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
# Linux/macOS (adjust OWNER/REPO, version, and RID)
curl -fsSL -o tmforge.tar.gz \
  https://github.com/hacks4snacks/tmforge/releases/download/v0.1.0/tmforge-0.1.0-linux-x64.tar.gz
tar -xzf tmforge.tar.gz
./tmforge-0.1.0-linux-x64/tmforge --version
```

Each release also ships `checksums.txt` (SHA-256) and `release-metadata.json`; verify with
`sha256sum -c checksums.txt`.

**Platform notes.** Linux binaries target a **glibc** baseline (not musl/Alpine). macOS binaries
are **not code-signed or notarized**. Clear the quarantine attribute before first run:

```bash
xattr -d com.apple.quarantine ./tmforge
```

Prefer a runtime-present install? Use the [container image](#containers) or the RID-agnostic
global tool (`dotnet pack -p:PackTools=true`).

## Build & test

Requires the .NET SDK pinned in [`global.json`](global.json).

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
docker run --rm -p 8080:8080 ghcr.io/hacks4snacks/tmforge               # -> http://localhost:8080/

# CLI tool
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli tmforge analyze model.tm7
```

Published tags include `latest`, the release version (e.g. `0.1.0`), `0.1`, and `edge` (latest
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
src/               libraries, the `tmforge` CLI, the engine API, and the React Studio SPA
test/              one *.Tests project per shipping library
```

`ThreatModelForge.slnx` lists every project for IDE users; the build is driven by `dirs.proj`
(`Microsoft.Build.Traversal`), which fans out to `src/dirs.proj` and `test/dirs.proj`.

## License

[MIT](LICENSE.md).
