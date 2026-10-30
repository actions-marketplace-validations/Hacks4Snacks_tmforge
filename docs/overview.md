# Overview & features

Threat Model Forge (`tmforge`) is a toolkit for **authoring, validating, and reporting on
threat models** across platforms. It reads and writes Microsoft Threat Modeling Tool `.tm7`
files natively, adds browser and VS Code authoring plus a headless CLI, and analyzes models
against a built-in rule set you can gate a CI build on.

## Why Threat Model Forge

The Microsoft Threat Modeling Tool (MTMT) is Windows-only and GUI-only. Threat Model Forge keeps
its file format and fidelity while removing those constraints:

- **Cross-platform.** Self-contained CLI binaries for Linux, macOS, and Windows (x64 and arm64),
  plus Linux amd64/arm64 container images. No Windows dependency for model processing.
- **Automatable.** A headless CLI and an HTTP API let agents and CI pipelines author and validate
  models without a GUI ("threat-model-as-code").
- **Native `.tm7` preservation.** Unchanged native saves retain the original bytes. Native edits
  preserve unrelated XML, template data, and threat decisions; XML formatting may change.
- **Pluggable formats.** Beyond `.tm7`, import/export draw.io and Visio for interoperability, plus
  a canonical JSON wire format.
- **Git-native.** Semantic `diff` and three-way `merge` treat `.tm7` files like source code, so
  threat models live in the same repo and review workflow as the systems they describe.
- **CI-grade validation.** A built-in rule set flags completeness and security-hygiene issues, with
  SARIF and HTML reports and meaningful exit codes.

## The interfaces

Everything runs on one .NET engine over a single canonical, `.tm7`-shaped in-memory model.

### 1. CLI (`tmforge`)

The headless, scriptable face. Inspect, author, validate, report on, and convert models from a
shell or CI pipeline. Model commands offer `--json` output and documented exit codes so agents and
pipelines can drive them deterministically; MCP uses JSON-RPC rather than the CLI envelope. See the
[CLI reference](cli-reference.md).

### 2. Studio (browser authoring)

A React single-page app whose data-flow-diagram canvas is built on React Flow. Drag stencils onto
a canvas, draw data flows, rename and resize elements, and validate against the live engine with
findings overlaid on the offending nodes and edges. Try it now with no install at the
**[hosted demo](https://hacks4snacks.github.io/tmforge/)** (the engine runs in your browser via
WebAssembly), or read the [Studio guide](studio-guide.md).

### 3. Engine API (`/v1`)

A small, versioned HTTP surface over the engine that also serves Studio from its root, so the API
and UI ship as one hosted artifact. It has no built-in authentication or model persistence; shared
deployments require an operator-provided access boundary. See the [API reference](api-reference.md)
and [security posture](deployment.md#security-posture).

### 4. VS Code extension

The same Studio editor opens `.tm7` and `.tmforge.json` in VS Code. A bundled WASM engine handles
local processing; VS Code owns saves, undo/redo, and source synchronization. Findings appear in
Problems, and manifests/rule packs/suppressions have JSON editing hints. See the
[extension guide](../src/ThreatModelForge.Vscode/README.md).

The CLI also exposes the engine over MCP for agents. The [Copilot plugin](../plugins/tmforge/README.md)
provides an evidence-backed threat-modeling workflow; it is separate from the VS Code extension.

## Core concepts

A threat model in Threat Model Forge is a **data-flow diagram (DFD)** made of a few primitives:

| Primitive | DFD meaning | Example |
| --- | --- | --- |
| **Process** | Code that transforms or acts on data | An API, a service, a function |
| **Data store** | Where data rests | A database, a queue, a bucket, a cache |
| **External entity** | An actor or system outside your control | A user, a browser, a third-party API |
| **Trust boundary** | A region where the trust level changes | A VNet, a DMZ, a subnet, a process boundary |
| **Data flow** | A directed connection carrying data | An HTTPS request, a SQL query |

Elements and flows carry **custom properties** (for example `Protocol`, `Port`, `DataType`,
`AuthenticationScheme`) that the validation rules inspect. Properties round-trip through `.tm7`, so
what you set in Studio, the CLI, or MTMT stays consistent.

## Features at a glance

### Authoring

- **Visual authoring** (Studio): a multi-pack stencil palette, drag-to-connect data flows,
  double-click rename, resizable elements and trust boundaries, pan/zoom/minimap/fit, undo/redo,
  multi-selection, and an inspector for element and flow properties.
- **Headless authoring** (CLI): `new`, `add`, `connect`, `remove`, `rename`, and `set` verbs
  mutate models in place with atomic writes and deterministic auto-layout. No GUI or server
  required.
- **Stencils.** Type elements from a built-in stencil catalog (`tmforge stencils`,
  `add --stencil <id>`) so authored models carry real stencil metadata.

### Inspection

- **Summaries and listings** (`open`, `list`): counts and enumerations of components, flows,
  boundaries, threats, and diagrams.
- **Element and schema discovery** (`show`, `stencils`, `properties`): inspect a single
  element/flow's properties, and list the stencil catalog and the typed property schema the rules
  read.
- **Terminal rendering** (`render`): draw the diagram directly in your terminal (Unicode/ANSI, or
  `--plain` ASCII).

### Versioning & collaboration

- **Semantic diff** (`diff`): compare models by stable element ID, ignoring geometry noise, with
  a `--textconv` mode for readable `git diff` output on `.tm7` files.
- **Three-way merge** (`merge`): a git merge driver that resolves concurrent edits semantically
  and emits a conflicts sidecar when it can't.
- **One-command git integration** (`git-setup`): wire the diff and merge drivers into a repo
  locally or globally.
- **Model-as-code manifests** (`apply`, `export`): build or capture a whole model from a
  declarative JSON manifest, atomically and idempotently.
- **Studio comparison**: review structural and findings changes without changing either model.
- **Browser sharing**: explicitly create a URL containing a compressed canonical snapshot; the
  fragment is not sent to the static host but is visible to anyone with the link.

### Validation

- **A built-in rule set** organized into rule packs (Core Hygiene, STRIDE Completeness,
  Input Validation, Data Protection, Transport Security, and Identity & Access), covering
  connectivity, naming, trust-boundary modeling, and declared security properties.
- **CI integration**: SARIF + HTML findings reports, suppression files, rule-set overrides, and
  a distinct exit code for "found issues" vs. "tool error." See
  [Analysis rules & CI](analysis-rules.md).

### Reporting

- **Self-contained HTML reports** (`report`) with inline SVG diagrams. A single file you can
  attach to a review or a pull request.

### Interoperability

- **Read/write formats**: `.tm7`, `tmforge-json`, `.drawio` (draw.io / diagrams.net), and `.vsdx`
  (Microsoft Visio). **Import only**: supported Threat Dragon v2 JSON, Mermaid, and Graphviz DOT
  subsets. Structural conversions are not lossless native round-trips. See [Formats](formats.md).

## Next steps

- [Quick start](quickstart.md): build your first model end to end.
- [Installation](installation.md): get the tools onto your machine or into CI.
