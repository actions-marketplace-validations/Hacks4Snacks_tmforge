# Threat Model Forge Studio

The Threat Model Forge front end: a React + TypeScript single‑page app whose DFD canvas is
built on [React Flow](https://reactflow.dev) (`@xyflow/react`, MIT). The UI depends only on an
`IEngineClient` interface; the shared .NET engine sits behind HTTP, browser WASM, or the VS Code
extension's worker transport. Only the HTTP transport uses the generated OpenAPI client.

The .NET build produces the SPA and serves it from `ThreatModelForge.Api` (`wwwroot`), so
`dotnet build dirs.proj` builds the API **and** this UI into one hosted artifact.

## Run

Use Node.js 22.12+ and the pinned .NET SDK. Commands below run from this directory.

```bash
# 1. Dev server (hot reload): talks to the API on :5205 (start the API separately).
npm ci
npm run dev          # http://localhost:5199

# 2. Hosted: build, then run the API, which serves this SPA at its root.
dotnet run --project ../ThreatModelForge.Api -- --urls http://localhost:5205
```

For static WASM builds and transport selection, see [Deployment](../../docs/deployment.md#studio-static-demo-in-browser-engine-no-backend).
For the extension build, see [contributor instructions](../README.md#vs-code-extension-development).

## Regenerate the API client

After changing the `/v1` contract, refresh the typed client from the engine's OpenAPI doc:

```bash
npm run gen:api      # openapi-typescript ../ThreatModelForge.Api/openapi/v1.json -> src/dfd/engine/schema.d.ts
```

## What it exercises

- **Multi-pack stencil palette** over four DFD primitives: Process, Data Store, External Entity,
  and Trust Boundary.
- **Connectors**: drag from any port (hover a node) to any other; `ConnectionMode.Loose`
  lets a flow start/end on any side.
- **Editing feel**: double‑click a node or flow to rename; `Delete` removes selection;
  the Trust Boundary is a resizable region; pan / zoom / minimap / fit.
- **Analysis**: Analyze uses the selected HTTP/WASM engine and overlays findings on affected
  objects. Offline authoring remains available without a working engine, but is not full analysis.
  The schema-driven inspector edits the recorded properties; changing a property is not proof that
  a real control exists. See [history limits](../../docs/studio-guide.md#pages) for browser undo/redo.
- **Documents**: canonical JSON editing and native TM7 preservation, with explicit conversion review
  for other formats. The [Studio guide](../../docs/studio-guide.md) covers current UI workflows.

## Engine Integration

- [`src/dfd/engineClient.ts`](src/dfd/engineClient.ts): interface and exports for the HTTP, WASM,
  and offline clients. Browser startup prefers HTTP, then staged WASM, then offline authoring.
  A `VITE_DEMO=true` build skips HTTP probing; the extension supplies its engine through `EditorHost`.
- [`src/dfd/mapping.ts`](src/dfd/mapping.ts): maps React Flow nodes/edges to and from `tmforge-json`.

## Stack

Vite 8 + React 19 + TypeScript + `@xyflow/react` v12 (MIT). No UI kit; plain CSS.

## Ownership and Security

Foreign-format parsing, threat generation, and native-save validation live in the shared .NET engine.
Browser recovery and file operations belong to the client; VS Code owns them in extension mode.
The HTTP API has no built-in authentication or model store. See its
[security posture](../../docs/deployment.md#security-posture) before shared hosting.
