# ThreatModelForge.Api

The Threat Model Forge **engine API host**. It exposes a small, versioned `/v1` HTTP surface
over the real .NET engine and serves the [Studio](../ThreatModelForge.Studio) single-page app
from `wwwroot`, so the API and UI ship as one hosted artifact.

Studio's HTTP transport uses this contract; browser and extension WASM transports call the same
engine locally. The HTTP client is generated from the checked-in OpenAPI copy at
[`openapi/v1.json`](openapi/v1.json).

**There is no built-in authentication, authorization, or model store.** Use a local listener or an
authenticated deployment boundary. Read the [security posture](../../docs/deployment.md#security-posture)
for data handling, resource limits, logging, and shared-host responsibilities.

## Contract

The [API reference](../../docs/api-reference.md#endpoints) owns the full endpoint catalog and request
contracts, including combined analysis, native saves, preflight, merge, comparison, layout, and
reports. Custom rule packs are trusted startup configuration, not uploaded request content.

Unknown `/v1` routes return API errors. Static assets are served normally; non-file browser routes
fall back to Studio's `index.html`.

## Run

```bash
dotnet run --project src/ThreatModelForge.Api -- --urls http://localhost:5205
```

The API allows CORS from `http://localhost:5199` in every environment, for the Vite dev server;
this is not access control. For the hosted experience,
`dotnet run` (or the container) serves the built SPA at the API root.

## Container

Run the published image, or build it from source (see `build/Dockerfile.api`).

```bash
# Published (pulls on first run)
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hacks4snacks/tmforge  # http://localhost:8080/

# From source
docker build -f build/Dockerfile.api -t tmforge .
docker run --rm -p 127.0.0.1:8080:8080 tmforge
```

## Regenerating the OpenAPI document

The document is produced by the ASP.NET Core OpenAPI integration and served at
`/openapi/v1.json`. Refresh the checked-in [`openapi/v1.json`](openapi/v1.json) after changing
the `/v1` contract so Studio's generated client stays in sync (Studio's `npm run gen:api`
reads that file).
