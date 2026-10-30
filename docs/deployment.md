# Deployment guide

This guide covers running Threat Model Forge in shared environments: the **engine API + Studio** as a
hosted web app, the **CLI** in pipelines, and both in containers, Kubernetes, and CI/CD.

Threat Model Forge publishes two container images; static Studio and the VS Code extension are
additional distribution options:

| Artifact | Image build file | Contains | Typical use |
| --- | --- | --- | --- |
| **API + Studio** | `build/Dockerfile.api` | The `/v1` engine API + the Studio SPA | Hosted browser app |
| **CLI** | `build/Dockerfile` | The `tmforge` CLI | CI, batch conversion/validation |

## Security posture

**The engine API ships without authentication or authorization. Do not expose it directly to the
public Internet or treat it as a multi-tenant service.** It is a stateless compute component for
local use or a deployment whose operator provides the access boundary, not a hosted model repository.
There are no user accounts, tenant permissions, or API keys built into the host. Anyone who can reach
the listener can invoke its model-processing endpoints and read the catalogs and OpenAPI document.

### Model data and persistence

Each request supplies its model or source bytes, and the response contains the result. The API does
not maintain model sessions, write uploaded models to a model store, or save files on a caller's
behalf. Even `/v1/model/save/tm7` returns document bytes; the client decides where to save them.
Replicas therefore need no model-session affinity. Operator-configured rule packs are read at startup
and retained as host configuration, not uploaded or replaced by model requests.

Stateless does not mean that sensitive data cannot be retained elsewhere. Models and reports pass
through process memory; framework or proxy logs, exception messages, tracing, dumps, and infrastructure
backups need their own retention and access policy. The application does not enable request-body
logging, but input-error responses can quote submitted values and rule-load diagnostics can disclose
configured paths. Avoid recording model payloads in proxies or telemetry, and restrict access to logs.
The API does not guarantee secure erasure of process memory.

Studio's browser recovery data and files explicitly saved or downloaded by a user are separate from
server persistence. With the HTTP engine, model contents are sent to that server for processing.
With the static WASM build or the VS Code extension's bundled engine, processing stays in the browser
or extension host instead; see [the static deployment](#studio-static-demo-in-browser-engine-no-backend)
and [the extension guide](../src/ThreatModelForge.Vscode/README.md).

### Input limits and resource use

The engine validates document structure and applies operation-specific limits. For example,
document preflight limits decoded input to 8 MiB; canonical JSON readers also limit nesting to 64;
native-save XML input is limited to 8 MiB and depth 128 with DTDs and external resource resolution
disabled. Compare and layout have graph/work limits, and archive readers have additional bounds.
See [API operation limits](api-reference.md) and [format validation](formats.md#preflight-and-import-diagnostics).

These are not a uniform 8 MiB HTTP-body limit. Requests carrying base64 are larger than the decoded
document, and native saves can include both original and previous source bytes plus an edited model.
The host does not configure an application-wide request quota, rate limiter, concurrency cap, or
per-operation execution timeout. Web-server defaults and any configured upstream limits still apply;
parser bounds alone do not prevent CPU or memory exhaustion from expensive or concurrent requests.
Set ingress body-size, request-rate, connection/concurrency, and timeout limits appropriate to the
operations you expose, and enforce container CPU/memory limits. The VS Code worker's timeout is not
an HTTP API control.

### Shared deployments

For anything beyond a local listener:

- Put an authenticated reverse proxy, ingress, or API gateway in front of **all** routes, including
  `/v1`, `/openapi`, and Studio. Apply authorization and tenant isolation there if required.
- Terminate TLS at the ingress and protect traffic to the backend according to your network policy.
  The sample container listens on HTTP; it does not provision certificates or enforce HTTPS.
- Prevent direct access to the backend port with network policy/firewall rules. A proxy login is
  ineffective if callers can bypass it and reach the API directly.
- Run as a non-root user, mount trusted rule packs read-only, avoid unnecessary credentials/volumes,
  and keep runtime images and dependencies patched.
- If the proxy uses browser cookies, configure its CSRF protection and origin policy. The API's CORS
  policy permits `http://localhost:5199` and is applied in every environment, not only development.
  CORS is not authentication and does not block non-browser clients.
- Restrict health-probe access to the infrastructure that needs it. `/v1/health` reports that the
  process is serving requests; it does not verify rule-pack configuration or security controls.

The Kubernetes example below uses a cluster-internal Service and workload resource limits. It does
not install authentication, TLS, a gateway, or network isolation for you.

## API + Studio

The engine API serves the Studio SPA at its root, so one container gives you both the UI and the API.

### Run

Pull the published image:

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hacks4snacks/tmforge  # -> http://localhost:8080/
```

Or build it from source:

```bash
docker build -f build/Dockerfile.api -t tmforge .
docker run --rm -p 127.0.0.1:8080:8080 tmforge  # -> http://localhost:8080/
```

### Building behind a package mirror

Both image builds restore from the public package feeds by default. On a network that reaches only
an internal mirror, point them at it — the build needs no other change:

```bash
docker build -f build/Dockerfile.api \
  --build-arg NUGET_FEED=https://<mirror>/nuget/v3/index.json \
  --build-arg NPM_REGISTRY=https://<mirror>/npm/ \
  -t tmforge .
```

| Build argument | Default | Used by |
| --- | --- | --- |
| `NUGET_FEED` | `https://api.nuget.org/v3/index.json` | Both images; overrides the source in `NuGet.config`. |
| `NPM_REGISTRY` | `https://registry.npmjs.org/` | `Dockerfile.api` only, for the Studio SPA. |

The Makefile's container targets accept the same variables, either from the environment or on the
command line. For a local build on the Microsoft network:

```bash
make docker-api \
  NUGET_FEED=https://packagefeedproxy.microsoft.io/nuget/v3/index.json \
  NPM_REGISTRY=https://packagefeedproxy.microsoft.io/npm/
```

Use `make docker` to build both images with those variables. They are also forwarded by the
`docker-push-*` targets. Docker build stages do not inherit your user-level npm or NuGet configuration;
pass the feed URLs explicitly. The NuGet v3 index is for .NET packages, not npm packages.

- Studio: `http://localhost:8080/`
- API: `http://localhost:8080/v1/...`
- OpenAPI: `http://localhost:8080/openapi/v1.json`

The runtime image is built on the ASP.NET Core runtime, runs as a **non-root** user, listens on
`8080` via `ASPNETCORE_URLS=http://+:8080`, and serves static assets plus Studio's `index.html` as
the fallback for non-file browser routes. Unknown `/v1` routes return API errors, not the SPA.

### Multi-architecture images

Both Dockerfiles build cleanly for amd64 and arm64. Managed assemblies compile as AnyCPU, so no
per-architecture source build is needed:

```bash
docker buildx build -f build/Dockerfile.api \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/tmforge:0.12.0 --push .
```

### Configuration

The API is **stateless for models**: it operates on the content each request carries without storing
model sessions. Custom rule packs are host configuration retained across calls. Relevant knobs:

| Setting | Default | Notes |
| --- | --- | --- |
| `ASPNETCORE_URLS` | `http://+:8080` (container) | Bind address/port. |
| Port (from source) | ASP.NET Core default unless configured | Use `dotnet run --project src/ThreatModelForge.Api -- --urls http://localhost:5205` for the Vite client's dev API. |
| CORS | allows `http://localhost:5199` | Configured for the Vite dev server but currently applied in every environment; not an access-control boundary. |
| `TmForge__Rules` / `TmForge__Rules__0` | no custom packs | Semicolon-separated paths or indexed entries; read at startup. See [custom API rules](api-reference.md#custom-rule-packs). |

Because it's stateless, scale it horizontally behind a load balancer with no session affinity.

### Health checks

Use `GET /v1/health` as a liveness/readiness probe.

```bash
curl -fsS http://localhost:8080/v1/health
```

## Studio static demo (in-browser engine, no backend)

The Studio can run as a **fully static site** with the .NET engine compiled to **WebAssembly**. The
same validation, `.tm7` round-trip, format conversion, and reports the `/v1` engine provides, running
**in the browser with no server**. This is how the public
[GitHub Pages demo](https://hacks4snacks.github.io/tmforge/) is deployed, and it doubles
as an offline/air-gapped deployment when all assets are staged on a reachable local static host.
Model processing is local; sharing and downloads remain explicit user actions. This is not an
installed PWA or a guarantee that an unvisited page works without downloading its assets.

The Studio picks its engine transport at startup and degrades cleanly:

| Order | Transport | When |
| --- | --- | --- |
| 1 | `/v1` HTTP engine | a `/v1/health` probe answers (hosted image, or a dev API) |
| 2 | **WASM engine** | no `/v1`, but the WASM bundle loads: full engine, in-browser |
| 3 | Offline | WASM cannot load (disabled/blocked): authoring only; engine ops report an honest error |

### Build it

The WASM engine project (`src/ThreatModelForge.Wasm`) is **opt-in** and needs the WASM workloads. The
Studio ships an npm script that publishes it and stages the runtime into `public/wasm/`:

```bash
# one-time: the browser-wasm workloads
dotnet workload install wasm-tools wasm-experimental

cd src/ThreatModelForge.Studio
npm ci
npm run stage:wasm                 # dotnet publish (Release, trimmed) -> copy _framework into public/wasm
VITE_DEMO=true npm run build       # emits dist/ with the SPA + wasm/_framework
```

Serve `dist/` from any static host:

```bash
python3 -m http.server --bind 127.0.0.1 -d dist 8080  # http://localhost:8080/
```

- `VITE_DEMO=true` skips the HTTP probe and goes directly to the staged WASM engine.
- `VITE_BASE` sets the base path when the site is served from a sub-path (e.g. `/tmforge/` on project
  Pages); omit it for a root deploy.
- The bundle contains the .NET WASM runtime, trimmed engine assemblies, and ICU. Download size
  depends on the build and the host's compression/cache configuration; WASM is loaded on demand
  when HTTP is unavailable or the build skips HTTP probing.

### GitHub Pages

The [`pages.yml`](../.github/workflows/pages.yml) workflow does exactly the above on push: installs the
workloads, runs `npm run stage:wasm`, builds with `VITE_DEMO=true` and `VITE_BASE=/<repo>/`, and
publishes `dist/` to Pages. Trimming keeps the `.tm7` `DataContractSerializer` and the engine
assemblies (rooted via `ILLink.Descriptors.xml`); a `wasm` job in
[`ci.yml`](../.github/workflows/ci.yml) guards that on every build.

> **Static-host note:** asset fingerprinting is disabled (`WasmFingerprintAssets=false`) so the
> runtime's literal `./_framework/dotnet.js` import resolves on a plain static server. This is already
> set in the project, no per-deploy configuration needed.

## Kubernetes

A minimal Deployment + Service for the API + Studio image. The example uses the published GHCR
image; point `image` at your own registry if you build it
yourself.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tmforge
  labels: { app: tmforge }
spec:
  replicas: 2
  selector:
    matchLabels: { app: tmforge }
  template:
    metadata:
      labels: { app: tmforge }
    spec:
      containers:
        - name: tmforge
          image: ghcr.io/hacks4snacks/tmforge:0.12.0
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet: { path: /v1/health, port: 8080 }
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /v1/health, port: 8080 }
            initialDelaySeconds: 10
            periodSeconds: 20
          resources:
            requests: { cpu: "100m", memory: "128Mi" }
            limits:   { cpu: "500m", memory: "512Mi" }
          securityContext:
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            capabilities: { drop: ["ALL"] }
---
apiVersion: v1
kind: Service
metadata:
  name: tmforge
spec:
  selector: { app: tmforge }
  ports:
    - port: 80
      targetPort: 8080
```

The container already runs as non-root; the `securityContext` above hardens it further. Add an
authenticated Ingress/Gateway and TLS per your cluster's conventions, and prevent direct backend
access. Resource requests are examples, not measured capacity recommendations; tune to your
model sizes and traffic.

## The CLI in containers

For batch validation/conversion, mount your working directory into the CLI image. Use the
published image:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli analyze model.tm7
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli convert model.tm7 --to drawio --out model.drawio
```

Or build it from source:

```bash
docker build -f build/Dockerfile -t tmforge-cli .
docker run --rm -v "$PWD:/work" tmforge-cli analyze model.tm7
```

The image mounts your files at `/work`, so paths in your commands are relative to it. Behind a
package mirror, pass `--build-arg NUGET_FEED=<mirror-v3-index-url>` — see
[Building behind a package mirror](#building-behind-a-package-mirror).

## CI/CD

On GitHub, use the first-party action. Elsewhere, run the self-contained binary or the CLI container.

### With the first-party GitHub Action (recommended)

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: hacks4snacks/tmforge@v0.12.0
    with:
      version: "0.12.0"       # pin the engine image, not just the action ref
      models: "**/*.tm7"
      max-severity: warning
```

It analyzes every matching model, uploads SARIF to code scanning, and gates the build. It also
accepts `rules`, `ruleset`, and `suppression-file`, so a pipeline gets the same custom-rule and
suppression behavior as the CLI. See [Analysis rules & CI](analysis-rules.md#ci-integration) for the
full input list.

### With the prebuilt binary (fastest cold start)

```yaml
# GitHub Actions
- name: Install tmforge
  run: |
    set -euo pipefail
    base=https://github.com/hacks4snacks/tmforge/releases/download/v0.12.0
    archive=tmforge-0.12.0-linux-x64.tar.gz
    curl -fsSLO "$base/$archive"
    curl -fsSLO "$base/checksums.txt"
    grep -F "  $archive" checksums.txt | sha256sum -c -
    tar -xzf "$archive"
    echo "$PWD/tmforge-0.12.0-linux-x64" >> "$GITHUB_PATH"
- name: Analyze
  run: tmforge analyze model.tm7 --reportFolder reports
```

### With the CLI container

```yaml
- name: Analyze
  run: |
    docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli:0.12.0 \
      analyze /work/model.tm7 --reportFolder /work/reports
```

Both fail the step on findings at the selected threshold (exit `2`, default `error`) and on tool
errors (exit `1`). Use `--max-severity warning` to include warnings. Upload the `reports/`
SARIF for code-scanning annotations. See [Analysis rules & CI](analysis-rules.md#ci-integration).

### Azure DevOps example

```yaml
- bash: |
    set -euo pipefail
    base=https://github.com/hacks4snacks/tmforge/releases/download/v0.12.0
    archive=tmforge-0.12.0-linux-x64.tar.gz
    curl -fsSLO "$base/$archive"
    curl -fsSLO "$base/checksums.txt"
    grep -F "  $archive" checksums.txt | sha256sum -c -
    tar -xzf "$archive"
    ./tmforge-0.12.0-linux-x64/tmforge analyze model.tm7 --reportFolder "$(Build.ArtifactStagingDirectory)/threatmodel"
  displayName: Analyze threat model
```

## Supply-chain verification

Each GitHub Release ships `checksums.txt` (SHA-256) and `release-metadata.json` (version, tag,
commit, and per-RID file / sha256 / size). Stable releases also include a VSIX in `checksums.txt`;
the metadata artifact array describes the CLI archives. Verify the checksum entry for the exact
downloaded filename before extraction or use, as shown above and in
[Installation](installation.md#verify-the-download). Checksums are integrity checks, not independent
publisher authentication; use an approved release source and pin image digests where required.

`tmforge --version` reports the released version (the release pipeline stamps the tag into the
assembly's informational version).

## Platform caveats

- **Linux binaries** target a **glibc** baseline (not musl/Alpine). On Alpine, use the container
  image, which is built on Microsoft's .NET base images.
- **macOS binaries** are **not code-signed or notarized**. Verify the download and follow local
  approval policy if Gatekeeper blocks it; see [platform notes](installation.md#platform-notes).

## See also

- [Installation](installation.md): all install channels.
- [Engine API reference](api-reference.md): endpoints and hosting notes.
- [Analysis rules & CI](analysis-rules.md): gating pipelines on findings.
