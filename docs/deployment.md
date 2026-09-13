# Deployment guide

This guide covers running Threat Model Forge in shared environments: the **engine API + Studio** as a
hosted web app, the **CLI** in pipelines, and both in containers, Kubernetes, and CI/CD.

Threat Model Forge has two deployable artifacts:

| Artifact | Image build file | Contains | Typical use |
| --- | --- | --- | --- |
| **API + Studio** | `build/Dockerfile.api` | The `/v1` engine API + the Studio SPA | Hosted browser app |
| **CLI** | `build/Dockerfile` | The `tmforge` CLI | CI, batch conversion/validation |

## API + Studio

The engine API serves the Studio SPA at its root, so one container gives you both the UI and the API.

### Run

Pull the published image:

```bash
docker run --rm -p 8080:8080 ghcr.io/hacks4snacks/tmforge          # -> http://localhost:8080/
```

Or build it from source:

```bash
docker build -f build/Dockerfile.api -t tmforge .
docker run --rm -p 8080:8080 tmforge          # -> http://localhost:8080/
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

- Studio: `http://localhost:8080/`
- API: `http://localhost:8080/v1/...`
- OpenAPI: `http://localhost:8080/openapi/v1.json`

The runtime image is built on the ASP.NET Core runtime, runs as a **non-root** user, listens on
`8080` via `ASPNETCORE_URLS=http://+:8080`, and serves any non-API path as Studio's `index.html`.

### Multi-architecture images

Both Dockerfiles build cleanly for amd64 and arm64. Managed assemblies compile as AnyCPU, so no
per-architecture source build is needed:

```bash
docker buildx build -f build/Dockerfile.api \
  --platform linux/amd64,linux/arm64 \
  -t <registry>/tmforge:0.1.0 --push .
```

### Configuration

The API is **stateless**: it operates on the model bytes each request carries and keeps nothing
between calls. Relevant knobs:

| Setting | Default | Notes |
| --- | --- | --- |
| `ASPNETCORE_URLS` | `http://+:8080` (container) | Bind address/port. |
| Port (from source) | `5205` | `dotnet run --project src/ThreatModelForge.Api`. |
| CORS (dev only) | allows `http://localhost:5199` | The Studio Vite dev server; not needed for the hosted image. |

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
as a genuine offline/air-gapped build: the model never leaves the page.

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
python3 -m http.server -d dist 8080     # -> http://localhost:8080/
```

- `VITE_DEMO=true` wires the WASM transport into the demo build.
- `VITE_BASE` sets the base path when the site is served from a sub-path (e.g. `/tmforge/` on project
  Pages); omit it for a root deploy.
- The bundle is the .NET WASM runtime + trimmed engine assemblies + ICU, roughly **3.3 MB brotli**,
  loaded lazily and cached, and only fetched when no `/v1` answers.

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
          image: ghcr.io/hacks4snacks/tmforge:0.1.0
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
Ingress/Gateway and TLS per your cluster's conventions. Resource requests are modest; tune to your
model sizes and traffic.

## The CLI in containers

For batch validation/conversion, mount your working directory into the CLI image. Use the
published image:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli tmforge analyze model.tm7
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli tmforge convert model.tm7 --to drawio --out model.drawio
```

Or build it from source:

```bash
docker build -f build/Dockerfile -t tmforge-cli .
docker run --rm -v "$PWD:/work" tmforge-cli tmforge analyze model.tm7
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
  - uses: hacks4snacks/tmforge@v0.7
    with:
      version: "0.7"          # pin the engine image, not just the action ref
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
    curl -fsSL -o tmforge.tar.gz \
      https://github.com/hacks4snacks/tmforge/releases/download/v0.1.0/tmforge-0.1.0-linux-x64.tar.gz
    tar -xzf tmforge.tar.gz
    echo "$PWD/tmforge-0.1.0-linux-x64" >> "$GITHUB_PATH"
- name: Analyze
  run: tmforge analyze model.tm7 --reportFolder reports
```

### With the CLI container

```yaml
- name: Analyze
  run: |
    docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli:0.1.0 \
      tmforge analyze /work/model.tm7 --reportFolder /work/reports
```

Both fail the step on findings (exit `2`) and on tool errors (exit `1`). Upload the `reports/`
SARIF for code-scanning annotations. See [Analysis rules & CI](analysis-rules.md#ci-integration).

### Azure DevOps example

```yaml
- script: |
    curl -fsSL -o tmforge.tar.gz \
      https://github.com/hacks4snacks/tmforge/releases/download/v0.1.0/tmforge-0.1.0-linux-x64.tar.gz
    tar -xzf tmforge.tar.gz
    ./tmforge-0.1.0-linux-x64/tmforge analyze model.tm7 --reportFolder $(Build.ArtifactStagingDirectory)/threatmodel
  displayName: Analyze threat model
```

## Supply-chain verification

Each GitHub Release ships `checksums.txt` (SHA-256) and `release-metadata.json` (version, tag,
commit, and per-RID file / sha256 / size). Verify downloads before use:

```bash
sha256sum -c checksums.txt
```

`tmforge --version` reports the released version (the release pipeline stamps the tag into the
assembly's informational version).

## Platform caveats

- **Linux binaries** target a **glibc** baseline (not musl/Alpine). On Alpine, use the container
  image, which is built on Microsoft's .NET base images.
- **macOS binaries** are **not code-signed or notarized** in this release; clear quarantine with
  `xattr -d com.apple.quarantine ./tmforge`, or install via `curl` (which doesn't set it).

## See also

- [Installation](installation.md): all install channels.
- [Engine API reference](api-reference.md): endpoints and hosting notes.
- [Analysis rules & CI](analysis-rules.md): gating pipelines on findings.
