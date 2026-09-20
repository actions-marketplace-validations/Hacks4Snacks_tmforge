# Engine API reference

The Threat Model Forge **engine API** exposes a small, versioned `/v1` HTTP surface over the real
.NET engine, and serves the [Studio](studio-guide.md) single-page app from its root, so the API and
UI ship as one hosted artifact.

The API contract is the single source of truth: the OpenAPI document at `/openapi/v1.json` is what
Studio's typed client is generated from. A checked-in copy lives at
[`src/ThreatModelForge.Api/openapi/v1.json`](../src/ThreatModelForge.Api/openapi/v1.json).

## Run

```bash
# From source: serves the built Studio SPA at the root.
dotnet run --project src/ThreatModelForge.Api        # http://localhost:5205/

# Container: the published engine API + Studio image (pulls on first run).
docker run --rm -p 8080:8080 ghcr.io/hacks4snacks/tmforge   # http://localhost:8080/
```

Any non-API path falls back to Studio's `index.html` (so client-side routes resolve), while `/v1`
and `/openapi` are matched first.

## Endpoints

| Method & path | Tag | Purpose |
| --- | --- | --- |
| `GET /v1/health` | System | Liveness probe. |
| `GET /v1/formats` | Formats | List supported formats and their capabilities. |
| `POST /v1/detect` | Formats | Detect a file's format from its bytes. |
| `GET /v1/stencils` | Catalog | List element stencils. |
| `GET /v1/stencil-packs` | Catalog | List stencil packs. |
| `GET /v1/rules` | Catalog | List analysis rules. |
| `GET /v1/rule-packs` | Catalog | List rule packs. |
| `GET /v1/rule-bundle` | Catalog | Report which custom rule packs this host loaded, and any load diagnostics. |
| `GET /v1/property-schema` | Catalog | List the typed custom-property schema the rules read. |
| `POST /v1/model/analyze` | Model | Analyze a model and return findings. |
| `POST /v1/model/analysis` | Model | One analysis action: findings **and** threats from a single rule evaluation, plus the effective rule packs and diagnostics. |
| `POST /v1/model/analysis-document` | Model | Record the analysis as a versioned, reconcilable `tmforge-analysis` document. |
| `POST /v1/model/threats` | Model | Generate the STRIDE threat register (rule threats plus the model's author overlay). |
| `POST /v1/model/threat-register` | Model | Split the register by origin and standing: manual, current-generated, stale-generated, and entries whose rule was not part of the run. |
| `POST /v1/model/read` | Model | Parse uploaded bytes (base64) into the canonical model. |
| `POST /v1/model/preflight?to=<format>` | Model | Check source bytes and optionally preview conversion losses without writing or analyzing. |
| `POST /v1/model/manifest` | Model | Materialize a declarative authoring manifest into a model (the `tmforge apply` build). |
| `POST /v1/model/compare` | Model | Read-only structural, boundary-crossing, and findings comparison of two canonical model snapshots. |
| `POST /v1/model/layout` | Model | Return geometry-only updates after preserving every boundary membership and actual flow crossing; unsafe candidates are refused atomically. |
| `POST /v1/model/convert?to=<format>` | Model | Convert a model to another format. |
| `POST /v1/model/export/tm7` | Model | Export a model as a `.tm7` file. |
| `POST /v1/model/report?format=<html\|svg>` | Report | Render a model to an HTML or SVG report. |
| `POST /v1/model/analysis-report?format=<sarif\|html\|json>` | Report | Render the analysis findings as SARIF, HTML, or JSON. |
| `GET /openapi/v1.json` | n/a | The OpenAPI document. |

`<format>` is one of `tm7`, `tmforge-json`, `drawio`, or `vsdx`. See
[Formats & interoperability](formats.md).

## Errors

Failures are answered as [RFC 9457 problem documents](https://www.rfc-editor.org/rfc/rfc9457)
(`application/problem+json`), and the status separates what you can fix from what you cannot:

| Status | Meaning | Examples |
| --- | --- | --- |
| `400` | The request was unusable as sent. Retrying it unchanged cannot help. | Body that is not JSON; a missing `?to=`; an unregistered format id; content that is not valid base64; uploaded bytes that are not the format they claim to be. |
| `404` | The path is not part of the `/v1` API, or the content was not recognized. | A mistyped endpoint; `POST /v1/detect` on bytes matching no known format. |
| `500` | The server failed. This one is worth reporting. | Anything unexpected — the classification above is deliberately narrow, so a real fault is never disguised as your mistake. |

The `detail` of a `400` names what was unusable, so the request can be corrected without guesswork:

```json
{
  "status": 400,
  "title": "The request could not be processed as sent.",
  "detail": "No threat model format with id 'nonsense'.",
  "instance": "/v1/model/convert"
}
```

An unmatched path under `/v1` answers `404` as the API rather than falling through to the Studio's
HTML shell, so a mistyped endpoint fails as a client error instead of returning a page a JSON client
cannot parse. Paths outside `/v1` still reach the SPA, which is what makes client-side routing work.

## Document preflight

Send the same `{ "contentBase64": "...", "formatId": "tmforge-json" }` payload used by the read
endpoint to `POST /v1/model/preflight`. `formatId` is optional; it can also be `tmforge-manifest` for
explicitly selected legacy manifests. The optional `to` query parameter selects a writable conversion
target. No rule evaluation, file write, or remote content resolution occurs.

The response is `{success,format,targetFormat,diagnostics}`. Each diagnostic contains a stable
`code`, `severity` (`error`, `warning`, `info`), source `path`, and actionable `message`. JSON
diagnostics use JSONPath locations; foreign-reader failures may include a provider-specific location
in their message. An assessment that finds input errors still returns HTTP **200** with
`success: false`. Invalid request JSON or base64 remains an ordinary **400** problem response.

Warnings indicate known omissions or changes, not security findings. Inspect them before calling
`/v1/model/read` or `/v1/model/convert`; those existing response shapes are unchanged. For an import
into Studio's canonical model, select `to=tmforge-json`. The limit is 8 MiB of decoded input and
100 diagnostics; JSON readers also cap nesting at 64. The final diagnostic is an error when the
diagnostic budget is exhausted, so a truncated result cannot look successful.

The WASM `Preflight(contentBase64, formatId, targetFormat)` export returns the same result; empty
strings omit the two format selections. MCP exposes `preflight(path, format?, to?)` with the existing
workspace sandbox and archive limits. Neither operation accepts rule content or changes models.

## One analysis action

Findings and threats are the same detection: a threat is a finding from a rule that declares a threat
category, kept for its lifecycle (open → mitigated → accepted). Asking for them separately makes the
engine evaluate every enabled rule twice for one user action, so a UI that shows both should call
`POST /v1/model/analysis`, which evaluates once and projects both:

```bash
curl -s -X POST http://localhost:8080/v1/model/analysis \
  -H 'Content-Type: application/json' --data @model.tmforge.json
# { "findings": […], "threats": […], "rulePacks": […], "diagnostics": [] }
```

`POST /v1/model/analyze` and `POST /v1/model/threats` remain available and return exactly what the
combined action returns for their half; they exist for callers that genuinely need only one
projection, and they do not materialize the other.

## Model comparison

`POST /v1/model/compare` accepts `{ "baseline": <tmforge-json>, "proposed": <tmforge-json> }`.
Both snapshots are required. It returns `ModelCompareResultDto`:

```json
{
  "success": true,
  "findingsAvailable": true,
  "unchangedFindings": 12,
  "changes": [],
  "warnings": [],
  "diagnostics": []
}
```

`success` describes the **structural comparison**, not analysis availability. Invalid topology,
ambiguous ids, or exceeded comparison limits return HTTP **200** with `success: false`, diagnostics,
and no partial changes. Malformed request JSON still receives a **400** problem response.

Each change has a stable `id`, a `section` (`structure`, `crossings`, or `findings`), a `kind`,
`title`, and `properties: [{key,from,to}]`. Structural/crossing kinds are `added`, `removed`, or
`modified`; finding kinds are `introduced`, `resolved`, or `reclassified`. Optional `elementKind`,
`ruleId`, and `severity` describe the target. `baselineElementIds`/`proposedElementIds` and the
side-specific page ids/names preserve the caller's ids for navigation; an absent side has no target.
Flow highlights include endpoints, and crossing highlights include changed boundaries.

Structural differences reuse the identity-keyed model diff; names never substitute for identity.
Page moves/names are included, while visual-only geometry is excluded. Crossing changes reuse the
analyzer's geometric boundary calculation. Both inputs are analyzed once using the host's same
trusted rule bundle and each input's disabled-rule selections. Finding identity and classification
reuse the versioned analysis-document diff, so renaming does not churn findings and accepting a
threat reclassifies it rather than resolving it.

A missing expected pack, load diagnostic, or analysis failure sets `findingsAvailable: false` and
returns **no findings changes**, while structural changes can remain available. Different source-id
representations of a shared object/page, such as aliases versus exported GUIDs, also disable findings
comparison instead of manufacturing resolutions. Different effective rule selections warn because
the resulting delta can reflect rule configuration rather than a changed security condition.

This is not a complete document/register diff. Metadata and author-owned threat-record differences
produce warnings; manual threat content, priority, justification, and orphaned triage are not reviewed
field by field. Preflight foreign source bytes with `to=tmforge-json` before reading them, and retain
those import-loss diagnostics with the review. The endpoint receives canonical snapshots, so it cannot
recover or diagnose information already omitted by an earlier conversion.

Limits per snapshot: 8 MiB of serialized canonical JSON, 32 pages, 1,024 elements, 2,048 flows, and
1,000,000 flow/boundary pairs. The total change limit is 10,000, with refusal rather than truncation.
No input model, file, rule selection, or stored triage is modified.

The WASM `Compare(requestJson)` export uses the same contract and the module's active rule bundle.
There is no browser-side comparison algorithm and no separate threat detection pass.

## Shared arrangement

`POST /v1/model/layout` accepts a `LayoutRequestDto`: `model` is the **original** canonical model;
optional `page` selects a name or one-based index (otherwise every page); and optional `options`
supplies layout metrics such as
`nodeSpacing`, `layerSpacing`, `maxWidth`, and `boundaryHeaderHeight`.

Without `positions`, the engine generates a bounded arrangement, as used by the CLI's explicit
layout command. `maxWidth` defaults to `1760` for its MTMT-oriented layout.

For in-place cleanup, supply `positions: [{id,x,y,width,height}, ...]` for every element on the
selected pages. The engine validates those exact rectangles against the original
model's memberships and crossings, recomputing connector endpoints but never re-layering the
candidate. Partial, duplicate, unknown or out-of-bounds positions are refused.
Studio's one-click Tidy uses only this validation path with the
released cleanup algorithm; Studio does not request engine-generated rearrangement.

Include text fitting in the proposed positions, not by resizing the input model first: the original geometry is
the baseline against which memberships and crossings must be preserved. Unknown or duplicate ids,
cross-page/dangling flows, boundary-ended flows, invalid geometry and excessive work are refused rather
than normalized into a different model. No analysis rules are evaluated, and property bags and
triage are not hydrated into the geometry candidate.

The response is `{success,error,elements,pages,components,labelOverlaps}`. On success, `elements`
contains only `{id,x,y,width,height}` keyed by the original author ids. Apply those rectangles to the
existing document; do not replace it. Pages, topology, properties, rule selections, triage and view
state remain owned by the caller. A refusal returns HTTP `200` with `success: false`, a reason, and
an empty `elements` array; malformed request JSON still receives the ordinary `400` problem response.

All requested pages succeed or none do. The engine checks complete component membership, both
connector endpoints' boundary sides, and crossing sets using the analyzer's boundary implementation.
Overlapping regions are not assumed to be invalid; an arrangement that would drop a claim is refused.
There is no force bypass. See the [CLI layout limits](cli-reference.md#layout) for computation bounds;
canonical model dimensions and proposed rectangles must be at least 20 units in width and height.

The WASM `Layout(requestJson)` export returns the identical contract. Studio retains client-side
text measurement when computing the candidate, then visual routing and label deconfliction after
the shared validation step.

## Custom rule packs

Custom rules are deployment configuration, not request input: this host never loads rules from a
request body, so a caller cannot inject detection logic. Name the packs (files or directories) with
the `TmForge:Rules` setting and they are read once at startup, then applied to every rule-reading
endpoint — catalogs, analysis, threats, reports, and `.tm7` export — as one effective bundle:

```bash
# a single pack, or a ';'-separated list
TmForge__Rules='/etc/tmforge/corporate.tmrules.json' dotnet ThreatModelForge.Api.dll
```

Confirm what actually loaded before trusting a clean run:

```bash
curl http://localhost:8080/v1/rule-bundle
# { "rulePacks": [ { "id": "corporate", "version": "2.1", "fingerprint": "sha256:…", "ruleCount": 12 } ],
#   "diagnostics": [] }
```

A model may pin the packs it was reviewed with; a missing or changed pack becomes an `error` finding
with rule id `rule-pack-mismatch`. See
[Custom rules on every surface](analysis-rules.md#custom-rules-on-every-surface).

## Usage examples

### Liveness

```bash
curl http://localhost:8080/v1/health
```

### Discover capabilities

```bash
curl http://localhost:8080/v1/formats          # what can be read/written and how faithfully
curl http://localhost:8080/v1/rules            # the analysis rules
curl http://localhost:8080/v1/rule-packs       # the rule packs (core-hygiene, stride-completeness, ...)
curl http://localhost:8080/v1/property-schema  # typed custom properties the rules read
curl http://localhost:8080/v1/stencils         # authoring stencils
```

### Detect a format

`POST /v1/detect` sniffs uploaded bytes and reports the matching format.

### Analyze a model

`POST /v1/model/analyze` returns findings for a supplied model, the same rule engine `tmforge analyze`
uses. This is how Studio's **Analyze** button overlays findings on the canvas.

Each finding's `id` is stable: `{ruleId}:{diagram}:{target}:{occurrence}`, where the diagram and
target segments are the element ids from the request model (they read `model` when the finding is
about the model or a whole diagram). The same model analyzed twice produces the same ids, and
enabling or disabling an unrelated rule leaves the other ids alone — so a caller can reconcile a
finding against a previous run. See
[finding identity](analysis-rules.md#finding-identity) for the details and the one caveat.

### Record the analysis

`POST /v1/model/analysis-document` returns a versioned `tmforge-analysis` document — the analysis as
**evidence** rather than as something to render:

```jsonc
{
  "schema": "tmforge-analysis",
  "version": 1,
  "model":    { "name": "Payments", "fingerprint": "sha256:b5c79b9a…" },
  "analyzer": { "name": "ThreatModelForge.Analysis", "version": "0.7.0.0", "fingerprint": "sha256:6f6d4de7…" },
  "rulePacks": [],
  "findings": [
    {
      "id": "TM1013:7e3f1d52…:f1:0",
      "ruleId": "TM1013",
      "severity": "warning",
      "message": "…",
      "diagram": "7e3f1d52…",
      "elementIds": ["f1"],
      "disposition": "generated-threat",
      "threatId": "80f5b13b…:TM1013"
    }
  ],
  "diagnostics": []
}
```

Every finding carries exactly one **disposition**:

| Disposition | Meaning |
| --- | --- |
| `generated-threat` | Threat-bearing and not yet triaged. |
| `unresolved` | Threat-bearing and explicitly marked as needing investigation. |
| `accepted` | Threat-bearing and accepted as a risk. |
| `mitigated` | Threat-bearing and mitigated. |
| `hygiene` | The rule declares no threat category, so this is a modelling-quality observation, not a risk. |
| `suppressed` | A suppression silenced it; it is recorded rather than dropped. |

The four threat-bearing dispositions always carry a `threatId` that joins to
`POST /v1/model/threats`; `hygiene` and `suppressed` never do. That separation is the point: a
reviewer should not have to accept "this diagram has no trust boundary" as a *risk* in order to clear
a gate.

Two things make the document comparable between runs. The **fingerprints** let a consumer detect that
a stored analysis no longer describes the model or rule selection in front of it — the model
fingerprint covers the structural model only, so triaging a threat does not report the model as
changed, while loading a pack or disabling a rule does move the analyzer fingerprint. And the document
carries **no timestamp**, so two analyses of the same inputs are byte-identical and a diff shows only
what actually changed. When a run happened is something CI already records; putting it here would cost
the property the artifact exists for.

### Generate threats

`POST /v1/model/threats` returns the model's **STRIDE threat register** the same rule findings as
`analyze`, framed as threats and overlaid with the model's author-owned state. The request model's
`threats` overlay carries risk acceptance, per-threat edits (state, priority, mitigation, description),
and **manually-authored threats** (`manual: true`, keyed in the reserved `manual:` namespace, scoped to
element ids or model-wide). Those edits and manual threats round-trip into the exported `.tm7` register,
so a threat accepted or authored in Studio opens in the Microsoft Threat Modeling Tool. This powers
Studio's threat panel and the `tmforge threats` verb.

A manual entry whose `id` is not a usable identity — malformed, or already claimed by another threat —
is reported in `diagnostics` rather than silently dropped, and the first entry to claim an id keeps it.

### Split the threat register

`POST /v1/model/threat-register` classifies every register entry against one analysis run and returns
the counts plus a per-entry `state`:

| State | Meaning |
| --- | --- |
| `manual` | An author wrote it. Rules never produce or retire it. |
| `current-generated` | The current rules still produce it. |
| `stale-generated` | Stored, but the rule ran and no longer produces it. |
| `indeterminate-generated` | Its rule was not part of this run, so its standing cannot be judged. |

Applying a generation result never deletes, so triage survives every re-run — which is exactly why a
left-over entry needs to be distinguishable from a live one. Staleness is only ever claimed when the
rule actually ran; an entry whose rule is missing or disabled is counted in `indeterminateGenerated`
and its rule named in `unavailableRuleIds`, never assumed stale.

The counts are **not a partition and must not be summed**. What "stored" means also depends on the
format: a `.tm7` carries the full generated register, while canonical tmforge-json persists only
author-owned state — so on this endpoint `staleGenerated` is most useful as *triage that no longer
matches any threat the rules produce*.

### Convert / export

```bash
# Convert (target chosen by the `to` query parameter):
#   POST /v1/model/convert?to=drawio
# Export a .tm7 specifically:
#   POST /v1/model/export/tm7
```

Both `.tm7` paths embed the Threat Model Forge knowledge base and write typed properties, so the
exported file opens in the Microsoft Threat Modeling Tool. See
[Formats](formats.md#tm7-and-the-microsoft-threat-modeling-tool).

### Report

`POST /v1/model/report?format=html` (or `format=svg`) renders a report from a model, the hosted
equivalent of `tmforge report`. Multi-page models render every diagram: the HTML report has one
section per page, and the SVG stacks the pages. HTML reports generate the enabled rule-backed threats
on demand, overlay the model's manual threats and triage, and show rule id, STRIDE category, scope,
priority, mitigation, references, and decision note. SVG output renders diagrams only.

`POST /v1/model/analysis-report?format=sarif` (or `html` / `json`) renders the *analysis* artifacts
instead — the findings evidence, not the threat-model document. These are the same artifacts
`tmforge analyze --reportFolder` writes, so a report served here and a file written in CI are the
same document. An unrecognized format falls back to the readable findings HTML.

```bash
curl -s -X POST 'http://localhost:8080/v1/model/analysis-report?format=sarif' \
  -H 'Content-Type: application/json' --data @model.tmforge.json -o findings.sarif
```

Both report endpoints run the host's configured rule packs and honor the model's own disabled
selection, so a report always matches the analysis it claims to describe.

## OpenAPI & client generation

The document is produced by the ASP.NET Core OpenAPI integration and served at `/openapi/v1.json`.
After changing the `/v1` contract, refresh the checked-in copy so Studio's generated client stays in
sync (Studio's `npm run gen:api` reads that file). See the
[Studio guide](studio-guide.md#regenerating-the-api-client).

## Notes for hosting

- The container listens on port **8080**; from source it listens on **5205**.
- In development the API permits CORS from the Studio dev server at `http://localhost:5199`.
- The API is stateless: it operates on the model bytes you send it, so it scales horizontally.
  See [Deployment](deployment.md).

## See also

- [Studio guide](studio-guide.md): the browser client of this API.
- [Deployment](deployment.md): running the API in containers and Kubernetes.
- [Formats & interoperability](formats.md): the formats the model endpoints speak.
