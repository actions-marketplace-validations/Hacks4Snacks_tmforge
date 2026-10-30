# Formats & interoperability

Threat Model Forge keeps one **canonical, `.tm7`-shaped in-memory model** and maps every file format
to and from it through a pluggable format layer. New formats plug in without changing the tools that
consume them, and each provider declares how faithfully it round-trips.

## Supported formats

| Format id | Extension | Display name | Read | Write | Round-trips |
| --- | --- | --- | :---: | :---: | :---: |
| `tm7` | `.tm7` | Microsoft Threat Modeling Tool | Yes | Yes | Native; see fidelity below |
| `tmforge-json` | `.tmforge.json` | Threat Model Forge JSON (canvas wire model) | Yes | Yes | Structural |
| `drawio` | `.drawio` | draw.io / diagrams.net | Yes | Yes | Structural |
| `vsdx` | `.vsdx` | Microsoft Visio | Yes | Yes | Structural |
| `threat-dragon` | `.threatdragon.json`; other JSON content-detected | OWASP Threat Dragon v2 | Yes, bounded subset | Yes, bounded subset | Structural; imported identities retained |
| `mermaid` | `.mmd`, `.mermaid` | Mermaid flowchart | Yes, bounded subset | No | Import only |
| `dot` | `.dot`, `.gv` | Graphviz DOT | Yes, bounded subset | No | Import only |

List these at runtime with `tmforge` (via conversion targets) or the API's `GET /v1/formats`, which
returns each provider's capabilities and fidelity note.

## Fidelity

Fidelity depends on both the format and the operation. A structural conversion retains only the
data its mapping represents; writing it back to `.tm7` cannot recover omitted native content.

### `tm7` (lossless)

The native format provider uses .NET's `DataContractSerializer` over the rich model graph, with
byte-stable fixture coverage. That is not a guarantee that arbitrary CLI edits or conversions retain
every byte of an input XML document: writing may prepare templates, coordinates, and connector labels.

Studio and `/v1/model/save/tm7` use a separate preserving edit path backed by the original XML.
An unchanged valid document with an existing template returns its original bytes. Edited saves
retain unrelated native XML, templates, and unaffected threat decisions, although XML formatting
can change. Missing templates/definitions are added as needed. Explicit deletion removes dependent
threats and decisions. Keep native sources when their full contents matter; see [native saving](api-reference.md#native-tm7-saving).

### `tm7` and the Microsoft Threat Modeling Tool

For a file to open in MTMT it must carry a **knowledge base** (the tool dereferences it without a null
check). So when you export a model that doesn't already have one, Threat Model Forge embeds its own
clean-room default — **“Threat Model Forge Core”**: the generic DFD element types, the six STRIDE
categories, a threat type per built-in rule, and a **standard element type for every authoring
stencil** so the tool's palette mirrors Threat Model Forge's. This happens on **every** `.tm7` write
(the CLI authoring verbs, `convert --to tm7`, and Studio/API export), so a `.tm7` is MTMT-ready at
every step.

- **Typed properties.** Schema properties (`Protocol`, `Encrypted`, `DataType`, …) are written as
  first-class **typed tool properties** — the drop-downs MTMT shows in its properties pane — rather
  than free-form custom attributes. Free-text properties (like `Port`) and any value outside a
  property's options are kept as custom attributes, so nothing is dropped.
- **Stencils as element types.** An element placed from a stencil (`azure-sql`, `entra-id`, …) is
  exported as the matching standard element type, so it appears in MTMT as that stencil rather than a
  bare generic.
- **Existing knowledge bases are retained.** A model that already carries a knowledge base, or one
  supplied with `tmforge convert --knowledge-base <file.tb7>`, is not replaced by the default.
  Writers can extend required definitions and priority values; native saves also add newly authored
  property values without replacing existing customizations. Retained does not mean byte-untouched.

Analysis reads typed and custom properties identically, so an exported or tool-authored `.tm7` is
validated the same as one authored with custom attributes.

### `tmforge-json` (canonical wire model)

The shape Studio and the API speak: elements, flows, trust boundaries, names, and geometry, plus an
optional analysis selection (disabled packs/rules) and an author-owned threat overlay, risk
acceptance, and per-threat edits (state, priority, mitigation, description), plus manually-authored
threats. An optional `metadata` object retains the model name, owner, description, contributors, and
reviewer. An optional `notes` array retains native model notes: integer `id`, free-text `message`,
ISO-8601 `date`, and optional `addedBy`. IDs, recorded dates, authors, and line breaks survive
canonical JSON and `.tm7` round trips. Models without notes remain valid; empty native collections
are omitted from canonical output. Notes are documentation, not analysis inputs or threat triage.
Imported manual threats and diagrams carry informational provenance in their optional
`source` objects, including Threat Dragon identifiers and methodology.
Multi-page models carry a `diagrams` array (one entry per page, with its name); a named or explicitly
identified single page also retains that array. The flat `elements`/`flows` mirror the first page for
older readers, and legacy flat documents remain readable. Knowledge-base
attributes and the full generated-threat register are not represented, the register is regenerated
from the rules on demand, and only the author-owned overlay round-trips so it's structural rather
than lossless. Use it to bridge Studio and the CLI.

### `drawio` (draw.io / diagrams.net)

A structural mapping to and from mxGraph: nodes, flows, trust boundaries, names, and geometry, with
each draw.io page mapped to a diagram. Import recognizes the shapes this provider writes and its
documented style convention. Knowledge-base attributes, model notes, and generated threats are not represented.

### `vsdx` (Microsoft Visio)

Editable Visio via template injection. **Every diagram (page) is exported as its own Visio page and
re-imported**, so multi-page models keep their pages. Structure (nodes, flows, trust boundaries,
names, geometry) is preserved; element custom properties and associated threats are written as
per-shape **Visio Shape Data** (visible in Visio's Shape Data pane) and re-imported as custom
properties. The rich threat model itself is not reconstructed, so the mapping is structural. Import
recognizes packages this provider wrote and the documented master/shape convention. Model notes
are not preserved; conversion preflight reports their loss.

### `threat-dragon` (OWASP Threat Dragon v2)

This is a **bounded import and export**, not lossless native Threat Dragon editing.
The reader recognizes the `summary` / `detail.diagrams` JSON envelope and accepts major version 2.
The writer emits v2 JSON, selected with `--to threat-dragon` or the `.threatdragon.json` suffix.
The provider does not claim the generic `.json` extension, execute foreign rules, or fetch external resources.
An unsupported construct refuses the entire import rather than returning a partial diagram.

**Preserved:** named pages and stable identities; actors, processes, stores and rectangular trust
boundaries; directed, page-local flows; model title/owner/description/contributors/reviewer; and
authored threats with title, description, category, mitigation, priority, supported state and scope.
Both `data.threats` and the cell-level `threats` schema variant are accepted, but two nonempty threat
arrays on the same cell are ambiguous and refused.

Imported threats use `manual:threat-dragon.<source-id>` keys and remain independent of generated
tmforge threats. Source format/version, threat/cell/diagram ids, methodology, original status,
severity, display number and custom score are retained as provenance. Non-STRIDE category text is preserved, not
coerced into STRIDE; importing a LINDDUN category does not install a LINDDUN evaluator. Source ids
must fit the manual-id vocabulary; malformed or duplicate identities are refused.

**Control mapping:** explicit store booleans map `storesCredentials` to `StoresCredentials`, `isALog`
to `StoresLogData`, `isSigned` to `Signed`, and `isEncrypted` to `Encrypted=At-rest` or `No`.
Actor `providesAuthentication` maps to `AuthenticatesItself`; flow `protocol` is preserved verbatim.
Missing values remain missing. Flow encryption alone does not invent a protocol such as TLS.
Other cell data is preserved under `ThreatDragon.data.*`, alongside source identity properties.
**Out-of-scope flags are retained as information, not applied as tmforge suppressions.** The imported
model is analyzed under the selected tmforge rules, not Threat Dragon's detection semantics.

**Refused on import:** curved/line trust boundaries, unknown cell kinds, bidirectional
or detached flows, cross-page endpoints, fractional/out-of-range rectangles, and unmappable threat
statuses or priorities. Supported statuses are `Open`, `Mitigated`, and `Accepted`; supported
priorities are `Critical`, `High`, `Medium`, and `Low`. For example, `NA`, `Transferred`, `Avoided`
and `Eliminated` are not silently rewritten to `Accepted`. Geometry must use integer coordinates
within +/-1,000,000 and dimensions from 1 to 100,000; rounding could alter a trust claim.

Limits are 8 MiB of UTF-8 JSON, depth 64, 128 diagrams, 10,000 cells, and 20,000 authored threats.
Style, thumbnails, free-form routing/vertices and unlisted document fields are not retained.
Keep the original file. In particular, the upstream v2 demo includes curved boundaries and is
deliberately refused; replacing those boundaries requires a human review,
not automatic conversion to rectangles.

```bash
tmforge open dragon.json
tmforge convert dragon.json --to tmforge-json --out imported.tmforge.json
tmforge convert dragon.json --to tm7 --out imported.tm7
tmforge preflight imported.tmforge.json --to threat-dragon
tmforge convert imported.tmforge.json --to threat-dragon --out returned.threatdragon.json
```

Studio **Open File**, the HTTP read endpoint, WASM and MCP use the same reader. In browser Studio,
opening a Threat Dragon file through the writable file picker binds **Save** to that same file and
format, just as for `.tm7` and canonical JSON. Unsupported edits fail before a writable stream is
opened; there is no fallback that overwrites the file with another format. Without writable file
access, Save offers a destination or downloads a copy using the original name and format. Recovery
retains that name and format, but browser permissions require selecting a file again after reload.
**Export** remains available to create a separate copy or choose another format.
Schema/sample grounding uses
[Threat Dragon v2.6.2](https://github.com/OWASP/threat-dragon/tree/v2.6.2/ThreatDragonModels); tests use
a synthetic fixture covering the supported subset, not a claim that every v2 model is importable.

#### Export fidelity

Imported page, cell and threat identities survive import -> canonical JSON -> export -> import,
including empty pages. Threat display numbers are retained when supplied; missing numbers are
allocated in stable threat-ID order. Imported diagram IDs must be unique, nonnegative JavaScript-safe
integers. Older inputs using nonnumeric diagram IDs remain readable but are refused on export rather
than silently renumbered. New pages receive deterministic numeric IDs, so their original tmforge page
GUIDs are not a round-trip guarantee. Keep provenance fields when editing canonical JSON.

Export includes current names, model metadata, integer rectangles, page-local directed flows and
authored threats. Supported control fields come from the current model, not cached import values.
Other supported source data remains under `ThreatDragon.data.*`. Contributor display text is retained
as one contributor entry. Styling, routing vertices and original thumbnails are not reconstructed;
the output uses the target's default shapes and an empty thumbnail.
Saving back to an imported file uses this same bounded conversion, not byte-preserving native editing.
Review the import fidelity warning and keep the original when those omitted presentation fields matter.

The writer refuses content outside this mapping before writing any output bytes. CLI preflight
surfaces the same refusal before opening the destination, naming the unsupported field or object.
This includes:

- Custom stencils, unknown properties, line boundaries, authored connector bends or ports, and
  rectangles smaller than 10 units (the upstream schema's minimum).
- Unrepresentable control values such as `Encrypted=Unknown`; no missing control is invented and
  no unknown value is converted to `false`.
- Generated threats, unscoped or multi-target threats, inconsistent page/flow scopes, unsupported
  treatment states, extra threat properties and audit metadata.
- Assumptions, external dependencies, notes, validations, embedded knowledge bases, native
  threat-generation settings, and canonical analysis selections or expected rule-pack fingerprints.

Export does not run threat generation or copy transient analyzer findings into authored threats.
Both repeat exports of the same input and imported identities are covered by regression tests.

### `mermaid` and `dot` (starter-model import)

Import an existing architecture diagram through the same readers used by Studio, HTTP, WASM and
MCP. No Mermaid runtime, Graphviz executable, network access or additional package is required.
These formats are **input-only**; save the resulting model as `tmforge-json` or `tm7`.

```bash
tmforge preflight architecture.mmd --to tmforge-json
tmforge convert architecture.mmd --to tmforge-json --out architecture.tmforge.json
tmforge convert architecture.dot --to tm7 --out architecture.tm7
tmforge analyze architecture.tm7
```

**Mapping and evidence:** source nodes become processes by default. Mermaid cylinders (`id[(Label)]`)
and DOT `shape=cylinder` become data stores. A Mermaid inline class `:::process`, `:::store`,
`:::datastore` or `:::external`, or a DOT `kind` attribute with one of those values, explicitly
selects the DFD kind. Kind annotations take precedence over shape hints. Names such as "User",
"Database" or "HTTPS" do not establish a kind or a security control.

Directed edges become flows. Named Mermaid subgraphs and DOT `subgraph cluster_*` groups become
rectangular trust boundaries, including nesting. This is a **modeling assumption, not proof of
enforced isolation**: review the imported boundaries. A node cannot belong to unrelated sibling
groups, and edges to subgraphs rather than component nodes are refused.

Control-like properties whose schema permits `Unknown` are initialized to `Unknown`; free-text
properties remain unset. In particular, an edge labeled "HTTPS" still has `Protocol=Unknown`.
The model is analyzable immediately, but remains a skeleton requiring evidence and human review.
Preflight always reports `import.structural-mapping` so Studio asks for confirmation and CLI
`--fail-on-loss` refuses it before writing.

**Supported Mermaid subset:** one `flowchart` or `graph` with `LR`, `RL`, `TB`, `TD` or `BT`;
newline/semicolon-separated statements; `%%` comments; bare nodes and plain/quoted labels;
rectangle, rounded, stadium, subroutine, circle, diamond, hexagon and cylinder syntax;
directed `-->`, `-.->` and `==>` edges, chains, `-->|label|`, `-- label -->`, `-. label .->`
and `== label ==>`; `subgraph id [Label]` or `subgraph id`, closed by `end`; and subgraph
`direction`. A single fenced `mermaid` block is accepted, without surrounding Markdown.

```mermaid
flowchart LR
  caller[Caller]:::external
  subgraph service[Service]
    api[API] -->|query| db[(Database)]
  end
  caller -->|request| api
```

**Supported DOT subset:** a non-strict `digraph`, optionally named; case-insensitive keywords;
plain/numeric or double-quoted identifiers; `//` and `/* ... */` comments; directed `->` edges
and chains; repeated node declarations; nested, uniquely named `cluster_*` subgraphs; bracketed
attributes and graph assignments. Node/edge defaults are scoped and apply when an object is first
created; graph labels are inherited when a subgraph is created. Labels support escaped quotes,
backslashes and `\n`/`\l`/`\r` line breaks. Quoted identifiers accept escaped quotes, but other
identifier escapes are refused rather than reinterpreted.

```dot
digraph Service {
  caller [label="Caller", kind=external];
  subgraph cluster_service {
    label="Service";
    api [label="API"];
    db [label="Database", shape=cylinder];
    api -> db [label="query", id=query];
  }
  caller -> api [label="request", id=request];
}
```

DOT maps `label`, node `kind`/`shape`, and optional explicit edge `id`. `dir` must be `forward`.
The accepted basic shapes are `box`, `rect`, `rectangle`, `ellipse`, `circle`, `doublecircle`,
`diamond`, `hexagon`, `oval`, `plaintext`, `plain`, `none`, and `cylinder`.
Accepted presentation-only attributes are `color`, `fontname`, `fontsize`, `fontcolor`, `penwidth`,
`style`; graph `rankdir`, `ranksep`, `nodesep`, `bgcolor`, `labelloc`, `labeljust`; node `fillcolor`,
`width`, `height`, `fixedsize`, `margin`; and edge `arrowhead`, `arrowsize`, `constraint`, `weight`,
`minlen`. These are deliberately not retained, and `style=invis` is refused.

**Refused:** other Mermaid diagram grammars, front matter, initialization/styling/click directives,
unlisted classes or shape syntax, Markdown/HTML/entity labels, edge IDs/metadata, grouped endpoints,
invisible/undirected/bidirectional or extended-length links; DOT strict/undirected graphs,
anonymous/non-cluster/reopened subgraphs, endpoint sets, ports/compass points, HTML/record shapes,
string concatenation, dynamic label escapes such as `\N`, preprocessor lines and unlisted attributes
(including URLs and images). Unsupported syntax refuses the whole import with a line, column and
specific reason. Nothing executes embedded callbacks or resolves external resources.

**Identity and geometry:** page, node and boundary IDs use `DeterministicGuid` with distinct source
namespaces, so relabeling does not renumber objects. Nodes retain `Source.Format` and `Source.Id`.
DOT edge `id` is preferred when present, must be unique, and cannot label an entire chain.
Otherwise flow identity uses the ordered source/target IDs plus the occurrence within that pair.
Unrelated edges do not renumber existing flows; reordering parallel same-endpoint edges can, so use
explicit DOT edge IDs when those flows need independent stable identity. Reimport is not a merge
with an edited model: retain the canonical model and use diff/compare to review source changes.

The existing deterministic layout engine regenerates geometry while preserving nested membership.
Source direction, dimensions, colors, line styles and routing are not reproduced. Two imports of
identical input produce byte-identical native output. Limits are 8 MiB of strict UTF-8 (optional
BOM), 256 nodes plus boundaries, 512 edges, 16 nested subgraphs, 2,048 characters per identifier or
label, 10,000 statements and 128 assignments per attribute-list sequence. Content detection examines
the first 4 KiB; use an explicit preflight format for a source with a longer comment preamble.

## Preflight and import diagnostics

Run `tmforge preflight <file> [--to <format>]` before migrating a model. It inspects raw input before
deserialization can hide misspelled fields, duplicate identities, or unresolved flows, then reports
known losses for the selected destination. Preflight is **document validation, not security
analysis**. A passing result does not claim that the design is secure or every foreign extension
can round-trip.

- Canonical JSON rejects duplicate JSON fields, empty or colliding page/element/flow identities,
  unknown element kinds, invalid field types, incomplete component sizes, and dangling/cross-page
  flows. References are checked before any connector can disappear during reconstruction.
- Manifest JSON rejects unknown fields, including `properties` where `props` is required. Custom
  keys inside `props` remain governed by existing property policy. `--force` does not bypass field
  spelling or JSON integrity checks. Legacy unversioned manifests remain supported when explicitly
  selected.
- Canonical extension fields remain readable for compatibility, but receive path-specific warnings
  that they are not represented by the engine and may be lost on conversion. Studio's existing
  flow handles and label offsets, custom property bags, and expected rule-pack fingerprints are
  recognized fields, not spelling errors.
- Draw.io input with missing/compressed graph content is refused rather than imported as an empty
  diagram. Use an uncompressed XML export. Duplicate cells and broken attached-flow endpoints are
  refused; preflight names free-standing lines omitted by the reader and unfamiliar shapes whose
  kinds are inferred.
- Visio preflight names shapes treated as annotations rather than model objects. Invalid/duplicate
  shape ids and broken connector attachments are refused; the existing bounded page-catalog and
  archive checks remain in force.

Conversion diagnostics identify known losses such as line boundaries and embedded knowledge bases
when projecting into canonical JSON; threat-register, property, identity and metadata loss when
exporting diagrams; rule settings not carried by a conversion; and TM7 coordinate translation.
These are conservative checks of the supported mappings, not a complete semantic diff or an
openability guarantee from another product. Retain the source document when warnings apply.

The command, API, WASM and MCP return the same diagnostic codes, severities, paths and messages.
Studio reviews warnings before **Open File**, **Save** with an engine, or **Export** continues;
blocking errors stop the normal operation. Rejection and cancellation leave the current workspace
unchanged. Native JSON saves retain the Studio wire model rather than performing a format
conversion, so they do not warn about losing their own analysis settings.

For TM7 imports whose only errors are unattached or cross-page flow endpoints, Studio and the
VS Code extension offer **Import recovery copy** after explicit review. This creates a separate,
unsaved canonical model with the broken flows and threats scoped to them omitted. No endpoints
are guessed or reconnected. Native-only content, including the embedded template, full generated
register and line trust boundaries, stays in the original file; conversion warnings describe these
losses. Review the copy against the original before relying on its analysis.

The original is never bound as the recovery copy's save destination. Recovery does not override
malformed XML, duplicate or empty identities, size/depth limits, or an exhausted diagnostic budget.
Ordinary preflight, saves, exports, CLI conversion and other formats retain their strict behavior.

Preflight and CLI conversion accept at most 8 MiB of source content. Canonical JSON reads are strict
UTF-8 with an optional BOM and a nesting limit of 64. At most 100 diagnostics are returned, with an
explicit error if the diagnostic budget is exhausted. Correct the reported problems and rerun.

## Converting

### CLI

```bash
tmforge convert <input> --to <format> --out <path>
```

The target is chosen by `--to`, or inferred from the `--out` extension.

Errors found by preflight block conversion before the output file is opened. Warnings are emitted
before writing and included in `--json` output. Use `--fail-on-loss` to refuse warnings as well, or
the read-only `preflight --to` command to review them first. Existing source and output files are
not changed by preflight or by a refused conversion.

```bash
tmforge convert model.tm7 --to drawio --out model.drawio
tmforge convert model.tm7 --to vsdx   --out model.vsdx
tmforge convert model.drawio --to tm7 --out model.tm7
tmforge convert model.tm7 --to tmforge-json --out model.tmforge.json
```

See the [CLI reference](cli-reference.md#convert).

### API

```http
POST /v1/model/convert?to=<format>     # convert to a writable format
POST /v1/model/export/tm7              # export a .tm7 specifically
POST /v1/model/save/tm7                # preserve an original .tm7 while applying edits
POST /v1/detect                        # sniff a file's format from its bytes
```

See the [API reference](api-reference.md).

### Studio

Studio uses `tmforge-json` for the canvas. Browser-opened `.tm7` files retain a separate native
backing document: Save applies supported edits to that document instead of reconstructing it from
the canvas. Unchanged saves return the original bytes; edited saves preserve unedited XML data,
existing template customizations and unaffected threat decisions. Missing definitions are added as
needed, and new generated-threat decisions use the active rules. Deleting an object or flow also
deletes its scoped threats and decisions. Unrelated and model-wide threats remain; undo restores
the deleted graph and decisions together during the editing session. No retirement state or
permanent deleted-ID list is required. Studio-only layout and analysis settings are
retained in a versioned, fingerprinted XML extension; this is also written on new exports when
needed. Native geometry can be translated for MTMT while Studio restores the authored positions.
Invalid references and unrecognized extension versions fail before writing. Explicit JSON/diagram exports and URL shares remain
structural conversions and do not carry the native backing document.

Native XML preservation validates the `ThreatModel` root name and namespace against a trusted,
compiled envelope schema. The body remains extensible so unknown native XML can survive edits;
the typed model reader and structural preflight validate the data used by the engine. Both the
original document and any previous-save input reject DTDs, external resource resolution, and XML
deeper than 128 levels, with an 8 MiB input limit. Inline schemas and `xsi:schemaLocation` values
never replace the trusted schema or cause resource retrieval.

**Open File** uses the active API or in-browser WASM
engine to read `.tm7`, `.drawio`, `.vsdx`, supported Threat Dragon JSON, Mermaid and DOT. Read-only inputs save
as new tmforge files, not back to their original format. The browser canvas itself does not parse
foreign file formats. See the [Studio guide](studio-guide.md#importing-and-exporting).

The VS Code editor uses the same preserving engine operation, with the current text document as
its native source and VS Code managing saves and undo. It does not use browser recovery storage.

## Choosing a format

| Goal | Use |
| --- | --- |
| Exchange with the Microsoft Threat Modeling Tool, or store the source of truth | `tm7` |
| Move a diagram between Studio and the CLI/API | `tmforge-json` |
| Share an editable diagram with draw.io / diagrams.net users | `drawio` |
| Share an editable diagram with Visio users | `vsdx` |

> **Tip:** retain `.tm7` as the source when native template/register data matters, or use canonical
> JSON or a manifest for a model-as-code workflow. Generate `.drawio` / `.vsdx` for sharing.
> Converting *from* a structural format *to* `.tm7` only reconstructs the structure the source captured.

## Extending

Formats are pluggable: a provider implements the format contract (`Id`, extensions, capabilities,
read/write, and content sniffing) and registers with the format registry. The tools depend on the
registry rather than any single format, so adding one doesn't touch the CLI, API, or Studio.

## See also

- [CLI reference: `convert`](cli-reference.md#convert)
- [Engine API reference](api-reference.md)
