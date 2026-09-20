# Studio guide

**Studio** is the Threat Model Forge browser front end: a React single-page app whose data-flow-diagram
(DFD) canvas is built on [React Flow](https://reactflow.dev). It talks to the real .NET engine over
the versioned [`/v1` API](api-reference.md), and the API serves Studio from its root, so the UI and
engine ship as one artifact.

## Launch Studio

The fastest way to try Studio is the hosted, no-install
**[browser demo](https://hacks4snacks.github.io/tmforge/)**, where the .NET engine runs entirely in
your browser via WebAssembly.

To run it locally, the engine API hosts Studio. The quickest way is the container image:

```bash
docker run --rm -p 8080:8080 tmforge      # then open http://localhost:8080/
```

Or run the API from source, which serves the built SPA at its root:

```bash
dotnet run --project src/ThreatModelForge.Api    # http://localhost:5205/
```

See [Deployment](deployment.md) for hosting options.

## The canvas

Studio gives you a DFD canvas with a stencil palette, an inspector, and engine-backed validation.

### Stencils

Drag any of the four DFD stencils from the palette onto the canvas:

| Stencil | Represents |
| --- | --- |
| **Process** | Code that acts on data (a service, API, function). |
| **Data Store** | Where data rests (database, queue, cache, bucket). |
| **External Entity** | An actor or system outside your control (user, browser, third party). |
| **Trust Boundary** | A resizable region where the trust level changes (VNet, DMZ, subnet). |

### Drawing data flows

Hover a node to reveal its ports, then drag from any port to another node. Connections use React
Flow's **loose** mode, so a flow can start or end on any side of a node. You focus on the logical
connection, not the geometry.

### Editing

| Action | How |
| --- | --- |
| Rename a node or flow | Double-click it and type. |
| Select several objects | Hold `Cmd` (`Ctrl` on Windows/Linux) and click, or drag a selection box with `Shift`. |
| Delete the selection | `Delete` key. Deleting an element takes its flows with it, and the whole deletion is a single undo step. |
| Resize a trust boundary | Drag its handles (it's a resizable region). |
| Tidy the diagram | Click **Tidy** to clean up the existing arrangement: fit text, separate overlaps, route flows and deconflict labels. The adjacent **Tidy options** menu offers offline **Labels only** with fixed rectangles. |
| Pan / zoom | Drag the canvas / scroll; use the minimap and **fit** control to navigate. |
| Step through the flows | `Alt+↓` / `Alt+↑` selects the next / previous flow in the outline's order. |
| Undo / redo | `Cmd+Z` / `Shift+Cmd+Z` (covers every edit). |

Arrangement applies to the **active page**, as one undo step. A failed or unsafe candidate changes
nothing and consumes no undo step. If an edit or page switch occurs while the engine is working,
the response is discarded rather than overwriting newer work. Repeating an unchanged arrangement is
a no-op.

**Tidy preserves the author's arrangement**, using the released Studio cleanup algorithm. It does
not move an already horizontal sketch into graph layers or shrink boundaries around newly ordered
groups. Objects move only as text fitting and overlap separation require. The engine validates the
proposed rectangles without rearranging them again, so the boundary-safety checks still apply.

Studio does not offer full layout rearrangement. The CLI's explicit `layout` command remains
available for callers that want to generate placement rather than tidy an existing drawing.

The engine preserves the **actual geometric trust claims**, including all memberships when regions
overlap; it never chooses one claim and discards another. If the candidate cannot preserve them,
Studio explains the refusal. Use **Labels only**, or edit the boundary placement explicitly before
trying again. Opening a file now preserves its shape and boundary rectangles: automatic import
cleanup is limited to visual routing and label offsets. Text-fit sizing requires an explicit
arrangement so importing a model cannot silently change analysis.

A single-page model can still contain a detached flow. An imported connector whose source or target
id is all zeros is not attached to an element. Tidy names the affected flow and endpoint; reconnect
it in the source model, or remove the flow if it is unintended. Tidy never guesses the missing target
or silently drops the connection. **Labels only** remains available without rearranging shapes.

### Pages

A model can hold several diagrams. The **page tab strip** below the canvas lets you work across them:

| Action | How |
| --- | --- |
| Switch pages | Click a tab. |
| Add a page | Click **+**. |
| Rename a page | Double-click the tab (or press `F2`) and type. |
| Reorder pages | Drag a tab. |
| Delete a page | Click the tab's **×** (the last page can't be deleted). |

Each page is an independent canvas with its own undo history; the active page and every page's
contents persist across reloads. Opening a multi-page `.tm7`, `.drawio`, or Visio model (imported via
the CLI or API into `tmforge-json`) shows each source diagram on its own page.

### Reviewing a large model

A big diagram is drawn wherever the shapes fit, so on the canvas alone there is no reliable reading
order: trust boundaries sit where they were placed rather than in sequence, and working out which
flow follows which means tracing lines by eye. Two controls at the top-left of the canvas turn the
same model into something you can read in order.

**Find element** searches every element and flow across all pages by name or kind. Picking a result
switches to its page, selects it, and frames it in view.

**Outline** lists the page itself:

| Part | What it gives you |
| --- | --- |
| Flows | Every flow, numbered in the review order, with `source -> target` and the trust boundaries it crosses. |
| Objects | Every process, data store, and external entity grouped under the trust boundary it sits in, with its kind and how many flows touch it — so an unconnected object or an empty boundary is obvious. |
| Order | **Model order** lists things as the file stores them; **Name order** sorts by name with numbers compared as numbers, so `F2` comes before `F10`. Your choice is remembered. |
| Boundary-crossing only | Hides the flows that stay inside one boundary. Positions do not renumber, so a flow keeps the same number whether or not the filter is on. |

Click any row to select it on the canvas, frame it, and highlight it the same way a picked finding is
highlighted. A flow lights up together with both of its endpoints, so what it connects is obvious at
a glance; clicking empty canvas clears the highlight. The selection runs both ways: selecting
something on the canvas marks its row in the outline and scrolls the list to it.

The **◂ ▸** stepper (or `Alt+↓` / `Alt+↑` anywhere on the canvas) walks the flows one at a time in
the listed order, wrapping at either end, so a review can be worked through flow by flow instead of
hunted for. Each step also opens that flow in the inspector, so its properties are right there while
you read it.

The outline groups an object by its authored `Boundary` property when it has one, and otherwise by
the smallest boundary region containing its center. Arrangement instead preserves the complete
geometry-derived membership set used for analysis. If a declared property disagrees with the
drawing, resolve that disagreement explicitly rather than relying on Tidy to change the trust claim.

### The inspector

The right-hand panel edits the selected elements or flows. It is **schema-driven**: it lists a typed
control for every property the engine declares for that primitive, so every property an analysis
rule can read is reachable, and you can clear any finding without leaving the canvas. A data flow,
for example, exposes **Protocol**, **Port**, **Channel**, **DataType**, **Algorithm**, **Identity**,
and more; a process exposes **AuthenticationScheme**, **Isolation**, **SanitizesInput**, and so on.
Enum and boolean properties render as dropdowns of canonical values (so the value always matches what
the rules expect); free-form properties render as text fields. You can also add arbitrary custom
properties below the typed ones.

Every control-like dropdown offers **Unknown** as its first value, and it is the default. Pick it when
nobody has established the answer yet — it is different from `No`/`None`, which state that you checked
and the control is not there. `Unknown` does **not** clear a finding: the rule still reports, and says
the property is not evidenced rather than that the control is absent. See
[`Unknown` and the three states of a control](analysis-rules.md#unknown-and-the-three-states-of-a-control).

#### Editing several objects at once

Select any number of elements of the same kind, or any number of data flows, and the inspector edits
all of them. Each control writes the whole selection in one step, so one change is one undo.

A property the selection disagrees about shows as **(mixed)** rather than picking one object's value
to display. `(mixed)` cannot be chosen, so simply opening the inspector on a mixed selection never
flattens it — only a property you actually change is written, and the rest are left as they are.
Clearing a property to **(none)** removes it from every selected object.

Names are not offered across a selection: a name identifies one thing, so renaming several objects to
the same string is not an edit worth making. Delete still applies to the whole selection.

Two cases deliberately offer delete but no property editing:

- **Mixed kinds** (say processes and data stores together). The same property name does not accept
  the same values on every kind — `AuthenticationScheme` allows `Token` and `PublicKey` on an
  external entity but not on a process — so one shared control would offer values the schema rejects
  for part of the selection. Narrow the selection to one kind.
- **Elements and flows together.** They have no properties in common at all.

## Comparing model revisions

Choose **Compare** in the toolbar to open **Model Review**, a separate read-only workspace.
Select a **baseline** file, then compare it with the snapshot of your current canvas or choose a
**proposed** file. Both sides accept the same model formats and explicitly versioned authoring
manifests as Open File. Preflight blocks invalid input and requires confirmation for known import
losses; acknowledged diagnostics stay visible beside the comparison.

The change list has three categories:

| Category | What is compared |
| --- | --- |
| Structure | Added/removed objects and pages; names, kinds, properties, flow endpoints, page names, and objects moving between pages. Added/removed objects include their attribute values. |
| Boundary crossings | Flows whose geometry-derived set of crossed trust boundaries changed, including added/removed crossing flows. Pure layout changes are otherwise quiet. |
| Findings | Introduced, resolved, and reclassified findings using stable finding ids; reclassification means severity or disposition changed. Unchanged findings are counted separately. |

Select a change to highlight and frame its objects on both diagrams, with independent page selectors
and pan/zoom controls. Flow changes include their endpoints; crossing changes also highlight the
affected boundaries. A deleted object remains navigable on the baseline side. Filter the list by
category or text, or step through it with the previous/next controls. Large lists show 100 rows at a
time. On narrow screens the diagrams stack vertically.

Both models are analyzed **now**, once each, with the same active engine and custom rule bundle,
honoring each model's own disabled-rule settings. This is not a replay of historical analysis.
Different effective rule selections produce a warning. Missing packs, failed analysis, or different
source-id representations make the findings comparison explicitly **unavailable**, never an empty
delta or a list of apparent resolutions. Objects match by stable identity, not name; unrelated
identities and conversion losses are disclosed.

Review does not compare the complete threat register, manual-threat content, priority, justification,
model metadata, or visual-only edits. Metadata and author-owned threat-record differences produce
scope warnings. Accepting or mitigating a currently detected threat is a finding reclassification,
not a resolved condition. Keep the original files for content outside the canonical model.

Review never merges, saves, changes triage, or consumes editor undo history. Its file selections do
not replace the working canvas or bind writable handles. Closing it returns to the existing editor;
late results from an abandoned comparison are discarded. Compare requires a ready API or WASM engine.

Each input is limited to 8 MiB, 32 pages, 1,024 elements, 2,048 flows, and 1,000,000 flow/boundary
pairs. Comparisons exceeding 10,000 changes are refused rather than silently truncated. See the
[comparison API](api-reference.md#model-comparison) for the shared result contract.

## Validating against the engine

Click **Analyze** to send the whole model (every page) to the live `/v1` engine. Findings come back
and are **overlaid on the offending nodes and edges**, so you can see exactly what to fix. In a
multi-page model, tabs that carry findings are badged. Click a threat or finding to narrow the overlay
to only the objects it impacts and jump to their page. Open the inspector, set the missing property
(e.g. a flow's protocol), and re-analyze.

If the engine is offline, Studio falls back to an offline stub so the canvas keeps working; connect
it to a running API to get the real rule set. See [Analysis rules & CI](analysis-rules.md) for
what the rules check.

### Custom rule packs

Open **Analysis Rules** and choose **Load rule pack…** to analyze against your own declarative pack
(`*.tmrules.json`) alongside the built-in rules. The in-browser engine loads the pack locally — the
file is never uploaded — and the panel then lists each pack that loaded with its id, version, rule
count, and content fingerprint, plus any diagnostic the loader raised. A pack that fails to parse
says so instead of quietly leaving you on the built-in rules.

Loading a pack also **pins it in the model**: the saved `.tmforge.json` records the pack id and
fingerprint. If the model is later analyzed without that pack, or the pack's content changed,
analysis reports an error finding rather than looking clean. **Use built-in rules** clears both the
loaded pack and the pin.

When Studio is talking to a `/v1` API instead of the in-browser engine, rule packs are the server's
configuration, so the loader reports that rather than pretending a local pack took effect — see
[the API reference](api-reference.md#custom-rule-packs).

## Authoring & editing threats

**Analyze** also returns the model's **STRIDE threat register** — the threat-bearing findings framed as
threats, grouped by category. Each threat is **editable inline**: click **Edit** to set its

- **title** — your wording in place of the rule's; clear it to restore the rule's;
- **state** — Open, Needs investigation, Mitigated, or Accepted (accepting reveals a justification field);
- **priority** — Critical / High / Medium / Low;
- **description** and **mitigation** notes.

The **category** control is disabled for a rule-derived threat, and says so. Its category is what the
analysis concluded, not an opinion held separately from the rules — editing it would record a claim
the rule set does not support. A manual threat has no rule behind it, so its author owns its category
as well as its title.

Retitling a rule threat changes nothing a later run depends on: the rule keeps detecting it, and the
threat keeps the identity that the analysis document, SARIF fingerprints, and the `.tm7` register key
are all built on.

Click **+ Add threat** to author a **manual threat** the rules do not detect: give it a title, a STRIDE
category, and a scope — a specific element or flow, or model-wide. Manual threats are badged **Manual**
and can be **deleted**; rule-derived threats cannot.

Your edits and manual threats are **persisted on the model** and round-trip through `tmforge-json` into
the `.tm7` register (see [Formats](formats.md#tmforge-json-canonical-wire-model)), so a threat you accept
or author survives an export and opens in the Microsoft Threat Modeling Tool. The register itself is
regenerated from the rules on demand — only your author-owned overlay (edits and manual threats) is
stored on the wire.

> **Editing a rule threat relies on stable element ids.** A rule threat's edit is keyed by the id of the
> element it targets. Studio nodes keep stable ids, so edits persist across re-analysis; if you delete
> and recreate the underlying element (giving it a new id), its rule threat is a fresh threat and the
> earlier edit no longer applies. Manual threats are keyed independently and are unaffected.

## Downloading reports

The **Report** menu offers every artifact the engine can render, and it renders them with the same
effective rules and disabled selections the **Analyze** button used:

| Choice | Artifact | Use it for |
| --- | --- | --- |
| Threat model report | HTML | The document a reviewer reads: threats, mitigations, and a diagram per page. |
| Diagram only | SVG | Just the picture, every page stacked. It runs no analysis, so it is not a threat report. |
| Findings report | HTML | The analysis results in readable form. |
| Findings (SARIF) | SARIF 2.1.0 | Upload to code scanning, or attach to a build. |
| Findings (JSON) | JSON | Automation over the raw analysis report. |

The last three are the same artifacts [`tmforge analyze --reportFolder`](cli-reference.md#analyze)
writes, so evidence produced in Studio and evidence produced in CI are the same document. With the
in-browser engine they are generated locally — the model never leaves the page.

## Importing and exporting

Studio round-trips through the canonical **`tmforge-json`** wire model:

- **Export tmforge-json**: save the diagram as `.tmforge.json`, which the CLI and API speak
  natively.
- **Import JSON**: load a `.tmforge.json` document back onto the canvas.

This is the bridge between visual authoring and the [CLI](cli-reference.md): export from Studio,
then `tmforge analyze` / `tmforge report` / `tmforge convert` in a pipeline, or vice versa.

> **Format parsing lives in the engine, not the canvas.** Studio's active HTTP or in-browser WASM
> engine reads foreign formats through **Open File** and returns the canonical `tmforge-json`
> representation. The browser canvas does not maintain a second set of format parsers.

### Preflight review

Before replacing the canvas, **Open File** runs preflight through the active engine. Structural
errors appear with their source paths and must be corrected in the input. Known import losses appear
in a review dialog with **Continue** and **Cancel**. Closing or cancelling leaves the current model
and undo history unchanged; a delayed import is discarded if the workspace changes while it runs.

**Save** and **Export** also review known conversion losses before writing. Native JSON saves do not
perform the engine's structural conversion, so they retain the existing wire state. Importing a new
file requires the API or WASM engine to be ready; offline authoring and saving the current JSON
workspace remain available. These diagnostics are separate from **Analyze** and do not accept or
mitigate threats. See [preflight coverage and limits](formats.md#preflight-and-import-diagnostics).

### Opening an authoring manifest

**Open File** also accepts a declarative [authoring manifest](cli-reference.md#apply) — the
review-friendly source `tmforge apply` builds a model from. A manifest is not a model document, so it
has no registered format; Studio recognizes the `"schema": "tmforge-manifest"` declaration and asks
the engine to build it, exactly as the CLI does. A manifest that will not build is refused with the
engine's own reason (the unresolved alias, the rejected property value).

The model that opens is **not** bound back to the manifest file. Saving offers a `.tmforge.json` name
derived from the manifest's, so the reviewable source is never overwritten by the model built from
it. To change the model, edit the manifest and re-apply, or save the model as its own file.

> A manifest that declares no `schema` (the concise pre-envelope form) is still accepted by
> `tmforge apply`, but Studio cannot recognize it: every manifest field is optional, so a recognizer
> that accepted an absent envelope would claim any JSON file. Add the envelope to open it here.

### Opening Threat Dragon v2 JSON

**Open File** recognizes supported OWASP Threat Dragon v2 JSON through the active engine. Imported
threats appear as manual entries alongside tmforge-generated threats after **Analyze**, retaining
their original category, text, treatment and scope. Model metadata and threat provenance survive
saving, reopening and exporting to `.tm7`.

This is import-only: Studio does not bind the original file for overwriting. **Save** offers a new
`.tmforge.json` filename, and Threat Dragon is not offered as an export target. Keep the original
for Threat Dragon-specific content such as styling and routing.

The first delivery supports rectangular boundaries and directed flows. Curved boundaries,
bidirectional flows, fractional rectangles and unsupported treatment states are refused, with no
partial replacement of the current workspace. Out-of-scope flags remain source information and do
not disable tmforge rules. See the [full import contract](formats.md#threat-dragon-owasp-threat-dragon-v2-import)
before migrating a model.

### Opening Mermaid or DOT

**Open File** accepts Mermaid `.mmd`/`.mermaid` flowcharts and Graphviz `.dot`/`.gv` diagrams.
Preflight explains the starter-model mapping before **Continue** loads the diagram. Nodes and
directed edges become components and flows; nested subgraphs become trust boundaries. Review those
boundaries and the inferred kinds, then use **Analyze** to inspect missing control evidence.
Controls begin at `Unknown`, even when an edge label names a protocol.

Import regenerates layout and does not reproduce source styling. Unsupported syntax is named with
a line and column and blocks the entire import; cancellation or rejection leaves the workspace
unchanged. **Save** offers a new `.tmforge.json` file and never binds the source for overwriting.
Mermaid and DOT are not export targets. See the [supported subset](formats.md#mermaid-and-dot-starter-model-import).

## Merging edits from two branches

When two people edit the same model on different branches, click **Merge** in the toolbar to
reconcile them visually, the canvas equivalent of the [`tmforge merge`](cli-reference.md#merge) git
driver. The modal takes:

- **Ours**: your version.
- **Theirs**: the incoming version.
- **Base** *(optional)*: the common ancestor both edits started from, when you have it.

**With a base**, Studio runs the same identity-keyed three-way merge as the CLI: non-overlapping
changes (a rename on one side, a new data store on the other) combine automatically, and only genuine
**conflicts** (where both sides changed the same property) are listed. **Without a base** (often the
original isn't at hand), it falls back to a two-way merge: elements unique to either side are unioned,
and every element both versions changed differently is listed as a conflict for you to resolve; the
modal shows a notice to that effect.

Pick **Ours** or **Theirs** for each conflict (the default keeps yours), then **Load into editor** to
drop the resolved model onto the canvas, or **Download .tm7** to save it (the downloaded `.tm7` embeds
the knowledge base, so it opens in the Microsoft Threat Modeling Tool). Structural conflicts (an
element deleted on one side and edited on the other, or a data flow left dangling) keep your version
and are flagged for you to fix after loading.

> The merge matches elements by their stable id, so it is most reliable on real `.tm7` files (and on
> `.tmforge.json` exported by this build, which preserves ids).

## Local development

To hack on Studio itself with hot reload, run the Vite dev server against a locally running API:

```bash
# Terminal 1: the engine API (Studio calls it on :5205)
dotnet run --project src/ThreatModelForge.Api

# Terminal 2: the Studio dev server with hot reload
cd src/ThreatModelForge.Studio
npm install
npm run dev        # http://localhost:5199
```

During development the API allows CORS from the Vite dev server at `http://localhost:5199`.

### Regenerating the API client

Studio's typed client is generated from the engine's OpenAPI document, the single source of truth.
After the `/v1` contract changes, refresh it:

```bash
npm run gen:api    # openapi-typescript ../ThreatModelForge.Api/openapi/v1.json -> src/dfd/engine/schema.d.ts
```

### Stack

Vite + React 18 + TypeScript + `@xyflow/react` v12 (React Flow, MIT). No UI kit; plain CSS.

## See also

- [Engine API reference](api-reference.md): the `/v1` surface Studio depends on.
- [Formats & interoperability](formats.md): `tmforge-json` and the other formats.
- [CLI reference](cli-reference.md): drive the same engine headlessly.
