# CLI reference

The `tmforge` command-line tool inspects, authors, validates, reports on, and converts
`.tm7`-compatible threat models from a shell or CI pipeline. It is the headless face of the same
engine Studio uses, so agents and pipelines can drive threat models without a GUI.

```text
tmforge <command> [options] <file>
```

## Conventions

- **Options are GNU-style.** Every option accepts either `--name value` or `--name=value`.
- **`--json` everywhere.** Add `--json` to any command for a single machine-readable document on
  stdout (see [JSON output](#json-output)). Human text and diagnostics go to stderr, so
  `tmforge ... --json | jq` stays clean.
- **Help.** `tmforge --help` lists commands; `tmforge <command> --help` (also `-h`, `-?`) shows
  command-specific options.
- **Version.** `tmforge --version` prints the released version.
- **Elements and flows are addressed by GUID, alias, or unique name.** `add --alias <name>` gives an
  element a stable, citeable id plus a handle that `connect`/`set`/`remove`/`rename`/`show` resolve
  (they also accept a unique name). A flow declared with an alias in a
  [manifest](#declarative-manifest) is addressable the same way. Discover ids with `tmforge list` or
  the output of `add`.

## Command summary

| Command | Kind | Purpose |
| --- | --- | --- |
| [`open`](#open) | Inspect | Summarize a model (element / flow / threat counts). |
| [`list`](#list) | Inspect | List components, flows, boundaries, threats, or diagrams. |
| [`show`](#show) | Inspect | Show one element/flow's name, type, and properties. |
| [`stencils`](#stencils) | Inspect | List the built-in authoring stencils. |
| [`properties`](#properties) | Inspect | List the typed custom-property schema. |
| [`schema`](#schema) | Inspect | Describe the `--json` envelope and per-command output shapes. |
| [`render`](#render) | Inspect | Draw the diagram in the terminal. |
| [`diff`](#diff) | Inspect | Structurally compare two models (or emit a git textconv). |
| [`merge`](#merge) | Merge | Three-way merge two models against a common ancestor (git driver). |
| [`git-setup`](#git-setup) | Git | Wire git to use tmforge for .tm7 diff/merge (no committed .gitattributes needed). |
| [`new`](#new) | Author | Create a new model (empty or from a template). |
| [`add`](#add) | Author | Add a process, store, external entity, or boundary. |
| [`connect`](#connect) | Author | Add a data flow between two elements. |
| [`remove`](#remove) | Author | Remove an element (and its connected flows). |
| [`rename`](#rename) | Author | Rename an element. |
| [`set`](#set) | Author | Set an element/flow's name or properties. |
| [`page`](#page) | Author | List, add, rename, reorder, or remove pages (diagrams). |
| [`layout`](#layout) | Author | Auto-lay-out the diagram (layered, boundary aware; places flow labels). |
| [`rules`](#rules) | Analyze | Compile an MTMT `.tb7` template into a versioned rule pack. |
| [`analyze`](#analyze) | Analyze | Evaluate the analysis rules against a model. |
| [`analysis`](#analysis) | Analyze | Validate a stored analysis document (and check whether it is stale), or compare two of them. |
| [`threats`](#threats) | Analyze | Report or author threats — the persisted, triaged view of the findings (`--write` to persist; `--add`/`--edit`/`--remove` to author). |
| [`accept`](#accept) | Analyze | Accept a generated threat's risk (records a justification). |
| [`report`](#report) | Report | Generate a self-contained HTML report. |
| [`convert`](#convert) | Convert | Convert a model between file formats. |
| [`apply`](#apply) | Author | Build a model from a declarative JSON manifest (all-or-nothing). |
| [`export`](#export) | Author | Export a model as a declarative JSON manifest. |
| [`mcp`](#mcp) | Agent | Run an MCP server over stdio (exposes the engine + authoring facade as tools). |

---

## Inspection commands

### `open`

Summarize a model: counts of elements, flows, and threats.

```text
tmforge open [--json] [--rules <path>] <input>
```

```bash
tmforge open payments.tm7
tmforge open payments.tm7 --json
tmforge open payments.tm7 --rules corporate.rules.json   # recognize a custom pack's threats
```

#### Threat counts are split by origin and standing

The register is append-only: applying a generation result never deletes, so triage is never lost when
a rule stops firing. The cost is that a left-over entry looks exactly like a live one. `open`
therefore classifies the register against one analysis run and reports four counts:

| Count | Meaning |
| --- | --- |
| `manual` | Entries an author wrote by hand. Rules never produce or retire them. |
| `persistedGenerated` | Rule-derived entries stored in the model's register. |
| `currentGenerated` | Threats the current rules produce, stored or not. Exceeds `persistedGenerated` when the register has not been written since the model changed. |
| `staleGenerated` | Stored entries the current rules no longer produce. |

These are **not a partition and must not be summed** — each answers a different question, and one
threat can appear in more than one.

A stored entry whose rule is absent from the effective bundle or disabled for the run is counted in
`indeterminateGenerated` and its rule named in `unavailableRuleIds`. It is never called stale: a rule
that was not given the chance to fire says nothing about the model, so treating its entries as stale
would invite deleting real findings after a mistyped `--rules` path or a disabled pack. Pass
`--rules` so a custom pack's threats are recognized rather than reported as unavailable.

The full register lives in `.tm7`. `tmforge-json` deliberately persists only author-owned state
(triage and manual threats), so `persistedGenerated` is zero for a model held in that format.

### `list`

List entities of a chosen kind.

```text
tmforge list <components|flows|boundaries|threats|diagrams> [--json] <input>
```

| Noun | Lists |
| --- | --- |
| `components` | Processes, data stores, and external entities (with GUIDs). |
| `flows` | Data flows and their endpoints. |
| `boundaries` | Trust boundaries. |
| `threats` | Threats stored in the model (e.g. authored in MTMT), with each entry's **standing**. |
| `diagrams` | Diagrams in the model. |

```bash
tmforge list components payments.tm7
tmforge list flows payments.tm7 --json
```

### `show`

Show a single element or flow by GUID: its name, type, and custom properties. Use it to inspect the
values a rule reads (for example a flow's `Protocol` / `Port`) before fixing a finding with
[`set`](#set).

```text
tmforge show --id <guid> [--json] <input>
```

```bash
tmforge show payments.tm7 --id <guid>
tmforge show payments.tm7 --id <guid> --json
```

### `stencils`

List the built-in authoring stencils and the ids you pass to `add --stencil`.

```text
tmforge stencils [--pack <id>] [--json]
```

```bash
tmforge stencils
tmforge stencils --pack azure --json
```

### `properties`

List the built-in **typed property schema**: the custom properties the linter reads and Studio
edits, with each property's value kind, allowed values, and default. This is the same schema the API
serves at `GET /v1/property-schema`; use it to discover closed enums (for example `Channel`,
`Encrypted`, `AccessControl`, or the approved cipher list) without running `analyze` first.

```text
tmforge properties [--base <process|datastore|external|flow>] [--explain] [--rules <path>] [--json]
```

```bash
tmforge properties
tmforge properties --base flow
tmforge properties --base datastore --json | jq '.data.properties'
```

Add `--explain` to map each property **value** to the rule id and severity it triggers, so you can
predict analysis behavior before running [`analyze`](#analyze). A value shown as `(unset/condition)` means the
rule fires when the property is absent or by a computed condition. Pass `--rules <path>` to fold your
[custom declarative rules](analysis-rules.md#authoring-custom-rules-declarative) into the explanation.

```bash
tmforge properties --base flow --explain
tmforge properties --base external --explain --json | jq '.data.explain'
```

### `schema`

Describe the machine-readable [`--json`](#json-output) envelope and the `data` payload shape of every
command, so automation can be written against a documented contract instead of shapes discovered by
probing output.

```text
tmforge schema [--json]
```

```bash
tmforge schema
tmforge schema --json | jq '.data.commands'
```

### `render`

Draw the first diagram in the terminal. Defaults to Unicode/ANSI; `--plain` uses ASCII only.
Boxes are clamped to the canvas (and to their enclosing trust boundary), so labels aren't clipped
or drawn over a boundary wall.

```text
tmforge render [--plain] [--width <n>] [--height <n>] <file>
```

| Option | Default | Range | Meaning |
| --- | --- | --- | --- |
| `--width <n>` | 100 | 20-400 | Canvas width in columns. |
| `--height <n>` | 30 | 10-200 | Canvas height in rows. |
| `--plain` | off | n/a | ASCII output (no Unicode/ANSI). |

```bash
tmforge render payments.tm7
tmforge render payments.tm7 --plain --width 120
```

### `diff`

Structurally compare two models, matched by each element's **stable id**, so re-layout or
re-serialization produces no diff, and a rename shows as a single modification rather than a
delete-plus-add. Reports added, removed, and modified elements, with per-property changes for
modifications. Geometry (position and size) is ignored.

```text
tmforge diff [--json] <base> <revised>
tmforge diff --textconv <model>
```

```bash
tmforge diff payments.v1.tm7 payments.v2.tm7
tmforge diff payments.v1.tm7 payments.v2.tm7 --json
```

Identity is preserved in `.tm7`; other formats do not round-trip element ids, so `diff` is most
useful on `.tm7`.

#### Trust boundary crossings

Ignoring geometry is what keeps the structural diff quiet when a model is merely re-laid-out, but
**which trust boundaries a flow crosses is derived from geometry**. Dragging a data store out of its
boundary changes no stored property at all, so on the structural comparison alone that edit is
indistinguishable from no edit — while being the single change most likely to matter in review.

`diff` therefore reports crossings as their own section:

```text
Boundary crossings:
  ~ flow "Browse & checkout" [Diagram 1]  6bf80ac0-f21b-46b4-ae4f-bafb8beef13a
      - no longer crosses "Public Internet"
      + now crosses "Partner Network"

0 added, 0 removed, 0 modified, 1 with changed boundary crossings.
```

Flows and boundaries are matched by id, so renaming a boundary is not a crossing change. A flow that
was added or deleted is labelled as such, and one that never crossed anything is left out — the
element sections already report it, and repeating it here would bury the crossings that carry the
signal. Under `--json` the same information appears as `data.crossings`, counted in
`data.summary.crossingChanges`.

#### Readable `.tm7` diffs in git

`--textconv` prints a canonical, deterministic outline of a **single** model. Wired as a git
[textconv](https://git-scm.com/docs/gitattributes#_generating_diff_text_via_textconv) it makes
`git diff`, `git log -p`, and pull requests render `.tm7` changes as readable structure instead of
opaque XML. Enable it once per clone:

```gitattributes
# .gitattributes (shipped in this repo)
*.tm7 diff=tmforge
```

```bash
git config diff.tmforge.textconv "tmforge diff --textconv"
```

Afterwards, `git diff` on a `.tm7` shows lines such as `process "API Gateway"  <id>` and
`Protocol=HTTPS`, so a reviewer sees exactly what changed.

> The committed `.gitattributes` is **optional**; you don't need this repository's source. Run
> [`tmforge git-setup`](#git-setup) to apply the config and a local (or global) mapping for you.

### `merge`

Three-way merge two edited models against their common ancestor, matched by element id.
Non-overlapping edits from both sides combine automatically; genuine conflicts (both sides changed
the same attribute, or one side deleted what the other modified) keep the `ours` value, are reported,
and are written to `<pathname>.conflicts.json`. The merged model is always valid; it never contains
textual conflict markers. The exit code is `0` on a clean merge and `1` when conflicts remain.

```text
tmforge merge <base> <ours> <theirs> [<pathname>] [--output <path>] [--json]
```

```bash
tmforge merge base.tm7 ours.tm7 theirs.tm7 --output merged.tm7
```

By default the result is written back to `<ours>`. Resolve any reported conflicts with
`tmforge set --id <guid> ...`.

#### Use as a git merge driver

Wire it up so `git merge`, `rebase`, and `cherry-pick` deconflict `.tm7` automatically:

```gitattributes
# .gitattributes (shipped in this repo)
*.tm7 merge=tmforge
```

```bash
git config merge.tmforge.name   "Threat Model Forge semantic merge"
git config merge.tmforge.driver "tmforge merge %O %A %B %P"
```

Git invokes the driver with the ancestor (`%O`), our version (`%A`, also where the result is
written), their version (`%B`), and the path (`%P`). A clean merge is applied silently; on conflict
the file keeps `ours` and the conflicts are listed on the console and in the sidecar.

### `git-setup`

Wire git to use tmforge for `.tm7` diffs and merges, **without** a committed `.gitattributes` and
**without** access to any repository's source. It registers the diff textconv and merge driver in
git config and maps `*.tm7` to them via `.git/info/attributes` (this repo) or your global attributes
file (`--global`).

```text
tmforge git-setup [--global] [--print]
```

```bash
tmforge git-setup            # configure the current repository (local; nothing is committed)
tmforge git-setup --global   # configure every repository for this user
tmforge git-setup --print    # print the exact commands instead of applying them
```

`tmforge diff` and `tmforge merge` also work **standalone** with no git configuration at all; the
setup above only enables the automatic `git diff` / `git merge` behavior. (Fully zero-config
auto-invocation isn't possible: git requires drivers to be configured explicitly, by design.)

---

## Authoring commands

Authoring verbs mutate the model **in place** and write back through the source format's writer
(byte-stable for `.tm7`). Writes are **atomic**: the tool writes to a temp file and renames on
success, so a failed run never corrupts the source. Elements without explicit coordinates get a
**deterministic** auto-layout.

### `new`

Create a new model, empty or from a template.

```text
tmforge new [--name <title>] [--template <file>] [--format <id>] [--json] <file>
```

| Option | Meaning |
| --- | --- |
| `--name <title>` | Model title. |
| `--template <file>` | Seed from a template file (thin copy + metadata reset). |
| `--format <id>` | Output format id (`tm7`, `tmforge-json`, `drawio`, `vsdx`). Inferred from the extension when omitted. |

```bash
tmforge new payments.tm7 --name "Payments"
tmforge new payments.tmforge.json --format tmforge-json
```

A `.tm7` written here — and by every authoring verb, `apply`, and `convert --to tm7` — embeds the
knowledge base, so it opens in the Microsoft Threat Modeling Tool without a separate export step.

### `add`

Add an element to a page (the first diagram by default; target another with `--page`). Use a **positional kind** for a generic element, **or**
`--stencil <id>` for a typed one (the two are mutually exclusive).

```text
tmforge add <process|store|external|boundary> [options] <file>
tmforge add --stencil <id> [options] <file>
```

| Option | Meaning |
| --- | --- |
| `--name <name>` | Element name (defaults to the stencil label when using `--stencil`). |
| `--alias <name>` | Stable authoring handle. Resolvable by `connect`/`set`/`remove`/`rename`/`show`, and gives the element a **deterministic** id (the same alias yields the same id across rebuilds) so reports and docs can cite it. |
| `--boundary <ref>` | Place the element inside this trust boundary (by alias, name, or GUID) and record membership, so `export` and boundary-aware rules see it. |
| `--stencil <id>` | Concrete stencil from the catalog; stamps `StencilType=<id>` plus preset defaults. On `.tm7` export the stencil becomes a first-class element type in the Microsoft Threat Modeling Tool's palette. |
| `--left <n>` / `--top <n>` | Explicit coordinates (otherwise auto-laid-out). |
| `--width <n>` / `--height <n>` | Size (boundaries default to 260×180 so they enclose in `render`). |
| `--page <name\|index>` | Target page: a 1-based index or a page name (default: the first page; one is created if the model has none). |
| `--property KEY=VALUE` | Repeatable. Sets a rule-checked custom property. |

```bash
tmforge add process  payments.tm7 --name "Checkout API"
tmforge add store    payments.tm7 --name "Orders DB" --property Encrypted=At-rest
tmforge add boundary payments.tm7 --name "Azure VNet"
tmforge add payments.tm7 --stencil azure-app-service --name "Checkout API"
```

`--alias` gives an element a durable handle and a deterministic id: authoring the same alias in a
rebuilt model yields the same GUID, so companion docs and reports can cite it. Reference it later by
alias (or unique name) instead of GUID:

```bash
tmforge add process payments.tm7 --alias P1 --name "Checkout API"
tmforge add store   payments.tm7 --alias ORD --name "Orders DB"
tmforge connect payments.tm7 --source P1 --target ORD --name "place order"
tmforge set payments.tm7 --id P1 --property AuthenticationScheme=OAuth
```

### `connect`

Add a directed data flow between two elements, addressed by GUID.

```text
tmforge connect --source <guid> --target <guid> [--name <name>] [--property KEY=VALUE ...] [--json] <file>
```

| Option | Meaning |
| --- | --- |
| `--source <guid>` | Source element GUID (required). |
| `--target <guid>` | Target element GUID (required). |
| `--name <name>` | Flow label. |
| `--page <name\|index>` | Page to connect within (default: the first page). Both endpoints must be on it. |
| `--property KEY=VALUE` | Repeatable. Sets flow custom properties (`Protocol`, `Port`, `DataType`, `Channel`, ...). |

Mark a non-network flow with `--property Channel=In-Process` (also `Local-file`, `Unix-socket`, or
`Loopback`) to skip the protocol, port, and cleartext-crossing checks. Run
[`tmforge properties --base flow`](#properties) to see every flow property and its allowed values.

```bash
tmforge connect payments.tm7 \
  --source 1111... --target 2222... \
  --name "Place order" --property Protocol=HTTPS --property Port=443
```

### `remove`

Remove an element and its connected flows, or remove a single flow. The object is found on any page
by default; `--page` scopes the search to one page.

```text
tmforge remove --id <ref> [--page <name|index>] [--json] <file>
```

`--id` accepts a GUID, an **alias**, or a unique name. An alias resolves a flow as readily as an
element, so a flow given an alias in the manifest can be removed by that alias — and removing a flow
removes only that flow, leaving both endpoints in place.

```bash
tmforge remove payments.tm7 --id ORD               # the store, plus every flow touching it
tmforge remove payments.tm7 --id checkout-request  # just that one flow
```

### `rename`

Rename an element. The element is found on any page by default; `--page` scopes the search.

```text
tmforge rename --id <ref> --name <name> [--page <name|index>] [--json] <file>
```

### `set`

Set the name and/or properties of an existing element or flow. Use this to resolve linter
findings (e.g. add a missing `Protocol`) without recreating the element. List every settable property
and its allowed values with [`tmforge properties`](#properties).

```text
tmforge set --id <ref> [--name <name>] [--page <name|index>] [--property KEY=VALUE ...] [--json] <file>
```

`--id` accepts a GUID, an **alias**, or a unique name — and an alias or name resolves a **flow** just
as it resolves an element, so a flow given an alias in the manifest can be edited by that alias
instead of by its GUID.

```bash
tmforge set payments.tm7 --id 3333... --property Protocol=HTTPS --property Port=443
tmforge set payments.tm7 --id checkout-request --property AuthenticationScheme=OAuth
```

### `page`

List and manage the **pages** (diagrams) of a model. A `.tm7` model can hold several diagrams (for
example a context diagram plus per-service DFDs); the authoring verbs target one page at a time with
`--page`, and read-only verbs (`list`, `show`, `render`) already report every page.

```text
tmforge page ls [--json] <file>
tmforge page add [--name <name>] [--json] <file>
tmforge page rename --page <name|index> --name <newname> [--json] <file>
tmforge page rm --page <name|index> [--json] <file>
tmforge page reorder --page <name|index> --to <index> [--json] <file>
```

| Subcommand | Purpose |
| --- | --- |
| `ls` | List pages with their 1-based index, name, and element / flow / boundary counts. |
| `add` | Append a page (named `--name`, else `Diagram N`). |
| `rename` | Rename the selected page. |
| `rm` | Delete the selected page (the last page cannot be removed). |
| `reorder` | Move the selected page to the 1-based position `--to`. |

`--page` accepts a **1-based index** or a **page name** (case-insensitive; an ambiguous name is
rejected; use the index).

```bash
tmforge page ls payments.tm7
tmforge page add payments.tm7 --name "Payments service"
tmforge add process payments.tm7 --name "Ledger" --page "Payments service"
tmforge page reorder payments.tm7 --page "Payments service" --to 1
```

### `layout`

Apply a deterministic **layered auto-layout** so you never hand-place coordinates: components are
arranged left-to-right by their data flows, connectors are re-routed, and flow labels are placed
clear of the shapes and of one another.

Layout is **trust-boundary aware**. Every component keeps the boundary it was inside, each boundary
is resized around exactly the members it holds, and the boundaries are then arranged by the flows
between them. That matters because boundary membership is what the analysis is derived from: an
arrangement that moved a component out of its boundary would change what the model means, not just
how it looks. Columns wrap onto a new row instead of running past the right-hand edge, because the
Microsoft Threat Modeling Tool's drawing surface is bounded and taller than it is wide.

```text
tmforge layout [--page <name|index>] [--node-spacing <n>] [--layer-spacing <n>] [--labels] [--check] [--json] <model>
```

| Option | Meaning |
| --- | --- |
| `--labels` | Place only the flow labels and leave every shape exactly where it is. Use this when the geometry is hand-placed or comes from a manifest and only the labels need sorting out. |
| `--check` | Report obstructed flow labels and write nothing. Exits `1` when any remain, so a publishing gate can require a legible diagram. |

```bash
tmforge layout payments.tm7
tmforge layout payments.tm7 --node-spacing 60 --layer-spacing 120
tmforge layout payments.tm7 --labels          # keep the authored geometry, fix the labels
tmforge layout payments.tm7 --check --json    # gate on legibility
```

A flow's name is drawn as a **single unwrapped line** centred on its connector, so a long name needs
far more room than the flow it names — at the tool's default font a fifty-character name is wider
than a typical trust boundary. `tmforge apply` places labels as well as it can, but placement cannot
shorten text: when `--check` still reports overlaps, the remedy is shorter flow names (with the
sentence moved into a property such as `Description`) or fewer objects per page.

---

## Analysis, reporting & conversion

### `rules`

Compile a Microsoft Threat Modeling Tool template into a deterministic version 2 rule pack. The
compiler translates each threat's `Include AND NOT Exclude` expression through the same interaction
expression engine used by analysis; it does not introduce a second detector.

```text
tmforge rules import --from <template.tb7> --out <pack.tmrules.json> [--pack-id <id>] [--strict] [--json]
```

| Option | Meaning |
| --- | --- |
| `--from <path>` | Source MTMT `.tb7` template. |
| `--out <path>` | Destination `*.tmrules.json` pack. Written atomically. |
| `--pack-id <id>` | Override the deterministic name-plus-content-fingerprint pack id. |
| `--strict` | Fail with exit `2` and write nothing if any source threat cannot be represented exactly. |
| `--json` | Emit source/emitted/skipped counts, warnings, category distribution, and diagnostics. |

Without `--strict`, representable threats are written and skipped threats are reported as a partial
success. Pack-wide catalog errors, malformed XML/UTF-8, duplicate threat ids, size-limit failures,
and unsafe input/output aliasing always fail with exit `1` and do not write a pack.

```bash
tmforge rules import \
  --from "Azure Cloud Services.tb7" \
  --out azure.tmrules.json \
  --strict --json

tmforge analyze model.tm7 --rules azure.tmrules.json
tmforge threats model.tm7 --rules azure.tmrules.json
```

Generated packs retain source identity, fingerprint, manifest metadata, original threat/category ids,
raw filters, and source threat metadata. Distributing a generated pack is a redistribution of source
template content: retain the source template's license and attribution. The official Microsoft
templates are MIT-licensed; see the repository [`NOTICE`](../NOTICE).

### `analyze`

Evaluate the analysis rules against the model. See [Analysis rules & CI](analysis-rules.md) for the
full rule catalog, packs, and suppressions.

```text
tmforge analyze [--ruleset <path>] [--rules <path>] [--suppressionFile <path>] [--reportFolder <dir>] [--taxonomy <path>] [--define name=value ...] [--max-severity <level>] [--json] <model>
```

| Option | Meaning |
| --- | --- |
| `--ruleset <path>` | Use a custom rule set instead of the built-in default. |
| `--rules <path>` | Load custom [declarative rules](analysis-rules.md#authoring-custom-rules-declarative) from a `*.tmrules.json` file (or a directory of them) in addition to the built-in rules. |
| `--suppressionFile <path>` | Apply a suppression document to filter findings. |
| `--reportFolder <dir>` | Also write SARIF + HTML findings reports, a JSON listing, and the versioned analysis document to `<dir>`. |
| `--taxonomy <path>` | Annotate the analysis document with your own threat-catalogue ids. See [mapping to your own taxonomy](analysis-rules.md#mapping-to-your-own-taxonomy). |
| `--define name=value` | Repeatable. Supplies a rule variable. |
| `--max-severity <level>` | Gate the exit code on findings at or above `<level>` (`error`, `warning`, or `info`). Default: `error`. |

**Exit codes:**

| Code | Meaning |
| --- | --- |
| `0` | Clean, no findings at or above `--max-severity`. |
| `1` | Tool error (bad arguments, load failure). |
| `2` | The model was analyzed and has findings at or above `--max-severity` (default: `error`). |

The distinct `2` lets CI fail on findings while separating them from a broken invocation. Lower the
gate with `--max-severity warning` (or `info`) to also fail the build on those severities.

```bash
tmforge analyze payments.tm7
tmforge analyze payments.tm7 --reportFolder ./findings
tmforge analyze payments.tm7 --suppressionFile suppressions.json --json
```

> When a model is loaded from the native `tmforge-json` format, its embedded analysis selection
> (disabled packs/rules) is honored automatically. Other formats use the full rule set or an
> explicit `--ruleset`.

### `analysis`

Validate a stored [analysis document](analysis-rules.md#the-analysis-document) — the
`<model>.analysis.json` written by `analyze --reportFolder` — or compare two of them.

```text
tmforge analysis validate [--model <path>] [--expect-version <n>] [--json] <document>
tmforge analysis diff [--json] <base> <head>
```

| Option | Meaning |
| --- | --- |
| `--model <path>` | Also check the document against the model it describes, so a **stale** analysis is reported instead of trusted. |
| `--expect-version <n>` | Pin the schema version your tooling was written against; any other version is refused rather than read on the wrong assumptions. |

**Exit codes:**

| Code | Meaning |
| --- | --- |
| `0` | The document is sound. |
| `1` | Tool error (bad arguments, file not found). |
| `2` | Problems were found. |

```bash
tmforge analysis validate findings/payments.analysis.json
tmforge analysis validate findings/payments.analysis.json --model payments.tm7
tmforge analysis validate findings/payments.analysis.json --expect-version 1 --json
```

Two different things can be wrong with a stored analysis and both are silent. It can contradict
itself — a finding with no disposition, two findings sharing an id, a threat-bearing finding with
nothing to join to. Or it can be perfectly coherent and simply **stale**, describing a model that has
since changed. Passing `--model` catches the second, which is the more dangerous of the two: a clean
report about last month's architecture reads exactly like a clean report about today's.

```text
The document describes a different model: it records sha256:187a6d5d… but 'payments.tm7' is
sha256:ca329391…. Re-run the analysis.
```

The command also refuses a document written by a **newer** build, rather than reading it on older
assumptions and silently misinterpreting fields whose meaning has changed. Version 1 is currently the
only schema version, so there is nothing to migrate from yet.

#### Comparing two analyses

`analysis diff` answers the question a count cannot: not how many findings there are now, but **which
ones arrived**.

```bash
tmforge analysis diff before/payments.analysis.json after/payments.analysis.json
```

```text
Introduced:
  warning  TM1014:48761fb5…:f59d24bf…:0  (generated-threat)
      Data store [Session Secrets …] stores credentials but is not encrypted at rest…

Resolved:
  warning  TM1021:48761fb5…:6b3c361c…:0  (generated-threat)
      Data store [Audit Log …] holds log or audit data and its Signed property is not evidenced…

4 introduced, 1 resolved, 0 reclassified, 1 unchanged.
```

Findings are matched on the stable id every document carries,
`{ruleId}:{diagram}:{target}:{occurrence}` — never on position, which renumbers the moment a rule is
enabled or disabled. Three consequences are worth knowing:

- **Renaming an element is not a finding change.** The message carries the display name, so it is
  rewritten; the identity is not. Editorial churn stays out of the delta.
- **A suppressed finding is reclassified, not resolved.** Suppressing something records it with a new
  disposition rather than dropping it, and saying "resolved" would claim the underlying condition
  went away — which a suppression explicitly does not claim. A rule whose severity was reconfigured
  lands in the same bucket.
- **A changed rule selection is reported, not folded in.** If the analyzer fingerprints differ, the
  command still compares but warns, so a finding that appeared only because a new rule was switched
  on is not read as one the change introduced.

**Exit codes:** `0` when nothing was introduced, `1` on tool error, `2` when findings were
introduced — so a gate can depend on "no new findings" without comparing counts itself. Resolving
findings never fails the command.

### `threats`

Report the model's **threats** — the persisted, triaged view of the threat-bearing analysis findings.
Detection is entirely the rule set: `threats` runs the same rules as [`analyze`](#analyze), keeps the
findings from rules that declare a threat category, and frames each as a threat against its element or flow.
The difference from `analyze` is **lifecycle** — where a finding is transient and gated, a threat is
persisted and triaged (`open -> mitigated -> accepted`). With `--write`, the threats are persisted into
the model's register, keyed so a re-run updates in place and never overwrites prior triage.

```text
tmforge threats [--write] [--rules <path>] [--json] <model>
```

| Option | Meaning |
| --- | --- |
| `--write` | Persist the threats into the model's register (preserves prior triage). |
| `--rules <path>` | Also project threats from custom [declarative rules](analysis-rules.md#authoring-custom-rules-declarative); a custom rule that declares `categoryId` or `stride` becomes threat-bearing. |

Each threat carries its rule-defined category, mitigation, and external references (CWE / CAPEC).
There is no separate threat catalog: **extend coverage the way detection is extended — add a rule to a
rule pack** (see [Analysis rules](analysis-rules.md)). Rules that represent structural or naming
hygiene (rather than a security weakness) are not reported as threats.

```bash
tmforge threats payments.tm7                 # report (read-only), same findings as lint
tmforge threats payments.tm7 --write         # persist into the register
tmforge threats payments.tm7 --json
```

After `--write`, triage the register with [`list threats`](#list) and [`accept`](#accept).

#### Authoring threats

Beyond acceptance, `threats` can **create, edit, and remove** threats. `--add` writes only the manual
entry; it does not persist the current generated findings. `--edit` materializes rule threats for
lookup when needed. `--remove` deletes a manual or stale entry. Each operation then saves the model:

```text
tmforge threats --add --title <t> --category <STRIDE> [--id <id>] [--scope <id>] [--state <s>] [--priority <p>] [--mitigation <m>] [--description <d>] <model>
tmforge threats --edit <id> [--title <t>] [--category <c>] [--state <s>] [--priority <p>] [--mitigation <m>] [--description <d>] [--note <n>] <model>
tmforge threats --remove <id> <model>
tmforge threats --remove-stale [--force] [--rules <path>] <model>
```

| Option | Meaning |
| --- | --- |
| `--add` | Author a **manual threat** the rules do not detect. `--category` is a STRIDE category (`Spoofing` / `Tampering` / `Repudiation` / `InformationDisclosure` / `DenialOfService` / `ElevationOfPrivilege`); `--scope` is an element or flow id (omit for a model-wide threat). Manual threats are keyed in the reserved `manual:` namespace and do not implicitly persist generated threats. |
| `--id <id>` | Key the threat yourself instead of taking a generated id, so it can be referenced from a ticket or control catalogue and the same authoring command can be re-run. Letters, digits, `-`, `_`, and `.`, up to 128 characters; the `manual:` prefix is added if you omit it. Re-using an existing id is an error — use `--edit` to change that threat. |
| `--edit <id>` | Change a threat's `--title`, `--state` (`Open` / `NeedsInvestigation` / `Mitigated` / `Accepted`), `--priority` (`Critical` / `High` / `Medium` / `Low`), `--mitigation`, `--description`, or `--note`. Works on rule-derived and manual threats. `--category` applies to **manual threats only**. |
| `--title <t>` | Retitle a threat. On a rule-derived threat this is an **override**: the rule keeps detecting the threat and keeps its identity, but the register shows your wording. Pass an empty title to drop the override and restore the rule's. |
| `--category <c>` | Set a **manual** threat's STRIDE category. Refused for a rule-derived threat, whose category is the rule's conclusion rather than an author's opinion. |
| `--remove <id>` | Delete a **manual** threat, or a **stale** one. A threat the rules still produce is refused: removing it would only bring it back on the next run — accept or edit it instead. |
| `--remove-stale` | Delete every stale entry at once. Entries carrying triage are **kept and listed**; `--force` discards them too. Refuses outright if any entry's rule was not part of the run, naming the rules so you can re-run with `--rules` rather than lose a real finding. |

```bash
tmforge threats app.tm7 --add --title "Admin actions are unlogged" --category Repudiation --scope <process-id> --priority High
tmforge threats app.tm7 --add --id unlogged-admin-actions --title "Admin actions are unlogged" --category Repudiation
tmforge threats app.tm7 --edit <id> --state Mitigated --description "Handled by the mesh"
tmforge threats app.tm7 --edit <id> --title "Unauthenticated ledger write"   # override the rule's wording
tmforge threats app.tm7 --edit <id> --title ""                               # and hand it back to the rule
tmforge list threats app.tm7                 # see the register and each entry's standing
tmforge threats app.tm7 --remove-stale       # clear leftovers; triaged ones are kept and listed
```

#### Who owns which field

A threat has two kinds of text on it and they answer to different people. **Detection** — the rule
that fired, the category it concluded, and the threat's identity — belongs to the rule set, so a
re-run can be trusted to say the same thing. **Judgement** — title, state, priority, description,
mitigation, and note — belongs to the author.

Title sits deliberately on the author's side of that line. Rule wording is written to be precise
about a class of problem, not about your system, and a reviewer reading the register is better served
by "Unauthenticated ledger write" than by a sentence naming a generic data flow. Overriding it
changes nothing a later run depends on: the rule still fires, the threat keeps its id, and the
analysis document, SARIF fingerprints, and register key are all unmoved. Clearing the override
restores the rule's wording, so the edit is reversible.

Category does not, and that asymmetry is the point. A generated threat's category is what the
analysis concluded; letting an author change it would record a claim the rules do not support, and
the register would no longer mean one thing. The edit is refused rather than ignored, so nobody is
left believing it took effect. A manual threat has no rule behind it, so its author owns both.

#### Clearing stale entries

Applying a generation result never deletes, so triage survives every re-run. The cost is that an
entry left behind by a rule that stopped firing stays in the register. `list threats` shows each
entry's standing, and `--remove-stale` is the explicit way to clear the leftovers.

Two things are deliberately never done for you:

- A stale entry that carries triage — investigated, mitigated, or accepted — is **kept and named**.
  The rule going quiet retires the finding, not the decision someone recorded against it. `--force`
  discards those too, but you have to ask.
- If any stored entry's rule was not part of the run, `--remove-stale` **refuses entirely** and names
  the rules. A rule that never ran says nothing about the model, so pruning on that basis would
  delete real findings after a mistyped `--rules` path or a disabled pack.

Authored threats and edits round-trip into the `.tm7` register (and open in the Microsoft Threat
Modeling Tool). A manual threat's id comes from `--id`, from the `list threats` output, or from
`--add --json`. An id you chose survives both `tmforge-json` and `.tm7` round trips unchanged.

Priority is author-owned and accepts `Critical`, `High`, `Medium`, or `Low`. Severity still drives
analysis gating; priority never affects detection. The knowledge base embedded in an exported `.tm7`
declares this whole vocabulary, so a priority you set is one the Microsoft Threat Modeling Tool also
offers and cannot be replaced on a round trip. When you embed a different knowledge base with
`convert --knowledge-base`, its priority list is **extended** rather than replaced, so both its values
and tmforge's remain selectable.

### `accept`

Record **inline risk acceptance** for a generated threat. Acceptance is a threat *state*: the threat
moves to `NotApplicable` with your justification, stays visible in the register and report, and no
longer counts as open. Because it is scoped to a single threat (one pattern on one interaction), it
can never silently swallow an unrelated finding — unlike a blanket suppression.

```text
tmforge accept --threat <id> --reason <text> [--json] <model>
```

| Option | Meaning |
| --- | --- |
| `--threat <id>` | The threat to accept: its register key, interaction key, or numeric id (from `list threats`). |
| `--reason <text>` | The justification, stored with the threat and shown in the register and report. |

```bash
tmforge threats payments.tm7 --write
tmforge list threats payments.tm7
tmforge accept --threat 3 --reason "Mitigated by the upstream WAF; residual risk accepted." payments.tm7
```

Acceptance round-trips through `.tm7` and is honored identically by the CLI, the `/v1` API, and Studio.

### `report`

Generate a self-contained HTML report with an inline SVG diagram per page, or export just the
diagram as a standalone SVG for review artifacts.

```text
tmforge report [--format <html|svg>] [--out <path>] [--rules <path>] [--json] <model.tm7>
```

- `--format html` (default) writes a responsive, print-friendly report with an executive summary,
  model context, inline SVG per page, and the full threat register. Rule-backed threats are generated
  on demand from the enabled STRIDE-bearing rules, then combined with manual threats and existing
  triage; a `tmforge-json` model's disabled packs and rules are honored.
- `--format svg` writes just the diagram as a standalone SVG (every page stacked), suitable for
  attaching to a pull request or embedding in docs. It does not run analysis.
- `--rules` loads custom declarative rules alongside the built-in rules, exactly as on
  [`analyze`](#analyze), so a report shows the same threats the analysis produced.

```bash
tmforge report payments.tm7 --out payments.html
tmforge report payments.tm7 --format svg --out payments.svg
tmforge report payments.tm7 --rules ./corporate.tmrules.json --out payments.html
```

### `convert`

Convert between formats. The target is chosen by `--to` or inferred from the `--out` extension.

```text
tmforge convert [--to <format>] [--out <path>] [--knowledge-base <file.tb7>] [--json] <input>
```

| Format id | Extension | Notes |
| --- | --- | --- |
| `tm7` | `.tm7` | Lossless, byte-stable; embeds a knowledge base so it opens in MTMT. |
| `tmforge-json` | `.tmforge.json` | Canonical wire model. |
| `drawio` | `.drawio` | draw.io / diagrams.net (structural). |
| `vsdx` | `.vsdx` | Microsoft Visio (structural). |

See [Formats & interoperability](formats.md) for fidelity details.

A `.tm7` target embeds the Threat Model Forge knowledge base by default so the file opens in the
[Microsoft Threat Modeling Tool](formats.md#tm7-and-the-microsoft-threat-modeling-tool); pass
`--knowledge-base <file.tb7>` to embed a specific one instead. A knowledge base already present in the
source model (for example, a file authored in the tool) is preserved.

A `.tm7` target also gets its flow labels placed, because the tool draws each flow's name on its
connector and most source formats carry no label position at all — `tmforge-json`, the canonical wire
model Studio and the API exchange, records only a flow's endpoints and name. Without this, every label
converted from one of them would land on its connector's midpoint and flows sharing a pair of
endpoints would print their names on top of each other. A label the source did position is preserved.

```bash
tmforge convert payments.tm7 --to drawio --out payments.drawio
tmforge convert payments.drawio --to tm7 --out payments.tm7
tmforge convert payments.tmforge.json --to tm7 --out payments.tm7 --knowledge-base Custom.tb7
```

---

## Declarative manifest

A manifest is a small, review-friendly JSON document that describes a whole model (boundaries,
elements, and flows) by **alias** instead of GUID, so it diffs cleanly in a pull request and is the
source of truth for the `.tm7`. `apply` materializes it; `export` emits it from any model.

```json
{
  "name": "Checkout Service",
  "boundaries": [
    { "alias": "TB1", "name": "Payments VNet" }
  ],
  "elements": [
    { "alias": "API", "kind": "process", "name": "Checkout API", "boundary": "TB1",
      "props": { "RunningAs": "Service Account", "AuthenticationScheme": "OAuth" } },
    { "alias": "DB", "kind": "store", "stencil": "azure-sql", "name": "Orders DB", "boundary": "TB1" }
  ],
  "flows": [
    { "alias": "F1", "from": "API", "to": "DB", "name": "store order",
      "props": { "DataType": "Customer Content", "Protocol": "SQL", "Port": "1433" } }
  ]
}
```

- `elements[].boundary` names the trust boundary an element belongs to; `apply` places the element
  inside it so trust-boundary crossings are computed and membership round-trips through `export`.
- `elements[].alias` gives each element a **deterministic** id (stable across rebuilds), and flows
  reference elements by that alias (or by unique name).
- `flows[].alias` does the same for a flow. It is optional: a flow without one still gets a stable id,
  derived from its endpoints and name. Declaring an alias is what lets a flow be **renamed or
  re-pointed without moving its id** — worth doing for any flow whose findings you expect to track.
  It is also the handle you pass to `set --id` or `remove --id` to edit that flow later, instead of
  looking up its GUID.
- Either `kind` or `stencil` identifies an element; a stencil's base primitive sets the kind.

**Every identifier `apply` assigns is derived, never minted**, so applying one manifest twice produces
the same model: the same page, component, and connector ids. That is what keeps finding ids
(`{ruleId}:{diagram}:{target}:{occurrence}`), threat-register triage, and `tmforge diff` aligned
across rebuilds. Aliases are the durable form of that identity; the structural fallback is stable
against re-applying a manifest, but renaming an alias-less object moves its id.

### Envelope

A manifest may declare `"schema": "tmforge-manifest"` and a numeric `"version"`. Both are optional —
a manifest without them is read as the current version, because the concise form predates the
envelope. What the envelope buys is refusal rather than guesswork: a manifest from a newer build is
rejected with an upgrade hint instead of being read on assumptions that no longer hold, and a
document of another schema (a model, a rule pack) is named as such instead of being coerced into a
manifest that declares almost nothing. `export` stamps the envelope.

### Pages

A manifest may declare `pages`, and each boundary and element may name the one it is drawn on:

```json
{
  "schema": "tmforge-manifest",
  "version": 1,
  "pages": [
    { "alias": "ctx", "name": "Context" },
    { "alias": "payments", "name": "Payments service" }
  ],
  "elements": [
    { "alias": "API", "kind": "process", "name": "Checkout API", "page": "ctx" },
    { "alias": "LEDGER", "kind": "process", "name": "Ledger", "page": "payments" }
  ]
}
```

Pages are optional: a manifest that declares none builds onto one default page, exactly as before. An
object that names no page goes on the first. A page's alias (or its name) fixes its identifier, which
matters because finding ids embed it.

**A flow may not cross pages.** A connector belongs to one surface, so both endpoints have to be
drawn on the same page; a flow whose endpoints are on different pages is refused rather than drawn on
whichever page resolved first. Naming a page the manifest does not declare is refused too, rather than
quietly placing the object on the first page.

`export` records `pages` only when the model has more than one, so a single-page model produces
exactly the manifest it always did.

### Geometry

`boundaries[]` and `elements[]` accept optional `x`, `y`, `width`, and `height`. Position and size are
each all-or-nothing: supplying `x` without `y` is an error rather than a half-honoured request.

- Omit them and the object is placed automatically, exactly as before.
- Supply them and the object goes where you asked.
- A boundary with no size grows to contain any member you placed explicitly, rather than clipping it.
- A boundary with a fixed size that cannot hold the members it must lay out is rejected, because the
  automatic grid would put them outside the box you drew.

A member placed outside the boundary it belongs to is allowed: nothing is being clipped, both objects
go where they were asked, and refusing it would make a diagram already in that state impossible to
re-apply.

`tmforge export --geometry` records the geometry. It is off by default because the manifest's job is
to be reviewable, and coordinates churn whenever a diagram is tidied — they bury the property change
somebody actually needs to read. **Turn it on when the layout matters.** Without it, `export` followed
by `apply` re-runs automatic placement, and because trust-boundary containment is derived from
geometry that can change which boundaries a flow crosses:

```bash
tmforge export --geometry --out payments.json payments.tm7   # lossless round trip
tmforge export --out payments.json payments.tm7              # concise, layout re-derived
```

### `apply`

Build a model from a manifest. The whole model is built in memory and written **atomically**, so a
bad manifest never leaves a half-built model; re-running regenerates the model idempotently.

```text
tmforge apply <manifest.json> [--out <model>] [--format <id>] [--force] [--dry-run] [--json]
```

| Option | Meaning |
| --- | --- |
| `--out <model>` | Output path (default: the manifest path with a `.tm7` extension). |
| `--format <id>` | Output format id (`tm7`, `tmforge-json`, `drawio`, `vsdx`); inferred from `--out` otherwise. |
| `--dry-run` | Validate the manifest and report counts without writing. |
| `--force` | Store unknown/invalid property values instead of rejecting them. |

```bash
tmforge apply model.json --out model.tm7
tmforge apply model.json --dry-run
```

Shapes go exactly where the manifest asks, but a flow's label has no coordinates to declare: the tool
draws the name on the connector itself, so two flows between one pair of elements would print their
names on the same spot. Every write to `.tm7` therefore places the labels for you, adjusting only the
connectors' curve handles — nothing the analysis reads, and never a label somebody has already moved.
Run [`tmforge layout --check`](#layout) on the result to confirm none is still covered.

A manifest is a model's *source*, not a model. The read-only verbs (`open`, `list`, `show`,
`analyze`, …) take a model file, so pointing one at a manifest reports that and names the `apply`
command to run first. The same recognition lets **Studio** open a manifest directly — see
[Importing and exporting](studio-guide.md#opening-an-authoring-manifest).

### `export`

Emit a manifest from an existing model (round-trips with `apply`). Geometry is dropped unless you ask
for it with `--geometry`, so the manifest stays a stable, diffable source by default.

```text
tmforge export [--out <manifest.json>] [--geometry] [--json] <model>
```

```bash
tmforge export payments.tm7 --out payments.json
tmforge export --geometry payments.tm7 --out payments.json
tmforge export payments.tm7 | jq '.elements'
```

---

## Agent / MCP server

### mcp

`tmforge mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio, so
an AI agent can drive Threat Model Forge with the same engine Studio and the CLI use. It projects the
stateless engine and authoring facade as MCP tools — each takes a canonical `tmforge-json` model in
and returns the edited model (or findings, threats, or a report) out, so there is no server-side
session state.

```text
tmforge mcp [--root <path>] [--max-read-bytes <n>] [--max-write-bytes <n>]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--root <path>` | Process working directory | Workspace root for every MCP file read and write. Relative tool paths resolve beneath it; traversal and symbolic-link escapes are rejected. |
| `--max-read-bytes <n>` | `67108864` (64 MiB) | Maximum size of one model file read by `read` or `detect`; for VSDX, the same budget also caps total expanded ZIP content. |
| `--max-write-bytes <n>` | `67108864` (64 MiB) | Maximum serialized output accepted by `save`, enforced while the format writes. |

Configure your MCP client to launch the tool:

```json
{
  "mcpServers": {
    "tmforge": {
      "command": "tmforge",
      "args": ["mcp", "--root", "/path/to/project"]
    }
  }
}
```

**Tools.** Grounding: `formats`, `stencils`, `property_schema`, `rules`, `rule_packs`,
`manifest_schema`, `detect`. Model I/O and analysis: `read`, `save`, `analyze`, `threats`,
`threat_register`, `report`, `merge`. Authoring: `apply`, `export_manifest`, `add`, `connect`, `set`,
`rename`, `remove`. Threat authoring: `add_threat`, `edit_threat`, `remove_threat`.

`threat_register` splits the register by origin and standing (manual, current-generated,
stale-generated, and entries whose rule was not part of the run), so an agent can tell a live finding
from one left behind by a rule that stopped firing.

**Custom rules.** `analyze`, `threats`, `threat_register`, `report`, `rules`, and `rule_packs` accept
an optional `rulesPath` naming a `*.tmrules.json` pack. It is resolved through the same workspace
sandbox as
every other file access, so an agent cannot load rules from outside `--root`.

A typical agent loop is **apply -> analyze -> set -> analyze -> save**: build a model from a manifest
(or incrementally with `add`/`connect`), analyze it, resolve findings by setting the properties the
rules read (for example `Protocol=HTTPS`), then materialize a `.tm7` with `save`. The JSON-RPC
protocol owns stdout; all diagnostics go to stderr.

**Filesystem boundary.** `read`, `detect`, and `save` are the only tools that access local files.
They accept paths inside `--root`; absolute paths are allowed only when they resolve inside that same
root. The server canonicalizes every existing path component and follows symbolic links only when
their final target remains inside the root. A missing intermediate directory is rejected rather than
created implicitly. `save` writes only exact extensions registered by writable model formats:
`.tm7`, `.tmforge.json`, `.drawio`, and `.vsdx`; an explicit format cannot override a mismatched or
non-model extension. Save streams into a fresh same-directory temporary file and atomically replaces
the destination, so an existing hard link is not truncated through to another pathname and an
oversized or failed conversion leaves no partial output. The result returned to the agent contains
the caller's path, not the canonical host path.

**Request budgets.** Every MCP tool validates model and manifest complexity before invoking the
engine: at most 128 pages, 10,000 elements, 20,000 flows, 20,000 threat-overlay entries, 100,000
properties, 65,536 characters in one string, and 16 Mi characters of aggregate model text. These
limits count every physically supplied collection (including top-level page-one mirrors), and all
models supplied to one merge share a single budget. They apply only to the MCP host; direct CLI and
API operations retain their existing contracts. Generated findings, threats, and merge conflicts are
capped at 100,000 items, and generated report text at 32 Mi characters.
ZIP model inputs are preflighted before package parsing (at most 4,096 entries, a 4 MiB central
directory, and 1,024-byte entry names; prefixed and ZIP64 packages are rejected), and VSDX expanded
content shares the read-byte budget. VSDX pages are imported/exported one at a time and threats are
indexed once per export rather than scanned for every element.
ModelContextProtocol 1.4.1 does not expose a stdio frame-size option, so deployers that accept
untrusted MCP clients should also apply process/container memory limits; tool-level budgets take
effect after the SDK has deserialized a request. Report generation also uses the existing in-memory
report writers before the response-text cap is checked; the model budget bounds that work, while a
future streaming report API could enforce the response cap during rendering.

---

## JSON output

With `--json`, every command emits a single **versioned envelope** to stdout:

```json
{
  "schemaVersion": 1,
  "command": "open",
  "data": { }
}
```

- `schemaVersion`: pin this; the shape evolves under SemVer.
- `command`: the verb that produced the payload.
- `data`: the command-specific payload (camelCase properties, enums as strings).

Diagnostics never mix into this stream (they go to stderr), so piping to `jq` is safe:

```bash
tmforge list components payments.tm7 --json | jq '.data'
```

For the `data` shape of each command, run [`tmforge schema`](#schema) (add `--json` for a
machine-readable catalog). For example, `add` returns the new element id at `data.id`, and `connect`
returns `data.id` / `data.source` / `data.target`.

## See also

- [Quick start](quickstart.md): the commands in a worked example.
- [Analysis rules & CI](analysis-rules.md): the rule catalog and gating.
- [Formats & interoperability](formats.md): conversion fidelity.
