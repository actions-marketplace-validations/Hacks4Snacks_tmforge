# tmforge CLI Workflow and Reference

Use the installed tool's `--help` output when it differs from this reference. Record version-specific differences
rather than guessing.

## Preflight and Discovery

Follow this skill's managed-launcher or explicit-CLI selection first. In the examples below, `tmf` is shorthand for
that chosen invocation, not another executable shipped by the plugin. For a managed binary, expand it to
`python3 "<skill-directory>/scripts/tmforge.py" --`. Check its status and obtain approval before provisioning a missing
binary; do not substitute a global CLI merely because the cache is empty. Then run:

```bash
tmf --version
tmf --help
tmf stencils
tmf properties
```

Use structured output when supported. Query narrower property or stencil views before authoring if the installed
version exposes filters. Property values are validated on write; use canonical values returned by the tool.

Truth rule: choose the evidenced value even when `properties` marks it with `*`. The marker means that a rule will
report the current posture. It does not authorize replacing the observed value with a more secure one. If evidence is
unavailable, represent the property as unknown when supported and record the unknown in the canonical analysis ledger.

## Machine-Readable Output

Prefer `--json` and parse the JSON structurally. Common shapes are:

```text
open --json                 -> .data metadata and counts
list <kind> --json          -> .data.items[]
show --id <guid> --json     -> .data object and properties
analyze --json              -> .data.ruleReports[] (rule-level reports/catalog)
threats --json              -> .data.threats[] (generated instances and triage state)
```

`analyze --json` rule reports are not per-object threat instances. Use `threats --json` for generated actionable
instances and `list threats --json` for the persisted register when supported.

Typical exit codes are `0` for no finding at the selected gate, `1` for a tool error, and `2` for findings. Treat exit
code `2` as valid analyzer output: retain and inspect the JSON rather than reporting a command failure.

When a core validator accepts `--tmforge`, provide the complete command string, not the shorthand `tmf` or a shell
function. For example: `--tmforge 'python3 "/absolute/installed-skill/scripts/tmforge.py" --'`. Quote paths containing
spaces. The wrapper preserves the caller's working directory, output streams, and CLI exit code.

## Existing Model Baseline

Before deciding whether an existing artifact is current or modifying it, run the installed equivalents of:

```bash
tmf open <model.tm7> --json
tmf list boundaries <model.tm7> --json
tmf list components <model.tm7> --json
tmf list flows <model.tm7> --json
tmf render <model.tm7> --plain
tmf analyze <model.tm7> --json
tmf threats <model.tm7> --json
tmf list threats <model.tm7> --json
```

For every material object and flow, use `show` to inspect encoded security properties. Names containing words such as
"secure", "authenticated", "encrypted", or a protocol name are labels, not proof that the corresponding property is
set.

Record the model title, page names, boundary/element/flow counts, stable IDs, generated-threat count, persisted-threat
count, and rendered boundary membership. Compare them to companion artifacts and current evidence. A scope or metadata
mismatch blocks a verified verdict.

## Declarative Manifest Workflow

When a manifest is source, edit the alias-keyed manifest and generate a candidate:

```bash
tmf apply <model.tm.json> --dry-run
tmf apply <model.tm.json> --out <candidate.tm7>
```

Use `export` only to bootstrap a manifest from an existing direct-mode artifact:

```bash
tmf export <model.tm7> --out <candidate.tm.json>
tmf apply <candidate.tm.json> --dry-run
tmf apply <candidate.tm.json> --out <candidate.tm7>
```

Do not migrate authoring modes during an unrelated update. If migration is requested, validate semantic parity by
comparing inventories, properties, rendered boundary membership, generated threats, and persisted triage before and
after conversion.

## Imperative Authoring Workflow

Use imperative verbs only when direct mode is established or a declarative command is unavailable. Discover exact
stencil IDs and properties first.

```bash
tmf new <candidate.tm7> --name "<scope> threat model" --json
tmf add --stencil <boundary-stencil> <candidate.tm7> --name "TB1: <boundary>" --json
tmf add --stencil <element-stencil> <candidate.tm7> --name "P1: <process>" --json
tmf connect <candidate.tm7> --source <guid> --target <guid> --name "F1: <flow>" --json
tmf set <candidate.tm7> --id <guid> --property <key>=<value> --json
tmf show <candidate.tm7> --id <guid> --json
```

Capture GUIDs from JSON output. Never transcribe or generate them manually. Address updates and removals by GUID, then
read the affected object back.

Add boundaries before their children and place elements deliberately. Trust-boundary crossings are often computed
from geometry.

## Diagram Legibility

A diagram is an argument, and one a reader cannot decipher argues badly. Three properties of the Microsoft Threat
Modeling Tool's drawing surface decide whether a generated model is readable, and none of them is discoverable from
the manifest:

1. **A flow's name is drawn as one unwrapped line, centred on its connector.** Its width is a function of its text
   (roughly 7 units per character), not of the shapes it joins. A fifty-character name is wider than a whole
   boundary column and prints across whatever it passes over.
2. **The canvas is bounded and taller than it is wide** — shapes are clamped past `(1890, 2090)`, connector points
   past `(1990, 2190)`. The tool clamps out-of-range shapes when it loads the file, piling them on top of each
   other, so a diagram cannot be made legible by spreading it sideways. Grow it downwards.
3. **Two flows between one pair of elements share a label position** unless something moves them apart.

Consequences for authoring:

- **The flow name is a label, not a sentence.** Write the stable ID plus a terse phrase, and keep the sentence in the
  canonical ledger and the data-flow document, where it is keyed by the same ID and is what a reviewer actually
  reads. The practical ceiling scales with how wide the diagram is: for a five-column diagram it is about 30
  characters, for four columns about 50, for three about 85. Past that the labels cannot be placed at all.
- **Derive geometry; do not invent it.** The layout generator provided by the loaded `threat-modeling` skill sizes each
  column gap from the labels that span it and exits non-zero when the result no longer fits the canvas, which is the
  signal that the names — not the placement — need to change.
- **Let tmforge place the labels.** Recent versions position every flow label clear of the shapes and of the other
  labels on each write to `.tm7` — whether it came from `apply`, `convert`, an authoring verb, or Studio's export —
  by adjusting curve handles only, which nothing in the analysis reads. A label somebody positioned is preserved.
  Confirm the result with `tmforge layout --check <model> --json`; it exits non-zero while any label is still
  covered. When the installed version has no `--check`, use
  the layout checker provided by the loaded `threat-modeling` skill instead.
- **Split the page before shortening past meaning.** A wider canvas is not available, so when the names cannot get
  shorter without losing what they say, carry less on one page: split on a boundary that no material flow crosses,
  since a flow cannot cross pages.

`tmforge layout` rearranges the whole diagram. Newer versions are trust-boundary aware — every component keeps the
boundary it was inside, each boundary is resized around its members, and columns wrap instead of running off the
canvas — but older ones move elements while leaving boundaries where they are, which lands elements outside the
boundary they belong to and is a semantic regression, not a cosmetic one. Do not assume which you have: run
`tmforge layout --help` and treat the presence of `--labels` as the signal, and compare rendered membership before
and after whenever you rearrange. On a model with deliberate placement, prefer `tmforge layout --labels`, which
places the labels and leaves every shape exactly where the manifest put it.

Carry geometry in the manifest, where it is reviewable and reproducible. Only `x`, `y`, `width`, and
`height` are honored; `left`, `top`, `posX`, `posY`, and nested `position` objects are silently ignored, so verify
that placement survived instead of assuming it applied. Resolve the layout generator and checker from the
loaded `threat-modeling` skill's bundled resources. Use the generator to derive geometry from the ledger and
the checker to confirm the result: it fails a diagram whose
canvas runs past the tool's limit or whose flow label is completely hidden behind a shape, and warns for every label
printed over something. The unified package verifier runs the same checker.

If a full re-layout is genuinely unavoidable, compare rendered membership and analyzer crossings before and after and
reject any semantic change.

## Property Mapping

Interrogate the installed property schema. Common property families include:

- processes: authentication, execution identity, isolation, input/output validation;
- stores: credential/log storage, encryption, access control, backup, integrity;
- flows: protocol or local channel, port, transported data classification;
- external entities: self-authentication and identity mechanism; and
- audit stores: log-data marker, integrity/signing, retention, encryption, access control.

Set a property only when the evidence ledger supports it. Preserve observed weak values. Do not create an audit store,
identity control, encryption property, fixed port, or validation behavior solely to suppress a finding.

Some security semantics cannot be represented by a topology property, including many identity-binding,
authorization-scope, freshness, replay, business-logic, and recovery guarantees. Keep those as manual STRIDE findings
in the canonical ledger rather than forcing an unrelated property.

## Generated and Persisted Threats

Run analysis before persistence:

```bash
tmf analyze <candidate.tm7> --json
tmf threats <candidate.tm7> --json
```

For each generated instance, either:

1. correct an inaccurate model property using evidence;
2. retain it as a real weakness and mirror it in the canonical STRIDE ledger; or
3. accept/suppress it only with a specific justification supported by the local convention.

Persist generated threats only after review and only when the convention requires it. Persistence may retain older
manual or triaged entries. After removals or substantial topology changes, regenerate from a clean candidate when
practical; otherwise remove stale entries explicitly and list the register again.

### Suppression Sidecars

A suppression sidecar records the accepted findings. Its shape is:

```json
{"files": [{"file": "<model>.tm7",
            "suppressions": [{"rule": "TM1014",
                              "model": "Diagram 1",
                              "target": "<analyzer target descriptor>",
                              "justification": "<why this posture is accepted>"}]}]}
```

Three details cause silent, not loud, failures, so confirm each one rather than assuming:

- **`file` resolves relative to the sidecar's own directory**, not the working directory. Keep the sidecar beside the
  `.tm7` it describes.
- **`model` is the drawing-surface name, typically `Diagram 1`, not a path.** A path produces
  `TM0001: names drawing surface [...] but no such surface exists` and the entry is skipped while the file still parses.
- **`target` must match the analyzer descriptor exactly, including its trailing `ID=<guid>`.** Those GUIDs derive from
  the element alias and survive geometry changes, so a sidecar keyed to them stays valid across relayouts.

The analyzer emits two target line shapes. A sidecar built by matching only one silently loses the other half of the
findings, and the run still reports success:

```text
Kind [NAME (Generic Process) ID=<guid>]      # bracketed form
The NAME (Generic Process) ID=<guid> ...     # inline form
```

Generate the sidecar rather than transcribing it, which handles both shapes and proves the result covers every finding:

```bash
python3 <threat-modeling-skill-directory>/scripts/generate_suppressions.py <model>.tm7 <justifications.json> \
    --out <model>.tm.suppressions.json --verify
```

Resolve the script from the bundled sibling `threat-modeling` skill, not from `PATH`
or the analyzed repository's skills directory.

`--verify` re-runs the analyzer with the sidecar applied and fails unless the residual finding count reaches zero, so
an entry that parsed but never matched is reported instead of assumed effective. Key the justification map by rule and
element **name**, never by ledger ID; IDs are positional and renumber when an element is inserted.

## Candidate Validation

Run every available check below against the candidate:

```bash
tmf open <candidate.tm7> --json
tmf list boundaries <candidate.tm7> --json
tmf list components <candidate.tm7> --json
tmf list flows <candidate.tm7> --json
tmf show <candidate.tm7> --id <material-guid> --json
tmf render <candidate.tm7> --plain
tmf analyze <candidate.tm7> --max-severity error
tmf threats <candidate.tm7> --json
tmf list threats <candidate.tm7> --json
tmf layout --check <candidate.tm7> --json
```

Use a stricter discovered local gate when it exists. If intentional findings remain, ensure the local suppression or
acceptance mechanism carries a justification and the canonical STRIDE ledger contains the corresponding risk.

Compare candidate and source inventories. Explain every addition, removal, rename, property change, boundary crossing,
generated finding, and persisted entry. Promote the candidate only after semantic parity checks pass.

After promotion, rerun the same checks against the final path. A validated temporary file does not prove that the
promoted artifact is identical or readable.

## Optional Reports and Conversion

Use only commands exposed by the installed version, for example:

```bash
tmf analyze <model.tm7> --reportFolder <report-directory>
tmf report <model.tm7> --out <report.html> --json
tmf convert <model.tm7> --to <supported-format>
```

Generated reports and conversions are outputs, not semantic sources. Validate converted artifacts separately when the
user intends to rely on them.

## Troubleshooting

- **Invalid property value**: query the exact property schema and use the evidenced canonical value. Use force only
  when intentionally preserving an out-of-schema observed value and document why.
- **Unexpected boundary crossing**: inspect geometry and rendered membership; do not suppress the rule before checking
  placement.
- **Property command succeeds but value is unchanged**: read it back with `show`; export/apply a clean candidate when
  direct mutation is unreliable.
- **Protocol or port finding on local communication**: use the discovered local-channel property only when evidence
  proves the communication is non-networked.
- **Missing audit finding**: add an audit store only when implementation evidence proves the records exist; otherwise
  retain the finding or unknown.
- **Analyzer exits with findings**: preserve structured output and inspect generated instances; do not retry as though
  it were a transient tool failure.
- **Stale persisted threats**: regenerate cleanly or remove stale entries, then list the register and compare object
  references with the final topology.
- **Rendering is visually compressed**: use semantic inventories and properties as the correctness source; rendering
  is a topology sanity check.
- **The model is unreadable in the Microsoft Threat Modeling Tool**: run `tmforge layout --check <model> --json` and
  the layout checker. Overlapping text is nearly always flow names too long for the gaps they span, not misplaced
  shapes — shorten the names and keep the sentence in the ledger. Shapes stacked in a corner mean the canvas ran past
  the tool's coordinate limit and the tool clamped them on load.
