---
name: threat-modeling
description: 'Create deterministic, evidence-backed STRIDE threat models. Use for scope discovery, data-flow diagrams, trust boundaries, assets, security controls, threat enumeration, risk scoring, model verification, and structured threat-model reports.'
user-invocable: false
---

# Evidence-Backed Threat Modeling

Use this workflow for every threat-modeling task. It defines the canonical reasoning contract; render documents and
diagrams from that contract rather than reasoning independently in each artifact.

Resolve resources relative to this installed skill directory, never the analyzed repository's skills directory.
The scripts require Python 3.10+ and only its standard library. Markdown analysis works without tmforge; load the
`threat-modeling-tmforge` skill by name for `.tm7` work and its approved managed launcher or user-selected CLI. Select the skill
provided by the `tmforge` plugin through the client's skill discovery, not a relative path outside this skill.

Bundled resources:

- [Analysis schema](./assets/analysis.schema.json)
- [Valid example ledger](./assets/analysis.example.json)
- [Canonical ledger validator](./scripts/validate_analysis.py)
- [Deterministic document renderer](./scripts/render_analysis.py)
- [Unified package verifier](./scripts/validate_package.py)
- [Changed-package verifier](./scripts/validate_changed_packages.py)
- [Suppression sidecar generator](./scripts/generate_suppressions.py)
- [Package rebuild driver](./scripts/rebuild_package.py)

## 1. Freeze Scope and Mode

Select exactly one mode before discovery:

- `analyze`: create one Markdown report; validate the canonical ledger in a temporary file and then remove it.
- `formal-package`: retain `analysis.json`, `data-flow.md`, `threat-model.md`, a lifecycle evidence sidecar, and a
  tmforge-generated `.tm7`. Prefer a declarative manifest as the authoritative source.
- `verify`: inspect existing artifacts and issue a lifecycle verdict without rewriting them unless requested.
- `update`: update the canonical ledger and affected artifacts while preserving stable IDs and the local convention.

### Resolve scope inputs

Record every scope source in `scope.inputs`. Use this precedence to decide what to model:

1. Explicit user scope, exclusions, and selected output mode.
2. User-referenced work items, issues, pull requests, branches, commits, files, selections, documents, or model
   artifacts.
3. The nearest existing model that owns the referenced workflow or trust boundary.
4. A bounded primary workflow inferred from current implementation and documentation.

Scope precedence selects the subject of the review. Evidence precedence in section 2 determines whether claims about
that subject are true. Implementation evidence may contradict a requested change record, but it must not silently
replace the workflow the user asked to model.

When a Feature, User Story, Bug, issue, pull request, branch, or commit is referenced:

- Resolve the primary record and material links needed to understand requirements, acceptance criteria, design notes,
  rollout constraints, and security expectations.
- Inspect related changes, commits, and changed files for implemented behavior, controls, and gaps.
- Record primary and supporting references separately. Treat record text as intent, not implementation proof.
- Follow a link only when it can change assets, actors, entry points, boundaries, flows, controls, threats, risk,
  mitigation, or ownership. Do not expand to every linked record.
- If the reference cannot be read, retain it as an unavailable scope input and state what access or artifact is needed.

Record the selected mode, workflow boundary, entry points, excluded adjacent systems, output location, artifact
convention, baseline revision when available, and lifecycle target before enumerating threats.

Start from assets, entry points, privileged operations, data flows, and trust-boundary crossings. Keep diagram scope
separate from implementation-evidence scope: an external component belongs in evidence scope when it authenticates,
authorizes, validates, transforms, routes, stores, or performs a privileged action for a material flow.

Maintain a scope ledger with: component, security role, question to answer, evidence source, and disposition
(`implementation-review`, `contract-only`, or `unavailable`). Follow another dependency only when the current
component delegates the relevant control. Stop when the question is answered, evidence is unavailable, the contract
is sufficient, or another hop cannot change a threat, risk, mitigation, or owner.

For external implementation evidence, derive the owning source from imports, dependency manifests, deployment
artifacts, generated clients, source-control links, and repository metadata. Check established local workspaces first.
Clone or fetch only when implementation review is required to answer a material security question; never clone every
linked repository. Use a known workspace location, or ask before choosing one. Authentication, authorization, network,
or metadata failures make that source `unavailable`, not evidence for or against a control.

### Resolve model ownership and drift

Models are owned by a bounded workflow or trust boundary, not an individual change record. Record exactly one
`scope.ownershipDecision`:

- `analysis-only` for a nonpersistent analysis and `verify-only` for verification without mutation.
- `update` when actors, entry points, boundaries, lifecycle, and ownership remain within an existing model.
- `append` for a tightly coupled subflow that shares that context but needs a separate diagram or view.
- `create` for materially distinct actors, entry points, boundaries, lifecycle, or ownership.
- `replace` only when scope drift or stale structure makes an in-place update misleading.

Before `verify` or `update`, compare model metadata, scope inputs, boundaries, elements, flows, controls, and persisted
findings with current evidence and the recorded baseline. Review changes since the baseline that can affect actors,
entry points, data flows, boundaries, privileges, credentials, protocols, validation, logging, storage, or recovery.
Mark the model `stale` when material drift remains unmodeled. Record the selected action, existing model reference when
applicable, and rationale.

## 2. Build the Evidence Ledger

Assign evidence IDs `E001`, `E002`, and so on. Preserve existing IDs and append monotonically. Sort new evidence by
normalized reference and locator before allocation.

Use this precedence when sources disagree:

1. Current runtime or deployed configuration from the scoped environment.
2. Generated configuration and current implementation at the recorded revision.
3. Executable tests, schemas, and interface contracts.
4. Current operational procedures and maintained technical documentation.
5. Design documents, work items, change descriptions, and names.
6. Assumptions and inference.

Higher-ranked evidence determines the modeled current state. Record lower-ranked contradictory evidence as drift.
Never use intent as proof that a control is active. Every material boundary, element, flow, asset, control, and threat
must reference at least one evidence ID. For unavailable evidence, create an `unknown` entry stating what is needed.

### Reconcile controls and findings

- Compare documentation, change records, generated configuration, deployed configuration, tests, and implementation
  when they describe the same capability. Record material contradictions as drift.
- Separate an implemented control from its residual gap. Mark current controls `implemented`, `partial`, or `unknown`;
  a partial or unknown control must state the gap and cannot reduce risk beyond what evidence proves.
- For privileged or high-impact permissions, identify the workload and effective identity, trace all applicable
  bindings, roles, policies, and exceptions, and determine whether privileges can be split by workload, identity,
  mode, or operation. Do not infer effective permission from one local policy fragment.
- Classify each finding as `design-gap`, `implementation-defect`, `operational-gap`, or `unknown`. A suspected
  implementation defect remains `unknown` until implementation or runtime evidence confirms it.
- For external dependencies, analyze outage and recovery behavior. A transient failure must not cause destructive
  state changes, credential revocation, integrity loss, or data loss unless an evidenced requirement deliberately
  selects fail-closed behavior.

## 3. Build the Canonical Analysis Ledger

Create `analysis.json` from the bundled schema before writing prose or diagrams. In `analyze` mode it may be a
temporary file; in `formal-package` and `update` modes retain it as the reviewable source for findings and counts.

The ledger contains:

- scope inputs, mode, lifecycle, baseline, exclusions, and the ownership decision;
- evidence, boundaries, elements, flows, assets, and threat actors;
- complete STRIDE coverage decisions;
- classified threats with independent origin and lifecycle status, implementation status for current controls,
  mitigations, verification steps, assumptions, and unknowns;
- the review disposition trail recorded against each reviewed threat; and
- canonical risk counts generated from the threat array.

Do not hand-maintain duplicate counts or inventories in rendered documents.

### Declare a boundary axis and keep boundaries flat

Every boundary declares an `axis` naming the kind of trust change it represents: `authority`, `host`,
`network-segment`, `network-namespace`, or `process-isolation`. Without it, boundaries drift into a mix of ownership
zones and network
segments, elements get assigned on one axis while a boundary was drawn on another, and a boundary can end up with no
members at all while the ledger still validates.

Nest boundaries only where the inner boundary is a strict subset of the parent *on the same axis* and containment is
enforced by a verified control. Cross-axis nesting asserts containment the deployment does not enforce. In Kubernetes
the axes deliberately do not nest: a pod network namespace is not inside a namespace authority zone, and a node
kernel is not inside either. Model a component that belongs to several zones by listing several `boundaryIds` rather
than by nesting the boundaries. Only the first entry is representable in a `.tm7` drawing surface, so order it
deliberately.

### Evidence where each component runs

Every material `process` and `data-store` names the evidence that establishes where it runs in
`placementEvidenceIds`, drawn from its own `evidenceIds`. Deployment location is routinely inferred from the
repository or component name that produced a component, which silently places it in the wrong cluster, host, or
namespace and then misstates every boundary it touches.

### Evidence the producer of every store

Every material `data-store` either receives at least one material inbound flow, or records in `producerRationale`
why no in-scope component writes it, naming the excluded renderer, external service, or bootstrap step that does.

A store with no writer is the point where models acquire invented elements. The reasoning that produces them is
plausible and wrong: something must write this object, no in-scope component does, therefore an operator or
administrator must. That reflex converts an unfinished trace into an actor, and the resulting model misstates who is
trusted, which identity an attacker must obtain, and where the mitigation belongs. Prefer an unknown that names the
missing evidence over a placeholder source, and re-test every writer-less store against an explanation once it has
been established for one of them.

### Derive boundary crossings, do not assert them

A flow crosses every boundary containing exactly one of its endpoints, so the crossed set is the symmetric difference
of the endpoint boundary sets. Sharing one axis does not cancel a crossing on another: a call between two pods in one
namespace still leaves a pod network namespace.

Record `crossesTrustBoundary` to match that derivation. To decline a derived crossing, add a `crossingExemptions`
entry naming the boundary, the rationale, and supporting evidence, for example a Secret that reaches a container as a
projected file rather than over the network. An exemption keeps a real judgement visible and arguable; an unexplained
`false` hides one and drops the flow from required STRIDE coverage.

## 4. Allocate Stable IDs and Ordering

Preserve every existing ID. Never renumber, reuse, or compact IDs after deletion.

The allocation rules below bootstrap a new model. They are not a rebuild strategy. Re-deriving IDs from a changed
inventory renumbers every entry after an insertion, because allocation is positional, and that silently invalidates
anything keyed by ID: diagram property tables, suppression justifications, review comments, and work-item links. The
failure is quiet and dangerous, because a justification written for one element stays syntactically valid while
attaching to a different one. Key every generator input, sidecar, and lookup table on a stable alias or name, and
prove stability by validating a rebuilt ledger against its predecessor with `validate_analysis.py --baseline`.

For a new model, freeze the discovered inventory, sort it, then allocate:

- Scope inputs: precedence order, then normalized `(kind, reference)` -> `SI001`, `SI002`, ...
- Boundaries: normalized `(parent ID, name)` order -> `TB1`, `TB2`, ...
- Elements: kind order `actor`, `external`, `process`, `data-store`, then normalized `(boundary IDs, name)`; use
  `A1`, `X1`, `P1`, and `DS1` respectively.
- Flows: normalized `(source ID, target ID, name)` order -> `F1`, `F2`, ...
- Assets: normalized name order -> `AS1`, `AS2`, ...
- Threat actors: normalized `(capability, name)` order -> `TA1`, `TA2`, ...
- Assumptions and unknowns: normalized text order -> `A001` and `U001`.

On update, allocate the next numeric suffix for that prefix after the highest existing value. Append new entries and
then sort arrays by natural ID order. Sort coverage by natural target ID and category order `S`, `T`, `R`, `I`, `D`,
`E`.

A `name` is a label, not a description. It is drawn on the diagram beside its ID, unwrapped, so a long one covers the
shapes around it; keep a flow name to a terse phrase and put the explanation in `data-flow.md`, which is keyed by the
same ID and is where a reviewer reads it. The tmforge skill records the exact budget and the check that enforces it.

For new threat IDs:

1. Derive `AREA` from the scope slug: uppercase it, remove non-alphanumeric characters, take the first 12 characters,
   and use `MODEL` if empty. Preserve an established area code on update.
2. Sort new candidates by natural target ID, STRIDE order, and normalized title.
3. Allocate the next unused ID per category as `AREA-S-001`, `AREA-T-001`, and so on.
4. Never change an ID because severity, title, status, or ordering changed.

Record threat provenance independently from lifecycle status:

- `manual`: authored from evidence-backed STRIDE analysis;
- `generated`: produced by an analyzer and reconciled into the canonical ledger; or
- `imported`: retained from a pre-existing register or external source.

Origin is immutable provenance unless evidence proves the entry was misclassified. It does not determine lifecycle:
a threat from any origin may be `open`, `mitigated`, `accepted`, `transferred`, or `unknown`.

## 5. Complete STRIDE Coverage

Required coverage targets are every material element and every material flow that crosses a trust boundary. Evaluate
all six STRIDE categories for each target in fixed order.

Each coverage cell must be exactly one of:

- `applicable`: references one or more threat IDs for the same target and category; or
- `not-applicable`: has no threat IDs and includes a specific, evidence-backed rationale.

Do not create generic checklist findings merely to fill a cell. A threat must identify the abuse path, preconditions,
affected target and asset, current controls, impact, and concrete mitigation. A shared threat may satisfy multiple
coverage cells only when every referenced target is explicitly included in that threat.

Every mitigation identifies the control to add or change, an accountable owner (`unassigned` when unresolved), the
implementation location or enforcement point, and an executable verification step.

## 6. Score Current Residual Risk

Score the current residual risk after controls proven by evidence. An unknown control does not lower likelihood or
impact; mark confidence lower without asserting that the control is absent.

Choose the highest applicable likelihood anchor:

| Score | Observable anchor                                                                                                                          |
|-------|--------------------------------------------------------------------------------------------------------------------------------------------|
| 1     | Requires trusted administrative control plus exceptional timing, with verified preventative controls.                                      |
| 2     | Requires specialized access or uncommon timing and bypass of strong, verified controls.                                                    |
| 3     | Requires privileged authenticated access or multiple plausible preconditions; controls are partial.                                        |
| 4     | Requires ordinary authenticated access, one common precondition, or compromise of a low-privilege component; barriers are weak or partial. |
| 5     | Reachable without authentication or with routine access and no meaningful verified barrier.                                                |

Choose the highest applicable impact anchor:

| Score | Observable anchor                                                                                                 |
|-------|-------------------------------------------------------------------------------------------------------------------|
| 1     | Negligible security or operational effect.                                                                        |
| 2     | Localized, readily recoverable effect involving no sensitive asset or privileged action.                          |
| 3     | Limited sensitive-data exposure, integrity loss, privilege misuse, or recoverable service disruption.             |
| 4     | Broad sensitive-data exposure, high-impact privileged action, significant isolation failure, or prolonged outage. |
| 5     | Systemic compromise, irreversible critical-data loss, catastrophic isolation failure, or safety-critical impact.  |

Calculate `score = likelihood * impact` and map it exactly:

| Score | Level      |
|-------|------------|
| 20-25 | `critical` |
| 12-19 | `high`     |
| 6-11  | `medium`   |
| 1-5   | `low`      |

Use only these threat statuses:

- `open`: residual risk remains and has not been accepted.
- `mitigated`: implementation evidence and the stated verification step prove the mitigation.
- `accepted`: an identified decision owner explicitly accepted the residual risk.
- `transferred`: a named owner or enforceable contract carries the risk.
- `unknown`: evidence is insufficient to determine current disposition.

Confidence is `0.0` to `1.0` and reflects evidence quality, not risk severity.

Before finalizing, compare threats with equivalent preconditions, controls, and impact. Apply the same likelihood and
impact anchors; when similar threats receive different values, record the material reason.

## 7. Record Review Dispositions

Review is where findings are most easily lost. A reviewer says a finding is already fixed, or duplicates another, or
belongs to a neighbouring team, and the assertion quietly closes it. Pull-request threads are the worst possible home
for those decisions: they are unversioned, unqueryable, and they disappear the moment the pull request merges, so the
next reviewer re-litigates the same finding from scratch.

Record each decision as a `triage` entry on the threat it concerns. The entry carries `date`, `reviewer`, `decision`,
and `rationale`, plus `reference`, `relatedThreatIds`, `workItemIds`, and `evidenceIds` where they apply. Entries
accumulate and are sorted by date then reviewer, so the trail shows how a finding's disposition changed rather than
only where it landed.

Use only these decisions:

- `confirmed`: reviewed and stands as written.
- `corrected`: reviewed and the ledger was amended in response; the rationale states what changed.
- `disputed`: the reviewer disagrees about existence, scope, or severity, and the disagreement is unresolved.
- `duplicate`: the reviewer asserts overlap with another finding named in `relatedThreatIds`.
- `deferred`: valid and understood, deliberately not scheduled.
- `resolved`: the reviewer states it is already addressed.

Triage records what review decided. It never substitutes for the evidence that decides whether a control is real, so
three rules are enforced rather than advised:

- `resolved` requires `evidenceIds` and a threat `status` of `mitigated` or `transferred`. A statement that something
  is fixed is not proof that it is; the commit, pull request, or runtime observation belongs in the evidence ledger
  first, at its true evidence rank. A reviewer's recollection is an `assumption`, not `runtime` evidence.
- `duplicate` requires `relatedThreatIds`. Overlapping findings are cross-linked, not merged: STRIDE coverage is
  per-element and per-category, and collapsing two categories into one leaves a coverage cell unanswered. Cross-link
  them, and note in the mitigation when a single fix closes both so remediation planning does not double-count.
- `disputed` requires a `reference`. A dispute that cannot be read later is indistinguishable from a finding nobody
  looked at.

A finding leaves a model by `transferred` to a named owner, never by deletion. "Not our component" is the most common
way cross-boundary risk evaporates: transfer states who now carries it, while deletion states nothing.

### Responding to review without rebuilding

Use `update` mode. Edit the ledger and rerender; never hand-edit a generated document, and never rebuild a package to
absorb a comment. The ID allocation rules in section 4 are not a rebuild strategy, and a rebuild renumbers every entry
after an insertion, silently detaching suppressions, work items, and the review comments being answered.

Triage classes cost very different amounts, so classify a comment before acting on it:

| Class                | Typical comment                         | Ledger change                                        |
|----------------------|-----------------------------------------|------------------------------------------------------|
| Disposition          | "fixed in that pull request", "tracked" | `triage` entry, `status`, new evidence               |
| Evidence correction  | "that external service refuses it"      | `triage` entry, new evidence, control, rescore       |
| Scope dispute        | "that belongs to the other component"   | `triage` entry, re-scope or `transferred`            |
| Duplicate claim      | "repeat of another finding"             | `triage` entry with `relatedThreatIds`, cross-link   |
| Topology correction  | "those are not separate processes"      | elements, flows, coverage, geometry, justifications  |

Only the last class touches structure, and it is the one that cascades into the diagram manifest and its sidecars.
Validate it with `validate_analysis.py --baseline` against the previous ledger, which refuses a rename, a renumber, or
a dropped ID.

Collect comments before the pull request merges and record each durable thread reference in the triage entry.
Reply on the originating thread with the threat ID, triage decision, and any correcting commit.

One person reconciles the ledger; reviewers comment rather than edit, and validation proves the reconciliation.
Re-baseline before circulating a draft. Record material drift as `stale` rather than asking reviewers to assess old code.

## 8. Render the Selected Deliverables

Do not hand-author persistent `data-flow.md` or `threat-model.md` files. After the canonical ledger passes validation,
resolve the bundled renderer from this skill's directory and run:

```bash
python3 <skill-directory>/scripts/render_analysis.py <package-directory>/analysis.json
```

The renderer is the sole owner of these generated documents. It uses stable templates and ledger ordering, writes
atomically, omits volatile timestamps, and does not rewrite unchanged files. Change the ledger and rerun the renderer
instead of editing generated Markdown. Its tables are padded to a common column width deliberately so that a
repository Markdown table formatter leaves them untouched; reformatting generated Markdown by any other tool desyncs
it from the ledger and turns the delivery gate permanently red. In `analyze` mode, render the requested standalone
report from the temporary ledger without companion links:

```bash
python3 <skill-directory>/scripts/render_analysis.py <temporary-analysis.json> \
  --standalone-report <report.md>
```

The threat-model report always includes these core sections:

1. Document information and lifecycle.
2. Scope, exclusions, evidence baseline, assumptions, and unknowns.
3. Architecture, boundaries, elements, enumerated flows, assets, and evidence-backed threat-actor profiles.
4. STRIDE coverage summary.
5. Threat register with current controls, residual risk, status, mitigation, and verification.
6. Prioritized recommendations.
7. Validation results and change log when applicable.

Include attack scenarios only for plausible high or critical paths. Include a separate controls inventory only when it
adds information not already present in the threat register. Do not add filler sections to satisfy a fixed count.

In `formal-package` mode, `data-flow.md` is the semantic architecture document and `threat-model.md` is the review
surface. Cross-link both to `analysis.json` and the generated `.tm7`. Keep diagrams aligned 1:1 with ledger IDs and
flows. In manifest-as-source mode retain both sibling files: edit the manifest, generate the `.tm7` with tmforge, and
never hand-edit the generated artifact. In `update` mode regenerate the `.tm7` whenever the manifest or modeled
topology changes.

The data-flow document includes actors, processes, stores, external dependencies, stable boundary IDs, stable flow
IDs, a flowchart, a sequence diagram for the primary workflow, intentionally excluded or absent flows, and evidence
references for every material object and flow. Do not add a diagram flow that is absent from the ledger.

Select attack scenarios from open or unknown high/critical threats, ordered by score descending and then natural
threat ID. Include at most five distinct end-to-end paths and omit the section when no plausible high-impact path
exists; never add filler scenarios to reach a fixed count.

## 9. Validate Before Delivery

For a temporary ledger used only in `analyze` mode, run the canonical validator:

```bash
python3 <skill-directory>/scripts/validate_analysis.py <analysis.json>
```

For every retained package, generate or refresh its `.tm7`, then run the unified package verifier after rendering:

```bash
python3 <skill-directory>/scripts/validate_package.py <package-directory>
```

Use `--json` for stable machine-readable results. When a candidate artifact is promoted, also pass explicit
`--candidate <path> --final <path>` arguments to verify byte equivalence. Use `--tmforge <command>` when tmforge is
available through a wrapper rather than directly on `PATH`, including the managed launcher selected by the tmforge
skill. Pass the same complete command, with quoted paths, to the package verifier, changed-package `verify`, and
rebuild driver so all checks use the same CLI version. Do not silently fall back to a different global executable.

### Validating every package changed in a session

The unified verifier checks one package at a time. To catch every package touched during a working session,
including ones changed incidentally, take a baseline before editing and verify afterwards:

```bash
python3 <skill-directory>/scripts/validate_changed_packages.py snapshot --root <repository-root>
python3 <skill-directory>/scripts/validate_changed_packages.py verify --root <repository-root>
```

Use the same root for both commands. Without `--root`, the current Git worktree is discovered from the working
directory, not from the installed script. An explicit root supports non-Git directories. `--state-dir` isolates
parallel sessions on the same worktree; default snapshots live in temporary storage, outside the installed plugin.

`verify` runs the unified verifier against each package whose files changed since the snapshot, and exits non-zero
when any package fails. Pass `--all` to validate every retained package without a baseline, and `--keep` to retain
the baseline for a later run. This detects document-only edits too, so a hand-edited generated Markdown file is
caught rather than silently diverging from its ledger.

The ledger validator enforces structure, unique and natural ID ordering, referential integrity, evidence references,
complete STRIDE coverage, category consistency, score arithmetic, risk mapping, controlled statuses, and canonical
summary counts. It also enforces the topology invariants that content review reliably misses: every boundary declares
a known axis, no boundary is left without members, nesting stays within one axis, every material process and store
evidences where it runs, each flow's crossing claim matches the topology or carries an evidenced exemption, every
material store either receives a modelled write or records `producerRationale`, and every coverage cell marked
`not-applicable` has no threat contradicting it. Pass `--baseline <previous-analysis.json>` when rebuilding an existing
ledger to catch positional ID renumbering before it invalidates manifests, sidecars, or published references.

The package verifier runs that contract, compares generated Markdown with deterministic expected bytes, checks
Markdown, Mermaid, local links, IDs, and counts, validates included `.tm7` artifacts through tmforge, checks stale
persisted object references, verifies explicit candidate/final equivalence, and checks diagram geometry. It fails a
package whose diagram draws an element outside its boundary or overlaps shapes, because a reader takes containment as
a trust claim; it warns on single-column stacking, connector crossings, and unreadable aspect ratios. Fix the
canonical ledger, rerender, and rerun the verifier before delivery.

Diagram geometry belongs in the manifest. Derive it with
[the layout generator](./scripts/layout.py), which layers boundaries left to right by flow direction, grids elements
inside their own boundary, and searches orderings to minimise crossings. It permutes exhaustively only within small
groups, so a dense model can settle in a poor local minimum; pass `--restarts <n> --seed <n>` to sample randomised
starting orders and keep the best result. Restarts cost time roughly linearly, so raise them only while crossings
remain. Inspect any generated `.tm7` directly with [the layout checker](./scripts/check_layout.py). Never repair a
diagram with an automatic layout pass; see the tmforge skill for why that silently breaks containment.

Rebuilding a package by hand invites a stale artifact, because the steps are order-dependent and a skipped one usually
fails silently rather than loudly. Drive the whole sequence with
[the rebuild driver](./scripts/rebuild_package.py), which regenerates the manifest, validates the ledger, applies the
manifest through tmforge, checks layout, regenerates and verifies the suppression sidecar, renders, and runs the
package verifier, stopping at the first failure:

```bash
python3 <skill-directory>/scripts/rebuild_package.py <package-directory> \
    --manifest-command "<command that regenerates the manifest>" \
    --justifications <justifications.json> --baseline <previous-analysis.json>
```

Run compatible local formatting and stricter package gates when discovered. If a required validator cannot run,
report the artifact as `unvalidated`; do not silently substitute a weaker verdict.

Capture repeatable friction separately from product findings: missing indexes or ownership metadata, inaccessible
evidence, unclear boundaries or flows, missing stencils/properties/rules, and recurring control patterns. Recommend the
smallest reusable documentation, tooling, or instruction improvement, or report `None`.
