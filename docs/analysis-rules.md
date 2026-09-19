# Analysis rules & CI

Threat Model Forge ships a built-in rule set that runs against any model and flags completeness,
diagram-hygiene, and security-property issues. The same engine backs `tmforge analyze`, Studio's
**Analyze** button, and the API's `POST /v1/model/analyze`.

## Running analysis

```bash
tmforge analyze model.tm7                       # human-readable
tmforge analyze model.tm7 --json                # machine-readable envelope
tmforge analyze model.tm7 --reportFolder ./out  # + SARIF, HTML, and JSON listing
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean, no findings at or above `--max-severity`. |
| `1` | Tool error (bad arguments, load failure). |
| `2` | The model was analyzed and has findings at or above `--max-severity` (default: `error`). |

The dedicated `2` lets CI **fail on findings** while distinguishing them from a broken invocation.

### Severities

Findings carry a severity: **Error**, **Warning**, or **Info**. By default only **Error** findings set
the "found issues" exit code (`2`); pass `--max-severity warning` (or `info`) to `tmforge analyze` to gate
the build on those severities too.

## Rule packs

A **rule pack** is a named, selectable group of related rules. Packs are the single source of truth
that hosts (the CLI, API, and Studio) consume, so their names and ordering never drift from the rules
that declare them. List them from the API with `GET /v1/rule-packs`.

| Pack id | Display name | Focus |
| --- | --- | --- |
| `core-hygiene` | Core Hygiene | Structural completeness and diagram hygiene (connectivity, naming, size). |
| `stride-completeness` | STRIDE Completeness | Trust boundaries, boundary crossings, external interactors, and flow metadata. |
| `input-validation` | Input Validation | Inputs/outputs validated or sanitized across trust boundaries. |
| `data-protection` | Data Protection | Data-at-rest protection: encryption, access control, integrity, retention. |
| `transport-security` | Transport Security | Data-in-transit protection across trust boundaries. |
| `identity-access` | Identity & Access | Authentication, least privilege, and access to components. |
| `availability` | Availability | Recoverability and audit-trail durability: backups for important data. |

## Built-in rules

The default rule set covers connectivity and naming hygiene, STRIDE modeling completeness, and a set
of security-property checks, grouped by pack. The set grows over time, so treat the tables below as a
snapshot. `tmforge` and the engine's `GET /v1/rules` report the live rule set.

### Core Hygiene (`core-hygiene`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1000 | Unconnected components | Error | Every component is connected by at least one flow. |
| 1001 | Unconnected edges | Error | Every data flow has both endpoints attached. |
| 1002 | Descriptive edge name | Warning | Flows have meaningful, non-default names. |
| 1005 | Minimum component count | Warning | A diagram has at least three components. |
| 1011 | Descriptive generic component name | Error | Generic components are renamed from their default label. |
| 1012 | Descriptive specific component name | Warning | Named components have meaningful names. |

### STRIDE Completeness (`stride-completeness`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1003 | Missing any trust boundary | Error | The model has at least one trust boundary. |
| 1004 | Missing any trust-boundary crossing | Error | At least one flow crosses a trust boundary. |
| 1006 | Missing any external interactors | Warning | At least one diagram has an external interactor. |
| 1007 | Outbound storage edge | Warning | Outbound flows from storage correctly describe data flow. |
| 1008 | Edge missing protocol | Error | A flow declares the protocol it uses. |
| 1009 | Edge missing protocol description | Info | A flow mentions its protocol in the description text. |
| 1010 | Edge missing port | Warning | A flow declares a port when it can't be inferred from the protocol. |
| 1013 | Edge missing data classification | Warning | A flow declares a data classification. |
| 1029 | Unaudited boundary process | Warning | A process receiving input across a trust boundary writes to an audit-log store so its actions can be attributed. |

### Input Validation (`input-validation`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1017 | Unsanitized cross-boundary input | Warning | A process receiving input across a trust boundary validates or sanitizes it. |
| 1018 | Unsanitized external output | Warning | A process sending output to an external entity encodes or sanitizes it. |
| 1019 | Weak process isolation | Warning | A process receiving input across a trust boundary runs with isolation. |

### Data Protection (`data-protection`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1014 | Unencrypted secret store | Warning | A store holding credentials is encrypted at rest. |
| 1020 | Unprotected credential store | Warning | A store holding credentials enforces meaningful access control (not `None`/`Public`). |
| 1021 | Unsigned audit-log store | Warning | A store holding log or audit data is signed for integrity. |
| 1022 | Credentials in log store | Warning | A store recording log data does not also store credentials. |
| 1025 | Weak or unapproved cipher | Warning | A flow or store declaring an encryption algorithm uses an approved authenticated cipher (AES-GCM, AES-CBC+HMAC, or ChaCha20-Poly1305). |
| 1027 | Cached credential read | Warning | A flow reading from a credential store is not cached (`Cached=No`), so a rotated or revoked credential is not served stale. |
| 1030 | Sensitive data to external | Warning | A flow carrying sensitive data (EUII, EUPI, customer content, account data, or access-control data) is not sent to an external interactor. |

### Transport Security (`transport-security`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1016 | Cleartext trust-boundary crossing | Warning | A flow crossing a trust boundary doesn't use a cleartext protocol. |

### Identity & Access (`identity-access`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1015 | Unauthenticated boundary process | Warning | A process receiving input across a trust boundary declares an authentication scheme. |
| 1023 | Unauthenticated external source | Warning | An external entity initiating flows into the system authenticates itself. |
| 1024 | Over-privileged process | Warning | A process does not run as a highly privileged account (root/admin/system). |
| 1026 | Shared static identity | Warning | A single `Identity` is not asserted by flows from 2+ distinct sources; each calling principal has its own scoped identity. |

### Availability (`availability`)

| ID | Rule | Severity | Checks |
| --- | --- | --- | --- |
| 1028 | Data store without backup | Warning | A store holding credentials or audit/log data declares a backup (`Backup=Yes`), so its contents can be recovered after loss or a destructive attack. |

## Rule help

Every finding carries the rule's **ID** (for example `TM1016`). To see what a rule checks and how to
clear it:

- **Studio**: open the **Analysis Rules** panel and click the **?** on a rule to expand its description
  and fix guidance in place. That text ships with the engine, so it always matches the rule that ran.
- **CLI / API**: `GET /v1/rules` returns each rule's `description`, `helpText`, and `helpUri`, and
  both the HTML report and SARIF carry the rule's `helpUri` for code-scanning dashboards.

Each rule also advertises a documentation link (`helpUri`) that points back at this page. The public
docs URL is still being finalized, so that external link goes live once the repository is published.
The in-app description and fix guidance never depend on it.

## Fixing findings

Many findings are cleared by setting a **custom property** on the offending element or flow. From the
CLI, use [`set`](cli-reference.md#set) (or `connect --property` / `add --property` at creation):

```bash
# Clear "edge missing protocol/port" on a flow:
tmforge set model.tm7 --id <flow-guid> --property Protocol=HTTPS --property Port=443

# Clear "unauthenticated boundary process" on a process:
tmforge set model.tm7 --id <process-guid> --property AuthenticationScheme=OAuth
```

Common rule-checked properties include `Protocol`, `Port`, `DataType` / data classification,
`AuthenticationScheme`, `SanitizesInput` / `SanitizesOutput`, `Isolation`, `AccessControl`, `Signed`,
`AuthenticatesItself`, `RunningAs`, `Algorithm`, `StoresCredentials` / `StoresLogData`, `Backup`, and
encryption/at-rest flags. In [Studio](studio-guide.md), edit the same properties in the inspector and
re-**Analyze**.

### `Unknown` and the three states of a control

A control property carries three distinct states, and they are not interchangeable:

| Value | Meaning | Effect |
| --- | --- | --- |
| `Encrypted=TDE` | The control is in place. | Finding cleared. |
| `Encrypted=No` | Somebody checked; the control is not in place. | Finding, worded as a confirmed absence. |
| `Encrypted=Unknown`, blank, or the property absent | Nobody has recorded anything. | Finding, worded as an evidence gap. |

`Unknown` is a real, schema-valid value on every control-like property, so you can record honest
uncertainty without `--force` and without claiming the control is missing:

```bash
tmforge set model.tm7 --id <store-guid> --property Encrypted=Unknown
```

**`Unknown` never clears a finding.** It reports at the same rule id and the same severity as an
absent control; only the message changes, from "is not encrypted at rest" to "its `Encrypted` property
is not evidenced". This is deliberate. A missing property has always produced a finding, so letting
`Unknown` suppress one would mean an author could silence a real risk by typing a word — and a report
that says "no findings" because nobody looked is worse than no report at all.

`Unknown` survives every format hop (`tmforge-json`, `.tm7`, manifests) and every surface (CLI, API,
MCP, WASM, Studio). Existing `No` and `None` values are left exactly as they are; there is no
migration, because those values are statements an author made.

## Customizing the rule set

### Selecting rules and packs

When a model is loaded from the native **`tmforge-json`** format, any embedded analysis selection
(disabled packs or rule ids) is honored automatically, so a model can carry its own policy. Other
formats (for example `.tm7`) use the full rule set unless you pass an explicit `--ruleset`.

### Custom rule set file

```bash
tmforge analyze model.tm7 --ruleset ./my-ruleset.xml
```

### Authoring custom rules (declarative)

Ship your own rules as **data**, not code. A declarative rule spec is a JSON file (`*.tmrules.json`)
loaded with `--rules` on [`analyze`](cli-reference.md#analyze), [`threats`](cli-reference.md#threats),
and [`properties`](cli-reference.md#properties):

```bash
tmforge analyze model.tm7 --rules ./rules.tmrules.json   # one spec file
tmforge analyze model.tm7 --rules ./rules/               # a directory of specs (searched recursively)
```

The [starter rule-pack library](../examples/README.md#starter-rule-packs) provides opt-in PCI-inspired,
HIPAA-inspired, and internal-service examples, with a runnable synthetic model, source/control
references, and tested command snippets. These examples do not certify compliance.

To compile an existing MTMT template instead of hand-authoring JSON, use [`rules import`](cli-reference.md#rules):

```bash
tmforge rules import --from template.tb7 --out template.tmrules.json --strict
tmforge analyze model.tm7 --rules template.tmrules.json
```

The import preserves source expressions and metadata in provenance. A non-strict import writes all
exactly representable threats and reports skipped threats; `--strict` writes nothing if any threat is
skipped. Generated packs remain subject to the source template's license and attribution terms.

#### `ROOT` rules run once per diagram

An imported threat whose filter is `source is 'ROOT'` — the six migrated STRIDE types `SU`, `TU`,
`RU`, `IU`, `DU`, and `EU` in Microsoft's default template — is evaluated **once per diagram**, and
reports the diagram itself as the finding's target.

This is a deliberate difference from the Microsoft Threat Modeling Tool, which generates strictly once
per interaction and never fires these rules at all: it builds an element's type chain without the
virtual `ROOT` type at its head, so `source is 'ROOT'` cannot hold for any element. The types are
inert there, and their own descriptions record them as migrated from version 3.

Threat Model Forge keeps them live because a per-diagram STRIDE sweep is useful coverage, so expect
these rules to report findings the tool does not. They are Threat Model Forge behavior rather than a
parity claim. Nothing changes on export: a rule that cannot fire in the tool contributes no threats to
an exported `.tm7`. The evidence is the committed capture under
`test/ThreatModelForge.Analysis.Tests/Fixtures/MtmtDifferential/`.

Because a spec is inspectable data — not an assembly — it is safe to share and review, and it runs
everywhere the CLI does. Custom rules are **added to** the built-in rules, never a replacement for
them: `--rules` loads your rules *alongside* the full built-in set and both are evaluated together
(custom rules show up in findings, SARIF, `analyze --json`, and — when they read a property — in
`properties --explain`). To narrow the built-ins, use the existing controls independently of
`--rules`: a model's embedded `disabledPacks`, an `--ruleset` override, or `--max-severity`.

A version 2 pack is a strict, self-describing envelope. The envelope is importer-neutral and names a
rule-language `dialect`; source-specific concepts belong in the optional generic `source` and
`provenance` records. It also carries the category, element-type, and property catalogs needed by
compiled rules. The runtime computes the pack's `sha256:` fingerprint from the exact file bytes;
authors do not declare it.

### Custom rules on every surface

A rule pack is not a CLI-only feature. Every transport resolves rules through the same engine seam,
so one pack produces the same catalog entries, findings, threats, reports, and `.tm7` exports
everywhere. Only *how the pack reaches the engine* differs, because only some hosts can safely touch
the filesystem:

| Surface | How a pack is supplied | Notes |
| --- | --- | --- |
| CLI | `--rules <file-or-directory>` on `analyze`, `threats`, `report`, `properties` | Paths are resolved by the CLI. |
| HTTP API | `TmForge:Rules` configuration (a `;`-separated list, or an array) read once at startup | Packs are trusted deployment configuration; a request can never inject rules. |
| Studio / in-browser engine | **Analysis Rules → Load rule pack…** | The pack is read in the browser and handed to the WebAssembly engine as content. |
| MCP server | `rulesPath` on the `analyze`, `threats`, `report`, `rules`, and `rule_packs` tools | Resolved only through the configured MCP workspace root. |

Ask any host what it actually loaded. The API exposes `GET /v1/rule-bundle`; the Studio shows the
same information under **Analysis Rules**. Both report each pack's id, version, dialect, rule count,
and content fingerprint, plus every load diagnostic — so a pack that failed to parse is visible
instead of looking like a clean run against the built-in rules.

Models can pin the packs they were reviewed with. A `tmforge-json` model's analysis selection may
carry `expectedPacks`:

```jsonc
{
  "analysis": {
    "expectedPacks": [
      { "id": "corporate", "fingerprint": "sha256:\u2026" }
    ]
  }
}
```

If an expected pack is missing from the effective bundle, or its content fingerprint has changed,
analysis emits an **error** finding with rule id `rule-pack-mismatch`. That fails a build gated on
errors, which is the point: a model must never look clean merely because the rules that would have
flagged it were not loaded. The Studio records these pins for you when you load a pack.

```jsonc
{
  "schema": "tmforge-rules",
  "version": 2,
  "dialect": "urn:tmforge:rules:flat-v1",
  "pack": {
    "id": "azure-template-a1b2c3d4",
    "name": "Azure Threat Model Template",
    "version": "1.0.0.33",
    "source": {
      "type": "urn:tmforge:source:mtmt-tb7",
      "name": "Azure Cloud Services.tb7",
      "id": "11111111-1111-1111-1111-111111111111",
      "version": "1.0.0.33"
    }
  },
  "categories": [
    { "id": "D", "name": "Denial of Service" }
  ],
  "elementTypes": [
    { "id": "GE.P", "name": "Process", "parentId": "ROOT" }
  ],
  "properties": [
    {
      "name": "Cache Type",
      "aliases": ["cacheType", "cache-type"],
      "allowedValues": ["Static", "Distributed"],
      "elementTypeIds": ["GE.P"]
    }
  ],
  "rules": [
    {
      "id": "TH112",
      "severity": "error",
      "appliesTo": "process",
      "message": "{name} uses an unsafe cache.",
      "assert": { "property": "Cache Type", "equals": "Distributed" },
      "provenance": {
        "sourceId": "TH112",
        "categoryId": "D",
        "expressions": [
          {
            "role": "include",
            "language": "urn:tmforge:source:mtmt-generation-filter",
            "text": "target is 'GE.P'"
          }
        ]
      }
    }
  ]
}
```

The authoritative Draft 2020-12 schema is packaged as `schemas/tmforge-rules-v2.schema.json` and is
available in-process through `RulePackSchema.VersionTwo`. Version 2 rejects unknown fields and
dialects, ambiguous property aliases, duplicate catalog ids, hierarchy cycles, unresolved catalog
links, and caller-supplied fingerprints. `source.type` and provenance expression `language` values
must be namespaced identifiers; the base schema does not reserve an importer vocabulary.
Rule `helpUri` values must use HTTP or HTTPS; HTML reports independently refuse other URI schemes.
Pack, category, element-type, and rule identity segments are printable ASCII without `/` or
surrounding whitespace so effective rule ids remain safe in persisted TM7 threat keys.

`urn:tmforge:rules:interaction-v1` evaluates rules over an interaction containing `source`, `target`,
`flow`, and crossed trust boundaries. Its recursive expression nodes are:

```jsonc
{
  "schema": "tmforge-rules",
  "version": 2,
  "dialect": "urn:tmforge:rules:interaction-v1",
  "pack": { "id": "interaction-example", "name": "Interaction example" },
  "elementTypes": [
    { "id": "GE.P", "name": "Process", "parentId": "ROOT" },
    { "id": "SE.P.Web", "name": "Web process", "parentId": "GE.P" },
    { "id": "GE.TB.B", "name": "Trust boundary", "parentId": "ROOT" }
  ],
  "properties": [
    { "name": "Protocol", "allowedValues": ["HTTP", "TLS"] }
  ],
  "rules": [
    {
      "id": "CLEAR-TEXT",
      "message": "{source.Name} sends {flow.Name} to {target.Name} without TLS.",
      "expression": {
        "allOf": [
          { "subject": "source", "type": "GE.P" },
          { "crosses": "GE.TB.B" },
          {
            "not": {
              "subject": "flow",
              "property": "Protocol",
              "valueIn": ["TLS"]
            }
          }
        ]
      }
    }
  ]
}
```

Type predicates walk `elementTypes.parentId` transitively. Property membership checks all stored
values. `crosses` matches the declared boundary type or one of its descendants. A
`source is ROOT` expression is evaluated once per diagram; ordinary expressions are evaluated once
per flow. `{source}`, `{target}`, and `{flow}` message tokens, with or without `.Name`, are replaced
case-insensitively.

The MTMT GenerationFilters compiler resolves source property aliases and element types against the
source TB7 catalog. Values for static attributes must appear in that attribute's declared value set;
dynamic attributes remain open to runtime-defined values. Include and Exclude are validated again
after composition, so node and depth limits apply to the final evaluator tree.

An effective v2 rule id is `pack.id/rule.id` (for example
`azure-template-a1b2c3d4/TH112`). This lets two imported templates retain the same source ThreatType
id without colliding in SARIF, suppressions, or generated threat keys. Duplicate effective ids that
involve a v2 rule reject every contender, so changing file or declaration order cannot choose a
winner. `RulePackIdentity.CreatePackId` provides the deterministic
`normalized-name-<32 hex chars>` convention used by importers (128 fingerprint bits). The full
fingerprint remains available on `RulePackDefinition.Fingerprint`, and every surface reports it (see
[Custom rules on every surface](#custom-rules-on-every-surface)).

The loader bounds untrusted input per pack to 8 MiB, 4,096 rules, 512 categories, 4,096 element
types, 8,192 property definitions, and 65,536 aggregate catalog/expression nodes and values. A single
load is additionally capped at 128 files, 32 MiB, 16,384 rules, 2,048 categories, 16,384 element
types, 32,768 properties, and 262,144 catalog/expression entries. Interaction expressions are limited
to 64 levels; evaluation is bounded to 100,000 interaction contexts and 1,000,000 expression
operations per rule, with 10,000,000 declarative operations shared across the full analysis
invocation. Analysis output is capped at 100,000 messages and 64 MiB of message text; individual
expanded messages in either dialect are capped at 65,536 characters. Strings are limited to 65,536
characters and identity segments to 512 characters.

The original unversioned shape remains supported unchanged for hand-authored packs. It is a `rules`
array, and each rule may declare its own `pack` value:

```jsonc
{
  "rules": [
    {
      "id": "ACME001",                 // your own id namespace (built-ins use TM####)
      "pack": "acme-governance",
      "severity": "error",             // error | warning | info (default: warning)
      "appliesTo": "datastore",        // process | datastore | external | flow
      "message": "Data store {name} does not declare encryption at rest.",
      "fullDescription": "Persisted data must be encrypted at rest.",
      "helpText": "Set Encrypted to At-rest, TDE, Client-side, or Platform.",
      "assert": { "property": "Encrypted", "anyOf": ["At-rest", "TDE", "Client-side", "Platform"] }
    },
    {
      "id": "ACME002",
      "pack": "acme-governance",
      "severity": "warning",
      "appliesTo": "flow",
      "message": "Flow {name} carries sensitive data in the clear across a trust boundary.",
      "stride": "InformationDisclosure",           // optional; makes it a `threats` threat
      "threatReferences": ["CWE:319"],             // optional: CWE:<n> | CAPEC:<n> | ATTACK:<id>
      "when":   { "property": "DataType", "anyOf": ["EUII", "Customer Content"], "crossesTrustBoundary": true },
      "assert": { "property": "Protocol", "anyOf": ["HTTPS", "TLS", "mTLS"] }
    }
  ]
}
```

For both versions, a finding is raised for each element of `appliesTo` that matches `when` (the
guard) and fails `assert` (the requirement); at least one of `when`/`assert` is required.

The `{name}` token in `message` is replaced with the element's display text. **Conditions** (`when`
and `assert`) are facets that must *all* hold; a bare `property` with no value matcher means "must be
present":

| Facet | Applies to | Meaning |
| --- | --- | --- |
| `property` + `anyOf` | any | The value is one of the listed values. |
| `property` + `notAnyOf` | any | The value is none of the listed values. |
| `property` + `equals` | any | The value equals a single value. |
| `property` + `present` | any | The property is present (`true`) or absent (`false`). |
| `property` + numeric bounds | any | Invariant-decimal `greaterThan`, `greaterThanOrEqual`, `lessThan`, or `lessThanOrEqual`. All supplied bounds must hold. |
| `property` + `matches` | any | The non-blank value matches a bounded .NET regular expression. |
| `crossesTrustBoundary` | `flow` | The flow crosses (`true`) or does not cross (`false`) a trust boundary. |
| `source` / `target` | `flow` | A condition on the flow's endpoint: its `kind` (`process`/`datastore`/`external`) and/or a property matcher. |
| `reachableFrom` | component | A matching component has a directed path of one or more edges to this component. |
| `connectsTo` | component | This component has a direct outgoing connector to a matching component. |

#### Numeric and regex predicates

Property matchers also work inside `source`/`target` and connectivity filters. For example:

```json
{
  "id": "RETENTION",
  "appliesTo": "datastore",
  "message": "{name} must declare retention between 1 and 30 days.",
  "assert": { "property": "RetentionDays", "greaterThanOrEqual": 1, "lessThanOrEqual": 30 }
}
```

Numeric bounds are JSON numbers within `System.Decimal` range, not quoted strings. Model values
use invariant decimal parsing: `.` is the decimal separator; signs, surrounding whitespace, and
exponents are allowed; thousands separators are not. Decimal precision and rounding apply. Absent,
blank, `Unknown`, non-numeric, overflowing, or longer-than-256-character values do not match.
Consequently a numeric `when` skips them, while a numeric `assert` reports the missing requirement.
Contradictory bounds reject the pack. To require numeric equality, use equal inclusive lower and
upper bounds; `equals` continues to compare strings.

`matches` searches the value rather than requiring a whole-string match. Use anchors when needed,
for example `"matches": "^svc-[a-z0-9-]+$"`. Matching is case-sensitive and culture-invariant;
inline `(?i)` enables case-insensitive matching. Missing and blank values never match, even `.*`.
`Unknown` is an ordinary recorded string and can match a permissive pattern; do not treat `.*`
as evidence of a control.

Patterns are prepared once per distinct pattern per load, using the .NET interpreter (no dynamic
code generation). Limits are 1,024 pattern characters, 128 distinct patterns per load, 4,096 input
characters, and a 50 ms match timeout. Regex evaluation shares a 1,000 ms budget across the entire
analysis, in addition to the declarative operation budget. Pattern construction has a 250 ms
per-pattern and 1,000 ms shared load budget, checked after each constructor returns: the .NET
constructor is not cancellable, so these are not preemptive compilation timeouts. Pattern length
and count also bound that work. Invalid patterns reject the whole containing pack with a rule-local
diagnostic. Evaluation timeouts and oversized input abort analysis with an error, never `false`;
`not` cannot turn a timeout into evidence that a requirement holds.

Use a version 2 pack for new matchers: an older engine rejects unknown v2 fields rather than silently
ignoring them as extensions in an unversioned pack. Existing legacy string predicates are unchanged.

The interaction dialect accepts `{"subject":"flow","property":"Port","greaterThan":1024}`
or `{"subject":"source","property":"ServiceName","matches":"^svc-"}`. Choose exactly one
property matcher family per interaction leaf (`valueIn`, numeric bounds, or `matches`); combine
families using `allOf`. Interaction property predicates match any stored value, with all numeric
bounds applied to the same value. Flat rules and endpoint/connectivity filters retain their
first-value behavior.

#### Directed connectivity

Connectivity selectors require `kind`, `property`, or both, and reuse endpoint property matchers:

```json
{
  "id": "AUDIT-PATH",
  "appliesTo": "process",
  "message": "{name} is externally reachable but lacks a direct audit-store connection.",
  "when": { "reachableFrom": { "kind": "external" } },
  "assert": { "connectsTo": { "kind": "datastore", "property": "StoresLogData", "equals": "Yes" } }
}
```

`reachableFrom` walks incoming connectors to find an upstream match; `connectsTo` checks one outgoing
edge only. There is no implicit zero-hop match. An explicit self-loop or cycle can establish a
positive-length path back to the same component. Parallel connectors do not duplicate findings.
Traversal stays on the candidate's page. Rectangular and line trust boundaries do not block it:
a boundary documents a trust transition, not an enforced network policy. Boundaries and annotations
are not graph vertices, and connectors ending on them do not create component paths. Dangling or
cross-page connectors still present in the loaded model cause a diagnostic when the graph is built.
This is not a raw-file topology validator: the existing canonical JSON reader drops flows whose
endpoints cannot be resolved on their page before analysis, so those flows never reach this guard.
Connectivity describes the loaded model; it does not recover omitted or malformed links.

For per-flow rules, use interaction leaves such as
`{"subject":"target","reachableFrom":{"kind":"external"}}` or
`{"subject":"source","connectsTo":{"kind":"datastore"}}`. Primitive-kind filters are also
available as `{"subject":"target","kind":"datastore"}` without a type catalog entry.
These predicates accept `source`/`target`, not the flow itself. Flat connectivity predicates require
a component `appliesTo` (`process`, `datastore`, or `external`). Filters cannot recursively contain
connectivity predicates.

One lazy, page-partitioned adjacency index is shared across all rules in an evaluation. The model's
topology must remain fixed for that evaluation context. Index construction is linear; each
reachability query visits at most the page's vertices and edges, without recursion. Index building,
edge visits, and filter evaluation charge the shared operation budget; interaction predicates also
charge their per-rule budget. Graph construction allows at most 1,024 pages, 100,000 shapes, and
200,000 lines across the model. Repeated queries remain bounded by the invocation budget rather
than allocating an all-pairs reachability table.

#### Compatibility and controls

- **Assert what a control *is*, not what it is not.** `anyOf` and `equals` compare exact strings, so
  `Unknown` satisfies them only if you list it. `notAnyOf` is a denylist: `{"property": "Encrypted",
  "notAnyOf": ["No"]}` treats `Unknown` — and every typo — as encrypted, which suppresses exactly the
  finding you wrote the rule for. Prefer `anyOf` with the values that actually satisfy the control.
  A bare `property` matcher tests only that the property is *recorded*; `Unknown` is recorded, so
  presence is not evidence that a control exists. See
  [`Unknown` and the three states of a control](#unknown-and-the-three-states-of-a-control).

- **Ids persist.** Legacy ids are preserved verbatim. Version 2 ids are pack-qualified as described
  above. A collision with an already-loaded built-in is dropped with a warning, so the built-in
  `TM####` namespace always wins.
- **Property names are validated** against the typed [property schema](cli-reference.md#properties).
  An unknown property is a warning, not an error — but it catches a typo (`Encryption` vs `Encrypted`)
  that would otherwise make a rule silently never match.
- **Resilient loading.** A malformed legacy file or individual invalid legacy rule is reported to
  standard error and skipped. Version 2 validates its envelope as a unit, then compiles valid rules;
  an invalid envelope/catalog is skipped rather than partially interpreted.
- **Threats.** A custom rule that declares a `stride` category is projected into
  [`threats`](cli-reference.md#threats) exactly like a built-in threat-bearing rule.
- **Every engine surface.** These matchers use the same evaluator for CLI, API, WASM/Studio, and
  MCP. Rule sources still follow each host's existing policy: CLI paths, MCP sandboxed paths,
  trusted API startup configuration, or in-memory content on WASM. No per-request API rule injection
  is added. See [Custom rules on every surface](#custom-rules-on-every-surface).

### Rule variables

Some rules read variables supplied on the command line (repeatable):

```bash
tmforge analyze model.tm7 --define key=value --define another=value
```

## Suppressions

Filter known/accepted findings with a suppression document:

```bash
tmforge analyze model.tm7 --suppressionFile ./suppressions.json
```

Suppressions are matched per model path and applied before evaluation, so suppressed findings don't
affect the exit code.

## Reports

`--reportFolder <dir>` writes machine- and human-readable findings artifacts:

- **SARIF**: for code-scanning dashboards and PR annotations.
- **HTML**: a human-readable findings report.
- **JSON listing**: a structured enumeration of the model.
- **`<model>.analysis.json`**: the versioned `tmforge-analysis` document — the run recorded as evidence.

```bash
tmforge analyze model.tm7 --reportFolder "$CI_ARTIFACTS/threatmodel"
```

### The analysis document

The other artifacts are for people and dashboards. `<model>.analysis.json` is the one meant to be
**stored and compared against the next run**:

```jsonc
{
  "schema": "tmforge-analysis",
  "version": 1,
  "model":    { "name": "Webshop", "fingerprint": "sha256:187a6d5d…" },
  "analyzer": { "name": "tmforge", "version": "0.7.0.0", "fingerprint": "sha256:5bf32a1d…" },
  "findings": [
    {
      "id": "TM1021:48761fb5…:6b3c361c…:0",
      "ruleId": "TM1021",
      "disposition": "generated-threat",
      "threatId": "6b3c361c…:TM1021"
    }
  ]
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
| `suppressed` | A suppression silenced it. |

The four threat-bearing dispositions carry a `threatId` that joins to `tmforge threats`; `hygiene` and
`suppressed` never do. That separation is the point — you should not have to accept "this diagram has
no trust boundary" as a *risk* to clear a gate.

A **suppressed** finding is recorded, not dropped. It keeps its identity, so a reviewer reading the
evidence can see the finding is still being produced and is deliberately silenced, rather than it
quietly vanishing from the record. It carries no `threatId`, because a suppression says this one does
not count.

The finding ids are the same ones the SARIF `partialFingerprints` carry, so the two artifacts from one
run describe the same findings. The document carries **no timestamp**: two analyses of the same model
with the same rules are byte-identical, so diffing yesterday's document against today's shows only
what actually changed.

Validate a stored document — and find out whether it still describes the model in front of you — with
[`tmforge analysis validate`](cli-reference.md#analysis):

```bash
tmforge analysis validate findings/payments.analysis.json --model payments.tm7
```

### Mapping to your own taxonomy

If your team already runs a threat catalogue, `--taxonomy` annotates the analysis document with your
ids:

```jsonc
// acme-taxonomy.json
{
  "schema": "tmforge-taxonomy",
  "version": 1,
  "rules": {
    "TM1021": ["ACME-T-017", "ACME-T-018"],
    "corporate/CORP-1": ["ACME-T-004"]
  }
}
```

```bash
tmforge analyze payments.tm7 --taxonomy acme-taxonomy.json --reportFolder ./findings
```

Each finding then carries a `canonicalIds` array. Two properties are deliberate:

- **Your catalogue is never part of detection.** The mapping is applied after everything else is
  decided, so no rule fires, changes severity, or changes disposition because of it. Remove the
  mapping and the findings, their ids, and their dispositions are identical.
- **Nothing is ever inferred.** A rule the mapping does not name gets an empty `canonicalIds` — never
  a guess derived from the rule id or the STRIDE category. An invented mapping is worse than an absent
  one, because a reader cannot tell it was guessed.

### Finding identity

Every finding carries a stable id of the form `{ruleId}:{diagram}:{target}:{occurrence}`:

```text
TM1021:48761fb5…c0b5:6b3c361c…6686:0
```

Each segment names something that determines the finding, so the id survives the things that must not
change it — evaluating rules in a different order, enabling or disabling an unrelated rule, and
rewording a message. A segment reads `model` when the finding is about the model or a whole diagram
rather than one element. The trailing counter distinguishes a rule that legitimately fires more than
once against the same target.

This is what makes a finding reconcilable across runs. In SARIF the id is emitted as the
`tmforgeFindingId/v1` **partial fingerprint**, which is how code scanning recognises an alert it has
already seen — without it, every run closes and reopens the whole set and any triage a reviewer
recorded is lost. Results also carry the element as a **logical location**, because a `.tm7` has no
line numbers and the physical location can only name the model file.

Element keys come from the model: a `.tm7` supplies its persisted guids, and canonical model JSON
supplies the author's own element and page ids. Ids that are not guid-shaped are re-keyed internally
on every load, so the author's id is what gets used — an identity built on the internal guid would
differ on every run.

The occurrence counter is the one positional segment. If a rule fires several times against the same
target and you fix some of them, the survivors can renumber; reconcile on the first three segments
when triage has to cross that kind of edit.

## CI integration

### The first-party GitHub Action

The action runs the pinned CLI container, writes the reports, uploads SARIF to code scanning, and
gates the build:

```yaml
name: threat-model
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hacks4snacks/tmforge@v0.7
        with:
          version: "0.7"                                  # pin the engine image, not just the action
          models: "**/*.tm7"
          rules: rules/corporate.tmrules.json
          suppression-file: .tmforge/suppressions.json
          max-severity: warning
```

| Input | Default | Purpose |
| --- | --- | --- |
| `models` | `**/*.tm7` | One glob per line. A file matched by two globs is analyzed once. |
| `rules` | *(none)* | Custom rule pack, or a directory of them. Added to the built-in rules. |
| `ruleset` | *(none)* | `.ruleset` file that enables or disables built-in rules. |
| `suppression-file` | *(none)* | Suppression `.json` file. |
| `max-severity` | `error` | Severity at or above which findings gate the build. |
| `fail-on-findings` | `true` | Set `false` to report findings without failing. |
| `upload-sarif` | `true` | Upload the SARIF to code scanning. |
| `upload-report` | `false` | Also keep the reports as a workflow artifact. |
| `image` / `version` | `ghcr.io/hacks4snacks/tmforge-cli` / `latest` | Pin `version` for a reproducible gate. |
| `pull` | `true` | Set `false` to run an image already loaded on the runner. |

Outputs are `result` (`pass`, `fail`, or `error`), `exit-code`, and `sarif-directory`.

A `rules`, `ruleset`, or `suppression-file` path that does not exist **fails the action** rather than
analyzing with the built-in rules alone. A model must never look clean because the policy it was
supposed to be judged against silently failed to load.

`examples/corporate-policy.tmrules.json` and `examples/corporate-policy.suppressions.json` are a
working pair: the rule reports an error on `examples/webshop.tm7`, and the suppression clears exactly
that finding. This repository's CI runs both through the action and through the CLI and requires the
two to agree.

### Drift detection

Analysis can only judge the model you have. It cannot tell you the model stopped describing the
system. Drift detection covers that gap: it reports a change that touched architecture-relevant code
without touching a threat model.

```yaml
      - uses: hacks4snacks/tmforge@v0.7
        with:
          drift: notice          # 'off', 'notice' (default), or 'fail'
          drift-watched-paths: |
            src/**
            infra/**
```

| Input | Default | Purpose |
| --- | --- | --- |
| `drift` | `notice` | `off`, `notice` (report without failing), or `fail`. |
| `drift-watched-paths` | *(none)* | Globs, one per line, whose change should come with a model update. |
| `drift-model-paths` | the `models` input | Globs that satisfy the check. |
| `drift-comment` | `false` | Keep one pull-request comment up to date with the result. |
| `token` | `github.token` | Used to read the event's file list. |

Outputs are `drift` (`true`, `false`, or `skipped`), `drift-reason`, `drift-watched-count`, and
`drift-model-count`. Every run writes a job-summary table, so the result is visible without granting
any additional permission.

Points worth knowing:

- **Drift is inert until `drift-watched-paths` is set.** Only you know which paths are
  architecture-relevant, so the default configuration reports `skipped` rather than guessing.
- **A file matching both glob sets counts as a model change**, because updating the model is exactly
  what the check asks for.
- **The change list comes from the API, not the work tree.** That is what makes it correct under
  `actions/checkout`'s default shallow clone, and what lets a deleted or renamed file still be seen.
  A rename counts under both its old and new path.
- **A run that cannot compute a change list reports `skipped`, never `false`.** That covers a first
  push, a `schedule` or `workflow_dispatch` run, and an unreadable file list. "We looked and found
  nothing" and "we never looked" are different answers, and only one of them is reassuring.
- `fail` mode is enforced in the same gate as findings, so the SARIF still reaches code scanning
  first and a run that trips both gates reports both.

#### Commenting on the pull request

`drift-comment: true` keeps **one** comment up to date instead of adding a new one per run:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write     # only needed for drift-comment

# ...
        with:
          drift-comment: "true"
          drift-watched-paths: src/**
```

The comment is found by a hidden `<!-- tmforge-drift -->` marker and updated in place, so a pull
request that drifts and is then fixed ends with a single comment saying it is resolved rather than a
stale warning. The marker must be at the *start* of a comment body, so quoting it in a review
conversation cannot cause the action to edit someone else's comment.

Commenting is best-effort and never fails the run: a pull request from a fork receives a read-only
token, and that case reports a warning. Nothing else about drift needs `pull-requests: write` — the
outputs, the job summary, and the gate all work without it.

### Reviewing model changes

Drift asks whether the model was updated. Review shows **how** it changed, so a reviewer does not
have to read a diff of serialized XML:

```yaml
      - uses: hacks4snacks/tmforge@v0.7
        with:
          review: "on"
          review-comment: "true"   # optional; needs pull-requests: write
          upload-report: "true"    # optional; keeps the full detail with the run
```

For every threat model the pull request touches, the action fetches the base revision and runs
`tmforge diff` against it, then renders one summary: a table of models with added, removed, and
modified counts, the findings the change introduced, the trust boundary crossings that changed, and
the individual element and property changes.

| Input | Default | Purpose |
| --- | --- | --- |
| `review` | `off` | `off` or `on`. Review is informational and never gates the build. |
| `review-comment` | `false` | Keep one pull-request comment up to date with the summary. |

Outputs are `review` (`reviewed` or `skipped`) and `review-changed-models`.

Points worth knowing:

- **Findings introduced by the change lead the summary.** The base revision is analyzed with the
  same rules and suppressions as the head, and the two analysis documents are compared by
  [finding identity](cli-reference.md#comparing-two-analyses) rather than by count, so a renamed
  element does not manufacture a new finding and a suppressed one is reported as reclassified rather
  than resolved. Up to 10 appear in the summary.
- **Trust boundary crossings are listed next and budgeted separately.** Which boundaries a flow
  crosses is derived from geometry, so moving an element across one changes no stored property and
  shows up in none of the element counts. A model can therefore report `0 added, 0 removed, 0
  modified` and still have changed what is exposed. Crossings get their own cap of 10 lines so a
  large rename sweep cannot crowd out the one change that alters exposure.
- **The summary is bounded and the detail is not.** At most 20 element changes appear in the summary
  and the comment; the complete diff for every model is written to `review.json` in the report
  directory, which `upload-report: true` attaches to the run alongside the HTML findings reports. A
  pull request that rewrites a model should not produce a comment nobody can read.
- **A renamed model is diffed against its previous path**, so moving a file reads as a move rather
  than a wholesale rewrite.
- **Comparison is by element id, not file position.** Re-layout and re-serialization produce no diff,
  which is what makes the summary worth reading. Boundaries are matched by id too, so renaming one is
  not reported as a crossing change.
- If a base revision or a diff cannot be produced for one model, that model is reported as
  `unavailable` and the rest of the review still runs. A findings delta that cannot be produced
  leaves the structural review in place rather than dropping the model, and a `tmforge` image that
  predates either comparison simply reports neither instead of failing the review.
- Like the drift comment, the review comment is opt-in, idempotent through its own
  `<!-- tmforge-review -->` marker, and best-effort: a fork's read-only token produces a warning
  rather than a failure.

### Without the action

Any runner that can execute the CLI works the same way — `analyze` returns `2` when a model has
findings, which fails the step, and `1` for a tool error:

```yaml
      - name: Analyze threat models
        run: |
          set -e
          for model in $(git ls-files '*.tm7'); do
            tmforge analyze "$model" --reportFolder "reports/$(basename "$model")"
          done
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports
```

See the [deployment guide](deployment.md#cicd) for container-based pipelines.

## See also

- [CLI reference: `analyze`](cli-reference.md#analyze): all options.
- [Overview & features](overview.md): where analysis fits.
- [Engine API reference](api-reference.md): `POST /v1/model/analyze` and the catalog endpoints.
