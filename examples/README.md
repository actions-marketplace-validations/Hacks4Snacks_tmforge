# Sample threat models and rule packs

Small, synthetic threat models used to demo Threat Model Forge, exercise the first-party
[GitHub Action](../action.yml), and dogfood the CLI in [CI](../.github/workflows/ci.yml), plus
opt-in starter packs for authoring model-specific policies.

## `webshop`

A minimal but realistic web-shop: a customer browser on the public internet talking to a web app and
an orders API inside a cloud VNet, backed by an orders database and an audit log.

| File | What it is |
|------|------------|
| [`webshop.manifest.json`](webshop.manifest.json) | The reviewable, diffable source — a declarative authoring manifest. |
| [`webshop.tm7`](webshop.tm7) | The built model (`DataContractSerializer` XML), analyzed by CI and the Action. |

The model is deliberately well-formed (it analyzes cleanly, exit code `0`) yet still surfaces a
couple of advisory **warnings** — the web app writes to no audit-log store (`TM1029`) and the audit
log is unsigned (`TM1021`) — so the SARIF output and HTML report are non-empty.

### Regenerate the model from the manifest

```bash
tmforge apply examples/webshop.manifest.json --out examples/webshop.tm7
```

### Analyze it

```bash
# Human-readable findings; exit 0 (clean/threshold-clear), 2 (findings at/above --max-severity), 1 (error).
tmforge analyze examples/webshop.tm7

# Machine-readable SARIF + HTML report into a folder.
tmforge analyze examples/webshop.tm7 --reportFolder out/reports
```

## Custom rules and suppressions

A matched pair showing how an organization layers its own policy on top of the built-in rules, and
how a reviewed exception is recorded.

| File | What it is |
|------|------------|
| [`corporate-policy.tmrules.json`](corporate-policy.tmrules.json) | One declarative rule: a store holding audit data must state a `RetentionDays` retention period. |
| [`corporate-policy.suppressions.json`](corporate-policy.suppressions.json) | Records a reviewed exception for the audit log in `webshop.tm7`. |

The rule reports an **error** against `webshop.tm7`, so it changes the gate outcome, and the
suppression clears exactly that finding:

```bash
tmforge analyze examples/webshop.tm7 \
  --rules examples/corporate-policy.tmrules.json                       # exit 2

tmforge analyze examples/webshop.tm7 \
  --rules examples/corporate-policy.tmrules.json \
  --suppressionFile examples/corporate-policy.suppressions.json        # exit 0
```

CI runs this pair through both the CLI and the first-party Action and requires the same outcome from
each, which is what keeps the Action's rule and suppression wiring honest. A suppressed finding is
still produced and recorded — it simply stops gating the build.

## Starter rule packs

Three small, inspectable version 2 packs demonstrate numeric, regex, Boolean, and connectivity
policies. **These examples do not certify compliance.** They evaluate recorded model properties and
directed connections, not deployed configurations, legal applicability, or control effectiveness.
They are opt-in examples, not new built-in rules. Use a build with the additional matchers described
in [the rule guide](../docs/analysis-rules.md#numeric-and-regex-predicates); older builds reject
unsupported version 2 fields.

| Pack | Checks | Source and Intent |
| --- | --- | --- |
| [PCI-inspired](rule-packs/pci-inspired.tmrules.json) | Stored PAN encryption; at least 12 months of CDE audit retention. | Inspired by [PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/), 3.5.1 and 10.5.1. The first rule covers encryption-based designs only; other permitted ways to protect PAN require adapting the policy. The second checks duration only, not log availability or completeness. |
| [HIPAA-inspired](rule-packs/hipaa-inspired.tmrules.json) | ePHI flows use an allowed TLS transport and certificate validation; receiving processes have a direct audit-store connection. | Inspired by [45 CFR 164.312(b) and (e)](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html). TLS allowlists and direct-store topology are example choices, not the legal text. Addressable encryption specifications still require assessment; this pack does not assess alternatives. |
| [Internal service](rule-packs/internal-service.tmrules.json) | Internal service names follow `svc-name`; externally reachable internal processes connect directly to an audit store. | Illustrative `EXAMPLE-SVC-1`/`EXAMPLE-SVC-2` policies, with [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#event-collection). Naming is hygiene, not a threat or an OWASP mandate. |

Each file contains two rules, versioned pack identity, control references, remediation guidance, and
scope limitations. PCI uses flat guard/requirement predicates and numeric retention; HIPAA shows
`allOf`/`not` Boolean composition; internal service shows whole-string regex and directed reachability.
All findings are warnings by default. Five rules declare STRIDE metadata and produce triageable
threats; `SERVICE-NAME` is a finding only. Use your existing ruleset/severity policy to choose gates.

### Record scope and evidence

Use these **property names** consistently; property lookup and enum comparisons are case-insensitive.
The service-name regex is case-sensitive. Record custom properties on the appropriate objects;
there is no automatic classification or data discovery.

| Property | Where | Meaning in These Examples |
| --- | --- | --- |
| `StoresPAN` | Datastore | `Yes` opts into the PAN rule; `No` and `Unknown` do not. |
| `Encrypted` | Datastore | The PAN rule accepts `At-rest`, `TDE`, `Client-side`, or `Platform`; `No`, `Unknown`, or missing evidence fails. These labels do not prove cryptographic strength or key management. |
| `AuditScope` | Datastore | `CDE` opts into audit retention; `Other` and `Unknown` do not. This marker denotes an audit store, not every datastore in a CDE. |
| `RetentionMonths` | Datastore | An invariant numeric string of at least `12`. No approximation of a month/year using days is made. |
| `DataClassification` | Flow | `ePHI` opts into HIPAA-inspired rules; `Other` and `Unknown` do not. This custom field is separate from the built-in `DataType` vocabulary. |
| `Protocol`, `CertificateValidation` | Flow | `HTTPS`, `TLS`, or `mTLS`, together with `CertificateValidation=Yes`. Unqualified `gRPC`, for example, does not establish TLS use. |
| `ServiceScope`, `ServiceName` | Process | `ServiceScope=Internal` opts into internal-service rules. Names use the case-sensitive `svc-` prefix and lowercase alphanumeric segments separated by single hyphens, such as `svc-billing-v2`. |
| `StoresLogData` | Datastore | `Yes` qualifies a direct audit destination. A process/collector with the same property does not qualify as a datastore. |

**Missing or Unknown scope means unassessed, not compliant or proven out of scope.** Within an
explicit scope, missing/Unknown control evidence fails the relevant requirement. Do not clear
findings by removing scope markers or asserting unevidenced controls.

Connectivity is directed and page-local. Trust boundaries do not block traversal. The audit checks
require a direct outgoing store connection; brokered/collector-based logging needs a policy adapted
to that architecture. HIPAA audit findings are per incoming ePHI flow, not per process, and isolated
processes are not assessed by an interaction rule. See the rule guide for
[graph and input limitations](../docs/analysis-rules.md#directed-connectivity).

### Try the demonstration model

[starter-model.tmforge.json](rule-packs/starter-model.tmforge.json) is a deliberately incomplete,
synthetic model that combines independent examples so every rule fires once. It contains no real
payment or health data and is not a recommended architecture. From the repository root:

```bash
tmforge analyze examples/rule-packs/starter-model.tmforge.json --rules examples/rule-packs/pci-inspired.tmrules.json --max-severity warning
tmforge analyze examples/rule-packs/starter-model.tmforge.json --rules examples/rule-packs/hipaa-inspired.tmrules.json --max-severity warning
tmforge analyze examples/rule-packs/starter-model.tmforge.json --rules examples/rule-packs/internal-service.tmrules.json --max-severity warning
tmforge analyze examples/rule-packs/starter-model.tmforge.json --rules examples/rule-packs --max-severity warning
```

Each command exits `2` for findings at the warning threshold, not a tool failure. Each individual
pack adds two findings; the directory loads all three and adds six. Built-in findings are also
reported, so total output is not limited to those counts. Add `--reportFolder <directory>` to retain
the analysis JSON, HTML, and SARIF using the usual CLI workflow. Tests run the command lines above
and check the resulting rule IDs and report identities.

To satisfy the example policies while retaining their scope declarations, change the demonstration
model as follows (only record such values on a real model when evidenced):

| Object | Example Change |
| --- | --- |
| Example PAN store | Set `Encrypted=At-rest`. |
| Example audit store | Set `RetentionMonths=12`. |
| Example gateway | Set `ServiceName=svc-gateway`. |
| Example ePHI request | Set `Protocol=TLS` and `CertificateValidation=Yes`. |
| Example gateway to Example audit store | Add a direct outgoing audit flow. The existing route through Example worker is indirect. |

Tests verify these changes clear the six starter findings without erasing scope markers. This does
not clear every built-in finding or establish compliance.

### Use Your Own Model

In Studio, open a model, load a chosen `.tmrules.json` under **Analysis Rules**, and run **Analyze**.
The browser/WASM engine accepts custom pack content; an API-backed Studio uses the server's trusted
startup configuration instead. API operators can point `TmForge__Rules` at the chosen pack or pack
directory, and MCP clients can use the existing sandboxed `rulesPath`. The first-party Action's
`rules` input accepts the same files. No model or pack is uploaded automatically by these examples.

Fork a pack with your own pack ID and version before adapting it; preserve useful source references
and record the changes from the example policy. Use the existing expected-pack fingerprints to
detect missing or changed policy content. Do not claim these selected checks implement the whole
standard, and do not treat a regex, protocol label, or drawn connection as proof of runtime behavior.
