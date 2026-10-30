# MTMT openability probe

`Tm7MtmtCompatibilityTests` locks the on-disk shape a `.tm7` must have for the Microsoft Threat
Modeling Tool to open it. That is the best proxy CI can run, and it is only a proxy: the assertions
encode what we currently *believe* the tool requires. This script asks the tool.

No Microsoft binaries are stored in this directory.

## What it answers

For every `.tm7` in a directory, it constructs MTMT's own `ObjectModel(StorageFile, bool)` and reads
`ModelLoadHasIssues` / `ModelLoadIssues` — the properties `DashboardViewModel` inspects before it
raises the "coordinates are corrupted" dialog. A model whose construction throws is a hard refusal:
the tool will not open it at all.

Given `-ElementId` and `-PropertyName` it also reads one property back through MTMT's `PropertyMap`,
which answers the stronger question: does the tool see the value tmforge wrote?

Exit code is `0` when every model opens and `1` when any does not, so it can gate a release check.
Results include the loaded MTMT assembly/file versions, each model's SHA-256 and size, and the
underlying exception with its stack trace when loading fails.

## Getting a payload

The probe does not download or install anything. Omit `-PayloadDirectory` to use a single complete
MTMT installation from the current user's ClickOnce cache. Missing or multiple installations fail
explicitly; use `-PayloadDirectory` to select an existing directory instead. No execution-policy
override is applied, so organization policy remains in effect.

For environments without an existing installation, the sibling
[`MtmtDifferential`](../../../ThreatModelForge.Analysis.Tests/Fixtures/MtmtDifferential/README.md)
capture script fetches MTMT from Microsoft's versioned ClickOnce distribution and checks the
application manifest SHA-256 and every payload digest against it:

```powershell
powershell.exe -NoProfile -File `
  test/ThreatModelForge.Analysis.Tests/Fixtures/MtmtDifferential/capture-mtmt-root-scope.ps1 `
  -Preflight -WorkingDirectory C:\mtmt
```

That leaves a verified payload at `C:\mtmt\TMT7_7_3_51110_1`. `-Preflight` stops after verifying, so
it needs neither WPF nor the 32-bit host.

## Running it

```powershell
powershell.exe -NoProfile -File `
  test/ThreatModelForge.Core.Tests/Fixtures/MtmtOpenability/probe-mtmt-openability.ps1 `
  -PayloadDirectory C:\mtmt\TMT7_7_3_51110_1 `
  -ModelDirectory C:\models `
  -ElementId c5adf20f-68d4-5971-a9d3-76a250ef77f0 -PropertyName Encrypted
```

Windows only, with .NET Framework 4.8. The script relaunches itself under 32-bit Windows PowerShell
in STA mode because the signed MTMT model assembly is x86 and derives its types from WPF.

Include controls in both directions, so a run that reports everything refused is distinguishable
from a broken probe and a run that reports everything fine is distinguishable from a probe that
stopped checking:

- **Positive:** `examples/webshop.tm7` is verified to open.
- **Negative:** `test/ThreatModelForge.Core.Tests/SampleModel.tm7` is verified *not* to open. It
  serializes `<PortSource i:nil="true"/>`, which MTMT refuses outright with
  `SerializationException: ValueType 'ThreatModeling.Common.StencilConnectionPort' cannot be null`.
  It is a hand-built round-trip fixture, not an openability oracle — a tmforge round trip repairs the
  ports and the result opens clean.

## Facts worth keeping

Established against MTMT `7.3.51110.1`; re-check when that version moves.

- **`ObjectModel(String, Boolean, Boolean, Boolean)` overflows the stack** and kills the host process,
  destroying buffered output along with it. Use the `(StorageFile, bool)` overload.
- **Elements have no `Properties` member.** Use `PropertyMap`, a `Dictionary` keyed by attribute id
  whose values are `ListDisplayAttribute`, `StringDisplayAttribute`, `BooleanDisplayAttribute`,
  `CustomStringDisplayAttribute`, or `HeaderDisplayAttribute`.
- **`ListDisplayAttribute.Value` is a `List<string>` typed as `Object`.** Neither `-is [string[]]` nor
  `GetType().IsArray` identifies it; both fall through silently and print the whole option list
  instead of the selection. Materialize the enumerable and index it by `SelectedIndex`.
- **`GetDrawingSurfaceModels()` returns nothing until the model is processed.** Call
  `ProcessModelImmediately(FullModel)`; `ConfigureThreatGeneration` needs a WPF dispatcher a
  console host does not have.
- **Duplicate element properties do not stop a model opening.** A file carrying five attributes with
  the same display name loads clean, and `PropertyMap` reports one entry. The hazard is not
  refusal — it is that the tool and tmforge can resolve the same file to *different values*, which is
  how the `set` defect fixed in `DiagramElementHelper` was found.
- **A persisted threat with a null `TypeId` is refused in `Threat.Configure`.** Native user-defined
  threats use `BS` followed by a hyphenated GUID; `IsUserDefined` also requires the complete
  38-character identity. Keep tmforge's `manual:` register key separately.
- **A non-null threat property bag disables migration of legacy text fields.** Titles, categories,
  descriptions, justifications and interaction text must also be present under their native
  property names. Supplying a native type ID alone can make a model load with missing finding text.
- **MTMT retains only metadata-declared threat properties.** Declare `Mitigation` and any
  provenance or override properties that must survive saving. These threat-contract facts were
  established from a user-run loader trace and the pinned 7.3.51110.1 assemblies; exporter
  regressions remain structural proxies, not a substitute for opening each corrected candidate.
