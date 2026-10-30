# ThreatModelForge.Analysis.Reporting

Pluggable report writers that render the results of threat-model **analysis** (linting) into
machine- and human-readable formats.

Given a `ModelReport` produced by `ThreatModelForge.Analysis` (the findings from evaluating a
rule set against a model), this library serializes those findings for consumption by CI and by
people. It is used by the `tmforge analyze` command (via `--reportFolder`).

The core pieces are:

- `ReportWriter`: the abstract base class for a findings report writer.
- `SarifReportWriter`: emits **SARIF** (via `Sarif.Sdk`), the standard static-analysis result
  format that CI systems and code-scanning tools understand.
- `FindingsHtmlReportWriter`: emits a self-contained **HTML** view of the findings.
- `FindingsMarkdownReportWriter`: emits deterministic **Markdown** with reported and suppressed
  findings, the same stable finding IDs as SARIF, and rule configuration. The CLI writes it as
  `<model>.findings.md` alongside the existing reports. Output uses LF endings, escaped model text,
  stable ordering, and no generated timestamp.

This is distinct from `ThreatModelForge.Reporting`, which renders the threat *model itself*
(its diagrams and threats) rather than analysis findings.

This targets `netstandard2.0` so it runs on Windows, Linux, macOS, and in containers.
