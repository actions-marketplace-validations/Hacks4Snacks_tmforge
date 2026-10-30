# ThreatModelForge.Reporting

Cross-platform HTML and Markdown report generation for Microsoft Threat Modeling documents.

Given a threat model (`.tm7`), this library produces a self-contained HTML report that
includes the model metadata, each data-flow diagram rendered as inline **SVG** (drawn
directly from the model geometry, so no native graphics libraries are required), and the
threats grouped per diagram with their origin, rule id, state, priority, STRIDE category,
scope, description, mitigation, references, and decision note. The responsive report includes
an executive treatment summary and print styles, with no external assets.

The core pieces are:

- `DiagramSvgRenderer`: renders a `DrawingSurfaceModel` to an SVG element.
- `HtmlReportWriter`: produces the full HTML report from a `ThreatModel` whose threat register
  has been materialized by the calling surface. `EngineService.Report` and `tmforge report` do
  this automatically from the enabled threat-bearing analysis rules while preserving manual
  threats and triage.
- `MarkdownReportWriter`: writes metadata, diagram tables, and the same complete threat register
  with stable identity ordering, invariant formatting, LF endings, and no generated timestamp.
  Available through `tmforge report --format md`; it does not evaluate rules or mutate the model.

HTML model text is escaped through `System.Xml.Linq`. Markdown model text is emitted literally
with markup characters escaped, including in headings and table cells.

This targets `netstandard2.0` so it runs on Windows, Linux, macOS, and in containers,
replacing the WPF/GDI+ report pipeline that historically shipped only in the Windows
Threat Modeling Tool.
