namespace ThreatModelForge.Reporting
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Xml.Linq;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Produces a self-contained HTML report for a threat model. All model-supplied text is
    /// emitted through <see cref="XElement"/>, which escapes it, so a report cannot be used to
    /// inject markup or script.
    /// </summary>
    public sealed class HtmlReportWriter
    {
        private const string ThemeScript =
            "(function () {"
            + " const param = new URLSearchParams(window.location.search).get(\"scoutTheme\");"
            + " const theme = param || (window.matchMedia(\"(prefers-color-scheme: dark)\").matches ? \"dark\" : \"light\");"
            + " document.documentElement.setAttribute(\"data-theme\", theme);"
            + " }());";

        private const string Css =
            ":root {"
            + " color-scheme: light;"
            + " --cp-bg: #f7f4ef;"
            + " --cp-bg-elevated: #fcfbf8;"
            + " --cp-surface: #ffffff;"
            + " --cp-surface-soft: #f5f5f5;"
            + " --cp-border: #dedede;"
            + " --cp-border-strong: #919191;"
            + " --cp-text: #242424;"
            + " --cp-text-muted: #5c5c5c;"
            + " --cp-text-soft: #6f6f6f;"
            + " --cp-accent: #b11f4b;"
            + " --cp-accent-hover: #9a1a41;"
            + " --cp-accent-soft: rgba(177, 31, 75, 0.08);"
            + " --cp-accent-fg: #ffffff;"
            + " --cp-success: #16a34a;"
            + " --cp-danger: #dc2626;"
            + " --cp-warning: #f59e0b;"
            + " --cp-link: #0078d4;"
            + " --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);"
            + " --cp-overlay: rgba(255, 255, 255, 0.8);"
            + " --cp-panel: rgba(255, 255, 255, 0.86);"
            + " --cp-panel-strong: rgba(255, 255, 255, 0.96);"
            + " --cp-sheen: rgba(255, 255, 255, 0.55);"
            + " --cp-highlight: rgba(177, 31, 75, 0.12);"
            + " }"
            + " html[data-theme=\"dark\"] {"
            + " color-scheme: dark;"
            + " --cp-bg: #3d3b3a;"
            + " --cp-bg-elevated: #343231;"
            + " --cp-surface: #292929;"
            + " --cp-surface-soft: #2e2e2e;"
            + " --cp-border: #474747;"
            + " --cp-border-strong: #5f5f5f;"
            + " --cp-text: #dedede;"
            + " --cp-text-muted: #919191;"
            + " --cp-text-soft: #b0b0b0;"
            + " --cp-accent: #fd8ea1;"
            + " --cp-accent-hover: #fb7b91;"
            + " --cp-accent-soft: rgba(253, 142, 161, 0.14);"
            + " --cp-accent-fg: #1a1a1a;"
            + " --cp-success: #4ade80;"
            + " --cp-danger: #f87171;"
            + " --cp-warning: #fbbf24;"
            + " --cp-link: #4da6ff;"
            + " --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);"
            + " --cp-overlay: rgba(41, 41, 41, 0.88);"
            + " --cp-panel: rgba(41, 41, 41, 0.72);"
            + " --cp-panel-strong: rgba(41, 41, 41, 0.96);"
            + " --cp-sheen: rgba(255, 255, 255, 0.04);"
            + " --cp-highlight: rgba(253, 142, 161, 0.12);"
            + " }"
            + " * { box-sizing: border-box; }"
            + " html { background: var(--cp-bg); }"
            + " body { margin: 0; background: var(--cp-bg); color: var(--cp-text);"
            + " font-family: \"Segoe UI\", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif; line-height: 1.5; }"
            + " .report-header { background: var(--cp-bg-elevated); border-bottom: 1px solid var(--cp-border); }"
            + " .report-header-inner, main, .report-footer { width: min(74rem, calc(100% - 3rem)); margin: 0 auto; }"
            + " .report-header-inner { padding: 3.5rem 0 2.75rem; }"
            + " .brand-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 2.5rem; }"
            + " .brand { color: var(--cp-accent); font-weight: 700; letter-spacing: 0; }"
            + " .report-kind { color: var(--cp-text-muted); font-size: 0.8125rem; font-weight: 600; }"
            + " h1, h2, h3, h4, p { margin-top: 0; }"
            + " h1 { max-width: 52rem; margin-bottom: 0.75rem; font-size: 2.5rem; line-height: 1.12; letter-spacing: 0; }"
            + " h2 { margin-bottom: 0.25rem; font-size: 1.5rem; line-height: 1.25; letter-spacing: 0; }"
            + " h3 { margin-bottom: 0; font-size: 1.0625rem; line-height: 1.35; letter-spacing: 0; }"
            + " h4 { margin-bottom: 0.35rem; font-size: 0.75rem; line-height: 1.3; letter-spacing: 0;"
            + " color: var(--cp-text-muted); text-transform: uppercase; }"
            + " .lede { max-width: 48rem; margin-bottom: 1.5rem; color: var(--cp-text-muted); font-size: 1.0625rem; }"
            + " .header-meta { display: flex; flex-wrap: wrap; gap: 0.5rem 1.5rem; color: var(--cp-text-soft); font-size: 0.875rem; }"
            + " main { padding: 2.75rem 0 4rem; }"
            + " .report-section { margin-bottom: 3.5rem; }"
            + " .section-heading { display: flex; align-items: end; justify-content: space-between; gap: 1rem; margin-bottom: 1.25rem; }"
            + " .eyebrow { margin-bottom: 0.25rem; color: var(--cp-accent); font-size: 0.75rem; font-weight: 700;"
            + " letter-spacing: 0; text-transform: uppercase; }"
            + " .section-copy { max-width: 42rem; margin-bottom: 0; color: var(--cp-text-muted); }"
            + " .metrics { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); background: var(--cp-surface);"
            + " border: 1px solid var(--cp-border); border-radius: 8px; overflow: hidden; }"
            + " .metric { min-width: 0; padding: 1.25rem; border-top: 4px solid var(--cp-border-strong); }"
            + " .metric + .metric { border-left: 1px solid var(--cp-border); }"
            + " .metric-open { border-top-color: var(--cp-danger); }"
            + " .metric-investigation { border-top-color: var(--cp-warning); }"
            + " .metric-mitigated { border-top-color: var(--cp-success); }"
            + " .metric-accepted { border-top-color: var(--cp-accent); }"
            + " .metric-value { display: block; margin-bottom: 0.2rem; font-size: 2rem; font-weight: 700; line-height: 1; }"
            + " .metric-label { color: var(--cp-text-muted); font-size: 0.8125rem; font-weight: 600; }"
            + " .summary-callout { margin: 1rem 0 0; color: var(--cp-text-muted); }"
            + " .summary-callout strong { color: var(--cp-text); }"
            + " .context-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 2rem; margin: 0; }"
            + " .context-item { padding: 1rem 0; border-top: 1px solid var(--cp-border); }"
            + " .context-item dt { margin-bottom: 0.25rem; color: var(--cp-text-muted); font-size: 0.75rem; font-weight: 700;"
            + " letter-spacing: 0; text-transform: uppercase; }"
            + " .context-item dd { margin: 0; white-space: pre-wrap; }"
            + " .notes-list { margin: 0; padding-left: 1.25rem; }"
            + " .notes-list li { margin-bottom: 0.5rem; padding-left: 0.25rem; white-space: pre-wrap; overflow-wrap: anywhere; }"
            + " .count-pill, .badge { display: inline-flex; align-items: center; border: 1px solid var(--cp-border);"
            + " border-radius: 999px; background: var(--cp-surface-soft); color: var(--cp-text-muted); font-size: 0.75rem; font-weight: 600; }"
            + " .count-pill { flex: 0 0 auto; padding: 0.35rem 0.7rem; }"
            + " .diagram-figure { width: fit-content; max-width: 100%; margin: 0 0 1.25rem; border: 1px solid var(--cp-border); border-radius: 8px;"
            + " background: var(--cp-surface); overflow: hidden; }"
            + " .diagram-canvas { padding: 1rem; overflow: auto; }"
            + " .diagram-canvas .tmf-diagram { --tmf-diagram-surface: var(--cp-surface);"
            + " --tmf-connector: var(--cp-text); --tmf-flow-label: var(--cp-text); --tmf-flow-halo: var(--cp-surface);"
            + " --tmf-page-title: var(--cp-text); --tmf-boundary: var(--cp-danger); }"
            + " .diagram-canvas > svg { display: block; width: 100%; height: auto; }"
            + " .diagram-figure figcaption { padding: 0.65rem 1rem; border-top: 1px solid var(--cp-border);"
            + " color: var(--cp-text-muted); font-size: 0.8125rem; }"
            + " .threat-list { display: grid; gap: 0.75rem; }"
            + " .threat-card { border: 1px solid var(--cp-border); border-left: 4px solid var(--cp-danger);"
            + " border-radius: 8px; background: var(--cp-surface); overflow: hidden; break-inside: avoid; }"
            + " .threat-investigation { border-left-color: var(--cp-warning); }"
            + " .threat-mitigated { border-left-color: var(--cp-success); }"
            + " .threat-accepted { border-left-color: var(--cp-accent); }"
            + " .threat-card-header { display: flex; align-items: start; justify-content: space-between; gap: 1.25rem; padding: 1.1rem 1.25rem; }"
            + " .threat-heading { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: start; gap: 0.75rem; min-width: 0; }"
            + " .threat-number { display: inline-flex; align-items: center; justify-content: center; min-width: 2.25rem; height: 2.25rem;"
            + " border-radius: 8px; background: var(--cp-accent-soft); color: var(--cp-accent); font-family: Consolas, \"Courier New\", Courier, monospace;"
            + " font-size: 0.75rem; font-weight: 700; }"
            + " .threat-title { overflow-wrap: anywhere; }"
            + " .badges { display: flex; flex: 0 0 auto; flex-wrap: wrap; justify-content: end; gap: 0.4rem; }"
            + " .badge { padding: 0.2rem 0.55rem; }"
            + " .badge-open { border-color: var(--cp-danger); color: var(--cp-danger); }"
            + " .badge-investigation { border-color: var(--cp-warning); color: var(--cp-warning); }"
            + " .badge-mitigated { border-color: var(--cp-success); color: var(--cp-success); }"
            + " .badge-accepted { border-color: var(--cp-accent); color: var(--cp-accent); }"
            + " .badge-stale { border-style: dashed; opacity: 0.85; }"
            + " .threat-stale .threat-title { text-decoration: line-through; text-decoration-thickness: 1px; }"
            + " .threat-facts { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); margin: 0; padding: 0 1.25rem;"
            + " border-top: 1px solid var(--cp-border); border-bottom: 1px solid var(--cp-border); background: var(--cp-surface-soft); }"
            + " .threat-fact { min-width: 0; padding: 0.8rem 1rem 0.8rem 0; }"
            + " .threat-fact dt { margin-bottom: 0.15rem; color: var(--cp-text-muted); font-size: 0.7rem; font-weight: 700;"
            + " letter-spacing: 0; text-transform: uppercase; }"
            + " .threat-fact dd { margin: 0; overflow-wrap: anywhere; font-size: 0.8125rem; }"
            + " .threat-details { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem 2rem; padding: 1rem 1.25rem 1.2rem; }"
            + " .threat-detail { min-width: 0; }"
            + " .threat-detail:only-child { grid-column: 1 / -1; }"
            + " .threat-detail p { margin-bottom: 0; color: var(--cp-text-soft); white-space: pre-wrap; overflow-wrap: anywhere; }"
            + " .threat-detail-note { grid-column: 1 / -1; padding-top: 0.8rem; border-top: 1px solid var(--cp-border); }"
            + " .empty-state { padding: 1.25rem; border: 1px dashed var(--cp-border-strong); border-radius: 8px;"
            + " background: var(--cp-surface-soft); color: var(--cp-text-muted); }"
            + " .empty-state strong { display: block; margin-bottom: 0.2rem; color: var(--cp-text); }"
            + " .report-footer { padding: 1.25rem 0 2.5rem; border-top: 1px solid var(--cp-border); color: var(--cp-text-muted);"
            + " font-size: 0.8125rem; }"
            + " @media (max-width: 800px) {"
            + " .report-header-inner, main, .report-footer { width: min(100% - 2rem, 74rem); }"
            + " .report-header-inner { padding: 2.25rem 0 2rem; }"
            + " h1 { font-size: 2rem; }"
            + " .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }"
            + " .metric + .metric { border-left: 0; }"
            + " .metric:nth-child(even) { border-left: 1px solid var(--cp-border); }"
            + " .metric:last-child:nth-child(odd) { grid-column: 1 / -1; }"
            + " .context-grid { grid-template-columns: 1fr; }"
            + " .threat-card-header { align-items: stretch; flex-direction: column; }"
            + " .badges { justify-content: start; padding-left: 3rem; }"
            + " .threat-facts { grid-template-columns: 1fr; }"
            + " .threat-fact + .threat-fact { border-top: 1px solid var(--cp-border); }"
            + " .threat-details { grid-template-columns: 1fr; }"
            + " .threat-detail-note { grid-column: auto; }"
            + " }"
            + " @media print {"
            + " @page { margin: 0.6in; }"
            + " .report-header-inner, main, .report-footer { width: 100%; }"
            + " .report-header-inner { padding-top: 0; }"
            + " .report-section { margin-bottom: 2rem; }"
            + " .diagram-figure, .threat-card { break-inside: avoid; }"
            + " }";

        /// <summary>
        /// Writes an HTML report for the given model.
        /// </summary>
        /// <param name="model">The threat model.</param>
        /// <returns>The HTML document text.</returns>
        public string Write(ThreatModel model) => this.Write(model, null);

        /// <summary>
        /// Writes an HTML report, marking the entries the caller has determined are stale.
        /// </summary>
        /// <remarks>
        /// The register keeps an entry after its rule stops firing so triage is never lost, which means
        /// a report rendered from the register alone shows a retired finding as though it were live.
        /// Deciding which entries are stale needs the rules, which this writer deliberately does not
        /// depend on, so the caller determines it and passes the keys in.
        /// </remarks>
        /// <param name="model">The threat model.</param>
        /// <param name="staleThreatIds">The register keys of stale entries, or <see langword="null"/> if unknown.</param>
        /// <returns>The HTML document text.</returns>
        public string Write(ThreatModel model, IReadOnlyCollection<string>? staleThreatIds)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            HashSet<string> stale = staleThreatIds == null
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(staleThreatIds, StringComparer.OrdinalIgnoreCase);
            List<Threat> threats = model.AllThreatsDictionary.Values.ToList();
            string reportTitle = FirstNonEmpty(model.MetaInformation?.ThreatModelName, "Threat Modeling Report");
            XElement main = new XElement("main", BuildSummary(threats));

            XElement? context = BuildModelContext(model.MetaInformation);
            if (context != null)
            {
                main.Add(context);
            }

            XElement? notes = BuildNotes(model.Notes);
            if (notes != null)
            {
                main.Add(notes);
            }

            DiagramSvgRenderer renderer = new DiagramSvgRenderer();
            for (int i = 0; i < model.DrawingSurfaceList.Count; i++)
            {
                main.Add(BuildDiagramSection(model.DrawingSurfaceList[i], i, model, renderer, stale));
            }

            if (model.DrawingSurfaceList.Count == 0)
            {
                main.Add(BuildUnscopedThreatSection(threats, stale));
            }

            XElement body = new XElement(
                "body",
                BuildHeader(model.MetaInformation),
                main,
                new XElement("footer", new XAttribute("class", "report-footer"), "Generated by Threat Model Forge"));
            XElement html = new XElement("html", new XAttribute("lang", "en-US"), BuildHead(reportTitle), body);
            return "<!DOCTYPE html>" + Environment.NewLine + html;
        }

        private static XElement BuildHead(string reportTitle)
        {
            return new XElement(
                "head",
                new XElement("meta", new XAttribute("charset", "utf-8")),
                new XElement(
                    "meta",
                    new XAttribute("name", "viewport"),
                    new XAttribute("content", "width=device-width, initial-scale=1")),
                new XElement("title", reportTitle + " | Threat Model Forge"),
                new XElement("script", ThemeScript),
                new XElement("style", new XAttribute("type", "text/css"), Css));
        }

        private static XElement BuildHeader(MetaInformation? meta)
        {
            string title = FirstNonEmpty(meta?.ThreatModelName, "Threat Modeling Report");
            string description = FirstNonEmpty(
                meta?.HighLevelSystemDescription,
                "Architecture, analysis findings, and threat treatment status in one review-ready view.");
            XElement headerMeta = new XElement(
                "div",
                new XAttribute("class", "header-meta"),
                new XElement("span", "Generated " + DateTime.Now.ToString("f", CultureInfo.CurrentCulture)));
            if (!string.IsNullOrWhiteSpace(meta?.Owner))
            {
                headerMeta.Add(new XElement("span", "Owner: " + meta!.Owner));
            }

            return new XElement(
                "header",
                new XAttribute("class", "report-header"),
                new XElement(
                    "div",
                    new XAttribute("class", "report-header-inner"),
                    new XElement(
                        "div",
                        new XAttribute("class", "brand-row"),
                        new XElement("span", new XAttribute("class", "brand"), "Threat Model Forge"),
                        new XElement("span", new XAttribute("class", "report-kind"), "Threat Modeling Report")),
                    new XElement("h1", title),
                    new XElement("p", new XAttribute("class", "lede"), description),
                    headerMeta));
        }

        private static XElement BuildSummary(IReadOnlyList<Threat> threats)
        {
            int open = threats.Count(t => t.State == ThreatState.AutoGenerated);
            int investigation = threats.Count(t => t.State == ThreatState.NeedsInvestigation);
            int mitigated = threats.Count(t => t.State == ThreatState.Mitigated);
            int accepted = threats.Count(t => t.State == ThreatState.NotApplicable);
            int actionRequired = open + investigation;
            string callout = actionRequired == 0
                ? "No threats currently require review or treatment."
                : CountText(actionRequired, "threat") + " require review or treatment.";

            string actionLabel = actionRequired == 1 ? " action required. " : " actions required. ";
            return new XElement(
                "section",
                new XAttribute("class", "report-section"),
                new XAttribute("aria-labelledby", "summary-title"),
                new XElement(
                    "div",
                    new XAttribute("class", "section-heading"),
                    new XElement(
                        "div",
                        new XElement("p", new XAttribute("class", "eyebrow"), "Assessment"),
                        new XElement("h2", new XAttribute("id", "summary-title"), "Executive summary"),
                        new XElement("p", new XAttribute("class", "section-copy"), "Current threat register and treatment posture."))),
                new XElement(
                    "div",
                    new XAttribute("class", "metrics"),
                    Metric("Total threats", threats.Count, "metric"),
                    Metric("Open", open, "metric metric-open"),
                    Metric("Needs investigation", investigation, "metric metric-investigation"),
                    Metric("Mitigated", mitigated, "metric metric-mitigated"),
                    Metric("Accepted", accepted, "metric metric-accepted")),
                new XElement(
                    "p",
                    new XAttribute("class", "summary-callout"),
                    new XElement("strong", actionRequired.ToString(CultureInfo.InvariantCulture) + actionLabel),
                    callout));
        }

        private static XElement Metric(string label, int value, string cssClass)
        {
            return new XElement(
                "div",
                new XAttribute("class", cssClass),
                new XElement("span", new XAttribute("class", "metric-value"), value.ToString(CultureInfo.InvariantCulture)),
                new XElement("span", new XAttribute("class", "metric-label"), label));
        }

        private static XElement? BuildModelContext(MetaInformation? meta)
        {
            List<XElement> items = new List<XElement>();
            AddContextItem(items, "Owner", meta?.Owner);
            AddContextItem(items, "Reviewer", meta?.Reviewer);
            AddContextItem(items, "Contributors", meta?.Contributors);
            AddContextItem(items, "Assumptions", meta?.Assumptions);
            AddContextItem(items, "External dependencies", meta?.ExternalDependencies);
            if (items.Count == 0)
            {
                return null;
            }

            return new XElement(
                "section",
                new XAttribute("class", "report-section"),
                new XElement(
                    "div",
                    new XAttribute("class", "section-heading"),
                    new XElement(
                        "div",
                        new XElement("p", new XAttribute("class", "eyebrow"), "Context"),
                        new XElement("h2", "Model context"))),
                new XElement("dl", new XAttribute("class", "context-grid"), items));
        }

        private static void AddContextItem(List<XElement> items, string label, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            items.Add(
                new XElement(
                    "div",
                    new XAttribute("class", "context-item"),
                    new XElement("dt", label),
                    new XElement("dd", value)));
        }

        private static XElement? BuildNotes(IEnumerable<Note> notes)
        {
            List<Note> ordered = notes.OrderBy(n => n.Id).ToList();
            if (ordered.Count == 0)
            {
                return null;
            }

            XElement list = new XElement("ul", new XAttribute("class", "notes-list"));
            foreach (Note note in ordered)
            {
                list.Add(new XElement("li", note.Message ?? string.Empty));
            }

            return new XElement(
                "section",
                new XAttribute("class", "report-section"),
                new XElement(
                    "div",
                    new XAttribute("class", "section-heading"),
                    new XElement(
                        "div",
                        new XElement("p", new XAttribute("class", "eyebrow"), "Record"),
                        new XElement("h2", "Notes"))),
                list);
        }

        private static XElement BuildDiagramSection(
            DrawingSurfaceModel diagram,
            int diagramIndex,
            ThreatModel model,
            DiagramSvgRenderer renderer,
            HashSet<string> stale)
        {
            List<Threat> threats = model.AllThreatsDictionary.Values
                .Where(threat => BelongsToDiagram(threat, diagram, diagramIndex, model.DrawingSurfaceList))
                .OrderBy(StateRank)
                .ThenBy(PriorityRank)
                .ThenBy(threat => threat.TypeId, StringComparer.Ordinal)
                .ThenBy(threat => threat.Title, StringComparer.Ordinal)
                .ToList();
            string sectionId = "diagram-" + (diagramIndex + 1).ToString(CultureInfo.InvariantCulture);
            string caption = CountText(diagram.Borders.Count, "object") + " | "
                + CountText(diagram.Lines.Count, "flow") + " | "
                + CountText(threats.Count, "threat");
            XElement section = new XElement(
                "section",
                new XAttribute("class", "report-section diagram-section"),
                new XAttribute("aria-labelledby", sectionId),
                new XElement(
                    "div",
                    new XAttribute("class", "section-heading"),
                    new XElement(
                        "div",
                        new XElement(
                            "p",
                            new XAttribute("class", "eyebrow"),
                            "Diagram " + (diagramIndex + 1).ToString("D2", CultureInfo.InvariantCulture)),
                        new XElement("h2", new XAttribute("id", sectionId), DiagramTitle(diagram))),
                    new XElement("span", new XAttribute("class", "count-pill"), CountText(threats.Count, "threat"))),
                new XElement(
                    "figure",
                    new XAttribute("class", "diagram-figure"),
                    new XElement("div", new XAttribute("class", "diagram-canvas"), renderer.Render(diagram)),
                    new XElement("figcaption", caption)));

            section.Add(BuildThreatList(threats, BuildEntityNames(diagram), stale));
            return section;
        }

        private static XElement BuildUnscopedThreatSection(IReadOnlyList<Threat> threats, HashSet<string> stale)
        {
            return new XElement(
                "section",
                new XAttribute("class", "report-section diagram-section"),
                new XElement(
                    "div",
                    new XAttribute("class", "section-heading"),
                    new XElement(
                        "div",
                        new XElement("p", new XAttribute("class", "eyebrow"), "Register"),
                        new XElement("h2", "Threat register")),
                    new XElement("span", new XAttribute("class", "count-pill"), CountText(threats.Count, "threat"))),
                BuildThreatList(threats, new Dictionary<Guid, string>(), stale));
        }

        private static XElement BuildThreatList(
            IReadOnlyList<Threat> threats,
            IReadOnlyDictionary<Guid, string> entityNames,
            HashSet<string> stale)
        {
            if (threats.Count == 0)
            {
                return new XElement(
                    "div",
                    new XAttribute("class", "empty-state"),
                    new XElement("strong", "No threats recorded"),
                    "No generated or manually authored threats are currently associated with this diagram.");
            }

            XElement list = new XElement("div", new XAttribute("class", "threat-list"));
            for (int i = 0; i < threats.Count; i++)
            {
                list.Add(BuildThreatCard(i + 1, threats[i], entityNames, stale));
            }

            return list;
        }

        private static XElement BuildThreatCard(
            int number,
            Threat threat,
            IReadOnlyDictionary<Guid, string> entityNames,
            HashSet<string> stale)
        {
            string title = FirstNonEmpty(threat.Title, threat.TypeId, "Threat");
            string category = FirstNonEmpty(threat.UserThreatCategory, "Uncategorized");
            string description = FirstNonEmpty(threat.UserThreatDescription, threat.UserThreatShortDescription);
            string mitigation = FirstNonEmpty(PropertyValue(threat, "Mitigation"), "Not documented.");
            string references = PropertyValue(threat, "References");
            string note = FirstNonEmpty(threat.StateInformation);
            string stateClass = StateClass(threat.State);
            bool manual = IsManual(threat);
            bool isStale = !manual && stale.Contains(RegisterKey(threat));
            XElement details = new XElement("div", new XAttribute("class", "threat-details"));
            AddThreatDetail(details, "Description", description, "threat-detail");
            AddThreatDetail(details, "Suggested mitigation", mitigation, "threat-detail");
            AddThreatDetail(details, "Decision note", note, "threat-detail threat-detail-note");

            return new XElement(
                "article",
                new XAttribute("class", "threat-card threat-" + stateClass + (isStale ? " threat-stale" : string.Empty)),
                new XElement(
                    "header",
                    new XAttribute("class", "threat-card-header"),
                    new XElement(
                        "div",
                        new XAttribute("class", "threat-heading"),
                        new XElement(
                            "span",
                            new XAttribute("class", "threat-number"),
                            "T" + number.ToString("D2", CultureInfo.InvariantCulture)),
                        new XElement("h3", new XAttribute("class", "threat-title"), title)),
                    new XElement(
                        "div",
                        new XAttribute("class", "badges"),
                        Badge(StateText(threat.State), "badge badge-" + stateClass),
                        Badge(category, "badge"),
                        Badge(FirstNonEmpty(threat.Priority, "Unprioritized"), "badge"),
                        isStale ? Badge("Stale", "badge badge-stale") : null)),
                new XElement(
                    "dl",
                    new XAttribute("class", "threat-facts"),
                    ThreatFact("Origin", OriginText(threat, manual, isStale)),
                    ThreatFact("Scope", ScopeText(threat, entityNames)),
                    ThreatFact("References", FirstNonEmpty(references, "None"))),
                details);
        }

        private static XElement Badge(string text, string cssClass)
        {
            return new XElement("span", new XAttribute("class", cssClass), text);
        }

        private static XElement ThreatFact(string label, string value)
        {
            return new XElement(
                "div",
                new XAttribute("class", "threat-fact"),
                new XElement("dt", label),
                new XElement("dd", value));
        }

        private static void AddThreatDetail(XElement details, string label, string value, string cssClass)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            details.Add(
                new XElement(
                    "section",
                    new XAttribute("class", cssClass),
                    new XElement("h4", label),
                    new XElement("p", value)));
        }

        private static bool BelongsToDiagram(
            Threat threat,
            DrawingSurfaceModel diagram,
            int diagramIndex,
            IEnumerable<DrawingSurfaceModel> diagrams)
        {
            Guid scopedDiagram = FindScopedDiagram(threat, diagrams);
            if (scopedDiagram != Guid.Empty)
            {
                return scopedDiagram == diagram.Guid;
            }

            if (threat.DrawingSurfaceGuid == diagram.Guid)
            {
                return true;
            }

            return diagramIndex == 0 &&
                (threat.DrawingSurfaceGuid == Guid.Empty || !diagrams.Any(item => item.Guid == threat.DrawingSurfaceGuid));
        }

        private static Guid FindScopedDiagram(Threat threat, IEnumerable<DrawingSurfaceModel> diagrams)
        {
            foreach (Guid id in new[] { threat.FlowGuid, threat.SourceGuid, threat.TargetGuid })
            {
                if (id == Guid.Empty)
                {
                    continue;
                }

                foreach (DrawingSurfaceModel diagram in diagrams)
                {
                    if (diagram.Borders.ContainsKey(id) || diagram.Lines.ContainsKey(id))
                    {
                        return diagram.Guid;
                    }
                }
            }

            return Guid.Empty;
        }

        private static IReadOnlyDictionary<Guid, string> BuildEntityNames(DrawingSurfaceModel diagram)
        {
            Dictionary<Guid, string> names = new Dictionary<Guid, string>();
            IEnumerable<Entity> entities = diagram.Borders.Values.OfType<Entity>().Concat(diagram.Lines.Values.OfType<Entity>());
            foreach (Entity entity in entities)
            {
                names[entity.Guid] = EntityName(entity);
            }

            return names;
        }

        private static string EntityName(Entity entity)
        {
            string? name = entity.Properties
                .OfType<StringDisplayAttribute>()
                .Where(item => string.Equals(item.DisplayName, "Name", StringComparison.OrdinalIgnoreCase))
                .Select(item => item.Value as string)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            string? header = entity.Properties
                .OfType<HeaderDisplayAttribute>()
                .Select(item => item.DisplayName)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            return FirstNonEmpty(name, header, entity.Guid.ToString());
        }

        private static string ScopeText(Threat threat, IReadOnlyDictionary<Guid, string> entityNames)
        {
            if (!string.IsNullOrWhiteSpace(threat.InteractionString))
            {
                return threat.InteractionString!;
            }

            string source = EntityName(threat.SourceGuid, entityNames);
            string target = EntityName(threat.TargetGuid, entityNames);
            string flow = EntityName(threat.FlowGuid, entityNames);
            if (!string.IsNullOrEmpty(source) && !string.IsNullOrEmpty(target))
            {
                return source + " -> " + target;
            }

            return FirstNonEmpty(flow, source, target, "Model-wide");
        }

        private static string EntityName(Guid id, IReadOnlyDictionary<Guid, string> names)
        {
            return id != Guid.Empty && names.TryGetValue(id, out string? name) ? name : string.Empty;
        }

        private static string PropertyValue(Threat threat, string key)
        {
            if (threat.Properties == null)
            {
                return string.Empty;
            }

            if (threat.Properties.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
            {
                return value!;
            }

            foreach (KeyValuePair<string, string> item in threat.Properties)
            {
                if (string.Equals(item.Key, key, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(item.Value))
                {
                    return item.Value;
                }
            }

            return string.Empty;
        }

        private static bool IsManual(Threat threat)
        {
            return string.IsNullOrWhiteSpace(threat.TypeId) ||
                ManualThreatId.IsManual(threat.InteractionKey);
        }

        private static string RegisterKey(Threat threat) =>
            string.IsNullOrEmpty(threat.InteractionKey) ? string.Empty : threat.InteractionKey!;

        private static string OriginText(Threat threat, bool manual, bool isStale)
        {
            if (manual)
            {
                return "Manual entry";
            }

            string rule = "Rule " + FirstNonEmpty(threat.TypeId, "Unknown");
            return isStale ? rule + " \u2014 no longer reported by this rule set" : rule;
        }

        private static int StateRank(Threat threat)
        {
            switch (threat.State)
            {
                case ThreatState.AutoGenerated:
                    return 0;
                case ThreatState.NeedsInvestigation:
                    return 1;
                case ThreatState.Mitigated:
                    return 2;
                default:
                    return 3;
            }
        }

        private static int PriorityRank(Threat threat)
        {
            if (string.Equals(threat.Priority, "High", StringComparison.OrdinalIgnoreCase))
            {
                return 0;
            }

            if (string.Equals(threat.Priority, "Medium", StringComparison.OrdinalIgnoreCase))
            {
                return 1;
            }

            return 2;
        }

        private static string DiagramTitle(DrawingSurfaceModel diagram)
        {
            return string.IsNullOrEmpty(diagram.Header) ? "Diagram" : diagram.Header!;
        }

        private static string StateText(ThreatState state)
        {
            switch (state)
            {
                case ThreatState.AutoGenerated:
                    return "Open";
                case ThreatState.NotApplicable:
                    return "Accepted";
                case ThreatState.NeedsInvestigation:
                    return "Needs Investigation";
                case ThreatState.Mitigated:
                    return "Mitigated";
                default:
                    return state.ToString();
            }
        }

        private static string StateClass(ThreatState state)
        {
            switch (state)
            {
                case ThreatState.NotApplicable:
                    return "accepted";
                case ThreatState.NeedsInvestigation:
                    return "investigation";
                case ThreatState.Mitigated:
                    return "mitigated";
                default:
                    return "open";
            }
        }

        private static string FirstNonEmpty(params string?[] values)
        {
            foreach (string? value in values.Where(value => !string.IsNullOrWhiteSpace(value)))
            {
                return value!;
            }

            return string.Empty;
        }

        private static string CountText(int count, string noun)
        {
            return count.ToString(CultureInfo.InvariantCulture) + " " + noun + (count == 1 ? string.Empty : "s");
        }
    }
}
