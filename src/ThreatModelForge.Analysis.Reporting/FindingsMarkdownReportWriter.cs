namespace ThreatModelForge.Analysis.Reporting
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Text;

    /// <summary>Writes deterministic Markdown from an already-evaluated analysis report.</summary>
    public sealed class FindingsMarkdownReportWriter
    {
        /// <summary>Writes reported and suppressed findings without running rules again.</summary>
        /// <param name="report">The same report used for HTML and SARIF output.</param>
        /// <returns>Markdown text with stable finding identities, LF endings and no timestamp.</returns>
        public string Write(ModelReport report)
        {
            if (report == null)
            {
                throw new ArgumentNullException(nameof(report));
            }

            StringBuilder output = new StringBuilder();
            output.Append("# Threat Model Forge Analysis Report\n\n");
            Field(output, "Model", report.ThreatModelName);
            Field(output, "Source", report.SourcePath);
            Field(output, "Owner", report.Owner);
            Field(output, "Reviewer", report.Reviewer);
            Field(output, "Contributors", report.Contributors);
            Field(output, "Description", report.Description);
            Field(output, "Assumptions", report.Assumptions);
            Field(output, "External dependencies", report.ExternalDependencies);
            Field(output, "Analyzer", report.AnalysisTool?.Name);
            Field(output, "Analyzer version", report.AnalysisTool?.Version);

            output.Append("\n## Summary\n\n| Severity | Reported | Suppressed |\n| --- | ---: | ---: |\n");
            foreach (MessageSeverity severity in new[] { MessageSeverity.Error, MessageSeverity.Warning, MessageSeverity.Info })
            {
                RuleReport[] rules = report.RuleReports.Where(rule => rule.Severity == severity).ToArray();
                output.Append("| ").Append(severity).Append(" | ").Append(Number(rules.Sum(rule => rule.Messages.Count)))
                    .Append(" | ").Append(Number(rules.Sum(rule => rule.SuppressedMessages.Count))).Append(" |\n");
            }

            output.Append("\n## Diagrams\n\n| ID | Name | Components | Flows | Trust boundaries |\n| --- | --- | ---: | ---: | ---: |\n");
            foreach (DiagramSummary diagram in report.DiagramSummaries.OrderBy(diagram => diagram.ID))
            {
                output.Append("| ").Append(diagram.ID.ToString("D")).Append(" | ").Append(Text(diagram.Header))
                    .Append(" | ").Append(Number(diagram.ComponentCount)).Append(" | ").Append(Number(diagram.ConnectorCount))
                    .Append(" | ").Append(Number(diagram.TrustBoundaryCount)).Append(" |\n");
            }

            output.Append("\n## Findings\n\n");
            if (!report.RuleReports.Any(rule => rule.Messages.Count > 0 || rule.SuppressedMessages.Count > 0))
            {
                output.Append("No findings reported. This is not a security certification.\n");
            }

            foreach (var finding in Findings(report).OrderBy(finding => finding.Rule.Severity).ThenBy(finding => finding.Id, StringComparer.Ordinal))
            {
                RuleReport rule = finding.Rule;
                RuleReportMessage message = finding.Message;
                output.Append("### ").Append(Text(rule.ID)).Append(" ( ").Append(rule.Severity).Append(" )\n\n");
                Field(output, "ID", finding.Id);
                Field(output, "Disposition", finding.Suppressed ? "Suppressed" : "Reported");
                Field(output, "Diagram", report.DiagramSummaries.FirstOrDefault(diagram => diagram.ID == message.Diagram)?.Header);
                Field(output, "Diagram ID", message.Diagram?.ToString("D"));
                Field(output, "Target", message.Entity);
                Field(output, "Target ID", message.TargetId?.ToString("D"));
                Field(output, "Message", message.Text);
                Field(output, "Rule description", rule.FullDescription);
                Field(output, "Category", rule.ThreatCategoryName);
                Field(output, "Suggested remediation", rule.HelpText);
                Field(output, "Help", rule.HelpUri?.ToString());
                output.Append('\n');
            }

            if (report.ThreatCategories.Count > 0)
            {
                output.Append("\n## Threat categories\n\n| ID | Name | Short description | Long description |\n| --- | --- | --- | --- |\n");
                foreach (RuleThreatCategory category in report.ThreatCategories.OrderBy(category => category.Id, StringComparer.Ordinal))
                {
                    output.Append("| ").Append(Text(category.Id)).Append(" | ").Append(Text(category.Name))
                        .Append(" | ").Append(Text(category.ShortDescription)).Append(" | ").Append(Text(category.LongDescription)).Append(" |\n");
                }
            }

            output.Append("\n## Rule configuration\n\n| Rule | Severity | Enabled | Reported | Suppressed | Category | Default priority | Analyzer |\n| --- | --- | --- | ---: | ---: | --- | --- | --- |\n");
            foreach (RuleReport rule in report.RuleReports.OrderBy(rule => rule.ID, StringComparer.Ordinal))
            {
                output.Append("| ").Append(Text(rule.ID)).Append(" | ").Append(rule.Severity).Append(" | ").Append(rule.Disabled ? "No" : "Yes")
                    .Append(" | ").Append(Number(rule.Messages.Count)).Append(" | ").Append(Number(rule.SuppressedMessages.Count))
                    .Append(" | ").Append(Text(rule.ThreatCategoryName)).Append(" | ").Append(rule.DefaultThreatPriority?.ToString())
                    .Append(" | ").Append(Text(rule.AnalyzerId)).Append(" |\n");
            }

            return output.ToString();
        }

        private static IEnumerable<(RuleReport Rule, RuleReportMessage Message, bool Suppressed, string Id)> Findings(ModelReport report)
        {
            FindingIdentity identity = new FindingIdentity();
            foreach (RuleReport rule in report.RuleReports)
            {
                foreach (RuleReportMessage message in rule.Messages)
                {
                    yield return (rule, message, false, identity.Next(rule.ID, message.Diagram?.ToString("N"), message.TargetId?.ToString("N")));
                }

                foreach (RuleReportMessage message in rule.SuppressedMessages)
                {
                    yield return (rule, message, true, identity.Next(rule.ID, message.Diagram?.ToString("N"), message.TargetId?.ToString("N")));
                }
            }
        }

        private static void Field(StringBuilder output, string label, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                output.Append("- **").Append(label).Append(":** ").Append(Text(value)).Append('\n');
            }
        }

        private static string Number(int value) => value.ToString(CultureInfo.InvariantCulture);

        private static string Text(string? value)
        {
            StringBuilder output = new StringBuilder();
            foreach (char character in (value ?? string.Empty).Replace("\r\n", "\n").Replace('\r', '\n'))
            {
                if (character == '\n')
                {
                    output.Append("<br />");
                }
                else if ("&<>\"'\\`*_{}[]()#+!|~:@".IndexOf(character) >= 0)
                {
                    output.Append("&#").Append(((int)character).ToString(CultureInfo.InvariantCulture)).Append(';');
                }
                else
                {
                    output.Append(character);
                }
            }

            return output.ToString();
        }
    }
}
