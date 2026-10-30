namespace ThreatModelForge.Analysis.Reporting.Tests
{
    using System;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Xml;
    using System.Xml.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>Tests the deterministic Markdown view of analysis findings.</summary>
    [TestClass]
    public class FindingsMarkdownReportWriterTests
    {
        /// <summary>Markdown retains the findings and metadata displayed by HTML.</summary>
        [TestMethod]
        public void MatchesHtmlContent()
        {
            ModelReport report = Report();
            string markdown = WebUtility.HtmlDecode(new FindingsMarkdownReportWriter().Write(report));
            StringBuilder output = new StringBuilder();
            using (XmlWriter inner = XmlWriter.Create(new StringWriter(output), new XmlWriterSettings { OmitXmlDeclaration = true }))
            using (FindingsHtmlReportWriter writer = new FindingsHtmlReportWriter(inner, "report.html"))
            {
                writer.Write(report);
            }

            string html = XDocument.Parse(output.ToString()).Root!.Value;
            foreach (string value in new[]
            {
                "Sample model", "Owner name", "Reviewer name", "Contributor name", "Model description",
                "A recorded assumption", "An external dependency", "Main page", "Gateway", "Reported risk",
                "PRIV-1", "Warning", "Privacy", "High", "Patient privacy", "Privacy harm.",
            })
            {
                StringAssert.Contains(markdown, value);
                StringAssert.Contains(html, value);
            }

            StringAssert.Contains(markdown, "Suggested treatment");
            StringAssert.Contains(markdown, "Rule description");
            StringAssert.Contains(markdown, "https://example.test/rule");
        }

        /// <summary>Reported and suppressed messages share the existing per-scope occurrence counter.</summary>
        [TestMethod]
        public void PreservesSuppressedAndRepeatedFindingIdentities()
        {
            ModelReport report = Report();
            RuleReport rule = report.RuleReports[0];
            RuleReportMessage message = rule.Messages[0];
            rule.Messages.Add(new RuleReportMessage { Diagram = message.Diagram, TargetId = message.TargetId, Text = "Second risk" });
            rule.SuppressedMessages.Add(new RuleReportMessage { Diagram = message.Diagram, TargetId = message.TargetId, Text = "Suppressed risk" });

            string markdown = WebUtility.HtmlDecode(new FindingsMarkdownReportWriter().Write(report));

            for (int occurrence = 0; occurrence < 3; occurrence++)
            {
                string id = FindingIdentity.Format(rule.ID, message.Diagram?.ToString("N"), message.TargetId?.ToString("N"), occurrence);
                Assert.AreEqual(1, markdown.Split("**ID:** " + id, StringSplitOptions.None).Length - 1);
            }

            StringAssert.Contains(markdown, "| Warning | 2 | 1 |");
            StringAssert.Contains(markdown, "**Disposition:** Suppressed");
            StringAssert.Contains(markdown, "Suppressed risk");
            Assert.AreEqual(2, rule.Messages.Count);
            Assert.AreEqual(1, rule.SuppressedMessages.Count);
        }

        /// <summary>Unsafe user text cannot introduce headings, links, HTML or table cells.</summary>
        [TestMethod]
        public void EscapesUntrustedFields()
        {
            ModelReport report = Report();
            const string hostile = "[link](javascript:alert(1)) | <script>run()</script>\r\n# Heading\n`code` @team";
            report.ThreatModelName = hostile;
            report.RuleReports[0].Messages[0].Text = hostile;
            report.RuleReports[0].HelpUri = new Uri("javascript:alert(1)");

            string markdown = new FindingsMarkdownReportWriter().Write(report);

            Assert.IsFalse(markdown.Contains("<script>", StringComparison.Ordinal));
            Assert.IsFalse(markdown.Contains("[link]", StringComparison.Ordinal));
            Assert.IsFalse(markdown.Contains("javascript:", StringComparison.Ordinal));
            Assert.IsFalse(markdown.Contains("@team", StringComparison.Ordinal));
            Assert.IsFalse(markdown.Contains('\r'));
            StringAssert.Contains(markdown, "<br />&#35; Heading<br />&#96;code&#96;");
            StringAssert.Contains(WebUtility.HtmlDecode(markdown), hostile.Replace("\r\n", "<br />").Replace("\n", "<br />"));
        }

        /// <summary>Rule and diagram insertion order and the current culture do not change output.</summary>
        [TestMethod]
        public void IsIndependentOfCultureAndCollectionOrder()
        {
            ModelReport report = Report();
            report.RuleReports.Add(new RuleReport { ID = "DISABLED", Disabled = true, Severity = MessageSeverity.Error });
            report.RuleReports.Add(new RuleReport { ID = "INFO", Severity = MessageSeverity.Info });
            report.DiagramSummaries.Add(new DiagramSummary { ID = Guid.NewGuid(), Header = "Other page" });
            CultureInfo original = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
                string first = new FindingsMarkdownReportWriter().Write(report);
                RuleReport[] rules = report.RuleReports.Reverse().ToArray();
                DiagramSummary[] diagrams = report.DiagramSummaries.Reverse().ToArray();
                report.RuleReports.Clear();
                report.DiagramSummaries.Clear();
                foreach (RuleReport rule in rules)
                {
                    report.RuleReports.Add(rule);
                }

                foreach (DiagramSummary diagram in diagrams)
                {
                    report.DiagramSummaries.Add(diagram);
                }

                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("tr-TR");
                Assert.AreEqual(first, new FindingsMarkdownReportWriter().Write(report));
                StringAssert.Contains(first, "| DISABLED | Error | No | 0 | 0 |");
                CollectionAssert.AreEqual(rules, report.RuleReports.ToArray());
                CollectionAssert.AreEqual(diagrams, report.DiagramSummaries.ToArray());
            }
            finally
            {
                CultureInfo.CurrentCulture = original;
            }
        }

        /// <summary>Empty reports are explicit and null input is rejected.</summary>
        [TestMethod]
        public void HandlesEmptyAndNullReports()
        {
            StringAssert.Contains(new FindingsMarkdownReportWriter().Write(new ModelReport()), "No findings reported.");
            Assert.Throws<ArgumentNullException>(() => new FindingsMarkdownReportWriter().Write(null!));
        }

        private static ModelReport Report()
        {
            ModelReport report = new ModelReport
            {
                ThreatModelName = "Sample model", SourcePath = "sample.tm7", Owner = "Owner name",
                Reviewer = "Reviewer name", Contributors = "Contributor name", Description = "Model description",
                Assumptions = "A recorded assumption", ExternalDependencies = "An external dependency",
            };
            DiagramSummary diagram = new DiagramSummary
            {
                ID = Guid.NewGuid(), Header = "Main page", ComponentCount = 2, ConnectorCount = 1, TrustBoundaryCount = 1,
            };
            report.DiagramSummaries.Add(diagram);
            report.ThreatCategories.Add(new RuleThreatCategory("medical/privacy", "privacy", "Privacy", "Patient privacy", "Privacy harm."));
            RuleReport rule = new RuleReport
            {
                ID = "PRIV-1", Severity = MessageSeverity.Warning, ThreatCategoryName = "Privacy",
                DefaultThreatPriority = ThreatPriority.High, FullDescription = "Rule description",
                HelpText = "Suggested treatment", HelpUri = new Uri("https://example.test/rule"), AnalyzerId = "Sample analyzer",
            };
            rule.Messages.Add(new RuleReportMessage { Diagram = diagram.ID, TargetId = Guid.NewGuid(), Entity = "Gateway", Text = "Reported risk" });
            report.RuleReports.Add(rule);
            return report;
        }
    }
}
