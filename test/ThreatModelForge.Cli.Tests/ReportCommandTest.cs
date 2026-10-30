namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Unit tests for the <see cref="ReportCommand"/> class.
    /// </summary>
    [TestClass]
    public class ReportCommandTest
    {
        private const string SampleJson =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[" +
            "{\"id\":\"p1\",\"kind\":\"process\",\"name\":\"API\",\"x\":100,\"y\":100}," +
            "{\"id\":\"ds1\",\"kind\":\"datastore\",\"name\":\"DB\",\"x\":400,\"y\":100}]," +
            "\"flows\":[{\"id\":\"f1\",\"source\":\"p1\",\"target\":\"ds1\",\"name\":\"query\"}]}";

        private const string ThreatBearingJson =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[" +
            "{\"id\":\"11111111-1111-4111-8111-111111111111\",\"kind\":\"external\",\"name\":\"Client\",\"x\":50,\"y\":50}," +
            "{\"id\":\"22222222-2222-4222-8222-222222222222\",\"kind\":\"process\",\"name\":\"Gateway\",\"x\":220,\"y\":50}]," +
            "\"flows\":[{\"id\":\"33333333-3333-4333-8333-333333333333\",\"source\":\"11111111-1111-4111-8111-111111111111\"," +
            "\"target\":\"22222222-2222-4222-8222-222222222222\",\"name\":\"request\"}]}";

        /// <summary>
        /// Gets or sets the working directory created for each test.
        /// </summary>
        private string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>
        /// Creates an isolated working directory for the test.
        /// </summary>
        [TestInitialize]
        public void Initialize()
        {
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-report-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(this.WorkingDirectory);
        }

        /// <summary>
        /// Removes the working directory after the test.
        /// </summary>
        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(this.WorkingDirectory))
            {
                Directory.Delete(this.WorkingDirectory, recursive: true);
            }
        }

        /// <summary>
        /// Verifies that <c>--json</c> with <c>--out</c> writes the HTML and emits a result envelope.
        /// </summary>
        [TestMethod]
        public void JsonEmitsEnvelope()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "report.html");

            (int exit, string stdout) = Run(new[] { "--out", output, "--json", input });

            Assert.AreEqual(0, exit);
            Assert.IsTrue(File.Exists(output));
            using JsonDocument document = JsonDocument.Parse(stdout);
            JsonElement root = document.RootElement;
            Assert.AreEqual("report", root.GetProperty("command").GetString());
            JsonElement data = root.GetProperty("data");
            Assert.AreEqual("html", data.GetProperty("format").GetString());
            Assert.IsTrue(data.GetProperty("bytes").GetInt32() > 0);
        }

        /// <summary>
        /// Verifies that, without <c>--out</c>, the HTML report is written to standard output.
        /// </summary>
        [TestMethod]
        public void WritesHtmlToStandardOutputByDefault()
        {
            string input = this.WriteInput();

            (int exit, string stdout) = Run(new[] { input });

            Assert.AreEqual(0, exit);
            StringAssert.Contains(stdout, "<");
        }

        /// <summary>
        /// Verifies that reports materialize rule-backed threats rather than showing only the
        /// model's manually-authored register entries.
        /// </summary>
        /// <param name="format">The report format.</param>
        [TestMethod]
        [DataRow("html")]
        [DataRow("md")]
        public void ReportIncludesGeneratedThreats(string format)
        {
            string input = this.WriteInput(ThreatBearingJson);

            (int exit, string stdout) = Run(new[] { "--format", format, input });

            Assert.AreEqual(0, exit);
            StringAssert.Contains(stdout, "TM1023");
            StringAssert.Contains(stdout, "CWE-287");
            StringAssert.Contains(stdout, "Client");
        }

        /// <summary>
        /// Verifies that generation for a report honors rule packs disabled in the model.
        /// </summary>
        /// <param name="format">The report format.</param>
        [TestMethod]
        [DataRow("html")]
        [DataRow("md")]
        public void ReportHonorsDisabledRulePacks(string format)
        {
            string json = ThreatBearingJson.Substring(0, ThreatBearingJson.Length - 1)
                + ",\"analysis\":{\"disabledPacks\":[\"identity-access\"]}}";
            string input = this.WriteInput(json);

            (int exit, string stdout) = Run(new[] { "--format", format, input });

            Assert.AreEqual(0, exit);
            Assert.IsFalse(stdout.Contains("TM1023", StringComparison.Ordinal));
        }

        /// <summary>
        /// Verifies that Markdown preserves generated threats and manual decisions without changing
        /// the input, and emits the same bytes on every run.
        /// </summary>
        [TestMethod]
        public void MarkdownIsDeterministicAndRetainsThreats()
        {
            string json = ThreatBearingJson.Substring(0, ThreatBearingJson.Length - 1)
                + ",\"threats\":[{\"id\":\"manual:reviewed\",\"manual\":true,\"state\":\"Accepted\","
                + "\"category\":\"Tampering\",\"title\":\"Reviewed risk\",\"justification\":\"Approved exception\","
                + "\"elementIds\":[\"22222222-2222-4222-8222-222222222222\"]}]}";
            string input = this.WriteInput(json);

            (int exit, string markdown) = Run(new[] { "--format", "md", input });
            (int repeatedExit, string repeated) = Run(new[] { "--format", "md", input });

            Assert.AreEqual(0, exit);
            Assert.AreEqual(0, repeatedExit);
            Assert.AreEqual(markdown, repeated);
            Assert.IsTrue(markdown.StartsWith("# ", StringComparison.Ordinal));
            StringAssert.Contains(markdown, "TM1023");
            StringAssert.Contains(markdown, "CWE-287");
            StringAssert.Contains(markdown, "Reviewed risk");
            StringAssert.Contains(markdown, "Accepted");
            StringAssert.Contains(markdown, "Approved exception");
            Assert.IsFalse(markdown.Contains('\r'));
            Assert.AreEqual(json, File.ReadAllText(input));
        }

        /// <summary>Markdown file output preserves the CLI JSON envelope contract.</summary>
        [TestMethod]
        public void MarkdownFileHasJsonEnvelope()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "report.md");

            (int exit, string stdout) = Run(new[] { "--format", "md", "--out", output, "--json", input });

            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            JsonElement data = document.RootElement.GetProperty("data");
            Assert.AreEqual("md", data.GetProperty("format").GetString());
            Assert.AreEqual(new FileInfo(output).Length, data.GetProperty("bytes").GetInt64());
            Assert.IsTrue(File.ReadAllText(output).StartsWith("# ", StringComparison.Ordinal));
        }

        /// <summary>
        /// Verifies that a missing input file is reported as an error.
        /// </summary>
        [TestMethod]
        public void MissingInputReturnsError()
        {
            (int exit, _) = Run(new[] { Path.Join(this.WorkingDirectory, "does-not-exist.tm7") });

            Assert.AreEqual(1, exit);
        }

        /// <summary>
        /// Verifies that <c>--format svg</c> writes a standalone SVG diagram to standard output.
        /// </summary>
        [TestMethod]
        public void SvgFormatWritesStandaloneSvgToStandardOutput()
        {
            string input = this.WriteInput();

            (int exit, string stdout) = Run(new[] { "--format", "svg", input });

            Assert.AreEqual(0, exit);
            StringAssert.Contains(stdout, "<svg");
            StringAssert.Contains(stdout, "http://www.w3.org/2000/svg");
        }

        /// <summary>
        /// Verifies that <c>--format svg</c> with <c>--out</c> and <c>--json</c> writes the SVG and
        /// reports the svg format in the envelope.
        /// </summary>
        [TestMethod]
        public void SvgFormatJsonWritesFileAndReportsSvg()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "diagram.svg");

            (int exit, string stdout) = Run(new[] { "--format", "svg", "--out", output, "--json", input });

            Assert.AreEqual(0, exit);
            Assert.IsTrue(File.Exists(output));
            StringAssert.Contains(File.ReadAllText(output), "<svg");
            using JsonDocument document = JsonDocument.Parse(stdout);
            Assert.AreEqual("svg", document.RootElement.GetProperty("data").GetProperty("format").GetString());
        }

        /// <summary>
        /// Verifies that an unknown <c>--format</c> is reported as an error.
        /// </summary>
        [TestMethod]
        public void UnknownFormatReturnsError()
        {
            string input = this.WriteInput();

            (int exit, _) = Run(new[] { "--format", "pdf", input });

            Assert.AreEqual(1, exit);
        }

        private static (int Exit, string Stdout) Run(string[] args)
        {
            using StringWriter outWriter = new StringWriter();
            using StringWriter errorWriter = new StringWriter();
            TextWriter originalOut = Console.Out;
            TextWriter originalError = Console.Error;
            Console.SetOut(outWriter);
            Console.SetError(errorWriter);
            try
            {
                int exit = ReportCommand.Run(args);
                return (exit, outWriter.ToString());
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalError);
            }
        }

        private string WriteInput(string json = SampleJson)
        {
            string input = Path.Join(this.WorkingDirectory, "model.tmforge.json");
            File.WriteAllText(input, json);
            return input;
        }
    }
}
