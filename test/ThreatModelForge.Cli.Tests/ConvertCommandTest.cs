namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Formats;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Unit tests for the <see cref="ConvertCommand"/> class.
    /// </summary>
    [TestClass]
    public class ConvertCommandTest
    {
        private const string SampleJson =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[" +
            "{\"id\":\"p1\",\"kind\":\"process\",\"name\":\"Web App\",\"x\":100,\"y\":100}," +
            "{\"id\":\"ds1\",\"kind\":\"datastore\",\"name\":\"Database\",\"x\":420,\"y\":100}]," +
            "\"flows\":[{\"id\":\"f1\",\"source\":\"p1\",\"target\":\"ds1\",\"name\":\"query\"}]}";

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
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-convert-" + Guid.NewGuid().ToString("N"));
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
        /// Verifies that converting a tmforge-json document to draw.io writes a well-formed mxGraph
        /// file, with the target inferred from the <c>-out</c> extension.
        /// </summary>
        [TestMethod]
        public void ConvertsToDrawioFromOutputExtension()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "model.drawio");

            int exit = ConvertCommand.Run(new[] { "--out", output, input });

            Assert.AreEqual(0, exit);
            Assert.IsTrue(File.Exists(output));
            StringAssert.Contains(File.ReadAllText(output), "<mxfile");
        }

        /// <summary>
        /// Verifies that converting to Visio via <c>--to vsdx</c> writes an OPC (zip) package.
        /// </summary>
        [TestMethod]
        public void ConvertsToVsdxByTargetId()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "model.vsdx");

            int exit = ConvertCommand.Run(new[] { "--to", "vsdx", "--out", output, input });

            Assert.AreEqual(0, exit);
            byte[] bytes = File.ReadAllBytes(output);
            Assert.IsTrue(bytes.Length > 4 && bytes[0] == (byte)'P' && bytes[1] == (byte)'K', "a .vsdx package is a zip");
        }

        /// <summary>
        /// Verifies that a missing input file is reported as an error.
        /// </summary>
        [TestMethod]
        public void MissingInputReturnsError()
        {
            int exit = ConvertCommand.Run(new[] { "--to", "drawio", Path.Join(this.WorkingDirectory, "does-not-exist.tm7") });

            Assert.AreEqual(1, exit);
        }

        /// <summary>
        /// Verifies that omitting both the target id and an output path is an error.
        /// </summary>
        [TestMethod]
        public void MissingTargetReturnsError()
        {
            string input = this.WriteInput();

            int exit = ConvertCommand.Run(new[] { input });

            Assert.AreEqual(1, exit);
        }

        /// <summary>
        /// Verifies that the canonical grammar plus <c>--json</c> converts and emits a result envelope.
        /// </summary>
        [TestMethod]
        public void CanonicalGrammarWithJsonEmitsEnvelope()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "model.drawio");

            using StringWriter writer = new StringWriter();
            TextWriter original = Console.Out;
            Console.SetOut(writer);
            int exit;
            try
            {
                exit = ConvertCommand.Run(new[] { "--to", "drawio", "--out", output, "--json", input });
            }
            finally
            {
                Console.SetOut(original);
            }

            Assert.AreEqual(0, exit);
            Assert.IsTrue(File.Exists(output));
            using JsonDocument document = JsonDocument.Parse(writer.ToString());
            Assert.AreEqual("convert", document.RootElement.GetProperty("command").GetString());
            Assert.AreEqual("drawio", document.RootElement.GetProperty("data").GetProperty("format").GetString());
        }

        /// <summary>
        /// A <c>.tm7</c> export that embeds a supplied knowledge base is still prepared for the tool.
        /// Supplying a knowledge base used to skip preparation entirely, which left the file without
        /// the declared priority vocabulary, the normalized coordinates, and the typed properties the
        /// Microsoft Threat Modeling Tool relies on.
        /// </summary>
        [TestMethod]
        public void SuppliedKnowledgeBaseIsStillPreparedForTheTool()
        {
            string input = this.WriteInput();
            string knowledgeBase = Path.Join(this.WorkingDirectory, "supplied.tb7");
            KnowledgeBaseData supplied = new KnowledgeBaseData
            {
                Manifest = new Manifest { Id = Guid.NewGuid(), Name = "Supplied" },
                ThreatMetaData = new ThreatMetaData { IsPriorityUsed = true },
            };
            ThreatMetaDatum priority = new ThreatMetaDatum
            {
                Id = "supplied:priority",
                Name = "Priority",
                Label = "Severity",
                AttributeType = 1,
            };
            priority.Values.Add("High");
            supplied.ThreatMetaData.PropertiesMetaData.Add(priority);
            supplied.Save(knowledgeBase);

            string output = Path.Join(this.WorkingDirectory, "model.tm7");
            int exit = ConvertCommand.Run(new[] { "--to", "tm7", "--knowledge-base", knowledgeBase, "--out", output, input });

            Assert.AreEqual(0, exit);
            ThreatModel written = ThreatModel.Load(output);
            ThreatMetaDatum merged = written.KnowledgeBase!.ThreatMetaData!.PropertiesMetaData.Single(
                datum => datum.Name == "Priority");

            // The supplied vocabulary keeps its own value and ordering, and every priority Threat Model
            // Forge can express is added so no threat carries a value the tool was never told about.
            Assert.AreEqual("High", merged.Values[0]);
            foreach (string expected in ThreatPriorities.All)
            {
                Assert.Contains(expected, merged.Values, expected + " must be declared.");
            }
        }

        /// <summary>The CLI imports a content-detected JSON file without changing its source bytes.</summary>
        /// <param name="formatId">The destination format.</param>
        [TestMethod]
        [DataRow("tmforge-json")]
        [DataRow("tm7")]
        public void ImportsThreatDragonWithoutRewritingSource(string formatId)
        {
            string input = Path.Join(this.WorkingDirectory, "dragon.json");
            File.Copy(Path.Join(AppContext.BaseDirectory, "Fixtures", "threat-dragon-v2.json"), input);
            byte[] original = File.ReadAllBytes(input);
            string output = Path.Join(this.WorkingDirectory, formatId == "tm7" ? "imported.tm7" : "imported.tmforge.json");

            Assert.AreEqual(0, ConvertCommand.Run(new[] { input, "--to", formatId, "--out", output }));

            ThreatModel model = ThreatModelFormatRegistry.CreateDefault().Load(output, formatId);
            Assert.HasCount(2, model.DrawingSurfaceList);
            Assert.HasCount(3, model.AllThreatsDictionary);
            Assert.AreEqual("Model owner", model.MetaInformation?.Owner);
            Threat threat = model.AllThreatsDictionary["manual:threat-dragon.linkability"];
            Assert.AreEqual("LINDDUN", threat.Properties?["Source.modelType"]);
            Assert.AreEqual(model.DrawingSurfaceList[1].Guid, threat.DrawingSurfaceGuid);
            CollectionAssert.AreEqual(original, File.ReadAllBytes(input));
        }

        /// <summary>An import-only destination is refused without truncating the selected file.</summary>
        [TestMethod]
        public void ThreatDragonExportDoesNotOverwriteAnExistingFile()
        {
            string input = this.WriteInput();
            byte[] original = File.ReadAllBytes(input);

            Assert.AreEqual(1, Program.Main(new[] { "convert", input, "--to", "threat-dragon", "--out", input }));

            CollectionAssert.AreEqual(original, File.ReadAllBytes(input));
        }

        /// <summary>Preflight emits structured diagnostics without creating or changing files.</summary>
        [TestMethod]
        public void PreflightReportsDanglingFlowWithoutWriting()
        {
            string path = this.WriteInput();
            string invalid = SampleJson.Replace("\"target\":\"ds1\"", "\"target\":\"missing\"");
            File.WriteAllText(path, invalid);
            using StringWriter output = new StringWriter();
            TextWriter previous = Console.Out;
            int exit;
            try
            {
                Console.SetOut(output);
                exit = PreflightCommand.Run(new[] { path, "--json" });
            }
            finally
            {
                Console.SetOut(previous);
            }

            Assert.AreEqual(2, exit);
            using JsonDocument result = JsonDocument.Parse(output.ToString());
            JsonElement data = result.RootElement.GetProperty("data");
            Assert.IsFalse(data.GetProperty("success").GetBoolean());
            Assert.IsTrue(data.GetProperty("diagnostics").EnumerateArray().Any(item => item.GetProperty("path").GetString() == "$.flows[0].target"));
            Assert.AreEqual(invalid, File.ReadAllText(path));
            Assert.AreEqual(1, Directory.GetFiles(this.WorkingDirectory).Length);
        }

        /// <summary>A strict conversion reports known loss before touching its existing destination.</summary>
        [TestMethod]
        public void FailOnLossLeavesDestinationUnchanged()
        {
            string input = this.WriteInput();
            string output = Path.Join(this.WorkingDirectory, "existing.drawio");
            File.WriteAllText(output, "original destination");
            using StringWriter writer = new StringWriter();
            TextWriter previous = Console.Out;
            int exit;
            try
            {
                Console.SetOut(writer);
                exit = ConvertCommand.Run(new[] { input, "--to", "drawio", "--out", output, "--fail-on-loss", "--json" });
            }
            finally
            {
                Console.SetOut(previous);
            }

            Assert.AreEqual(2, exit);
            Assert.AreEqual("original destination", File.ReadAllText(output));
            using JsonDocument result = JsonDocument.Parse(writer.ToString());
            JsonElement data = result.RootElement.GetProperty("data");
            Assert.AreEqual(JsonValueKind.Null, data.GetProperty("output").ValueKind);
            Assert.IsTrue(data.GetProperty("diagnostics").EnumerateArray().Any(item => item.GetProperty("code").GetString() == "conversion.identity"));
        }

        /// <summary>A malformed graph is refused before an existing output can be truncated.</summary>
        [TestMethod]
        public void InvalidInputLeavesDestinationUnchanged()
        {
            string input = this.WriteInput();
            File.WriteAllText(input, SampleJson.Replace("\"target\":\"ds1\"", "\"target\":\"missing\""));
            string output = Path.Join(this.WorkingDirectory, "existing.tm7");
            File.WriteAllText(output, "original destination");

            Assert.AreEqual(1, ConvertCommand.Run(new[] { input, "--to", "tm7", "--out", output }));
            Assert.AreEqual("original destination", File.ReadAllText(output));
        }

        /// <summary>Both text formats convert deterministically and preflight protects existing destinations.</summary>
        /// <param name="format">The source provider.</param>
        /// <param name="extension">The registered file extension.</param>
        /// <param name="source">The diagram source.</param>
        [TestMethod]
        [DataRow("mermaid", ".mmd", "flowchart LR\nsubgraph zone[Service]\napi[API] --> db[(Database)]\nend")]
        [DataRow("dot", ".dot", "digraph G { subgraph cluster_zone { api -> db; db[shape=cylinder]; } }")]
        public void TextDiagramConversionIsDeterministicAndProtectsSource(string format, string extension, string source)
        {
            string input = Path.Join(this.WorkingDirectory, "source" + extension);
            File.WriteAllText(input, source);
            string output = Path.Join(this.WorkingDirectory, "imported.tm7");
            File.WriteAllText(output, "existing destination");
            Assert.AreEqual(2, PreflightCommand.Run(new[] { input, "--to", format }));
            Assert.AreEqual(2, ConvertCommand.Run(new[] { input, "--to", "tm7", "--out", output, "--fail-on-loss" }));
            Assert.AreEqual("existing destination", File.ReadAllText(output));
            Assert.AreEqual(0, ConvertCommand.Run(new[] { input, "--to", "tm7", "--out", output }));
            byte[] first = File.ReadAllBytes(output);
            Assert.AreEqual(0, ConvertCommand.Run(new[] { input, "--to", "tm7", "--out", output }));
            CollectionAssert.AreEqual(first, File.ReadAllBytes(output));
            ThreatModel model = ThreatModel.Load(output);
            Assert.HasCount(3, model.DrawingSurfaceList.Single().Borders);
            Assert.HasCount(1, model.DrawingSurfaceList.Single().Lines);
            Assert.AreEqual(1, ConvertCommand.Run(new[] { output, "--to", format, "--out", input }));
            Assert.AreEqual(source, File.ReadAllText(input));
        }

        /// <summary>Unsupported source syntax cannot replace an existing model with a partial import.</summary>
        /// <param name="extension">The source file extension.</param>
        /// <param name="source">A graph with a valid prefix followed by unsupported syntax.</param>
        [TestMethod]
        [DataRow(".mermaid", "flowchart LR\na --> b\nclick a callback")]
        [DataRow(".gv", "digraph G { a -> b; a -> b [dir=both]; }")]
        public void TextDiagramFailuresLeaveDestinationUnchanged(string extension, string source)
        {
            string input = Path.Join(this.WorkingDirectory, "source" + extension);
            File.WriteAllText(input, source);
            string output = Path.Join(this.WorkingDirectory, "existing.tmforge.json");
            File.WriteAllText(output, SampleJson);
            Assert.AreEqual(1, Program.Main(new[] { "convert", input, "--to", "tmforge-json", "--out", output }));
            Assert.AreEqual(SampleJson, File.ReadAllText(output));
            Assert.AreEqual(source, File.ReadAllText(input));
        }

        private string WriteInput()
        {
            string input = Path.Join(this.WorkingDirectory, "model.tmforge.json");
            File.WriteAllText(input, SampleJson);
            return input;
        }
    }
}
