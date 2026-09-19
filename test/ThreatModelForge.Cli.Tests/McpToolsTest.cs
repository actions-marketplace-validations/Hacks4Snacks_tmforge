namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.IO.Compression;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ModelContextProtocol;
    using ModelContextProtocol.Client;
    using ModelContextProtocol.Protocol;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Engine;

    /// <summary>
    /// Unit tests for the <c>tmforge mcp</c> tool layer: the mapping from agent-friendly parameters
    /// (kind nouns, property maps, file paths) onto the engine and authoring facades. The MCP protocol
    /// wiring itself is exercised by a stdio smoke test; these verify the thin tool adapters.
    /// </summary>
    [TestClass]
    public class McpToolsTest
    {
        /// <summary>Gets or sets the working directory created for each test.</summary>
        private string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>Creates an isolated working directory for the test.</summary>
        [TestInitialize]
        public void Initialize()
        {
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-mcp-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(this.WorkingDirectory);
        }

        /// <summary>Removes the working directory after the test.</summary>
        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(this.WorkingDirectory))
            {
                Directory.Delete(this.WorkingDirectory, recursive: true);
            }
        }

        /// <summary>
        /// Verifies that <c>add</c> resolves the kind noun, marshals the property map, and returns the model.
        /// </summary>
        [TestMethod]
        public void Add_ResolvesKindNounAndStampsProperties()
        {
            AuthoringResultDto result = McpAuthoringTools.Add(
                model: null,
                kind: "process",
                name: "API",
                alias: "api",
                properties: new Dictionary<string, string> { ["AuthenticationScheme"] = "OAuth" });

            Assert.IsTrue(result.Success, result.Error);
            TmForgeElementDto element = result.Model!.Elements!.Single();
            Assert.AreEqual("OAuth", element.Properties["AuthenticationScheme"]);
        }

        /// <summary>
        /// Verifies that <c>add</c> with an unrecognized kind reports an error instead of throwing.
        /// </summary>
        [TestMethod]
        public void Add_UnknownKind_ReturnsError()
        {
            AuthoringResultDto result = McpAuthoringTools.Add(model: null, kind: "widget", name: "X");

            Assert.IsFalse(result.Success);
            Assert.IsNotNull(result.Error);
        }

        /// <summary>
        /// Verifies that a model built with <c>apply</c> threads into <c>analyze</c> and produces real findings.
        /// </summary>
        [TestMethod]
        public void Apply_ThenAnalyze_ThreadsModelThroughTools()
        {
            Manifest manifest = new Manifest
            {
                Elements = new List<ManifestElement>
                {
                    new ManifestElement { Alias = "p1", Kind = "process", Name = "Web" },
                    new ManifestElement { Alias = "e1", Kind = "external", Name = "User" },
                },
                Flows = new List<ManifestFlow> { new ManifestFlow { From = "e1", To = "p1", Name = "req" } },
            };

            ApplyResultDto applied = McpAuthoringTools.Apply(manifest, force: false);
            Assert.IsTrue(applied.Success, applied.Error);

            IReadOnlyList<FindingDto> findings = McpModelTools.Analyze(applied.Model!, CreateServices(this.WorkingDirectory));
            Assert.IsFalse(findings.Any(finding => finding.Id == "engine-error"));
        }

        /// <summary>The sandboxed MCP rule path preserves results from all three added matcher families.</summary>
        [TestMethod]
        public void AdditionalMatchersAgreeWithTheEngine()
        {
            using JsonDocument fixture = JsonDocument.Parse(File.ReadAllText(Path.Join(AppContext.BaseDirectory, "Fixtures", "additional-matchers.json")));
            TmForgeModelDto model = fixture.RootElement.GetProperty("model").Deserialize<TmForgeModelDto>(new JsonSerializerOptions(JsonSerializerDefaults.Web))
                ?? throw new InvalidDataException("The matcher fixture requires a model.");
            string packJson = fixture.RootElement.GetProperty("pack").GetRawText();
            File.WriteAllText(Path.Join(this.WorkingDirectory, "matchers.tmrules.json"), packJson);
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            EngineRuleOptions rules = new EngineRuleOptions
            {
                Sources = new[] { new RuleSourceDto { Name = "matchers.tmrules.json", Json = packJson } },
            };

            IReadOnlyList<FindingDto> actual = McpModelTools.Analyze(model, services, rulesPath: "matchers.tmrules.json");
            IReadOnlyList<FindingDto> expected = EngineService.Analyze(model, rules).Findings;

            Assert.AreEqual(3, actual.Count(finding => finding.RuleId?.StartsWith("rule005/", StringComparison.Ordinal) == true));
            Assert.AreEqual(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        }

        /// <summary>Sandboxed Threat Dragon import retains authored evidence through an MCP save.</summary>
        [TestMethod]
        public void ReadThreatDragonAndSavePreservesEvidence()
        {
            string path = Path.Join(this.WorkingDirectory, "dragon.json");
            File.Copy(Path.Join(AppContext.BaseDirectory, "Fixtures", "threat-dragon-v2.json"), path);
            byte[] original = File.ReadAllBytes(path);
            using ServiceProvider services = CreateServices(this.WorkingDirectory);

            TmForgeModelDto imported = McpModelTools.Read("dragon.json", services);
            McpSaveResult saved = McpModelTools.Save(imported, "imported.tmforge.json", services, "tmforge-json");
            TmForgeModelDto restored = McpModelTools.Read("imported.tmforge.json", services);

            Assert.IsTrue(saved.Bytes > 0);
            Assert.IsNotNull(restored.Threats);
            Assert.HasCount(3, restored.Threats);
            Assert.AreEqual("Model owner", restored.Metadata?.Owner);
            Assert.AreEqual("LINDDUN", restored.Threats.Single(threat => threat.Id == "manual:threat-dragon.linkability").Source?["modelType"]);
            CollectionAssert.AreEqual(original, File.ReadAllBytes(path));
        }

        /// <summary>
        /// Verifies that <c>save</c> writes a model to disk and <c>read</c> loads it back.
        /// </summary>
        [TestMethod]
        public void Save_And_Read_RoundTripAModel()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web", alias: "web");
            ServiceProvider services = CreateServices(this.WorkingDirectory);
            string path = "model.tm7";

            McpSaveResult saved = McpModelTools.Save(added.Model!, path, services);
            Assert.IsTrue(File.Exists(Path.Join(this.WorkingDirectory, path)));
            Assert.AreEqual("tm7", saved.Format);
            Assert.IsTrue(saved.Bytes > 0);

            TmForgeModelDto reread = McpModelTools.Read(path, services);
            Assert.AreEqual(1, reread.Elements!.Count);
            Assert.AreEqual("Web", reread.Elements![0].Name);
        }

        /// <summary>MCP preflight uses the workspace sandbox and returns the common input diagnostics.</summary>
        [TestMethod]
        public void PreflightRemainsReadOnlyAndSandboxed()
        {
            const string Json = "{\"schema\":\"tmforge-json\",\"elements\":[],\"flows\":[{\"id\":\"f\",\"source\":\"a\",\"target\":\"b\"}]}";
            string path = Path.Join(this.WorkingDirectory, "broken.json");
            File.WriteAllText(path, Json);
            using ServiceProvider services = CreateServices(this.WorkingDirectory);

            PreflightResultDto result = McpModelTools.Preflight("broken.json", services);

            Assert.IsFalse(result.Success);
            Assert.IsTrue(result.Diagnostics.Any(diagnostic => diagnostic.Path == "$.flows[0].source"));
            Assert.AreEqual(Json, File.ReadAllText(path));
            Assert.Throws<UnauthorizedAccessException>(() => McpModelTools.Preflight("../outside.json", services));
        }

        /// <summary>Verifies that relative traversal cannot leave the configured MCP workspace root.</summary>
        [TestMethod]
        public void Read_RejectsPathTraversal()
        {
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            _ = Assert.Throws<UnauthorizedAccessException>(() => McpModelTools.Read("../outside.tm7", services));
        }

        /// <summary>Verifies that MCP writes require a registered threat-model file extension.</summary>
        [TestMethod]
        public void Save_RejectsNonModelExtension()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            _ = Assert.Throws<NotSupportedException>(() => McpModelTools.Save(added.Model!, "workflow.yml", services, "tm7"));
            _ = Assert.Throws<NotSupportedException>(() => McpModelTools.Save(added.Model!, "package.json", services, "tmforge-json"));
        }

        /// <summary>Verifies that MCP-specific options are removed before generic host parsing.</summary>
        [TestMethod]
        public void CommandOptions_ParseRootAndLimits()
        {
            bool parsed = McpCommand.TryParseOptions(
                new[]
                {
                    "--root=" + this.WorkingDirectory,
                    "--max-read-bytes",
                    "1234",
                    "--max-write-bytes=5678",
                    "--environment",
                    "Development",
                },
                out string root,
                out long maxReadBytes,
                out long maxWriteBytes,
                out string[] hostArgs,
                out string? error);

            Assert.IsTrue(parsed, error);
            Assert.AreEqual(this.WorkingDirectory, root);
            Assert.AreEqual(1234, maxReadBytes);
            Assert.AreEqual(5678, maxWriteBytes);
            CollectionAssert.AreEqual(new[] { "--environment", "Development" }, hostArgs);
        }

        /// <summary>Verifies that missing and invalid MCP option values fail before server startup.</summary>
        [TestMethod]
        public void CommandOptions_RejectInvalidValues()
        {
            bool missing = McpCommand.TryParseOptions(
                new[] { "--root" },
                out _,
                out _,
                out _,
                out _,
                out string? missingError);
            bool invalid = McpCommand.TryParseOptions(
                new[] { "--max-read-bytes", "0" },
                out _,
                out _,
                out _,
                out _,
                out string? invalidError);

            Assert.IsFalse(missing);
            StringAssert.Contains(missingError!, "Missing value");
            Assert.IsFalse(invalid);
            StringAssert.Contains(invalidError!, "positive integer");
        }

        /// <summary>Verifies that oversized direct MCP model text is rejected before engine work.</summary>
        [TestMethod]
        public void Analyze_RejectsOversizedModelString()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "p1", Kind = "process", Name = new string('x', 65537) },
                },
            };

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Analyze(model, CreateServices(this.WorkingDirectory)));
        }

        /// <summary>Verifies that physical top-level collections cannot hide behind diagrams.</summary>
        [TestMethod]
        public void Analyze_BudgetsTopLevelAndDiagramCollectionsTogether()
        {
            TmForgeElementDto[] elements = Enumerable.Range(0, 6000)
                .Select(index => new TmForgeElementDto { Id = "p" + index, Kind = "process" })
                .ToArray();
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = elements,
                Diagrams = new[]
                {
                    new TmForgeDiagramDto { Id = "d1", Name = "Page 1", Elements = elements },
                },
            };

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Analyze(model, CreateServices(this.WorkingDirectory)));
        }

        /// <summary>Verifies that one object cannot concentrate a quadratic property-update workload.</summary>
        [TestMethod]
        public void Analyze_RejectsExcessivePropertiesOnOneObject()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto
                    {
                        Id = "p1",
                        Kind = "process",
                        Properties = Enumerable.Range(0, 257).ToDictionary(index => "key" + index, index => "value" + index),
                    },
                },
            };

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Analyze(model, CreateServices(this.WorkingDirectory)));
        }

        /// <summary>Verifies that property-update work is cumulative across otherwise valid objects.</summary>
        [TestMethod]
        public void Analyze_RejectsDistributedPropertyWork()
        {
            Dictionary<string, string> properties = Enumerable.Range(0, 256)
                .ToDictionary(index => "key" + index, index => "value" + index);
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Enumerable.Range(0, 129).Select(index => new TmForgeElementDto
                {
                    Id = "p" + index,
                    Kind = "process",
                    Properties = properties,
                }).ToArray(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Analyze(model, CreateServices(this.WorkingDirectory)));
        }

        /// <summary>Verifies that valid collection counts cannot create excessive cross-product work.</summary>
        [TestMethod]
        public void Analyze_RejectsExcessiveRelationshipWork()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Enumerable.Range(0, 2049)
                    .Select(index => new TmForgeElementDto { Id = "p" + index, Kind = "process" })
                    .ToArray(),
                Flows = Enumerable.Range(0, 2049)
                    .Select(index => new TmForgeFlowDto { Id = "f" + index, Source = "p0", Target = "p1" })
                    .ToArray(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Analyze(model, CreateServices(this.WorkingDirectory)));
        }

        /// <summary>Verifies that repeated flow-to-boundary checks share the operation work budget.</summary>
        [TestMethod]
        public void Analyze_RejectsExcessiveBoundaryFlowWork()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Enumerable.Range(0, 700)
                    .Select(index => new TmForgeElementDto { Id = "b" + index, Kind = "boundary" })
                    .ToArray(),
                Flows = Enumerable.Range(0, 1000)
                    .Select(index => new TmForgeFlowDto { Id = "f" + index, Source = "missing", Target = "missing" })
                    .ToArray(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Analyze(model, CreateServices(this.WorkingDirectory)));
        }

        /// <summary>Verifies that merge operands share one pre-execution complexity budget.</summary>
        [TestMethod]
        public void Merge_RejectsCombinedOversizedInputs()
        {
            TmForgeModelDto ours = ModelWithElements(6000, "ours");
            TmForgeModelDto theirs = ModelWithElements(6000, "theirs");

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Merge(ours, theirs));
        }

        /// <summary>Verifies that repeated conflict metadata is budgeted cumulatively in merge output.</summary>
        [TestMethod]
        public void Merge_RejectsCumulativeOversizedResponse()
        {
            string diagramId = Guid.NewGuid().ToString();
            string diagramName = new string('d', 60000);
            string[] elementIds = Enumerable.Range(0, 600).Select(_ => Guid.NewGuid().ToString()).ToArray();
            TmForgeModelDto ours = ModelWithConflicts(diagramId, diagramName, elementIds, "ours");
            TmForgeModelDto theirs = ModelWithConflicts(diagramId, diagramName, elementIds, "theirs");

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Merge(ours, theirs));
        }

        /// <summary>Verifies that oversized direct authoring arguments are rejected before edits.</summary>
        [TestMethod]
        public void Add_RejectsOversizedDirectArgument()
        {
            _ = Assert.Throws<InvalidDataException>(() => McpAuthoringTools.Add(
                model: null,
                kind: "process",
                name: new string('x', 65537)));
        }

        /// <summary>Verifies that oversized manifests are rejected before materialization.</summary>
        [TestMethod]
        public void Apply_RejectsOversizedManifest()
        {
            Manifest manifest = new Manifest
            {
                Elements = Enumerable.Range(0, 10001)
                    .Select(index => new ManifestElement { Alias = "p" + index, Kind = "process" })
                    .ToList(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpAuthoringTools.Apply(manifest));
        }

        /// <summary>Verifies that manifest flow resolution cannot create excessive cumulative scan work.</summary>
        [TestMethod]
        public void Apply_RejectsExcessiveRelationshipWork()
        {
            Manifest manifest = new Manifest
            {
                Elements = Enumerable.Range(0, 2048)
                    .Select(index => new ManifestElement { Alias = "p" + index, Kind = "process" })
                    .ToList(),
                Flows = Enumerable.Range(0, 1024)
                    .Select(_ => new ManifestFlow { From = "p0", To = "p1" })
                    .ToList(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpAuthoringTools.Apply(manifest));
        }

        /// <summary>Verifies that repeated endpoint names are budgeted cumulatively in manifest output.</summary>
        [TestMethod]
        public void ExportManifest_RejectsCumulativeOversizedResponse()
        {
            string sourceId = Guid.NewGuid().ToString();
            string targetId = Guid.NewGuid().ToString();
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = sourceId, Kind = "process", Name = new string('s', 60000) },
                    new TmForgeElementDto { Id = targetId, Kind = "process", Name = new string('t', 60000) },
                },
                Flows = Enumerable.Range(0, 300)
                    .Select(index => new TmForgeFlowDto { Id = "f" + index, Source = sourceId, Target = targetId })
                    .ToArray(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpAuthoringTools.ExportManifest(model));
        }

        /// <summary>Verifies that JSON escaping is included in the structured response budget.</summary>
        [TestMethod]
        public void ExportManifest_RejectsEscapeAmplifiedResponse()
        {
            string sourceId = Guid.NewGuid().ToString();
            string targetId = Guid.NewGuid().ToString();
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = sourceId, Kind = "process", Name = new string('"', 60000) },
                    new TmForgeElementDto { Id = targetId, Kind = "process", Name = new string('"', 60000) },
                },
                Flows = Enumerable.Range(0, 70)
                    .Select(index => new TmForgeFlowDto { Id = "f" + index, Source = sourceId, Target = targetId })
                    .ToArray(),
            };

            _ = Assert.Throws<InvalidDataException>(() => McpAuthoringTools.ExportManifest(model));
        }

        /// <summary>Verifies that a sibling whose name starts with the root name is still outside.</summary>
        [TestMethod]
        public void Read_RejectsSiblingPrefixPath()
        {
            string sibling = this.WorkingDirectory + "-other";
            Directory.CreateDirectory(sibling);
            try
            {
                string outside = Path.Join(sibling, "model.tm7");
                File.WriteAllBytes(outside, new byte[] { 1 });
                ServiceProvider services = CreateServices(this.WorkingDirectory);

                _ = Assert.Throws<UnauthorizedAccessException>(() => McpModelTools.Read(outside, services));
            }
            finally
            {
                Directory.Delete(sibling, recursive: true);
            }
        }

        /// <summary>Verifies that an in-root file symlink cannot redirect a read outside the root.</summary>
        [TestMethod]
        public void Read_RejectsFileSymlinkEscape()
        {
            string outside = Path.Join(Path.GetTempPath(), "tmforge-mcp-outside-" + Guid.NewGuid().ToString("N") + ".tm7");
            string link = Path.Join(this.WorkingDirectory, "linked.tm7");
            File.WriteAllBytes(outside, new byte[] { 1 });
            try
            {
                File.CreateSymbolicLink(link, outside);
                ServiceProvider services = CreateServices(this.WorkingDirectory);

                _ = Assert.Throws<UnauthorizedAccessException>(() => McpModelTools.Read("linked.tm7", services));
            }
            finally
            {
                File.Delete(link);
                File.Delete(outside);
            }
        }

        /// <summary>Verifies that a symlinked parent cannot redirect a new output outside the root.</summary>
        [TestMethod]
        public void Save_RejectsParentSymlinkEscape()
        {
            string outside = Path.Join(Path.GetTempPath(), "tmforge-mcp-outside-" + Guid.NewGuid().ToString("N"));
            string link = Path.Join(this.WorkingDirectory, "linked");
            Directory.CreateDirectory(outside);
            try
            {
                Directory.CreateSymbolicLink(link, outside);
                AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
                ServiceProvider services = CreateServices(this.WorkingDirectory);

                _ = Assert.Throws<UnauthorizedAccessException>(() => McpModelTools.Save(added.Model!, "linked/model.tm7", services));
                Assert.IsFalse(File.Exists(Path.Join(outside, "model.tm7")));
            }
            finally
            {
                Directory.Delete(link);
                Directory.Delete(outside, recursive: true);
            }
        }

        /// <summary>Verifies that the read limit is checked before an oversized file is buffered.</summary>
        [TestMethod]
        public void Read_RejectsOversizedFile()
        {
            File.WriteAllBytes(Path.Join(this.WorkingDirectory, "large.tm7"), new byte[17]);
            ServiceProvider services = CreateServices(this.WorkingDirectory, maxReadBytes: 16);

            _ = Assert.Throws<IOException>(() => McpModelTools.Read("large.tm7", services));
        }

        /// <summary>Verifies that a small compressed VSDX cannot expand beyond the read budget.</summary>
        [TestMethod]
        public void Read_RejectsVsdxExpansionBomb()
        {
            string path = Path.Join(this.WorkingDirectory, "large.vsdx");
            using (FileStream output = File.Create(path))
            using (ZipArchive archive = new ZipArchive(output, ZipArchiveMode.Create))
            {
                WriteZipEntry(archive, "visio/document.xml", "<VisioDocument/>");
                WriteZipEntry(archive, "visio/pages/page1.xml", new string('x', 4096));
            }

            Assert.IsTrue(new FileInfo(path).Length < 1024, "fixture must pass the compressed-byte limit");
            ServiceProvider services = CreateServices(this.WorkingDirectory, maxReadBytes: 1024);

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Read("large.vsdx", services, "vsdx"));
        }

        /// <summary>Verifies that an empty format still applies the detected VSDX expansion budget.</summary>
        [TestMethod]
        public void Read_RejectsVsdxExpansionBombWhenFormatIsEmpty()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
            ServiceProvider writeServices = CreateServices(this.WorkingDirectory);
            _ = McpModelTools.Save(added.Model!, "large.vsdx", writeServices);
            string path = Path.Join(this.WorkingDirectory, "large.vsdx");
            using (FileStream package = File.Open(path, FileMode.Open, FileAccess.ReadWrite))
            using (ZipArchive archive = new ZipArchive(package, ZipArchiveMode.Update))
            {
                WriteZipEntry(archive, "unreferenced-large.xml", new string('x', 1024 * 1024));
            }

            long compressedBytes = new FileInfo(path).Length;
            ServiceProvider services = CreateServices(this.WorkingDirectory, maxReadBytes: compressedBytes);

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Read("large.vsdx", services, string.Empty));
        }

        /// <summary>Verifies that prefixed ZIP packages are rejected before package parsing.</summary>
        [TestMethod]
        public void Detect_RejectsPrefixedZipPackage()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
            ServiceProvider services = CreateServices(this.WorkingDirectory);
            _ = McpModelTools.Save(added.Model!, "model.vsdx", services);
            byte[] package = File.ReadAllBytes(Path.Join(this.WorkingDirectory, "model.vsdx"));
            File.WriteAllBytes(
                Path.Join(this.WorkingDirectory, "prefixed.vsdx"),
                new byte[] { 1, 2, 3, 4 }.Concat(package).ToArray());

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Detect("prefixed.vsdx", services));
        }

        /// <summary>Verifies that the write limit is enforced before any output file is created.</summary>
        [TestMethod]
        public void Save_RejectsOversizedOutput()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
            ServiceProvider services = CreateServices(this.WorkingDirectory, maxWriteBytes: 16);

            _ = Assert.Throws<IOException>(() => McpModelTools.Save(added.Model!, "model.tm7", services));
            Assert.IsFalse(File.Exists(Path.Join(this.WorkingDirectory, "model.tm7")));
        }

        /// <summary>Verifies that excessive per-shape data is rejected before VSDX serialization starts.</summary>
        [TestMethod]
        public void Save_RejectsExcessiveShapeDataBeforeVsdxWrite()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto
                    {
                        Id = Guid.NewGuid().ToString(),
                        Kind = "process",
                        Properties = Enumerable.Range(0, 257).ToDictionary(index => "key" + index, index => "value" + index),
                    },
                },
            };
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Save(model, "model.vsdx", services));
            Assert.IsFalse(File.Exists(Path.Join(this.WorkingDirectory, "model.vsdx")));
        }

        /// <summary>Verifies that Shape Data cannot produce malformed XML through control characters.</summary>
        [TestMethod]
        public void Save_RejectsInvalidXmlCharacterInShapeData()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto
                    {
                        Id = Guid.NewGuid().ToString(),
                        Kind = "process",
                        Properties = new Dictionary<string, string> { ["note"] = "invalid\u0001value" },
                    },
                },
            };
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            _ = Assert.Throws<InvalidDataException>(() => McpModelTools.Save(model, "model.vsdx", services));
            Assert.IsFalse(File.Exists(Path.Join(this.WorkingDirectory, "model.vsdx")));
        }

        /// <summary>Verifies that VSDX save streams through the bounded output and reads back.</summary>
        [TestMethod]
        public void Save_And_Read_VsdxRoundTripsAModel()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(
                model: null,
                kind: "process",
                name: "Web",
                alias: "web",
                properties: new Dictionary<string, string> { ["Owner's note"] = "Use 'strict' \"mode\" & verify" },
                force: true);
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            McpSaveResult saved = McpModelTools.Save(added.Model!, "model.vsdx", services);
            TmForgeModelDto reread = McpModelTools.Read("model.vsdx", services, "vsdx");

            Assert.AreEqual("vsdx", saved.Format);
            Assert.IsTrue(saved.Bytes > 0);
            Assert.AreEqual("Web", reread.Elements!.Single().Name);
            Assert.AreEqual("Use 'strict' \"mode\" & verify", reread.Elements![0].Properties["Owner's note"]);
        }

        /// <summary>Verifies that save does not create caller-selected intermediate directories.</summary>
        [TestMethod]
        public void Save_RejectsMissingParentDirectory()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            _ = Assert.Throws<FileNotFoundException>(() => McpModelTools.Save(added.Model!, "missing/model.tm7", services));
        }

        /// <summary>Verifies that an explicit format cannot disagree with the destination extension.</summary>
        [TestMethod]
        public void Save_RejectsFormatExtensionMismatch()
        {
            AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
            ServiceProvider services = CreateServices(this.WorkingDirectory);

            _ = Assert.Throws<NotSupportedException>(() => McpModelTools.Save(added.Model!, "model.tm7", services, "drawio"));
        }

        /// <summary>Verifies that save replaces a hard-link entry instead of truncating its outside inode.</summary>
        [TestMethod]
        public void Save_DoesNotWriteThroughHardLink()
        {
            string outside = Path.Join(Path.GetTempPath(), "tmforge-mcp-outside-" + Guid.NewGuid().ToString("N") + ".tm7");
            string destination = Path.Join(this.WorkingDirectory, "model.tm7");
            byte[] original = new byte[] { 1, 2, 3, 4 };
            File.WriteAllBytes(outside, original);
            try
            {
                CreateHardLink(destination, outside);
                AuthoringResultDto added = McpAuthoringTools.Add(model: null, kind: "process", name: "Web");
                ServiceProvider services = CreateServices(this.WorkingDirectory);

                McpSaveResult saved = McpModelTools.Save(added.Model!, "model.tm7", services);

                CollectionAssert.AreEqual(original, File.ReadAllBytes(outside));
                Assert.IsTrue(saved.Bytes > original.Length);
                TmForgeModelDto reread = McpModelTools.Read("model.tm7", services);
                Assert.AreEqual("Web", reread.Elements!.Single().Name);
            }
            finally
            {
                File.Delete(destination);
                File.Delete(outside);
            }
        }

        /// <summary>Verifies that replacing the configured root with a symlink is detected before I/O.</summary>
        [TestMethod]
        public void Read_RejectsRootReplacement()
        {
            ServiceProvider services = CreateServices(this.WorkingDirectory);
            string movedRoot = this.WorkingDirectory + "-moved";
            string outside = this.WorkingDirectory + "-outside";
            Directory.CreateDirectory(outside);
            File.WriteAllBytes(Path.Join(outside, "model.tm7"), new byte[] { 1 });
            Directory.Move(this.WorkingDirectory, movedRoot);
            Directory.CreateSymbolicLink(this.WorkingDirectory, outside);
            try
            {
                _ = Assert.Throws<UnauthorizedAccessException>(() => McpModelTools.Read("model.tm7", services));
            }
            finally
            {
                Directory.Delete(this.WorkingDirectory);
                Directory.Move(movedRoot, this.WorkingDirectory);
                Directory.Delete(outside, recursive: true);
            }
        }

        /// <summary>
        /// Verifies that the grounding tools return their catalogs (schema, rules, stencils, formats).
        /// </summary>
        [TestMethod]
        public void Grounding_Tools_ReturnCatalogs()
        {
            Assert.IsTrue(McpGroundingTools.ManifestSchema().Length > 0);
            Assert.IsTrue(McpGroundingTools.Rules(CreateServices(this.WorkingDirectory)).Count > 0);
            Assert.IsTrue(McpGroundingTools.PropertySchema().Count > 0);
            Assert.IsTrue(McpGroundingTools.Stencils().Count > 0);
            Assert.IsTrue(McpGroundingTools.Formats().Count > 0);
        }

        /// <summary>The formats resource is a stable snapshot of the existing grounding tool's content.</summary>
        [TestMethod]
        public void Grounding_FormatsResourceIsVersionedAndFingerprintable()
        {
            string snapshot = McpGroundingResources.Formats();
            Assert.AreEqual(snapshot, McpGroundingResources.Formats());
            using JsonDocument document = JsonDocument.Parse(snapshot);
            JsonElement root = document.RootElement;
            Assert.AreEqual("tmforge-grounding", root.GetProperty("schema").GetString());
            Assert.AreEqual(1, root.GetProperty("version").GetInt32());
            Assert.AreEqual("formats", root.GetProperty("kind").GetString());
            Assert.AreEqual("application/json", root.GetProperty("contentType").GetString());
            Assert.IsFalse(string.IsNullOrEmpty(root.GetProperty("engineVersion").GetString()));
            string content = root.GetProperty("content").GetString() ?? string.Empty;
            Assert.AreEqual(CliJson.Serialize(McpGroundingTools.Formats()), content);
            Assert.AreEqual(RulePackIdentity.CreateFingerprint(Encoding.UTF8.GetBytes(content)), root.GetProperty("fingerprint").GetString());
        }

        /// <summary>All fixed resources retain compatibility-tool content and stable cache metadata.</summary>
        /// <param name="kind">The requested catalog.</param>
        [TestMethod]
        [DataRow("manifest-schema")]
        [DataRow("property-schema")]
        [DataRow("rule-packs")]
        public void Grounding_StaticResourcesMatchTheTools(string kind)
        {
            Func<string> read = kind switch
            {
                "manifest-schema" => McpGroundingResources.ManifestSchema,
                "property-schema" => McpGroundingResources.PropertySchema,
                _ => McpGroundingResources.RulePacks,
            };
            string snapshot = read();
            Assert.AreEqual(snapshot, read());
            using JsonDocument document = JsonDocument.Parse(snapshot);
            JsonElement root = document.RootElement;
            Assert.AreEqual("tmforge-grounding", root.GetProperty("schema").GetString());
            Assert.AreEqual(1, root.GetProperty("version").GetInt32());
            Assert.AreEqual(kind, root.GetProperty("kind").GetString());
            Assert.AreEqual(kind == "manifest-schema" ? "text/plain" : "application/json", root.GetProperty("contentType").GetString());
            string content = root.GetProperty("content").GetString() ?? string.Empty;
            Assert.AreEqual(RulePackIdentity.CreateFingerprint(Encoding.UTF8.GetBytes(content)), root.GetProperty("fingerprint").GetString());
            if (kind == "manifest-schema")
            {
                Assert.AreEqual(McpGroundingTools.ManifestSchema(), content);
                StringAssert.Contains(content, "\"schema\": \"" + Manifest.SchemaName + "\"");
                StringAssert.Contains(content, "\"version\": " + Manifest.CurrentVersion);
                foreach (string field in new[] { "pages", "page", "x", "y", "width", "height", "alias" })
                {
                    StringAssert.Contains(content, "\"" + field + "\"");
                }
            }
            else if (kind == "property-schema")
            {
                Assert.AreEqual(CliJson.Serialize(McpGroundingTools.PropertySchema()), content);
            }
            else
            {
                using JsonDocument packs = JsonDocument.Parse(content);
                IReadOnlyList<RulePackDto>? actual = packs.RootElement.GetProperty("rulePacks").Deserialize<IReadOnlyList<RulePackDto>>(new JsonSerializerOptions(JsonSerializerDefaults.Web));
                Assert.AreEqual(CliJson.Serialize(McpGroundingTools.RulePacks(CreateServices(this.WorkingDirectory))), CliJson.Serialize(actual!));
                Assert.AreEqual(0, packs.RootElement.GetProperty("customPacks").GetArrayLength());
                Assert.AreEqual(0, packs.RootElement.GetProperty("diagnostics").GetArrayLength());
            }
        }

        /// <summary>Custom metadata matches tool catalogs and invalidates pins even when pack counts do not change.</summary>
        /// <param name="versioned">Whether the selected source carries v2 pack identity.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void Grounding_CustomResourcesTrackContentAndPins(bool versioned)
        {
            const string path = "custom rules.tmrules.json";
            string json = GroundingRuleJson(versioned, "Before");
            File.WriteAllText(Path.Join(this.WorkingDirectory, path), json);
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            string snapshot = McpGroundingResources.CustomRulePacks(services, path);
            using JsonDocument envelope = JsonDocument.Parse(snapshot);
            string fingerprint = envelope.RootElement.GetProperty("fingerprint").GetString() ?? string.Empty;
            string content = envelope.RootElement.GetProperty("content").GetString() ?? string.Empty;
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            Assert.AreEqual(RulePackIdentity.CreateFingerprint(Encoding.UTF8.GetBytes(content)), fingerprint);
            Assert.AreEqual(0, root.GetProperty("diagnostics").GetArrayLength());
            Assert.AreEqual(versioned ? 1 : 0, root.GetProperty("customPacks").GetArrayLength());
            Assert.AreEqual(RulePackIdentity.CreateFingerprint(Encoding.UTF8.GetBytes(json)), root.GetProperty("sources")[0].GetProperty("fingerprint").GetString());
            IReadOnlyList<RulePackDto>? packs = root.GetProperty("rulePacks").Deserialize<IReadOnlyList<RulePackDto>>(new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.IsNotNull(packs);
            Assert.AreEqual(CliJson.Serialize(McpGroundingTools.RulePacks(services, path)), CliJson.Serialize(packs));
            Assert.AreEqual(snapshot, McpGroundingResources.CustomRulePacks(services, path));
            Assert.AreEqual(snapshot, McpGroundingResources.CustomRulePacks(services, path, fingerprint));

            File.WriteAllText(Path.Join(this.WorkingDirectory, path), GroundingRuleJson(versioned, "After"));
            string updated = McpGroundingResources.CustomRulePacks(services, path);
            Assert.AreNotEqual(snapshot, updated);
            using JsonDocument newEnvelope = JsonDocument.Parse(updated);
            Assert.AreNotEqual(fingerprint, newEnvelope.RootElement.GetProperty("fingerprint").GetString());
            McpException mismatch = Assert.Throws<McpException>(() => McpGroundingResources.CustomRulePacks(services, path, fingerprint));
            StringAssert.Contains(mismatch.Message, "fingerprint mismatch");
        }

        /// <summary>A malformed selected pack remains visible instead of presenting a built-ins-only success.</summary>
        [TestMethod]
        public void Grounding_CustomResourcePreservesDiagnostics()
        {
            const string path = "invalid.tmrules.json";
            File.WriteAllText(Path.Join(this.WorkingDirectory, path), "{ invalid json");
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            using JsonDocument envelope = JsonDocument.Parse(McpGroundingResources.CustomRulePacks(services, path));
            using JsonDocument content = JsonDocument.Parse(envelope.RootElement.GetProperty("content").GetString() ?? string.Empty);
            Assert.AreEqual(0, content.RootElement.GetProperty("customPacks").GetArrayLength());
            Assert.IsTrue(content.RootElement.GetProperty("diagnostics").GetArrayLength() > 0);
            Assert.AreEqual(1, content.RootElement.GetProperty("sources").GetArrayLength());
            Assert.IsFalse(string.IsNullOrWhiteSpace(content.RootElement.GetProperty("sources")[0].GetProperty("fingerprint").GetString()));
        }

        /// <summary>Resource reads retain file-tool path and byte limits, including pinned rereads.</summary>
        [TestMethod]
        public void Grounding_CustomResourceEnforcesSandboxAndLimits()
        {
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            Assert.Throws<ArgumentException>(() => McpGroundingResources.CustomRulePacks(services, " "));
            Assert.Throws<ArgumentException>(() => McpGroundingResources.CustomRulePacks(services, "rules.tmrules.json", "invalid"));
            Assert.Throws<UnauthorizedAccessException>(() => McpGroundingResources.CustomRulePacks(services, "../outside.tmrules.json"));
            Assert.Throws<FileNotFoundException>(() => McpGroundingResources.CustomRulePacks(services, "missing.tmrules.json"));

            string path = Path.Join(this.WorkingDirectory, "rules.tmrules.json");
            File.WriteAllText(path, GroundingRuleJson(versioned: true, "Read limit"));
            string snapshot = McpGroundingResources.CustomRulePacks(services, "rules.tmrules.json");
            using JsonDocument document = JsonDocument.Parse(snapshot);
            string fingerprint = document.RootElement.GetProperty("fingerprint").GetString() ?? string.Empty;
            using ServiceProvider limited = CreateServices(this.WorkingDirectory, maxReadBytes: 16);
            Assert.Throws<IOException>(() => McpGroundingResources.CustomRulePacks(limited, "rules.tmrules.json", fingerprint));
            File.Delete(path);
            Assert.Throws<FileNotFoundException>(() => McpGroundingResources.CustomRulePacks(services, "rules.tmrules.json", fingerprint));
        }

        /// <summary>A matching pin cannot authorize a file that now resolves outside the configured root.</summary>
        [TestMethod]
        public void Grounding_PinnedResourcesStillRejectSymlinkEscapes()
        {
            const string path = "rules.tmrules.json";
            string fullPath = Path.Join(this.WorkingDirectory, path);
            string outside = this.WorkingDirectory + "-outside.tmrules.json";
            string json = GroundingRuleJson(versioned: true, "Same content");
            File.WriteAllText(fullPath, json);
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            using JsonDocument envelope = JsonDocument.Parse(McpGroundingResources.CustomRulePacks(services, path));
            string fingerprint = envelope.RootElement.GetProperty("fingerprint").GetString() ?? string.Empty;
            File.WriteAllText(outside, json);
            File.Delete(fullPath);
            try
            {
                File.CreateSymbolicLink(fullPath, outside);
                Assert.Throws<UnauthorizedAccessException>(() => McpGroundingResources.CustomRulePacks(services, path, fingerprint));
            }
            finally
            {
                File.Delete(fullPath);
                File.Delete(outside);
            }
        }

        /// <summary>Pins use one canonical spelling and cannot turn malformed values into unpinned reads.</summary>
        [TestMethod]
        public void Grounding_RejectsMalformedFingerprintPins()
        {
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            foreach (string pin in new[] { string.Empty, "sha256:" + new string('a', 63), "SHA256:" + new string('a', 64), "sha256:" + new string('g', 64) })
            {
                Assert.Throws<ArgumentException>(() => McpGroundingResources.CustomRulePacks(services, "rules.tmrules.json", pin));
            }
        }

        /// <summary>The real stdio host discovers and reads resources while retaining grounding tools.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Grounding_ResourcesAreDiscoverableOverStdio()
        {
            using CancellationTokenSource deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using McpClient client = await this.StartGroundingClient(deadline.Token);
            Assert.IsNotNull(client.ServerCapabilities.Resources);
            Dictionary<string, Func<string>> expected = new Dictionary<string, Func<string>>(StringComparer.Ordinal)
            {
                ["tmforge://grounding/v1/formats"] = McpGroundingResources.Formats,
                ["tmforge://grounding/v1/property-schema"] = McpGroundingResources.PropertySchema,
                ["tmforge://grounding/v1/manifest-schema"] = McpGroundingResources.ManifestSchema,
                ["tmforge://grounding/v1/rule-packs"] = McpGroundingResources.RulePacks,
            };
            IList<McpClientResource> resources = await client.ListResourcesAsync(cancellationToken: deadline.Token);
            CollectionAssert.AreEquivalent(expected.Keys.ToArray(), resources.Select(resource => resource.Uri).ToArray());
            foreach (McpClientResource resource in resources)
            {
                Assert.AreEqual("application/json", resource.MimeType);
                ReadResourceResult result = await client.ReadResourceAsync(resource.Uri, cancellationToken: deadline.Token);
                TextResourceContents text = (TextResourceContents)result.Contents.Single();
                Assert.AreEqual(resource.Uri, text.Uri);
                Assert.AreEqual("application/json", text.MimeType);
                Assert.AreEqual(expected[resource.Uri](), text.Text);
            }

            IList<McpClientResourceTemplate> templates = await client.ListResourceTemplatesAsync(cancellationToken: deadline.Token);
            Assert.AreEqual("tmforge://grounding/v1/rule-packs/custom{?rulesPath,fingerprint}", templates.Single().UriTemplate);
            IList<McpClientTool> tools = await client.ListToolsAsync(cancellationToken: deadline.Token);
            foreach (string name in new[] { "formats", "property_schema", "manifest_schema", "rule_packs", "rules", "stencils" })
            {
                Assert.IsTrue(tools.Any(tool => tool.Name == name), name);
            }

            CallToolResult legacy = await client.CallToolAsync("formats", cancellationToken: deadline.Token);
            Assert.IsFalse(legacy.IsError == true);
            string json = ((TextContentBlock)legacy.Content.Single()).Text;
            IReadOnlyList<FormatDto>? formats = JsonSerializer.Deserialize<IReadOnlyList<FormatDto>>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.IsNotNull(formats);
            Assert.AreEqual(CliJson.Serialize(McpGroundingTools.Formats()), CliJson.Serialize(formats));
            await Assert.ThrowsAsync<McpException>(() => client.ReadResourceAsync("tmforge://grounding/v99/formats", cancellationToken: deadline.Token).AsTask());
        }

        /// <summary>URI parameters preserve file names and cache pins without bypassing the file sandbox.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Grounding_CustomResourceUrisWorkOverStdio()
        {
            const string path = "policy files/custom +#%.tmrules.json";
            string fullPath = Path.Join(this.WorkingDirectory, path);
            Directory.CreateDirectory(Path.Join(this.WorkingDirectory, "policy files"));
            File.WriteAllText(fullPath, GroundingRuleJson(versioned: true, "Before"));
            using CancellationTokenSource deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await using McpClient client = await this.StartGroundingClient(deadline.Token);
            using ServiceProvider services = CreateServices(this.WorkingDirectory);
            const string resource = "tmforge://grounding/v1/rule-packs/custom";
            string uri = resource + "?rulesPath=" + Uri.EscapeDataString(path);
            ReadResourceResult result = await client.ReadResourceAsync(uri, cancellationToken: deadline.Token);
            TextResourceContents first = (TextResourceContents)result.Contents.Single();
            Assert.AreEqual(uri, first.Uri);
            Assert.AreEqual("application/json", first.MimeType);
            Assert.AreEqual(McpGroundingResources.CustomRulePacks(services, path), first.Text);
            using JsonDocument envelope = JsonDocument.Parse(first.Text);
            string fingerprint = envelope.RootElement.GetProperty("fingerprint").GetString() ?? string.Empty;
            string pinnedUri = uri + "&fingerprint=" + Uri.EscapeDataString(fingerprint);
            ReadResourceResult pinned = await client.ReadResourceAsync(pinnedUri, cancellationToken: deadline.Token);
            Assert.AreEqual(first.Text, ((TextResourceContents)pinned.Contents.Single()).Text);

            CallToolResult legacy = await client.CallToolAsync("rule_packs", new Dictionary<string, object?> { ["rulesPath"] = path }, cancellationToken: deadline.Token);
            Assert.IsFalse(legacy.IsError == true);
            StringAssert.Contains(((TextContentBlock)legacy.Content.Single()).Text, "cached-policy");
            File.WriteAllText(fullPath, GroundingRuleJson(versioned: true, "After"));
            ReadResourceResult updated = await client.ReadResourceAsync(uri, cancellationToken: deadline.Token);
            Assert.AreNotEqual(first.Text, ((TextResourceContents)updated.Contents.Single()).Text);
            McpException mismatch = await Assert.ThrowsAsync<McpException>(() => client.ReadResourceAsync(pinnedUri, cancellationToken: deadline.Token).AsTask());
            StringAssert.Contains(mismatch.Message, "fingerprint mismatch");

            string escapeUri = resource + "?rulesPath=" + Uri.EscapeDataString("../outside.tmrules.json");
            await Assert.ThrowsAsync<McpException>(() => client.ReadResourceAsync(escapeUri, cancellationToken: deadline.Token).AsTask());
            await Assert.ThrowsAsync<McpException>(() => client.ReadResourceAsync(resource, cancellationToken: deadline.Token).AsTask());
            File.WriteAllText(fullPath, "{ invalid json");
            ReadResourceResult invalid = await client.ReadResourceAsync(uri, cancellationToken: deadline.Token);
            using JsonDocument invalidEnvelope = JsonDocument.Parse(((TextResourceContents)invalid.Contents.Single()).Text);
            using JsonDocument invalidContent = JsonDocument.Parse(invalidEnvelope.RootElement.GetProperty("content").GetString() ?? string.Empty);
            Assert.AreEqual(0, invalidContent.RootElement.GetProperty("customPacks").GetArrayLength());
            Assert.IsTrue(invalidContent.RootElement.GetProperty("diagnostics").GetArrayLength() > 0);
            File.Delete(fullPath);
            await Assert.ThrowsAsync<McpException>(() => client.ReadResourceAsync(pinnedUri, cancellationToken: deadline.Token).AsTask());
        }

        /// <summary>
        /// Verifies that a property map is marshaled into the <c>KEY=VALUE</c> assignment list.
        /// </summary>
        [TestMethod]
        public void ToAssignments_MarshalsPropertyMap()
        {
            List<string> assignments = McpToolSupport.ToAssignments(new Dictionary<string, string> { ["Protocol"] = "HTTPS", ["Port"] = "443" }).ToList();

            Assert.AreEqual(2, assignments.Count);
            CollectionAssert.Contains(assignments, "Protocol=HTTPS");
            CollectionAssert.Contains(assignments, "Port=443");
        }

        /// <summary>
        /// Verifies that <c>add_threat</c> records a manually-authored threat on the model's overlay.
        /// </summary>
        [TestMethod]
        public void AddThreat_CreatesManualOverlayEntry()
        {
            AuthoringResultDto result = McpAuthoringTools.AddThreat(
                model: null,
                title: "Config is world-writable",
                category: "Tampering",
                scope: "22222222-2222-4222-8222-222222222222",
                priority: "High");

            Assert.IsTrue(result.Success, result.Error);
            Assert.IsTrue(result.Id!.StartsWith("manual:", StringComparison.Ordinal));
            ThreatStateDto entry = result.Model!.Threats!.Single();
            Assert.IsTrue(entry.Manual == true);
            Assert.AreEqual("Tampering", entry.Category);
            Assert.AreEqual("Config is world-writable", entry.Title);
            Assert.AreEqual("22222222-2222-4222-8222-222222222222", entry.ElementIds!.Single());
        }

        /// <summary>
        /// Verifies that <c>edit_threat</c> records a rule-threat edit that the projection then applies.
        /// </summary>
        [TestMethod]
        public void EditThreat_RecordsEditAndProjectsIt()
        {
            TmForgeModelDto model = ModelWithSpoofingThreat();
            ThreatDto spoof = EngineService.GenerateThreats(model).First(threat => threat.RuleId == "TM1023");

            AuthoringResultDto result = McpAuthoringTools.EditThreat(model, spoof.Id, state: "Mitigated", priority: "Low");

            Assert.IsTrue(result.Success, result.Error);
            ThreatDto after = EngineService.GenerateThreats(result.Model!).First(threat => threat.Id == spoof.Id);
            Assert.AreEqual("Mitigated", after.State);
            Assert.AreEqual("Low", after.Priority);
        }

        /// <summary>
        /// Verifies that <c>remove_threat</c> deletes a manually-authored threat's overlay entry.
        /// </summary>
        [TestMethod]
        public void RemoveThreat_DeletesManualOverlayEntry()
        {
            AuthoringResultDto added = McpAuthoringTools.AddThreat(model: null, title: "X", category: "Repudiation");
            Assert.IsTrue(added.Success, added.Error);
            string id = added.Id!;

            AuthoringResultDto removed = McpAuthoringTools.RemoveThreat(added.Model!, id);

            Assert.IsTrue(removed.Success, removed.Error);
            Assert.IsNull(removed.Model!.Threats);
            Assert.AreEqual(id, removed.Removed!.Single());
        }

        private static string GroundingRuleJson(bool versioned, string message)
        {
            string rule = "{\"id\":\"CACHE\",\"appliesTo\":\"process\",\"message\":\"" + message + "\",\"when\":{\"property\":\"Isolation\"}}";
            return versioned
                ? "{\"schema\":\"tmforge-rules\",\"version\":2,\"dialect\":\"urn:tmforge:rules:flat-v1\",\"pack\":{\"id\":\"cached-policy\",\"name\":\"Cached policy\",\"version\":\"1.0\"},\"properties\":[{\"name\":\"Isolation\"}],\"rules\":[" + rule + "]}"
                : "{\"rules\":[" + rule + "]}";
        }

        private static TmForgeModelDto ModelWithSpoofingThreat()
        {
            const string externalId = "11111111-1111-4111-8111-111111111111";
            const string processId = "22222222-2222-4222-8222-222222222222";
            return new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = externalId, Kind = "external", Name = "Client", X = 40, Y = 40 },
                    new TmForgeElementDto { Id = processId, Kind = "process", Name = "Gateway", X = 220, Y = 40 },
                },
                Flows = new[]
                {
                    new TmForgeFlowDto { Id = "33333333-3333-4333-8333-333333333333", Source = externalId, Target = processId, Name = "request" },
                },
            };
        }

        private static TmForgeModelDto ModelWithElements(int count, string prefix)
        {
            return new TmForgeModelDto
            {
                Elements = Enumerable.Range(0, count)
                    .Select(index => new TmForgeElementDto
                    {
                        Id = prefix + index,
                        Kind = "process",
                    })
                    .ToArray(),
            };
        }

        private static TmForgeModelDto ModelWithConflicts(
            string diagramId,
            string diagramName,
            IEnumerable<string> elementIds,
            string elementName)
        {
            return new TmForgeModelDto
            {
                Diagrams = new[]
                {
                    new TmForgeDiagramDto
                    {
                        Id = diagramId,
                        Name = diagramName,
                        Elements = elementIds.Select(id => new TmForgeElementDto
                        {
                            Id = id,
                            Kind = "process",
                            Name = elementName,
                        }).ToArray(),
                    },
                },
            };
        }

        private static ServiceProvider CreateServices(
            string root,
            long maxReadBytes = McpPathPolicy.DefaultMaxReadBytes,
            long maxWriteBytes = McpPathPolicy.DefaultMaxWriteBytes)
        {
            return new ServiceCollection()
                .AddSingleton(new McpPathPolicy(root, maxReadBytes, maxWriteBytes))
                .BuildServiceProvider();
        }

        private static void CreateHardLink(string linkPath, string existingPath)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = OperatingSystem.IsWindows() ? "cmd.exe" : "ln",
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            if (OperatingSystem.IsWindows())
            {
                startInfo.ArgumentList.Add("/c");
                startInfo.ArgumentList.Add("mklink");
                startInfo.ArgumentList.Add("/H");
                startInfo.ArgumentList.Add(linkPath);
                startInfo.ArgumentList.Add(existingPath);
            }
            else
            {
                startInfo.ArgumentList.Add(existingPath);
                startInfo.ArgumentList.Add(linkPath);
            }

            Process? started = Process.Start(startInfo);
            using Process process = started!;
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();
            Assert.AreEqual(0, process.ExitCode, error);
        }

        private static void WriteZipEntry(ZipArchive archive, string name, string content)
        {
            ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.SmallestSize);
            using StreamWriter writer = new StreamWriter(entry.Open());
            writer.Write(content);
        }

        private Task<McpClient> StartGroundingClient(CancellationToken cancellationToken)
        {
            StdioClientTransport transport = new StdioClientTransport(new StdioClientTransportOptions
            {
                Command = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet",
                Arguments = new[] { typeof(McpGroundingResources).Assembly.Location, "mcp", "--root", this.WorkingDirectory },
                WorkingDirectory = this.WorkingDirectory,
                InheritEnvironmentVariables = false,
                EnvironmentVariables = StdioClientTransportOptions.GetDefaultEnvironmentVariables(),
                ShutdownTimeout = TimeSpan.FromSeconds(3),
            });
            return McpClient.CreateAsync(transport, cancellationToken: cancellationToken);
        }
    }
}
