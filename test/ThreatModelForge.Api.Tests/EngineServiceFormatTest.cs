namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Unit tests for the format-facing methods of <see cref="EngineService"/> —
    /// <see cref="EngineService.ReadModel"/>, <see cref="EngineService.Convert(TmForgeModelDto, string)"/>,
    /// <see cref="EngineService.Detect"/>, and <see cref="EngineService.Report(TmForgeModelDto, string)"/> — which are the
    /// single seam the CLI, API, and WebAssembly hosts all funnel document I/O through.
    /// </summary>
    [TestClass]
    public class EngineServiceFormatTest
    {
        /// <summary>
        /// Converting to the canonical tmforge-json format and reading it back preserves the model's
        /// elements and flows (name, kind, and flow properties) through the facade.
        /// </summary>
        [TestMethod]
        public void ConvertToTmForgeJsonRoundTripsThroughReadModel()
        {
            byte[] bytes = EngineService.Convert(ConnectedModel(), "tmforge-json");

            TmForgeModelDto restored = EngineService.ReadModel(bytes, "tmforge-json");

            Assert.IsNotNull(restored.Elements);
            Assert.IsNotNull(restored.Flows);
            CollectionAssert.AreEquivalent(
                new[] { "Web App", "Database" },
                restored.Elements!.Select(e => e.Name).ToArray());
            Assert.AreEqual(1, restored.Flows!.Count);
            Assert.AreEqual("writes", restored.Flows[0].Name);
            Assert.AreEqual("TLS", restored.Flows[0].Properties["Protocol"]);
        }

        /// <summary>
        /// Converting to the lossless <c>.tm7</c> format and reading it back preserves the model's
        /// elements and flows through the facade.
        /// </summary>
        [TestMethod]
        public void ConvertToTm7RoundTripsThroughReadModel()
        {
            byte[] bytes = EngineService.Convert(ConnectedModel(), "tm7");

            TmForgeModelDto restored = EngineService.ReadModel(bytes, "tm7");

            Assert.IsNotNull(restored.Elements);
            Assert.IsNotNull(restored.Flows);
            CollectionAssert.AreEquivalent(
                new[] { "Web App", "Database" },
                restored.Elements!.Select(e => e.Name).ToArray());
            Assert.AreEqual(1, restored.Flows!.Count);
            Assert.AreEqual("writes", restored.Flows[0].Name);
        }

        /// <summary>
        /// When no format id is supplied, <see cref="EngineService.ReadModel"/> sniffs the content and
        /// still parses it.
        /// </summary>
        [TestMethod]
        public void ReadModelSniffsFormatWhenIdOmitted()
        {
            byte[] bytes = EngineService.Convert(SingleProcessModel(), "tm7");

            TmForgeModelDto restored = EngineService.ReadModel(bytes, null);

            Assert.IsNotNull(restored.Elements);
            Assert.AreEqual(1, restored.Elements!.Count);
            Assert.AreEqual("Web App", restored.Elements[0].Name);
        }

        /// <summary>
        /// <see cref="EngineService.ReadModel"/> rejects null content.
        /// </summary>
        [TestMethod]
        public void ReadModelNullContentThrows()
        {
            Assert.Throws<ArgumentNullException>(() => EngineService.ReadModel(null!, "tm7"));
        }

        /// <summary>
        /// <see cref="EngineService.Convert(TmForgeModelDto, string)"/> rejects an empty or null format id.
        /// </summary>
        [TestMethod]
        public void ConvertEmptyFormatIdThrows()
        {
            Assert.Throws<ArgumentException>(() => EngineService.Convert(SingleProcessModel(), string.Empty));
            Assert.Throws<ArgumentException>(() => EngineService.Convert(SingleProcessModel(), null!));
        }

        /// <summary>
        /// <see cref="EngineService.Convert(TmForgeModelDto, string)"/> rejects a format id that is not registered.
        /// </summary>
        [TestMethod]
        public void ConvertUnknownFormatIdThrows()
        {
            Assert.Throws<NotSupportedException>(
                () => EngineService.Convert(SingleProcessModel(), "does-not-exist"));
        }

        /// <summary>
        /// <see cref="EngineService.Detect"/> recognizes tmforge-json content by sniffing.
        /// </summary>
        [TestMethod]
        public void DetectRecognizesTmForgeJson()
        {
            byte[] bytes = EngineService.Convert(SingleProcessModel(), "tmforge-json");

            FormatDto? detected = EngineService.Detect(bytes);

            Assert.IsNotNull(detected);
            Assert.AreEqual("tmforge-json", detected!.Id);
        }

        /// <summary>
        /// <see cref="EngineService.Detect"/> recognizes <c>.tm7</c> content by sniffing.
        /// </summary>
        [TestMethod]
        public void DetectRecognizesTm7()
        {
            byte[] bytes = EngineService.Convert(SingleProcessModel(), "tm7");

            FormatDto? detected = EngineService.Detect(bytes);

            Assert.IsNotNull(detected);
            Assert.AreEqual("tm7", detected!.Id);
        }

        /// <summary>
        /// <see cref="EngineService.Detect"/> returns null when the content matches no known format.
        /// </summary>
        [TestMethod]
        public void DetectUnrecognizedContentReturnsNull()
        {
            byte[] bytes = Encoding.UTF8.GetBytes("this is plainly not a threat model document");

            Assert.IsNull(EngineService.Detect(bytes));
        }

        /// <summary>
        /// <see cref="EngineService.Detect"/> rejects null content.
        /// </summary>
        [TestMethod]
        public void DetectNullContentThrows()
        {
            Assert.Throws<ArgumentNullException>(() => EngineService.Detect(null!));
        }

        /// <summary>
        /// <see cref="EngineService.Report(TmForgeModelDto, string)"/> renders an HTML document for the default format.
        /// </summary>
        [TestMethod]
        public void ReportHtmlProducesHtmlDocument()
        {
            byte[] bytes = EngineService.Report(SingleProcessModel(), "html");

            string report = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(report.Contains('<'), "Expected markup in the HTML report.");
            Assert.IsTrue(
                report.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0,
                "Expected an HTML report to contain an html tag.");
        }

        /// <summary>
        /// <see cref="EngineService.Report(TmForgeModelDto, string)"/> includes the rule-backed threats generated for the model,
        /// not only threats that were manually authored into its register.
        /// </summary>
        [TestMethod]
        public void ReportHtmlIncludesGeneratedThreats()
        {
            TmForgeModelDto model = ThreatBearingModel();
            ThreatDto generated = EngineService.GenerateThreats(model).First(threat => threat.RuleId == "TM1023");

            string report = Encoding.UTF8.GetString(EngineService.Report(model, "html"));

            StringAssert.Contains(report, generated.Title);
            StringAssert.Contains(report, generated.RuleId);
            StringAssert.Contains(report, generated.Interaction);
            StringAssert.Contains(report, generated.Mitigation!);
            StringAssert.Contains(report, generated.References[0]);
        }

        /// <summary>
        /// <see cref="EngineService.Report(TmForgeModelDto, string)"/> enriches sparse accepted triage with the generated threat
        /// details while retaining the author's state and justification.
        /// </summary>
        [TestMethod]
        public void ReportHtmlIncludesAcceptedThreatDetails()
        {
            ThreatDto generated = EngineService.GenerateThreats(ThreatBearingModel()).First(threat => threat.RuleId == "TM1023");
            TmForgeModelDto model = ThreatBearingModel(
                new[]
                {
                    new ThreatStateDto
                    {
                        Id = generated.Id,
                        State = "Accepted",
                        Justification = "Authenticated by the upstream identity proxy.",
                    },
                });

            string report = Encoding.UTF8.GetString(EngineService.Report(model, "html"));

            StringAssert.Contains(report, generated.Title);
            StringAssert.Contains(report, "TM1023");
            StringAssert.Contains(report, "Accepted");
            StringAssert.Contains(report, "Authenticated by the upstream identity proxy.");
        }

        /// <summary>
        /// <see cref="EngineService.Report(TmForgeModelDto, string)"/> renders SVG when asked, matching the format string
        /// case-insensitively.
        /// </summary>
        [TestMethod]
        public void ReportSvgIsCaseInsensitive()
        {
            byte[] bytes = EngineService.Report(SingleProcessModel(), "SVG");

            string report = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(
                report.IndexOf("<svg", StringComparison.OrdinalIgnoreCase) >= 0,
                "Expected an <svg> root for the SVG report.");
        }

        /// <summary>
        /// <see cref="EngineService.Report(TmForgeModelDto, string)"/> falls back to HTML for an unrecognized report format.
        /// </summary>
        [TestMethod]
        public void ReportUnknownFormatFallsBackToHtml()
        {
            byte[] bytes = EngineService.Report(SingleProcessModel(), "pdf");

            string report = Encoding.UTF8.GetString(bytes);
            Assert.IsTrue(
                report.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0,
                "An unknown report format should fall back to HTML.");
            Assert.IsFalse(
                report.TrimStart().StartsWith("<svg", StringComparison.OrdinalIgnoreCase),
                "The fallback should not be SVG.");
        }

        /// <summary>Imported threats retain their source, scope and treatment across engine operations.</summary>
        /// <param name="formatId">The destination format.</param>
        [TestMethod]
        [DataRow("tmforge-json")]
        [DataRow("tm7")]
        public void ThreatDragonImportSurvivesEngineOperations(string formatId)
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "threat-dragon-v2.json"));
            TmForgeModelDto model = EngineService.ReadModel(bytes, null);
            Assert.AreEqual("threat-dragon", EngineService.Detect(bytes)?.Id);
            Assert.AreEqual("Model owner", model.Metadata?.Owner);
            Assert.IsNotNull(model.Diagrams);
            Assert.IsNotNull(model.Threats);
            Assert.HasCount(2, model.Diagrams);
            Assert.HasCount(3, model.Threats);
            ThreatStateDto imported = model.Threats!.Single(threat => threat.Id == "manual:threat-dragon.linkability");
            Assert.AreEqual("LINDDUN", imported.Source?["modelType"]);

            AnalysisResultDto result = EngineService.RunAnalysis(model, null);
            Assert.HasCount(3, result.Threats.Where(threat => threat.Manual));
            Assert.IsTrue(result.Threats.Any(threat => !threat.Manual));
            Assert.AreEqual("threat-dragon", result.Threats.Single(threat => threat.Id == imported.Id).Source?["format"]);

            AuthoringResultDto edited = AuthoringService.EditThreat(model, new EditThreatRequest
            {
                Id = imported.Id,
                Title = "Reviewed linkability",
            });
            Assert.IsTrue(edited.Success, edited.Error);
            Assert.IsNotNull(edited.Model);
            TmForgeModelDto restored = EngineService.ReadModel(EngineService.Convert(edited.Model!, formatId), formatId);
            ThreatStateDto threat = restored.Threats!.Single(threat => threat.Id == imported.Id);
            Assert.AreEqual("Reviewed linkability", threat.Title);
            Assert.AreEqual("Linkability", threat.Category);
            Assert.AreEqual("Accepted", threat.State);
            Assert.AreEqual("Use short-lived identifiers.", threat.Mitigation);
            Assert.AreEqual("linkability", threat.Source?["id"]);
            CollectionAssert.AreEqual(imported.ElementIds!.ToArray(), threat.ElementIds!.ToArray());
            Assert.AreEqual(model.Diagrams![1].Id, restored.Diagrams![1].Id);
            Assert.AreEqual("Model owner", restored.Metadata?.Owner);
            string report = Encoding.UTF8.GetString(EngineService.Report(restored, "html"));
            StringAssert.Contains(report, "Reviewed linkability");
            StringAssert.Contains(report, "Linkability");
        }

        /// <summary>Preflight distinguishes malformed, ambiguous and unsupported documents.</summary>
        /// <param name="content">The source document.</param>
        /// <param name="format">An optional format selection.</param>
        /// <param name="code">The expected diagnostic.</param>
        [TestMethod]
        [DataRow("not a model", null, "input.unknown-format")]
        [DataRow("{", null, "input.unreadable")]
        [DataRow("{\"elements\":[]}", null, "input.ambiguous-json")]
        [DataRow("{\"schema\":\"foreign\"}", null, "input.unsupported-format")]
        [DataRow("{}", "foreign", "input.unsupported-format")]
        [DataRow("null", "tmforge-json", "input.object-required")]
        [DataRow("<mxfile><diagram>compressed</diagram></mxfile>", "drawio", "input.unreadable")]
        [DataRow("{\"schema\":\"tmforge-manifest\",\"version\":99}", null, "manifest.invalid")]
        [DataRow("{\"schema\":\"tmforge-manifest\",\"flows\":[{\"from\":\"missing\",\"to\":\"other\"}]}", null, "manifest.invalid")]
        public void PreflightReportsUnusableInput(string content, string? format, string code)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(content);
            byte[] original = (byte[])bytes.Clone();

            PreflightResultDto result = DocumentPreflight.Inspect(bytes, format);

            Assert.IsFalse(result.Success);
            Assert.IsTrue(result.Diagnostics.Any(item => item.Code == code), string.Join("; ", result.Diagnostics.Select(item => item.Code + ": " + item.Message)));
            CollectionAssert.AreEqual(original, bytes);
        }

        /// <summary>Unknown targets, oversized files and invalid encoding return bounded diagnostics.</summary>
        [TestMethod]
        public void PreflightBoundsAndValidatesRequests()
        {
            Assert.Throws<ArgumentNullException>(() => DocumentPreflight.Inspect(null!));
            Assert.AreEqual("input.too-large", DocumentPreflight.Inspect(new byte[JsonDocumentPreflight.MaxBytes + 1]).Diagnostics.Single().Code);
            Assert.IsFalse(DocumentPreflight.Inspect(new byte[] { 0xff }, "tmforge-json").Success);
            byte[] model = EngineService.Convert(SingleProcessModel(), "tmforge-json");
            Assert.IsTrue(DocumentPreflight.Inspect(model).Success);
            Assert.IsTrue(DocumentPreflight.Inspect(model, "TMFORGE-JSON").Success);
            Assert.AreEqual("conversion.unsupported-target", DocumentPreflight.Inspect(model, targetFormat: "threat-dragon").Diagnostics.Last().Code);
            Assert.IsTrue(DocumentPreflight.Inspect(Encoding.UTF8.GetBytes("{\"name\":\"Legacy\"}"), "tmforge-manifest").Success);
            Assert.IsTrue(DocumentPreflight.Inspect(Encoding.UTF8.GetBytes("\uFEFF\n\t{\"schema\":\"tmforge-json\"}")).Success);
        }

        /// <summary>Conversion warnings name the actual register, property and metadata losses.</summary>
        /// <param name="target">The diagram format.</param>
        [TestMethod]
        [DataRow("drawio")]
        [DataRow("vsdx")]
        public void PreflightReportsDiagramConversionLosses(string target)
        {
            byte[] bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "threat-dragon-v2.json"));

            PreflightResultDto result = DocumentPreflight.Inspect(bytes, targetFormat: target);

            Assert.IsTrue(result.Success);
            Assert.IsTrue(result.Diagnostics.Any(item => item.Code == "import.structural-mapping"));
            Assert.IsTrue(result.Diagnostics.Any(item => item.Code == "conversion.threat-register"));
            Assert.IsTrue(result.Diagnostics.Any(item => item.Code == "conversion.metadata"));
            Assert.AreEqual(target == "drawio", result.Diagnostics.Any(item => item.Code == "conversion.properties"));
        }

        /// <summary>Canonical conversion warns about line boundaries, embedded rules and the generated register.</summary>
        [TestMethod]
        public void PreflightReportsTm7ProjectionLosses()
        {
            ThreatModel model = new ThreatModel { KnowledgeBase = new KnowledgeBaseData() };
            DrawingSurfaceModel page = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Context" };
            model.DrawingSurfaceList.Add(page);
            DiagramEditor editor = new DiagramEditor(model);
            Guid process = editor.AddElement(page, StencilKind.Process, 30, 30);
            LineBoundary boundary = new LineBoundary { Guid = Guid.NewGuid(), SourceX = 10, SourceY = 10, TargetX = 150, TargetY = 150 };
            page.Lines.Add(boundary.Guid, boundary);
            string key = process.ToString("N") + ":TM1000";
            model.AllThreatsDictionary.Add(key, new Threat { Id = 1, InteractionKey = key, TypeId = "TM1000", SourceGuid = process });
            using MemoryStream source = new MemoryStream();
            model.Save(source);

            PreflightResultDto result = DocumentPreflight.Inspect(source.ToArray(), targetFormat: "tmforge-json");

            Assert.IsTrue(result.Success);
            CollectionAssert.IsSubsetOf(new[] { "conversion.line-boundaries", "conversion.knowledge-base", "conversion.generated-register" }, result.Diagnostics.Select(item => item.Code).ToArray());
        }

        /// <summary>Recorded settings and out-of-range geometry are warned about without changing the input.</summary>
        [TestMethod]
        public void PreflightWarnsAboutSettingsAndCoordinateTranslation()
        {
            const string Json = "{\"schema\":\"tmforge-json\",\"analysis\":{\"disabledPacks\":[\"test\"]},\"elements\":[{\"id\":\"p\",\"x\":-50,\"y\":-20}]}";
            byte[] content = Encoding.UTF8.GetBytes(Json);

            PreflightResultDto result = DocumentPreflight.Inspect(content, targetFormat: "tm7");

            Assert.IsTrue(result.Success);
            Assert.IsTrue(result.Diagnostics.Any(item => item.Code == "conversion.analysis-settings"));
            Assert.IsTrue(result.Diagnostics.Any(item => item.Code == "conversion.coordinates"));
            Assert.AreEqual(Json, Encoding.UTF8.GetString(content));
            Assert.IsFalse(DocumentPreflight.Inspect(content).Diagnostics.Any(item => item.Code.StartsWith("conversion.", StringComparison.Ordinal)));
        }

        /// <summary>Loaded foreign graphs with duplicate ids or detached flows are structurally invalid.</summary>
        [TestMethod]
        public void PreflightRejectsMalformedLoadedGraphs()
        {
            ThreatModel model = new ThreatModel();
            DrawingSurfaceModel page = new DrawingSurfaceModel { Guid = Guid.Empty };
            StencilEllipse element = new StencilEllipse { Guid = Guid.Empty };
            Connector flow = new Connector { Guid = Guid.NewGuid(), SourceGuid = Guid.NewGuid(), TargetGuid = Guid.NewGuid() };
            page.Borders.Add(element.Guid, element);
            page.Lines.Add(flow.Guid, flow);
            model.DrawingSurfaceList.Add(page);
            List<DocumentDiagnostic> diagnostics = new List<DocumentDiagnostic>();

            DocumentPreflight.InspectModel(model, diagnostics);

            Assert.AreEqual(2, diagnostics.Count(item => item.Code == "model.duplicate-id"));
            Assert.IsTrue(diagnostics.Any(item => item.Code == "model.unresolved-endpoint"));
        }

        private static TmForgeModelDto SingleProcessModel()
        {
            return new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "web", Kind = "process", Name = "Web App", X = 100, Y = 100 },
                },
            };
        }

        private static TmForgeModelDto ConnectedModel()
        {
            return new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "web", Kind = "process", Name = "Web App", X = 100, Y = 100 },
                    new TmForgeElementDto { Id = "db", Kind = "datastore", Name = "Database", X = 300, Y = 100 },
                },
                Flows = new[]
                {
                    new TmForgeFlowDto
                    {
                        Id = "f1",
                        Source = "web",
                        Target = "db",
                        Name = "writes",
                        Properties = new Dictionary<string, string> { { "Protocol", "TLS" } },
                    },
                },
            };
        }

        private static TmForgeModelDto ThreatBearingModel(IReadOnlyList<ThreatStateDto>? threats = null)
        {
            const string externalId = "11111111-1111-4111-8111-111111111111";
            const string processId = "22222222-2222-4222-8222-222222222222";
            return new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = externalId, Kind = "external", Name = "Client", X = 50, Y = 50 },
                    new TmForgeElementDto { Id = processId, Kind = "process", Name = "Gateway", X = 220, Y = 50 },
                },
                Flows = new[]
                {
                    new TmForgeFlowDto
                    {
                        Id = "33333333-3333-4333-8333-333333333333",
                        Source = externalId,
                        Target = processId,
                        Name = "request",
                    },
                },
                Threats = threats,
            };
        }
    }
}
