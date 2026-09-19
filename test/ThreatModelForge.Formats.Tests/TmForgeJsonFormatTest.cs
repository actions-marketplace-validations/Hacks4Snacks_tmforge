namespace ThreatModelForge.Formats.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Unit tests for <see cref="TmForgeJsonFormat"/>.
    /// </summary>
    [TestClass]
    public class TmForgeJsonFormatTest
    {
        private const string SampleJson =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[" +
            "{\"id\":\"p1\",\"kind\":\"process\",\"name\":\"Web App\",\"x\":100,\"y\":100}," +
            "{\"id\":\"ds1\",\"kind\":\"datastore\",\"name\":\"Database\",\"x\":420,\"y\":100}]," +
            "\"flows\":[{\"id\":\"f1\",\"source\":\"p1\",\"target\":\"ds1\",\"name\":\"query\"}]}";

        private const string MultiPageJson =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[],\"flows\":[]," +
            "\"diagrams\":[" +
            "{\"id\":\"d1\",\"name\":\"Context\",\"elements\":[" +
            "{\"id\":\"u1\",\"kind\":\"external\",\"name\":\"User\",\"x\":100,\"y\":100}," +
            "{\"id\":\"g1\",\"kind\":\"process\",\"name\":\"Gateway\",\"x\":400,\"y\":100}]," +
            "\"flows\":[{\"id\":\"f1\",\"source\":\"u1\",\"target\":\"g1\",\"name\":\"request\"}]}," +
            "{\"id\":\"d2\",\"name\":\"Payments\",\"elements\":[" +
            "{\"id\":\"ps1\",\"kind\":\"process\",\"name\":\"Payment Svc\",\"x\":100,\"y\":100}," +
            "{\"id\":\"l1\",\"kind\":\"datastore\",\"name\":\"Ledger\",\"x\":400,\"y\":100}]," +
            "\"flows\":[{\"id\":\"f2\",\"source\":\"ps1\",\"target\":\"l1\",\"name\":\"write\"}]}]}";

        /// <summary>
        /// Verifies the provider advertises the canonical identifier and read+write capabilities.
        /// </summary>
        [TestMethod]
        public void AdvertisesIdentityAndCapabilities()
        {
            TmForgeJsonFormat format = new TmForgeJsonFormat();

            Assert.AreEqual("tmforge-json", format.Id);
            Assert.IsTrue(format.Capabilities.CanRead);
            Assert.IsTrue(format.Capabilities.CanWrite);
        }

        /// <summary>A dangling flow is refused with its authored location instead of disappearing.</summary>
        [TestMethod]
        public void ReadRejectsUnresolvedFlowWithJsonPath()
        {
            string json = SampleJson.Replace("\"target\":\"ds1\"", "\"target\":\"missing\"");

            InvalidDataException error = Assert.Throws<InvalidDataException>(() => ReadJson(json));

            StringAssert.Contains(error.Message, "$.flows[0].target");
            StringAssert.Contains(error.Message, "missing");
            StringAssert.Contains(error.Message, "f1");
        }

        /// <summary>Preflight reports every local structural issue with stable codes and paths.</summary>
        [TestMethod]
        public void PreflightFindsUnknownFieldsDuplicateIdsAndKinds()
        {
            string json = SampleJson.Replace("\"id\":\"ds1\"", "\"id\":\"p1\"")
                .Replace("\"kind\":\"datastore\"", "\"kind\":\"widget\"")
                .Replace("\"name\":\"query\"", "\"name\":\"query\",\"props\":{\"Protocol\":\"TLS\"}");

            IReadOnlyList<DocumentDiagnostic> diagnostics = JsonModelPreflight.Inspect(json);

            Assert.IsTrue(diagnostics.Any(item => item.Code == "input.unknown-field" && item.Path == "$.flows[0].props"));
            Assert.IsTrue(diagnostics.Any(item => item.Code == "model.duplicate-id" && item.Path == "$.elements[1].id"));
            Assert.IsTrue(diagnostics.Any(item => item.Code == "model.unsupported-kind" && item.Path == "$.elements[1].kind"));
            Assert.IsTrue(diagnostics.Any(item => item.Code == "model.unresolved-endpoint" && item.Path == "$.flows[0].target"));
            Assert.Throws<InvalidDataException>(() => ReadJson(json));
        }

        /// <summary>Custom property bags and Studio view state remain part of the accepted contract.</summary>
        [TestMethod]
        public void PreflightAllowsCustomPropertiesAndViewFields()
        {
            string json = SampleJson.Replace(
                "\"name\":\"query\"",
                "\"name\":\"query\",\"sourceHandle\":\"r\",\"targetHandle\":\"l\",\"labelOffset\":{\"x\":12,\"y\":4},\"properties\":{\"OrganizationPolicy\":\"Unknown\"}");

            Assert.HasCount(0, JsonModelPreflight.Inspect(json));
            Assert.AreEqual(1, ReadJson(json).DrawingSurfaceList[0].Lines.Count);
        }

        /// <summary>Raw document defects cannot be hidden by serializer defaults or coercion.</summary>
        /// <param name="json">The invalid input.</param>
        /// <param name="code">The expected stable diagnostic.</param>
        [TestMethod]
        [DataRow("null", "input.object-required")]
        [DataRow("[]", "input.object-required")]
        [DataRow("{", "input.invalid-json")]
        [DataRow("{\"schema\":\"other\"}", "input.schema")]
        [DataRow("{\"version\":\"9.0\"}", "input.version")]
        [DataRow("{\"elements\":[null]}", "input.null-entry")]
        [DataRow("{\"elements\":[{}]}", "model.invalid-id")]
        [DataRow("{\"elements\":[{\"id\":\"00000000-0000-0000-0000-000000000000\"}]}", "model.invalid-id")]
        [DataRow("{\"elements\":[{\"id\":\"x\",\"ID\":\"y\"}]}", "input.duplicate-field")]
        [DataRow("{\"elements\":[{\"id\":\"x\",\"width\":30}]}", "model.incomplete-size")]
        [DataRow("{\"elements\":[{\"id\":\"x\",\"width\":-1,\"height\":30}]}", "model.invalid-size")]
        [DataRow("{\"elements\":[{\"id\":\"x\",\"x\":0.5}]}", "input.invalid-value")]
        [DataRow("{\"elements\":[{\"id\":\"x\",\"properties\":{\"Protocol\":true}}]}", "input.invalid-value")]
        [DataRow("{\"diagrams\":[{\"id\":\"page\"},{\"id\":\"page\"}]}", "model.duplicate-id")]
        [DataRow("{\"diagrams\":[{\"id\":\"a\",\"elements\":[{\"id\":\"x\"}],\"flows\":[{\"id\":\"f\",\"source\":\"x\",\"target\":\"y\"}]},{\"id\":\"b\",\"elements\":[{\"id\":\"y\"}]}]}", "model.unresolved-endpoint")]
        public void PreflightRejectsMalformedInput(string json, string code)
        {
            IReadOnlyList<DocumentDiagnostic> diagnostics = JsonModelPreflight.Inspect(json);

            Assert.IsTrue(diagnostics.Any(item => item.Code == code && item.Severity == "error"), string.Join("; ", diagnostics.Select(item => item.Code + ": " + item.Message)));
            Assert.Throws<InvalidDataException>(() => ReadJson(json));
        }

        /// <summary>Equivalent GUID spellings and alias-derived identities cannot collide silently.</summary>
        [TestMethod]
        public void PreflightDetectsInternalIdentityCollisions()
        {
            string guid = DeterministicGuid.FromElementId("alias").ToString("D");
            string json = "{\"elements\":[{\"id\":\"alias\"},{\"id\":\"" + guid + "\"}]}";

            Assert.IsTrue(JsonModelPreflight.Inspect(json).Any(item => item.Code == "model.duplicate-id"));
            string upper = Guid.NewGuid().ToString("D").ToUpperInvariant();
            json = "{\"elements\":[{\"id\":\"" + upper + "\"},{\"id\":\"" + upper.ToLowerInvariant() + "\"}]}";
            Assert.IsTrue(JsonModelPreflight.Inspect(json).Any(item => item.Code == "model.duplicate-id"));
        }

        /// <summary>Extension fields remain readable but preflight explicitly names their loss risk.</summary>
        [TestMethod]
        public void PreflightWarnsForCanonicalExtensionsWithoutRejectingThem()
        {
            string json = SampleJson.Replace("\"version\":\"0.1\"", "\"version\":\"0.1\",\"extension\":{\"owner\":\"team\"}");
            IReadOnlyList<DocumentDiagnostic> diagnostics = JsonModelPreflight.Inspect(json);

            DocumentDiagnostic warning = diagnostics.Single();
            Assert.AreEqual("input.unknown-field", warning.Code);
            Assert.AreEqual("warning", warning.Severity);
            Assert.AreEqual("$.extension", warning.Path);
            Assert.HasCount(1, ReadJson(json).DrawingSurfaceList[0].Lines);
            Assert.HasCount(0, JsonModelPreflight.Inspect("{\"analysis\":{\"expectedPacks\":[{\"id\":\"pack\",\"fingerprint\":\"sha256:pin\"}]}}"));
        }

        /// <summary>Preflight limits bound malformed input and the diagnostic response.</summary>
        [TestMethod]
        public void PreflightBoundsInputAndDiagnosticSize()
        {
            Assert.AreEqual("input.too-large", JsonModelPreflight.Inspect(new string(' ', JsonDocumentPreflight.MaxBytes + 1)).Single().Code);
            string pages = "{\"diagrams\":[" + string.Join(",", Enumerable.Range(0, 1025).Select(index => "{\"id\":\"p" + index + "\"}")) + "]}";
            Assert.IsTrue(JsonModelPreflight.Inspect(pages).Any(item => item.Code == "model.too-many-pages"));
            string many = "{" + string.Join(",", Enumerable.Range(0, 200).Select(index => "\"unknown" + index + "\":0")) + "}";
            IReadOnlyList<DocumentDiagnostic> diagnostics = JsonModelPreflight.Inspect(many);
            Assert.HasCount(JsonDocumentPreflight.MaxDiagnostics, diagnostics);
            Assert.AreEqual("input.diagnostic-limit", diagnostics.Last().Code);
            Assert.AreEqual("error", diagnostics.Last().Severity);

            List<DocumentDiagnostic> bounded = new List<DocumentDiagnostic>();
            JsonDocumentPreflight.Add(bounded, "code", new string('p', 2048), new string('m', 4096));
            Assert.AreEqual(1024, bounded[0].Path.Length);
            Assert.AreEqual(2048, bounded[0].Message.Length);
        }

        /// <summary>Strict UTF-8 and byte limits apply to actual stream reads without closing the source.</summary>
        [TestMethod]
        public void PreflightReadsBoundedUtf8Streams()
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes("\uFEFF" + SampleJson));
            Assert.AreEqual(SampleJson, JsonDocumentPreflight.ReadText(stream));
            Assert.IsTrue(stream.CanRead);
            using MemoryStream oversized = new MemoryStream(new byte[JsonDocumentPreflight.MaxBytes + 1]);
            Assert.Throws<InvalidDataException>(() => JsonDocumentPreflight.ReadText(oversized));
            using MemoryStream malformed = new MemoryStream(new byte[] { 0xff });
            Assert.Throws<DecoderFallbackException>(() => JsonDocumentPreflight.ReadText(malformed));
            Assert.Throws<ArgumentNullException>(() => JsonDocumentPreflight.ReadText(null!));
            Assert.Throws<ArgumentNullException>(() => JsonDocumentPreflight.Inspect<TmForgeJsonModel>(null!));
        }

        /// <summary>
        /// A <c>Critical</c> priority survives a tmforge-json round trip unchanged. Priority is
        /// author-owned, so no write path may quietly narrow it to the tool's historical
        /// High/Medium/Low vocabulary.
        /// </summary>
        [TestMethod]
        public void CriticalPrioritySurvivesRoundTrip()
        {
            const string Id = "manual:crown-jewel-exposure";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[Id] = new Threat
            {
                Id = 1,
                State = ThreatState.NeedsInvestigation,
                InteractionKey = Id,
                SourceGuid = System.Guid.NewGuid(),
                Title = "Signing key is readable by the web tier",
                UserThreatCategory = "InformationDisclosure",
                Priority = "Critical",
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(source, output);
                bytes = output.ToArray();
            }

            using (JsonDocument parsed = JsonDocument.Parse(bytes))
            {
                Assert.AreEqual(
                    "Critical",
                    parsed.RootElement.GetProperty("threats")[0].GetProperty("priority").GetString());
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new TmForgeJsonFormat().Read(input);
            }

            Assert.AreEqual("Critical", reread.AllThreatsDictionary[Id].Priority);
        }

        /// <summary>
        /// Verifies that a GUID element id in the source document is preserved as the element's
        /// identity, so the structural diff and three-way merge can match elements across files.
        /// </summary>
        [TestMethod]
        public void ReadPreservesGuidElementIds()
        {
            System.Guid id = System.Guid.NewGuid();
            string json = "{\"schema\":\"tmforge-json\",\"version\":\"0.1\",\"elements\":[" +
                "{\"id\":\"" + id + "\",\"kind\":\"process\",\"name\":\"P\",\"x\":0,\"y\":0}]}";

            ThreatModel model;
            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                model = new TmForgeJsonFormat().Read(stream);
            }

            Assert.IsTrue(model.DrawingSurfaceList[0].Borders.ContainsKey(id));
        }

        /// <summary>
        /// Verifies that an author-chosen id that is not a GUID still yields the same internal identity
        /// on every read.
        /// </summary>
        /// <remarks>
        /// These used to get a fresh guid per load, which meant anything keyed on the guid churned
        /// between runs: a threat register entry no longer matched the triage recorded against it, and
        /// the guid embedded in a finding message changed while the model had not. Two independent
        /// reads must agree, or a stored analysis cannot be compared to the next one.
        /// </remarks>
        [TestMethod]
        public void ReadDerivesStableIdentityForAuthoredIds()
        {
            string json = "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
                "\"diagrams\":[{\"id\":\"page-one\",\"name\":\"Page one\",\"elements\":[" +
                "{\"id\":\"web-app\",\"kind\":\"process\",\"name\":\"P\",\"x\":0,\"y\":0}]}]}";

            ThreatModel first = ReadJson(json);
            ThreatModel second = ReadJson(json);

            System.Guid element = first.DrawingSurfaceList[0].Borders.Keys.Single();
            Assert.AreEqual(element, second.DrawingSurfaceList[0].Borders.Keys.Single());
            Assert.AreEqual(first.DrawingSurfaceList[0].Guid, second.DrawingSurfaceList[0].Guid);

            // An element and a page that share an id must not collide onto one identity.
            Assert.AreNotEqual(
                DeterministicGuid.FromElementId("page-one"),
                DeterministicGuid.FromPageId("page-one"));
            Assert.AreEqual(DeterministicGuid.FromElementId("web-app"), element);
        }

        /// <summary>
        /// Verifies that the authored width and height of a component (not only a trust boundary) are
        /// applied on read, so an element keeps the size the canvas gave it instead of shrinking to the
        /// stencil's default size on the round trip.
        /// </summary>
        [TestMethod]
        public void ReadAppliesAuthoredComponentSize()
        {
            string json = "{\"schema\":\"tmforge-json\",\"version\":\"0.1\",\"elements\":[" +
                "{\"id\":\"p1\",\"kind\":\"process\",\"name\":\"Web App\",\"x\":100,\"y\":100,\"width\":140,\"height\":132}]}";

            ThreatModel model;
            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                model = new TmForgeJsonFormat().Read(stream);
            }

            StencilEllipse element = (StencilEllipse)model.DrawingSurfaceList[0].Borders.Values.Single();
            Assert.AreEqual(140, element.Width);
            Assert.AreEqual(132, element.Height);
        }

        /// <summary>
        /// Verifies content sniffing matches a tmforge-json document and rejects a <c>.tm7</c>
        /// document, leaving the stream position unchanged.
        /// </summary>
        [TestMethod]
        public void CanReadSniffsSchemaToken()
        {
            TmForgeJsonFormat format = new TmForgeJsonFormat();

            using (MemoryStream json = new MemoryStream(Encoding.UTF8.GetBytes(SampleJson)))
            using (MemoryStream xml = new MemoryStream(
                Encoding.UTF8.GetBytes("<ThreatModel xmlns=\"http://schemas.datacontract.org/2004/07/ThreatModeling.Model\">")))
            {
                Assert.IsTrue(format.CanRead(json));
                Assert.AreEqual(0, json.Position);
                Assert.IsFalse(format.CanRead(xml));
            }
        }

        /// <summary>
        /// Verifies a document round-trips element and flow structure through the engine model:
        /// read into a <see cref="ThreatModel"/>, then write back to tmforge-json.
        /// </summary>
        [TestMethod]
        public void RoundTripsElementsAndFlows()
        {
            TmForgeJsonFormat format = new TmForgeJsonFormat();

            ThreatModel model;
            using (MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(SampleJson)))
            {
                model = format.Read(input);
            }

            string json;
            using (MemoryStream output = new MemoryStream())
            {
                format.Write(model, output);
                json = Encoding.UTF8.GetString(output.ToArray());
            }

            using (JsonDocument parsed = JsonDocument.Parse(json))
            {
                JsonElement root = parsed.RootElement;
                Assert.AreEqual("tmforge-json", root.GetProperty("schema").GetString());
                Assert.AreEqual(2, root.GetProperty("elements").GetArrayLength());
                Assert.AreEqual(1, root.GetProperty("flows").GetArrayLength());
            }

            StringAssert.Contains(json, "Web App");
            StringAssert.Contains(json, "Database");
            StringAssert.Contains(json, "query");
        }

        /// <summary>
        /// A multi-page document maps to one drawing surface per page on read, and writes back one
        /// <c>diagrams</c> entry per surface (with its name) instead of flattening every page into a
        /// single element/flow list. The top-level arrays mirror the first page for older readers.
        /// </summary>
        [TestMethod]
        public void MultiPageRoundTripsPerSurface()
        {
            TmForgeJsonFormat format = new TmForgeJsonFormat();

            ThreatModel model;
            using (MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(MultiPageJson)))
            {
                model = format.Read(input);
            }

            Assert.AreEqual(2, model.DrawingSurfaceList.Count);
            Assert.AreEqual("Context", model.DrawingSurfaceList[0].Header);
            Assert.AreEqual("Payments", model.DrawingSurfaceList[1].Header);
            Assert.AreEqual(2, model.DrawingSurfaceList[0].Borders.Count);
            Assert.AreEqual(1, model.DrawingSurfaceList[0].Lines.Count);
            Assert.AreEqual(2, model.DrawingSurfaceList[1].Borders.Count);
            Assert.AreEqual(1, model.DrawingSurfaceList[1].Lines.Count);

            string json;
            using (MemoryStream output = new MemoryStream())
            {
                format.Write(model, output);
                json = Encoding.UTF8.GetString(output.ToArray());
            }

            using (JsonDocument parsed = JsonDocument.Parse(json))
            {
                JsonElement root = parsed.RootElement;
                JsonElement diagrams = root.GetProperty("diagrams");
                Assert.AreEqual(2, diagrams.GetArrayLength());
                Assert.AreEqual("Context", diagrams[0].GetProperty("name").GetString());
                Assert.AreEqual("Payments", diagrams[1].GetProperty("name").GetString());
                Assert.AreEqual(2, diagrams[0].GetProperty("elements").GetArrayLength());
                Assert.AreEqual(1, diagrams[0].GetProperty("flows").GetArrayLength());
                Assert.AreEqual(2, diagrams[1].GetProperty("elements").GetArrayLength());
                Assert.AreEqual(1, diagrams[1].GetProperty("flows").GetArrayLength());

                // Top-level arrays mirror the first page for single-page readers.
                Assert.AreEqual(2, root.GetProperty("elements").GetArrayLength());
                Assert.AreEqual(1, root.GetProperty("flows").GetArrayLength());
            }

            StringAssert.Contains(json, "Gateway");
            StringAssert.Contains(json, "Payment Svc");
            StringAssert.Contains(json, "Ledger");
        }

        /// <summary>
        /// A single-page model writes no <c>diagrams</c> array, keeping the wire shape backward
        /// compatible with existing single-page readers and files.
        /// </summary>
        [TestMethod]
        public void SinglePageOmitsDiagramsArray()
        {
            TmForgeJsonFormat format = new TmForgeJsonFormat();

            ThreatModel model;
            using (MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(SampleJson)))
            {
                model = format.Read(input);
            }

            string json;
            using (MemoryStream output = new MemoryStream())
            {
                format.Write(model, output);
                json = Encoding.UTF8.GetString(output.ToArray());
            }

            using (JsonDocument parsed = JsonDocument.Parse(json))
            {
                Assert.IsFalse(parsed.RootElement.TryGetProperty("diagrams", out _));
            }
        }

        /// <summary>
        /// The per-model analysis selection round-trips through the analysis-aware Write overload
        /// and <see cref="TmForgeJsonFormat.TryReadAnalysis"/>.
        /// </summary>
        [TestMethod]
        public void AnalysisRoundTrips()
        {
            ThreatModel model = new ThreatModel();
            TmForgeJsonAnalysis analysis = new TmForgeJsonAnalysis
            {
                DisabledPacks = new[] { "stride-completeness" },
                DisabledRuleIds = new[] { "TM1002" },
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(model, output, analysis);
                bytes = output.ToArray();
            }

            using (MemoryStream input = new MemoryStream(bytes))
            {
                bool hasSelection = TmForgeJsonFormat.TryReadAnalysis(
                    input,
                    out IReadOnlyList<string> packs,
                    out IReadOnlyList<string> ruleIds);

                Assert.IsTrue(hasSelection);
                Assert.AreEqual(1, packs.Count);
                Assert.AreEqual("stride-completeness", packs[0]);
                Assert.AreEqual(1, ruleIds.Count);
                Assert.AreEqual("TM1002", ruleIds[0]);
            }
        }

        /// <summary>
        /// A document written without an analysis selection reports none on read.
        /// </summary>
        [TestMethod]
        public void AnalysisAbsentWhenNotWritten()
        {
            ThreatModel model = new ThreatModel();

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(model, output);
                bytes = output.ToArray();
            }

            using (MemoryStream input = new MemoryStream(bytes))
            {
                bool hasSelection = TmForgeJsonFormat.TryReadAnalysis(
                    input,
                    out IReadOnlyList<string> packs,
                    out IReadOnlyList<string> ruleIds);

                Assert.IsFalse(hasSelection);
                Assert.AreEqual(0, packs.Count);
                Assert.AreEqual(0, ruleIds.Count);
            }
        }

        /// <summary>
        /// A tmforge-json document carrying a risk-acceptance triage overlay seeds the model's threat
        /// register on read, so acceptance recorded in Studio survives an export to <c>.tm7</c> or a
        /// CLI round-trip (the register natively round-trips in <c>.tm7</c>). The seeded threat carries
        /// the accepted state, the justification, and the target/rule parsed from its register id.
        /// </summary>
        [TestMethod]
        public void AcceptedTriageSeedsRegisterOnRead()
        {
            System.Guid target = System.Guid.NewGuid();
            string threatId = target.ToString("N") + ":TM1013";
            string json = "{\"schema\":\"tmforge-json\",\"version\":\"0.1\",\"elements\":[]," +
                "\"flows\":[],\"threats\":[{\"id\":\"" + threatId +
                "\",\"state\":\"Accepted\",\"justification\":\"Compensating control in place.\"}]}";

            ThreatModel model;
            using (MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                model = new TmForgeJsonFormat().Read(input);
            }

            Assert.IsTrue(model.AllThreatsDictionary.TryGetValue(threatId, out Threat? threat));
            Assert.AreEqual(ThreatState.NotApplicable, threat!.State);
            Assert.AreEqual("Compensating control in place.", threat.StateInformation);
            Assert.AreEqual("TM1013", threat.TypeId);
            Assert.AreEqual(target, threat.SourceGuid);
            Assert.AreEqual(threatId, threat.InteractionKey);
        }

        /// <summary>
        /// An accepted threat in the model's register writes back as an <c>Accepted</c> triage entry
        /// on the document, and reading that document restores the acceptance — the symmetric
        /// round-trip that carries Studio acceptance across the wire and the CLI.
        /// </summary>
        [TestMethod]
        public void AcceptedTriageRoundTrips()
        {
            System.Guid target = System.Guid.NewGuid();
            string threatId = target.ToString("N") + ":TM1023";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[threatId] = new Threat
            {
                Id = 1,
                TypeId = "TM1023",
                State = ThreatState.NotApplicable,
                InteractionKey = threatId,
                StateInformation = "Accepted by security review.",
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(source, output);
                bytes = output.ToArray();
            }

            using (JsonDocument parsed = JsonDocument.Parse(bytes))
            {
                JsonElement threats = parsed.RootElement.GetProperty("threats");
                Assert.AreEqual(1, threats.GetArrayLength());
                Assert.AreEqual(threatId, threats[0].GetProperty("id").GetString());
                Assert.AreEqual("Accepted", threats[0].GetProperty("state").GetString());
                Assert.AreEqual("Accepted by security review.", threats[0].GetProperty("justification").GetString());
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new TmForgeJsonFormat().Read(input);
            }

            Assert.IsTrue(reread.AllThreatsDictionary.TryGetValue(threatId, out Threat? threat));
            Assert.AreEqual(ThreatState.NotApplicable, threat!.State);
            Assert.AreEqual("Accepted by security review.", threat.StateInformation);
        }

        /// <summary>
        /// A model with no accepted threats writes no <c>threats</c> overlay, keeping the wire shape
        /// backward compatible for the common (untriaged) case.
        /// </summary>
        [TestMethod]
        public void TriageAbsentWhenNothingAccepted()
        {
            TmForgeJsonFormat format = new TmForgeJsonFormat();

            ThreatModel model;
            using (MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(SampleJson)))
            {
                model = format.Read(input);
            }

            string json;
            using (MemoryStream output = new MemoryStream())
            {
                format.Write(model, output);
                json = Encoding.UTF8.GetString(output.ToArray());
            }

            using (JsonDocument parsed = JsonDocument.Parse(json))
            {
                Assert.IsFalse(parsed.RootElement.TryGetProperty("threats", out _));
            }
        }

        /// <summary>
        /// A manually-authored threat (keyed <c>manual:{guid}</c>) round-trips through the overlay in
        /// full: its category, title, description, mitigation, priority, scope, and state survive a
        /// write and re-read, so a threat the author created by hand is not lost on save.
        /// </summary>
        [TestMethod]
        public void ManualThreatRoundTrips()
        {
            System.Guid node = System.Guid.NewGuid();
            string id = "manual:" + System.Guid.NewGuid().ToString("N");
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[id] = new Threat
            {
                Id = 1,
                State = ThreatState.NeedsInvestigation,
                InteractionKey = id,
                SourceGuid = node,
                Title = "Stolen session token",
                UserThreatCategory = "Spoofing",
                UserThreatDescription = "An attacker replays a captured bearer token.",
                Priority = "High",
                StateInformation = "Under review.",
                Properties = new Dictionary<string, string> { ["Mitigation"] = "Bind tokens to the client." },
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(source, output);
                bytes = output.ToArray();
            }

            using (JsonDocument parsed = JsonDocument.Parse(bytes))
            {
                JsonElement entry = parsed.RootElement.GetProperty("threats")[0];
                Assert.AreEqual(id, entry.GetProperty("id").GetString());
                Assert.IsTrue(entry.GetProperty("manual").GetBoolean());
                Assert.AreEqual("NeedsInvestigation", entry.GetProperty("state").GetString());
                Assert.AreEqual("Spoofing", entry.GetProperty("category").GetString());
                Assert.AreEqual("Stolen session token", entry.GetProperty("title").GetString());
                Assert.AreEqual("Bind tokens to the client.", entry.GetProperty("mitigation").GetString());
                Assert.AreEqual(node.ToString(), entry.GetProperty("elementIds")[0].GetString());
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new TmForgeJsonFormat().Read(input);
            }

            Assert.IsTrue(reread.AllThreatsDictionary.TryGetValue(id, out Threat? threat));
            Assert.AreEqual(ThreatState.NeedsInvestigation, threat!.State);
            Assert.AreEqual("Stolen session token", threat.Title);
            Assert.AreEqual("Spoofing", threat.UserThreatCategory);
            Assert.AreEqual("An attacker replays a captured bearer token.", threat.UserThreatDescription);
            Assert.AreEqual("High", threat.Priority);
            Assert.AreEqual("Under review.", threat.StateInformation);
            Assert.AreEqual(node, threat.SourceGuid);
            Assert.IsNotNull(threat.Properties);
            Assert.AreEqual("Bind tokens to the client.", threat.Properties!["Mitigation"]);
        }

        /// <summary>
        /// An author-chosen manual id survives a tmforge-json round trip byte for byte. This is the
        /// point of letting authors name their threats: the id they wrote down and referenced from a
        /// ticket must still address the same threat after the model is saved and reopened.
        /// </summary>
        [TestMethod]
        public void AuthorSuppliedManualIdSurvivesTmForgeJsonRoundTrip()
        {
            const string Id = "manual:replay-of-captured-token";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[Id] = new Threat
            {
                Id = 1,
                State = ThreatState.NeedsInvestigation,
                InteractionKey = Id,
                SourceGuid = System.Guid.NewGuid(),
                Title = "Stolen session token",
                UserThreatCategory = "Spoofing",
                Priority = "High",
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(source, output);
                bytes = output.ToArray();
            }

            using (JsonDocument parsed = JsonDocument.Parse(bytes))
            {
                Assert.AreEqual(Id, parsed.RootElement.GetProperty("threats")[0].GetProperty("id").GetString());
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new TmForgeJsonFormat().Read(input);
            }

            Assert.IsTrue(reread.AllThreatsDictionary.ContainsKey(Id));
            Assert.AreEqual(Id, reread.AllThreatsDictionary[Id].InteractionKey);
            Assert.IsTrue(ManualThreatId.IsManual(Id));
        }

        /// <summary>
        /// The same author-chosen id survives a <c>.tm7</c> round trip, so exporting to MTMT and back
        /// does not silently re-key the author's threat.
        /// </summary>
        [TestMethod]
        public void AuthorSuppliedManualIdSurvivesTm7RoundTrip()
        {
            const string Id = "manual:replay-of-captured-token";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[Id] = new Threat
            {
                Id = 1,
                State = ThreatState.NeedsInvestigation,
                InteractionKey = Id,
                SourceGuid = System.Guid.NewGuid(),
                Title = "Stolen session token",
                UserThreatCategory = "Spoofing",
                Priority = "High",
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new Tm7Format().Write(source, output);
                bytes = output.ToArray();
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new Tm7Format().Read(input);
            }

            string keys = string.Join(", ", reread.AllThreatsDictionary.Keys);
            Assert.IsTrue(
                reread.AllThreatsDictionary.ContainsKey(Id),
                "The author's manual id must survive the .tm7 round trip: " + keys);
            Assert.AreEqual("Stolen session token", reread.AllThreatsDictionary[Id].Title);
        }

        /// <summary>A priority-only edit on a generated threat survives the sparse author overlay.</summary>
        [TestMethod]
        public void RuleThreatPriorityOnlyEditRoundTrips()
        {
            System.Guid target = System.Guid.NewGuid();
            string threatId = target.ToString("N") + ":TM1023";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[threatId] = new Threat
            {
                Id = 1,
                State = ThreatState.AutoGenerated,
                InteractionKey = threatId,
                SourceGuid = target,
                Priority = "Low",
                Properties = new Dictionary<string, string> { ["PriorityOverride"] = "true" },
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(source, output);
                bytes = output.ToArray();
            }

            using (JsonDocument parsed = JsonDocument.Parse(bytes))
            {
                JsonElement entry = parsed.RootElement.GetProperty("threats")[0];
                Assert.AreEqual("Low", entry.GetProperty("priority").GetString());
                Assert.IsFalse(entry.TryGetProperty("manual", out _));
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new TmForgeJsonFormat().Read(input);
            }

            Threat threat = reread.AllThreatsDictionary[threatId];
            Assert.AreEqual("Low", threat.Priority);
            Assert.AreEqual("true", threat.Properties!["PriorityOverride"]);
        }

        /// <summary>An MTMT priority edit is detected by its difference from the generated default.</summary>
        [TestMethod]
        public void MarkerlessPriorityDifferentFromGeneratedDefaultRoundTrips()
        {
            System.Guid target = System.Guid.NewGuid();
            string threatId = target.ToString("N") + ":medical/PRIV-1";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[threatId] = new Threat
            {
                Id = 1,
                State = ThreatState.AutoGenerated,
                InteractionKey = threatId,
                SourceGuid = target,
                Priority = "Low",
                Properties = new Dictionary<string, string> { ["GeneratedDefaultPriority"] = "High" },
            };
            using MemoryStream output = new MemoryStream();

            new TmForgeJsonFormat().Write(source, output);
            output.Position = 0;
            ThreatModel reread = new TmForgeJsonFormat().Read(output);

            Threat threat = reread.AllThreatsDictionary[threatId];
            Assert.AreEqual("Low", threat.Priority);
            Assert.AreEqual("true", threat.Properties!["PriorityOverride"]);
        }

        /// <summary>A markerless historical priority on a triaged rule threat survives the sparse overlay.</summary>
        [TestMethod]
        public void MarkerlessTriagedPriorityRoundTrips()
        {
            System.Guid target = System.Guid.NewGuid();
            string threatId = target.ToString("N") + ":TM1023";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[threatId] = new Threat
            {
                Id = 1,
                State = ThreatState.NotApplicable,
                InteractionKey = threatId,
                SourceGuid = target,
                Priority = "Low",
                StateInformation = "Historical acceptance.",
            };
            using MemoryStream output = new MemoryStream();

            new TmForgeJsonFormat().Write(source, output);
            output.Position = 0;
            ThreatModel reread = new TmForgeJsonFormat().Read(output);

            Threat threat = reread.AllThreatsDictionary[threatId];
            Assert.AreEqual(ThreatState.NotApplicable, threat.State);
            Assert.AreEqual("Low", threat.Priority);
            Assert.AreEqual("true", threat.Properties!["PriorityOverride"]);
        }

        /// <summary>
        /// An edited rule threat — one whose state moved to <c>Mitigated</c> with a description — round
        /// trips its author-owned fields on the overlay without storing the regenerable rule text, so
        /// the edit survives a save while the register stays sparse (no <c>manual</c> flag emitted).
        /// </summary>
        [TestMethod]
        public void EditedRuleThreatRoundTrips()
        {
            System.Guid target = System.Guid.NewGuid();
            string threatId = target.ToString("N") + ":TM1013";
            ThreatModel source = new ThreatModel();
            source.AllThreatsDictionary[threatId] = new Threat
            {
                Id = 1,
                TypeId = "TM1013",
                State = ThreatState.Mitigated,
                InteractionKey = threatId,
                SourceGuid = target,
                UserThreatDescription = "Handled by the WAF rule set.",
            };

            byte[] bytes;
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(source, output);
                bytes = output.ToArray();
            }

            using (JsonDocument parsed = JsonDocument.Parse(bytes))
            {
                JsonElement entry = parsed.RootElement.GetProperty("threats")[0];
                Assert.AreEqual("Mitigated", entry.GetProperty("state").GetString());
                Assert.AreEqual("Handled by the WAF rule set.", entry.GetProperty("description").GetString());
                Assert.IsFalse(entry.TryGetProperty("manual", out _));
            }

            ThreatModel reread;
            using (MemoryStream input = new MemoryStream(bytes))
            {
                reread = new TmForgeJsonFormat().Read(input);
            }

            Assert.IsTrue(reread.AllThreatsDictionary.TryGetValue(threatId, out Threat? threat));
            Assert.AreEqual(ThreatState.Mitigated, threat!.State);
            Assert.AreEqual("Handled by the WAF rule set.", threat.UserThreatDescription);
            Assert.AreEqual("TM1013", threat.TypeId);
        }

        private static ThreatModel ReadJson(string json)
        {
            using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
            {
                return new TmForgeJsonFormat().Read(stream);
            }
        }
    }
}
