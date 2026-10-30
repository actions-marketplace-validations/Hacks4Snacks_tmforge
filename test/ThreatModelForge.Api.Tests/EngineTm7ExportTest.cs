namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Xml.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Regression tests for the user-facing <c>.tm7</c> generation paths (<see cref="EngineService.ExportTm7(TmForgeModelDto)"/>
    /// and <see cref="EngineService.Convert(TmForgeModelDto, string)"/>), asserting the serialized document carries what the
    /// Microsoft Threat Modeling Tool (MTMT) needs to open it: the recognized version stamp, the
    /// document scaffolding, non-nil connector ports, and — for the lossless export path — an embedded
    /// knowledge base. These exercise the real engine pipeline the CLI, API, and WebAssembly hosts use.
    /// </summary>
    [TestClass]
    public class EngineTm7ExportTest
    {
        private const string XsiNamespace = "http://www.w3.org/2001/XMLSchema-instance";

        /// <summary>
        /// The lossless export embeds the knowledge base so MTMT resolves threat types and typed
        /// properties when it opens the file.
        /// </summary>
        [TestMethod]
        public void ExportTm7EmbedsKnowledgeBase()
        {
            AssertEmbedsKnowledgeBase(Parse(EngineService.ExportTm7(ConnectedModel())));
        }

        /// <summary>
        /// The generic <c>convert --to tm7</c> path embeds the knowledge base too, so every path that
        /// writes a <c>.tm7</c> (including the Studio "Download .tm7" and the API convert endpoint, which
        /// both route through this method) produces the same tool-openable file.
        /// </summary>
        [TestMethod]
        public void ConvertToTm7EmbedsKnowledgeBase()
        {
            AssertEmbedsKnowledgeBase(Parse(EngineService.Convert(ConnectedModel(), "tm7")));
        }

        /// <summary>Every engine save path emits native manual findings with their complete authored content.</summary>
        /// <param name="path">The export or save path to exercise.</param>
        [TestMethod]
        [DataRow("export")]
        [DataRow("convert")]
        [DataRow("native")]
        public void ManualThreatsCarryMtmtIdentityAndProperties(string path)
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            const string Key = "manual:native-contract";
            ThreatStateDto finding = new ThreatStateDto
            {
                Id = Key,
                Manual = true,
                Title = "Authored finding",
                Category = "Tampering",
                Priority = "High",
                Description = "Authored description",
                Mitigation = "Authored mitigation",
                State = "NeedsInvestigation",
                Justification = "Awaiting evidence",
                ElementIds = new[] { baseline.Elements![0].Id },
            };
            TmForgeModelDto edited = new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = baseline.Metadata,
                Diagrams = baseline.Diagrams,
                Elements = baseline.Elements,
                Flows = baseline.Flows,
                Threats = (baseline.Threats ?? Array.Empty<ThreatStateDto>()).Append(finding).ToArray(),
            };

            byte[] bytes = path switch
            {
                "export" => EngineService.ExportTm7(edited),
                "convert" => EngineService.Convert(edited, "tm7"),
                _ => EngineService.SaveTm7(original, edited),
            };
            ThreatModel model = ReadBack(bytes);
            Threat threat = model.AllThreatsDictionary[Key];

            Assert.AreEqual(ManualThreatId.ToNativeTypeId(Key), threat.TypeId);
            Assert.AreEqual(finding.Title, threat.Properties!["Title"]);
            Assert.AreEqual(finding.Description, threat.Properties["UserThreatDescription"]);
            Assert.AreEqual(finding.Category, threat.Properties["UserThreatCategory"]);
            Assert.AreEqual(finding.Priority, threat.Properties["Priority"]);
            Assert.AreEqual(finding.Mitigation, threat.Properties["Mitigation"]);
            Assert.AreEqual(finding.Justification, threat.Properties["StateInformation"]);
            Assert.AreEqual(Guid.Parse(finding.ElementIds[0]), threat.SourceGuid);
            Assert.IsTrue(model.KnowledgeBase!.ThreatMetaData!.PropertiesMetaData.Any(datum => datum.Name == "Mitigation" && !datum.HideFromUI));
            CollectionAssert.AreEqual(bytes, EngineService.SaveTm7(bytes, EngineService.ReadModel(bytes, "tm7")));
        }

        /// <summary>
        /// The exported document carries the scaffolding MTMT reads without a null guard: the recognized
        /// version, the metadata block, the profile's prompted knowledge-base versions, drawing-surface
        /// type identifiers, and non-nil connector ports.
        /// </summary>
        [TestMethod]
        public void ExportTm7CarriesToolScaffolding()
        {
            XDocument doc = Parse(EngineService.ExportTm7(ConnectedModel()));

            AssertOpenableScaffolding(doc);
        }

        /// <summary>
        /// The exported bytes read back through the engine without loss.
        /// </summary>
        [TestMethod]
        public void ExportTm7OutputReloads()
        {
            byte[] bytes = EngineService.ExportTm7(ConnectedModel());

            TmForgeModelDto restored = EngineService.ReadModel(bytes, "tm7");

            Assert.IsNotNull(restored.Elements);
            CollectionAssert.AreEquivalent(
                new[] { "Web App", "Database" },
                restored.Elements!.Select(e => e.Name).ToArray());
        }

        /// <summary>
        /// The generic <c>convert --to tm7</c> path also stamps the document scaffolding MTMT reads
        /// without a null guard, matching <see cref="EngineService.ExportTm7(TmForgeModelDto)"/>.
        /// </summary>
        [TestMethod]
        public void ConvertToTm7CarriesToolScaffolding()
        {
            XDocument doc = Parse(EngineService.Convert(ConnectedModel(), "tm7"));

            AssertOpenableScaffolding(doc);
        }

        /// <summary>
        /// MTMT rejects drawing coordinates below a small minimum and silently corrects the file on
        /// open. This reproduces a Studio export whose elements sit at or above the canvas origin
        /// (Top &lt;= 0) and asserts the exported document shifts every element and connector coordinate
        /// to or beyond that minimum, so the tool opens it without a correction warning.
        /// </summary>
        [TestMethod]
        public void ConvertToTm7NormalizesCoordinatesBelowTheToolMinimum()
        {
            TmForgeModelDto dto = new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "p", Kind = "process", Name = "Process", X = 400, Y = -16, Width = 100, Height = 60 },
                    new TmForgeElementDto { Id = "h", Kind = "external", Name = "Human Actor", X = 80, Y = 0, Width = 120, Height = 60 },
                },
                Flows = new[]
                {
                    new TmForgeFlowDto { Id = "f", Source = "h", Target = "p", Name = "uses" },
                },
            };

            XDocument doc = Parse(EngineService.Convert(dto, "tm7"));

            List<int> coordinates = CoordinateValues(doc).ToList();
            Assert.IsTrue(coordinates.Count > 0, "Expected the surface to carry coordinates.");
            Assert.IsTrue(
                coordinates.All(v => v >= 10),
                "Every border and connector coordinate must sit at or beyond the tool minimum (10); found " + coordinates.Min() + ".");
            Assert.AreEqual(
                10,
                coordinates.Min(),
                "The whole-surface shift should land the lowest coordinate exactly on the minimum.");
        }

        /// <summary>
        /// Triage recorded against a rule the current bundle no longer produces survives the export.
        /// </summary>
        /// <remarks>
        /// The export rebuilds the register from the current rules so every threat carries its full
        /// rule-owned text. An entry the rules no longer produce has nothing to rebuild from, and
        /// dropping it would delete a decision a reviewer recorded — the one thing the register is not
        /// allowed to lose when a rule falls silent.
        /// </remarks>
        [TestMethod]
        public void ExportPreservesTriageForARuleThatNoLongerFires()
        {
            const string OrphanKey = "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa:CORP-1";
            TmForgeModelDto source = ConnectedModel();
            TmForgeModelDto model = new TmForgeModelDto
            {
                Schema = source.Schema,
                Version = source.Version,
                Elements = source.Elements,
                Flows = source.Flows,
                Threats = new[]
                {
                    new ThreatStateDto
                    {
                        Id = OrphanKey,
                        State = "Mitigated",
                        Justification = "Handled by the platform team in Q2.",
                    },
                },
            };

            ThreatModel exported = ReadBack(EngineService.ExportTm7(model));

            string keys = string.Join(", ", exported.AllThreatsDictionary.Keys);
            Assert.IsTrue(
                exported.AllThreatsDictionary.ContainsKey(OrphanKey),
                "The decision must survive the rule going quiet: " + keys);
            Threat orphan = exported.AllThreatsDictionary[OrphanKey];
            Assert.AreEqual(ThreatState.Mitigated, orphan.State);
            Assert.AreEqual("Handled by the platform team in Q2.", orphan.StateInformation);
            Assert.AreEqual("CORP-1", orphan.TypeId, "It must stay identifiable as rule-derived, not manual.");
        }

        /// <summary>
        /// The same triage survives a full tmforge-json round trip through the engine, so reopening an
        /// exported model does not quietly shed the decision either.
        /// </summary>
        [TestMethod]
        public void RoundTripPreservesTriageForARuleThatNoLongerFires()
        {
            const string OrphanKey = "bbbbbbbbbbbb4bbb8bbbbbbbbbbbbbbb:CORP-2";
            TmForgeModelDto source = ConnectedModel();
            TmForgeModelDto model = new TmForgeModelDto
            {
                Schema = source.Schema,
                Version = source.Version,
                Elements = source.Elements,
                Flows = source.Flows,
                Threats = new[]
                {
                    new ThreatStateDto { Id = OrphanKey, State = "Accepted", Justification = "Accepted risk." },
                },
            };

            TmForgeModelDto reread = EngineService.ReadModel(EngineService.Convert(model, "tmforge-json"), "tmforge-json");

            ThreatStateDto? kept = reread.Threats?.FirstOrDefault(entry => entry.Id == OrphanKey);
            Assert.IsNotNull(kept, "The overlay entry must round-trip.");
            Assert.AreEqual("Accepted", kept!.State);
            Assert.AreEqual("Accepted risk.", kept.Justification);
        }

        /// <summary>
        /// The tool resolves six threat properties by name while loading a model and throws
        /// <c>"KnowledgeBase is missing a required Threat Property in ThreatMetaData"</c> when any of
        /// them is absent, refusing to open the file. Declaring no threat metadata at all is tolerated,
        /// but declaring a partial block is not, so an embedded knowledge base must carry the complete
        /// required set.
        /// </summary>
        [TestMethod]
        public void ExportDeclaresEveryThreatPropertyTheToolRequires()
        {
            AssertDeclaresRequiredThreatMetadata(Parse(EngineService.ExportTm7(ConnectedModel())));
            AssertDeclaresRequiredThreatMetadata(Parse(EngineService.Convert(ConnectedModel(), "tm7")));
        }

        private static void AssertOpenableScaffolding(XDocument doc)
        {
            XElement? version = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Version");
            Assert.IsNotNull(version, "Expected a <Version> element.");
            Assert.AreEqual("4.3", version!.Value);

            Assert.IsTrue(
                doc.Descendants().Any(e => e.Name.LocalName == "MetaInformation"),
                "Expected a <MetaInformation> block.");
            Assert.IsTrue(
                doc.Descendants().Any(e => e.Name.LocalName == "PromptedKb"),
                "Expected the profile's <PromptedKb> block.");

            XElement surface = doc.Descendants().First(e => e.Name.LocalName == "DrawingSurfaceModel");
            Assert.AreEqual(
                "DRAWINGSURFACE",
                surface.Elements().First(e => e.Name.LocalName == "GenericTypeId").Value);
            Assert.AreEqual(
                "DRAWINGSURFACE",
                surface.Elements().First(e => e.Name.LocalName == "TypeId").Value);

            var ports = doc.Descendants()
                .Where(e => e.Name.LocalName == "PortSource" || e.Name.LocalName == "PortTarget")
                .ToList();
            Assert.IsTrue(ports.Count >= 2, "Expected the connector to serialize both ports.");
            Assert.IsTrue(
                ports.All(p => p.Attribute(XName.Get("nil", XsiNamespace)) == null && p.Value == "None"),
                "Connector ports must serialize as \"None\", never nil.");
        }

        private static void AssertEmbedsKnowledgeBase(XDocument doc)
        {
            XElement? kb = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "KnowledgeBase");
            Assert.IsNotNull(kb, "The .tm7 must contain a <KnowledgeBase> element.");
            Assert.IsNull(
                kb!.Attribute(XName.Get("nil", XsiNamespace)),
                "The knowledge base must be embedded, not nil.");
            Assert.IsTrue(kb.HasElements, "The embedded knowledge base must carry content.");
            AssertDeclaresRequiredThreatMetadata(doc);
        }

        private static void AssertDeclaresRequiredThreatMetadata(XDocument doc)
        {
            string[] required =
            {
                "Title",
                "UserThreatCategory",
                "UserThreatShortDescription",
                "UserThreatDescription",
                "StateInformation",
                "InteractionString",
            };

            XElement? metadata = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "ThreatMetaData");
            Assert.IsNotNull(metadata, "Expected a <ThreatMetaData> block.");
            Assert.IsNull(
                metadata!.Attribute(XName.Get("nil", XsiNamespace)),
                "A knowledge base that embeds threat types must declare its threat metadata.");

            var declared = metadata.Descendants()
                .Where(e => e.Name.LocalName == "Name")
                .Select(e => e.Value)
                .ToList();

            foreach (string name in required)
            {
                string message = $"The tool requires the '{name}' threat property; without it the model " +
                    "cannot be opened.";
                Assert.IsTrue(declared.Contains(name), message);
            }
        }

        private static IEnumerable<int> CoordinateValues(XDocument doc)
        {
            string[] names = { "Left", "Top", "SourceX", "SourceY", "TargetX", "TargetY", "HandleX", "HandleY" };
            foreach (XElement surface in doc.Descendants().Where(e => e.Name.LocalName == "DrawingSurfaceModel"))
            {
                foreach (XElement coordinate in surface.Descendants().Where(e => names.Contains(e.Name.LocalName)))
                {
                    bool parsed = int.TryParse(coordinate.Value, out int value);
                    if (parsed)
                    {
                        yield return value;
                    }
                }
            }
        }

        private static XDocument Parse(byte[] bytes)
        {
            using MemoryStream stream = new MemoryStream(bytes);
            return XDocument.Load(stream);
        }

        private static ThreatModel ReadBack(byte[] tm7)
        {
            using MemoryStream stream = new MemoryStream(tm7);
            return ThreatModel.Load(stream);
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
                    new TmForgeFlowDto { Id = "f1", Source = "web", Target = "db", Name = "writes" },
                },
            };
        }
    }
}
