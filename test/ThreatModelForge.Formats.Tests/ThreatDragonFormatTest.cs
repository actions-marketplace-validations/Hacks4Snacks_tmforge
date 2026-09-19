namespace ThreatModelForge.Formats.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Tests the read-only Threat Dragon v2 provider.</summary>
    [TestClass]
    public class ThreatDragonFormatTest
    {
        private const string EmptyV2 = @"{
  ""version"": ""2.6.2"",
  ""summary"": { ""title"": ""Imported model"" },
  ""detail"": { ""diagrams"": [] }
}";

        /// <summary>The registry exposes import without advertising native export.</summary>
        [TestMethod]
        public void RegistersReadOnlyProvider()
        {
            IThreatModelFormat? format = ThreatModelFormatRegistry.CreateDefault().FindById("threat-dragon");

            Assert.IsNotNull(format);
            Assert.IsTrue(format.Capabilities.CanRead);
            Assert.IsFalse(format.Capabilities.CanWrite);
            Assert.IsFalse(format.Capabilities.RoundTrips);
        }

        /// <summary>Content detection accepts v2 documents without consuming the caller's stream.</summary>
        [TestMethod]
        public void DetectsV2WithoutConsumingStream()
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(EmptyV2));

            IThreatModelFormat? format = ThreatModelFormatRegistry.CreateDefault().Sniff(stream);

            Assert.IsNotNull(format);
            Assert.AreEqual("threat-dragon", format.Id);
            Assert.AreEqual(0L, stream.Position);
            Assert.IsTrue(stream.CanRead);
        }

        /// <summary>The reader retains pages, geometry, endpoints and manual threat treatment.</summary>
        [TestMethod]
        public void ImportsStructureAndAuthoredThreats()
        {
            ThreatModel model = Read(Fixture().ToJsonString());

            Assert.AreEqual("Threat Dragon import fixture", model.MetaInformation?.ThreatModelName);
            Assert.AreEqual("Model owner", model.MetaInformation?.Owner);
            Assert.HasCount(2, model.DrawingSurfaceList);
            Assert.HasCount(4, model.DrawingSurfaceList[0].Borders);
            Assert.HasCount(2, model.DrawingSurfaceList[0].Lines);
            Assert.HasCount(1, model.DrawingSurfaceList[1].Borders);
            Assert.HasCount(3, model.AllThreatsDictionary);
            DrawingElement store = model.DrawingSurfaceList[0].Borders.Values.OfType<DrawingElement>()
                .Single(element => DiagramElementHelper.GetName(element) == "Credentials");
            Assert.AreEqual(500, store.Left);
            Assert.AreEqual(160, store.Width);
            Assert.AreEqual("No", DiagramElementHelper.GetCustomProperties(store)["Encrypted"]);
            Threat flowThreat = model.AllThreatsDictionary["manual:threat-dragon.request-tampering"];
            Assert.AreEqual(ThreatState.Mitigated, flowThreat.State);
            Assert.IsTrue(model.DrawingSurfaceList[0].Lines.ContainsKey(flowThreat.FlowGuid));
            Assert.AreEqual("Require TLS.", flowThreat.Properties?["Mitigation"]);
            Threat privacyThreat = model.AllThreatsDictionary["manual:threat-dragon.linkability"];
            Assert.AreEqual("Linkability", privacyThreat.UserThreatCategory);
            Assert.AreEqual(ThreatState.NotApplicable, privacyThreat.State);
            Assert.AreEqual(model.DrawingSurfaceList[1].Guid, privacyThreat.DrawingSurfaceGuid);
        }

        /// <summary>Reimporting the same source does not change element, page or threat identity.</summary>
        [TestMethod]
        public void ImportIdentitiesAreStable()
        {
            string json = Fixture().ToJsonString();
            ThreatModel first = Read(json);
            ThreatModel second = Read(json);

            CollectionAssert.AreEqual(first.DrawingSurfaceList.Select(page => page.Guid).ToArray(), second.DrawingSurfaceList.Select(page => page.Guid).ToArray());
            CollectionAssert.AreEqual(first.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys)).ToArray(), second.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys)).ToArray());
            CollectionAssert.AreEqual(first.AllThreatsDictionary.Keys.ToArray(), second.AllThreatsDictionary.Keys.ToArray());
        }

        /// <summary>Canonical conversion retains source evidence and the page each threat belongs to.</summary>
        /// <param name="formatId">The destination format.</param>
        [TestMethod]
        [DataRow("tmforge-json")]
        [DataRow("tm7")]
        public void RoundTripPreservesImportEvidence(string formatId)
        {
            ThreatModel original = Read(Fixture().ToJsonString());
            IThreatModelFormat format = ThreatModelFormatRegistry.CreateDefault().FindById(formatId)
                ?? throw new InvalidOperationException("Missing format.");
            using MemoryStream stream = new MemoryStream();
            format.Write(original, stream);
            stream.Position = 0;

            ThreatModel restored = format.Read(stream);

            Threat privacy = restored.AllThreatsDictionary["manual:threat-dragon.linkability"];
            Assert.AreEqual(original.DrawingSurfaceList[1].Guid, privacy.DrawingSurfaceGuid);
            Assert.AreEqual("Model owner", restored.MetaInformation?.Owner);
            Assert.AreEqual("Threat Dragon import fixture", restored.MetaInformation?.ThreatModelName);
            Assert.AreEqual("linkability", privacy.Properties?["Source.id"]);
            Assert.AreEqual("LINDDUN", privacy.Properties?["Source.modelType"]);
            Assert.AreEqual("Approved for the documented retention window.", privacy.StateInformation);
            Assert.AreEqual("Use short-lived identifiers.", privacy.Properties?["Mitigation"]);
        }

        /// <summary>A one-page import does not lose its named page identity in the canonical wire format.</summary>
        [TestMethod]
        public void SinglePageIdentitySurvivesCanonicalConversion()
        {
            JsonNode document = Fixture();
            At(document, "detail", "diagrams").AsArray().RemoveAt(1);
            ThreatModel original = Read(document.ToJsonString());
            TmForgeJsonFormat format = new TmForgeJsonFormat();
            using MemoryStream stream = new MemoryStream();
            format.Write(original, stream);
            stream.Position = 0;

            ThreatModel restored = format.Read(stream);

            Assert.AreEqual(original.DrawingSurfaceList[0].Guid, restored.DrawingSurfaceList[0].Guid);
            Assert.AreEqual("Requests", restored.DrawingSurfaceList[0].Header);
        }

        /// <summary>Descriptions naming other formats cannot redirect a valid Threat Dragon import.</summary>
        [TestMethod]
        public void SniffUsesDocumentShapeRatherThanDescriptionText()
        {
            JsonNode document = Fixture();
            At(document, "summary")["description"] = "Convert this to tmforge-json.";
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(document.ToJsonString()));

            Assert.AreEqual("threat-dragon", ThreatModelFormatRegistry.CreateDefault().Sniff(stream)?.Id);
            Assert.AreEqual(0L, stream.Position);
            Assert.IsNull(ThreatModelFormatRegistry.CreateDefault().FindByExtension("unknown.json"));
        }

        /// <summary>Missing controls are not promoted to positive evidence; explicit booleans are mapped.</summary>
        [TestMethod]
        public void MapsOnlyExplicitControlEvidence()
        {
            JsonNode document = Fixture();
            JsonNode cells = At(document, "detail", "diagrams", 0, "cells");
            At(cells, 0, "data").AsObject().Remove("providesAuthentication");
            At(cells, 2, "data")["isEncrypted"] = true;
            At(cells, 2, "data")["isALog"] = true;
            At(cells, 2, "data")["isSigned"] = true;
            At(cells, 2, "data")["outOfScope"] = true;
            ThreatModel model = Read(document.ToJsonString());
            Entity actor = model.DrawingSurfaceList[0].Borders.Values.OfType<Entity>().Single(element => DiagramElementHelper.GetName(element) == "Caller");
            Entity store = model.DrawingSurfaceList[0].Borders.Values.OfType<Entity>().Single(element => DiagramElementHelper.GetName(element) == "Credentials");

            Assert.IsFalse(DiagramElementHelper.GetCustomProperties(actor).ContainsKey("AuthenticatesItself"));
            Assert.AreEqual("At-rest", DiagramElementHelper.GetCustomProperties(store)["Encrypted"]);
            Assert.AreEqual("Yes", DiagramElementHelper.GetCustomProperties(store)["StoresLogData"]);
            Assert.AreEqual("Yes", DiagramElementHelper.GetCustomProperties(store)["Signed"]);
            Assert.AreEqual("true", DiagramElementHelper.GetCustomProperties(store)["ThreatDragon.data.outOfScope"]);
            Assert.HasCount(3, model.AllThreatsDictionary);
        }

        /// <summary>The v2 cell-level schema variant retains the same authored threats.</summary>
        [TestMethod]
        public void ReadsCellLevelThreatsAndNumberedIdentities()
        {
            JsonNode document = Fixture();
            JsonNode cell = At(document, "detail", "diagrams", 0, "cells", 2);
            JsonNode threats = At(cell, "data", "threats");
            At(threats, 0).AsObject().Remove("id");
            At(threats, 0)["number"] = 42;
            At(threats, 0).AsObject().Remove("modelType");
            cell["threats"] = threats.DeepClone();
            At(cell, "data").AsObject().Remove("threats");
            At(document, "detail")["contributors"] = new JsonArray(new JsonObject { ["name"] = "Contributor" });

            ThreatModel model = Read(document.ToJsonString());

            Assert.HasCount(3, model.AllThreatsDictionary);
            Assert.AreEqual("STRIDE", model.AllThreatsDictionary["manual:threat-dragon.42"].Properties?["Source.modelType"]);
            Assert.AreEqual("2.6.2", model.AllThreatsDictionary["manual:threat-dragon.42"].Properties?["Source.version"]);
            Assert.AreEqual("Contributor", model.MetaInformation?.Contributors);
        }

        /// <summary>The sniff and reader respect offsets, UTF-8 BOMs and caller ownership.</summary>
        [TestMethod]
        public void SupportsBomAndRestoresNonzeroStreamPosition()
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes("prefix\uFEFF" + EmptyV2));
            stream.Position = 6;
            ThreatDragonFormat format = new ThreatDragonFormat();

            Assert.IsTrue(format.CanRead(stream));
            Assert.AreEqual(6L, stream.Position);
            Assert.AreEqual("Imported model", format.Read(stream).MetaInformation?.ThreatModelName);
            Assert.IsTrue(stream.CanRead);
            using MemoryStream output = new MemoryStream();
            Assert.Throws<NotSupportedException>(() => format.Write(new ThreatModel(), output));
            Assert.AreEqual(0L, output.Length);
            Assert.Throws<NotSupportedException>(() => ThreatModelFormatRegistry.CreateDefault().ResolveForWrite("source.json", "threat-dragon"));
        }

        /// <summary>Null inputs and non-seekable sniffing fail explicitly.</summary>
        [TestMethod]
        public void RejectsInvalidStreamArguments()
        {
            ThreatDragonFormat format = new ThreatDragonFormat();
            Assert.Throws<ArgumentNullException>(() => format.Read(null!));
            Assert.Throws<ArgumentNullException>(() => format.CanRead(null!));
            using NonSeekableStream stream = new NonSeekableStream();
            Assert.Throws<NotSupportedException>(() => format.CanRead(stream));
        }

        /// <summary>Malformed JSON, deep objects and non-UTF-8 input are not recognized as valid files.</summary>
        [TestMethod]
        public void RejectsInvalidEncodingAndJson()
        {
            ThreatDragonFormat format = new ThreatDragonFormat();
            using MemoryStream invalidUtf8 = new MemoryStream(new byte[] { 0xff, 0xfe, 0xff });
            Assert.IsFalse(format.CanRead(invalidUtf8));
            Assert.AreEqual(0L, invalidUtf8.Position);
            Assert.Throws<DecoderFallbackException>(() => format.Read(invalidUtf8));
            Assert.Throws<JsonException>(() => Read("{"));
            Assert.Throws<JsonException>(() => Read(new string('[', 65) + new string(']', 65)));
            Assert.Throws<InvalidDataException>(() => Read("{}"));
            Assert.Throws<InvalidDataException>(() => Read(EmptyV2.Replace("\"version\":", "\"VERSION\":\"2.0\",\"version\":")));
        }

        /// <summary>Document and graph limits reject oversized input before materializing the graph.</summary>
        [TestMethod]
        public void BoundsDocumentAndGraphSizes()
        {
            using MemoryStream oversized = new MemoryStream(new byte[(8 * 1024 * 1024) + 1]);
            ThreatDragonFormat format = new ThreatDragonFormat();
            Assert.IsFalse(format.CanRead(oversized));
            Assert.AreEqual(0L, oversized.Position);
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => format.Read(oversized)).Message, "8 MiB");

            JsonNode document = Fixture();
            JsonArray pages = At(document, "detail", "diagrams").AsArray();
            pages.Clear();
            for (int index = 0; index < 129; index++)
            {
                pages.Add(new JsonObject());
            }

            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(document.ToJsonString())).Message, "128 diagrams");
            document = Fixture();
            JsonArray cells = At(document, "detail", "diagrams", 0, "cells").AsArray();
            cells.Clear();
            for (int index = 0; index < 10001; index++)
            {
                cells.Add(new JsonObject());
            }

            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(document.ToJsonString())).Message, "10000 cells");
        }

        /// <summary>The authored threat limit bounds register construction independently of cell count.</summary>
        [TestMethod]
        public void BoundsAuthoredThreatCount()
        {
            JsonNode document = Fixture();
            JsonArray threats = At(document, "detail", "diagrams", 0, "cells", 2, "data", "threats").AsArray();
            threats.Clear();
            for (int index = 0; index < 20001; index++)
            {
                threats.Add(new JsonObject
                {
                    ["number"] = index,
                    ["title"] = "Threat",
                    ["type"] = "Spoofing",
                    ["status"] = "Open",
                    ["severity"] = "Low",
                });
            }

            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(document.ToJsonString())).Message, "20000 threats");
        }

        /// <summary>Unsupported content is rejected instead of producing a partial or misleading model.</summary>
        /// <param name="variation">The unsupported fixture change.</param>
        /// <param name="message">The expected diagnostic fragment.</param>
        [TestMethod]
        [DataRow("curved-boundary", "curved trust boundary")]
        [DataRow("bidirectional", "bidirectional")]
        [DataRow("foreign-state", "Transferred")]
        [DataRow("unknown-type", "tm.Unknown")]
        [DataRow("old-version", "v2")]
        [DataRow("new-version", "v2")]
        [DataRow("priority", "severity")]
        public void RejectsUnsupportedSemantics(string variation, string message)
        {
            JsonNode document = Fixture();
            JsonNode cells = At(document, "detail", "diagrams", 0, "cells");
            switch (variation)
            {
                case "curved-boundary": At(cells, 3, "data")["type"] = "tm.Boundary"; break;
                case "bidirectional": At(cells, 4, "data")["isBidirectional"] = true; break;
                case "foreign-state": At(cells, 2, "data", "threats", 0)["status"] = "Transferred"; break;
                case "unknown-type": At(cells, 0, "data")["type"] = "tm.Unknown"; break;
                case "old-version": document["version"] = "1.0"; break;
                case "new-version": document["version"] = "3.0"; break;
                case "priority": At(cells, 2, "data", "threats", 0)["severity"] = "Urgent"; break;
            }

            NotSupportedException exception = Assert.Throws<NotSupportedException>(() => Read(document.ToJsonString()));
            StringAssert.Contains(exception.Message, message);
        }

        /// <summary>Malformed graph references, identities and geometry fail before a model is returned.</summary>
        /// <param name="variation">The malformed fixture change.</param>
        /// <param name="message">The expected diagnostic fragment.</param>
        [TestMethod]
        [DataRow("endpoint", "unresolved")]
        [DataRow("duplicate-cell", "Duplicate")]
        [DataRow("duplicate-page", "Duplicate")]
        [DataRow("fractional", "integer")]
        [DataRow("boolean", "boolean")]
        [DataRow("threat-id", "threat id")]
        [DataRow("duplicate-threat", "Duplicate")]
        [DataRow("duplicate-threat-locations", "both")]
        [DataRow("missing-id", "identifier")]
        [DataRow("missing-version", "version")]
        [DataRow("wrong-title-type", "string")]
        [DataRow("long-title", "65536")]
        [DataRow("wrong-cells-type", "Array")]
        [DataRow("boundary-endpoint", "non-component")]
        public void RejectsMalformedModels(string variation, string message)
        {
            JsonNode document = Fixture();
            JsonNode pages = At(document, "detail", "diagrams");
            JsonNode cells = At(pages, 0, "cells");
            switch (variation)
            {
                case "endpoint": At(cells, 4, "source")["cell"] = "missing"; break;
                case "duplicate-cell": At(cells, 1)["id"] = "actor"; break;
                case "duplicate-page": At(pages, 1)["id"] = 0; break;
                case "fractional": At(cells, 0, "position")["x"] = 0.5; break;
                case "boolean": At(cells, 2, "data")["isEncrypted"] = "true"; break;
                case "threat-id": At(cells, 2, "data", "threats", 0)["id"] = "invalid:id"; break;
                case "duplicate-threat": At(cells, 2, "data", "threats", 0)["id"] = "linkability"; break;
                case "duplicate-threat-locations": At(cells, 2)["threats"] = At(cells, 2, "data", "threats").DeepClone(); break;
                case "missing-id": At(cells, 0).AsObject().Remove("id"); break;
                case "missing-version": document.AsObject().Remove("version"); break;
                case "wrong-title-type": At(document, "summary")["title"] = true; break;
                case "long-title": At(document, "summary")["title"] = new string('x', 65537); break;
                case "wrong-cells-type": At(pages, 0)["cells"] = new JsonObject(); break;
                case "boundary-endpoint": At(cells, 4, "source")["cell"] = "boundary"; break;
            }

            InvalidDataException exception = Assert.Throws<InvalidDataException>(() => Read(document.ToJsonString()));
            StringAssert.Contains(exception.Message, message);
        }

        private static JsonNode Fixture() => JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "threat-dragon-v2.json")))
            ?? throw new InvalidDataException("Missing fixture document.");

        private static JsonNode At(JsonNode node, params object[] path)
        {
            foreach (object part in path)
            {
                node = (part is int index ? node[index] : node[(string)part])
                    ?? throw new InvalidDataException("Missing fixture member: " + part);
            }

            return node;
        }

        private static ThreatModel Read(string json)
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
            return new ThreatDragonFormat().Read(stream);
        }

        private sealed class NonSeekableStream : MemoryStream
        {
            public override bool CanSeek => false;
        }
    }
}
