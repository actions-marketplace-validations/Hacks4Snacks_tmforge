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

    /// <summary>Tests the bounded Threat Dragon v2 provider.</summary>
    [TestClass]
    public class ThreatDragonFormatTest
    {
        private const string EmptyV2 = @"{
  ""version"": ""2.6.2"",
  ""summary"": { ""title"": ""Imported model"" },
  ""detail"": { ""diagrams"": [] }
}";

        /// <summary>The registry exposes bounded export without claiming lossless native round trips.</summary>
        [TestMethod]
        public void RegistersBoundedProvider()
        {
            IThreatModelFormat? format = ThreatModelFormatRegistry.CreateDefault().FindById("threat-dragon");

            Assert.IsNotNull(format);
            Assert.IsTrue(format.Capabilities.CanRead);
            Assert.IsTrue(format.Capabilities.CanWrite);
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
        [DataRow("threat-dragon")]
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

        /// <summary>Exporting the imported subset preserves identities and display numbers deterministically.</summary>
        /// <param name="canonical">Whether to store the imported model as canonical JSON first.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void ExportsImportedFixtureWithStableIdentities(bool canonical)
        {
            JsonNode fixture = Fixture();
            At(fixture, "detail", "diagrams", 0, "cells", 2, "data", "threats", 0)["number"] = 42;
            ThreatModel original = Read(fixture.ToJsonString());
            if (canonical)
            {
                using MemoryStream storage = new MemoryStream();
                TmForgeJsonFormat json = new TmForgeJsonFormat();
                json.Write(original, storage);
                storage.Position = 0;
                original = json.Read(storage);
            }

            ThreatDragonFormat format = new ThreatDragonFormat();
            using MemoryStream first = new MemoryStream();
            using MemoryStream second = new MemoryStream();
            format.Write(original, first);
            format.Write(original, second);

            CollectionAssert.AreEqual(first.ToArray(), second.ToArray());
            Assert.IsTrue(first.CanWrite);
            using JsonDocument document = JsonDocument.Parse(first.ToArray());
            JsonElement detail = document.RootElement.GetProperty("detail");
            Assert.AreEqual(0, detail.GetProperty("diagrams")[0].GetProperty("id").GetInt32());
            Assert.AreEqual(1, detail.GetProperty("diagrams")[1].GetProperty("id").GetInt32());
            Assert.IsTrue(detail.GetProperty("diagrams")[0].TryGetProperty("thumbnail", out _));
            Assert.AreEqual(2, detail.GetProperty("diagramTop").GetInt32());
            JsonElement[] threats = detail.GetProperty("diagrams").EnumerateArray()
                .SelectMany(page => page.GetProperty("cells").EnumerateArray())
                .SelectMany(cell => cell.GetProperty("data").GetProperty("threats").EnumerateArray()).ToArray();
            Assert.AreEqual(3, threats.Select(threat => threat.GetProperty("number").GetInt64()).Distinct().Count());
            Assert.AreEqual(42L, threats.Single(threat => threat.GetProperty("id").GetString() == "credential-disclosure").GetProperty("number").GetInt64());
            Assert.AreEqual(42L, detail.GetProperty("threatTop").GetInt64());
            first.Position = 0;
            ThreatModel restored = format.Read(first);
            CollectionAssert.AreEqual(original.DrawingSurfaceList.Select(page => page.Guid).ToArray(), restored.DrawingSurfaceList.Select(page => page.Guid).ToArray());
            CollectionAssert.AreEquivalent(original.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys)).ToArray(), restored.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys)).ToArray());
            CollectionAssert.AreEquivalent(original.AllThreatsDictionary.Keys.ToArray(), restored.AllThreatsDictionary.Keys.ToArray());
            foreach (string key in original.AllThreatsDictionary.Keys)
            {
                Assert.AreEqual(original.AllThreatsDictionary[key].State, restored.AllThreatsDictionary[key].State);
                Assert.AreEqual(original.AllThreatsDictionary[key].FlowGuid, restored.AllThreatsDictionary[key].FlowGuid);
                Assert.AreEqual(original.AllThreatsDictionary[key].UserThreatCategory, restored.AllThreatsDictionary[key].UserThreatCategory);
            }

            Assert.AreEqual("42", restored.AllThreatsDictionary["manual:threat-dragon.credential-disclosure"].Properties?["Source.number"]);
        }

        /// <summary>Empty imported pages retain their source identity through canonical storage.</summary>
        /// <param name="canonical">Whether to pass through canonical JSON before exporting.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void ExportsEmptyImportedPage(bool canonical)
        {
            JsonNode document = Fixture();
            At(document, "detail", "diagrams").AsArray().RemoveAt(0);
            At(document, "detail", "diagrams", 0, "cells").AsArray().Clear();
            ThreatModel original = Read(document.ToJsonString());
            ThreatModel model = original;
            if (canonical)
            {
                using MemoryStream intermediate = new MemoryStream();
                TmForgeJsonFormat json = new TmForgeJsonFormat();
                json.Write(model, intermediate);
                intermediate.Position = 0;
                model = json.Read(intermediate);
            }

            using MemoryStream output = new MemoryStream();
            new ThreatDragonFormat().Write(model, output);
            string exported = Encoding.UTF8.GetString(output.ToArray());
            ThreatModel restored = Read(exported);

            Assert.AreEqual(original.DrawingSurfaceList[0].Guid, restored.DrawingSurfaceList[0].Guid);
            using JsonDocument result = JsonDocument.Parse(exported);
            Assert.AreEqual("LINDDUN", result.RootElement.GetProperty("detail").GetProperty("diagrams")[0].GetProperty("diagramType").GetString());
        }

        /// <summary>Export reads current controls, names and treatment instead of stale source values.</summary>
        [TestMethod]
        public void ExportsCurrentEdits()
        {
            ThreatModel model = Read(Fixture().ToJsonString());
            Entity store = model.DrawingSurfaceList[0].Borders.Values.OfType<Entity>().Single(entity => DiagramElementHelper.GetName(entity) == "Credentials");
            DiagramElementHelper.SetName(store, "Encrypted vault");
            DiagramElementHelper.SetCustomProperty(store, "Encrypted", "At-rest");
            Threat threat = model.AllThreatsDictionary["manual:threat-dragon.credential-disclosure"];
            threat.State = ThreatState.Mitigated;
            threat.StateInformation = "Encryption deployed.";
            threat.Properties!["Mitigation"] = "Use managed keys.";
            using MemoryStream output = new MemoryStream();

            new ThreatDragonFormat().Write(model, output);
            ThreatModel restored = Read(Encoding.UTF8.GetString(output.ToArray()));

            Entity restoredStore = (Entity)restored.DrawingSurfaceList[0].Borders[store.Guid];
            Assert.AreEqual("Encrypted vault", DiagramElementHelper.GetName(restoredStore));
            Assert.AreEqual("At-rest", DiagramElementHelper.GetCustomProperties(restoredStore)["Encrypted"]);
            Assert.AreEqual(ThreatState.Mitigated, restored.AllThreatsDictionary[threat.InteractionKey!].State);
            Assert.AreEqual("Encryption deployed.", restored.AllThreatsDictionary[threat.InteractionKey!].StateInformation);
            Assert.AreEqual("Use managed keys.", restored.AllThreatsDictionary[threat.InteractionKey!].Properties?["Mitigation"]);
            Assert.AreEqual("false", DiagramElementHelper.GetCustomProperties(store)["ThreatDragon.data.isEncrypted"]);
        }

        /// <summary>Native compatibility fields do not make an otherwise supported authored finding unexportable.</summary>
        [TestMethod]
        public void ExportsManualThreatsWithNativeTypeAndMirroredProperties()
        {
            ThreatModel model = Read(Fixture().ToJsonString());
            ThreatDragonFormat format = new ThreatDragonFormat();
            using MemoryStream before = new MemoryStream();
            format.Write(model, before);
            foreach (Threat threat in model.AllThreatsDictionary.Values)
            {
                threat.TypeId = ManualThreatId.ToNativeTypeId(threat.InteractionKey!);
                threat.Properties!["Title"] = threat.Title!;
                threat.Properties["UserThreatCategory"] = threat.UserThreatCategory!;
                threat.Properties["UserThreatDescription"] = threat.UserThreatDescription!;
                threat.Properties["StateInformation"] = threat.StateInformation!;
                threat.Properties["Priority"] = threat.Priority!;
            }

            using MemoryStream after = new MemoryStream();
            format.Write(model, after);

            CollectionAssert.AreEqual(before.ToArray(), after.ToArray());
        }

        /// <summary>Unsupported semantics refuse the whole export before touching the destination.</summary>
        /// <param name="variation">The unsupported content to add.</param>
        /// <param name="message">A diagnostic fragment identifying the loss.</param>
        [TestMethod]
        [DataRow("property", "UnsupportedControl")]
        [DataRow("unknown-control", "Encrypted")]
        [DataRow("metadata", "Assumptions")]
        [DataRow("notes", "notes")]
        [DataRow("generated", "generated threat")]
        [DataRow("invalid-native-type", "generated threat")]
        [DataRow("conflicting-native-property", "Title")]
        [DataRow("state", "NeedsInvestigation")]
        [DataRow("wide", "model-wide")]
        [DataRow("multiple-targets", "multiple")]
        [DataRow("threat-property", "References")]
        [DataRow("custom-stencil", "custom-process")]
        [DataRow("line-boundary", "LineBoundary")]
        [DataRow("unscoped", "scoped")]
        [DataRow("routing", "routing")]
        [DataRow("ports", "ports")]
        [DataRow("empty-id", "identities")]
        [DataRow("duplicate-id", "identities")]
        [DataRow("audit", "audit")]
        [DataRow("small-shape", "at least 10")]
        [DataRow("threat-number", "source number")]
        [DataRow("duplicate-number", "source number")]
        public void RefusesUnsupportedExportsWithoutWriting(string variation, string message)
        {
            ThreatModel model = Read(Fixture().ToJsonString());
            DrawingSurfaceModel page = model.DrawingSurfaceList[0];
            Entity store = page.Borders.Values.OfType<Entity>().Single(entity => DiagramElementHelper.GetName(entity) == "Credentials");
            Threat threat = model.AllThreatsDictionary["manual:threat-dragon.credential-disclosure"];
            switch (variation)
            {
                case "property": DiagramElementHelper.SetCustomProperty(store, "UnsupportedControl", "Yes"); break;
                case "unknown-control": DiagramElementHelper.SetCustomProperty(store, "Encrypted", "Unknown"); break;
                case "metadata": model.MetaInformation!.Assumptions = "Must not disappear."; break;
                case "notes": model.Notes.Add(new Note { Message = "Must not disappear." }); break;
                case "generated": threat.TypeId = "TM1023"; break;
                case "invalid-native-type": threat.TypeId = "BSnot-a-native-guid"; break;
                case "conflicting-native-property": threat.Properties!["Title"] = "Different native title"; break;
                case "state": threat.State = ThreatState.NeedsInvestigation; break;
                case "wide": threat.Wide = true; break;
                case "multiple-targets": threat.TargetGuid = page.Borders.Keys.First(id => id != store.Guid); break;
                case "threat-property": threat.Properties!["References"] = "Important evidence"; break;
                case "custom-stencil": store.TypeId = "custom-process"; break;
                case "line-boundary":
                    LineBoundary boundary = new LineBoundary { Guid = Guid.NewGuid() };
                    page.Lines.Add(boundary.Guid, boundary);
                    break;
                case "unscoped": threat.SourceGuid = Guid.Empty; break;
                case "routing": page.Lines.Values.OfType<Connector>().First().HandleX += 25; break;
                case "ports": page.Lines.Values.OfType<Connector>().First().PortSource = "East"; break;
                case "empty-id": store.Guid = Guid.Empty; break;
                case "duplicate-id": store.Guid = page.Guid; break;
                case "audit": threat.ModifiedAt = new DateTime(2026, 9, 23, 0, 0, 0, DateTimeKind.Utc); break;
                case "small-shape": ((DrawingElement)store).Width = 9; break;
                case "threat-number": threat.Properties!["Source.number"] = "-1"; break;
                case "duplicate-number":
                    foreach (Threat entry in model.AllThreatsDictionary.Values)
                    {
                        entry.Properties!["Source.number"] = "1";
                    }

                    break;
            }

            using MemoryStream output = new MemoryStream();
            output.Write(new byte[] { 1, 2, 3 });
            NotSupportedException error = Assert.Throws<NotSupportedException>(() => new ThreatDragonFormat().Write(model, output));

            StringAssert.Contains(error.Message, message);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, output.ToArray());
            Assert.AreEqual(3L, output.Position);
        }

        /// <summary>The supported v2 data vocabulary remains typed and survives export.</summary>
        [TestMethod]
        public void ExportsSupportedSourceProperties()
        {
            JsonNode fixture = Fixture();
            JsonNode data = At(fixture, "detail", "diagrams", 0, "cells", 1, "data");
            data["isWebApplication"] = true;
            data["handlesCardPayment"] = false;
            data["handlesGoodsOrServices"] = true;
            data["privilegeLevel"] = "User";
            At(fixture, "detail", "diagrams", 0, "cells", 2, "data")["storesInventory"] = false;
            ThreatModel model = Read(fixture.ToJsonString());
            using MemoryStream output = new MemoryStream();

            new ThreatDragonFormat().Write(model, output);

            using JsonDocument document = JsonDocument.Parse(output.ToArray());
            JsonElement cells = document.RootElement.GetProperty("detail").GetProperty("diagrams")[0].GetProperty("cells");
            JsonElement process = cells.EnumerateArray().Single(cell => cell.GetProperty("id").GetString() == "api").GetProperty("data");
            Assert.IsTrue(process.GetProperty("isWebApplication").GetBoolean());
            Assert.IsFalse(process.GetProperty("handlesCardPayment").GetBoolean());
            Assert.IsTrue(process.GetProperty("handlesGoodsOrServices").GetBoolean());
            Assert.AreEqual("User", process.GetProperty("privilegeLevel").GetString());
            JsonElement store = cells.EnumerateArray().Single(cell => cell.GetProperty("id").GetString() == "store").GetProperty("data");
            Assert.IsFalse(store.GetProperty("storesInventory").GetBoolean());
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
            format.Write(Read(EmptyV2), output);
            Assert.IsTrue(output.Length > 0);
            Assert.AreEqual("threat-dragon", ThreatModelFormatRegistry.CreateDefault().ResolveForWrite("source.json", "threat-dragon").Id);
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
