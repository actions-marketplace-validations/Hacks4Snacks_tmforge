namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using System.Xml.Linq;
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

        /// <summary>Model notes survive every engine-backed model format and reach the model report.</summary>
        /// <param name="format">The model format.</param>
        [TestMethod]
        [DataRow("tm7")]
        [DataRow("tmforge-json")]
        public void ModelNotesSurviveEngineRoundTrips(string format)
        {
            Note note = new Note
            {
                Id = 7, Message = "Scope <review>\nEvidence & assumptions", AddedBy = "Reviewer",
                Date = new DateTime(2026, 9, 30, 12, 0, 0, DateTimeKind.Utc),
            };
            TmForgeModelDto model = WithNotes(ConnectedModel(), new[] { note });
            Assert.AreEqual(EngineService.DescribeAnalysis(ConnectedModel()).Model.Fingerprint, EngineService.DescribeAnalysis(model).Model.Fingerprint);

            TmForgeModelDto restored = EngineService.ReadModel(EngineService.Convert(model, format), format);

            Assert.IsNotNull(restored.Notes);
            Assert.HasCount(1, restored.Notes);
            Assert.AreEqual(JsonSerializer.Serialize(note), JsonSerializer.Serialize(restored.Notes[0]));
            string report = Encoding.UTF8.GetString(EngineService.Report(restored, "html"));
            StringAssert.Contains(report, "Scope &lt;review&gt;");
            TmForgeModelDto authored = AuthoringService.AddThreat(restored, new AddThreatRequest
            {
                Id = "notes-check", Title = "Manual review", Category = "Spoofing",
            }).Model!;
            Assert.AreEqual(JsonSerializer.Serialize(restored.Notes), JsonSerializer.Serialize(authored.Notes));
        }

        /// <summary>Native note changes leave every unrelated XML member and the original register intact.</summary>
        [TestMethod]
        public void SaveTm7EditsModelNotesWithoutChangingOtherNativeXml()
        {
            Note first = new Note { Id = 7, Message = "Original scope", AddedBy = "Reviewer", Date = new DateTime(2026, 9, 30) };
            Note second = new Note { Id = 12, Message = "Remove this note", Date = new DateTime(2026, 9, 29) };
            byte[] original = EngineService.Convert(WithNotes(ConnectedModel(), new[] { first, second }), "tm7");
            XDocument source = XDocument.Parse(Encoding.UTF8.GetString(original));
            XElement[] sourceNotes = source.Root!.Elements().Single(element => element.Name.LocalName == "Notes").Elements().ToArray();
            XName extension = XNamespace.Get("urn:tmforge:test") + "Evidence";
            sourceNotes[0].Add(new XElement(extension, "Keep with note 7"));
            sourceNotes[1].Add(new XElement(extension, "Remove with note 12"));
            original = Encoding.UTF8.GetBytes(source.ToString());
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, baseline));
            Note edited = new Note { Id = first.Id, Message = "Updated scope\nKeep the timestamp", AddedBy = first.AddedBy, Date = first.Date };
            Note added = new Note { Id = 13, Message = "New evidence", AddedBy = "Author", Date = new DateTime(2026, 9, 30, 12, 0, 0, DateTimeKind.Utc) };
            TmForgeModelDto requested = WithNotes(baseline, new[] { edited, added });

            byte[] saved = EngineService.SaveTm7(original, requested);
            TmForgeModelDto restored = EngineService.ReadModel(saved, "tm7");

            Assert.AreEqual(JsonSerializer.Serialize(requested.Notes), JsonSerializer.Serialize(restored.Notes));
            XDocument before = XDocument.Parse(Encoding.UTF8.GetString(original));
            XDocument after = XDocument.Parse(Encoding.UTF8.GetString(saved));
            XElement notes = after.Root!.Elements().Single(element => element.Name.LocalName == "Notes");
            CollectionAssert.AreEqual(new[] { "Keep with note 7" }, notes.Descendants(extension).Select(element => element.Value).ToArray());
            Assert.IsNull(notes.Elements().Last().Element(extension));
            before.Root!.Elements().Single(element => element.Name.LocalName == "Notes").ReplaceWith(new XElement(notes));
            after.Root.Element(XNamespace.Get("urn:tmforge:studio:v1") + "State")?.Remove();
            Assert.IsTrue(XNode.DeepEquals(before, after));
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, restored));
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, baseline, null, saved));

            byte[] cleared = EngineService.SaveTm7(original, WithNotes(baseline, Array.Empty<Note>()), null, saved);
            Assert.AreEqual(0, EngineService.ReadModel(cleared, "tm7").Notes?.Count ?? 0);
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, baseline, null, cleared));
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, WithNotes(baseline, null)));
        }

        /// <summary>Older Studio state without notes still exposes the authoritative native collection.</summary>
        [TestMethod]
        public void ModelNotesSurviveOlderStudioState()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            Note note = new Note { Id = 1, Message = "Native note", Date = new DateTime(2026, 9, 30) };
            byte[] saved = EngineService.SaveTm7(original, WithNotes(baseline, new[] { note }));
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(saved));
            XElement state = document.Root!.Element(XNamespace.Get("urn:tmforge:studio:v1") + "State") ?? throw new InvalidOperationException();
            JsonNode value = JsonNode.Parse(state.Value) ?? throw new InvalidOperationException();
            JsonObject model = value["model"]?.AsObject() ?? throw new InvalidOperationException();
            model.Remove("notes");
            state.Value = value.ToJsonString();
            byte[] legacy = Encoding.UTF8.GetBytes(document.ToString());

            TmForgeModelDto restored = EngineService.ReadModel(legacy, "tm7");

            Assert.AreEqual("Native note", restored.Notes?.Single().Message);
            CollectionAssert.AreEqual(legacy, EngineService.SaveTm7(legacy, restored));
        }

        /// <summary>Reopened native models accept newly generated threats without losing the original register.</summary>
        [TestMethod]
        public void SaveTm7AcceptsNewlyGeneratedThreatsAfterReopening()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeDiagramDto page = baseline.Diagrams!.Single();
            TmForgeElementDto added = new TmForgeElementDto
            {
                Id = Guid.NewGuid().ToString("D"), Kind = "datastore", Name = "New secrets", X = 600, Y = 100, Width = 120, Height = 60,
                Properties = new Dictionary<string, string> { ["StoresCredentials"] = "Yes", ["Encrypted"] = "No" },
            };
            TmForgeModelDto WithThreats(IReadOnlyList<ThreatStateDto>? threats) => new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = baseline.Metadata,
                Diagrams = new[] { new TmForgeDiagramDto { Id = page.Id, Name = page.Name, Elements = page.Elements!.Append(added).ToArray(), Flows = page.Flows } },
                Threats = threats,
            };
            ThreatDto generated = EngineService.GenerateThreats(WithThreats(baseline.Threats)).First(threat => threat.ElementIds.Contains(added.Id));
            ThreatStateDto decision = new ThreatStateDto { Id = generated.Id, State = "Accepted", Justification = "Reviewed in tmforge" };

            byte[] saved = EngineService.SaveTm7(original, WithThreats(new[] { decision }));
            using MemoryStream output = new MemoryStream(saved);
            using MemoryStream source = new MemoryStream(original);
            ThreatModel restored = ThreatModel.Load(output);
            ThreatModel initial = ThreatModel.Load(source);

            Assert.AreEqual(ThreatState.NotApplicable, restored.AllThreatsDictionary[generated.Id].State);
            Assert.AreEqual("Reviewed in tmforge", restored.AllThreatsDictionary[generated.Id].StateInformation);
            Assert.AreEqual(generated.Title, restored.AllThreatsDictionary[generated.Id].Title);
            Assert.IsTrue(initial.AllThreatsDictionary.Keys.All(restored.AllThreatsDictionary.ContainsKey));
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, EngineService.ReadModel(saved, "tm7")));

            TmForgeModelDto deleted = new TmForgeModelDto
            {
                Schema = baseline.Schema, Version = baseline.Version, Metadata = baseline.Metadata,
                Diagrams = baseline.Diagrams, Elements = baseline.Elements, Flows = baseline.Flows, Threats = new[] { decision },
            };
            byte[] deletedBytes = EngineService.SaveTm7(original, deleted, null, saved);
            using MemoryStream deletedInput = new MemoryStream(deletedBytes);
            Assert.IsFalse(ThreatModel.Load(deletedInput).AllThreatsDictionary.ContainsKey(generated.Id));
            Assert.IsFalse(EngineService.ReadModel(deletedBytes, "tm7").Threats?.Any(threat => threat.Id == generated.Id) == true);
            byte[] undone = EngineService.SaveTm7(saved, WithThreats(new[] { decision }), null, deletedBytes);
            using MemoryStream undoneInput = new MemoryStream(undone);
            Threat reattached = ThreatModel.Load(undoneInput).AllThreatsDictionary[generated.Id];
            Assert.AreEqual(Guid.Parse(added.Id), reattached.SourceGuid);
            Assert.AreEqual(ThreatState.NotApplicable, reattached.State);
            Assert.AreEqual("Reviewed in tmforge", reattached.StateInformation);
        }

        /// <summary>Moving an object and changing its kind keeps its identity, foreign properties and extension XML.</summary>
        [TestMethod]
        public void SaveTm7MovesAndRetypesObjectsWithoutDroppingNativeData()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto initial = EngineService.ReadModel(original, "tm7");
            string id = initial.Elements![0].Id;
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(original));
            XNamespace abstracts = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts";
            XElement native = document.Descendants(abstracts + "Guid").Single(element => element.Value == id).Parent!;
            native.Add(new XElement(XNamespace.Get("urn:test:custom") + "Evidence", "Keep this with the object"));
            byte[] source = Encoding.UTF8.GetBytes(document.ToString());
            TmForgeModelDto baseline = EngineService.ReadModel(source, "tm7");
            TmForgeElementDto old = baseline.Elements![0];
            string pageId = Guid.NewGuid().ToString("D");
            TmForgeElementDto changed = new TmForgeElementDto
            {
                Id = id, Kind = "external", Name = old.Name, X = old.X, Y = old.Y, Width = old.Width, Height = old.Height, Properties = old.Properties,
            };
            TmForgeModelDto edited = new TmForgeModelDto
            {
                Schema = baseline.Schema, Version = baseline.Version, Metadata = baseline.Metadata,
                Diagrams = new[] { new TmForgeDiagramDto { Id = pageId, Name = "Moved page", Elements = new[] { changed, baseline.Elements[1] }, Flows = baseline.Flows } },
            };

            byte[] saved = EngineService.SaveTm7(source, edited);
            XDocument output = XDocument.Parse(Encoding.UTF8.GetString(saved));
            XElement retained = output.Descendants(abstracts + "Guid").Single(element => element.Value == id).Parent!;
            Assert.AreEqual("Keep this with the object", retained.Element(XNamespace.Get("urn:test:custom") + "Evidence")?.Value);
            TmForgeModelDto restored = EngineService.ReadModel(saved, "tm7");
            Assert.AreEqual(pageId, restored.Diagrams![0].Id);
            Assert.AreEqual("external", restored.Elements![0].Kind);
            Assert.AreEqual(id, restored.Elements[0].Id);
            using MemoryStream result = new MemoryStream(saved);
            Assert.IsTrue(ThreatModel.Load(result).AllThreatsDictionary.Values.Where(threat => threat.SourceGuid == Guid.Parse(id)).All(threat => threat.DrawingSurfaceGuid == Guid.Parse(pageId)));
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, restored));
        }

        /// <summary>Saving an unchanged native document retains its original bytes and opaque XML.</summary>
        [TestMethod]
        public void SaveTm7WithoutEditsPreservesOriginalBytes()
        {
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(EngineService.Convert(ConnectedModel(), "tm7")));
            document.Root!.Add(new XElement(XNamespace.Get("urn:tmforge:test") + "Extension", "untouched"));
            byte[] original = Encoding.UTF8.GetBytes(document.ToString());
            TmForgeModelDto model = EngineService.ReadModel(original, "tm7");

            byte[] saved = EngineService.SaveTm7(original, model);

            CollectionAssert.AreEqual(original, saved);
        }

        /// <summary>A single rename changes only the corresponding name value in the retained document.</summary>
        [TestMethod]
        public void SaveTm7RenamePreservesUneditedXml()
        {
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(EngineService.Convert(ConnectedModel(), "tm7")));
            document.Root!.Add(new XElement(XNamespace.Get("urn:tmforge:test") + "Extension", "untouched"));
            byte[] original = Encoding.UTF8.GetBytes(document.ToString());
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeModelDto renamed = AuthoringService.Rename(baseline, new RenameRequest
            {
                Id = baseline.Elements![0].Id,
                Name = "Renamed service",
            }).Model!;

            XDocument saved = XDocument.Parse(Encoding.UTF8.GetString(EngineService.SaveTm7(original, renamed)));
            document = XDocument.Parse(Encoding.UTF8.GetString(original));
            XElement name = document.Descendants().Single(element => element.Name.LocalName == "Value" && !element.HasElements && element.Value == "Web App");
            name.Value = "Renamed service";
            saved.Root!.Element(XNamespace.Get("urn:tmforge:studio:v1") + "State")?.Remove();

            Assert.IsTrue(XNode.DeepEquals(document, saved));
        }

        /// <summary>Native geometry and property edits retain the template and original threat register.</summary>
        [TestMethod]
        public void SaveTm7EditsGeometryAndPropertiesWithoutRegeneratingThreats()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            JsonNode edited = JsonNode.Parse(JsonSerializer.Serialize(baseline)) ?? throw new InvalidOperationException();
            JsonNode elements = edited["Elements"] ?? throw new InvalidOperationException();
            JsonNode element = elements[0] ?? throw new InvalidOperationException();
            element["X"] = baseline.Elements![0].X + 32;
            JsonNode properties = element["Properties"] ?? throw new InvalidOperationException();
            properties["NativeEdit"] = "kept";
            if (edited["Diagrams"] is JsonArray pages)
            {
                JsonNode page = pages[0] ?? throw new InvalidOperationException();
                page["Elements"] = elements.DeepClone();
            }

            TmForgeModelDto requested = edited.Deserialize<TmForgeModelDto>() ?? throw new InvalidOperationException();
            byte[] saved = EngineService.SaveTm7(original, requested);
            TmForgeModelDto restored = EngineService.ReadModel(saved, "tm7");
            XDocument before = XDocument.Parse(Encoding.UTF8.GetString(original));
            XDocument after = XDocument.Parse(Encoding.UTF8.GetString(saved));

            Assert.AreEqual(baseline.Elements![0].X + 32, restored.Elements![0].X);
            Assert.AreEqual("kept", restored.Elements[0].Properties["NativeEdit"]);
            foreach (string member in new[] { "KnowledgeBase", "ThreatInstances", "Profile", "Notes", "Validations" })
            {
                Assert.IsTrue(XNode.DeepEquals(before.Root!.Elements().Single(item => item.Name.LocalName == member), after.Root!.Elements().Single(item => item.Name.LocalName == member)), member);
            }

            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, restored));
        }

        /// <summary>Deleting scoped objects removes their threats without resurrecting them on save or reopen.</summary>
        [TestMethod]
        public void SaveTm7DeletesScopedThreatsAndRestoresThemOnUndo()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeModelDto edited = new TmForgeModelDto { Schema = baseline.Schema, Version = baseline.Version, Metadata = baseline.Metadata };

            byte[] saved = EngineService.SaveTm7(original, edited);
            using MemoryStream source = new MemoryStream(original);
            using MemoryStream output = new MemoryStream(saved);
            ThreatModel initial = ThreatModel.Load(source);
            ThreatModel result = ThreatModel.Load(output);
            Assert.IsTrue(initial.AllThreatsDictionary.Count > 0);
            Assert.AreEqual(0, result.AllThreatsDictionary.Count);

            TmForgeModelDto reopened = EngineService.ReadModel(saved, "tm7");
            Assert.AreEqual(0, reopened.Threats?.Count ?? 0);
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, reopened));
            byte[] repeated = EngineService.SaveTm7(original, reopened, null, saved);
            using MemoryStream repeatedInput = new MemoryStream(repeated);
            Assert.AreEqual(0, ThreatModel.Load(repeatedInput).AllThreatsDictionary.Count);
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, EngineService.ReadModel(original, "tm7"), null, saved));
        }

        /// <summary>Object deletion removes generated and manual scoped threats but preserves unrelated and model-wide decisions.</summary>
        [TestMethod]
        public void SaveTm7DeletionKeepsUnrelatedAndModelWideThreats()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            using MemoryStream input = new MemoryStream(original);
            ThreatModel native = ThreatModel.Load(input);
            DrawingSurfaceModel page = native.DrawingSurfaceList[0];
            Guid removedId = page.Borders.Keys.First();
            native.AllThreatsDictionary["manual:model-wide"] = new Threat
            {
                Id = 100, InteractionKey = "manual:model-wide", Title = "Model-wide risk", Wide = true,
                UserThreatCategory = "Tampering", DrawingSurfaceGuid = page.Guid, State = ThreatState.NotApplicable, StateInformation = "Keep this decision",
            };
            native.AllThreatsDictionary["manual:scoped"] = new Threat
            {
                Id = 101, InteractionKey = "manual:scoped", Title = "Scoped risk", SourceGuid = removedId,
                UserThreatCategory = "Tampering", DrawingSurfaceGuid = page.Guid, State = ThreatState.NotApplicable, StateInformation = "Remove this decision",
            };
            native.AllThreatsDictionary["manual:unrelated"] = new Threat
            {
                Id = 102, InteractionKey = "manual:unrelated", Title = "Unrelated risk", SourceGuid = page.Borders.Keys.First(id => id != removedId),
                UserThreatCategory = "Tampering", DrawingSurfaceGuid = page.Guid, State = ThreatState.NotApplicable, StateInformation = "Unrelated decision",
            };
            using MemoryStream prepared = new MemoryStream();
            native.Save(prepared);
            original = prepared.ToArray();
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeElementDto[] remaining = baseline.Elements!.Where(element => Guid.Parse(element.Id) != removedId).ToArray();
            TmForgeModelDto edited = new TmForgeModelDto
            {
                Schema = baseline.Schema, Version = baseline.Version, Metadata = baseline.Metadata,
                Diagrams = new[] { new TmForgeDiagramDto { Id = page.Guid.ToString("D"), Name = page.Header ?? "Page 1", Elements = remaining } },
                Threats = baseline.Threats,
            };
            string[] expected = native.AllThreatsDictionary.Where(entry => entry.Value.SourceGuid != removedId && entry.Value.TargetGuid != removedId
                && !page.Lines.ContainsKey(entry.Value.FlowGuid)).Select(entry => entry.Key).OrderBy(id => id).ToArray();
            byte[] saved = EngineService.SaveTm7(original, edited);
            using MemoryStream output = new MemoryStream(saved);
            ThreatModel result = ThreatModel.Load(output);
            CollectionAssert.AreEqual(expected, result.AllThreatsDictionary.Keys.OrderBy(id => id).ToArray());
            Assert.IsTrue(expected.Length > 1);
            Assert.AreEqual("Keep this decision", result.AllThreatsDictionary["manual:model-wide"].StateInformation);
            Assert.AreEqual("Unrelated decision", result.AllThreatsDictionary["manual:unrelated"].StateInformation);
            Assert.IsFalse(EngineService.ReadModel(saved, "tm7").Threats!.Any(threat => threat.Id == "manual:scoped"));
        }

        /// <summary>Deleting a whole page retains true model-wide decisions without retaining its scoped register entries.</summary>
        [TestMethod]
        public void SaveTm7PageDeletionKeepsModelWideDecisions()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            using MemoryStream input = new MemoryStream(original);
            ThreatModel native = ThreatModel.Load(input);
            Guid oldPage = native.DrawingSurfaceList[0].Guid;
            native.AllThreatsDictionary["manual:model-wide"] = new Threat
            {
                Id = 100, InteractionKey = "manual:model-wide", Title = "Model-wide risk", Wide = true,
                UserThreatCategory = "Tampering", DrawingSurfaceGuid = oldPage, State = ThreatState.NotApplicable, StateInformation = "Keep this decision",
            };
            native.AllThreatsDictionary["page-rule"] = new Threat
            {
                Id = 101, InteractionKey = "page-rule", Title = "Page risk", DrawingSurfaceGuid = oldPage,
            };
            using MemoryStream prepared = new MemoryStream();
            native.Save(prepared);
            original = prepared.ToArray();
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            string nextPage = Guid.NewGuid().ToString("D");
            TmForgeModelDto edited = new TmForgeModelDto
            {
                Schema = baseline.Schema, Version = baseline.Version, Metadata = baseline.Metadata,
                Diagrams = new[] { new TmForgeDiagramDto { Id = nextPage, Name = "Remaining page" } },
                Threats = baseline.Threats,
            };
            byte[] saved = EngineService.SaveTm7(original, edited);
            using MemoryStream output = new MemoryStream(saved);
            ThreatModel restored = ThreatModel.Load(output);
            CollectionAssert.AreEqual(new[] { "manual:model-wide" }, restored.AllThreatsDictionary.Keys.ToArray());
            Assert.AreEqual(Guid.Parse(nextPage), restored.AllThreatsDictionary["manual:model-wide"].DrawingSurfaceGuid);
            Assert.AreEqual("Keep this decision", restored.AllThreatsDictionary["manual:model-wide"].StateInformation);
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, baseline, null, saved));
        }

        /// <summary>Opaque imported register keys expose existing scope for deletion without changing a no-op save.</summary>
        [TestMethod]
        public void SaveTm7ExposesImportedThreatScopeWithoutRewritingIt()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            using MemoryStream input = new MemoryStream(original);
            ThreatModel native = ThreatModel.Load(input);
            Threat target = native.AllThreatsDictionary.Values.First();
            target.State = ThreatState.NotApplicable;
            target.InteractionKey = "opaque-imported-identity";
            target.StateInformation = "Keep the imported decision";
            using MemoryStream prepared = new MemoryStream();
            native.Save(prepared);
            original = prepared.ToArray();
            TmForgeModelDto opened = EngineService.ReadModel(original, "tm7");
            ThreatStateDto decision = opened.Threats!.Single(entry => entry.Id == target.InteractionKey);
            string[] expected = new[] { target.SourceGuid, target.TargetGuid, target.FlowGuid }.Where(id => id != Guid.Empty)
                .Select(id => id.ToString("D")).ToArray();
            CollectionAssert.AreEqual(expected, decision.ElementIds!.ToArray());
            Assert.IsTrue(expected.Length > 0);
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, opened));
        }

        /// <summary>Editing one native threat keeps all other threats and their native metadata unchanged.</summary>
        [TestMethod]
        public void SaveTm7EditsOnlyTheSelectedThreat()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            using MemoryStream source = new MemoryStream(original);
            ThreatModel native = ThreatModel.Load(source);
            string id = native.AllThreatsDictionary.Keys.First();
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeModelDto edited = new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = baseline.Metadata,
                Elements = baseline.Elements,
                Flows = baseline.Flows,
                Diagrams = baseline.Diagrams,
                Threats = new[] { new ThreatStateDto { Id = id, State = "Accepted", Justification = "Native decision" } },
            };

            byte[] saved = EngineService.SaveTm7(original, edited);
            using MemoryStream result = new MemoryStream(saved);
            ThreatModel restored = ThreatModel.Load(result);

            Assert.AreEqual(native.AllThreatsDictionary.Count, restored.AllThreatsDictionary.Count);
            Assert.AreEqual(ThreatState.NotApplicable, restored.AllThreatsDictionary[id].State);
            Assert.AreEqual("Native decision", restored.AllThreatsDictionary[id].StateInformation);
            foreach (KeyValuePair<string, Threat> threat in native.AllThreatsDictionary.Where(pair => pair.Key != id))
            {
                Assert.AreEqual(JsonSerializer.Serialize(threat.Value), JsonSerializer.Serialize(restored.AllThreatsDictionary[threat.Key]));
            }

            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, EngineService.ReadModel(saved, "tm7")));
        }

        /// <summary>The native default page keeps its identity when Studio adds another page.</summary>
        [TestMethod]
        public void SaveTm7KeepsTheDefaultPageWhenAddingAPage()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            Assert.HasCount(1, baseline.Diagrams!);
            TmForgeModelDto edited = new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = baseline.Metadata,
                Threats = baseline.Threats,
                Elements = baseline.Elements,
                Flows = baseline.Flows,
                Diagrams = baseline.Diagrams!.Concat(new[] { new TmForgeDiagramDto { Id = Guid.NewGuid().ToString("D"), Name = "New page" } }).ToArray(),
            };

            byte[] saved = EngineService.SaveTm7(original, edited);
            TmForgeModelDto restored = EngineService.ReadModel(saved, "tm7");

            Assert.HasCount(2, restored.Diagrams!);
            Assert.AreEqual(baseline.Diagrams![0].Id, restored.Diagrams![0].Id);
            Assert.AreEqual("New page", restored.Diagrams[1].Name);
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, restored));
        }

        /// <summary>Typed values are changed in place and hidden native boundaries survive unrelated edits.</summary>
        [TestMethod]
        public void SaveTm7PreservesTypedPropertiesAndNativeLineBoundaries()
        {
            byte[] initial = EngineService.Convert(ConnectedModel(), "tm7");
            using MemoryStream input = new MemoryStream(initial);
            ThreatModel native = ThreatModel.Load(input);
            DrawingSurfaceModel page = native.DrawingSurfaceList[0];
            LineBoundary boundary = new LineBoundary { Guid = Guid.NewGuid(), TypeId = "GE.TB.L", GenericTypeId = "GE.TB.L", SourceX = 250, SourceY = 10, TargetX = 250, TargetY = 400 };
            page.Lines.Add(boundary.Guid, boundary);
            using MemoryStream source = new MemoryStream();
            native.Save(source);
            byte[] original = source.ToArray();
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeModelDto edited = AuthoringService.Set(baseline, new SetRequest
            {
                Id = baseline.Flows![0].Id,
                Properties = new[] { "Protocol=HTTPS" },
            }).Model!;

            byte[] saved = EngineService.SaveTm7(original, edited);
            using MemoryStream result = new MemoryStream(saved);
            ThreatModel restored = ThreatModel.Load(result);
            LineBoundary retained = (LineBoundary)restored.DrawingSurfaceList[0].Lines[boundary.Guid];
            Connector connector = restored.DrawingSurfaceList[0].Lines.Values.OfType<Connector>().Single();

            Assert.AreEqual(JsonSerializer.Serialize(boundary), JsonSerializer.Serialize(retained));
            Assert.AreEqual("HTTPS", DiagramElementHelper.GetCustomProperties(connector)["Protocol"]);
            Assert.HasCount(1, connector.Properties.OfType<ListDisplayAttribute>().Where(property => property.DisplayName == "Protocol").ToArray());
            Assert.IsFalse(connector.Properties.OfType<CustomStringDisplayAttribute>().Any(property => (property.Value as string ?? string.Empty).StartsWith("Protocol:", StringComparison.Ordinal)));
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, EngineService.ReadModel(saved, "tm7")));
        }

        /// <summary>Missing templates and newly chosen native property values are supplied without discarding customizations.</summary>
        [TestMethod]
        public void SaveTm7SuppliesTemplatesAndExtendsNativeValues()
        {
            using MemoryStream initial = new MemoryStream(EngineService.Convert(ConnectedModel(), "tm7"));
            ThreatModel native = ThreatModel.Load(initial);
            native.KnowledgeBase = null;
            using MemoryStream source = new MemoryStream();
            native.Save(source);
            byte[] original = source.ToArray();
            byte[] supplied = EngineService.SaveTm7(original, EngineService.ReadModel(original, "tm7"));
            using MemoryStream suppliedStream = new MemoryStream(supplied);
            ThreatModel withTemplate = ThreatModel.Load(suppliedStream);
            Assert.IsNotNull(withTemplate.KnowledgeBase);
            withTemplate.KnowledgeBase.Manifest!.Name = "Customized template";
            withTemplate.KnowledgeBase.GenericElements.Single(type => type.Id == "GE.DF").Description = "Preserve this description";
            using MemoryStream customized = new MemoryStream();
            withTemplate.Save(customized);
            byte[] bytes = customized.ToArray();
            TmForgeModelDto baseline = EngineService.ReadModel(bytes, "tm7");
            TmForgeModelDto edited = AuthoringService.Set(baseline, new SetRequest { Id = baseline.Flows![0].Id, Properties = new[] { "Protocol=CustomTransport" }, Force = true }).Model!;

            byte[] saved = EngineService.SaveTm7(bytes, edited);
            using MemoryStream output = new MemoryStream(saved);
            ThreatModel restored = ThreatModel.Load(output);
            Assert.AreEqual("Customized template", restored.KnowledgeBase!.Manifest!.Name);
            Assert.AreEqual("Preserve this description", restored.KnowledgeBase.GenericElements.Single(type => type.Id == "GE.DF").Description);
            Assert.AreEqual("CustomTransport", DiagramElementHelper.GetCustomProperties(restored.DrawingSurfaceList[0].Lines.Values.OfType<Connector>().Single())["Protocol"]);
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, EngineService.ReadModel(saved, "tm7")));
        }

        /// <summary>Canvas geometry and labels survive MTMT normalization and external native edits invalidate stale views.</summary>
        [TestMethod]
        public void SaveTm7RetainsCanvasGeometryAndLabelOffsets()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            JsonNode edited = JsonNode.Parse(JsonSerializer.Serialize(baseline)) ?? throw new InvalidOperationException();
            JsonNode page = edited["Diagrams"]?[0] ?? throw new InvalidOperationException();
            JsonNode element = page["Elements"]?[0] ?? throw new InvalidOperationException();
            JsonNode flow = page["Flows"]?[0] ?? throw new InvalidOperationException();
            element["X"] = -160;
            flow["labelOffset"] = new JsonObject { ["X"] = 42, ["Y"] = -30 };
            flow["sourceHandle"] = "r";
            TmForgeModelDto requested = edited.Deserialize<TmForgeModelDto>() ?? throw new InvalidOperationException();
            byte[] saved = EngineService.SaveTm7(original, requested);
            TmForgeModelDto restored = EngineService.ReadModel(saved, "tm7");
            Assert.AreEqual(-160, restored.Diagrams![0].Elements![0].X);
            Assert.AreEqual(42, restored.Diagrams[0].Flows![0].LabelOffset!.X);
            Assert.AreEqual("r", restored.Diagrams[0].Flows![0].SourceHandle);
            using MemoryStream output = new MemoryStream(saved);
            Assert.IsTrue(ThreatModel.Load(output).DrawingSurfaceList.SelectMany(surface => surface.Borders.Values).OfType<ThreatModelForge.Model.Abstracts.DrawingElement>().All(box => box.Left >= 10));
            CollectionAssert.AreEqual(saved, EngineService.SaveTm7(saved, restored));
            XDocument external = XDocument.Parse(Encoding.UTF8.GetString(saved));
            external.Descendants().First(node => node.Name.LocalName == "Value" && !node.HasElements && node.Value == "Web App").Value = "Externally renamed";
            TmForgeModelDto changed = EngineService.ReadModel(Encoding.UTF8.GetBytes(external.ToString()), "tm7");
            Assert.AreEqual("Externally renamed", changed.Elements![0].Name);

            XDocument tampered = XDocument.Parse(Encoding.UTF8.GetString(saved));
            XElement extension = tampered.Root!.Element(XNamespace.Get("urn:tmforge:studio:v1") + "State") ?? throw new InvalidOperationException();
            JsonNode state = JsonNode.Parse(extension.Value) ?? throw new InvalidOperationException();
            JsonNode counterfeit = state["model"]?["diagrams"]?[0]?["elements"]?[0] ?? throw new InvalidOperationException();
            counterfeit["name"] = "Counterfeit canvas";
            extension.Value = state.ToJsonString();
            TmForgeModelDto verified = EngineService.ReadModel(Encoding.UTF8.GetBytes(tampered.ToString()), "tm7");
            Assert.AreEqual("Web App", verified.Elements![0].Name);
        }

        /// <summary>New TM7 exports retain their first canvas layout before a native save has occurred.</summary>
        [TestMethod]
        public void SaveTm7ExportRetainsInitialStudioLayout()
        {
            TmForgeModelDto seed = ConnectedModel();
            TmForgeFlowDto sourceFlow = seed.Flows!.Single();
            TmForgeModelDto canvas = new TmForgeModelDto
            {
                Schema = seed.Schema, Version = seed.Version, Elements = seed.Elements,
                Analysis = new TmForgeAnalysisDto { DisabledRuleIds = new[] { "TM1000" } },
                Flows = new[]
                {
                    new TmForgeFlowDto
                    {
                        Id = sourceFlow.Id, Source = sourceFlow.Source, Target = sourceFlow.Target, Name = sourceFlow.Name,
                        Properties = sourceFlow.Properties, LabelOffset = new TmForgePointDto { X = 48, Y = -32 }, SourceHandle = "r", TargetHandle = "l",
                    },
                },
            };

            byte[] bytes = EngineService.Convert(canvas, "tm7");
            TmForgeModelDto restored = EngineService.ReadModel(bytes, "tm7");
            Assert.AreEqual(48, restored.Flows![0].LabelOffset!.X);
            Assert.AreEqual("r", restored.Flows[0].SourceHandle);
            Assert.AreEqual("TM1000", restored.Analysis!.DisabledRuleIds![0]);
            CollectionAssert.AreEqual(bytes, EngineService.SaveTm7(bytes, restored));
        }

        /// <summary>Native input is bounded and never resolves XML DTDs or accepts malformed XML.</summary>
        /// <param name="xml">The rejected input.</param>
        [TestMethod]
        [DataRow("<invalid")]
        [DataRow("<!DOCTYPE ThreatModel [<!ENTITY secret SYSTEM 'file:///not-read'>]><ThreatModel>&secret;</ThreatModel>")]
        [DataRow("<WrongRoot xmlns='http://schemas.datacontract.org/2004/07/ThreatModeling.Model' />")]
        [DataRow("<ThreatModel xmlns='urn:untrusted' />")]
        [DataRow("<ThreatModel />")]
        public void SaveTm7RejectsInvalidXml(string xml)
        {
            byte[] invalid = Encoding.UTF8.GetBytes(xml);
            InvalidDataException error = Assert.Throws<InvalidDataException>(() => EngineService.SaveTm7(invalid, ConnectedModel()));
            StringAssert.Contains(error.Message, "The native TM7 XML is invalid:");
            Assert.Throws<InvalidDataException>(() => EngineService.SaveTm7(new byte[JsonDocumentPreflight.MaxBytes + 1], ConnectedModel()));
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            Assert.Throws<InvalidDataException>(() => EngineService.SaveTm7(original, ConnectedModel(), null, invalid));
        }

        /// <summary>Untrusted schema hints never replace the native envelope schema or fetch external resources.</summary>
        [TestMethod]
        public void SaveTm7IgnoresUserSuppliedSchemas()
        {
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(EngineService.Convert(ConnectedModel(), "tm7")));
            XNamespace schema = "http://www.w3.org/2001/XMLSchema";
            document.Root!.SetAttributeValue(
                XNamespace.Get("http://www.w3.org/2001/XMLSchema-instance") + "schemaLocation",
                document.Root.Name.NamespaceName + " file:///tmforge-must-not-read.xsd");
            document.Root.Add(new XElement(
                schema + "schema",
                new XAttribute("targetNamespace", document.Root.Name.NamespaceName),
                new XAttribute(XNamespace.Xmlns + "xs", schema),
                new XElement(schema + "element", new XAttribute("name", "ThreatModel"), new XAttribute("type", "xs:int"))));
            byte[] original = Encoding.UTF8.GetBytes(document.ToString());
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");

            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, baseline));
            CollectionAssert.AreEqual(original, EngineService.SaveTm7(original, baseline, null, original));
        }

        /// <summary>Opaque XML remains bounded before document materialization for both native input parameters.</summary>
        [TestMethod]
        public void SaveTm7RejectsExcessiveXmlDepth()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            XDocument document = XDocument.Parse(Encoding.UTF8.GetString(original));
            XElement nested = new XElement("opaque");
            for (int depth = 0; depth < 130; depth++)
            {
                nested = new XElement("opaque", nested);
            }

            document.Root!.Add(nested);
            byte[] excessive = Encoding.UTF8.GetBytes(document.ToString(SaveOptions.DisableFormatting));
            Assert.Throws<InvalidDataException>(() => EngineService.SaveTm7(excessive, ConnectedModel()));
            Assert.Throws<InvalidDataException>(() => EngineService.SaveTm7(original, ConnectedModel(), null, excessive));
        }

        /// <summary>Native structural edits retain the original template and do not create generated threats.</summary>
        [TestMethod]
        public void SaveTm7AddsRemovesAndReordersNativeObjects()
        {
            using MemoryStream seed = new MemoryStream(EngineService.Convert(ConnectedModel(), "tm7"));
            ThreatModel model = ThreatModel.Load(seed);
            model.AllThreatsDictionary.Clear();
            using MemoryStream source = new MemoryStream();
            model.Save(source);
            byte[] original = source.ToArray();
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            TmForgeDiagramDto first = baseline.Diagrams!.Single();
            TmForgeElementDto extra = new TmForgeElementDto { Id = Guid.NewGuid().ToString("D"), Kind = "process", Name = "Extra", X = 600, Y = 100, Width = 120, Height = 60 };
            TmForgeModelDto added = new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = new MetaInformation { Owner = "Native owner" },
                Diagrams = new[]
                {
                    new TmForgeDiagramDto { Id = Guid.NewGuid().ToString("D"), Name = "New first page" },
                    new TmForgeDiagramDto
                    {
                        Id = first.Id,
                        Name = "Renamed page",
                        Elements = first.Elements!.Append(extra).Reverse().ToArray(),
                        Flows = new[] { new TmForgeFlowDto { Id = first.Flows![0].Id, Source = extra.Id, Target = first.Elements![1].Id, Name = "Reconnected", Properties = first.Flows[0].Properties } },
                    },
                },
            };

            byte[] saved = EngineService.SaveTm7(original, added);
            TmForgeModelDto restored = EngineService.ReadModel(saved, "tm7");
            Assert.AreEqual("New first page", restored.Diagrams![0].Name);
            Assert.AreEqual("Renamed page", restored.Diagrams[1].Name);
            Assert.AreEqual(extra.Id, restored.Diagrams[1].Elements![0].Id);
            Assert.AreEqual(extra.Id, restored.Diagrams[1].Flows![0].Source);
            Assert.AreEqual("Native owner", restored.Metadata!.Owner);
            using MemoryStream nativeResult = new MemoryStream(saved);
            ThreatModel native = ThreatModel.Load(nativeResult);
            Assert.HasCount(0, native.AllThreatsDictionary);
            TmForgeModelDto removed = new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = baseline.Metadata,
                Diagrams = new[] { new TmForgeDiagramDto { Id = first.Id, Name = "Remaining", Elements = new[] { extra } } },
            };
            byte[] reduced = EngineService.SaveTm7(saved, removed);
            TmForgeModelDto final = EngineService.ReadModel(reduced, "tm7");
            Assert.HasCount(1, final.Diagrams!);
            Assert.HasCount(1, final.Elements!);
            Assert.HasCount(0, final.Flows!);
            Assert.AreEqual(extra.Id, final.Elements![0].Id);
            XDocument initialXml = XDocument.Parse(Encoding.UTF8.GetString(original));
            XDocument finalXml = XDocument.Parse(Encoding.UTF8.GetString(reduced));
            Assert.IsTrue(XNode.DeepEquals(initialXml.Root!.Elements().Single(item => item.Name.LocalName == "KnowledgeBase"), finalXml.Root!.Elements().Single(item => item.Name.LocalName == "KnowledgeBase")));
        }

        /// <summary>Manual threat creation, editing and removal preserve unrelated native register entries.</summary>
        [TestMethod]
        public void SaveTm7SupportsExplicitManualThreatChanges()
        {
            byte[] original = EngineService.Convert(ConnectedModel(), "tm7");
            TmForgeModelDto baseline = EngineService.ReadModel(original, "tm7");
            const string Id = "manual:native-review";
            TmForgeModelDto WithThreat(ThreatStateDto? threat) => new TmForgeModelDto
            {
                Schema = baseline.Schema,
                Version = baseline.Version,
                Metadata = baseline.Metadata,
                Elements = baseline.Elements,
                Flows = baseline.Flows,
                Diagrams = baseline.Diagrams,
                Threats = threat == null ? null : new[] { threat },
            };
            byte[] added = EngineService.SaveTm7(original, WithThreat(new ThreatStateDto
            {
                Id = Id, Manual = true, Title = "Manual review", Category = "Spoofing", Priority = "High", ElementIds = new[] { baseline.Elements![0].Id },
            }));
            byte[] edited = EngineService.SaveTm7(added, WithThreat(new ThreatStateDto
            {
                Id = Id, Manual = true, Title = "Retitled review", Category = "Tampering", Priority = "Low", State = "Mitigated",
                Description = "Evidence", Mitigation = "Control", Justification = "Verified", ElementIds = new[] { baseline.Elements![0].Id },
            }));
            using MemoryStream editedStream = new MemoryStream(edited);
            Threat updated = ThreatModel.Load(editedStream).AllThreatsDictionary[Id];
            Assert.AreEqual("Retitled review", updated.Title);
            Assert.AreEqual("Tampering", updated.UserThreatCategory);
            Assert.AreEqual("Low", updated.Priority);
            Assert.AreEqual("Control", updated.Properties!["Mitigation"]);
            Assert.AreEqual(ThreatState.Mitigated, updated.State);
            byte[] removed = EngineService.SaveTm7(edited, WithThreat(null));
            using MemoryStream result = new MemoryStream(removed);
            using MemoryStream source = new MemoryStream(original);
            Assert.AreEqual(JsonSerializer.Serialize(ThreatModel.Load(source).AllThreatsDictionary), JsonSerializer.Serialize(ThreatModel.Load(result).AllThreatsDictionary));
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
        [DataRow("threat-dragon")]
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

        /// <summary>The engine preserves empty-page provenance and does not rerun rules during export.</summary>
        [TestMethod]
        public void ThreatDragonExportPreservesEmptyPageProvenance()
        {
            const string json = "{\"version\":\"2.6.2\",\"summary\":{\"title\":\"Empty review\"},\"detail\":{\"diagrams\":[{\"id\":7,\"title\":\"Privacy\",\"diagramType\":\"LINDDUN\",\"cells\":[]}]}}";
            TmForgeModelDto imported = EngineService.ReadModel(Encoding.UTF8.GetBytes(json), "threat-dragon");
            TmForgeModelDto canonical = EngineService.ReadModel(EngineService.Convert(imported, "tmforge-json"), "tmforge-json");

            byte[] first = EngineService.Convert(canonical, "threat-dragon");
            byte[] second = EngineService.Convert(canonical, "threat-dragon");
            TmForgeModelDto restored = EngineService.ReadModel(first, "threat-dragon");

            CollectionAssert.AreEqual(first, second);
            Assert.AreEqual(imported.Diagrams![0].Id, restored.Diagrams![0].Id);
            Assert.AreEqual("7", restored.Diagrams[0].Source?["id"]);
            Assert.AreEqual("LINDDUN", restored.Diagrams[0].Source?["modelType"]);
            Assert.IsTrue(restored.Threats == null || restored.Threats.Count == 0);
        }

        /// <summary>Rule selections cannot be silently lost through the direct engine export API.</summary>
        [TestMethod]
        public void ThreatDragonExportRejectsRuleSelectionsBeforeWriting()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Analysis = new TmForgeAnalysisDto { DisabledPacks = new[] { "identity-access" } },
            };
            using MemoryStream output = new MemoryStream();

            NotSupportedException error = Assert.Throws<NotSupportedException>(() => EngineService.WriteConverted(model, "threat-dragon", output));

            StringAssert.Contains(error.Message, "analysis");
            Assert.AreEqual(0L, output.Length);
            Assert.IsTrue(output.CanWrite);
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
            Assert.IsFalse(result.CanRecover);
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
            Assert.AreEqual("conversion.unsupported-target", DocumentPreflight.Inspect(model, targetFormat: "unknown-format").Diagnostics.Last().Code);
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

        /// <summary>Preflight reports notes lost by diagram formats and refuses unsupported Threat Dragon notes.</summary>
        /// <param name="target">The target format.</param>
        /// <param name="code">The expected diagnostic, or empty when notes are preserved.</param>
        /// <param name="success">Whether conversion remains available.</param>
        [TestMethod]
        [DataRow("drawio", "conversion.notes", true)]
        [DataRow("vsdx", "conversion.notes", true)]
        [DataRow("threat-dragon", "conversion.threat-dragon.unsupported", false)]
        [DataRow("tm7", "", true)]
        public void PreflightModelNotesConversion(string target, string code, bool success)
        {
            TmForgeModelDto model = WithNotes(ConnectedModel(), new[] { new Note { Id = 1, Message = "Keep this note" } });
            byte[] bytes = EngineService.Convert(model, "tmforge-json");

            PreflightResultDto result = DocumentPreflight.Inspect(bytes, targetFormat: target);

            Assert.AreEqual(success, result.Success);
            if (code.Length > 0)
            {
                Assert.IsTrue(result.Diagnostics.Any(item => item.Code == code && item.Message.Contains("notes", StringComparison.Ordinal)));
            }
            else
            {
                Assert.IsFalse(result.Diagnostics.Any(item => item.Path == "$.notes"));
            }
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
            Assert.IsFalse(new PreflightResultDto { Format = "tm7", Diagnostics = diagnostics }.CanRecover);
        }

        /// <summary>Only a TM7 import with unresolved endpoints alone offers an explicit recovery copy.</summary>
        [TestMethod]
        public void PreflightOffersRecoveryWithoutRelaxingStrictValidation()
        {
            ThreatModel model = new ThreatModel();
            DrawingSurfaceModel page = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Recovery" };
            Connector flow = new Connector { Guid = Guid.NewGuid(), SourceGuid = Guid.Empty, TargetGuid = Guid.NewGuid() };
            page.Lines.Add(flow.Guid, flow);
            model.DrawingSurfaceList.Add(page);
            using MemoryStream stream = new MemoryStream();
            model.Save(stream);
            byte[] source = stream.ToArray();

            PreflightResultDto result = DocumentPreflight.Inspect(source, targetFormat: "tmforge-json");

            Assert.IsFalse(result.Success);
            Assert.IsTrue(result.CanRecover);
            Assert.IsTrue(DocumentPreflight.Inspect(source).CanRecover);
            Assert.IsFalse(DocumentPreflight.Inspect(source, targetFormat: "tm7").CanRecover);
            Assert.IsFalse(new PreflightResultDto { Format = "drawio", Diagnostics = result.Diagnostics }.CanRecover);
            Assert.IsFalse(new PreflightResultDto { Format = "tm7" }.CanRecover);
            CollectionAssert.AreEqual(source, stream.ToArray());
        }

        /// <summary>Recovery preserves valid pages and identities while omitting broken flows and scoped threats only.</summary>
        /// <param name="crossPage">Whether the broken endpoint belongs to another page rather than being unattached.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void RecoverTm7ProducesSeparateValidatedCopy(bool crossPage)
        {
            ThreatModel model = new ThreatModel();
            DrawingSurfaceModel page = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Context" };
            DrawingSurfaceModel otherPage = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Details" };
            model.DrawingSurfaceList.Add(page);
            model.DrawingSurfaceList.Add(otherPage);
            DiagramEditor editor = new DiagramEditor(model);
            Guid source = editor.AddElement(page, StencilKind.Process, 30, 40);
            Guid target = editor.AddElement(page, StencilKind.DataStore, 350, 40);
            Guid otherTarget = editor.AddElement(otherPage, StencilKind.Process, 60, 80);
            Guid validFlow = editor.AddConnector(page, source, target);
            Guid brokenFlow = editor.AddConnector(page, source, target);
            ((Connector)page.Lines[brokenFlow]).TargetGuid = crossPage ? otherTarget : Guid.Empty;
            DiagramElementHelper.SetName((Connector)page.Lines[brokenFlow], "Create MOBO Resource");
            model.AllThreatsDictionary.Add("manual:kept", new Threat
            {
                Id = 1, InteractionKey = "manual:kept", Title = "Retained decision", SourceGuid = source,
                State = ThreatState.NotApplicable, StateInformation = "Reviewed control",
            });
            model.AllThreatsDictionary.Add("manual:omitted", new Threat
            {
                Id = 2, InteractionKey = "manual:omitted", Title = "Broken flow decision", FlowGuid = brokenFlow,
            });
            using MemoryStream stream = new MemoryStream();
            model.Save(stream);
            byte[] bytes = stream.ToArray();
            byte[] original = bytes.ToArray();

            TmForgeModelDto recovered = EngineService.RecoverTm7(bytes);

            Assert.HasCount(2, recovered.Diagrams!);
            Assert.AreEqual(page.Guid.ToString("D"), recovered.Diagrams![0].Id);
            Assert.AreEqual("Context", recovered.Diagrams[0].Name);
            Assert.AreEqual("Details", recovered.Diagrams[1].Name);
            Assert.HasCount(2, recovered.Elements!);
            Assert.AreEqual(30, recovered.Elements!.Single(element => element.Id == source.ToString("D")).X);
            Assert.HasCount(1, recovered.Flows!);
            Assert.AreEqual(validFlow.ToString("D"), recovered.Flows![0].Id);
            Assert.AreEqual(validFlow.ToString("D"), recovered.Diagrams[0].Flows!.Single().Id);
            Assert.AreEqual(otherTarget.ToString("D"), recovered.Diagrams[1].Elements!.Single().Id);
            Assert.AreEqual("manual:kept", recovered.Threats!.Single().Id);
            Assert.AreEqual("Accepted", recovered.Threats!.Single().State);
            Assert.IsTrue(DocumentPreflight.Inspect(EngineService.Convert(recovered, "tmforge-json")).Success);
            Assert.IsFalse(EngineService.RunAnalysis(recovered, null).Findings.Any(finding => finding.RuleId == "engine-error"));
            Assert.IsTrue(DocumentPreflight.Inspect(bytes).CanRecover);
            CollectionAssert.AreEqual(original, bytes);
        }

        /// <summary>Recovery never bypasses parsing, size, identity or diagnostic completeness checks.</summary>
        [TestMethod]
        public void RecoverTm7RefusesOtherFailures()
        {
            Assert.Throws<ArgumentNullException>(() => EngineService.RecoverTm7(null!));
            Assert.Throws<InvalidDataException>(() => EngineService.RecoverTm7(Encoding.UTF8.GetBytes("<ThreatModel>")));
            Assert.Throws<InvalidDataException>(() => EngineService.RecoverTm7(new byte[JsonDocumentPreflight.MaxBytes + 1]));
            Assert.Throws<InvalidDataException>(() => EngineService.RecoverTm7(Encoding.UTF8.GetBytes("{\"schema\":\"tmforge-json\"}")));
            ThreatModel model = new ThreatModel();
            DrawingSurfaceModel page = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            model.DrawingSurfaceList.Add(page);
            Connector flow = new Connector { Guid = page.Guid };
            page.Lines.Add(flow.Guid, flow);
            using MemoryStream duplicate = new MemoryStream();
            model.Save(duplicate);
            Assert.Throws<InvalidDataException>(() => EngineService.RecoverTm7(duplicate.ToArray()));

            page.Lines.Clear();
            for (int index = 0; index <= JsonDocumentPreflight.MaxDiagnostics; index++)
            {
                Connector detached = new Connector { Guid = Guid.NewGuid() };
                page.Lines.Add(detached.Guid, detached);
            }

            using MemoryStream truncated = new MemoryStream();
            model.Save(truncated);
            Assert.Throws<InvalidDataException>(() => EngineService.RecoverTm7(truncated.ToArray()));
        }

        /// <summary>Text diagrams use shared preflight, analysis and native export without inventing controls.</summary>
        /// <param name="format">The source provider.</param>
        /// <param name="source">A small boundary-crossing service diagram.</param>
        [TestMethod]
        [DataRow("mermaid", "flowchart LR\ncaller[Caller]:::external\nsubgraph zone[Service]\napi[API] --> db[(Database)]\nend\ncaller -->|HTTPS| api")]
        [DataRow("dot", "digraph G { caller[label=\"Caller\",kind=external]; subgraph cluster_zone { label=\"Service\"; api[label=\"API\"]; db[label=\"Database\",shape=cylinder]; api -> db; } caller -> api[label=\"HTTPS\"]; }")]
        public void TextDiagramImportsRemainAnalyzableAndStable(string format, string source)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(source);
            Assert.AreEqual(format, EngineService.Detect(bytes)?.Id);
            PreflightResultDto preflight = DocumentPreflight.Inspect(bytes, targetFormat: "tmforge-json");
            Assert.IsTrue(preflight.Success);
            Assert.AreEqual(format, preflight.Format);
            Assert.IsTrue(preflight.Diagnostics.Any(item => item.Code == "import.structural-mapping" && item.Severity == "warning"));
            StringAssert.Contains(preflight.Diagnostics.Single(item => item.Code == "import.structural-mapping").Message, "Unknown");
            TmForgeModelDto model = EngineService.ReadModel(bytes, null);
            Assert.HasCount(4, model.Elements!);
            Assert.HasCount(2, model.Flows!);
            Assert.AreEqual("Unknown", model.Flows!.Single(flow => flow.Name == "HTTPS").Properties["Protocol"]);
            AnalysisResultDto result = EngineService.RunAnalysis(model, null);
            Assert.IsFalse(result.Findings.Any(finding => finding.RuleId == "engine-error"));
            Assert.IsTrue(result.Findings.Any(finding => finding.Message.Contains("is not evidenced", StringComparison.Ordinal)));
            Assert.IsTrue(result.Threats.Any(threat => !threat.Manual));
            string first = JsonSerializer.Serialize(EngineService.DescribeAnalysis(model));
            string repeated = JsonSerializer.Serialize(EngineService.DescribeAnalysis(EngineService.ReadModel(bytes, null)));
            Assert.AreEqual(first, repeated);
            foreach (string destination in new[] { "tmforge-json", "tm7" })
            {
                TmForgeModelDto restored = EngineService.ReadModel(EngineService.Convert(model, destination), destination);
                CollectionAssert.AreEquivalent(model.Elements!.Select(element => element.Id).ToArray(), restored.Elements!.Select(element => element.Id).ToArray());
                CollectionAssert.AreEquivalent(model.Flows!.Select(flow => flow.Id).ToArray(), restored.Flows!.Select(flow => flow.Id).ToArray());
                Assert.AreEqual("Unknown", restored.Elements!.Single(element => element.Name == "API").Properties["AuthenticationScheme"]);
            }

            Assert.Throws<NotSupportedException>(() => EngineService.Convert(model, format));
            CollectionAssert.AreEqual(Encoding.UTF8.GetBytes(source), bytes);
        }

        /// <summary>Preflight returns actionable source locations for unsupported text syntax.</summary>
        /// <param name="format">The detected format.</param>
        /// <param name="source">The rejected graph.</param>
        /// <param name="reason">The named unsupported construct.</param>
        [TestMethod]
        [DataRow("mermaid", "flowchart LR\na --> b\nclick a callback", "click")]
        [DataRow("dot", "digraph G { a -> b [dir=both]; }", "direction")]
        public void TextDiagramPreflightRefusesPartialImports(string format, string source, string reason)
        {
            PreflightResultDto result = DocumentPreflight.Inspect(Encoding.UTF8.GetBytes(source));
            Assert.IsFalse(result.Success);
            Assert.AreEqual(format, result.Format);
            DocumentDiagnostic error = result.Diagnostics.Single(item => item.Severity == "error");
            Assert.AreEqual("input.unreadable", error.Code);
            StringAssert.Contains(error.Message, reason);
            StringAssert.Contains(error.Message, "line ");
            StringAssert.Contains(error.Message, "column ");
        }

        /// <summary>Read-only inspection retains line boundaries that the canonical projection omits.</summary>
        [TestMethod]
        public void InspectFilePreservesNativeLineBoundaries()
        {
            ThreatModel model = new ThreatModel();
            DrawingSurfaceModel page = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Native boundary" };
            model.DrawingSurfaceList.Add(page);
            DiagramEditor editor = new DiagramEditor(model);
            Guid source = editor.AddElement(page, StencilKind.ExternalEntity, 30, 50);
            Guid target = editor.AddElement(page, StencilKind.Process, 350, 50);
            editor.AddConnector(page, source, target);
            LineBoundary boundary = new LineBoundary
            {
                Guid = Guid.NewGuid(),
                TypeId = "GE.TB.L",
                GenericTypeId = "GE.TB.L",
                SourceX = 250,
                SourceY = 10,
                TargetX = 250,
                TargetY = 250,
            };
            DiagramElementHelper.SetName(boundary, "Native isolation boundary");
            page.Lines.Add(boundary.Guid, boundary);
            using MemoryStream stream = new MemoryStream();
            model.Save(stream);
            byte[] input = stream.ToArray();
            FileInspectionDto result = EngineService.InspectFile(input, "tm7");
            Assert.HasCount(1, result.Pages);
            System.Xml.Linq.XElement svg = System.Xml.Linq.XElement.Parse(result.Pages[0].Svg);
            Assert.AreEqual("M 250,10 Q 250,130 250,250", svg.Descendants().Single(element => element.Attribute("class")?.Value == "tmf-boundary").Attribute("d")?.Value);
            Assert.IsNotNull(result.Analysis);
            Assert.IsFalse(result.Analysis.Findings.Any(finding => finding.RuleId == "TM1004" || finding.Id == "engine-error"));
            Assert.IsTrue(result.Analysis.Findings.Any(finding => finding.ElementIds.Contains(source.ToString("D"))));
            CollectionAssert.AreEqual(input, stream.ToArray());
        }

        /// <summary>Canonical inspection retains rule selections, original ids and explicit missing-pack errors.</summary>
        [TestMethod]
        public void InspectFilePreservesCanonicalAnalysisSettings()
        {
            const string Json = "{\"schema\":\"tmforge-json\",\"version\":\"0.1\",\"elements\":[{\"id\":\"caller\",\"kind\":\"external\",\"name\":\"Caller\",\"x\":10,\"y\":10}],\"flows\":[],\"analysis\":{\"disabledRuleIds\":[\"TM1003\"],\"expectedPacks\":[{\"id\":\"missing\",\"fingerprint\":\"sha256:missing\"}]}}";
            FileInspectionDto result = EngineService.InspectFile(Encoding.UTF8.GetBytes(Json));
            Assert.AreEqual("tmforge-json", result.Format);
            Assert.IsNotNull(result.Analysis);
            Assert.IsFalse(result.Analysis.Findings.Any(finding => finding.Id == "engine-error" || finding.RuleId == "TM1003"));
            Assert.IsTrue(result.Analysis.Findings.Any(finding => finding.RuleId == "rule-pack-mismatch"));
            Assert.HasCount(1, result.Pages);
            Assert.AreEqual(JsonSerializer.Serialize(result), JsonSerializer.Serialize(EngineService.InspectFile(Encoding.UTF8.GetBytes(Json))));
        }

        /// <summary>Unusable input yields diagnostics rather than a partial preview or false clean analysis.</summary>
        [TestMethod]
        public void InspectFileRefusesMalformedInput()
        {
            FileInspectionDto result = EngineService.InspectFile(Encoding.UTF8.GetBytes("not a model"));
            Assert.HasCount(0, result.Pages);
            Assert.IsNull(result.Analysis);
            Assert.IsTrue(result.Diagnostics.Any(diagnostic => diagnostic.Severity == "error"));
        }

        /// <summary>Every page is rendered, and source labels remain inert XML text.</summary>
        [TestMethod]
        public void InspectFileRendersEveryPageWithEscapedLabels()
        {
            const string Label = "<script>alert('not executable')</script>";
            TmForgeModelDto model = new TmForgeModelDto
            {
                Diagrams = new[]
                {
                    new TmForgeDiagramDto
                    {
                        Id = "first", Name = "Context",
                        Elements = new[] { new TmForgeElementDto { Id = "api", Kind = "process", Name = Label, X = 10, Y = 10 } },
                    },
                    new TmForgeDiagramDto { Id = "second", Name = "Empty page" },
                },
            };
            byte[] bytes = EngineService.Convert(model, "tmforge-json");
            FileInspectionDto result = EngineService.InspectFile(bytes, "tmforge-json");
            Assert.HasCount(2, result.Pages);
            CollectionAssert.AreEqual(new[] { "Context", "Empty page" }, result.Pages.Select(page => page.Name).ToArray());
            System.Xml.Linq.XElement svg = System.Xml.Linq.XElement.Parse(result.Pages[0].Svg);
            Assert.IsFalse(svg.Descendants().Any(element => element.Name.LocalName == "script"));
            Assert.IsTrue(svg.Descendants().Any(element => element.Name.LocalName == "title" && element.Value == Label));
        }

        /// <summary>Native inspection rejects oversized workloads before rendering or rule evaluation.</summary>
        [TestMethod]
        public void InspectFileBoundsPageAndGraphWork()
        {
            TmForgeModelDto manyPages = new TmForgeModelDto
            {
                Diagrams = Enumerable.Range(0, 33).Select(index => new TmForgeDiagramDto { Id = "page" + index, Name = "Page" }).ToArray(),
            };
            byte[] pages = EngineService.Convert(manyPages, "tmforge-json");
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => EngineService.InspectFile(pages)).Message, "32 pages");
            TmForgeModelDto manyElements = new TmForgeModelDto
            {
                Elements = Enumerable.Range(0, 1025).Select(index => new TmForgeElementDto { Id = "element" + index, Kind = "process", X = 10, Y = 10 }).ToArray(),
            };
            byte[] elements = EngineService.Convert(manyElements, "tmforge-json");
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => EngineService.InspectFile(elements)).Message, "1024 elements");
        }

        private static TmForgeModelDto WithNotes(TmForgeModelDto model, IReadOnlyList<Note>? notes)
        {
            JsonNode document = JsonSerializer.SerializeToNode(model) ?? throw new InvalidOperationException();
            document["Notes"] = JsonSerializer.SerializeToNode(notes);
            return document.Deserialize<TmForgeModelDto>() ?? throw new InvalidOperationException();
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
