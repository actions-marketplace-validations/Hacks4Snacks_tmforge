namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Integration tests for the <c>tmforge threats</c> and <c>tmforge accept</c> commands: threats are
    /// the persisted, triaged view of the validation findings — persistence, idempotency, and
    /// acceptance through the real CLI entry points.
    /// </summary>
    [TestClass]
    public class ThreatsCommandTest
    {
        /// <summary>Gets or sets the working directory created for each test.</summary>
        private string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>Gets the path of the model created by <see cref="NewModelWithFlow"/>.</summary>
        private string ModelPath => Path.Join(this.WorkingDirectory, "model.tm7");

        /// <summary>Creates an isolated working directory for the test.</summary>
        [TestInitialize]
        public void Initialize()
        {
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-threats-" + Guid.NewGuid().ToString("N"));
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

        /// <summary>Threats are reported from the validation findings (an unauthenticated external → TM1023).</summary>
        [TestMethod]
        public void ThreatsReportsThreatsFromFindings()
        {
            string path = this.NewModelWithFlow();

            (int exit, string stdout) = Capture(() => ThreatsCommand.Run(new[] { path, "--json" }));

            Assert.AreEqual(0, exit);
            JsonElement data = JsonDocument.Parse(stdout).RootElement.GetProperty("data");
            Assert.IsTrue(data.GetProperty("summary").GetProperty("count").GetInt32() > 0);
            Assert.IsTrue(HasRule(data, "TM1023"));
        }

        /// <summary>Writing persists the threats into the model's register.</summary>
        [TestMethod]
        public void ThreatsWritePersistsRegister()
        {
            string path = this.NewModelWithFlow();

            (int exit, string stdout) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));

            Assert.AreEqual(0, exit);
            JsonElement data = JsonDocument.Parse(stdout).RootElement.GetProperty("data");
            int added = data.GetProperty("summary").GetProperty("written").GetProperty("added").GetInt32();
            Assert.IsTrue(added > 0);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.AreEqual(added, model.AllThreatsDictionary.Count);
            foreach (Threat threat in model.AllThreatsDictionary.Values)
            {
                Assert.IsNotNull(threat.TypeId);
                Assert.AreEqual(threat.Title, threat.Properties!["Title"]);
                Assert.AreEqual(threat.Priority, threat.Properties["Priority"]);
                Assert.IsTrue(threat.Properties.Keys.All(name =>
                    model.KnowledgeBase!.ThreatMetaData!.PropertiesMetaData.Any(datum => datum.Name == name)));
            }
        }

        /// <summary>Custom threat metadata remains referentially complete in the written TM7 knowledge base.</summary>
        [TestMethod]
        public void ThreatsWriteEmbedsCustomCategoryAndType()
        {
            string path = this.NewModelWithFlow();
            string specPath = Path.Join(this.WorkingDirectory, "privacy.tmrules.json");
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
                "\"pack\":{\"id\":\"medical\",\"name\":\"Medical\"}," +
                "\"categories\":[{\"id\":\"privacy\",\"name\":\"Privacy\"}]," +
                "\"elementTypes\":[],\"properties\":[]," +
                "\"rules\":[{\"id\":\"PRIV-1\",\"categoryId\":\"privacy\"," +
                "\"defaultPriority\":\"High\",\"appliesTo\":\"process\",\"message\":\"Privacy risk\"," +
                "\"assert\":{\"property\":\"PrivacyReviewed\",\"present\":true}," +
                "\"provenance\":{\"sourceId\":\"PRIV-1\",\"categoryId\":\"raw-privacy\"}}]}";
            File.WriteAllText(specPath, spec);

            (int exit, string stdout) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--rules", specPath, "--write", "--json",
            }));

            Assert.AreEqual(0, exit);
            JsonElement threats = JsonDocument.Parse(stdout).RootElement.GetProperty("data").GetProperty("threats");
            JsonElement privacy = threats.EnumerateArray().Single(
                threat => threat.GetProperty("ruleId").GetString() == "medical/PRIV-1");
            Assert.AreEqual("Privacy", privacy.GetProperty("category").GetString());
            Assert.AreEqual("medical/privacy", privacy.GetProperty("categoryId").GetString());
            Assert.AreEqual("Privacy", privacy.GetProperty("categoryName").GetString());
            Assert.AreEqual(JsonValueKind.Null, privacy.GetProperty("stride").ValueKind);
            Assert.AreEqual("High", privacy.GetProperty("priority").GetString());

            (int humanExit, string humanOutput) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--rules", specPath,
            }));
            Assert.AreEqual(0, humanExit);
            StringAssert.Contains(humanOutput, "[Privacy] medical/PRIV-1");
            Assert.IsFalse(humanOutput.Contains("[?] medical/PRIV-1", StringComparison.Ordinal));

            (ThreatModel model, _) = CliModelLoader.Load(path);
            Threat persisted = model.AllThreatsDictionary.Values.Single(threat => threat.TypeId == "medical/PRIV-1");
            ThreatType type = model.KnowledgeBase!.ThreatTypes.Single(threat => threat.Id == persisted.TypeId);
            Assert.AreEqual("medical/privacy", type.Category);
            Assert.IsTrue(model.KnowledgeBase.ThreatCategories.Any(category => category.Id == type.Category));
            Assert.AreEqual("medical/privacy", persisted.Properties!["CategoryId"]);

            string processId = model.DrawingSurfaceList.Single().Borders.Values
                .OfType<StencilEllipse>().Single().Guid.ToString();
            (int renameExit, _) = Capture(() => RenameCommand.Run(new[]
            {
                path, "--id", processId, "--name", "Renamed gateway",
            }));
            Assert.AreEqual(0, renameExit);

            (ThreatModel renamed, _) = CliModelLoader.Load(path);
            Threat renamedThreat = renamed.AllThreatsDictionary.Values.Single(
                threat => threat.TypeId == "medical/PRIV-1");
            ThreatType renamedType = renamed.KnowledgeBase!.ThreatTypes.Single(
                threat => threat.Id == renamedThreat.TypeId);
            Assert.AreEqual("medical/privacy", renamedType.Category);
            ThreatCategory renamedCategory = renamed.KnowledgeBase.ThreatCategories.Single(
                category => category.Id == renamedType.Category);
            Assert.AreEqual("Privacy", renamedCategory.Name);
            Assert.AreEqual("medical/privacy", renamedThreat.Properties!["CategoryId"]);
        }

        /// <summary>Writing twice is idempotent — nothing is added the second time.</summary>
        [TestMethod]
        public void ThreatsWriteIsIdempotent()
        {
            string path = this.NewModelWithFlow();
            Capture(() => ThreatsCommand.Run(new[] { path, "--write" }));

            (int exit, string stdout) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));

            Assert.AreEqual(0, exit);
            JsonElement data = JsonDocument.Parse(stdout).RootElement.GetProperty("data");
            Assert.AreEqual(0, data.GetProperty("summary").GetProperty("written").GetProperty("added").GetInt32());
        }

        /// <summary>JSON write output reports the effective persisted priority override.</summary>
        [TestMethod]
        public void ThreatsWriteJsonReportsPersistedPriorityOverride()
        {
            string path = this.NewModelWithFlow();
            (_, string firstOutput) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(firstOutput).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;
            (int editExit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--edit", id, "--priority", "Low",
            }));
            Assert.AreEqual(0, editExit);

            (int exit, string output) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));

            Assert.AreEqual(0, exit);
            JsonElement threat = JsonDocument.Parse(output).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().Single(candidate => candidate.GetProperty("id").GetString() == id);
            Assert.AreEqual("Low", threat.GetProperty("priority").GetString());
            (ThreatModel persisted, _) = CliModelLoader.Load(path);
            Assert.AreEqual("Low", persisted.AllThreatsDictionary[id].Priority);
        }

        /// <summary>Accepting a persisted threat marks it not-applicable with the justification.</summary>
        [TestMethod]
        public void AcceptMarksThreatNotApplicable()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            JsonElement data = JsonDocument.Parse(writeOut).RootElement.GetProperty("data");
            string id = data.GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (int exit, _) = Capture(() => AcceptCommand.Run(new[] { path, "--threat", id, "--reason", "Accepted for test" }));

            Assert.AreEqual(0, exit);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.IsTrue(model.AllThreatsDictionary.TryGetValue(id, out Threat? threat));
            Assert.AreEqual(ThreatState.NotApplicable, threat!.State);
            Assert.AreEqual("Accepted for test", threat.StateInformation);
        }

        /// <summary>Accepting without a reason is reported as an error.</summary>
        [TestMethod]
        public void AcceptWithoutReasonReturnsError()
        {
            string path = this.NewModelWithFlow();

            (int exit, _) = Capture(() => AcceptCommand.Run(new[] { path, "--threat", "anything" }));

            Assert.AreEqual(1, exit);
        }

        /// <summary>Adding a manual threat persists it into the register keyed <c>manual:{guid}</c>.</summary>
        [TestMethod]
        public void ThreatsAddCreatesManualThreat()
        {
            string path = this.NewModelWithFlow();

            (int exit, string stdout) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--title", "Admin actions are not logged", "--category", "Repudiation", "--priority", "High", "--json",
            }));

            Assert.AreEqual(0, exit);
            JsonElement data = JsonDocument.Parse(stdout).RootElement.GetProperty("data");
            string id = data.GetProperty("id").GetString() ?? string.Empty;
            Assert.IsTrue(id.StartsWith("manual:", StringComparison.Ordinal));
            Assert.AreEqual("Repudiation", data.GetProperty("category").GetString());

            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.IsTrue(model.AllThreatsDictionary.TryGetValue(id, out Threat? threat));
            Assert.AreEqual("Admin actions are not logged", threat!.Title);
            Assert.AreEqual("Repudiation", threat.UserThreatCategory);
            Assert.AreEqual(ManualThreatId.ToNativeTypeId(id), threat.TypeId);
            Assert.AreEqual("High", threat.Priority);
            Assert.AreEqual(threat.Title, threat.Properties!["Title"]);
            Assert.AreEqual(threat.UserThreatCategory, threat.Properties["UserThreatCategory"]);
            Assert.AreEqual(threat.Priority, threat.Properties["Priority"]);
            Assert.AreEqual(1, model.AllThreatsDictionary.Count);
        }

        /// <summary>Native finding properties follow edits and explicit clears without changing identity.</summary>
        [TestMethod]
        public void ThreatsEditUpdatesAndClearsNativeFindingProperties()
        {
            string path = this.NewModelWithFlow();
            (int added, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--id", "native-edit", "--title", "Original", "--category", "Tampering",
                "--description", "Original description", "--mitigation", "Original mitigation",
            }));
            Assert.AreEqual(0, added);
            (int revised, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--edit", "manual:native-edit", "--title", "Revised", "--priority", "Low",
                "--description", "Revised description", "--mitigation", "Revised mitigation",
            }));
            Assert.AreEqual(0, revised);
            (ThreatModel edited, _) = CliModelLoader.Load(path);
            Threat threat = edited.AllThreatsDictionary["manual:native-edit"];
            Assert.AreEqual("Revised", threat.Properties!["Title"]);
            Assert.AreEqual("Low", threat.Properties["Priority"]);
            Assert.AreEqual("Revised description", threat.Properties["UserThreatDescription"]);
            Assert.AreEqual("Revised mitigation", threat.Properties["Mitigation"]);
            string? nativeId = threat.TypeId;

            (int removed, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--edit", "manual:native-edit", "--description", string.Empty, "--mitigation", string.Empty,
            }));
            Assert.AreEqual(0, removed);
            (ThreatModel cleared, _) = CliModelLoader.Load(path);
            Threat clearedThreat = cleared.AllThreatsDictionary["manual:native-edit"];
            Assert.AreEqual(nativeId, clearedThreat.TypeId);
            Assert.IsNull(clearedThreat.UserThreatDescription);
            Assert.IsFalse(clearedThreat.Properties!.ContainsKey("UserThreatDescription"));
            Assert.IsFalse(clearedThreat.Properties.ContainsKey("Mitigation"));
        }

        /// <summary>A scoped manual threat belongs to its target's page, not the first page.</summary>
        /// <param name="flowScope">Whether the scope is a flow rather than a process.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void ThreatsAddUsesScopedObjectsPage(bool flowScope)
        {
            string path = this.NewModelWithFlow();
            (ThreatModel model, _) = CliModelLoader.Load(path);
            DrawingSurfaceModel scopedPage = model.DrawingSurfaceList.Single();
            Guid scope = flowScope
                ? scopedPage.Lines.Keys.Single()
                : scopedPage.Borders.Values.OfType<StencilEllipse>().Single().Guid;
            model.DrawingSurfaceList.Insert(0, new DrawingSurfaceModel
            {
                Guid = Guid.NewGuid(),
                Header = "Unrelated page",
            });
            model.Save(path);

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--id", "page-scope", "--title", "Scoped finding",
                "--category", "Tampering", "--scope", scope.ToString(), "--json",
            }));

            Assert.AreEqual(0, exit);
            (ThreatModel saved, _) = CliModelLoader.Load(path);
            Threat threat = saved.AllThreatsDictionary["manual:page-scope"];
            Assert.AreEqual(scopedPage.Guid, threat.DrawingSurfaceGuid);
            Assert.AreEqual(scope, threat.SourceGuid);
            Assert.IsFalse(threat.Wide);
        }

        /// <summary>
        /// <c>--id</c> lets the author key the threat themselves, so the same authoring command can be
        /// re-run and the id can be referenced from outside the model.
        /// </summary>
        [TestMethod]
        public void ThreatsAddAcceptsAuthorSuppliedId()
        {
            string path = this.NewModelWithFlow();

            (int exit, string stdout) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--id", "unlogged-admin-actions", "--title", "Admin actions are not logged",
                "--category", "Repudiation", "--json",
            }));

            Assert.AreEqual(0, exit);
            JsonElement data = JsonDocument.Parse(stdout).RootElement.GetProperty("data");
            Assert.AreEqual("manual:unlogged-admin-actions", data.GetProperty("id").GetString());

            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.IsTrue(model.AllThreatsDictionary.ContainsKey("manual:unlogged-admin-actions"));
        }

        /// <summary>A malformed <c>--id</c> is refused before anything is written.</summary>
        [TestMethod]
        public void ThreatsAddRejectsMalformedId()
        {
            string path = this.NewModelWithFlow();

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--id", "not a valid id", "--title", "Anything", "--category", "Repudiation",
            }));

            Assert.AreEqual(1, exit);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.AreEqual(0, model.AllThreatsDictionary.Count, "Nothing may be written when the id is refused.");
        }

        /// <summary>Re-using an existing id is refused, leaving the original threat untouched.</summary>
        [TestMethod]
        public void ThreatsAddRejectsDuplicateId()
        {
            string path = this.NewModelWithFlow();
            Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--id", "dup", "--title", "First", "--category", "Repudiation",
            }));

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--id", "dup", "--title", "Second", "--category", "Repudiation",
            }));

            Assert.AreEqual(1, exit);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.AreEqual(1, model.AllThreatsDictionary.Count);
            Assert.AreEqual("First", model.AllThreatsDictionary["manual:dup"].Title);
        }

        /// <summary>Editing a rule threat changes its state, priority, and description in the register.</summary>
        [TestMethod]
        public void ThreatsEditChangesRuleThreatState()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(writeOut).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--edit", id, "--state", "Mitigated", "--priority", "Low", "--description", "Handled by the mesh.",
            }));

            Assert.AreEqual(0, exit);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.IsTrue(model.AllThreatsDictionary.TryGetValue(id, out Threat? threat));
            Assert.AreEqual(ThreatState.Mitigated, threat!.State);
            Assert.AreEqual("Low", threat.Priority);
            Assert.AreEqual("Handled by the mesh.", threat.UserThreatDescription);
            Assert.AreEqual(threat.Priority, threat.Properties!["Priority"]);
            Assert.AreEqual(threat.UserThreatDescription, threat.Properties["UserThreatDescription"]);
        }

        /// <summary>
        /// Retitling a rule threat records the author's wording and survives the register being
        /// rewritten, which is what every later `--write` does.
        /// </summary>
        [TestMethod]
        public void ThreatsEditRetitlesARuleThreatAndTheTitleSurvivesRegeneration()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(writeOut).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[] { path, "--edit", id, "--title", "Unauthenticated ledger write" }));
            Assert.AreEqual(0, exit);

            Assert.AreEqual(0, ThreatsCommand.Run(new[] { path, "--write" }));

            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.IsTrue(model.AllThreatsDictionary.TryGetValue(id, out Threat? threat));
            Assert.AreEqual("Unauthenticated ledger write", threat!.Title);
            Assert.AreEqual(threat.Title, threat.Properties!["Title"]);
        }

        /// <summary>Clearing the title hands the threat back to its rule, so the edit is reversible.</summary>
        [TestMethod]
        public void ThreatsEditClearingATitleRestoresTheRuleWording()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(writeOut).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (ThreatModel before, _) = CliModelLoader.Load(path);
            string generated = before.AllThreatsDictionary[id].Title ?? string.Empty;

            Capture(() => ThreatsCommand.Run(new[] { path, "--edit", id, "--title", "Something else" }));
            (int exit, _) = Capture(() => ThreatsCommand.Run(new[] { path, "--edit", id, "--title", string.Empty }));

            Assert.AreEqual(0, exit);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.AreEqual(generated, model.AllThreatsDictionary[id].Title);
        }

        /// <summary>A rule threat's category is the rule's, so the CLI refuses rather than ignores it.</summary>
        [TestMethod]
        public void ThreatsEditRefusesACategoryOnARuleThreat()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(writeOut).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[] { path, "--edit", id, "--category", "Tampering" }));

            Assert.AreEqual(1, exit);
        }

        /// <summary>CLI priority edits canonicalize casing and reject values outside the wire catalog.</summary>
        [TestMethod]
        public void ThreatsPriorityMustBeCanonicalValue()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(writeOut).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (int canonicalExit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--edit", id, "--priority", "low",
            }));
            Assert.AreEqual(0, canonicalExit);
            (ThreatModel canonical, _) = CliModelLoader.Load(path);
            Assert.AreEqual("Low", canonical.AllThreatsDictionary[id].Priority);

            (int invalidExit, _) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--edit", id, "--priority", "Urgent",
            }));
            Assert.AreEqual(1, invalidExit);
            (ThreatModel unchanged, _) = CliModelLoader.Load(path);
            Assert.AreEqual("Low", unchanged.AllThreatsDictionary[id].Priority);
        }

        /// <summary>Removing a manual threat deletes it from the register.</summary>
        [TestMethod]
        public void ThreatsRemoveDeletesManualThreat()
        {
            string path = this.NewModelWithFlow();
            (int addExit, string addOut) = Capture(() => ThreatsCommand.Run(new[]
            {
                path, "--add", "--title", "Hand-authored", "--category", "Tampering", "--json",
            }));
            Assert.AreEqual(0, addExit);
            string id = JsonDocument.Parse(addOut).RootElement.GetProperty("data").GetProperty("id").GetString() ?? string.Empty;

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[] { path, "--remove", id }));

            Assert.AreEqual(0, exit);
            (ThreatModel model, _) = CliModelLoader.Load(path);
            Assert.IsFalse(model.AllThreatsDictionary.ContainsKey(id));
        }

        /// <summary>A rule threat cannot be removed — it regenerates from the rules.</summary>
        [TestMethod]
        public void ThreatsRemoveRuleThreatIsRejected()
        {
            string path = this.NewModelWithFlow();
            (_, string writeOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--write", "--json" }));
            string id = JsonDocument.Parse(writeOut).RootElement.GetProperty("data")
                .GetProperty("threats").EnumerateArray().First().GetProperty("id").GetString() ?? string.Empty;

            (int exit, _) = Capture(() => ThreatsCommand.Run(new[] { path, "--remove", id }));

            Assert.AreEqual(1, exit);
        }

        /// <summary>
        /// Pruning keeps a stale entry that carries triage and names it, so a recorded decision is
        /// never lost just because its rule went quiet. <c>--force</c> is the explicit way to drop it.
        /// </summary>
        [TestMethod]
        public void RemoveStaleKeepsTriagedEntriesUntilForced()
        {
            Capture(() => NewCommand.Run(new[] { this.ModelPath, "--name", "Stale Test" }));
            string external = this.AddElement("external", "Client");
            string process = this.AddElement("process", "Gateway");
            this.Connect(external, process);
            string path = this.ModelPath;
            Assert.AreEqual(0, ThreatsCommand.Run(new[] { path, "--write" }));

            (ThreatModel written, _) = CliModelLoader.Load(path);
            Threat target = written.AllThreatsDictionary.Values.First(threat => !string.IsNullOrEmpty(threat.TypeId));
            string key = target.InteractionKey!;
            Assert.AreEqual(0, ThreatsCommand.Run(new[] { path, "--edit", key, "--state", "Mitigated" }));

            // Delete the elements the findings were about. The rules stay loaded and enabled, they
            // simply produce nothing now, which is what makes the stored entries stale rather than
            // unevaluated.
            Capture(() => RemoveCommand.Run(new[] { path, "--id", process }));
            Capture(() => RemoveCommand.Run(new[] { path, "--id", external }));

            (int kept, string keptOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--remove-stale", "--json" }));
            Assert.AreEqual(0, kept);
            JsonElement data = JsonDocument.Parse(keptOut).RootElement.GetProperty("data");
            Assert.AreEqual("remove-stale", data.GetProperty("action").GetString());
            Assert.IsTrue(
                data.GetProperty("retainedWithTriage").EnumerateArray().Any(id => id.GetString() == key),
                "The triaged entry must be reported, not removed.");

            (ThreatModel afterKeep, _) = CliModelLoader.Load(path);
            Assert.IsTrue(afterKeep.AllThreatsDictionary.Values.Any(threat => threat.InteractionKey == key));

            (int forced, string forcedOut) = Capture(() => ThreatsCommand.Run(new[] { path, "--remove-stale", "--force", "--json" }));
            Assert.AreEqual(0, forced);
            JsonElement forcedData = JsonDocument.Parse(forcedOut).RootElement.GetProperty("data");
            Assert.IsTrue(forcedData.GetProperty("removed").EnumerateArray().Any(id => id.GetString() == key));

            (ThreatModel afterForce, _) = CliModelLoader.Load(path);
            Assert.IsFalse(afterForce.AllThreatsDictionary.Values.Any(threat => threat.InteractionKey == key));
        }

        private static (int Exit, string Stdout) Capture(Func<int> run)
        {
            using StringWriter outWriter = new StringWriter();
            using StringWriter errorWriter = new StringWriter();
            TextWriter originalOut = Console.Out;
            TextWriter originalError = Console.Error;
            Console.SetOut(outWriter);
            Console.SetError(errorWriter);
            try
            {
                int exit = run();
                return (exit, outWriter.ToString());
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalError);
            }
        }

        private static bool HasRule(JsonElement data, string ruleId)
        {
            foreach (JsonElement threat in data.GetProperty("threats").EnumerateArray()
                .Where(threat => threat.GetProperty("ruleId").GetString() == ruleId))
            {
                return true;
            }

            return false;
        }

        private string NewModelWithFlow()
        {
            Capture(() => NewCommand.Run(new[] { this.ModelPath, "--name", "Threats Test" }));
            string external = this.AddElement("external", "Client");
            string process = this.AddElement("process", "Gateway");
            this.Connect(external, process);
            return this.ModelPath;
        }

        private string AddElement(string kind, string name)
        {
            (int exit, string stdout) = Capture(() => AddCommand.Run(new[] { kind, this.ModelPath, "--name", name, "--json" }));
            Assert.AreEqual(0, exit);
            return JsonDocument.Parse(stdout).RootElement.GetProperty("data").GetProperty("id").GetGuid().ToString();
        }

        private string Connect(string source, string target)
        {
            (int exit, string stdout) = Capture(() => ConnectCommand.Run(new[] { this.ModelPath, "--source", source, "--target", target, "--json" }));
            Assert.AreEqual(0, exit);
            return JsonDocument.Parse(stdout).RootElement.GetProperty("data").GetProperty("id").GetGuid().ToString();
        }
    }
}
