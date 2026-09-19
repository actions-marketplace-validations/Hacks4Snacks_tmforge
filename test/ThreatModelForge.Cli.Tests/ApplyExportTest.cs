namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for the declarative manifest verbs (<c>tmforge apply</c> and <c>tmforge export</c>).
    /// </summary>
    [TestClass]
    public class ApplyExportTest
    {
        private const string SampleManifest =
            "{\"name\":\"T\",\"boundaries\":[{\"alias\":\"TB\",\"name\":\"Edge\"}]," +
            "\"elements\":[" +
            "{\"alias\":\"P1\",\"kind\":\"process\",\"name\":\"Proc\",\"boundary\":\"TB\"}," +
            "{\"alias\":\"DS\",\"kind\":\"store\",\"name\":\"Store\",\"boundary\":\"TB\"}," +
            "{\"alias\":\"EXT\",\"kind\":\"external\",\"name\":\"Client\"}]," +
            "\"flows\":[{\"from\":\"EXT\",\"to\":\"P1\",\"name\":\"call\",\"props\":{\"Protocol\":\"HTTPS\"}}," +
            "{\"from\":\"P1\",\"to\":\"DS\",\"name\":\"write\"}]}";

        /// <summary>Two flows the structural key cannot tell apart: same endpoints, same name.</summary>
        private const string DuplicateFlowManifest =
            "{\"name\":\"T\",\"elements\":[" +
            "{\"alias\":\"a\",\"kind\":\"external\",\"name\":\"Client\"}," +
            "{\"alias\":\"b\",\"kind\":\"process\",\"name\":\"Service\"}]," +
            "\"flows\":[{\"from\":\"a\",\"to\":\"b\",\"name\":\"Call\"}," +
            "{\"from\":\"a\",\"to\":\"b\",\"name\":\"Call\"}]}";

        /// <summary>A flow carrying its own alias.</summary>
        private const string AliasedFlowManifest =
            "{\"name\":\"T\",\"elements\":[" +
            "{\"alias\":\"a\",\"kind\":\"external\",\"name\":\"Client\"}," +
            "{\"alias\":\"b\",\"kind\":\"process\",\"name\":\"Service\"}]," +
            "\"flows\":[{\"alias\":\"primary\",\"from\":\"a\",\"to\":\"b\",\"name\":\"Request\"}]}";

        /// <summary>A manifest declaring no aliases at all — every id has to come from a structural key.</summary>
        private const string NoAliasManifest =
            "{\"name\":\"T\",\"boundaries\":[{\"name\":\"Edge\"}]," +
            "\"elements\":[" +
            "{\"kind\":\"external\",\"name\":\"Client\"}," +
            "{\"kind\":\"process\",\"name\":\"Service\"}]," +
            "\"flows\":[{\"from\":\"Client\",\"to\":\"Service\",\"name\":\"Call\"}]}";

        /// <summary>
        /// An alias written to look exactly like the structural key of another element. Both are
        /// author-controlled strings, so the two derivations have to live in separate namespaces.
        /// </summary>
        private const string AliasShapedLikeAStructuralKeyManifest =
            "{\"name\":\"T\",\"elements\":[" +
            "{\"alias\":\"element:Widget\",\"kind\":\"process\",\"name\":\"Aliased\"}," +
            "{\"kind\":\"process\",\"name\":\"Widget\"}]}";

        /// <summary>The same manifest carrying the envelope this build writes.</summary>
        private const string VersionedManifest =
            "{\"schema\":\"tmforge-manifest\",\"version\":1,\"name\":\"T\"," +
            "\"elements\":[{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"Proc\"}]}";

        /// <summary>A canonical model, which is a different document that happens to look similar.</summary>
        private const string ModelNotManifest =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[{\"id\":\"d\",\"kind\":\"datastore\",\"name\":\"Audit\"}],\"flows\":[]}";

        /// <summary>
        /// A rule pack: another schema whose version is numeric, so nothing about the manifest's own
        /// types rejects it. This is the document that demonstrates why the envelope check exists.
        /// </summary>
        private const string RulePackNotManifest =
            "{\"schema\":\"tmforge-rules\",\"version\":2,\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
            "\"pack\":{\"id\":\"p\",\"name\":\"P\",\"version\":\"1.0.0\"},\"rules\":[]}";

        /// <summary>Two aliased flows between the same pair, so targeting one must not hit the other.</summary>
        private const string TwoAliasedFlowsManifest =
            "{\"name\":\"T\",\"elements\":[" +
            "{\"alias\":\"a\",\"kind\":\"external\",\"name\":\"Client\"}," +
            "{\"alias\":\"b\",\"kind\":\"process\",\"name\":\"Service\"}]," +
            "\"flows\":[{\"alias\":\"primary\",\"from\":\"a\",\"to\":\"b\",\"name\":\"Request\"}," +
            "{\"alias\":\"backup\",\"from\":\"a\",\"to\":\"b\",\"name\":\"Retry\"}]}";

        /// <summary>
        /// A manifest describing two pages, with objects on each. The second page carries a boundary as
        /// well as elements: with boundaries only on the first page, building every boundary onto page
        /// one would be indistinguishable from building it correctly.
        /// </summary>
        private const string TwoPageManifest =
            "{\"schema\":\"tmforge-manifest\",\"version\":1,\"name\":\"T\"," +
            "\"pages\":[{\"alias\":\"ctx\",\"name\":\"Context\"},{\"alias\":\"svc\",\"name\":\"Service\"}]," +
            "\"boundaries\":[{\"alias\":\"tb\",\"name\":\"Edge\",\"page\":\"ctx\"}," +
            "{\"alias\":\"vault\",\"name\":\"Vault\",\"page\":\"svc\"}]," +
            "\"elements\":[" +
            "{\"alias\":\"a\",\"kind\":\"external\",\"name\":\"Client\",\"page\":\"ctx\",\"boundary\":\"tb\"}," +
            "{\"alias\":\"b\",\"kind\":\"process\",\"name\":\"Front\",\"page\":\"ctx\"}," +
            "{\"kind\":\"process\",\"name\":\"Ledger\",\"page\":\"svc\",\"boundary\":\"vault\"}," +
            "{\"kind\":\"store\",\"name\":\"Ledger DB\",\"page\":\"svc\"}]," +
            "\"flows\":[{\"from\":\"a\",\"to\":\"b\",\"name\":\"Call\"}]}";

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
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-manifest-" + Guid.NewGuid().ToString("N"));
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
        /// <c>apply</c> materializes the manifest into a model with the right element/flow/boundary counts.
        /// </summary>
        [TestMethod]
        public void ApplyBuildsModelFromManifest()
        {
            string manifest = this.WriteManifest(SampleManifest);
            string model = Path.ChangeExtension(manifest, ".tm7");

            (int exit, string stdout) = Capture(() => ApplyCommand.Run(new[] { manifest, "--json" }));

            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            JsonElement data = document.RootElement.GetProperty("data");
            Assert.AreEqual(1, data.GetProperty("boundaries").GetInt32());
            Assert.AreEqual(3, data.GetProperty("elements").GetInt32());
            Assert.AreEqual(2, data.GetProperty("flows").GetInt32());
            Assert.IsTrue(File.Exists(model));

            JsonElement open = OpenData(model);
            Assert.AreEqual(3, open.GetProperty("componentCount").GetInt32());
            Assert.AreEqual(2, open.GetProperty("connectorCount").GetInt32());
            Assert.AreEqual(1, open.GetProperty("trustBoundaryCount").GetInt32());
        }

        /// <summary>
        /// <c>apply --dry-run</c> validates the manifest but writes nothing.
        /// </summary>
        [TestMethod]
        public void ApplyDryRunWritesNothing()
        {
            string manifest = this.WriteManifest(SampleManifest);
            string model = Path.ChangeExtension(manifest, ".tm7");

            (int exit, string stdout) = Capture(() => ApplyCommand.Run(new[] { manifest, "--dry-run", "--json" }));

            Assert.AreEqual(0, exit);
            Assert.IsFalse(File.Exists(model), "--dry-run must not write the model");
            using JsonDocument document = JsonDocument.Parse(stdout);
            Assert.IsTrue(document.RootElement.GetProperty("data").GetProperty("dryRun").GetBoolean());
        }

        /// <summary>
        /// A manifest with an unresolvable flow endpoint fails and writes no partial model
        /// (transactional apply).
        /// </summary>
        [TestMethod]
        public void ApplyIsTransactionalOnError()
        {
            string bad = "{\"elements\":[{\"alias\":\"P1\",\"kind\":\"process\",\"name\":\"Proc\"}]," +
                "\"flows\":[{\"from\":\"P1\",\"to\":\"NOPE\",\"name\":\"x\"}]}";
            string manifest = this.WriteManifest(bad);
            string model = Path.ChangeExtension(manifest, ".tm7");

            (int exit, _) = Capture(() => ApplyCommand.Run(new[] { manifest, "--json" }));

            Assert.AreEqual(1, exit);
            Assert.IsFalse(File.Exists(model), "a failed apply must not leave a partial model");
        }

        /// <summary>
        /// A manifest that reuses an alias is rejected.
        /// </summary>
        [TestMethod]
        public void ApplyDuplicateAliasFails()
        {
            string dup = "{\"elements\":[" +
                "{\"alias\":\"P1\",\"kind\":\"process\",\"name\":\"A\"}," +
                "{\"alias\":\"P1\",\"kind\":\"process\",\"name\":\"B\"}]}";
            string manifest = this.WriteManifest(dup);

            (int exit, _) = Capture(() => ApplyCommand.Run(new[] { manifest, "--json" }));

            Assert.AreEqual(1, exit);
        }

        /// <summary>
        /// <c>export</c> round-trips a model applied from a manifest back into an equivalent manifest,
        /// preserving aliases, kinds, boundary membership, and properties.
        /// </summary>
        [TestMethod]
        public void ExportRoundTripsManifest()
        {
            string manifest = this.WriteManifest(SampleManifest);
            string model = Path.ChangeExtension(manifest, ".tm7");
            Capture(() => ApplyCommand.Run(new[] { manifest }));

            (int exit, string stdout) = Capture(() => ExportCommand.Run(new[] { model }));

            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            JsonElement root = document.RootElement;
            Assert.AreEqual("T", root.GetProperty("name").GetString());
            Assert.AreEqual(1, root.GetProperty("boundaries").GetArrayLength());
            Assert.AreEqual(3, root.GetProperty("elements").GetArrayLength());
            Assert.AreEqual(2, root.GetProperty("flows").GetArrayLength());

            bool foundP1 = false;
            foreach (JsonElement element in root.GetProperty("elements").EnumerateArray()
                .Where(element => element.GetProperty("alias").GetString() == "P1"))
            {
                Assert.AreEqual("process", element.GetProperty("kind").GetString());
                Assert.AreEqual("TB", element.GetProperty("boundary").GetString());
                foundP1 = true;
            }

            Assert.IsTrue(foundP1, "the exported manifest must preserve P1 with its boundary membership");
        }

        /// <summary>
        /// Applying one manifest twice reproduces every identifier — the page, each component, and each
        /// connector.
        /// </summary>
        /// <remarks>
        /// <c>apply</c> rebuilds the whole model, so any identifier it mints rather than derives moves
        /// on every run. That is not cosmetic: a finding id is
        /// <c>{ruleId}:{diagram}:{target}:{occurrence}</c>, so a fresh page guid alone moves every
        /// finding in the model, orphans the triage recorded against a threat-register key, and makes
        /// a no-op re-apply read as a wholesale rewrite in <c>tmforge diff</c> and in the pull-request
        /// review the Action posts.
        /// </remarks>
        [TestMethod]
        public void ApplyingOneManifestTwiceReproducesEveryIdentifier()
        {
            Manifest manifest = ManifestSupport.Deserialize(SampleManifest)
                ?? throw new InvalidOperationException("the sample manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel first, out _, out string? firstError), firstError);
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel second, out _, out string? secondError), secondError);

            DrawingSurfaceModel firstPage = first.DrawingSurfaceList[0];
            DrawingSurfaceModel secondPage = second.DrawingSurfaceList[0];

            Assert.AreEqual(firstPage.Guid, secondPage.Guid, "the page identifier moved between applies");
            CollectionAssert.AreEquivalent(
                firstPage.Borders.Keys.ToList(),
                secondPage.Borders.Keys.ToList(),
                "component identifiers moved between applies");
            CollectionAssert.AreEquivalent(
                firstPage.Lines.Keys.ToList(),
                secondPage.Lines.Keys.ToList(),
                "connector identifiers moved between applies");
        }

        /// <summary>
        /// Two flows between the same pair of elements with the same name still get distinct identifiers,
        /// and the same two on the next apply. Deriving an id from a structural key is only safe if
        /// same-keyed siblings are disambiguated; collapsing them would silently drop a flow.
        /// </summary>
        [TestMethod]
        public void FlowsSharingEndpointsAndNameGetDistinctStableIdentifiers()
        {
            Manifest manifest = ManifestSupport.Deserialize(DuplicateFlowManifest)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel first, out _, out string? error), error);
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel second, out _, out error), error);

            List<Guid> firstFlows = first.DrawingSurfaceList[0].Lines.Keys.ToList();

            Assert.AreEqual(2, firstFlows.Count, "both flows must survive");
            Assert.AreEqual(2, firstFlows.Distinct().Count(), "the two flows collapsed onto one identifier");
            CollectionAssert.AreEquivalent(firstFlows, second.DrawingSurfaceList[0].Lines.Keys.ToList());
        }

        /// <summary>
        /// A flow alias fixes the connector's identity and survives <c>export</c>, so a flow's identity
        /// can be carried deliberately rather than inferred from its endpoints and name — which is what
        /// lets a flow be renamed or re-pointed without moving its id.
        /// </summary>
        [TestMethod]
        public void FlowAliasFixesIdentityAndSurvivesExport()
        {
            Manifest manifest = ManifestSupport.Deserialize(AliasedFlowManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Guid expected = AuthoringSupport.DeterministicId("primary");
            Assert.IsTrue(
                model.DrawingSurfaceList[0].Lines.ContainsKey(expected),
                "the connector did not take the identifier its alias derives");

            Manifest exported = ManifestSupport.Extract(model);
            Assert.AreEqual("primary", exported.Flows![0].Alias, "export dropped the flow alias");
        }

        /// <summary>
        /// Renaming an aliased flow leaves its identifier alone, which is the point of declaring one:
        /// the structural fallback would move the id, because the name is part of its key.
        /// </summary>
        [TestMethod]
        public void RenamingAnAliasedFlowKeepsItsIdentifier()
        {
            Manifest before = ManifestSupport.Deserialize(AliasedFlowManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Manifest after = ManifestSupport.Deserialize(AliasedFlowManifest.Replace("Request", "Renamed", StringComparison.Ordinal))
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(before, force: false, out ThreatModel first, out _, out string? error), error);
            Assert.IsTrue(ManifestSupport.Build(after, force: false, out ThreatModel second, out _, out error), error);

            CollectionAssert.AreEquivalent(
                first.DrawingSurfaceList[0].Lines.Keys.ToList(),
                second.DrawingSurfaceList[0].Lines.Keys.ToList(),
                "renaming an aliased flow moved its identifier");
        }

        /// <summary>A flow may not take an alias an element already holds, or the two would collide.</summary>
        [TestMethod]
        public void FlowAliasCollidingWithAnElementIsRejected()
        {
            Manifest manifest = ManifestSupport.Deserialize(
                AliasedFlowManifest.Replace("\"alias\":\"primary\"", "\"alias\":\"a\"", StringComparison.Ordinal))
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsFalse(ManifestSupport.Build(manifest, force: false, out _, out _, out string? error));
            StringAssert.Contains(error, "Duplicate alias");
        }

        /// <summary>
        /// A manifest that declares no aliases is still reproduced identically. Aliases are optional and
        /// a concise manifest is the documented starting point, so the structural fallback has to hold
        /// on its own — otherwise the guarantee would reach only manifests somebody had already annotated.
        /// </summary>
        [TestMethod]
        public void AManifestWithoutAliasesIsStillReproducedIdentically()
        {
            Manifest manifest = ManifestSupport.Deserialize(NoAliasManifest)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel first, out _, out string? error), error);
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel second, out _, out error), error);

            DrawingSurfaceModel firstPage = first.DrawingSurfaceList[0];
            DrawingSurfaceModel secondPage = second.DrawingSurfaceList[0];

            Assert.AreEqual(3, firstPage.Borders.Count, "the boundary and both elements must be present");
            CollectionAssert.AreEquivalent(
                firstPage.Borders.Keys.ToList(),
                secondPage.Borders.Keys.ToList(),
                "component identifiers moved between applies");
            CollectionAssert.AreEquivalent(
                firstPage.Lines.Keys.ToList(),
                secondPage.Lines.Keys.ToList(),
                "connector identifiers moved between applies");
        }

        /// <summary>
        /// An alias may read exactly like another element's structural key without the two colliding.
        /// Both strings are author-controlled, and the alias and structural allocators use separate
        /// uniqueness sets, so a shared derivation namespace would let the second object overwrite the
        /// first in the diagram and vanish — while the summary still counted it.
        /// </summary>
        [TestMethod]
        public void AnAliasShapedLikeAStructuralKeyDoesNotCollide()
        {
            Manifest manifest = ManifestSupport.Deserialize(AliasShapedLikeAStructuralKeyManifest)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Assert.AreEqual(2, model.DrawingSurfaceList[0].Borders.Count, "an element was lost to an identifier collision");
        }

        /// <summary>
        /// A manifest with no envelope is still read. The concise form predates the envelope and is the
        /// documented starting point, so requiring one would break every manifest already written.
        /// </summary>
        [TestMethod]
        public void AManifestWithoutAnEnvelopeIsStillRead()
        {
            Assert.IsTrue(ManifestSupport.TryRead(SampleManifest, out Manifest? manifest, out string? error), error);
            Assert.AreEqual(3, manifest.Elements!.Count);
        }

        /// <summary>A manifest carrying the current envelope is read.</summary>
        [TestMethod]
        public void AVersionedManifestIsRead()
        {
            Assert.IsTrue(ManifestSupport.TryRead(VersionedManifest, out Manifest? manifest, out string? error), error);
            Assert.AreEqual(Manifest.SchemaName, manifest.Schema);
            Assert.AreEqual(Manifest.CurrentVersion, manifest.Version);
        }

        /// <summary>
        /// A manifest from a newer build is refused with an upgrade hint rather than read on assumptions
        /// that no longer hold — the whole reason to carry a version.
        /// </summary>
        [TestMethod]
        public void AFutureSchemaVersionIsRefused()
        {
            string future = VersionedManifest.Replace("\"version\":1", "\"version\":2", StringComparison.Ordinal);

            Assert.IsFalse(ManifestSupport.TryRead(future, out _, out string? error));
            StringAssert.Contains(error, "cannot read");
            StringAssert.Contains(error, "Upgrade");
        }

        /// <summary>
        /// A document of another schema is refused rather than coerced. The check runs against the raw
        /// JSON before deserialization, so it reports the schema mismatch rather than whatever binding
        /// error the foreign document happens to produce.
        /// </summary>
        [TestMethod]
        public void ADocumentOfAnotherSchemaIsRefused()
        {
            Assert.IsFalse(ManifestSupport.TryRead(ModelNotManifest, out _, out string? error));
            StringAssert.Contains(error, "tmforge-manifest");
            StringAssert.Contains(error, "tmforge-json");
        }

        /// <summary>
        /// The case the envelope earns its keep on. A rule pack carries a numeric version, so no type
        /// mismatch rejects it. Both the low-level deserializer and the envelope-aware reader now
        /// reject it instead of constructing an empty manifest.
        /// </summary>
        [TestMethod]
        public void ADocumentThatWouldOtherwiseCoerceIsRefused()
        {
            Assert.Throws<InvalidDataException>(() => ManifestSupport.Deserialize(RulePackNotManifest));

            Assert.IsFalse(ManifestSupport.TryRead(RulePackNotManifest, out _, out string? error));
            StringAssert.Contains(error, "tmforge-rules");
        }

        /// <summary>Malformed JSON is reported as such rather than throwing out of the reader.</summary>
        [TestMethod]
        public void MalformedJsonIsReportedNotThrown()
        {
            Assert.IsFalse(ManifestSupport.TryRead("{ not json", out _, out string? error));
            StringAssert.Contains(error, "not valid JSON");
        }

        /// <summary>Export stamps the envelope, so a round-tripped manifest is versioned.</summary>
        [TestMethod]
        public void ExportStampsTheEnvelope()
        {
            Manifest source = ManifestSupport.Deserialize(SampleManifest)
                ?? throw new InvalidOperationException("the sample manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(source, force: false, out ThreatModel model, out _, out string? error), error);

            Manifest exported = ManifestSupport.Extract(model);

            Assert.AreEqual(Manifest.SchemaName, exported.Schema);
            Assert.AreEqual(Manifest.CurrentVersion, exported.Version);
            StringAssert.Contains(ManifestSupport.Serialize(exported), "\"schema\": \"tmforge-manifest\"");
        }

        /// <summary>A boundary's explicit rectangle is honoured rather than replaced by the stacking layout.</summary>
        [TestMethod]
        public void ExplicitBoundaryGeometryIsHonoured()
        {
            const string Placed =
                "{\"name\":\"T\",\"boundaries\":[{\"alias\":\"tb\",\"name\":\"Edge\"," +
                "\"x\":300,\"y\":250,\"width\":500,\"height\":400}]}";

            Manifest manifest = ManifestSupport.Deserialize(Placed)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            DrawingElement boundary = model.DrawingSurfaceList[0].Borders.Values
                .OfType<DrawingElement>().Single(element => element is BorderBoundary);

            Assert.AreEqual(300, boundary.Left);
            Assert.AreEqual(250, boundary.Top);
            Assert.AreEqual(500, boundary.Width);
            Assert.AreEqual(400, boundary.Height);
        }

        /// <summary>Explicit geometry is honoured instead of being replaced by automatic placement.</summary>
        [TestMethod]
        public void ExplicitGeometryIsHonoured()
        {
            const string Placed =
                "{\"name\":\"T\",\"elements\":[" +
                "{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"Proc\",\"x\":640,\"y\":480,\"width\":90,\"height\":40}]}";

            Manifest manifest = ManifestSupport.Deserialize(Placed)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            DrawingElement placed = model.DrawingSurfaceList[0].Borders.Values.OfType<DrawingElement>().Single();

            Assert.AreEqual(640, placed.Left);
            Assert.AreEqual(480, placed.Top);
            Assert.AreEqual(90, placed.Width);
            Assert.AreEqual(40, placed.Height);
        }

        /// <summary>
        /// Half a rectangle is refused. Defaulting the missing half would place the object somewhere the
        /// author did not ask for while looking like the request had been honoured.
        /// </summary>
        [TestMethod]
        public void HalfSuppliedGeometryIsRefused()
        {
            const string HalfPlaced =
                "{\"name\":\"T\",\"elements\":[{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"P\",\"x\":10}]}";

            Manifest manifest = ManifestSupport.Deserialize(HalfPlaced)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsFalse(ManifestSupport.Build(manifest, force: false, out _, out _, out string? error));
            StringAssert.Contains(error, "only one of 'x' and 'y'");
        }

        /// <summary>An auto-sized boundary grows to contain a member placed outside its default box.</summary>
        [TestMethod]
        public void AnAutoSizedBoundaryGrowsToContainAnExplicitlyPlacedMember()
        {
            const string Mixed =
                "{\"name\":\"T\",\"boundaries\":[{\"alias\":\"tb\",\"name\":\"Edge\"}]," +
                "\"elements\":[{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"P\",\"boundary\":\"tb\"," +
                "\"x\":900,\"y\":700,\"width\":100,\"height\":60}]}";

            Manifest manifest = ManifestSupport.Deserialize(Mixed)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            DrawingElement boundary = model.DrawingSurfaceList[0].Borders.Values
                .OfType<DrawingElement>().Single(element => element is BorderBoundary);

            Assert.IsTrue(
                boundary.Left + boundary.Width >= 1000 && boundary.Top + boundary.Height >= 760,
                "the boundary did not grow to contain its member, so the member sits outside it");
        }

        /// <summary>
        /// A fixed boundary too small for the members it must lay out is refused, because the grid would
        /// place them outside the box the author drew — the one case where the manifest cannot be honoured.
        /// </summary>
        [TestMethod]
        public void AFixedBoundaryTooSmallForItsAutoPlacedMembersIsRefused()
        {
            const string Cramped =
                "{\"name\":\"T\",\"boundaries\":[{\"alias\":\"tb\",\"name\":\"Edge\",\"x\":0,\"y\":0,\"width\":40,\"height\":40}]," +
                "\"elements\":[{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"P\",\"boundary\":\"tb\"}]}";

            Manifest manifest = ManifestSupport.Deserialize(Cramped)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsFalse(ManifestSupport.Build(manifest, force: false, out _, out _, out string? error));
            StringAssert.Contains(error, "need at least");
            StringAssert.Contains(error, "Boundary 'tb'");
        }

        /// <summary>
        /// A member placed outside the boundary it belongs to is allowed. Nothing is clipped — both
        /// objects go exactly where they were asked to — and refusing it would make a diagram that is
        /// already in that state impossible to export and re-apply.
        /// </summary>
        [TestMethod]
        public void AnExplicitlyPlacedMemberOutsideItsFixedBoundaryIsAllowed()
        {
            const string Outside =
                "{\"name\":\"T\",\"boundaries\":[{\"alias\":\"tb\",\"name\":\"Edge\",\"x\":0,\"y\":0,\"width\":400,\"height\":300}]," +
                "\"elements\":[{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"P\",\"boundary\":\"tb\"," +
                "\"x\":900,\"y\":700,\"width\":100,\"height\":60}]}";

            Manifest manifest = ManifestSupport.Deserialize(Outside)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);
            Assert.AreEqual(2, model.DrawingSurfaceList[0].Borders.Count);
        }

        /// <summary>Export omits geometry by default and records it on request.</summary>
        [TestMethod]
        public void ExportRecordsGeometryOnlyWhenAsked()
        {
            Manifest source = ManifestSupport.Deserialize(SampleManifest)
                ?? throw new InvalidOperationException("the sample manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(source, force: false, out ThreatModel model, out _, out string? error), error);

            Assert.IsNull(ManifestSupport.Extract(model).Elements![0].X, "the default export leaked geometry");
            Assert.IsNotNull(ManifestSupport.Extract(model, includeGeometry: true).Elements![0].X);
        }

        /// <summary>
        /// Export with geometry, apply, and export again produces the same manifest — the round trip the
        /// whole feature exists to make lossless.
        /// </summary>
        [TestMethod]
        public void ExportApplyExportIsStableWithGeometry()
        {
            Manifest source = ManifestSupport.Deserialize(SampleManifest)
                ?? throw new InvalidOperationException("the sample manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(source, force: false, out ThreatModel first, out _, out string? error), error);

            string once = ManifestSupport.Serialize(ManifestSupport.Extract(first, includeGeometry: true));

            Manifest reread = ManifestSupport.Deserialize(once)
                ?? throw new InvalidOperationException("the exported manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(reread, force: false, out ThreatModel second, out _, out error), error);

            Assert.AreEqual(once, ManifestSupport.Serialize(ManifestSupport.Extract(second, includeGeometry: true)));
        }

        /// <summary>Objects land on the page they declare, rather than all on the first one.</summary>
        [TestMethod]
        public void ObjectsAreBuiltOntoTheirDeclaredPage()
        {
            Manifest manifest = ManifestSupport.Deserialize(TwoPageManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Assert.AreEqual(2, model.DrawingSurfaceList.Count);
            Assert.AreEqual("Context", model.DrawingSurfaceList[0].Header);
            Assert.AreEqual("Service", model.DrawingSurfaceList[1].Header);
            Assert.AreEqual(3, model.DrawingSurfaceList[0].Borders.Count, "the Edge boundary and its two elements belong on Context");
            Assert.AreEqual(3, model.DrawingSurfaceList[1].Borders.Count, "the Vault boundary and its two elements belong on Service");
            Assert.AreEqual(1, model.DrawingSurfaceList[0].Lines.Count, "the flow belongs on the page its endpoints are on");
            Assert.AreEqual(
                1,
                model.DrawingSurfaceList[1].Borders.Values.OfType<BorderBoundary>().Count(),
                "the Vault boundary was not built onto the second page");
        }

        /// <summary>
        /// A multi-page manifest applied twice reproduces every identifier, on every page.
        /// </summary>
        /// <remarks>
        /// This caught a real defect: alias-less elements on the second page were being re-keyed
        /// against the first page's surface, where they do not exist, so the re-key silently did
        /// nothing and they kept the minted guid it exists to replace. Counting elements did not
        /// notice — they were all present, just unstable — which is why this asserts the ids.
        /// </remarks>
        [TestMethod]
        public void AMultiPageManifestAppliedTwiceReproducesEveryIdentifier()
        {
            Manifest manifest = ManifestSupport.Deserialize(TwoPageManifest)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel first, out _, out string? error), error);
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel second, out _, out error), error);

            for (int page = 0; page < first.DrawingSurfaceList.Count; page++)
            {
                Assert.AreEqual(
                    first.DrawingSurfaceList[page].Guid,
                    second.DrawingSurfaceList[page].Guid,
                    "page " + page.ToString(CultureInfo.InvariantCulture) + " changed identity");
                CollectionAssert.AreEquivalent(
                    first.DrawingSurfaceList[page].Borders.Keys.ToList(),
                    second.DrawingSurfaceList[page].Borders.Keys.ToList(),
                    "component identifiers moved on page " + page.ToString(CultureInfo.InvariantCulture));
            }
        }

        /// <summary>
        /// A flow whose endpoints sit on different pages is refused. A connector belongs to one
        /// surface, so drawing it on whichever page resolved first would leave its endpoints elsewhere.
        /// </summary>
        [TestMethod]
        public void AFlowCrossingPagesIsRefused()
        {
            string crossing = TwoPageManifest.Replace(
                "\"flows\":[{\"from\":\"a\",\"to\":\"b\",\"name\":\"Call\"}]",
                "\"flows\":[{\"from\":\"a\",\"to\":\"Ledger\",\"name\":\"Call\"}]",
                StringComparison.Ordinal);
            Manifest manifest = ManifestSupport.Deserialize(crossing)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsFalse(ManifestSupport.Build(manifest, force: false, out _, out _, out string? error));
            StringAssert.Contains(error, "cannot cross pages");
        }

        /// <summary>An object naming a page the manifest never declares is refused, not silently moved.</summary>
        [TestMethod]
        public void AnUnknownPageReferenceIsRefused()
        {
            string unknown = TwoPageManifest.Replace("\"page\":\"svc\"", "\"page\":\"nope\"", StringComparison.Ordinal);
            Manifest manifest = ManifestSupport.Deserialize(unknown)
                ?? throw new InvalidOperationException("the manifest must parse");

            Assert.IsFalse(ManifestSupport.Build(manifest, force: false, out _, out _, out string? error));
            StringAssert.Contains(error, "does not declare");
        }

        /// <summary>
        /// A single-page model exports exactly the shape it always did, with no pages block and no page
        /// reference on any object, so a manifest written before pages existed still reads identically.
        /// </summary>
        [TestMethod]
        public void ASinglePageModelExportsWithoutPages()
        {
            Manifest source = ManifestSupport.Deserialize(SampleManifest)
                ?? throw new InvalidOperationException("the sample manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(source, force: false, out ThreatModel model, out _, out string? error), error);

            Manifest exported = ManifestSupport.Extract(model);

            Assert.IsNull(exported.Pages, "a single-page model must not grow a pages block");
            Assert.IsTrue(exported.Elements!.TrueForAll(element => element.Page == null));
        }

        /// <summary>A multi-page model round-trips its pages through export and apply.</summary>
        [TestMethod]
        public void PagesSurviveExportAndApply()
        {
            Manifest source = ManifestSupport.Deserialize(TwoPageManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(source, force: false, out ThreatModel model, out _, out string? error), error);

            Manifest exported = ManifestSupport.Extract(model);
            Assert.AreEqual(2, exported.Pages!.Count);

            Assert.IsTrue(ManifestSupport.Build(exported, force: false, out ThreatModel rebuilt, out _, out error), error);

            Assert.AreEqual(2, rebuilt.DrawingSurfaceList.Count);
            Assert.AreEqual(
                model.DrawingSurfaceList[1].Borders.Count,
                rebuilt.DrawingSurfaceList[1].Borders.Count,
                "the second page lost or gained members on the round trip");
        }

        /// <summary>
        /// Re-keying against a surface that does not hold the object throws rather than doing nothing.
        /// The silent version is what let the multi-page defect above go unnoticed.
        /// </summary>
        [TestMethod]
        public void RekeyingAgainstTheWrongSurfaceThrows()
        {
            Manifest manifest = ManifestSupport.Deserialize(TwoPageManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Guid onSecondPage = model.DrawingSurfaceList[1].Borders.Keys.First();

            Assert.ThrowsExactly<ArgumentException>(
                () => AuthoringSupport.RekeyComponent(model.DrawingSurfaceList[0], onSecondPage, Guid.NewGuid()));
        }

        /// <summary>
        /// A flow alias resolves to that connector, so the authoring verbs can target a flow the way
        /// they target an element.
        /// </summary>
        /// <remarks>
        /// The resolver has always scanned connectors as well as components, but until flows could
        /// carry an alias that branch could never match — it was unreachable rather than working. This
        /// pins the behaviour now that it is live, so narrowing the resolver to components would fail
        /// here instead of quietly removing the only way to name a flow.
        /// </remarks>
        [TestMethod]
        public void AFlowIsResolvableByItsAlias()
        {
            Manifest manifest = ManifestSupport.Deserialize(TwoAliasedFlowsManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Assert.IsTrue(AuthoringSupport.TryResolveElementId(model, null, "primary", out Guid id, out error), error);

            DrawingSurfaceModel page = model.DrawingSurfaceList[0];
            Assert.IsTrue(page.Lines.ContainsKey(id), "the alias resolved to something that is not a connector");
            Assert.AreEqual(AuthoringSupport.DeterministicId("primary"), id);
        }

        /// <summary>Targeting one flow alias does not touch the other flow between the same pair.</summary>
        [TestMethod]
        public void AFlowAliasTargetsOnlyThatFlow()
        {
            Manifest manifest = ManifestSupport.Deserialize(TwoAliasedFlowsManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Assert.IsTrue(AuthoringSupport.TryResolveElementId(model, null, "primary", out Guid primary, out error), error);
            Assert.IsTrue(AuthoringSupport.TryResolveElementId(model, null, "backup", out Guid backup, out error), error);

            Assert.AreNotEqual(primary, backup, "two aliases resolved to one connector");
        }

        /// <summary>Removing by flow alias removes that flow and leaves its endpoints standing.</summary>
        [TestMethod]
        public void RemovingByFlowAliasRemovesOnlyThatFlow()
        {
            Manifest manifest = ManifestSupport.Deserialize(TwoAliasedFlowsManifest)
                ?? throw new InvalidOperationException("the manifest must parse");
            Assert.IsTrue(ManifestSupport.Build(manifest, force: false, out ThreatModel model, out _, out string? error), error);

            Assert.IsTrue(
                AuthoringOperations.Remove(model, new RemoveRequest { Id = "backup" }, out IReadOnlyList<Guid> removed, out error),
                error);

            DrawingSurfaceModel page = model.DrawingSurfaceList[0];

            Assert.AreEqual(1, removed.Count, "removing a flow must not take anything else with it");
            Assert.AreEqual(2, page.Borders.Count, "the endpoints must survive removing the flow between them");
            Assert.AreEqual(1, page.Lines.Count);
            Assert.IsTrue(
                page.Lines.ContainsKey(AuthoringSupport.DeterministicId("primary")),
                "the wrong flow was removed");
        }

        private static JsonElement OpenData(string path)
        {
            (int exit, string stdout) = Capture(() => OpenCommand.Run(new[] { "--json", path }));
            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            return document.RootElement.GetProperty("data").Clone();
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

        private string WriteManifest(string json)
        {
            string path = Path.Join(this.WorkingDirectory, "model.json");
            File.WriteAllText(path, json);
            return path;
        }
    }
}
