namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for logical boundary membership (<c>add --boundary</c>) and the auto-layout verb
    /// (<c>tmforge layout</c>).
    /// </summary>
    [TestClass]
    public class BoundaryAndLayoutTest
    {
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
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-boundary-" + Guid.NewGuid().ToString("N"));
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
        /// <c>add --boundary</c> records membership and positions the element inside the boundary.
        /// </summary>
        [TestMethod]
        public void AddBoundaryRecordsMembershipAndPlacesInside()
        {
            string path = this.NewModel();
            Capture(() => AddCommand.Run(new[] { "boundary", path, "--alias", "TB", "--name", "Edge" }));

            (int exit, _) = Capture(() => AddCommand.Run(new[] { "process", path, "--alias", "P1", "--name", "Proc", "--boundary", "TB" }));
            Assert.AreEqual(0, exit);

            (int showExit, string showOut) = Capture(() => ShowCommand.Run(new[] { path, "--id", "P1", "--json" }));
            Assert.AreEqual(0, showExit);
            using JsonDocument document = JsonDocument.Parse(showOut);
            Assert.AreEqual("TB", document.RootElement.GetProperty("data").GetProperty("properties").GetProperty("Boundary").GetString());

            (DrawingElement boundary, DrawingElement process) = LoadPair(path, "Edge", "Proc");
            Assert.IsTrue(process.Left >= boundary.Left && process.Left < boundary.Left + boundary.Width, "the element must be within the boundary horizontally");
            Assert.IsTrue(process.Top >= boundary.Top && process.Top < boundary.Top + boundary.Height, "the element must be within the boundary vertically");
        }

        /// <summary>
        /// <c>add --boundary</c> with an unknown boundary reference is rejected.
        /// </summary>
        [TestMethod]
        public void AddBoundaryUnknownReferenceFails()
        {
            string path = this.NewModel();

            (int exit, _) = Capture(() => AddCommand.Run(new[] { "process", path, "--name", "Proc", "--boundary", "does-not-exist" }));

            Assert.AreEqual(1, exit);
        }

        /// <summary>
        /// <c>tmforge layout</c> arranges the components and reports how many it placed.
        /// </summary>
        [TestMethod]
        public void LayoutArrangesComponents()
        {
            string path = this.NewModel();
            string a = AddElement("process", path, "A");
            string b = AddElement("process", path, "B");
            Capture(() => ConnectCommand.Run(new[] { path, "--source", a, "--target", b }));

            (int exit, string stdout) = Capture(() => LayoutCommand.Run(new[] { path, "--json" }));

            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            Assert.AreEqual(2, document.RootElement.GetProperty("data").GetProperty("components").GetInt32());

            (DrawingElement first, DrawingElement second) = LoadPair(path, "A", "B");
            Assert.AreNotEqual(first.Left, second.Left, "connected components should land in different layers (columns)");
        }

        /// <summary>
        /// <c>tmforge layout --labels</c> places the flow labels without rearranging hand-placed
        /// shapes, which is what a model whose geometry comes from a manifest needs. The whole surface
        /// may still be translated to stay inside the tool's coordinate range, so what must hold is
        /// that the shapes keep their positions relative to one another.
        /// </summary>
        [TestMethod]
        public void LayoutLabelsLeavesShapesInPlace()
        {
            string path = this.NewModel();
            string a = AddElement("process", path, "A");
            string b = AddElement("process", path, "B");
            Capture(() => ConnectCommand.Run(new[] { path, "--source", a, "--target", b, "--name", "Credential material handed to the signer" }));
            Capture(() => ConnectCommand.Run(new[] { path, "--source", b, "--target", a, "--name", "Signed material returned to the caller" }));
            (DrawingElement beforeFirst, DrawingElement beforeSecond) = LoadPair(path, "A", "B");
            (int offsetX, int offsetY) = (beforeSecond.Left - beforeFirst.Left, beforeSecond.Top - beforeFirst.Top);

            (int exit, string stdout) = Capture(() => LayoutCommand.Run(new[] { path, "--labels", "--json" }));

            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            Assert.AreEqual(0, document.RootElement.GetProperty("data").GetProperty("labelOverlaps").GetInt32());

            (DrawingElement afterFirst, DrawingElement afterSecond) = LoadPair(path, "A", "B");
            Assert.AreEqual(offsetX, afterSecond.Left - afterFirst.Left, "shapes must keep their relative arrangement");
            Assert.AreEqual(offsetY, afterSecond.Top - afterFirst.Top, "shapes must keep their relative arrangement");
        }

        /// <summary>
        /// <c>tmforge layout --check</c> fails and writes nothing when a label cannot be placed clear.
        /// Placement can move a name but not shorten it, so a name with nowhere to go stays covered,
        /// and a publishing gate has to be able to see that.
        /// </summary>
        [TestMethod]
        public void LayoutCheckReportsObstructedLabelsWithoutWriting()
        {
            // A long name between two shapes, with a third covering every direction it could move to.
            const string Boxed =
                "{\"name\":\"Boxed\",\"elements\":[" +
                "{\"alias\":\"a\",\"kind\":\"process\",\"name\":\"A\",\"x\":100,\"y\":200,\"width\":100,\"height\":60}," +
                "{\"alias\":\"b\",\"kind\":\"process\",\"name\":\"B\",\"x\":700,\"y\":200,\"width\":100,\"height\":60}," +
                "{\"alias\":\"c\",\"kind\":\"store\",\"name\":\"Covering store\",\"x\":210,\"y\":100,\"width\":480,\"height\":300}]," +
                "\"flows\":[{\"from\":\"a\",\"to\":\"b\",\"name\":\"A long flow name with nowhere to go\"}]}";
            string manifest = Path.Join(this.WorkingDirectory, "boxed.tm.json");
            string path = Path.Join(this.WorkingDirectory, "boxed.tm7");
            File.WriteAllText(manifest, Boxed);
            Assert.AreEqual(0, Capture(() => ApplyCommand.Run(new[] { manifest, "--out", path })).Exit);
            string before = File.ReadAllText(path);

            (int exit, string stdout) = Capture(() => LayoutCommand.Run(new[] { path, "--check", "--json" }));

            Assert.AreEqual(1, exit, "an obstructed diagram must fail the check");
            using JsonDocument document = JsonDocument.Parse(stdout);
            Assert.IsTrue(document.RootElement.GetProperty("data").GetProperty("labelOverlaps").GetInt32() > 0);
            Assert.AreEqual(before, File.ReadAllText(path), "--check must not write the model");
        }

        /// <summary>
        /// <c>tmforge layout --check</c> passes on a model the authoring verbs produced. Every write
        /// path to the tool's format places the labels, so an authored model is legible on arrival
        /// rather than only after someone remembers to run a layout pass.
        /// </summary>
        [TestMethod]
        public void LayoutCheckPassesForAnAuthoredModel()
        {
            string path = this.NewModel();
            string a = AddElement("process", path, "A");
            string b = AddElement("process", path, "B");
            Capture(() => ConnectCommand.Run(new[] { path, "--source", a, "--target", b, "--name", "Credential material handed to the signer" }));
            Capture(() => ConnectCommand.Run(new[] { path, "--source", b, "--target", a, "--name", "Signed material returned to the caller" }));

            Assert.AreEqual(0, Capture(() => LayoutCommand.Run(new[] { path, "--check" })).Exit);
        }

        /// <summary>A layout must not discard one of an element's overlapping trust claims.</summary>
        [TestMethod]
        public void LayoutRefusesOverlappingMembershipWithoutWriting()
        {
            ThreatModel model = LayoutFixture(overlapping: true);
            string path = this.SaveFixture(model);
            string before = File.ReadAllText(path);
            Assert.AreEqual(2, BoundaryCrossingDiff.Capture(model).Single().Boundaries.Count);

            Assert.AreEqual(1, Capture(() => LayoutCommand.Run(new[] { path, "--json" })).Exit);

            Assert.AreEqual(before, File.ReadAllText(path), "a refused layout must not write anything");
        }

        /// <summary>Connector coordinates, rather than node centers, determine the actual crossings.</summary>
        [TestMethod]
        public void LayoutRefusesConnectorCrossingChangesWithoutWriting()
        {
            ThreatModel model = LayoutFixture(overlapping: false);
            Connector flow = model.DrawingSurfaceList[0].Lines.Values.OfType<Connector>().Single();
            flow.SourceX = 50;
            Assert.AreEqual(0, BoundaryCrossingDiff.Capture(model).Single().Boundaries.Count);
            string path = this.SaveFixture(model);
            string before = File.ReadAllText(path);

            Assert.AreEqual(1, Capture(() => LayoutCommand.Run(new[] { path })).Exit);

            Assert.AreEqual(before, File.ReadAllText(path));
        }

        /// <summary>Nested boundary memberships and crossings survive successful arrangement and save.</summary>
        [TestMethod]
        public void LayoutPreservesNestedBoundaryCrossings()
        {
            ThreatModel model = LayoutFixture(overlapping: false);
            DrawingSurfaceModel surface = model.DrawingSurfaceList[0];
            AddFixtureBoundary(surface, 100, 100, 600, 600, "Outer");
            string path = this.SaveFixture(model);
            Assert.AreEqual(2, BoundaryCrossingDiff.Capture(model).Single().Boundaries.Count);

            Assert.AreEqual(0, Capture(() => LayoutCommand.Run(new[] { path })).Exit);

            (ThreatModel after, _) = CliModelLoader.Load(path);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(model, after).IsEmpty);
            Assert.IsTrue(ModelDiff.Compare(model, after).IsEmpty, "layout must not change identities, topology or properties");
        }

        /// <summary>An unsafe later page must prevent an earlier page from being saved too.</summary>
        [TestMethod]
        public void LayoutRefusesAllPagesAtomically()
        {
            ThreatModel model = LayoutFixture(overlapping: false);
            model.DrawingSurfaceList.Add(LayoutFixture(overlapping: true).DrawingSurfaceList[0]);
            string path = this.SaveFixture(model);
            string before = File.ReadAllText(path);

            Assert.AreEqual(1, Capture(() => LayoutCommand.Run(new[] { path })).Exit);

            Assert.AreEqual(before, File.ReadAllText(path));
        }

        /// <summary>Label-only cleanup remains usable when full layout would change trust claims.</summary>
        [TestMethod]
        public void LayoutLabelsPreservesOverlappingBoundaryCrossings()
        {
            ThreatModel model = LayoutFixture(overlapping: true);
            string path = this.SaveFixture(model);

            Assert.AreEqual(0, Capture(() => LayoutCommand.Run(new[] { path, "--labels" })).Exit);

            (ThreatModel after, _) = CliModelLoader.Load(path);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(model, after).IsEmpty);
        }

        /// <summary>Line trust boundaries use intersection semantics and must also be preserved.</summary>
        [TestMethod]
        public void LayoutRefusesChangedLineBoundaryIntersections()
        {
            ThreatModel model = LayoutFixture(overlapping: false);
            DrawingSurfaceModel surface = model.DrawingSurfaceList[0];
            LineBoundary boundary = new LineBoundary
            {
                Guid = Guid.NewGuid(), SourceX = 600, SourceY = 100, TargetX = 600, TargetY = 900,
            };
            surface.Lines.Add(boundary.Guid, boundary);
            Assert.AreEqual(2, BoundaryCrossingDiff.Capture(model).Single().Boundaries.Count);
            string path = this.SaveFixture(model);
            string before = File.ReadAllText(path);

            Assert.AreEqual(1, Capture(() => LayoutCommand.Run(new[] { path })).Exit);

            Assert.AreEqual(before, File.ReadAllText(path));
        }

        /// <summary>A refused multi-page operation leaves the original in-memory geometry untouched.</summary>
        [TestMethod]
        public void SharedLayoutRefusalIsAtomicInMemory()
        {
            ThreatModel model = LayoutFixture(overlapping: false);
            model.DrawingSurfaceList.Add(LayoutFixture(overlapping: true).DrawingSurfaceList[0]);
            string before = Geometry(model);

            bool success = LayoutOperations.TryApply(model.DrawingSurfaceList, null, out int moved, out string? error);

            Assert.IsFalse(success);
            Assert.AreEqual(0, moved);
            StringAssert.Contains(error, "No pages were changed");
            Assert.AreEqual(before, Geometry(model));
        }

        /// <summary>Scoping layout to a safe page does not arrange an unsafe sibling.</summary>
        [TestMethod]
        public void LayoutCanScopeToOnePage()
        {
            ThreatModel model = LayoutFixture(overlapping: false);
            model.DrawingSurfaceList.Add(LayoutFixture(overlapping: true).DrawingSurfaceList[0]);
            string path = this.SaveFixture(model);

            Assert.AreEqual(0, Capture(() => LayoutCommand.Run(new[] { path, "--page", "1" })).Exit);

            (ThreatModel after, _) = CliModelLoader.Load(path);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(model, after).IsEmpty);
            Assert.AreEqual(
                model.DrawingSurfaceList[1].Borders.Values.OfType<BorderBoundary>().First().Left,
                after.DrawingSurfaceList[1].Borders.Values.OfType<BorderBoundary>().First().Left);
        }

        /// <summary>Boundary placement refuses a clipped shape rather than claiming it is contained.</summary>
        [TestMethod]
        public void AddBoundaryRefusesAnOversizedMemberWithoutWriting()
        {
            string path = this.NewModel();
            Assert.AreEqual(0, Capture(() => AddCommand.Run(new[] { "boundary", path, "--alias", "TB" })).Exit);
            string before = File.ReadAllText(path);

            string[] arguments = new[]
            {
                "process", path, "--name", "Oversized", "--boundary", "TB", "--width", "400", "--height", "200",
            };
            Assert.AreEqual(1, Capture(() => AddCommand.Run(arguments)).Exit);

            Assert.AreEqual(before, File.ReadAllText(path));
        }

        /// <summary>Canonical JSON layout patches geometry instead of rewriting identities or author state.</summary>
        [TestMethod]
        public void LayoutPreservesCanonicalJsonIdentityAndMetadata()
        {
            const string Json = """
                {"schema":"tmforge-json","version":"0.1",
                 "elements":[{"id":"source","kind":"process","name":"A","x":600,"y":600,"width":100,"height":60},
                             {"id":"target","kind":"process","name":"B","x":100,"y":100,"width":100,"height":60}],
                 "flows":[{"id":"f","source":"source","target":"target","name":"Request","labelOffset":{"x":20,"y":30}}],
                 "analysis":{"disabledRuleIds":["TM1003"],"expectedPacks":[{"id":"policy","fingerprint":"sha256:pinned"}]},
                 "threats":[{"id":"manual:review","manual":true,"state":"Accepted","title":"Decision","justification":"Reviewed"}],
                 "extension":{"ownedBy":"author"}}
                """;
            string path = Path.Join(this.WorkingDirectory, "layout.tmforge.json");
            File.WriteAllText(path, Json);

            Assert.AreEqual(0, Capture(() => LayoutCommand.Run(new[] { path })).Exit);

            using JsonDocument before = JsonDocument.Parse(Json);
            using JsonDocument after = JsonDocument.Parse(File.ReadAllText(path));
            Assert.AreEqual("source", after.RootElement.GetProperty("elements")[0].GetProperty("id").GetString());
            Assert.AreNotEqual(600, after.RootElement.GetProperty("elements")[0].GetProperty("x").GetInt32());
            foreach (string field in new[] { "flows", "analysis", "threats", "extension" })
            {
                Assert.IsTrue(JsonElement.DeepEquals(before.RootElement.GetProperty(field), after.RootElement.GetProperty(field)), field);
            }
        }

        /// <summary>Duplicate wire ids must be refused before the reader silently rekeys the duplicate.</summary>
        [TestMethod]
        public void LayoutRefusesDuplicateCanonicalJsonIdsWithoutWriting()
        {
            const string Json = """
                {"schema":"tmforge-json","version":"0.1","elements":[
                    {"id":"p","kind":"process","x":100,"y":100,"width":100,"height":60},
                    {"id":"p","kind":"process","x":600,"y":100,"width":100,"height":60}],"flows":[]}
                """;
            string path = Path.Join(this.WorkingDirectory, "duplicate.tmforge.json");
            File.WriteAllText(path, Json);

            Assert.AreEqual(1, Capture(() => LayoutCommand.Run(new[] { path })).Exit);

            Assert.AreEqual(Json, File.ReadAllText(path));
        }

        /// <summary>JSON cannot store engine label handles, so labels-only reports a non-persisted no-op.</summary>
        [TestMethod]
        public void LayoutJsonLabelsOnlyReportsNoPersistedChange()
        {
            const string Json = """
                {"schema":"tmforge-json","version":"0.1","elements":[
                    {"id":"p","kind":"process","x":100,"y":100,"width":100,"height":60}],"flows":[],
                 "extension":"retain"}
                """;
            string path = Path.Join(this.WorkingDirectory, "labels.tmforge.json");
            File.WriteAllText(path, Json);

            (int exit, string output) = Capture(() => LayoutCommand.Run(new[] { path, "--labels", "--json" }));

            Assert.AreEqual(0, exit);
            Assert.AreEqual(Json, File.ReadAllText(path));
            using JsonDocument report = JsonDocument.Parse(output);
            Assert.IsFalse(report.RootElement.GetProperty("data").GetProperty("labelsPersisted").GetBoolean());
            Assert.AreEqual(0, report.RootElement.GetProperty("data").GetProperty("labelsMoved").GetInt32());
        }

        /// <summary>Invalid spacing must be rejected, not ignored or allowed to overlap components.</summary>
        /// <param name="spacing">The invalid spacing argument.</param>
        [TestMethod]
        [DataRow("0")]
        [DataRow("-1")]
        [DataRow("2147483647")]
        [DataRow("not-a-number")]
        public void LayoutRejectsInvalidSpacingWithoutWriting(string spacing)
        {
            string path = this.SaveFixture(LayoutFixture(overlapping: false));
            string before = File.ReadAllText(path);

            Assert.AreEqual(1, Capture(() => LayoutCommand.Run(new[] { path, "--node-spacing", spacing })).Exit);

            Assert.AreEqual(before, File.ReadAllText(path));
        }

        private static string Geometry(ThreatModel model)
        {
            return JsonSerializer.Serialize(model.DrawingSurfaceList.Select(surface => new
            {
                shapes = surface.Borders.Values.OfType<DrawingElement>().Select(element => new
                {
                    element.Guid, element.Left, element.Top, element.Width, element.Height,
                }),
                lines = surface.Lines.Values.OfType<LineElement>().Select(line => new
                {
                    line.Guid, line.SourceX, line.SourceY, line.TargetX, line.TargetY, line.HandleX, line.HandleY,
                }),
            }));
        }

        private static ThreatModel LayoutFixture(bool overlapping)
        {
            ThreatModel model = new ThreatModel();
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Header = "Layout", Guid = Guid.NewGuid() };
            model.DrawingSurfaceList.Add(surface);
            DiagramEditor editor = new DiagramEditor(model);
            Guid source = editor.AddElement(surface, StencilKind.Process, 340, 250);
            Guid target = editor.AddElement(surface, StencilKind.Process, 760, 250);
            editor.SetElementName(surface, source, "Source");
            editor.SetElementName(surface, target, "Target");
            Guid flow = editor.AddConnector(surface, source, target);
            editor.SetElementName(surface, flow, "Request");
            AddFixtureBoundary(surface, 100, 100, 400, 400, "First");
            if (overlapping)
            {
                AddFixtureBoundary(surface, 300, 100, 400, 400, "Second");
            }

            return model;
        }

        private static void AddFixtureBoundary(DrawingSurfaceModel surface, int x, int y, int width, int height, string name)
        {
            BorderBoundary boundary = new BorderBoundary { Guid = Guid.NewGuid(), Left = x, Top = y, Width = width, Height = height };
            DiagramElementHelper.SetName(boundary, name);
            surface.Borders.Add(boundary.Guid, boundary);
        }

        private static string AddElement(string kind, string path, string name)
        {
            (int exit, string stdout) = Capture(() => AddCommand.Run(new[] { kind, path, "--name", name, "--json" }));
            Assert.AreEqual(0, exit);
            using JsonDocument document = JsonDocument.Parse(stdout);
            return document.RootElement.GetProperty("data").GetProperty("id").GetString() ?? string.Empty;
        }

        private static (DrawingElement First, DrawingElement Second) LoadPair(string path, string firstName, string secondName)
        {
            (ThreatModel model, _) = CliModelLoader.Load(path);
            DrawingSurfaceModel diagram = model.DrawingSurfaceList[0];
            DrawingElement first = FindByName(diagram, firstName);
            DrawingElement second = FindByName(diagram, secondName);
            return (first, second);
        }

        private static DrawingElement FindByName(DrawingSurfaceModel diagram, string name)
        {
            foreach (DrawingElement element in diagram.Borders.Values.OfType<DrawingElement>()
                .Where(element => string.Equals(DiagramElementHelper.GetName(element), name, StringComparison.Ordinal)))
            {
                return element;
            }

            throw new InvalidOperationException("Element not found: " + name);
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

        private string NewModel()
        {
            string path = Path.Join(this.WorkingDirectory, "model.tm7");
            Capture(() => NewCommand.Run(new[] { path, "--name", "Test" }));
            return path;
        }

        private string SaveFixture(ThreatModel model)
        {
            string path = Path.Join(this.WorkingDirectory, "layout.tm7");
            using FileStream stream = File.Create(path);
            model.Save(stream);
            return path;
        }
    }
}
