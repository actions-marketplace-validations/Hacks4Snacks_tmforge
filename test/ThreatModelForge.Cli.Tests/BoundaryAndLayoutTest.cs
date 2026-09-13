namespace ThreatModelForge.Cli.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;
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
    }
}
