namespace ThreatModelForge.Formats.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Xml.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for <see cref="DrawIoFormat"/>.
    /// </summary>
    [TestClass]
    public class DrawIoFormatTest
    {
        /// <summary>
        /// Gets or sets the test context, used to locate deployed fixtures.
        /// </summary>
        public TestContext? TestContext { get; set; }

        /// <summary>
        /// Verifies that a real <c>.tm7</c> model writes to a well-formed mxGraph document with
        /// at least one diagram page, one vertex, and one edge.
        /// </summary>
        [TestMethod]
        public void WritesWellFormedMxGraphFromTm7()
        {
            string sourcePath = Path.Join(this.TestContext!.DeploymentDirectory!, "SampleModel.tm7");
            ThreatModel model = ThreatModelFormatRegistry.CreateDefault().Load(sourcePath);

            DrawIoFormat format = new DrawIoFormat();
            using MemoryStream stream = new MemoryStream();
            format.Write(model, stream);
            stream.Position = 0;

            XDocument doc = XDocument.Load(stream);
            Assert.AreEqual("mxfile", doc.Root!.Name.LocalName);

            List<XElement> cells = doc.Descendants().Where(e => e.Name.LocalName == "mxCell").ToList();
            Assert.IsTrue(doc.Descendants().Any(e => e.Name.LocalName == "diagram"), "expected a diagram page");
            Assert.IsTrue(cells.Any(c => c.Attribute("vertex")?.Value == "1"), "expected at least one vertex");
            Assert.IsTrue(cells.Any(c => c.Attribute("edge")?.Value == "1"), "expected at least one edge");
        }

        /// <summary>
        /// Verifies that the provider advertises read and write capabilities.
        /// </summary>
        [TestMethod]
        public void AdvertisesReadWrite()
        {
            DrawIoFormat format = new DrawIoFormat();

            Assert.IsTrue(format.Capabilities.CanRead);
            Assert.IsTrue(format.Capabilities.CanWrite);
        }

        /// <summary>
        /// Verifies content sniffing matches an mxGraph document and rejects a <c>.tm7</c> document,
        /// leaving the stream position unchanged.
        /// </summary>
        [TestMethod]
        public void CanReadSniffsMxGraph()
        {
            DrawIoFormat format = new DrawIoFormat();

            using (MemoryStream mx = new MemoryStream(Encoding.UTF8.GetBytes("<mxfile host=\"ThreatModelForge\"><diagram/></mxfile>")))
            using (MemoryStream xml = new MemoryStream(
                Encoding.UTF8.GetBytes("<ThreatModel xmlns=\"http://schemas.datacontract.org/2004/07/ThreatModeling.Model\">")))
            {
                Assert.IsTrue(format.CanRead(mx));
                Assert.AreEqual(0, mx.Position);
                Assert.IsFalse(format.CanRead(xml));
            }
        }

        /// <summary>
        /// Verifies that an empty model still produces a valid single-page document.
        /// </summary>
        [TestMethod]
        public void EmptyModelProducesOnePage()
        {
            DrawIoFormat format = new DrawIoFormat();
            using MemoryStream stream = new MemoryStream();

            format.Write(new ThreatModel(), stream);
            stream.Position = 0;

            XDocument doc = XDocument.Load(stream);
            Assert.AreEqual(1, doc.Descendants().Count(e => e.Name.LocalName == "diagram"));
        }

        /// <summary>
        /// Verifies that the structural diagram survives a write-then-read round-trip through the
        /// engine model: the vertex (component and boundary) count and the connector count are
        /// preserved when a real <c>.tm7</c> model is exported to mxGraph and imported back.
        /// </summary>
        [TestMethod]
        public void RoundTripsStructureThroughModel()
        {
            string sourcePath = Path.Join(this.TestContext!.DeploymentDirectory!, "SampleModel.tm7");
            ThreatModel original = ThreatModelFormatRegistry.CreateDefault().Load(sourcePath);

            DrawIoFormat format = new DrawIoFormat();
            using MemoryStream stream = new MemoryStream();
            format.Write(original, stream);
            stream.Position = 0;
            ThreatModel roundTripped = format.Read(stream);

            int originalVertices = CountVertices(original);
            int originalConnectors = CountConnectors(original);

            Assert.IsTrue(originalVertices > 0, "fixture should contain at least one component");
            Assert.IsTrue(originalConnectors > 0, "fixture should contain at least one connector");
            Assert.AreEqual(originalVertices, CountVertices(roundTripped), "vertex count should survive the round-trip");
            Assert.AreEqual(originalConnectors, CountConnectors(roundTripped), "connector count should survive the round-trip");
        }

        /// <summary>
        /// Verifies that a trust-boundary line with an offset handle is written as a curved mxGraph
        /// edge (a <c>curved=1</c> style with an on-curve waypoint).
        /// </summary>
        [TestMethod]
        public void WritesCurvedBoundaryLine()
        {
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "D" };
            LineBoundary boundary = new LineBoundary
            {
                Guid = Guid.NewGuid(),
                SourceX = 0,
                SourceY = 0,
                TargetX = 200,
                TargetY = 0,
                HandleX = 100,
                HandleY = 80,
            };
            surface.Lines[boundary.Guid] = boundary;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);

            using MemoryStream stream = new MemoryStream();
            new DrawIoFormat().Write(model, stream);
            stream.Position = 0;
            XDocument doc = XDocument.Load(stream);

            XElement edge = doc.Descendants().First(e => e.Name.LocalName == "mxCell" && e.Attribute("edge")?.Value == "1");
            StringAssert.Contains((string?)edge.Attribute("style"), "curved=1");
            Assert.IsTrue(
                edge.Descendants().Any(e => e.Name.LocalName == "Array" && e.Attribute("as")?.Value == "points"),
                "expected a curve waypoint");
        }

        /// <summary>Unreadable graphs are not accepted as empty or incomplete models.</summary>
        /// <param name="xml">The malformed draw.io input.</param>
        [TestMethod]
        [DataRow("<ThreatModel />")]
        [DataRow("<mxfile />")]
        [DataRow("<mxGraphModel><root><mxCell id='x' vertex='1'/><mxCell id='x' vertex='1'/></root></mxGraphModel>")]
        [DataRow("<mxGraphModel><root><mxCell id='x' vertex='1'/><mxCell id='flow' edge='1' source='x' target='missing'/></root></mxGraphModel>")]
        [DataRow("<mxGraphModel><root><mxCell id='flow' edge='1' source='missing'/></root></mxGraphModel>")]
        public void ReadRejectsMalformedGraphs(string xml)
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(xml));

            Assert.Throws<InvalidDataException>(() => new DrawIoFormat().Read(stream));
        }

        /// <summary>Compressed input is explicitly refused instead of returning an empty diagram.</summary>
        [TestMethod]
        public void ReadRejectsUnsupportedCompressedPage()
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes("<mxfile><diagram>compressed-payload</diagram></mxfile>"));

            StringAssert.Contains(Assert.Throws<NotSupportedException>(() => new DrawIoFormat().Read(stream)).Message, "uncompressed XML");
        }

        /// <summary>Preflight can identify each omitted free-standing edge and inferred shape.</summary>
        [TestMethod]
        public void ReadReportsOmittedContent()
        {
            const string Xml = "<mxGraphModel><root><mxCell id='node' vertex='1'/><mxCell id='line' edge='1'/></root></mxGraphModel>";
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(Xml));
            List<DocumentDiagnostic> diagnostics = new List<DocumentDiagnostic>();

            ThreatModel model = new DrawIoFormat().Read(stream, diagnostics);

            Assert.AreEqual(1, model.DrawingSurfaceList[0].Borders.Count);
            Assert.IsTrue(diagnostics.Any(item => item.Code == "import.omitted-edge" && item.Path.Contains("line", StringComparison.Ordinal)));
            Assert.IsTrue(diagnostics.Any(item => item.Code == "import.inferred-kind" && item.Path.Contains("node", StringComparison.Ordinal)));
        }

        private static int CountVertices(ThreatModel model)
        {
            return model.DrawingSurfaceList.Sum(surface => surface.Borders.Values.OfType<DrawingElement>().Count());
        }

        private static int CountConnectors(ThreatModel model)
        {
            int total = 0;
            foreach (DrawingSurfaceModel surface in model.DrawingSurfaceList)
            {
                HashSet<Guid> vertexIds = new HashSet<Guid>(surface.Borders.Values.OfType<DrawingElement>().Select(e => e.Guid));
                total += surface.Lines.Values.OfType<Connector>()
                    .Count(c => vertexIds.Contains(c.SourceGuid) && vertexIds.Contains(c.TargetGuid));
            }

            return total;
        }
    }
}
