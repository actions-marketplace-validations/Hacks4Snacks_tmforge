namespace ThreatModelForge.Editing.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for <see cref="DiagramLabels"/>.
    /// </summary>
    [TestClass]
    public class DiagramLabelsTest
    {
        private static readonly Guid NodeA = new Guid("00000000-0000-0000-0000-0000000000a1");
        private static readonly Guid NodeB = new Guid("00000000-0000-0000-0000-0000000000b2");

        /// <summary>
        /// Verifies that two flows between the same pair of elements do not print their names on the
        /// same spot, which is what the geometric midpoint gives them by default.
        /// </summary>
        [TestMethod]
        public void DeconflictSeparatesTwoFlowsBetweenOnePair()
        {
            DrawingSurfaceModel diagram = BuildPair();
            Connector first = AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, "Request submitted for approval");
            Connector second = AddConnector(diagram, "22222222-0000-0000-0000-000000000002", NodeB, NodeA, "Approval result returned");
            Assert.AreEqual(DiagramLabels.LabelCenter(first), DiagramLabels.LabelCenter(second), "the defect under test is that both start in one place");

            DiagramLabels.Deconflict(diagram);

            Assert.AreNotEqual(DiagramLabels.LabelCenter(first), DiagramLabels.LabelCenter(second));
            Assert.AreEqual(0, DiagramLabels.Inspect(diagram).Count(overlap => overlap.Kind == "flow"));
        }

        /// <summary>
        /// Verifies that a label is moved off an element it would otherwise be printed across.
        /// </summary>
        [TestMethod]
        public void DeconflictMovesALabelOffAnElementItCovers()
        {
            DrawingSurfaceModel diagram = BuildPair();
            AddComponent(diagram, new Guid("00000000-0000-0000-0000-0000000000c3"), 260, 84);
            Connector connector = AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, "Credential material handed to the signer");

            Assert.IsTrue(DiagramLabels.Inspect(diagram).Count > 0, "the label must start out covered for this to test anything");

            DiagramLabels.Deconflict(diagram);

            Assert.AreEqual(0, DiagramLabels.Inspect(diagram).Count);
            Assert.IsNotNull(connector);
        }

        /// <summary>
        /// Verifies that placement is a pure function of the diagram, so repeated runs are identical.
        /// </summary>
        [TestMethod]
        public void DeconflictIsDeterministic()
        {
            DrawingSurfaceModel first = BuildCrowdedDiagram();
            DrawingSurfaceModel second = BuildCrowdedDiagram();

            DiagramLabels.Deconflict(first);
            DiagramLabels.Deconflict(second);

            List<(int X, int Y)> left = Centers(first);
            List<(int X, int Y)> right = Centers(second);
            CollectionAssert.AreEqual(left, right);
        }

        /// <summary>
        /// Verifies that a label with nothing in its way is left exactly where the tool would draw it,
        /// so a legible diagram is not perturbed.
        /// </summary>
        [TestMethod]
        public void DeconflictLeavesAClearLabelInPlace()
        {
            DrawingSurfaceModel diagram = BuildPair();
            Connector connector = AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, "Ping");
            (int X, int Y) before = DiagramLabels.LabelCenter(connector);

            DiagramLabels.Deconflict(diagram);

            Assert.AreEqual(before, DiagramLabels.LabelCenter(connector));
        }

        /// <summary>
        /// Verifies that source and target endpoints are untouched, because trust-boundary crossing —
        /// and therefore the analysis — is derived from them.
        /// </summary>
        [TestMethod]
        public void DeconflictLeavesConnectorEndpointsUntouched()
        {
            DrawingSurfaceModel diagram = BuildCrowdedDiagram();
            List<(int, int, int, int)> before = diagram.Lines.Values.OfType<Connector>()
                .OrderBy(connector => connector.Guid)
                .Select(connector => (connector.SourceX, connector.SourceY, connector.TargetX, connector.TargetY))
                .ToList();

            DiagramLabels.Deconflict(diagram);

            List<(int, int, int, int)> after = diagram.Lines.Values.OfType<Connector>()
                .OrderBy(connector => connector.Guid)
                .Select(connector => (connector.SourceX, connector.SourceY, connector.TargetX, connector.TargetY))
                .ToList();
            CollectionAssert.AreEqual(before, after);
        }

        /// <summary>
        /// Verifies that an unnamed connector draws no text and so is not placed.
        /// </summary>
        [TestMethod]
        public void DeconflictIgnoresUnnamedConnectors()
        {
            DrawingSurfaceModel diagram = BuildPair();
            AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, null);
            AddConnector(diagram, "22222222-0000-0000-0000-000000000002", NodeB, NodeA, null);

            Assert.AreEqual(0, DiagramLabels.Deconflict(diagram));
            Assert.AreEqual(0, DiagramLabels.Inspect(diagram).Count);
        }

        /// <summary>
        /// Verifies that a label covered by an element is reported, with the element named.
        /// </summary>
        [TestMethod]
        public void InspectReportsALabelCoveredByAnElement()
        {
            DrawingSurfaceModel diagram = BuildPair();
            DrawingElement blocker = AddComponent(diagram, new Guid("00000000-0000-0000-0000-0000000000c3"), 260, 84);
            DiagramElementHelper.SetName(blocker, "Broker");
            AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, "Credential material handed to the signer");

            IReadOnlyList<LabelOverlap> overlaps = DiagramLabels.Inspect(diagram);

            Assert.AreEqual(1, overlaps.Count);
            Assert.AreEqual("element", overlaps[0].Kind);
            Assert.AreEqual("Broker", overlaps[0].ObstructedBy);
            Assert.IsTrue(overlaps[0].Area > 0);
        }

        /// <summary>
        /// Verifies that a label sitting inside a trust boundary is not reported: a boundary is a
        /// region a label legitimately sits in, not something that covers it.
        /// </summary>
        [TestMethod]
        public void InspectIgnoresTrustBoundaries()
        {
            DrawingSurfaceModel diagram = BuildPair();
            Guid guid = Guid.NewGuid();
            diagram.Borders[guid] = new BorderBoundary { Guid = guid, Left = 0, Top = 0, Width = 600, Height = 400 };
            AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, "Credential material handed to the signer");

            Assert.AreEqual(0, DiagramLabels.Inspect(diagram).Count);
        }

        /// <summary>
        /// Verifies that a null diagram throws rather than being silently ignored.
        /// </summary>
        [TestMethod]
        public void ThrowsOnNullDiagram()
        {
            Assert.Throws<ArgumentNullException>(() => DiagramLabels.Deconflict(null!));
            Assert.Throws<ArgumentNullException>(() => DiagramLabels.Inspect(null!));
        }

        private static List<(int X, int Y)> Centers(DrawingSurfaceModel diagram)
        {
            return diagram.Lines.Values
                .OfType<Connector>()
                .OrderBy(connector => connector.Guid)
                .Select(DiagramLabels.LabelCenter)
                .ToList();
        }

        private static DrawingElement AddComponent(DrawingSurfaceModel diagram, Guid guid, int left, int top)
        {
            StencilEllipse element = new StencilEllipse
            {
                Guid = guid,
                TypeId = "GE.P",
                GenericTypeId = "GE.P",
                Left = left,
                Top = top,
                Width = 100,
                Height = 60,
            };
            diagram.Borders[guid] = element;
            return element;
        }

        private static Connector AddConnector(DrawingSurfaceModel diagram, string guid, Guid source, Guid target, string? name)
        {
            DrawingElement from = (DrawingElement)diagram.Borders[source];
            DrawingElement to = (DrawingElement)diagram.Borders[target];
            Connector connector = new Connector
            {
                Guid = new Guid(guid),
                TypeId = "GE.DF",
                SourceGuid = source,
                TargetGuid = target,
                SourceX = from.Left + from.Width,
                SourceY = from.Top + (from.Height / 2),
                TargetX = to.Left,
                TargetY = to.Top + (to.Height / 2),
            };

            if (name != null)
            {
                DiagramElementHelper.SetName(connector, name);
            }

            diagram.Lines[connector.Guid] = connector;
            return connector;
        }

        private static DrawingSurfaceModel BuildPair()
        {
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Main" };
            AddComponent(diagram, NodeA, 40, 84);
            AddComponent(diagram, NodeB, 480, 84);
            return diagram;
        }

        private static DrawingSurfaceModel BuildCrowdedDiagram()
        {
            DrawingSurfaceModel diagram = BuildPair();
            AddComponent(diagram, new Guid("00000000-0000-0000-0000-0000000000c3"), 260, 84);
            AddConnector(diagram, "11111111-0000-0000-0000-000000000001", NodeA, NodeB, "Rotated encryption key delivered by the manager");
            AddConnector(diagram, "22222222-0000-0000-0000-000000000002", NodeB, NodeA, "Rotation policy consumed by the manager");
            AddConnector(diagram, "33333333-0000-0000-0000-000000000003", NodeA, NodeB, "Snapshot manifest published to the sync job");
            return diagram;
        }
    }
}
