namespace ThreatModelForge.Editing.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for <see cref="DiagramLayout"/>.
    /// </summary>
    [TestClass]
    public class DiagramLayoutTest
    {
        private static readonly Guid NodeA = new Guid("00000000-0000-0000-0000-0000000000a1");
        private static readonly Guid NodeB = new Guid("00000000-0000-0000-0000-0000000000b2");
        private static readonly Guid NodeC = new Guid("00000000-0000-0000-0000-0000000000c3");

        /// <summary>
        /// Verifies that a connected source is placed in an earlier (left) layer than its target.
        /// </summary>
        [TestMethod]
        public void ApplyPlacesConnectedSourceLeftOfTarget()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB);

            DiagramLayout.Apply(diagram);

            Assert.IsTrue(Component(diagram, NodeA).Left < Component(diagram, NodeB).Left);
        }

        /// <summary>
        /// Verifies that layout is a pure function of the input: two identical diagrams lay out identically.
        /// </summary>
        [TestMethod]
        public void ApplyIsDeterministic()
        {
            DrawingSurfaceModel first = BuildChain(NodeA, NodeB, NodeC);
            DrawingSurfaceModel second = BuildChain(NodeA, NodeB, NodeC);

            DiagramLayout.Apply(first);
            DiagramLayout.Apply(second);

            foreach (Guid guid in new[] { NodeA, NodeB, NodeC })
            {
                Assert.AreEqual(Component(first, guid).Left, Component(second, guid).Left);
                Assert.AreEqual(Component(first, guid).Top, Component(second, guid).Top);
            }
        }

        /// <summary>
        /// Verifies that no two components overlap after layout.
        /// </summary>
        [TestMethod]
        public void ApplyProducesNoOverlappingComponents()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB, NodeC);

            // Add a second, disconnected node in the same starting layer as A to exercise stacking.
            Guid extra = new Guid("00000000-0000-0000-0000-0000000000d4");
            AddComponent(diagram, extra);

            DiagramLayout.Apply(diagram);

            List<DrawingElement> components = diagram.Borders.Values.OfType<DrawingElement>().ToList();
            for (int i = 0; i < components.Count; i++)
            {
                for (int j = i + 1; j < components.Count; j++)
                {
                    Assert.IsFalse(Overlaps(components[i], components[j]), "components must not overlap");
                }
            }
        }

        /// <summary>
        /// Verifies that connector endpoints are re-routed to the element edges facing each other.
        /// </summary>
        [TestMethod]
        public void ApplyReroutesConnectorEndpointsToElementEdges()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB);
            Connector connector = diagram.Lines.Values.OfType<Connector>().Single();

            DiagramLayout.Apply(diagram);

            DrawingElement source = Component(diagram, NodeA);
            DrawingElement target = Component(diagram, NodeB);

            // A is left of B on the same row, so the flow leaves A's right edge and enters B's left edge.
            Assert.AreEqual(source.Left + source.Width, connector.SourceX);
            Assert.AreEqual(target.Left, connector.TargetX);
            Assert.AreEqual((connector.SourceX + connector.TargetX) / 2, connector.HandleX);
        }

        /// <summary>
        /// Verifies that a component stays inside the trust boundary it started in. Boundary
        /// membership is what the analysis is derived from, so an arrangement that moved a component
        /// out of its boundary would change the model's meaning rather than just its drawing.
        /// </summary>
        [TestMethod]
        public void ApplyKeepsComponentsInsideTheirTrustBoundary()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB);
            BorderBoundary boundary = AddBoundary(diagram, 500, 600, 300, 200);
            DrawingElement member = Component(diagram, NodeA);
            member.Left = 520;
            member.Top = 620;

            DiagramLayout.Apply(diagram);

            member = Component(diagram, NodeA);
            Assert.IsTrue(
                member.Left >= boundary.Left && member.Top >= boundary.Top
                && member.Left + member.Width <= boundary.Left + boundary.Width
                && member.Top + member.Height <= boundary.Top + boundary.Height,
                "the member must still be inside its boundary");
        }

        /// <summary>
        /// Verifies that a trust boundary is resized around its members instead of keeping a size that
        /// no longer has anything to do with what it holds.
        /// </summary>
        [TestMethod]
        public void ApplyResizesTrustBoundaryAroundItsMembers()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB);
            BorderBoundary boundary = AddBoundary(diagram, 500, 600, 900, 800);
            Component(diagram, NodeA).Left = 520;
            Component(diagram, NodeA).Top = 620;

            DiagramLayout.Apply(diagram);

            DrawingElement member = Component(diagram, NodeA);
            Assert.IsTrue(boundary.Width < 900, "an oversized boundary should shrink to its one member");
            Assert.IsTrue(boundary.Width >= member.Width, "the boundary must still hold its member");
            Assert.IsTrue(boundary.Height >= member.Height, "the boundary must still hold its member");
        }

        /// <summary>
        /// Verifies that two trust boundaries are placed apart, so a member cannot be read as
        /// belonging to the wrong one.
        /// </summary>
        [TestMethod]
        public void ApplySeparatesOverlappingTrustBoundaries()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB);
            BorderBoundary first = AddBoundary(diagram, 100, 100, 400, 400);
            BorderBoundary second = AddBoundary(diagram, 150, 150, 400, 400);
            Component(diagram, NodeA).Left = 120;
            Component(diagram, NodeA).Top = 120;
            Component(diagram, NodeB).Left = 400;
            Component(diagram, NodeB).Top = 400;

            DiagramLayout.Apply(diagram);

            Assert.IsFalse(Overlaps(first, second), "boundaries must not overlap after layout");
        }

        /// <summary>
        /// Verifies that a wide graph wraps onto a new row rather than running off the right-hand edge
        /// of the tool's bounded drawing surface.
        /// </summary>
        [TestMethod]
        public void ApplyWrapsColumnsWithinTheCanvasWidth()
        {
            Guid[] nodes = Enumerable.Range(1, 20)
                .Select(index => new Guid("00000000-0000-0000-0000-0000000000" + index.ToString("x2", CultureInfo.InvariantCulture)))
                .ToArray();
            DrawingSurfaceModel diagram = BuildChain(nodes);
            LayoutOptions options = new LayoutOptions();

            DiagramLayout.Apply(diagram, options);

            int right = diagram.Borders.Values.OfType<DrawingElement>().Max(element => element.Left + element.Width);
            Assert.IsTrue(right <= options.OriginX + options.MaxWidth, "layout must stay within the canvas width, was " + right);
        }

        /// <summary>
        /// Verifies that a cyclic graph lays out without hanging and places each node distinctly.
        /// </summary>
        [TestMethod]
        public void ApplyTerminatesOnCycle()
        {
            DrawingSurfaceModel diagram = BuildChain(NodeA, NodeB);
            AddConnector(diagram, NodeB, NodeA);

            DiagramLayout.Apply(diagram);

            Assert.AreNotEqual(Component(diagram, NodeA).Left, Component(diagram, NodeB).Left);
        }

        /// <summary>
        /// Verifies that an empty diagram is a no-op rather than an error.
        /// </summary>
        [TestMethod]
        public void ApplyIgnoresEmptyDiagram()
        {
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Empty" };

            DiagramLayout.Apply(diagram);

            Assert.AreEqual(0, diagram.Borders.Count);
        }

        /// <summary>
        /// Verifies that a null diagram throws.
        /// </summary>
        [TestMethod]
        public void ApplyThrowsOnNullDiagram()
        {
            Assert.Throws<ArgumentNullException>(() => DiagramLayout.Apply(null!));
        }

        private static bool Overlaps(DrawingElement first, DrawingElement second)
        {
            return !(first.Left + first.Width <= second.Left
                || second.Left + second.Width <= first.Left
                || first.Top + first.Height <= second.Top
                || second.Top + second.Height <= first.Top);
        }

        private static DrawingElement Component(DrawingSurfaceModel diagram, Guid guid)
        {
            return (DrawingElement)diagram.Borders[guid];
        }

        private static void AddComponent(DrawingSurfaceModel diagram, Guid guid)
        {
            diagram.Borders[guid] = new StencilEllipse { Guid = guid, TypeId = "GE.P", GenericTypeId = "GE.P", Width = 100, Height = 60 };
        }

        private static BorderBoundary AddBoundary(DrawingSurfaceModel diagram, int left, int top, int width, int height)
        {
            Guid guid = Guid.NewGuid();
            BorderBoundary boundary = new BorderBoundary { Guid = guid, Left = left, Top = top, Width = width, Height = height };
            diagram.Borders[guid] = boundary;
            return boundary;
        }

        private static void AddConnector(DrawingSurfaceModel diagram, Guid source, Guid target)
        {
            Guid guid = Guid.NewGuid();
            diagram.Lines[guid] = new Connector { Guid = guid, TypeId = "GE.DF", SourceGuid = source, TargetGuid = target };
        }

        private static DrawingSurfaceModel BuildChain(params Guid[] nodes)
        {
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Main" };
            foreach (Guid node in nodes)
            {
                AddComponent(diagram, node);
            }

            for (int i = 0; i < nodes.Length - 1; i++)
            {
                AddConnector(diagram, nodes[i], nodes[i + 1]);
            }

            return diagram;
        }
    }
}
