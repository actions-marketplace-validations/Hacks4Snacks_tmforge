namespace ThreatModelForge.Editing
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Deterministic placement of data-flow labels. A connector's name is drawn as a single unwrapped
    /// line of text at the midpoint of its curve, so a long name occupies far more of the canvas than
    /// the line it belongs to: at the Microsoft Threat Modeling Tool's default font a fifty-character
    /// flow name is wider than a trust boundary. Nothing in the model records that, so a diagram whose
    /// shapes are perfectly placed still renders as overlapping text, and two flows between the same
    /// pair of elements get byte-identical label positions and print on top of each other.
    /// </summary>
    /// <remarks>
    /// This moves the curve handle only. Trust-boundary crossing — and therefore the whole analysis —
    /// is derived from a connector's source and target endpoints, which are left untouched, so
    /// relabelling a diagram cannot change what it means. The handle is chosen by sliding the label
    /// along its own connector first, which leaves the drawn line straight because a control point on
    /// the segment reparameterizes the curve without bending it, and only then by offsetting it into a
    /// parallel lane, which bows the line away from whatever it was covering.
    /// </remarks>
    public static class DiagramLabels
    {
        /// <summary>Fractions along the connector the label is allowed to slide to, nearest the middle first.</summary>
        private static readonly double[] Positions = { 0.50, 0.40, 0.60, 0.32, 0.68, 0.26, 0.74 };

        /// <summary>Lane offsets perpendicular to the connector, in lane widths, nearest first.</summary>
        private static readonly int[] Lanes = { 0, -1, 1, -2, 2, -3, 3 };

        /// <summary>
        /// Chooses a legible position for every named data-flow label on a diagram, in place. The
        /// result is a pure function of the diagram, so repeated runs are byte-identical.
        /// </summary>
        /// <param name="diagram">The diagram to relabel.</param>
        /// <param name="options">Label metrics, or <see langword="null"/> for the defaults.</param>
        /// <returns>The number of connectors whose handle moved.</returns>
        public static int Deconflict(DrawingSurfaceModel diagram, LayoutOptions? options = null)
        {
            return Place(diagram, options, onlyUnplaced: false);
        }

        /// <summary>
        /// Chooses a position for each named data-flow label that has none, leaving every label an
        /// author already positioned exactly where it is and treating those as obstacles to avoid.
        /// </summary>
        /// <remarks>
        /// This is what a format export wants. A model arriving from the canonical tmforge-json — which
        /// carries no connector geometry at all — has no label positions to preserve, so every label
        /// needs one or they all pile onto their connectors' midpoints. A model loaded from a
        /// hand-arranged <c>.tm7</c> has them, and rewriting those would discard a person's work on
        /// the way through a tool that was only asked to save the file. A label still sitting at its
        /// connector's midpoint counts as unplaced: that is where every connector starts.
        /// </remarks>
        /// <param name="diagram">The diagram to relabel.</param>
        /// <param name="options">Label metrics, or <see langword="null"/> for the defaults.</param>
        /// <returns>The number of labels that were given a position.</returns>
        public static int DeconflictUnplaced(DrawingSurfaceModel diagram, LayoutOptions? options = null)
        {
            return Place(diagram, options, onlyUnplaced: true);
        }

        /// <summary>
        /// Reports every data-flow label that is covered by a shape or by another label, worst first.
        /// Reads the diagram without modifying it, so a caller can gate on a diagram being legible
        /// before it is published.
        /// </summary>
        /// <param name="diagram">The diagram to inspect.</param>
        /// <param name="options">Label metrics, or <see langword="null"/> for the defaults.</param>
        /// <returns>The overlapping pairs; empty when every label is clear.</returns>
        public static IReadOnlyList<LabelOverlap> Inspect(DrawingSurfaceModel diagram, LayoutOptions? options = null)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            LayoutOptions effective = options ?? new LayoutOptions();
            List<Connector> connectors = NamedConnectors(diagram).ToList();
            List<Rect> labels = connectors.Select(connector => LabelBox(connector, effective)).ToList();
            List<LabelOverlap> overlaps = new List<LabelOverlap>();

            for (int index = 0; index < connectors.Count; index++)
            {
                foreach (DrawingElement shape in Shapes(diagram))
                {
                    int area = labels[index].Overlap(Rect.Of(shape));
                    if (area > 0)
                    {
                        overlaps.Add(new LabelOverlap(
                            DiagramElementHelper.GetName(connectors[index]),
                            DiagramElementHelper.GetName(shape),
                            "element",
                            area));
                    }
                }

                for (int other = index + 1; other < connectors.Count; other++)
                {
                    int area = labels[index].Overlap(labels[other]);
                    if (area > 0)
                    {
                        overlaps.Add(new LabelOverlap(
                            DiagramElementHelper.GetName(connectors[index]),
                            DiagramElementHelper.GetName(connectors[other]),
                            "flow",
                            area));
                    }
                }
            }

            return overlaps
                .OrderByDescending(overlap => overlap.Area)
                .ThenBy(overlap => overlap.Flow, StringComparer.Ordinal)
                .ThenBy(overlap => overlap.ObstructedBy, StringComparer.Ordinal)
                .ToList();
        }

        /// <summary>
        /// Gets the point a connector's label is drawn at: the midpoint of the quadratic curve through
        /// its handle, which is what the renderer and the Microsoft Threat Modeling Tool both center
        /// the text on.
        /// </summary>
        /// <param name="line">The connector.</param>
        /// <returns>The label's center point.</returns>
        public static (int X, int Y) LabelCenter(LineElement line)
        {
            if (line == null)
            {
                throw new ArgumentNullException(nameof(line));
            }

            return (
                (line.SourceX + (2 * line.HandleX) + line.TargetX) / 4,
                (line.SourceY + (2 * line.HandleY) + line.TargetY) / 4);
        }

        private static int Place(DrawingSurfaceModel diagram, LayoutOptions? options, bool onlyUnplaced)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            LayoutOptions effective = options ?? new LayoutOptions();
            List<Rect> obstacles = ShapeRects(diagram);
            List<Rect> placed = new List<Rect>();
            int moved = 0;

            List<Connector> connectors = NamedConnectors(diagram).ToList();
            if (onlyUnplaced)
            {
                // A label somebody moved keeps its place, but still occupies it: a label being placed
                // now has to avoid it, or honouring that choice would just move the collision. A handle
                // at the endpoint midpoint is the default every connector is created with, so it counts
                // as unplaced rather than as a decision to leave the label there.
                foreach (Connector positioned in connectors.Where(connector => !connector.HandleIsAtMidpoint))
                {
                    placed.Add(LabelBox(positioned, effective));
                }

                connectors = connectors.Where(connector => connector.HandleIsAtMidpoint).ToList();
            }

            foreach (Connector connector in connectors)
            {
                Rect label = LabelBox(connector, effective);
                Rect chosen = label;
                long best = long.MaxValue;

                foreach ((int X, int Y) candidate in Candidates(connector, effective))
                {
                    Rect option = label.CenteredOn(candidate.X, candidate.Y);
                    long cost = Cost(option, obstacles, placed);
                    if (cost < best)
                    {
                        best = cost;
                        chosen = option;
                        if (cost == 0)
                        {
                            break;
                        }
                    }
                }

                placed.Add(chosen);
                if (SetLabelCenter(connector, chosen.CenterX, chosen.CenterY))
                {
                    moved++;
                }
            }

            return moved;
        }

        /// <summary>Moves a connector's handle so its label is drawn centered on a point.</summary>
        /// <param name="line">The connector.</param>
        /// <param name="x">The x coordinate the label should center on.</param>
        /// <param name="y">The y coordinate the label should center on.</param>
        /// <returns><see langword="true"/> when the handle moved.</returns>
        private static bool SetLabelCenter(LineElement line, int x, int y)
        {
            int handleX = ((4 * x) - line.SourceX - line.TargetX) / 2;
            int handleY = ((4 * y) - line.SourceY - line.TargetY) / 2;

            // A handle stored as zero means "unset" and reads back as the endpoint midpoint, which
            // would silently discard the placement. One unit off is invisible and unambiguous.
            handleX = handleX == 0 ? 1 : handleX;
            handleY = handleY == 0 ? 1 : handleY;

            if (line.HandleX == handleX && line.HandleY == handleY)
            {
                return false;
            }

            line.HandleX = handleX;
            line.HandleY = handleY;
            return true;
        }

        /// <summary>
        /// Enumerates the positions a label may take, in order of increasing disturbance: the natural
        /// midpoint first, then slid along the connector, then pushed into parallel lanes.
        /// </summary>
        /// <param name="connector">The connector being labelled.</param>
        /// <param name="options">The label metrics.</param>
        /// <returns>The candidate label centers.</returns>
        private static IEnumerable<(int X, int Y)> Candidates(Connector connector, LayoutOptions options)
        {
            double deltaX = connector.TargetX - connector.SourceX;
            double deltaY = connector.TargetY - connector.SourceY;
            double length = Math.Sqrt((deltaX * deltaX) + (deltaY * deltaY));

            // A connector between two coincident points has no direction to slide or offset along;
            // lanes are stacked straight up so at least the labels do not print on one another.
            (double NormalX, double NormalY) normal = length <= 0.0
                ? (0.0, -1.0)
                : (-deltaY / length, deltaX / length);

            int lanes = Math.Max(0, options.LabelLanes);
            foreach (int lane in Lanes)
            {
                if (Math.Abs(lane) > lanes)
                {
                    continue;
                }

                double offset = lane * options.LabelLaneSpacing;
                foreach (double position in Positions)
                {
                    double x = connector.SourceX + (deltaX * position) + (normal.NormalX * offset);
                    double y = connector.SourceY + (deltaY * position) + (normal.NormalY * offset);
                    yield return ((int)Math.Round(x), (int)Math.Round(y));
                }
            }
        }

        /// <summary>Scores a candidate by how much of it is covered; zero means clear.</summary>
        /// <param name="candidate">The label rectangle being scored.</param>
        /// <param name="obstacles">The shapes on the diagram.</param>
        /// <param name="placed">The labels already positioned.</param>
        /// <returns>The total covered area.</returns>
        private static long Cost(Rect candidate, List<Rect> obstacles, List<Rect> placed)
        {
            long cost = 0;
            foreach (Rect obstacle in obstacles)
            {
                cost += candidate.Overlap(obstacle);
            }

            foreach (Rect label in placed)
            {
                cost += candidate.Overlap(label);
            }

            return cost;
        }

        /// <summary>Builds the rectangle a connector's label currently occupies.</summary>
        /// <param name="connector">The connector.</param>
        /// <param name="options">The label metrics.</param>
        /// <returns>The label rectangle.</returns>
        private static Rect LabelBox(Connector connector, LayoutOptions options)
        {
            int width = Math.Max(
                options.LabelCharacterWidth,
                DiagramElementHelper.GetName(connector).Length * options.LabelCharacterWidth);
            (int x, int y) = LabelCenter(connector);
            return new Rect(x - (width / 2), y - (options.LabelHeight / 2), width, options.LabelHeight);
        }

        /// <summary>
        /// Gets the named connectors of a diagram in identifier order, so placement does not depend on
        /// dictionary enumeration order. An unnamed connector draws no text and is skipped.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <returns>The connectors to label.</returns>
        private static IEnumerable<Connector> NamedConnectors(DrawingSurfaceModel diagram)
        {
            return diagram.Lines.Values
                .OfType<Connector>()
                .Where(connector => !string.IsNullOrWhiteSpace(DiagramElementHelper.GetName(connector)))
                .OrderBy(connector => connector.Guid);
        }

        /// <summary>
        /// Gets the shapes a label must avoid. A trust boundary is excluded: it is a region that a
        /// label legitimately sits inside, not something a label can be covered by.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <returns>The shapes.</returns>
        private static IEnumerable<DrawingElement> Shapes(DrawingSurfaceModel diagram)
        {
            return diagram.Borders.Values
                .OfType<DrawingElement>()
                .Where(element => !(element is BorderBoundary))
                .OrderBy(element => element.Guid);
        }

        /// <summary>Gets the shape rectangles a label must avoid.</summary>
        /// <param name="diagram">The diagram.</param>
        /// <returns>The rectangles.</returns>
        private static List<Rect> ShapeRects(DrawingSurfaceModel diagram)
        {
            return Shapes(diagram).Select(Rect.Of).ToList();
        }

        /// <summary>An axis-aligned rectangle in drawing coordinates.</summary>
        private readonly struct Rect
        {
            public Rect(int x, int y, int width, int height)
            {
                this.X = x;
                this.Y = y;
                this.Width = width;
                this.Height = height;
            }

            public int X { get; }

            public int Y { get; }

            public int Width { get; }

            public int Height { get; }

            public int CenterX => this.X + (this.Width / 2);

            public int CenterY => this.Y + (this.Height / 2);

            public static Rect Of(DrawingElement element)
                => new Rect(element.Left, element.Top, element.Width, element.Height);

            public Rect CenteredOn(int x, int y)
                => new Rect(x - (this.Width / 2), y - (this.Height / 2), this.Width, this.Height);

            public int Overlap(Rect other)
            {
                int width = Math.Min(this.X + this.Width, other.X + other.Width) - Math.Max(this.X, other.X);
                int height = Math.Min(this.Y + this.Height, other.Y + other.Height) - Math.Max(this.Y, other.Y);
                return width > 0 && height > 0 ? width * height : 0;
            }
        }
    }
}
