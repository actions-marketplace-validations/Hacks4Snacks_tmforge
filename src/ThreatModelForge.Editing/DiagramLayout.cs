namespace ThreatModelForge.Editing
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Deterministic, dependency-free automatic layout for a diagram. Given a logical graph whose
    /// components may lack coordinates — for example, an agent- or CLI-authored model — it assigns
    /// readable, non-overlapping positions using a layered left-to-right placement derived from the
    /// data-flow connectors, then re-routes connector endpoints to the element edges and places the
    /// flow labels so they do not print over one another. The result is a pure function of the input,
    /// so repeated runs are byte-identical.
    /// </summary>
    /// <remarks>
    /// Layout is trust-boundary aware. Every component keeps the boundary it was inside, because a
    /// boundary is not decoration: which boundaries a flow crosses is what the analysis is derived
    /// from, so an arrangement that moved a component out of its boundary would silently change the
    /// model's meaning rather than just its drawing. Members are arranged within their boundary, the
    /// boundary is then sized to hold exactly them, and the boundaries themselves are arranged by the
    /// flows between them. Columns wrap onto a new row rather than running off the canvas, because the
    /// Microsoft Threat Modeling Tool's drawing surface is bounded and taller than it is wide.
    /// <para>
    /// One case cannot be preserved: a component sitting in the intersection of two boundaries that
    /// merely overlap. Nesting is representable and is kept, but a partial overlap is not, so such a
    /// component keeps only the innermost boundary and the arrangement drops the other claim on it.
    /// Overlapping boundaries are a modelling defect rather than a drawing one — they assert two
    /// unrelated trust claims over one shape — so resolve them in the model before laying it out.
    /// </para>
    /// </remarks>
    public static class DiagramLayout
    {
        /// <summary>The size given to a trust boundary that holds nothing.</summary>
        private const int EmptyBoundarySize = 120;

        /// <summary>
        /// Applies the layered auto-layout to the supplied diagram in place.
        /// </summary>
        /// <param name="diagram">The diagram to lay out.</param>
        /// <param name="options">Spacing options, or <see langword="null"/> for the defaults.</param>
        /// <returns>The number of flow labels that were moved clear of an obstruction.</returns>
        public static int Apply(DrawingSurfaceModel diagram, LayoutOptions? options = null)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            LayoutOptions effectiveOptions = options ?? new LayoutOptions();

            List<DrawingElement> components = CollectComponents(diagram);
            if (components.Count == 0)
            {
                return 0;
            }

            HashSet<Guid> componentGuids = new HashSet<Guid>(components.Select(element => element.Guid));
            List<(Guid Source, Guid Target)> edges = CollectEdges(diagram, componentGuids);

            Group root = BuildGroups(diagram, components);
            Measure(root, edges, effectiveOptions, effectiveOptions.MaxWidth);
            Place(root, effectiveOptions.OriginX, effectiveOptions.OriginY, effectiveOptions);

            RerouteConnectors(diagram, componentGuids);
            return DiagramLabels.Deconflict(diagram, effectiveOptions);
        }

        private static List<DrawingElement> CollectComponents(DrawingSurfaceModel diagram)
        {
            return diagram.Borders.Values
                .OfType<DrawingElement>()
                .Where(element => !(element is BorderBoundary))
                .OrderBy(element => element.Guid)
                .ToList();
        }

        private static List<(Guid Source, Guid Target)> CollectEdges(DrawingSurfaceModel diagram, HashSet<Guid> componentGuids)
        {
            return diagram.Lines.Values
                .OfType<Connector>()
                .Where(connector => connector.SourceGuid != connector.TargetGuid
                    && componentGuids.Contains(connector.SourceGuid)
                    && componentGuids.Contains(connector.TargetGuid))
                .Select(connector => (connector.SourceGuid, connector.TargetGuid))
                .OrderBy(edge => edge.SourceGuid)
                .ThenBy(edge => edge.TargetGuid)
                .ToList();
        }

        /// <summary>
        /// Builds the containment tree the layout preserves: each component joins the innermost trust
        /// boundary that currently holds it, and each boundary joins the innermost boundary that
        /// currently holds it. Membership is read from the existing geometry because that is exactly
        /// what the analyzer reads, so the arrangement cannot disagree with the analysis.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <param name="components">The components to place.</param>
        /// <returns>The root group, whose members and children are the unbounded objects.</returns>
        private static Group BuildGroups(DrawingSurfaceModel diagram, List<DrawingElement> components)
        {
            List<BorderBoundary> boundaries = diagram.Borders.Values
                .OfType<BorderBoundary>()
                .OrderBy(boundary => boundary.Guid)
                .ToList();

            Group root = new Group(null);
            Dictionary<Guid, Group> groups = boundaries.ToDictionary(
                boundary => boundary.Guid,
                boundary => new Group(boundary));

            foreach (BorderBoundary boundary in boundaries)
            {
                // Strictly larger, so two boundaries drawn on one rectangle cannot each claim the other
                // as its parent and produce a cycle in the tree.
                BorderBoundary? parent = boundaries
                    .Where(other => other.Guid != boundary.Guid
                        && Area(other) > Area(boundary)
                        && Contains(other, boundary.Left, boundary.Top)
                        && Contains(other, boundary.Left + boundary.Width, boundary.Top + boundary.Height))
                    .OrderBy(Area)
                    .ThenBy(other => other.Guid)
                    .FirstOrDefault();

                (parent == null ? root : groups[parent.Guid]).Children.Add(groups[boundary.Guid]);
            }

            foreach (DrawingElement component in components)
            {
                BorderBoundary? host = boundaries
                    .Where(boundary => Contains(
                        boundary,
                        component.Left + (component.Width / 2),
                        component.Top + (component.Height / 2)))
                    .OrderBy(Area)
                    .ThenBy(boundary => boundary.Guid)
                    .FirstOrDefault();

                (host == null ? root : groups[host.Guid]).Members.Add(component);
            }

            return root;
        }

        /// <summary>
        /// Arranges a group's contents and records the size it needs, innermost group first.
        /// </summary>
        /// <param name="group">The group to measure.</param>
        /// <param name="edges">Every data flow in the diagram, as component pairs.</param>
        /// <param name="options">The spacing options.</param>
        /// <param name="available">The width the group's contents may occupy before wrapping.</param>
        private static void Measure(Group group, List<(Guid Source, Guid Target)> edges, LayoutOptions options, int available)
        {
            int padding = group.Boundary == null ? 0 : options.BoundaryPadding;
            int inner = Math.Max(EmptyBoundarySize, available - (2 * padding));

            foreach (Group child in group.Children.OrderBy(child => child.Key))
            {
                Measure(child, edges, options, inner);
            }

            group.Cells.AddRange(group.Members.OrderBy(member => member.Guid).Select(Cell.For));
            group.Cells.AddRange(group.Children.OrderBy(child => child.Key).Select(Cell.For));
            foreach (Cell cell in group.Cells)
            {
                group.Reach.UnionWith(cell.Reach);
            }

            if (group.Cells.Count == 0)
            {
                group.Width = group.Boundary == null ? 0 : EmptyBoundarySize;
                group.Height = group.Boundary == null ? 0 : EmptyBoundarySize;
                return;
            }

            (int contentWidth, int contentHeight) = PlaceCells(group, edges, options, inner);
            group.Width = contentWidth + (2 * padding);
            group.Height = contentHeight + (2 * padding) + (group.Boundary == null ? 0 : options.BoundaryHeaderHeight);
        }

        /// <summary>
        /// Assigns each cell of a group an offset relative to the group's content box, by layering the
        /// cells left to right along the flows between them and wrapping onto a new row when a column
        /// run would exceed the available width.
        /// </summary>
        /// <param name="group">The group whose cells are being placed.</param>
        /// <param name="edges">Every data flow in the diagram, as component pairs.</param>
        /// <param name="options">The spacing options.</param>
        /// <param name="available">The width the content may occupy before wrapping.</param>
        /// <returns>The size of the arranged content.</returns>
        private static (int Width, int Height) PlaceCells(
            Group group,
            List<(Guid Source, Guid Target)> edges,
            LayoutOptions options,
            int available)
        {
            List<List<Cell>> layers = AssignLayers(group.Cells, CellEdges(group, edges));

            int contentWidth = 0;
            int contentHeight = 0;
            int columnX = 0;
            int rowTop = 0;
            int rowBottom = 0;

            foreach (List<Cell> column in layers)
            {
                int columnWidth = column.Max(cell => cell.Width);
                if (columnX > 0 && columnX + columnWidth > available)
                {
                    columnX = 0;
                    rowTop = rowBottom + options.NodeSpacing;
                }

                int y = rowTop;
                foreach (Cell cell in column)
                {
                    cell.OffsetX = columnX + ((columnWidth - cell.Width) / 2);
                    cell.OffsetY = y;
                    y += cell.Height + options.NodeSpacing;
                    contentWidth = Math.Max(contentWidth, cell.OffsetX + cell.Width);
                    contentHeight = Math.Max(contentHeight, cell.OffsetY + cell.Height);
                }

                rowBottom = Math.Max(rowBottom, y - options.NodeSpacing);
                columnX += columnWidth + options.LayerSpacing;
            }

            return (contentWidth, contentHeight);
        }

        /// <summary>
        /// Projects the diagram's flows onto a group's own cells: a flow between two components in
        /// different cells of this group orders those cells, and one that stays inside a single cell
        /// is that cell's own business.
        /// </summary>
        /// <param name="group">The group.</param>
        /// <param name="edges">Every data flow in the diagram, as component pairs.</param>
        /// <returns>The distinct ordered cell pairs.</returns>
        private static List<(int Source, int Target)> CellEdges(Group group, List<(Guid Source, Guid Target)> edges)
        {
            Dictionary<Guid, int> owner = new Dictionary<Guid, int>();
            for (int index = 0; index < group.Cells.Count; index++)
            {
                foreach (Guid component in group.Cells[index].Reach)
                {
                    owner[component] = index;
                }
            }

            HashSet<(int Source, int Target)> seen = new HashSet<(int Source, int Target)>();
            List<(int Source, int Target)> projected = new List<(int Source, int Target)>();
            foreach ((Guid source, Guid target) in edges)
            {
                if (owner.TryGetValue(source, out int from) &&
                    owner.TryGetValue(target, out int to) &&
                    from != to &&
                    seen.Add((from, to)))
                {
                    projected.Add((from, to));
                }
            }

            return projected;
        }

        private static List<List<Cell>> AssignLayers(List<Cell> cells, List<(int Source, int Target)> edges)
        {
            // Longest-path layering by bounded relaxation: layer[target] = max(layer[source] + 1).
            // The pass count is capped at the node count so a cyclic graph terminates deterministically
            // instead of relaxing forever.
            int[] layerOf = new int[cells.Count];
            for (int pass = 0; pass < cells.Count; pass++)
            {
                bool changed = false;
                foreach ((int source, int target) in edges)
                {
                    int candidate = layerOf[source] + 1;
                    if (candidate > layerOf[target])
                    {
                        layerOf[target] = candidate;
                        changed = true;
                    }
                }

                if (!changed)
                {
                    break;
                }
            }

            return cells
                .Select((cell, index) => (Cell: cell, Layer: layerOf[index]))
                .GroupBy(entry => entry.Layer)
                .OrderBy(layer => layer.Key)
                .Select(layer => layer.Select(entry => entry.Cell).OrderBy(cell => cell.Key).ToList())
                .ToList();
        }

        /// <summary>
        /// Writes a measured group's arrangement to the diagram, outermost group first.
        /// </summary>
        /// <param name="group">The measured group.</param>
        /// <param name="x">The left edge the group occupies.</param>
        /// <param name="y">The top edge the group occupies.</param>
        /// <param name="options">The spacing options.</param>
        private static void Place(Group group, int x, int y, LayoutOptions options)
        {
            if (group.Boundary != null)
            {
                group.Boundary.Left = x;
                group.Boundary.Top = y;
                group.Boundary.Width = group.Width;
                group.Boundary.Height = group.Height;
            }

            int padding = group.Boundary == null ? 0 : options.BoundaryPadding;
            int header = group.Boundary == null ? 0 : options.BoundaryHeaderHeight;
            int innerX = x + padding;
            int innerY = y + padding + header;

            foreach (Cell cell in group.Cells)
            {
                if (cell.Element != null)
                {
                    cell.Element.Left = innerX + cell.OffsetX;
                    cell.Element.Top = innerY + cell.OffsetY;
                }
                else
                {
                    Place(cell.Child!, innerX + cell.OffsetX, innerY + cell.OffsetY, options);
                }
            }
        }

        private static void RerouteConnectors(DrawingSurfaceModel diagram, HashSet<Guid> componentGuids)
        {
            foreach (Connector connector in diagram.Lines.Values.OfType<Connector>())
            {
                if (!componentGuids.Contains(connector.SourceGuid) || !componentGuids.Contains(connector.TargetGuid))
                {
                    continue;
                }

                (int sourceCenterX, int sourceCenterY) = DiagramGeometry.CenterOf(diagram, connector.SourceGuid);
                (int targetCenterX, int targetCenterY) = DiagramGeometry.CenterOf(diagram, connector.TargetGuid);
                (int sourceX, int sourceY) = DiagramGeometry.EdgePoint(diagram, connector.SourceGuid, targetCenterX, targetCenterY);
                (int targetX, int targetY) = DiagramGeometry.EdgePoint(diagram, connector.TargetGuid, sourceCenterX, sourceCenterY);

                connector.SourceX = sourceX;
                connector.SourceY = sourceY;
                connector.TargetX = targetX;
                connector.TargetY = targetY;
                connector.HandleX = (sourceX + targetX) / 2;
                connector.HandleY = (sourceY + targetY) / 2;
            }
        }

        private static long Area(DrawingElement element) => (long)element.Width * element.Height;

        private static bool Contains(DrawingElement outer, int x, int y)
            => x >= outer.Left && x <= outer.Left + outer.Width
            && y >= outer.Top && y <= outer.Top + outer.Height;

        /// <summary>A trust boundary and everything drawn inside it, arranged as a unit.</summary>
        private sealed class Group
        {
            public Group(BorderBoundary? boundary)
            {
                this.Boundary = boundary;
            }

            /// <summary>Gets the boundary this group draws, or <see langword="null"/> for the page itself.</summary>
            public BorderBoundary? Boundary { get; }

            /// <summary>Gets the components directly inside this boundary.</summary>
            public List<DrawingElement> Members { get; } = new List<DrawingElement>();

            /// <summary>Gets the boundaries nested directly inside this one.</summary>
            public List<Group> Children { get; } = new List<Group>();

            /// <summary>Gets the arranged contents, in placement order.</summary>
            public List<Cell> Cells { get; } = new List<Cell>();

            /// <summary>Gets every component in this group's subtree.</summary>
            public HashSet<Guid> Reach { get; } = new HashSet<Guid>();

            /// <summary>Gets the identifier this group sorts by.</summary>
            public Guid Key => this.Boundary?.Guid ?? Guid.Empty;

            /// <summary>Gets or sets the measured width.</summary>
            public int Width { get; set; }

            /// <summary>Gets or sets the measured height.</summary>
            public int Height { get; set; }
        }

        /// <summary>One arranged item of a group: either a component or a nested boundary.</summary>
        private sealed class Cell
        {
            private Cell(DrawingElement? element, Group? child)
            {
                this.Element = element;
                this.Child = child;
            }

            /// <summary>Gets the component this cell holds, or <see langword="null"/> when it holds a boundary.</summary>
            public DrawingElement? Element { get; }

            /// <summary>Gets the nested boundary this cell holds, or <see langword="null"/> when it holds a component.</summary>
            public Group? Child { get; }

            /// <summary>Gets or sets the left offset within the owning group's content box.</summary>
            public int OffsetX { get; set; }

            /// <summary>Gets or sets the top offset within the owning group's content box.</summary>
            public int OffsetY { get; set; }

            /// <summary>Gets the width this cell occupies.</summary>
            public int Width => this.Element?.Width ?? this.Child!.Width;

            /// <summary>Gets the height this cell occupies.</summary>
            public int Height => this.Element?.Height ?? this.Child!.Height;

            /// <summary>Gets the identifier this cell sorts by.</summary>
            public Guid Key => this.Element?.Guid ?? this.Child!.Key;

            /// <summary>Gets every component this cell contains.</summary>
            public IEnumerable<Guid> Reach => this.Element != null
                ? new[] { this.Element.Guid }
                : this.Child!.Reach;

            /// <summary>Creates a cell for a component.</summary>
            /// <param name="element">The component.</param>
            /// <returns>The cell.</returns>
            public static Cell For(DrawingElement element) => new Cell(element, null);

            /// <summary>Creates a cell for a nested boundary.</summary>
            /// <param name="child">The nested group.</param>
            /// <returns>The cell.</returns>
            public static Cell For(Group child) => new Cell(null, child);
        }
    }
}
