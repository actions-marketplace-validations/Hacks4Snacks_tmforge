namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Arranges geometry on a candidate, checks it against the analyzer's actual trust-boundary
    /// semantics, and commits only when every requested page is safe. No rules are evaluated and no
    /// identities, properties, or threat-register entries are rewritten.
    /// </summary>
    public static class LayoutOperations
    {
        /// <summary>The maximum number of shapes in one arrangement request.</summary>
        public const int MaximumElements = 512;

        /// <summary>The maximum number of lines in one arrangement request.</summary>
        public const int MaximumLines = 1024;

        /// <summary>The maximum number of pages in one arrangement request.</summary>
        public const int MaximumPages = 32;

        private const int MaximumCoordinate = 1000000;
        private const int MaximumSize = 100000;
        private const long MaximumWork = 25000000;

        /// <summary>
        /// Tries to arrange all supplied pages atomically, or validates the supplied cleanup
        /// positions without rearranging them. A refused candidate leaves every page untouched.
        /// </summary>
        /// <param name="diagrams">The pages to arrange.</param>
        /// <param name="options">Spacing and label metrics, or the defaults.</param>
        /// <param name="labelsMoved">The number of labels moved on success.</param>
        /// <param name="error">The reason the arrangement was refused.</param>
        /// <param name="positions">Optional complete proposed placement to validate instead of generating a layout.</param>
        /// <returns>Whether every page could be arranged without changing its meaning.</returns>
        public static bool TryApply(
            IReadOnlyList<DrawingSurfaceModel> diagrams,
            LayoutOptions? options,
            out int labelsMoved,
            out string? error,
            IReadOnlyDictionary<Guid, LayoutElementDto>? positions = null)
        {
            if (diagrams == null)
            {
                throw new ArgumentNullException(nameof(diagrams));
            }

            labelsMoved = 0;
            LayoutOptions effective = options ?? new LayoutOptions();
            error = Validate(diagrams, effective);
            if (error != null)
            {
                return false;
            }

            if (positions != null && (positions.Count != diagrams.Sum(diagram => diagram.Borders.Count)
                || diagrams.SelectMany(diagram => diagram.Borders.Keys).Any(id => !positions.ContainsKey(id))))
            {
                error = "Proposed positions must name every selected element exactly once.";
                return false;
            }

            List<DrawingSurfaceModel> candidates = new List<DrawingSurfaceModel>();
            int moved = 0;
            foreach (DrawingSurfaceModel diagram in diagrams)
            {
                DrawingSurfaceModel candidate = CopyGeometry(diagram);
                if (positions == null)
                {
                    moved += DiagramLayout.Apply(candidate, effective);
                }
                else
                {
                    foreach (DrawingElement element in candidate.Borders.Values.OfType<DrawingElement>())
                    {
                        LayoutElementDto position = positions[element.Guid];
                        element.Left = position.X;
                        element.Top = position.Y;
                        element.Width = position.Width;
                        element.Height = position.Height;
                    }

                    error = Validate(new[] { candidate }, effective);
                    if (error != null)
                    {
                        return false;
                    }

                    DiagramGeometry.RerouteConnectors(candidate);
                }

                error = Validate(new[] { candidate }, effective) ?? FindSemanticChange(diagram, candidate);
                if (error != null)
                {
                    error += " No pages were changed. Keep the geometry and use label-only cleanup, or resolve the boundary placement explicitly.";
                    return false;
                }

                candidates.Add(candidate);
            }

            for (int index = 0; index < diagrams.Count; index++)
            {
                CommitGeometry(candidates[index], diagrams[index]);
            }

            labelsMoved = moved;
            return true;
        }

        private static string? Validate(
            IReadOnlyList<DrawingSurfaceModel> diagrams,
            LayoutOptions options)
        {
            if (diagrams.Count > MaximumPages
                || diagrams.Sum(diagram => (long)diagram.Borders.Count) > MaximumElements
                || diagrams.Sum(diagram => (long)diagram.Lines.Count) > MaximumLines)
            {
                return $"Arrangement is limited to {MaximumPages} pages, {MaximumElements} shapes and {MaximumLines} lines per request.";
            }

            if (!Within(options.OriginX, -MaximumCoordinate, MaximumCoordinate)
                || !Within(options.OriginY, -MaximumCoordinate, MaximumCoordinate)
                || !Within(options.NodeSpacing, 1, 4096)
                || !Within(options.LayerSpacing, 1, 4096)
                || !Within(options.BoundaryPadding, 1, 4096)
                || !Within(options.BoundaryHeaderHeight, 1, 4096)
                || !Within(options.MaxWidth, 120, MaximumSize)
                || !Within(options.LabelCharacterWidth, 1, 64)
                || !Within(options.LabelHeight, 1, 512)
                || !Within(options.LabelLaneSpacing, 1, 4096)
                || !Within(options.LabelLanes, 0, 3))
            {
                return "Invalid arrangement metrics: spacing, boundary padding and header height must be between 1 and 4096; all other metrics must be within their documented limits.";
            }

            HashSet<Guid> ids = new HashSet<Guid>();
            long work = 0;
            foreach (DrawingSurfaceModel diagram in diagrams)
            {
                // Bound the quadratic label search as well as the graph size. Its candidate count
                // is at most seven positions in each of seven lanes (DiagramLabels).
                long lines = diagram.Lines.Count;
                long shapes = diagram.Borders.Count;
                work += (49 * lines * (lines + shapes)) + (shapes * shapes) + (shapes * lines);
                if (work > MaximumWork)
                {
                    return "Arrangement exceeds the layout work budget. Split the diagram into smaller pages.";
                }

                foreach (KeyValuePair<Guid, object> entry in diagram.Borders)
                {
                    if (entry.Value is not DrawingElement element || entry.Key != element.Guid || !ids.Add(element.Guid))
                    {
                        return "Arrangement requires uniquely identified drawing elements.";
                    }

                    if (!Within(element.Left, -MaximumCoordinate, MaximumCoordinate)
                        || !Within(element.Top, -MaximumCoordinate, MaximumCoordinate)
                        || !Within(element.Width, 1, MaximumSize)
                        || !Within(element.Height, 1, MaximumSize)
                        || DiagramElementHelper.GetName(element).Length > 4096)
                    {
                        return "Arrangement requires positive shape sizes up to 100000, coordinates within +/-1000000 and names of at most 4096 characters.";
                    }
                }

                foreach (KeyValuePair<Guid, object> entry in diagram.Lines)
                {
                    if (entry.Value is not LineElement line
                        || (line is not Connector && line is not LineBoundary)
                        || entry.Key != line.Guid || !ids.Add(line.Guid))
                    {
                        return "Arrangement requires uniquely identified connectors or trust-boundary lines.";
                    }

                    if (!Within(line.SourceX, -MaximumCoordinate, MaximumCoordinate)
                        || !Within(line.SourceY, -MaximumCoordinate, MaximumCoordinate)
                        || !Within(line.TargetX, -MaximumCoordinate, MaximumCoordinate)
                        || !Within(line.TargetY, -MaximumCoordinate, MaximumCoordinate)
                        || DiagramElementHelper.GetName(line).Length > 4096)
                    {
                        return "Arrangement requires line endpoints within +/-1000000 and names of at most 4096 characters.";
                    }

                    if (line is Connector && (!diagram.Borders.ContainsKey(line.SourceGuid) || !diagram.Borders.ContainsKey(line.TargetGuid)))
                    {
                        return "Arrangement requires both endpoints of every flow to exist on its page.";
                    }

                    if (line is Connector && (diagram.Borders[line.SourceGuid] is BorderBoundary || diagram.Borders[line.TargetGuid] is BorderBoundary))
                    {
                        return "Arrangement requires flows to connect components, not trust boundaries. Use label-only cleanup for this page.";
                    }
                }
            }

            return null;
        }

        private static bool Within(int value, int minimum, int maximum) => value >= minimum && value <= maximum;

        private static DrawingSurfaceModel CopyGeometry(DrawingSurfaceModel source)
        {
            DrawingSurfaceModel copy = new DrawingSurfaceModel { Guid = source.Guid, Header = source.Header };
            foreach (DrawingElement original in source.Borders.Values.OfType<DrawingElement>())
            {
                // Layout uses bounding rectangles, not stencil rendering. These are geometry-only
                // proxies: the originals' types and properties are never replaced on commit.
                DrawingElement element = original is BorderBoundary ? new BorderBoundary() : new StencilRectangle();
                element.Guid = original.Guid;
                element.Left = original.Left;
                element.Top = original.Top;
                element.Width = original.Width;
                element.Height = original.Height;
                DiagramElementHelper.SetName(element, DiagramElementHelper.GetName(original));
                copy.Borders.Add(element.Guid, element);
            }

            foreach (LineElement original in source.Lines.Values.OfType<LineElement>())
            {
                LineElement line = original is LineBoundary ? new LineBoundary() : new Connector();
                line.Guid = original.Guid;
                line.SourceGuid = original.SourceGuid;
                line.TargetGuid = original.TargetGuid;
                line.SourceX = original.SourceX;
                line.SourceY = original.SourceY;
                line.TargetX = original.TargetX;
                line.TargetY = original.TargetY;
                line.HandleX = original.HandleX;
                line.HandleY = original.HandleY;
                DiagramElementHelper.SetName(line, DiagramElementHelper.GetName(original));
                copy.Lines.Add(line.Guid, line);
            }

            return copy;
        }

        private static string? FindSemanticChange(DrawingSurfaceModel before, DrawingSurfaceModel after)
        {
            foreach (BorderBoundary boundary in before.Borders.Values.OfType<BorderBoundary>())
            {
                BorderBoundary placedBoundary = (BorderBoundary)after.Borders[boundary.Guid];
                foreach (DrawingElement element in before.Borders.Values.OfType<DrawingElement>().Where(element => element is not BorderBoundary))
                {
                    DrawingElement placed = (DrawingElement)after.Borders[element.Guid];
                    bool wasMember = boundary.Contains(element.Left + (element.Width / 2), element.Top + (element.Height / 2));
                    bool isMember = placedBoundary.Contains(placed.Left + (placed.Width / 2), placed.Top + (placed.Height / 2));
                    if (wasMember != isMember)
                    {
                        return $"Layout would change boundary membership of '{DiagramElementHelper.GetName(element)}' ({element.Guid}) in '{DiagramElementHelper.GetName(boundary)}' on page '{before.Header}'.";
                    }
                }

                foreach (Connector flow in before.Lines.Values.OfType<Connector>())
                {
                    Connector placed = (Connector)after.Lines[flow.Guid];
                    if (boundary.Contains(flow.SourceX, flow.SourceY) != placedBoundary.Contains(placed.SourceX, placed.SourceY)
                        || boundary.Contains(flow.TargetX, flow.TargetY) != placedBoundary.Contains(placed.TargetX, placed.TargetY))
                    {
                        return $"Layout would change the boundary side of an endpoint of flow '{DiagramElementHelper.GetName(flow)}' ({flow.Guid}) on page '{before.Header}'.";
                    }
                }
            }

            // Reuse the analysis implementation, including line-boundary intersections. Comparing
            // component centers alone misses both detached connector endpoints and boundary lines.
            ThreatModel original = new ThreatModel();
            original.DrawingSurfaceList.Add(before);
            ThreatModel candidate = new ThreatModel();
            candidate.DrawingSurfaceList.Add(after);
            CrossingDifference crossings = BoundaryCrossingDiff.Compare(original, candidate);
            if (!crossings.IsEmpty)
            {
                CrossingChange changed = crossings.Changes[0];
                return $"Layout would change trust-boundary crossings of flow '{changed.FlowName}' ({changed.FlowId}) on page '{before.Header}'.";
            }

            return null;
        }

        private static void CommitGeometry(DrawingSurfaceModel source, DrawingSurfaceModel target)
        {
            foreach (DrawingElement placed in source.Borders.Values.OfType<DrawingElement>())
            {
                DrawingElement original = (DrawingElement)target.Borders[placed.Guid];
                original.Left = placed.Left;
                original.Top = placed.Top;
                original.Width = placed.Width;
                original.Height = placed.Height;
            }

            foreach (Connector placed in source.Lines.Values.OfType<Connector>())
            {
                Connector original = (Connector)target.Lines[placed.Guid];
                original.SourceX = placed.SourceX;
                original.SourceY = placed.SourceY;
                original.TargetX = placed.TargetX;
                original.TargetY = placed.TargetY;
                original.HandleX = placed.HandleX;
                original.HandleY = placed.HandleY;
            }
        }
    }
}
