namespace ThreatModelForge.Editing
{
    using System;
    using System.Linq;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Geometry helpers for a diagram, shared by the renderer and the interactive canvas.
    /// </summary>
    public static class DiagramGeometry
    {
        /// <summary>Reattaches component-to-component flows to their facing edges after placement.</summary>
        /// <param name="diagram">The diagram whose component rectangles were placed.</param>
        public static void RerouteConnectors(DrawingSurfaceModel diagram)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            foreach (Connector connector in diagram.Lines.Values.OfType<Connector>())
            {
                if (!diagram.Borders.TryGetValue(connector.SourceGuid, out object? source)
                    || source is not DrawingElement || source is BorderBoundary
                    || !diagram.Borders.TryGetValue(connector.TargetGuid, out object? target)
                    || target is not DrawingElement || target is BorderBoundary)
                {
                    continue;
                }

                (int sourceCenterX, int sourceCenterY) = CenterOf(diagram, connector.SourceGuid);
                (int targetCenterX, int targetCenterY) = CenterOf(diagram, connector.TargetGuid);
                (int sourceX, int sourceY) = EdgePoint(diagram, connector.SourceGuid, targetCenterX, targetCenterY);
                (int targetX, int targetY) = EdgePoint(diagram, connector.TargetGuid, sourceCenterX, sourceCenterY);
                connector.SourceX = sourceX;
                connector.SourceY = sourceY;
                connector.TargetX = targetX;
                connector.TargetY = targetY;
                connector.HandleX = (sourceX + targetX) / 2;
                connector.HandleY = (sourceY + targetY) / 2;
            }
        }

        /// <summary>
        /// Computes the bounding box that encloses every element in a diagram. Returns a default
        /// 100x100 box when the diagram is empty.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <returns>The inclusive bounding box.</returns>
        public static (int MinX, int MinY, int MaxX, int MaxY) GetBounds(DrawingSurfaceModel diagram)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            int minX = int.MaxValue;
            int minY = int.MaxValue;
            int maxX = int.MinValue;
            int maxY = int.MinValue;

            foreach (DrawingElement element in diagram.Borders.Values.OfType<DrawingElement>())
            {
                minX = Math.Min(minX, element.Left);
                minY = Math.Min(minY, element.Top);
                maxX = Math.Max(maxX, element.Left + element.Width);
                maxY = Math.Max(maxY, element.Top + element.Height);
            }

            foreach (LineElement line in diagram.Lines.Values.OfType<LineElement>())
            {
                minX = Math.Min(minX, Math.Min(line.SourceX, line.TargetX));
                minY = Math.Min(minY, Math.Min(line.SourceY, line.TargetY));
                maxX = Math.Max(maxX, Math.Max(line.SourceX, line.TargetX));
                maxY = Math.Max(maxY, Math.Max(line.SourceY, line.TargetY));
            }

            return minX == int.MaxValue ? (0, 0, 100, 100) : (minX, minY, maxX, maxY);
        }

        /// <summary>
        /// Gets the center point of a component or boundary, or (0, 0) when not found.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <param name="guid">The element identifier.</param>
        /// <returns>The center point.</returns>
        public static (int X, int Y) CenterOf(DrawingSurfaceModel diagram, Guid guid)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Borders.TryGetValue(guid, out object? value) && value is DrawingElement element)
            {
                return (element.Left + (element.Width / 2), element.Top + (element.Height / 2));
            }

            return (0, 0);
        }

        /// <summary>
        /// Finds the identifier of a component (not a trust boundary) whose bounding box contains the
        /// given point, or <see cref="Guid.Empty"/> when none does. Used to attach flow endpoints.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <param name="x">The x coordinate.</param>
        /// <param name="y">The y coordinate.</param>
        /// <returns>The element identifier, or <see cref="Guid.Empty"/>.</returns>
        public static Guid ElementAt(DrawingSurfaceModel diagram, int x, int y)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            return diagram.Borders.Keys.FirstOrDefault(key =>
                diagram.Borders[key] is DrawingElement element && !(element is BorderBoundary)
                && x >= element.Left && x <= element.Left + element.Width
                && y >= element.Top && y <= element.Top + element.Height);
        }

        /// <summary>
        /// Computes the point on a component's bounding-box border along the ray from its center
        /// toward the given external point. Used to attach flow endpoints to an element's edge
        /// (facing the other end) rather than burying them in the element's center.
        /// </summary>
        /// <param name="diagram">The diagram.</param>
        /// <param name="guid">The element identifier.</param>
        /// <param name="fromX">The x coordinate the edge should face.</param>
        /// <param name="fromY">The y coordinate the edge should face.</param>
        /// <returns>The point on the element's border, or the given point when the element is not found.</returns>
        public static (int X, int Y) EdgePoint(DrawingSurfaceModel diagram, Guid guid, int fromX, int fromY)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (!(diagram.Borders.TryGetValue(guid, out object? value) && value is DrawingElement element))
            {
                return (fromX, fromY);
            }

            int centerX = element.Left + (element.Width / 2);
            int centerY = element.Top + (element.Height / 2);
            double deltaX = fromX - centerX;
            double deltaY = fromY - centerY;
            if (Math.Abs(deltaX) <= 0.0 && Math.Abs(deltaY) <= 0.0)
            {
                return (centerX, centerY);
            }

            double halfWidth = Math.Max(1, element.Width / 2.0);
            double halfHeight = Math.Max(1, element.Height / 2.0);
            double scaleX = Math.Abs(deltaX) > 0.0 ? halfWidth / Math.Abs(deltaX) : double.MaxValue;
            double scaleY = Math.Abs(deltaY) > 0.0 ? halfHeight / Math.Abs(deltaY) : double.MaxValue;
            double scale = Math.Min(scaleX, scaleY);
            return (centerX + (int)Math.Round(deltaX * scale), centerY + (int)Math.Round(deltaY * scale));
        }
    }
}
