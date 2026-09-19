namespace ThreatModelForge.Engine
{
    /// <summary>A geometry-only update, keyed by the original author-assigned element identity.</summary>
    public sealed class LayoutElementDto
    {
        /// <summary>Gets the unchanged author-assigned element id.</summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>Gets the arranged left coordinate.</summary>
        public int X { get; init; }

        /// <summary>Gets the arranged top coordinate.</summary>
        public int Y { get; init; }

        /// <summary>Gets the arranged width.</summary>
        public int Width { get; init; }

        /// <summary>Gets the arranged height.</summary>
        public int Height { get; init; }
    }
}
