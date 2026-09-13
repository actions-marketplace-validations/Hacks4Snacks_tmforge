namespace ThreatModelForge.Editing
{
    /// <summary>
    /// Tunable spacing parameters for <see cref="DiagramLayout"/>. Defaults produce a readable
    /// layered diagram; callers may widen the gaps for larger stencils.
    /// </summary>
    public sealed class LayoutOptions
    {
        /// <summary>
        /// Gets or sets the x coordinate of the top-left origin of the laid-out region.
        /// </summary>
        public int OriginX { get; set; } = 40;

        /// <summary>
        /// Gets or sets the y coordinate of the top-left origin of the laid-out region.
        /// </summary>
        public int OriginY { get; set; } = 40;

        /// <summary>
        /// Gets or sets the horizontal gap between adjacent layers (columns).
        /// </summary>
        public int LayerSpacing { get; set; } = 160;

        /// <summary>
        /// Gets or sets the vertical gap between adjacent nodes within a layer.
        /// </summary>
        public int NodeSpacing { get; set; } = 48;

        /// <summary>
        /// Gets or sets the width a row of columns may occupy before the next column wraps onto a new
        /// row. The Microsoft Threat Modeling Tool's drawing surface is bounded and taller than it is
        /// wide, so a wide model has to grow downwards; anything drawn past the right-hand limit is
        /// clamped by the tool on load, which would pile elements on top of each other.
        /// </summary>
        public int MaxWidth { get; set; } = 1760;

        /// <summary>
        /// Gets or sets the padding between a trust boundary's edge and the members inside it.
        /// </summary>
        public int BoundaryPadding { get; set; } = 24;

        /// <summary>
        /// Gets or sets the extra headroom reserved at the top of a trust boundary for its title,
        /// which is drawn inside the box and would otherwise print over the topmost member.
        /// </summary>
        public int BoundaryHeaderHeight { get; set; } = 24;

        /// <summary>
        /// Gets or sets the width one character of a data-flow label occupies. Labels are drawn as a
        /// single unwrapped line, so this is what converts a flow's name into the space it needs.
        /// </summary>
        public int LabelCharacterWidth { get; set; } = 7;

        /// <summary>
        /// Gets or sets the height of a data-flow label.
        /// </summary>
        public int LabelHeight { get; set; } = 18;

        /// <summary>
        /// Gets or sets the perpendicular distance between adjacent label lanes.
        /// </summary>
        public int LabelLaneSpacing { get; set; } = 26;

        /// <summary>
        /// Gets or sets how many lanes either side of a connector a label may be pushed into before
        /// the least-covered position is accepted. Larger values clear more labels at the cost of
        /// bowing connectors further from a straight line.
        /// </summary>
        public int LabelLanes { get; set; } = 3;
    }
}
