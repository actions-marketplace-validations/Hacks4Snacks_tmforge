namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// The result of a guarded arrangement. A refusal contains no geometry to apply. On success only
    /// rectangles are returned, so a client retains its own topology, pages, properties and triage.
    /// </summary>
    public sealed class LayoutResultDto
    {
        /// <summary>Gets whether all pages passed membership and crossing-preservation checks.</summary>
        public bool Success { get; init; }

        /// <summary>Gets the reason the arrangement was refused.</summary>
        public string? Error { get; init; }

        /// <summary>Gets every arranged rectangle, or an empty list on refusal.</summary>
        public IReadOnlyList<LayoutElementDto> Elements { get; init; } = Array.Empty<LayoutElementDto>();

        /// <summary>Gets the number of pages arranged.</summary>
        public int Pages { get; init; }

        /// <summary>Gets the number of components arranged, excluding trust boundaries.</summary>
        public int Components { get; init; }

        /// <summary>Gets the remaining label overlaps under the engine's label metrics.</summary>
        public int LabelOverlaps { get; init; }
    }
}
