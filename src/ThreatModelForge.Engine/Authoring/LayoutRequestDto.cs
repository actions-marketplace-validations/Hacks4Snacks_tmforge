namespace ThreatModelForge.Engine
{
    using System.Collections.Generic;
    using ThreatModelForge.Editing;

    /// <summary>Inputs to a semantic-preserving arrangement of all pages in a model.</summary>
    public sealed class LayoutRequestDto
    {
        /// <summary>Gets the original model, before any client-side resizing or placement.</summary>
        public TmForgeModelDto? Model { get; init; }

        /// <summary>Gets an optional page name or one-based index. Omitted means every page.</summary>
        public string? Page { get; init; }

        /// <summary>Gets optional spacing and label metrics. Omitted metrics use engine defaults.</summary>
        public LayoutOptions? Options { get; init; }

        /// <summary>
        /// Gets optional proposed rectangles for every element on the selected pages. When present,
        /// validates this placement without rearranging it.
        /// </summary>
        public IReadOnlyList<LayoutElementDto>? Positions { get; init; }
    }
}
