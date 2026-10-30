namespace ThreatModelForge.Engine
{
    using System.Collections.Generic;
    using System.Text.Json.Serialization;

    /// <summary>
    /// A named page (diagram) within a <see cref="TmForgeModelDto"/>, carrying its own elements and
    /// flows. Maps to one drawing surface in the engine model.
    /// </summary>
    public sealed class TmForgeDiagramDto
    {
        /// <summary>Gets the page identifier.</summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>Gets the page (tab) label.</summary>
        public string Name { get; init; } = string.Empty;

        /// <summary>Gets inert source-format provenance retained for return conversions.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public IReadOnlyDictionary<string, string>? Source { get; init; }

        /// <summary>Gets the DFD elements on this page.</summary>
        public IReadOnlyList<TmForgeElementDto>? Elements { get; init; }

        /// <summary>Gets the data flows on this page.</summary>
        public IReadOnlyList<TmForgeFlowDto>? Flows { get; init; }
    }
}
