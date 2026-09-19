namespace ThreatModelForge.Engine
{
    using System.Collections.Generic;
    using ThreatModelForge.Model;

    /// <summary>
    /// The canonical tmforge-json model posted by the editor.
    /// </summary>
    public sealed class TmForgeModelDto
    {
        /// <summary>Gets the schema tag (<c>tmforge-json</c>).</summary>
        public string? Schema { get; init; }

        /// <summary>Gets the schema version.</summary>
        public string? Version { get; init; }

        /// <summary>Gets the author-owned model description, owner and review metadata.</summary>
        public MetaInformation? Metadata { get; init; }

        /// <summary>Gets the DFD elements.</summary>
        public IReadOnlyList<TmForgeElementDto>? Elements { get; init; }

        /// <summary>Gets the data flows.</summary>
        public IReadOnlyList<TmForgeFlowDto>? Flows { get; init; }

        /// <summary>
        /// Gets the named pages (diagrams). When present, this is the authoritative multi-page form;
        /// the top-level <see cref="Elements"/> and <see cref="Flows"/> mirror the first page.
        /// </summary>
        public IReadOnlyList<TmForgeDiagramDto>? Diagrams { get; init; }

        /// <summary>Gets the per-model analysis configuration (which rule packs or rules to skip).</summary>
        public TmForgeAnalysisDto? Analysis { get; init; }

        /// <summary>
        /// Gets the threat triage overlay: the persisted lifecycle state (accepted risks and their
        /// justifications) of generated threats, keyed by threat id. Absent or empty means every
        /// threat is open.
        /// </summary>
        public IReadOnlyList<ThreatStateDto>? Threats { get; init; }
    }
}
