namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using ThreatModelForge.Model;

    /// <summary>
    /// The <c>tmforge-json</c> document: the canvas's canonical in-memory model and the wire shape
    /// exchanged with clients. It carries diagram structure (elements, flows, trust boundaries,
    /// names, and geometry) plus the per-model analysis selection and the risk-acceptance triage
    /// overlay; it does not carry knowledge-base attributes or the full (regenerable) threat register.
    /// </summary>
    public sealed class TmForgeJsonModel
    {
        /// <summary>Gets the schema discriminator (always <c>tmforge-json</c>).</summary>
        public string Schema { get; init; } = "tmforge-json";

        /// <summary>Gets the document version.</summary>
        public string Version { get; init; } = "0.1";

        /// <summary>Gets the author-owned model description, owner and review metadata.</summary>
        public MetaInformation? Metadata { get; init; }

        /// <summary>Gets the diagram elements (processes, data stores, external entities, boundaries).</summary>
        public TmForgeJsonElement[] Elements { get; init; } = Array.Empty<TmForgeJsonElement>();

        /// <summary>Gets the directed data flows between elements.</summary>
        public TmForgeJsonFlow[] Flows { get; init; } = Array.Empty<TmForgeJsonFlow>();

        /// <summary>
        /// Gets the named pages (diagrams). When present, this is the authoritative page form and
        /// the top-level <see cref="Elements"/> and <see cref="Flows"/> mirror the first page for older,
        /// single-page readers. A named or explicitly identified single page also uses this form.
        /// </summary>
        public IReadOnlyList<TmForgeJsonDiagram>? Diagrams { get; init; }

        /// <summary>Gets the per-model analysis selection (which rule packs or rules to skip).</summary>
        public TmForgeJsonAnalysis? Analysis { get; init; }

        /// <summary>
        /// Gets the threat triage overlay: the persisted lifecycle state (accepted risks and their
        /// justifications) of generated threats, keyed by threat id. Absent or empty means every
        /// threat is open. This is the only part of the (otherwise regenerable) threat register that
        /// <c>tmforge-json</c> carries, so risk acceptance survives a Studio export or CLI round-trip.
        /// </summary>
        public IReadOnlyList<TmForgeJsonThreatState>? Threats { get; init; }
    }
}
