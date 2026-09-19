namespace ThreatModelForge.Engine
{
    using System.Collections.Generic;

    /// <summary>
    /// A threat-overlay entry carried on the model: the durable, author-owned state of one threat, so
    /// edits and manually-authored threats round-trip with the structural model even though the rest of
    /// the (regenerable) register is not stored. A rule-derived threat is keyed by its register id
    /// (<c>{targetGuid:N}:{ruleId}</c>) and only needs an entry once it is edited; a manually-authored
    /// threat sets <see cref="Manual"/> and is keyed in the reserved <c>manual:</c> namespace.
    /// </summary>
    public sealed class ThreatStateDto
    {
        /// <summary>Gets the register id of the threat this entry applies to.</summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>Gets the lifecycle state (<c>Open</c>, <c>NeedsInvestigation</c>, <c>Mitigated</c>, or <c>Accepted</c>).</summary>
        public string State { get; init; } = "Open";

        /// <summary>Gets the risk-acceptance justification or state note.</summary>
        public string? Justification { get; init; }

        /// <summary>Gets a value indicating whether this is a manually-authored threat (not projected from a rule).</summary>
        public bool? Manual { get; init; }

        /// <summary>Gets the STRIDE category, for a manually-authored threat.</summary>
        public string? Category { get; init; }

        /// <summary>Gets the author-set title override (or the manual threat's title).</summary>
        public string? Title { get; init; }

        /// <summary>Gets the author-set description.</summary>
        public string? Description { get; init; }

        /// <summary>Gets the author-set mitigation override.</summary>
        public string? Mitigation { get; init; }

        /// <summary>Gets informational source provenance for an imported manual threat, never rule input.</summary>
        public IReadOnlyDictionary<string, string>? Source { get; init; }

        /// <summary>Gets the author-set priority (<c>High</c> / <c>Medium</c> / <c>Low</c>).</summary>
        public string? Priority { get; init; }

        /// <summary>
        /// Gets the element identifiers a manually-authored threat is scoped to (source, then optional
        /// target and flow). Empty or absent means the threat is model-wide.
        /// </summary>
        public IReadOnlyList<string>? ElementIds { get; init; }
    }
}
