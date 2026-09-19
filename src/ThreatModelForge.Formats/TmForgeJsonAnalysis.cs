namespace ThreatModelForge.Formats
{
    using System.Collections.Generic;

    /// <summary>
    /// The per-model analysis selection persisted inside a <c>tmforge-json</c> document: which
    /// analysis rule packs or individual rules to skip. It travels with the model so the editor and
    /// the CLI analyze against the same rules.
    /// </summary>
    public sealed class TmForgeJsonAnalysis
    {
        /// <summary>Gets the ids of rule packs to skip (for example, <c>stride-completeness</c>).</summary>
        public IReadOnlyList<string>? DisabledPacks { get; init; }

        /// <summary>Gets the ids of individual rules to skip (for example, <c>TM1002</c>).</summary>
        public IReadOnlyList<string>? DisabledRuleIds { get; init; }

        /// <summary>Gets the expected custom rule-pack identities carried by the wire model.</summary>
        public IReadOnlyList<TmForgeJsonExpectedPack>? ExpectedPacks { get; init; }
    }
}
