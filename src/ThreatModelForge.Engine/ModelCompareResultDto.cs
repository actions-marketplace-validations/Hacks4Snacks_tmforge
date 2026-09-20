namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using ThreatModelForge.Formats;

    /// <summary>The read-only comparison of two canonical model snapshots.</summary>
    public sealed class ModelCompareResultDto
    {
        /// <summary>Gets whether both inputs could be compared structurally.</summary>
        public bool Success { get; init; }

        /// <summary>Gets the navigable changes in deterministic order.</summary>
        public IReadOnlyList<ModelReviewChangeDto> Changes { get; init; } = Array.Empty<ModelReviewChangeDto>();

        /// <summary>Gets whether findings were successfully evaluated on both sides.</summary>
        public bool FindingsAvailable { get; init; }

        /// <summary>Gets the number of findings whose identity and disposition did not change.</summary>
        public int UnchangedFindings { get; init; }

        /// <summary>Gets caveats about identity or analysis comparability.</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();

        /// <summary>Gets input or evaluation diagnostics; failures never become resolved findings.</summary>
        public IReadOnlyList<DocumentDiagnostic> Diagnostics { get; init; } = Array.Empty<DocumentDiagnostic>();
    }
}
