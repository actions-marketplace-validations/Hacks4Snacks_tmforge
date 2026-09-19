namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.Formats;

    /// <summary>A read-only assessment of document validity and known conversion losses.</summary>
    public sealed class PreflightResultDto
    {
        /// <summary>Gets whether the assessed operation has no blocking diagnostics.</summary>
        public bool Success => !this.Diagnostics.Any(diagnostic => diagnostic.Severity == "error");

        /// <summary>Gets the identified input format, or null when it could not be identified.</summary>
        public string? Format { get; init; }

        /// <summary>Gets the optional conversion target.</summary>
        public string? TargetFormat { get; init; }

        /// <summary>Gets source paths, stable codes and explanations in deterministic order.</summary>
        public IReadOnlyList<DocumentDiagnostic> Diagnostics { get; init; } = Array.Empty<DocumentDiagnostic>();
    }
}
