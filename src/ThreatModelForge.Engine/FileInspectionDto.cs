namespace ThreatModelForge.Engine
{
    using System.Collections.Generic;
    using ThreatModelForge.Formats;

    /// <summary>A read-only inspection of a source document without a lossy model projection.</summary>
    public sealed class FileInspectionDto
    {
        /// <summary>Gets the detected source format.</summary>
        public string? Format { get; init; }

        /// <summary>Gets the structural and input diagnostics.</summary>
        public IReadOnlyList<DocumentDiagnostic> Diagnostics { get; init; } = Array.Empty<DocumentDiagnostic>();

        /// <summary>Gets the pages rendered directly from the source model.</summary>
        public IReadOnlyList<DiagramPreviewDto> Pages { get; init; } = Array.Empty<DiagramPreviewDto>();

        /// <summary>Gets the findings from the same source model.</summary>
        public AnalysisResultDto? Analysis { get; init; }
    }
}
