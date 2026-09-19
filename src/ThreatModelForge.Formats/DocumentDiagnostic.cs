namespace ThreatModelForge.Formats
{
    /// <summary>A structural input or conversion diagnostic, separate from security findings.</summary>
    public sealed class DocumentDiagnostic
    {
        /// <summary>Gets the stable diagnostic code.</summary>
        public string Code { get; init; } = string.Empty;

        /// <summary>Gets the severity: error, warning or info.</summary>
        public string Severity { get; init; } = "error";

        /// <summary>Gets the location in the source document, using JSONPath for JSON input.</summary>
        public string Path { get; init; } = "$";

        /// <summary>Gets the actionable diagnostic text.</summary>
        public string Message { get; init; } = string.Empty;
    }
}
