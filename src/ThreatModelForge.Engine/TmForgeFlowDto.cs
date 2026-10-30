namespace ThreatModelForge.Engine
{
    using System.Collections.Generic;
    using System.Text.Json.Serialization;

    /// <summary>
    /// A data flow between two elements.
    /// </summary>
    public sealed class TmForgeFlowDto
    {
        /// <summary>Gets the client-assigned flow identifier.</summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>Gets the source element identifier.</summary>
        public string Source { get; init; } = string.Empty;

        /// <summary>Gets the target element identifier.</summary>
        public string Target { get; init; } = string.Empty;

        /// <summary>Gets the flow label.</summary>
        public string? Name { get; init; }

        /// <summary>Gets the author-positioned canvas label offset.</summary>
        [JsonPropertyName("labelOffset")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public TmForgePointDto? LabelOffset { get; init; }

        /// <summary>Gets the canvas source port.</summary>
        [JsonPropertyName("sourceHandle")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? SourceHandle { get; init; }

        /// <summary>Gets the canvas target port.</summary>
        [JsonPropertyName("targetHandle")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? TargetHandle { get; init; }

        /// <summary>Gets the engine custom properties (for example, <c>Protocol</c>, <c>DataType</c>) attached to the flow.</summary>
        public IReadOnlyDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();
    }
}
