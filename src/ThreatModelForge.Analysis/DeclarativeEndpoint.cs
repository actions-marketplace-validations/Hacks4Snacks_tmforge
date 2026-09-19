namespace ThreatModelForge.Analysis
{
    using System.Collections.Generic;
    using System.Text.Json.Serialization;
    using System.Text.RegularExpressions;

    /// <summary>
    /// A condition on the element at one end of a flow, resolved through the flow's source or target
    /// reference. Every specified facet must hold (logical AND).
    /// </summary>
    internal sealed class DeclarativeEndpoint
    {
        /// <summary>Gets or sets the required kind of the endpoint element (<c>process</c>, <c>datastore</c>, or <c>external</c>).</summary>
        public string? Kind { get; set; }

        /// <summary>Gets or sets the custom-property name to read on the endpoint element.</summary>
        public string? Property { get; set; }

        /// <summary>Gets or sets the values that satisfy the condition; the property must equal one of them.</summary>
        public List<string>? AnyOf { get; set; }

        /// <summary>Gets or sets the values that violate the condition; the property must equal none of them.</summary>
        public List<string>? NotAnyOf { get; set; }

        /// <summary>Gets or sets the single value the property must equal.</summary>
        [JsonPropertyName("equals")]
        public string? EqualTo { get; set; }

        /// <summary>Gets or sets whether the property must be present (<c>true</c>) or absent (<c>false</c>).</summary>
        public bool? Present { get; set; }

        /// <summary>Gets or sets the exclusive numeric lower bound.</summary>
        public decimal? GreaterThan { get; set; }

        /// <summary>Gets or sets the inclusive numeric lower bound.</summary>
        public decimal? GreaterThanOrEqual { get; set; }

        /// <summary>Gets or sets the exclusive numeric upper bound.</summary>
        public decimal? LessThan { get; set; }

        /// <summary>Gets or sets the inclusive numeric upper bound.</summary>
        public decimal? LessThanOrEqual { get; set; }

        /// <summary>Gets or sets the regular expression the property must match.</summary>
        public string? Matches { get; set; }

        /// <summary>Gets or sets the pattern prepared during pack validation.</summary>
        internal Regex? CompiledPattern { get; set; }
    }
}
