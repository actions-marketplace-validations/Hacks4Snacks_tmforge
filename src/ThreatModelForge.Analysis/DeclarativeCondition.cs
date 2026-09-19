namespace ThreatModelForge.Analysis
{
    using System.Collections.Generic;
    using System.Text.Json.Serialization;
    using System.Text.RegularExpressions;

    /// <summary>
    /// A condition over an element. Every specified facet must hold (logical AND). A bare
    /// <see cref="Property"/> with no value matcher is treated as "must be present". The relational
    /// facets — <see cref="CrossesTrustBoundary"/>, <see cref="Source"/>, and <see cref="Target"/> — are
    /// only valid on a rule whose <c>appliesTo</c> is <c>flow</c>.
    /// </summary>
    internal sealed class DeclarativeCondition
    {
        /// <summary>Gets or sets the custom-property name the condition reads on the element.</summary>
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

        /// <summary>Gets or sets whether the flow must cross a trust boundary (<c>true</c>) or not (<c>false</c>).</summary>
        public bool? CrossesTrustBoundary { get; set; }

        /// <summary>Gets or sets a condition on the element at the flow's source end.</summary>
        public DeclarativeEndpoint? Source { get; set; }

        /// <summary>Gets or sets a condition on the element at the flow's target end.</summary>
        public DeclarativeEndpoint? Target { get; set; }

        /// <summary>Gets or sets a filter for a component with a positive-length directed path to this component.</summary>
        public DeclarativeEndpoint? ReachableFrom { get; set; }

        /// <summary>Gets or sets a filter for a component reached by one outgoing connector.</summary>
        public DeclarativeEndpoint? ConnectsTo { get; set; }

        /// <summary>Gets or sets the pattern prepared during pack validation.</summary>
        internal Regex? CompiledPattern { get; set; }
    }
}
