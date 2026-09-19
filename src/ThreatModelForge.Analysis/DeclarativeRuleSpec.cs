namespace ThreatModelForge.Analysis
{
    using System.Collections.Generic;
    using System.Text.RegularExpressions;

    /// <summary>
    /// A single declarative rule. A finding is raised for each element of <see cref="AppliesTo"/> that
    /// matches <see cref="When"/> (or every such element when <see cref="When"/> is omitted) and fails
    /// <see cref="Assert"/> (or unconditionally when <see cref="Assert"/> is omitted). At least one of
    /// <see cref="When"/> or <see cref="Assert"/> must be present.
    /// </summary>
    internal sealed class DeclarativeRuleSpec
    {
        /// <summary>Gets or sets the unique rule id in the pack's own namespace (for example <c>ACME001</c>).</summary>
        public string? Id { get; set; }

        /// <summary>Gets or sets the identifier of the rule pack this rule belongs to.</summary>
        public string? Pack { get; set; }

        /// <summary>Gets or sets the severity (<c>error</c>, <c>warning</c>, or <c>info</c>); defaults to <c>warning</c>.</summary>
        public string? Severity { get; set; }

        /// <summary>Gets or sets the DFD primitive the rule targets (<c>process</c>, <c>datastore</c>, <c>external</c>, or <c>flow</c>).</summary>
        public string? AppliesTo { get; set; }

        /// <summary>Gets or sets the finding message; the token <c>{name}</c> is replaced with the element's display text.</summary>
        public string? Message { get; set; }

        /// <summary>Gets or sets the long description of what the rule checks and why.</summary>
        public string? FullDescription { get; set; }

        /// <summary>Gets or sets guidance on how to resolve a finding.</summary>
        public string? HelpText { get; set; }

        /// <summary>Gets or sets an optional documentation URL.</summary>
        public string? HelpUri { get; set; }

        /// <summary>Gets or sets the optional STRIDE category the finding represents (enables threat generation).</summary>
        public string? Stride { get; set; }

        /// <summary>Gets or sets the executable category id from the versioned pack catalog.</summary>
        public string? CategoryId { get; set; }

        /// <summary>Gets or sets the generated threat priority independently of finding severity.</summary>
        public string? DefaultPriority { get; set; }

        /// <summary>Gets or sets the optional external references (for example <c>CWE:319</c>, <c>CAPEC:157</c>, <c>ATTACK:T1040</c>).</summary>
        public List<string>? ThreatReferences { get; set; }

        /// <summary>Gets or sets the original source identity and filter expressions.</summary>
        public RuleProvenanceSpec? Provenance { get; set; }

        /// <summary>Gets or sets the recursive interaction expression for interaction-v1.</summary>
        public InteractionExpressionSpec? Expression { get; set; }

        /// <summary>Gets or sets the optional guard; the rule only evaluates elements that match it.</summary>
        public DeclarativeCondition? When { get; set; }

        /// <summary>Gets or sets the requirement; a matching element that fails it produces a finding.</summary>
        public DeclarativeCondition? Assert { get; set; }

        /// <summary>The mutable JSON shape of imported-rule provenance.</summary>
        internal sealed class RuleProvenanceSpec
        {
            /// <summary>Gets or sets the source-local rule id.</summary>
            public string? SourceId { get; set; }

            /// <summary>Gets or sets the source-local category id.</summary>
            public string? CategoryId { get; set; }

            /// <summary>Gets or sets the optional source location.</summary>
            public string? Location { get; set; }

            /// <summary>Gets or sets preserved source expressions.</summary>
            public List<SourceExpressionSpec>? Expressions { get; set; }
        }

        /// <summary>The mutable JSON shape of one preserved source expression.</summary>
        internal sealed class SourceExpressionSpec
        {
            /// <summary>Gets or sets the source-defined role.</summary>
            public string? Role { get; set; }

            /// <summary>Gets or sets the namespaced source expression language.</summary>
            public string? Language { get; set; }

            /// <summary>Gets or sets the original expression text.</summary>
            public string? Text { get; set; }
        }

        /// <summary>The recursive JSON shape used by the interaction-v1 dialect.</summary>
        internal sealed class InteractionExpressionSpec
        {
            /// <summary>Gets or sets a logical conjunction.</summary>
            public List<InteractionExpressionSpec>? AllOf { get; set; }

            /// <summary>Gets or sets a logical disjunction.</summary>
            public List<InteractionExpressionSpec>? AnyOf { get; set; }

            /// <summary>Gets or sets a logical negation.</summary>
            public InteractionExpressionSpec? Not { get; set; }

            /// <summary>Gets or sets the interaction subject.</summary>
            public string? Subject { get; set; }

            /// <summary>Gets or sets the expected element type.</summary>
            public string? Type { get; set; }

            /// <summary>Gets or sets the expected primitive component kind.</summary>
            public string? Kind { get; set; }

            /// <summary>Gets or sets the property to read.</summary>
            public string? Property { get; set; }

            /// <summary>Gets or sets accepted property values.</summary>
            public List<string>? ValueIn { get; set; }

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

            /// <summary>Gets or sets the specific crossed-boundary type.</summary>
            public string? Crosses { get; set; }

            /// <summary>Gets or sets an upstream component filter for positive-length directed reachability.</summary>
            public DeclarativeEndpoint? ReachableFrom { get; set; }

            /// <summary>Gets or sets a component filter for one outgoing connector.</summary>
            public DeclarativeEndpoint? ConnectsTo { get; set; }

            /// <summary>Gets or sets the pattern prepared during pack validation.</summary>
            internal Regex? CompiledPattern { get; set; }
        }
    }
}
