namespace ThreatModelForge.Analysis.Rules
{
    using System;

    /// <summary>
    /// The single source of truth for where the built-in rules are documented publicly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every built-in rule advertises a <see cref="Rule.HelpUri"/> that flows through to the CLI,
    /// SARIF output, the engine API, Studio, and the HTML report. Updating
    /// <see cref="RulesReferenceUrl"/> changes the documentation link on every surface.
    /// </para>
    /// <para>
    /// The authoritative, human-readable explanation of each rule (what it checks and how to fix a
    /// finding) is carried on the rule itself as <see cref="Rule.FullDescription"/> and
    /// <see cref="Rule.HelpText"/>, so authoring surfaces can show it in place without depending on
    /// this external link. This link is the "learn more" pointer for tools (for example SARIF
    /// code-scanning) that expect a documentation URL per rule.
    /// </para>
    /// </remarks>
    public static class RuleDocumentation
    {
        /// <summary>
        /// The canonical, public documentation page for the built-in rule set.
        /// </summary>
        public const string RulesReferenceUrl =
            "https://github.com/hacks4snacks/tmforge/blob/main/docs/analysis-rules.md";

        /// <summary>
        /// Builds the documentation URL for a single rule.
        /// </summary>
        /// <param name="ruleId">The rule identifier (for example, <c>TM1008</c>).</param>
        /// <returns>An absolute URL pointing at the rule's documentation.</returns>
        /// <remarks>
        /// The rule id is carried as a <c>?rule=</c> query so every rule gets a distinct link (the
        /// engine requires a unique help URI per rule) while still pointing at the single canonical
        /// rules reference — there is no per-rule page to duplicate and let drift. A docs site can
        /// read <c>?rule=</c> to scroll to the matching rule.
        /// </remarks>
        public static Uri HelpUriFor(string ruleId)
        {
            if (string.IsNullOrWhiteSpace(ruleId))
            {
                throw new ArgumentException("A rule id is required.", nameof(ruleId));
            }

            return new Uri($"{RulesReferenceUrl}?rule={ruleId}", UriKind.Absolute);
        }
    }
}
