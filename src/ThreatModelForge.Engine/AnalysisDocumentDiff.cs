namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Compares two <c>tmforge-analysis</c> documents by finding identity.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Findings are matched on the stable id every document carries,
    /// <c>{ruleId}:{diagram}:{target}:{occurrence}</c>. That is the point of the whole exercise: a
    /// count tells you the number moved, and a positional comparison renumbers the moment a rule is
    /// enabled or disabled, but an identity tells you <em>which</em> finding arrived and which one
    /// went away. Renaming an element changes a finding's message and not its identity, so editorial
    /// churn does not read as security churn.
    /// </para>
    /// <para>
    /// The comparison never refuses. Two documents can be less comparable than they look — a different
    /// rule selection, or two different models entirely — and in that case the difference is reported
    /// alongside a warning saying so, because a reviewer who can see the caveat is better served than
    /// one who gets an error or, worse, a confident answer.
    /// </para>
    /// </remarks>
    public static class AnalysisDocumentDiff
    {
        /// <summary>
        /// Compares a base analysis against a head analysis.
        /// </summary>
        /// <param name="baseDocument">The earlier analysis.</param>
        /// <param name="headDocument">The later analysis.</param>
        /// <returns>The findings introduced, resolved, and reclassified between them.</returns>
        public static AnalysisDifference Compare(
            AnalysisDocumentDto baseDocument,
            AnalysisDocumentDto headDocument)
        {
            _ = baseDocument ?? throw new ArgumentNullException(nameof(baseDocument));
            _ = headDocument ?? throw new ArgumentNullException(nameof(headDocument));

            Dictionary<string, AnalysisFindingDto> before = Index(baseDocument.Findings);
            Dictionary<string, AnalysisFindingDto> after = Index(headDocument.Findings);

            List<AnalysisFindingDto> introduced = new List<AnalysisFindingDto>();
            List<AnalysisFindingDto> resolved = new List<AnalysisFindingDto>();
            List<AnalysisFindingChange> reclassified = new List<AnalysisFindingChange>();
            int unchanged = 0;

            foreach (KeyValuePair<string, AnalysisFindingDto> entry in before)
            {
                if (!after.TryGetValue(entry.Key, out AnalysisFindingDto? head))
                {
                    resolved.Add(entry.Value);
                    continue;
                }

                if (IsReclassified(entry.Value, head))
                {
                    reclassified.Add(new AnalysisFindingChange { Before = entry.Value, After = head });
                }
                else
                {
                    unchanged++;
                }
            }

            introduced.AddRange(after.Where(entry => !before.ContainsKey(entry.Key)).Select(entry => entry.Value));

            introduced.Sort(CompareFindings);
            resolved.Sort(CompareFindings);
            reclassified.Sort((left, right) => CompareFindings(left.After, right.After));

            return new AnalysisDifference
            {
                Introduced = introduced,
                Resolved = resolved,
                Reclassified = reclassified,
                Unchanged = unchanged,
                Warnings = Warnings(baseDocument, headDocument, introduced, resolved, reclassified),
            };
        }

        private static Dictionary<string, AnalysisFindingDto> Index(IReadOnlyList<AnalysisFindingDto> findings)
        {
            Dictionary<string, AnalysisFindingDto> map =
                new Dictionary<string, AnalysisFindingDto>(StringComparer.Ordinal);
            foreach (AnalysisFindingDto finding in findings)
            {
                // Indexer assignment rather than Add: a duplicate id is a document defect that
                // 'analysis validate' reports, and refusing to compare here would only hide it.
                map[finding.Id] = finding;
            }

            return map;
        }

        /// <summary>
        /// Decides whether a surviving finding was classified differently. Only the disposition and the
        /// severity count: the message carries the element's display name, so treating it as a change
        /// would report every rename as a finding change.
        /// </summary>
        /// <param name="before">The finding as the base document recorded it.</param>
        /// <param name="after">The finding as the head document records it.</param>
        /// <returns><see langword="true"/> when the classification moved.</returns>
        private static bool IsReclassified(AnalysisFindingDto before, AnalysisFindingDto after)
        {
            return !string.Equals(before.Disposition, after.Disposition, StringComparison.Ordinal)
                || !string.Equals(before.Severity, after.Severity, StringComparison.Ordinal);
        }

        private static IReadOnlyList<string> Warnings(
            AnalysisDocumentDto baseDocument,
            AnalysisDocumentDto headDocument,
            IReadOnlyList<AnalysisFindingDto> introduced,
            IReadOnlyList<AnalysisFindingDto> resolved,
            IReadOnlyList<AnalysisFindingChange> reclassified)
        {
            List<string> warnings = new List<string>();

            if (!string.Equals(baseDocument.Model.Name, headDocument.Model.Name, StringComparison.Ordinal))
            {
                warnings.Add(
                    $"These documents describe different models ('{baseDocument.Model.Name}' and " +
                    $"'{headDocument.Model.Name}'). Findings are being compared across models.");
            }

            bool sameAnalyzer = string.Equals(
                baseDocument.Analyzer.Fingerprint,
                headDocument.Analyzer.Fingerprint,
                StringComparison.Ordinal);

            if (!sameAnalyzer)
            {
                warnings.Add(
                    "The analyzer or its rule selection changed between these runs, so some of these " +
                    "differences may come from the rules rather than from the model.");
            }

            bool sameModel = string.Equals(
                baseDocument.Model.Fingerprint,
                headDocument.Model.Fingerprint,
                StringComparison.Ordinal);

            bool differs = introduced.Count > 0 || resolved.Count > 0 || reclassified.Count > 0;
            if (sameModel && sameAnalyzer && differs)
            {
                warnings.Add(
                    "The model and analyzer fingerprints are identical yet the findings differ. " +
                    "Suppressions or author-owned triage may have changed; check both before treating a reclassification as a resolved condition.");
            }

            return warnings;
        }

        private static int CompareFindings(AnalysisFindingDto left, AnalysisFindingDto right)
        {
            return string.CompareOrdinal(left.Id, right.Id);
        }
    }
}
