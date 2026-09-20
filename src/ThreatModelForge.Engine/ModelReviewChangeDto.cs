namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using ThreatModelForge.Editing;

    /// <summary>A review change with navigation targets on both original model snapshots.</summary>
    public sealed class ModelReviewChangeDto
    {
        /// <summary>Gets the stable review-row identity.</summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>Gets the section: structure, crossings or findings.</summary>
        public string Section { get; init; } = "structure";

        /// <summary>Gets the change kind, such as added, removed, modified or introduced.</summary>
        public string Kind { get; init; } = string.Empty;

        /// <summary>Gets the display title for the changed object or finding.</summary>
        public string Title { get; init; } = string.Empty;

        /// <summary>Gets the object kind when the change describes an element or flow.</summary>
        public string? ElementKind { get; init; }

        /// <summary>Gets the original author ids to highlight in the baseline.</summary>
        public IReadOnlyList<string> BaselineElementIds { get; init; } = Array.Empty<string>();

        /// <summary>Gets the original author ids to highlight in the proposed model.</summary>
        public IReadOnlyList<string> ProposedElementIds { get; init; } = Array.Empty<string>();

        /// <summary>Gets the baseline page id, if the change belongs to a page.</summary>
        public string? BaselinePageId { get; init; }

        /// <summary>Gets the proposed page id, if the change belongs to a page.</summary>
        public string? ProposedPageId { get; init; }

        /// <summary>Gets the baseline page name.</summary>
        public string? BaselinePageName { get; init; }

        /// <summary>Gets the proposed page name.</summary>
        public string? ProposedPageName { get; init; }

        /// <summary>Gets changed attributes or review evidence, with before and after values.</summary>
        public IReadOnlyList<PropertyChange> Properties { get; init; } = Array.Empty<PropertyChange>();

        /// <summary>Gets the finding's rule id, when applicable.</summary>
        public string? RuleId { get; init; }

        /// <summary>Gets the finding's severity, when applicable.</summary>
        public string? Severity { get; init; }
    }
}
