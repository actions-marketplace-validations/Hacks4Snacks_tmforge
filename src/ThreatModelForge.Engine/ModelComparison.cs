namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Formats;
    using ThreatModelForge.Model;

    /// <summary>Projects existing model differences into a read-only, author-id review contract.</summary>
    internal static class ModelComparison
    {
        private const int MaxChanges = 10000;
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);

        internal static ModelCompareResultDto Compare(ModelCompareRequestDto request, EngineRuleOptions? rules)
        {
            _ = request ?? throw new ArgumentNullException(nameof(request));
            List<DocumentDiagnostic> diagnostics = new List<DocumentDiagnostic>();
            if (request.Baseline == null || request.Proposed == null)
            {
                diagnostics.Add(new DocumentDiagnostic { Code = "compare.missing-input", Message = "Both baseline and proposed models are required." });
                return new ModelCompareResultDto { Diagnostics = diagnostics };
            }

            Snapshot? baseline = Read(request.Baseline, "baseline", diagnostics);
            Snapshot? proposed = Read(request.Proposed, "proposed", diagnostics);
            if (baseline == null || proposed == null)
            {
                return new ModelCompareResultDto { Diagnostics = diagnostics };
            }

            List<string> warnings = new List<string>();
            if (baseline.Elements.Count > 0 && proposed.Elements.Count > 0 && !baseline.Elements.Keys.Intersect(proposed.Elements.Keys).Any())
            {
                warnings.Add("The models share no element identities. They may be unrelated or an import may have replaced their ids; additions and removals are not matched by name.");
            }

            IEnumerable<Guid> sharedIds = baseline.Elements.Keys.Intersect(proposed.Elements.Keys).Concat(
                baseline.Model.DrawingSurfaceList.Select(page => page.Guid).Intersect(proposed.Model.DrawingSurfaceList.Select(page => page.Guid)));
            bool sameSourceIds = sharedIds.All(id => OriginalId(id, baseline.Ids) == OriginalId(id, proposed.Ids));
            if (!sameSourceIds)
            {
                warnings.Add("Shared objects or pages use different source ids (for example aliases versus exported GUIDs). Structure is matched by internal identity, but findings comparison is unavailable. Use snapshots with the same source-id representation.");
            }

            if (!JsonElement.DeepEquals(JsonSerializer.SerializeToElement(request.Baseline.Metadata, JsonOptions), JsonSerializer.SerializeToElement(request.Proposed.Metadata, JsonOptions)))
            {
                warnings.Add("Model metadata differs. Metadata fields are outside this structural and findings review.");
            }

            IEnumerable<ThreatStateDto> baselineThreats = (request.Baseline.Threats ?? Array.Empty<ThreatStateDto>()).OrderBy(threat => threat.Id, StringComparer.Ordinal);
            IEnumerable<ThreatStateDto> proposedThreats = (request.Proposed.Threats ?? Array.Empty<ThreatStateDto>()).OrderBy(threat => threat.Id, StringComparer.Ordinal);
            if (!JsonElement.DeepEquals(JsonSerializer.SerializeToElement(baselineThreats, JsonOptions), JsonSerializer.SerializeToElement(proposedThreats, JsonOptions)))
            {
                warnings.Add("Author-owned threat records differ. This review compares finding dispositions, not the full threat register (manual threats, text, priority, and orphaned triage).");
            }

            ModelDifference difference = ModelDiff.Compare(baseline.Model, proposed.Model);
            List<ModelReviewChangeDto> changes = new List<ModelReviewChangeDto>();
            foreach (ElementChange change in difference.Added.Concat(difference.Removed).Concat(difference.Modified))
            {
                List<PropertyChange> properties = change.PropertyChanges.Select(property => new PropertyChange
                {
                    Key = property.Key,
                    From = EndpointValue(property.Key, property.From, baseline.Ids),
                    To = EndpointValue(property.Key, property.To, proposed.Ids),
                }).ToList();
                AddPageMove(change.Id, baseline, proposed, properties);
                changes.Add(ElementChange(change.Id, "structure", change.Kind.ToString().ToLowerInvariant(), change.Name, baseline, proposed, properties));
            }

            HashSet<Guid> changed = new HashSet<Guid>(difference.Modified.Select(change => change.Id));
            foreach (ElementDescriptor previous in baseline.Elements.Values.OrderBy(element => element.Id))
            {
                if (!changed.Contains(previous.Id) && proposed.Elements.TryGetValue(previous.Id, out ElementDescriptor? current) && previous.DiagramId != current.DiagramId)
                {
                    List<PropertyChange> properties = new List<PropertyChange>();
                    AddPageMove(previous.Id, baseline, proposed, properties);
                    changes.Add(ElementChange(previous.Id, "structure", "modified", current.Name, baseline, proposed, properties));
                }
            }

            AddPages(baseline, proposed, changes);
            foreach (CrossingChange crossing in BoundaryCrossingDiff.Compare(baseline.Model, proposed.Model).Changes)
            {
                List<PropertyChange> properties = crossing.Removed.Select(boundary => new PropertyChange
                {
                    Key = boundary.Name,
                    From = "Crosses",
                    To = "Does not cross",
                }).Concat(crossing.Added.Select(boundary => new PropertyChange
                {
                    Key = boundary.Name,
                    From = "Does not cross",
                    To = "Crosses",
                })).ToList();
                changes.Add(ElementChange(
                    crossing.FlowId,
                    "crossings",
                    crossing.Kind.ToString().ToLowerInvariant(),
                    crossing.FlowName,
                    baseline,
                    proposed,
                    properties,
                    crossing.Removed.Select(boundary => boundary.Id),
                    crossing.Added.Select(boundary => boundary.Id)));
            }

            AnalysisDocumentDto before = EngineService.DescribeAnalysis(request.Baseline, rules);
            AnalysisDocumentDto after = EngineService.DescribeAnalysis(request.Proposed, rules);
            bool baselineAvailable = CheckAnalysis(before, "baseline", diagnostics);
            bool proposedAvailable = CheckAnalysis(after, "proposed", diagnostics);
            bool available = baselineAvailable && proposedAvailable && sameSourceIds;
            int unchangedFindings = 0;
            if (available)
            {
                AnalysisDifference findings = AnalysisDocumentDiff.Compare(before, after);
                warnings.AddRange(findings.Warnings);
                unchangedFindings = findings.Unchanged;
                foreach (AnalysisFindingDto finding in findings.Introduced)
                {
                    changes.Add(FindingChange(null, finding, "introduced", baseline, proposed));
                }

                foreach (AnalysisFindingDto finding in findings.Resolved)
                {
                    changes.Add(FindingChange(finding, null, "resolved", baseline, proposed));
                }

                foreach (AnalysisFindingChange finding in findings.Reclassified)
                {
                    changes.Add(FindingChange(finding.Before, finding.After, "reclassified", baseline, proposed));
                }
            }

            if (changes.Count > MaxChanges)
            {
                JsonDocumentPreflight.Add(diagnostics, "compare.too-many-changes", "$", "Comparison exceeds 10000 changes. Compare smaller model snapshots.");
                return new ModelCompareResultDto { Diagnostics = diagnostics, Warnings = warnings };
            }

            return new ModelCompareResultDto
            {
                Success = true,
                Changes = changes.OrderBy(change => change.Section, StringComparer.Ordinal).ThenBy(change => change.Id, StringComparer.Ordinal).ToArray(),
                FindingsAvailable = available,
                UnchangedFindings = unchangedFindings,
                Warnings = warnings.Distinct(StringComparer.Ordinal).ToArray(),
                Diagnostics = diagnostics,
            };
        }

        private static Snapshot? Read(TmForgeModelDto model, string side, List<DocumentDiagnostic> diagnostics)
        {
            string json = JsonSerializer.Serialize(model, JsonOptions);
            IReadOnlyList<DocumentDiagnostic> input = JsonModelPreflight.Inspect(json);
            foreach (DocumentDiagnostic diagnostic in input)
            {
                JsonDocumentPreflight.Add(diagnostics, diagnostic.Code, "$." + side + diagnostic.Path.Substring(1), diagnostic.Message, diagnostic.Severity);
            }

            if (input.Any(diagnostic => diagnostic.Severity == "error"))
            {
                return null;
            }

            IReadOnlyList<TmForgeDiagramDto> pages = model.Diagrams is { Count: > 0 }
                ? model.Diagrams
                : new[] { new TmForgeDiagramDto { Elements = model.Elements, Flows = model.Flows } };
            int elements = pages.Sum(page => page.Elements?.Count ?? 0);
            int flows = pages.Sum(page => page.Flows?.Count ?? 0);
            long crossingWork = pages.Sum(page => (long)(page.Flows?.Count ?? 0) * (page.Elements?.Count(element => element.Kind == "boundary") ?? 0));
            if (pages.Count > 32 || elements > 1024 || flows > 2048 || crossingWork > 1000000)
            {
                JsonDocumentPreflight.Add(diagnostics, "compare.model-limit", "$." + side, "Review supports at most 32 pages, 1024 elements, 2048 flows and 1000000 flow/boundary pairs per model. Compare smaller snapshots.");
                return null;
            }

            Dictionary<Guid, string> ids = new Dictionary<Guid, string>();
            using MemoryStream stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(json));
            ThreatModel parsed = TmForgeJsonFormat.ReadWithOriginalIds(stream, ids);
            return new Snapshot(parsed, ids);
        }

        private static void AddPageMove(Guid id, Snapshot before, Snapshot after, List<PropertyChange> properties)
        {
            if (before.Elements.TryGetValue(id, out ElementDescriptor? previous) && after.Elements.TryGetValue(id, out ElementDescriptor? current)
                && previous.DiagramId != current.DiagramId)
            {
                properties.Add(new PropertyChange { Key = "page", From = previous.DiagramName, To = current.DiagramName });
            }
        }

        private static void AddPages(Snapshot before, Snapshot after, List<ModelReviewChangeDto> changes)
        {
            Dictionary<Guid, DrawingSurfaceModel> previous = before.Model.DrawingSurfaceList.ToDictionary(page => page.Guid);
            Dictionary<Guid, DrawingSurfaceModel> current = after.Model.DrawingSurfaceList.ToDictionary(page => page.Guid);
            foreach (Guid id in previous.Keys.Union(current.Keys).OrderBy(id => id))
            {
                previous.TryGetValue(id, out DrawingSurfaceModel? baseline);
                current.TryGetValue(id, out DrawingSurfaceModel? proposed);
                if (baseline != null && proposed != null && baseline.Header == proposed.Header)
                {
                    continue;
                }

                changes.Add(new ModelReviewChangeDto
                {
                    Id = "page:" + id.ToString("N"),
                    Kind = baseline == null ? "added" : proposed == null ? "removed" : "modified",
                    ElementKind = "page",
                    Title = proposed?.Header ?? baseline?.Header ?? "Page",
                    BaselinePageId = baseline == null ? null : OriginalId(id, before.Ids),
                    ProposedPageId = proposed == null ? null : OriginalId(id, after.Ids),
                    BaselinePageName = baseline?.Header,
                    ProposedPageName = proposed?.Header,
                    Properties = new[] { new PropertyChange { Key = "page name", From = baseline?.Header, To = proposed?.Header } },
                });
            }
        }

        private static ModelReviewChangeDto ElementChange(
            Guid id,
            string section,
            string kind,
            string title,
            Snapshot baseline,
            Snapshot proposed,
            IReadOnlyList<PropertyChange> properties,
            IEnumerable<Guid>? removedBoundaries = null,
            IEnumerable<Guid>? addedBoundaries = null)
        {
            baseline.Elements.TryGetValue(id, out ElementDescriptor? before);
            proposed.Elements.TryGetValue(id, out ElementDescriptor? after);
            ElementDescriptor? present = after ?? before;
            if (section == "structure" && (before == null || after == null) && present != null)
            {
                properties = present.Attributes.OrderBy(attribute => attribute.Key, StringComparer.Ordinal).Select(attribute => new PropertyChange
                {
                    Key = attribute.Key,
                    From = before == null ? null : EndpointValue(attribute.Key, attribute.Value, baseline.Ids),
                    To = after == null ? null : EndpointValue(attribute.Key, attribute.Value, proposed.Ids),
                }).ToArray();
            }

            return new ModelReviewChangeDto
            {
                Id = section + ":" + id.ToString("N"),
                Section = section,
                Kind = kind,
                Title = title,
                ElementKind = (after ?? before)?.Kind,
                BaselineElementIds = Highlight(before, baseline.Ids, removedBoundaries),
                ProposedElementIds = Highlight(after, proposed.Ids, addedBoundaries),
                BaselinePageId = before == null ? null : OriginalId(before.DiagramId, baseline.Ids),
                ProposedPageId = after == null ? null : OriginalId(after.DiagramId, proposed.Ids),
                BaselinePageName = before?.DiagramName,
                ProposedPageName = after?.DiagramName,
                Properties = properties,
            };
        }

        private static IReadOnlyList<string> Highlight(ElementDescriptor? element, IReadOnlyDictionary<Guid, string> ids, IEnumerable<Guid>? boundaries)
        {
            if (element == null)
            {
                return Array.Empty<string>();
            }

            List<Guid> targets = new List<Guid> { element.Id };
            if (element.Kind == "flow")
            {
                foreach (string endpoint in new[] { "source", "target" })
                {
                    if (element.Attributes.TryGetValue(endpoint, out string? value) && Guid.TryParse(value, out Guid parsed))
                    {
                        targets.Add(parsed);
                    }
                }
            }

            targets.AddRange(boundaries ?? Array.Empty<Guid>());
            return targets.Distinct().Select(id => OriginalId(id, ids)).ToArray();
        }

        private static bool CheckAnalysis(AnalysisDocumentDto analysis, string side, List<DocumentDiagnostic> diagnostics)
        {
            IEnumerable<string> failures = analysis.Diagnostics.Concat(analysis.Findings
                .Where(finding => finding.RuleId == "engine-error" || finding.RuleId == "rule-pack-mismatch")
                .Select(finding => finding.Message));
            bool available = true;
            foreach (string failure in failures)
            {
                available = false;
                JsonDocumentPreflight.Add(diagnostics, "compare.analysis-unavailable", "$." + side + ".analysis", side + ": " + failure);
            }

            return available;
        }

        private static ModelReviewChangeDto FindingChange(AnalysisFindingDto? before, AnalysisFindingDto? after, string kind, Snapshot baseline, Snapshot proposed)
        {
            AnalysisFindingDto finding = after ?? before!;
            return new ModelReviewChangeDto
            {
                Id = "finding:" + finding.Id,
                Section = "findings",
                Kind = kind,
                Title = finding.Message,
                RuleId = finding.RuleId,
                Severity = finding.Severity,
                BaselineElementIds = before?.ElementIds ?? Array.Empty<string>(),
                ProposedElementIds = after?.ElementIds ?? Array.Empty<string>(),
                BaselinePageId = before?.Diagram,
                ProposedPageId = after?.Diagram,
                BaselinePageName = before?.Diagram != null && baseline.PageNames.TryGetValue(before.Diagram, out string? beforeName) ? beforeName : null,
                ProposedPageName = after?.Diagram != null && proposed.PageNames.TryGetValue(after.Diagram, out string? afterName) ? afterName : null,
                Properties = new[]
                {
                    new PropertyChange { Key = "severity", From = before?.Severity, To = after?.Severity },
                    new PropertyChange { Key = "disposition", From = before?.Disposition, To = after?.Disposition },
                },
            };
        }

        private static string? EndpointValue(string key, string? value, IReadOnlyDictionary<Guid, string> ids)
            => (key == ModelSnapshot.SourceKey || key == ModelSnapshot.TargetKey) && Guid.TryParse(value, out Guid id) ? OriginalId(id, ids) : value;

        private static string OriginalId(Guid id, IReadOnlyDictionary<Guid, string> ids)
            => ids.TryGetValue(id, out string? original) ? original : id.ToString();

        private sealed class Snapshot
        {
            internal Snapshot(ThreatModel model, IReadOnlyDictionary<Guid, string> ids)
            {
                this.Model = model;
                this.Ids = ids;
                this.Elements = ModelSnapshot.Capture(model).ToDictionary(element => element.Id);
                this.PageNames = model.DrawingSurfaceList.ToDictionary(page => OriginalId(page.Guid, ids), page => page.Header ?? "Page", StringComparer.Ordinal);
            }

            internal ThreatModel Model { get; }

            internal IReadOnlyDictionary<Guid, string> Ids { get; }

            internal Dictionary<Guid, ElementDescriptor> Elements { get; }

            internal Dictionary<string, string> PageNames { get; }
        }
    }
}
