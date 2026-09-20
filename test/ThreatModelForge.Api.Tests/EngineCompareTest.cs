namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;
    using ThreatModelForge.Model;

    /// <summary>Tests the read-only comparison used by Studio review.</summary>
    [TestClass]
    public class EngineCompareTest
    {
        /// <summary>A rename is one change with the author's ids and neither input is mutated.</summary>
        [TestMethod]
        public void CompareReportsRenameWithoutMutatingInputs()
        {
            TmForgeModelDto baseline = Model("Original API");
            TmForgeModelDto proposed = Model("Renamed API");
            string before = JsonSerializer.Serialize(baseline);
            string after = JsonSerializer.Serialize(proposed);

            ModelCompareResultDto result = EngineService.Compare(
                new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            Assert.IsTrue(result.Success);
            ModelReviewChangeDto change = result.Changes.Single(item => item.Section == "structure");
            Assert.AreEqual("modified", change.Kind);
            CollectionAssert.Contains(change.BaselineElementIds.ToArray(), "api");
            CollectionAssert.Contains(change.ProposedElementIds.ToArray(), "api");
            Assert.AreEqual("name", change.Properties.Single().Key);
            Assert.AreEqual("Original API", change.Properties.Single().From);
            Assert.AreEqual("Renamed API", change.Properties.Single().To);
            Assert.AreEqual(before, JsonSerializer.Serialize(baseline));
            Assert.AreEqual(after, JsonSerializer.Serialize(proposed));
        }

        /// <summary>Geometry-only movement remains quiet unless it changes trust-boundary crossings.</summary>
        [TestMethod]
        public void CompareDetectsCrossingsWithoutInventingPropertyChanges()
        {
            ModelCompareRequestDto request = new ModelCompareRequestDto
            {
                Baseline = ConnectedModel(300, "No"),
                Proposed = ConnectedModel(800, "No"),
            };
            ModelCompareResultDto result = EngineService.Compare(request, null);

            Assert.IsTrue(result.Success);
            Assert.IsTrue(result.FindingsAvailable);
            Assert.IsFalse(result.Changes.Any(item => item.Section == "structure"));
            ModelReviewChangeDto crossing = result.Changes.Single(item => item.Section == "crossings");
            CollectionAssert.Contains(crossing.BaselineElementIds.ToArray(), "request");
            CollectionAssert.Contains(crossing.BaselineElementIds.ToArray(), "zone");
            Assert.AreEqual("Crosses", crossing.Properties.Single().From);
            Assert.AreEqual("Does not cross", crossing.Properties.Single().To);
        }

        /// <summary>Control changes produce the same finding delta as the existing evidence comparison.</summary>
        [TestMethod]
        public void CompareReusesFindingIdentity()
        {
            TmForgeModelDto baseline = ConnectedModel(300, "No");
            TmForgeModelDto proposed = ConnectedModel(300, "Yes");
            AnalysisDifference expected = AnalysisDocumentDiff.Compare(EngineService.DescribeAnalysis(baseline), EngineService.DescribeAnalysis(proposed));

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            Assert.IsTrue(result.FindingsAvailable);
            Assert.AreEqual(expected.Introduced.Count, result.Changes.Count(item => item.Kind == "introduced"));
            Assert.AreEqual(expected.Resolved.Count, result.Changes.Count(item => item.Kind == "resolved"));
            Assert.AreEqual(expected.Unchanged, result.UnchangedFindings);
            Assert.IsTrue(result.Changes.Any(item => item.RuleId == "TM1023" && item.Kind == "resolved"));
        }

        /// <summary>A bad source or unavailable rule pack never turns an analysis failure into resolutions.</summary>
        [TestMethod]
        public void CompareRefusesInvalidInputsAndMarksUnavailableAnalysis()
        {
            TmForgeModelDto invalid = new TmForgeModelDto
            {
                Elements = new[] { new TmForgeElementDto { Id = "duplicate" }, new TmForgeElementDto { Id = "duplicate" } },
            };
            ModelCompareResultDto refused = EngineService.Compare(new ModelCompareRequestDto { Baseline = invalid, Proposed = Model("Valid") }, null);
            Assert.IsFalse(refused.Success);
            Assert.HasCount(0, refused.Changes);
            Assert.IsTrue(refused.Diagnostics.Any(item => item.Path.StartsWith("$.baseline", StringComparison.Ordinal)));

            TmForgeModelDto unavailable = new TmForgeModelDto
            {
                Elements = Model("Changed").Elements,
                Analysis = new TmForgeAnalysisDto { ExpectedPacks = new[] { new ExpectedRulePackDto { Id = "missing", Fingerprint = "sha256:missing" } } },
            };
            ModelCompareResultDto partial = EngineService.Compare(new ModelCompareRequestDto { Baseline = Model("Original"), Proposed = unavailable }, null);
            Assert.IsTrue(partial.Success);
            Assert.IsFalse(partial.FindingsAvailable);
            Assert.IsTrue(partial.Changes.Any(item => item.Section == "structure"));
            Assert.IsFalse(partial.Changes.Any(item => item.Section == "findings"));
            Assert.IsTrue(partial.Diagnostics.Any(item => item.Code == "compare.analysis-unavailable"));
        }

        /// <summary>A changed rule selection is disclosed instead of attributed only to the model.</summary>
        [TestMethod]
        public void CompareWarnsWhenEffectiveRulesDiffer()
        {
            TmForgeModelDto baseline = ConnectedModel(300, "No");
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Elements = baseline.Elements,
                Flows = baseline.Flows,
                Analysis = new TmForgeAnalysisDto { DisabledRuleIds = new[] { "TM1023" } },
            };

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            Assert.IsTrue(result.FindingsAvailable);
            Assert.IsTrue(result.Warnings.Any(warning => warning.Contains("rule selection", StringComparison.Ordinal)));
        }

        /// <summary>No-op and in-boundary layout changes do not invent findings or property changes.</summary>
        [TestMethod]
        public void CompareIsDeterministicAndQuietForSafeLayout()
        {
            TmForgeModelDto baseline = ConnectedModel(300, "No");
            foreach (TmForgeModelDto proposed in new[] { baseline, ConnectedModel(310, "No") })
            {
                ModelCompareRequestDto request = new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed };
                ModelCompareResultDto result = EngineService.Compare(request, null);
                Assert.IsTrue(result.Success);
                Assert.IsTrue(result.FindingsAvailable);
                Assert.HasCount(0, result.Changes);
                Assert.HasCount(0, result.Warnings);
                Assert.IsGreaterThan(0, result.UnchangedFindings);
                Assert.AreEqual(JsonSerializer.Serialize(result), JsonSerializer.Serialize(EngineService.Compare(request, null)));
            }
        }

        /// <summary>Page moves, renames, additions and deletions retain both navigation targets.</summary>
        [TestMethod]
        public void CompareTracksPagesAndPageMoves()
        {
            TmForgeModelDto baseline = new TmForgeModelDto
            {
                Diagrams = new[]
                {
                    new TmForgeDiagramDto { Id = "one", Name = "Original", Elements = Model("API").Elements },
                    new TmForgeDiagramDto { Id = "two", Name = "Retired" },
                },
            };
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Diagrams = new[]
                {
                    new TmForgeDiagramDto { Id = "one", Name = "Renamed" },
                    new TmForgeDiagramDto { Id = "three", Name = "New page", Elements = Model("API").Elements },
                },
            };

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            Assert.IsTrue(result.Success);
            Assert.HasCount(4, result.Changes.Where(change => change.Section == "structure").ToArray());
            ModelReviewChangeDto moved = result.Changes.Single(change => change.Section == "structure" && change.ElementKind == "process");
            Assert.AreEqual("one", moved.BaselinePageId);
            Assert.AreEqual("three", moved.ProposedPageId);
            Assert.AreEqual("page", moved.Properties.Single().Key);
            Assert.AreEqual("Original", moved.Properties.Single().From);
            Assert.AreEqual("New page", moved.Properties.Single().To);
            ModelReviewChangeDto added = result.Changes.Single(change => change.ElementKind == "page" && change.Kind == "added");
            Assert.IsNull(added.BaselinePageId);
            Assert.AreEqual("three", added.ProposedPageId);
            ModelReviewChangeDto removed = result.Changes.Single(change => change.ElementKind == "page" && change.Kind == "removed");
            Assert.AreEqual("two", removed.BaselinePageId);
            Assert.IsNull(removed.ProposedPageId);
        }

        /// <summary>Rerouted flows show original endpoint ids, including removed and new objects.</summary>
        [TestMethod]
        public void CompareMapsReroutesAndOneSidedObjects()
        {
            TmForgeModelDto baseline = ConnectedModel(300, "No");
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Elements = baseline.Elements!.Where(element => element.Id != "api").Append(new TmForgeElementDto { Id = "replacement", Kind = "process", Name = "API", X = 800, Y = 100 }).ToArray(),
                Flows = new[] { new TmForgeFlowDto { Id = "request", Source = "caller", Target = "replacement", Name = "Request" } },
            };

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            ModelReviewChangeDto flow = result.Changes.Single(change => change.Section == "structure" && change.ElementKind == "flow");
            Assert.AreEqual("api", flow.Properties.Single().From);
            Assert.AreEqual("replacement", flow.Properties.Single().To);
            CollectionAssert.AreEquivalent(new[] { "request", "caller", "api" }, flow.BaselineElementIds.ToArray());
            CollectionAssert.AreEquivalent(new[] { "request", "caller", "replacement" }, flow.ProposedElementIds.ToArray());
            Assert.HasCount(0, result.Changes.Single(change => change.Section == "structure" && change.Kind == "added").BaselineElementIds);
            Assert.HasCount(0, result.Changes.Single(change => change.Section == "structure" && change.Kind == "removed").ProposedElementIds);
            ModelReviewChangeDto added = result.Changes.Single(change => change.Section == "structure" && change.Kind == "added");
            Assert.AreEqual("API", added.Properties.Single(property => property.Key == "name").To);
            Assert.IsTrue(added.Properties.All(property => property.From == null));
            ModelReviewChangeDto removed = result.Changes.Single(change => change.Section == "structure" && change.Kind == "removed");
            Assert.AreEqual("API", removed.Properties.Single(property => property.Key == "name").From);
            Assert.IsTrue(removed.Properties.All(property => property.To == null));
        }

        /// <summary>Triage changes disposition without resolving the finding or modifying the inputs.</summary>
        [TestMethod]
        public void CompareReclassifiesAcceptedThreatWithoutResolvingIt()
        {
            TmForgeModelDto baseline = ConnectedModel(300, "No");
            AnalysisFindingDto finding = EngineService.DescribeAnalysis(baseline).Findings.Single(item => item.RuleId == "TM1023");
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Elements = baseline.Elements,
                Flows = baseline.Flows,
                Threats = new[] { new ThreatStateDto { Id = finding.ThreatId!, State = "Accepted", Justification = "Reviewed risk" } },
            };
            string original = JsonSerializer.Serialize(proposed);

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            ModelReviewChangeDto change = result.Changes.Single(item => item.RuleId == "TM1023");
            Assert.AreEqual("reclassified", change.Kind);
            Assert.AreEqual("generated-threat", change.Properties.Single(property => property.Key == "disposition").From);
            Assert.AreEqual("accepted", change.Properties.Single(property => property.Key == "disposition").To);
            Assert.IsTrue(result.Warnings.Any(warning => warning.Contains("triage", StringComparison.Ordinal)));
            Assert.AreEqual(original, JsonSerializer.Serialize(proposed));
        }

        /// <summary>Different spellings of the same identity must not produce false finding resolutions.</summary>
        [TestMethod]
        public void CompareDisclosesSourceIdentityRepresentationChanges()
        {
            TmForgeModelDto baseline = Model("API");
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Elements = new[] { new TmForgeElementDto { Id = DeterministicGuid.FromElementId("api").ToString(), Kind = "process", Name = "API", X = 100, Y = 100 } },
            };

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            Assert.IsTrue(result.Success);
            Assert.IsFalse(result.FindingsAvailable);
            Assert.HasCount(0, result.Changes);
            Assert.IsTrue(result.Warnings.Any(warning => warning.Contains("different source ids", StringComparison.Ordinal)));
        }

        /// <summary>Changes outside the bounded review scope are disclosed even if no reviewed field changed.</summary>
        [TestMethod]
        public void CompareDisclosesMetadataAndManualThreatChanges()
        {
            TmForgeModelDto baseline = Model("API");
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Elements = baseline.Elements,
                Metadata = new MetaInformation { Owner = "Security" },
                Threats = new[] { new ThreatStateDto { Id = "manual:new", Manual = true, Title = "Manual risk", Category = "Privacy" } },
            };

            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed }, null);

            Assert.IsTrue(result.Success);
            Assert.HasCount(0, result.Changes);
            Assert.IsTrue(result.Warnings.Any(warning => warning.Contains("metadata differs", StringComparison.Ordinal)));
            Assert.IsTrue(result.Warnings.Any(warning => warning.Contains("threat records differ", StringComparison.Ordinal)));
        }

        /// <summary>Missing and excessive inputs fail without partial results; names never substitute for identity.</summary>
        [TestMethod]
        public void CompareEnforcesLimitsAndIdentityMatching()
        {
            Assert.Throws<ArgumentNullException>(() => EngineService.Compare(null!, null));
            ModelCompareResultDto missing = EngineService.Compare(new ModelCompareRequestDto(), null);
            Assert.IsFalse(missing.Success);
            Assert.AreEqual("compare.missing-input", missing.Diagnostics.Single().Code);
            TmForgeModelDto oversized = new TmForgeModelDto
            {
                Diagrams = Enumerable.Range(0, 33).Select(index => new TmForgeDiagramDto { Id = "page-" + index, Name = "Page" }).ToArray(),
            };
            ModelCompareResultDto refused = EngineService.Compare(new ModelCompareRequestDto { Baseline = oversized, Proposed = Model("API") }, null);
            Assert.IsFalse(refused.Success);
            Assert.HasCount(0, refused.Changes);
            Assert.AreEqual("compare.model-limit", refused.Diagnostics.Single().Code);

            TmForgeModelDto unrelated = new TmForgeModelDto { Elements = new[] { new TmForgeElementDto { Id = "unrelated", Name = "API", Kind = "process" } } };
            ModelCompareResultDto result = EngineService.Compare(new ModelCompareRequestDto { Baseline = Model("API"), Proposed = unrelated }, null);
            Assert.IsTrue(result.Warnings.Any(warning => warning.Contains("no element identities", StringComparison.Ordinal)));
            CollectionAssert.AreEquivalent(new[] { "added", "removed" }, result.Changes.Where(change => change.Section == "structure").Select(change => change.Kind).ToArray());
        }

        private static TmForgeModelDto ConnectedModel(int processX, string authentication)
        {
            return new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "caller", Kind = "external", Name = "Caller", X = 10, Y = 100, Width = 120, Height = 80, Properties = new Dictionary<string, string> { ["AuthenticatesItself"] = authentication } },
                    new TmForgeElementDto { Id = "api", Kind = "process", Name = "API", X = processX, Y = 100, Width = 100, Height = 100 },
                    new TmForgeElementDto { Id = "zone", Kind = "boundary", Name = "Service zone", X = 250, Y = 40, Width = 300, Height = 250 },
                },
                Flows = new[] { new TmForgeFlowDto { Id = "request", Source = "caller", Target = "api", Name = "Request" } },
            };
        }

        private static TmForgeModelDto Model(string name)
        {
            return new TmForgeModelDto
            {
                Schema = "tmforge-json",
                Version = "0.1",
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "api", Name = name, Kind = "process", X = 100, Y = 100 },
                },
            };
        }
    }
}
