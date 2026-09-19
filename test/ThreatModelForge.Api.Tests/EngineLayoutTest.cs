namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Crossing-preserving layout through the host-neutral facade.</summary>
    [TestClass]
    public class EngineLayoutTest
    {
        /// <summary>Layout returns original author ids without rewriting any input or author state.</summary>
        [TestMethod]
        public void LayoutPreservesIdentityFindingsAndAuthorState()
        {
            TmForgeModelDto model = Model();
            string before = JsonSerializer.Serialize(model);
            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsTrue(result.Success, result.Error);
            Assert.AreEqual(1, result.Pages);
            Assert.AreEqual(2, result.Components);
            CollectionAssert.AreEquivalent(model.Elements!.Select(element => element.Id).ToList(), result.Elements.Select(element => element.Id).ToList());
            Assert.AreEqual(before, JsonSerializer.Serialize(model), "the request is immutable on success too");

            TmForgeModelDto placed = ApplyGeometry(model, result);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(Read(model), Read(placed)).IsEmpty);
            Assert.IsTrue(ModelDiff.Compare(Read(model), Read(placed)).IsEmpty);

            // The metadata fixture pins an unavailable pack to prove the pin survives. Compare
            // real detection with that deliberately missing dependency removed on both sides.
            IReadOnlyList<FindingDto> beforeFindings = EngineService.Analyze(WithoutPackExpectation(model));
            IReadOnlyList<FindingDto> afterFindings = EngineService.Analyze(WithoutPackExpectation(placed));
            Assert.IsTrue(beforeFindings.Count > 2);
            Assert.IsFalse(beforeFindings.Concat(afterFindings).Any(finding => finding.Id == "engine-error"));
            CollectionAssert.AreEquivalent(
                beforeFindings.Select(finding => finding.Id).ToList(),
                afterFindings.Select(finding => finding.Id).ToList());
            Assert.AreEqual(JsonSerializer.Serialize(model.Analysis), JsonSerializer.Serialize(placed.Analysis));
            Assert.AreEqual(JsonSerializer.Serialize(model.Threats), JsonSerializer.Serialize(placed.Threats));
        }

        /// <summary>Two arrangements and a repeated arrangement all produce the same rectangles.</summary>
        [TestMethod]
        public void LayoutIsDeterministicAndIdempotent()
        {
            TmForgeModelDto model = Model();
            LayoutResultDto first = EngineService.Layout(new LayoutRequestDto { Model = model });
            LayoutResultDto second = EngineService.Layout(new LayoutRequestDto { Model = model });
            LayoutResultDto repeated = EngineService.Layout(new LayoutRequestDto { Model = ApplyGeometry(model, first) });

            Assert.IsTrue(first.Success, first.Error);
            Assert.IsTrue(repeated.Success, repeated.Error);
            Assert.AreEqual(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
            Assert.AreEqual(JsonSerializer.Serialize(first), JsonSerializer.Serialize(repeated));
        }

        /// <summary>Nested membership is retained and members clear the boundary title and edges.</summary>
        [TestMethod]
        public void LayoutHonorsBoundaryHeaderClearance()
        {
            TmForgeModelDto model = Model();
            LayoutRequestDto request = new LayoutRequestDto
            {
                Model = model,
                Options = new LayoutOptions { BoundaryHeaderHeight = 80 },
            };

            LayoutResultDto result = EngineService.Layout(request);

            Assert.IsTrue(result.Success, result.Error);
            LayoutElementDto member = result.Elements.Single(element => element.Id == "source");
            LayoutElementDto boundary = result.Elements.Single(element => element.Id == "boundary");
            Assert.AreEqual(100, member.Width);
            Assert.AreEqual(60, member.Height);
            Assert.IsTrue(member.Y >= boundary.Y + 80 + 24);
            Assert.IsTrue(member.X > boundary.X && member.X + member.Width < boundary.X + boundary.Width);
            Assert.IsTrue(member.Y + member.Height < boundary.Y + boundary.Height);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(Read(model), Read(ApplyGeometry(model, result))).IsEmpty);
        }

        /// <summary>Overlapping claims cannot be discarded by automatic placement.</summary>
        [TestMethod]
        public void LayoutRefusesOverlappingMembershipWithoutMutatingInput()
        {
            TmForgeModelDto model = Model(overlapping: true);
            string before = JsonSerializer.Serialize(model);
            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto
            {
                Model = model,
            });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "boundary");
            Assert.AreEqual(before, JsonSerializer.Serialize(model));
        }

        /// <summary>An unsafe page refuses the whole multi-page request without partial patches.</summary>
        [TestMethod]
        public void LayoutRefusesMultiplePagesAtomically()
        {
            TmForgeModelDto model = MultiPage(overlapping: true);
            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            Assert.AreEqual(0, result.Pages);
        }

        /// <summary>All page identities and crossing sets survive a multi-page arrangement.</summary>
        [TestMethod]
        public void LayoutPreservesEveryPage()
        {
            TmForgeModelDto model = MultiPage(overlapping: false);
            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsTrue(result.Success, result.Error);
            Assert.AreEqual(2, result.Pages);
            Assert.AreEqual(6, result.Elements.Count);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(Read(model), Read(ApplyGeometry(model, result))).IsEmpty);
        }

        /// <summary>Zero-hop flows and directed cycles terminate without changing their topology.</summary>
        [TestMethod]
        public void LayoutHandlesCyclesAndSelfLoops()
        {
            TmForgeModelDto original = Model();
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = original.Elements,
                Flows = new[]
                {
                    original.Flows![0],
                    new TmForgeFlowDto { Id = "return", Source = "target", Target = "source" },
                    new TmForgeFlowDto { Id = "self", Source = "source", Target = "source" },
                },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsTrue(result.Success, result.Error);
            Assert.IsTrue(BoundaryCrossingDiff.Compare(Read(model), Read(ApplyGeometry(model, result))).IsEmpty);
        }

        /// <summary>Invalid shapes must not be normalized into apparently safe input by the format reader.</summary>
        /// <param name="kind">The kind to validate.</param>
        /// <param name="width">The authored width.</param>
        /// <param name="height">The authored height.</param>
        [TestMethod]
        [DataRow("mystery", 100, 60)]
        [DataRow("process", 0, 60)]
        [DataRow("process", -1, 60)]
        [DataRow("process", 10, 60)]
        [DataRow("process", 100001, 60)]
        public void LayoutRejectsInvalidShapes(string kind, int width, int height)
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[] { new TmForgeElementDto { Id = "a", Kind = kind, Width = width, Height = height } },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
        }

        /// <summary>Duplicate IDs, including differently-spelled copies of one GUID, are refused.</summary>
        /// <param name="first">The first identity.</param>
        /// <param name="second">The colliding identity.</param>
        [TestMethod]
        [DataRow("a", "a")]
        [DataRow("00000000-0000-0000-0000-000000000abc", "00000000000000000000000000000ABC")]
        [DataRow("", "b")]
        public void LayoutRejectsIdentityCollisions(string first, string second)
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = first, Kind = "process" },
                    new TmForgeElementDto { Id = second, Kind = "process" },
                },
            };

            Assert.IsFalse(EngineService.Layout(new LayoutRequestDto { Model = model }).Success);
        }

        /// <summary>Single-page dangling flows identify the missing endpoint rather than implying a page mismatch.</summary>
        /// <param name="source">The source endpoint id.</param>
        /// <param name="target">The target endpoint id.</param>
        /// <param name="endpoint">The endpoint role that must be named in the error.</param>
        [TestMethod]
        [DataRow("missing", "target", "source")]
        [DataRow("source", "missing", "target")]
        public void LayoutRejectsDanglingFlows(string source, string target, string endpoint)
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = new[] { new TmForgeFlowDto { Id = "audit-request", Name = "Read audit", Source = source, Target = target } },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "audit-request");
            StringAssert.Contains(result.Error, "Read audit");
            StringAssert.Contains(result.Error, endpoint);
            StringAssert.Contains(result.Error, "missing");
        }

        /// <summary>An imported floating connector names its unattached endpoint and leaves the model untouched.</summary>
        [TestMethod]
        public void LayoutIdentifiesUnattachedTarget()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = new[] { new TmForgeFlowDto { Id = "watch", Name = "TLS: Watch", Source = "source", Target = Guid.Empty.ToString() } },
            };
            string before = JsonSerializer.Serialize(model);

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "TLS: Watch");
            StringAssert.Contains(result.Error, "unattached target endpoint");
            StringAssert.Contains(result.Error, Guid.Empty.ToString());
            Assert.AreEqual(before, JsonSerializer.Serialize(model));
        }

        /// <summary>Duplicate flow ids are reported as identity collisions, not endpoint or page errors.</summary>
        [TestMethod]
        public void LayoutIdentifiesDuplicateFlowIds()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = new[]
                {
                    new TmForgeFlowDto { Id = "audit-request", Name = "Read audit", Source = "source", Target = "target" },
                    new TmForgeFlowDto { Id = "audit-request", Name = "Read audit again", Source = "source", Target = "target" },
                },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "audit-request");
            StringAssert.Contains(result.Error, "duplicate");
        }

        /// <summary>An oversized flow label must not be presented as an endpoint or page error.</summary>
        [TestMethod]
        public void LayoutIdentifiesOversizedFlowLabels()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = new[] { new TmForgeFlowDto { Id = "verbose-flow", Name = new string('x', 4097), Source = "source", Target = "target" } },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "verbose-flow");
            StringAssert.Contains(result.Error, "4096");
        }

        /// <summary>Malformed endpoint text is bounded when it is reported to the caller.</summary>
        [TestMethod]
        public void LayoutIdentifiesOversizedEndpointIds()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = new[] { new TmForgeFlowDto { Id = "invalid-endpoint", Source = "source", Target = new string('x', 10000) } },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "invalid-endpoint");
            StringAssert.Contains(result.Error, "target endpoint id longer than 256");
            Assert.IsTrue(result.Error!.Length < 256);
        }

        /// <summary>Oversized graphs fail before arrangement and empty models are valid no-ops.</summary>
        [TestMethod]
        public void LayoutBoundsGraphWork()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Enumerable.Range(0, LayoutOperations.MaximumElements + 1)
                    .Select(index => new TmForgeElementDto { Id = "p" + index, Kind = "process" }).ToArray(),
            };

            LayoutResultDto tooLarge = EngineService.Layout(new LayoutRequestDto { Model = model });
            Assert.IsFalse(tooLarge.Success);
            StringAssert.Contains(tooLarge.Error, "limited");

            LayoutResultDto empty = EngineService.Layout(new LayoutRequestDto { Model = new TmForgeModelDto() });
            Assert.IsTrue(empty.Success, empty.Error);
            Assert.IsEmpty(empty.Elements);
            Assert.IsFalse(EngineService.Layout(new LayoutRequestDto()).Success);
        }

        /// <summary>Boundary-ended flows cannot validate with stale endpoints and then reroute on read.</summary>
        [TestMethod]
        public void LayoutRefusesBoundaryEndpoints()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = new[] { new TmForgeFlowDto { Id = "f", Source = "boundary", Target = "source" } },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "not trust boundaries");
        }

        /// <summary>Output must satisfy the same bounds as input, so every success remains arrangeable.</summary>
        [TestMethod]
        public void LayoutRefusesOutOfRangeCandidate()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "a", Kind = "process", Width = 20, Height = 20 },
                    new TmForgeElementDto { Id = "b", Kind = "process", Width = 20, Height = 20 },
                },
            };
            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto
            {
                Model = model, Options = new LayoutOptions { OriginY = 1000000 },
            });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
        }

        /// <summary>Page identity must never replace a component identity in the wire-id map.</summary>
        [TestMethod]
        public void LayoutRefusesCrossNamespaceGuidCollision()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Diagrams = new[]
                {
                    new TmForgeDiagramDto
                    {
                        Id = "page-one",
                        Elements = new[] { new TmForgeElementDto { Id = "00000000-0000-0000-0000-000000000001", Kind = "process" } },
                    },
                    new TmForgeDiagramDto { Id = "00000000000000000000000000000001" },
                },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            StringAssert.Contains(result.Error, "same internal GUID");
        }

        /// <summary>A page and element may share an author alias when their internal namespaces differ.</summary>
        [TestMethod]
        public void LayoutAcceptsSeparatePageAndElementAliasNamespaces()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Diagrams = new[]
                {
                    new TmForgeDiagramDto { Id = "source", Elements = Model().Elements, Flows = Model().Flows },
                },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsTrue(result.Success, result.Error);
            CollectionAssert.Contains(result.Elements.Select(element => element.Id).ToArray(), "source");
        }

        /// <summary>A large property bag has no effect and is not hydrated into the geometry candidate.</summary>
        [TestMethod]
        public void LayoutIgnoresNonGeometryState()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto
                    {
                        Id = "p", Kind = "process", Name = "Process",
                        Properties = Enumerable.Range(0, 20000).ToDictionary(index => "k" + index, _ => "value"),
                    },
                },
                Threats = new[] { new ThreatStateDto { Id = "ignored-malformed-triage" } },
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsTrue(result.Success, result.Error);
            Assert.AreEqual("p", result.Elements.Single().Id);
        }

        /// <summary>Page scoping validates one candidate without touching an unsafe sibling.</summary>
        [TestMethod]
        public void LayoutScopesToOnePage()
        {
            TmForgeModelDto model = MultiPage(overlapping: true);
            LayoutResultDto first = EngineService.Layout(new LayoutRequestDto { Model = model, Page = "1" });
            LayoutResultDto named = EngineService.Layout(new LayoutRequestDto { Model = model, Page = "A" });

            Assert.IsTrue(first.Success, first.Error);
            Assert.AreEqual(1, first.Pages);
            Assert.AreEqual(JsonSerializer.Serialize(first), JsonSerializer.Serialize(named));
            Assert.IsFalse(EngineService.Layout(new LayoutRequestDto { Model = model, Page = "missing" }).Success);
        }

        /// <summary>Large dense label sets trip the work bound even below the element-count limits.</summary>
        [TestMethod]
        public void LayoutBoundsDenseGraphWork()
        {
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = Model().Elements,
                Flows = Enumerable.Range(0, 900).Select(index => new TmForgeFlowDto
                {
                    Id = "f" + index, Name = "Request", Source = "source", Target = "target",
                }).ToArray(),
            };

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model });

            Assert.IsFalse(result.Success);
            StringAssert.Contains(result.Error, "work budget");
        }

        /// <summary>In-place cleanup keeps its proposed coordinates rather than being layered again.</summary>
        [TestMethod]
        public void LayoutValidatesProposedPositionsWithoutRearranging()
        {
            TmForgeModelDto model = Model();
            string before = JsonSerializer.Serialize(model);
            LayoutElementDto[] positions = model.Elements!.Select(element => new LayoutElementDto
            {
                Id = element.Id, X = element.X + 300, Y = element.Y - 50,
                Width = element.Width!.Value, Height = element.Height!.Value,
            }).ToArray();

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model, Positions = positions });

            Assert.IsTrue(result.Success, result.Error);
            Assert.AreEqual(JsonSerializer.Serialize(positions), JsonSerializer.Serialize(result.Elements));
            Assert.AreEqual(before, JsonSerializer.Serialize(model));
            Assert.IsTrue(BoundaryCrossingDiff.Compare(Read(model), Read(ApplyGeometry(model, result))).IsEmpty);
        }

        /// <summary>A supplied cleanup candidate cannot bypass the crossing-preservation guard.</summary>
        [TestMethod]
        public void LayoutRejectsUnsafeProposedPositions()
        {
            TmForgeModelDto model = Model();
            LayoutElementDto[] positions = model.Elements!.Select(element => new LayoutElementDto
            {
                Id = element.Id, X = element.Id == "source" ? 1000 : element.X, Y = element.Y,
                Width = element.Width!.Value, Height = element.Height!.Value,
            }).ToArray();

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto { Model = model, Positions = positions });

            Assert.IsFalse(result.Success);
            Assert.IsEmpty(result.Elements);
            StringAssert.Contains(result.Error, "boundary membership");
        }

        /// <summary>Proposed geometry must be complete, unique and bounded.</summary>
        /// <param name="scenario">The invalid candidate shape.</param>
        [TestMethod]
        [DataRow("partial")]
        [DataRow("duplicate")]
        [DataRow("unknown")]
        [DataRow("oversized")]
        public void LayoutRejectsInvalidProposedPositions(string scenario)
        {
            TmForgeModelDto model = Model();
            List<LayoutElementDto> positions = model.Elements!.Select(element => new LayoutElementDto
            {
                Id = element.Id, X = element.X, Y = element.Y, Width = element.Width!.Value, Height = element.Height!.Value,
            }).ToList();
            if (scenario == "partial")
            {
                positions.RemoveAt(0);
            }
            else if (scenario == "duplicate")
            {
                positions[0] = positions[1];
            }
            else if (scenario == "unknown" || scenario == "oversized")
            {
                positions[0] = new LayoutElementDto
                {
                    Id = scenario == "unknown" ? "absent" : positions[0].Id,
                    X = 1000001, Width = 100, Height = 100,
                };
            }

            LayoutResultDto result = EngineService.Layout(new LayoutRequestDto
            {
                Model = model, Positions = positions,
            });

            Assert.IsFalse(result.Success, scenario);
            Assert.IsEmpty(result.Elements);
        }

        private static TmForgeModelDto WithoutPackExpectation(TmForgeModelDto model) => new TmForgeModelDto
        {
            Schema = model.Schema, Version = model.Version, Elements = model.Elements, Flows = model.Flows,
            Diagrams = model.Diagrams, Threats = model.Threats,
            Analysis = new TmForgeAnalysisDto { DisabledRuleIds = model.Analysis?.DisabledRuleIds },
        };

        private static TmForgeModelDto Model(bool overlapping = false, string prefix = "")
        {
            List<TmForgeElementDto> elements = new List<TmForgeElementDto>
            {
                new TmForgeElementDto { Id = prefix + "boundary", Kind = "boundary", Name = "Service", X = 100, Y = 100, Width = 400, Height = 400 },
                new TmForgeElementDto { Id = prefix + "source", Kind = "process", Name = "API", X = 340, Y = 250, Width = 100, Height = 60 },
                new TmForgeElementDto { Id = prefix + "target", Kind = "datastore", Name = "Audit", X = 760, Y = 250, Width = 100, Height = 60 },
            };
            if (overlapping)
            {
                elements.Add(new TmForgeElementDto { Id = prefix + "overlap", Kind = "boundary", Name = "Other claim", X = 300, Y = 100, Width = 400, Height = 400 });
            }

            return new TmForgeModelDto
            {
                Schema = "tmforge-json", Version = "0.1", Elements = elements,
                Flows = new[] { new TmForgeFlowDto { Id = prefix + "flow", Name = "Request", Source = prefix + "source", Target = prefix + "target" } },
                Analysis = new TmForgeAnalysisDto
                {
                    DisabledRuleIds = new[] { "TM1003" },
                    ExpectedPacks = new[] { new ExpectedRulePackDto { Id = "policy", Fingerprint = "sha256:pinned" } },
                },
                Threats = new[] { new ThreatStateDto { Id = "manual:review", Manual = true, Title = "Reviewed", State = "Accepted", Justification = "Tracked decision" } },
            };
        }

        private static TmForgeModelDto MultiPage(bool overlapping)
        {
            TmForgeModelDto first = Model();
            TmForgeModelDto second = Model(overlapping, "second-");
            return new TmForgeModelDto
            {
                Elements = first.Elements, Flows = first.Flows,
                Diagrams = new[]
                {
                    new TmForgeDiagramDto { Id = "page-a", Name = "A", Elements = first.Elements, Flows = first.Flows },
                    new TmForgeDiagramDto { Id = "page-b", Name = "B", Elements = second.Elements, Flows = second.Flows },
                },
            };
        }

        private static TmForgeModelDto ApplyGeometry(TmForgeModelDto model, LayoutResultDto result)
        {
            Dictionary<string, LayoutElementDto> patches = result.Elements.ToDictionary(element => element.Id);
            IReadOnlyList<TmForgeElementDto>? Update(IReadOnlyList<TmForgeElementDto>? elements) => elements?.Select(element => new TmForgeElementDto
            {
                Id = element.Id, Kind = element.Kind, Name = element.Name, Properties = element.Properties,
                X = patches[element.Id].X, Y = patches[element.Id].Y,
                Width = patches[element.Id].Width, Height = patches[element.Id].Height,
            }).ToArray();
            return new TmForgeModelDto
            {
                Schema = model.Schema, Version = model.Version, Analysis = model.Analysis, Threats = model.Threats,
                Elements = Update(model.Elements), Flows = model.Flows,
                Diagrams = model.Diagrams?.Select(page => new TmForgeDiagramDto
                {
                    Id = page.Id, Name = page.Name, Elements = Update(page.Elements), Flows = page.Flows,
                }).ToArray(),
            };
        }

        private static ThreatModel Read(TmForgeModelDto dto)
        {
            using MemoryStream stream = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(dto));
            return new TmForgeJsonFormat().Read(stream);
        }
    }
}
