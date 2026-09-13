namespace ThreatModelForge.Analysis.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for <see cref="Tm7ExportPreparer"/>.
    /// </summary>
    [TestClass]
    public class Tm7ExportPreparerTest
    {
        /// <summary>
        /// Verifies that a null model is rejected.
        /// </summary>
        [TestMethod]
        public void PrepareThrowsForNullModel()
        {
            Assert.Throws<ArgumentNullException>(() => Tm7ExportPreparer.Prepare(null!));
        }

        /// <summary>
        /// Verifies that flow labels with no recorded position are placed apart. Every write path to
        /// the tool's format runs through here, so this is what stops a model that arrived over the
        /// canonical tmforge-json — which carries no connector geometry — from drawing two flows'
        /// names on the same point.
        /// </summary>
        [TestMethod]
        public void PreparePlacesUnpositionedFlowLabels()
        {
            ThreatModel model = ModelWithStackedFlowLabels();
            DrawingSurfaceModel surface = model.DrawingSurfaceList[0];
            Assert.AreEqual(1, LabelCenters(surface).Distinct().Count(), "the defect under test is that both labels start on one point");

            Tm7ExportPreparer.Prepare(model);

            Assert.AreEqual(2, LabelCenters(surface).Distinct().Count(), "each flow label needs its own position");
        }

        /// <summary>
        /// Verifies that a label somebody positioned is carried through untouched. Saving a file is not
        /// permission to re-arrange the diagram inside it.
        /// </summary>
        [TestMethod]
        public void PreparePreservesPositionedFlowLabels()
        {
            ThreatModel model = ModelWithStackedFlowLabels();
            DrawingSurfaceModel surface = model.DrawingSurfaceList[0];
            Connector chosen = surface.Lines.Values.OfType<Connector>().OrderBy(flow => flow.Guid).First();
            chosen.HandleX = 400;
            chosen.HandleY = 260;

            Tm7ExportPreparer.Prepare(model);

            Assert.AreEqual(400, chosen.HandleX);
            Assert.AreEqual(260, chosen.HandleY);
        }

        /// <summary>
        /// Verifies that re-preparing an already-prepared model leaves its label positions alone, so an
        /// iterative authoring loop does not shuffle the diagram on every save.
        /// </summary>
        [TestMethod]
        public void PrepareLeavesAlreadyPlacedLabelsAlone()
        {
            ThreatModel model = ModelWithStackedFlowLabels();
            DrawingSurfaceModel surface = model.DrawingSurfaceList[0];

            Tm7ExportPreparer.Prepare(model);
            List<(int X, int Y)> first = LabelCenters(surface).ToList();
            Tm7ExportPreparer.Prepare(model);

            CollectionAssert.AreEqual(first, LabelCenters(surface).ToList());
        }

        /// <summary>
        /// Verifies that a model without a knowledge base gains the default one and has its
        /// schema-backed properties typed.
        /// </summary>
        [TestMethod]
        public void PrepareEmbedsDefaultKnowledgeBaseAndTypesProperties()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");

            Tm7ExportPreparer.Prepare(model);

            Assert.IsNotNull(model.KnowledgeBase);
            Assert.IsTrue(KnowledgeBaseCatalog.IsDefault(model.KnowledgeBase!));
            Assert.IsTrue(Flow(model).Properties.OfType<ListDisplayAttribute>().Any(p => p.DisplayName == "Protocol"));
        }

        /// <summary>
        /// Verifies that a model carrying a foreign knowledge base is left untouched: the knowledge
        /// base is preserved and its properties are not retyped.
        /// </summary>
        [TestMethod]
        public void PrepareLeavesForeignKnowledgeBaseUntouched()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");
            KnowledgeBaseData foreign = new KnowledgeBaseData
            {
                Manifest = new Manifest { Id = Guid.NewGuid(), Name = "Third Party" },
            };
            model.KnowledgeBase = foreign;

            Tm7ExportPreparer.Prepare(model);

            Assert.AreSame(foreign, model.KnowledgeBase);
            Assert.IsFalse(Flow(model).Properties.OfType<ListDisplayAttribute>().Any());
        }

        /// <summary>A foreign category cannot silently reuse an effective category id with another name.</summary>
        [TestMethod]
        public void PrepareRejectsConflictingForeignThreatCategory()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");
            model.KnowledgeBase = new KnowledgeBaseData
            {
                Manifest = new Manifest { Id = Guid.NewGuid(), Name = "Third Party" },
                ThreatCategories =
                {
                    new ThreatCategory { Id = "S", Name = "Safety" },
                },
            };

            InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
                () => Tm7ExportPreparer.Prepare(model));

            StringAssert.Contains(exception.Message, "category 'S'");
        }

        /// <summary>A foreign threat type cannot silently bind a rule id to different metadata.</summary>
        [TestMethod]
        public void PrepareRejectsConflictingForeignThreatType()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");
            model.KnowledgeBase = new KnowledgeBaseData
            {
                Manifest = new Manifest { Id = Guid.NewGuid(), Name = "Third Party" },
                ThreatTypes =
                {
                    new ThreatType
                    {
                        Id = "TM1023",
                        Category = "T",
                        ShortTitle = "Unrelated foreign threat",
                        Description = "Unrelated foreign threat",
                    },
                },
            };

            InvalidOperationException exception = Assert.Throws<InvalidOperationException>(
                () => Tm7ExportPreparer.Prepare(model));

            StringAssert.Contains(exception.Message, "threat type 'TM1023'");
        }

        /// <summary>
        /// The embedded knowledge base declares the priority vocabulary even when no rule declares a
        /// default priority. Every generated threat carries a priority regardless, and the Microsoft
        /// Threat Modeling Tool drives its priority field from this declaration; without it the tool
        /// can replace a value it was never told about.
        /// </summary>
        [TestMethod]
        public void PrepareDeclaresThePriorityVocabularyWithoutAnyPriorityRule()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");
            using RuleSet rules = new RuleSet();

            Tm7ExportPreparer.Prepare(model, rules);

            ThreatMetaData? metadata = model.KnowledgeBase!.ThreatMetaData;
            Assert.IsNotNull(metadata, "The knowledge base must declare threat metadata.");
            Assert.IsTrue(metadata!.IsPriorityUsed);
            ThreatMetaDatum priority = metadata.PropertiesMetaData.Single(
                datum => datum.Name == "Priority");
            CollectionAssert.AreEqual(ThreatPriorities.All.ToArray(), priority.Values);
        }

        /// <summary>Foreign category spelling is retained and generated priority metadata is merged.</summary>
        [TestMethod]
        public void PrepareCanonicalizesForeignCategoryReferenceAndMergesPriority()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");
            ThreatMetaData metadata = new ThreatMetaData { IsPriorityUsed = true };
            ThreatMetaDatum nativePriority = new ThreatMetaDatum
            {
                Id = "22222222-2222-2222-2222-222222222222",
                Name = "Priority",
                Label = "Severity",
                AttributeType = 1,
            };
            nativePriority.Values.Add("High");
            nativePriority.Values.Add("Medium");
            nativePriority.Values.Add("Low");
            ThreatMetaDatum mitigation = new ThreatMetaDatum
            {
                Id = nativePriority.Id,
                Name = "PossibleMitigations",
                Label = "Possible Mitigation(s)",
                AttributeType = 2,
            };
            mitigation.Values.Add(string.Empty);
            metadata.PropertiesMetaData.Add(mitigation);
            metadata.PropertiesMetaData.Add(nativePriority);
            model.KnowledgeBase = new KnowledgeBaseData
            {
                Manifest = new Manifest { Id = Guid.NewGuid(), Name = "Third Party" },
                ThreatCategories =
                {
                    new ThreatCategory { Id = "MEDICAL/PRIVACY", Name = "Privacy" },
                },
                ThreatMetaData = metadata,
            };
            ThreatType existingType = new ThreatType
            {
                Id = "medical/PRIV-1",
                Category = "MEDICAL/PRIVACY",
                ShortTitle = "Privacy risk",
                Description = "Minimize retained data.",
            };
            ThreatMetaDatum stalePriority = new ThreatMetaDatum
            {
                Id = "tmforge:priority",
                Name = "Priority",
                Label = "Priority",
                AttributeType = 1,
            };
            stalePriority.Values.Add("High");
            existingType.PropertiesMetaData.Add(stalePriority);
            model.KnowledgeBase.ThreatTypes.Add(existingType);
            using RuleSet rules = new RuleSet();
            rules.Rules.Add(new PriorityRule());

            Tm7ExportPreparer.Prepare(model, rules);

            ThreatType injectedType = model.KnowledgeBase.ThreatTypes.Single(
                threat => threat.Id == "medical/PRIV-1");
            Assert.AreEqual("MEDICAL/PRIVACY", injectedType.Category);
            ThreatMetaDatum priority = injectedType.PropertiesMetaData.Single();
            Assert.AreEqual(nativePriority.Id, priority.Id);
            Assert.AreEqual(nativePriority.Name, priority.Name);
            Assert.AreEqual(nativePriority.Label, priority.Label);
            Assert.AreEqual(nativePriority.HideFromUI, priority.HideFromUI);
            Assert.AreEqual(nativePriority.AttributeType, priority.AttributeType);
            Assert.AreEqual("High", priority.Values.Single());
            Assert.IsTrue(model.KnowledgeBase.ThreatCategories.Any(category => category.Id == injectedType.Category));
            Assert.AreSame(nativePriority, model.KnowledgeBase.ThreatMetaData!.PropertiesMetaData.Single(
                datum => datum.Name == "Priority"));

            // Merging must not drop any property the tool resolves by name while loading a model.
            string[] required =
            {
                "Title", "UserThreatCategory", "UserThreatShortDescription",
                "UserThreatDescription", "StateInformation", "InteractionString",
            };
            foreach (string name in required)
            {
                Assert.IsTrue(
                    model.KnowledgeBase.ThreatMetaData.PropertiesMetaData.Any(datum => datum.Name == name),
                    $"The merged metadata must still declare '{name}'.");
            }
        }

        /// <summary>
        /// A foreign knowledge base that declares a different priority vocabulary has its list extended
        /// rather than replaced or rejected. Two vocabularies are not a conflict: taking either side
        /// alone would leave threats carrying a value the tool no longer offers, which is precisely the
        /// silent downgrade the export exists to prevent.
        /// </summary>
        [TestMethod]
        public void PrepareUnionsForeignPriorityVocabulary()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");
            ThreatMetaData metadata = new ThreatMetaData { IsPriorityUsed = true };
            ThreatMetaDatum priority = new ThreatMetaDatum
            {
                Id = "tmforge:priority",
                Name = "Priority",
                Label = "Priority",
                Description = "Different definition.",
                AttributeType = 1,
            };
            priority.Values.Add("Urgent");
            metadata.PropertiesMetaData.Add(priority);
            model.KnowledgeBase = new KnowledgeBaseData
            {
                Manifest = new Manifest { Id = Guid.NewGuid(), Name = "Third Party" },
                ThreatMetaData = metadata,
            };
            using RuleSet rules = new RuleSet();
            rules.Rules.Add(new PriorityRule());

            Tm7ExportPreparer.Prepare(model, rules);

            ThreatMetaDatum merged = model.KnowledgeBase.ThreatMetaData!.PropertiesMetaData.Single(
                datum => datum.Name == "Priority");

            // The foreign template's own value and ordering survive, and every priority Threat Model
            // Forge can express is appended so it stays selectable in the tool.
            Assert.AreEqual("Urgent", merged.Values[0]);
            foreach (string expected in ThreatPriorities.All)
            {
                Assert.Contains(expected, merged.Values, expected + " must remain selectable.");
            }
        }

        /// <summary>
        /// Verifies that preparing an already-prepared model is idempotent: the knowledge base stays
        /// the default and the property is typed exactly once.
        /// </summary>
        [TestMethod]
        public void PrepareIsIdempotent()
        {
            ThreatModel model = ModelWithFlow("Protocol", "HTTPS");

            Tm7ExportPreparer.Prepare(model);
            Tm7ExportPreparer.Prepare(model);

            Assert.IsTrue(KnowledgeBaseCatalog.IsDefault(model.KnowledgeBase!));
            Assert.AreEqual(1, Flow(model).Properties.OfType<ListDisplayAttribute>().Count(p => p.DisplayName == "Protocol"));
        }

        /// <summary>
        /// Verifies that a surface whose elements sit below the tool's minimum drawing coordinate is
        /// translated as a whole: the lowest element lands on the minimum, the relative layout is
        /// preserved, and connectors move with their endpoints so they stay attached.
        /// </summary>
        [TestMethod]
        public void PrepareShiftsSurfaceAboveTheToolMinimum()
        {
            StencilEllipse process = new StencilEllipse { Guid = Guid.NewGuid(), Left = 400, Top = -16, Width = 100, Height = 60 };
            StencilRectangle actor = new StencilRectangle { Guid = Guid.NewGuid(), Left = 80, Top = 0, Width = 120, Height = 60 };
            Connector flow = new Connector
            {
                Guid = Guid.NewGuid(),
                GenericTypeId = "GE.DF",
                SourceGuid = actor.Guid,
                TargetGuid = process.Guid,
                SourceX = 200,
                SourceY = 4,
                TargetX = 400,
                TargetY = -6,
                HandleX = 300,
                HandleY = -1,
            };

            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            surface.Borders[process.Guid] = process;
            surface.Borders[actor.Guid] = actor;
            surface.Lines[flow.Guid] = flow;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);

            Tm7ExportPreparer.Prepare(model);

            // The lowest coordinate was the process top (-16); a whole-surface shift of +26 lands it on
            // the minimum while preserving the 16px gap above the actor.
            Assert.AreEqual(10, process.Top);
            Assert.AreEqual(26, actor.Top);

            // The horizontal minimum (80) was already valid, so x is unchanged.
            Assert.AreEqual(400, process.Left);
            Assert.AreEqual(80, actor.Left);

            // The connector's endpoints and handle move with the surface.
            Assert.AreEqual(30, flow.SourceY);
            Assert.AreEqual(20, flow.TargetY);
            Assert.AreEqual(25, flow.HandleY);
            Assert.AreEqual(200, flow.SourceX);
            Assert.AreEqual(400, flow.TargetX);
        }

        /// <summary>
        /// Verifies that a surface already above the minimum is left in place.
        /// </summary>
        [TestMethod]
        public void PrepareLeavesValidCoordinatesUnchanged()
        {
            StencilEllipse process = new StencilEllipse { Guid = Guid.NewGuid(), Left = 220, Top = 60, Width = 100, Height = 60 };
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            surface.Borders[process.Guid] = process;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);

            Tm7ExportPreparer.Prepare(model);

            Assert.AreEqual(220, process.Left);
            Assert.AreEqual(60, process.Top);
        }

        /// <summary>
        /// Verifies that a surface reaching past the tool's maximum border coordinate is translated back
        /// as a whole, so the furthest element lands on the maximum with the layout intact.
        /// </summary>
        [TestMethod]
        public void PrepareShiftsSurfaceBelowTheToolMaximum()
        {
            StencilEllipse far = new StencilEllipse { Guid = Guid.NewGuid(), Left = 2000, Top = 100, Width = 100, Height = 60 };
            StencilRectangle near = new StencilRectangle { Guid = Guid.NewGuid(), Left = 1800, Top = 100, Width = 120, Height = 60 };
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            surface.Borders[far.Guid] = far;
            surface.Borders[near.Guid] = near;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);

            Tm7ExportPreparer.Prepare(model);

            // A whole-surface shift of -110 lands the furthest border on the maximum and keeps the 200px
            // gap between the two.
            Assert.AreEqual(1890, far.Left);
            Assert.AreEqual(1690, near.Left);

            // The vertical extent was already legal, so y is untouched.
            Assert.AreEqual(100, far.Top);
            Assert.AreEqual(100, near.Top);
        }

        /// <summary>
        /// Verifies that the tool's higher allowance for connector coordinates is respected: a connector
        /// reaching past the border maximum is legal on its own and must not drag the surface backwards.
        /// </summary>
        [TestMethod]
        public void PrepareAllowsConnectorsBeyondTheBorderMaximum()
        {
            StencilEllipse process = new StencilEllipse { Guid = Guid.NewGuid(), Left = 1890, Top = 100, Width = 100, Height = 60 };
            Connector flow = new Connector
            {
                Guid = Guid.NewGuid(),
                GenericTypeId = "GE.DF",
                SourceX = 1900,
                SourceY = 100,
                TargetX = 1950,
                TargetY = 100,
                HandleX = 1925,
                HandleY = 100,
            };

            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            surface.Borders[process.Guid] = process;
            surface.Lines[flow.Guid] = flow;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);

            Tm7ExportPreparer.Prepare(model);

            Assert.AreEqual(1890, process.Left);
            Assert.AreEqual(1950, flow.TargetX);
        }

        /// <summary>
        /// Verifies that a surface drawn wider than the tool's canvas is anchored at the minimum. No
        /// translation satisfies both bounds, and rescaling would move elements relative to the trust
        /// boundaries that contain them, changing the analysis rather than the drawing.
        /// </summary>
        [TestMethod]
        public void PrepareAnchorsASurfaceWiderThanTheToolCanvas()
        {
            StencilRectangle near = new StencilRectangle { Guid = Guid.NewGuid(), Left = 0, Top = 100, Width = 120, Height = 60 };
            StencilEllipse far = new StencilEllipse { Guid = Guid.NewGuid(), Left = 2500, Top = 100, Width = 100, Height = 60 };
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            surface.Borders[near.Guid] = near;
            surface.Borders[far.Guid] = far;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);

            Tm7ExportPreparer.Prepare(model);

            Assert.AreEqual(10, near.Left);
            Assert.AreEqual(2510, far.Left);
        }

        private static ThreatModel ModelWithFlow(string key, string value)
        {
            Connector flow = new Connector { Guid = Guid.NewGuid(), GenericTypeId = "GE.DF" };
            flow.Properties.Add(new CustomStringDisplayAttribute { Value = key + ":" + value });
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            surface.Lines[flow.Guid] = flow;
            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);
            return model;
        }

        /// <summary>
        /// Builds a surface holding two named flows between one pair of elements. The canonical
        /// tmforge-json the API and Studio exchange carries no connector geometry, so a model arriving
        /// from it looks exactly like this: endpoints derived from the shapes and no label position,
        /// which draws both names on the same point.
        /// </summary>
        /// <returns>The model.</returns>
        private static ThreatModel ModelWithStackedFlowLabels()
        {
            DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = Guid.NewGuid() };
            Guid left = Guid.NewGuid();
            Guid right = Guid.NewGuid();
            surface.Borders[left] = new StencilEllipse { Guid = left, GenericTypeId = "GE.P", Left = 100, Top = 100, Width = 100, Height = 60 };
            surface.Borders[right] = new StencilEllipse { Guid = right, GenericTypeId = "GE.P", Left = 600, Top = 100, Width = 100, Height = 60 };

            foreach ((string Name, Guid Source, Guid Target) flow in new[]
            {
                ("Credential material handed to the signer", left, right),
                ("Signed material returned to the caller", right, left),
            })
            {
                Connector connector = new Connector
                {
                    Guid = Guid.NewGuid(),
                    GenericTypeId = "GE.DF",
                    SourceGuid = flow.Source,
                    TargetGuid = flow.Target,
                    SourceX = 200,
                    SourceY = 130,
                    TargetX = 600,
                    TargetY = 130,
                };
                connector.Properties.Add(new StringDisplayAttribute { DisplayName = "Name", Name = "Name", Value = flow.Name });
                surface.Lines[connector.Guid] = connector;
            }

            ThreatModel model = new ThreatModel();
            model.DrawingSurfaceList.Add(surface);
            return model;
        }

        private static Connector Flow(ThreatModel model)
        {
            return model.DrawingSurfaceList[0].Lines.Values.OfType<Connector>().Single();
        }

        /// <summary>Gets the point each flow's label is drawn on, in a stable order.</summary>
        /// <param name="surface">The surface to read.</param>
        /// <returns>The label centers.</returns>
        private static IEnumerable<(int X, int Y)> LabelCenters(DrawingSurfaceModel surface)
        {
            return surface.Lines.Values
                .OfType<Connector>()
                .OrderBy(flow => flow.Guid)
                .Select(flow => (
                    (flow.SourceX + (2 * flow.HandleX) + flow.TargetX) / 4,
                    (flow.SourceY + (2 * flow.HandleY) + flow.TargetY) / 4))
                .ToList();
        }

        private sealed class PriorityRule : Rule
        {
            /// <summary>Initializes a new instance of the <see cref="PriorityRule"/> class.</summary>
            public PriorityRule()
                : base("medical/PRIV-1", MessageSeverity.Info, "medical")
            {
                this.FullDescription = "Privacy risk";
                this.HelpText = "Minimize retained data.";
            }

            /// <inheritdoc/>
            public override RuleThreatCategory ThreatCategory { get; } = new RuleThreatCategory(
                "medical/privacy",
                "privacy",
                "Privacy",
                null,
                null);

            /// <inheritdoc/>
            public override ThreatPriority? DefaultThreatPriority => ThreatPriority.High;

            /// <inheritdoc/>
            public override void Evaluate(RuleEvaluationContext context)
            {
            }
        }
    }
}
