namespace ThreatModelForge.Analysis.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using System.Text.RegularExpressions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Unit tests for the <see cref="DeclarativeRuleProvider"/> class.
    /// </summary>
    [TestClass]
    public class DeclarativeRuleProviderTests
    {
        private const string V2Rule =
            "{\"id\":\"TH112\",\"severity\":\"error\",\"appliesTo\":\"process\"," +
            "\"message\":\"{name} uses an unsafe cache\",\"assert\":{\"property\":\"Cache Type\",\"equals\":\"Distributed\"}," +
            "\"provenance\":{\"sourceId\":\"TH112\",\"categoryId\":\"D\",\"expressions\":[" +
            "{\"role\":\"include\",\"language\":\"urn:tmforge:source:mtmt-generation-filter\",\"text\":\"target is 'GE.P'\"}," +
            "{\"role\":\"exclude\",\"language\":\"urn:tmforge:source:mtmt-generation-filter\",\"text\":\"\"}]}}";

        /// <summary>
        /// Gets or sets the working directory created for each test.
        /// </summary>
        private string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>
        /// Creates an isolated working directory for the test.
        /// </summary>
        [TestInitialize]
        public void Initialize()
        {
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-rules-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(this.WorkingDirectory);
        }

        /// <summary>
        /// Removes the working directory after the test.
        /// </summary>
        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(this.WorkingDirectory))
            {
                Directory.Delete(this.WorkingDirectory, recursive: true);
            }
        }

        /// <summary>
        /// A valid spec loads a single rule whose id is surfaced verbatim (the string-id constructor)
        /// and whose severity, pack, STRIDE category, and external references are parsed.
        /// </summary>
        [TestMethod]
        public void LoadsValidRuleWithMetadata()
        {
            string spec =
                "{\"rules\":[{" +
                "\"id\":\"ACME001\",\"pack\":\"acme\",\"severity\":\"error\"," +
                "\"appliesTo\":\"datastore\",\"message\":\"{name} is not encrypted\"," +
                "\"stride\":\"InformationDisclosure\",\"threatReferences\":[\"CWE:311\"]," +
                "\"assert\":{\"property\":\"Encrypted\",\"notAnyOf\":[\"No\"]}}]}";
            string path = this.WriteSpec(spec);

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { path });

            Assert.AreEqual(1, rules.Count);
            Rule rule = rules[0];
            Assert.AreEqual("ACME001", rule.ID);
            Assert.AreEqual("acme", rule.Pack);
            Assert.AreEqual(MessageSeverity.Error, rule.Severity);
            Assert.AreEqual(StrideCategory.InformationDisclosure, rule.Stride);
            Assert.AreEqual(1, rule.ThreatReferences.Count);
            Assert.AreEqual("CWE-311", rule.ThreatReferences[0].Id);
        }

        /// <summary>Flat guards and requirements are lowered into the shared immutable AST.</summary>
        [TestMethod]
        public void FlatRulesCompileToInteractionExpressionTree()
        {
            string spec =
                "{\"rules\":[{\"id\":\"LOWERED\",\"appliesTo\":\"process\"," +
                "\"message\":\"x\",\"when\":{\"property\":\"Marker\"}," +
                "\"assert\":{\"property\":\"Mode\",\"equals\":\"Safe\"}}]}";

            DeclarativeRule rule = (DeclarativeRule)DeclarativeRuleProvider.Load(
                new[] { this.WriteSpec(spec) }).Single();

            Assert.AreEqual(InteractionExpression.OperationKind.All, rule.CompiledExpression.Operation);
            Assert.AreEqual(2, rule.CompiledExpression.Children.Count);
            Assert.AreEqual(InteractionExpression.OperationKind.FlatProperty, rule.CompiledExpression.Children[0].Operation);
            Assert.AreEqual(InteractionExpression.OperationKind.Not, rule.CompiledExpression.Children[1].Operation);
            Assert.AreEqual(
                InteractionExpression.OperationKind.FlatProperty,
                rule.CompiledExpression.Children[1].Child!.Operation);
            Assert.IsTrue(rule.CompiledExpression.Children[1].Child!.FirstValueOnly);
        }

        /// <summary>Compound flat predicates retain the legacy one-scan operation accounting.</summary>
        [TestMethod]
        public void FlatCompoundPropertyPreservesOperationCount()
        {
            string spec =
                "{\"rules\":[{\"id\":\"ACCOUNTING\",\"appliesTo\":\"process\",\"message\":\"x\"," +
                "\"when\":{\"property\":\"Marker\",\"present\":true,\"equals\":\"set\"," +
                "\"anyOf\":[\"other\",\"set\"],\"notAnyOf\":[\"blocked\",\"also-blocked\"]}}]}";
            Rule rule = DeclarativeRuleProvider.Load(new[] { this.WriteSpec(spec) }).Single();
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            StencilEllipse process = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Worker");
            process.Properties.Add(new CustomStringDisplayAttribute { Value = "Marker:set" });
            process.Properties.Add(new CustomStringDisplayAttribute { Value = "Noise:value" });
            diagram.Borders.Add(process.Guid, process);
            MockMessageWriter writer = new MockMessageWriter();
            RuleEvaluationContext context = new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { diagram } },
                writer);

            rule.Evaluate(context);

            Assert.AreEqual(1, writer.Messages.Count);
            Assert.AreEqual(19, context.GetDeclarativeOperationCount());
        }

        /// <summary>Declarative evaluation work is bounded across every rule sharing one context.</summary>
        [TestMethod]
        public void SharesEvaluationBudgetAcrossRules()
        {
            string spec =
                "{\"rules\":[" +
                "{\"id\":\"FIRST\",\"appliesTo\":\"process\",\"message\":\"first\",\"when\":{\"property\":\"Marker\"}}," +
                "{\"id\":\"SECOND\",\"appliesTo\":\"process\",\"message\":\"second\",\"when\":{\"property\":\"Marker\"}}]}";
            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { this.WriteSpec(spec) });
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            StencilEllipse process = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Worker");
            process.Properties.Add(new CustomStringDisplayAttribute { Value = "Marker:set" });
            diagram.Borders.Add(process.Guid, process);
            RuleEvaluationContext context = new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { diagram } },
                new MockMessageWriter());

            rules[0].Evaluate(context);
            context.SetDeclarativeOperationLimit(context.GetDeclarativeOperationCount());

            Assert.Throws<InvalidDataException>(() => rules[1].Evaluate(context));
        }

        /// <summary>Numeric guards use invariant decimals and never match missing or invalid values.</summary>
        /// <param name="value">The stored property value, or null for an absent property.</param>
        /// <param name="expected">Whether the numeric guard should match.</param>
        [TestMethod]
        [DataRow(null, false)]
        [DataRow("", false)]
        [DataRow("Unknown", false)]
        [DataRow("NaN", false)]
        [DataRow("Infinity", false)]
        [DataRow("10,5", false)]
        [DataRow("10", false)]
        [DataRow("9", false)]
        [DataRow("10.5", true)]
        [DataRow("  +11  ", true)]
        [DataRow("1e2", true)]
        public void NumericGuardsUseInvariantValues(string? value, bool expected)
        {
            string rule =
                "{\"id\":\"LIMIT\",\"appliesTo\":\"process\",\"message\":\"limit exceeded\"," +
                "\"when\":{\"property\":\"Cache Type\",\"greaterThan\":10}}";
            string spec = VersionTwoSpec("numeric", rule);
            List<string> diagnostics = new List<string>();
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) }, diagnostics.Add);
            Assert.AreEqual(1, bundle.Rules.Count, string.Join("; ", diagnostics));
            StencilEllipse process = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Worker");
            if (value != null)
            {
                process.Properties.Add(new CustomStringDisplayAttribute { Value = "Cache Type:" + value });
            }

            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Header = "Numeric" };
            diagram.Borders.Add(process.Guid, process);
            MockMessageWriter writer = new MockMessageWriter();
            RuleEvaluationContext context = new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { diagram } },
                writer);
            CultureInfo originalCulture = CultureInfo.CurrentCulture;
            try
            {
                CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
                bundle.Rules[0].Evaluate(context);
            }
            finally
            {
                CultureInfo.CurrentCulture = originalCulture;
            }

            Assert.AreEqual(expected ? 1 : 0, writer.Messages.Count);
        }

        /// <summary>Numeric comparisons agree on each subject in both rule dialects.</summary>
        /// <param name="matcher">The numeric comparison.</param>
        /// <param name="value">The property value.</param>
        /// <param name="expected">Whether the comparison matches.</param>
        [TestMethod]
        [DataRow("\"greaterThan\":10", "9", false)]
        [DataRow("\"greaterThan\":10", "10", false)]
        [DataRow("\"greaterThan\":10", "11", true)]
        [DataRow("\"greaterThanOrEqual\":10", "9", false)]
        [DataRow("\"greaterThanOrEqual\":10", "10", true)]
        [DataRow("\"greaterThanOrEqual\":10", "11", true)]
        [DataRow("\"lessThan\":10", "9", true)]
        [DataRow("\"lessThan\":10", "10", false)]
        [DataRow("\"lessThan\":10", "11", false)]
        [DataRow("\"lessThanOrEqual\":10", "9", true)]
        [DataRow("\"lessThanOrEqual\":10", "10", true)]
        [DataRow("\"lessThanOrEqual\":10", "11", false)]
        [DataRow("\"greaterThanOrEqual\":10,\"lessThan\":20", "15", true)]
        [DataRow("\"greaterThanOrEqual\":10,\"lessThan\":20", "20", false)]
        [DataRow("\"greaterThan\":9,\"greaterThanOrEqual\":10,\"lessThan\":11,\"lessThanOrEqual\":10", "10", true)]
        [DataRow("\"greaterThanOrEqual\":0", "1e99", false)]
        [DataRow("\"greaterThanOrEqual\":0", "1,000", false)]
        public void NumericPredicatesApplyAcrossSubjects(string matcher, string value, bool expected)
        {
            foreach (string form in new[] { "element", "flow", "source", "target", "interaction-source", "interaction-target", "interaction-flow" })
            {
                MockMessageWriter writer = this.RunPropertyRule(matcher, value, form);
                Assert.AreEqual(expected ? 1 : 0, writer.Messages.Count, form);
            }
        }

        /// <summary>Missing or invalid numeric evidence fails a requirement instead of proving it.</summary>
        /// <param name="value">The absent or invalid evidence.</param>
        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("Unknown")]
        [DataRow("not a number")]
        public void NumericRequirementsFailWithoutEvidence(string? value)
        {
            MockMessageWriter writer = this.RunPropertyRule("\"lessThanOrEqual\":30", value, "element", requirement: true);
            Assert.AreEqual(1, writer.Messages.Count);
        }

        /// <summary>Numeric parsing and comparison consume the invocation budget.</summary>
        [TestMethod]
        public void NumericEvaluationIsBounded()
        {
            Assert.Throws<InvalidDataException>(() => this.RunPropertyRule("\"greaterThan\":0", "1", "element", operationLimit: 1));
            Assert.AreEqual(0, this.RunPropertyRule("\"greaterThanOrEqual\":0", new string('0', 257), "element").Messages.Count);
        }

        /// <summary>Invalid numeric constraints are diagnosed before a pack can be evaluated.</summary>
        /// <param name="condition">The invalid condition.</param>
        [TestMethod]
        [DataRow("{\"greaterThan\":10}")]
        [DataRow("{\"property\":\"Cache Type\",\"greaterThan\":\"10\"}")]
        [DataRow("{\"property\":\"Cache Type\",\"greaterThan\":1e99}")]
        [DataRow("{\"property\":\"Cache Type\",\"greaterThan\":null}")]
        [DataRow("{\"property\":\"Cache Type\",\"greaterThan\":10,\"lessThanOrEqual\":10}")]
        [DataRow("{\"property\":\"Cache Type\",\"greaterThanOrEqual\":11,\"lessThan\":10}")]
        public void RejectsInvalidNumericConstraints(string condition)
        {
            string rule = "{\"id\":\"BAD\",\"appliesTo\":\"process\",\"message\":\"bad\",\"when\":" + condition + "}";
            List<string> diagnostics = new List<string>();
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(VersionTwoSpec("numeric-invalid", rule)) }, diagnostics.Add);
            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.AreEqual(0, bundle.Packs.Count);
            Assert.IsTrue(diagnostics.Count > 0);
        }

        /// <summary>Regex predicates have identical subject and missing-value semantics in both dialects.</summary>
        /// <param name="pattern">The regular expression.</param>
        /// <param name="value">The property value.</param>
        /// <param name="expected">Whether it should match.</param>
        [TestMethod]
        [DataRow("^svc-[0-9]+$", "svc-42", true)]
        [DataRow("^svc-[0-9]+$", "SVC-42", false)]
        [DataRow("(?i)^svc-[0-9]+$", "SVC-42", true)]
        [DataRow("svc", "prefix-svc-suffix", true)]
        [DataRow("^svc$", "prefix-svc-suffix", false)]
        [DataRow("^svc$", null, false)]
        [DataRow(".*", "", false)]
        [DataRow(".*", "   ", false)]
        [DataRow("^svc$", "Unknown", false)]
        [DataRow("^Unknown$", "Unknown", true)]
        public void RegexPredicatesApplyAcrossSubjects(string pattern, string? value, bool expected)
        {
            string matcher = "\"matches\":" + JsonSerializer.Serialize(pattern);
            foreach (string form in new[] { "element", "flow", "source", "target", "interaction-source", "interaction-target", "interaction-flow" })
            {
                Assert.AreEqual(expected ? 1 : 0, this.RunPropertyRule(matcher, value, form).Messages.Count, form);
            }
        }

        /// <summary>Missing evidence fails a regex requirement, and excessive input aborts analysis.</summary>
        [TestMethod]
        public void RegexRequirementsAndInputLimitsAreExplicit()
        {
            Assert.AreEqual(1, this.RunPropertyRule("\"matches\":\"^svc-\"", null, "element", requirement: true).Messages.Count);
            Assert.AreEqual(1, this.RunPropertyRule("\"matches\":\"^a+$\"", new string('a', 4096), "element").Messages.Count);
            InvalidDataException error = Assert.Throws<InvalidDataException>(
                () => this.RunPropertyRule("\"matches\":\".*\"", new string('a', 4097), "element"));
            StringAssert.Contains(error.Message, "regex input");
            StringAssert.Contains(error.Message, "4096");
        }

        /// <summary>A timeout aborts analysis even when the failed predicate is under negation.</summary>
        [TestMethod]
        public void RegexTimeoutIsNeverAFalsePredicate()
        {
            string matcher = "\"matches\":\"^(a+)+$\"";
            foreach (string form in new[] { "element", "interaction-source" })
            {
                InvalidDataException error = Assert.Throws<InvalidDataException>(
                    () => this.RunPropertyRule(matcher, new string('a', 4095) + "!", form, requirement: true));
                StringAssert.Contains(error.Message, "property-matchers/VALUE");
                StringAssert.Contains(error.Message, "timeout");
                Assert.IsInstanceOfType<RegexMatchTimeoutException>(error.InnerException);
            }
        }

        /// <summary>The shared regex budget is cumulative and remains exhausted for subsequent rules.</summary>
        [TestMethod]
        public void RegexTimeBudgetIsShared()
        {
            RuleEvaluationContext context = new RuleEvaluationContext(new ThreatModel(), new MockMessageWriter());
            context.AccountRegexTime(TimeSpan.FromMilliseconds(600));
            Assert.Throws<InvalidDataException>(() => context.AccountRegexTime(TimeSpan.FromMilliseconds(401)));
            Assert.Throws<InvalidDataException>(() => context.AccountRegexTime(TimeSpan.Zero));
        }

        /// <summary>Invalid patterns reject their whole pack with rule-local diagnostics.</summary>
        /// <param name="pattern">An invalid or empty pattern.</param>
        [TestMethod]
        [DataRow("[")]
        [DataRow("")]
        [DataRow("(?invalid)")]
        public void RejectsInvalidRegexPatterns(string pattern)
        {
            string predicate = "{\"property\":\"Cache Type\",\"matches\":" + JsonSerializer.Serialize(pattern) + "}";
            string rule = "{\"id\":\"REGEX\",\"appliesTo\":\"process\",\"message\":\"regex\",\"when\":" + predicate + "}";
            List<string> diagnostics = new List<string>();
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(VersionTwoSpec("regex-invalid", V2Rule + "," + rule)) }, diagnostics.Add);
            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.AreEqual(0, bundle.Packs.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("REGEX")));
        }

        /// <summary>Regex text and distinct-pattern counts are bounded across all loaded sources.</summary>
        [TestMethod]
        public void RegexPatternLimitsAndReuse()
        {
            string RuleText(string id, string pattern) =>
                "{\"id\":\"" + id + "\",\"appliesTo\":\"process\",\"message\":\"regex\",\"when\":{\"property\":\"Cache Type\",\"matches\":" + JsonSerializer.Serialize(pattern) + "}}";
            List<string> diagnostics = new List<string>();
            string overlong = RuleText("LONG", new string('a', 1025));
            RuleBundle rejected = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(VersionTwoSpec("regex-long", overlong)) }, diagnostics.Add);
            Assert.AreEqual(0, rejected.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("1024")));

            string repeated = string.Join(",", Enumerable.Range(0, 130).Select(index => RuleText("R" + index, "^svc$")));
            RuleBundle reused = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(VersionTwoSpec("regex-reuse", repeated)) });
            Assert.AreEqual(130, reused.Rules.Count);
            DeclarativeRule first = (DeclarativeRule)reused.Rules[0];
            DeclarativeRule second = (DeclarativeRule)reused.Rules[1];
            Assert.AreSame(first.CompiledExpression.Pattern, second.CompiledExpression.Pattern);

            string distinct = string.Join(",", Enumerable.Range(0, 128).Select(index => RuleText("D" + index, "^svc" + index + "$")));
            string extra = RuleText("EXTRA", "^other$");
            RuleBundle limited = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(VersionTwoSpec("regex-first", distinct)), this.WriteSpec(VersionTwoSpec("regex-extra", extra)) }, diagnostics.Add);
            Assert.AreEqual(128, limited.Rules.Count);
            Assert.AreEqual(1, limited.Packs.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("128 distinct regex")));
        }

        /// <summary>Connectivity follows directed edges and never invents a zero-hop path.</summary>
        /// <param name="predicate">The connectivity condition.</param>
        /// <param name="appliesTo">The kind of component being checked.</param>
        /// <param name="names">The expected finding targets.</param>
        [TestMethod]
        [DataRow("\"reachableFrom\":{\"kind\":\"external\"}", "process", "Gateway,Worker")]
        [DataRow("\"reachableFrom\":{\"kind\":\"process\"}", "process", "Worker")]
        [DataRow("\"reachableFrom\":{\"kind\":\"external\"}", "external", "")]
        [DataRow("\"reachableFrom\":{\"kind\":\"datastore\"}", "process", "")]
        [DataRow("\"connectsTo\":{\"kind\":\"datastore\"}", "process", "Worker")]
        [DataRow("\"connectsTo\":{\"kind\":\"process\"}", "process", "Gateway")]
        [DataRow("\"connectsTo\":{\"kind\":\"external\"}", "process", "")]
        [DataRow("\"reachableFrom\":{\"kind\":\"external\"},\"connectsTo\":{\"kind\":\"datastore\"}", "process", "Worker")]
        public void ConnectivityIsDirectedAndNonReflexive(string predicate, string appliesTo, string names)
        {
            ThreatModel model = CreateConnectivityModel();
            Rule rule = this.LoadGraphRule(predicate, appliesTo: appliesTo);
            MockMessageWriter writer = new MockMessageWriter();

            rule.Evaluate(new RuleEvaluationContext(model, writer));

            string actual = string.Join(",", writer.Messages.Select(message => message.Target!.Name()).OrderBy(name => name, StringComparer.Ordinal));
            Assert.AreEqual(names, actual);
        }

        /// <summary>Interaction expressions can inspect connectivity and primitive kinds at either endpoint.</summary>
        /// <param name="predicate">The endpoint predicate.</param>
        /// <param name="subject">The endpoint being inspected.</param>
        /// <param name="count">The expected matching flows.</param>
        [TestMethod]
        [DataRow("\"reachableFrom\":{\"kind\":\"external\"}", "target", 3)]
        [DataRow("\"reachableFrom\":{\"kind\":\"external\"}", "source", 2)]
        [DataRow("\"connectsTo\":{\"kind\":\"datastore\"}", "source", 1)]
        [DataRow("\"connectsTo\":{\"kind\":\"datastore\"}", "target", 1)]
        [DataRow("\"kind\":\"external\"", "source", 1)]
        [DataRow("\"kind\":\"external\"", "target", 0)]
        [DataRow("\"kind\":\"datastore\"", "target", 1)]
        public void InteractionConnectivityUsesTheChosenEndpoint(string predicate, string subject, int count)
        {
            Rule rule = this.LoadGraphRule(predicate, interaction: true, subject: subject);
            MockMessageWriter writer = new MockMessageWriter();
            rule.Evaluate(new RuleEvaluationContext(CreateConnectivityModel(), writer));
            Assert.AreEqual(count, writer.Messages.Count);
        }

        /// <summary>Explicit cycles and self-loops supply positive-length paths without infinite traversal.</summary>
        [TestMethod]
        public void ConnectivityHandlesCyclesSelfLoopsAndParallelEdges()
        {
            ThreatModel model = CreateConnectivityModel();
            DrawingSurfaceModel page = model.DrawingSurfaceList[0];
            Entity gateway = page.Components().Single(element => element.Name() == "Gateway");
            Entity worker = page.Components().Single(element => element.Name() == "Worker");
            Entity isolated = page.Components().Single(element => element.Name() == "Isolated");
            AddGraphFlow(page, worker, gateway);
            AddGraphFlow(page, worker, gateway);
            AddGraphFlow(page, isolated, isolated);
            Rule rule = this.LoadGraphRule("\"reachableFrom\":{\"kind\":\"process\"}");
            MockMessageWriter writer = new MockMessageWriter();
            rule.Evaluate(new RuleEvaluationContext(model, writer));
            Assert.AreEqual(3, writer.Messages.Count);
            Assert.AreEqual(3, writer.Messages.Select(message => message.Target!.Guid).Distinct().Count());
        }

        /// <summary>Connectivity is page-local and does not infer access control from boundary geometry.</summary>
        [TestMethod]
        public void ConnectivityIgnoresBoundaryGeometryButNeverCrossesPages()
        {
            ThreatModel model = CreateConnectivityModel();
            DrawingSurfaceModel first = model.DrawingSurfaceList[0];
            DrawingSurfaceModel second = new DrawingSurfaceModel { Header = "Other page" };
            foreach (KeyValuePair<Guid, object> component in first.Borders)
            {
                second.Borders.Add(component.Key, component.Value);
            }

            model.DrawingSurfaceList.Add(second);
            BorderBoundary boundary = new BorderBoundary { Guid = Guid.NewGuid(), Left = -1000, Top = -1000, Width = 2000, Height = 2000 };
            first.Borders.Add(boundary.Guid, boundary);
            Rule rule = this.LoadGraphRule("\"reachableFrom\":{\"kind\":\"external\"}");
            MockMessageWriter before = new MockMessageWriter();
            rule.Evaluate(new RuleEvaluationContext(model, before));
            boundary.Left = 5000;
            MockMessageWriter after = new MockMessageWriter();
            rule.Evaluate(new RuleEvaluationContext(model, after));
            Assert.AreEqual(2, after.Messages.Count);
            Assert.IsTrue(after.Messages.All(message => ReferenceEquals(first, message.Model)));
            CollectionAssert.AreEquivalent(before.Messages.Select(message => message.Target!.Guid).ToArray(), after.Messages.Select(message => message.Target!.Guid).ToArray());
        }

        /// <summary>Connectivity filters reuse property aliases, numeric/regex matching, and policy bindings.</summary>
        /// <param name="interaction">Whether the rule uses the interaction dialect.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void ConnectivityFiltersReusePropertyMatchers(bool interaction)
        {
            ThreatModel model = CreateConnectivityModel();
            Entity entry = model.DrawingSurfaceList[0].Components().Single(element => element.Name() == "Entry");
            entry.Properties.Add(new CustomStringDisplayAttribute { Value = "Cache Type:42" });
            string predicate = "\"reachableFrom\":{\"kind\":\"external\",\"property\":\"cacheType\",\"greaterThan\":40,\"matches\":\"^[0-9]+$\"}";
            Rule rule = this.LoadGraphRule(predicate, interaction: interaction);
            MockMessageWriter writer = new MockMessageWriter();
            rule.Evaluate(new RuleEvaluationContext(model, writer));
            Assert.AreEqual(interaction ? 3 : 2, writer.Messages.Count);
            Assert.IsTrue(rule.PropertyBindings.Any(binding => binding.AppliesTo == "external" && binding.PropertyName == "Cache Type"));
            entry.Properties.RemoveAt(entry.Properties.Count - 1);
            MockMessageWriter absent = new MockMessageWriter();
            rule.Evaluate(new RuleEvaluationContext(model, absent));
            Assert.AreEqual(0, absent.Messages.Count);
        }

        /// <summary>Long cyclic paths are iterative and consume work proportional to vertices and edges.</summary>
        /// <param name="count">The number of intermediate components.</param>
        [TestMethod]
        [DataRow(256)]
        [DataRow(4096)]
        public void ConnectivityWorkIsLinearForLargeCycles(int count)
        {
            DrawingSurfaceModel page = new DrawingSurfaceModel();
            List<StencilEllipse> nodes = Enumerable.Range(0, count)
                .Select(index => CreateEntity<StencilEllipse>("GE.P", "GE.P", "Node " + index)).ToList();
            StencilParallelLines store = CreateEntity<StencilParallelLines>("GE.DS", "GE.DS", "Store");
            foreach (StencilEllipse node in nodes)
            {
                page.Borders.Add(node.Guid, node);
            }

            page.Borders.Add(store.Guid, store);
            for (int index = 0; index < count - 1; index++)
            {
                AddGraphFlow(page, nodes[index], nodes[index + 1]);
            }

            AddGraphFlow(page, nodes[count - 1], nodes[0]);
            AddGraphFlow(page, nodes[count - 1], store);
            ThreatModel model = new ThreatModel { DrawingSurfaceList = { page } };
            Rule rule = this.LoadGraphRule("\"reachableFrom\":{\"kind\":\"external\"}", appliesTo: "datastore");
            MockMessageWriter writer = new MockMessageWriter();
            RuleEvaluationContext context = new RuleEvaluationContext(model, writer);
            context.SetDeclarativeOperationLimit((10 * count) + 100);
            rule.Evaluate(context);
            Assert.AreEqual(0, writer.Messages.Count);
            Assert.IsTrue(context.GetDeclarativeOperationCount() < (10 * count) + 100);
            context.SetDeclarativeOperationLimit(context.GetDeclarativeOperationCount() + count + 10);
            Assert.Throws<InvalidDataException>(() => rule.Evaluate(context));
        }

        /// <summary>Connectivity rejects ambiguous filters and invalid subjects before evaluation.</summary>
        /// <param name="predicate">The invalid predicate.</param>
        /// <param name="interaction">Whether to use the interaction dialect.</param>
        /// <param name="subject">The flat appliesTo or interaction subject.</param>
        [TestMethod]
        [DataRow("\"reachableFrom\":{}", false, "process")]
        [DataRow("\"reachableFrom\":{\"kind\":\"flow\"}", false, "process")]
        [DataRow("\"connectsTo\":{\"kind\":\"process\"}", false, "flow")]
        [DataRow("\"connectsTo\":{\"kind\":\"process\"}", true, "flow")]
        [DataRow("\"connectsTo\":{},\"reachableFrom\":{}", true, "source")]
        [DataRow("\"connectsTo\":{\"greaterThan\":10}", true, "source")]
        [DataRow("\"connectsTo\":{\"kind\":\"unknown\"}", true, "source")]
        [DataRow("\"connectsTo\":{\"property\":\"Missing\"}", true, "source")]
        [DataRow("\"connectsTo\":{\"property\":\"cacheType\",\"equals\":\"INVALID\"}", true, "source")]
        [DataRow("\"kind\":\"process\",\"type\":\"GE.P\"", true, "source")]
        [DataRow("\"kind\":\"process\"", true, "flow")]
        public void RejectsInvalidConnectivityPredicates(string predicate, bool interaction, string subject)
        {
            string rule = GraphRuleText(predicate, interaction, subject, subject);
            string spec = VersionTwoSpec("invalid-connectivity", rule);
            if (interaction)
            {
                spec = spec.Replace(RulePackDialects.FlatV1, RulePackDialects.InteractionV1);
            }

            List<string> diagnostics = new List<string>();
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) }, diagnostics.Add);
            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.AreEqual(0, bundle.Packs.Count);
            Assert.IsTrue(diagnostics.Count > 0);
        }

        /// <summary>
        /// A version 2 envelope owns the pack identity and namespaces each source rule id with it.
        /// </summary>
        [TestMethod]
        public void LoadsVersionTwoEnvelopeWithEffectiveIdentity()
        {
            string spec = VersionTwoSpec("azure-template-a1b2c3d4", V2Rule);
            string path = this.WriteSpec(spec);

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path });

            Assert.AreEqual(1, bundle.Rules.Count);
            Rule rule = bundle.Rules[0];
            Assert.AreEqual("azure-template-a1b2c3d4/TH112", rule.ID);
            Assert.AreEqual("azure-template-a1b2c3d4", rule.Pack);
            Assert.AreEqual("TH112", rule.Provenance!.SourceId);
            Assert.IsNull(rule.ThreatCategory);
            Assert.AreEqual("target is 'GE.P'", rule.Provenance.Expressions.Single(expression => expression.Role == "include").Text);

            Assert.AreEqual(1, bundle.Packs.Count);
            RulePackDefinition pack = bundle.Packs[0];
            Assert.AreEqual("Azure Template", pack.Name);
            Assert.IsTrue(pack.Fingerprint!.StartsWith("sha256:", StringComparison.Ordinal));
            Assert.AreEqual("D", pack.Categories.Single().Id);
            Assert.AreEqual("GE.P", pack.ElementTypes.Single().Id);
            Assert.AreEqual("Cache Type", pack.Properties.Single().Name);
            Assert.AreSame(pack, rule.PackDefinition);
        }

        /// <summary>
        /// Version 2 metadata is importer-neutral: a non-MTMT source uses generic source and
        /// provenance fields without manifests or GenerationFilters terminology.
        /// </summary>
        [TestMethod]
        public void LoadsImporterNeutralEnvelopeMetadata()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
                "\"pack\":{\"id\":\"otm-pack\",\"name\":\"OTM pack\",\"source\":{" +
                "\"type\":\"urn:tmforge:source:otm\",\"name\":\"model.otm\",\"id\":\"catalog-42\"," +
                "\"version\":\"1.0\",\"uri\":\"https://example.test/model.otm\",\"fingerprint\":\"sha256:source\"}}," +
                "\"categories\":[{\"id\":\"security\",\"name\":\"Security\"}],\"elementTypes\":[]," +
                "\"properties\":[{\"name\":\"security/encrypted\",\"aliases\":[\"encryption-state\"]," +
                "\"allowedValues\":[\"Yes\",\"No\"]}]," +
                "\"rules\":[{\"id\":\"OTM-1\",\"appliesTo\":\"datastore\",\"message\":\"x\"," +
                "\"assert\":{\"property\":\"encryption-state\",\"equals\":\"Yes\"}," +
                "\"provenance\":{\"sourceId\":\"rule-1\",\"categoryId\":\"security\",\"location\":\"/threats/0\"," +
                "\"expressions\":[{\"role\":\"condition\",\"language\":\"urn:example:otm-expression\",\"text\":\"encrypted = true\"}]}}]}";
            string path = this.WriteSpec(spec);

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path });

            Assert.AreEqual(1, bundle.Rules.Count);
            Rule rule = bundle.Rules.Single();
            Assert.AreEqual("otm-pack/OTM-1", rule.ID);
            Assert.AreEqual("urn:tmforge:rules:flat-v1", rule.PackDefinition!.Dialect);
            Assert.AreEqual("urn:tmforge:source:otm", rule.PackDefinition.Source!.Type);
            Assert.AreEqual("catalog-42", rule.PackDefinition.Source.Id);
            Assert.AreEqual("rule-1", rule.Provenance!.SourceId);
            Assert.AreEqual("urn:example:otm-expression", rule.Provenance.Expressions.Single().Language);
            Assert.AreEqual("security/encrypted", rule.PropertyBindings.Single().PropertyName);
        }

        /// <summary>Unversioned rule documents ignore metadata introduced by the versioned envelope.</summary>
        [TestMethod]
        public void LegacyDocumentIgnoresVersionTwoThreatPriority()
        {
            string spec =
                "{\"rules\":[{\"id\":\"LEGACY\",\"severity\":\"info\",\"stride\":\"Spoofing\"," +
                "\"defaultPriority\":\"High\",\"appliesTo\":\"process\",\"message\":\"x\"," +
                "\"when\":{\"property\":\"Marker\"}}]}";

            Rule rule = DeclarativeRuleProvider.Load(new[] { this.WriteSpec(spec) }).Single();

            Assert.AreEqual(StrideCategory.Spoofing, rule.Stride);
            Assert.IsNull(rule.DefaultThreatPriority);
        }

        /// <summary>Legacy extension fields that collide with new v2 names remain ignored regardless of value type.</summary>
        [TestMethod]
        public void LegacyDocumentIgnoresCollidingVersionTwoExtensionFields()
        {
            string spec =
                "{\"rules\":[{\"id\":\"LEGACY\",\"appliesTo\":\"process\",\"message\":\"x\"," +
                "\"categoryId\":{\"future\":true},\"defaultPriority\":42," +
                "\"when\":{\"property\":\"Marker\"}}]}";

            Rule rule = DeclarativeRuleProvider.Load(new[] { this.WriteSpec(spec) }).Single();

            Assert.AreEqual("LEGACY", rule.ID);
            Assert.IsNull(rule.ThreatCategory);
            Assert.IsNull(rule.DefaultThreatPriority);
        }

        /// <summary>
        /// A versioned non-STRIDE category makes a rule threat-bearing, keeps priority independent
        /// from severity, and survives projection, persistence, reporting, and MTMT export.
        /// </summary>
        [TestMethod]
        public void GeneralizedThreatMetadataFlowsThroughEveryAnalysisSurface()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
                "\"pack\":{\"id\":\"medical-device\",\"name\":\"Medical device\"}," +
                "\"categories\":[{\"id\":\"privacy\",\"name\":\"Privacy\"," +
                "\"shortDescription\":\"Patient privacy\",\"longDescription\":\"Privacy harm.\"}," +
                "{\"id\":\"safety\",\"name\":\"Patient Safety\"}]," +
                "\"elementTypes\":[{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}]," +
                "\"properties\":[{\"name\":\"Marker\",\"elementTypeIds\":[\"GE.P\"]}]," +
                "\"rules\":[{\"id\":\"PRIV-1\",\"severity\":\"info\",\"categoryId\":\"privacy\"," +
                "\"defaultPriority\":\"High\"," +
                "\"appliesTo\":\"process\",\"message\":\"Privacy exposure at {name}\"," +
                "\"helpText\":\"Minimize retained patient data.\",\"when\":{\"property\":\"Marker\"}," +
                "\"provenance\":{\"sourceId\":\"PRIV-1\",\"categoryId\":\"source-privacy\"}}]}";
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) });
            Rule rule = bundle.Rules.Single();
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            StencilEllipse process = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Records service");
            process.Properties.Add(new CustomStringDisplayAttribute { Value = "Marker:set" });
            diagram.Borders.Add(process.Guid, process);
            ThreatModel model = new ThreatModel { DrawingSurfaceList = { diagram } };

            Assert.IsFalse(rule.Stride.HasValue);
            Assert.AreEqual("medical-device/privacy", rule.ThreatCategory!.Id);
            Assert.AreEqual("privacy", rule.ThreatCategory.SourceId);
            Assert.AreEqual("Privacy", rule.ThreatCategory.Name);
            Assert.AreEqual("source-privacy", rule.Provenance!.CategoryId);
            Assert.AreEqual(ThreatPriority.High, rule.DefaultThreatPriority);

            using RuleSet ruleSet = new RuleSet();
            ruleSet.Rules.Add(rule);
            GenerationResult generated = ThreatGenerator.Generate(model, ruleSet);
            GeneratedThreat threat = generated.Threats.Single();
            Assert.AreEqual(StrideCategory.Unknown, threat.Category);
            Assert.AreEqual("medical-device/privacy", threat.ThreatCategory.Id);
            Assert.AreEqual("Privacy", threat.ThreatCategory.Name);
            Assert.IsFalse(threat.Stride.HasValue);
            Assert.AreEqual("info", threat.Severity);
            Assert.AreEqual("High", threat.Priority);

            ThreatGenerator.Apply(model, generated);
            Threat persisted = model.AllThreatsDictionary.Values.Single();
            Assert.AreEqual("Privacy", persisted.UserThreatCategory);
            Assert.AreEqual("High", persisted.Priority);
            Assert.AreEqual("medical-device/privacy", persisted.Properties!["CategoryId"]);

            RuleEvaluationContext context = new RuleEvaluationContext(model, new MockMessageWriter());
            ruleSet.Evaluate(context);
            ModelReport report = context.GenerateReport(ruleSet);
            Assert.HasCount(2, report.ThreatCategories);
            Assert.IsTrue(report.ThreatCategories.Any(category => category.Id == "medical-device/privacy"));
            Assert.IsTrue(report.ThreatCategories.Any(category => category.Id == "medical-device/safety"));
            Assert.AreEqual("Privacy", report.RuleReports.Single().ThreatCategoryName);
            Assert.AreEqual(ThreatPriority.High, report.RuleReports.Single().DefaultThreatPriority);

            KnowledgeBaseData knowledgeBase = KnowledgeBaseCatalog.CreateDefault(ruleSet);
            ThreatCategory exportedCategory = knowledgeBase.ThreatCategories.Single(
                category => category.Id == "medical-device/privacy");
            Assert.AreEqual("Privacy", exportedCategory.Name);
            Assert.IsTrue(knowledgeBase.ThreatCategories.Any(category => category.Id == "medical-device/safety"));
            ThreatType exportedType = knowledgeBase.ThreatTypes.Single(type => type.Id == "medical-device/PRIV-1");
            Assert.AreEqual("medical-device/privacy", exportedType.Category);
            Assert.AreEqual("High", exportedType.PropertiesMetaData.Single().Values.Single());
            Assert.IsTrue(knowledgeBase.ThreatMetaData!.IsPriorityUsed);
            ThreatMetaDatum exportedPriority = knowledgeBase.ThreatMetaData.PropertiesMetaData
                .Single(datum => datum.Name == "Priority");
            CollectionAssert.AreEqual(new[] { "Critical", "High", "Medium", "Low" }, exportedPriority.Values);
        }

        /// <summary>Default threat priority must be valid and attached to a threat-bearing rule.</summary>
        [TestMethod]
        public void RejectsInvalidOrCategoryLessDefaultPriority()
        {
            string categoryLess =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
                "\"pack\":{\"id\":\"priority-pack\",\"name\":\"Priority pack\"}," +
                "\"categories\":[],\"elementTypes\":[],\"properties\":[]," +
                "\"rules\":[{\"id\":\"P1\",\"defaultPriority\":\"High\"," +
                "\"appliesTo\":\"process\",\"message\":\"x\",\"when\":{\"property\":\"Marker\"}}]}";
            List<string> categoryDiagnostics = new List<string>();

            RuleBundle categoryBundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(categoryLess, "category-less.tmrules.json") },
                categoryDiagnostics.Add);

            Assert.AreEqual(0, categoryBundle.Rules.Count);
            Assert.IsTrue(categoryDiagnostics.Any(message => message.Contains("defaultPriority")));

            string invalid = categoryLess
                .Replace("\"defaultPriority\":\"High\",", "\"defaultPriority\":\"Urgent\",")
                .Replace("priority-pack", "invalid-priority");
            List<string> invalidDiagnostics = new List<string>();
            RuleBundle invalidBundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(invalid, "invalid-priority.tmrules.json") },
                invalidDiagnostics.Add);

            Assert.AreEqual(0, invalidBundle.Rules.Count);
            Assert.IsTrue(invalidDiagnostics.Any(message => message.Contains("defaultPriority")));
        }

        /// <summary>
        /// The first new dialect accepts the recursive interaction AST independently of source type.
        /// </summary>
        [TestMethod]
        public void LoadsInteractionVersionOneDialect()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"interaction-pack\",\"name\":\"Interaction pack\"}," +
                "\"categories\":[],\"elementTypes\":[{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}]," +
                "\"properties\":[{\"name\":\"Protocol\"}],\"rules\":[{\"id\":\"I1\",\"message\":\"{source.Name} to {target.Name} via {flow.Name}\"," +
                "\"expression\":{\"allOf\":[{\"subject\":\"source\",\"type\":\"GE.P\"},{\"not\":{" +
                "\"subject\":\"flow\",\"property\":\"Protocol\",\"valueIn\":[\"TLS\"]}}]}}]}";
            string path = this.WriteSpec(spec);

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path });

            Assert.AreEqual(1, bundle.Rules.Count);
            Assert.AreEqual("interaction-pack/I1", bundle.Rules.Single().ID);
            Assert.AreEqual("urn:tmforge:rules:interaction-v1", bundle.Rules.Single().PackDefinition!.Dialect);
        }

        /// <summary>
        /// Interaction rules evaluate hierarchy-aware type, property, and boundary predicates over flows,
        /// expand message tokens case-insensitively, and evaluate ROOT once per diagram.
        /// </summary>
        [TestMethod]
        public void EvaluatesInteractionVersionOneDialect()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"interaction-pack\",\"name\":\"Interaction pack\"}," +
                "\"elementTypes\":[" +
                "{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}," +
                "{\"id\":\"SE.P.Web\",\"name\":\"Web process\",\"parentId\":\"GE.P\"}," +
                "{\"id\":\"GE.TB.B\",\"name\":\"Boundary\",\"parentId\":\"ROOT\"}," +
                "{\"id\":\"SE.TB.Azure\",\"name\":\"Azure boundary\",\"parentId\":\"GE.TB.B\"}]," +
                "\"properties\":[{\"name\":\"Protocol\",\"aliases\":[\"wireProtocol\"],\"allowedValues\":[\"HTTP\",\"TLS\"]}]," +
                "\"rules\":[" +
                "{\"id\":\"FLOW\",\"message\":\"{SOURCE.name} to {target.Name} via {Flow.Name}; {unknown}\"," +
                "\"expression\":{\"allOf\":[" +
                "{\"subject\":\"source\",\"type\":\"GE.P\"}," +
                "{\"subject\":\"flow\",\"property\":\"wireProtocol\",\"valueIn\":[\"HTTP\"]}," +
                "{\"crosses\":\"GE.TB.B\"}]}} ," +
                "{\"id\":\"ROOT\",\"message\":\"Diagram root\"," +
                "\"expression\":{\"subject\":\"source\",\"type\":\"ROOT\"}}]}";
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) });

            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            StencilEllipse source = CreateEntity<StencilEllipse>("SE.P.Web", "GE.P", "{target.Name}");
            StencilRectangle target = CreateEntity<StencilRectangle>("GE.EI", "GE.EI", "Browser");
            BorderBoundary boundary = CreateEntity<BorderBoundary>("SE.TB.Azure", "GE.TB.B", "Azure");
            boundary.Left = 5;
            boundary.Top = 5;
            boundary.Width = 20;
            boundary.Height = 20;
            diagram.Borders.Add(source.Guid, source);
            diagram.Borders.Add(target.Guid, target);
            diagram.Borders.Add(boundary.Guid, boundary);

            Connector flow = CreateEntity<Connector>("GE.DF", "GE.DF", "Request");
            flow.SourceGuid = source.Guid;
            flow.TargetGuid = target.Guid;
            flow.SourceX = 0;
            flow.SourceY = 0;
            flow.TargetX = 10;
            flow.TargetY = 10;
            flow.Properties.Add(new CustomStringDisplayAttribute { Value = "Protocol:HTTP" });
            diagram.Lines.Add(flow.Guid, flow);

            ThreatModel model = new ThreatModel { DrawingSurfaceList = { diagram } };
            MockMessageWriter writer = new MockMessageWriter();
            RuleEvaluationContext context = new RuleEvaluationContext(model, writer);
            foreach (Rule rule in bundle.Rules)
            {
                rule.Evaluate(context);
            }

            Assert.AreEqual(2, writer.Messages.Count);
            Message flowMessage = writer.Messages.Single(message => message.Source!.ID.EndsWith("/FLOW", StringComparison.Ordinal));
            Assert.AreEqual("{target.Name} to Browser via Request; {unknown}", flowMessage.Text);
            Assert.AreSame(flow, flowMessage.Target);
            Rule flowRule = bundle.Rules.Single(rule => rule.ID.EndsWith("/FLOW", StringComparison.Ordinal));
            Assert.AreEqual("Protocol", flowRule.PropertyBindings.Single().PropertyName);
            Message rootMessage = writer.Messages.Single(message => message.Source!.ID.EndsWith("/ROOT", StringComparison.Ordinal));
            Assert.AreEqual("Diagram root", rootMessage.Text);
            Assert.AreSame(diagram, rootMessage.Target);
        }

        /// <summary>ROOT creates exactly one synthetic finding for each diagram containing an interaction.</summary>
        [TestMethod]
        public void RootEvaluatesOncePerDiagram()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"root-scope\",\"name\":\"ROOT scope\"}," +
                "\"rules\":[{\"id\":\"ROOT\",\"message\":\"root\"," +
                "\"expression\":{\"subject\":\"source\",\"type\":\"ROOT\"}}]}";
            Rule rule = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) }).Rules.Single();
            DrawingSurfaceModel first = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "First" };
            DrawingSurfaceModel second = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Second" };
            foreach (DrawingSurfaceModel diagram in new[] { first, second })
            {
                StencilRectangle source = CreateEntity<StencilRectangle>("GE.EI", "GE.EI", "Client");
                StencilEllipse target = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Service");
                Connector flow = CreateEntity<Connector>("GE.DF", "GE.DF", "Request");
                flow.SourceGuid = source.Guid;
                flow.TargetGuid = target.Guid;
                diagram.Borders.Add(source.Guid, source);
                diagram.Borders.Add(target.Guid, target);
                diagram.Lines.Add(flow.Guid, flow);
            }

            Connector secondFlow = CreateEntity<Connector>("GE.DF", "GE.DF", "Response");
            Connector existingFlow = (Connector)second.Lines.Values.Single();
            secondFlow.SourceGuid = existingFlow.SourceGuid;
            secondFlow.TargetGuid = existingFlow.TargetGuid;
            second.Lines.Add(secondFlow.Guid, secondFlow);

            MockMessageWriter writer = new MockMessageWriter();

            rule.Evaluate(new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { first, second } },
                writer));

            Assert.AreEqual(2, writer.Messages.Count);
            CollectionAssert.AreEquivalent(
                new object[] { first, second },
                writer.Messages.Select(message => message.Target).ToArray());
        }

        /// <summary>
        /// A target-only MTMT filter evaluates once per matching interaction. Microsoft's public
        /// <c>sample1.tm7</c> persists TH53 on both parallel flows between the same endpoints.
        /// </summary>
        [TestMethod]
        public void EndpointOnlyMtmtFilterEvaluatesOncePerMatchingFlow()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"mtmt-sample1\",\"name\":\"MTMT sample 1\"}," +
                "\"elementTypes\":[" +
                "{\"id\":\"GE.DS\",\"name\":\"Data store\",\"parentId\":\"ROOT\"}," +
                "{\"id\":\"SE.P.TMCore.AzureDocumentDB\",\"name\":\"Azure Cosmos DB\"," +
                "\"parentId\":\"GE.DS\"}]," +
                "\"rules\":[{\"id\":\"TH53\",\"message\":\"Clear-text data in {target.Name}\"," +
                "\"expression\":{\"subject\":\"target\",\"type\":\"SE.P.TMCore.AzureDocumentDB\"}}]}";
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) });

            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Diagram 1" };
            StencilParallelLines source = CreateEntity<StencilParallelLines>("GE.DS", "GE.DS", "Azure Key Vault");
            StencilParallelLines target = CreateEntity<StencilParallelLines>(
                "SE.P.TMCore.AzureDocumentDB",
                "GE.DS",
                "Azure Cosmos DB");
            Connector request = CreateEntity<Connector>("GE.DF", "GE.DF", "Request");
            request.SourceGuid = source.Guid;
            request.TargetGuid = target.Guid;
            Connector response = CreateEntity<Connector>("GE.DF", "GE.DF", "Response");
            response.SourceGuid = source.Guid;
            response.TargetGuid = target.Guid;
            diagram.Borders.Add(source.Guid, source);
            diagram.Borders.Add(target.Guid, target);
            diagram.Lines.Add(request.Guid, request);
            diagram.Lines.Add(response.Guid, response);

            MockMessageWriter writer = new MockMessageWriter();
            bundle.Rules.Single().Evaluate(new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { diagram } },
                writer));

            Assert.AreEqual(2, writer.Messages.Count);
            Assert.IsTrue(writer.Messages.Any(message => ReferenceEquals(message.Target, request)));
            Assert.IsTrue(writer.Messages.Any(message => ReferenceEquals(message.Target, response)));
        }

        /// <summary>
        /// Crosses evaluates false on synthetic ROOT contexts without dereferencing a missing flow.
        /// </summary>
        [TestMethod]
        public void RootCompositeCrossesExpressionsDoNotCrash()
        {
            string root = "{\"subject\":\"source\",\"type\":\"ROOT\"}";
            string crosses = "{\"crosses\":\"GE.TB.B\"}";
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"root-composites\",\"name\":\"ROOT composites\"}," +
                "\"elementTypes\":[{\"id\":\"GE.TB.B\",\"name\":\"Boundary\",\"parentId\":\"ROOT\"}]," +
                "\"rules\":[" +
                $"{{\"id\":\"ALL\",\"message\":\"all\",\"expression\":{{\"allOf\":[{root},{crosses}]}}}}," +
                $"{{\"id\":\"ANY-CROSS-FIRST\",\"message\":\"any1\",\"expression\":{{\"anyOf\":[{crosses},{root}]}}}}," +
                $"{{\"id\":\"ANY-ROOT-FIRST\",\"message\":\"any2\",\"expression\":{{\"anyOf\":[{root},{crosses}]}}}}," +
                "{\"id\":\"NOT-CROSSES\",\"message\":\"not\",\"expression\":{\"allOf\":[" +
                root + ",{\"not\":" + crosses + "}]}}]}";
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) });
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            ThreatModel model = new ThreatModel { DrawingSurfaceList = { diagram } };
            MockMessageWriter writer = new MockMessageWriter();
            RuleEvaluationContext context = new RuleEvaluationContext(model, writer);

            foreach (Rule rule in bundle.Rules)
            {
                rule.Evaluate(context);
            }

            CollectionAssert.AreEquivalent(
                new[] { "any1", "any2", "not" },
                writer.Messages.Select(message => message.Text).ToArray());
        }

        /// <summary>Logical nodes do not spend operation budget on siblings after the result is known.</summary>
        [TestMethod]
        public void InteractionExpressionsShortCircuitWithinOperationLimit()
        {
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            RuleEvaluationContext context = new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { diagram } },
                new MockMessageWriter());
            InteractionExpression.Evaluator evaluator = new InteractionExpression.Evaluator(
                "SHORT-CIRCUIT",
                new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase),
                operationLimit: 2,
                accountExpressionNodes: true);
            InteractionExpression skipped = InteractionExpression.CrossesAnyBoundary();

            int allOperations = 0;
            bool allResult = evaluator.Evaluate(
                InteractionExpression.All(new[]
                {
                    InteractionExpression.SubjectExists("source"),
                    skipped,
                }),
                InteractionExpression.EvaluationContext.Root(diagram),
                context,
                ref allOperations);

            int anyOperations = 0;
            bool anyResult = evaluator.Evaluate(
                InteractionExpression.Any(new[]
                {
                    InteractionExpression.TypeIs("source", "ROOT"),
                    skipped,
                }),
                InteractionExpression.EvaluationContext.Root(diagram),
                context,
                ref anyOperations);

            Assert.IsFalse(allResult);
            Assert.IsTrue(anyResult);
            Assert.AreEqual(2, allOperations);
            Assert.AreEqual(2, anyOperations);
        }

        /// <summary>Interaction token expansion is bounded before constructing the result.</summary>
        [TestMethod]
        public void RejectsOversizedInteractionMessage()
        {
            string spec =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"message-limit\",\"name\":\"Message limit\"}," +
                "\"elementTypes\":[{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}]," +
                "\"rules\":[{\"id\":\"LIMIT\",\"message\":\"{source.Name}\"," +
                "\"expression\":{\"subject\":\"source\",\"type\":\"GE.P\"}}]}";
            Rule rule = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) }).Rules.Single();
            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "DFD-0" };
            StencilEllipse source = CreateEntity<StencilEllipse>("GE.P", "GE.P", new string('x', 65537));
            StencilRectangle target = CreateEntity<StencilRectangle>("GE.EI", "GE.EI", "Target");
            diagram.Borders.Add(source.Guid, source);
            diagram.Borders.Add(target.Guid, target);
            Connector flow = CreateEntity<Connector>("GE.DF", "GE.DF", "Flow");
            flow.SourceGuid = source.Guid;
            flow.TargetGuid = target.Guid;
            diagram.Lines.Add(flow.Guid, flow);
            RuleEvaluationContext context = new RuleEvaluationContext(
                new ThreatModel { DrawingSurfaceList = { diagram } },
                new MockMessageWriter());

            Assert.Throws<InvalidDataException>(() => rule.Evaluate(context));
        }

        /// <summary>
        /// Unknown dialects and unresolved interaction catalog references are rejected even when a
        /// document has no rules or otherwise has a valid recursive expression shape.
        /// </summary>
        [TestMethod]
        public void RejectsUnknownDialectAndInteractionReferences()
        {
            string unknownDialect =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:example:unknown\"," +
                "\"pack\":{\"id\":\"unknown\",\"name\":\"Unknown\"},\"rules\":[]}";
            string unknownPath = this.WriteSpec(unknownDialect, "unknown-dialect.tmrules.json");
            List<string> unknownDiagnostics = new List<string>();

            RuleBundle unknown = DeclarativeRuleProvider.LoadBundle(new[] { unknownPath }, unknownDiagnostics.Add);

            Assert.AreEqual(0, unknown.Rules.Count);
            Assert.AreEqual(0, unknown.Packs.Count);
            Assert.IsTrue(unknownDiagnostics.Any(message => message.Contains("unknown rule dialect")));

            string interaction =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"bad-reference\",\"name\":\"Bad reference\"}," +
                "\"elementTypes\":[{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}]," +
                "\"properties\":[{\"name\":\"Protocol\"}]," +
                "\"rules\":[{\"id\":\"BAD\",\"message\":\"x\"," +
                "\"expression\":{\"allOf\":[" +
                "{\"subject\":\"source\",\"type\":\"GE.UNKNOWN\"}," +
                "{\"subject\":\"flow\",\"property\":\"Missing\",\"valueIn\":[\"x\"]}]}}]}";
            string interactionPath = this.WriteSpec(interaction, "bad-reference.tmrules.json");
            List<string> interactionDiagnostics = new List<string>();

            RuleBundle invalid = DeclarativeRuleProvider.LoadBundle(new[] { interactionPath }, interactionDiagnostics.Add);

            Assert.AreEqual(0, invalid.Rules.Count);
            Assert.AreEqual(0, invalid.Packs.Count);
            Assert.IsTrue(interactionDiagnostics.Any(message => message.Contains("unknown element type 'GE.UNKNOWN'")));
        }

        /// <summary>Catalog-backed rule categories and interaction values must resolve exactly.</summary>
        [TestMethod]
        public void RejectsUnknownCategoryAndPropertyValueReferences()
        {
            string unknownCategoryRule = V2Rule.Replace(
                "\"severity\":\"error\",",
                "\"severity\":\"error\",\"categoryId\":\"missing\",");
            string unknownCategory = VersionTwoSpec("bad-category", unknownCategoryRule);
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(unknownCategory, "bad-category.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("unknown category 'missing'")));

            string flatUnknownValue = VersionTwoSpec("bad-flat-value", V2Rule)
                .Replace("\"equals\":\"Distributed\"", "\"equals\":\"Distibuted\"");
            diagnostics.Clear();

            bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(flatUnknownValue, "bad-flat-value.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("unknown value 'Distibuted'")));

            string unknownValue =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"bad-value\",\"name\":\"Bad value\"}," +
                "\"properties\":[{\"name\":\"Protocol\",\"allowedValues\":[\"HTTP\",\"TLS\"]}]," +
                "\"rules\":[{\"id\":\"BAD-VALUE\",\"message\":\"x\"," +
                "\"expression\":{\"subject\":\"flow\",\"property\":\"Protocol\",\"valueIn\":[\"TLX\"]}}]}";
            diagnostics.Clear();

            bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(unknownValue, "bad-value.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("unknown value 'TLX'")));
        }

        /// <summary>ROOT is reserved for the synthetic source predicate and cannot be declared.</summary>
        [TestMethod]
        public void RejectsInvalidRootUsage()
        {
            string targetRoot =
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"target-root\",\"name\":\"Target ROOT\"}," +
                "\"rules\":[{\"id\":\"BAD-ROOT\",\"message\":\"x\"," +
                "\"expression\":{\"subject\":\"target\",\"type\":\"ROOT\"}}]}";
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(targetRoot, "target-root.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("only valid for source")));

            string declaredRoot = targetRoot
                .Replace("target-root", "declared-root")
                .Replace("Target ROOT", "Declared ROOT")
                .Replace(
                    "\"rules\":[",
                    "\"elementTypes\":[{\"id\":\"ROOT\",\"name\":\"Root\"}],\"rules\":[")
                .Replace("\"subject\":\"target\"", "\"subject\":\"source\"");
            diagnostics.Clear();

            bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(declaredRoot, "declared-root.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("reserved")));
        }

        /// <summary>
        /// Source ids that collide across different packs remain distinct after namespacing.
        /// </summary>
        [TestMethod]
        public void SameSourceRuleIdInDifferentPacksLoadsDistinctRules()
        {
            string first = this.WriteSpec(VersionTwoSpec("pack-a", V2Rule));
            string second = this.WriteSpec(VersionTwoSpec("pack-b", V2Rule));

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { first, second });

            CollectionAssert.AreEquivalent(
                new[] { "pack-a/TH112", "pack-b/TH112" },
                bundle.Rules.Select(rule => rule.ID).ToArray());
        }

        /// <summary>Repeated and overlapping source paths load each physical file once.</summary>
        [TestMethod]
        public void RepeatedInputPathsLoadOnce()
        {
            string path = this.WriteSpec(VersionTwoSpec("once-pack", V2Rule), "once.tmrules.json");

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path, this.WorkingDirectory, path });

            Assert.AreEqual(1, bundle.Packs.Count);
            Assert.AreEqual(1, bundle.Rules.Count);
            Assert.AreEqual("once-pack/TH112", bundle.Rules.Single().ID);
        }

        /// <summary>
        /// Duplicate effective ids reject every declaration, independent of declaration order.
        /// </summary>
        [TestMethod]
        public void DuplicateEffectiveRuleIdsAreOrderIndependentErrors()
        {
            string duplicate = V2Rule.Replace("\"TH112\"", "\"th112\"");
            List<string> firstDiagnostics = new List<string>();
            string firstPath = this.WriteSpec(
                VersionTwoSpec("duplicate-pack", V2Rule + "," + duplicate),
                "duplicate.tmrules.json");
            RuleBundle first = DeclarativeRuleProvider.LoadBundle(new[] { firstPath }, firstDiagnostics.Add);

            List<string> secondDiagnostics = new List<string>();
            string secondPath = this.WriteSpec(
                VersionTwoSpec("duplicate-pack", duplicate + "," + V2Rule),
                "duplicate.tmrules.json");
            RuleBundle second = DeclarativeRuleProvider.LoadBundle(new[] { secondPath }, secondDiagnostics.Add);

            Assert.AreEqual(0, first.Rules.Count);
            Assert.AreEqual(0, second.Rules.Count);
            Assert.AreEqual(1, firstDiagnostics.Count);
            Assert.AreEqual(1, secondDiagnostics.Count);
            Assert.AreEqual(firstDiagnostics[0], secondDiagnostics[0]);
            StringAssert.Contains(firstDiagnostics[0], "duplicate effective rule id 'duplicate-pack/TH112'");
        }

        /// <summary>
        /// Unsupported version markers are rejected rather than being interpreted as legacy files.
        /// </summary>
        [TestMethod]
        public void RejectsUnsupportedVersion()
        {
            string path = this.WriteSpec(VersionTwoSpec("versioned-pack", V2Rule).Replace("\"version\":2", "\"version\":4"));
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("version 2")));
        }

        /// <summary>
        /// Version 2 rejects unknown members so a misspelled catalog or rule field cannot be ignored.
        /// </summary>
        [TestMethod]
        public void RejectsUnknownVersionTwoMembers()
        {
            string path = this.WriteSpec(VersionTwoSpec("strict-pack", V2Rule).Replace("\"allowedValues\"", "\"allowedValuse\""));
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("allowedValuse")));
        }

        /// <summary>
        /// Numeric enum text is not a valid severity or STRIDE name even when it maps to an enum value.
        /// </summary>
        [TestMethod]
        public void RejectsNumericEnumText()
        {
            string numericSeverity = V2Rule.Replace("\"severity\":\"error\"", "\"severity\":\"3\"");
            string severityPath = this.WriteSpec(VersionTwoSpec("numeric-severity", numericSeverity));
            List<string> severityDiagnostics = new List<string>();

            RuleBundle severityBundle = DeclarativeRuleProvider.LoadBundle(new[] { severityPath }, severityDiagnostics.Add);

            Assert.AreEqual(0, severityBundle.Rules.Count);
            Assert.IsTrue(severityDiagnostics.Any(message => message.Contains("unknown severity '3'")));

            string numericStride = V2Rule.Replace("\"severity\":\"error\"", "\"severity\":\"error\",\"stride\":\"6\"");
            string stridePath = this.WriteSpec(VersionTwoSpec("numeric-stride", numericStride));
            List<string> strideDiagnostics = new List<string>();

            RuleBundle strideBundle = DeclarativeRuleProvider.LoadBundle(new[] { stridePath }, strideDiagnostics.Add);

            Assert.AreEqual(0, strideBundle.Rules.Count);
            Assert.IsTrue(strideDiagnostics.Any(message => message.Contains("unknown stride '6'")));
        }

        /// <summary>
        /// Legacy files keep case-insensitive enum names but reject numeric enum syntax.
        /// </summary>
        [TestMethod]
        public void LegacyRulesRejectNumericEnumText()
        {
            string severityPath = this.WriteSpec(
                "{\"rules\":[{\"id\":\"LEGACY-SEV\",\"severity\":\"3\",\"appliesTo\":\"process\"," +
                "\"message\":\"x\",\"when\":{\"property\":\"P\"}}]}");
            List<string> severityDiagnostics = new List<string>();

            IReadOnlyList<Rule> severityRules = DeclarativeRuleProvider.Load(new[] { severityPath }, severityDiagnostics.Add);

            Assert.AreEqual(0, severityRules.Count);
            Assert.IsTrue(severityDiagnostics.Any(message => message.Contains("unknown severity '3'")));

            string stridePath = this.WriteSpec(
                "{\"rules\":[{\"id\":\"LEGACY-STRIDE\",\"stride\":\"6\",\"appliesTo\":\"process\"," +
                "\"message\":\"x\",\"when\":{\"property\":\"P\"}}]}");
            List<string> strideDiagnostics = new List<string>();

            IReadOnlyList<Rule> strideRules = DeclarativeRuleProvider.Load(new[] { stridePath }, strideDiagnostics.Add);

            Assert.AreEqual(0, strideRules.Count);
            Assert.IsTrue(strideDiagnostics.Any(message => message.Contains("unknown stride '6'")));
        }

        /// <summary>
        /// Runtime validation enforces the strict rule shape published by the v2 JSON Schema.
        /// </summary>
        [TestMethod]
        public void RejectsSchemaInvalidVersionTwoRuleShapes()
        {
            string[] invalidRules =
            {
                V2Rule.Replace("\"severity\":\"error\"", "\"severity\":\"ERROR\""),
                V2Rule.Replace("\"appliesTo\":\"process\"", "\"appliesTo\":\"Process\""),
                V2Rule.Replace("\"severity\":\"error\"", "\"severity\":\"error\",\"stride\":\"informationdisclosure\""),
                V2Rule.Replace("\"id\":\"TH112\"", "\"id\":\"bad/id\""),
                V2Rule.Replace("\"severity\":\"error\"", "\"pack\":\"override\",\"severity\":\"error\""),
                V2Rule.Replace("\"assert\":{\"property\":\"Cache Type\",\"equals\":\"Distributed\"},", string.Empty),
                V2Rule.Replace(
                    "\"assert\":{\"property\":\"Cache Type\",\"equals\":\"Distributed\"}",
                    "\"when\":{\"source\":{\"kind\":\"Widget\"}}"),
                V2Rule.Replace(
                    "\"assert\":{\"property\":\"Cache Type\",\"equals\":\"Distributed\"}",
                    "\"assert\":{\"equals\":\"Distributed\"}"),
                V2Rule.Replace(
                    "\"assert\":{\"property\":\"Cache Type\",\"equals\":\"Distributed\"}",
                    "\"assert\":{\"property\":\"Cache Type\",\"anyOf\":[]}"),
            };

            for (int index = 0; index < invalidRules.Length; index++)
            {
                string path = this.WriteSpec(
                    VersionTwoSpec($"invalid-{index}", invalidRules[index]),
                    $"invalid-{index}.tmrules.json");
                List<string> diagnostics = new List<string>();

                RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path }, diagnostics.Add);

                Assert.AreEqual(0, bundle.Rules.Count, $"Invalid case {index} unexpectedly loaded.");
                Assert.IsTrue(diagnostics.Count > 0, $"Invalid case {index} produced no diagnostic.");
            }
        }

        /// <summary>
        /// Generic source metadata requires a namespaced type and an absolute URI when present.
        /// </summary>
        [TestMethod]
        public void RejectsInvalidSourceMetadata()
        {
            string invalidType = VersionTwoSpec("bad-source", V2Rule, sourceType: "custom")
                .Replace("urn:tmforge:source:custom", "plugin");
            string typePath = this.WriteSpec(invalidType);
            List<string> typeDiagnostics = new List<string>();

            RuleBundle typeBundle = DeclarativeRuleProvider.LoadBundle(new[] { typePath }, typeDiagnostics.Add);

            Assert.AreEqual(0, typeBundle.Rules.Count);
            Assert.IsTrue(typeDiagnostics.Any(message => message.Contains("namespaced identifier")));

            string invalidUri = VersionTwoSpec("bad-uri", V2Rule, sourceType: "custom")
                .Replace("\"type\":\"urn:tmforge:source:custom\"", "\"type\":\"urn:tmforge:source:custom\",\"uri\":\"relative/path\"");
            string uriPath = this.WriteSpec(invalidUri);
            List<string> uriDiagnostics = new List<string>();

            RuleBundle uriBundle = DeclarativeRuleProvider.LoadBundle(new[] { uriPath }, uriDiagnostics.Add);

            Assert.AreEqual(0, uriBundle.Rules.Count);
            Assert.IsTrue(uriDiagnostics.Any(message => message.Contains("uri must be absolute")));
        }

        /// <summary>
        /// Explicit version/catalog markers cannot be null to downgrade a document into legacy mode.
        /// </summary>
        [TestMethod]
        public void RejectsNullVersionMarkersAndCatalogs()
        {
            string markers = this.WriteSpec(
                "{\"schema\":null,\"version\":null,\"pack\":null,\"rules\":[]}",
                "null-markers.tmrules.json");
            List<string> markerDiagnostics = new List<string>();

            RuleBundle markerBundle = DeclarativeRuleProvider.LoadBundle(new[] { markers }, markerDiagnostics.Add);

            Assert.AreEqual(0, markerBundle.Rules.Count);
            Assert.IsTrue(markerDiagnostics.Any(message => message.Contains("schema 'tmforge-rules' version 2")));

            string nullCatalog = VersionTwoSpec("null-catalog", V2Rule).Replace(
                "\"categories\":[{\"id\":\"D\",\"name\":\"Denial of Service\"}]",
                "\"categories\":null");
            string catalogPath = this.WriteSpec(nullCatalog, "null-catalog.tmrules.json");
            List<string> catalogDiagnostics = new List<string>();

            RuleBundle catalogBundle = DeclarativeRuleProvider.LoadBundle(new[] { catalogPath }, catalogDiagnostics.Add);

            Assert.AreEqual(0, catalogBundle.Rules.Count);
            Assert.IsTrue(catalogDiagnostics.Count > 0);
        }

        /// <summary>Version 2 rejects explicit nulls for optional nested members just as its schema does.</summary>
        [TestMethod]
        public void RejectsExplicitNullVersionTwoMembers()
        {
            string spec = VersionTwoSpec("nested-null", V2Rule)
                .Replace(
                    "\"name\":\"Azure Template\"",
                    "\"name\":\"Azure Template\",\"description\":null");
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(spec, "nested-null.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("explicit null")));
        }

        /// <summary>Semantic interaction depth 64 loads; depth 65 reaches the explicit semantic limit.</summary>
        [TestMethod]
        public void EnforcesSemanticInteractionExpressionDepth()
        {
            RuleBundle acceptedNot = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(InteractionSpecWithDepth(64, useArray: false), "not-depth-64.tmrules.json") });
            RuleBundle acceptedAll = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(InteractionSpecWithDepth(64, useArray: true), "all-depth-64.tmrules.json") });
            List<string> notDiagnostics = new List<string>();
            List<string> allDiagnostics = new List<string>();

            RuleBundle rejectedNot = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(InteractionSpecWithDepth(65, useArray: false), "not-depth-65.tmrules.json") },
                notDiagnostics.Add);
            RuleBundle rejectedAll = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(InteractionSpecWithDepth(65, useArray: true), "all-depth-65.tmrules.json") },
                allDiagnostics.Add);

            Assert.AreEqual(1, acceptedNot.Rules.Count);
            Assert.AreEqual(1, acceptedAll.Rules.Count);
            Assert.AreEqual(0, rejectedNot.Rules.Count);
            Assert.AreEqual(0, rejectedAll.Rules.Count);
            Assert.IsTrue(notDiagnostics.Any(message => message.Contains("depth exceeds the limit of 64")));
            Assert.IsTrue(allDiagnostics.Any(message => message.Contains("depth exceeds the limit of 64")));
        }

        /// <summary>
        /// Case-variant v2 markers are routed to strict parsing and rejected rather than silently
        /// loading as legacy rules without pack identity.
        /// </summary>
        [TestMethod]
        public void RejectsCaseVariantVersionTwoMarkers()
        {
            string spec =
                "{\"Schema\":\"tmforge-rules\",\"Version\":2," +
                "\"Dialect\":\"urn:tmforge:rules:flat-v1\"," +
                "\"Pack\":{\"id\":\"case-pack\",\"name\":\"Case pack\"}," +
                "\"Rules\":[{\"id\":\"CASE1\",\"appliesTo\":\"process\",\"message\":\"x\"," +
                "\"when\":{\"property\":\"P\"}}]}";
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(spec, "case-variant.tmrules.json") },
                diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.AreEqual(0, bundle.Packs.Count);
            Assert.IsTrue(diagnostics.Count > 0);
        }

        /// <summary>Declarative help links reject executable and local-resource URI schemes.</summary>
        [TestMethod]
        public void RejectsUnsafeHelpUriSchemes()
        {
            foreach (string scheme in new[] { "javascript:alert(1)", "data:text/html,x", "file:///tmp/help" })
            {
                string rule = V2Rule.Replace(
                    "\"severity\":\"error\"",
                    $"\"severity\":\"error\",\"helpUri\":\"{scheme}\"");
                List<string> diagnostics = new List<string>();

                RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(
                    new[] { this.WriteSpec(VersionTwoSpec("unsafe-help", rule)) },
                    diagnostics.Add);

                Assert.AreEqual(0, bundle.Rules.Count, scheme);
                Assert.IsTrue(diagnostics.Any(message => message.Contains("HTTP or HTTPS")), scheme);
            }
        }

        /// <summary>
        /// Rule files are rejected before parsing when they exceed the input byte limit.
        /// </summary>
        [TestMethod]
        public void RejectsOversizedRuleFile()
        {
            string path = this.WriteSpec(new string(' ', (8 * 1024 * 1024) + 1));
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("File size exceeds")));
        }

        /// <summary>
        /// Legacy files reject null rule entries and use the same per-file text/value limits as v2.
        /// </summary>
        [TestMethod]
        public void LegacyFilesRejectNullEntriesAndExcessiveText()
        {
            string nullPath = this.WriteSpec("{\"rules\":[null]}");
            List<string> nullDiagnostics = new List<string>();

            RuleBundle nullBundle = DeclarativeRuleProvider.LoadBundle(new[] { nullPath }, nullDiagnostics.Add);

            Assert.AreEqual(0, nullBundle.Rules.Count);
            Assert.IsTrue(nullDiagnostics.Any(message => message.Contains("null entries")));

            string longMessage = new string('x', 65537);
            string longPath = this.WriteSpec(
                "{\"rules\":[{\"id\":\"LONG\",\"appliesTo\":\"process\",\"message\":\"" + longMessage +
                "\",\"when\":{\"property\":\"P\"}}]}");
            List<string> longDiagnostics = new List<string>();

            RuleBundle longBundle = DeclarativeRuleProvider.LoadBundle(new[] { longPath }, longDiagnostics.Add);

            Assert.AreEqual(0, longBundle.Rules.Count);
            Assert.IsTrue(longDiagnostics.Any(message => message.Contains("string value exceeds")));
        }

        /// <summary>Pack text cannot carry terminal controls or characters that break XML exports.</summary>
        [TestMethod]
        public void RejectsUnsafePackTextCharacters()
        {
            string escapeCategory = VersionTwoSpec("escape-category", V2Rule)
                .Replace("Denial of Service", "Denial \\u001b[31mService");
            List<string> escapeDiagnostics = new List<string>();

            RuleBundle escapeBundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(escapeCategory, "escape.tmrules.json") },
                escapeDiagnostics.Add);

            Assert.AreEqual(0, escapeBundle.Rules.Count);
            Assert.IsTrue(escapeDiagnostics.Any(message => message.Contains("unsafe control character")));

            string invalidXml = VersionTwoSpec("invalid-xml", V2Rule)
                .Replace("Denial of Service", "Denial \\ufffe Service");
            List<string> xmlDiagnostics = new List<string>();

            RuleBundle xmlBundle = DeclarativeRuleProvider.LoadBundle(
                new[] { this.WriteSpec(invalidXml, "invalid-xml.tmrules.json") },
                xmlDiagnostics.Add);

            Assert.AreEqual(0, xmlBundle.Rules.Count);
            Assert.IsTrue(xmlDiagnostics.Any(message => message.Contains("cannot be represented in XML")));
        }

        /// <summary>
        /// Excessive rule and catalog counts are deterministic validation errors.
        /// </summary>
        [TestMethod]
        public void RejectsExcessiveRuleAndCatalogCounts()
        {
            string rule = "{\"id\":\"R$ID$\",\"appliesTo\":\"process\",\"message\":\"x\",\"when\":{\"property\":\"P\"}}";
            string rules = string.Join(",", Enumerable.Range(0, 4097).Select(index => rule.Replace("$ID$", index.ToString())));
            string excessiveRules = VersionTwoSpec("rule-heavy", rules, sourceType: "custom");
            string rulePath = this.WriteSpec(excessiveRules);
            List<string> ruleDiagnostics = new List<string>();

            RuleBundle ruleBundle = DeclarativeRuleProvider.LoadBundle(new[] { rulePath }, ruleDiagnostics.Add);

            Assert.AreEqual(0, ruleBundle.Rules.Count);
            Assert.IsTrue(ruleDiagnostics.Any(message => message.Contains("rule count exceeds")));

            string categories = string.Join(",", Enumerable.Range(0, 513).Select(index => $"{{\"id\":\"C{index}\",\"name\":\"Category {index}\"}}"));
            string excessiveCatalog = VersionTwoSpec("catalog-heavy", V2Rule, categories);
            string catalogPath = this.WriteSpec(excessiveCatalog);
            List<string> catalogDiagnostics = new List<string>();

            RuleBundle catalogBundle = DeclarativeRuleProvider.LoadBundle(new[] { catalogPath }, catalogDiagnostics.Add);

            Assert.AreEqual(0, catalogBundle.Rules.Count);
            Assert.IsTrue(catalogDiagnostics.Any(message => message.Contains("category count exceeds")));
        }

        /// <summary>
        /// Matcher and reference arrays participate in the aggregate catalog-value budget.
        /// </summary>
        [TestMethod]
        public void RejectsExcessiveMatcherValues()
        {
            string values = string.Join(",", Enumerable.Range(0, 65537).Select(index => $"\"V{index}\""));
            string rule =
                "{\"id\":\"VALUES\",\"appliesTo\":\"process\",\"message\":\"x\"," +
                $"\"when\":{{\"property\":\"Cache Type\",\"anyOf\":[{values}]}}}}";
            string path = this.WriteSpec(VersionTwoSpec("value-heavy", rule, sourceType: "custom"));
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("catalog value count exceeds")));
        }

        /// <summary>
        /// A single load is bounded across files, not only within each individually valid pack.
        /// </summary>
        [TestMethod]
        public void RejectsExcessiveSourceFileCount()
        {
            List<string> paths = new List<string>();
            for (int index = 0; index < 129; index++)
            {
                paths.Add(this.WriteSpec("{\"rules\":[]}", $"rules-{index:D3}.tmrules.json"));
            }

            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(paths, diagnostics.Add);

            Assert.IsTrue(bundle.Rules.Count == 0);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("source file count exceeds")));
        }

        /// <summary>
        /// Ambiguous aliases and cyclic element hierarchies are rejected before rules compile.
        /// </summary>
        [TestMethod]
        public void RejectsAmbiguousCatalogs()
        {
            string spec = VersionTwoSpec("ambiguous", V2Rule)
                .Replace(
                    "{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}",
                    "{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"GE.X\"},{\"id\":\"GE.X\",\"name\":\"Other\",\"parentId\":\"GE.P\"}")
                .Replace(
                    "}] ,\"rules\"",
                    "},{\"name\":\"Other\",\"aliases\":[\"cache-type\"],\"elementTypeIds\":[\"GE.P\"]}] ,\"rules\"");
            string path = this.WriteSpec(spec);
            List<string> diagnostics = new List<string>();

            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, bundle.Rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("cycle") || message.Contains("ambiguous")));
        }

        /// <summary>
        /// Case-insensitive catalog duplicates use one canonical diagnostic regardless of order.
        /// </summary>
        [TestMethod]
        public void DuplicateCatalogDiagnosticsAreOrderIndependent()
        {
            string firstCategories =
                "{\"id\":\"D\",\"name\":\"One\"},{\"id\":\"d\",\"name\":\"Two\"}";
            string secondCategories =
                "{\"id\":\"d\",\"name\":\"Two\"},{\"id\":\"D\",\"name\":\"One\"}";
            string path = this.WriteSpec(
                VersionTwoSpec("catalog-duplicates", V2Rule, firstCategories),
                "catalog-duplicates.tmrules.json");
            List<string> firstDiagnostics = new List<string>();
            _ = DeclarativeRuleProvider.LoadBundle(new[] { path }, firstDiagnostics.Add);

            File.WriteAllText(path, VersionTwoSpec("catalog-duplicates", V2Rule, secondCategories));
            List<string> secondDiagnostics = new List<string>();
            _ = DeclarativeRuleProvider.LoadBundle(new[] { path }, secondDiagnostics.Add);

            Assert.AreEqual(1, firstDiagnostics.Count);
            Assert.AreEqual(firstDiagnostics[0], secondDiagnostics.Single());
            StringAssert.Contains(firstDiagnostics[0], "duplicate category id 'D'");
        }

        /// <summary>
        /// A rule without an id is skipped and reported through diagnostics.
        /// </summary>
        [TestMethod]
        public void SkipsRuleMissingId()
        {
            string spec = "{\"rules\":[{\"appliesTo\":\"datastore\",\"message\":\"x\",\"assert\":{\"property\":\"Encrypted\",\"present\":true}}]}";
            string path = this.WriteSpec(spec);
            List<string> diagnostics = new List<string>();

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("id")));
        }

        /// <summary>
        /// A rule with an unrecognized <c>appliesTo</c> is skipped and reported.
        /// </summary>
        [TestMethod]
        public void SkipsUnknownAppliesTo()
        {
            string spec = "{\"rules\":[{\"id\":\"X1\",\"appliesTo\":\"widget\",\"message\":\"x\",\"assert\":{\"property\":\"P\",\"present\":true}}]}";
            string path = this.WriteSpec(spec);
            List<string> diagnostics = new List<string>();

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("appliesTo")));
        }

        /// <summary>
        /// Relational facets are only valid on flow rules; using one on a non-flow rule is rejected.
        /// </summary>
        [TestMethod]
        public void SkipsRelationalConditionOnNonFlow()
        {
            string spec = "{\"rules\":[{\"id\":\"X1\",\"appliesTo\":\"datastore\",\"message\":\"x\",\"when\":{\"crossesTrustBoundary\":true}}]}";
            string path = this.WriteSpec(spec);
            List<string> diagnostics = new List<string>();

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("flow")));
        }

        /// <summary>
        /// A rule with neither a guard nor a requirement is rejected.
        /// </summary>
        [TestMethod]
        public void SkipsRuleWithoutWhenOrAssert()
        {
            string spec = "{\"rules\":[{\"id\":\"X1\",\"appliesTo\":\"process\",\"message\":\"x\"}]}";
            string path = this.WriteSpec(spec);
            List<string> diagnostics = new List<string>();

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, rules.Count);
            Assert.IsTrue(diagnostics.Any(message => message.Contains("when") || message.Contains("assert")));
        }

        /// <summary>
        /// A malformed spec file is skipped with a diagnostic rather than throwing.
        /// </summary>
        [TestMethod]
        public void SkipsMalformedJson()
        {
            string path = this.WriteSpec("{ this is not valid json");
            List<string> diagnostics = new List<string>();

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { path }, diagnostics.Add);

            Assert.AreEqual(0, rules.Count);
            Assert.AreEqual(1, diagnostics.Count);
        }

        /// <summary>
        /// Tolerant legacy files ignore malformed generic provenance entries instead of aborting the
        /// load; version 2 rejects the same shape through strict pack validation.
        /// </summary>
        [TestMethod]
        public void LegacyRulesIgnoreMalformedProvenanceEntries()
        {
            string spec =
                "{\"rules\":[{\"id\":\"LEGACY-PROVENANCE\",\"appliesTo\":\"process\"," +
                "\"message\":\"x\",\"when\":{\"property\":\"P\"}," +
                "\"provenance\":{\"sourceId\":\"source-rule\",\"expressions\":[null," +
                "{\"role\":\"condition\",\"language\":\"not-namespaced\",\"text\":\"x\"}," +
                "{\"role\":\"condition\",\"language\":\"urn:example:expression\",\"text\":\"valid\"}]}}]}";

            IReadOnlyList<Rule> rules = DeclarativeRuleProvider.Load(new[] { this.WriteSpec(spec) });

            Assert.AreEqual(1, rules.Count);
            Assert.AreEqual("source-rule", rules.Single().Provenance!.SourceId);
            Assert.AreEqual("valid", rules.Single().Provenance!.Expressions.Single().Text);
        }

        private static string VersionTwoSpec(
            string packId,
            string rules,
            string categories = "{\"id\":\"D\",\"name\":\"Denial of Service\"}",
            string sourceType = "mtmt-tb7")
        {
            string source = string.Equals(sourceType, "mtmt-tb7", StringComparison.Ordinal)
                ? "{\"type\":\"urn:tmforge:source:mtmt-tb7\",\"name\":\"Azure Cloud Services.tb7\"," +
                    "\"id\":\"11111111-1111-1111-1111-111111111111\",\"version\":\"1.0.0.33\"}"
                : $"{{\"type\":\"urn:tmforge:source:{sourceType}\"}}";
            return
                "{\"schema\":\"tmforge-rules\",\"version\":2,\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
                $"\"pack\":{{\"id\":\"{packId}\",\"name\":\"Azure Template\",\"source\":{source}}}," +
                $"\"categories\":[{categories}]," +
                "\"elementTypes\":[{\"id\":\"GE.P\",\"name\":\"Process\",\"parentId\":\"ROOT\"}]," +
                "\"properties\":[{\"name\":\"Cache Type\",\"aliases\":[\"cacheType\",\"cache-type\"]," +
                "\"allowedValues\":[\"Static\",\"Distributed\"],\"elementTypeIds\":[\"GE.P\"]}] ," +
                $"\"rules\":[{rules}]}}";
        }

        private static string InteractionSpecWithDepth(int depth, bool useArray)
        {
            string expression = "{\"subject\":\"source\",\"type\":\"ROOT\"}";
            for (int current = 1; current < depth; current++)
            {
                expression = useArray
                    ? "{\"allOf\":[" + expression + "]}"
                    : "{\"not\":" + expression + "}";
            }

            return
                "{\"schema\":\"tmforge-rules\",\"version\":2," +
                "\"dialect\":\"urn:tmforge:rules:interaction-v1\"," +
                "\"pack\":{\"id\":\"depth-pack\",\"name\":\"Depth pack\"}," +
                "\"rules\":[{\"id\":\"DEPTH\",\"message\":\"depth\",\"expression\":" + expression + "}]}";
        }

        private static T CreateEntity<T>(string typeId, string genericTypeId, string name)
            where T : Entity, new()
        {
            T entity = new T
            {
                Guid = Guid.NewGuid(),
                TypeId = typeId,
                GenericTypeId = genericTypeId,
            };
            entity.Properties.Add(new StringDisplayAttribute { Name = "Name", DisplayName = "Name", Value = name });
            return entity;
        }

        private static ThreatModel CreateConnectivityModel()
        {
            DrawingSurfaceModel page = new DrawingSurfaceModel { Header = "Connectivity" };
            StencilRectangle entry = CreateEntity<StencilRectangle>("GE.EI", "GE.EI", "Entry");
            StencilEllipse gateway = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Gateway");
            StencilEllipse worker = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Worker");
            StencilParallelLines store = CreateEntity<StencilParallelLines>("GE.DS", "GE.DS", "Store");
            StencilEllipse isolated = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Isolated");
            foreach (Entity component in new Entity[] { entry, gateway, worker, store, isolated })
            {
                page.Borders.Add(component.Guid, component);
            }

            AddGraphFlow(page, entry, gateway);
            AddGraphFlow(page, gateway, worker);
            AddGraphFlow(page, worker, store);
            return new ThreatModel { DrawingSurfaceList = { page } };
        }

        private static void AddGraphFlow(DrawingSurfaceModel page, Entity source, Entity target)
        {
            Connector flow = CreateEntity<Connector>("GE.DF", "GE.DF", "Flow");
            flow.SourceGuid = source.Guid;
            flow.TargetGuid = target.Guid;
            page.Lines.Add(flow.Guid, flow);
        }

        private static string GraphRuleText(string predicate, bool interaction, string subject, string appliesTo) =>
            interaction
                ? "{\"id\":\"GRAPH\",\"message\":\"graph\",\"expression\":{\"subject\":\"" + subject + "\"," + predicate + "}}"
                : "{\"id\":\"GRAPH\",\"appliesTo\":\"" + appliesTo + "\",\"message\":\"graph\",\"when\":{" + predicate + "}}";

        private string WriteSpec(string json, string? fileName = null)
        {
            string path = Path.Join(
                this.WorkingDirectory,
                fileName ?? Guid.NewGuid().ToString("N") + ".tmrules.json");
            File.WriteAllText(path, json);
            return path;
        }

        private Rule LoadGraphRule(string predicate, bool interaction = false, string subject = "target", string appliesTo = "process")
        {
            string spec = VersionTwoSpec("connectivity", GraphRuleText(predicate, interaction, subject, appliesTo));
            if (interaction)
            {
                spec = spec.Replace(RulePackDialects.FlatV1, RulePackDialects.InteractionV1);
            }

            List<string> diagnostics = new List<string>();
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) }, diagnostics.Add);
            Assert.AreEqual(1, bundle.Rules.Count, string.Join("; ", diagnostics));
            return bundle.Rules[0];
        }

        private MockMessageWriter RunPropertyRule(
            string matcher,
            string? value,
            string form,
            bool requirement = false,
            long? operationLimit = null)
        {
            bool interaction = form.StartsWith("interaction-", StringComparison.Ordinal);
            string subject = interaction ? form.Substring("interaction-".Length) : form;
            string predicate = "{\"property\":\"cacheType\"," + matcher + "}";
            string condition = subject == "source" || subject == "target"
                ? "{\"" + subject + "\":" + predicate + "}"
                : predicate;
            string rule = interaction
                ? "{\"id\":\"VALUE\",\"message\":\"value\",\"expression\":{\"subject\":\"" + subject + "\",\"property\":\"cacheType\"," + matcher + "}}"
                : "{\"id\":\"VALUE\",\"message\":\"value\",\"appliesTo\":\"" + (subject == "element" ? "process" : "flow") +
                    "\",\"" + (requirement ? "assert" : "when") + "\":" + condition + "}";
            if (interaction && requirement)
            {
                using JsonDocument document = JsonDocument.Parse(rule);
                string expression = document.RootElement.GetProperty("expression").GetRawText();
                rule = "{\"id\":\"VALUE\",\"message\":\"value\",\"expression\":{\"not\":" + expression + "}}";
            }

            string spec = VersionTwoSpec("property-matchers", rule);
            if (interaction)
            {
                spec = spec.Replace(RulePackDialects.FlatV1, RulePackDialects.InteractionV1);
            }

            List<string> diagnostics = new List<string>();
            RuleBundle bundle = DeclarativeRuleProvider.LoadBundle(new[] { this.WriteSpec(spec) }, diagnostics.Add);
            Assert.AreEqual(1, bundle.Rules.Count, string.Join("; ", diagnostics));
            StencilEllipse source = CreateEntity<StencilEllipse>("GE.P", "GE.P", "Source");
            StencilRectangle target = CreateEntity<StencilRectangle>("GE.EI", "GE.EI", "Target");
            Connector flow = CreateEntity<Connector>("GE.DF", "GE.DF", "Flow");
            flow.SourceGuid = source.Guid;
            flow.TargetGuid = target.Guid;
            Entity candidate = subject == "flow" ? flow : subject == "target" ? target : source;
            if (value != null)
            {
                candidate.Properties.Add(new CustomStringDisplayAttribute { Value = "Cache Type:" + value });
            }

            DrawingSurfaceModel diagram = new DrawingSurfaceModel { Header = "Matchers" };
            diagram.Borders.Add(source.Guid, source);
            diagram.Borders.Add(target.Guid, target);
            diagram.Lines.Add(flow.Guid, flow);
            MockMessageWriter writer = new MockMessageWriter();
            RuleEvaluationContext context = new RuleEvaluationContext(new ThreatModel { DrawingSurfaceList = { diagram } }, writer);
            if (operationLimit.HasValue)
            {
                context.SetDeclarativeOperationLimit(operationLimit.Value);
            }

            bundle.Rules[0].Evaluate(context);
            return writer;
        }
    }
}
