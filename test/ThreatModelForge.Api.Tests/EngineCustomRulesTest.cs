namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;

    /// <summary>
    /// Contract tests for custom rule content on the shared engine facade. Every transport — the CLI,
    /// the HTTP API, the in-browser engine, and the MCP server — reaches the rule set through this
    /// facade, so proving that one pack yields the same catalog entry, finding, threat, report, and
    /// export here proves it for all of them by construction.
    /// </summary>
    [TestClass]
    public class EngineCustomRulesTest
    {
        private const string PackJson =
            "{\"schema\":\"tmforge-rules\",\"version\":2,\"dialect\":\"urn:tmforge:rules:flat-v1\"," +
            "\"pack\":{\"id\":\"corporate\",\"name\":\"Corporate baseline\",\"version\":\"2.1\"}," +
            "\"categories\":[{\"id\":\"privacy\",\"name\":\"Privacy\"}]," +
            "\"elementTypes\":[{\"id\":\"GE.DS\",\"name\":\"Data store\",\"parentId\":\"ROOT\"}]," +
            "\"properties\":[{\"name\":\"Encrypted\",\"allowedValues\":[\"No\",\"At-rest\"],\"elementTypeIds\":[\"GE.DS\"]}]," +
            "\"rules\":[{\"id\":\"CORP-1\",\"severity\":\"error\",\"categoryId\":\"privacy\",\"defaultPriority\":\"High\"," +
            "\"appliesTo\":\"datastore\",\"message\":\"{name} must encrypt data at rest.\"," +
            "\"helpText\":\"Set Encrypted to At-rest.\"," +
            "\"assert\":{\"property\":\"Encrypted\",\"equals\":\"At-rest\"}}]}";

        private const string EffectiveRuleId = "corporate/CORP-1";

        /// <summary>Review uses the same custom bundle on both sides and never resolves load failures.</summary>
        [TestMethod]
        public void CompareUsesTheEffectiveCustomRuleBundle()
        {
            TmForgeModelDto baseline = UnencryptedStoreModel();
            TmForgeElementDto store = baseline.Elements!.Single();
            TmForgeModelDto proposed = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = store.Id, Kind = store.Kind, Name = store.Name, X = store.X, Y = store.Y, Properties = new Dictionary<string, string> { ["Encrypted"] = "At-rest" } },
                },
            };
            ModelCompareRequestDto request = new ModelCompareRequestDto { Baseline = baseline, Proposed = proposed };

            ModelCompareResultDto result = EngineService.Compare(request, Rules());

            Assert.IsTrue(result.FindingsAvailable);
            Assert.AreEqual("resolved", result.Changes.Single(change => change.RuleId == EffectiveRuleId).Kind);
            EngineRuleOptions broken = new EngineRuleOptions { Sources = new[] { new RuleSourceDto { Name = "broken", Json = "invalid" } } };
            ModelCompareResultDto unavailable = EngineService.Compare(request, broken);
            Assert.IsTrue(unavailable.Success);
            Assert.IsFalse(unavailable.FindingsAvailable);
            Assert.IsFalse(unavailable.Changes.Any(change => change.Section == "findings"));
        }

        /// <summary>The custom pack contributes to the rule catalog every surface reads.</summary>
        [TestMethod]
        public void CustomPackAppearsInTheRuleCatalog()
        {
            IReadOnlyList<RuleDto> builtIn = EngineService.GetRules();
            IReadOnlyList<RuleDto> effective = EngineService.GetRules(Rules());

            Assert.IsFalse(builtIn.Any(rule => rule.Id == EffectiveRuleId));
            RuleDto custom = effective.Single(rule => rule.Id == EffectiveRuleId);
            Assert.AreEqual("corporate", custom.Pack);
            Assert.AreEqual("error", custom.Severity);
            Assert.AreEqual(builtIn.Count + 1, effective.Count);
        }

        /// <summary>The custom pack is selectable, so per-model toggles cover imported packs too.</summary>
        [TestMethod]
        public void CustomPackAppearsInTheRulePackCatalog()
        {
            RulePackDto pack = EngineService.GetRulePacks(Rules()).Single(entry => entry.Id == "corporate");

            Assert.AreEqual("Corporate baseline", pack.Name);
            Assert.AreEqual(1, pack.Count);
        }

        /// <summary>
        /// Analysis runs the custom rule and reports the pack identity and content fingerprint that
        /// produced the findings, so a caller can tell which rules actually ran.
        /// </summary>
        [TestMethod]
        public void AnalyzeRunsTheCustomRuleAndReportsTheEffectivePack()
        {
            AnalysisResultDto result = EngineService.Analyze(UnencryptedStoreModel(), Rules());

            FindingDto finding = result.Findings.Single(entry => entry.RuleId == EffectiveRuleId);
            Assert.AreEqual("error", finding.Severity);
            Assert.IsTrue(finding.Message.Contains("Ledger", StringComparison.Ordinal));

            RulePackInfoDto pack = result.RulePacks.Single();
            Assert.AreEqual("corporate", pack.Id);
            Assert.AreEqual("2.1", pack.Version);
            Assert.AreEqual(1, pack.RuleCount);
            Assert.IsTrue(pack.Fingerprint.StartsWith("sha256:", StringComparison.Ordinal));
            Assert.AreEqual(0, result.Diagnostics.Count);
        }

        /// <summary>Without the pack the same model produces no such finding: the rule is opt-in.</summary>
        [TestMethod]
        public void AnalyzeWithoutTheCustomPackDoesNotRunTheRule()
        {
            IReadOnlyList<FindingDto> findings = EngineService.Analyze(UnencryptedStoreModel());

            Assert.IsFalse(findings.Any(finding => finding.RuleId == EffectiveRuleId));
        }

        /// <summary>
        /// A threat-bearing custom rule projects into the register with the pack's category and
        /// declared priority, exactly as a built-in threat-bearing rule does.
        /// </summary>
        [TestMethod]
        public void GenerateThreatsProjectsTheCustomRule()
        {
            IReadOnlyList<ThreatDto> threats = EngineService.GenerateThreats(UnencryptedStoreModel(), Rules());

            ThreatDto threat = threats.Single(entry => entry.RuleId == EffectiveRuleId);
            Assert.AreEqual("corporate/privacy", threat.CategoryId);
            Assert.AreEqual("Privacy", threat.CategoryName);
            Assert.AreEqual("High", threat.Priority);
        }

        /// <summary>Disabling the custom pack suppresses it exactly as it does a built-in pack.</summary>
        [TestMethod]
        public void DisablingTheCustomPackSuppressesIt()
        {
            TmForgeModelDto model = UnencryptedStoreModel();
            TmForgeModelDto disabled = new TmForgeModelDto
            {
                Elements = model.Elements,
                Analysis = new TmForgeAnalysisDto { DisabledPacks = new[] { "corporate" } },
            };

            AnalysisResultDto result = EngineService.Analyze(disabled, Rules());

            Assert.IsFalse(result.Findings.Any(finding => finding.RuleId == EffectiveRuleId));
            Assert.AreEqual("corporate", result.RulePacks.Single().Id);
        }

        /// <summary>
        /// The custom rule's threat reaches the rendered report, so the report a reviewer reads matches
        /// the analysis they ran.
        /// </summary>
        [TestMethod]
        public void ReportIncludesTheCustomRuleThreat()
        {
            string html = Encoding.UTF8.GetString(EngineService.Report(UnencryptedStoreModel(), "html", Rules()));

            Assert.IsTrue(html.Contains("must encrypt data at rest", StringComparison.Ordinal));
        }

        /// <summary>
        /// The register-bearing <c>.tm7</c> export carries the custom rule's threat, so the pack's
        /// findings survive a round trip through the lossless format.
        /// </summary>
        [TestMethod]
        public void Tm7ExportCarriesTheCustomRuleThreat()
        {
            string document = Encoding.UTF8.GetString(EngineService.ExportTm7(UnencryptedStoreModel(), Rules()));

            Assert.IsTrue(document.Contains("must encrypt data at rest", StringComparison.Ordinal));
        }

        /// <summary>
        /// A model that pins a pack it was reviewed with reports an error when that pack is absent,
        /// rather than looking clean because the rule never ran.
        /// </summary>
        [TestMethod]
        public void MissingExpectedPackIsReportedAsAnError()
        {
            TmForgeModelDto model = UnencryptedStoreModel();
            TmForgeModelDto pinned = new TmForgeModelDto
            {
                Elements = model.Elements,
                Analysis = new TmForgeAnalysisDto
                {
                    ExpectedPacks = new[] { new ExpectedRulePackDto { Id = "corporate" } },
                },
            };

            AnalysisResultDto result = EngineService.Analyze(pinned, null);

            FindingDto finding = result.Findings.Single(entry => entry.RuleId == "rule-pack-mismatch");
            Assert.AreEqual("error", finding.Severity);
            Assert.IsTrue(finding.Message.Contains("corporate", StringComparison.Ordinal));
        }

        /// <summary>Changed pack content is reported: pinning is by fingerprint, not by name.</summary>
        [TestMethod]
        public void ChangedPackContentIsReportedAsAnError()
        {
            TmForgeModelDto model = UnencryptedStoreModel();
            TmForgeModelDto pinned = new TmForgeModelDto
            {
                Elements = model.Elements,
                Analysis = new TmForgeAnalysisDto
                {
                    ExpectedPacks = new[]
                    {
                        new ExpectedRulePackDto { Id = "corporate", Fingerprint = "sha256:stale" },
                    },
                },
            };

            AnalysisResultDto result = EngineService.Analyze(pinned, Rules());

            FindingDto finding = result.Findings.Single(entry => entry.RuleId == "rule-pack-mismatch");
            Assert.IsTrue(finding.Message.Contains("sha256:stale", StringComparison.Ordinal));
        }

        /// <summary>A matching fingerprint passes silently: the pin only speaks up when it is broken.</summary>
        [TestMethod]
        public void MatchingFingerprintProducesNoMismatchFinding()
        {
            AnalysisResultDto probe = EngineService.Analyze(UnencryptedStoreModel(), Rules());
            TmForgeModelDto model = UnencryptedStoreModel();
            TmForgeModelDto pinned = new TmForgeModelDto
            {
                Elements = model.Elements,
                Analysis = new TmForgeAnalysisDto
                {
                    ExpectedPacks = new[]
                    {
                        new ExpectedRulePackDto { Id = "corporate", Fingerprint = probe.RulePacks.Single().Fingerprint },
                    },
                },
            };

            AnalysisResultDto result = EngineService.Analyze(pinned, Rules());

            Assert.IsFalse(result.Findings.Any(finding => finding.RuleId == "rule-pack-mismatch"));
        }

        /// <summary>
        /// A pack that fails to load is reported through diagnostics and contributes no rules, so a
        /// host never presents a broken pack as a working one.
        /// </summary>
        [TestMethod]
        public void MalformedPackIsReportedThroughDiagnostics()
        {
            EngineRuleOptions broken = new EngineRuleOptions
            {
                Sources = new[] { new RuleSourceDto { Name = "broken.tmrules.json", Json = "{ not json" } },
            };

            RuleBundleDto bundle = EngineService.DescribeRules(broken);

            Assert.AreEqual(0, bundle.RulePacks.Count);
            Assert.IsTrue(bundle.Diagnostics.Any(message => message.Contains("broken.tmrules.json", StringComparison.Ordinal)));
        }

        /// <summary>The combined metadata operation retains the existing catalog and diagnostics contracts.</summary>
        /// <param name="selection">The rule source selection.</param>
        [TestMethod]
        [DataRow("built-in")]
        [DataRow("custom")]
        [DataRow("invalid")]
        public void RulePackCatalogAndMetadataDescribeOneBundle(string selection)
        {
            EngineRuleOptions? rules = selection == "built-in" ? null : selection == "custom" ? Rules() : new EngineRuleOptions
            {
                Sources = new[] { new RuleSourceDto { Name = "invalid.tmrules.json", Json = "{ invalid json" } },
            };
            RuleBundleDto metadata = EngineService.DescribeRules(rules, out IReadOnlyList<RulePackDto> catalog);
            Assert.AreEqual(JsonSerializer.Serialize(EngineService.GetRulePacks(rules)), JsonSerializer.Serialize(catalog));
            Assert.AreEqual(JsonSerializer.Serialize(EngineService.DescribeRules(rules)), JsonSerializer.Serialize(metadata));
            Assert.AreEqual(selection == "custom" ? 1 : 0, metadata.RulePacks.Count);
            Assert.AreEqual(selection == "invalid", metadata.Diagnostics.Count > 0);
            foreach (RulePackInfoDto pack in metadata.RulePacks)
            {
                Assert.AreEqual(pack.RuleCount, catalog.Single(entry => entry.Id == pack.Id).Count);
            }
        }

        /// <summary>New predicates preserve finding/threat identities, reports, and exported model semantics.</summary>
        /// <param name="format">The round-trip format.</param>
        [TestMethod]
        [DataRow("tmforge-json")]
        [DataRow("tm7")]
        public void AdditionalMatchersPreserveResultsAcrossFormats(string format)
        {
            (TmForgeModelDto model, EngineRuleOptions rules) = AdditionalMatchers();
            AnalysisResultDto original = EngineService.RunAnalysis(model, rules);
            Assert.AreEqual(0, original.Diagnostics.Count);
            FindingDto[] findings = original.Findings.Where(finding => finding.RuleId?.StartsWith("rule005/", StringComparison.Ordinal) == true).ToArray();
            ThreatDto[] threats = original.Threats.Where(threat => threat.RuleId?.StartsWith("rule005/", StringComparison.Ordinal) == true).ToArray();
            CollectionAssert.AreEquivalent(
                new[] { "rule005/RETENTION", "rule005/SERVICE-NAME", "rule005/AUDIT-PATH" },
                findings.Select(finding => finding.RuleId).ToArray());
            Assert.AreEqual(3, threats.Length);
            Assert.IsTrue(threats.All(threat => threat.CategoryId == "rule005/policy" && threat.Priority == "High"));

            byte[] bytes = EngineService.Convert(model, format, rules);
            TmForgeModelDto restored = EngineService.ReadModel(bytes, format);
            AnalysisResultDto roundTrip = EngineService.RunAnalysis(restored, rules);
            CollectionAssert.AreEquivalent(findings.Select(finding => finding.Id).ToArray(), roundTrip.Findings
                .Where(finding => finding.RuleId?.StartsWith("rule005/", StringComparison.Ordinal) == true).Select(finding => finding.Id).ToArray());
            CollectionAssert.AreEquivalent(threats.Select(threat => threat.Id).ToArray(), roundTrip.Threats
                .Where(threat => threat.RuleId?.StartsWith("rule005/", StringComparison.Ordinal) == true).Select(threat => threat.Id).ToArray());
            Assert.IsFalse(roundTrip.Findings.Any(finding => finding.Id == "engine-error"));
            Assert.AreEqual(original.RulePacks.Single().Fingerprint, roundTrip.RulePacks.Single().Fingerprint);
            string html = Encoding.UTF8.GetString(EngineService.Report(model, "html", rules));
            StringAssert.Contains(html, "retention between 1 and 30 days");
            StringAssert.Contains(html, "service name beginning with svc-");
            StringAssert.Contains(html, "lacks a direct audit-store connection");
        }

        /// <summary>Existing per-rule and per-pack toggles apply to every new matcher.</summary>
        /// <param name="disablePack">Whether to disable the whole pack.</param>
        [TestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public void AdditionalMatchersHonorDisabledSelections(bool disablePack)
        {
            (TmForgeModelDto model, EngineRuleOptions rules) = AdditionalMatchers();
            TmForgeModelDto selected = new TmForgeModelDto
            {
                Elements = model.Elements,
                Flows = model.Flows,
                Analysis = new TmForgeAnalysisDto
                {
                    DisabledPacks = disablePack ? new[] { "rule005" } : Array.Empty<string>(),
                    DisabledRuleIds = disablePack ? Array.Empty<string>() : new[] { "rule005/RETENTION" },
                },
            };
            AnalysisResultDto result = EngineService.RunAnalysis(selected, rules);
            Assert.AreEqual(disablePack ? 0 : 2, result.Findings.Count(finding => finding.RuleId?.StartsWith("rule005/", StringComparison.Ordinal) == true));
            Assert.IsFalse(result.Findings.Any(finding => finding.RuleId == "rule005/RETENTION" || finding.Id == "engine-error"));
        }

        /// <summary>A regex timeout is a visible failure in both projections, not an empty successful analysis.</summary>
        [TestMethod]
        public void RegexTimeoutIsVisibleOnTheEngineFacade()
        {
            EngineRuleOptions rules = new EngineRuleOptions
            {
                Sources = new[]
                {
                    new RuleSourceDto
                    {
                        Name = "timeout.tmrules.json",
                        Json = "{\"rules\":[{\"id\":\"TIMEOUT\",\"appliesTo\":\"process\",\"message\":\"timeout\",\"assert\":{\"property\":\"Value\",\"matches\":\"^(a+)+$\"}}]}",
                    },
                },
            };
            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto
                    {
                        Id = "timeout",
                        Kind = "process",
                        Properties = new Dictionary<string, string> { ["Value"] = new string('a', 4095) + "!" },
                    },
                },
            };

            AnalysisResultDto result = EngineService.RunAnalysis(model, rules);

            StringAssert.Contains(result.Findings.Single(finding => finding.Id == "engine-error").Message, "TIMEOUT");
            StringAssert.Contains(result.Threats.Single(threat => threat.Id == "engine-error").Title, "timeout");
            Assert.IsFalse(result.Findings.Any(finding => finding.RuleId == "TIMEOUT"));
        }

        /// <summary>The internal-service starter pack is opt-in and enforces whole-string service names.</summary>
        /// <param name="scope">The recorded service scope, or null when unclassified.</param>
        /// <param name="name">The recorded service name, or null when absent.</param>
        /// <param name="expected">Whether the naming policy should report a finding.</param>
        [TestMethod]
        [DataRow("Internal", "svc-billing", false)]
        [DataRow("Internal", "svc-billing-v2", false)]
        [DataRow("Internal", "billing", true)]
        [DataRow("Internal", "svc-Billing", true)]
        [DataRow("Internal", "svc-billing\n", true)]
        [DataRow("Internal", "svc--billing", true)]
        [DataRow("Internal", "svc-", true)]
        [DataRow("Internal", "Unknown", true)]
        [DataRow("Internal", null, true)]
        [DataRow("External", "billing", false)]
        [DataRow("Unknown", "billing", false)]
        [DataRow(null, "billing", false)]
        public void StarterServiceNamesAreScoped(string? scope, string? name, bool expected)
        {
            Dictionary<string, string> properties = new Dictionary<string, string>();
            if (scope != null)
            {
                properties["ServiceScope"] = scope;
            }

            if (name != null)
            {
                properties["ServiceName"] = name;
            }

            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[] { new TmForgeElementDto { Id = "service", Name = "Billing", Kind = "process", Properties = properties } },
            };
            AnalysisResultDto result = EngineService.RunAnalysis(model, StarterRules("internal-service"));

            Assert.AreEqual(0, result.Diagnostics.Count, string.Join("; ", result.Diagnostics));
            Assert.AreEqual(2, result.RulePacks.Single().RuleCount);
            Assert.IsFalse(result.Findings.Any(finding => finding.Id == "engine-error"));
            Assert.AreEqual(expected ? 1 : 0, result.Findings.Count(finding => finding.RuleId == "example-internal-service/SERVICE-NAME"));
            Assert.IsFalse(result.Threats.Any(threat => threat.RuleId == "example-internal-service/SERVICE-NAME"));
        }

        /// <summary>Each starter pack loads as two opt-in rules with source references and non-certification wording.</summary>
        /// <param name="name">The pack file name.</param>
        /// <param name="id">The published pack id.</param>
        [TestMethod]
        [DataRow("internal-service", "example-internal-service")]
        [DataRow("pci-inspired", "example-pci")]
        [DataRow("hipaa-inspired", "example-hipaa")]
        public void StarterPacksLoadWithScopeAndProvenance(string name, string id)
        {
            EngineRuleOptions options = StarterRules(name);
            RuleBundleDto result = EngineService.DescribeRules(options);
            Assert.AreEqual(0, result.Diagnostics.Count, string.Join("; ", result.Diagnostics));
            RulePackInfoDto pack = result.RulePacks.Single();
            Assert.AreEqual(id, pack.Id);
            Assert.AreEqual("1.0.0", pack.Version);
            Assert.AreEqual(2, pack.RuleCount);
            StringAssert.StartsWith(pack.Fingerprint, "sha256:");
            string? json = options.Sources![0].Json;
            Assert.IsNotNull(json);
            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            StringAssert.Contains(root.GetProperty("pack").GetProperty("description").GetString() ?? string.Empty, "do not certify compliance");
            Assert.IsTrue(Uri.TryCreate(root.GetProperty("pack").GetProperty("source").GetProperty("uri").GetString(), UriKind.Absolute, out Uri? source));
            Assert.AreEqual("https", source!.Scheme);
            foreach (JsonElement rule in root.GetProperty("rules").EnumerateArray())
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(rule.GetProperty("provenance").GetProperty("sourceId").GetString()));
                Assert.IsFalse(string.IsNullOrWhiteSpace(rule.GetProperty("provenance").GetProperty("location").GetString()));
                Assert.IsFalse(string.IsNullOrWhiteSpace(rule.GetProperty("fullDescription").GetString()));
                Assert.IsFalse(string.IsNullOrWhiteSpace(rule.GetProperty("helpText").GetString()));
            }

            AnalysisResultDto unclassified = EngineService.RunAnalysis(new TmForgeModelDto(), options);
            Assert.AreEqual(0, unclassified.Diagnostics.Count);
            Assert.IsFalse(unclassified.Findings.Any(finding => finding.RuleId?.StartsWith(id + "/", StringComparison.Ordinal) == true));
        }

        /// <summary>The published demonstration model exercises both rules in every starter pack.</summary>
        /// <param name="name">The starter pack file.</param>
        /// <param name="first">The first expected rule id.</param>
        /// <param name="second">The second expected rule id.</param>
        [TestMethod]
        [DataRow("internal-service", "SERVICE-NAME", "AUDIT-CONNECTION")]
        [DataRow("pci-inspired", "PAN-ENCRYPTION", "AUDIT-RETENTION")]
        [DataRow("hipaa-inspired", "EPHI-TRANSPORT", "EPHI-AUDIT")]
        public void StarterDemonstrationTriggersEveryRule(string name, string first, string second)
        {
            TmForgeModelDto model = StarterModel();
            string original = JsonSerializer.Serialize(model);
            AnalysisResultDto result = AssertStarterFindings(model, name, first, second);
            string packId = result.RulePacks.Single().Id;
            Assert.AreEqual(name == "internal-service" ? 1 : 2, result.Threats.Count(threat => threat.RuleId?.StartsWith(packId + "/", StringComparison.Ordinal) == true));
            Assert.AreEqual(original, JsonSerializer.Serialize(model));
        }

        /// <summary>PCI-inspired PAN protection accepts only evidenced encryption on explicitly scoped stores.</summary>
        /// <param name="scope">Whether PAN storage is declared.</param>
        /// <param name="encryption">The recorded encryption mode.</param>
        /// <param name="expected">Whether the rule should fire.</param>
        [TestMethod]
        [DataRow("Yes", "At-rest", false)]
        [DataRow("Yes", "TDE", false)]
        [DataRow("Yes", "Client-side", false)]
        [DataRow("Yes", "Platform", false)]
        [DataRow("Yes", "No", true)]
        [DataRow("Yes", "Unknown", true)]
        [DataRow("Yes", "Tokenized", true)]
        [DataRow("Yes", "", true)]
        [DataRow("Yes", null, true)]
        [DataRow("No", "No", false)]
        [DataRow("Unknown", "No", false)]
        [DataRow(null, "No", false)]
        public void StarterPanEncryptionRequiresEvidence(string? scope, string? encryption, bool expected)
        {
            TmForgeModelDto model = StarterStore("StoresPAN", scope, "Encrypted", encryption);
            AssertStarterFindings(model, "pci-inspired", expected ? new[] { "PAN-ENCRYPTION" } : Array.Empty<string>());
        }

        /// <summary>The retention example checks a minimum in months without coercing invalid evidence.</summary>
        /// <param name="scope">The audit scope.</param>
        /// <param name="months">The declared retention in months.</param>
        /// <param name="expected">Whether the rule should fire.</param>
        [TestMethod]
        [DataRow("CDE", "11.99", true)]
        [DataRow("CDE", "12", false)]
        [DataRow("CDE", "12.5", false)]
        [DataRow("CDE", "24", false)]
        [DataRow("CDE", "1.2e1", false)]
        [DataRow("CDE", "0", true)]
        [DataRow("CDE", "-1", true)]
        [DataRow("CDE", "12,0", true)]
        [DataRow("CDE", "Unknown", true)]
        [DataRow("CDE", "twelve", true)]
        [DataRow("CDE", null, true)]
        [DataRow("Other", "0", false)]
        [DataRow("Unknown", "0", false)]
        [DataRow(null, "0", false)]
        public void StarterAuditRetentionRequiresTwelveMonths(string? scope, string? months, bool expected)
        {
            TmForgeModelDto model = StarterStore("AuditScope", scope, "RetentionMonths", months);
            AssertStarterFindings(model, "pci-inspired", expected ? new[] { "AUDIT-RETENTION" } : Array.Empty<string>());
        }

        /// <summary>Both transport and certificate validation are required on explicitly ePHI flows.</summary>
        /// <param name="classification">The flow classification.</param>
        /// <param name="protocol">The recorded transport.</param>
        /// <param name="validation">The recorded certificate validation.</param>
        /// <param name="expected">Whether the rule should fire.</param>
        [TestMethod]
        [DataRow("ePHI", "HTTPS", "Yes", false)]
        [DataRow("ePHI", "TLS", "Yes", false)]
        [DataRow("ePHI", "mTLS", "Yes", false)]
        [DataRow("ePHI", "HTTP", "Yes", true)]
        [DataRow("ePHI", "gRPC", "Yes", true)]
        [DataRow("ePHI", "Unknown", "Yes", true)]
        [DataRow("ePHI", null, "Yes", true)]
        [DataRow("ePHI", "TLS", "No", true)]
        [DataRow("ePHI", "TLS", "Unknown", true)]
        [DataRow("ePHI", "TLS", null, true)]
        [DataRow("ePHI", null, null, true)]
        [DataRow("Other", "HTTP", "No", false)]
        [DataRow("Unknown", "HTTP", "No", false)]
        [DataRow(null, "HTTP", "No", false)]
        public void StarterEphiTransportRequiresBothControls(string? classification, string? protocol, string? validation, bool expected)
        {
            Dictionary<string, string> properties = new Dictionary<string, string>();
            foreach ((string key, string? value) in new[] { ("DataClassification", classification), ("Protocol", protocol), ("CertificateValidation", validation) })
            {
                if (value != null)
                {
                    properties[key] = value;
                }
            }

            TmForgeModelDto model = new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "source", Kind = "external", Name = "Client" },
                    new TmForgeElementDto { Id = "target", Kind = "datastore", Name = "Records" },
                },
                Flows = new[] { new TmForgeFlowDto { Id = "request", Source = "source", Target = "target", Name = "Request", Properties = properties } },
            };
            AssertStarterFindings(model, "hipaa-inspired", expected ? new[] { "EPHI-TRANSPORT" } : Array.Empty<string>());
        }

        /// <summary>Audit policies require a direct outgoing connection to an evidenced audit datastore.</summary>
        /// <param name="connection">The modeled audit connection topology.</param>
        /// <param name="marker">The destination's logging property.</param>
        /// <param name="kind">The destination's primitive kind.</param>
        /// <param name="expected">Whether the audit rule should fire.</param>
        [TestMethod]
        [DataRow("direct", "Yes", "datastore", false)]
        [DataRow("direct", "No", "datastore", true)]
        [DataRow("direct", "Unknown", "datastore", true)]
        [DataRow("direct", null, "datastore", true)]
        [DataRow("indirect", "Yes", "datastore", true)]
        [DataRow("reverse", "Yes", "datastore", true)]
        [DataRow("none", "Yes", "datastore", true)]
        [DataRow("direct", "Yes", "process", true)]
        public void StarterAuditConnectionsRequireDirectEvidencedStores(string connection, string? marker, string kind, bool expected)
        {
            TmForgeModelDto model = StarterAuditModel(connection, marker, kind);
            AssertStarterFindings(model, "internal-service", expected ? new[] { "AUDIT-CONNECTION" } : Array.Empty<string>());
            AssertStarterFindings(model, "hipaa-inspired", expected ? new[] { "EPHI-AUDIT" } : Array.Empty<string>());
        }

        /// <summary>Scope must be recorded; neither example infers scope from names or topology.</summary>
        /// <param name="scope">The internal-service scope.</param>
        /// <param name="classification">The incoming flow's classification.</param>
        [TestMethod]
        [DataRow("External", "Other")]
        [DataRow("Unknown", "Unknown")]
        [DataRow(null, null)]
        public void StarterAuditRulesDoNotInferScope(string? scope, string? classification)
        {
            TmForgeModelDto model = StarterAuditModel("none", "Yes", "datastore", scope, classification);
            AssertStarterFindings(model, "internal-service");
            AssertStarterFindings(model, "hipaa-inspired");
        }

        /// <summary>Only the internal-service example uses external reachability as its scope guard.</summary>
        [TestMethod]
        public void StarterInternalAuditRequiresAnExternalPath()
        {
            TmForgeModelDto source = StarterAuditModel("none", "Yes", "datastore");
            TmForgeModelDto isolated = new TmForgeModelDto { Elements = source.Elements, Flows = Array.Empty<TmForgeFlowDto>() };
            AssertStarterFindings(isolated, "internal-service");
        }

        /// <summary>The documented remediation clears only starter-policy findings and keeps every scope declaration.</summary>
        /// <param name="name">The pack file name.</param>
        [TestMethod]
        [DataRow("internal-service")]
        [DataRow("pci-inspired")]
        [DataRow("hipaa-inspired")]
        public void StarterRemediationSatisfiesTheExamplePolicies(string name)
        {
            TmForgeModelDto model = StarterModel(satisfyPolicies: true);
            AssertStarterFindings(model, name);
            Assert.AreEqual("Internal", model.Elements!.Single(element => element.Name == "Example gateway").Properties["ServiceScope"]);
            Assert.AreEqual("Yes", model.Elements!.Single(element => element.Name == "Example PAN store").Properties["StoresPAN"]);
            Assert.AreEqual("CDE", model.Elements!.Single(element => element.Name == "Example audit store").Properties["AuditScope"]);
            Assert.AreEqual("ePHI", model.Flows!.Single(flow => flow.Name == "Example ePHI request").Properties["DataClassification"]);
        }

        /// <summary>All packs compose without collisions and their threat identities survive model export.</summary>
        /// <param name="format">The exported format.</param>
        [TestMethod]
        [DataRow("tmforge-json")]
        [DataRow("tm7")]
        public void StarterLibraryPreservesFindingsAndThreatsAcrossFormats(string format)
        {
            EngineRuleOptions rules = new EngineRuleOptions
            {
                Sources = new[] { "pci-inspired", "hipaa-inspired", "internal-service" }.SelectMany(name => StarterRules(name).Sources!).ToArray(),
            };
            TmForgeModelDto model = StarterModel();
            AnalysisResultDto before = EngineService.RunAnalysis(model, rules);
            Assert.AreEqual(0, before.Diagnostics.Count);
            Assert.AreEqual(3, before.RulePacks.Count);
            FindingDto[] findings = before.Findings.Where(finding => finding.RuleId?.StartsWith("example-", StringComparison.Ordinal) == true).ToArray();
            ThreatDto[] threats = before.Threats.Where(threat => threat.RuleId?.StartsWith("example-", StringComparison.Ordinal) == true).ToArray();
            Assert.AreEqual(6, findings.Length);
            Assert.AreEqual(5, threats.Length);

            TmForgeModelDto restored = EngineService.ReadModel(EngineService.Convert(model, format, rules), format);
            AnalysisResultDto after = EngineService.RunAnalysis(restored, rules);
            Assert.AreEqual(0, after.Diagnostics.Count);
            Assert.IsFalse(after.Findings.Any(finding => finding.Id == "engine-error"));
            CollectionAssert.AreEquivalent(findings.Select(finding => finding.Id).ToArray(), after.Findings
                .Where(finding => finding.RuleId?.StartsWith("example-", StringComparison.Ordinal) == true).Select(finding => finding.Id).ToArray());
            CollectionAssert.AreEquivalent(threats.Select(threat => threat.Id).ToArray(), after.Threats
                .Where(threat => threat.RuleId?.StartsWith("example-", StringComparison.Ordinal) == true).Select(threat => threat.Id).ToArray());
        }

        /// <summary>Reads identical rule content and model input for direct-engine and HTTP parity checks.</summary>
        /// <returns>The fixture model and rule sources.</returns>
        internal static (TmForgeModelDto Model, EngineRuleOptions Rules) AdditionalMatchers()
        {
            using JsonDocument fixture = JsonDocument.Parse(File.ReadAllText(Path.Join(AppContext.BaseDirectory, "Fixtures", "additional-matchers.json")));
            TmForgeModelDto model = fixture.RootElement.GetProperty("model").Deserialize<TmForgeModelDto>(new JsonSerializerOptions(JsonSerializerDefaults.Web))
                ?? throw new InvalidDataException("The matcher fixture requires a model.");
            EngineRuleOptions rules = new EngineRuleOptions
            {
                Sources = new[] { new RuleSourceDto { Name = "additional-matchers.tmrules.json", Json = fixture.RootElement.GetProperty("pack").GetRawText() } },
            };
            return (model, rules);
        }

        private static TmForgeModelDto StarterModel(bool satisfyPolicies = false)
        {
            static JsonNode Required(JsonNode node, string key) => node[key] ?? throw new InvalidDataException("The starter example requires " + key + ".");
            string file = Path.Join(AppContext.BaseDirectory, "Fixtures", "RulePacks", "starter-model.tmforge.json");
            JsonNode document = JsonNode.Parse(File.ReadAllText(file)) ?? throw new InvalidDataException("The starter example requires a model.");
            if (satisfyPolicies)
            {
                JsonArray elements = Required(document, "elements").AsArray();
                JsonObject gateway = elements.OfType<JsonObject>().Single(element => Required(element, "name").GetValue<string>() == "Example gateway");
                JsonObject audit = elements.OfType<JsonObject>().Single(element => Required(element, "name").GetValue<string>() == "Example audit store");
                JsonObject pan = elements.OfType<JsonObject>().Single(element => Required(element, "name").GetValue<string>() == "Example PAN store");
                Required(gateway, "properties")["ServiceName"] = "svc-gateway";
                Required(audit, "properties")["RetentionMonths"] = "12";
                Required(pan, "properties")["Encrypted"] = "At-rest";
                JsonArray flows = Required(document, "flows").AsArray();
                JsonObject request = flows.OfType<JsonObject>().Single(flow => Required(flow, "name").GetValue<string>() == "Example ePHI request");
                Required(request, "properties")["Protocol"] = "TLS";
                Required(request, "properties")["CertificateValidation"] = "Yes";
                flows.Add(new JsonObject
                {
                    ["id"] = "20000000-0000-4000-8000-000000000005",
                    ["name"] = "Example direct audit event",
                    ["source"] = Required(gateway, "id").GetValue<string>(),
                    ["target"] = Required(audit, "id").GetValue<string>(),
                });
            }

            return document.Deserialize<TmForgeModelDto>(new JsonSerializerOptions(JsonSerializerDefaults.Web))
                ?? throw new InvalidDataException("The starter example requires a model.");
        }

        private static TmForgeModelDto StarterAuditModel(string connection, string? marker, string kind, string? scope = "Internal", string? classification = "ePHI")
        {
            Dictionary<string, string> serviceProperties = new Dictionary<string, string> { ["ServiceName"] = "svc-service" };
            if (scope != null)
            {
                serviceProperties["ServiceScope"] = scope;
            }

            Dictionary<string, string> flowProperties = new Dictionary<string, string> { ["Protocol"] = "TLS", ["CertificateValidation"] = "Yes" };
            if (classification != null)
            {
                flowProperties["DataClassification"] = classification;
            }

            Dictionary<string, string> logProperties = new Dictionary<string, string>();
            if (marker != null)
            {
                logProperties["StoresLogData"] = marker;
            }

            List<TmForgeFlowDto> flows = new List<TmForgeFlowDto>
            {
                new TmForgeFlowDto { Id = "request", Source = "entry", Target = "service", Name = "Request", Properties = flowProperties },
            };
            if (connection != "none")
            {
                flows.Add(new TmForgeFlowDto
                {
                    Id = "audit",
                    Source = connection == "reverse" ? "logs" : "service",
                    Target = connection == "reverse" ? "service" : connection == "indirect" ? "relay" : "logs",
                    Name = "Audit event",
                });
            }

            if (connection == "indirect")
            {
                flows.Add(new TmForgeFlowDto { Id = "forward", Source = "relay", Target = "logs", Name = "Forward event" });
            }

            return new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto { Id = "entry", Kind = "external", Name = "Entry" },
                    new TmForgeElementDto { Id = "service", Kind = "process", Name = "Service", Properties = serviceProperties },
                    new TmForgeElementDto { Id = "relay", Kind = "process", Name = "Collector" },
                    new TmForgeElementDto { Id = "logs", Kind = kind, Name = "Logs", Properties = logProperties },
                },
                Flows = flows,
            };
        }

        private static TmForgeModelDto StarterStore(string scopeName, string? scope, string valueName, string? value)
        {
            Dictionary<string, string> properties = new Dictionary<string, string>();
            if (scope != null)
            {
                properties[scopeName] = scope;
            }

            if (value != null)
            {
                properties[valueName] = value;
            }

            return new TmForgeModelDto
            {
                Elements = new[] { new TmForgeElementDto { Id = "store", Name = "Store", Kind = "datastore", Properties = properties } },
            };
        }

        private static AnalysisResultDto AssertStarterFindings(TmForgeModelDto model, string name, params string[] expectedRules)
        {
            AnalysisResultDto result = EngineService.RunAnalysis(model, StarterRules(name));
            Assert.AreEqual(0, result.Diagnostics.Count, string.Join("; ", result.Diagnostics));
            Assert.IsFalse(result.Findings.Any(finding => finding.Id == "engine-error"));
            Assert.IsFalse(result.Threats.Any(threat => threat.Id == "engine-error"));
            string prefix = result.RulePacks.Single().Id + "/";
            FindingDto[] findings = result.Findings.Where(finding => finding.RuleId?.StartsWith(prefix, StringComparison.Ordinal) == true).ToArray();
            CollectionAssert.AreEquivalent(expectedRules.Select(rule => prefix + rule).ToArray(), findings.Select(finding => finding.RuleId).ToArray());
            Assert.IsTrue(findings.All(finding => finding.Severity == "warning"));
            return result;
        }

        private static EngineRuleOptions StarterRules(string name)
        {
            string file = Path.Join(AppContext.BaseDirectory, "Fixtures", "RulePacks", name + ".tmrules.json");
            return new EngineRuleOptions
            {
                Sources = new[] { new RuleSourceDto { Name = Path.GetFileName(file), Json = File.ReadAllText(file) } },
            };
        }

        private static EngineRuleOptions Rules()
        {
            return new EngineRuleOptions
            {
                Sources = new[] { new RuleSourceDto { Name = "corporate.tmrules.json", Json = PackJson } },
            };
        }

        private static TmForgeModelDto UnencryptedStoreModel()
        {
            return new TmForgeModelDto
            {
                Elements = new[]
                {
                    new TmForgeElementDto
                    {
                        Id = "s1",
                        Kind = "datastore",
                        Name = "Ledger",
                        Properties = new Dictionary<string, string> { ["Encrypted"] = "No" },
                    },
                },
            };
        }
    }
}
