namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using System.Xml;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Analysis.Reporting;
    using ThreatModelForge.Analysis.Rules;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Formats;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;
    using ThreatModelForge.Reporting;

    /// <summary>
    /// Bridges the canonical tmforge-json contract to the real .NET engine: it builds a
    /// <see cref="ThreatModel"/> with the UI-agnostic <see cref="DiagramEditor"/>, runs the real
    /// analysis rule set, and serializes to the lossless <c>.tm7</c> format via the format registry.
    /// </summary>
    public static class EngineService
    {
        /// <summary>
        /// The synthetic rule id used to report a rule-pack expectation that the effective bundle did
        /// not meet.
        /// </summary>
        private const string RulePackMismatchRuleId = "rule-pack-mismatch";

        private static readonly string AnalyzerName =
            typeof(RuleSet).Assembly.GetName().Name ?? "ThreatModelForge.Analysis";

        private static readonly string AnalyzerVersion =
            typeof(RuleSet).Assembly.GetName().Version?.ToString() ?? "0.0.0.0";

        private static readonly JsonSerializerOptions CanonicalJsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };

        /// <summary>
        /// Matches the shape <c>tmforge analyze --reportFolder</c> writes, so the findings JSON a host
        /// serves and the file the CLI writes are the same document.
        /// </summary>
        private static readonly JsonSerializerOptions AnalysisReportJsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter() },
        };

        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

        /// <summary>
        /// Lists the registered file-format providers and their capabilities.
        /// </summary>
        /// <returns>The available formats.</returns>
        public static IReadOnlyList<FormatDto> GetFormats()
        {
            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();
            List<FormatDto> result = new List<FormatDto>();
            foreach (IThreatModelFormat format in registry.Formats)
            {
                result.Add(MapFormat(format));
            }

            return result;
        }

        /// <summary>
        /// Lists the built-in authoring stencils offered to the palette.
        /// </summary>
        /// <returns>The available stencils.</returns>
        public static IReadOnlyList<StencilDto> GetStencils() => StencilCatalog.All;

        /// <summary>
        /// Lists the stencil packs offered to the palette, for show/hide toggles.
        /// </summary>
        /// <returns>The available stencil packs.</returns>
        public static IReadOnlyList<PackDto> GetStencilPacks() => StencilCatalog.Packs;

        /// <summary>
        /// Lists the typed property schema (the known element properties, each with its value kind,
        /// allowed values, and default) so authoring surfaces can render typed controls and emit
        /// canonical values that the analysis rules read with confidence.
        /// </summary>
        /// <returns>The property descriptors across all DFD primitives.</returns>
        public static IReadOnlyList<PropertyDescriptor> GetPropertySchema() => PropertySchemaCatalog.All;

        /// <summary>
        /// Lists the analysis rules offered by the engine, with their pack, severity, and help link.
        /// </summary>
        /// <returns>The available rules, ordered by id.</returns>
        public static IReadOnlyList<RuleDto> GetRules() => GetRules(null);

        /// <summary>
        /// Lists the effective analysis rules: the built-in rules plus the custom packs selected by
        /// <paramref name="rules"/>. Every transport passes the same options here, so a custom rule
        /// appears in the catalog wherever it is loaded.
        /// </summary>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The available rules, ordered by id.</returns>
        public static IReadOnlyList<RuleDto> GetRules(EngineRuleOptions? rules)
        {
            List<RuleDto> result = new List<RuleDto>();
            using (RuleSet ruleSet = LoadRuleSet(rules, null, out _))
            {
                foreach (Rule rule in ruleSet.Rules)
                {
                    result.Add(new RuleDto
                    {
                        Id = rule.ID,
                        Pack = rule.Pack,
                        Severity = MapSeverity(rule.Severity),
                        Description = rule.FullDescription,
                        HelpText = rule.HelpText,
                        HelpUri = rule.HelpUri?.ToString(),
                    });
                }
            }

            result.Sort((left, right) => string.CompareOrdinal(left.Id, right.Id));
            return result;
        }

        /// <summary>
        /// Lists the rule packs offered by the engine, for per-model validation toggles.
        /// </summary>
        /// <returns>The available rule packs, in presentation order.</returns>
        public static IReadOnlyList<RulePackDto> GetRulePacks() => GetRulePacks(null);

        /// <summary>
        /// Lists the effective rule packs: the built-in packs plus the custom packs selected by
        /// <paramref name="rules"/>, so a validation toggle exists for imported and hand-written packs
        /// alike.
        /// </summary>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The available rule packs, in presentation order.</returns>
        public static IReadOnlyList<RulePackDto> GetRulePacks(EngineRuleOptions? rules)
        {
            using (RuleSet ruleSet = LoadRuleSet(rules, null, out IReadOnlyList<RulePackDefinition> packs))
            {
                return MapRulePackCatalog(packs, ruleSet);
            }
        }

        /// <summary>
        /// Describes the custom rule content that would run for the given options: the packs that load
        /// and the diagnostics raised while loading them. A host calls this to confirm that the pack it
        /// configured is the pack that runs.
        /// </summary>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The effective packs and load diagnostics.</returns>
        public static RuleBundleDto DescribeRules(EngineRuleOptions? rules) => DescribeRules(rules, out _);

        /// <summary>Returns catalog counts and custom metadata from one effective rule-set load.</summary>
        /// <param name="rules">The custom rule content, or <see langword="null"/> for built-ins only.</param>
        /// <param name="catalog">The built-in and custom pack catalog in presentation order.</param>
        /// <returns>The custom pack identities and diagnostics from the same load.</returns>
        public static RuleBundleDto DescribeRules(EngineRuleOptions? rules, out IReadOnlyList<RulePackDto> catalog)
        {
            List<string> diagnostics = new List<string>();
            IReadOnlyList<RulePackInfoDto> effective;
            using (RuleSet ruleSet = LoadRuleSet(rules, diagnostics, out IReadOnlyList<RulePackDefinition> packs))
            {
                effective = MapRulePacks(packs, ruleSet);
                catalog = MapRulePackCatalog(packs, ruleSet);
            }

            return new RuleBundleDto { RulePacks = effective, Diagnostics = diagnostics };
        }

        /// <summary>
        /// Runs the real analysis rule set (ThreatModelForge.Analysis.Rules) over the model.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <returns>The findings produced by the engine.</returns>
        public static IReadOnlyList<FindingDto> Analyze(TmForgeModelDto dto) => Analyze(dto, null).Findings;

        /// <summary>
        /// Runs the effective rule set — the built-in rules plus the custom packs selected by
        /// <paramref name="rules"/> — over the model, and reports which packs actually loaded so the
        /// caller can tell a clean model from a model analyzed against the wrong rules.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The findings, the effective custom packs, and any load diagnostics.</returns>
        public static AnalysisResultDto Analyze(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            return RunAnalysis(dto, rules, AnalysisProjection.Findings);
        }

        /// <summary>
        /// Runs one analysis action: evaluates the effective rule set <em>once</em> and projects both
        /// the transient findings and the lifecycle-bearing threats from the same messages. This is what
        /// an interactive surface should call — asking for findings and threats separately evaluates
        /// every enabled rule twice for a single user action.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The findings, threats, effective custom packs, and any load diagnostics.</returns>
        public static AnalysisResultDto RunAnalysis(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            return RunAnalysis(dto, rules, AnalysisProjection.Findings | AnalysisProjection.Threats);
        }

        /// <summary>
        /// Projects the model's threat-bearing analysis findings into threats. Detection is entirely the
        /// rule set's — this runs the same rules <see cref="Analyze(TmForgeModelDto)"/> runs and frames
        /// the findings from threat-bearing rules as persistable threats. CLI, <c>/v1</c>, and WASM call
        /// the same projector, so results are identical by construction.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <returns>The generated threats.</returns>
        public static IReadOnlyList<ThreatDto> GenerateThreats(TmForgeModelDto dto) => GenerateThreats(dto, null);

        /// <summary>
        /// Projects threats from the effective rule set — the built-in rules plus the custom packs
        /// selected by <paramref name="rules"/> — so a custom threat-bearing rule yields the same threat
        /// id, category, priority, and mitigation on every transport. A caller that also needs the
        /// findings of the same action should use <see cref="RunAnalysis(TmForgeModelDto, EngineRuleOptions)"/>
        /// instead, which evaluates the rules once for both.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The generated threats.</returns>
        public static IReadOnlyList<ThreatDto> GenerateThreats(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            return RunAnalysis(dto, rules, AnalysisProjection.Threats).Threats;
        }

        /// <summary>
        /// Records one analysis run as a versioned <c>tmforge-analysis</c> document: every finding with
        /// its structural disposition, plus the fingerprints of the model and rule selection that
        /// produced it.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <returns>The analysis document.</returns>
        public static AnalysisDocumentDto DescribeAnalysis(TmForgeModelDto dto) => DescribeAnalysis(dto, null);

        /// <summary>
        /// Records one analysis run against the effective rule bundle as a versioned
        /// <c>tmforge-analysis</c> document.
        /// </summary>
        /// <remarks>
        /// This is the artifact meant to be stored between runs, so it is deliberately reconcilable
        /// rather than merely descriptive: the finding ids are stable, every finding carries exactly
        /// one disposition, and the fingerprints let a consumer detect that the document no longer
        /// describes the model or rules in front of it. Two runs over the same inputs produce identical
        /// documents.
        /// </remarks>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The analysis document.</returns>
        public static AnalysisDocumentDto DescribeAnalysis(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            _ = dto ?? throw new ArgumentNullException(nameof(dto));

            List<AnalysisFindingDto> evidence = new List<AnalysisFindingDto>();
            string analyzerFingerprint = string.Empty;
            AnalysisResultDto result = RunAnalysis(
                dto,
                rules,
                AnalysisProjection.Evidence,
                evidence,
                ruleSet => analyzerFingerprint =
                    AnalysisDocumentBuilder.AnalyzerFingerprint(AnalyzerName, AnalyzerVersion, ruleSet));

            return new AnalysisDocumentDto
            {
                Model = new AnalysisIdentityDto
                {
                    Name = AnalysisReportName(dto),
                    Fingerprint = AnalysisDocumentBuilder.ModelFingerprint(dto),
                },
                Analyzer = new AnalysisIdentityDto
                {
                    Name = AnalyzerName,
                    Version = AnalyzerVersion,
                    Fingerprint = analyzerFingerprint,
                },
                RulePacks = result.RulePacks,
                Findings = evidence,
                Diagnostics = result.Diagnostics,
            };
        }

        /// <summary>
        /// Describes the model's threat register split by origin and by standing against the current
        /// rules, using the built-in rules.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <returns>The split register.</returns>
        public static ThreatRegisterDto DescribeThreatRegister(TmForgeModelDto dto)
            => DescribeThreatRegister(dto, null);

        /// <summary>
        /// Describes the model's threat register split by origin and by standing against the current
        /// rules.
        /// </summary>
        /// <remarks>
        /// The register alone cannot tell a live entry from one left behind by a rule that stopped
        /// firing, because applying a generation result never deletes. This classifies it against one
        /// evaluation so both are distinguishable, and reports an entry whose rule was not part of the
        /// run separately rather than calling it stale.
        /// </remarks>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The split register.</returns>
        public static ThreatRegisterDto DescribeThreatRegister(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            _ = dto ?? throw new ArgumentNullException(nameof(dto));

            ThreatRegisterSummary? summary = null;
            AnalysisResultDto result = RunAnalysis(
                dto,
                rules,
                AnalysisProjection.Register,
                onRegister: register => summary = register);

            if (summary == null)
            {
                // The evaluation failed; report the diagnostics rather than an empty register that
                // would read as "nothing stored".
                return new ThreatRegisterDto
                {
                    Diagnostics = result.Diagnostics,
                    RulePacks = result.RulePacks,
                };
            }

            return new ThreatRegisterDto
            {
                Manual = summary.Manual,
                PersistedGenerated = summary.PersistedGenerated,
                CurrentGenerated = summary.CurrentGenerated,
                StaleGenerated = summary.StaleGenerated,
                IndeterminateGenerated = summary.IndeterminateGenerated,
                UnavailableRuleIds = summary.UnavailableRuleIds,
                Entries = summary.Entries.Select(entry => new ThreatRegisterEntryDto
                {
                    Id = entry.Id,
                    State = entry.State,
                    RuleId = entry.RuleId,
                    Title = entry.Title,
                    Triage = ThreatStateWire.ToWire(entry.Triage),
                    HasTriage = entry.HasTriage,
                }).ToList(),
                Diagnostics = result.Diagnostics,
                RulePacks = result.RulePacks,
            };
        }

        /// <summary>
        /// Serializes the supplied model to lossless <c>.tm7</c> bytes via the real engine.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <returns>The <c>.tm7</c> document bytes.</returns>
        public static byte[] ExportTm7(TmForgeModelDto dto) => ExportTm7(dto, null);

        /// <summary>
        /// Serializes the supplied model to lossless <c>.tm7</c> bytes, materializing its threat register
        /// from the effective rule set so a custom threat-bearing pack is carried into the export.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The <c>.tm7</c> document bytes.</returns>
        public static byte[] ExportTm7(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            ThreatModel model = BuildModelForExport(dto, rules);
            Tm7ExportPreparer.Prepare(model);

            using (MemoryStream stream = new MemoryStream())
            {
                model.Save(stream);
                return stream.ToArray();
            }
        }

        /// <summary>
        /// Reads a document in any registered format and projects it onto the canonical
        /// tmforge-json model the canvas edits.
        /// </summary>
        /// <param name="content">The raw document bytes.</param>
        /// <param name="formatId">An optional explicit format id; when omitted the engine sniffs the content.</param>
        /// <returns>The canonical model.</returns>
        public static TmForgeModelDto ReadModel(byte[] content, string? formatId)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();
            ThreatModel model;
            using (MemoryStream input = new MemoryStream(content))
            {
                model = registry.Load(input, string.IsNullOrEmpty(formatId) ? null : formatId);
            }

            return ToDto(model);
        }

        /// <summary>
        /// Serializes the supplied model to the requested registered format's bytes.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="formatId">The target format id (for example, <c>tm7</c>, <c>drawio</c>, <c>vsdx</c>).</param>
        /// <returns>The serialized document bytes.</returns>
        public static byte[] Convert(TmForgeModelDto dto, string formatId) => Convert(dto, formatId, null);

        /// <summary>
        /// Serializes the supplied model to the requested registered format's bytes, materializing any
        /// register-bearing format from the effective rule set.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="formatId">The target format id (for example, <c>tm7</c>, <c>drawio</c>, <c>vsdx</c>).</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The serialized document bytes.</returns>
        public static byte[] Convert(TmForgeModelDto dto, string formatId, EngineRuleOptions? rules)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                WriteConverted(dto, formatId, stream, rules);
                return stream.ToArray();
            }
        }

        /// <summary>Serializes the supplied model to the requested registered format stream.</summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="formatId">The target format id.</param>
        /// <param name="output">The destination stream, which remains open.</param>
        public static void WriteConverted(TmForgeModelDto dto, string formatId, Stream output) =>
            WriteConverted(dto, formatId, output, null);

        /// <summary>
        /// Serializes the supplied model to the requested registered format stream, materializing any
        /// register-bearing format from the effective rule set.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="formatId">The target format id.</param>
        /// <param name="output">The destination stream, which remains open.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        public static void WriteConverted(TmForgeModelDto dto, string formatId, Stream output, EngineRuleOptions? rules)
        {
            if (string.IsNullOrEmpty(formatId))
            {
                throw new ArgumentException("Value cannot be null or empty.", nameof(formatId));
            }

            if (output == null)
            {
                throw new ArgumentNullException(nameof(output));
            }

            // .tm7 is the lossless, register-bearing format, so materialize the full threat register
            // (with acceptance) and prepare it for the Microsoft Threat Modeling Tool — embed the
            // knowledge base and type schema-backed properties — so every path that writes a .tm7 (this
            // facade, the CLI, and the dedicated export) produces the same tool-openable file. The other
            // formats drop the register, so keep the cheaper build.
            ThreatModel model;
            if (string.Equals(formatId, Tm7Format.FormatId, StringComparison.OrdinalIgnoreCase))
            {
                model = BuildModelForExport(dto, rules);
                Tm7ExportPreparer.Prepare(model);
            }
            else
            {
                model = BuildModel(dto, out _);
            }

            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();
            IThreatModelFormat format = registry.FindById(formatId)
                ?? throw new NotSupportedException($"No threat model format with id '{formatId}'.");
            if (!format.Capabilities.CanWrite)
            {
                throw new NotSupportedException($"Format '{formatId}' does not support writing.");
            }

            format.Write(model, output);
        }

        /// <summary>
        /// Detects the format of a document by content sniffing.
        /// </summary>
        /// <param name="content">The raw document bytes.</param>
        /// <returns>The detected format, or <see langword="null"/> if none matches.</returns>
        public static FormatDto? Detect(byte[] content)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();
            using (MemoryStream input = new MemoryStream(content))
            {
                IThreatModelFormat? format = registry.Sniff(input);
                return format == null ? null : MapFormat(format);
            }
        }

        /// <summary>
        /// Renders a report for the supplied model.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="format">The report format: <c>html</c> (default) or <c>svg</c>.</param>
        /// <returns>The report bytes (UTF-8).</returns>
        public static byte[] Report(TmForgeModelDto dto, string format) => Report(dto, format, null);

        /// <summary>
        /// Renders a report for the supplied model against the effective rule set, so a report shows the
        /// same threats a custom pack produced during analysis.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="format">The report format: <c>html</c> (default) or <c>svg</c>.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The report bytes (UTF-8).</returns>
        public static byte[] Report(TmForgeModelDto dto, string format, EngineRuleOptions? rules)
        {
            if (string.Equals(format, "svg", StringComparison.OrdinalIgnoreCase))
            {
                ThreatModel diagramModel = BuildModel(dto, out _);
                return Encoding.UTF8.GetBytes(new DiagramSvgRenderer().RenderModel(diagramModel).ToString());
            }

            ThreatModel model = BuildModelForExport(dto, rules);
            string html = new HtmlReportWriter().Write(model);
            return Encoding.UTF8.GetBytes(html);
        }

        /// <summary>
        /// Renders an <em>analysis</em> report: the findings artifacts, as distinct from
        /// <see cref="Report(TmForgeModelDto, string)"/>, which renders the threat-model document.
        /// These are the same artifacts <c>tmforge analyze --reportFolder</c> writes, so a review
        /// produced in the Studio and one produced in CI are the same evidence.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="format">The report format: <c>sarif</c>, <c>html</c>, or <c>json</c>.</param>
        /// <returns>The report bytes (UTF-8).</returns>
        public static byte[] AnalysisReport(TmForgeModelDto dto, string format) => AnalysisReport(dto, format, null);

        /// <summary>
        /// Renders an analysis report against the effective rule set, so a custom pack's findings and
        /// the model's disabled selections are carried into SARIF and the findings documents.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="format">The report format: <c>sarif</c>, <c>html</c>, or <c>json</c>.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The report bytes (UTF-8).</returns>
        public static byte[] AnalysisReport(TmForgeModelDto dto, string format, EngineRuleOptions? rules)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                WriteAnalysisReport(dto, format, stream, rules);
                return stream.ToArray();
            }
        }

        /// <summary>
        /// Writes an analysis report to a stream, so a host can stream a large findings document
        /// straight to its response or to disk instead of buffering it.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="format">The report format: <c>sarif</c>, <c>html</c>, or <c>json</c>.</param>
        /// <param name="output">The destination stream, which remains open.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        public static void WriteAnalysisReport(
            TmForgeModelDto dto,
            string format,
            Stream output,
            EngineRuleOptions? rules)
        {
            if (output == null)
            {
                throw new ArgumentNullException(nameof(output));
            }

            string reportName = AnalysisReportName(dto);
            ModelReport report = BuildAnalysisReport(dto, rules, reportName);
            switch ((format ?? string.Empty).ToUpperInvariant())
            {
                case "SARIF":
                    using (SarifReportWriter writer = new SarifReportWriter(new NonClosingStream(output), reportName + ".sarif"))
                    {
                        writer.Write(report);
                    }

                    break;

                case "JSON":
                    using (StreamWriter text = new StreamWriter(output, Utf8NoBom, 1024, leaveOpen: true))
                    {
                        text.Write(JsonSerializer.Serialize(report, AnalysisReportJsonOptions));
                    }

                    break;

                default:
                    // Findings HTML is the readable form of the same report; it is also the fallback,
                    // matching Report's behavior for an unrecognized format.
                    using (XmlWriter xml = XmlWriter.Create(
                        output,
                        new XmlWriterSettings { Indent = true, CloseOutput = false, ConformanceLevel = ConformanceLevel.Document }))
                    {
                        using (FindingsHtmlReportWriter writer = new FindingsHtmlReportWriter(xml, reportName + ".html"))
                        {
                            writer.Write(report);
                        }
                    }

                    break;
            }
        }

        /// <summary>Compares immutable baseline and proposed snapshots without merging either model.</summary>
        /// <param name="request">The two model snapshots.</param>
        /// <param name="rules">The rule bundle used by the host, or null for the built-ins.</param>
        /// <returns>The read-only review changes and comparability diagnostics.</returns>
        public static ModelCompareResultDto Compare(ModelCompareRequestDto request, EngineRuleOptions? rules)
            => ModelComparison.Compare(request, rules);

        /// <summary>
        /// Merges two edited models, keyed by element identity. When <paramref name="baseModel"/> is
        /// supplied it is a three-way merge against that common ancestor, so non-overlapping edits
        /// combine automatically; when it is <c>null</c> (the ancestor is unavailable) it falls back
        /// to a two-way merge where any divergence on a shared element is reported as a conflict.
        /// Genuine conflicts are resolved in favor of <paramref name="ours"/> and reported so the
        /// caller can present them for resolution.
        /// </summary>
        /// <param name="baseModel">The common ancestor model, or <c>null</c> for a two-way merge.</param>
        /// <param name="ours">The local model.</param>
        /// <param name="theirs">The incoming model.</param>
        /// <returns>The merged model and any conflicts (all resolved to <c>ours</c>).</returns>
        public static MergeResultDto Merge(TmForgeModelDto? baseModel, TmForgeModelDto ours, TmForgeModelDto theirs)
        {
            ThreatModel oursTm = BuildModel(ours ?? new TmForgeModelDto(), out _);
            ThreatModel theirsTm = BuildModel(theirs ?? new TmForgeModelDto(), out _);

            MergeResult result = baseModel == null
                ? ModelMerge.Merge(oursTm, theirsTm)
                : ModelMerge.Merge(BuildModel(baseModel, out _), oursTm, theirsTm);

            List<MergeConflictDto> conflicts = new List<MergeConflictDto>();
            foreach (MergeConflict conflict in result.Conflicts)
            {
                conflicts.Add(new MergeConflictDto
                {
                    ElementId = conflict.ElementId.ToString(),
                    ElementKind = conflict.ElementKind,
                    Name = conflict.Name,
                    DiagramName = conflict.DiagramName,
                    Kind = conflict.Kind.ToString(),
                    Property = conflict.Property,
                    Base = conflict.Base,
                    Ours = conflict.Ours,
                    Theirs = conflict.Theirs,
                });
            }

            return new MergeResultDto { Merged = ToDto(result.Merged), Conflicts = conflicts };
        }

        /// <summary>
        /// Arranges a model's pages without changing trust-boundary membership or connector
        /// crossings. Returns only geometry keyed by original author ids; never rewrites author
        /// state or evaluates detection rules. Unsafe candidates are refused without partial output.
        /// </summary>
        /// <param name="request">The original model, optional proposed positions and layout metrics.</param>
        /// <returns>Geometry updates on success, or a reason with no updates on refusal.</returns>
        public static LayoutResultDto Layout(LayoutRequestDto request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            string? error = ValidateLayoutInput(request);
            if (error != null)
            {
                return new LayoutResultDto { Error = error };
            }

            // Properties and triage cannot influence placement. Do not build them only to discard
            // them: the canonical reader types properties and hydrates the register, which can be
            // expensive for untrusted property bags and is unrelated to a geometry-only operation.
            ThreatModel model = BuildModel(LayoutStructure(request.Model!), out _, out Dictionary<Guid, string> originalIds);
            IReadOnlyList<DrawingSurfaceModel> targets = model.DrawingSurfaceList;
            if (!string.IsNullOrEmpty(request.Page))
            {
                if (!AuthoringSupport.TryResolveDiagram(model, request.Page, out DrawingSurfaceModel? selected, out error))
                {
                    return new LayoutResultDto { Error = error };
                }

                targets = new[] { selected! };
            }

            Dictionary<string, Guid> internalIds = targets
                .SelectMany(diagram => diagram.Borders.Values.OfType<DrawingElement>())
                .ToDictionary(element => originalIds[element.Guid], element => element.Guid, StringComparer.Ordinal);
            Dictionary<Guid, LayoutElementDto>? positions = null;
            if (request.Positions != null)
            {
                positions = new Dictionary<Guid, LayoutElementDto>();
                foreach (LayoutElementDto position in request.Positions)
                {
                    if (!internalIds.TryGetValue(position.Id, out Guid id) || !positions.TryAdd(id, position))
                    {
                        return new LayoutResultDto { Error = "Proposed positions must name each selected element exactly once." };
                    }
                }
            }

            if (!LayoutOperations.TryApply(targets, request.Options, out _, out error, positions))
            {
                return new LayoutResultDto { Error = error };
            }

            List<LayoutElementDto> elements = targets
                .SelectMany(diagram => diagram.Borders.Values.OfType<DrawingElement>())
                .Select(element => new LayoutElementDto
                {
                    Id = originalIds[element.Guid],
                    X = element.Left,
                    Y = element.Top,
                    Width = element.Width,
                    Height = element.Height,
                })
                .ToList();
            return new LayoutResultDto
            {
                Success = true,
                Elements = elements,
                Pages = targets.Count,
                Components = targets.Sum(diagram => diagram.Borders.Values.OfType<DrawingElement>().Count(element => element is not BorderBoundary)),
                LabelOverlaps = targets.Sum(diagram => DiagramLabels.Inspect(diagram, request.Options).Count),
            };
        }

        private static TmForgeModelDto LayoutStructure(TmForgeModelDto model)
        {
            IReadOnlyList<TmForgeElementDto>? Elements(IReadOnlyList<TmForgeElementDto>? elements) => elements?.Select(element => new TmForgeElementDto
            {
                Id = element.Id, Kind = element.Kind, Name = element.Name,
                X = element.X, Y = element.Y, Width = element.Width, Height = element.Height,
            }).ToArray();
            IReadOnlyList<TmForgeFlowDto>? Flows(IReadOnlyList<TmForgeFlowDto>? flows) => flows?.Select(flow => new TmForgeFlowDto
            {
                Id = flow.Id, Source = flow.Source, Target = flow.Target, Name = flow.Name,
            }).ToArray();
            bool paged = model.Diagrams is { Count: > 0 };
            return new TmForgeModelDto
            {
                Elements = paged ? null : Elements(model.Elements),
                Flows = paged ? null : Flows(model.Flows),
                Diagrams = paged ? model.Diagrams!.Select(page => new TmForgeDiagramDto
                {
                    Id = page.Id, Name = page.Name, Elements = Elements(page.Elements), Flows = Flows(page.Flows),
                }).ToArray() : null,
            };
        }

        private static string? ValidateLayoutInput(LayoutRequestDto request)
        {
            if (request.Model == null)
            {
                return "A model is required for arrangement.";
            }

            TmForgeModelDto model = request.Model;
            IReadOnlyList<TmForgeDiagramDto> pages = model.Diagrams is { Count: > 0 }
                ? model.Diagrams
                : new[] { new TmForgeDiagramDto { Elements = model.Elements, Flows = model.Flows } };
            if (pages.Count > LayoutOperations.MaximumPages
                || pages.Sum(page => (long)(page?.Elements?.Count ?? 0)) > LayoutOperations.MaximumElements
                || pages.Sum(page => (long)(page?.Flows?.Count ?? 0)) > LayoutOperations.MaximumLines)
            {
                return $"Arrangement is limited to {LayoutOperations.MaximumPages} pages, {LayoutOperations.MaximumElements} shapes and {LayoutOperations.MaximumLines} lines per request.";
            }

            HashSet<string> ids = new HashSet<string>(StringComparer.Ordinal);
            HashSet<string> pageIds = new HashSet<string>(StringComparer.Ordinal);
            HashSet<Guid> elementKeys = new HashSet<Guid>();
            HashSet<Guid> pageKeys = new HashSet<Guid>();
            foreach (TmForgeDiagramDto page in pages)
            {
                if (page == null || (model.Diagrams is { Count: > 0 }
                    && (string.IsNullOrWhiteSpace(page.Id) || page.Id.Length > 256 || page.Name?.Length > 4096 || !pageIds.Add(page.Id)
                        || !pageKeys.Add(Guid.TryParse(page.Id, out Guid pageId) ? pageId : DeterministicGuid.FromPageId(page.Id)))))
                {
                    return "Arrangement requires unique non-empty page ids.";
                }

                HashSet<string> endpoints = new HashSet<string>(StringComparer.Ordinal);
                foreach (TmForgeElementDto element in page.Elements ?? Array.Empty<TmForgeElementDto>())
                {
                    if (element == null || string.IsNullOrWhiteSpace(element.Id) || element.Id.Length > 256 || !ids.Add(element.Id)
                        || !elementKeys.Add(Guid.TryParse(element.Id, out Guid id) ? id : DeterministicGuid.FromElementId(element.Id)))
                    {
                        return "Arrangement requires unique non-empty element and flow ids.";
                    }

                    if ((element.Kind != "process" && element.Kind != "external" && element.Kind != "datastore" && element.Kind != "boundary")
                        || element.Width.HasValue != element.Height.HasValue
                        || element.Width < 20 || element.Height < 20 || element.Name?.Length > 4096)
                    {
                        return "Arrangement requires supported element kinds and either omitted sizes or width and height of at least 20.";
                    }

                    endpoints.Add(element.Id);
                }

                foreach (TmForgeFlowDto flow in page.Flows ?? Array.Empty<TmForgeFlowDto>())
                {
                    if (flow == null)
                    {
                        return "Arrangement found a null flow entry. No pages were changed.";
                    }

                    if (string.IsNullOrWhiteSpace(flow.Id) || flow.Id.Length > 256)
                    {
                        return "Arrangement requires a non-empty id of at most 256 characters for every flow. No pages were changed.";
                    }

                    if (flow.Name?.Length > 4096)
                    {
                        return $"Flow '{flow.Id}' has a label longer than 4096 characters. No pages were changed.";
                    }

                    string description = string.IsNullOrWhiteSpace(flow.Name) ? $"Flow '{flow.Id}'" : $"Flow '{flow.Name}' ({flow.Id})";
                    if (!ids.Add(flow.Id))
                    {
                        return description + " has a duplicate id shared with another element or flow. No pages were changed.";
                    }

                    if (!elementKeys.Add(Guid.TryParse(flow.Id, out Guid id) ? id : DeterministicGuid.FromElementId(flow.Id)))
                    {
                        return description + " resolves to the same internal GUID as another element or flow. No pages were changed.";
                    }

                    if (!endpoints.Contains(flow.Source))
                    {
                        return LayoutEndpointError(description, "source", flow.Source);
                    }

                    if (!endpoints.Contains(flow.Target))
                    {
                        return LayoutEndpointError(description, "target", flow.Target);
                    }
                }
            }

            if (pageKeys.Overlaps(elementKeys))
            {
                return "A page and an element cannot use the same internal GUID for arrangement.";
            }

            if (request.Positions != null && (request.Positions.Count > LayoutOperations.MaximumElements
                || request.Positions.Any(position => position == null || string.IsNullOrWhiteSpace(position.Id)
                    || position.Id.Length > 256 || position.Width < 20 || position.Height < 20)))
            {
                return "Proposed positions require valid element ids and sizes of at least 20.";
            }

            return null;
        }

        private static string LayoutEndpointError(string flow, string endpoint, string? id)
        {
            if (id?.Length > 256)
            {
                return flow + $" has a {endpoint} endpoint id longer than 256 characters. No pages were changed.";
            }

            bool unattached = string.IsNullOrWhiteSpace(id) || (Guid.TryParse(id, out Guid parsed) && parsed == Guid.Empty);
            string problem = unattached
                ? $" has an unattached {endpoint} endpoint ('{id}')."
                : $" references {endpoint} element '{id}', which is not present on this page.";
            return flow + problem + " Reconnect that endpoint to an element before arranging. No pages were changed.";
        }

        /// <summary>
        /// The one place the effective rule set is evaluated for an analysis action. It builds the model
        /// once, loads the effective bundle once, evaluates every enabled rule once, and then projects
        /// only what the caller asked for from the collected messages — so requesting findings and
        /// threats together costs one evaluation, and requesting one never materializes the other.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <param name="projections">The projections to materialize.</param>
        /// <param name="evidence">Receives the persistable evidence when that projection is requested.</param>
        /// <param name="onRuleSet">Invoked with the effective rule set once the selection has been applied.</param>
        /// <returns>The requested projections, the effective custom packs, and any load diagnostics.</returns>
        private static AnalysisResultDto RunAnalysis(
            TmForgeModelDto dto,
            EngineRuleOptions? rules,
            AnalysisProjection projections,
            List<AnalysisFindingDto>? evidence = null,
            Action<RuleSet>? onRuleSet = null,
            Action<ThreatRegisterSummary>? onRegister = null)
        {
            bool wantFindings = (projections & AnalysisProjection.Findings) != 0;
            bool wantThreats = (projections & AnalysisProjection.Threats) != 0;
            bool wantEvidence = (projections & AnalysisProjection.Evidence) != 0 && evidence != null;
            bool wantRegister = (projections & AnalysisProjection.Register) != 0 && onRegister != null;
            List<FindingDto> findings = new List<FindingDto>();
            List<ThreatDto> threats = new List<ThreatDto>();
            List<string> diagnostics = new List<string>();
            IReadOnlyList<RulePackInfoDto> effectivePacks = Array.Empty<RulePackInfoDto>();
            try
            {
                ThreatModel model = BuildModel(
                    dto,
                    out Dictionary<string, List<string>> nameToIds,
                    out Dictionary<Guid, string> originalIds);
                using (RuleSet ruleSet = LoadRuleSet(rules, diagnostics, out IReadOnlyList<RulePackDefinition> packs))
                {
                    effectivePacks = MapRulePacks(packs, ruleSet);
                    if (wantFindings || wantEvidence)
                    {
                        IReadOnlyList<FindingDto> mismatches =
                            VerifyExpectedPacks(dto.Analysis?.ExpectedPacks, effectivePacks);
                        if (wantFindings)
                        {
                            findings.AddRange(mismatches);
                        }

                        // A pack mismatch is a problem with the analysis rather than a risk in the
                        // model, so it is recorded as hygiene: it must not land in the threat register.
                        foreach (FindingDto mismatch in mismatches)
                        {
                            evidence!.Add(new AnalysisFindingDto
                            {
                                Id = mismatch.Id,
                                RuleId = mismatch.RuleId ?? string.Empty,
                                Severity = mismatch.Severity,
                                Message = mismatch.Message,
                                Disposition = FindingDispositions.Hygiene,
                            });
                        }
                    }

                    if (dto.Analysis != null)
                    {
                        ruleSet.Disable(dto.Analysis.DisabledPacks, dto.Analysis.DisabledRuleIds);
                    }

                    // Provenance is taken from the effective catalog, after selection, so it records
                    // the rules that actually ran rather than the ones that were offered.
                    onRuleSet?.Invoke(ruleSet);

                    // One evaluation, one shared operation budget, every projection. Detection happens
                    // here and nowhere else; findings, threats, and evidence differ only in lifecycle.
                    CollectingMessageWriter writer = new CollectingMessageWriter();
                    RuleEvaluationContext context = new RuleEvaluationContext(model, writer);
                    ruleSet.Evaluate(context);

                    if (wantFindings)
                    {
                        ProjectFindings(writer.Messages, originalIds, nameToIds, findings);
                    }

                    if (wantThreats)
                    {
                        ProjectThreats(writer.Messages, dto, nameToIds, threats, diagnostics);
                    }

                    if (wantEvidence)
                    {
                        ProjectEvidence(writer.Messages, dto, originalIds, nameToIds, evidence!);
                    }

                    if (wantRegister)
                    {
                        // Projected from the same messages, so the register is classified against the
                        // very run it is being compared to rather than a second evaluation.
                        onRegister!(ThreatRegisterClassifier.Classify(
                            model,
                            ThreatGenerator.Project(writer.Messages),
                            ruleSet));
                    }
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex) when (ex is not OutOfMemoryException && ex is not StackOverflowException)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                // One failure, reported once in each projection the caller is actually reading.
                if (wantFindings)
                {
                    findings.Add(new FindingDto
                    {
                        Id = "engine-error",
                        Severity = "warning",
                        Message = $"Engine analysis failed: {ex.Message}",
                    });
                }

                if (wantThreats)
                {
                    threats.Add(new ThreatDto
                    {
                        Id = "engine-error",
                        Severity = "error",
                        Title = $"Threat generation failed: {ex.Message}",
                    });
                }

                if (wantEvidence)
                {
                    evidence!.Add(new AnalysisFindingDto
                    {
                        Id = "engine-error",
                        RuleId = "engine-error",
                        Severity = "warning",
                        Message = $"Engine analysis failed: {ex.Message}",
                        Disposition = FindingDispositions.Hygiene,
                    });
                }
            }

            return new AnalysisResultDto
            {
                Findings = findings,
                Threats = threats,
                RulePacks = effectivePacks,
                Diagnostics = diagnostics,
            };
        }

        /// <summary>
        /// Evaluates the effective rule set once and captures the run as a <see cref="ModelReport"/> —
        /// the same structure the CLI serializes to SARIF, findings HTML, and findings JSON. It goes
        /// through the same bundle load and disabled-selection policy as every other analysis action,
        /// so a report can never disagree with the analysis it claims to describe.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <param name="sourceName">The logical model name recorded as the report's source.</param>
        /// <returns>The analysis report.</returns>
        private static ModelReport BuildAnalysisReport(TmForgeModelDto dto, EngineRuleOptions? rules, string sourceName)
        {
            ThreatModel model = BuildModel(dto, out _);
            using (RuleSet ruleSet = LoadRuleSet(rules, null, out _))
            {
                if (dto.Analysis != null)
                {
                    ruleSet.Disable(dto.Analysis.DisabledPacks, dto.Analysis.DisabledRuleIds);
                }

                CollectingMessageWriter writer = new CollectingMessageWriter();
                RuleEvaluationContext context = new RuleEvaluationContext(model, writer, null, sourceName);
                ruleSet.Evaluate(context);
                return context.GenerateReport(ruleSet);
            }
        }

        /// <summary>
        /// Names the analyzed document. The engine has no filesystem path, but SARIF and the findings
        /// documents identify what was analyzed, so derive a stable logical name from the model. The
        /// model's own metadata name still wins in the report; this only fills the artifact location.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <returns>The logical source name, without an extension.</returns>
        private static string AnalysisReportName(TmForgeModelDto dto)
        {
            string? name = dto?.Diagrams?.FirstOrDefault()?.Name;
            if (string.IsNullOrWhiteSpace(name))
            {
                return "model";
            }

            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder builder = new StringBuilder(name!.Length);
            foreach (char character in name!)
            {
                builder.Append(Array.IndexOf(invalid, character) >= 0 ? '_' : character);
            }

            return builder.ToString();
        }

        /// <summary>Projects every collected message as a transient finding.</summary>
        /// <param name="messages">The messages from one rule-set evaluation.</param>
        /// <param name="originalIds">The map from model guid to the caller's element id.</param>
        /// <param name="nameToIds">The map from element name to the caller's element ids.</param>
        /// <param name="findings">The list that receives the findings.</param>
        private static void ProjectFindings(
            IReadOnlyList<Message> messages,
            Dictionary<Guid, string> originalIds,
            Dictionary<string, List<string>> nameToIds,
            List<FindingDto> findings)
        {
            FindingIdentity identity = new FindingIdentity();
            foreach (Message message in messages)
            {
                string ruleId = message.Source?.ID ?? string.Empty;
                IReadOnlyList<string> elementIds = ResolveIds(message.Target, originalIds, nameToIds);
                findings.Add(new FindingDto
                {
                    Id = identity.Next(
                        ruleId,
                        StableKey(message.Model?.Guid, originalIds),
                        TargetKey(message.Target, elementIds)),
                    Severity = MapSeverity(message.Severity),
                    RuleId = ruleId,
                    Message = message.Text ?? string.Empty,
                    ElementIds = elementIds,
                });
            }
        }

        /// <summary>
        /// Projects every collected message as persistable evidence: the finding, its stable identity,
        /// the structural conclusion drawn about it, and the threat it feeds when it is threat-bearing.
        /// </summary>
        /// <remarks>
        /// A finding is threat-bearing exactly when its rule declares a threat category and it names a
        /// target — the same test <see cref="ThreatGenerator.Project(IEnumerable{Message})"/> applies —
        /// and the register id is computed with the same formula, so the two always agree. Everything
        /// else is hygiene and stays a finding, which is the point: a reviewer should not have to
        /// accept "this diagram has no trust boundary" as a risk in order to clear a gate.
        /// </remarks>
        /// <param name="messages">The messages from one rule-set evaluation.</param>
        /// <param name="dto">The canonical model, which carries the author's triage.</param>
        /// <param name="originalIds">The map from model guid to the caller's element id.</param>
        /// <param name="nameToIds">The map from element name to the caller's element ids.</param>
        /// <param name="evidence">The list that receives the evidence.</param>
        private static void ProjectEvidence(
            IReadOnlyList<Message> messages,
            TmForgeModelDto dto,
            Dictionary<Guid, string> originalIds,
            Dictionary<string, List<string>> nameToIds,
            List<AnalysisFindingDto> evidence)
        {
            Dictionary<string, ThreatStateDto> overlay = BuildTriage(dto.Threats);
            FindingIdentity identity = new FindingIdentity();
            foreach (Message message in messages)
            {
                Rule? rule = message.Source;
                string ruleId = rule?.ID ?? string.Empty;
                IReadOnlyList<string> elementIds = ResolveIds(message.Target, originalIds, nameToIds);
                string? diagramKey = StableKey(message.Model?.Guid, originalIds);

                string? threatId = null;
                if (rule?.ThreatCategory != null && message.Target != null)
                {
                    threatId = string.Format(
                        CultureInfo.InvariantCulture,
                        "{0:N}:{1}",
                        message.Target.Guid,
                        ruleId);
                }

                evidence.Add(new AnalysisFindingDto
                {
                    Id = identity.Next(ruleId, diagramKey, TargetKey(message.Target, elementIds)),
                    RuleId = ruleId,
                    Severity = MapSeverity(message.Severity),
                    Message = message.Text ?? string.Empty,
                    Diagram = diagramKey,
                    ElementIds = elementIds,
                    Disposition = FindingDispositions.Classify(false, threatId, Triage(threatId, overlay)),
                    ThreatId = threatId,
                });
            }
        }

        /// <summary>Reads the author's recorded state for a threat, if they recorded one.</summary>
        /// <param name="threatId">The register id, or <see langword="null"/>.</param>
        /// <param name="overlay">The author's triage, keyed by register id.</param>
        /// <returns>The recorded state, or <see langword="null"/>.</returns>
        private static string? Triage(string? threatId, IReadOnlyDictionary<string, ThreatStateDto> overlay)
        {
            return threatId != null && overlay.TryGetValue(threatId, out ThreatStateDto? state)
                ? state.State
                : null;
        }

        /// <summary>
        /// Resolves the caller-facing key for a model guid, falling back to the guid itself. The
        /// caller's own id is preferred because a model whose element ids are not guid-shaped is
        /// assigned fresh guids on every load, which would churn any identity built on them.
        /// </summary>
        /// <param name="guid">The internal guid, if any.</param>
        /// <param name="originalIds">The map from model guid to the caller's id.</param>
        /// <returns>The stable key, or <see langword="null"/> when there is nothing to key on.</returns>
        private static string? StableKey(Guid? guid, IReadOnlyDictionary<Guid, string> originalIds)
        {
            if (guid == null)
            {
                return null;
            }

            return originalIds.TryGetValue(guid.Value, out string? original)
                ? original
                : guid.Value.ToString("N");
        }

        /// <summary>
        /// Resolves the key for a finding's target, reusing the ids already reported to the caller so
        /// the identity and the highlight refer to the same element.
        /// </summary>
        /// <param name="target">The target entity, if any.</param>
        /// <param name="elementIds">The caller-facing ids resolved for that target.</param>
        /// <returns>The stable key, or <see langword="null"/> for a finding with no target.</returns>
        private static string? TargetKey(Entity? target, IReadOnlyList<string> elementIds)
        {
            if (target == null)
            {
                return null;
            }

            return elementIds.Count == 1 ? elementIds[0] : target.Guid.ToString("N");
        }

        /// <summary>
        /// Projects the messages whose rule declares a threat category as lifecycle-bearing threats,
        /// then layers the author's triage and appends the model's manually authored threats.
        /// </summary>
        /// <param name="messages">The messages from one rule-set evaluation.</param>
        /// <param name="dto">The canonical model, which carries the author overlay.</param>
        /// <param name="nameToIds">The map from element name to the caller's element ids.</param>
        /// <param name="threats">The list that receives the threats.</param>
        private static void ProjectThreats(
            IReadOnlyList<Message> messages,
            TmForgeModelDto dto,
            Dictionary<string, List<string>> nameToIds,
            List<ThreatDto> threats,
            ICollection<string>? diagnostics)
        {
            GenerationResult generation = ThreatGenerator.Project(messages);
            Dictionary<string, ThreatStateDto> overlay = BuildTriage(dto.Threats);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (GeneratedThreat threat in generation.Threats)
            {
                overlay.TryGetValue(threat.Id, out ThreatStateDto? edit);
                seen.Add(threat.Id);
                threats.Add(new ThreatDto
                {
                    Id = threat.Id,
                    RuleId = threat.RuleId,
                    Category = threat.Stride?.ToString() ?? threat.ThreatCategory.Name,
                    CategoryId = threat.ThreatCategory.Id,
                    CategoryName = threat.ThreatCategory.Name,
                    Stride = threat.Stride?.ToString(),
                    Title = string.IsNullOrEmpty(edit?.Title) ? threat.Title : edit!.Title!,
                    Mitigation = string.IsNullOrEmpty(edit?.Mitigation) ? threat.Mitigation : edit!.Mitigation,
                    Description = edit?.Description,
                    Severity = threat.Severity,
                    Priority = string.IsNullOrEmpty(edit?.Priority) ? threat.Priority : edit!.Priority,
                    References = threat.References.Select(r => r.Id).ToList(),
                    ElementIds = BuildElementIds(threat),
                    Interaction = threat.InteractionString,
                    State = NormalizeState(edit?.State),
                    Justification = edit?.Justification,
                    Manual = false,
                });
            }

            AppendManualThreats(threats, dto.Threats, seen, nameToIds, diagnostics);
        }

        private static IReadOnlyList<string> BuildElementIds(GeneratedThreat threat)
        {
            List<string> ids = new List<string> { threat.SourceGuid.ToString() };
            if (threat.IsFlowScoped)
            {
                ids.Add(threat.TargetGuid.ToString());
                ids.Add(threat.FlowGuid.ToString());
            }

            return ids;
        }

        private static Dictionary<string, ThreatStateDto> BuildTriage(IReadOnlyList<ThreatStateDto>? states)
        {
            Dictionary<string, ThreatStateDto> map = new Dictionary<string, ThreatStateDto>(StringComparer.OrdinalIgnoreCase);
            if (states != null)
            {
                foreach (ThreatStateDto state in states.Where(state => !string.IsNullOrEmpty(state.Id)))
                {
                    map[state.Id!] = state;
                }
            }

            return map;
        }

        private static string NormalizeState(string? state) => ThreatStateWire.Canonical(state);

        private static void AppendManualThreats(
            List<ThreatDto> result,
            IReadOnlyList<ThreatStateDto>? overlay,
            HashSet<string> seen,
            Dictionary<string, List<string>> nameToIds,
            ICollection<string>? diagnostics)
        {
            if (overlay == null)
            {
                return;
            }

            Dictionary<string, string> idToName = InvertNames(nameToIds);
            foreach (ThreatStateDto entry in overlay)
            {
                if (entry.Manual != true)
                {
                    continue;
                }

                // An author-owned id is only useful if it is exactly what the author wrote and refers
                // to exactly one threat. A malformed or already-taken id is reported rather than
                // dropped, because a threat that silently fails to appear reads as no threat at all.
                if (!ManualThreatId.TryCanonicalize(entry.Id, out string id, out string? error))
                {
                    diagnostics?.Add($"Skipped a manual threat: {error}");
                    continue;
                }

                if (!seen.Add(id))
                {
                    diagnostics?.Add(
                        $"Skipped the manual threat '{id}': that id is already used by another threat in this model.");
                    continue;
                }

                IReadOnlyList<string> ids = entry.ElementIds ?? Array.Empty<string>();
                result.Add(new ThreatDto
                {
                    Id = id,
                    RuleId = string.Empty,
                    Category = entry.Category ?? string.Empty,
                    Title = entry.Title ?? string.Empty,
                    Mitigation = entry.Mitigation,
                    Description = entry.Description,
                    Severity = "warning",
                    Priority = string.IsNullOrEmpty(entry.Priority) ? "Medium" : entry.Priority!,
                    References = Array.Empty<string>(),
                    ElementIds = ids,
                    Interaction = DescribeScope(ids, idToName),
                    State = NormalizeState(entry.State),
                    Justification = entry.Justification,
                    Source = entry.Source,
                    Manual = true,
                });
            }
        }

        private static Dictionary<string, string> InvertNames(Dictionary<string, List<string>> nameToIds)
        {
            Dictionary<string, string> idToName = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, List<string>> pair in nameToIds)
            {
                foreach (string id in pair.Value)
                {
                    idToName[id] = pair.Key;
                }
            }

            return idToName;
        }

        private static string DescribeScope(IReadOnlyList<string> ids, Dictionary<string, string> idToName)
        {
            if (ids.Count == 0)
            {
                return "Model-wide";
            }

            if (ids.Count == 1)
            {
                return NameFor(ids[0], idToName);
            }

            return NameFor(ids[0], idToName) + " -> " + NameFor(ids[1], idToName);
        }

        private static string NameFor(string id, Dictionary<string, string> idToName)
            => idToName.TryGetValue(id, out string? name) ? name : id;

        /// <summary>
        /// Builds the model for a register-bearing export (for example, <c>.tm7</c>), materializing the
        /// full, titled threat register the CLI's <c>tmforge threats --write</c> produces and overlaying
        /// the model's acceptance triage. The canonical read seeds only a sparse (accepted-only) register
        /// from the wire overlay because the register is otherwise regenerable; for a lossless export we
        /// regenerate it in full so the file carries a complete, titled register — accepted risks keep
        /// their state and justification — for tools that consume it, such as the Microsoft Threat
        /// Modeling Tool.
        /// </summary>
        /// <param name="dto">The canonical model.</param>
        /// <param name="rules">The custom rule content to load, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The model with its threat register materialized and triaged.</returns>
        private static ThreatModel BuildModelForExport(TmForgeModelDto dto, EngineRuleOptions? rules)
        {
            ThreatModel model = BuildModel(dto, out _);

            // BuildModel (through the tmforge-json read) has seeded the durable overlay: manually
            // authored threats in full, plus edited rule threats as sparse patches. Drop the sparse
            // patches so the rules regenerate those threats with their full title and category, but keep
            // the manual threats (which no rule produces), then re-apply the author's edits on top so a
            // lossless export carries a complete, titled register with the author's state and edits.
            Dictionary<string, Threat> seeded = new Dictionary<string, Threat>(StringComparer.OrdinalIgnoreCase);
            List<string> ruleSeeded = model.AllThreatsDictionary.Keys
                .Where(key => !ThreatStateWire.IsManualKey(key))
                .ToList();
            foreach (string key in ruleSeeded)
            {
                seeded[key] = model.AllThreatsDictionary[key];
                model.AllThreatsDictionary.Remove(key);
            }

            using (RuleSet ruleSet = LoadRuleSet(rules, null, out _))
            {
                if (dto.Analysis != null)
                {
                    ruleSet.Disable(dto.Analysis.DisabledPacks, dto.Analysis.DisabledRuleIds);
                }

                GenerationResult generation = ThreatGenerator.Generate(model, ruleSet);
                ThreatGenerator.Apply(model, generation);
            }

            RestoreUnregeneratedEntries(model, seeded);
            ApplyOverlayEdits(model, dto.Threats);
            return model;
        }

        /// <summary>
        /// Puts back any seeded entry the rules did not regenerate.
        /// </summary>
        /// <remarks>
        /// A rule-derived entry only reaches the overlay because someone triaged, described, or
        /// re-prioritized it, so every one carries author intent. Dropping the sparse patch is safe when
        /// the rule regenerates the threat, and only then: if the rule has fallen silent there is
        /// nothing to regenerate, and leaving it out would delete the decision along with the finding.
        /// The entry keeps its rule id, so it is reported as stale rather than reappearing as manual.
        /// </remarks>
        /// <param name="model">The regenerated model.</param>
        /// <param name="seeded">The entries removed before regeneration, keyed by register key.</param>
        private static void RestoreUnregeneratedEntries(ThreatModel model, Dictionary<string, Threat> seeded)
        {
            int nextId = model.AllThreatsDictionary.Values.Count == 0
                ? 1
                : model.AllThreatsDictionary.Values.Max(threat => threat.Id) + 1;
            foreach (KeyValuePair<string, Threat> pair in seeded)
            {
                if (model.AllThreatsDictionary.ContainsKey(pair.Key))
                {
                    continue;
                }

                // Renumber so the restored entry cannot collide with one the regeneration just assigned.
                pair.Value.Id = nextId++;
                model.AllThreatsDictionary[pair.Key] = pair.Value;
            }
        }

        /// <summary>
        /// Re-applies the author overlay to the freshly generated register: for each edited rule threat
        /// it layers the author's state, justification, priority, title, description, and mitigation on
        /// top of the rule-generated threat. Manual threats are already materialized by the tmforge-json
        /// read and are left untouched here.
        /// </summary>
        /// <param name="model">The model whose register is edited.</param>
        /// <param name="overlay">The author overlay from the document.</param>
        private static void ApplyOverlayEdits(ThreatModel model, IReadOnlyList<ThreatStateDto>? overlay)
        {
            foreach (ThreatStateDto entry in overlay ?? Array.Empty<ThreatStateDto>())
            {
                if (string.IsNullOrEmpty(entry.Id) ||
                    entry.Manual == true ||
                    !model.AllThreatsDictionary.TryGetValue(entry.Id, out Threat? threat))
                {
                    continue;
                }

                threat.State = ThreatStateWire.Parse(entry.State);
                if (!string.IsNullOrEmpty(entry.Justification))
                {
                    threat.StateInformation = entry.Justification;
                }

                if (!string.IsNullOrEmpty(entry.Priority))
                {
                    threat.Priority = entry.Priority;
                    threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    threat.Properties["PriorityOverride"] = "true";
                }

                if (!string.IsNullOrEmpty(entry.Title))
                {
                    threat.Title = entry.Title;
                    threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    threat.Properties["TitleOverride"] = "true";
                }

                if (!string.IsNullOrEmpty(entry.Description))
                {
                    threat.UserThreatDescription = entry.Description;
                }

                if (!string.IsNullOrEmpty(entry.Mitigation))
                {
                    threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    threat.Properties["Mitigation"] = entry.Mitigation!;
                }

                threat.ModifiedAt = DateTime.UtcNow;
            }
        }

        private static ThreatModel BuildModel(TmForgeModelDto dto, out Dictionary<string, List<string>> nameToIds)
        {
            return BuildModel(dto, out nameToIds, out _);
        }

        private static ThreatModel BuildModel(
            TmForgeModelDto dto,
            out Dictionary<string, List<string>> nameToIds,
            out Dictionary<Guid, string> originalIds)
        {
            nameToIds = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            originalIds = new Dictionary<Guid, string>();

            // For a multi-page model the top-level elements/flows mirror the first page, so index the
            // pages when present (and only then) to avoid double-counting page one.
            if (dto.Diagrams != null && dto.Diagrams.Count > 0)
            {
                foreach (TmForgeDiagramDto page in dto.Diagrams)
                {
                    foreach (TmForgeElementDto element in page.Elements ?? Array.Empty<TmForgeElementDto>())
                    {
                        AddName(nameToIds, element.Name, element.Id);
                    }

                    foreach (TmForgeFlowDto flow in page.Flows ?? Array.Empty<TmForgeFlowDto>())
                    {
                        AddName(nameToIds, flow.Name, flow.Id);
                    }
                }
            }
            else
            {
                foreach (TmForgeElementDto element in dto.Elements ?? Array.Empty<TmForgeElementDto>())
                {
                    AddName(nameToIds, element.Name, element.Id);
                }

                foreach (TmForgeFlowDto flow in dto.Flows ?? Array.Empty<TmForgeFlowDto>())
                {
                    AddName(nameToIds, flow.Name, flow.Id);
                }
            }

            // Build the engine model through the canonical tmforge-json format provider so the
            // DTO -> ThreatModel mapping (including custom properties) lives in exactly one place.
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(dto, CanonicalJsonOptions);
            using (MemoryStream stream = new MemoryStream(json))
            {
                return TmForgeJsonFormat.ReadWithOriginalIds(stream, originalIds);
            }
        }

        private static TmForgeModelDto ToDto(ThreatModel model)
        {
            using (MemoryStream output = new MemoryStream())
            {
                new TmForgeJsonFormat().Write(model, output);
                return JsonSerializer.Deserialize<TmForgeModelDto>(output.ToArray(), CanonicalJsonOptions)
                    ?? new TmForgeModelDto();
            }
        }

        private static void AddName(Dictionary<string, List<string>> map, string? name, string id)
        {
            if (string.IsNullOrEmpty(name))
            {
                return;
            }

            if (!map.TryGetValue(name!, out List<string>? ids))
            {
                ids = new List<string>();
                map[name!] = ids;
            }

            ids.Add(id);
        }

        private static IReadOnlyList<string> ResolveIds(
            Entity? target,
            IReadOnlyDictionary<Guid, string> originalIds,
            IReadOnlyDictionary<string, List<string>> nameToIds)
        {
            if (target == null)
            {
                return Array.Empty<string>();
            }

            if (originalIds.TryGetValue(target.Guid, out string? originalId))
            {
                return new[] { originalId };
            }

            string name = DiagramElementHelper.GetName(target);
            return nameToIds.TryGetValue(name, out List<string>? ids) && ids.Count == 1
                ? new[] { ids[0] }
                : Array.Empty<string>();
        }

        /// <summary>
        /// Loads the effective rule set: the built-in rules plus any custom packs supplied as content.
        /// This is the single seam every rule-reading engine operation goes through, so one selection
        /// yields one effective bundle across catalogs, findings, threats, reports, and exports.
        /// </summary>
        /// <param name="rules">The custom rule content, or <see langword="null"/> for built-in rules only.</param>
        /// <param name="diagnostics">An optional sink that collects non-fatal load warnings.</param>
        /// <param name="packs">On return, the custom packs that contributed rules.</param>
        /// <returns>The effective rule set. The caller owns and disposes it.</returns>
        private static RuleSet LoadRuleSet(
            EngineRuleOptions? rules,
            ICollection<string>? diagnostics,
            out IReadOnlyList<RulePackDefinition> packs)
        {
            List<RuleContent> contents = new List<RuleContent>();
            foreach (RuleSourceDto source in rules?.Sources ?? Array.Empty<RuleSourceDto>())
            {
                if (source == null || string.IsNullOrWhiteSpace(source.Json))
                {
                    diagnostics?.Add($"Skipped rule source '{source?.Name ?? "(unnamed)"}': content is empty.");
                    continue;
                }

                string name = string.IsNullOrWhiteSpace(source.Name) ? "rules.tmrules.json" : source.Name!;
                contents.Add(RuleContent.FromJson(name, source.Json!));
            }

            Action<string>? sink = diagnostics == null ? null : new Action<string>(diagnostics.Add);
            RuleSourceOptions options = new RuleSourceOptions(null, sink, contents);
            return AnalysisRuleSources.Create(options, out packs);
        }

        private static IReadOnlyList<RulePackDto> MapRulePackCatalog(IReadOnlyList<RulePackDefinition> packs, RuleSet ruleSet)
        {
            Dictionary<string, int> counts = new Dictionary<string, int>(StringComparer.Ordinal);
            Dictionary<string, string> customNames = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (Rule rule in ruleSet.Rules)
            {
                counts[rule.Pack] = counts.TryGetValue(rule.Pack, out int existing) ? existing + 1 : 1;
            }

            foreach (RulePackDefinition pack in packs)
            {
                customNames[pack.Id] = pack.Name;
            }

            List<RulePackDto> result = new List<RulePackDto>();
            foreach (KeyValuePair<string, string> pack in RulePackCatalog.Ordered)
            {
                bool found = counts.TryGetValue(pack.Key, out int known);
                if (found)
                {
                    result.Add(new RulePackDto { Id = pack.Key, Name = pack.Value, Count = known });
                    counts.Remove(pack.Key);
                }
            }

            List<string> remaining = new List<string>(counts.Keys);
            remaining.Sort(StringComparer.Ordinal);
            foreach (string packId in remaining)
            {
                string name = customNames.TryGetValue(packId, out string? custom)
                    ? custom
                    : RulePackCatalog.DisplayName(packId);
                result.Add(new RulePackDto { Id = packId, Name = name, Count = counts[packId] });
            }

            return result;
        }

        /// <summary>
        /// Describes the custom packs that contributed rules, with the rule count each pack added, so a
        /// caller sees the identity and content fingerprint of the rules that actually ran.
        /// </summary>
        /// <param name="packs">The loaded pack definitions.</param>
        /// <param name="ruleSet">The effective rule set.</param>
        /// <returns>The effective pack descriptions, ordered by id.</returns>
        private static IReadOnlyList<RulePackInfoDto> MapRulePacks(
            IReadOnlyList<RulePackDefinition> packs,
            RuleSet ruleSet)
        {
            if (packs.Count == 0)
            {
                return Array.Empty<RulePackInfoDto>();
            }

            Dictionary<string, int> counts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (Rule rule in ruleSet.Rules)
            {
                RulePackDefinition? definition = rule.PackDefinition;
                if (definition != null)
                {
                    counts[definition.Id] = counts.TryGetValue(definition.Id, out int existing) ? existing + 1 : 1;
                }
            }

            return packs
                .Select(pack => new RulePackInfoDto
                {
                    Id = pack.Id,
                    Name = pack.Name,
                    Version = pack.Version,
                    Fingerprint = pack.Fingerprint,
                    Dialect = pack.Dialect,
                    RuleCount = counts.TryGetValue(pack.Id, out int count) ? count : 0,
                })
                .OrderBy(pack => pack.Id, StringComparer.Ordinal)
                .ToList();
        }

        /// <summary>
        /// Compares the packs the model expects against the packs that actually loaded. A missing pack or
        /// a changed fingerprint is reported as an error finding, so analyzing against different rules is
        /// visible in every surface that shows findings and fails a build that gates on errors.
        /// </summary>
        /// <param name="expected">The expected packs recorded with the model, if any.</param>
        /// <param name="effective">The packs that contributed rules to this run.</param>
        /// <returns>One finding per unmet expectation.</returns>
        private static IReadOnlyList<FindingDto> VerifyExpectedPacks(
            IReadOnlyList<ExpectedRulePackDto>? expected,
            IReadOnlyList<RulePackInfoDto> effective)
        {
            if (expected == null || expected.Count == 0)
            {
                return Array.Empty<FindingDto>();
            }

            Dictionary<string, RulePackInfoDto> loaded = new Dictionary<string, RulePackInfoDto>(StringComparer.Ordinal);
            foreach (RulePackInfoDto pack in effective)
            {
                loaded[pack.Id] = pack;
            }

            List<FindingDto> findings = new List<FindingDto>();
            foreach (ExpectedRulePackDto entry in expected)
            {
                if (entry == null || string.IsNullOrWhiteSpace(entry.Id))
                {
                    continue;
                }

                if (!loaded.TryGetValue(entry.Id!, out RulePackInfoDto? pack))
                {
                    findings.Add(new FindingDto
                    {
                        Id = FindingIdentity.Format(RulePackMismatchRuleId, null, entry.Id, 0),
                        Severity = "error",
                        RuleId = RulePackMismatchRuleId,
                        Message = $"Expected rule pack '{entry.Id}' did not load, so this model was analyzed without it.",
                    });
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(entry.Fingerprint) &&
                    !string.Equals(entry.Fingerprint, pack.Fingerprint, StringComparison.Ordinal))
                {
                    findings.Add(new FindingDto
                    {
                        Id = FindingIdentity.Format(RulePackMismatchRuleId, null, entry.Id, 0),
                        Severity = "error",
                        RuleId = RulePackMismatchRuleId,
                        Message =
                            $"Rule pack '{entry.Id}' content changed: expected fingerprint '{entry.Fingerprint}' but loaded '{pack.Fingerprint}'.",
                    });
                }
            }

            return findings;
        }

        private static string MapSeverity(MessageSeverity severity)
        {
            switch (severity)
            {
                case MessageSeverity.Error:
                    return "error";
                case MessageSeverity.Warning:
                    return "warning";
                default:
                    return "info";
            }
        }

        private static FormatDto MapFormat(IThreatModelFormat format)
        {
            return new FormatDto
            {
                Id = format.Id,
                DisplayName = format.DisplayName,
                Extensions = format.Extensions,
                CanRead = format.Capabilities.CanRead,
                CanWrite = format.Capabilities.CanWrite,
            };
        }
    }
}
