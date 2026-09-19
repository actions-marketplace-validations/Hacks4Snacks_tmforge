namespace ThreatModelForge.Wasm
{
    using System;
    using System.Runtime.InteropServices.JavaScript;
    using System.Text.Json;
    using ThreatModelForge.Engine;

    /// <summary>
    /// The in-browser engine interop surface. These <c>[JSExport]</c> methods are a thin marshaling
    /// shim over the shared <see cref="EngineService"/> — the SAME facade the <c>/v1</c> API calls — so
    /// the browser runs identical engine logic with no network. tmforge-json crosses the JS boundary as
    /// a string; binary documents (<c>.tm7</c>, <c>.drawio</c>, <c>.vsdx</c>, reports) as base64.
    /// </summary>
    public static partial class Engine
    {
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
        };

        private static EngineRuleOptions ruleOptions = new EngineRuleOptions();

        /// <summary>Sanity check that the module loaded and interop works.</summary>
        /// <returns>The engine runtime banner.</returns>
        [JSExport]
        public static string Ping()
            => $".NET {Environment.Version} WASM engine ready";

        /// <summary>
        /// Selects the custom rule packs this engine instance runs, and reports what actually loaded.
        /// The selection persists until it is replaced, so every later call — catalogs, analysis, threat
        /// generation, reports, and exports — uses one effective bundle, exactly as a configured API
        /// host does.
        /// </summary>
        /// <param name="sourcesJson">A JSON array of <c>{ name, json }</c> rule packs, or an empty string to clear.</param>
        /// <returns>The loaded packs and diagnostics as JSON (the /v1 RuleBundleDto shape).</returns>
        [JSExport]
        public static string SetRules(string sourcesJson)
        {
            if (string.IsNullOrWhiteSpace(sourcesJson))
            {
                ruleOptions = new EngineRuleOptions();
                return Serialize(EngineService.DescribeRules(ruleOptions));
            }

            RuleSourceDto[] sources = JsonSerializer.Deserialize<RuleSourceDto[]>(sourcesJson, JsonOptions)
                ?? Array.Empty<RuleSourceDto>();
            ruleOptions = new EngineRuleOptions { Sources = sources };
            return Serialize(EngineService.DescribeRules(ruleOptions));
        }

        /// <summary>Describes the custom rule packs this engine instance currently runs.</summary>
        /// <returns>The loaded packs and diagnostics as JSON (the /v1 RuleBundleDto shape).</returns>
        [JSExport]
        public static string RuleBundle()
            => Serialize(EngineService.DescribeRules(ruleOptions));

        /// <summary>Lists the registered file formats and their capabilities.</summary>
        /// <returns>The formats as a JSON array.</returns>
        [JSExport]
        public static string Formats()
            => Serialize(EngineService.GetFormats());

        /// <summary>Lists the authoring stencil catalog offered to the palette.</summary>
        /// <returns>The stencils as a JSON array.</returns>
        [JSExport]
        public static string Stencils()
            => Serialize(EngineService.GetStencils());

        /// <summary>Lists the stencil packs offered to the palette.</summary>
        /// <returns>The stencil packs as a JSON array.</returns>
        [JSExport]
        public static string StencilPacks()
            => Serialize(EngineService.GetStencilPacks());

        /// <summary>Lists the analysis rules offered by the engine.</summary>
        /// <returns>The rules as a JSON array.</returns>
        [JSExport]
        public static string Rules()
            => Serialize(EngineService.GetRules(ruleOptions));

        /// <summary>Lists the rule packs offered by the engine.</summary>
        /// <returns>The rule packs as a JSON array.</returns>
        [JSExport]
        public static string RulePacks()
            => Serialize(EngineService.GetRulePacks(ruleOptions));

        /// <summary>Lists the typed element-property schema.</summary>
        /// <returns>The property descriptors as a JSON array.</returns>
        [JSExport]
        public static string PropertySchema()
            => Serialize(EngineService.GetPropertySchema());

        /// <summary>Runs the shared engine's analysis rule set over a tmforge-json model.</summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <returns>The findings as a JSON array (the /v1 FindingDto shape).</returns>
        [JSExport]
        public static string Analyze(string tmforgeJson)
            => Serialize(EngineService.Analyze(Deserialize(tmforgeJson), ruleOptions).Findings);

        /// <summary>
        /// Runs one analysis action: evaluates the rule set once and returns both the findings and the
        /// threats projected from the same evaluation, plus the effective rule packs and diagnostics.
        /// A UI that shows both should call this instead of Analyze and Threats, which would evaluate
        /// every enabled rule twice for one user action.
        /// </summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <returns>The analysis result as JSON (the /v1 AnalysisResultDto shape).</returns>
        [JSExport]
        public static string Analysis(string tmforgeJson)
            => Serialize(EngineService.RunAnalysis(Deserialize(tmforgeJson), ruleOptions));

        /// <summary>
        /// Records the analysis as a versioned tmforge-analysis document: every finding with its
        /// structural disposition, plus the model and analyzer fingerprints. This is the artifact meant
        /// to be stored and compared between runs, unlike Analysis which is what a client renders.
        /// </summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <returns>The analysis document as JSON (the /v1 AnalysisDocumentDto shape).</returns>
        [JSExport]
        public static string AnalysisDocument(string tmforgeJson)
            => Serialize(EngineService.DescribeAnalysis(Deserialize(tmforgeJson), ruleOptions));

        /// <summary>Projects the model's validation findings into STRIDE threats via the shared engine.</summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <returns>The generated threats as a JSON array (the /v1 ThreatDto shape).</returns>
        [JSExport]
        public static string Threats(string tmforgeJson)
            => Serialize(EngineService.GenerateThreats(Deserialize(tmforgeJson), ruleOptions));

        /// <summary>
        /// Splits the model's threat register by origin and by standing against the current rules, so a
        /// stored entry the rules no longer produce is distinguishable from a live one.
        /// </summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <returns>The split register as JSON (the /v1 ThreatRegisterDto shape).</returns>
        [JSExport]
        public static string ThreatRegister(string tmforgeJson)
            => Serialize(EngineService.DescribeThreatRegister(Deserialize(tmforgeJson), ruleOptions));

        /// <summary>Merges two edited tmforge-json models, keyed by element identity.</summary>
        /// <param name="baseJson">The common ancestor model, or an empty string for a two-way merge.</param>
        /// <param name="oursJson">The local model.</param>
        /// <param name="theirsJson">The incoming model.</param>
        /// <returns>The merged model and conflicts as JSON (the /v1 MergeResultDto shape).</returns>
        [JSExport]
        public static string Merge(string baseJson, string oursJson, string theirsJson)
            => Serialize(EngineService.Merge(
                string.IsNullOrWhiteSpace(baseJson) ? null : Deserialize(baseJson),
                Deserialize(oursJson),
                Deserialize(theirsJson)));

        /// <summary>Detects the format of a document, or returns an empty string when none matches.</summary>
        /// <param name="contentBase64">The raw document bytes, base64-encoded.</param>
        /// <returns>The detected format as JSON, or an empty string when unrecognized.</returns>
        [JSExport]
        public static string Detect(string contentBase64)
        {
            FormatDto? format = EngineService.Detect(Convert.FromBase64String(contentBase64));
            return format is null ? string.Empty : Serialize(format);
        }

        /// <summary>Checks input validity and conversion losses without writing or evaluating rules.</summary>
        /// <param name="contentBase64">The source bytes encoded as base64.</param>
        /// <param name="formatId">An optional input format, or empty to detect.</param>
        /// <param name="targetFormat">An optional conversion target, or empty for input validation only.</param>
        /// <returns>The shared preflight result as JSON.</returns>
        [JSExport]
        public static string Preflight(string contentBase64, string formatId, string targetFormat)
            => Serialize(DocumentPreflight.Inspect(Convert.FromBase64String(contentBase64), formatId, targetFormat));

        /// <summary>Arranges geometry while preserving boundary membership and actual flow crossings.</summary>
        /// <param name="requestJson">The LayoutRequestDto JSON: original model, optional proposed positions and metrics.</param>
        /// <returns>Geometry updates or an explicit refusal, as LayoutResultDto JSON.</returns>
        [JSExport]
        public static string Layout(string requestJson)
            => Serialize(EngineService.Layout(JsonSerializer.Deserialize<LayoutRequestDto>(requestJson, JsonOptions) ?? new LayoutRequestDto()));

        /// <summary>Reads a document in any registered format into the canonical tmforge-json model.</summary>
        /// <param name="contentBase64">The raw document bytes, base64-encoded.</param>
        /// <param name="formatId">An explicit format id, or an empty string to content-sniff.</param>
        /// <returns>The canonical tmforge-json model.</returns>
        [JSExport]
        public static string ReadFile(string contentBase64, string formatId)
        {
            TmForgeModelDto model = EngineService.ReadModel(
                Convert.FromBase64String(contentBase64),
                string.IsNullOrEmpty(formatId) ? null : formatId);
            return Serialize(model);
        }

        /// <summary>
        /// Materializes a declarative authoring manifest into a model. A manifest is a threat model's
        /// reviewable source rather than one of the registered model formats, so <see cref="Detect"/>
        /// cannot claim it and <see cref="ReadFile"/> cannot parse it.
        /// </summary>
        /// <param name="manifestJson">The manifest document text.</param>
        /// <returns>The built model and counts, or a blocking error, as JSON (the /v1 ApplyResultDto shape).</returns>
        [JSExport]
        public static string ApplyManifest(string manifestJson)
            => Serialize(AuthoringService.ApplyManifestJson(manifestJson, force: false));

        /// <summary>Serializes a tmforge-json model to lossless <c>.tm7</c> bytes, returned as base64.</summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <returns>The <c>.tm7</c> document bytes, base64-encoded.</returns>
        [JSExport]
        public static string ExportTm7(string tmforgeJson)
            => Convert.ToBase64String(EngineService.ExportTm7(Deserialize(tmforgeJson), ruleOptions));

        /// <summary>Serializes a tmforge-json model to another registered format, returned as base64.</summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <param name="toFormatId">The target format id (for example <c>drawio</c>, <c>vsdx</c>, <c>tm7</c>).</param>
        /// <returns>The serialized document bytes, base64-encoded.</returns>
        [JSExport]
        public static string ConvertModel(string tmforgeJson, string toFormatId)
            => Convert.ToBase64String(EngineService.Convert(Deserialize(tmforgeJson), toFormatId, ruleOptions));

        /// <summary>Renders an HTML or SVG report for a tmforge-json model, returned as base64.</summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <param name="format">The report format: <c>html</c> or <c>svg</c>.</param>
        /// <returns>The report bytes (UTF-8), base64-encoded.</returns>
        [JSExport]
        public static string Report(string tmforgeJson, string format)
            => Convert.ToBase64String(EngineService.Report(Deserialize(tmforgeJson), format, ruleOptions));

        /// <summary>
        /// Renders an analysis (findings) report for a tmforge-json model, returned as base64. These
        /// are the same artifacts the CLI writes for CI, produced here with no backend.
        /// </summary>
        /// <param name="tmforgeJson">The canonical tmforge-json model.</param>
        /// <param name="format">The report format: <c>sarif</c>, <c>html</c>, or <c>json</c>.</param>
        /// <returns>The report bytes (UTF-8), base64-encoded.</returns>
        [JSExport]
        public static string AnalysisReport(string tmforgeJson, string format)
            => Convert.ToBase64String(EngineService.AnalysisReport(Deserialize(tmforgeJson), format, ruleOptions));

        private static string Serialize<T>(T value)
            => JsonSerializer.Serialize(value, JsonOptions);

        private static TmForgeModelDto Deserialize(string tmforgeJson)
            => JsonSerializer.Deserialize<TmForgeModelDto>(tmforgeJson, JsonOptions) ?? new TmForgeModelDto();
    }
}
