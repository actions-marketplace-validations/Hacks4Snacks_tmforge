namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Text;
    using Microsoft.Extensions.DependencyInjection;
    using ModelContextProtocol.Server;
    using ThreatModelForge.Engine;

    /// <summary>
    /// MCP tools for reading, saving, analyzing, and reporting on threat models. Analysis tools are
    /// stateless: they take a canonical tmforge-json model in and return findings, threats, or a
    /// report out.
    /// </summary>
    [McpServerToolType]
    public static class McpModelTools
    {
        /// <summary>
        /// Reads a threat model file from a local path and returns the canonical tmforge-json model.
        /// </summary>
        /// <param name="path">The local file path to read.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="format">An optional explicit format id; omit to auto-detect by content.</param>
        /// <returns>The canonical model.</returns>
        [McpServerTool(Name = "read")]
        [Description("Reads a threat model file (.tm7, .tmforge.json, .drawio, .vsdx) from a path inside the configured MCP workspace root and returns the canonical tmforge-json model.")]
        public static TmForgeModelDto Read(
            [Description("The file path to read, relative to (or contained by) the configured MCP workspace root.")] string path,
            IServiceProvider services,
            [Description("Optional explicit format id (tm7, tmforge-json, drawio, vsdx); omit to auto-detect.")] string? format = null)
        {
            McpToolSupport.ValidateArguments(new[] { path, format });
            McpPathPolicy pathPolicy = services.GetRequiredService<McpPathPolicy>();
            byte[] content = pathPolicy.ReadAllBytes(path);
            pathPolicy.ValidateArchiveContainer(content);
            string? effectiveFormat = string.IsNullOrEmpty(format) ? EngineService.Detect(content)?.Id : format;
            pathPolicy.ValidateExpandedContent(content, effectiveFormat);
            TmForgeModelDto model = EngineService.ReadModel(content, effectiveFormat);
            McpToolSupport.ValidateModel(model);
            return model;
        }

        /// <summary>Checks a document inside the MCP sandbox and previews optional conversion losses.</summary>
        /// <param name="path">The sandboxed input path.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="format">An optional source format.</param>
        /// <param name="to">An optional destination format.</param>
        /// <returns>The structural diagnostics, without model mutation or rule evaluation.</returns>
        [McpServerTool(Name = "preflight")]
        [Description("Checks model or manifest input and optional conversion losses without writing files or evaluating security rules. Returns structured diagnostic codes, severities and source paths.")]
        public static PreflightResultDto Preflight(
            [Description("Input path inside the configured MCP workspace root.")] string path,
            IServiceProvider services,
            [Description("Optional input format id, including tmforge-manifest for a legacy manifest.")] string? format = null,
            [Description("Optional target format to preview conversion losses.")] string? to = null)
        {
            McpToolSupport.ValidateArguments(new[] { path, format, to });
            McpPathPolicy policy = services.GetRequiredService<McpPathPolicy>();
            byte[] content = policy.ReadAllBytes(path);
            policy.ValidateArchiveContainer(content);
            string? source = string.IsNullOrEmpty(format) ? EngineService.Detect(content)?.Id : format;
            policy.ValidateExpandedContent(content, source);
            return DocumentPreflight.Inspect(content, format, to);
        }

        /// <summary>
        /// Detects the file format of a local threat model document by content sniffing.
        /// </summary>
        /// <param name="path">The local file path to inspect.</param>
        /// <param name="services">The MCP request services.</param>
        /// <returns>The detected format, or <see langword="null"/> when none matches.</returns>
        [McpServerTool(Name = "detect")]
        [Description("Detects the format of a threat model document inside the configured MCP workspace root by content sniffing.")]
        public static FormatDto? Detect(
            [Description("The file path to inspect, relative to (or contained by) the configured MCP workspace root.")] string path,
            IServiceProvider services)
        {
            McpToolSupport.ValidateArguments(new[] { path });
            McpPathPolicy pathPolicy = services.GetRequiredService<McpPathPolicy>();
            byte[] content = pathPolicy.ReadAllBytes(path);
            pathPolicy.ValidateArchiveContainer(content);
            return EngineService.Detect(content);
        }

        /// <summary>
        /// Writes a tmforge-json model to a local file, materializing it as <c>.tm7</c> or another format.
        /// </summary>
        /// <param name="model">The tmforge-json model to write.</param>
        /// <param name="path">The local file path to write.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="format">An optional format id; omit to infer from the path extension.</param>
        /// <returns>Where the model was written, in what format, and how many bytes.</returns>
        [McpServerTool(Name = "save")]
        [Description("Writes a tmforge-json model to a file inside the configured MCP workspace root (format inferred from its registered model extension). Use this to materialize .tm7/.tmforge.json/.vsdx/.drawio.")]
        public static McpSaveResult Save(
            [Description("The tmforge-json model to write.")] TmForgeModelDto model,
            [Description("The destination path, relative to (or contained by) the configured MCP workspace root.")] string path,
            IServiceProvider services,
            [Description("Optional format id (tm7, tmforge-json, drawio, vsdx); omit to infer from the path extension.")] string? format = null)
        {
            McpToolSupport.ValidateModel(model);
            McpToolSupport.ValidateArguments(new[] { path, format });
            McpPathPolicy pathPolicy = services.GetRequiredService<McpPathPolicy>();
            (string resolvedPath, string formatId) = pathPolicy.ResolveWriteTarget(path, format);
            int bytes = pathPolicy.WriteAtomically(
                resolvedPath,
                output => EngineService.WriteConverted(model, formatId, output));
            return new McpSaveResult { Path = path, Format = formatId, Bytes = bytes };
        }

        /// <summary>
        /// Runs the analysis rule set over the model and returns the findings.
        /// </summary>
        /// <param name="model">The tmforge-json model to analyze.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="rulesPath">An optional custom rule pack inside the workspace root.</param>
        /// <returns>The findings.</returns>
        [McpServerTool(Name = "analyze")]
        [Description("Runs the analysis rule set over the model and returns the findings (rule id, severity, message, affected element ids).")]
        public static IReadOnlyList<FindingDto> Analyze(
            [Description("The tmforge-json model to analyze.")] TmForgeModelDto model,
            IServiceProvider services,
            [Description("Optional path to a custom .tmrules.json pack inside the configured MCP workspace root; omit to run the built-in rules only.")] string? rulesPath = null)
        {
            McpToolSupport.ValidateModel(model);
            EngineRuleOptions? rules = McpToolSupport.LoadRules(services, rulesPath);
            return McpToolSupport.ValidateResponse(EngineService.Analyze(model, rules).Findings);
        }

        /// <summary>
        /// Projects the model's threat-bearing findings into threats (the persistable, triaged view).
        /// </summary>
        /// <param name="model">The tmforge-json model.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="rulesPath">An optional custom rule pack inside the workspace root.</param>
        /// <returns>The generated threats.</returns>
        [McpServerTool(Name = "threats")]
        [Description("Projects the model's threat-bearing findings into threats (the persistable, triaged view with category, title, mitigation, and references).")]
        public static IReadOnlyList<ThreatDto> Threats(
            [Description("The tmforge-json model.")] TmForgeModelDto model,
            IServiceProvider services,
            [Description("Optional path to a custom .tmrules.json pack inside the configured MCP workspace root; omit to run the built-in rules only.")] string? rulesPath = null)
        {
            McpToolSupport.ValidateModel(model);
            EngineRuleOptions? rules = McpToolSupport.LoadRules(services, rulesPath);
            return McpToolSupport.ValidateResponse(EngineService.GenerateThreats(model, rules));
        }

        /// <summary>
        /// Splits the model's threat register by origin and by standing against the current rules.
        /// </summary>
        /// <param name="model">The tmforge-json model.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="rulesPath">An optional custom rule pack inside the workspace root.</param>
        /// <returns>The split register.</returns>
        [McpServerTool(Name = "threat_register")]
        [Description("Splits the model's threat register by origin and standing: manual, current-generated, stale-generated (stored but the rule no longer fires), and indeterminate-generated (the rule was not part of this run, so it cannot be judged stale). Counts are not a partition and must not be summed.")]
        public static ThreatRegisterDto ThreatRegister(
            [Description("The tmforge-json model.")] TmForgeModelDto model,
            IServiceProvider services,
            [Description("Optional path to a custom .tmrules.json pack inside the configured MCP workspace root; omit to run the built-in rules only.")] string? rulesPath = null)
        {
            McpToolSupport.ValidateModel(model);
            EngineRuleOptions? rules = McpToolSupport.LoadRules(services, rulesPath);
            return McpToolSupport.ValidateResponse(EngineService.DescribeThreatRegister(model, rules));
        }

        /// <summary>
        /// Renders a self-contained report for the model as text (HTML or SVG).
        /// </summary>
        /// <param name="model">The tmforge-json model.</param>
        /// <param name="services">The MCP request services.</param>
        /// <param name="format">The report format: <c>html</c> (default) or <c>svg</c>.</param>
        /// <param name="rulesPath">An optional custom rule pack inside the workspace root.</param>
        /// <returns>The report content.</returns>
        [McpServerTool(Name = "report")]
        [Description("Renders a self-contained report for the model as text. Format 'html' (default) or 'svg'.")]
        public static string Report(
            [Description("The tmforge-json model.")] TmForgeModelDto model,
            IServiceProvider services,
            [Description("The report format: html or svg.")] string format = "html",
            [Description("Optional path to a custom .tmrules.json pack inside the configured MCP workspace root; omit to run the built-in rules only.")] string? rulesPath = null)
        {
            McpToolSupport.ValidateModel(model);
            McpToolSupport.ValidateArguments(new[] { format });
            EngineRuleOptions? rules = McpToolSupport.LoadRules(services, rulesPath);
            return McpToolSupport.ValidateResponse(Encoding.UTF8.GetString(EngineService.Report(model, format, rules)));
        }

        /// <summary>
        /// Merges two edited models by element identity, reporting conflicts (resolved to <c>ours</c>).
        /// </summary>
        /// <param name="ours">The local model.</param>
        /// <param name="theirs">The incoming model.</param>
        /// <param name="baseModel">An optional common ancestor for a three-way merge; omit for two-way.</param>
        /// <returns>The merged model and any conflicts.</returns>
        [McpServerTool(Name = "merge")]
        [Description("Three-way (or two-way when base is omitted) identity-keyed merge of two edited models; conflicts are resolved to 'ours' and reported.")]
        public static MergeResultDto Merge(
            [Description("The local model.")] TmForgeModelDto ours,
            [Description("The incoming model.")] TmForgeModelDto theirs,
            [Description("Optional common ancestor for a three-way merge; omit for two-way.")] TmForgeModelDto? baseModel = null)
        {
            McpToolSupport.ValidateModels(baseModel, ours, theirs);
            MergeResultDto result = EngineService.Merge(baseModel, ours, theirs);
            return McpToolSupport.ValidateResult(result);
        }
    }
}
