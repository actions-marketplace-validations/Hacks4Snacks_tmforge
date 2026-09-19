namespace ThreatModelForge.Api
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Http.HttpResults;
    using Microsoft.Extensions.DependencyInjection;
    using ThreatModelForge.Engine;

    /// <summary>
    /// The Threat Model Forge engine API host. Exposes a small, versioned <c>/v1</c> surface over
    /// the real .NET engine (validate, convert, read, report, detect) and serves the Studio SPA
    /// from <c>wwwroot</c> so the API and UI ship as one hosted artifact.
    /// </summary>
    public static class Program
    {
        /// <summary>
        /// The application entry point.
        /// </summary>
        /// <param name="args">The command-line arguments.</param>
        public static void Main(string[] args)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

            // Allow the local React (Vite) dev server to call the API during development.
            builder.Services.AddCors(options =>
                options.AddDefaultPolicy(policy =>
                    policy.WithOrigins("http://localhost:5199")
                        .AllowAnyHeader()
                        .AllowAnyMethod()));

            // Publish the OpenAPI document (served at /openapi/v1.json). It is the single source of
            // truth for the API contract; the React client's types are generated from it.
            builder.Services.AddOpenApi();

            // Report a caller's bad input as 400 rather than 500. See InputErrorHandler for what
            // counts as the caller's fault; everything else still surfaces as a server error.
            builder.Services.AddProblemDetails();
            builder.Services.AddExceptionHandler<InputErrorHandler>();

            WebApplication app = builder.Build();

            // First in the pipeline so it wraps every endpoint below.
            app.UseExceptionHandler();
            app.UseCors();

            // Custom rule packs are deployment configuration, not request input: they are named by the
            // operator, read once here, and applied to every rule-reading endpoint, so this host's
            // catalogs, findings, threats, reports, and exports all come from one effective bundle.
            (EngineRuleOptions rules, IReadOnlyList<string> ruleDiagnostics) = ApiRuleSources.Load(builder.Configuration);

            // Serve the built Studio SPA's static assets from wwwroot (populated by the build).
            app.UseStaticFiles();

            app.MapOpenApi();

            app.MapGet("/v1/health", () => TypedResults.Ok(new HealthStatusDto { Status = "ok" }))
                .WithName("GetHealth")
                .WithTags("System");
            app.MapGet("/v1/formats", () => TypedResults.Ok(EngineService.GetFormats()))
                .WithName("GetFormats")
                .WithTags("Formats");
            app.MapGet("/v1/stencils", () => TypedResults.Ok(EngineService.GetStencils()))
                .WithName("GetStencils")
                .WithTags("Catalog");
            app.MapGet("/v1/stencil-packs", () => TypedResults.Ok(EngineService.GetStencilPacks()))
                .WithName("GetStencilPacks")
                .WithTags("Catalog");
            app.MapGet("/v1/rules", () => TypedResults.Ok(EngineService.GetRules(rules)))
                .WithName("GetRules")
                .WithTags("Catalog");
            app.MapGet("/v1/rule-packs", () => TypedResults.Ok(EngineService.GetRulePacks(rules)))
                .WithName("GetRulePacks")
                .WithTags("Catalog");
            app.MapGet("/v1/rule-bundle", () => TypedResults.Ok(DescribeRuleBundle(rules, ruleDiagnostics)))
                .WithName("GetRuleBundle")
                .WithTags("Catalog");
            app.MapGet("/v1/property-schema", () => TypedResults.Ok(EngineService.GetPropertySchema()))
                .WithName("GetPropertySchema")
                .WithTags("Catalog");
            app.MapPost("/v1/model/analyze", (TmForgeModelDto model) => TypedResults.Ok(EngineService.Analyze(model, rules).Findings))
                .WithName("AnalyzeModel")
                .WithTags("Model");
            app.MapPost("/v1/model/analysis", (TmForgeModelDto model) => TypedResults.Ok(EngineService.RunAnalysis(model, rules)))
                .WithName("RunAnalysis")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/analysis-document",
                (TmForgeModelDto model) => TypedResults.Ok(EngineService.DescribeAnalysis(model, rules)))
                .WithName("DescribeAnalysis")
                .WithTags("Model");
            app.MapPost("/v1/model/threats", (TmForgeModelDto model) => TypedResults.Ok(EngineService.GenerateThreats(model, rules)))
                .WithName("GenerateThreats")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/threat-register",
                (TmForgeModelDto model) => TypedResults.Ok(EngineService.DescribeThreatRegister(model, rules)))
                .WithName("DescribeThreatRegister")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/merge",
                (MergeRequestDto request) => TypedResults.Ok(
                    EngineService.Merge(
                        request.Base,
                        request.Ours ?? new TmForgeModelDto(),
                        request.Theirs ?? new TmForgeModelDto())))
                .WithName("MergeModels")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/layout",
                (LayoutRequestDto request) => TypedResults.Ok(EngineService.Layout(request)))
                .WithName("LayoutModel")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/export/tm7",
                (TmForgeModelDto model) => TypedResults.File(EngineService.ExportTm7(model, rules), "application/xml", "model.tm7"))
                .WithName("ExportModelTm7")
                .WithTags("Model");
            app.MapPost("/v1/model/convert", (TmForgeModelDto model, string to) =>
                {
                    byte[] bytes = EngineService.Convert(model, to, rules);
                    (string contentType, string fileName) = DescribeConversion(to);
                    return TypedResults.File(bytes, contentType, fileName);
                })
                .WithName("ConvertModel")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/read",
                (FileContentDto file) => TypedResults.Ok(
                    EngineService.ReadModel(Convert.FromBase64String(file.ContentBase64), file.FormatId)))
                .WithName("ReadModel")
                .WithTags("Model");
            app.MapPost(
                "/v1/model/preflight",
                (FileContentDto file, string? to) => TypedResults.Ok(
                    DocumentPreflight.Inspect(Convert.FromBase64String(file.ContentBase64), file.FormatId, to)))
                .WithName("PreflightModel")
                .WithTags("Model");

            // A declarative authoring manifest is a threat model's reviewable source, not one of the
            // registered model formats, so /v1/detect cannot claim it and /v1/model/read cannot parse
            // it. Materializing it here lets a client open a manifest without shelling out to the CLI.
            app.MapPost(
                "/v1/model/manifest",
                (ManifestRequestDto request) => TypedResults.Ok(
                    AuthoringService.ApplyManifestJson(request.Manifest, request.Force)))
                .WithName("ApplyManifest")
                .WithTags("Model");
            app.MapPost("/v1/model/report", (TmForgeModelDto model, string format) =>
                {
                    bool svg = string.Equals(format, "svg", StringComparison.OrdinalIgnoreCase);
                    byte[] bytes = EngineService.Report(model, format, rules);
                    return TypedResults.File(bytes, svg ? "image/svg+xml" : "text/html", svg ? "report.svg" : "report.html");
                })
                .WithName("ReportModel")
                .WithTags("Report");
            app.MapPost("/v1/model/analysis-report", (TmForgeModelDto model, string format) =>
                {
                    byte[] bytes = EngineService.AnalysisReport(model, format, rules);
                    (string contentType, string fileName) = DescribeAnalysisReport(format);
                    return TypedResults.File(bytes, contentType, fileName);
                })
                .WithName("AnalysisReport")
                .WithTags("Report");
            app.MapPost("/v1/detect", DetectFormat)
                .WithName("DetectFormat")
                .WithTags("Formats");

            // An unmatched /v1 path is a wrong API call, not a client-side route: answer it as the API
            // rather than letting the SPA fallback below serve index.html with a 200. A caller that
            // mistypes an endpoint gets a 404 it can act on instead of HTML it will fail to parse.
            app.MapFallback("/v1/{**rest}", (HttpContext context) => TypedResults.Problem(
                title: "No such endpoint.",
                detail: $"{context.Request.Method} {context.Request.Path} is not part of the /v1 API.",
                statusCode: StatusCodes.Status404NotFound,
                instance: context.Request.Path));

            // Serve the Studio SPA's entry document for any non-API path so client-side routes
            // resolve. The /v1 and /openapi endpoints are matched first, so this only catches the rest.
            app.MapFallbackToFile("index.html");

            app.Run();
        }

        /// <summary>
        /// Describes how an analysis report is delivered. The names match what
        /// <c>tmforge analyze</c> writes, so a downloaded artifact drops straight into a review folder.
        /// </summary>
        /// <param name="formatId">The requested report format.</param>
        /// <returns>The content type and download file name.</returns>
        private static (string ContentType, string FileName) DescribeAnalysisReport(string formatId)
        {
            switch ((formatId ?? string.Empty).ToUpperInvariant())
            {
                case "SARIF":
                    return ("application/sarif+json", "findings.sarif");
                case "JSON":
                    return ("application/json", "findings.json");
                default:
                    return ("text/html", "findings.html");
            }
        }

        private static RuleBundleDto DescribeRuleBundle(EngineRuleOptions rules, IReadOnlyList<string> hostDiagnostics)
        {
            RuleBundleDto bundle = EngineService.DescribeRules(rules);
            return hostDiagnostics.Count == 0
                ? bundle
                : new RuleBundleDto
                {
                    RulePacks = bundle.RulePacks,
                    Diagnostics = hostDiagnostics.Concat(bundle.Diagnostics).ToList(),
                };
        }

        private static Results<Ok<FormatDto>, NotFound> DetectFormat(FileContentDto file)
        {
            FormatDto? detected = EngineService.Detect(Convert.FromBase64String(file.ContentBase64));
            return detected is null ? TypedResults.NotFound() : TypedResults.Ok(detected);
        }

        private static (string ContentType, string FileName) DescribeConversion(string formatId)
        {
            switch (formatId)
            {
                case "drawio":
                    return ("application/xml", "model.drawio");
                case "vsdx":
                    return ("application/vnd.ms-visio.drawing", "model.vsdx");
                case "tmforge-json":
                    return ("application/json", "model.tmforge.json");
                default:
                    return ("application/xml", "model.tm7");
            }
        }
    }
}
