namespace ThreatModelForge.Cli
{
    using System;
    using System.IO;
    using System.Linq;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Implements the <c>tmforge convert</c> command, translating a threat model between any two
    /// registered file formats (for example <c>.tm7</c>, <c>.tmforge.json</c>, <c>.drawio</c>, and
    /// <c>.vsdx</c>). The source format is detected from the input; the target is taken from
    /// <c>--to</c> or inferred from the <c>--out</c> extension.
    /// </summary>
    internal static class ConvertCommand
    {
        /// <summary>
        /// Runs the convert command.
        /// </summary>
        /// <param name="args">The command arguments (after the verb).</param>
        /// <returns>Zero on success; a non-zero value on error.</returns>
        public static int Run(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                PrintUsage();
                return 1;
            }

            CliArgs parsed = CliArgs.Parse(args, new[] { "to", "out", "knowledge-base" }, new[] { "fail-on-loss" });
            if (parsed.Help)
            {
                PrintUsage();
                return 0;
            }

            if (parsed.UnknownFlags.Count > 0)
            {
                Console.Error.WriteLine("Unknown option: " + parsed.UnknownFlags[0]);
                PrintUsage();
                return 1;
            }

            string? input = parsed.Positionals.Count > 0 ? parsed.Positionals[0] : null;
            string? targetId = parsed.Get("to");
            string? output = parsed.Get("out");

            if (string.IsNullOrEmpty(input))
            {
                PrintUsage();
                return 1;
            }

            if (!File.Exists(input))
            {
                Console.Error.WriteLine("File not found: " + input);
                return 1;
            }

            ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();

            IThreatModelFormat? target = !string.IsNullOrEmpty(targetId)
                ? registry.FindById(targetId!)
                : !string.IsNullOrEmpty(output) ? registry.FindByExtension(output!) : null;

            if (target == null)
            {
                Console.Error.WriteLine("Specify a target format with --to <format>, or an --out path with a known extension.");
                PrintUsage();
                return 1;
            }

            if (!target.Capabilities.CanWrite)
            {
                Console.Error.WriteLine("Format '" + target.Id + "' does not support writing.");
                return 1;
            }

            if (new FileInfo(input).Length > JsonDocumentPreflight.MaxBytes)
            {
                Console.Error.WriteLine("Preflight input exceeds the 8 MiB limit.");
                return 1;
            }

            byte[] content = File.ReadAllBytes(input);
            string? sourceFormat = registry.FindByExtension(input)?.Id;
            PreflightResultDto preflight = DocumentPreflight.Inspect(content, sourceFormat, target.Id);
            bool refused = !preflight.Success || (parsed.HasFlag("fail-on-loss") && preflight.Diagnostics.Any(diagnostic => diagnostic.Severity == "warning"));
            foreach (DocumentDiagnostic diagnostic in preflight.Diagnostics)
            {
                Console.Error.WriteLine(diagnostic.Severity + " " + diagnostic.Code + " " + diagnostic.Path + ": " + diagnostic.Message);
            }

            if (refused)
            {
                if (parsed.Json)
                {
                    CliJson.WriteEnvelope("convert", new { input, output = (string?)null, format = target.Id, diagnostics = preflight.Diagnostics });
                }

                return preflight.Success ? 2 : 1;
            }

            using MemoryStream inputStream = new MemoryStream(content, writable: false);
            ThreatModel model = registry.Load(inputStream, preflight.Format);

            string? knowledgeBasePath = parsed.Get("knowledge-base");
            if (!string.IsNullOrEmpty(knowledgeBasePath))
            {
                if (target is not Tm7Format)
                {
                    Console.Error.WriteLine("--knowledge-base can only be embedded when the target format is tm7.");
                    return 1;
                }

                if (!File.Exists(knowledgeBasePath))
                {
                    Console.Error.WriteLine("Knowledge base not found: " + knowledgeBasePath);
                    return 1;
                }

                model.KnowledgeBase = KnowledgeBaseData.Load(knowledgeBasePath!);
            }

            // Prepare runs for every tm7 export, including one embedding a supplied knowledge base.
            // Skipping it there would leave the file without the coordinate normalization and typed
            // properties the tool needs, and would leave a threat carrying a priority the supplied
            // knowledge base never declared.
            if (target is Tm7Format)
            {
                Tm7ExportPreparer.Prepare(model);
            }

            string outputPath = !string.IsNullOrEmpty(output)
                ? output!
                : Path.ChangeExtension(input!, target.Extensions.Count > 0 ? target.Extensions[0] : ".out");

            using (FileStream stream = File.Create(outputPath))
            {
                target.Write(model, stream);
            }

            if (parsed.Json)
            {
                CliJson.WriteEnvelope("convert", new { input, output = outputPath, format = target.Id, diagnostics = preflight.Diagnostics });
            }
            else
            {
                Console.Error.WriteLine("Converted " + input + " -> " + outputPath + " (" + target.Id + ").");
            }

            return 0;
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Threat Model Forge format converter.");
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  tmforge convert [--to <format>] [--out <path>] [--knowledge-base <file.tb7>] [--fail-on-loss] [--json] <input>");
            Console.Error.WriteLine();
            Console.Error.WriteLine("The target format is taken from --to, or inferred from the --out extension.");
            Console.Error.WriteLine("If --out is omitted, the input name is reused with the target extension.");
            Console.Error.WriteLine("Formats: tm7, tmforge-json, drawio, vsdx.");
            Console.Error.WriteLine("--fail-on-loss refuses conversion warnings before opening the destination. Use preflight for a read-only preview.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("A tm7 export embeds the Threat Model Forge knowledge base by default so the file opens");
            Console.Error.WriteLine("in the Microsoft Threat Modeling Tool; use --knowledge-base <file.tb7> to embed a different");
            Console.Error.WriteLine("one. A knowledge base already present in the source model is preserved.");
        }
    }
}
