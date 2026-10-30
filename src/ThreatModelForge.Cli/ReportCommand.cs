namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;
    using ThreatModelForge.Model;
    using ThreatModelForge.Reporting;

    /// <summary>
    /// Implements the <c>tmforge report</c> command.
    /// </summary>
    internal static class ReportCommand
    {
        /// <summary>
        /// Runs the report command.
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

            CliArgs parsed = CliArgs.Parse(args, new[] { "out", "format", RuleSourceCli.OptionName });
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
            string? output = parsed.Get("out");
            string formatId = (parsed.Get("format") ?? "html").ToLowerInvariant();
            if (formatId != "html" && formatId != "svg" && formatId != "md")
            {
                Console.Error.WriteLine("Unknown --format: " + formatId + " (expected html, svg, or md).");
                return 1;
            }

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

            ThreatModel model = ThreatModelFormatRegistry.CreateDefault().Load(input!);
            IReadOnlyCollection<string>? staleIds = null;
            if (formatId != "svg")
            {
                using RuleSet ruleSet = AnalysisRuleSources.Create(RuleSourceCli.FromPath(parsed.Get(RuleSourceCli.OptionName)));
                ApplyModelRuleSelection(ruleSet, input!);

                // Classify before applying, while the register is still what the file stored. Applying
                // adds the current threats, after which a leftover is no longer distinguishable.
                GenerationResult generation = ThreatGenerator.Generate(model, ruleSet);
                staleIds = ThreatRegisterClassifier.Classify(model, generation, ruleSet)
                    .Entries
                    .Where(entry => entry.State == ThreatRegisterStates.StaleGenerated)
                    .Select(entry => entry.Id)
                    .ToList();
                ThreatGenerator.Apply(model, generation);
            }

            string content = formatId switch
            {
                "svg" => new DiagramSvgRenderer().RenderModel(model).ToString(),
                "md" => new MarkdownReportWriter().Write(model, staleIds),
                _ => new HtmlReportWriter().Write(model, staleIds),
            };

            if (parsed.Json)
            {
                if (!string.IsNullOrEmpty(output))
                {
                    File.WriteAllText(output!, content);
                }

                CliJson.WriteEnvelope(
                    "report",
                    new
                    {
                        output = string.IsNullOrEmpty(output) ? null : output,
                        format = formatId,
                        bytes = Encoding.UTF8.GetByteCount(content),
                    });
                return 0;
            }

            if (string.IsNullOrEmpty(output))
            {
                Console.Out.Write(content);
            }
            else
            {
                File.WriteAllText(output!, content);
                Console.Error.WriteLine("Report written to " + output);
            }

            return 0;
        }

        private static void ApplyModelRuleSelection(RuleSet ruleSet, string path)
        {
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                if (!new TmForgeJsonFormat().CanRead(stream))
                {
                    return;
                }

                if (TmForgeJsonFormat.TryReadAnalysis(
                    stream,
                    out IReadOnlyList<string> disabledPacks,
                    out IReadOnlyList<string> disabledRuleIds))
                {
                    ruleSet.Disable(disabledPacks, disabledRuleIds);
                }
            }
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Threat Model Forge report generator.");
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  tmforge report [--format <html|svg|md>] [--out <path>] [--rules <path>] [--json] <model.tm7>");
            Console.Error.WriteLine("If --out is omitted, the report is written to standard output.");
            Console.Error.WriteLine("--format html (default) writes a self-contained HTML report; --format svg writes the diagram as a standalone SVG.");
            Console.Error.WriteLine("--format md writes deterministic Markdown with diagram tables and the threat register, without a generated timestamp.");
            Console.Error.WriteLine("--rules loads custom declarative rules (a *.tmrules.json file or a directory of them) alongside the built-in rules.");
        }
    }
}
