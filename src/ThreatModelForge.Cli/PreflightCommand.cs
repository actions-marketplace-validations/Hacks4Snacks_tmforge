namespace ThreatModelForge.Cli
{
    using System;
    using System.IO;
    using ThreatModelForge.Engine;
    using ThreatModelForge.Formats;

    /// <summary>Checks a model or manifest and previews conversion losses without writing output.</summary>
    internal static class PreflightCommand
    {
        /// <summary>Runs document preflight.</summary>
        /// <param name="args">The command arguments.</param>
        /// <returns>Zero for valid input, two for structural errors, or one for command and I/O errors.</returns>
        public static int Run(string[] args)
        {
            CliArgs parsed = CliArgs.Parse(args, new[] { "format", "to" });
            if (parsed.Help || parsed.UnknownFlags.Count > 0 || parsed.Positionals.Count != 1)
            {
                Console.Error.WriteLine("Usage: tmforge preflight <file> [--format <id>] [--to <id>] [--json]");
                Console.Error.WriteLine("Read-only: checks model integrity and known conversion losses; no security rules are evaluated.");
                return parsed.Help ? 0 : 1;
            }

            string path = parsed.Positionals[0];
            if (!File.Exists(path))
            {
                Console.Error.WriteLine("File not found: " + path);
                return 1;
            }

            if (new FileInfo(path).Length > JsonDocumentPreflight.MaxBytes)
            {
                Console.Error.WriteLine("Preflight input exceeds the 8 MiB limit.");
                return 1;
            }

            PreflightResultDto result = DocumentPreflight.Inspect(File.ReadAllBytes(path), parsed.Get("format"), parsed.Get("to"));
            if (parsed.Json)
            {
                CliJson.WriteEnvelope("preflight", result);
            }
            else
            {
                Console.WriteLine(result.Success ? "Preflight passed (not a security assessment)." : "Preflight failed; the document is not safe to import as supplied.");
                foreach (DocumentDiagnostic diagnostic in result.Diagnostics)
                {
                    Console.WriteLine(diagnostic.Severity + " " + diagnostic.Code + " " + diagnostic.Path + ": " + diagnostic.Message);
                }
            }

            return result.Success ? 0 : 2;
        }
    }
}
