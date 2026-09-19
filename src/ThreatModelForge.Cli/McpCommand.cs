namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Threading.Tasks;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Implements <c>tmforge mcp</c>: hosts a Model Context Protocol server over stdio, projecting the
    /// engine facade (read/analyze/threats/report/save/merge) and the authoring facade
    /// (apply/add/connect/set/rename/remove/export) as MCP tools so an AI agent can drive Threat Model
    /// Forge end to end. The server speaks JSON-RPC on stdin/stdout; every diagnostic goes to stderr so
    /// the protocol channel stays clean.
    /// </summary>
    internal static class McpCommand
    {
        /// <summary>
        /// Runs the MCP stdio server until the client disconnects.
        /// </summary>
        /// <param name="args">The command arguments (after the verb).</param>
        /// <returns>Zero on a clean shutdown.</returns>
        public static int Run(string[] args)
        {
            if (args != null && (Array.IndexOf(args, "--help") >= 0 || Array.IndexOf(args, "-h") >= 0 || Array.IndexOf(args, "-?") >= 0))
            {
                PrintUsage();
                return 0;
            }

            try
            {
                if (!TryParseOptions(
                    args ?? Array.Empty<string>(),
                    out string root,
                    out long maxReadBytes,
                    out long maxWriteBytes,
                    out string[] hostArgs,
                    out string? error))
                {
                    Console.Error.WriteLine(error);
                    PrintUsage();
                    return 1;
                }

                McpPathPolicy pathPolicy = new McpPathPolicy(root, maxReadBytes, maxWriteBytes);
                RunAsync(hostArgs, pathPolicy).GetAwaiter().GetResult();
                return 0;
            }
            catch (Exception ex) when (ex is ArgumentException || ex is IOException || ex is UnauthorizedAccessException)
            {
                Console.Error.WriteLine("Could not start the MCP server: " + ex.Message);
                return 1;
            }
        }

        /// <summary>Parses MCP-specific hosting options and removes them from the generic host arguments.</summary>
        /// <param name="args">The arguments supplied after <c>tmforge mcp</c>.</param>
        /// <param name="root">The configured workspace root.</param>
        /// <param name="maxReadBytes">The configured maximum input size.</param>
        /// <param name="maxWriteBytes">The configured maximum output size.</param>
        /// <param name="hostArgs">Arguments left for the generic host.</param>
        /// <param name="error">A parse error, or <see langword="null"/> on success.</param>
        /// <returns><see langword="true"/> when the options are valid; otherwise <see langword="false"/>.</returns>
        internal static bool TryParseOptions(
            IReadOnlyList<string> args,
            out string root,
            out long maxReadBytes,
            out long maxWriteBytes,
            out string[] hostArgs,
            out string? error)
        {
            return TryParseOptionsCore(args, out root, out maxReadBytes, out maxWriteBytes, out hostArgs, out error);
        }

        private static async Task RunAsync(string[] args, McpPathPolicy pathPolicy)
        {
            HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

            // The stdio transport owns stdout for JSON-RPC, so route every log to stderr and keep it quiet.
            builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            builder.Services.AddSingleton(pathPolicy);

            builder.Services
                .AddMcpServer()
                .WithStdioServerTransport()
                .WithToolsFromAssembly(typeof(McpCommand).Assembly)
                .WithResourcesFromAssembly(typeof(McpCommand).Assembly);

            await builder.Build().RunAsync().ConfigureAwait(false);
        }

        private static void PrintUsage()
        {
            Console.Error.WriteLine("Run a Model Context Protocol (MCP) server over stdio for AI agents.");
            Console.Error.WriteLine("Usage:");
            Console.Error.WriteLine("  tmforge mcp [--root <path>] [--max-read-bytes <n>] [--max-write-bytes <n>]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("File tools are confined to --root (default: the process working directory), reject");
            Console.Error.WriteLine("symbolic-link escapes, and only write registered threat-model file extensions.");
            Console.Error.WriteLine("Read/write limits default to 67108864 bytes (64 MiB) per file.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Exposes tmforge's engine and authoring facade as MCP tools: read, apply, add, connect,");
            Console.Error.WriteLine("set, rename, remove, analyze, threats, report, save, merge, export_manifest, plus grounding");
            Console.Error.WriteLine("(formats, stencils, property_schema, rules, rule_packs, manifest_schema, detect).");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Also exposes versioned grounding resources at tmforge://grounding/v1/:");
            Console.Error.WriteLine("formats, property-schema, manifest-schema, rule-packs, and a sandboxed custom-pack template.");
            Console.Error.WriteLine("Existing grounding tools remain available for clients without resource support.");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Configure your MCP client to launch: command \"tmforge\", args [\"mcp\"].");
        }

        private static bool TryParseOptionsCore(
            IReadOnlyList<string> args,
            out string root,
            out long maxReadBytes,
            out long maxWriteBytes,
            out string[] hostArgs,
            out string? error)
        {
            root = Environment.CurrentDirectory;
            maxReadBytes = McpPathPolicy.DefaultMaxReadBytes;
            maxWriteBytes = McpPathPolicy.DefaultMaxWriteBytes;
            error = null;
            List<string> remaining = new List<string>();

            for (int index = 0; index < args.Count; index++)
            {
                string argument = args[index];
                if (!TryReadOption(args, ref index, argument, "root", out string? value) &&
                    !TryReadOption(args, ref index, argument, "max-read-bytes", out value) &&
                    !TryReadOption(args, ref index, argument, "max-write-bytes", out value))
                {
                    remaining.Add(argument);
                    continue;
                }

                string option = argument.Substring(2).Split('=')[0];
                if (value == null)
                {
                    hostArgs = Array.Empty<string>();
                    error = "Missing value for --" + option + ".";
                    return false;
                }

                if (option == "root")
                {
                    root = value;
                    continue;
                }

                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long limit) || limit <= 0)
                {
                    hostArgs = Array.Empty<string>();
                    error = "--" + option + " must be a positive integer.";
                    return false;
                }

                if (option == "max-read-bytes")
                {
                    maxReadBytes = limit;
                }
                else
                {
                    maxWriteBytes = limit;
                }
            }

            hostArgs = remaining.ToArray();
            return true;
        }

        private static bool TryReadOption(
            IReadOnlyList<string> args,
            ref int index,
            string argument,
            string name,
            out string? value)
        {
            string option = "--" + name;
            if (string.Equals(argument, option, StringComparison.Ordinal))
            {
                value = index + 1 < args.Count ? args[++index] : null;
                return true;
            }

            string prefix = option + "=";
            if (argument.StartsWith(prefix, StringComparison.Ordinal))
            {
                value = argument.Substring(prefix.Length);
                return true;
            }

            value = null;
            return false;
        }
    }
}
