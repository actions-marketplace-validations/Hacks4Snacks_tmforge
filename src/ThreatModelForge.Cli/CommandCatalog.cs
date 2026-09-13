namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// The single source of truth for the <c>tmforge</c> verbs. <see cref="Program"/> dispatches and
    /// prints its usage from this list, and <c>tmforge schema</c> documents the <c>--json</c> output
    /// from it, so a new verb is registered exactly once and cannot drift out of sync across the
    /// dispatcher, the help text, and the machine-readable schema.
    /// </summary>
    internal static class CommandCatalog
    {
        private static readonly IReadOnlyList<CommandInfo> All = new List<CommandInfo>
        {
            new CommandInfo("open", "Summarize a threat model (counts of elements, flows, and threats).", "name, owner, source, format{id,name}, diagramCount, componentCount, connectorCount, trustBoundaryCount, threatCount, diagrams[]", OpenCommand.Run),
            new CommandInfo("list", "List components, flows, boundaries, threats, or diagrams.", "kind, count, items[]", ListCommand.Run),
            new CommandInfo("show", "Show an element/flow's name, type, and custom properties.", "id, kind, name, stencil, stencilLabel, properties{}", ShowCommand.Run),
            new CommandInfo("diff", "Show a structural diff between two models (added/removed/modified).", "summary, added[], removed[], modified[]", DiffCommand.Run),
            new CommandInfo("merge", "Three-way merge two models against a common ancestor (git driver).", "status, summary, conflicts[]", MergeCommand.Run),
            new CommandInfo("stencils", "List the built-in authoring stencils (ids for 'add --stencil').", "packs[], stencils[]", StencilsCommand.Run),
            new CommandInfo("properties", "List the typed property schema (custom properties the analyzer reads).", "bases[], properties[]; with --explain: bases[], explain[]{appliesTo,property,value,rule,severity}", PropertiesCommand.Run),
            new CommandInfo("schema", "Describe the --json envelope and per-command output shapes.", "envelope{schemaVersion,fields,description}, commands[]{command,data}", SchemaCommand.Run),
            new CommandInfo("render", "Render the diagram in the terminal (Unicode/ANSI; --plain for ASCII).", null, RenderCommand.Run),
            new CommandInfo("new", "Create a new threat model.", "path, format, name", NewCommand.Run),
            new CommandInfo("add", "Add a process, store, external interactor, or boundary.", "id, kind, name, stencil, diagramId, alias", AddCommand.Run),
            new CommandInfo("connect", "Add a data flow between two elements.", "id, source, target", ConnectCommand.Run),
            new CommandInfo("remove", "Remove an element (and its connected flows).", "removed", RemoveCommand.Run),
            new CommandInfo("rename", "Rename an element.", "id, name", RenameCommand.Run),
            new CommandInfo("set", "Set an element/flow's name or properties (protocol, port, auth, ...).", "id, name, properties{}", SetCommand.Run),
            new CommandInfo("page", "List, add, rename, reorder, or remove pages (diagrams).", "ls: count, items[]; add: index, name, id; rename: id, name; rm: id, name, remaining; reorder: id, name, index", PageCommand.Run),
            new CommandInfo("layout", "Auto-lay-out the diagram (layered, boundary aware; --labels places only the flow labels, --check reports obstructed ones).", "pages, components, labelsMoved, labelOverlaps; with --check also overlaps[]{flow,obstructedBy,kind,area}", LayoutCommand.Run),
            new CommandInfo("rules", "Compile MTMT templates into versioned analysis rule packs.", "operation,input,output,strict,status,packId,packName,sourceCount,emittedCount,skippedCount,warningCount,categoryDistribution{},diagnostics[]", RulesCommand.Run),
            new CommandInfo("analyze", "Analyze a threat model against its analysis rules.", "a SARIF-style model report (runs[].results[]); see docs/cli-reference.md", AnalyzeCommand.Run),
            new CommandInfo("analysis", "Validate a stored tmforge-analysis document (optionally against its model).", "operation, path, status, stale, schemaVersion, findingCount, problems[]", AnalysisCommand.Run),
            new CommandInfo("threats", "Report threats: the persisted, triaged view of the analysis findings (--write to persist).", "summary{count,written}, threats[]{id,ruleId,category,categoryId,categoryName,stride,title,mitigation,severity,priority,references[],scope,interaction}", ThreatsCommand.Run),
            new CommandInfo("accept", "Accept a generated threat's risk (marks it not-applicable with a reason).", "threat, state, reason", AcceptCommand.Run),
            new CommandInfo("report", "Generate an HTML report from a threat model.", "output, format, bytes", ReportCommand.Run),
            new CommandInfo("convert", "Convert a threat model between file formats.", "input, output, format", ConvertCommand.Run),
            new CommandInfo("apply", "Build a model from a declarative JSON manifest (all-or-nothing).", "output, format, dryRun, boundaries, elements, flows", ApplyCommand.Run),
            new CommandInfo("export", "Export a model as a declarative JSON manifest.", "output, boundaries, elements, flows", ExportCommand.Run),
            new CommandInfo("git-setup", "Wire git to use tmforge for .tm7 diff/merge (or --print the commands).", null, GitSetupCommand.Run),
            new CommandInfo("mcp", "Run an MCP server over stdio for AI agents (exposes the engine + authoring facade as tools).", null, McpCommand.Run),
        };

        private static readonly IReadOnlyDictionary<string, CommandInfo> ByVerb = Index(All);

        /// <summary>Gets every registered command, in presentation order.</summary>
        public static IReadOnlyList<CommandInfo> Commands => All;

        /// <summary>Finds the command for a verb, or <see langword="null"/> when the verb is unknown.</summary>
        /// <param name="verb">The verb to look up.</param>
        /// <returns>The matching command, or <see langword="null"/>.</returns>
        public static CommandInfo? Find(string verb)
        {
            return ByVerb.TryGetValue(verb, out CommandInfo? command) ? command : null;
        }

        private static IReadOnlyDictionary<string, CommandInfo> Index(IReadOnlyList<CommandInfo> commands)
        {
            Dictionary<string, CommandInfo> map = new Dictionary<string, CommandInfo>(StringComparer.Ordinal);
            foreach (CommandInfo command in commands)
            {
                map[command.Verb] = command;
            }

            return map;
        }
    }
}
