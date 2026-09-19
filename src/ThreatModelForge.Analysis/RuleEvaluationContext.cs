namespace ThreatModelForge.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Configuration, services, and properties passed along to all rules during evaluation.
    /// </summary>
    public class RuleEvaluationContext
    {
        private const long DefaultDeclarativeOperationLimit = 10000000;

        private readonly Dictionary<string, string> variables = new Dictionary<string, string>(
            StringComparer.OrdinalIgnoreCase);

        private readonly SuppressedMessageWriter writer;

        private long declarativeOperationCount;
        private long declarativeOperationLimit = DefaultDeclarativeOperationLimit;
        private TimeSpan regexTime;
        private ConnectivityGraph? connectivityGraph;

        /// <summary>
        /// Initializes a new instance of the <see cref="RuleEvaluationContext"/> class.
        /// </summary>
        /// <param name="model">The input model.</param>
        /// <param name="writer">The writer for output messages.</param>
        /// <param name="variables">The defined variables.</param>
        /// <param name="modelSourcePath">The optional path to the input model.</param>
        /// <param name="analysisTool">The optional information about the tool.</param>
        public RuleEvaluationContext(
            ThreatModel model,
            MessageWriter writer,
            IReadOnlyDictionary<string, string>? variables = null,
            string? modelSourcePath = null,
            ToolInfo? analysisTool = null)
        {
            this.Model = model ?? throw new ArgumentNullException(nameof(model));
            this.ModelSourcePath = modelSourcePath;
            this.writer = new SuppressedMessageWriter(
                writer ?? throw new ArgumentNullException(nameof(writer)));
            this.AnalysisTool = analysisTool ??
                GetDefaultToolInfo();
            if (variables == null)
            {
                return;
            }

            foreach (string key in variables.Keys)
            {
                this.variables[key] = variables[key];
            }
        }

        /// <summary>
        /// Gets the threat model being evaluated.
        /// </summary>
        public ThreatModel Model { get; }

        /// <summary>
        /// Gets the path to the input model file for reference or <see langword="null"/> if not specified.
        /// </summary>
        public string? ModelSourcePath { get; }

        /// <summary>
        /// Gets information about the analysis tool.
        /// </summary>
        public ToolInfo AnalysisTool { get; }

        /// <summary>
        /// Gets the writer for messages.
        /// </summary>
        public MessageWriter Writer => this.writer;

        /// <summary>
        /// Gets the dictionary of variables.
        /// </summary>
        public IReadOnlyDictionary<string, string> Variables => this.variables;

        /// <summary>
        /// Gets the collection of individual suppressions active.
        /// </summary>
        public Collection<SuppressMessage> Suppressions => this.writer.Suppressions;

        /// <summary>
        /// Gets custom properties to include in the report.
        /// </summary>
        public IDictionary<string, string> CustomReportProperties { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Applies individual suppressions to the context.
        /// </summary>
        /// <param name="items">The list of suppressions.</param>
        /// <param name="ruleSet">The rule set that will be used.</param>
        public void ApplySuppressions(
            IEnumerable<SuppressMessage> items,
            RuleSet ruleSet)
        {
            if (items == null)
            {
                throw new ArgumentNullException(nameof(items));
            }

            if (ruleSet == null)
            {
                throw new ArgumentNullException(nameof(ruleSet));
            }

            foreach (SuppressMessage item in items.Where(item => item.TryResolve(ruleSet, this.Model, this.Writer)))
            {
                this.Suppressions.Add(item);
            }
        }

        /// <summary>
        /// Generates a report of the run after the rules have been evaluated.
        /// </summary>
        /// <param name="ruleSet">The rule set used.</param>
        /// <returns>A new instance of the <see cref="ModelReport"/> class.</returns>
        public ModelReport GenerateReport(RuleSet ruleSet)
        {
            if (ruleSet == null)
            {
                throw new ArgumentNullException(nameof(ruleSet));
            }

            ModelReport result = new ModelReport
            {
                SourcePath = this.ModelSourcePath ?? string.Empty,
                Assumptions = this.Model.MetaInformation?.Assumptions ?? string.Empty,
                Contributors = this.Model.MetaInformation?.Contributors ?? string.Empty,
                Description = this.Model.MetaInformation?.HighLevelSystemDescription ?? string.Empty,
                ExternalDependencies = this.Model.MetaInformation?.ExternalDependencies ?? string.Empty,
                Owner = this.Model.MetaInformation?.Owner ?? string.Empty,
                Reviewer = this.Model.MetaInformation?.Reviewer ?? string.Empty,
                ThreatGenerationEnabled = this.Model.ThreatGenerationEnabled ?? false,
                ThreatModelName = this.GetThreatModelName(),
                ToolVersion = this.Model.Version ?? string.Empty,
                KnowledgeBaseName = this.Model.KnowledgeBase?.Manifest?.Name ?? string.Empty,
                KnowledgeBaseVersion = this.Model.KnowledgeBase?.Manifest?.Version ?? string.Empty,
                AnalysisTool = this.AnalysisTool,
            };

            foreach (KeyValuePair<string, string> pair in this.CustomReportProperties)
            {
                result.CustomProperties.Add(pair.Key, pair.Value);
            }

            foreach (DrawingSurfaceModel diagram in this.Model.DrawingSurfaceList)
            {
                DiagramSummary summary = DiagramSummary.FromDrawingSurfaceModel(diagram);
                result.DiagramSummaries.Add(summary);
            }

            foreach (Rule rule in ruleSet.Rules)
            {
                RuleReport ruleReport = RuleReport.FromRule(rule);
                result.RuleReports.Add(ruleReport);

                CollectRuleReportMessages(rule, this.writer.Messages, ruleReport.Messages);
                CollectRuleReportMessages(rule, this.writer.SuppressedMessages, ruleReport.SuppressedMessages);
            }

            IEnumerable<RuleThreatCategory> declaredCategories = ruleSet.Rules
                .Select(rule => rule.PackDefinition)
                .Where(pack => pack != null)
                .Select(pack => pack!)
                .GroupBy(pack => pack.Id, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .SelectMany(pack => pack.Categories.Select(category => RuleThreatCategory.FromPack(pack, category)));
            foreach (RuleThreatCategory category in declaredCategories
                .Concat(ruleSet.Rules.Select(rule => rule.ThreatCategory).Where(category => category != null).Select(category => category!))
                .Where(category => category != null)
                .GroupBy(category => category.Id, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.OrderBy(category => category.Id, StringComparer.Ordinal).First())
                .OrderBy(category => category.Id, StringComparer.Ordinal))
            {
                result.ThreatCategories.Add(category);
            }

            return result;
        }

        /// <summary>
        /// Generates a listing from the model.
        /// </summary>
        /// <returns>A new instance of the <see cref="ModelListing"/> class.</returns>
        public ModelListing GenerateListing()
        {
            ModelListing result = new ModelListing();
            foreach (DrawingSurfaceModel diagram in this.Model.DrawingSurfaceList)
            {
                foreach (var component in diagram.Components())
                {
                    result.Components.Add(ComponentListing.FromComponent(component, diagram));
                }

                foreach (Connector connector in diagram.Lines.Values.OfType<Connector>())
                {
                    result.Connectors.Add(ConnectorListing.FromConnector(connector, diagram));
                }

                foreach (BorderBoundary border in diagram.TrustBoundaryBorders())
                {
                    result.TrustBoundaries.Add(TrustBoundaryListing.FromBorderBoundary(border, diagram));
                }

                foreach (LineBoundary line in diagram.TrustBoundaryLines())
                {
                    result.TrustBoundaries.Add(TrustBoundaryListing.FromLineBoundary(line, diagram));
                }
            }

            return result;
        }

        /// <summary>Charges declarative work to the shared invocation budget.</summary>
        /// <param name="operations">The number of operations to charge.</param>
        internal void AccountDeclarativeOperations(int operations = 1)
        {
            if (operations < 0 || this.declarativeOperationCount > this.declarativeOperationLimit - operations)
            {
                throw new InvalidDataException(
                    $"Analysis exceeded the declarative operation limit of {this.declarativeOperationLimit}.");
            }

            this.declarativeOperationCount += operations;
        }

        /// <summary>Gets the declarative operations consumed by this analysis invocation.</summary>
        /// <returns>The consumed operation count.</returns>
        internal long GetDeclarativeOperationCount()
        {
            return this.declarativeOperationCount;
        }

        /// <summary>Charges regex work to the shared one-second invocation budget.</summary>
        /// <param name="elapsed">The elapsed regular-expression evaluation time.</param>
        internal void AccountRegexTime(TimeSpan elapsed)
        {
            this.regexTime += elapsed;
            if (this.regexTime > TimeSpan.FromSeconds(1))
            {
                throw new InvalidDataException("Analysis exceeded the shared regex evaluation time limit of 1000 ms.");
            }
        }

        /// <summary>Gets the page-partitioned graph shared by all predicates in this evaluation.</summary>
        /// <returns>The lazily constructed graph index.</returns>
        internal ConnectivityGraph GetConnectivityGraph()
        {
            return this.connectivityGraph ??= new ConnectivityGraph(this);
        }

        /// <summary>Sets the declarative operation limit for this analysis invocation.</summary>
        /// <param name="value">The new non-negative limit.</param>
        internal void SetDeclarativeOperationLimit(long value)
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            this.declarativeOperationLimit = value;
        }

        private static void CollectRuleReportMessages(
            Rule rule,
            IEnumerable<Message> source,
            Collection<RuleReportMessage> target)
        {
            foreach (Message message in source.Where(message => string.Equals(message.Source?.ID, rule.ID, StringComparison.Ordinal)))
            {
                target.Add(RuleReportMessage.FromMessage(message));
            }
        }

        /// <summary>
        /// Provides a default tool info for the assembly if not supplied by the caller.
        /// </summary>
        /// <returns>A new instance of the <see cref="ToolInfo"/> class.</returns>
        private static ToolInfo GetDefaultToolInfo()
        {
            System.Reflection.Assembly asm = System.Reflection.Assembly.GetExecutingAssembly();
            System.Reflection.AssemblyName asmName = asm.GetName();
            return new ToolInfo
            {
                Name = asmName.Name,
                FullName = asmName.FullName,
                Version = asmName.Version.ToString(),
                Organization = Properties.Resources.DefaultToolOrganization,
                InformationUri = new Uri(Properties.Resources.DefaultToolInformationUri),
            };
        }

        private string GetThreatModelName()
        {
            string? metaThreatModelName = this.Model.MetaInformation?.ThreatModelName;
            if (!string.IsNullOrWhiteSpace(metaThreatModelName))
            {
                return metaThreatModelName!;
            }

            return !string.IsNullOrWhiteSpace(this.ModelSourcePath) ?
                System.IO.Path.GetFileNameWithoutExtension(this.ModelSourcePath) :
                string.Empty;
        }

        /// <summary>An invocation-local adjacency index; model topology must remain fixed during evaluation.</summary>
        internal sealed class ConnectivityGraph
        {
            private readonly Dictionary<DrawingSurfaceModel, GraphPage> pages = new Dictionary<DrawingSurfaceModel, GraphPage>();

            /// <summary>Initializes a new instance of the <see cref="ConnectivityGraph"/> class.</summary>
            /// <param name="context">The evaluation owning this index and its operation budget.</param>
            internal ConnectivityGraph(RuleEvaluationContext context)
            {
                if (context.Model.DrawingSurfaceList.Count > 1024)
                {
                    throw new InvalidDataException("Connectivity exceeds the limit of 1024 pages.");
                }

                long borders = 0;
                long lines = 0;
                foreach (DrawingSurfaceModel diagram in context.Model.DrawingSurfaceList)
                {
                    context.AccountDeclarativeOperations();
                    borders += diagram.Borders.Count;
                    lines += diagram.Lines.Count;
                }

                if (borders > 100000 || lines > 200000)
                {
                    throw new InvalidDataException("Connectivity exceeds the limit of 100000 shapes or 200000 lines.");
                }

                foreach (DrawingSurfaceModel diagram in context.Model.DrawingSurfaceList)
                {
                    context.AccountDeclarativeOperations(diagram.Borders.Count);
                    context.AccountDeclarativeOperations(diagram.Lines.Count);
                    GraphPage page = new GraphPage();
                    foreach (KeyValuePair<Guid, object> entry in diagram.Borders)
                    {
                        if (entry.Value is not Entity component || !component.IsComponent())
                        {
                            continue;
                        }

                        if (entry.Key == Guid.Empty || component.Guid != entry.Key)
                        {
                            throw new InvalidDataException("Connectivity requires non-empty component ids matching their page keys.");
                        }

                        page.Outgoing.Add(component.Guid, new List<Entity>());
                        page.Incoming.Add(component.Guid, new List<Entity>());
                    }

                    foreach (Connector flow in diagram.Lines.Values.OfType<Connector>())
                    {
                        if (!diagram.Borders.TryGetValue(flow.SourceGuid, out object? sourceValue) || sourceValue is not Entity source ||
                            !diagram.Borders.TryGetValue(flow.TargetGuid, out object? targetValue) || targetValue is not Entity target)
                        {
                            throw new InvalidDataException($"Connectivity requires flow '{flow.Guid}' endpoints to resolve on the same page.");
                        }

                        if (page.Outgoing.TryGetValue(source.Guid, out List<Entity>? outgoing) &&
                            page.Incoming.TryGetValue(target.Guid, out List<Entity>? incoming))
                        {
                            outgoing.Add(target);
                            incoming.Add(source);
                        }
                    }

                    this.pages.Add(diagram, page);
                }
            }

            /// <summary>Returns the neighbors of a component without scanning model lines again.</summary>
            /// <param name="diagram">The containing page.</param>
            /// <param name="component">The component id.</param>
            /// <param name="incoming">Whether to follow incoming rather than outgoing edges.</param>
            /// <returns>The page-local neighbors, including explicit self-loops and parallel edges.</returns>
            internal IReadOnlyList<Entity> Neighbors(DrawingSurfaceModel diagram, Guid component, bool incoming)
            {
                if (this.pages.TryGetValue(diagram, out GraphPage? page) &&
                    (incoming ? page.Incoming : page.Outgoing).TryGetValue(component, out List<Entity>? neighbors))
                {
                    return neighbors;
                }

                return Array.Empty<Entity>();
            }

            private sealed class GraphPage
            {
                public Dictionary<Guid, List<Entity>> Outgoing { get; } = new Dictionary<Guid, List<Entity>>();

                public Dictionary<Guid, List<Entity>> Incoming { get; } = new Dictionary<Guid, List<Entity>>();
            }
        }
    }
}
