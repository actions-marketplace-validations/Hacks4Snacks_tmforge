namespace ThreatModelForge.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Evaluates one interaction-v1 expression over connector and synthetic diagram-root contexts.
    /// </summary>
    internal sealed class InteractionRule : Rule
    {
        private const int MaxInteractionsPerRule = 100000;
        private const int MaxOperationsPerRule = 1000000;
        private const int MaxFindingsPerRule = 100000;
        private const long MaxMessageCharactersPerRule = 64L * 1024 * 1024;

        private readonly InteractionExpression expression;
        private readonly string messageTemplate;
        private readonly RulePackDefinition packDefinition;
        private readonly RuleProvenance? provenance;
        private readonly StrideCategory? stride;
        private readonly IReadOnlyList<ThreatReference> threatReferences;
        private readonly IReadOnlyList<PropertyBinding> propertyBindings;
        private readonly Dictionary<string, string?> parents;
        private readonly bool evaluatesRoot;
        private readonly InteractionExpression.Evaluator evaluator;
        private readonly RuleThreatCategory? threatCategory;
        private readonly ThreatPriority? defaultThreatPriority;

        /// <summary>Initializes a new instance of the <see cref="InteractionRule"/> class.</summary>
        /// <param name="id">The effective rule identifier.</param>
        /// <param name="severity">The message severity.</param>
        /// <param name="message">The message template.</param>
        /// <param name="fullDescription">The full rule description.</param>
        /// <param name="helpText">The remediation guidance.</param>
        /// <param name="helpUri">The optional help URI.</param>
        /// <param name="stride">The optional STRIDE category.</param>
        /// <param name="threatCategory">The optional generalized threat category.</param>
        /// <param name="defaultThreatPriority">The optional default threat priority.</param>
        /// <param name="threatReferences">The external threat references.</param>
        /// <param name="expression">The compiled interaction expression.</param>
        /// <param name="packDefinition">The containing pack metadata.</param>
        /// <param name="provenance">The optional source provenance.</param>
        internal InteractionRule(
            string id,
            MessageSeverity severity,
            string message,
            string fullDescription,
            string helpText,
            Uri? helpUri,
            StrideCategory? stride,
            RuleThreatCategory? threatCategory,
            ThreatPriority? defaultThreatPriority,
            IReadOnlyList<ThreatReference> threatReferences,
            InteractionExpression expression,
            RulePackDefinition packDefinition,
            RuleProvenance? provenance)
            : base(id, severity, packDefinition.Id)
        {
            this.messageTemplate = message;
            this.FullDescription = fullDescription;
            this.HelpText = helpText;
            this.HelpUri = helpUri;
            this.stride = stride;
            this.threatCategory = threatCategory;
            this.defaultThreatPriority = defaultThreatPriority;
            this.threatReferences = threatReferences;
            this.expression = expression;
            this.evaluatesRoot = UsesRoot(expression);
            this.packDefinition = packDefinition;
            this.provenance = provenance;
            this.parents = packDefinition.ElementTypes.ToDictionary(
                element => element.Id,
                element => element.ParentId,
                StringComparer.OrdinalIgnoreCase);
            this.evaluator = new InteractionExpression.Evaluator(
                id,
                this.parents,
                MaxOperationsPerRule,
                accountExpressionNodes: true);
            this.propertyBindings = BuildPropertyBindings(expression, packDefinition, this.parents);
        }

        /// <inheritdoc/>
        public override StrideCategory? Stride => this.stride;

        /// <inheritdoc/>
        public override RuleThreatCategory? ThreatCategory => this.threatCategory ?? base.ThreatCategory;

        /// <inheritdoc/>
        public override ThreatPriority? DefaultThreatPriority => this.defaultThreatPriority;

        /// <inheritdoc/>
        public override IReadOnlyList<ThreatReference> ThreatReferences => this.threatReferences;

        /// <inheritdoc/>
        public override IReadOnlyList<PropertyBinding> PropertyBindings => this.propertyBindings;

        /// <inheritdoc/>
        public override RulePackDefinition PackDefinition => this.packDefinition;

        /// <inheritdoc/>
        public override RuleProvenance? Provenance => this.provenance;

        /// <inheritdoc/>
        public override void Evaluate(RuleEvaluationContext context)
        {
            _ = context ?? throw new ArgumentNullException(nameof(context));
            int interactions = 0;
            int operations = 0;
            int findings = 0;
            long messageCharacters = 0;
            foreach (DrawingSurfaceModel diagram in context.Model.DrawingSurfaceList)
            {
                context.AccountDeclarativeOperations(diagram.Lines.Count);

                // A deliberate divergence from the Microsoft Threat Modeling Tool, recorded by
                // MtmtRootDifferentialTests against a capture taken from the pinned tool build. The tool
                // cannot fire a ROOT predicate at all: it builds an element's type chain without the
                // virtual ROOT type at its head, so "source is 'ROOT'" is never true and the six
                // migrated ROOT threat types are inert. Threat Model Forge keeps them live as a
                // per-diagram STRIDE sweep - coverage the tool lost - so a ROOT rule fires once per
                // diagram rather than once per interaction.
                if (this.evaluatesRoot)
                {
                    InteractionExpression.EvaluationContext root = InteractionExpression.EvaluationContext.Root(diagram);
                    this.EvaluateContext(
                        context,
                        root,
                        ref interactions,
                        ref operations,
                        ref findings,
                        ref messageCharacters);
                }

                foreach (Connector flow in diagram.Lines.Values.OfType<Connector>())
                {
                    Entity? source = Resolve(diagram, flow.SourceGuid);
                    Entity? target = Resolve(diagram, flow.TargetGuid);
                    InteractionExpression.EvaluationContext interaction = new InteractionExpression.EvaluationContext(
                        diagram,
                        source,
                        target,
                        flow,
                        isRoot: false);
                    this.EvaluateContext(
                        context,
                        interaction,
                        ref interactions,
                        ref operations,
                        ref findings,
                        ref messageCharacters);
                }
            }
        }

        private static Entity? Resolve(DrawingSurfaceModel diagram, Guid id)
        {
            return diagram.Borders.TryGetValue(id, out object? value) ? value as Entity : null;
        }

        private static string? MessageTokenValue(
            string token,
            string sourceName,
            string targetName,
            string flowName)
        {
            if (string.Equals(token, "source", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "source.Name", StringComparison.OrdinalIgnoreCase))
            {
                return sourceName;
            }

            if (string.Equals(token, "target", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "target.Name", StringComparison.OrdinalIgnoreCase))
            {
                return targetName;
            }

            if (string.Equals(token, "flow", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(token, "flow.Name", StringComparison.OrdinalIgnoreCase))
            {
                return flowName;
            }

            return null;
        }

        private static bool UsesRoot(InteractionExpression expression)
        {
            if (expression.Operation == InteractionExpression.OperationKind.Type &&
                string.Equals(expression.Subject, "source", StringComparison.Ordinal) &&
                string.Equals(expression.Type, "ROOT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return (expression.Child != null && UsesRoot(expression.Child)) || expression.Children.Any(UsesRoot);
        }

        private static IReadOnlyList<PropertyBinding> BuildPropertyBindings(
            InteractionExpression expression,
            RulePackDefinition pack,
            IReadOnlyDictionary<string, string?> parents)
        {
            List<PropertyBinding> bindings = new List<PropertyBinding>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            AddPropertyBindings(expression, pack, parents, bindings, seen);
            return bindings.AsReadOnly();
        }

        private static void AddPropertyBindings(
            InteractionExpression expression,
            RulePackDefinition pack,
            IReadOnlyDictionary<string, string?> parents,
            List<PropertyBinding> bindings,
            ISet<string> seen)
        {
            if (expression.Operation == InteractionExpression.OperationKind.Property ||
                expression.Operation == InteractionExpression.OperationKind.FlatProperty)
            {
                foreach (string appliesTo in PropertyKinds(expression, pack, parents))
                {
                    string key = appliesTo + "\u0000" + expression.Property;
                    if (seen.Add(key))
                    {
                        bindings.Add(new PropertyBinding(appliesTo, expression.Property!));
                    }
                }
            }

            if (expression.Child != null)
            {
                AddPropertyBindings(expression.Child, pack, parents, bindings, seen);
            }

            foreach (InteractionExpression child in expression.Children)
            {
                AddPropertyBindings(child, pack, parents, bindings, seen);
            }
        }

        private static IEnumerable<string> PropertyKinds(
            InteractionExpression expression,
            RulePackDefinition pack,
            IReadOnlyDictionary<string, string?> parents)
        {
            if (expression.Kind != null)
            {
                return new[] { expression.Kind };
            }

            if (string.Equals(expression.Subject, "flow", StringComparison.Ordinal))
            {
                return new[] { "flow" };
            }

            RulePropertyDefinition? definition = pack.ResolveProperty(expression.Property!);
            List<string> kinds = (definition?.ElementTypeIds ?? Array.Empty<string>())
                .Select(type => PrimitiveKind(type, parents))
                .Where(kind => kind != null)
                .Select(kind => kind!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return kinds.Count > 0 ? kinds : new[] { "process", "datastore", "external" };
        }

        private static string? PrimitiveKind(
            string type,
            IReadOnlyDictionary<string, string?> parents)
        {
            HashSet<string> visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string? current = type;
            while (!string.IsNullOrWhiteSpace(current) && visited.Add(current!))
            {
                if (string.Equals(current, "GE.P", StringComparison.OrdinalIgnoreCase))
                {
                    return "process";
                }

                if (string.Equals(current, "GE.DS", StringComparison.OrdinalIgnoreCase))
                {
                    return "datastore";
                }

                if (string.Equals(current, "GE.EI", StringComparison.OrdinalIgnoreCase))
                {
                    return "external";
                }

                current = parents.TryGetValue(current!, out string? parent) ? parent : null;
            }

            return null;
        }

        private void EvaluateContext(
            RuleEvaluationContext context,
            InteractionExpression.EvaluationContext interaction,
            ref int interactions,
            ref int operations,
            ref int findings,
            ref long messageCharacters)
        {
            interactions++;
            if (interactions > MaxInteractionsPerRule)
            {
                throw new InvalidDataException($"Rule '{this.ID}' exceeded the interaction limit of {MaxInteractionsPerRule}.");
            }

            if (!this.evaluator.Evaluate(this.expression, interaction, context, ref operations))
            {
                return;
            }

            findings++;
            if (findings > MaxFindingsPerRule)
            {
                throw new InvalidDataException($"Rule '{this.ID}' exceeded the finding limit of {MaxFindingsPerRule}.");
            }

            context.AccountDeclarativeOperations(interaction.Source?.Properties.Count ?? 0);
            context.AccountDeclarativeOperations(interaction.Target?.Properties.Count ?? 0);
            context.AccountDeclarativeOperations(interaction.Flow?.Properties.Count ?? 0);
            string sourceName = interaction.Source?.Name() ?? string.Empty;
            string targetName = interaction.Target?.Name() ?? string.Empty;
            string flowName = interaction.Flow?.Name() ?? string.Empty;
            string message = ExpandMessageTemplate(
                this.messageTemplate,
                token => MessageTokenValue(token, sourceName, targetName, flowName));
            messageCharacters += message.Length;
            if (messageCharacters > MaxMessageCharactersPerRule)
            {
                throw new InvalidDataException(
                    $"Rule '{this.ID}' exceeded the message-output limit of {MaxMessageCharactersPerRule} characters.");
            }

            Entity target = interaction.IsRoot ? interaction.Diagram : interaction.Flow!;
            context.Writer.Write(this.CreateMessage(target, interaction.Diagram, message));
        }
    }
}
