namespace ThreatModelForge.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text.RegularExpressions;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// An immutable node in the interaction-v1 expression tree.
    /// </summary>
    internal sealed class InteractionExpression
    {
        private InteractionExpression(
            OperationKind operation,
            IReadOnlyList<InteractionExpression>? children = null,
            InteractionExpression? child = null,
            string? subject = null,
            string? type = null,
            string? kind = null,
            string? property = null,
            IReadOnlyList<string>? values = null,
            IReadOnlyList<string>? rejectedValues = null,
            string? equalTo = null,
            bool? present = null,
            string? boundaryType = null,
            bool firstValueOnly = false,
            decimal? greaterThan = null,
            decimal? greaterThanOrEqual = null,
            decimal? lessThan = null,
            decimal? lessThanOrEqual = null,
            Regex? pattern = null)
        {
            this.Operation = operation;
            this.Children = children ?? Array.Empty<InteractionExpression>();
            this.Child = child;
            this.Subject = subject;
            this.Type = type;
            this.Kind = kind;
            this.Property = property;
            this.Values = values ?? Array.Empty<string>();
            this.RejectedValues = rejectedValues ?? Array.Empty<string>();
            this.EqualTo = equalTo;
            this.Present = present;
            this.BoundaryType = boundaryType;
            this.FirstValueOnly = firstValueOnly;
            this.GreaterThan = greaterThan;
            this.GreaterThanOrEqual = greaterThanOrEqual;
            this.LessThan = lessThan;
            this.LessThanOrEqual = lessThanOrEqual;
            this.Pattern = pattern;
        }

        /// <summary>The operation represented by this node.</summary>
        internal enum OperationKind
        {
            /// <summary>Logical conjunction.</summary>
            All,

            /// <summary>Logical disjunction.</summary>
            Any,

            /// <summary>Logical negation.</summary>
            Not,

            /// <summary>Subject type equality.</summary>
            Type,

            /// <summary>Subject primitive-kind equality.</summary>
            Kind,

            /// <summary>Subject existence.</summary>
            Exists,

            /// <summary>Subject property value membership.</summary>
            Property,

            /// <summary>Subject property presence.</summary>
            Present,

            /// <summary>Composite first-value property condition for the legacy flat dialect.</summary>
            FlatProperty,

            /// <summary>Specific crossed-boundary type.</summary>
            Crosses,

            /// <summary>Positive-length reachability from a filtered upstream component.</summary>
            ReachableFrom,

            /// <summary>A direct outgoing connector to a filtered component.</summary>
            ConnectsTo,
        }

        /// <summary>Gets the node operation.</summary>
        public OperationKind Operation { get; }

        /// <summary>Gets logical child expressions.</summary>
        public IReadOnlyList<InteractionExpression> Children { get; }

        /// <summary>Gets the negated child expression.</summary>
        public InteractionExpression? Child { get; }

        /// <summary>Gets the interaction subject.</summary>
        public string? Subject { get; }

        /// <summary>Gets the expected element type.</summary>
        public string? Type { get; }

        /// <summary>Gets the expected primitive kind.</summary>
        public string? Kind { get; }

        /// <summary>Gets the runtime property name.</summary>
        public string? Property { get; }

        /// <summary>Gets accepted property values.</summary>
        public IReadOnlyList<string> Values { get; }

        /// <summary>Gets rejected property values for a composite flat condition.</summary>
        public IReadOnlyList<string> RejectedValues { get; }

        /// <summary>Gets the required equality value for a composite flat condition.</summary>
        public string? EqualTo { get; }

        /// <summary>Gets the required presence state for a composite flat condition.</summary>
        public bool? Present { get; }

        /// <summary>Gets the exclusive numeric lower bound.</summary>
        public decimal? GreaterThan { get; }

        /// <summary>Gets the inclusive numeric lower bound.</summary>
        public decimal? GreaterThanOrEqual { get; }

        /// <summary>Gets the exclusive numeric upper bound.</summary>
        public decimal? LessThan { get; }

        /// <summary>Gets the inclusive numeric upper bound.</summary>
        public decimal? LessThanOrEqual { get; }

        /// <summary>Gets a value indicating whether a numeric constraint is present.</summary>
        public bool HasNumericMatcher => this.GreaterThan.HasValue || this.GreaterThanOrEqual.HasValue ||
            this.LessThan.HasValue || this.LessThanOrEqual.HasValue;

        /// <summary>Gets the validated, reusable regular expression.</summary>
        public Regex? Pattern { get; }

        /// <summary>Gets the expected crossed-boundary type.</summary>
        public string? BoundaryType { get; }

        /// <summary>Gets a value indicating whether only the first stored property value is considered.</summary>
        public bool FirstValueOnly { get; }

        /// <summary>Creates a conjunction.</summary>
        /// <param name="children">The expressions that must all match.</param>
        /// <returns>The conjunction expression.</returns>
        public static InteractionExpression All(IReadOnlyList<InteractionExpression> children) =>
            new InteractionExpression(OperationKind.All, children: children);

        /// <summary>Creates a disjunction.</summary>
        /// <param name="children">The expressions of which at least one must match.</param>
        /// <returns>The disjunction expression.</returns>
        public static InteractionExpression Any(IReadOnlyList<InteractionExpression> children) =>
            new InteractionExpression(OperationKind.Any, children: children);

        /// <summary>Creates a negation.</summary>
        /// <param name="child">The expression to negate.</param>
        /// <returns>The negation expression.</returns>
        public static InteractionExpression Negate(InteractionExpression child) =>
            new InteractionExpression(OperationKind.Not, child: child);

        /// <summary>Creates a subject type predicate.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <param name="type">The expected type.</param>
        /// <returns>The type predicate.</returns>
        public static InteractionExpression TypeIs(string subject, string type) =>
            new InteractionExpression(OperationKind.Type, subject: subject, type: type);

        /// <summary>Creates a primitive-kind predicate.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <param name="kind">The expected primitive kind.</param>
        /// <returns>The primitive-kind predicate.</returns>
        public static InteractionExpression KindIs(string subject, string kind) =>
            new InteractionExpression(OperationKind.Kind, subject: subject, kind: kind);

        /// <summary>Creates a subject-existence predicate.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <returns>The subject-existence predicate.</returns>
        public static InteractionExpression SubjectExists(string subject) =>
            new InteractionExpression(OperationKind.Exists, subject: subject);

        /// <summary>Creates a subject property predicate.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <param name="property">The runtime property name.</param>
        /// <param name="values">The accepted values.</param>
        /// <returns>The property predicate.</returns>
        public static InteractionExpression PropertyIn(string subject, string property, IReadOnlyList<string> values) =>
            new InteractionExpression(OperationKind.Property, subject: subject, property: property, values: values);

        /// <summary>Creates a regular-expression property predicate.</summary>
        /// <param name="subject">The subject to read.</param>
        /// <param name="property">The property to read.</param>
        /// <param name="pattern">The validated expression with a match timeout.</param>
        /// <returns>The regular-expression predicate.</returns>
        public static InteractionExpression RegexProperty(string subject, string property, Regex pattern) =>
            new InteractionExpression(OperationKind.Property, subject: subject, property: property, pattern: pattern);

        /// <summary>Creates a numeric property predicate.</summary>
        /// <param name="subject">The subject to read.</param>
        /// <param name="property">The property to read.</param>
        /// <param name="greaterThan">The exclusive lower bound.</param>
        /// <param name="greaterThanOrEqual">The inclusive lower bound.</param>
        /// <param name="lessThan">The exclusive upper bound.</param>
        /// <param name="lessThanOrEqual">The inclusive upper bound.</param>
        /// <returns>The numeric predicate.</returns>
        public static InteractionExpression NumericProperty(
            string subject,
            string property,
            decimal? greaterThan,
            decimal? greaterThanOrEqual,
            decimal? lessThan,
            decimal? lessThanOrEqual) =>
            new InteractionExpression(
                OperationKind.Property,
                subject: subject,
                property: property,
                greaterThan: greaterThan,
                greaterThanOrEqual: greaterThanOrEqual,
                lessThan: lessThan,
                lessThanOrEqual: lessThanOrEqual);

        /// <summary>Creates a first-value property predicate for legacy flat-rule compatibility.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <param name="property">The runtime property name.</param>
        /// <param name="values">The accepted values.</param>
        /// <returns>The first-value property predicate.</returns>
        public static InteractionExpression FirstPropertyIn(
            string subject,
            string property,
            IReadOnlyList<string> values) =>
            new InteractionExpression(
                OperationKind.Property,
                subject: subject,
                property: property,
                values: values,
                firstValueOnly: true);

        /// <summary>Creates a first-value property-presence predicate for legacy flat rules.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <param name="property">The runtime property name.</param>
        /// <returns>The property-presence predicate.</returns>
        public static InteractionExpression FirstPropertyPresent(string subject, string property) =>
            new InteractionExpression(
                OperationKind.Present,
                subject: subject,
                property: property,
                firstValueOnly: true);

        /// <summary>Creates one composite first-value property condition for the legacy flat dialect.</summary>
        /// <param name="subject">The interaction subject.</param>
        /// <param name="property">The runtime property name.</param>
        /// <param name="anyOf">The accepted values.</param>
        /// <param name="notAnyOf">The rejected values.</param>
        /// <param name="equalTo">The required equality value.</param>
        /// <param name="present">The required presence state.</param>
        /// <param name="greaterThan">The exclusive numeric lower bound.</param>
        /// <param name="greaterThanOrEqual">The inclusive numeric lower bound.</param>
        /// <param name="lessThan">The exclusive numeric upper bound.</param>
        /// <param name="lessThanOrEqual">The inclusive numeric upper bound.</param>
        /// <param name="pattern">The optional validated regular expression.</param>
        /// <param name="kind">The optional enclosing component-kind filter for property policy.</param>
        /// <returns>The composite property condition.</returns>
        public static InteractionExpression FlatPropertyCondition(
            string subject,
            string property,
            IReadOnlyList<string>? anyOf,
            IReadOnlyList<string>? notAnyOf,
            string? equalTo,
            bool? present,
            decimal? greaterThan = null,
            decimal? greaterThanOrEqual = null,
            decimal? lessThan = null,
            decimal? lessThanOrEqual = null,
            Regex? pattern = null,
            string? kind = null) =>
            new InteractionExpression(
                OperationKind.FlatProperty,
                subject: subject,
                property: property,
                values: anyOf?.ToArray(),
                rejectedValues: notAnyOf?.ToArray(),
                equalTo: equalTo,
                present: present,
                firstValueOnly: true,
                greaterThan: greaterThan,
                greaterThanOrEqual: greaterThanOrEqual,
                lessThan: lessThan,
                lessThanOrEqual: lessThanOrEqual,
                pattern: pattern,
                kind: kind);

        /// <summary>Creates a crossed-boundary predicate.</summary>
        /// <param name="boundaryType">The expected boundary type.</param>
        /// <returns>The boundary predicate.</returns>
        public static InteractionExpression Crosses(string boundaryType) =>
            new InteractionExpression(OperationKind.Crosses, boundaryType: boundaryType);

        /// <summary>Creates a predicate that matches any crossed trust boundary.</summary>
        /// <returns>The generic crossed-boundary predicate.</returns>
        public static InteractionExpression CrossesAnyBoundary() =>
            new InteractionExpression(OperationKind.Crosses);

        /// <summary>Creates a directed component connectivity predicate.</summary>
        /// <param name="subject">The component subject.</param>
        /// <param name="filter">The filter evaluated against each connected component as source.</param>
        /// <param name="incoming">Whether to follow incoming paths rather than one outgoing edge.</param>
        /// <returns>The connectivity predicate.</returns>
        public static InteractionExpression Connectivity(string subject, InteractionExpression filter, bool incoming) =>
            new InteractionExpression(incoming ? OperationKind.ReachableFrom : OperationKind.ConnectsTo, child: filter, subject: subject);

        /// <summary>Checks whether an entity belongs to one of the flat dialect's primitive kinds.</summary>
        /// <param name="entity">The entity to classify.</param>
        /// <param name="kind">The expected primitive kind.</param>
        /// <returns><see langword="true"/> when the entity has the expected kind.</returns>
        internal static bool MatchesPrimitiveKind(Entity entity, string kind)
        {
            if (string.Equals(kind, "external", StringComparison.OrdinalIgnoreCase))
            {
                return entity.IsExternalInteractor();
            }

            if (string.Equals(kind, "datastore", StringComparison.OrdinalIgnoreCase))
            {
                return entity.IsStorageComponent();
            }

            return string.Equals(kind, "process", StringComparison.OrdinalIgnoreCase) &&
                entity.IsComponent() &&
                !entity.IsExternalInteractor() &&
                !entity.IsStorageComponent();
        }

        /// <summary>An evaluation context for one connector, component, or synthetic diagram root.</summary>
        internal sealed class EvaluationContext
        {
            /// <summary>Initializes a new instance of the <see cref="EvaluationContext"/> class.</summary>
            /// <param name="diagram">The containing diagram.</param>
            /// <param name="source">The source subject, or a flat component candidate.</param>
            /// <param name="target">The target subject.</param>
            /// <param name="flow">The flow subject.</param>
            /// <param name="isRoot">Whether this is the synthetic diagram-root context.</param>
            internal EvaluationContext(
                DrawingSurfaceModel diagram,
                Entity? source,
                Entity? target,
                Connector? flow,
                bool isRoot)
            {
                this.Diagram = diagram;
                this.Source = source;
                this.Target = target;
                this.Flow = flow;
                this.IsRoot = isRoot;
            }

            /// <summary>Gets the containing diagram.</summary>
            internal DrawingSurfaceModel Diagram { get; }

            /// <summary>Gets the source subject.</summary>
            internal Entity? Source { get; }

            /// <summary>Gets the target subject.</summary>
            internal Entity? Target { get; }

            /// <summary>Gets the flow subject.</summary>
            internal Connector? Flow { get; }

            /// <summary>Gets a value indicating whether this is the synthetic diagram root.</summary>
            internal bool IsRoot { get; }

            /// <summary>Creates a synthetic diagram-root context.</summary>
            /// <param name="diagram">The diagram.</param>
            /// <returns>The root context.</returns>
            internal static EvaluationContext Root(DrawingSurfaceModel diagram) =>
                new EvaluationContext(diagram, null, null, null, isRoot: true);

            /// <summary>Returns concrete trust-boundary candidates in the diagram.</summary>
            /// <returns>The boundary candidates.</returns>
            internal IEnumerable<Entity> BoundaryCandidates() =>
                this.Diagram.TrustBoundaryBorders().OfType<Entity>()
                    .Concat(this.Diagram.TrustBoundaryLines().OfType<Entity>());

            /// <summary>Resolves an expression subject.</summary>
            /// <param name="subject">The subject name.</param>
            /// <returns>The subject entity, or <see langword="null"/>.</returns>
            internal Entity? Subject(string subject)
            {
                if (string.Equals(subject, "source", StringComparison.Ordinal))
                {
                    return this.Source;
                }

                if (string.Equals(subject, "target", StringComparison.Ordinal))
                {
                    return this.Target;
                }

                return string.Equals(subject, "flow", StringComparison.Ordinal) ? this.Flow : null;
            }
        }

        /// <summary>Evaluates immutable expressions with optional per-rule operation limits.</summary>
        internal sealed class Evaluator
        {
            private readonly int? operationLimit;
            private readonly bool accountExpressionNodes;
            private readonly IReadOnlyDictionary<string, string?> parents;
            private readonly string ruleId;

            /// <summary>Initializes a new instance of the <see cref="Evaluator"/> class.</summary>
            /// <param name="ruleId">The rule id used in limit errors.</param>
            /// <param name="parents">The element-type parent map.</param>
            /// <param name="operationLimit">The optional per-rule operation limit.</param>
            /// <param name="accountExpressionNodes">Whether expression nodes consume shared operations.</param>
            internal Evaluator(
                string ruleId,
                IReadOnlyDictionary<string, string?> parents,
                int? operationLimit,
                bool accountExpressionNodes)
            {
                this.ruleId = ruleId;
                this.parents = parents;
                this.operationLimit = operationLimit;
                this.accountExpressionNodes = accountExpressionNodes;
            }

            /// <summary>Evaluates one expression.</summary>
            /// <param name="expression">The expression.</param>
            /// <param name="interaction">The subject context.</param>
            /// <param name="context">The shared rule context.</param>
            /// <param name="operations">The rule-local operation count.</param>
            /// <returns><see langword="true"/> when the expression matches.</returns>
            internal bool Evaluate(
                InteractionExpression expression,
                EvaluationContext interaction,
                RuleEvaluationContext context,
                ref int operations)
            {
                if (this.accountExpressionNodes)
                {
                    this.AccountOperation(context, ref operations);
                }

                switch (expression.Operation)
                {
                    case OperationKind.All:
                        foreach (InteractionExpression child in expression.Children)
                        {
                            if (!this.Evaluate(child, interaction, context, ref operations))
                            {
                                return false;
                            }
                        }

                        return true;
                    case OperationKind.Any:
                        foreach (InteractionExpression child in expression.Children)
                        {
                            if (this.Evaluate(child, interaction, context, ref operations))
                            {
                                return true;
                            }
                        }

                        return false;
                    case OperationKind.Not:
                        return !this.Evaluate(expression.Child!, interaction, context, ref operations);
                    case OperationKind.Crosses:
                        return this.EvaluateCrosses(expression, interaction, context, ref operations);
                    case OperationKind.Type:
                        if (string.Equals(expression.Subject, "source", StringComparison.Ordinal) &&
                            string.Equals(expression.Type, "ROOT", StringComparison.OrdinalIgnoreCase))
                        {
                            return interaction.IsRoot;
                        }

                        return this.MatchesType(
                            interaction.Subject(expression.Subject!),
                            expression.Type!,
                            context,
                            ref operations);
                    case OperationKind.Kind:
                        Entity? kindSubject = interaction.Subject(expression.Subject!);
                        if (!this.accountExpressionNodes)
                        {
                            this.AccountOperation(context, ref operations);
                        }

                        return kindSubject != null && MatchesPrimitiveKind(kindSubject, expression.Kind!);
                    case OperationKind.Exists:
                        return interaction.Subject(expression.Subject!) != null;
                    case OperationKind.Property:
                        return this.EvaluateProperty(expression, interaction, context, ref operations);
                    case OperationKind.Present:
                        return this.EvaluatePresence(expression, interaction, context, ref operations);
                    case OperationKind.FlatProperty:
                        return this.EvaluateFlatProperty(expression, interaction, context, ref operations);
                    case OperationKind.ReachableFrom:
                    case OperationKind.ConnectsTo:
                        return this.EvaluateConnectivity(expression, interaction, context, ref operations);
                    default:
                        return false;
                }
            }

            private static bool Crosses(Connector flow, Entity boundary) =>
                boundary is BorderBoundary border
                    ? flow.Crosses(border)
                    : boundary is LineBoundary line && flow.Crosses(line);

            private bool EvaluateConnectivity(
                InteractionExpression expression,
                EvaluationContext interaction,
                RuleEvaluationContext context,
                ref int operations)
            {
                Entity? subject = interaction.Subject(expression.Subject!);
                if (subject == null || subject is Connector || !subject.IsComponent())
                {
                    return false;
                }

                RuleEvaluationContext.ConnectivityGraph graph = context.GetConnectivityGraph();
                bool incoming = expression.Operation == OperationKind.ReachableFrom;
                Queue<Guid> pending = new Queue<Guid>();
                HashSet<Guid> visited = new HashSet<Guid>();
                pending.Enqueue(subject.Guid);
                while (pending.Count > 0)
                {
                    this.AccountOperation(context, ref operations);
                    Guid current = pending.Dequeue();
                    foreach (Entity neighbor in graph.Neighbors(interaction.Diagram, current, incoming))
                    {
                        this.AccountOperation(context, ref operations);
                        if (!visited.Add(neighbor.Guid))
                        {
                            continue;
                        }

                        EvaluationContext candidate = new EvaluationContext(interaction.Diagram, neighbor, null, null, isRoot: false);
                        if (this.Evaluate(expression.Child!, candidate, context, ref operations))
                        {
                            return true;
                        }

                        if (incoming)
                        {
                            pending.Enqueue(neighbor.Guid);
                        }
                    }
                }

                return false;
            }

            private bool EvaluateCrosses(
                InteractionExpression expression,
                EvaluationContext interaction,
                RuleEvaluationContext context,
                ref int operations)
            {
                if (interaction.Flow == null)
                {
                    return false;
                }

                context.AccountDeclarativeOperations(interaction.Diagram.Borders.Count);
                context.AccountDeclarativeOperations(interaction.Diagram.Lines.Count);
                foreach (Entity boundary in interaction.BoundaryCandidates())
                {
                    this.AccountLocalOperation(ref operations);
                    if (Crosses(interaction.Flow, boundary) &&
                        (expression.BoundaryType == null ||
                        this.MatchesType(boundary, expression.BoundaryType, context, ref operations)))
                    {
                        return true;
                    }
                }

                return false;
            }

            private bool EvaluateProperty(
                InteractionExpression expression,
                EvaluationContext interaction,
                RuleEvaluationContext context,
                ref int operations)
            {
                Entity? subject = interaction.Subject(expression.Subject!);
                if (!this.TryGetValues(subject, expression.Property!, context, ref operations, out IList<string> values))
                {
                    return false;
                }

                IEnumerable<string> candidates = expression.FirstValueOnly ? values.Take(1) : values;
                foreach (string value in candidates)
                {
                    if (expression.Pattern != null)
                    {
                        if (this.MatchesRegexValue(expression, value, context, ref operations))
                        {
                            return true;
                        }

                        continue;
                    }

                    if (expression.HasNumericMatcher)
                    {
                        if (this.MatchesNumericValue(expression, value, context, ref operations))
                        {
                            return true;
                        }

                        continue;
                    }

                    if (expression.FirstValueOnly && string.IsNullOrWhiteSpace(value))
                    {
                        return false;
                    }

                    foreach (string expected in expression.Values)
                    {
                        this.AccountOperation(context, ref operations);
                        if (string.Equals(value, expected, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            private bool EvaluatePresence(
                InteractionExpression expression,
                EvaluationContext interaction,
                RuleEvaluationContext context,
                ref int operations)
            {
                Entity? subject = interaction.Subject(expression.Subject!);
                if (!this.TryGetValues(subject, expression.Property!, context, ref operations, out IList<string> values))
                {
                    return false;
                }

                return expression.FirstValueOnly
                    ? !string.IsNullOrWhiteSpace(values[0])
                    : values.Any(value => !string.IsNullOrWhiteSpace(value));
            }

            private bool EvaluateFlatProperty(
                InteractionExpression expression,
                EvaluationContext interaction,
                RuleEvaluationContext context,
                ref int operations)
            {
                Entity? subject = interaction.Subject(expression.Subject!);
                if (subject == null)
                {
                    return false;
                }

                this.AccountOperations(context, ref operations, subject.Properties.Count);
                this.AccountOperations(context, ref operations, subject.Properties.Count);
                bool defined = subject.TryGetCustomPropertyValue(expression.Property!, out string? raw);
                string value = raw ?? string.Empty;
                bool isPresent = defined && !string.IsNullOrWhiteSpace(value);
                bool hasMatcher = expression.Present.HasValue ||
                    expression.EqualTo != null ||
                    expression.Values.Count > 0 ||
                    expression.RejectedValues.Count > 0 ||
                    expression.HasNumericMatcher || expression.Pattern != null;
                if (!hasMatcher)
                {
                    return isPresent;
                }

                if (expression.Present.HasValue && isPresent != expression.Present.Value)
                {
                    return false;
                }

                if (expression.EqualTo != null)
                {
                    this.AccountOperation(context, ref operations);
                    if (!isPresent || !string.Equals(value, expression.EqualTo, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }

                if (expression.Values.Count > 0 &&
                    (!isPresent || !this.ContainsFlatValue(expression.Values, value, context, ref operations)))
                {
                    return false;
                }

                if (expression.RejectedValues.Count > 0 &&
                    isPresent &&
                    this.ContainsFlatValue(expression.RejectedValues, value, context, ref operations))
                {
                    return false;
                }

                return (!expression.HasNumericMatcher ||
                    (isPresent && this.MatchesNumericValue(expression, value, context, ref operations))) &&
                    (expression.Pattern == null ||
                    (isPresent && this.MatchesRegexValue(expression, value, context, ref operations)));
            }

            private bool MatchesRegexValue(
                InteractionExpression expression,
                string value,
                RuleEvaluationContext context,
                ref int operations)
            {
                const int maximumLength = 4096;
                if (value.Length > maximumLength)
                {
                    throw new InvalidDataException($"Rule '{this.ruleId}' regex input for '{expression.Property}' exceeds {maximumLength} characters.");
                }

                this.AccountOperations(context, ref operations, value.Length + 1);
                if (string.IsNullOrWhiteSpace(value))
                {
                    return false;
                }

                context.AccountRegexTime(TimeSpan.Zero);
                Stopwatch elapsed = Stopwatch.StartNew();
                try
                {
                    return expression.Pattern!.IsMatch(value);
                }
                catch (RegexMatchTimeoutException ex)
                {
                    throw new InvalidDataException($"Rule '{this.ruleId}' regex match for '{expression.Property}' exceeded the 50 ms timeout.", ex);
                }
                finally
                {
                    context.AccountRegexTime(elapsed.Elapsed);
                }
            }

            private bool MatchesNumericValue(
                InteractionExpression expression,
                string value,
                RuleEvaluationContext context,
                ref int operations)
            {
                const int maximumLength = 256;
                this.AccountOperations(context, ref operations, Math.Min(value.Length, maximumLength) + 1);
                return value.Length <= maximumLength &&
                    decimal.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out decimal number) &&
                    (!expression.GreaterThan.HasValue || number > expression.GreaterThan.Value) &&
                    (!expression.GreaterThanOrEqual.HasValue || number >= expression.GreaterThanOrEqual.Value) &&
                    (!expression.LessThan.HasValue || number < expression.LessThan.Value) &&
                    (!expression.LessThanOrEqual.HasValue || number <= expression.LessThanOrEqual.Value);
            }

            private bool ContainsFlatValue(
                IEnumerable<string> candidates,
                string value,
                RuleEvaluationContext context,
                ref int operations)
            {
                foreach (string candidate in candidates)
                {
                    this.AccountOperation(context, ref operations);
                    if (string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }

            private bool TryGetValues(
                Entity? subject,
                string property,
                RuleEvaluationContext context,
                ref int operations,
                out IList<string> values)
            {
                values = Array.Empty<string>();
                if (subject == null)
                {
                    return false;
                }

                this.AccountOperations(context, ref operations, subject.Properties.Count);
                this.AccountOperations(context, ref operations, subject.Properties.Count);
                return subject.TryGetCustomPropertyValues(property, out values);
            }

            private bool MatchesType(
                Entity? entity,
                string expected,
                RuleEvaluationContext context,
                ref int operations)
            {
                return entity != null &&
                    (this.MatchesTypeId(entity.TypeId, expected, context, ref operations) ||
                    this.MatchesTypeId(entity.GenericTypeId, expected, context, ref operations));
            }

            private bool MatchesTypeId(
                string? actual,
                string expected,
                RuleEvaluationContext context,
                ref int operations)
            {
                HashSet<string> visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                while (!string.IsNullOrWhiteSpace(actual) && visited.Add(actual!))
                {
                    this.AccountOperation(context, ref operations);
                    if (string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    actual = this.parents.TryGetValue(actual!, out string? parent) ? parent : null;
                }

                return false;
            }

            private void AccountOperation(RuleEvaluationContext context, ref int operations) =>
                this.AccountOperations(context, ref operations, count: 1);

            private void AccountOperations(RuleEvaluationContext context, ref int operations, int count)
            {
                context.AccountDeclarativeOperations(count);
                if (count < 0 || operations > int.MaxValue - count)
                {
                    throw new InvalidDataException($"Rule '{this.ruleId}' exceeded the operation counter range.");
                }

                if (this.operationLimit.HasValue && operations > this.operationLimit.Value - count)
                {
                    throw new InvalidDataException(
                        $"Rule '{this.ruleId}' exceeded the operation limit of {this.operationLimit.Value}.");
                }

                operations += count;
            }

            private void AccountLocalOperation(ref int operations)
            {
                if (operations == int.MaxValue)
                {
                    throw new InvalidDataException($"Rule '{this.ruleId}' exceeded the operation counter range.");
                }

                operations++;
                if (this.operationLimit.HasValue && operations > this.operationLimit.Value)
                {
                    throw new InvalidDataException(
                        $"Rule '{this.ruleId}' exceeded the operation limit of {this.operationLimit.Value}.");
                }
            }
        }
    }
}
