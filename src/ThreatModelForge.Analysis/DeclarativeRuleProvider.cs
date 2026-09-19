namespace ThreatModelForge.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using System.Text.RegularExpressions;
    using System.Xml;
    using ThreatModelForge.Editing;

    /// <summary>
    /// Loads <see cref="DeclarativeRule"/> instances from declarative spec files (<c>*.tmrules.json</c>).
    /// Loading is resilient: a spec file that cannot be read or parsed, or an individual rule that fails
    /// validation, is reported through the diagnostics sink and skipped rather than aborting the load, so
    /// one malformed rule never takes down the whole set. Property names are validated against the
    /// typed property schema and produce a warning (not a failure) when unknown, because custom
    /// properties are open-ended.
    /// </summary>
    public static class DeclarativeRuleProvider
    {
        /// <summary>The maximum accepted size of one declarative rule-pack file.</summary>
        internal const int MaxRuleFileBytes = 8 * 1024 * 1024;
        private const int MaxSourceFiles = 128;
        private const long MaxTotalRuleBytes = 32L * 1024 * 1024;
        private const int MaxRulesPerPack = 4096;
        private const int MaxRulesPerLoad = 16384;
        private const int MaxCategoriesPerPack = 512;
        private const int MaxCategoriesPerLoad = 2048;
        private const int MaxElementTypesPerPack = 4096;
        private const int MaxElementTypesPerLoad = 16384;
        private const int MaxPropertiesPerPack = 8192;
        private const int MaxPropertiesPerLoad = 32768;
        private const int MaxCatalogValuesPerPack = 65536;
        private const int MaxCatalogValuesPerLoad = 262144;
        private const int MaxStringLength = 65536;
        private const int MaxJsonDepth = 256;

        private static readonly JsonSerializerOptions Options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            MaxDepth = MaxJsonDepth,
        };

        private static readonly JsonSerializerOptions StrictOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            MaxDepth = MaxJsonDepth,
        };

        private static readonly HashSet<string> Kinds = new HashSet<string>(
            new[] { "process", "datastore", "external", "flow" },
            StringComparer.OrdinalIgnoreCase);

        private static readonly StringComparer PathComparer =
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)
                ? StringComparer.OrdinalIgnoreCase
                : StringComparer.Ordinal;

        /// <summary>
        /// Loads all declarative rules from the given spec paths. A path may be a single
        /// <c>*.tmrules.json</c> file or a directory that is searched recursively for them.
        /// </summary>
        /// <param name="paths">The spec files or directories to load.</param>
        /// <param name="diagnostics">An optional sink for non-fatal load and validation warnings.</param>
        /// <returns>The loaded rules, in file then declaration order.</returns>
        public static IReadOnlyList<Rule> Load(IEnumerable<string> paths, Action<string>? diagnostics = null)
        {
            return LoadBundle(paths, diagnostics).Rules;
        }

        /// <summary>
        /// Loads compiled declarative rules together with validated version 2 pack metadata.
        /// Legacy <c>{ "rules": [...] }</c> files continue to contribute rules but no pack metadata.
        /// </summary>
        /// <param name="paths">The spec files or directories to load.</param>
        /// <param name="diagnostics">An optional sink for non-fatal load and validation warnings.</param>
        /// <returns>The compiled rules and validated pack definitions.</returns>
        public static RuleBundle LoadBundle(IEnumerable<string> paths, Action<string>? diagnostics = null)
        {
            if (paths == null)
            {
                throw new ArgumentNullException(nameof(paths));
            }

            return LoadBundle(paths, null, diagnostics);
        }

        /// <summary>
        /// Loads compiled declarative rules from in-memory content, for hosts that cannot resolve
        /// filesystem paths. The content is parsed, validated, and fingerprinted exactly as a file is,
        /// so the same pack yields the same rules and the same fingerprint on every transport.
        /// </summary>
        /// <param name="contents">The rule documents to load.</param>
        /// <param name="diagnostics">An optional sink for non-fatal load and validation warnings.</param>
        /// <returns>The compiled rules and validated pack definitions.</returns>
        public static RuleBundle LoadBundle(IEnumerable<RuleContent> contents, Action<string>? diagnostics = null)
        {
            if (contents == null)
            {
                throw new ArgumentNullException(nameof(contents));
            }

            return LoadBundle(null, contents, diagnostics);
        }

        /// <summary>
        /// Loads compiled declarative rules from filesystem paths and in-memory content together, so a
        /// host that mixes both sees one effective bundle with one duplicate-identity check.
        /// </summary>
        /// <param name="paths">The spec files or directories to load, or <see langword="null"/> for none.</param>
        /// <param name="contents">The in-memory rule documents to load, or <see langword="null"/> for none.</param>
        /// <param name="diagnostics">An optional sink for non-fatal load and validation warnings.</param>
        /// <returns>The compiled rules and validated pack definitions.</returns>
        public static RuleBundle LoadBundle(
            IEnumerable<string>? paths,
            IEnumerable<RuleContent>? contents,
            Action<string>? diagnostics)
        {
            List<string> files = new List<string>();
            HashSet<string> seenFiles = new HashSet<string>(PathComparer);
            int sourcePaths = 0;
            foreach (string path in paths ?? Array.Empty<string>())
            {
                sourcePaths++;
                if (sourcePaths > MaxSourceFiles)
                {
                    diagnostics?.Invoke($"Skipped rule sources: source file count exceeds the limit of {MaxSourceFiles}.");
                    return EmptyBundle();
                }

                foreach (string file in ExpandFiles(path, diagnostics))
                {
                    string normalized = Path.GetFullPath(file);
                    if (!seenFiles.Add(normalized))
                    {
                        continue;
                    }

                    files.Add(normalized);
                    if (files.Count > MaxSourceFiles)
                    {
                        diagnostics?.Invoke($"Skipped rule sources: source file count exceeds the limit of {MaxSourceFiles}.");
                        return EmptyBundle();
                    }
                }
            }

            List<RuleContent> inline = (contents ?? Array.Empty<RuleContent>())
                .Where(content => content != null)
                .ToList();
            if (files.Count + inline.Count > MaxSourceFiles)
            {
                diagnostics?.Invoke($"Skipped rule sources: source file count exceeds the limit of {MaxSourceFiles}.");
                return EmptyBundle();
            }

            List<ParsedDocument> documents = new List<ParsedDocument>();
            RegexCompiler regexCompiler = new RegexCompiler();
            long totalBytes = 0;
            foreach (string file in files)
            {
                ParsedDocument? document = LoadFile(file, diagnostics, regexCompiler, out int bytesRead);
                totalBytes += bytesRead;
                if (totalBytes > MaxTotalRuleBytes)
                {
                    diagnostics?.Invoke($"Skipped rule sources: total file size exceeds the limit of {MaxTotalRuleBytes} bytes.");
                    return EmptyBundle();
                }

                if (document != null)
                {
                    documents.Add(document);
                }
            }

            foreach (RuleContent content in inline)
            {
                ParsedDocument? document = LoadContent(content, diagnostics, regexCompiler, out int bytesRead);
                totalBytes += bytesRead;
                if (totalBytes > MaxTotalRuleBytes)
                {
                    diagnostics?.Invoke($"Skipped rule sources: total file size exceeds the limit of {MaxTotalRuleBytes} bytes.");
                    return EmptyBundle();
                }

                if (document != null)
                {
                    documents.Add(document);
                }
            }

            string? bundleLimitError = ValidateBundleCounts(documents);
            if (bundleLimitError != null)
            {
                diagnostics?.Invoke($"Skipped rule sources: {bundleLimitError}");
                return EmptyBundle();
            }

            HashSet<ParsedDocument> duplicatePackDocuments = FindDuplicatePackDocuments(documents, diagnostics);
            List<RulePackDefinition> packs = documents
                .Where(document => document.Pack != null && !duplicatePackDocuments.Contains(document))
                .Select(document => document.Pack!)
                .OrderBy(pack => pack.Id, StringComparer.Ordinal)
                .ToList();

            List<RuleCandidate> candidates = new List<RuleCandidate>();
            foreach (ParsedDocument document in documents.Where(document => !duplicatePackDocuments.Contains(document)))
            {
                for (int index = 0; index < document.Rules.Count; index++)
                {
                    DeclarativeRuleSpec spec = document.Rules[index];
                    string effectiveId = spec.Id ?? string.Empty;
                    if (document.Pack != null)
                    {
                        try
                        {
                            effectiveId = RulePackIdentity.CreateEffectiveRuleId(document.Pack.Id, spec.Id!);
                        }
                        catch (ArgumentException ex)
                        {
                            diagnostics?.Invoke($"Skipped rule '{spec.Id}' in '{document.File}': {ex.Message}");
                            continue;
                        }
                    }

                    candidates.Add(new RuleCandidate(document, spec, effectiveId, index));
                }
            }

            HashSet<RuleCandidate> duplicates = FindDuplicateRules(candidates, diagnostics);
            List<Rule> rules = new List<Rule>();
            foreach (RuleCandidate candidate in candidates.Where(candidate => !duplicates.Contains(candidate)))
            {
                Rule? rule = Compile(candidate, diagnostics);
                if (rule != null)
                {
                    rules.Add(rule);
                }
            }

            return new RuleBundle(rules.AsReadOnly(), packs.AsReadOnly());
        }

        /// <summary>
        /// Reads declarative rule documents from the filesystem into content, expanding directories the
        /// same way a direct load does. Hosts that can resolve paths (the CLI, the MCP server, and the
        /// API's trusted startup configuration) use this to hand content to the host-neutral engine
        /// facade, so path handling stays in the host and the analysis layer stays filesystem-free.
        /// </summary>
        /// <param name="paths">The spec files or directories to read.</param>
        /// <param name="diagnostics">An optional sink for non-fatal read warnings.</param>
        /// <returns>The document content, in path then file order.</returns>
        public static IReadOnlyList<RuleContent> ReadContents(IEnumerable<string> paths, Action<string>? diagnostics = null)
        {
            if (paths == null)
            {
                throw new ArgumentNullException(nameof(paths));
            }

            List<RuleContent> contents = new List<RuleContent>();
            HashSet<string> seenFiles = new HashSet<string>(PathComparer);
            foreach (string path in paths)
            {
                foreach (string file in ExpandFiles(path, diagnostics))
                {
                    string normalized = Path.GetFullPath(file);
                    if (!seenFiles.Add(normalized))
                    {
                        continue;
                    }

                    if (contents.Count >= MaxSourceFiles)
                    {
                        diagnostics?.Invoke($"Skipped rule sources: source file count exceeds the limit of {MaxSourceFiles}.");
                        return contents;
                    }

                    try
                    {
                        contents.Add(RuleContent.FromBytes(normalized, ReadFile(normalized, out _)));
                    }
                    catch (Exception ex) when (ex is IOException || ex is InvalidDataException || ex is UnauthorizedAccessException)
                    {
                        diagnostics?.Invoke($"Skipped rule file '{normalized}': {ex.Message}");
                    }
                }
            }

            return contents;
        }

        /// <summary>Validates an in-memory version 2 pack using the loader's authoritative contract.</summary>
        /// <param name="dialect">The rule language dialect.</param>
        /// <param name="header">The pack header.</param>
        /// <param name="categories">The category catalog.</param>
        /// <param name="elementTypes">The element-type catalog.</param>
        /// <param name="properties">The property catalog.</param>
        /// <param name="rules">The rules.</param>
        /// <returns>A validation error, or <see langword="null"/> when the pack is valid.</returns>
        internal static string? ValidateCompiledPack(
            string dialect,
            DeclarativeRuleFile.PackSpec header,
            IReadOnlyList<DeclarativeRuleFile.CategorySpec> categories,
            IReadOnlyList<DeclarativeRuleFile.ElementTypeSpec> elementTypes,
            IReadOnlyList<DeclarativeRuleFile.PropertySpec> properties,
            IReadOnlyList<DeclarativeRuleSpec> rules)
        {
            return ValidateVersionTwoPack(dialect, header, categories, elementTypes, properties, rules);
        }

        private static string? ValidateVersionTwoRule(DeclarativeRuleSpec spec)
        {
            string? metadataError = ValidateVersionTwoRuleMetadata(spec);
            if (metadataError != null)
            {
                return metadataError;
            }

            if (spec.AppliesTo == null ||
                (!string.Equals(spec.AppliesTo, "process", StringComparison.Ordinal) &&
                !string.Equals(spec.AppliesTo, "datastore", StringComparison.Ordinal) &&
                !string.Equals(spec.AppliesTo, "external", StringComparison.Ordinal) &&
                !string.Equals(spec.AppliesTo, "flow", StringComparison.Ordinal)))
            {
                return $"unknown appliesTo '{spec.AppliesTo}'.";
            }

            if (spec.When == null && spec.Assert == null)
            {
                return "at least one of 'when' or 'assert' is required.";
            }

            string? conditionError = ValidateConditionShape(spec.When);
            if (conditionError != null)
            {
                return conditionError;
            }

            conditionError = ValidateConditionShape(spec.Assert);
            if (conditionError != null)
            {
                return conditionError;
            }

            if (!string.Equals(spec.AppliesTo, "flow", StringComparison.Ordinal) &&
                (UsesRelational(spec.When) || UsesRelational(spec.Assert)))
            {
                return "crossesTrustBoundary, source, and target require appliesTo 'flow'.";
            }

            string? endpointError = ValidateEndpointKinds(spec.When);
            return endpointError ?? ValidateEndpointKinds(spec.Assert) ?? ValidateConnectivityConditions(spec);
        }

        private static string? ValidateVersionTwoRuleMetadata(DeclarativeRuleSpec spec)
        {
            if (!RulePackIdentity.IsValidSegment(spec.Id))
            {
                return $"id must be printable ASCII, at most {RulePackIdentity.IdentitySegmentLength} characters, and cannot contain '/' or surrounding whitespace.";
            }

            if (!string.IsNullOrWhiteSpace(spec.Pack))
            {
                return "version 2 rules inherit pack identity and cannot declare 'pack'.";
            }

            if (spec.Severity != null &&
                !string.Equals(spec.Severity, "error", StringComparison.Ordinal) &&
                !string.Equals(spec.Severity, "warning", StringComparison.Ordinal) &&
                !string.Equals(spec.Severity, "info", StringComparison.Ordinal))
            {
                return $"unknown severity '{spec.Severity}'.";
            }

            if (string.IsNullOrWhiteSpace(spec.Message))
            {
                return "message is required.";
            }

            if (spec.Stride != null &&
                (!Enum.GetNames(typeof(StrideCategory)).Contains(spec.Stride, StringComparer.Ordinal) ||
                string.Equals(spec.Stride, nameof(StrideCategory.Unknown), StringComparison.Ordinal)))
            {
                return $"unknown stride '{spec.Stride}'.";
            }

            if (spec.DefaultPriority != null &&
                !Enum.GetNames(typeof(ThreatPriority)).Contains(spec.DefaultPriority, StringComparer.Ordinal))
            {
                return $"unknown defaultPriority '{spec.DefaultPriority}'.";
            }

            if (spec.HelpUri != null && !TryCreateSafeHelpUri(spec.HelpUri, out _))
            {
                return $"helpUri '{spec.HelpUri}' must use HTTP or HTTPS.";
            }

            if (spec.ThreatReferences?.Any(string.IsNullOrWhiteSpace) == true)
            {
                return "threatReferences cannot contain null or empty values.";
            }

            if (spec.Provenance != null &&
                ((spec.Provenance.SourceId != null && string.IsNullOrWhiteSpace(spec.Provenance.SourceId)) ||
                (spec.Provenance.CategoryId != null && string.IsNullOrWhiteSpace(spec.Provenance.CategoryId)) ||
                (spec.Provenance.Location != null && string.IsNullOrWhiteSpace(spec.Provenance.Location))))
            {
                return "provenance sourceId, categoryId, and location cannot be empty when present.";
            }

            return null;
        }

        private static string? ValidateRuleForDialect(string dialect, DeclarativeRuleSpec spec)
        {
            if (string.Equals(dialect, RulePackDialects.FlatV1, StringComparison.Ordinal))
            {
                if (spec.Expression != null)
                {
                    return "flat-v1 rules cannot declare expression.";
                }

                return ValidateVersionTwoRule(spec);
            }

            if (string.Equals(dialect, RulePackDialects.InteractionV1, StringComparison.Ordinal))
            {
                if (spec.When != null || spec.Assert != null || spec.AppliesTo != null)
                {
                    return "interaction-v1 rules use expression and cannot declare appliesTo, when, or assert.";
                }

                string? metadataError = ValidateVersionTwoRuleMetadata(spec);
                if (metadataError != null)
                {
                    return metadataError;
                }

                if (spec.Expression == null)
                {
                    return "interaction-v1 rules require expression.";
                }

                return ValidateInteractionExpression(spec.Expression, depth: 1);
            }

            return $"unknown rule dialect '{dialect}'.";
        }

        private static string? ValidateInteractionExpression(
            DeclarativeRuleSpec.InteractionExpressionSpec expression,
            int depth)
        {
            if (depth > 64)
            {
                return "interaction expression depth exceeds the limit of 64.";
            }

            bool hasNumeric = expression.GreaterThan.HasValue || expression.GreaterThanOrEqual.HasValue ||
                expression.LessThan.HasValue || expression.LessThanOrEqual.HasValue;
            bool hasPredicate = expression.Subject != null ||
                expression.Type != null ||
                expression.Property != null ||
                expression.Kind != null || expression.ReachableFrom != null || expression.ConnectsTo != null ||
                expression.ValueIn != null || hasNumeric || expression.Matches != null;
            int shapes = (expression.AllOf != null ? 1 : 0) +
                (expression.AnyOf != null ? 1 : 0) +
                (expression.Not != null ? 1 : 0) +
                (expression.Crosses != null ? 1 : 0) +
                (hasPredicate ? 1 : 0);
            if (shapes != 1)
            {
                return "each interaction expression node must declare exactly one operation.";
            }

            if (expression.AllOf != null || expression.AnyOf != null)
            {
                List<DeclarativeRuleSpec.InteractionExpressionSpec> children = expression.AllOf ?? expression.AnyOf!;
                if (children.Count == 0 || children.Any(child => child == null))
                {
                    return "allOf and anyOf require at least one non-null child.";
                }

                foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in children)
                {
                    string? error = ValidateInteractionExpression(child, depth + 1);
                    if (error != null)
                    {
                        return error;
                    }
                }

                return null;
            }

            if (expression.Not != null)
            {
                return ValidateInteractionExpression(expression.Not, depth + 1);
            }

            if (expression.Crosses != null)
            {
                return string.IsNullOrWhiteSpace(expression.Crosses)
                    ? "crosses requires a boundary type."
                    : null;
            }

            if (!string.Equals(expression.Subject, "source", StringComparison.Ordinal) &&
                !string.Equals(expression.Subject, "target", StringComparison.Ordinal) &&
                !string.Equals(expression.Subject, "flow", StringComparison.Ordinal))
            {
                return $"unknown interaction subject '{expression.Subject}'.";
            }

            int predicates = (expression.Type != null ? 1 : 0) + (expression.Property != null ? 1 : 0) +
                (expression.Kind != null ? 1 : 0) + (expression.ReachableFrom != null ? 1 : 0) + (expression.ConnectsTo != null ? 1 : 0);
            if (predicates != 1)
            {
                return "interaction predicates require exactly one of type, kind, property, reachableFrom, or connectsTo.";
            }

            if (expression.Kind != null || expression.ReachableFrom != null || expression.ConnectsTo != null)
            {
                if (expression.Subject == "flow" || expression.ValueIn != null || hasNumeric || expression.Matches != null)
                {
                    return "kind and connectivity predicates require source or target and cannot declare property matchers.";
                }

                return expression.Kind != null
                    ? ValidateEndpointKind(new DeclarativeEndpoint { Kind = expression.Kind })
                    : ValidateConnectivityFilter(expression.ReachableFrom ?? expression.ConnectsTo);
            }

            bool hasType = expression.Type != null;
            bool hasProperty = expression.Property != null;
            if ((hasType && string.IsNullOrWhiteSpace(expression.Type)) || (hasProperty && string.IsNullOrWhiteSpace(expression.Property)))
            {
                return "interaction type and property names cannot be empty.";
            }

            if (hasProperty && !hasNumeric && expression.Matches == null && (expression.ValueIn == null || expression.ValueIn.Count == 0))
            {
                return "interaction property predicates require valueIn, numeric bounds, or matches.";
            }

            if (expression.Matches != null && (hasType || hasNumeric || expression.ValueIn != null))
            {
                return "regex predicates require property and cannot be combined with type, valueIn, or numeric bounds.";
            }

            if (hasNumeric && (hasType || expression.ValueIn != null))
            {
                return "numeric predicates require property and cannot be combined with type or valueIn.";
            }

            if (hasType && expression.ValueIn != null)
            {
                return "interaction type predicates cannot declare valueIn.";
            }

            string? numericError = ValidateNumericBounds(
                expression.Property, expression.GreaterThan, expression.GreaterThanOrEqual, expression.LessThan, expression.LessThanOrEqual);
            return numericError ?? (expression.ValueIn?.Any(value => value == null) == true
                ? "interaction valueIn cannot contain null values."
                : null);
        }

        private static string? ValidateConditionShape(DeclarativeCondition? condition)
        {
            if (condition == null)
            {
                return null;
            }

            if (condition.Property != null && string.IsNullOrWhiteSpace(condition.Property))
            {
                return "condition property names cannot be empty.";
            }

            if (condition.AnyOf?.Any(value => value == null) == true ||
                condition.NotAnyOf?.Any(value => value == null) == true)
            {
                return "condition matchers cannot contain null values.";
            }

            bool hasValueMatcher = condition.EqualTo != null ||
                condition.Present.HasValue ||
                condition.AnyOf != null ||
                condition.NotAnyOf != null ||
                condition.GreaterThan.HasValue || condition.GreaterThanOrEqual.HasValue ||
                condition.LessThan.HasValue || condition.LessThanOrEqual.HasValue || condition.Matches != null;
            if (hasValueMatcher && string.IsNullOrWhiteSpace(condition.Property))
            {
                return "condition value matchers require property.";
            }

            if (condition.AnyOf?.Count == 0 || condition.NotAnyOf?.Count == 0)
            {
                return "condition matcher arrays cannot be empty.";
            }

            string? numericError = ValidateNumericBounds(
                condition.Property, condition.GreaterThan, condition.GreaterThanOrEqual, condition.LessThan, condition.LessThanOrEqual);
            return numericError ?? ValidateEndpointShape(condition.Source) ?? ValidateEndpointShape(condition.Target) ??
                ValidateConnectivityFilter(condition.ReachableFrom) ?? ValidateConnectivityFilter(condition.ConnectsTo);
        }

        private static string? ValidateEndpointShape(DeclarativeEndpoint? endpoint)
        {
            if (endpoint?.Property != null && string.IsNullOrWhiteSpace(endpoint.Property))
            {
                return "endpoint property names cannot be empty.";
            }

            bool hasValueMatcher = endpoint?.EqualTo != null ||
                endpoint?.Present.HasValue == true ||
                endpoint?.AnyOf != null ||
                endpoint?.NotAnyOf != null || endpoint?.GreaterThan != null || endpoint?.GreaterThanOrEqual != null ||
                endpoint?.LessThan != null || endpoint?.LessThanOrEqual != null || endpoint?.Matches != null;
            if (hasValueMatcher && string.IsNullOrWhiteSpace(endpoint?.Property))
            {
                return "endpoint value matchers require property.";
            }

            if (endpoint?.AnyOf?.Count == 0 || endpoint?.NotAnyOf?.Count == 0)
            {
                return "endpoint matcher arrays cannot be empty.";
            }

            string? numericError = ValidateNumericBounds(
                endpoint?.Property, endpoint?.GreaterThan, endpoint?.GreaterThanOrEqual, endpoint?.LessThan, endpoint?.LessThanOrEqual);
            return numericError ?? (endpoint?.AnyOf?.Any(value => value == null) == true ||
                endpoint?.NotAnyOf?.Any(value => value == null) == true
                    ? "endpoint matchers cannot contain null values."
                    : null);
        }

        private static string? PrepareMatchers(IReadOnlyList<DeclarativeRuleSpec> rules, RegexCompiler compiler, bool interaction)
        {
            foreach (DeclarativeRuleSpec rule in rules)
            {
                try
                {
                    string? connectivityError = ValidateConnectivityConditions(rule);
                    if (connectivityError != null)
                    {
                        throw new InvalidDataException(connectivityError);
                    }

                    PrepareCondition(rule.When, compiler);
                    PrepareCondition(rule.Assert, compiler);
                    if (interaction && rule.Expression != null)
                    {
                        PrepareExpression(rule.Expression, compiler);
                    }
                }
                catch (Exception ex) when (ex is ArgumentException || ex is InvalidDataException)
                {
                    return $"rule '{rule.Id}': {ex.Message}";
                }
            }

            return null;
        }

        private static void PrepareCondition(DeclarativeCondition? condition, RegexCompiler compiler)
        {
            if (condition == null)
            {
                return;
            }

            condition.CompiledPattern = PreparePropertyMatcher(
                condition.Property, condition.GreaterThan, condition.GreaterThanOrEqual, condition.LessThan, condition.LessThanOrEqual, condition.Matches, compiler);
            PrepareEndpoint(condition.Source, compiler);
            PrepareEndpoint(condition.Target, compiler);
            PrepareEndpoint(condition.ReachableFrom, compiler);
            PrepareEndpoint(condition.ConnectsTo, compiler);
        }

        private static void PrepareEndpoint(DeclarativeEndpoint? endpoint, RegexCompiler compiler)
        {
            if (endpoint != null)
            {
                endpoint.CompiledPattern = PreparePropertyMatcher(
                    endpoint.Property, endpoint.GreaterThan, endpoint.GreaterThanOrEqual, endpoint.LessThan, endpoint.LessThanOrEqual, endpoint.Matches, compiler);
            }
        }

        private static void PrepareExpression(DeclarativeRuleSpec.InteractionExpressionSpec expression, RegexCompiler compiler)
        {
            expression.CompiledPattern = PreparePropertyMatcher(
                expression.Property, expression.GreaterThan, expression.GreaterThanOrEqual, expression.LessThan, expression.LessThanOrEqual, expression.Matches, compiler);
            PrepareEndpoint(expression.ReachableFrom, compiler);
            PrepareEndpoint(expression.ConnectsTo, compiler);
            if (expression.Not != null)
            {
                PrepareExpression(expression.Not, compiler);
            }

            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in
                (expression.AllOf ?? Enumerable.Empty<DeclarativeRuleSpec.InteractionExpressionSpec>())
                    .Concat(expression.AnyOf ?? Enumerable.Empty<DeclarativeRuleSpec.InteractionExpressionSpec>()))
            {
                PrepareExpression(child, compiler);
            }
        }

        private static Regex? PreparePropertyMatcher(
            string? property,
            decimal? greaterThan,
            decimal? greaterThanOrEqual,
            decimal? lessThan,
            decimal? lessThanOrEqual,
            string? matches,
            RegexCompiler compiler)
        {
            string? error = ValidateNumericBounds(property, greaterThan, greaterThanOrEqual, lessThan, lessThanOrEqual);
            if (error != null)
            {
                throw new InvalidDataException(error);
            }

            return compiler.Prepare(property, matches);
        }

        private static string? ValidateConnectivityConditions(DeclarativeRuleSpec rule)
        {
            foreach (DeclarativeCondition? condition in new[] { rule.When, rule.Assert })
            {
                if (condition?.ReachableFrom == null && condition?.ConnectsTo == null)
                {
                    continue;
                }

                if (string.Equals(rule.AppliesTo, "flow", StringComparison.OrdinalIgnoreCase))
                {
                    return "reachableFrom and connectsTo require a component appliesTo; use interaction source or target for flows.";
                }

                string? error = ValidateConnectivityFilter(condition!.ReachableFrom) ?? ValidateConnectivityFilter(condition.ConnectsTo);
                if (error != null)
                {
                    return error;
                }
            }

            return null;
        }

        private static string? ValidateConnectivityFilter(DeclarativeEndpoint? filter)
        {
            if (filter == null)
            {
                return null;
            }

            if (filter.Kind == null && filter.Property == null)
            {
                return "connectivity filters require kind or property.";
            }

            return ValidateEndpointKind(filter) ?? ValidateEndpointShape(filter);
        }

        private static string? ValidateNumericBounds(
            string? property,
            decimal? greaterThan,
            decimal? greaterThanOrEqual,
            decimal? lessThan,
            decimal? lessThanOrEqual)
        {
            if (!greaterThan.HasValue && !greaterThanOrEqual.HasValue && !lessThan.HasValue && !lessThanOrEqual.HasValue)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(property))
            {
                return "numeric bounds require property.";
            }

            decimal lower = Math.Max(greaterThan ?? decimal.MinValue, greaterThanOrEqual ?? decimal.MinValue);
            decimal upper = Math.Min(lessThan ?? decimal.MaxValue, lessThanOrEqual ?? decimal.MaxValue);
            return lower > upper || (lower == upper && (greaterThan == lower || lessThan == upper))
                ? "numeric bounds describe an empty range."
                : null;
        }

        private static string? ValidateEndpointKinds(DeclarativeCondition? condition)
        {
            if (condition == null)
            {
                return null;
            }

            string? sourceError = ValidateEndpointKind(condition.Source);
            return sourceError ?? ValidateEndpointKind(condition.Target);
        }

        private static string? ValidateEndpointKind(DeclarativeEndpoint? endpoint)
        {
            if (endpoint?.Kind == null ||
                string.Equals(endpoint.Kind, "process", StringComparison.Ordinal) ||
                string.Equals(endpoint.Kind, "datastore", StringComparison.Ordinal) ||
                string.Equals(endpoint.Kind, "external", StringComparison.Ordinal))
            {
                return null;
            }

            return $"unknown endpoint kind '{endpoint.Kind}'.";
        }

        private static RuleBundle EmptyBundle()
        {
            return new RuleBundle(Array.Empty<Rule>(), Array.Empty<RulePackDefinition>());
        }

        private static IEnumerable<string> ExpandFiles(string path, Action<string>? diagnostics)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return Array.Empty<string>();
            }

            if (Directory.Exists(path))
            {
                return Directory.EnumerateFiles(path, "*.tmrules.json", SearchOption.AllDirectories)
                    .Take(MaxSourceFiles + 1)
                    .OrderBy(p => p, StringComparer.Ordinal)
                    .ToList();
            }

            if (File.Exists(path))
            {
                return new[] { path };
            }

            diagnostics?.Invoke($"Rule source not found: '{path}'.");
            return Array.Empty<string>();
        }

        private static ParsedDocument? LoadFile(string file, Action<string>? diagnostics, RegexCompiler regexCompiler, out int bytesRead)
        {
            bytesRead = 0;
            byte[] content;
            try
            {
                content = ReadFile(file, out bytesRead);
            }
            catch (Exception ex) when (ex is IOException || ex is InvalidDataException || ex is UnauthorizedAccessException)
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': {ex.Message}");
                return null;
            }

            return ParseDocument(file, content, diagnostics, regexCompiler);
        }

        private static ParsedDocument? LoadContent(RuleContent source, Action<string>? diagnostics, RegexCompiler regexCompiler, out int bytesRead)
        {
            byte[] content = source.Bytes();
            bytesRead = content.Length;
            if (bytesRead > MaxRuleFileBytes)
            {
                diagnostics?.Invoke(
                    $"Skipped rule file '{source.Name}': File size exceeds the limit of {MaxRuleFileBytes} bytes.");
                return null;
            }

            return ParseDocument(source.Name, content, diagnostics, regexCompiler);
        }

        private static ParsedDocument? ParseDocument(string file, byte[] content, Action<string>? diagnostics, RegexCompiler regexCompiler)
        {
            DeclarativeRuleFile? parsed;
            string json;
            bool hasVersionMarker;
            bool hasCategories;
            bool hasElementTypes;
            bool hasProperties;
            try
            {
                json = ReadJson(content);
                using JsonDocument document = ParseJsonDocument(json);
                JsonElement root = document.RootElement;
                hasVersionMarker = HasVersionMarker(root);
                hasCategories = HasRootProperty(root, "categories");
                hasElementTypes = HasRootProperty(root, "elementTypes");
                hasProperties = HasRootProperty(root, "properties");
                if (hasVersionMarker)
                {
                    if (IsVersionTwo(root) && ContainsNull(root))
                    {
                        throw new InvalidDataException("Versioned rule packs cannot contain explicit null values.");
                    }

                    parsed = JsonSerializer.Deserialize<DeclarativeRuleFile>(json, StrictOptions);
                }
                else
                {
                    parsed = DeserializeLegacy(root);
                }
            }
            catch (Exception ex) when (ex is IOException || ex is InvalidDataException || ex is JsonException || ex is UnauthorizedAccessException)
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': {ex.Message}");
                return null;
            }

            if (parsed == null)
            {
                return null;
            }

            if (!hasVersionMarker)
            {
                List<DeclarativeRuleSpec> legacyRules = parsed.Rules ?? new List<DeclarativeRuleSpec>();
                if (legacyRules.Any(rule => rule == null))
                {
                    diagnostics?.Invoke($"Skipped rule file '{file}': rules cannot contain null entries.");
                    return null;
                }

                if (legacyRules.Count > MaxRulesPerPack)
                {
                    diagnostics?.Invoke($"Skipped rule file '{file}': rule count exceeds the limit of {MaxRulesPerPack}.");
                    return null;
                }

                string? countError = ValidateCounts(
                    Array.Empty<DeclarativeRuleFile.CategorySpec>(),
                    Array.Empty<DeclarativeRuleFile.ElementTypeSpec>(),
                    Array.Empty<DeclarativeRuleFile.PropertySpec>(),
                    legacyRules,
                    sourceMetadataCount: 0);
                string? textError = ValidatePackText(
                    null,
                    Array.Empty<DeclarativeRuleFile.CategorySpec>(),
                    Array.Empty<DeclarativeRuleFile.ElementTypeSpec>(),
                    Array.Empty<DeclarativeRuleFile.PropertySpec>(),
                    legacyRules);
                string? matcherError = countError ?? textError ?? PrepareMatchers(legacyRules, regexCompiler, interaction: false);
                if (matcherError != null)
                {
                    diagnostics?.Invoke($"Skipped rule file '{file}': {matcherError}");
                    return null;
                }

                return new ParsedDocument(file, version: 0, null, legacyRules);
            }

            if (!string.Equals(parsed.Schema, "tmforge-rules", StringComparison.Ordinal) || parsed.Version != 2)
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': expected schema 'tmforge-rules' version 2.");
                return null;
            }

            int version = parsed.Version.Value;

            DeclarativeRuleFile.PackSpec? header = parsed.Pack;
            if (header == null || string.IsNullOrWhiteSpace(header.Id) || string.IsNullOrWhiteSpace(header.Name))
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': version {version} requires pack 'id' and 'name'.");
                return null;
            }

            if (string.IsNullOrWhiteSpace(parsed.Dialect))
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': version {version} requires a rule dialect.");
                return null;
            }

            if (!RulePackIdentity.IsValidSegment(header.Id))
            {
                diagnostics?.Invoke(
                    $"Skipped rule file '{file}': pack id must be printable ASCII, at most {RulePackIdentity.IdentitySegmentLength} characters, and cannot contain '/' or surrounding whitespace.");
                return null;
            }

            if (header.Fingerprint != null)
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': pack fingerprint is computed from content and cannot be declared.");
                return null;
            }

            if (parsed.Rules == null)
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': version {version} requires a rules array.");
                return null;
            }

            if ((parsed.Categories == null && hasCategories) ||
                (parsed.ElementTypes == null && hasElementTypes) ||
                (parsed.Properties == null && hasProperties))
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': version {version} catalog arrays cannot be null.");
                return null;
            }

            List<DeclarativeRuleSpec> rules = parsed.Rules;
            List<DeclarativeRuleFile.CategorySpec> categories = parsed.Categories ?? new List<DeclarativeRuleFile.CategorySpec>();
            List<DeclarativeRuleFile.ElementTypeSpec> elementTypes = parsed.ElementTypes ?? new List<DeclarativeRuleFile.ElementTypeSpec>();
            List<DeclarativeRuleFile.PropertySpec> properties = parsed.Properties ?? new List<DeclarativeRuleFile.PropertySpec>();
            if (rules.Any(rule => rule == null) ||
                categories.Any(category => category == null) ||
                elementTypes.Any(element => element == null) ||
                properties.Any(property => property == null))
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': arrays cannot contain null entries.");
                return null;
            }

            string? validationError = ValidateVersionTwoPack(parsed.Dialect!, header, categories, elementTypes, properties, rules) ??
                PrepareMatchers(rules, regexCompiler, interaction: true);
            if (validationError != null)
            {
                diagnostics?.Invoke($"Skipped rule file '{file}': {validationError}");
                return null;
            }

            List<RuleCategoryDefinition> immutableCategories = categories
                .Select(category => new RuleCategoryDefinition(
                    category.Id!, category.Name!, category.ShortDescription, category.LongDescription))
                .ToList();
            List<RuleElementTypeDefinition> immutableElementTypes = elementTypes
                .Select(element => new RuleElementTypeDefinition(element.Id!, element.Name!, element.ParentId))
                .ToList();
            List<RulePropertyDefinition> immutableProperties = properties.Select(property => new RulePropertyDefinition(
                property.Name!,
                new List<string>(property.Aliases ?? new List<string>()).AsReadOnly(),
                new List<string>(property.AllowedValues ?? new List<string>()).AsReadOnly(),
                new List<string>(property.ElementTypeIds ?? new List<string>()).AsReadOnly())).ToList();
            DeclarativeRuleFile.SourceSpec? source = header.Source;
            RulePackSource? immutableSource = source == null
                ? null
                : new RulePackSource(
                    source.Type!,
                    source.Name,
                    source.Id,
                    source.Version,
                    source.Uri,
                    source.Fingerprint,
                    (source.Metadata ?? new List<DeclarativeRuleFile.SourceMetadataSpec>())
                        .ToDictionary(item => item.Key!, item => item.Value!, StringComparer.Ordinal));
            RulePackDefinition pack = new RulePackDefinition(
                header.Id!,
                parsed.Dialect!,
                header.Name!,
                header.Description,
                header.Version,
                RulePackIdentity.CreateFingerprint(content),
                immutableSource,
                immutableCategories.AsReadOnly(),
                immutableElementTypes.AsReadOnly(),
                immutableProperties.AsReadOnly());

            return new ParsedDocument(file, version, pack, rules);
        }

        private static byte[] ReadFile(string file, out int bytesRead)
        {
            bytesRead = 0;
            using FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            using MemoryStream content = new MemoryStream();
            byte[] buffer = new byte[81920];
            while (true)
            {
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0)
                {
                    break;
                }

                bytesRead += read;
                if (bytesRead > MaxRuleFileBytes)
                {
                    throw new InvalidDataException($"File size exceeds the limit of {MaxRuleFileBytes} bytes.");
                }

                content.Write(buffer, 0, read);
            }

            return content.ToArray();
        }

        private static string ReadJson(byte[] content)
        {
            return RuleContent.DecodeJson(content);
        }

        private static string? ValidateVersionTwoPack(
            string dialect,
            DeclarativeRuleFile.PackSpec header,
            IReadOnlyList<DeclarativeRuleFile.CategorySpec> categories,
            IReadOnlyList<DeclarativeRuleFile.ElementTypeSpec> elementTypes,
            IReadOnlyList<DeclarativeRuleFile.PropertySpec> properties,
            IReadOnlyList<DeclarativeRuleSpec> rules)
        {
            if (!string.Equals(dialect, RulePackDialects.FlatV1, StringComparison.Ordinal) &&
                !string.Equals(dialect, RulePackDialects.InteractionV1, StringComparison.Ordinal))
            {
                return $"unknown rule dialect '{dialect}'.";
            }

            foreach (DeclarativeRuleSpec rule in rules)
            {
                string? ruleError = ValidateRuleForDialect(dialect, rule);
                if (ruleError != null)
                {
                    return $"rule '{rule.Id ?? "(no id)"}' is invalid: {ruleError}";
                }
            }

            foreach (DeclarativeRuleSpec rule in rules.Where(rule => rule.Provenance != null))
            {
                DeclarativeRuleSpec.RuleProvenanceSpec provenance = rule.Provenance!;
                if (provenance.Expressions?.Any(expression => expression == null) == true)
                {
                    return $"rule '{rule.Id}' provenance expressions cannot contain null entries.";
                }

                foreach (DeclarativeRuleSpec.SourceExpressionSpec expression in provenance.Expressions ?? new List<DeclarativeRuleSpec.SourceExpressionSpec>())
                {
                    if (string.IsNullOrWhiteSpace(expression.Role) ||
                        !IsNamespacedIdentifier(expression.Language) ||
                        expression.Text == null)
                    {
                        return $"rule '{rule.Id}' provenance expressions require role, namespaced language, and text.";
                    }
                }
            }

            string? countError = ValidateCounts(
                categories,
                elementTypes,
                properties,
                rules,
                header.Source?.Metadata?.Count ?? 0);
            if (countError != null)
            {
                return countError;
            }

            string? textError = ValidatePackText(header, categories, elementTypes, properties, rules);
            if (textError != null)
            {
                return textError;
            }

            string? sourceType = header.Source?.Type;
            if (header.Source != null && !IsNamespacedIdentifier(sourceType))
            {
                return "pack.source.type must be a namespaced identifier when source is present.";
            }

            if (header.Source?.Metadata?.Any(item => item == null ||
                !IsNamespacedIdentifier(item.Key) || item.Value == null) == true)
            {
                return "pack.source.metadata entries require namespaced keys and values.";
            }

            string? sourceMetadataDuplicate = FindDuplicateId(
                header.Source?.Metadata?.Select(item => item.Key) ?? Enumerable.Empty<string>(),
                "source metadata");
            if (sourceMetadataDuplicate != null)
            {
                return sourceMetadataDuplicate;
            }

            string? categoryError = FindDuplicateId(categories.Select(category => category.Id), "category");
            if (categoryError != null)
            {
                return categoryError;
            }

            if (categories.Any(category =>
                !RulePackIdentity.IsValidSegment(category.Id) || string.IsNullOrWhiteSpace(category.Name)))
            {
                return $"categories require non-empty names and printable ASCII ids no longer than {RulePackIdentity.IdentitySegmentLength} characters without '/' or surrounding whitespace.";
            }

            string? elementError = ValidateElementTypes(elementTypes);
            if (elementError != null)
            {
                return elementError;
            }

            string? propertyError = ValidateProperties(properties, elementTypes);
            if (propertyError != null)
            {
                return propertyError;
            }

            HashSet<string> categoryIds = new HashSet<string>(
                categories.Select(category => category.Id!),
                StringComparer.OrdinalIgnoreCase);
            foreach (DeclarativeRuleSpec rule in rules)
            {
                if (rule.CategoryId != null && !categoryIds.Contains(rule.CategoryId))
                {
                    return $"rule '{rule.Id}' references unknown category '{rule.CategoryId}'.";
                }

                if (rule.DefaultPriority != null && rule.CategoryId == null && rule.Stride == null)
                {
                    return $"rule '{rule.Id}' defaultPriority requires categoryId or stride.";
                }
            }

            IReadOnlyDictionary<string, DeclarativeRuleFile.PropertySpec> propertyIndex = BuildPropertyIndex(properties);
            if (string.Equals(dialect, RulePackDialects.FlatV1, StringComparison.Ordinal))
            {
                foreach (DeclarativeRuleSpec rule in rules)
                {
                    string? valueError = ValidateConditionCatalogValues(rule.When, propertyIndex) ??
                        ValidateConditionCatalogValues(rule.Assert, propertyIndex);
                    if (valueError != null)
                    {
                        return $"rule '{rule.Id}' is invalid: {valueError}";
                    }
                }
            }

            if (string.Equals(dialect, RulePackDialects.InteractionV1, StringComparison.Ordinal))
            {
                HashSet<string> elementIds = new HashSet<string>(
                    elementTypes.Select(element => element.Id!),
                    StringComparer.OrdinalIgnoreCase);
                foreach (DeclarativeRuleSpec rule in rules)
                {
                    string? referenceError = ValidateInteractionReferences(rule.Expression!, elementIds, propertyIndex);
                    if (referenceError != null)
                    {
                        return $"rule '{rule.Id}' is invalid: {referenceError}";
                    }
                }
            }

            if (header.Source != null &&
                ((header.Source.Name != null && string.IsNullOrWhiteSpace(header.Source.Name)) ||
                (header.Source.Id != null && string.IsNullOrWhiteSpace(header.Source.Id)) ||
                (header.Source.Version != null && string.IsNullOrWhiteSpace(header.Source.Version)) ||
                (header.Source.Uri != null && !Uri.TryCreate(header.Source.Uri, UriKind.Absolute, out _)) ||
                (header.Source.Fingerprint != null && string.IsNullOrWhiteSpace(header.Source.Fingerprint))))
            {
                return "pack.source optional fields must be non-empty and uri must be absolute.";
            }

            return null;
        }

        private static string? ValidateConditionCatalogValues(
            DeclarativeCondition? condition,
            IReadOnlyDictionary<string, DeclarativeRuleFile.PropertySpec> properties)
        {
            if (condition == null)
            {
                return null;
            }

            string? error = ValidateMatcherValues(
                condition.Property,
                condition.EqualTo,
                condition.AnyOf,
                condition.NotAnyOf,
                properties);
            return error ??
                ValidateEndpointCatalogValues(condition.Source, properties) ??
                ValidateEndpointCatalogValues(condition.Target, properties) ??
                ValidateEndpointCatalogValues(condition.ReachableFrom, properties) ??
                ValidateEndpointCatalogValues(condition.ConnectsTo, properties);
        }

        private static string? ValidateEndpointCatalogValues(
            DeclarativeEndpoint? endpoint,
            IReadOnlyDictionary<string, DeclarativeRuleFile.PropertySpec> properties)
        {
            return endpoint == null
                ? null
                : ValidateMatcherValues(
                    endpoint.Property,
                    endpoint.EqualTo,
                    endpoint.AnyOf,
                    endpoint.NotAnyOf,
                    properties);
        }

        private static string? ValidateMatcherValues(
            string? propertyName,
            string? equalTo,
            IEnumerable<string>? anyOf,
            IEnumerable<string>? notAnyOf,
            IReadOnlyDictionary<string, DeclarativeRuleFile.PropertySpec> properties)
        {
            if (propertyName == null ||
                !properties.TryGetValue(propertyName, out DeclarativeRuleFile.PropertySpec? property) ||
                property.AllowedValues?.Count > 0 != true)
            {
                return null;
            }

            HashSet<string> allowed = new HashSet<string>(property.AllowedValues, StringComparer.OrdinalIgnoreCase);
            IEnumerable<string> values = (anyOf ?? Enumerable.Empty<string>())
                .Concat(notAnyOf ?? Enumerable.Empty<string>());
            if (equalTo != null)
            {
                values = values.Concat(new[] { equalTo });
            }

            string? unknown = values.FirstOrDefault(value => !allowed.Contains(value));
            return unknown == null
                ? null
                : $"matcher uses unknown value '{unknown}' for property '{property.Name}'.";
        }

        private static string? ValidateInteractionReferences(
            DeclarativeRuleSpec.InteractionExpressionSpec expression,
            ISet<string> elementIds,
            IReadOnlyDictionary<string, DeclarativeRuleFile.PropertySpec> properties)
        {
            if (string.Equals(expression.Type, "ROOT", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(expression.Subject, "source", StringComparison.Ordinal))
            {
                return "ROOT is only valid for source type predicates.";
            }

            if (expression.Type != null &&
                !string.Equals(expression.Type, "ROOT", StringComparison.OrdinalIgnoreCase) &&
                !elementIds.Contains(expression.Type))
            {
                return $"interaction expression references unknown element type '{expression.Type}'.";
            }

            if (expression.Crosses != null && !elementIds.Contains(expression.Crosses))
            {
                return $"interaction expression references unknown boundary type '{expression.Crosses}'.";
            }

            DeclarativeRuleFile.PropertySpec? property = null;
            if (expression.Property != null && !properties.TryGetValue(expression.Property, out property))
            {
                return $"interaction expression references unknown property '{expression.Property}'.";
            }

            if (property?.AllowedValues?.Count > 0 && expression.ValueIn != null)
            {
                HashSet<string> allowedValues = new HashSet<string>(property.AllowedValues, StringComparer.OrdinalIgnoreCase);
                string? unknownValue = expression.ValueIn.FirstOrDefault(value => !allowedValues.Contains(value));
                if (unknownValue != null)
                {
                    return $"interaction expression uses unknown value '{unknownValue}' for property '{property.Name}'.";
                }
            }

            foreach (DeclarativeEndpoint? filter in new[] { expression.ReachableFrom, expression.ConnectsTo })
            {
                if (filter?.Property != null && !properties.ContainsKey(filter.Property))
                {
                    return $"connectivity filter references unknown property '{filter.Property}'.";
                }

                string? error = ValidateEndpointCatalogValues(filter, properties);
                if (error != null)
                {
                    return error;
                }
            }

            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in expression.AllOf ?? new List<DeclarativeRuleSpec.InteractionExpressionSpec>())
            {
                string? error = ValidateInteractionReferences(child, elementIds, properties);
                if (error != null)
                {
                    return error;
                }
            }

            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in expression.AnyOf ?? new List<DeclarativeRuleSpec.InteractionExpressionSpec>())
            {
                string? error = ValidateInteractionReferences(child, elementIds, properties);
                if (error != null)
                {
                    return error;
                }
            }

            return expression.Not == null
                ? null
                : ValidateInteractionReferences(expression.Not, elementIds, properties);
        }

        private static IReadOnlyDictionary<string, DeclarativeRuleFile.PropertySpec> BuildPropertyIndex(
            IEnumerable<DeclarativeRuleFile.PropertySpec> properties)
        {
            Dictionary<string, DeclarativeRuleFile.PropertySpec> result =
                new Dictionary<string, DeclarativeRuleFile.PropertySpec>(StringComparer.OrdinalIgnoreCase);
            foreach (DeclarativeRuleFile.PropertySpec property in properties)
            {
                result[property.Name!] = property;
                foreach (string alias in property.Aliases ?? new List<string>())
                {
                    result[alias] = property;
                }
            }

            return result;
        }

        private static JsonDocument ParseJsonDocument(string json)
        {
            return JsonDocument.Parse(
                json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = true,
                    CommentHandling = JsonCommentHandling.Skip,
                    MaxDepth = MaxJsonDepth,
                });
        }

        private static DeclarativeRuleFile? DeserializeLegacy(JsonElement root)
        {
            if (root.ValueKind != JsonValueKind.Object)
            {
                return JsonSerializer.Deserialize<DeclarativeRuleFile>(root.GetRawText(), Options);
            }

            using MemoryStream buffer = new MemoryStream();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                foreach (JsonProperty property in root.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    if (!string.Equals(property.Name, "rules", StringComparison.OrdinalIgnoreCase) ||
                        property.Value.ValueKind != JsonValueKind.Array)
                    {
                        property.Value.WriteTo(writer);
                        continue;
                    }

                    writer.WriteStartArray();
                    foreach (JsonElement rule in property.Value.EnumerateArray())
                    {
                        if (rule.ValueKind != JsonValueKind.Object)
                        {
                            rule.WriteTo(writer);
                            continue;
                        }

                        writer.WriteStartObject();
                        foreach (JsonProperty ruleProperty in rule.EnumerateObject())
                        {
                            if (string.Equals(ruleProperty.Name, "categoryId", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(ruleProperty.Name, "defaultPriority", StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            ruleProperty.WriteTo(writer);
                        }

                        writer.WriteEndObject();
                    }

                    writer.WriteEndArray();
                }

                writer.WriteEndObject();
            }

            return JsonSerializer.Deserialize<DeclarativeRuleFile>(buffer.ToArray(), Options);
        }

        private static bool HasVersionMarker(JsonElement root)
        {
            if (root.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (string.Equals(property.Name, "schema", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(property.Name, "version", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(property.Name, "dialect", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(property.Name, "pack", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(property.Name, "categories", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(property.Name, "elementTypes", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(property.Name, "properties", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool HasRootProperty(JsonElement root, string propertyName)
        {
            return root.ValueKind == JsonValueKind.Object && root.TryGetProperty(propertyName, out _);
        }

        private static bool IsVersionTwo(JsonElement root)
        {
            return root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("schema", out JsonElement schema) &&
                schema.ValueKind == JsonValueKind.String &&
                string.Equals(schema.GetString(), "tmforge-rules", StringComparison.Ordinal) &&
                root.TryGetProperty("version", out JsonElement version) &&
                version.ValueKind == JsonValueKind.Number &&
                version.TryGetInt32(out int value) &&
                value == 2;
        }

        private static bool ContainsNull(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Null)
            {
                return true;
            }

            if (element.ValueKind == JsonValueKind.Object)
            {
                return element.EnumerateObject().Any(property => ContainsNull(property.Value));
            }

            return element.ValueKind == JsonValueKind.Array && element.EnumerateArray().Any(ContainsNull);
        }

        private static string? ValidateCounts(
            IReadOnlyList<DeclarativeRuleFile.CategorySpec> categories,
            IReadOnlyList<DeclarativeRuleFile.ElementTypeSpec> elementTypes,
            IReadOnlyList<DeclarativeRuleFile.PropertySpec> properties,
            IReadOnlyList<DeclarativeRuleSpec> rules,
            int sourceMetadataCount)
        {
            if (rules.Count > MaxRulesPerPack)
            {
                return $"rule count exceeds the limit of {MaxRulesPerPack}.";
            }

            if (categories.Count > MaxCategoriesPerPack)
            {
                return $"category count exceeds the limit of {MaxCategoriesPerPack}.";
            }

            if (elementTypes.Count > MaxElementTypesPerPack)
            {
                return $"element type count exceeds the limit of {MaxElementTypesPerPack}.";
            }

            if (properties.Count > MaxPropertiesPerPack)
            {
                return $"property count exceeds the limit of {MaxPropertiesPerPack}.";
            }

            long catalogValues = 0;
            foreach (DeclarativeRuleFile.PropertySpec property in properties)
            {
                catalogValues += property.Aliases?.Count ?? 0;
                catalogValues += property.AllowedValues?.Count ?? 0;
                catalogValues += property.ElementTypeIds?.Count ?? 0;
            }

            catalogValues += sourceMetadataCount;

            foreach (DeclarativeRuleSpec rule in rules)
            {
                catalogValues += rule.ThreatReferences?.Count ?? 0;
                catalogValues += rule.Provenance?.Expressions?.Count ?? 0;
                catalogValues += CountConditionValues(rule.When);
                catalogValues += CountConditionValues(rule.Assert);
                catalogValues += CountInteractionValues(rule.Expression);
            }

            return catalogValues > MaxCatalogValuesPerPack
                ? $"catalog value count exceeds the limit of {MaxCatalogValuesPerPack}."
                : null;
        }

        private static string? ValidateBundleCounts(IReadOnlyList<ParsedDocument> documents)
        {
            long rules = 0;
            long categories = 0;
            long elementTypes = 0;
            long properties = 0;
            long catalogValues = 0;
            foreach (ParsedDocument document in documents)
            {
                rules += document.Rules.Count;
                foreach (DeclarativeRuleSpec rule in document.Rules)
                {
                    catalogValues += rule.ThreatReferences?.Count ?? 0;
                    catalogValues += rule.Provenance?.Expressions?.Count ?? 0;
                    catalogValues += CountConditionValues(rule.When);
                    catalogValues += CountConditionValues(rule.Assert);
                    catalogValues += CountInteractionValues(rule.Expression);
                }

                if (document.Pack == null)
                {
                    continue;
                }

                categories += document.Pack.Categories.Count;
                elementTypes += document.Pack.ElementTypes.Count;
                properties += document.Pack.Properties.Count;
                catalogValues += document.Pack.Source?.Metadata.Count ?? 0;
                foreach (RulePropertyDefinition property in document.Pack.Properties)
                {
                    catalogValues += property.Aliases.Count + property.AllowedValues.Count + property.ElementTypeIds.Count;
                }
            }

            if (rules > MaxRulesPerLoad)
            {
                return $"rule count exceeds the invocation limit of {MaxRulesPerLoad}.";
            }

            if (categories > MaxCategoriesPerLoad)
            {
                return $"category count exceeds the invocation limit of {MaxCategoriesPerLoad}.";
            }

            if (elementTypes > MaxElementTypesPerLoad)
            {
                return $"element type count exceeds the invocation limit of {MaxElementTypesPerLoad}.";
            }

            if (properties > MaxPropertiesPerLoad)
            {
                return $"property count exceeds the invocation limit of {MaxPropertiesPerLoad}.";
            }

            return catalogValues > MaxCatalogValuesPerLoad
                ? $"catalog value count exceeds the invocation limit of {MaxCatalogValuesPerLoad}."
                : null;
        }

        private static long CountConditionValues(DeclarativeCondition? condition)
        {
            if (condition == null)
            {
                return 0;
            }

            long count = (condition.AnyOf?.Count ?? 0) + (condition.NotAnyOf?.Count ?? 0);
            count += CountEndpointValues(condition.Source);
            count += CountEndpointValues(condition.Target);
            count += CountEndpointValues(condition.ReachableFrom);
            count += CountEndpointValues(condition.ConnectsTo);
            return count;
        }

        private static long CountEndpointValues(DeclarativeEndpoint? endpoint)
        {
            return endpoint == null ? 0 : (endpoint.AnyOf?.Count ?? 0) + (endpoint.NotAnyOf?.Count ?? 0);
        }

        private static long CountInteractionValues(DeclarativeRuleSpec.InteractionExpressionSpec? expression)
        {
            if (expression == null)
            {
                return 0;
            }

            long count = 1 + (expression.ValueIn?.Count ?? 0) +
                CountEndpointValues(expression.ReachableFrom) + CountEndpointValues(expression.ConnectsTo);
            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in expression.AllOf ?? new List<DeclarativeRuleSpec.InteractionExpressionSpec>())
            {
                count += CountInteractionValues(child);
            }

            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in expression.AnyOf ?? new List<DeclarativeRuleSpec.InteractionExpressionSpec>())
            {
                count += CountInteractionValues(child);
            }

            return count + CountInteractionValues(expression.Not);
        }

        private static string? ValidatePackText(
            DeclarativeRuleFile.PackSpec? header,
            IEnumerable<DeclarativeRuleFile.CategorySpec> categories,
            IEnumerable<DeclarativeRuleFile.ElementTypeSpec> elementTypes,
            IEnumerable<DeclarativeRuleFile.PropertySpec> properties,
            IEnumerable<DeclarativeRuleSpec> rules)
        {
            List<string?> values = new List<string?>
            {
                header?.Id,
                header?.Name,
                header?.Description,
                header?.Version,
                header?.Source?.Type,
                header?.Source?.Name,
                header?.Source?.Id,
                header?.Source?.Version,
                header?.Source?.Uri,
                header?.Source?.Fingerprint,
            };
            foreach (DeclarativeRuleFile.SourceMetadataSpec metadata in
                header?.Source?.Metadata ?? new List<DeclarativeRuleFile.SourceMetadataSpec>())
            {
                values.Add(metadata.Key);
                values.Add(metadata.Value);
            }

            values.AddRange(categories.SelectMany(category => new[] { category.Id, category.Name, category.ShortDescription, category.LongDescription }));
            values.AddRange(elementTypes.SelectMany(element => new[] { element.Id, element.Name, element.ParentId }));
            foreach (DeclarativeRuleFile.PropertySpec property in properties)
            {
                values.Add(property.Name);
                values.AddRange(property.Aliases ?? new List<string>());
                values.AddRange(property.AllowedValues ?? new List<string>());
                values.AddRange(property.ElementTypeIds ?? new List<string>());
            }

            foreach (DeclarativeRuleSpec rule in rules)
            {
                values.AddRange(new[]
                {
                    rule.Id,
                    rule.Pack,
                    rule.Severity,
                    rule.AppliesTo,
                    rule.Message,
                    rule.FullDescription,
                    rule.HelpText,
                    rule.HelpUri,
                    rule.Stride,
                    rule.DefaultPriority,
                    rule.Provenance?.SourceId,
                    rule.Provenance?.CategoryId,
                    rule.Provenance?.Location,
                });
                foreach (DeclarativeRuleSpec.SourceExpressionSpec expression in rule.Provenance?.Expressions ?? new List<DeclarativeRuleSpec.SourceExpressionSpec>())
                {
                    if (expression == null)
                    {
                        continue;
                    }

                    values.Add(expression.Role);
                    values.Add(expression.Language);
                    values.Add(expression.Text);
                }

                values.AddRange(rule.ThreatReferences ?? new List<string>());
                AddConditionText(values, rule.When);
                AddConditionText(values, rule.Assert);
                AddInteractionText(values, rule.Expression);
            }

            if (values.Any(value => value != null && value.Length > MaxStringLength))
            {
                return $"a string value exceeds the limit of {MaxStringLength} characters.";
            }

            foreach (string value in values.Where(value => value != null).Select(value => value!))
            {
                if (value.Any(character => char.IsControl(character) && character != '\t' && character != '\r' && character != '\n'))
                {
                    return "a string value contains an unsafe control character.";
                }

                try
                {
                    XmlConvert.VerifyXmlChars(value);
                }
                catch (XmlException)
                {
                    return "a string value contains a character that cannot be represented in XML.";
                }
            }

            return null;
        }

        private static void AddConditionText(List<string?> values, DeclarativeCondition? condition)
        {
            if (condition == null)
            {
                return;
            }

            values.Add(condition.Property);
            values.Add(condition.EqualTo);
            values.Add(condition.Matches);
            values.AddRange(condition.AnyOf ?? new List<string>());
            values.AddRange(condition.NotAnyOf ?? new List<string>());
            AddEndpointText(values, condition.Source);
            AddEndpointText(values, condition.Target);
            AddEndpointText(values, condition.ReachableFrom);
            AddEndpointText(values, condition.ConnectsTo);
        }

        private static void AddEndpointText(List<string?> values, DeclarativeEndpoint? endpoint)
        {
            if (endpoint == null)
            {
                return;
            }

            values.Add(endpoint.Kind);
            values.Add(endpoint.Property);
            values.Add(endpoint.EqualTo);
            values.Add(endpoint.Matches);
            values.AddRange(endpoint.AnyOf ?? new List<string>());
            values.AddRange(endpoint.NotAnyOf ?? new List<string>());
        }

        private static void AddInteractionText(
            List<string?> values,
            DeclarativeRuleSpec.InteractionExpressionSpec? expression)
        {
            if (expression == null)
            {
                return;
            }

            values.Add(expression.Subject);
            values.Add(expression.Type);
            values.Add(expression.Kind);
            values.Add(expression.Property);
            values.Add(expression.Crosses);
            values.Add(expression.Matches);
            AddEndpointText(values, expression.ReachableFrom);
            AddEndpointText(values, expression.ConnectsTo);
            values.AddRange(expression.ValueIn ?? new List<string>());
            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in expression.AllOf ?? new List<DeclarativeRuleSpec.InteractionExpressionSpec>())
            {
                AddInteractionText(values, child);
            }

            foreach (DeclarativeRuleSpec.InteractionExpressionSpec child in expression.AnyOf ?? new List<DeclarativeRuleSpec.InteractionExpressionSpec>())
            {
                AddInteractionText(values, child);
            }

            AddInteractionText(values, expression.Not);
        }

        private static string? ValidateElementTypes(IReadOnlyList<DeclarativeRuleFile.ElementTypeSpec> elementTypes)
        {
            string? duplicate = FindDuplicateId(elementTypes.Select(element => element.Id), "element type");
            if (duplicate != null)
            {
                return duplicate;
            }

            Dictionary<string, DeclarativeRuleFile.ElementTypeSpec> byId = elementTypes.ToDictionary(
                element => element.Id!,
                StringComparer.OrdinalIgnoreCase);
            foreach (DeclarativeRuleFile.ElementTypeSpec element in elementTypes)
            {
                if (!RulePackIdentity.IsValidSegment(element.Id) || string.IsNullOrWhiteSpace(element.Name))
                {
                    return $"element types require non-empty names and ids no longer than {RulePackIdentity.IdentitySegmentLength} characters without '/' or surrounding whitespace.";
                }

                if (string.Equals(element.Id, "ROOT", StringComparison.OrdinalIgnoreCase))
                {
                    return "ROOT is reserved and cannot be declared as an element type.";
                }

                if (element.ParentId != null &&
                    !RulePackIdentity.IsValidSegment(element.ParentId) &&
                    !string.Equals(element.ParentId, "ROOT", StringComparison.OrdinalIgnoreCase))
                {
                    return $"element type '{element.Id}' has an invalid parent id '{element.ParentId}'.";
                }

                if (!string.IsNullOrWhiteSpace(element.ParentId) &&
                    !string.Equals(element.ParentId, "ROOT", StringComparison.OrdinalIgnoreCase) &&
                    !byId.ContainsKey(element.ParentId!))
                {
                    return $"element type '{element.Id}' references unknown parent '{element.ParentId}'.";
                }
            }

            foreach (DeclarativeRuleFile.ElementTypeSpec element in elementTypes)
            {
                HashSet<string> ancestors = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { element.Id! };
                DeclarativeRuleFile.ElementTypeSpec current = element;
                while (!string.IsNullOrWhiteSpace(current.ParentId) &&
                    !string.Equals(current.ParentId, "ROOT", StringComparison.OrdinalIgnoreCase))
                {
                    if (!ancestors.Add(current.ParentId!))
                    {
                        return $"element type hierarchy contains a cycle at '{current.ParentId}'.";
                    }

                    if (!byId.TryGetValue(current.ParentId!, out DeclarativeRuleFile.ElementTypeSpec? parent))
                    {
                        return $"element type '{current.Id}' references unknown parent '{current.ParentId}'.";
                    }

                    current = parent;
                }
            }

            return null;
        }

        private static string? ValidateProperties(
            IReadOnlyList<DeclarativeRuleFile.PropertySpec> properties,
            IReadOnlyList<DeclarativeRuleFile.ElementTypeSpec> elementTypes)
        {
            string? duplicate = FindDuplicateId(properties.Select(property => property.Name), "property");
            if (duplicate != null)
            {
                return duplicate;
            }

            HashSet<string> elementIds = new HashSet<string>(
                elementTypes.Select(element => element.Id!),
                StringComparer.OrdinalIgnoreCase);
            Dictionary<string, string> aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DeclarativeRuleFile.PropertySpec property in properties)
            {
                string? propertyName = property.Name;
                if (string.IsNullOrWhiteSpace(propertyName) ||
                    !string.Equals(propertyName, propertyName?.Trim(), StringComparison.Ordinal))
                {
                    return "properties require non-empty names without surrounding whitespace.";
                }

                IEnumerable<string> names = new[] { propertyName! }
                    .Concat(property.Aliases ?? new List<string>());
                foreach (string name in names)
                {
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        return $"property '{propertyName}' contains an empty alias.";
                    }

                    if (aliases.TryGetValue(name, out string? existing) &&
                        !string.Equals(existing, propertyName, StringComparison.OrdinalIgnoreCase))
                    {
                        return $"property alias '{name}' is ambiguous between '{existing}' and '{propertyName}'.";
                    }

                    aliases[name] = propertyName!;
                }

                string? duplicateValue = FindDuplicateId(
                    property.AllowedValues ?? new List<string>(),
                    $"allowed value on property '{propertyName}'");
                if (duplicateValue != null)
                {
                    return duplicateValue;
                }

                string? duplicateType = FindDuplicateId(
                    property.ElementTypeIds ?? new List<string>(),
                    $"element type on property '{propertyName}'");
                if (duplicateType != null)
                {
                    return duplicateType;
                }

                foreach (string elementTypeId in property.ElementTypeIds ?? new List<string>())
                {
                    if (!RulePackIdentity.IsValidSegment(elementTypeId) || !elementIds.Contains(elementTypeId))
                    {
                        return $"property '{propertyName}' references unknown element type '{elementTypeId}'.";
                    }
                }
            }

            return null;
        }

        private static bool IsNamespacedIdentifier(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            int separator = value!.IndexOf(':');
            if (separator <= 0 || separator == value.Length - 1)
            {
                return false;
            }

            for (int index = 0; index < separator; index++)
            {
                if (char.IsWhiteSpace(value[index]) || value[index] == ':')
                {
                    return false;
                }
            }

            return true;
        }

        private static string? FindDuplicateId(IEnumerable<string?> ids, string kind)
        {
            List<string?> candidates = ids.ToList();
            if (candidates.Any(string.IsNullOrWhiteSpace))
            {
                return $"{kind} ids cannot be empty.";
            }

            List<string> values = candidates.Select(value => value!).ToList();

            string? duplicate = values
                .GroupBy(value => value, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() > 1)
                .Select(group => group.OrderBy(value => value, StringComparer.Ordinal).First())
                .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
            return duplicate == null ? null : $"duplicate {kind} id '{duplicate}'.";
        }

        private static Rule? Compile(RuleCandidate candidate, Action<string>? diagnostics)
        {
            DeclarativeRuleSpec spec = candidate.Spec;
            string file = candidate.Document.File;
            string origin = $"rule '{spec.Id ?? "(no id)"}' in '{file}'";

            if (string.IsNullOrWhiteSpace(spec.Id))
            {
                diagnostics?.Invoke($"Skipped a rule in '{file}': missing 'id'.");
                return null;
            }

            if (candidate.Document.Pack != null && !string.IsNullOrWhiteSpace(spec.Pack))
            {
                diagnostics?.Invoke($"Skipped {origin}: version 2 rules inherit pack identity and cannot declare 'pack'.");
                return null;
            }

            if (string.IsNullOrWhiteSpace(spec.Message))
            {
                diagnostics?.Invoke($"Skipped {origin}: missing 'message'.");
                return null;
            }

            if (!TryParseSeverity(spec.Severity, out MessageSeverity severity))
            {
                diagnostics?.Invoke($"Skipped {origin}: unknown severity '{spec.Severity}'.");
                return null;
            }

            if (!TryParseStride(spec.Stride, out StrideCategory? stride))
            {
                diagnostics?.Invoke($"Skipped {origin}: unknown stride '{spec.Stride}'.");
                return null;
            }

            string? defaultPriority = candidate.Document.Version == 2 ? spec.DefaultPriority : null;
            if (!TryParseThreatPriority(defaultPriority, out ThreatPriority? defaultThreatPriority))
            {
                diagnostics?.Invoke($"Skipped {origin}: unknown defaultPriority '{spec.DefaultPriority}'.");
                return null;
            }

            Uri? helpUri = null;
            if (!string.IsNullOrWhiteSpace(spec.HelpUri) && !TryCreateSafeHelpUri(spec.HelpUri, out helpUri))
            {
                diagnostics?.Invoke($"Ignored invalid 'helpUri' on {origin}: '{spec.HelpUri}'.");
                helpUri = null;
            }

            List<ThreatReference> references = ParseReferences(spec.ThreatReferences, origin, diagnostics);
            RuleProvenance? provenance = CompileProvenance(spec.Provenance);
            RuleThreatCategory? threatCategory = CompileThreatCategory(
                candidate.Document,
                spec,
                stride);
            if (defaultThreatPriority.HasValue && threatCategory == null)
            {
                diagnostics?.Invoke($"Skipped {origin}: defaultPriority requires a threat category.");
                return null;
            }

            string message = spec.Message!;
            if (string.Equals(candidate.Document.Pack?.Dialect, RulePackDialects.InteractionV1, StringComparison.Ordinal))
            {
                return new InteractionRule(
                    candidate.EffectiveId,
                    severity,
                    message,
                    string.IsNullOrWhiteSpace(spec.FullDescription) ? message : spec.FullDescription!,
                    spec.HelpText ?? string.Empty,
                    helpUri,
                    stride,
                    threatCategory,
                    defaultThreatPriority,
                    references,
                    CompileInteractionExpression(spec.Expression!, candidate.Document.Pack!),
                    candidate.Document.Pack!,
                    provenance);
            }

            if (string.IsNullOrWhiteSpace(spec.AppliesTo) || !Kinds.Contains(spec.AppliesTo!))
            {
                diagnostics?.Invoke($"Skipped {origin}: 'appliesTo' must be one of process, datastore, external, flow.");
                return null;
            }

            if (spec.When == null && spec.Assert == null)
            {
                diagnostics?.Invoke($"Skipped {origin}: at least one of 'when' or 'assert' is required.");
                return null;
            }

            bool isFlow = string.Equals(spec.AppliesTo, "flow", StringComparison.OrdinalIgnoreCase);
            if (!isFlow && (UsesRelational(spec.When) || UsesRelational(spec.Assert)))
            {
                diagnostics?.Invoke($"Skipped {origin}: 'crossesTrustBoundary', 'source', and 'target' require appliesTo 'flow'.");
                return null;
            }

            CanonicalizePropertyReferences(spec, candidate.Document.Pack);
            WarnUnknownProperties(spec, candidate.Document.Pack, origin, diagnostics);
            return new DeclarativeRule(
                candidate.EffectiveId,
                candidate.Document.Pack?.Id ?? (string.IsNullOrWhiteSpace(spec.Pack) ? "custom" : spec.Pack!),
                severity,
                spec.AppliesTo!,
                message,
                string.IsNullOrWhiteSpace(spec.FullDescription) ? message : spec.FullDescription!,
                spec.HelpText ?? string.Empty,
                helpUri,
                stride,
                threatCategory,
                defaultThreatPriority,
                references,
                spec.When,
                spec.Assert,
                candidate.Document.Pack,
                provenance);
        }

        private static RuleThreatCategory? CompileThreatCategory(
            ParsedDocument document,
            DeclarativeRuleSpec spec,
            StrideCategory? stride)
        {
            RulePackDefinition? pack = document.Pack;
            string? categoryId = document.Version == 2 ? spec.CategoryId : null;
            if (pack != null && categoryId != null)
            {
                RuleCategoryDefinition? resolvedCategory = pack.ResolveCategory(categoryId);
                RuleCategoryDefinition category = resolvedCategory!;
                return RuleThreatCategory.FromPack(pack, category);
            }

            return stride.HasValue ? RuleThreatCategory.FromStride(stride.Value) : null;
        }

        private static RuleProvenance? CompileProvenance(DeclarativeRuleSpec.RuleProvenanceSpec? provenance)
        {
            if (provenance == null)
            {
                return null;
            }

            List<RuleSourceExpression> expressions = (provenance.Expressions ?? new List<DeclarativeRuleSpec.SourceExpressionSpec>())
                .Where(expression => expression != null &&
                    !string.IsNullOrWhiteSpace(expression.Role) &&
                    IsNamespacedIdentifier(expression.Language) &&
                    expression.Text != null)
                .Select(expression => new RuleSourceExpression(expression.Role!, expression.Language!, expression.Text!))
                .ToList();
            return new RuleProvenance(
                provenance.SourceId,
                provenance.CategoryId,
                provenance.Location,
                expressions.AsReadOnly());
        }

        private static InteractionExpression CompileInteractionExpression(
            DeclarativeRuleSpec.InteractionExpressionSpec expression,
            RulePackDefinition pack)
        {
            if (expression.AllOf != null)
            {
                return InteractionExpression.All(expression.AllOf
                    .Select(child => CompileInteractionExpression(child, pack)).ToList().AsReadOnly());
            }

            if (expression.AnyOf != null)
            {
                return InteractionExpression.Any(expression.AnyOf
                    .Select(child => CompileInteractionExpression(child, pack)).ToList().AsReadOnly());
            }

            if (expression.Not != null)
            {
                return InteractionExpression.Negate(CompileInteractionExpression(expression.Not, pack));
            }

            if (expression.Crosses != null)
            {
                return InteractionExpression.Crosses(CanonicalElementTypeId(expression.Crosses, pack));
            }

            if (expression.Type != null)
            {
                return InteractionExpression.TypeIs(
                    expression.Subject!,
                    CanonicalElementTypeId(expression.Type, pack));
            }

            if (expression.Kind != null)
            {
                return InteractionExpression.KindIs(expression.Subject!, expression.Kind);
            }

            DeclarativeEndpoint? connected = expression.ReachableFrom ?? expression.ConnectsTo;
            if (connected != null)
            {
                CanonicalizeEndpoint(connected, pack);
                return InteractionExpression.Connectivity(
                    expression.Subject!, DeclarativeRule.CompileEndpoint(connected, "source"), expression.ReachableFrom != null);
            }

            string? property = CanonicalPropertyName(expression.Property!, pack);
            if (expression.CompiledPattern != null)
            {
                return InteractionExpression.RegexProperty(expression.Subject!, property!, expression.CompiledPattern);
            }

            if (expression.GreaterThan.HasValue || expression.GreaterThanOrEqual.HasValue ||
                expression.LessThan.HasValue || expression.LessThanOrEqual.HasValue)
            {
                return InteractionExpression.NumericProperty(
                    expression.Subject!, property!, expression.GreaterThan, expression.GreaterThanOrEqual, expression.LessThan, expression.LessThanOrEqual);
            }

            return InteractionExpression.PropertyIn(
                expression.Subject!,
                property!,
                new List<string>(expression.ValueIn!).AsReadOnly());
        }

        private static string CanonicalElementTypeId(string type, RulePackDefinition pack)
        {
            return pack.ResolveElementType(type)?.Id ?? type;
        }

        private static HashSet<ParsedDocument> FindDuplicatePackDocuments(
            IReadOnlyList<ParsedDocument> documents,
            Action<string>? diagnostics)
        {
            HashSet<ParsedDocument> duplicates = new HashSet<ParsedDocument>();
            IEnumerable<IGrouping<string, ParsedDocument>> groups = documents
                .Where(document => document.Pack != null)
                .GroupBy(document => document.Pack!.Id, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() > 1)
                .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase);

            foreach (IGrouping<string, ParsedDocument> group in groups)
            {
                string canonicalId = group
                    .Select(document => document.Pack!.Id)
                    .OrderBy(id => id, StringComparer.Ordinal)
                    .First();
                List<string> files = group.Select(document => document.File).OrderBy(file => file, StringComparer.Ordinal).ToList();
                diagnostics?.Invoke($"Skipped duplicate pack id '{canonicalId}' declared by: {string.Join(", ", files)}.");
                foreach (ParsedDocument document in group)
                {
                    duplicates.Add(document);
                }
            }

            return duplicates;
        }

        private static HashSet<RuleCandidate> FindDuplicateRules(
            IReadOnlyList<RuleCandidate> candidates,
            Action<string>? diagnostics)
        {
            HashSet<RuleCandidate> duplicates = new HashSet<RuleCandidate>();
            IEnumerable<IGrouping<string, RuleCandidate>> groups = candidates
                .Where(candidate => !string.IsNullOrWhiteSpace(candidate.EffectiveId))
                .GroupBy(candidate => candidate.EffectiveId, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() > 1 && group.Any(candidate => candidate.Document.Pack != null))
                .OrderBy(group => group.Key, StringComparer.OrdinalIgnoreCase);

            foreach (IGrouping<string, RuleCandidate> group in groups)
            {
                string canonicalId = group
                    .Select(candidate => candidate.EffectiveId)
                    .OrderBy(id => id, StringComparer.Ordinal)
                    .First();
                List<string> origins = group
                    .Select(candidate => $"'{candidate.Document.File}' source rule '{candidate.Spec.Id}'")
                    .OrderBy(origin => origin, StringComparer.Ordinal)
                    .ToList();
                diagnostics?.Invoke(
                    $"Skipped duplicate effective rule id '{canonicalId}' declared by {string.Join(", ", origins)}; all declarations were ignored.");
                foreach (RuleCandidate candidate in group)
                {
                    duplicates.Add(candidate);
                }
            }

            return duplicates;
        }

        private static bool UsesRelational(DeclarativeCondition? condition)
        {
            return condition != null &&
                (condition.CrossesTrustBoundary.HasValue || condition.Source != null || condition.Target != null);
        }

        private static bool TryParseSeverity(string? value, out MessageSeverity severity)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                severity = MessageSeverity.Warning;
                return true;
            }

            string? name = Enum.GetNames(typeof(MessageSeverity))
                .FirstOrDefault(candidate => string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase));
            if (name != null && Enum.TryParse(name, out severity))
            {
                return true;
            }

            severity = default;
            return false;
        }

        private static bool TryCreateSafeHelpUri(string? value, out Uri? uri)
        {
            uri = null;
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? candidate) ||
                (!string.Equals(candidate.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(candidate.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            uri = candidate;
            return true;
        }

        private static bool TryParseStride(string? value, out StrideCategory? stride)
        {
            stride = null;
            if (string.IsNullOrWhiteSpace(value))
            {
                return true;
            }

            string? name = Enum.GetNames(typeof(StrideCategory))
                .FirstOrDefault(candidate => string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase));
            if (name != null &&
                !string.Equals(name, nameof(StrideCategory.Unknown), StringComparison.Ordinal) &&
                Enum.TryParse(name, out StrideCategory parsed))
            {
                stride = parsed;
                return true;
            }

            return false;
        }

        private static bool TryParseThreatPriority(string? value, out ThreatPriority? priority)
        {
            priority = null;
            if (string.IsNullOrWhiteSpace(value))
            {
                return true;
            }

            string? name = Enum.GetNames(typeof(ThreatPriority))
                .FirstOrDefault(candidate => string.Equals(candidate, value, StringComparison.OrdinalIgnoreCase));
            if (name != null && Enum.TryParse(name, out ThreatPriority parsed))
            {
                priority = parsed;
                return true;
            }

            return false;
        }

        private static void CanonicalizePropertyReferences(DeclarativeRuleSpec spec, RulePackDefinition? pack)
        {
            if (pack == null)
            {
                return;
            }

            CanonicalizeCondition(spec.When, pack);
            CanonicalizeCondition(spec.Assert, pack);
        }

        private static void CanonicalizeCondition(DeclarativeCondition? condition, RulePackDefinition pack)
        {
            if (condition == null)
            {
                return;
            }

            condition.Property = CanonicalPropertyName(condition.Property, pack);
            CanonicalizeEndpoint(condition.Source, pack);
            CanonicalizeEndpoint(condition.Target, pack);
            CanonicalizeEndpoint(condition.ReachableFrom, pack);
            CanonicalizeEndpoint(condition.ConnectsTo, pack);
        }

        private static void CanonicalizeEndpoint(DeclarativeEndpoint? endpoint, RulePackDefinition pack)
        {
            if (endpoint != null)
            {
                endpoint.Property = CanonicalPropertyName(endpoint.Property, pack);
            }
        }

        private static string? CanonicalPropertyName(string? property, RulePackDefinition pack)
        {
            if (string.IsNullOrWhiteSpace(property))
            {
                return property;
            }

            RulePropertyDefinition? definition = pack.ResolveProperty(property!);
            return definition?.Name ?? property;
        }

        private static List<ThreatReference> ParseReferences(List<string>? references, string origin, Action<string>? diagnostics)
        {
            List<ThreatReference> result = new List<ThreatReference>();
            if (references == null)
            {
                return result;
            }

            foreach (string reference in references)
            {
                ThreatReference? parsed = ParseReference(reference);
                if (parsed == null)
                {
                    diagnostics?.Invoke($"Ignored unrecognized threat reference '{reference}' on {origin}.");
                    continue;
                }

                result.Add(parsed);
            }

            return result;
        }

        private static ThreatReference? ParseReference(string reference)
        {
            if (string.IsNullOrWhiteSpace(reference))
            {
                return null;
            }

            int separator = reference.IndexOf(':');
            if (separator <= 0)
            {
                return null;
            }

            string catalog = reference.Substring(0, separator).Trim();
            string id = reference.Substring(separator + 1).Trim();
            if (id.Length == 0)
            {
                return null;
            }

            if (string.Equals(catalog, "CWE", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(id, NumberStyles.Integer, CultureInfo.InvariantCulture, out int cwe))
            {
                return ThreatReference.Cwe(cwe);
            }

            if (string.Equals(catalog, "CAPEC", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(id, NumberStyles.Integer, CultureInfo.InvariantCulture, out int capec))
            {
                return ThreatReference.Capec(capec);
            }

            if (string.Equals(catalog, "ATTACK", StringComparison.OrdinalIgnoreCase))
            {
                return ThreatReference.Attack(id);
            }

            return null;
        }

        private static void WarnUnknownProperties(
            DeclarativeRuleSpec spec,
            RulePackDefinition? pack,
            string origin,
            Action<string>? diagnostics)
        {
            if (diagnostics == null)
            {
                return;
            }

            WarnProperty(spec.AppliesTo!, spec.When?.Property, pack, origin, diagnostics);
            WarnProperty(spec.AppliesTo!, spec.Assert?.Property, pack, origin, diagnostics);
            WarnEndpointProperties(spec.When, pack, origin, diagnostics);
            WarnEndpointProperties(spec.Assert, pack, origin, diagnostics);
        }

        private static void WarnEndpointProperties(
            DeclarativeCondition? condition,
            RulePackDefinition? pack,
            string origin,
            Action<string> diagnostics)
        {
            if (condition?.Source?.Kind != null)
            {
                WarnProperty(condition.Source.Kind!, condition.Source.Property, pack, origin, diagnostics);
            }

            if (condition?.Target?.Kind != null)
            {
                WarnProperty(condition.Target.Kind!, condition.Target.Property, pack, origin, diagnostics);
            }

            foreach (DeclarativeEndpoint? filter in new[] { condition?.ReachableFrom, condition?.ConnectsTo })
            {
                if (filter?.Property != null)
                {
                    foreach (string kind in filter.Kind == null ? new[] { "process", "datastore", "external" } : new[] { filter.Kind })
                    {
                        WarnProperty(kind, filter.Property, pack, origin, diagnostics);
                    }
                }
            }
        }

        private static void WarnProperty(
            string appliesTo,
            string? property,
            RulePackDefinition? pack,
            string origin,
            Action<string> diagnostics)
        {
            if (string.IsNullOrWhiteSpace(property))
            {
                return;
            }

            bool known = PropertySchemaCatalog.All.Any(descriptor =>
                string.Equals(descriptor.AppliesTo, appliesTo, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(descriptor.Name, property, StringComparison.OrdinalIgnoreCase));
            known = known || pack?.ResolveProperty(property!) != null;

            if (!known)
            {
                diagnostics($"{origin} reads property '{property}' on '{appliesTo}', which is not in the property schema.");
            }
        }

        private sealed class ParsedDocument
        {
            public ParsedDocument(string file, int version, RulePackDefinition? pack, List<DeclarativeRuleSpec> rules)
            {
                this.File = file;
                this.Version = version;
                this.Pack = pack;
                this.Rules = rules;
            }

            public string File { get; }

            public int Version { get; }

            public RulePackDefinition? Pack { get; }

            public List<DeclarativeRuleSpec> Rules { get; }
        }

        private sealed class RuleCandidate
        {
            public RuleCandidate(ParsedDocument document, DeclarativeRuleSpec spec, string effectiveId, int index)
            {
                this.Document = document;
                this.Spec = spec;
                this.EffectiveId = effectiveId;
                this.Index = index;
            }

            public ParsedDocument Document { get; }

            public DeclarativeRuleSpec Spec { get; }

            public string EffectiveId { get; }

            public int Index { get; }
        }

        private sealed class RegexCompiler
        {
            private readonly Dictionary<string, Regex> patterns = new Dictionary<string, Regex>(StringComparer.Ordinal);
            private TimeSpan elapsed;

            public Regex? Prepare(string? property, string? pattern)
            {
                if (pattern == null)
                {
                    return null;
                }

                if (string.IsNullOrWhiteSpace(property))
                {
                    throw new InvalidDataException("matches requires property.");
                }

                if (pattern.Length == 0 || pattern.Length > 1024)
                {
                    throw new InvalidDataException("Regex patterns must contain 1 to 1024 characters.");
                }

                if (this.elapsed > TimeSpan.FromSeconds(1))
                {
                    throw new InvalidDataException("Regex construction exceeded the shared 1000 ms load limit.");
                }

                if (this.patterns.TryGetValue(pattern, out Regex? existing))
                {
                    return existing;
                }

                if (this.patterns.Count >= 128)
                {
                    throw new InvalidDataException("Rule sources exceed the limit of 128 distinct regex patterns.");
                }

                Regex compiled;
                Stopwatch timer = Stopwatch.StartNew();
                try
                {
                    compiled = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
                }
                finally
                {
                    timer.Stop();
                    this.elapsed += timer.Elapsed;
                }

                if (timer.Elapsed > TimeSpan.FromMilliseconds(250) || this.elapsed > TimeSpan.FromSeconds(1))
                {
                    throw new InvalidDataException("Regex construction exceeded the 250 ms pattern or 1000 ms load limit.");
                }

                this.patterns.Add(pattern, compiled);
                return compiled;
            }
        }
    }
}
