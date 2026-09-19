namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text.Json;
    using Microsoft.Extensions.DependencyInjection;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Engine;

    /// <summary>
    /// Shared helpers for the <c>tmforge mcp</c> tool classes: property-assignment marshaling and the
    /// grounding text an agent needs to author declarative manifests.
    /// </summary>
    internal static class McpToolSupport
    {
        /// <summary>
        /// A human-readable description of the declarative manifest shape accepted by the
        /// <c>apply</c> tool, returned by the <c>manifest_schema</c> tool as agent grounding.
        /// </summary>
        public const string ManifestSchemaText =
            "A declarative threat-model manifest is a JSON object with these fields:\n" +
            "{\n" +
            "  \"name\": \"<model title>\",\n" +
            "  \"boundaries\": [ { \"alias\": \"<stable id>\", \"name\": \"<label>\" } ],\n" +
            "  \"elements\": [ {\n" +
            "    \"alias\": \"<stable id>\",\n" +
            "    \"kind\": \"process | store | external\",   // omit when 'stencil' is set\n" +
            "    \"name\": \"<label>\",\n" +
            "    \"stencil\": \"<stencil id from the stencils tool>\",  // optional\n" +
            "    \"boundary\": \"<boundary alias>\",           // optional\n" +
            "    \"props\": { \"<Key>\": \"<Value>\" }            // optional, validated against property_schema\n" +
            "  } ],\n" +
            "  \"flows\": [ {\n" +
            "    \"from\": \"<element alias or unique name>\",\n" +
            "    \"to\": \"<element alias or unique name>\",\n" +
            "    \"name\": \"<label>\",\n" +
            "    \"props\": { \"Protocol\": \"HTTPS\", \"Port\": \"443\" }   // optional\n" +
            "  } ]\n" +
            "}\n" +
            "The optional versioned envelope is \"schema\": \"tmforge-manifest\", \"version\": 1; " +
            "unversioned manifests remain supported. Optional \"pages\" is an array of {\"alias\":\"page-id\",\"name\":\"Page title\"}. " +
            "A boundary or element can select a page with \"page\":\"page-id\"; omission uses the first page. " +
            "Both flow endpoints must be on the same page.\n" +
            "Boundaries and elements accept optional integer \"x\"/\"y\" coordinates and \"width\"/\"height\" dimensions. " +
            "Supply coordinates as a pair and dimensions as a pair; omitted geometry uses deterministic placement. " +
            "Flows can declare an \"alias\" for stable connector identity and later edits.\n" +
            "Elements and flow endpoints are referenced by alias (or unique name), so the manifest needs no GUIDs " +
            "and round-trips with the export_manifest tool. Property values are validated against the property_schema " +
            "tool's catalog; pass force=true to store unknown names or values.";

        private const int MaxPages = 128;
        private const int MaxElements = 10000;
        private const int MaxFlows = 20000;
        private const int MaxThreats = 20000;
        private const int MaxProperties = 100000;
        private const int MaxPropertiesPerObject = 256;
        private const int MaxListItems = 100000;
        private const int MaxGeneratedItems = 100000;
        private const int MaxStringLength = 65536;
        private const long MaxTextCharacters = 16L * 1024 * 1024;
        private const long MaxOperationWork = 4L * 1024 * 1024;

        // Typed MCP results are serialized to JSON text and then escaped into the JSON-RPC envelope.
        // Keep the inner payload below half the 32 MiB response budget, with room for the envelope.
        private const long MaxStructuredResponseBytes = 15L * 1024 * 1024;

        private static readonly JsonSerializerOptions ResponseJsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        /// <summary>
        /// Marshals a property map (a JSON object of key/value strings) into the <c>KEY=VALUE</c>
        /// assignment list the authoring requests consume.
        /// </summary>
        /// <param name="properties">The property map, or <see langword="null"/>.</param>
        /// <returns>The assignments, or an empty list.</returns>
        public static IReadOnlyList<string> ToAssignments(IReadOnlyDictionary<string, string>? properties)
        {
            if (properties == null || properties.Count == 0)
            {
                return Array.Empty<string>();
            }

            List<string> assignments = new List<string>(properties.Count);
            foreach (KeyValuePair<string, string> pair in properties)
            {
                assignments.Add(pair.Key + "=" + pair.Value);
            }

            return assignments;
        }

        /// <summary>
        /// Resolves an optional custom rule pack path through the MCP workspace sandbox and reads it
        /// into engine rule options. Path resolution stays in this host: the engine facade only ever
        /// sees content, so an agent cannot reach outside the configured workspace root to load rules.
        /// </summary>
        /// <param name="services">The MCP request services.</param>
        /// <param name="rulesPath">The rule pack path, or <see langword="null"/> for built-in rules only.</param>
        /// <returns>The engine rule options, or <see langword="null"/> when no pack is selected.</returns>
        public static EngineRuleOptions? LoadRules(IServiceProvider services, string? rulesPath)
        {
            if (string.IsNullOrWhiteSpace(rulesPath))
            {
                return null;
            }

            ValidateArguments(new[] { rulesPath });
            McpPathPolicy pathPolicy = services.GetRequiredService<McpPathPolicy>();
            byte[] content = pathPolicy.ReadAllBytes(rulesPath!);
            return new EngineRuleOptions
            {
                Sources = new[]
                {
                    new RuleSourceDto { Name = rulesPath, Json = RuleContent.FromBytes(rulesPath!, content).ToJson() },
                },
            };
        }

        /// <summary>Validates a model against the MCP request complexity budget.</summary>
        /// <param name="model">The model to validate, or <see langword="null"/>.</param>
        public static void ValidateModel(TmForgeModelDto? model)
        {
            ValidateModels(model);
        }

        /// <summary>Validates several models against one shared MCP operation budget.</summary>
        /// <param name="models">The models participating in one operation.</param>
        public static void ValidateModels(params TmForgeModelDto?[] models)
        {
            Budget budget = new Budget();
            foreach (TmForgeModelDto? model in models)
            {
                AddModel(budget, model);
            }
        }

        /// <summary>Validates generated findings before returning them to an MCP caller.</summary>
        /// <param name="findings">The generated findings.</param>
        /// <returns>The unchanged findings.</returns>
        public static IReadOnlyList<FindingDto> ValidateResponse(IReadOnlyList<FindingDto> findings)
        {
            if (findings.Count > MaxGeneratedItems)
            {
                throw new InvalidDataException($"MCP response exceeds the limit of {MaxGeneratedItems} findings.");
            }

            Budget budget = new Budget();
            foreach (FindingDto finding in findings)
            {
                budget.AddText(finding.Id);
                budget.AddText(finding.Severity);
                budget.AddText(finding.RuleId);
                budget.AddText(finding.Message);
                budget.AddTexts(finding.ElementIds);
            }

            ValidateStructuredResponse(findings);
            return findings;
        }

        /// <summary>Validates generated threats before returning them to an MCP caller.</summary>
        /// <param name="threats">The generated threats.</param>
        /// <returns>The unchanged threats.</returns>
        public static IReadOnlyList<ThreatDto> ValidateResponse(IReadOnlyList<ThreatDto> threats)
        {
            if (threats.Count > MaxGeneratedItems)
            {
                throw new InvalidDataException($"MCP response exceeds the limit of {MaxGeneratedItems} threats.");
            }

            Budget budget = new Budget();
            foreach (ThreatDto threat in threats)
            {
                budget.AddText(threat.Id);
                budget.AddText(threat.RuleId);
                budget.AddText(threat.Category);
                budget.AddText(threat.CategoryId);
                budget.AddText(threat.CategoryName);
                budget.AddText(threat.Stride);
                budget.AddText(threat.Title);
                budget.AddText(threat.Mitigation);
                budget.AddText(threat.Severity);
                budget.AddText(threat.Priority);
                budget.AddTexts(threat.References);
                budget.AddTexts(threat.ElementIds);
                budget.AddText(threat.Interaction);
                budget.AddText(threat.State);
                budget.AddText(threat.Justification);
                budget.AddText(threat.Description);
            }

            ValidateStructuredResponse(threats);
            return threats;
        }

        /// <summary>Validates a threat register before returning it to an MCP caller.</summary>
        /// <param name="register">The split register.</param>
        /// <returns>The unchanged register.</returns>
        public static ThreatRegisterDto ValidateResponse(ThreatRegisterDto register)
        {
            if (register.Entries.Count > MaxGeneratedItems)
            {
                throw new InvalidDataException($"MCP response exceeds the limit of {MaxGeneratedItems} threats.");
            }

            Budget budget = new Budget();
            foreach (ThreatRegisterEntryDto entry in register.Entries)
            {
                budget.AddText(entry.Id);
                budget.AddText(entry.State);
                budget.AddText(entry.RuleId);
                budget.AddText(entry.Title);
                budget.AddText(entry.Triage);
            }

            budget.AddTexts(register.UnavailableRuleIds);
            budget.AddTexts(register.Diagnostics);

            ValidateStructuredResponse(register);
            return register;
        }

        /// <summary>Validates generated text before returning it to an MCP caller.</summary>
        /// <param name="text">The response text.</param>
        /// <returns>The unchanged text.</returns>
        public static string ValidateResponse(string text)
        {
            ValidateStructuredResponse(text);
            return text;
        }

        /// <summary>Validates a merge result before returning it to an MCP caller.</summary>
        /// <param name="result">The merge result.</param>
        /// <returns>The unchanged merge result.</returns>
        public static MergeResultDto ValidateResult(MergeResultDto result)
        {
            ValidateModel(result.Merged);
            int conflicts = result.Conflicts?.Count ?? 0;
            if (conflicts > MaxGeneratedItems)
            {
                throw new InvalidDataException($"MCP response exceeds the limit of {MaxGeneratedItems} merge conflicts.");
            }

            Budget budget = new Budget();
            foreach (MergeConflictDto conflict in result.Conflicts ?? Array.Empty<MergeConflictDto>())
            {
                budget.AddText(conflict.ElementId);
                budget.AddText(conflict.ElementKind);
                budget.AddText(conflict.Name);
                budget.AddText(conflict.DiagramName);
                budget.AddText(conflict.Kind);
                budget.AddText(conflict.Property);
                budget.AddText(conflict.Base);
                budget.AddText(conflict.Ours);
                budget.AddText(conflict.Theirs);
            }

            ValidateStructuredResponse(result);
            return result;
        }

        /// <summary>Validates an authoring manifest against the MCP request complexity budget.</summary>
        /// <param name="manifest">The manifest to validate.</param>
        public static void ValidateManifest(Manifest manifest)
        {
            if (manifest == null)
            {
                throw new ArgumentNullException(nameof(manifest));
            }

            Budget budget = new Budget();
            budget.AddText(manifest.Name);
            if (manifest.Boundaries != null)
            {
                budget.AddElements(manifest.Boundaries.Count);
                foreach (ManifestBoundary boundary in manifest.Boundaries)
                {
                    budget.AddText(boundary.Alias);
                    budget.AddText(boundary.Name);
                }
            }

            if (manifest.Elements != null)
            {
                budget.AddElements(manifest.Elements.Count);
                foreach (ManifestElement element in manifest.Elements)
                {
                    budget.AddText(element.Alias);
                    budget.AddText(element.Kind);
                    budget.AddText(element.Name);
                    budget.AddText(element.Stencil);
                    budget.AddText(element.Boundary);
                    budget.AddProperties(element.Props);
                }
            }

            if (manifest.Flows != null)
            {
                budget.AddFlows(manifest.Flows.Count);
                foreach (ManifestFlow flow in manifest.Flows)
                {
                    budget.AddText(flow.From);
                    budget.AddText(flow.To);
                    budget.AddText(flow.Name);
                    budget.AddProperties(flow.Props);
                }
            }

            int boundaries = manifest.Boundaries?.Count ?? 0;
            int elements = manifest.Elements?.Count ?? 0;
            int flows = manifest.Flows?.Count ?? 0;
            long endpointScans = checked((2L * flows * (boundaries + elements)) + ((long)flows * (flows - 1)));
            budget.AddOperationWork(endpointScans);
        }

        /// <summary>Validates an exported manifest and returns the same result.</summary>
        /// <param name="result">The manifest to validate.</param>
        /// <returns>The unchanged manifest.</returns>
        public static Manifest ValidateResult(Manifest result)
        {
            ValidateManifest(result);
            ValidateStructuredResponse(result);
            return result;
        }

        /// <summary>Validates direct string and property arguments before an MCP tool processes them.</summary>
        /// <param name="values">The string arguments to validate.</param>
        /// <param name="properties">An optional property map to validate.</param>
        public static void ValidateArguments(
            IEnumerable<string?> values,
            IReadOnlyDictionary<string, string>? properties = null)
        {
            Budget budget = new Budget();
            foreach (string? value in values)
            {
                budget.AddText(value);
            }

            budget.AddProperties(properties);
        }

        /// <summary>Validates the model in an authoring result and returns the same result.</summary>
        /// <param name="result">The result to validate.</param>
        /// <returns>The unchanged result.</returns>
        public static AuthoringResultDto ValidateResult(AuthoringResultDto result)
        {
            ValidateModel(result.Model);
            ValidateStructuredResponse(result);
            return result;
        }

        /// <summary>Validates the model in an apply result and returns the same result.</summary>
        /// <param name="result">The result to validate.</param>
        /// <returns>The unchanged result.</returns>
        public static ApplyResultDto ValidateResult(ApplyResultDto result)
        {
            ValidateModel(result.Model);
            ValidateStructuredResponse(result);
            return result;
        }

        private static void AddModel(Budget budget, TmForgeModelDto? model)
        {
            if (model == null)
            {
                return;
            }

            budget.AddText(model.Schema);
            budget.AddText(model.Version);
            (int topLevelElements, int topLevelBoundaries) = AddElements(budget, model.Elements);
            int topLevelFlows = AddFlows(budget, model.Flows);
            budget.AddAnalysisWork(topLevelElements - topLevelBoundaries, topLevelBoundaries, topLevelFlows);
            if (model.Diagrams != null && model.Diagrams.Count > 0)
            {
                budget.AddPages(model.Diagrams.Count);
                foreach (TmForgeDiagramDto diagram in model.Diagrams)
                {
                    budget.AddText(diagram.Id);
                    budget.AddText(diagram.Name);
                    (int elements, int boundaries) = AddElements(budget, diagram.Elements);
                    int flows = AddFlows(budget, diagram.Flows);
                    budget.AddAnalysisWork(elements - boundaries, boundaries, flows);
                }
            }

            if (model.Analysis != null)
            {
                budget.AddTexts(model.Analysis.DisabledPacks);
                budget.AddTexts(model.Analysis.DisabledRuleIds);
            }

            IReadOnlyList<ThreatStateDto>? threats = model.Threats;
            if (threats != null)
            {
                budget.AddThreats(threats.Count);
                foreach (ThreatStateDto threat in threats)
                {
                    budget.AddText(threat.Id);
                    budget.AddText(threat.State);
                    budget.AddText(threat.Justification);
                    budget.AddText(threat.Category);
                    budget.AddText(threat.Title);
                    budget.AddText(threat.Description);
                    budget.AddText(threat.Mitigation);
                    budget.AddText(threat.Priority);
                    budget.AddTexts(threat.ElementIds);
                }
            }
        }

        private static (int Elements, int Boundaries) AddElements(Budget budget, IReadOnlyList<TmForgeElementDto>? elements)
        {
            if (elements == null)
            {
                return (0, 0);
            }

            budget.AddElements(elements.Count);
            int boundaries = 0;
            foreach (TmForgeElementDto element in elements)
            {
                budget.AddText(element.Id);
                budget.AddText(element.Kind);
                budget.AddText(element.Name);
                budget.AddProperties(element.Properties);
                if (string.Equals(element.Kind, "boundary", StringComparison.OrdinalIgnoreCase))
                {
                    boundaries++;
                }
            }

            return (elements.Count, boundaries);
        }

        private static int AddFlows(Budget budget, IReadOnlyList<TmForgeFlowDto>? flows)
        {
            if (flows == null)
            {
                return 0;
            }

            budget.AddFlows(flows.Count);
            foreach (TmForgeFlowDto flow in flows)
            {
                budget.AddText(flow.Id);
                budget.AddText(flow.Source);
                budget.AddText(flow.Target);
                budget.AddText(flow.Name);
                budget.AddProperties(flow.Properties);
            }

            return flows.Count;
        }

        private static void ValidateStructuredResponse<T>(T value)
        {
            using CountingWriteStream stream = new CountingWriteStream(MaxStructuredResponseBytes);
            JsonSerializer.Serialize(stream, value, ResponseJsonOptions);
        }

        private sealed class Budget
        {
            private int elements;
            private int flows;
            private int listItems;
            private int pages;
            private int properties;
            private long operationWork;
            private long textCharacters;
            private int threats;

            public void AddElements(int count)
            {
                this.elements = CheckedTotal(this.elements, count, MaxElements, "elements");
            }

            public void AddFlows(int count)
            {
                this.flows = CheckedTotal(this.flows, count, MaxFlows, "flows");
            }

            public void AddPages(int count)
            {
                this.pages = CheckedTotal(this.pages, count, MaxPages, "pages");
            }

            public void AddThreats(int count)
            {
                this.threats = CheckedTotal(this.threats, count, MaxThreats, "threats");
            }

            public void AddProperties(IReadOnlyDictionary<string, string>? values)
            {
                if (values == null)
                {
                    return;
                }

                if (values.Count > MaxPropertiesPerObject)
                {
                    throw new InvalidDataException($"MCP model object exceeds the limit of {MaxPropertiesPerObject} properties.");
                }

                this.properties = CheckedTotal(this.properties, values.Count, MaxProperties, "properties");
                this.AddOperationWork(checked((long)values.Count * (values.Count + 1) / 2));
                foreach (KeyValuePair<string, string> value in values)
                {
                    this.AddText(value.Key);
                    this.AddText(value.Value);
                }
            }

            public void AddAnalysisWork(int components, int boundaries, int flows)
            {
                long scansPerFlow = checked((5L * components) + (6L * boundaries));
                this.AddOperationWork(checked(scansPerFlow * flows));
            }

            public void AddOperationWork(long added)
            {
                if (added < 0 || added > MaxOperationWork - this.operationWork)
                {
                    throw new InvalidDataException($"MCP operation exceeds the work limit of {MaxOperationWork} steps.");
                }

                this.operationWork += added;
            }

            public void AddTexts(IEnumerable<string>? values)
            {
                if (values == null)
                {
                    return;
                }

                foreach (string value in values)
                {
                    this.listItems = CheckedTotal(this.listItems, 1, MaxListItems, "nested list items");
                    this.AddText(value);
                }
            }

            public void AddText(string? value)
            {
                if (string.IsNullOrEmpty(value))
                {
                    return;
                }

                if (value!.Length > MaxStringLength)
                {
                    throw new InvalidDataException($"MCP model string exceeds the limit of {MaxStringLength} characters.");
                }

                this.textCharacters += value.Length;
                if (this.textCharacters > MaxTextCharacters)
                {
                    throw new InvalidDataException($"MCP model text exceeds the limit of {MaxTextCharacters} characters.");
                }
            }

            private static int CheckedTotal(int current, int added, int limit, string name)
            {
                if (added < 0 || added > limit - current)
                {
                    throw new InvalidDataException($"MCP model exceeds the limit of {limit} {name}.");
                }

                return current + added;
            }
        }

        private sealed class CountingWriteStream : Stream
        {
            private readonly long limit;
            private long length;

            public CountingWriteStream(long limit)
            {
                this.limit = limit;
            }

            public override bool CanRead => false;

            public override bool CanSeek => false;

            public override bool CanWrite => true;

            public override long Length => this.length;

            public override long Position
            {
                get => this.length;
                set => throw new NotSupportedException();
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
            {
                this.Add(count);
            }

            public override void Write(ReadOnlySpan<byte> buffer)
            {
                this.Add(buffer.Length);
            }

            private void Add(int count)
            {
                if (count < 0 || count > this.limit - this.length)
                {
                    throw new InvalidDataException($"MCP response exceeds the limit of {this.limit} bytes.");
                }

                this.length += count;
            }
        }
    }
}
