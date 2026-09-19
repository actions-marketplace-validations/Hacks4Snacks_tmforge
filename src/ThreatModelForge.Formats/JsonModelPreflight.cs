namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text.Json;

    /// <summary>Checks canonical model JSON before deserialization can discard authored information.</summary>
    public static class JsonModelPreflight
    {
        /// <summary>Inspects a document without constructing or changing a model.</summary>
        /// <param name="json">The canonical model JSON.</param>
        /// <returns>The structural diagnostics in source order.</returns>
        public static IReadOnlyList<DocumentDiagnostic> Inspect(string json)
        {
            List<DocumentDiagnostic> diagnostics = JsonDocumentPreflight.Inspect<TmForgeJsonModel>(json).ToList();
            if (diagnostics.Any(diagnostic => diagnostic.Code == "input.invalid-json" || diagnostic.Code == "input.too-large" || diagnostic.Code == "input.object-required"))
            {
                return diagnostics;
            }

            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;
            if (Find(root, "schema", out JsonElement schema) && schema.ValueKind != JsonValueKind.Null && Text(root, "schema") != "tmforge-json")
            {
                JsonDocumentPreflight.Add(diagnostics, "input.schema", "$.schema", "Expected a 'tmforge-json' document. Use the reader for the declared format.");
            }

            if (Find(root, "version", out JsonElement version) && version.ValueKind != JsonValueKind.Null && Text(root, "version") != "0.1")
            {
                JsonDocumentPreflight.Add(diagnostics, "input.version", "$.version", "Unsupported canonical model version. This build reads version '0.1'.");
            }

            Dictionary<Guid, string> identities = new Dictionary<Guid, string>();
            if (Find(root, "diagrams", out JsonElement pages) && pages.ValueKind == JsonValueKind.Array && pages.GetArrayLength() > 0)
            {
                if (pages.GetArrayLength() > 1024)
                {
                    JsonDocumentPreflight.Add(diagnostics, "model.too-many-pages", "$.diagrams", "A model may contain at most 1024 pages.");
                    return diagnostics;
                }

                int index = 0;
                foreach (JsonElement page in pages.EnumerateArray())
                {
                    string path = "$.diagrams[" + index.ToString(CultureInfo.InvariantCulture) + "]";
                    Identity(page, path, identities, diagnostics, page: true);
                    InspectPage(page, path, identities, diagnostics);
                    index++;
                }
            }
            else
            {
                InspectPage(root, "$", identities, diagnostics);
            }

            return diagnostics;
        }

        /// <summary>Refuses a document when preflight reports an error.</summary>
        /// <param name="diagnostics">The previously collected diagnostics.</param>
        public static void ThrowIfInvalid(IReadOnlyList<DocumentDiagnostic> diagnostics)
        {
            string[] errors = diagnostics.Where(diagnostic => diagnostic.Severity == "error")
                .Select(diagnostic => diagnostic.Path + ": " + diagnostic.Message).ToArray();
            if (errors.Length > 0)
            {
                throw new InvalidDataException(string.Join(Environment.NewLine, errors));
            }
        }

        private static void InspectPage(JsonElement page, string path, Dictionary<Guid, string> identities, List<DocumentDiagnostic> diagnostics)
        {
            HashSet<string> ids = new HashSet<string>(StringComparer.Ordinal);
            if (Find(page, "elements", out JsonElement elements) && elements.ValueKind == JsonValueKind.Array)
            {
                int elementIndex = 0;
                foreach (JsonElement element in elements.EnumerateArray())
                {
                    string elementPath = path + ".elements[" + elementIndex.ToString(CultureInfo.InvariantCulture) + "]";
                    Identity(element, elementPath, identities, diagnostics);
                    ids.Add(Text(element, "id"));
                    string kind = Text(element, "kind");
                    if (Find(element, "kind", out _) && kind != "process" && kind != "datastore" && kind != "external" && kind != "boundary")
                    {
                        JsonDocumentPreflight.Add(diagnostics, "model.unsupported-kind", elementPath + ".kind", "Unsupported element kind '" + kind + "'. Use process, datastore, external or boundary; unknown kinds are not treated as processes.");
                    }

                    bool hasWidth = Find(element, "width", out JsonElement width) && width.ValueKind != JsonValueKind.Null;
                    bool hasHeight = Find(element, "height", out JsonElement height) && height.ValueKind != JsonValueKind.Null;
                    if (kind != "boundary" && hasWidth != hasHeight)
                    {
                        JsonDocumentPreflight.Add(diagnostics, "model.incomplete-size", elementPath, "Specify both width and height; a partial size would be ignored by the reader.");
                    }

                    if ((hasWidth && width.ValueKind == JsonValueKind.Number && width.TryGetInt32(out int widthValue) && widthValue <= 0)
                        || (hasHeight && height.ValueKind == JsonValueKind.Number && height.TryGetInt32(out int heightValue) && heightValue <= 0))
                    {
                        JsonDocumentPreflight.Add(diagnostics, "model.invalid-size", elementPath, "Element width and height must be positive.");
                    }

                    elementIndex++;
                    if (diagnostics.Count >= JsonDocumentPreflight.MaxDiagnostics)
                    {
                        return;
                    }
                }
            }

            if (!Find(page, "flows", out JsonElement flows) || flows.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            int index = 0;
            foreach (JsonElement flow in flows.EnumerateArray())
            {
                string flowPath = path + ".flows[" + index.ToString(CultureInfo.InvariantCulture) + "]";
                Identity(flow, flowPath, identities, diagnostics);
                foreach (string endpoint in new[] { "source", "target" })
                {
                    string id = Text(flow, endpoint);
                    if (string.IsNullOrWhiteSpace(id) || !ids.Contains(id))
                    {
                        JsonDocumentPreflight.Add(
                            diagnostics,
                            "model.unresolved-endpoint",
                            flowPath + "." + endpoint,
                            $"Flow '{Text(flow, "id")}' refers to '{id}', which is not an element on this page. Correct the {endpoint} reference; the flow will not be dropped.");
                    }
                }

                index++;
            }
        }

        private static void Identity(JsonElement item, string path, Dictionary<Guid, string> identities, List<DocumentDiagnostic> diagnostics, bool page = false)
        {
            string id = Text(item, "id");
            if (string.IsNullOrWhiteSpace(id) || id.Length > 1024)
            {
                JsonDocumentPreflight.Add(diagnostics, "model.invalid-id", path + ".id", "An explicit, nonblank id of at most 1024 characters is required; import will not invent a replacement identity.");
                return;
            }

            Guid guid = Guid.TryParse(id, out Guid parsed) ? parsed
                : page ? DeterministicGuid.FromPageId(id) : DeterministicGuid.FromElementId(id);
            if (guid == Guid.Empty)
            {
                JsonDocumentPreflight.Add(diagnostics, "model.invalid-id", path + ".id", "An all-zero GUID is not a valid model identity.");
            }
            else if (identities.TryGetValue(guid, out string? previous))
            {
                JsonDocumentPreflight.Add(diagnostics, "model.duplicate-id", path + ".id", "Identity '" + id + "' is already used at " + previous + ".id. Assign distinct ids; import will not re-key duplicates.");
            }
            else
            {
                identities.Add(guid, path);
            }
        }

        private static string Text(JsonElement value, string name)
            => Find(value, name, out JsonElement member) && member.ValueKind == JsonValueKind.String ? member.GetString() ?? string.Empty : string.Empty;

        private static bool Find(JsonElement value, string name, out JsonElement member)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                    {
                        member = property.Value;
                        return true;
                    }
                }
            }

            member = default;
            return false;
        }
    }
}
