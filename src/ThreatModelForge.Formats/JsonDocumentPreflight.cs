namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization.Metadata;

    /// <summary>Validates raw JSON against the existing serializer contract without losing unknown fields.</summary>
    public static class JsonDocumentPreflight
    {
        /// <summary>The maximum UTF-8 document size.</summary>
        public const int MaxBytes = 8 * 1024 * 1024;

        /// <summary>The maximum number of diagnostics, including a truncation diagnostic.</summary>
        public const int MaxDiagnostics = 100;

        private static readonly JsonSerializerOptions Options = CreateOptions();

        /// <summary>Reads bounded, strict UTF-8 without closing the caller's stream.</summary>
        /// <param name="stream">The source stream.</param>
        /// <returns>The document text, without an optional UTF-8 BOM.</returns>
        public static string ReadText(Stream stream)
        {
            _ = stream ?? throw new ArgumentNullException(nameof(stream));
            using MemoryStream content = new MemoryStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (content.Length + count > MaxBytes)
                {
                    throw new InvalidDataException("$: JSON input exceeds the 8 MiB preflight limit.");
                }

                content.Write(buffer, 0, count);
            }

            string text = new UTF8Encoding(false, true).GetString(content.ToArray());
            return text.Length > 0 && text[0] == '\uFEFF' ? text.Substring(1) : text;
        }

        /// <summary>Checks syntax, duplicate fields, unknown fields and serializer-compatible types.</summary>
        /// <typeparam name="T">The existing wire contract.</typeparam>
        /// <param name="json">The document text.</param>
        /// <returns>Diagnostics with stable codes and source paths.</returns>
        public static IReadOnlyList<DocumentDiagnostic> Inspect<T>(string json)
        {
            _ = json ?? throw new ArgumentNullException(nameof(json));
            List<DocumentDiagnostic> diagnostics = new List<DocumentDiagnostic>();
            if (Encoding.UTF8.GetByteCount(json) > MaxBytes)
            {
                Add(diagnostics, "input.too-large", "$", "JSON input exceeds the 8 MiB preflight limit.");
                return diagnostics;
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    Add(diagnostics, "input.object-required", "$", "The document must be a JSON object.");
                    return diagnostics;
                }

                InspectValue(document.RootElement, typeof(T), "$", diagnostics, typeof(T) == typeof(TmForgeJsonModel));
            }
            catch (JsonException error)
            {
                Add(diagnostics, "input.invalid-json", error.Path ?? "$", error.Message);
                return diagnostics;
            }

            try
            {
                _ = JsonSerializer.Deserialize<T>(json, Options);
            }
            catch (JsonException error)
            {
                Add(diagnostics, "input.invalid-value", error.Path ?? "$", error.Message);
            }

            return diagnostics;
        }

        /// <summary>Adds a diagnostic while bounding output size.</summary>
        /// <param name="diagnostics">The destination.</param>
        /// <param name="code">The stable code.</param>
        /// <param name="path">The source path.</param>
        /// <param name="message">The explanation.</param>
        /// <param name="severity">The severity.</param>
        public static void Add(List<DocumentDiagnostic> diagnostics, string code, string path, string message, string severity = "error")
        {
            if (diagnostics.Count >= MaxDiagnostics)
            {
                return;
            }

            bool truncated = diagnostics.Count == MaxDiagnostics - 1;
            diagnostics.Add(new DocumentDiagnostic
            {
                Code = truncated ? "input.diagnostic-limit" : code,
                Path = truncated ? "$" : path.Length <= 1024 ? path : path.Substring(0, 1024),
                Message = truncated ? "Diagnostic limit reached. Correct the reported problems and run preflight again." : message.Length <= 2048 ? message : message.Substring(0, 2048),
                Severity = truncated ? "error" : severity,
            });
        }

        private static JsonSerializerOptions CreateOptions()
        {
            JsonSerializerOptions options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true,
                TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
                MaxDepth = 64,
            };
            options.MakeReadOnly();
            return options;
        }

        private static void InspectValue(JsonElement value, Type? type, string path, List<DocumentDiagnostic> diagnostics, bool allowExtensions)
        {
            if (diagnostics.Count >= MaxDiagnostics)
            {
                return;
            }

            JsonTypeInfo? contract = type == null ? null : Options.GetTypeInfo(type);
            if (value.ValueKind == JsonValueKind.Array)
            {
                Type? itemType = type?.IsArray == true ? type.GetElementType()
                    : contract?.Kind == JsonTypeInfoKind.Enumerable ? type?.GenericTypeArguments.FirstOrDefault() : null;
                int index = 0;
                foreach (JsonElement item in value.EnumerateArray())
                {
                    string itemPath = path + "[" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + "]";
                    if (item.ValueKind == JsonValueKind.Null)
                    {
                        Add(diagnostics, "input.null-entry", itemPath, "A collection entry cannot be null.");
                    }
                    else
                    {
                        InspectValue(item, itemType, itemPath, diagnostics, allowExtensions);
                    }

                    index++;
                    if (diagnostics.Count >= MaxDiagnostics)
                    {
                        break;
                    }
                }

                return;
            }

            if (value.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty member in value.EnumerateObject())
            {
                string memberPath = path + "." + member.Name;
                if (!names.Add(member.Name))
                {
                    Add(diagnostics, "input.duplicate-field", memberPath, "Duplicate JSON field; the reader would otherwise keep only one value.");
                }

                JsonPropertyInfo? property = contract?.Properties.FirstOrDefault(candidate => string.Equals(candidate.Name, member.Name, StringComparison.OrdinalIgnoreCase));
                Type? memberType = property?.PropertyType;
                bool viewField = type == typeof(TmForgeJsonFlow) && (member.Name == "sourceHandle" || member.Name == "targetHandle" || member.Name == "labelOffset");
                if (contract?.Kind == JsonTypeInfoKind.Object && property == null && !viewField)
                {
                    string hint = member.Name == "properties" && contract.Properties.Any(candidate => candidate.Name == "props")
                        ? " Use 'props' for manifest properties."
                        : " Expected fields: " + string.Join(", ", contract.Properties.Select(candidate => candidate.Name)) + ".";
                    Add(diagnostics, "input.unknown-field", memberPath, "Unknown field '" + member.Name + "' is not represented by the engine and may be lost on conversion." + hint, allowExtensions ? "warning" : "error");
                }

                if (contract?.Kind == JsonTypeInfoKind.Dictionary)
                {
                    memberType = type?.GenericTypeArguments.LastOrDefault();
                }

                InspectValue(member.Value, memberType, memberPath, diagnostics, allowExtensions);
                if (diagnostics.Count >= MaxDiagnostics)
                {
                    break;
                }
            }
        }
    }
}
