namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Text;
    using System.Text.Json;
    using System.Xml;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Formats;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Inspects source documents and conversion fidelity without writing files or evaluating rules.</summary>
    public static class DocumentPreflight
    {
        /// <summary>Checks raw input and, optionally, the losses expected when converting it.</summary>
        /// <param name="content">The source bytes.</param>
        /// <param name="formatId">An explicit input format, including tmforge-manifest, or null to detect.</param>
        /// <param name="targetFormat">An optional conversion target.</param>
        /// <returns>The input and conversion diagnostics; no model is returned or mutated.</returns>
        public static PreflightResultDto Inspect(byte[] content, string? formatId = null, string? targetFormat = null)
        {
            _ = content ?? throw new ArgumentNullException(nameof(content));
            List<DocumentDiagnostic> diagnostics = new List<DocumentDiagnostic>();
            string? source = string.IsNullOrWhiteSpace(formatId) ? null : formatId;
            string? target = string.IsNullOrWhiteSpace(targetFormat) ? null : targetFormat;
            try
            {
                if (content.Length > JsonDocumentPreflight.MaxBytes)
                {
                    JsonDocumentPreflight.Add(diagnostics, "input.too-large", "$", "Preflight input exceeds the 8 MiB limit.");
                    return Result(source, target, diagnostics);
                }

                ThreatModelFormatRegistry registry = ThreatModelFormatRegistry.CreateDefault();
                using MemoryStream stream = new MemoryStream(content, writable: false);
                string? json = null;
                if (LooksJson(content) || source == Manifest.SchemaName || source == TmForgeJsonFormat.FormatId)
                {
                    json = JsonDocumentPreflight.ReadText(stream);
                    stream.Position = 0;
                    if (source == null)
                    {
                        using JsonDocument probe = JsonDocument.Parse(json);
                        if (Find(probe.RootElement, "schema", out JsonElement schema) && schema.ValueKind == JsonValueKind.String)
                        {
                            source = schema.GetString();
                        }
                        else if (Find(probe.RootElement, "elements", out _) || Find(probe.RootElement, "flows", out _))
                        {
                            JsonDocumentPreflight.Add(diagnostics, "input.ambiguous-json", "$", "JSON without a schema is ambiguous. Specify --format tmforge-manifest for a legacy manifest, or declare the intended schema.");
                            return Result(source, target, diagnostics);
                        }
                    }
                }

                source ??= registry.Sniff(stream)?.Id;
                if (source == null)
                {
                    JsonDocumentPreflight.Add(diagnostics, "input.unknown-format", "$", "The document does not match a supported model format. Specify the input format or check its contents.");
                    return Result(source, target, diagnostics);
                }

                ThreatModel model;
                if (source == Manifest.SchemaName)
                {
                    json ??= JsonDocumentPreflight.ReadText(stream);
                    diagnostics.AddRange(JsonDocumentPreflight.Inspect<Manifest>(json));
                    if (HasErrors(diagnostics))
                    {
                        return Result(source, target, diagnostics);
                    }

                    if (!ManifestSupport.TryRead(json, out Manifest? manifest, out string? error))
                    {
                        JsonDocumentPreflight.Add(diagnostics, "manifest.invalid", "$", error ?? "The manifest cannot be read.");
                        return Result(source, target, diagnostics);
                    }

                    if (!ManifestSupport.Build(manifest, false, out model, out _, out error))
                    {
                        JsonDocumentPreflight.Add(diagnostics, "manifest.invalid", "$", error ?? "The manifest cannot be built.");
                        return Result(source, target, diagnostics);
                    }
                }
                else
                {
                    IThreatModelFormat? format = registry.FindById(source);
                    if (format == null || !format.Capabilities.CanRead)
                    {
                        JsonDocumentPreflight.Add(diagnostics, "input.unsupported-format", "$", "No readable format is registered for '" + source + "'.");
                        return Result(source, target, diagnostics);
                    }

                    source = format.Id;
                    if (source == TmForgeJsonFormat.FormatId)
                    {
                        json ??= JsonDocumentPreflight.ReadText(stream);
                        stream.Position = 0;
                        diagnostics.AddRange(JsonModelPreflight.Inspect(json));
                        if (HasErrors(diagnostics))
                        {
                            return Result(source, target, diagnostics);
                        }
                    }

                    model = format switch
                    {
                        DrawIoFormat drawIo => drawIo.Read(stream, diagnostics),
                        VisioFormat visio => visio.Read(stream, diagnostics),
                        _ => format.Read(stream),
                    };
                    if (source == ThreatDragonFormat.FormatId || source == DrawIoFormat.FormatId || source == VisioFormat.FormatId
                        || source == MermaidFormat.FormatId || source == GraphvizDotFormat.FormatId)
                    {
                        JsonDocumentPreflight.Add(diagnostics, "import.structural-mapping", "$", format.Capabilities.FidelityNote, "warning");
                    }
                }

                InspectModel(model, diagnostics);
                if (target != null)
                {
                    IThreatModelFormat? destination = registry.FindById(target);
                    if (destination == null || !destination.Capabilities.CanWrite)
                    {
                        JsonDocumentPreflight.Add(diagnostics, "conversion.unsupported-target", "$", "Format '" + target + "' is not a writable model format.");
                    }
                    else
                    {
                        target = destination.Id;
                        InspectConversion(model, source, target, diagnostics, json);
                    }
                }
            }
            catch (Exception error) when (error is JsonException || error is XmlException || error is SerializationException
                || error is InvalidDataException || error is NotSupportedException || error is DecoderFallbackException || error is FormatException)
            {
                JsonDocumentPreflight.Add(diagnostics, "input.unreadable", error is JsonException jsonError ? jsonError.Path ?? "$" : "$", error.Message);
            }

            return Result(source, target, diagnostics);
        }

        /// <summary>Checks a loaded model for ambiguous identities and unattached connectors.</summary>
        /// <param name="model">The loaded graph.</param>
        /// <param name="diagnostics">The destination diagnostic collection.</param>
        public static void InspectModel(ThreatModel model, List<DocumentDiagnostic> diagnostics)
        {
            HashSet<Guid> ids = new HashSet<Guid>();
            int pageIndex = 0;
            foreach (DrawingSurfaceModel page in model.DrawingSurfaceList)
            {
                string path = "$.diagrams[" + pageIndex.ToString(System.Globalization.CultureInfo.InvariantCulture) + "]";
                if (page.Guid == Guid.Empty || !ids.Add(page.Guid))
                {
                    JsonDocumentPreflight.Add(diagnostics, "model.duplicate-id", path + ".id", "The page has an empty or duplicate identity.");
                }

                foreach (Entity element in page.Borders.Values.Concat(page.Lines.Values).OfType<Entity>())
                {
                    if (element.Guid == Guid.Empty || !ids.Add(element.Guid))
                    {
                        JsonDocumentPreflight.Add(diagnostics, "model.duplicate-id", path, "Empty or duplicate object id '" + element.Guid + "'.");
                    }
                }

                foreach (Connector flow in page.Lines.Values.OfType<Connector>())
                {
                    if (!page.Borders.ContainsKey(flow.SourceGuid) || !page.Borders.ContainsKey(flow.TargetGuid))
                    {
                        JsonDocumentPreflight.Add(diagnostics, "model.unresolved-endpoint", path + ".flows", "Flow '" + DiagramElementHelper.GetName(flow) + "' (" + flow.Guid + ") has an unattached or cross-page endpoint.");
                    }
                }

                pageIndex++;
                if (diagnostics.Count >= JsonDocumentPreflight.MaxDiagnostics)
                {
                    break;
                }
            }
        }

        private static PreflightResultDto Result(string? source, string? target, List<DocumentDiagnostic> diagnostics)
            => new PreflightResultDto { Format = source, TargetFormat = target, Diagnostics = diagnostics };

        private static bool HasErrors(IEnumerable<DocumentDiagnostic> diagnostics)
            => diagnostics.Any(diagnostic => diagnostic.Severity == "error");

        private static void InspectConversion(ThreatModel model, string source, string target, List<DocumentDiagnostic> diagnostics, string? json)
        {
            List<Entity> elements = model.DrawingSurfaceList.SelectMany(page => page.Borders.Values.Concat(page.Lines.Values)).OfType<Entity>().ToList();
            if (target == TmForgeJsonFormat.FormatId)
            {
                int boundaries = elements.OfType<LineBoundary>().Count();
                if (boundaries > 0)
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.line-boundaries", "$.diagrams", boundaries + " line trust boundaries are not represented in canonical JSON. Keep the source model; importing it into Studio would omit these boundaries.", "warning");
                }

                if (model.KnowledgeBase != null)
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.knowledge-base", "$.knowledgeBase", "The embedded knowledge base is not carried in canonical JSON. Rules and catalogs must be supplied separately.", "warning");
                }

                if (model.AllThreatsDictionary.Keys.Any(key => !ManualThreatId.IsManual(key)))
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.generated-register", "$.threats", "Canonical JSON retains author-owned threat edits, not the complete generated register. Generated threats are reconstructed from the effective tmforge rules.", "warning");
                }
            }
            else if (target == DrawIoFormat.FormatId || target == VisioFormat.FormatId)
            {
                if (model.AllThreatsDictionary.Count > 0)
                {
                    string message = target == DrawIoFormat.FormatId
                        ? "The threat register and triage are not written to draw.io."
                        : "Threats are written as Visio Shape Data, not a reconstructable threat register or triage history.";
                    JsonDocumentPreflight.Add(diagnostics, "conversion.threat-register", "$.threats", message, "warning");
                }

                if (target == DrawIoFormat.FormatId && elements.Any(element => DiagramElementHelper.GetCustomProperties(element).Count > 0))
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.properties", "$.elements", "Custom security properties are not written to draw.io; reimporting cannot reproduce the same analysis.", "warning");
                }

                JsonDocumentPreflight.Add(diagnostics, "conversion.identity", "$.diagrams", "The " + target + " reader does not preserve all original object identities; a return conversion may change finding and threat keys.", "warning");
                if (model.KnowledgeBase != null || model.MetaInformation != null)
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.metadata", "$.metadata", "The embedded knowledge base and full model metadata are not reconstructed from this diagram format.", "warning");
                }
            }

            if (source == TmForgeJsonFormat.FormatId && json != null)
            {
                using JsonDocument raw = JsonDocument.Parse(json);
                if (Find(raw.RootElement, "analysis", out _))
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.analysis-settings", "$.analysis", "A format conversion does not carry all workspace rule selections and expected pack fingerprints. Keep the canonical source and its rule configuration.", "warning");
                }
            }

            if (target == Tm7Format.FormatId)
            {
                bool outsideCanvas = model.DrawingSurfaceList.Any(page =>
                    page.Borders.Values.OfType<DrawingElement>().Any(element => element.Left < 10 || element.Top < 10 || element.Left > 1890 || element.Top > 2090)
                    || page.Lines.Values.OfType<LineElement>().Any(line => line.SourceX < 10 || line.TargetX < 10 || line.HandleX < 10
                        || line.SourceY < 10 || line.TargetY < 10 || line.HandleY < 10 || line.SourceX > 1990 || line.TargetX > 1990
                        || line.HandleX > 1990 || line.SourceY > 2190 || line.TargetY > 2190 || line.HandleY > 2190));
                if (outsideCanvas)
                {
                    JsonDocumentPreflight.Add(diagnostics, "conversion.coordinates", "$.diagrams", "TM7 export translates drawing surfaces into MTMT's coordinate range where possible. Oversized surfaces may still need correction in MTMT; geometry is never rescaled.", "warning");
                }
            }
        }

        private static bool LooksJson(byte[] content)
        {
            int index = content.Length >= 3 && content[0] == 0xef && content[1] == 0xbb && content[2] == 0xbf ? 3 : 0;
            while (index < content.Length && (content[index] == 32 || content[index] == 9 || content[index] == 10 || content[index] == 13))
            {
                index++;
            }

            return index < content.Length && (content[index] == (byte)'{' || content[index] == (byte)'[');
        }

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
