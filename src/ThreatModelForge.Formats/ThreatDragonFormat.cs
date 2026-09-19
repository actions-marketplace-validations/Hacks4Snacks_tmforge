namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using ThreatModelForge.Editing;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Imports OWASP Threat Dragon v2 JSON without executing foreign analysis rules.</summary>
    public sealed class ThreatDragonFormat : IThreatModelFormat
    {
        /// <summary>The stable identifier for the import-only provider.</summary>
        public const string FormatId = "threat-dragon";

        private const int MaxDocumentBytes = 8 * 1024 * 1024;
        private const int MaxDiagrams = 128;
        private const int MaxCells = 10000;
        private const int MaxThreats = 20000;

        private static readonly FormatCapabilities ImportCapabilities = new FormatCapabilities(
            canRead: true,
            canWrite: false,
            roundTrips: false,
            fidelityNote: "Import-only Threat Dragon v2: pages, integer rectangles, directed flows, source properties and authored threats. Curved boundaries, bidirectional flows and unmappable threat states are refused. Styling and flow routing are not retained; out-of-scope flags do not suppress tmforge analysis. Native export is not supported.");

        /// <inheritdoc/>
        public string Id => FormatId;

        /// <inheritdoc/>
        public string DisplayName => "OWASP Threat Dragon v2 (.json)";

        /// <inheritdoc/>
        public IReadOnlyList<string> Extensions => Array.Empty<string>();

        /// <inheritdoc/>
        public FormatCapabilities Capabilities => ImportCapabilities;

        /// <inheritdoc/>
        public bool CanRead(Stream stream)
        {
            _ = stream ?? throw new ArgumentNullException(nameof(stream));
            if (!stream.CanSeek)
            {
                throw new NotSupportedException("Content sniffing requires a seekable stream.");
            }

            long position = stream.Position;
            try
            {
                using JsonDocument document = ReadDocument(stream);
                return HasEnvelope(document.RootElement);
            }
            catch (JsonException)
            {
                return false;
            }
            catch (InvalidDataException)
            {
                return false;
            }
            catch (DecoderFallbackException)
            {
                return false;
            }
            finally
            {
                stream.Position = position;
            }
        }

        /// <inheritdoc/>
        public ThreatModel Read(Stream stream)
        {
            _ = stream ?? throw new ArgumentNullException(nameof(stream));
            using JsonDocument document = ReadDocument(stream);
            JsonElement root = document.RootElement;
            if (!HasEnvelope(root))
            {
                throw new InvalidDataException("Not an OWASP Threat Dragon document: expected summary and detail.diagrams.");
            }

            ValidateVersion(root);
            ValidateMembers(root);
            JsonElement summary = Object(root, "summary");
            JsonElement detail = Object(root, "detail");
            JsonElement diagrams = root.GetProperty("detail").GetProperty("diagrams");
            if (diagrams.GetArrayLength() > MaxDiagrams)
            {
                throw new InvalidDataException($"Threat Dragon import is limited to {MaxDiagrams} diagrams.");
            }

            ThreatModel model = new ThreatModel
            {
                Version = "1.0",
                MetaInformation = new MetaInformation
                {
                    ThreatModelName = Text(summary, "title", required: true),
                    Owner = Text(summary, "owner"),
                    HighLevelSystemDescription = Text(summary, "description"),
                    Reviewer = Text(detail, "reviewer"),
                    Contributors = detail.TryGetProperty("contributors", out _)
                        ? string.Join(", ", ArrayMember(detail, "contributors").EnumerateArray().Select(contributor => Text(contributor, "name", required: true)))
                        : null,
                },
            };
            DiagramEditor editor = new DiagramEditor(model);
            HashSet<string> pageIds = new HashSet<string>(StringComparer.Ordinal);
            HashSet<Guid> objectIds = new HashSet<Guid>();
            int cellCount = 0;
            foreach (JsonElement diagram in diagrams.EnumerateArray())
            {
                string pageId = Identifier(diagram, "id");
                if (!pageIds.Add(pageId))
                {
                    throw new InvalidDataException($"Duplicate Threat Dragon diagram id '{pageId}'.");
                }

                if (diagram.TryGetProperty("version", out _))
                {
                    ValidateVersion(diagram);
                }

                DrawingSurfaceModel surface = new DrawingSurfaceModel
                {
                    Guid = DeterministicGuid.FromPageId("threat-dragon:" + pageId),
                    Header = Text(diagram, "title", required: true),
                };
                if (!objectIds.Add(surface.Guid))
                {
                    throw new InvalidDataException($"Threat Dragon diagram '{pageId}' collides with an existing object identity.");
                }

                model.DrawingSurfaceList.Add(surface);
                JsonElement cells = ArrayMember(diagram, "cells");
                cellCount += cells.GetArrayLength();
                if (cellCount > MaxCells)
                {
                    throw new InvalidDataException($"Threat Dragon import is limited to {MaxCells} cells.");
                }

                ReadCells(model, editor, surface, pageId, Text(diagram, "diagramType"), cells, objectIds);
            }

            string sourceVersion = Text(root, "version", required: true);
            foreach (Threat threat in model.AllThreatsDictionary.Values)
            {
                threat.Properties!["Source.version"] = sourceVersion;
            }

            return model;
        }

        /// <inheritdoc/>
        public void Write(ThreatModel model, Stream stream)
        {
            throw new NotSupportedException("Threat Dragon is import-only. Save as tmforge-json or tm7 instead.");
        }

        private static void ReadCells(
            ThreatModel model,
            DiagramEditor editor,
            DrawingSurfaceModel surface,
            string pageId,
            string methodology,
            JsonElement cells,
            HashSet<Guid> objectIds)
        {
            Dictionary<string, Guid> ids = new Dictionary<string, Guid>(StringComparer.Ordinal);
            Dictionary<string, string> kinds = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (JsonElement cell in cells.EnumerateArray())
            {
                string sourceId = Identifier(cell, "id");
                Guid id = Guid.TryParse(sourceId, out Guid parsed) && parsed != Guid.Empty
                    ? parsed
                    : DeterministicGuid.FromElementId($"threat-dragon:{pageId.Length}:{pageId}:{sourceId}");
                if (ids.ContainsKey(sourceId) || !objectIds.Add(id))
                {
                    throw new InvalidDataException($"Duplicate Threat Dragon cell id '{sourceId}' on diagram '{pageId}'.");
                }

                ids.Add(sourceId, id);
                JsonElement data = Object(cell, "data");
                string kind = Text(data, "type", required: true);
                kinds.Add(sourceId, kind);
                if (kind == "tm.Flow")
                {
                    if (Boolean(data, "isBidirectional") == true)
                    {
                        throw new NotSupportedException($"Threat Dragon flow '{sourceId}' is bidirectional. Split it into two directed flows before importing.");
                    }

                    continue;
                }

                StencilKind stencil = kind switch
                {
                    "tm.Actor" => StencilKind.ExternalEntity,
                    "tm.Process" => StencilKind.Process,
                    "tm.Store" => StencilKind.DataStore,
                    "tm.BoundaryBox" => StencilKind.TrustBoundary,
                    "tm.Boundary" => throw new NotSupportedException($"Threat Dragon cell '{sourceId}' is a curved trust boundary. Curved boundaries cannot be preserved through Studio; use rectangular boundary boxes before importing."),
                    _ => throw new NotSupportedException($"Threat Dragon cell '{sourceId}' has unsupported type '{kind}'."),
                };
                JsonElement position = Object(cell, "position");
                JsonElement size = Object(cell, "size");
                int left = Coordinate(position, "x", -1000000, 1000000);
                int top = Coordinate(position, "y", -1000000, 1000000);
                int width = Coordinate(size, "width", 1, 100000);
                int height = Coordinate(size, "height", 1, 100000);
                Guid created = editor.AddElement(surface, stencil, left, top);
                Entity entity = (Entity)surface.Borders[created];
                surface.Borders.Remove(created);
                entity.Guid = id;
                surface.Borders.Add(id, entity);
                editor.ResizeElement(surface, id, left, top, width, height);
                editor.SetElementName(surface, id, Text(data, "name"));
                SetProperties(entity, data, sourceId, pageId, methodology, kind);
                ReadThreats(model, surface, entity, cell, sourceId, pageId, methodology);
            }

            foreach (JsonElement cell in cells.EnumerateArray())
            {
                string sourceId = Identifier(cell, "id");
                if (kinds[sourceId] != "tm.Flow")
                {
                    continue;
                }

                JsonElement data = Object(cell, "data");
                Guid source = Endpoint(cell, "source", sourceId, ids, kinds);
                Guid target = Endpoint(cell, "target", sourceId, ids, kinds);
                Guid created = editor.AddConnector(surface, source, target);
                Connector connector = (Connector)surface.Lines[created];
                surface.Lines.Remove(created);
                connector.Guid = ids[sourceId];
                surface.Lines.Add(connector.Guid, connector);
                editor.SetElementName(surface, connector.Guid, Text(data, "name"));
                SetProperties(connector, data, sourceId, pageId, methodology, "tm.Flow");
                ReadThreats(model, surface, connector, cell, sourceId, pageId, methodology);
            }
        }

        private static void SetProperties(Entity entity, JsonElement data, string sourceId, string pageId, string methodology, string kind)
        {
            DiagramElementHelper.SetCustomProperty(entity, "ThreatDragon.Id", sourceId);
            DiagramElementHelper.SetCustomProperty(entity, "ThreatDragon.DiagramId", pageId);
            DiagramElementHelper.SetCustomProperty(entity, "ThreatDragon.ModelType", methodology);
            foreach (JsonProperty property in data.EnumerateObject().Where(property => property.Name != "threats"))
            {
                string value = property.Value.ValueKind == JsonValueKind.String
                    ? property.Value.GetString() ?? string.Empty
                    : property.Value.GetRawText();
                DiagramElementHelper.SetCustomProperty(entity, "ThreatDragon.data." + property.Name, value);
            }

            if (kind == "tm.Store")
            {
                MapBoolean(entity, data, "storesCredentials", "StoresCredentials");
                MapBoolean(entity, data, "isALog", "StoresLogData");
                MapBoolean(entity, data, "isSigned", "Signed");
                MapBoolean(entity, data, "isEncrypted", "Encrypted", "At-rest");
            }
            else if (kind == "tm.Actor")
            {
                MapBoolean(entity, data, "providesAuthentication", "AuthenticatesItself");
            }
            else if (kind == "tm.Flow")
            {
                string protocol = Text(data, "protocol");
                if (!string.IsNullOrWhiteSpace(protocol))
                {
                    DiagramElementHelper.SetCustomProperty(entity, "Protocol", protocol);
                }
            }
        }

        private static void MapBoolean(Entity entity, JsonElement data, string source, string target, string positive = "Yes")
        {
            bool? value = Boolean(data, source);
            if (value.HasValue)
            {
                DiagramElementHelper.SetCustomProperty(entity, target, value.Value ? positive : "No");
            }
        }

        private static void ReadThreats(
            ThreatModel model,
            DrawingSurfaceModel surface,
            Entity entity,
            JsonElement cell,
            string cellId,
            string pageId,
            string methodology)
        {
            JsonElement data = Object(cell, "data");
            bool hasDataThreats = data.TryGetProperty("threats", out _);
            bool hasCellThreats = cell.TryGetProperty("threats", out _);
            if (!hasDataThreats && !hasCellThreats)
            {
                return;
            }

            JsonElement threats = ArrayMember(hasDataThreats ? data : cell, "threats");
            if (hasDataThreats && hasCellThreats)
            {
                JsonElement outerThreats = ArrayMember(cell, "threats");
                if (threats.GetArrayLength() > 0 && outerThreats.GetArrayLength() > 0)
                {
                    throw new InvalidDataException($"Threat Dragon cell '{cellId}' declares threats in both cell.threats and data.threats.");
                }

                if (outerThreats.GetArrayLength() > 0)
                {
                    threats = outerThreats;
                }
            }

            foreach (JsonElement item in threats.EnumerateArray())
            {
                if (model.AllThreatsDictionary.Count >= MaxThreats)
                {
                    throw new InvalidDataException($"Threat Dragon import is limited to {MaxThreats} threats.");
                }

                string sourceId = item.TryGetProperty("id", out _) ? Identifier(item, "id")
                    : item.TryGetProperty("threatId", out _) ? Identifier(item, "threatId")
                    : Identifier(item, "number");
                if (!ManualThreatId.TryCanonicalize("threat-dragon." + sourceId, out string key, out string? error))
                {
                    throw new InvalidDataException("Unsupported Threat Dragon threat id: " + error);
                }

                if (model.AllThreatsDictionary.ContainsKey(key))
                {
                    throw new InvalidDataException($"Duplicate Threat Dragon threat id '{sourceId}'.");
                }

                string status = Text(item, "status", required: true);
                ThreatState state = status switch
                {
                    "Open" => ThreatState.AutoGenerated,
                    "Mitigated" => ThreatState.Mitigated,
                    "Accepted" => ThreatState.NotApplicable,
                    _ => throw new NotSupportedException($"Threat Dragon threat '{sourceId}' has status '{status}', which cannot be represented faithfully. Supported states are Open, Mitigated and Accepted."),
                };
                string priority = Text(item, "severity", required: true);
                if (priority != "Critical" && priority != "High" && priority != "Medium" && priority != "Low")
                {
                    throw new NotSupportedException($"Threat Dragon threat '{sourceId}' has unsupported severity '{priority}'.");
                }

                Connector? flow = entity as Connector;
                string declaredMethodology = Text(item, "modelType");
                model.AllThreatsDictionary.Add(key, new Threat
                {
                    Id = model.AllThreatsDictionary.Count + 1,
                    InteractionKey = key,
                    DrawingSurfaceGuid = surface.Guid,
                    SourceGuid = flow?.SourceGuid ?? entity.Guid,
                    TargetGuid = flow?.TargetGuid ?? Guid.Empty,
                    FlowGuid = flow?.Guid ?? Guid.Empty,
                    Title = Text(item, "title", required: true),
                    UserThreatCategory = Text(item, "type", required: true),
                    UserThreatDescription = Text(item, "description"),
                    State = state,
                    StateInformation = Text(item, "justification"),
                    Priority = priority,
                    Properties = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["Mitigation"] = Text(item, "mitigation"),
                        ["Source.format"] = FormatId,
                        ["Source.id"] = sourceId,
                        ["Source.cellId"] = cellId,
                        ["Source.diagramId"] = pageId,
                        ["Source.modelType"] = declaredMethodology.Length > 0 ? declaredMethodology : methodology,
                        ["Source.status"] = status,
                        ["Source.severity"] = priority,
                        ["Source.score"] = Text(item, "score"),
                    },
                });
            }
        }

        private static Guid Endpoint(JsonElement cell, string name, string flowId, Dictionary<string, Guid> ids, Dictionary<string, string> kinds)
        {
            string reference = Text(Object(cell, name), "cell", required: true);
            if (!ids.TryGetValue(reference, out Guid id)
                || (kinds[reference] != "tm.Actor" && kinds[reference] != "tm.Process" && kinds[reference] != "tm.Store"))
            {
                throw new InvalidDataException($"Threat Dragon flow '{flowId}' has an unresolved or non-component {name} '{reference}'. Endpoints must be on the same diagram.");
            }

            return id;
        }

        private static string Identifier(JsonElement value, string name)
        {
            if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out JsonElement id))
            {
                string? text = id.ValueKind == JsonValueKind.String ? id.GetString()
                    : id.ValueKind == JsonValueKind.Number && id.TryGetInt64(out long number) && number >= 0
                        ? number.ToString(CultureInfo.InvariantCulture) : null;
                if (!string.IsNullOrWhiteSpace(text) && text!.Length <= 256)
                {
                    return text;
                }
            }

            throw new InvalidDataException($"Threat Dragon '{name}' must be a nonempty identifier of at most 256 characters.");
        }

        private static string Text(JsonElement value, string name, bool required = false)
        {
            if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out JsonElement property))
            {
                if (property.ValueKind == JsonValueKind.String)
                {
                    string text = property.GetString() ?? string.Empty;
                    if (text.Length <= 65536 && (!required || !string.IsNullOrWhiteSpace(text)))
                    {
                        return text;
                    }
                }

                throw new InvalidDataException($"Threat Dragon '{name}' must be a string of at most 65536 characters.");
            }

            if (required)
            {
                throw new InvalidDataException($"Threat Dragon is missing required field '{name}'.");
            }

            return string.Empty;
        }

        private static JsonElement Object(JsonElement value, string name) => Member(value, name, JsonValueKind.Object);

        private static JsonElement ArrayMember(JsonElement value, string name) => Member(value, name, JsonValueKind.Array);

        private static JsonElement Member(JsonElement value, string name, JsonValueKind kind)
        {
            if (value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out JsonElement member) && member.ValueKind == kind)
            {
                return member;
            }

            throw new InvalidDataException($"Threat Dragon '{name}' must be a JSON {kind}.");
        }

        private static bool? Boolean(JsonElement value, string name)
        {
            if (!value.TryGetProperty(name, out JsonElement property))
            {
                return null;
            }

            return property.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => throw new InvalidDataException($"Threat Dragon '{name}' must be a boolean."),
            };
        }

        private static int Coordinate(JsonElement value, string name, int minimum, int maximum)
        {
            if (value.TryGetProperty(name, out JsonElement property)
                && property.ValueKind == JsonValueKind.Number
                && property.TryGetDecimal(out decimal number)
                && number >= minimum && number <= maximum && decimal.Truncate(number) == number)
            {
                return (int)number;
            }

            throw new InvalidDataException($"Threat Dragon '{name}' must be an integer between {minimum} and {maximum}; import does not round trust-boundary geometry.");
        }

        private static void ValidateVersion(JsonElement value)
        {
            if (!Version.TryParse(Text(value, "version", required: true), out Version? parsed) || parsed.Major != 2)
            {
                throw new NotSupportedException("Only OWASP Threat Dragon v2 JSON is supported. Convert older models with Threat Dragon first.");
            }
        }

        private static void ValidateMembers(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (JsonProperty member in value.EnumerateObject())
                {
                    if (!names.Add(member.Name))
                    {
                        throw new InvalidDataException($"Duplicate Threat Dragon JSON member '{member.Name}'.");
                    }

                    ValidateMembers(member.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement child in value.EnumerateArray())
                {
                    ValidateMembers(child);
                }
            }
        }

        private static bool HasEnvelope(JsonElement root)
        {
            return root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("summary", out JsonElement summary)
                && summary.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("detail", out JsonElement detail)
                && detail.ValueKind == JsonValueKind.Object
                && detail.TryGetProperty("diagrams", out JsonElement diagrams)
                && diagrams.ValueKind == JsonValueKind.Array;
        }

        private static JsonDocument ReadDocument(Stream stream)
        {
            using MemoryStream content = new MemoryStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = stream.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (content.Length + count > MaxDocumentBytes)
                {
                    throw new InvalidDataException("Threat Dragon JSON exceeds the 8 MiB import limit.");
                }

                content.Write(buffer, 0, count);
            }

            string json = new UTF8Encoding(false, true).GetString(content.ToArray());
            if (json.Length > 0 && json[0] == '\uFEFF')
            {
                json = json.Substring(1);
            }

            return JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 64 });
        }
    }
}
