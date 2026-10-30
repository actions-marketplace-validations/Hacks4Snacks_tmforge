namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using ThreatModelForge.Editing;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Reads and writes a bounded OWASP Threat Dragon v2 subset without executing foreign rules.</summary>
    public sealed class ThreatDragonFormat : IThreatModelFormat
    {
        /// <summary>The stable format identifier.</summary>
        public const string FormatId = "threat-dragon";

        private const int MaxDocumentBytes = 8 * 1024 * 1024;
        private const int MaxDiagrams = 128;
        private const int MaxCells = 10000;
        private const int MaxThreats = 20000;

        private static readonly FormatCapabilities DragonCapabilities = new FormatCapabilities(
            canRead: true,
            canWrite: true,
            roundTrips: false,
            fidelityNote: "Bounded Threat Dragon v2: pages, integer rectangles, directed flows, supported source properties and authored threats. Unsupported geometry, properties and threat states are refused on export. Imported identities are retained. Styling and flow routing are not retained; out-of-scope flags do not suppress tmforge analysis.");

        /// <inheritdoc/>
        public string Id => FormatId;

        /// <inheritdoc/>
        public string DisplayName => "OWASP Threat Dragon v2 (.json)";

        /// <inheritdoc/>
        public IReadOnlyList<string> Extensions { get; } = new[] { ".threatdragon.json" };

        /// <inheritdoc/>
        public FormatCapabilities Capabilities => DragonCapabilities;

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
                DiagramElementHelper.SetCustomProperty(surface, "Source.format", FormatId);
                DiagramElementHelper.SetCustomProperty(surface, "Source.id", pageId);
                DiagramElementHelper.SetCustomProperty(surface, "Source.modelType", Text(diagram, "diagramType"));
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
            _ = model ?? throw new ArgumentNullException(nameof(model));
            _ = stream ?? throw new ArgumentNullException(nameof(stream));
            RefuseField(model.MetaInformation?.Assumptions, "metadata.Assumptions");
            RefuseField(model.MetaInformation?.ExternalDependencies, "metadata.ExternalDependencies");
            if (model.Notes.Count > 0 || model.Validations.Count > 0 || model.KnowledgeBase != null || model.ThreatGenerationEnabled.HasValue)
            {
                throw new NotSupportedException("Threat Dragon export cannot preserve model notes, validations, embedded knowledge bases or native threat-generation settings.");
            }

            if (model.DrawingSurfaceList.Count > MaxDiagrams || model.AllThreatsDictionary.Count > MaxThreats
                || model.DrawingSurfaceList.Sum(page => (long)page.Borders.Count + page.Lines.Count) > MaxCells)
            {
                throw new NotSupportedException($"Threat Dragon export is limited to {MaxDiagrams} diagrams, {MaxCells} cells and {MaxThreats} threats.");
            }

            HashSet<Guid> objectIds = new HashSet<Guid>();
            foreach (DrawingSurfaceModel page in model.DrawingSurfaceList)
            {
                foreach (Entity entity in new Entity[] { page }.Concat(page.Borders.Values.Concat(page.Lines.Values).OfType<Entity>()))
                {
                    if (entity.Guid == Guid.Empty || !objectIds.Add(entity.Guid))
                    {
                        throw new NotSupportedException($"Threat Dragon export requires unique nonempty object identities; found '{entity.Guid}'.");
                    }
                }
            }

            JsonArray diagrams = new JsonArray();
            Dictionary<Guid, long> pageIds = ExportPageIds(model);
            Dictionary<string, long> threatNumbers = ExportThreatNumbers(model);
            HashSet<string> writtenThreats = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ILookup<Guid, KeyValuePair<string, Threat>> scopedThreats = model.AllThreatsDictionary
                .OrderBy(entry => entry.Key, StringComparer.Ordinal)
                .ToLookup(entry => entry.Value.FlowGuid != Guid.Empty ? entry.Value.FlowGuid : entry.Value.SourceGuid);
            foreach (DrawingSurfaceModel page in model.DrawingSurfaceList)
            {
                diagrams.Add(WriteDiagram(page, pageIds[page.Guid], scopedThreats, threatNumbers, writtenThreats));
            }

            if (writtenThreats.Count != model.AllThreatsDictionary.Count)
            {
                string missing = model.AllThreatsDictionary.Keys.First(key => !writtenThreats.Contains(key));
                throw new NotSupportedException($"Threat Dragon export cannot represent threat '{missing}': it must be scoped to one supported cell on an existing diagram.");
            }

            JsonArray contributors = new JsonArray();
            if (!string.IsNullOrEmpty(model.MetaInformation?.Contributors))
            {
                contributors.Add(new JsonObject { ["name"] = model.MetaInformation!.Contributors });
            }

            JsonObject document = new JsonObject
            {
                ["version"] = "2.6.2",
                ["summary"] = new JsonObject
                {
                    ["title"] = string.IsNullOrWhiteSpace(model.MetaInformation?.ThreatModelName) ? "Threat model" : model.MetaInformation!.ThreatModelName,
                    ["owner"] = model.MetaInformation?.Owner ?? string.Empty,
                    ["description"] = model.MetaInformation?.HighLevelSystemDescription ?? string.Empty,
                },
                ["detail"] = new JsonObject
                {
                    ["reviewer"] = model.MetaInformation?.Reviewer ?? string.Empty,
                    ["contributors"] = contributors,
                    ["diagrams"] = diagrams,
                    ["diagramTop"] = pageIds.Count == 0 ? 0 : pageIds.Values.Max() + 1,
                    ["threatTop"] = threatNumbers.Count == 0 ? 0 : threatNumbers.Values.Max(),
                },
            };
            byte[] bytes = Encoding.UTF8.GetBytes(document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            using MemoryStream candidate = new MemoryStream(bytes, writable: false);
            this.Read(candidate);
            stream.Write(bytes, 0, bytes.Length);
        }

        private static JsonObject WriteDiagram(
            DrawingSurfaceModel page,
            long diagramId,
            ILookup<Guid, KeyValuePair<string, Threat>> scopedThreats,
            IReadOnlyDictionary<string, long> threatNumbers,
            HashSet<string> writtenThreats)
        {
            List<Entity> entities = page.Borders.Values.Concat(page.Lines.Values).OfType<Entity>().ToList();
            if (entities.Count != page.Borders.Count + page.Lines.Count)
            {
                throw new NotSupportedException($"Threat Dragon diagram '{page.Header}' contains an unsupported object.");
            }

            string pageId = diagramId.ToString(CultureInfo.InvariantCulture);
            string methodology = ExportProperty(page, "Source.modelType");
            if (methodology.Length == 0)
            {
                methodology = entities.Select(entity => ExportProperty(entity, "ThreatDragon.ModelType"))
                    .FirstOrDefault(value => value.Length > 0) ?? "STRIDE";
            }

            Dictionary<Guid, string> ids = entities.ToDictionary(entity => entity.Guid, entity => ExportCellId(entity, pageId));
            JsonArray cells = new JsonArray();
            foreach (Entity entity in entities.OrderBy(entity => entity is BorderBoundary ? 0 : entity is Connector ? 2 : 1).ThenBy(entity => entity.Guid))
            {
                string kind = entity switch
                {
                    BorderBoundary => "tm.BoundaryBox",
                    StencilEllipse => "tm.Process",
                    StencilParallelLines => "tm.Store",
                    StencilRectangle => "tm.Actor",
                    Connector => "tm.Flow",
                    _ => throw new NotSupportedException($"Threat Dragon cell '{entity.Guid}' has unsupported type '{entity.GetType().Name}'."),
                };
                string shape = kind switch
                {
                    "tm.BoundaryBox" => "trust-boundary-box",
                    "tm.Process" => "process",
                    "tm.Store" => "store",
                    "tm.Actor" => "actor",
                    _ => "flow",
                };
                string genericType = kind switch
                {
                    "tm.BoundaryBox" => "GE.TB.B",
                    "tm.Process" => "GE.P",
                    "tm.Store" => "GE.DS",
                    "tm.Actor" => "GE.EI",
                    _ => "GE.DF",
                };
                if ((!string.IsNullOrEmpty(entity.TypeId) && entity.TypeId != genericType)
                    || (!string.IsNullOrEmpty(entity.GenericTypeId) && entity.GenericTypeId != genericType))
                {
                    throw new NotSupportedException($"Threat Dragon cell '{entity.Guid}' has unsupported stencil '{entity.TypeId}' / '{entity.GenericTypeId}'.");
                }

                string name = DiagramElementHelper.GetName(entity);
                JsonObject data = WriteData(entity, kind, name);
                JsonArray threats = new JsonArray();
                foreach (KeyValuePair<string, Threat> entry in scopedThreats[entity.Guid])
                {
                    Threat threat = entry.Value;
                    if (threat.Wide)
                    {
                        throw new NotSupportedException($"Threat Dragon export cannot preserve model-wide threat '{entry.Key}'.");
                    }

                    bool invalidTargetReference = entity is Connector connector
                        ? threat.SourceGuid != connector.SourceGuid || threat.TargetGuid != connector.TargetGuid
                        : threat.TargetGuid != Guid.Empty;
                    if (invalidTargetReference)
                    {
                        throw new NotSupportedException($"Threat Dragon threat '{entry.Key}' references multiple or inconsistent target cells.");
                    }

                    if (threat.DrawingSurfaceGuid != Guid.Empty && threat.DrawingSurfaceGuid != page.Guid)
                    {
                        throw new NotSupportedException($"Threat Dragon threat '{entry.Key}' references a different diagram from its cell.");
                    }

                    threats.Add(WriteThreat(entry.Key, threat, methodology, threatNumbers[entry.Key]));
                    writtenThreats.Add(entry.Key);
                }

                data["threats"] = threats;
                data["hasOpenThreats"] = threats.Any(threat => (string?)threat?["status"] == "Open");
                JsonObject cell = new JsonObject { ["id"] = ids[entity.Guid], ["shape"] = shape, ["data"] = data, ["zIndex"] = kind == "tm.BoundaryBox" ? 0 : 1 };
                if (entity is DrawingElement rectangle)
                {
                    if (rectangle.Width < 10 || rectangle.Height < 10)
                    {
                        throw new NotSupportedException($"Threat Dragon cell '{entity.Guid}' dimensions must be at least 10 to satisfy the v2 schema.");
                    }

                    cell["position"] = new JsonObject { ["x"] = rectangle.Left, ["y"] = rectangle.Top };
                    cell["size"] = new JsonObject { ["width"] = rectangle.Width, ["height"] = rectangle.Height };
                    cell["attrs"] = new JsonObject { ["text"] = new JsonObject { ["text"] = name } };
                }
                else if (entity is Connector flow)
                {
                    if (!flow.HandleIsAtMidpoint || flow.PortSource != "None" || flow.PortTarget != "None")
                    {
                        throw new NotSupportedException($"Threat Dragon flow '{entity.Guid}' has authored routing or ports outside the supported export subset.");
                    }

                    if (!page.Borders.ContainsKey(flow.SourceGuid) || !page.Borders.ContainsKey(flow.TargetGuid))
                    {
                        throw new NotSupportedException($"Threat Dragon flow '{entity.Guid}' has an unattached or cross-page endpoint.");
                    }

                    cell["source"] = new JsonObject { ["cell"] = ids[flow.SourceGuid] };
                    cell["target"] = new JsonObject { ["cell"] = ids[flow.TargetGuid] };
                    cell["labels"] = new JsonArray(new JsonObject
                    {
                        ["position"] = 0.5,
                        ["attrs"] = new JsonObject { ["label"] = new JsonObject { ["text"] = name } },
                    });
                }

                cells.Add(cell);
            }

            return new JsonObject { ["id"] = diagramId, ["title"] = page.Header, ["diagramType"] = methodology, ["thumbnail"] = string.Empty, ["version"] = "2.0", ["cells"] = cells };
        }

        private static Dictionary<Guid, long> ExportPageIds(ThreatModel model)
        {
            Dictionary<Guid, long> ids = new Dictionary<Guid, long>();
            HashSet<long> used = new HashSet<long>();
            foreach (DrawingSurfaceModel page in model.DrawingSurfaceList)
            {
                string sourceId = ExportProperty(page, "Source.id");
                if (sourceId.Length == 0)
                {
                    sourceId = page.Borders.Values.Concat(page.Lines.Values).OfType<Entity>()
                        .Select(entity => ExportProperty(entity, "ThreatDragon.DiagramId"))
                        .FirstOrDefault(id => id.Length > 0 && DeterministicGuid.FromPageId("threat-dragon:" + id) == page.Guid) ?? string.Empty;
                }

                if (sourceId.Length == 0)
                {
                    continue;
                }

                if (!long.TryParse(sourceId, NumberStyles.None, CultureInfo.InvariantCulture, out long number)
                    || number > 9007199254740990 || number.ToString(CultureInfo.InvariantCulture) != sourceId
                    || DeterministicGuid.FromPageId("threat-dragon:" + sourceId) != page.Guid || !used.Add(number))
                {
                    throw new NotSupportedException($"Threat Dragon diagram '{page.Header}' source id '{sourceId}' must be a unique nonnegative safe integer matching its imported identity.");
                }

                ids.Add(page.Guid, number);
            }

            long next = 0;
            foreach (DrawingSurfaceModel page in model.DrawingSurfaceList.Where(page => !ids.ContainsKey(page.Guid)))
            {
                while (used.Contains(next))
                {
                    next++;
                }

                ids.Add(page.Guid, next);
                used.Add(next++);
            }

            return ids;
        }

        private static Dictionary<string, long> ExportThreatNumbers(ThreatModel model)
        {
            Dictionary<string, long> numbers = new Dictionary<string, long>(StringComparer.Ordinal);
            HashSet<long> used = new HashSet<long>();
            foreach (KeyValuePair<string, Threat> entry in model.AllThreatsDictionary)
            {
                if (entry.Value.Properties == null || !entry.Value.Properties.TryGetValue("Source.number", out string? source))
                {
                    continue;
                }

                if (!long.TryParse(source, NumberStyles.None, CultureInfo.InvariantCulture, out long number)
                    || number > 9007199254740990 || number.ToString(CultureInfo.InvariantCulture) != source || !used.Add(number))
                {
                    throw new NotSupportedException($"Threat Dragon threat '{entry.Key}' source number '{source}' must be a unique nonnegative safe integer.");
                }

                numbers.Add(entry.Key, number);
            }

            long next = 1;
            foreach (string key in model.AllThreatsDictionary.Keys.OrderBy(key => key, StringComparer.Ordinal).Where(key => !numbers.ContainsKey(key)))
            {
                while (used.Contains(next))
                {
                    next++;
                }

                numbers.Add(key, next);
                used.Add(next++);
            }

            return numbers;
        }

        private static JsonObject WriteData(Entity entity, string kind, string name)
        {
            JsonObject data = new JsonObject();
            IReadOnlyDictionary<string, string> properties = DiagramElementHelper.GetCustomProperties(entity);
            foreach (string key in properties.Keys)
            {
                bool mapped = kind switch
                {
                    "tm.Store" => key is "StoresCredentials" or "StoresLogData" or "Signed" or "Encrypted",
                    "tm.Actor" => key == "AuthenticatesItself",
                    "tm.Flow" => key == "Protocol",
                    _ => false,
                };
                if (!mapped && key != "ThreatDragon.Id" && key != "ThreatDragon.DiagramId" && key != "ThreatDragon.ModelType"
                    && !key.StartsWith("ThreatDragon.data.", StringComparison.Ordinal))
                {
                    throw new NotSupportedException($"Threat Dragon cell '{entity.Guid}' has unsupported property '{key}'.");
                }
            }

            foreach (KeyValuePair<string, string> property in properties
                .Where(property => property.Key.StartsWith("ThreatDragon.data.", StringComparison.Ordinal)).OrderBy(property => property.Key, StringComparer.Ordinal))
            {
                string key = property.Key.Substring("ThreatDragon.data.".Length);
                switch (key)
                {
                    case "name":
                    case "type":
                    case "hasOpenThreats":
                    case "isTrustBoundary":
                        break;
                    case "outOfScope":
                    case "isBidirectional":
                    case "providesAuthentication":
                    case "storesCredentials":
                    case "isALog":
                    case "isSigned":
                    case "isEncrypted":
                    case "isPublicNetwork":
                    case "isWebApplication":
                    case "handlesCardPayment":
                    case "handlesGoodsOrServices":
                    case "storesInventory":
                        if (!bool.TryParse(property.Value, out bool boolean))
                        {
                            throw new NotSupportedException($"Threat Dragon cell '{entity.Guid}' property '{key}' must be a boolean.");
                        }

                        data[key] = boolean;
                        break;
                    case "description":
                    case "reasonOutOfScope":
                    case "protocol":
                    case "privilegeLevel":
                        data[key] = property.Value;
                        break;
                    default:
                        throw new NotSupportedException($"Threat Dragon cell '{entity.Guid}' has unsupported source property '{key}'.");
                }
            }

            data["type"] = kind;
            data["name"] = name;
            data["isTrustBoundary"] = kind == "tm.BoundaryBox";
            if (kind == "tm.Store")
            {
                WriteControl(data, properties, entity.Guid, "storesCredentials", "StoresCredentials");
                WriteControl(data, properties, entity.Guid, "isALog", "StoresLogData");
                WriteControl(data, properties, entity.Guid, "isSigned", "Signed");
                WriteControl(data, properties, entity.Guid, "isEncrypted", "Encrypted", "At-rest");
            }
            else if (kind == "tm.Actor")
            {
                WriteControl(data, properties, entity.Guid, "providesAuthentication", "AuthenticatesItself");
            }
            else if (kind == "tm.Flow")
            {
                data.Remove("protocol");
                if (properties.TryGetValue("Protocol", out string? protocol))
                {
                    data["protocol"] = protocol;
                }
            }

            return data;
        }

        private static void WriteControl(JsonObject data, IReadOnlyDictionary<string, string> properties, Guid id, string field, string key, string positive = "Yes")
        {
            data.Remove(field);
            if (!properties.TryGetValue(key, out string? value))
            {
                return;
            }

            if (value != positive && value != "No")
            {
                throw new NotSupportedException($"Threat Dragon cell '{id}' property '{key}' has value '{value}'; only '{positive}' and 'No' can be exported as a boolean.");
            }

            data[field] = value == positive;
        }

        private static JsonObject WriteThreat(string key, Threat threat, string methodology, long number)
        {
            if (!ManualThreatId.IsManual(key)
                || (!string.IsNullOrEmpty(threat.TypeId) && !ManualThreatId.IsNativeTypeId(threat.TypeId)))
            {
                throw new NotSupportedException($"Threat Dragon export cannot preserve generated threat '{key}'; only authored threats are supported.");
            }

            RefuseField(threat.ChangedBy, "threat '" + key + "'.ChangedBy");
            RefuseField(threat.InteractionString, "threat '" + key + "'.InteractionString");
            if (threat.ModifiedAt != default || threat.Upgraded)
            {
                throw new NotSupportedException($"Threat Dragon threat '{key}' contains unsupported audit metadata.");
            }

            foreach (string property in threat.Properties?.Keys ?? Enumerable.Empty<string>())
            {
                string? projected = property switch
                {
                    "Title" => threat.Title,
                    "UserThreatCategory" => threat.UserThreatCategory,
                    "UserThreatShortDescription" => threat.UserThreatShortDescription,
                    "UserThreatDescription" => threat.UserThreatDescription,
                    "StateInformation" => threat.StateInformation,
                    "InteractionString" => threat.InteractionString,
                    "Priority" => threat.Priority,
                    _ => null,
                };
                if (projected != null && string.Equals(projected, threat.Properties![property], StringComparison.Ordinal))
                {
                    continue;
                }

                if (property != "Mitigation" && property != "Source.format" && property != "Source.version" && property != "Source.id"
                    && property != "Source.cellId" && property != "Source.diagramId" && property != "Source.modelType"
                    && property != "Source.status" && property != "Source.severity" && property != "Source.score" && property != "Source.number")
                {
                    throw new NotSupportedException($"Threat Dragon threat '{key}' has unsupported property '{property}'.");
                }
            }

            string status = threat.State switch
            {
                ThreatState.AutoGenerated => "Open",
                ThreatState.Mitigated => "Mitigated",
                ThreatState.NotApplicable => "Accepted",
                _ => throw new NotSupportedException($"Threat Dragon threat '{key}' has unsupported state '{threat.State}'."),
            };
            string id = key.StartsWith("manual:threat-dragon.", StringComparison.OrdinalIgnoreCase)
                ? key.Substring("manual:threat-dragon.".Length) : key.Substring("manual:".Length);
            return new JsonObject
            {
                ["id"] = id,
                ["number"] = number,
                ["title"] = threat.Title,
                ["type"] = threat.UserThreatCategory,
                ["modelType"] = threat.Properties != null && threat.Properties.TryGetValue("Source.modelType", out string? modelType) ? modelType : methodology,
                ["description"] = threat.UserThreatDescription ?? threat.UserThreatShortDescription ?? string.Empty,
                ["mitigation"] = threat.Properties != null && threat.Properties.TryGetValue("Mitigation", out string? mitigation) ? mitigation : string.Empty,
                ["severity"] = threat.Priority,
                ["status"] = status,
                ["justification"] = threat.StateInformation ?? string.Empty,
                ["score"] = threat.Properties != null && threat.Properties.TryGetValue("Source.score", out string? score) ? score : string.Empty,
            };
        }

        private static string ExportProperty(Entity entity, string key) =>
            DiagramElementHelper.GetCustomProperties(entity).TryGetValue(key, out string? value) ? value : string.Empty;

        private static void RefuseField(string? value, string field)
        {
            if (!string.IsNullOrEmpty(value))
            {
                throw new NotSupportedException($"Threat Dragon export cannot preserve '{field}'.");
            }
        }

        private static string ExportCellId(Entity entity, string pageId)
        {
            string sourceId = ExportProperty(entity, "ThreatDragon.Id");
            Guid imported = Guid.TryParse(sourceId, out Guid parsed) ? parsed
                : DeterministicGuid.FromElementId($"threat-dragon:{pageId.Length}:{pageId}:{sourceId}");
            return sourceId.Length > 0 && imported == entity.Guid ? sourceId : entity.Guid.ToString("D");
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
                if (item.TryGetProperty("number", out _))
                {
                    model.AllThreatsDictionary[key].Properties!["Source.number"] = Identifier(item, "number");
                }
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
