namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using ThreatModelForge.Editing;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// The <c>tmforge-json</c> format provider: the canvas's canonical wire model. It reads and
    /// writes the structural diagram (elements, flows, trust boundaries, names, and geometry) the
    /// React front end edits, reconstructing a <see cref="ThreatModel"/> via the UI-agnostic
    /// <see cref="DiagramEditor"/>.
    /// </summary>
    public sealed class TmForgeJsonFormat : IThreatModelFormat
    {
        /// <summary>The stable format identifier.</summary>
        public const string FormatId = "tmforge-json";

        private const string SchemaToken = "tmforge-json";

        private static readonly IReadOnlyList<string> SupportedExtensions = new[] { ".tmforge.json" };

        private static readonly FormatCapabilities JsonCapabilities = new FormatCapabilities(
            canRead: true,
            canWrite: true,
            roundTrips: false,
            fidelityNote: "The canvas wire model: elements, flows, trust boundaries, names, and geometry. Knowledge-base attributes and the generated-threat register are not represented, except risk-acceptance triage, which round-trips.");

        private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        /// <summary>
        /// The stable identity for the single implicit page of a flat (non-<c>diagrams</c>) document,
        /// so separate reads of single-page models share a surface id and the merge folds one side's
        /// additions onto the other's page instead of spawning a second page.
        /// </summary>
        private static readonly Guid DefaultSurfaceGuid = new Guid("7e3f1d52-0000-4000-8000-000000000001");

        /// <inheritdoc/>
        public string Id => FormatId;

        /// <inheritdoc/>
        public string DisplayName => "Threat Model Forge JSON (.tmforge.json)";

        /// <inheritdoc/>
        public IReadOnlyList<string> Extensions => SupportedExtensions;

        /// <inheritdoc/>
        public FormatCapabilities Capabilities => JsonCapabilities;

        /// <summary>
        /// Reads only the per-model analysis selection from a <c>tmforge-json</c> stream, without
        /// building the full model. Used to honor a model's rule selection when analyzing.
        /// </summary>
        /// <param name="stream">The source stream positioned at the start of the document.</param>
        /// <param name="disabledPacks">On return, the rule pack ids to skip (empty when none).</param>
        /// <param name="disabledRuleIds">On return, the rule ids to skip (empty when none).</param>
        /// <returns><c>true</c> if the document declared any pack or rule to skip; otherwise <c>false</c>.</returns>
        public static bool TryReadAnalysis(
            Stream stream,
            out IReadOnlyList<string> disabledPacks,
            out IReadOnlyList<string> disabledRuleIds)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            disabledPacks = Array.Empty<string>();
            disabledRuleIds = Array.Empty<string>();

            string text;
            using (StreamReader reader = new StreamReader(
                stream,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 1024,
                leaveOpen: true))
            {
                text = reader.ReadToEnd();
            }

            TmForgeJsonModel? document = JsonSerializer.Deserialize<TmForgeJsonModel>(text, SerializerOptions);
            if (document?.Analysis == null)
            {
                return false;
            }

            disabledPacks = document.Analysis.DisabledPacks ?? Array.Empty<string>();
            disabledRuleIds = document.Analysis.DisabledRuleIds ?? Array.Empty<string>();
            return disabledPacks.Count > 0 || disabledRuleIds.Count > 0;
        }

        /// <inheritdoc/>
        public bool CanRead(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (!stream.CanSeek)
            {
                throw new NotSupportedException("Content sniffing requires a seekable stream.");
            }

            long originalPosition = stream.Position;
            try
            {
                using (StreamReader reader = new StreamReader(
                    stream,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: true,
                    bufferSize: 1024,
                    leaveOpen: true))
                {
                    char[] buffer = new char[512];
                    int count = reader.Read(buffer, 0, buffer.Length);
                    string prefix = new string(buffer, 0, count);
                    Utf8JsonReader json = new Utf8JsonReader(Encoding.UTF8.GetBytes(prefix), isFinalBlock: false, state: default);
                    while (json.Read())
                    {
                        if (json.TokenType == JsonTokenType.PropertyName && json.CurrentDepth == 1 && json.ValueTextEquals("schema"))
                        {
                            return json.Read() && json.TokenType == JsonTokenType.String && json.ValueTextEquals(SchemaToken);
                        }
                    }

                    return false;
                }
            }
            catch (JsonException)
            {
                return false;
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        /// <inheritdoc/>
        public ThreatModel Read(Stream stream)
        {
            return ReadCore(stream, null);
        }

        /// <inheritdoc/>
        public void Write(ThreatModel model, Stream stream)
        {
            this.Write(model, stream, null);
        }

        /// <summary>
        /// Writes the model to <c>tmforge-json</c>, embedding the given per-model analysis selection.
        /// </summary>
        /// <param name="model">The model to write.</param>
        /// <param name="stream">The destination stream.</param>
        /// <param name="analysis">The analysis selection to embed, or <see langword="null"/> to omit it.</param>
        public void Write(ThreatModel model, Stream stream, TmForgeJsonAnalysis? analysis)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            List<TmForgeJsonDiagram> diagrams = new List<TmForgeJsonDiagram>();
            int index = 1;
            foreach (DrawingSurfaceModel surface in model.DrawingSurfaceList)
            {
                (TmForgeJsonElement[] pageElements, TmForgeJsonFlow[] pageFlows) = ExtractSurface(surface);
                string name = string.IsNullOrEmpty(surface.Header)
                    ? "Diagram " + index.ToString(CultureInfo.InvariantCulture)
                    : surface.Header!;
                diagrams.Add(new TmForgeJsonDiagram
                {
                    Id = surface.Guid.ToString(),
                    Name = name,
                    Elements = pageElements,
                    Flows = pageFlows,
                });
                index++;
            }

            TmForgeJsonModel document = new TmForgeJsonModel
            {
                Schema = SchemaToken,
                Version = "0.1",
                Metadata = model.MetaInformation,
                Elements = diagrams.Count > 0 ? diagrams[0].Elements : Array.Empty<TmForgeJsonElement>(),
                Flows = diagrams.Count > 0 ? diagrams[0].Flows : Array.Empty<TmForgeJsonFlow>(),
                Diagrams = diagrams.Count > 0 && (diagrams.Count > 1
                    || model.DrawingSurfaceList[0].Guid != DefaultSurfaceGuid
                    || diagrams[0].Name != "Diagram 1") ? diagrams.ToArray() : null,
                Analysis = analysis,
                Threats = CollectTriage(model),
            };

            string json = JsonSerializer.Serialize(document, SerializerOptions);
            using (StreamWriter writer = new StreamWriter(
                stream,
                new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                bufferSize: 1024,
                leaveOpen: true))
            {
                writer.Write(json);
            }
        }

        /// <summary>Reads a model while recording each internal GUID's original wire identifier.</summary>
        /// <param name="stream">The canonical JSON input.</param>
        /// <param name="originalIds">The map populated with internal GUID to wire identifier entries.</param>
        /// <returns>The parsed threat model.</returns>
        internal static ThreatModel ReadWithOriginalIds(Stream stream, IDictionary<Guid, string> originalIds)
        {
            if (originalIds == null)
            {
                throw new ArgumentNullException(nameof(originalIds));
            }

            return ReadCore(stream, originalIds);
        }

        private static ThreatModel ReadCore(Stream stream, IDictionary<Guid, string>? originalIds)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            string text = JsonDocumentPreflight.ReadText(stream);
            JsonModelPreflight.ThrowIfInvalid(JsonModelPreflight.Inspect(text));
            TmForgeJsonModel document = JsonSerializer.Deserialize<TmForgeJsonModel>(text, SerializerOptions)
                ?? new TmForgeJsonModel();

            ThreatModel model = new ThreatModel { Version = "1.0", MetaInformation = document.Metadata };
            DiagramEditor editor = new DiagramEditor(model);

            if (document.Diagrams != null && document.Diagrams.Count > 0)
            {
                int index = 1;
                foreach (TmForgeJsonDiagram page in document.Diagrams)
                {
                    string header = string.IsNullOrEmpty(page.Name)
                        ? "Diagram " + index.ToString(CultureInfo.InvariantCulture)
                        : page.Name;
                    DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = ResolveSurfaceGuid(page.Id), Header = header };
                    model.DrawingSurfaceList.Add(surface);

                    // Record the page's wire id too. A page id that is not guid-shaped gets a fresh
                    // surface guid on every load, so anything that has to be stable across runs (a
                    // finding identity, for one) must key off the author's id rather than the guid.
                    if (!string.IsNullOrWhiteSpace(page.Id))
                    {
                        originalIds?[surface.Guid] = page.Id!;
                    }

                    PopulateSurface(editor, surface, page.Elements, page.Flows, originalIds);
                    index++;
                }
            }
            else
            {
                DrawingSurfaceModel surface = new DrawingSurfaceModel { Guid = DefaultSurfaceGuid, Header = "Diagram 1" };
                model.DrawingSurfaceList.Add(surface);
                PopulateSurface(editor, surface, document.Elements, document.Flows, originalIds);
            }

            SeedRegister(model, document.Threats);
            return model;
        }

        /// <summary>
        /// Seeds the model's threat register from the author overlay carried on the document, so edits
        /// and manually-authored threats recorded in Studio (or a prior CLI session) survive the
        /// round-trip. Only the durable, author-owned overlay is stored on <c>tmforge-json</c>; the rest
        /// of the register is a projection of the analysis findings and is regenerated on demand
        /// (<c>tmforge threats</c>), which preserves these entries by their register key.
        /// </summary>
        /// <param name="model">The model whose register is seeded.</param>
        /// <param name="overlay">The author overlay from the document, if any.</param>
        private static void SeedRegister(ThreatModel model, IReadOnlyList<TmForgeJsonThreatState>? overlay)
        {
            if (overlay == null)
            {
                return;
            }

            Guid surfaceGuid = FirstSurfaceGuid(model);
            int nextId = 1;
            foreach (TmForgeJsonThreatState entry in overlay)
            {
                if (string.IsNullOrEmpty(entry.Id) || model.AllThreatsDictionary.ContainsKey(entry.Id))
                {
                    continue;
                }

                bool manual = entry.Manual == true || ThreatStateWire.IsManualKey(entry.Id);
                ThreatState state = ThreatStateWire.Parse(entry.State);
                bool edited = state != ThreatState.AutoGenerated
                    || !string.IsNullOrEmpty(entry.Title)
                    || !string.IsNullOrEmpty(entry.Description)
                    || !string.IsNullOrEmpty(entry.Mitigation)
                    || !string.IsNullOrEmpty(entry.Priority);
                if (!manual && !edited)
                {
                    // A rule-derived, unedited entry carries nothing the regenerable register does not
                    // already produce, so leave it out and keep the seeded register sparse.
                    continue;
                }

                Threat threat = BuildOverlayThreat(entry, manual, state, surfaceGuid, nextId);
                DrawingSurfaceModel? scopedPage = model.DrawingSurfaceList.FirstOrDefault(page =>
                    page.Borders.ContainsKey(threat.SourceGuid) || page.Lines.ContainsKey(threat.SourceGuid)
                    || page.Lines.ContainsKey(threat.FlowGuid));
                threat.DrawingSurfaceGuid = scopedPage?.Guid ?? surfaceGuid;
                model.AllThreatsDictionary[entry.Id] = threat;
                nextId++;
            }
        }

        /// <summary>
        /// Builds a register threat from an author-overlay entry: a manually-authored threat carries its
        /// own scope and text, while an edited rule threat carries the edit fields on top of the target
        /// element parsed from its register id.
        /// </summary>
        /// <param name="entry">The overlay entry.</param>
        /// <param name="manual">Whether the entry is a manually-authored threat.</param>
        /// <param name="state">The parsed lifecycle state.</param>
        /// <param name="surfaceGuid">The drawing surface to record the threat against.</param>
        /// <param name="id">The numeric register id to assign.</param>
        /// <returns>The register threat.</returns>
        private static Threat BuildOverlayThreat(
            TmForgeJsonThreatState entry,
            bool manual,
            ThreatState state,
            Guid surfaceGuid,
            int id)
        {
            (Guid source, Guid target, Guid flow) = ResolveScope(entry.ElementIds);
            string? ruleId = null;
            if (!manual)
            {
                (Guid parsedTarget, string? parsedRule) = ParseThreatId(entry.Id);
                ruleId = parsedRule;
                if (source == Guid.Empty)
                {
                    source = parsedTarget;
                }
            }

            Threat threat = new Threat
            {
                Id = id,
                TypeId = ruleId,
                SourceGuid = source,
                TargetGuid = target,
                FlowGuid = flow,
                DrawingSurfaceGuid = surfaceGuid,
                State = state,
                InteractionKey = entry.Id,
                StateInformation = entry.Justification ?? string.Empty,
                Title = entry.Title,
                Priority = entry.Priority,
                UserThreatCategory = entry.Category,
                UserThreatDescription = entry.Description,
                Wide = manual && source == Guid.Empty && target == Guid.Empty && flow == Guid.Empty,
                ModifiedAt = DateTime.UtcNow,
            };
            if (!string.IsNullOrEmpty(entry.Mitigation))
            {
                threat.Properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Mitigation"] = entry.Mitigation!,
                };
            }

            if (manual && entry.Source != null)
            {
                threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (KeyValuePair<string, string> provenance in entry.Source)
                {
                    threat.Properties["Source." + provenance.Key] = provenance.Value;
                }
            }

            if (!manual && !string.IsNullOrEmpty(entry.Priority))
            {
                threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                threat.Properties["PriorityOverride"] = "true";
            }

            return threat;
        }

        private static (Guid Source, Guid Target, Guid Flow) ResolveScope(IReadOnlyList<string>? ids)
        {
            Guid source = Guid.Empty;
            Guid target = Guid.Empty;
            Guid flow = Guid.Empty;
            if (ids != null)
            {
                if (ids.Count > 0)
                {
                    Guid.TryParse(ids[0], out source);
                }

                if (ids.Count > 1)
                {
                    Guid.TryParse(ids[1], out target);
                }

                if (ids.Count > 2)
                {
                    Guid.TryParse(ids[2], out flow);
                }
            }

            return (source, target, flow);
        }

        /// <summary>
        /// Projects the model's author-owned register threats back onto the document overlay so edits
        /// and manually-authored threats round-trip. Manual threats are emitted in full; edited rule
        /// threats emit their state, justification, and description (fields the rules never set); the
        /// rest of the register is regenerable and is not stored.
        /// </summary>
        /// <param name="model">The model whose register is read.</param>
        /// <returns>The author overlay, or <see langword="null"/> when nothing is author-owned.</returns>
        private static IReadOnlyList<TmForgeJsonThreatState>? CollectTriage(ThreatModel model)
        {
            List<TmForgeJsonThreatState> overlay = new List<TmForgeJsonThreatState>();
            foreach (KeyValuePair<string, Threat> pair in model.AllThreatsDictionary)
            {
                Threat threat = pair.Value;
                string id = string.IsNullOrEmpty(threat.InteractionKey) ? pair.Key : threat.InteractionKey!;
                bool manual = ThreatStateWire.IsManualKey(id);
                bool explicitPriorityOverride = threat.Properties?.TryGetValue("PriorityOverride", out string? marker) == true &&
                    string.Equals(marker, "true", StringComparison.OrdinalIgnoreCase);
                bool generatedDefaultDiffers =
                    threat.Properties?.TryGetValue("GeneratedDefaultPriority", out string? generatedDefault) == true &&
                    !string.IsNullOrEmpty(threat.Priority) &&
                    !string.Equals(threat.Priority, generatedDefault, StringComparison.OrdinalIgnoreCase);
                bool priorityOverride = explicitPriorityOverride || generatedDefaultDiffers;
                bool markerlessTriagedPriority = threat.State != ThreatState.AutoGenerated &&
                    !string.IsNullOrEmpty(threat.Priority) &&
                    threat.Properties?.ContainsKey("GeneratedDefaultPriority") != true;

                // A retitled threat is edited even when nothing else about it changed. Without this a
                // title override is dropped here and the next regeneration restores the rule's wording,
                // so the edit survives in the tool's own file but not through the canonical format.
                bool explicitTitleOverride = threat.Properties?.TryGetValue("TitleOverride", out string? titleMarker) == true &&
                    string.Equals(titleMarker, "true", StringComparison.OrdinalIgnoreCase);
                bool generatedTitleDiffers =
                    threat.Properties?.TryGetValue("GeneratedDefaultTitle", out string? generatedTitle) == true &&
                    !string.IsNullOrEmpty(threat.Title) &&
                    !string.Equals(threat.Title, generatedTitle, StringComparison.Ordinal);
                bool titleOverride = explicitTitleOverride || generatedTitleDiffers;

                bool edited = threat.State != ThreatState.AutoGenerated
                    || !string.IsNullOrEmpty(threat.UserThreatDescription)
                    || priorityOverride
                    || titleOverride;
                if (!manual && !edited)
                {
                    continue;
                }

                overlay.Add(new TmForgeJsonThreatState
                {
                    Id = id,
                    State = ThreatStateWire.ToWire(threat.State),
                    Justification = NullIfEmpty(threat.StateInformation),
                    Manual = manual ? true : (bool?)null,
                    Category = manual ? NullIfEmpty(threat.UserThreatCategory) : null,
                    Title = manual || titleOverride ? NullIfEmpty(threat.Title) : null,
                    Description = NullIfEmpty(threat.UserThreatDescription),
                    Mitigation = manual ? MitigationOf(threat) : null,
                    Source = manual ? SourceOf(threat) : null,
                    Priority = manual || priorityOverride || markerlessTriagedPriority ? NullIfEmpty(threat.Priority) : null,
                    ElementIds = manual ? ScopeIds(threat) : null,
                });
            }

            if (overlay.Count == 0)
            {
                return null;
            }

            overlay.Sort((left, right) => string.CompareOrdinal(left.Id, right.Id));
            return overlay;
        }

        private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;

        private static IReadOnlyDictionary<string, string>? SourceOf(Threat threat)
        {
            Dictionary<string, string>? source = threat.Properties?
                .Where(property => property.Key.StartsWith("Source.", StringComparison.OrdinalIgnoreCase))
                .ToDictionary(property => property.Key.Substring("Source.".Length), property => property.Value, StringComparer.Ordinal);
            return source?.Count > 0 ? source : null;
        }

        private static string? MitigationOf(Threat threat)
        {
            if (threat.Properties != null &&
                threat.Properties.TryGetValue("Mitigation", out string? mitigation) &&
                !string.IsNullOrEmpty(mitigation))
            {
                return mitigation;
            }

            return null;
        }

        private static IReadOnlyList<string>? ScopeIds(Threat threat)
        {
            List<string> ids = new List<string>();
            if (threat.SourceGuid != Guid.Empty)
            {
                ids.Add(threat.SourceGuid.ToString());
            }

            if (threat.TargetGuid != Guid.Empty)
            {
                ids.Add(threat.TargetGuid.ToString());
            }

            if (threat.FlowGuid != Guid.Empty)
            {
                ids.Add(threat.FlowGuid.ToString());
            }

            return ids.Count > 0 ? ids : null;
        }

        /// <summary>
        /// Splits a register id (<c>{targetGuid:N}:{ruleId}</c>) into its target element GUID and rule
        /// id. Returns an empty GUID and <see langword="null"/> rule id when the id is not in that form.
        /// </summary>
        /// <param name="id">The register id.</param>
        /// <returns>The parsed target GUID and rule id.</returns>
        private static (Guid TargetGuid, string? RuleId) ParseThreatId(string id)
        {
            int colon = id.IndexOf(':');
            if (colon <= 0)
            {
                return (Guid.Empty, null);
            }

            string guidPart = id.Substring(0, colon);
            string ruleId = id.Substring(colon + 1);
            Guid.TryParseExact(guidPart, "N", out Guid targetGuid);
            return (targetGuid, string.IsNullOrEmpty(ruleId) ? null : ruleId);
        }

        private static Guid FirstSurfaceGuid(ThreatModel model)
        {
            foreach (DrawingSurfaceModel surface in model.DrawingSurfaceList)
            {
                return surface.Guid;
            }

            return Guid.Empty;
        }

        private static void PopulateSurface(
            DiagramEditor editor,
            DrawingSurfaceModel surface,
            IReadOnlyList<TmForgeJsonElement>? elements,
            IReadOnlyList<TmForgeJsonFlow>? flows,
            IDictionary<Guid, string>? originalIds)
        {
            Dictionary<string, Guid> idMap = new Dictionary<string, Guid>(StringComparer.Ordinal);

            foreach (TmForgeJsonElement element in elements ?? Array.Empty<TmForgeJsonElement>())
            {
                StencilKind kind = MapKind(element.Kind);
                Guid guid = editor.AddElement(surface, kind, element.X, element.Y);
                guid = PreserveId(surface.Borders, guid, element.Id);
                editor.SetElementName(surface, guid, element.Name ?? string.Empty);
                if (element.Width.HasValue && element.Height.HasValue)
                {
                    // Honor the authored size for every kind — AddElement only stamps the stencil's
                    // default size, so without this a component (process, store, external) would shrink
                    // to that default on the round trip instead of keeping the size the canvas gave it.
                    editor.ResizeElement(surface, guid, element.X, element.Y, element.Width.Value, element.Height.Value);
                }
                else if (kind == StencilKind.TrustBoundary)
                {
                    editor.ResizeElement(surface, guid, element.X, element.Y, element.Width ?? 260, element.Height ?? 180);
                }

                ApplyProperties(surface.Borders[guid] as Entity, element.Properties);

                if (!string.IsNullOrEmpty(element.Id))
                {
                    idMap[element.Id] = guid;
                    originalIds?[guid] = element.Id;
                }
            }

            foreach (TmForgeJsonFlow flow in flows ?? Array.Empty<TmForgeJsonFlow>())
            {
                bool hasSource = idMap.TryGetValue(flow.Source, out Guid source);
                bool hasTarget = idMap.TryGetValue(flow.Target, out Guid target);
                if (hasSource && hasTarget)
                {
                    Guid connector = editor.AddConnector(surface, source, target);
                    connector = PreserveId(surface.Lines, connector, flow.Id);
                    editor.SetElementName(surface, connector, flow.Name ?? string.Empty);
                    ApplyProperties(surface.Lines[connector] as Entity, flow.Properties);
                    if (!string.IsNullOrEmpty(flow.Id))
                    {
                        originalIds?[connector] = flow.Id;
                    }
                }
            }
        }

        /// <summary>
        /// Resolves a diagram's surface identity from the id carried by the source document: the id
        /// itself when it is a GUID, otherwise a stable id derived from it, so pages align across files
        /// for the three-way merge and anything keyed on the surface survives a round trip.
        /// </summary>
        /// <param name="id">The diagram id from the source document, if any.</param>
        /// <returns>The surface <see cref="Guid"/> to use.</returns>
        private static Guid ResolveSurfaceGuid(string? id)
        {
            if (Guid.TryParse(id, out Guid parsed))
            {
                return parsed;
            }

            return string.IsNullOrWhiteSpace(id)
                ? Guid.NewGuid()
                : DeterministicGuid.FromPageId(id!);
        }

        /// <summary>
        /// Re-keys a freshly created element to a stable identifier derived from the source document:
        /// the id itself when it is a GUID, otherwise a hash of the author's id. Element identity then
        /// survives the tmforge-json round-trip, which the structural diff and three-way merge match on
        /// and which anything keyed on the guid — a threat register entry, for one — depends on.
        /// </summary>
        /// <param name="elements">The surface dictionary (borders or lines) the element lives in.</param>
        /// <param name="current">The generated identifier the element was added under.</param>
        /// <param name="id">The identifier from the source document, if any.</param>
        /// <returns>The identifier the element is keyed under after this call.</returns>
        private static Guid PreserveId(IDictionary<Guid, object> elements, Guid current, string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return current;
            }

            Guid desired = Guid.TryParse(id, out Guid parsed) ? parsed : DeterministicGuid.FromElementId(id!);
            if (desired == current || elements.ContainsKey(desired))
            {
                return current;
            }

            if (elements.TryGetValue(current, out object? value) && value is Entity entity)
            {
                elements.Remove(current);
                entity.Guid = desired;
                elements[desired] = entity;
                return desired;
            }

            return current;
        }

        private static (TmForgeJsonElement[] Elements, TmForgeJsonFlow[] Flows) ExtractSurface(DrawingSurfaceModel surface)
        {
            List<TmForgeJsonElement> elements = new List<TmForgeJsonElement>();
            List<TmForgeJsonFlow> flows = new List<TmForgeJsonFlow>();

            foreach (DrawingElement element in surface.Borders.Values.OfType<DrawingElement>())
            {
                elements.Add(new TmForgeJsonElement
                {
                    Id = element.Guid.ToString(),
                    Kind = KindOf(element),
                    Name = DiagramElementHelper.GetName(element),
                    X = element.Left,
                    Y = element.Top,
                    Width = element.Width,
                    Height = element.Height,
                    Properties = DiagramElementHelper.GetCustomProperties(element),
                });
            }

            foreach (Connector connector in surface.Lines.Values.OfType<Connector>())
            {
                flows.Add(new TmForgeJsonFlow
                {
                    Id = connector.Guid.ToString(),
                    Source = connector.SourceGuid.ToString(),
                    Target = connector.TargetGuid.ToString(),
                    Name = DiagramElementHelper.GetName(connector),
                    Properties = DiagramElementHelper.GetCustomProperties(connector),
                });
            }

            return (elements.ToArray(), flows.ToArray());
        }

        private static void ApplyProperties(Entity? entity, IReadOnlyDictionary<string, string>? properties)
        {
            if (entity == null || properties == null)
            {
                return;
            }

            foreach (KeyValuePair<string, string> pair in properties)
            {
                DiagramElementHelper.SetCustomProperty(entity, pair.Key, pair.Value);
            }
        }

        private static StencilKind MapKind(string? kind)
        {
            switch (kind)
            {
                case "datastore":
                    return StencilKind.DataStore;
                case "external":
                    return StencilKind.ExternalEntity;
                case "boundary":
                    return StencilKind.TrustBoundary;
                default:
                    return StencilKind.Process;
            }
        }

        private static string KindOf(DrawingElement element)
        {
            return element switch
            {
                BorderBoundary => "boundary",
                StencilEllipse => "process",
                StencilParallelLines => "datastore",
                _ => "external",
            };
        }
    }
}
