namespace ThreatModelForge.Engine
{
    using System.Globalization;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.Json;
    using System.Xml;
    using System.Xml.Linq;
    using System.Xml.Schema;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Formats;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Applies canvas edits to a retained native document without rebuilding its unedited data.</summary>
    internal static class NativeTm7Document
    {
        private static readonly XNamespace Instance = "http://www.w3.org/2001/XMLSchema-instance";
        private static readonly XName StudioStateName = XNamespace.Get("urn:tmforge:studio:v1") + "State";
        private static readonly JsonSerializerOptions StateOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        private static readonly XmlSchemaSet NativeEnvelopeSchemas = CreateNativeEnvelopeSchemas();

        /// <summary>Saves supported edits while retaining unrepresented native XML.</summary>
        /// <param name="original">The native source bytes.</param>
        /// <param name="edited">The edited canvas projection.</param>
        /// <param name="rules">The active analysis rules.</param>
        /// <param name="ruleErrors">Unavailable or mismatched rule-pack diagnostics.</param>
        /// <param name="previous">The latest successful save in this editing session.</param>
        /// <returns>The original bytes for a no-op, otherwise the patched native document.</returns>
        internal static byte[] Save(byte[] original, TmForgeModelDto edited, RuleSet rules, IReadOnlyList<string> ruleErrors, byte[] previous)
        {
            if (original.Length > JsonDocumentPreflight.MaxBytes)
            {
                throw new InvalidDataException("Native TM7 editing is limited to 8 MiB documents.");
            }

            XDocument retained = ReadXml(original);
            PreflightResultDto preflight = DocumentPreflight.Inspect(original, Tm7Format.FormatId);
            if (!preflight.Success)
            {
                throw new InvalidDataException(string.Join(" ", preflight.Diagnostics.Select(item => item.Message)));
            }

            using MemoryStream input = new MemoryStream(original, writable: false);
            ThreatModel native = ThreatModel.Load(input);
            XDocument before = Serialize(native);
            StudioState? state = ReadState(retained, native);
            TmForgeModelDto baseline = WithNativeThreatScopes(state?.Model ?? ModelDtoMapper.ToDto(native), native);
            TranslateCoordinates(native, state, -1);
            XDocument editableBefore = Serialize(native);
            ThreatModel beforeProjection = ModelDtoMapper.ToModel(baseline);
            ThreatModel requested = ModelDtoMapper.ToModel(edited);
            HashSet<Guid> originalIds = native.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys).Append(page.Guid)).ToHashSet();
            IReadOnlyList<ThreatStateDto>? previousThreats = baseline.Threats;
            if (previous.Length > 0)
            {
                if (previous.Length > JsonDocumentPreflight.MaxBytes)
                {
                    throw new InvalidDataException("The previous native save exceeds the 8 MiB limit.");
                }

                _ = ReadXml(previous);
                using MemoryStream savedInput = new MemoryStream(previous, writable: false);
                ThreatModel prior = ThreatModel.Load(savedInput);
                StudioState? savedState = ReadState(ReadXml(previous), prior);
                HashSet<string> introduced = prior.AllThreatsDictionary.Keys.Where(key => !native.AllThreatsDictionary.ContainsKey(key)).ToHashSet(StringComparer.Ordinal);
                foreach (string key in introduced)
                {
                    native.AllThreatsDictionary[key] = prior.AllThreatsDictionary[key];
                }

                originalIds.UnionWith(prior.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys).Append(page.Guid)));
                previousThreats = (baseline.Threats ?? Array.Empty<ThreatStateDto>()).Concat(
                    (savedState?.Model?.Threats ?? ModelDtoMapper.ToDto(prior).Threats ?? Array.Empty<ThreatStateDto>())
                    .Where(threat => introduced.Contains(threat.Id))).ToArray();
                PreserveAddedDefinitions(native, prior);
            }

            ApplyPages(native, beforeProjection, requested);
            if (!Same(baseline.Metadata, edited.Metadata))
            {
                native.MetaInformation = edited.Metadata;
            }

            if (edited.Notes != null && !Same(baseline.Notes, edited.Notes))
            {
                native.Notes.Clear();
                native.Notes.AddRange(requested.Notes);
            }

            HashSet<string> deletedThreatIds = RemoveDeletedScopes(native, originalIds);
            edited = WithoutDeletedThreats(edited, deletedThreatIds);
            ApplyThreats(native, previousThreats, edited.Threats, requested, rules, ruleErrors, deletedThreatIds);

            bool viewChanged = !Same(View(baseline), View(edited));
            if (XNode.DeepEquals(editableBefore, Serialize(native)) && !viewChanged && native.KnowledgeBase != null)
            {
                return original.ToArray();
            }

            Dictionary<Guid, TmForgePointDto> positions = native.DrawingSurfaceList.ToDictionary(page => page.Guid, Anchor);
            Tm7ExportPreparer.NormalizeNativeCoordinates(native);
            Dictionary<Guid, TmForgePointDto> offsets = native.DrawingSurfaceList.ToDictionary(page => page.Guid, page => new TmForgePointDto
            {
                X = Anchor(page).X - positions[page.Guid].X,
                Y = Anchor(page).Y - positions[page.Guid].Y,
            });
            Tm7ExportPreparer.ExtendNativeTemplate(native, rules);
            XDocument after = Serialize(native);
            Patch(retained.Root!, before.Root!, after.Root!);
            StudioState next = new StudioState { Fingerprint = Fingerprint(native), Model = edited, Offsets = offsets };
            retained.Root!.Element(StudioStateName)?.Remove();
            retained.Root.Add(new XElement(StudioStateName, JsonSerializer.Serialize(next, StateOptions)));
            using MemoryStream output = new MemoryStream();
            using (XmlWriter writer = XmlWriter.Create(output, new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false),
                OmitXmlDeclaration = retained.Declaration == null,
                NewLineHandling = NewLineHandling.None,
                CloseOutput = false,
            }))
            {
                retained.Save(writer);
            }

            byte[] saved = output.ToArray();
            PreflightResultDto checkedOutput = DocumentPreflight.Inspect(saved, Tm7Format.FormatId);
            if (!checkedOutput.Success)
            {
                throw new InvalidDataException("The native edit could not be saved without invalidating the document.");
            }

            return saved;
        }

        /// <summary>Restores Studio presentation only when it matches the native model's current content.</summary>
        /// <param name="content">The native document bytes.</param>
        /// <param name="native">The parsed native model.</param>
        /// <param name="fallback">The native canvas projection.</param>
        /// <returns>The current Studio projection or the native projection after an external edit.</returns>
        internal static TmForgeModelDto RestoreView(byte[] content, ThreatModel native, TmForgeModelDto fallback)
            => WithNativeThreatScopes(ReadState(ReadXml(content), native)?.Model ?? fallback, native);

        /// <summary>Writes a new TM7 while retaining presentation unavailable in MTMT's model.</summary>
        /// <param name="model">The prepared native document.</param>
        /// <param name="canvas">The authored canvas state.</param>
        /// <param name="output">The destination stream.</param>
        internal static void WriteNew(ThreatModel model, TmForgeModelDto canvas, Stream output)
        {
            ThreatModel projected = ModelDtoMapper.ToModel(canvas);
            Dictionary<Guid, TmForgePointDto> positions = projected.DrawingSurfaceList.ToDictionary(page => page.Guid, Anchor);
            Dictionary<Guid, TmForgePointDto> offsets = model.DrawingSurfaceList.ToDictionary(page => page.Guid, page => new TmForgePointDto
            {
                X = Anchor(page).X - positions[page.Guid].X,
                Y = Anchor(page).Y - positions[page.Guid].Y,
            });
            bool needsState = canvas.Analysis != null || offsets.Values.Any(offset => offset.X != 0 || offset.Y != 0)
                || (canvas.Diagrams?.SelectMany(page => page.Flows ?? Array.Empty<TmForgeFlowDto>()) ?? canvas.Flows ?? Array.Empty<TmForgeFlowDto>())
                    .Any(flow => flow.LabelOffset != null || flow.SourceHandle != null || flow.TargetHandle != null);
            if (!needsState)
            {
                model.Save(output);
                return;
            }

            XDocument document = Serialize(model);
            StudioState state = new StudioState
            {
                Fingerprint = Fingerprint(model), Model = canvas, Offsets = offsets,
            };
            document.Root!.Add(new XElement(StudioStateName, JsonSerializer.Serialize(state, StateOptions)));
            using XmlWriter writer = XmlWriter.Create(output, new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false), OmitXmlDeclaration = true, NewLineHandling = NewLineHandling.None, CloseOutput = false,
            });
            document.Save(writer);
        }

        private static void PreserveAddedDefinitions(ThreatModel target, ThreatModel saved)
        {
            if (saved.KnowledgeBase == null)
            {
                return;
            }

            if (target.KnowledgeBase == null)
            {
                target.KnowledgeBase = saved.KnowledgeBase;
                return;
            }

            foreach (ElementType type in saved.KnowledgeBase.GenericElements.Where(type => !target.KnowledgeBase.GenericElements.Any(existing => existing.Id == type.Id)))
            {
                target.KnowledgeBase.GenericElements.Add(type);
            }

            foreach (ElementType type in saved.KnowledgeBase.StandardElements.Where(type => !target.KnowledgeBase.StandardElements.Any(existing => existing.Id == type.Id)))
            {
                target.KnowledgeBase.StandardElements.Add(type);
            }

            foreach (ThreatType type in saved.KnowledgeBase.ThreatTypes.Where(type => !target.KnowledgeBase.ThreatTypes.Any(existing => existing.Id == type.Id)))
            {
                target.KnowledgeBase.ThreatTypes.Add(type);
            }

            foreach (ThreatCategory category in saved.KnowledgeBase.ThreatCategories.Where(category => !target.KnowledgeBase.ThreatCategories.Any(existing => existing.Id == category.Id)))
            {
                target.KnowledgeBase.ThreatCategories.Add(category);
            }
        }

        private static TmForgeModelDto WithNativeThreatScopes(TmForgeModelDto canvas, ThreatModel native)
        {
            IReadOnlyList<Note>? notes = native.Notes.Count > 0 ? native.Notes.ToArray() : canvas.Notes;
            if (canvas.Threats == null)
            {
                return WithThreats(canvas, null, notes);
            }

            Dictionary<string, Threat> register = native.AllThreatsDictionary.Values.Where(threat => !string.IsNullOrEmpty(threat.InteractionKey))
                .GroupBy(threat => threat.InteractionKey!, StringComparer.OrdinalIgnoreCase)
                .Where(group => group.Count() == 1).ToDictionary(group => group.Key, group => group.Single(), StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, Threat> entry in native.AllThreatsDictionary)
            {
                register.TryAdd(entry.Key, entry.Value);
            }

            ThreatStateDto[] threats = canvas.Threats.Select(entry =>
            {
                if (entry.Manual == true || ManualThreatId.IsManual(entry.Id) || !register.TryGetValue(entry.Id, out Threat? threat))
                {
                    return entry;
                }

                return new ThreatStateDto
                {
                    Id = entry.Id, State = entry.State, Manual = entry.Manual, Justification = entry.Justification,
                    Title = entry.Title, Category = entry.Category, Priority = entry.Priority, Description = entry.Description,
                    Mitigation = entry.Mitigation, Source = entry.Source,
                    ElementIds = ThreatScope(threat),
                };
            }).ToArray();
            return WithThreats(canvas, threats, notes);
        }

        private static string[] ThreatScope(Threat threat) => new[] { threat.SourceGuid, threat.TargetGuid, threat.FlowGuid }
            .Where(id => id != Guid.Empty).Select(id => id.ToString("D")).ToArray();

        private static TmForgeModelDto WithoutDeletedThreats(TmForgeModelDto canvas, HashSet<string> deleted)
        {
            if (deleted.Count == 0)
            {
                return canvas;
            }

            return WithThreats(canvas, canvas.Threats?.Where(threat => !deleted.Contains(threat.Id)).ToArray(), canvas.Notes);
        }

        private static TmForgeModelDto WithThreats(TmForgeModelDto canvas, IReadOnlyList<ThreatStateDto>? threats, IReadOnlyList<Note>? notes)
        {
            return new TmForgeModelDto
            {
                Schema = canvas.Schema, Version = canvas.Version, Metadata = canvas.Metadata, Notes = notes,
                Diagrams = canvas.Diagrams, Elements = canvas.Elements, Flows = canvas.Flows, Analysis = canvas.Analysis,
                Threats = threats,
            };
        }

        private static StudioState? ReadState(XDocument document, ThreatModel native)
        {
            XElement? element = document.Root?.Element(StudioStateName);
            if (element == null)
            {
                return null;
            }

            StudioState state;
            try
            {
                state = JsonSerializer.Deserialize<StudioState>(element.Value, StateOptions)
                    ?? throw new InvalidDataException("Invalid Studio state in TM7.");
            }
            catch (JsonException error)
            {
                throw new InvalidDataException("Invalid Studio state in TM7.", error);
            }

            if (state.Version != 1)
            {
                throw new NotSupportedException("This TM7 contains a newer Studio state version. Update tmforge to edit it without losing that state.");
            }

            if (state.Fingerprint != Fingerprint(native))
            {
                return null;
            }

            if (state.Model == null || state.Offsets == null || state.Offsets.Any(pair => pair.Value == null
                || Math.Abs((long)pair.Value.X) > 1000000 || Math.Abs((long)pair.Value.Y) > 1000000))
            {
                throw new InvalidDataException("Invalid Studio coordinates in TM7.");
            }

            ThreatModel projected = ModelDtoMapper.ToModel(state.Model);
            TranslateCoordinates(projected, state, 1);
            _ = Serialize(projected);
            TmForgeModelDto expected = ModelDtoMapper.ToDto(projected);
            TmForgeModelDto actual = ModelDtoMapper.ToDto(native);
            if (!Same(expected.Elements, actual.Elements) || !Same(expected.Flows, actual.Flows)
                || !Same(expected.Diagrams, actual.Diagrams) || !Same(expected.Metadata, actual.Metadata)
                || (state.Model.Notes != null && !Same(expected.Notes, actual.Notes)))
            {
                return null;
            }

            return state;
        }

        private static string Fingerprint(ThreatModel native)
        {
            using MemoryStream stream = new MemoryStream();
            native.Save(stream);
            return Convert.ToHexString(SHA256.HashData(stream.ToArray()));
        }

        private static object View(TmForgeModelDto model) => new
        {
            model.Analysis,
            Flows = (model.Diagrams?.SelectMany(page => page.Flows ?? Array.Empty<TmForgeFlowDto>()) ?? model.Flows ?? Array.Empty<TmForgeFlowDto>())
                .OrderBy(flow => flow.Id, StringComparer.Ordinal).Select(flow => new { flow.Id, flow.LabelOffset, flow.SourceHandle, flow.TargetHandle }),
        };

        private static TmForgePointDto Anchor(DrawingSurfaceModel page)
        {
            if (page.Borders.Values.OfType<DrawingElement>().FirstOrDefault() is DrawingElement box)
            {
                return new TmForgePointDto { X = box.Left, Y = box.Top };
            }

            LineElement? line = page.Lines.Values.OfType<LineElement>().FirstOrDefault();
            return new TmForgePointDto { X = line?.SourceX ?? 0, Y = line?.SourceY ?? 0 };
        }

        private static void TranslateCoordinates(ThreatModel native, StudioState? state, int direction)
        {
            foreach (DrawingSurfaceModel page in native.DrawingSurfaceList)
            {
                if (state == null || !state.Offsets.TryGetValue(page.Guid, out TmForgePointDto? offset) || offset == null)
                {
                    continue;
                }

                foreach (DrawingElement box in page.Borders.Values.OfType<DrawingElement>())
                {
                    box.Left = checked(box.Left + (direction * offset.X));
                    box.Top = checked(box.Top + (direction * offset.Y));
                }

                foreach (LineElement line in page.Lines.Values.OfType<LineElement>())
                {
                    line.HandleX = checked(line.HandleX + (direction * offset.X));
                    line.HandleY = checked(line.HandleY + (direction * offset.Y));
                    line.SourceX = checked(line.SourceX + (direction * offset.X));
                    line.SourceY = checked(line.SourceY + (direction * offset.Y));
                    line.TargetX = checked(line.TargetX + (direction * offset.X));
                    line.TargetY = checked(line.TargetY + (direction * offset.Y));
                }
            }
        }

        private static void ApplyPages(ThreatModel native, ThreatModel baseline, ThreatModel requested)
        {
            Dictionary<Guid, DrawingSurfaceModel> oldPages = baseline.DrawingSurfaceList.ToDictionary(page => page.Guid);
            Dictionary<Guid, DrawingSurfaceModel> nativePages = native.DrawingSurfaceList.ToDictionary(page => page.Guid);
            Dictionary<Guid, object> oldObjects = baseline.DrawingSurfaceList.SelectMany(page => page.Borders.Concat(page.Lines)).ToDictionary(pair => pair.Key, pair => pair.Value);
            Dictionary<Guid, object> nativeObjects = native.DrawingSurfaceList.SelectMany(page => page.Borders.Concat(page.Lines)).ToDictionary(pair => pair.Key, pair => pair.Value);
            List<DrawingSurfaceModel> orderedPages = new List<DrawingSurfaceModel>();
            foreach (DrawingSurfaceModel after in requested.DrawingSurfaceList)
            {
                if (!nativePages.TryGetValue(after.Guid, out DrawingSurfaceModel? page))
                {
                    page = new DrawingSurfaceModel { Guid = after.Guid, Header = after.Header };
                }

                if (!oldPages.TryGetValue(after.Guid, out DrawingSurfaceModel? before) || before.Header != after.Header)
                {
                    page.Header = after.Header;
                    DiagramElementHelper.SetName(page, after.Header ?? string.Empty);
                }

                ApplyObjects(page.Borders, oldObjects, nativeObjects, after.Borders);
                ApplyObjects(page.Lines, oldObjects, nativeObjects, after.Lines);
                UpdateConnectors(page, oldObjects, after);
                orderedPages.Add(page);
            }

            native.DrawingSurfaceList.Clear();
            foreach (DrawingSurfaceModel page in orderedPages)
            {
                native.DrawingSurfaceList.Add(page);
            }
        }

        private static void ApplyObjects(IDictionary<Guid, object> native, IDictionary<Guid, object> baseline, IDictionary<Guid, object> originals, IDictionary<Guid, object> requested)
        {
            foreach (Guid id in native.Keys.Where(id => baseline.ContainsKey(id) && !requested.ContainsKey(id)).ToArray())
            {
                native.Remove(id);
            }

            foreach (KeyValuePair<Guid, object> pair in requested)
            {
                if (originals.TryGetValue(pair.Key, out object? original) && !baseline.ContainsKey(pair.Key))
                {
                    throw new NotSupportedException("A new object collides with an unrepresented native object identity.");
                }

                native[pair.Key] = original ?? pair.Value;
            }

            foreach (KeyValuePair<Guid, object> pair in baseline.Where(pair => requested.ContainsKey(pair.Key)))
            {
                Entity before = (Entity)pair.Value;
                Entity after = (Entity)requested[pair.Key];
                Entity target = (Entity)native[pair.Key];
                if (before.GetType() != after.GetType())
                {
                    DrawingElement oldShape = (DrawingElement)target;
                    DrawingElement newShape = (DrawingElement)after;
                    newShape.StrokeDashArray = oldShape.StrokeDashArray;
                    newShape.StrokeThickness = oldShape.StrokeThickness;
                    newShape.Properties.Clear();
                    foreach (object property in oldShape.Properties)
                    {
                        newShape.Properties.Add(property);
                    }

                    target = newShape;
                    native[pair.Key] = newShape;
                }

                if (DiagramElementHelper.GetName(before) != DiagramElementHelper.GetName(after))
                {
                    DiagramElementHelper.SetName(target, DiagramElementHelper.GetName(after));
                }

                ApplyProperties(target, DiagramElementHelper.GetCustomProperties(before), DiagramElementHelper.GetCustomProperties(after));
                if (before is DrawingElement oldBox && after is DrawingElement newBox
                    && (oldBox.Left != newBox.Left || oldBox.Top != newBox.Top || oldBox.Width != newBox.Width || oldBox.Height != newBox.Height))
                {
                    DrawingElement box = (DrawingElement)target;
                    box.Left = newBox.Left;
                    box.Top = newBox.Top;
                    box.Width = newBox.Width;
                    box.Height = newBox.Height;
                }
            }

            Queue<KeyValuePair<Guid, object>> ordered = new Queue<KeyValuePair<Guid, object>>(
                requested.Keys.Select(id => new KeyValuePair<Guid, object>(id, native[id])));
            KeyValuePair<Guid, object>[] entries = native.Select(pair => requested.ContainsKey(pair.Key) ? ordered.Dequeue() : pair).ToArray();
            native.Clear();
            foreach (KeyValuePair<Guid, object> entry in entries)
            {
                native.Add(entry.Key, entry.Value);
            }
        }

        private static HashSet<string> RemoveDeletedScopes(ThreatModel model, HashSet<Guid> originalIds)
        {
            Dictionary<Guid, Guid> owners = model.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys)
                .Select(id => (Id: id, Page: page.Guid))).ToDictionary(item => item.Id, item => item.Page);
            originalIds.ExceptWith(owners.Keys.Concat(model.DrawingSurfaceList.Select(page => page.Guid)));
            Guid fallbackPage = model.DrawingSurfaceList.FirstOrDefault()?.Guid ?? Guid.Empty;
            HashSet<string> deleted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (KeyValuePair<string, Threat> entry in model.AllThreatsDictionary.ToArray())
            {
                Threat threat = entry.Value;
                Guid[] scope = new[] { threat.SourceGuid, threat.TargetGuid, threat.FlowGuid };
                Guid scoped = scope.FirstOrDefault(owners.ContainsKey);
                if (scope.Any(originalIds.Contains)
                    || (scoped == Guid.Empty && !threat.Wide && originalIds.Contains(threat.DrawingSurfaceGuid)))
                {
                    model.AllThreatsDictionary.Remove(entry.Key);
                    deleted.Add(entry.Key);
                    if (!string.IsNullOrEmpty(threat.InteractionKey))
                    {
                        deleted.Add(threat.InteractionKey);
                    }

                    continue;
                }

                if (owners.TryGetValue(scoped, out Guid page))
                {
                    threat.DrawingSurfaceGuid = page;
                }
                else if (threat.DrawingSurfaceGuid == Guid.Empty || originalIds.Contains(threat.DrawingSurfaceGuid))
                {
                    threat.DrawingSurfaceGuid = fallbackPage;
                }
            }

            return deleted;
        }

        private static void UpdateConnectors(DrawingSurfaceModel native, IDictionary<Guid, object> baseline, DrawingSurfaceModel requested)
        {
            foreach (Connector flow in native.Lines.Values.OfType<Connector>())
            {
                if (!baseline.TryGetValue(flow.Guid, out object? original))
                {
                    continue;
                }

                Connector before = (Connector)original;
                Connector after = (Connector)requested.Lines[flow.Guid];
                int sourceX = flow.SourceX;
                int sourceY = flow.SourceY;
                int targetX = flow.TargetX;
                int targetY = flow.TargetY;
                int handleX = flow.HandleX;
                int handleY = flow.HandleY;
                if (before.SourceGuid != after.SourceGuid)
                {
                    flow.SourceGuid = after.SourceGuid;
                    flow.SourceX = after.SourceX;
                    flow.SourceY = after.SourceY;
                    flow.PortSource = "None";
                }
                else
                {
                    (flow.SourceX, flow.SourceY) = MoveEndpoint(sourceX, sourceY, (DrawingElement)baseline[before.SourceGuid], (DrawingElement)requested.Borders[after.SourceGuid]);
                }

                if (before.TargetGuid != after.TargetGuid)
                {
                    flow.TargetGuid = after.TargetGuid;
                    flow.TargetX = after.TargetX;
                    flow.TargetY = after.TargetY;
                    flow.PortTarget = "None";
                }
                else
                {
                    (flow.TargetX, flow.TargetY) = MoveEndpoint(targetX, targetY, (DrawingElement)baseline[before.TargetGuid], (DrawingElement)requested.Borders[after.TargetGuid]);
                }

                if (sourceX != flow.SourceX || sourceY != flow.SourceY || targetX != flow.TargetX || targetY != flow.TargetY)
                {
                    flow.HandleX = handleX + ((flow.SourceX - sourceX + flow.TargetX - targetX) / 2);
                    flow.HandleY = handleY + ((flow.SourceY - sourceY + flow.TargetY - targetY) / 2);
                }
            }
        }

        private static (int X, int Y) MoveEndpoint(int positionX, int positionY, DrawingElement before, DrawingElement after)
        {
            if (before.Left == after.Left && before.Top == after.Top && before.Width == after.Width && before.Height == after.Height)
            {
                return (positionX, positionY);
            }

            return (
                after.Left + (int)Math.Round((positionX - before.Left) * (double)after.Width / before.Width),
                after.Top + (int)Math.Round((positionY - before.Top) * (double)after.Height / before.Height));
        }

        private static void ApplyProperties(Entity target, IReadOnlyDictionary<string, string> before, IReadOnlyDictionary<string, string> after)
        {
            foreach (string key in before.Keys.Union(after.Keys, StringComparer.Ordinal))
            {
                before.TryGetValue(key, out string? previous);
                after.TryGetValue(key, out string? value);
                if (previous == value)
                {
                    continue;
                }

                List<ListDisplayAttribute> typed = target.Properties.OfType<ListDisplayAttribute>()
                    .Where(property => string.Equals(property.DisplayName, key, StringComparison.OrdinalIgnoreCase)).ToList();
                foreach (ListDisplayAttribute property in typed)
                {
                    List<string> options = property.Value is string[] values ? values.ToList() : new List<string>();
                    string selected = value ?? "Select";
                    int index = options.FindIndex(option => string.Equals(option, selected, StringComparison.OrdinalIgnoreCase));
                    if (index < 0)
                    {
                        index = options.Count;
                        options.Add(selected);
                    }

                    property.Value = options.ToArray();
                    property.SelectedIndex = index;
                }

                CustomStringDisplayAttribute[] custom = target.Properties.OfType<CustomStringDisplayAttribute>()
                    .Where(property => (property.Value as string ?? string.Empty).StartsWith(key + ":", StringComparison.OrdinalIgnoreCase)).ToArray();
                foreach (CustomStringDisplayAttribute property in custom)
                {
                    if (value == null)
                    {
                        target.Properties.Remove(property);
                    }
                    else
                    {
                        property.Value = key + ":" + value;
                    }
                }

                if (value != null && typed.Count == 0 && custom.Length == 0)
                {
                    DiagramElementHelper.SetCustomProperty(target, key, value);
                }
            }
        }

        private static void ApplyThreats(ThreatModel native, IReadOnlyList<ThreatStateDto>? baseline, IReadOnlyList<ThreatStateDto>? edited, ThreatModel requested, RuleSet rules, IReadOnlyList<string> ruleErrors, HashSet<string> removals)
        {
            if (Same(baseline, edited))
            {
                return;
            }

            Dictionary<string, ThreatStateDto> before = (baseline ?? Array.Empty<ThreatStateDto>()).ToDictionary(threat => threat.Id, StringComparer.Ordinal);
            Dictionary<string, ThreatStateDto> after = (edited ?? Array.Empty<ThreatStateDto>()).ToDictionary(threat => threat.Id, StringComparer.Ordinal);
            HashSet<string> generatedEdits = after.Values.Where(entry => !ManualThreatId.IsManual(entry.Id)
                && (!before.TryGetValue(entry.Id, out ThreatStateDto? previous) || !Same(previous, entry)))
                .Select(entry => entry.Id).ToHashSet(StringComparer.Ordinal);
            if (generatedEdits.Count > 0)
            {
                if (ruleErrors.Count > 0 && generatedEdits.Any(id => !native.AllThreatsDictionary.Any(pair => pair.Key == id || pair.Value.InteractionKey == id)))
                {
                    throw new InvalidDataException(string.Join(" ", ruleErrors));
                }

                if (ruleErrors.Count == 0)
                {
                    GenerationResult generated = ThreatGenerator.Generate(native, rules);
                    GeneratedThreat[] selected = generated.Threats.Where(threat => generatedEdits.Contains(threat.Id)).ToArray();
                    if (selected.Length > 0)
                    {
                        ThreatGenerator.Apply(native, new GenerationResult(selected));
                    }
                }
            }

            foreach (string id in before.Keys.Union(after.Keys, StringComparer.Ordinal).Where(id => !removals.Contains(id)))
            {
                before.TryGetValue(id, out ThreatStateDto? oldEntry);
                after.TryGetValue(id, out ThreatStateDto? newEntry);
                if (Same(oldEntry, newEntry))
                {
                    continue;
                }

                KeyValuePair<string, Threat>[] matches = native.AllThreatsDictionary
                    .Where(pair => pair.Key == id || pair.Value.InteractionKey == id).ToArray();
                if (matches.Length > 1)
                {
                    throw new NotSupportedException("The native register contains an ambiguous threat identity: " + id);
                }

                bool manual = ManualThreatId.IsManual(id);
                if (newEntry == null && manual)
                {
                    native.AllThreatsDictionary.Remove(matches.Single().Key);
                    continue;
                }

                newEntry ??= new ThreatStateDto { Id = id };
                if (newEntry.Manual == true && !manual)
                {
                    throw new NotSupportedException("A generated native threat cannot be changed into a manual threat.");
                }

                if (matches.Length == 0)
                {
                    if (!manual || !ManualThreatId.TryCanonicalize(id, out string? canonical, out _) || canonical != id)
                    {
                        throw new InvalidDataException("The selected threat is not produced by the active rules for this model. Analyze again before saving its decision.");
                    }

                    Threat added = requested.AllThreatsDictionary[id];
                    ValidateThreatScope(native, added);
                    added.Id = native.AllThreatsDictionary.Count == 0 ? 1 : native.AllThreatsDictionary.Values.Max(threat => threat.Id) + 1;
                    native.AllThreatsDictionary.Add(id, added);
                    continue;
                }

                Threat target = matches[0].Value;
                oldEntry ??= new ThreatStateDto { Id = id };
                if (oldEntry.State != newEntry.State)
                {
                    target.State = ThreatStateWire.Parse(newEntry.State);
                }

                if (oldEntry.Justification != newEntry.Justification)
                {
                    target.StateInformation = newEntry.Justification ?? string.Empty;
                }

                if (oldEntry.Title != newEntry.Title)
                {
                    target.Title = newEntry.Title ?? (manual ? string.Empty : GeneratedDefault(native, target, "GeneratedDefaultTitle"));
                    SetThreatProperty(target, "TitleOverride", manual || newEntry.Title == null ? null : "true");
                }

                if (oldEntry.Priority != newEntry.Priority)
                {
                    target.Priority = newEntry.Priority ?? (manual ? string.Empty : GeneratedDefault(native, target, "GeneratedDefaultPriority"));
                    SetThreatProperty(target, "PriorityOverride", manual || newEntry.Priority == null ? null : "true");
                }

                if (oldEntry.Category != newEntry.Category)
                {
                    if (!manual)
                    {
                        throw new NotSupportedException("The category of a generated native threat belongs to its template.");
                    }

                    target.UserThreatCategory = newEntry.Category;
                }

                if (oldEntry.Description != newEntry.Description)
                {
                    target.UserThreatDescription = newEntry.Description ?? string.Empty;
                }

                if (oldEntry.Mitigation != newEntry.Mitigation)
                {
                    SetThreatProperty(target, "Mitigation", newEntry.Mitigation);
                }

                if (!manual && newEntry.ElementIds?.Count > 0 && !Same(newEntry.ElementIds, ThreatScope(target)))
                {
                    throw new InvalidDataException("The scope of a generated threat belongs to the rule that detected it.");
                }

                if (manual && !Same(oldEntry.ElementIds, newEntry.ElementIds))
                {
                    Threat scoped = requested.AllThreatsDictionary[id];
                    ValidateThreatScope(native, scoped);
                    target.SourceGuid = scoped.SourceGuid;
                    target.TargetGuid = scoped.TargetGuid;
                    target.FlowGuid = scoped.FlowGuid;
                    target.DrawingSurfaceGuid = scoped.DrawingSurfaceGuid;
                    target.Wide = scoped.Wide;
                }

                if (!Same(oldEntry.Source, newEntry.Source))
                {
                    IReadOnlyDictionary<string, string> previousSource = oldEntry.Source ?? new Dictionary<string, string>();
                    IReadOnlyDictionary<string, string> nextSource = newEntry.Source ?? new Dictionary<string, string>();
                    foreach (string key in previousSource.Keys.Union(nextSource.Keys, StringComparer.Ordinal))
                    {
                        nextSource.TryGetValue(key, out string? value);
                        SetThreatProperty(target, "Source." + key, value);
                    }
                }

                target.ModifiedAt = DateTime.UtcNow;
            }
        }

        private static void ValidateThreatScope(ThreatModel model, Threat threat)
        {
            HashSet<Guid> ids = model.DrawingSurfaceList.SelectMany(page => page.Borders.Keys.Concat(page.Lines.Keys)).ToHashSet();
            if (new[] { threat.SourceGuid, threat.TargetGuid, threat.FlowGuid }.Any(id => id != Guid.Empty && !ids.Contains(id)))
            {
                throw new NotSupportedException("A new native threat must reference objects present in the document.");
            }
        }

        private static string GeneratedDefault(ThreatModel model, Threat threat, string key)
        {
            if (threat.Properties?.TryGetValue(key, out string? value) == true)
            {
                return value;
            }

            ThreatType? type = model.KnowledgeBase?.ThreatTypes.FirstOrDefault(item => string.Equals(item.Id, threat.TypeId, StringComparison.OrdinalIgnoreCase));
            string? declared = key == "GeneratedDefaultTitle" ? type?.ShortTitle
                : type?.PropertiesMetaData.FirstOrDefault(item => string.Equals(item.Name, "Priority", StringComparison.OrdinalIgnoreCase))?.Values.FirstOrDefault();
            return declared ?? throw new InvalidDataException("This threat has no recorded template default. Enter an explicit title or priority instead of clearing it.");
        }

        private static void SetThreatProperty(Threat threat, string key, string? value)
        {
            if (value == null)
            {
                threat.Properties?.Remove(key);
            }
            else
            {
                threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                threat.Properties[key] = value;
            }
        }

        private static bool Same<T>(T before, T after) => JsonElement.DeepEquals(JsonSerializer.SerializeToElement(before), JsonSerializer.SerializeToElement(after));

        private static XmlSchemaSet CreateNativeEnvelopeSchemas()
        {
            XmlSchema schema = new XmlSchema
            {
                TargetNamespace = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model",
                ElementFormDefault = XmlSchemaForm.Qualified,
            };
            schema.Items.Add(new XmlSchemaElement
            {
                Name = "ThreatModel",
                SchemaType = new XmlSchemaComplexType
                {
                    Particle = new XmlSchemaSequence
                    {
                        Items = { new XmlSchemaAny { MinOccurs = 0, MaxOccursString = "unbounded", ProcessContents = XmlSchemaContentProcessing.Skip } },
                    },
                    AnyAttribute = new XmlSchemaAnyAttribute { ProcessContents = XmlSchemaContentProcessing.Skip },
                },
            });
            XmlSchemaSet schemas = new XmlSchemaSet { XmlResolver = null };
            schemas.Add(schema);
            schemas.Compile();
            return schemas;
        }

        private static XDocument ReadXml(byte[] content)
        {
            using MemoryStream stream = new MemoryStream(content, writable: false);
            XmlReaderSettings settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                ValidationType = ValidationType.Schema,
                ValidationFlags = XmlSchemaValidationFlags.ReportValidationWarnings,
                Schemas = NativeEnvelopeSchemas,
                MaxCharactersInDocument = JsonDocumentPreflight.MaxBytes,
                CloseInput = false,
            };
            settings.ValidationEventHandler += (sender, arguments) => throw arguments.Exception;
            try
            {
                using (XmlReader probe = XmlReader.Create(stream, settings))
                {
                    while (probe.Read())
                    {
                        if (probe.Depth > 128)
                        {
                            throw new InvalidDataException("Native TM7 XML exceeds the depth limit of 128.");
                        }
                    }
                }

                stream.Position = 0;
                using XmlReader reader = XmlReader.Create(stream, settings);
                return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
            }
            catch (Exception error) when (error is XmlException || error is XmlSchemaException)
            {
                throw new InvalidDataException("The native TM7 XML is invalid: " + error.Message, error);
            }
        }

        private static XDocument Serialize(ThreatModel model)
        {
            using MemoryStream output = new MemoryStream();
            model.Save(output);
            return ReadXml(output.ToArray());
        }

        private static void Patch(XElement retained, XElement before, XElement after, IReadOnlyDictionary<Guid, (XElement Source, XElement Before)>? originals = null)
        {
            if (XNode.DeepEquals(before, after))
            {
                return;
            }

            if (originals == null)
            {
                Dictionary<Guid, XElement> sourceObjects = retained.DescendantsAndSelf().Where(element => ObjectId(element).HasValue)
                    .ToDictionary(element => ObjectId(element).GetValueOrDefault(), element => CopyWithNamespaces(element));
                originals = before.DescendantsAndSelf().Where(element => ObjectId(element).HasValue && sourceObjects.ContainsKey(ObjectId(element).GetValueOrDefault()))
                    .ToDictionary(element => ObjectId(element).GetValueOrDefault(), element => (sourceObjects[ObjectId(element).GetValueOrDefault()], element));
            }

            foreach (XName name in before.Attributes().Concat(after.Attributes()).Where(attribute => !attribute.IsNamespaceDeclaration)
                .Select(attribute => attribute.Name).Distinct().Where(name => before.Attribute(name)?.Value != after.Attribute(name)?.Value))
            {
                if (name == Instance + "type" && after.Attribute(name) is XAttribute type)
                {
                    string[] parts = type.Value.Split(':');
                    XNamespace typeNamespace = parts.Length == 2
                        ? after.GetNamespaceOfPrefix(parts[0]) ?? throw new InvalidDataException("Unresolved XML type namespace.")
                        : after.GetDefaultNamespace();
                    string prefix = retained.GetPrefixOfNamespace(typeNamespace) ?? string.Empty;
                    if (prefix.Length == 0)
                    {
                        int suffix = 0;
                        do
                        {
                            prefix = "native" + suffix++.ToString(CultureInfo.InvariantCulture);
                        }
                        while (retained.GetNamespaceOfPrefix(prefix) != null);
                        retained.SetAttributeValue(XNamespace.Xmlns + prefix, typeNamespace.NamespaceName);
                    }

                    retained.SetAttributeValue(name, prefix + ":" + parts[^1]);
                }
                else
                {
                    retained.SetAttributeValue(name, after.Attribute(name)?.Value);
                }
            }

            if (!before.HasElements && !after.HasElements)
            {
                if (before.Value != after.Value)
                {
                    if (retained.HasElements)
                    {
                        throw new NotSupportedException("An edited native value contains unrecognized XML that cannot be replaced safely.");
                    }

                    retained.Value = after.Value;
                }

                return;
            }

            Dictionary<string, XElement> oldChildren = Children(before);
            Dictionary<string, XElement> newChildren = Children(after);
            Dictionary<string, XElement> retainedChildren = Children(retained);
            foreach (KeyValuePair<string, XElement> child in oldChildren)
            {
                if (!retainedChildren.TryGetValue(child.Key, out XElement? originalChild))
                {
                    if (newChildren.TryGetValue(child.Key, out XElement? unchanged) && XNode.DeepEquals(child.Value, unchanged))
                    {
                        continue;
                    }

                    throw new NotSupportedException("The native XML identity of an edited field could not be matched safely.");
                }

                if (newChildren.TryGetValue(child.Key, out XElement? replacement))
                {
                    Patch(originalChild, child.Value, replacement, originals);
                }
                else
                {
                    originalChild.Remove();
                    retainedChildren.Remove(child.Key);
                }
            }

            XElement? previous = null;
            foreach (KeyValuePair<string, XElement> child in newChildren)
            {
                if (!oldChildren.ContainsKey(child.Key))
                {
                    XElement added = CopyPreserved(child.Value, originals);
                    if (previous != null)
                    {
                        previous.AddAfterSelf(added);
                    }
                    else
                    {
                        retained.AddFirst(added);
                    }

                    retainedChildren[child.Key] = added;
                }

                retainedChildren.TryGetValue(child.Key, out previous);
            }

            if (!oldChildren.Keys.Where(newChildren.ContainsKey).SequenceEqual(newChildren.Keys.Where(oldChildren.ContainsKey)))
            {
                List<XElement> ordered = newChildren.Keys.Where(retainedChildren.ContainsKey).Select(key => retainedChildren[key]).ToList();
                List<XComment> slots = new List<XComment>();
                foreach (XElement child in retained.Elements().Where(ordered.Contains).ToArray())
                {
                    XComment slot = new XComment("native-order");
                    child.ReplaceWith(slot);
                    slots.Add(slot);
                }

                for (int index = 0; index < slots.Count; index++)
                {
                    slots[index].ReplaceWith(ordered[index]);
                }
            }
        }

        private static Guid? ObjectId(XElement element)
        {
            XNamespace abstracts = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts";
            return Guid.TryParse(element.Element(abstracts + "Guid")?.Value, out Guid id) ? id : null;
        }

        private static XElement CopyPreserved(XElement source, IReadOnlyDictionary<Guid, (XElement Source, XElement Before)> originals)
        {
            if (ObjectId(source) is Guid id && originals.TryGetValue(id, out (XElement Source, XElement Before) original))
            {
                XElement retained = CopyWithNamespaces(original.Source);
                Patch(retained, original.Before, source, originals);
                return retained;
            }

            XElement copy = CopyWithNamespaces(source);
            foreach ((XElement before, XElement after) in source.Elements().Zip(copy.Elements().ToArray()))
            {
                after.ReplaceWith(CopyPreserved(before, originals));
            }

            return copy;
        }

        private static Dictionary<string, XElement> Children(XElement parent)
        {
            Dictionary<string, XElement> children = new Dictionary<string, XElement>(StringComparer.Ordinal);
            Dictionary<string, int> counts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (XElement child in parent.Elements())
            {
                string identity = child.Name.ToString();
                XElement? key = child.Elements().FirstOrDefault(element => element.Name == child.Name.Namespace + "Key")
                    ?? child.Elements().FirstOrDefault(element => element.Name.LocalName == "Guid" && element.Name.NamespaceName == "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts")
                    ?? (child.Name == XNamespace.Get("http://schemas.datacontract.org/2004/07/ThreatModeling.Model") + "Note"
                        ? child.Element(child.Name.Namespace + "Id") : null);
                if (key != null)
                {
                    identity += ":" + (Guid.TryParse(key.Value, out Guid guid) ? guid.ToString("D") : key.Value);
                }
                else if (child.Name.LocalName == "anyType")
                {
                    XNamespace knowledge = "http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase";
                    string name = child.Element(knowledge + "Name")?.Value ?? string.Empty;
                    string display = child.Element(knowledge + "DisplayName")?.Value ?? string.Empty;
                    string value = child.Element(knowledge + "Value")?.Value ?? string.Empty;
                    string type = child.Attribute(Instance + "type")?.Value.Split(':').Last() ?? string.Empty;
                    identity += ":" + type + ":" + name + ":" + display;
                    if (type == "CustomStringDisplayAttribute")
                    {
                        identity += ":" + value.Split(':')[0];
                    }
                }

                counts.TryGetValue(identity, out int occurrence);
                counts[identity] = occurrence + 1;
                children.Add(identity + "#" + occurrence.ToString(CultureInfo.InvariantCulture), child);
            }

            return children;
        }

        private static XElement CopyWithNamespaces(XElement source)
        {
            XElement copy = new XElement(source);
            foreach (XElement ancestor in source.Ancestors())
            {
                foreach (XAttribute declaration in ancestor.Attributes().Where(attribute => attribute.IsNamespaceDeclaration && copy.Attribute(attribute.Name) == null))
                {
                    copy.Add(new XAttribute(declaration));
                }
            }

            return copy;
        }

        private sealed class StudioState
        {
            public int Version { get; init; } = 1;

            public string Fingerprint { get; init; } = string.Empty;

            public TmForgeModelDto? Model { get; init; }

            public Dictionary<Guid, TmForgePointDto> Offsets { get; init; } = new Dictionary<Guid, TmForgePointDto>();
        }
    }
}
