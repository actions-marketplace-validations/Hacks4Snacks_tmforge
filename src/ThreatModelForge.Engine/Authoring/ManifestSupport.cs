namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.Linq;
    using System.Text.Json;
    using System.Text.Json.Serialization;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Builds a <see cref="ThreatModel"/> from a declarative <see cref="Manifest"/> (for
    /// <c>tmforge apply</c>) and extracts a manifest from a model (for <c>tmforge export</c>). The
    /// build is all-or-nothing: it reports the first blocking problem and produces no partial model,
    /// so the caller can write atomically. Element references (aliases, unique names) and boundary
    /// membership reuse the same resolution the imperative verbs use.
    /// </summary>
    public static class ManifestSupport
    {
        /// <summary>The page a manifest builds onto. Also the key its deterministic id derives from.</summary>
        private const string DefaultPageName = "Diagram 1";

        private static readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = true,
        };

        /// <summary>Deserializes a manifest from JSON text.</summary>
        /// <param name="json">The manifest JSON.</param>
        /// <returns>The manifest, or <see langword="null"/> when the JSON is the literal <c>null</c>.</returns>
        public static Manifest? Deserialize(string json)
        {
            return JsonSerializer.Deserialize<Manifest>(json, SerializerOptions);
        }

        /// <summary>
        /// Reports whether document text positively declares itself an authoring manifest, so a caller
        /// holding an unidentified file can route it here instead of reporting it unreadable.
        /// <para>
        /// Recognition deliberately requires an explicit <c>schema</c>, where <see cref="TryRead"/>
        /// accepts the concise pre-envelope form. The two differ because they answer different
        /// questions: <c>TryRead</c> is told the document is a manifest, while this decides. Every
        /// member of the manifest DTO is optional, so accepting an absent envelope here would claim
        /// any JSON document — and then build it into an empty model.
        /// </para>
        /// </summary>
        /// <param name="json">The candidate document text.</param>
        /// <returns><see langword="true"/> when the document declares the manifest schema.</returns>
        public static bool LooksLikeManifest(string? json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return false;
            }

            try
            {
                using (JsonDocument probe = JsonDocument.Parse(json))
                {
                    return probe.RootElement.ValueKind == JsonValueKind.Object
                        && TryFindProperty(probe.RootElement, "schema", out JsonElement schema)
                        && schema.ValueKind == JsonValueKind.String
                        && string.Equals(schema.GetString(), Manifest.SchemaName, StringComparison.Ordinal);
                }
            }
            catch (JsonException)
            {
                return false;
            }
        }

        /// <summary>
        /// Reads a manifest and checks this build can interpret it. A manifest that declares no
        /// envelope is read as the current version: the shape predates the envelope and is still the
        /// documented concise form, so requiring one would break every manifest already written.
        /// </summary>
        /// <param name="json">The manifest JSON.</param>
        /// <param name="manifest">On success, the parsed manifest.</param>
        /// <param name="error">On failure, why the manifest was refused.</param>
        /// <returns><see langword="true"/> when the manifest was read.</returns>
        public static bool TryRead(string json, [NotNullWhen(true)] out Manifest? manifest, out string? error)
        {
            manifest = null;
            error = null;

            try
            {
                // Checked against the raw JSON rather than the deserialized object, because the DTO
                // supplies defaults: a file declaring a foreign schema would still deserialize into
                // something that looks like a valid manifest. This is the same trap the analysis
                // document reader documents.
                using (JsonDocument probe = JsonDocument.Parse(json))
                {
                    if (!CheckEnvelope(probe.RootElement, out error))
                    {
                        return false;
                    }
                }

                manifest = JsonSerializer.Deserialize<Manifest>(json, SerializerOptions);
            }
            catch (JsonException ex)
            {
                error = "The manifest is not valid JSON: " + ex.Message;
                return false;
            }

            if (manifest == null)
            {
                error = "The manifest is empty.";
                return false;
            }

            return true;
        }

        /// <summary>Serializes a manifest to indented, camelCase JSON.</summary>
        /// <param name="manifest">The manifest to serialize.</param>
        /// <returns>The JSON text.</returns>
        public static string Serialize(Manifest manifest)
        {
            return JsonSerializer.Serialize(manifest, SerializerOptions);
        }

        /// <summary>
        /// Materializes a manifest into a model. Boundaries are laid out top to bottom and each element
        /// is placed inside its declared boundary (so trust-boundary crossings are computed correctly),
        /// with a deterministic id when it declares an alias.
        /// </summary>
        /// <param name="manifest">The manifest to build.</param>
        /// <param name="force">Whether to store unknown/invalid property values instead of rejecting them.</param>
        /// <param name="model">On success, the built model.</param>
        /// <param name="summary">On success, the counts of what was built.</param>
        /// <param name="error">On failure, a message describing the first blocking problem.</param>
        /// <returns><see langword="true"/> when the whole manifest was applied.</returns>
        public static bool Build(Manifest manifest, bool force, out ThreatModel model, out ManifestSummary summary, out string? error)
        {
            error = null;
            summary = default;
            model = new ThreatModel { Version = "1.0" };

            // Every identifier this method assigns is derived, never minted. Applying a manifest
            // rebuilds the whole model, so a fresh guid anywhere means two applies of one manifest
            // share no identity: finding ids (which embed the page and the target), threat-register
            // keys, and structural diffs all move even though nothing about the model changed.
            List<ManifestPage> pages = manifest.Pages is { Count: > 0 }
                ? manifest.Pages
                : new List<ManifestPage> { new ManifestPage { Name = DefaultPageName } };

            Dictionary<string, PageContext> pagesByRef = new Dictionary<string, PageContext>(StringComparer.OrdinalIgnoreCase);
            List<PageContext> pageOrder = new List<PageContext>(pages.Count);
            foreach (ManifestPage page in pages)
            {
                string header = page.Name ?? page.Alias ?? DefaultPageName;
                string key = page.Alias ?? header;
                DrawingSurfaceModel surface = new DrawingSurfaceModel
                {
                    Guid = AuthoringSupport.DeterministicPageId(key),
                    Header = header,
                };

                PageContext context = new PageContext(surface);
                if (pagesByRef.ContainsKey(key))
                {
                    error = "Duplicate page '" + key + "'; pages must be uniquely referenceable.";
                    return false;
                }

                pagesByRef[key] = context;
                if (!string.IsNullOrEmpty(page.Alias) && !pagesByRef.ContainsKey(header))
                {
                    // Reachable by name too, so an element can say either.
                    pagesByRef[header] = context;
                }

                pageOrder.Add(context);
                model.DrawingSurfaceList.Add(surface);
            }

            if (!string.IsNullOrWhiteSpace(manifest.Name))
            {
                model.MetaInformation ??= new MetaInformation();
                model.MetaInformation.ThreatModelName = manifest.Name;
            }

            List<ManifestBoundary> boundaries = manifest.Boundaries ?? new List<ManifestBoundary>();
            List<ManifestElement> elements = manifest.Elements ?? new List<ManifestElement>();
            List<ManifestFlow> flows = manifest.Flows ?? new List<ManifestFlow>();

            DiagramEditor editor = new DiagramEditor(model);
            HashSet<Guid> aliasIds = new HashSet<Guid>();
            HashSet<string> structuralKeys = new HashSet<string>(StringComparer.Ordinal);

            // Only auto-placed members are counted: an explicitly placed one does not consume a grid
            // cell, so counting it would inflate every boundary that holds one.
            Dictionary<string, int> memberCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (ManifestElement element in elements.Where(element => !string.IsNullOrEmpty(element.Boundary) && !element.X.HasValue))
            {
                memberCounts.TryGetValue(element.Boundary!, out int count);
                memberCounts[element.Boundary!] = count + 1;
            }

            // Kinds are resolved before anything is created because a boundary has to be sized before
            // its members exist, and an explicitly placed member's size depends on its kind.
            List<ResolvedElement> resolved = new List<ResolvedElement>(elements.Count);
            foreach (ManifestElement element in elements)
            {
                if (!ValidateGeometry(element.X, element.Y, element.Width, element.Height, Describe(element), out error) ||
                    !TryResolveKind(element, out StencilKind kind, out StencilDto? stencil, out error))
                {
                    return false;
                }

                resolved.Add(new ResolvedElement(element, kind, stencil));
            }

            // An explicitly placed member constrains the boundary holding it: an auto-sized boundary
            // grows to contain it rather than clipping it, and an explicitly sized one is checked
            // against it below. Clipping would silently move the member out of the boundary, which
            // changes which trust boundaries its flows cross — an analysis change, not a drawing one.
            Dictionary<string, Rect> memberExtents = new Dictionary<string, Rect>(StringComparer.OrdinalIgnoreCase);
            foreach (ResolvedElement entry in resolved)
            {
                if (string.IsNullOrEmpty(entry.Element.Boundary) || !entry.Element.X.HasValue)
                {
                    continue;
                }

                Rect rect = entry.PlacedBounds();
                memberExtents[entry.Element.Boundary!] = memberExtents.TryGetValue(entry.Element.Boundary!, out Rect seen)
                    ? Rect.Union(seen, rect)
                    : rect;
            }

            Dictionary<string, BoundaryBox> boxes = new Dictionary<string, BoundaryBox>(StringComparer.OrdinalIgnoreCase);
            foreach (ManifestBoundary boundary in boundaries)
            {
                if (!ValidateGeometry(boundary.X, boundary.Y, boundary.Width, boundary.Height, Describe(boundary), out error) ||
                    !TryResolvePage(boundary.Page, pagesByRef, pageOrder, Describe(boundary), out PageContext page, out error))
                {
                    return false;
                }

                DrawingSurfaceModel surface = page.Surface;
                int members = !string.IsNullOrEmpty(boundary.Alias) && memberCounts.TryGetValue(boundary.Alias!, out int m) ? m : 0;
                int rows = Math.Max(1, (members + 2) / 3);
                int columns = Math.Min(Math.Max(members, 1), 3);
                int gridWidth = 24 + (columns * 120) + 24;
                int gridHeight = 48 + (rows * 84) + 24;
                Rect bounds = new Rect(
                    boundary.X ?? 40,
                    boundary.Y ?? page.CursorY,
                    boundary.Width ?? (24 + (3 * 120) + 24),
                    boundary.Height ?? gridHeight);

                bool sizeWasDeclared = boundary.Width.HasValue;

                // A fixed boundary that cannot hold the members it has to lay out is the one case where
                // honouring the manifest is impossible: the grid would place them outside the box the
                // author drew. Explicitly placed members are not checked — nothing is being clipped
                // there, both objects go exactly where they were asked to, and a member sitting outside
                // a boundary it claims membership of is a modelling question rather than a layout
                // failure. Refusing it would make an exported diagram impossible to re-apply.
                if (sizeWasDeclared && members > 0 && (bounds.Width < gridWidth || bounds.Height < gridHeight))
                {
                    error = Describe(boundary) + " is fixed at " + bounds + " but has to lay out " +
                        members.ToString(CultureInfo.InvariantCulture) + " member(s), which need at least " +
                        gridWidth.ToString(CultureInfo.InvariantCulture) + "x" +
                        gridHeight.ToString(CultureInfo.InvariantCulture) +
                        ". Enlarge it, place those members explicitly, or drop its size to have it fit them.";
                    return false;
                }

                if (!sizeWasDeclared &&
                    !string.IsNullOrEmpty(boundary.Alias) &&
                    memberExtents.TryGetValue(boundary.Alias!, out Rect extent))
                {
                    bounds = Rect.Union(bounds, Grow(extent, 24));
                }

                Guid id = editor.AddElement(surface, StencilKind.TrustBoundary, bounds.X, bounds.Y);
                editor.ResizeElement(surface, id, bounds.X, bounds.Y, bounds.Width, bounds.Height);
                Entity? boundaryEntity = DiagramEditor.FindElement(surface, id);
                if (boundaryEntity != null && !string.IsNullOrWhiteSpace(boundary.Name))
                {
                    DiagramElementHelper.SetName(boundaryEntity, boundary.Name!);
                }

                if (!string.IsNullOrEmpty(boundary.Alias))
                {
                    if (!TryAssignAlias(surface, id, boundary.Alias!, aliasIds, out _, out error))
                    {
                        return false;
                    }

                    boxes[boundary.Alias!] = new BoundaryBox(bounds, sizeWasDeclared);
                }
                else
                {
                    AuthoringSupport.RekeyComponent(surface, id, StructuralId("boundary:" + boundary.Name, structuralKeys));
                }

                page.CursorY = bounds.Bottom + 40;
            }

            foreach (ResolvedElement entry in resolved)
            {
                ManifestElement element = entry.Element;
                StencilKind kind = entry.Kind;
                StencilDto? stencil = entry.Stencil;
                if (!TryResolvePage(element.Page, pagesByRef, pageOrder, Describe(element), out PageContext page, out error))
                {
                    return false;
                }

                DrawingSurfaceModel surface = page.Surface;
                int unassigned = page.Unassigned;
                (int ex, int ey) = element.X.HasValue
                    ? (element.X.Value, element.Y!.Value)
                    : NextElementPosition(element.Boundary, boxes, ref unassigned, page.CursorY);
                page.Unassigned = unassigned;
                Guid id = editor.AddElement(surface, kind, ex, ey);
                Entity? added = DiagramEditor.FindElement(surface, id);
                if (added == null)
                {
                    error = "Failed to create element.";
                    return false;
                }

                if (element.Width.HasValue)
                {
                    editor.ResizeElement(surface, id, ex, ey, element.Width.Value, element.Height!.Value);
                }

                string? name = element.Name ?? stencil?.Label;
                if (!string.IsNullOrEmpty(name))
                {
                    DiagramElementHelper.SetName(added, name!);
                }

                if (stencil != null)
                {
                    DiagramElementHelper.SetCustomProperty(added, "StencilType", stencil.Id);
                    foreach (KeyValuePair<string, string> preset in stencil.Defaults)
                    {
                        DiagramElementHelper.SetCustomProperty(added, preset.Key, preset.Value);
                    }
                }

                if (!string.IsNullOrEmpty(element.Boundary))
                {
                    DiagramElementHelper.SetCustomProperty(added, AuthoringSupport.BoundaryPropertyName, element.Boundary!);
                }

                if (element.Props != null && element.Props.Count > 0 &&
                    !AuthoringSupport.TryApplyProperties(added, ToAssignments(element.Props), AuthoringSupport.SchemaBase(kind), force, out error, out _))
                {
                    return false;
                }

                if (!string.IsNullOrEmpty(element.Alias) && !TryAssignAlias(surface, id, element.Alias!, aliasIds, out _, out error))
                {
                    return false;
                }

                if (string.IsNullOrEmpty(element.Alias))
                {
                    AuthoringSupport.RekeyComponent(surface, id, StructuralId("element:" + name, structuralKeys));
                }
            }

            foreach (ManifestFlow flow in flows)
            {
                if (string.IsNullOrEmpty(flow.From) || string.IsNullOrEmpty(flow.To))
                {
                    error = "Each flow needs a 'from' and a 'to'.";
                    return false;
                }

                // A flow lives on one page, so both endpoints must be found on the same one. Resolving
                // against the whole model and drawing the connector on whichever page came first would
                // produce a connector whose endpoints are not on its own surface.
                PageContext? host = null;
                Guid source = Guid.Empty;
                Guid target = Guid.Empty;
                foreach (PageContext candidate in pageOrder)
                {
                    if (AuthoringSupport.TryResolveElementId(model, candidate.Surface, flow.From!, out Guid from, out _) &&
                        candidate.Surface.Borders.ContainsKey(from) &&
                        AuthoringSupport.TryResolveElementId(model, candidate.Surface, flow.To!, out Guid to, out _) &&
                        candidate.Surface.Borders.ContainsKey(to))
                    {
                        host = candidate;
                        source = from;
                        target = to;
                        break;
                    }
                }

                if (host == null)
                {
                    error = "Flow '" + (flow.Alias ?? flow.Name ?? flow.From + " -> " + flow.To) +
                        "' does not have both endpoints on one page. A flow cannot cross pages: '" + flow.From +
                        "' and '" + flow.To + "' must be drawn on the same one.";
                    return false;
                }

                DrawingSurfaceModel surface = host.Surface;
                Guid id = editor.AddConnector(surface, source, target);
                Entity? connector = DiagramEditor.FindElement(surface, id);
                if (connector != null && !string.IsNullOrEmpty(flow.Name))
                {
                    DiagramElementHelper.SetName(connector, flow.Name!);
                }

                if (connector != null && flow.Props != null && flow.Props.Count > 0 &&
                    !AuthoringSupport.TryApplyProperties(connector, ToAssignments(flow.Props), "flow", force, out error, out _))
                {
                    return false;
                }

                if (!string.IsNullOrEmpty(flow.Alias))
                {
                    if (!TryAssignFlowAlias(surface, id, flow.Alias!, aliasIds, out error))
                    {
                        return false;
                    }
                }
                else
                {
                    string key = "flow:" + flow.From + ">" + flow.To + ":" + flow.Name;
                    AuthoringSupport.RekeyConnector(surface, id, StructuralId(key, structuralKeys));
                }
            }

            // Identifiers are derived, and every object is stored under its own. If two ever derived the
            // same one, the second would overwrite the first in the diagram's dictionaries and simply be
            // missing from the model while the summary below still counted it. Checking what was built
            // against what was declared turns that into a failure instead of silent loss.
            int expectedComponents = boundaries.Count + elements.Count;
            int builtComponents = pageOrder.Sum(page => page.Surface.Borders.Count);
            int builtConnectors = pageOrder.Sum(page => page.Surface.Lines.Count);
            if (builtComponents != expectedComponents || builtConnectors != flows.Count)
            {
                error = "Internal error: the manifest declared " + expectedComponents.ToString(CultureInfo.InvariantCulture) +
                    " components and " + flows.Count.ToString(CultureInfo.InvariantCulture) + " flows, but the model holds " +
                    builtComponents.ToString(CultureInfo.InvariantCulture) + " and " +
                    builtConnectors.ToString(CultureInfo.InvariantCulture) + ". Two objects resolved to one identifier.";
                return false;
            }

            // Shapes go exactly where the manifest asks, but a flow's label has no coordinates to
            // declare: the tool draws it on the connector, so two flows between one pair of elements
            // print their names on the same spot and a long name runs across whatever it passes over.
            // Placing the labels is therefore the builder's job, not the author's. It moves only the
            // curve handles, which nothing in the analysis reads.
            foreach (PageContext page in pageOrder)
            {
                DiagramLabels.Deconflict(page.Surface);
            }

            summary = new ManifestSummary(boundaries.Count, elements.Count, flows.Count);
            return true;
        }

        /// <summary>
        /// Extracts a manifest from a model: boundaries, elements, and flows across every page, with
        /// each flow endpoint referenced by the element's alias (or name). Geometry is dropped, so the
        /// manifest stays a stable, review-friendly authoring source — see the overload for what that
        /// costs.
        /// </summary>
        /// <param name="model">The model to capture.</param>
        /// <returns>The extracted manifest.</returns>
        public static Manifest Extract(ThreatModel model) => Extract(model, includeGeometry: false);

        /// <summary>
        /// Extracts a manifest, optionally capturing where each object sits.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Geometry is off by default because the manifest's job is to be a reviewable source: layout
        /// churns whenever a diagram is tidied, and coordinates in the diff bury the property change
        /// somebody actually needs to read. Turn it on to round-trip a diagram that was laid out by
        /// hand, which is the case where dropping it silently loses work.
        /// </para>
        /// <para>
        /// That default is a deliberate trade, not a free one. Trust-boundary containment is derived
        /// from geometry, so re-applying a manifest extracted without it re-runs automatic placement
        /// and can change which boundaries a flow crosses. Measured on the sample model, a concise
        /// round trip moved three flows across boundaries while a round trip with geometry reported no
        /// differences at all. Prefer the geometry form whenever the result will be analysed rather
        /// than only read.
        /// </para>
        /// </remarks>
        /// <param name="model">The model to capture.</param>
        /// <param name="includeGeometry">Whether to record positions and sizes.</param>
        /// <returns>The extracted manifest.</returns>
        public static Manifest Extract(ThreatModel model, bool includeGeometry)
        {
            List<ManifestBoundary> boundaries = new List<ManifestBoundary>();
            List<ManifestElement> elements = new List<ManifestElement>();
            List<ManifestFlow> flows = new List<ManifestFlow>();

            // Pages are recorded only when there is more than one. A single-page model exports exactly
            // the shape it always has, so nothing that reads an existing manifest sees a new field.
            bool multiPage = model.DrawingSurfaceList.Count > 1;
            List<ManifestPage> pages = new List<ManifestPage>();

            foreach (DrawingSurfaceModel surface in model.DrawingSurfaceList)
            {
                string? pageRef = multiPage ? NullIfEmpty(surface.Header ?? string.Empty) : null;
                if (multiPage)
                {
                    pages.Add(new ManifestPage { Name = pageRef });
                }

                foreach (Entity entity in surface.Borders.Values.OfType<Entity>())
                {
                    IReadOnlyDictionary<string, string> props = DiagramElementHelper.GetCustomProperties(entity);
                    string? alias = props.TryGetValue(AuthoringSupport.AliasPropertyName, out string? a) ? a : null;
                    string name = DiagramElementHelper.GetName(entity);
                    if (entity is BorderBoundary)
                    {
                        (int? bx, int? by, int? bw, int? bh) = GeometryOf(entity, includeGeometry);
                        boundaries.Add(new ManifestBoundary
                        {
                            Alias = alias,
                            Name = NullIfEmpty(name),
                            Page = pageRef,
                            X = bx,
                            Y = by,
                            Width = bw,
                            Height = bh,
                        });
                        continue;
                    }

                    Dictionary<string, string> userProps = FilterProps(props);
                    (int? ex, int? ey, int? ew, int? eh) = GeometryOf(entity, includeGeometry);
                    elements.Add(new ManifestElement
                    {
                        Alias = alias,
                        Kind = KindNoun(entity),
                        Name = NullIfEmpty(name),
                        Stencil = props.TryGetValue("StencilType", out string? stencil) ? stencil : null,
                        Boundary = props.TryGetValue(AuthoringSupport.BoundaryPropertyName, out string? boundary) ? boundary : null,
                        Page = pageRef,
                        Props = userProps.Count > 0 ? userProps : null,
                        X = ex,
                        Y = ey,
                        Width = ew,
                        Height = eh,
                    });
                }

                foreach (Connector connector in surface.Lines.Values.OfType<Connector>())
                {
                    IReadOnlyDictionary<string, string> connectorProps = DiagramElementHelper.GetCustomProperties(connector);
                    Dictionary<string, string> userProps = FilterProps(connectorProps);
                    flows.Add(new ManifestFlow
                    {
                        Alias = connectorProps.TryGetValue(AuthoringSupport.AliasPropertyName, out string? flowAlias) ? flowAlias : null,
                        From = ReferenceFor(surface, connector.SourceGuid),
                        To = ReferenceFor(surface, connector.TargetGuid),
                        Name = NullIfEmpty(DiagramElementHelper.GetName(connector)),
                        Props = userProps.Count > 0 ? userProps : null,
                    });
                }
            }

            return new Manifest
            {
                Schema = Manifest.SchemaName,
                Version = Manifest.CurrentVersion,
                Name = NullIfEmpty(model.MetaInformation?.ThreatModelName ?? string.Empty),
                Pages = pages.Count > 0 ? pages : null,
                Boundaries = boundaries.Count > 0 ? boundaries : null,
                Elements = elements.Count > 0 ? elements : null,
                Flows = flows.Count > 0 ? flows : null,
            };
        }

        /// <summary>
        /// Checks the envelope against the raw JSON. A manifest with no <c>schema</c> is the concise
        /// form that predates the envelope and is read as the current version; one that names a
        /// different schema is refused rather than coerced, because a model or a rule pack would
        /// otherwise deserialize into an empty-looking manifest and apply as an empty model.
        /// </summary>
        private static bool CheckEnvelope(JsonElement root, out string? error)
        {
            error = null;
            if (root.ValueKind != JsonValueKind.Object)
            {
                error = "The manifest must be a JSON object.";
                return false;
            }

            if (!TryFindProperty(root, "schema", out JsonElement schema))
            {
                return true;
            }

            string declared = schema.ValueKind == JsonValueKind.String
                ? schema.GetString() ?? string.Empty
                : schema.ToString();
            if (!string.Equals(declared, Manifest.SchemaName, StringComparison.Ordinal))
            {
                error = "Expected a '" + Manifest.SchemaName + "' document but found '" + declared +
                    "'. Check that this is an authoring manifest rather than a model or a rule pack.";
                return false;
            }

            if (!TryFindProperty(root, "version", out JsonElement version))
            {
                return true;
            }

            if (version.ValueKind != JsonValueKind.Number || !version.TryGetInt32(out int declaredVersion))
            {
                error = "The manifest declares a non-numeric schema version.";
                return false;
            }

            if (declaredVersion > Manifest.CurrentVersion)
            {
                error = "The manifest declares schema version " +
                    declaredVersion.ToString(CultureInfo.InvariantCulture) +
                    ", which this build cannot read (it understands version " +
                    Manifest.CurrentVersion.ToString(CultureInfo.InvariantCulture) + "). Upgrade tmforge.";
                return false;
            }

            if (declaredVersion < 1)
            {
                error = "The manifest declares an invalid schema version: " +
                    declaredVersion.ToString(CultureInfo.InvariantCulture) + ".";
                return false;
            }

            return true;
        }

        /// <summary>Finds a top-level property by name, matching the reader's case-insensitivity.</summary>
        private static bool TryFindProperty(JsonElement root, string name, out JsonElement value)
        {
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }

            value = default;
            return false;
        }

        /// <summary>
        /// Resolves the page an object names, defaulting to the first declared page so a manifest that
        /// never mentions pages behaves exactly as it did before pages existed.
        /// </summary>
        private static bool TryResolvePage(
            string? reference,
            Dictionary<string, PageContext> pagesByRef,
            List<PageContext> pageOrder,
            string what,
            out PageContext page,
            out string? error)
        {
            error = null;
            if (string.IsNullOrEmpty(reference))
            {
                page = pageOrder[0];
                return true;
            }

            if (pagesByRef.TryGetValue(reference!, out PageContext? found))
            {
                page = found;
                return true;
            }

            page = pageOrder[0];
            error = what + " names page '" + reference + "', which the manifest does not declare.";
            return false;
        }

        /// <summary>
        /// Rejects half-supplied geometry. A position or a size is only meaningful as a pair, and
        /// silently defaulting the missing half would place the object somewhere the author did not
        /// ask for while looking like it had been honoured.
        /// </summary>
        private static bool ValidateGeometry(int? x, int? y, int? width, int? height, string what, out string? error)
        {
            error = null;
            if (x.HasValue != y.HasValue)
            {
                error = what + " supplies only one of 'x' and 'y'. Give both or neither.";
                return false;
            }

            if (width.HasValue != height.HasValue)
            {
                error = what + " supplies only one of 'width' and 'height'. Give both or neither.";
                return false;
            }

            if (width is <= 0 || height is <= 0)
            {
                error = what + " has a width or height that is not positive.";
                return false;
            }

            return true;
        }

        /// <summary>Reads an object's rectangle, or nulls when geometry is not being captured.</summary>
        private static (int? X, int? Y, int? Width, int? Height) GeometryOf(Entity entity, bool includeGeometry)
            => includeGeometry && entity is DrawingElement drawing
                ? (drawing.Left, drawing.Top, drawing.Width, drawing.Height)
                : (null, null, null, null);

        /// <summary>Expands a rectangle by a margin on every side.</summary>
        private static Rect Grow(Rect rect, int margin)
            => new Rect(rect.X - margin, rect.Y - margin, rect.Width + (2 * margin), rect.Height + (2 * margin));

        /// <summary>Names an element in an error message, preferring whatever the author can search for.</summary>
        private static string Describe(ManifestElement element)
            => "Element '" + (element.Alias ?? element.Name ?? element.Kind ?? "(unnamed)") + "'";

        /// <summary>Names a boundary in an error message.</summary>
        private static string Describe(ManifestBoundary boundary)
            => "Boundary '" + (boundary.Alias ?? boundary.Name ?? "(unnamed)") + "'";

        private static bool TryResolveKind(ManifestElement element, out StencilKind kind, out StencilDto? stencil, out string? error)
        {
            error = null;
            stencil = null;
            if (!string.IsNullOrEmpty(element.Stencil))
            {
                stencil = StencilCatalog.Find(element.Stencil!);
                if (stencil == null)
                {
                    kind = StencilKind.Process;
                    error = "Unknown stencil: " + element.Stencil + " (run 'tmforge stencils').";
                    return false;
                }

                if (!AuthoringSupport.TryParseKind(stencil.Base, out kind))
                {
                    error = "Stencil '" + stencil.Id + "' has an unrecognized base primitive: " + stencil.Base + ".";
                    return false;
                }

                return true;
            }

            if (!string.IsNullOrEmpty(element.Kind))
            {
                if (!AuthoringSupport.TryParseKind(element.Kind!, out kind))
                {
                    error = "Unknown element kind: " + element.Kind + " (expected process, store, external, or boundary).";
                    return false;
                }

                return true;
            }

            kind = StencilKind.Process;
            error = "Each element needs a 'kind' or a 'stencil'.";
            return false;
        }

        private static bool TryAssignAlias(DrawingSurfaceModel diagram, Guid current, string alias, HashSet<Guid> used, out Guid assigned, out string? error)
        {
            error = null;
            Guid desired = AuthoringSupport.DeterministicId(alias);
            if (!used.Add(desired))
            {
                assigned = current;
                error = "Duplicate alias '" + alias + "'; aliases must be unique within a model.";
                return false;
            }

            Entity? entity = DiagramEditor.FindElement(diagram, current);
            if (entity != null)
            {
                DiagramElementHelper.SetCustomProperty(entity, AuthoringSupport.AliasPropertyName, alias);
            }

            AuthoringSupport.RekeyComponent(diagram, current, desired);
            assigned = desired;
            return true;
        }

        /// <summary>
        /// Gives a connector its deterministic id from a declared alias, mirroring <see cref="TryAssignAlias"/>.
        /// Flow aliases share the element alias space because both resolve through the same reference
        /// syntax, so a flow may not take an alias an element already holds.
        /// </summary>
        private static bool TryAssignFlowAlias(DrawingSurfaceModel diagram, Guid current, string alias, HashSet<Guid> used, out string? error)
        {
            error = null;
            Guid desired = AuthoringSupport.DeterministicId(alias);
            if (!used.Add(desired))
            {
                error = "Duplicate alias '" + alias + "'; aliases must be unique within a model.";
                return false;
            }

            if (DiagramEditor.FindElement(diagram, current) is Entity connector)
            {
                DiagramElementHelper.SetCustomProperty(connector, AuthoringSupport.AliasPropertyName, alias);
            }

            AuthoringSupport.RekeyConnector(diagram, current, desired);
            return true;
        }

        /// <summary>
        /// Derives an identifier for an object the manifest did not give an alias, from a structural
        /// key describing what the manifest does say about it. Two objects with the same key — two
        /// unnamed stores, two flows between one pair of elements — get an occurrence suffix, so the
        /// ids stay distinct and still land in the same order on the next apply.
        /// </summary>
        /// <remarks>
        /// This is a fallback, not a substitute for an alias: it is stable against re-applying the
        /// same manifest, but renaming an object or reordering same-keyed siblings moves the id.
        /// Declaring an alias is what makes an identity survive editing.
        /// </remarks>
        private static Guid StructuralId(string key, HashSet<string> used)
        {
            string unique = key;
            for (int occurrence = 2; !used.Add(unique); occurrence++)
            {
                unique = key + "#" + occurrence.ToString(CultureInfo.InvariantCulture);
            }

            return AuthoringSupport.DeterministicStructuralId(unique);
        }

        private static (int X, int Y) NextElementPosition(string? boundaryAlias, Dictionary<string, BoundaryBox> boxes, ref int unassigned, int unassignedBaseY)
        {
            if (!string.IsNullOrEmpty(boundaryAlias) && boxes.TryGetValue(boundaryAlias!, out BoundaryBox? box))
            {
                int index = box.Cursor;
                box.Cursor = index + 1;
                return (box.X + 24 + ((index % 3) * 120), box.Y + 48 + ((index / 3) * 84));
            }

            int k = unassigned;
            unassigned = k + 1;
            return (40 + ((k % 5) * 150), unassignedBaseY + ((k / 5) * 90));
        }

        private static IReadOnlyList<string> ToAssignments(Dictionary<string, string> props)
        {
            List<string> assignments = new List<string>();
            foreach (KeyValuePair<string, string> pair in props)
            {
                assignments.Add(pair.Key + "=" + pair.Value);
            }

            return assignments;
        }

        private static Dictionary<string, string> FilterProps(IReadOnlyDictionary<string, string> props)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in props)
            {
                if (string.Equals(pair.Key, AuthoringSupport.AliasPropertyName, StringComparison.Ordinal) ||
                    string.Equals(pair.Key, AuthoringSupport.BoundaryPropertyName, StringComparison.Ordinal) ||
                    string.Equals(pair.Key, "StencilType", StringComparison.Ordinal))
                {
                    continue;
                }

                result[pair.Key] = pair.Value;
            }

            return result;
        }

        private static string ReferenceFor(DrawingSurfaceModel surface, Guid guid)
        {
            Entity? entity = DiagramEditor.FindElement(surface, guid);
            if (entity == null)
            {
                return guid.ToString();
            }

            IReadOnlyDictionary<string, string> props = DiagramElementHelper.GetCustomProperties(entity);
            if (props.TryGetValue(AuthoringSupport.AliasPropertyName, out string? alias) && !string.IsNullOrEmpty(alias))
            {
                return alias!;
            }

            string name = DiagramElementHelper.GetName(entity);
            return string.IsNullOrWhiteSpace(name) ? guid.ToString() : name;
        }

        private static string KindNoun(Entity entity)
        {
            return AuthoringSupport.SchemaBase(entity) switch
            {
                "datastore" => "store",
                "external" => "external",
                _ => "process",
            };
        }

        private static string? NullIfEmpty(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        private readonly struct Rect
        {
            public Rect(int x, int y, int width, int height)
            {
                this.X = x;
                this.Y = y;
                this.Width = width;
                this.Height = height;
            }

            public int X { get; }

            public int Y { get; }

            public int Width { get; }

            public int Height { get; }

            public int Right => this.X + this.Width;

            public int Bottom => this.Y + this.Height;

            public static Rect Union(Rect first, Rect second)
            {
                int x = Math.Min(first.X, second.X);
                int y = Math.Min(first.Y, second.Y);
                return new Rect(x, y, Math.Max(first.Right, second.Right) - x, Math.Max(first.Bottom, second.Bottom) - y);
            }

            public bool Contains(Rect inner)
                => inner.X >= this.X && inner.Y >= this.Y && inner.Right <= this.Right && inner.Bottom <= this.Bottom;

            public override string ToString()
                => string.Create(
                    CultureInfo.InvariantCulture,
                    $"({this.X}, {this.Y}) {this.Width}x{this.Height}");
        }

        private sealed class PageContext
        {
            public PageContext(DrawingSurfaceModel surface)
            {
                this.Surface = surface;
            }

            public DrawingSurfaceModel Surface { get; }

            /// <summary>Where the next auto-placed boundary starts. Each page stacks independently.</summary>
            public int CursorY { get; set; } = 40;

            /// <summary>How many boundary-less elements this page has already placed.</summary>
            public int Unassigned { get; set; }
        }

        private sealed class ResolvedElement
        {
            public ResolvedElement(ManifestElement element, StencilKind kind, StencilDto? stencil)
            {
                this.Element = element;
                this.Kind = kind;
                this.Stencil = stencil;
            }

            public ManifestElement Element { get; }

            public StencilKind Kind { get; }

            public StencilDto? Stencil { get; }

            /// <summary>The rectangle an explicitly positioned element occupies, at its declared or default size.</summary>
            public Rect PlacedBounds()
            {
                (int width, int height) = DefaultSize(this.Kind);
                return new Rect(
                    this.Element.X ?? 0,
                    this.Element.Y ?? 0,
                    this.Element.Width ?? width,
                    this.Element.Height ?? height);
            }

            private static (int Width, int Height) DefaultSize(StencilKind kind) => kind switch
            {
                StencilKind.Process => (100, 60),
                StencilKind.ExternalEntity => (120, 60),
                StencilKind.DataStore => (120, 50),
                _ => (220, 160),
            };
        }

        private sealed class BoundaryBox
        {
            public BoundaryBox(Rect bounds, bool sizeWasDeclared)
            {
                this.Bounds = bounds;
                this.SizeWasDeclared = sizeWasDeclared;
            }

            public Rect Bounds { get; }

            /// <summary>Whether the author fixed the size, so members must fit rather than grow it.</summary>
            public bool SizeWasDeclared { get; }

            public int X => this.Bounds.X;

            public int Y => this.Bounds.Y;

            public int Cursor { get; set; }
        }
    }
}
