namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Formats;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Shared helpers for the imperative authoring verbs (<c>new</c>, <c>add</c>, <c>connect</c>,
    /// <c>remove</c>, <c>rename</c>): diagram resolution, deterministic placement, element-kind
    /// parsing, and atomic model writes.
    /// </summary>
    public static class AuthoringSupport
    {
        /// <summary>
        /// The custom-property key that stores an element's authoring alias (set by <c>add --alias</c>).
        /// The alias is a stable, human-chosen handle that <c>connect</c>/<c>set</c>/<c>remove</c>/
        /// <c>rename</c>/<c>show</c> can resolve instead of a GUID, and that survives round-trips.
        /// </summary>
        public const string AliasPropertyName = "Alias";

        /// <summary>
        /// The custom-property key that records the alias of the trust boundary an element belongs to,
        /// so logical membership declared in a manifest survives round-trips and can be exported back.
        /// </summary>
        public const string BoundaryPropertyName = "Boundary";

        /// <summary>
        /// Returns the model's first diagram, creating an empty "Diagram 1" when it has none.
        /// </summary>
        /// <param name="model">The model to inspect.</param>
        /// <returns>The first (or newly created) diagram.</returns>
        public static DrawingSurfaceModel GetOrCreateFirstDiagram(ThreatModel model)
        {
            if (model.DrawingSurfaceList.Count > 0)
            {
                return model.DrawingSurfaceList[0];
            }

            DrawingSurfaceModel created = new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Diagram 1" };
            model.DrawingSurfaceList.Add(created);
            return created;
        }

        /// <summary>
        /// Returns the model's first diagram, or <see langword="null"/> when it has none.
        /// </summary>
        /// <param name="model">The model to inspect.</param>
        /// <returns>The first diagram, or <see langword="null"/>.</returns>
        public static DrawingSurfaceModel? FirstDiagram(ThreatModel model)
        {
            return model.DrawingSurfaceList.Count > 0 ? model.DrawingSurfaceList[0] : null;
        }

        /// <summary>
        /// Resolves a non-empty <c>--page</c> selector to a diagram. A pure integer selects a
        /// 1-based page index; anything else matches a page name (the diagram <c>Header</c>,
        /// case-insensitive).
        /// </summary>
        /// <param name="model">The model to search.</param>
        /// <param name="pageSpec">The page selector (a 1-based index or a page name).</param>
        /// <param name="diagram">On success, the resolved diagram.</param>
        /// <param name="error">On failure, a message describing why the page could not be resolved.</param>
        /// <returns><see langword="true"/> when a single diagram was resolved.</returns>
        public static bool TryResolveDiagram(
            ThreatModel model,
            string pageSpec,
            out DrawingSurfaceModel? diagram,
            out string? error)
        {
            diagram = null;
            error = null;
            DrawingSurfaceModelList list = model.DrawingSurfaceList;
            if (list.Count == 0)
            {
                error = "The model has no pages.";
                return false;
            }

            if (int.TryParse(pageSpec, NumberStyles.Integer, CultureInfo.InvariantCulture, out int index))
            {
                if (index < 1 || index > list.Count)
                {
                    error = "Page index " + index.ToString(CultureInfo.InvariantCulture) + " is out of range (the model has " +
                        list.Count.ToString(CultureInfo.InvariantCulture) + " page(s)).";
                    return false;
                }

                diagram = list[index - 1];
                return true;
            }

            List<DrawingSurfaceModel> matches = list
                .Where(surface => string.Equals(surface.Header, pageSpec, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matches.Count == 0)
            {
                error = "No page named '" + pageSpec + "'. Run 'tmforge page ls <file>' to list pages.";
                return false;
            }

            if (matches.Count > 1)
            {
                error = "Page name '" + pageSpec + "' is ambiguous (" + matches.Count.ToString(CultureInfo.InvariantCulture) +
                    " pages match); use a 1-based index instead.";
                return false;
            }

            diagram = matches[0];
            return true;
        }

        /// <summary>
        /// Finds the diagram that contains the element with the given identifier, searching every
        /// page, or <see langword="null"/> when no page contains it.
        /// </summary>
        /// <param name="model">The model to search.</param>
        /// <param name="id">The element identifier.</param>
        /// <returns>The containing diagram, or <see langword="null"/>.</returns>
        public static DrawingSurfaceModel? FindDiagramContaining(ThreatModel model, Guid id)
        {
            return model.DrawingSurfaceList
                .FirstOrDefault(surface => DiagramEditor.FindElement(surface, id) != null);
        }

        /// <summary>
        /// Resolves an element reference to a GUID. The token may be a GUID, an element's authoring
        /// alias (the <see cref="AliasPropertyName"/> custom property), or an element's unique display
        /// name. Alias matches take priority over name matches; a name that matches more than one
        /// element is rejected as ambiguous.
        /// </summary>
        /// <param name="model">The model to search.</param>
        /// <param name="scope">A single surface to restrict the search to, or <see langword="null"/> to search every page.</param>
        /// <param name="token">The GUID, alias, or name to resolve.</param>
        /// <param name="id">On success, the resolved element GUID.</param>
        /// <param name="error">On failure, a message describing why the reference could not be resolved.</param>
        /// <returns><see langword="true"/> when the reference resolved to a single element.</returns>
        public static bool TryResolveElementId(
            ThreatModel model,
            DrawingSurfaceModel? scope,
            string token,
            out Guid id,
            out string? error)
        {
            id = Guid.Empty;
            error = null;
            if (string.IsNullOrEmpty(token))
            {
                error = "An element reference (GUID, alias, or name) is required.";
                return false;
            }

            if (Guid.TryParse(token, out Guid parsed))
            {
                id = parsed;
                return true;
            }

            IEnumerable<DrawingSurfaceModel> surfaces = scope != null
                ? new[] { scope }
                : (IEnumerable<DrawingSurfaceModel>)model.DrawingSurfaceList;
            List<Guid> aliasMatches = new List<Guid>();
            List<Guid> nameMatches = new List<Guid>();
            foreach (DrawingSurfaceModel surface in surfaces)
            {
                foreach (Entity entity in surface.Borders.Values.OfType<Entity>().Concat(surface.Lines.Values.OfType<Entity>()))
                {
                    IReadOnlyDictionary<string, string> properties = DiagramElementHelper.GetCustomProperties(entity);
                    if (properties.TryGetValue(AliasPropertyName, out string? alias) &&
                        string.Equals(alias, token, StringComparison.OrdinalIgnoreCase))
                    {
                        aliasMatches.Add(entity.Guid);
                    }
                    else if (string.Equals(DiagramElementHelper.GetName(entity), token, StringComparison.Ordinal))
                    {
                        nameMatches.Add(entity.Guid);
                    }
                }
            }

            if (aliasMatches.Count == 1)
            {
                id = aliasMatches[0];
                return true;
            }

            if (aliasMatches.Count > 1)
            {
                error = "Alias '" + token + "' matches " + aliasMatches.Count.ToString(CultureInfo.InvariantCulture) +
                    " objects; use a GUID to disambiguate.";
                return false;
            }

            if (nameMatches.Count == 1)
            {
                id = nameMatches[0];
                return true;
            }

            if (nameMatches.Count > 1)
            {
                error = "Name '" + token + "' matches " + nameMatches.Count.ToString(CultureInfo.InvariantCulture) +
                    " objects; use an --alias or a GUID.";
                return false;
            }

            error = "No element or flow with GUID, alias, or name '" + token +
                "' (run 'tmforge list components <file>' or 'tmforge list flows <file>').";
            return false;
        }

        /// <summary>
        /// Derives a stable, deterministic element GUID from an authoring alias, so a model rebuilt
        /// from the same alias produces the same id and reports and companion docs can cite it durably.
        /// </summary>
        /// <param name="alias">The authoring alias.</param>
        /// <returns>A deterministic GUID for the alias.</returns>
        public static Guid DeterministicId(string alias) => DeterministicGuid.FromElementId(alias);

        /// <summary>
        /// Derives a stable, deterministic page GUID from a page id, in its own namespace so a page and
        /// an element that happen to share an id do not collide.
        /// </summary>
        /// <param name="pageId">The page id.</param>
        /// <returns>A deterministic GUID for the page.</returns>
        public static Guid DeterministicPageId(string pageId) => DeterministicGuid.FromPageId(pageId);

        /// <summary>
        /// Derives a stable identifier for an object with no author-supplied alias, in its own namespace
        /// so it can never collide with an alias.
        /// </summary>
        /// <param name="key">The structural key describing the object.</param>
        /// <returns>A deterministic GUID for the key.</returns>
        public static Guid DeterministicStructuralId(string key) => DeterministicGuid.FromStructuralKey(key);

        /// <summary>
        /// Re-keys a component to a new GUID within its diagram, updating both the dictionary key and
        /// the entity. Used to give an aliased element its deterministic id after it is created.
        /// </summary>
        /// <param name="diagram">The diagram containing the component.</param>
        /// <param name="current">The component's current GUID.</param>
        /// <param name="desired">The desired GUID.</param>
        /// <exception cref="ArgumentException">
        /// The diagram does not hold <paramref name="current"/>. Every caller has just created it there,
        /// so this means the wrong surface was passed — and returning quietly would leave the object
        /// carrying the minted identifier this re-key exists to replace.
        /// </exception>
        public static void RekeyComponent(DrawingSurfaceModel diagram, Guid current, Guid desired)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (current == desired)
            {
                return;
            }

            if (!diagram.Borders.TryGetValue(current, out object? border))
            {
                throw new ArgumentException(
                    "The diagram does not contain a component with id " + current.ToString() + ".",
                    nameof(current));
            }

            diagram.Borders.Remove(current);
            if (border is Entity entity)
            {
                entity.Guid = desired;
            }

            diagram.Borders[desired] = border!;
        }

        /// <summary>
        /// Re-keys a connector to a new GUID within its diagram. Connectors live in a separate
        /// collection from components, so re-keying one needs its own routine.
        /// </summary>
        /// <param name="diagram">The diagram containing the connector.</param>
        /// <param name="current">The connector's current GUID.</param>
        /// <param name="desired">The desired GUID.</param>
        /// <exception cref="ArgumentException">The diagram does not hold <paramref name="current"/>.</exception>
        public static void RekeyConnector(DrawingSurfaceModel diagram, Guid current, Guid desired)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (current == desired)
            {
                return;
            }

            if (!diagram.Lines.TryGetValue(current, out object? line))
            {
                throw new ArgumentException(
                    "The diagram does not contain a connector with id " + current.ToString() + ".",
                    nameof(current));
            }

            diagram.Lines.Remove(current);
            if (line is Connector connector)
            {
                connector.Guid = desired;
            }

            diagram.Lines[desired] = line!;
        }

        /// <summary>
        /// Computes a non-overlapping position for the <paramref name="memberIndex"/>-th element placed
        /// inside a trust boundary, laying members out in a three-column grid inset from the boundary's
        /// top-left corner.
        /// </summary>
        /// <param name="boundary">The trust boundary the element belongs to.</param>
        /// <param name="memberIndex">The zero-based index of the element among the boundary's members.</param>
        /// <returns>The left and top coordinates for the element.</returns>
        public static (int Left, int Top) PositionInsideBoundary(DrawingElement boundary, int memberIndex)
        {
            int column = memberIndex % 3;
            int row = memberIndex / 3;
            return (boundary.Left + 24 + (column * 120), boundary.Top + 48 + (row * 84));
        }

        /// <summary>
        /// Counts the elements on a diagram that already declare membership of the given boundary (by
        /// the <see cref="BoundaryPropertyName"/> custom property), so a new member can be placed after
        /// them.
        /// </summary>
        /// <param name="diagram">The diagram to inspect.</param>
        /// <param name="boundaryKey">The boundary membership key (its alias or name).</param>
        /// <returns>The number of existing members.</returns>
        public static int CountBoundaryMembers(DrawingSurfaceModel diagram, string boundaryKey)
        {
            int count = 0;
            foreach (Entity entity in diagram.Borders.Values.OfType<Entity>())
            {
                IReadOnlyDictionary<string, string> properties = DiagramElementHelper.GetCustomProperties(entity);
                if (properties.TryGetValue(BoundaryPropertyName, out string? value) &&
                    string.Equals(value, boundaryKey, StringComparison.OrdinalIgnoreCase))
                {
                    count++;
                }
            }

            return count;
        }

        /// <summary>
        /// Maps a CLI element-kind noun (case-insensitive) to a <see cref="StencilKind"/>.
        /// </summary>
        /// <param name="kind">The kind noun (for example, <c>process</c> or <c>store</c>).</param>
        /// <param name="result">On success, the mapped stencil kind.</param>
        /// <returns><see langword="true"/> if the noun was recognized.</returns>
        public static bool TryParseKind(string kind, out StencilKind result)
        {
            switch (kind.ToLowerInvariant())
            {
                case "process":
                    result = StencilKind.Process;
                    return true;
                case "store":
                case "datastore":
                case "data-store":
                    result = StencilKind.DataStore;
                    return true;
                case "external":
                case "externalinteractor":
                case "interactor":
                case "entity":
                    result = StencilKind.ExternalEntity;
                    return true;
                case "boundary":
                case "trustboundary":
                case "trust-boundary":
                    result = StencilKind.TrustBoundary;
                    return true;
                default:
                    result = StencilKind.Process;
                    return false;
            }
        }

        /// <summary>
        /// Resolves an element-kind noun or a concrete stencil id to a <see cref="StencilKind"/> (and,
        /// for a stencil, the resolved <see cref="StencilDto"/>). A stencil id takes precedence; its
        /// base primitive determines the kind. This is the single kind-resolution seam shared by the
        /// CLI <c>add</c> verb and the engine authoring facade.
        /// </summary>
        /// <param name="kindNoun">The element-kind noun (<c>process</c>, <c>store</c>, <c>external</c>, <c>boundary</c>), or <see langword="null"/>.</param>
        /// <param name="stencilId">The concrete stencil id, or <see langword="null"/>.</param>
        /// <param name="kind">On success, the resolved element kind.</param>
        /// <param name="stencil">On success, the resolved stencil when <paramref name="stencilId"/> was supplied; otherwise <see langword="null"/>.</param>
        /// <param name="error">On failure, a message describing why the kind could not be resolved.</param>
        /// <returns><see langword="true"/> when a kind was resolved.</returns>
        public static bool TryResolveKind(string? kindNoun, string? stencilId, out StencilKind kind, out StencilDto? stencil, out string? error)
        {
            error = null;
            stencil = null;
            if (!string.IsNullOrEmpty(stencilId))
            {
                stencil = StencilCatalog.Find(stencilId!);
                if (stencil == null)
                {
                    kind = StencilKind.Process;
                    error = "Unknown stencil: " + stencilId + " (run 'tmforge stencils' to list available stencils).";
                    return false;
                }

                if (!TryParseKind(stencil.Base, out kind))
                {
                    error = "Stencil '" + stencil.Id + "' has an unrecognized base primitive: " + stencil.Base + ".";
                    return false;
                }

                return true;
            }

            if (!string.IsNullOrEmpty(kindNoun))
            {
                if (!TryParseKind(kindNoun!, out kind))
                {
                    error = "Unknown element kind: " + kindNoun + " (expected process, store, external, or boundary).";
                    return false;
                }

                return true;
            }

            kind = StencilKind.Process;
            error = "An element kind or stencil is required.";
            return false;
        }

        /// <summary>
        /// Computes a deterministic, non-overlapping grid position for the next element, based on the
        /// current element count, so successive additions do not stack.
        /// </summary>
        /// <param name="diagram">The diagram receiving the element.</param>
        /// <returns>The left and top coordinates for the new element.</returns>
        public static (int Left, int Top) NextPosition(DrawingSurfaceModel diagram)
        {
            int index = diagram.Borders.Count;
            int column = index % 4;
            int row = index / 4;
            return (48 + (column * 220), 48 + (row * 140));
        }

        /// <summary>
        /// Maps a CLI element kind to its property-schema base primitive
        /// (<c>process</c>/<c>datastore</c>/<c>external</c>), or <see langword="null"/> when the kind
        /// has no typed schema (a trust boundary).
        /// </summary>
        /// <param name="kind">The element kind.</param>
        /// <returns>The schema base primitive, or <see langword="null"/>.</returns>
        public static string? SchemaBase(StencilKind kind)
        {
            switch (kind)
            {
                case StencilKind.Process:
                    return "process";
                case StencilKind.DataStore:
                    return "datastore";
                case StencilKind.ExternalEntity:
                    return "external";
                default:
                    return null;
            }
        }

        /// <summary>
        /// Maps an existing element or flow to its property-schema base primitive
        /// (<c>flow</c>/<c>process</c>/<c>datastore</c>/<c>external</c>), or <see langword="null"/>
        /// when it has no typed schema (a trust boundary).
        /// </summary>
        /// <param name="entity">The element or connector.</param>
        /// <returns>The schema base primitive, or <see langword="null"/>.</returns>
        public static string? SchemaBase(Entity entity)
        {
            switch (entity)
            {
                case Connector:
                    return "flow";
                case StencilEllipse:
                    return "process";
                case StencilParallelLines:
                    return "datastore";
                case BorderBoundary:
                    return null;
                case DrawingElement:
                    return "external";
                default:
                    return null;
            }
        }

        /// <summary>
        /// Applies <c>key=value</c> custom-property assignments (from repeated <c>--property</c>) to an
        /// element or flow, validating each against the typed property schema for
        /// <paramref name="appliesTo"/>. Unknown properties and values outside a closed enum are
        /// rejected (so a typo can't silently make a rule fail to match) unless <paramref name="force"/>
        /// is set, in which case they are stored and reported as warnings. Matched enum values are
        /// canonicalized to the schema's casing. Validation is skipped when the base has no schema.
        /// </summary>
        /// <param name="element">The element or connector to annotate.</param>
        /// <param name="assignments">The raw <c>key=value</c> assignments.</param>
        /// <param name="appliesTo">The schema base primitive, or <see langword="null"/> to skip validation.</param>
        /// <param name="force">Whether to store unknown/invalid assignments (reported as warnings) instead of rejecting them.</param>
        /// <param name="error">On failure, a message describing the blocking assignments.</param>
        /// <param name="warnings">On return, non-blocking warnings for forced overrides.</param>
        /// <returns><see langword="true"/> when the assignments were applied (or forced).</returns>
        public static bool TryApplyProperties(
            Entity element,
            IReadOnlyList<string> assignments,
            string? appliesTo,
            bool force,
            out string? error,
            out IReadOnlyList<string> warnings)
        {
            error = null;
            List<string> warn = new List<string>();
            warnings = warn;

            List<(string Key, string Value)> parsedAssignments = new List<(string Key, string Value)>();
            foreach (string assignment in assignments)
            {
                int separator = assignment.IndexOf('=');
                if (separator <= 0)
                {
                    error = "Invalid --property (expected KEY=VALUE): " + assignment;
                    return false;
                }

                parsedAssignments.Add((assignment.Substring(0, separator), assignment.Substring(separator + 1)));
            }

            bool schemaKnown = !string.IsNullOrEmpty(appliesTo) && PropertySchemaCatalog.For(appliesTo!).Count > 0;
            List<string> blocking = new List<string>();
            List<(string Key, string Value)> toApply = new List<(string Key, string Value)>();
            foreach ((string key, string value) in parsedAssignments)
            {
                string canonical = value;
                if (schemaKnown)
                {
                    PropertySchemaIssue? issue = PropertySchemaCatalog.Validate(appliesTo!, key, value, out canonical);
                    if (issue != null)
                    {
                        if (force)
                        {
                            warn.Add("warning: " + Describe(issue) + "; stored anyway (--force).");
                        }
                        else
                        {
                            blocking.Add(Describe(issue));
                            continue;
                        }
                    }
                }

                toApply.Add((key, canonical));
            }

            if (blocking.Count > 0)
            {
                blocking.Add("Pass --force to store unknown properties/values, or run 'tmforge properties" +
                    (string.IsNullOrEmpty(appliesTo) ? string.Empty : " --base " + appliesTo) +
                    "' to see valid names and values.");
                error = string.Join(Environment.NewLine, blocking);
                return false;
            }

            foreach ((string key, string value) in toApply)
            {
                DiagramElementHelper.SetCustomProperty(element, key, value);
            }

            return true;
        }

        /// <summary>
        /// Writes the model to <paramref name="path"/> atomically: it serializes to a temporary file
        /// in the same directory and renames it over the target, so a failed write never corrupts an
        /// existing file.
        /// </summary>
        /// <param name="model">The model to write.</param>
        /// <param name="path">The destination path.</param>
        /// <param name="format">The format provider to write with.</param>
        public static void Save(ThreatModel model, string path, IThreatModelFormat format)
        {
            Save(model, path, format, ruleSet: null);
        }

        /// <summary>
        /// Writes the model atomically and, for TM7, embeds categories and threat types from the
        /// supplied effective rule set.
        /// </summary>
        /// <param name="model">The model to write.</param>
        /// <param name="path">The destination path.</param>
        /// <param name="format">The format provider to write with.</param>
        /// <param name="ruleSet">The effective rule set, or <see langword="null"/> for built-ins.</param>
        public static void Save(ThreatModel model, string path, IThreatModelFormat format, RuleSet? ruleSet)
        {
            if (format is Tm7Format)
            {
                if (ruleSet == null)
                {
                    Tm7ExportPreparer.Prepare(model);
                }
                else
                {
                    Tm7ExportPreparer.Prepare(model, ruleSet);
                }
            }

            WriteAtomically(path, stream => format.Write(model, stream));
        }

        /// <summary>Writes document content via a same-directory temporary file and atomic rename.</summary>
        /// <param name="path">The destination path.</param>
        /// <param name="write">The content writer, called before the destination is replaced.</param>
        public static void WriteAtomically(string path, Action<Stream> write)
        {
            if (write == null)
            {
                throw new ArgumentNullException(nameof(write));
            }

            string fullPath = Path.GetFullPath(path);
            string directory = Path.GetDirectoryName(fullPath) ?? ".";
            string temp = Path.Join(directory, "." + Path.GetFileName(fullPath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (FileStream stream = File.Create(temp))
                {
                    write(stream);
                }

                File.Move(temp, fullPath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temp))
                {
                    File.Delete(temp);
                }
            }
        }

        private static string Describe(PropertySchemaIssue issue)
        {
            return issue.Kind == PropertySchemaIssueKind.UnknownProperty
                ? "unknown property '" + issue.Property + "' for " + issue.AppliesTo + " (known: " + string.Join(", ", issue.Allowed) + ")"
                : "invalid value '" + issue.Value + "' for " + issue.AppliesTo + " property '" + issue.Property + "' (allowed: " + string.Join(", ", issue.Allowed) + ")";
        }
    }
}
