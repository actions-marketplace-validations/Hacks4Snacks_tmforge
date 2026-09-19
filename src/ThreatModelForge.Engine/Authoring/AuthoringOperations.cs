namespace ThreatModelForge.Engine
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// The imperative authoring operations (<c>add</c>, <c>connect</c>, <c>set</c>, <c>rename</c>,
    /// <c>remove</c>), lifted out of the CLI so the CLI, the HTTP API, the WASM shim, and the MCP
    /// server all drive one implementation. Each operation mutates the supplied <see cref="ThreatModel"/>
    /// in place and reports success, resolved identifiers, and non-blocking warnings; it performs no
    /// file or console I/O, leaving persistence and presentation to the host.
    /// </summary>
    public static class AuthoringOperations
    {
        /// <summary>
        /// Adds a process, data store, external interactor, or trust boundary. The element is placed
        /// deterministically when no coordinates are given, stamped with any stencil identity and
        /// preset defaults, optionally placed inside a trust boundary (recording membership), and
        /// optionally given a stable, deterministic id derived from an alias.
        /// </summary>
        /// <param name="model">The model to mutate.</param>
        /// <param name="request">The add inputs (kind, stencil, placement, boundary, alias, properties).</param>
        /// <param name="id">On success, the identifier of the new element (the deterministic alias id when an alias is set).</param>
        /// <param name="warnings">On return, non-blocking warnings for forced property overrides.</param>
        /// <param name="error">On failure, a message describing the blocking problem.</param>
        /// <returns><see langword="true"/> when the element was added.</returns>
        public static bool Add(ThreatModel model, AddRequest request, out Guid id, out IReadOnlyList<string> warnings, out string? error)
        {
            id = Guid.Empty;
            List<string> warn = new List<string>();
            warnings = warn;
            error = null;

            StencilKind kind = request.Kind;
            StencilDto? stencil = request.Stencil;

            DrawingSurfaceModel diagram;
            if (string.IsNullOrEmpty(request.Page))
            {
                diagram = AuthoringSupport.GetOrCreateFirstDiagram(model);
            }
            else if (AuthoringSupport.TryResolveDiagram(model, request.Page!, out DrawingSurfaceModel? resolved, out string? pageError))
            {
                diagram = resolved!;
            }
            else
            {
                error = pageError;
                return false;
            }

            DiagramEditor editor = new DiagramEditor(model);
            (int defaultLeft, int defaultTop) = AuthoringSupport.NextPosition(diagram);
            int left = request.Left ?? defaultLeft;
            int top = request.Top ?? defaultTop;
            bool hasWidth = request.Width.HasValue;
            bool hasHeight = request.Height.HasValue;
            int argWidth = request.Width ?? 0;
            int argHeight = request.Height ?? 0;

            id = editor.AddElement(diagram, kind, left, top);
            if (kind == StencilKind.TrustBoundary)
            {
                editor.ResizeElement(diagram, id, left, top, hasWidth ? argWidth : 260, hasHeight ? argHeight : 180);
            }
            else if (hasWidth || hasHeight)
            {
                DrawingElement? placed = DiagramEditor.FindElement(diagram, id) as DrawingElement;
                editor.ResizeElement(diagram, id, left, top, hasWidth ? argWidth : placed?.Width ?? 100, hasHeight ? argHeight : placed?.Height ?? 60);
            }

            string? name = request.Name;
            if (string.IsNullOrEmpty(name) && stencil != null)
            {
                name = stencil.Label;
            }

            if (!string.IsNullOrEmpty(name))
            {
                editor.SetElementName(diagram, id, name!);
            }

            Entity? added = DiagramEditor.FindElement(diagram, id);
            if (stencil != null && added != null)
            {
                DiagramElementHelper.SetCustomProperty(added, "StencilType", stencil.Id);
                foreach (KeyValuePair<string, string> preset in stencil.Defaults)
                {
                    DiagramElementHelper.SetCustomProperty(added, preset.Key, preset.Value);
                }
            }

            if (added != null && request.Properties.Count > 0)
            {
                if (!AuthoringSupport.TryApplyProperties(added, request.Properties, AuthoringSupport.SchemaBase(kind), request.Force, out string? propertyError, out IReadOnlyList<string> propertyWarnings))
                {
                    error = propertyError;
                    return false;
                }

                warn.AddRange(propertyWarnings);
            }

            if (!string.IsNullOrEmpty(request.Boundary) && added is DrawingElement placedComponent)
            {
                if (!AuthoringSupport.TryResolveElementId(model, diagram, request.Boundary!, out Guid boundaryId, out string? boundaryError))
                {
                    error = boundaryError;
                    return false;
                }

                Entity? boundaryEntity = DiagramEditor.FindElement(diagram, boundaryId);
                if (boundaryEntity is not BorderBoundary boundaryBox)
                {
                    error = "The --boundary reference must be a trust boundary.";
                    return false;
                }

                IReadOnlyDictionary<string, string> boundaryProps = DiagramElementHelper.GetCustomProperties(boundaryEntity);
                string boundaryName = DiagramElementHelper.GetName(boundaryEntity);
                string membershipKey = boundaryProps.TryGetValue(AuthoringSupport.AliasPropertyName, out string? boundaryAlias) && !string.IsNullOrEmpty(boundaryAlias)
                    ? boundaryAlias!
                    : (string.IsNullOrWhiteSpace(boundaryName) ? request.Boundary! : boundaryName);
                int memberIndex = AuthoringSupport.CountBoundaryMembers(diagram, membershipKey);
                (int insideLeft, int insideTop) = AuthoringSupport.PositionInsideBoundary(boundaryBox, memberIndex);
                if ((long)insideLeft + placedComponent.Width >= (long)boundaryBox.Left + boundaryBox.Width
                    || (long)insideTop + placedComponent.Height >= (long)boundaryBox.Top + boundaryBox.Height)
                {
                    editor.RemoveElement(diagram, id);
                    error = "The component does not fit inside boundary '" + membershipKey + "'. Enlarge the boundary explicitly before adding this member.";
                    return false;
                }

                editor.ResizeElement(diagram, id, insideLeft, insideTop, placedComponent.Width, placedComponent.Height);
                DiagramElementHelper.SetCustomProperty(added, AuthoringSupport.BoundaryPropertyName, membershipKey);
            }

            if (!string.IsNullOrEmpty(request.Alias) && added != null)
            {
                Guid desired = AuthoringSupport.DeterministicId(request.Alias!);
                if (desired != id && AuthoringSupport.FindDiagramContaining(model, desired) != null)
                {
                    error = "Alias '" + request.Alias + "' already maps to an existing element in this model; aliases must be unique.";
                    return false;
                }

                DiagramElementHelper.SetCustomProperty(added, AuthoringSupport.AliasPropertyName, request.Alias!);
                AuthoringSupport.RekeyComponent(diagram, id, desired);
                id = desired;
            }

            return true;
        }

        /// <summary>
        /// Adds a data-flow connector between two existing elements on the same page.
        /// </summary>
        /// <param name="model">The model to mutate.</param>
        /// <param name="request">The connect inputs (source, target, name, page, properties).</param>
        /// <param name="id">On success, the identifier of the new connector.</param>
        /// <param name="source">On success, the resolved source element identifier.</param>
        /// <param name="target">On success, the resolved target element identifier.</param>
        /// <param name="warnings">On return, non-blocking warnings for forced property overrides.</param>
        /// <param name="error">On failure, a message describing the blocking problem.</param>
        /// <returns><see langword="true"/> when the connector was added.</returns>
        public static bool Connect(ThreatModel model, ConnectRequest request, out Guid id, out Guid source, out Guid target, out IReadOnlyList<string> warnings, out string? error)
        {
            id = Guid.Empty;
            source = Guid.Empty;
            target = Guid.Empty;
            List<string> warn = new List<string>();
            warnings = warn;
            error = null;

            if (string.IsNullOrEmpty(request.Source) || string.IsNullOrEmpty(request.Target))
            {
                error = "A source and a target are required.";
                return false;
            }

            DrawingSurfaceModel? diagram;
            if (string.IsNullOrEmpty(request.Page))
            {
                diagram = AuthoringSupport.FirstDiagram(model);
            }
            else if (AuthoringSupport.TryResolveDiagram(model, request.Page!, out DrawingSurfaceModel? resolved, out string? pageError))
            {
                diagram = resolved;
            }
            else
            {
                error = pageError;
                return false;
            }

            if (diagram == null)
            {
                error = "The model has no diagram to connect within.";
                return false;
            }

            if (!AuthoringSupport.TryResolveElementId(model, diagram, request.Source, out source, out error))
            {
                return false;
            }

            if (!AuthoringSupport.TryResolveElementId(model, diagram, request.Target, out target, out error))
            {
                return false;
            }

            if (!diagram.Borders.ContainsKey(source))
            {
                error = "Source element not found on this page: " + request.Source;
                return false;
            }

            if (!diagram.Borders.ContainsKey(target))
            {
                error = "Target element not found on this page: " + request.Target;
                return false;
            }

            DiagramEditor editor = new DiagramEditor(model);
            id = editor.AddConnector(diagram, source, target);
            if (!string.IsNullOrEmpty(request.Name))
            {
                editor.SetElementName(diagram, id, request.Name!);
            }

            if (request.Properties.Count > 0)
            {
                Entity? flow = DiagramEditor.FindElement(diagram, id);
                if (flow != null)
                {
                    if (!AuthoringSupport.TryApplyProperties(flow, request.Properties, "flow", request.Force, out string? propertyError, out IReadOnlyList<string> propertyWarnings))
                    {
                        error = propertyError;
                        return false;
                    }

                    warn.AddRange(propertyWarnings);
                }
            }

            return true;
        }

        /// <summary>
        /// Sets the name and/or custom properties of an existing element or flow.
        /// </summary>
        /// <param name="model">The model to mutate.</param>
        /// <param name="request">The set inputs (reference, name, page, properties).</param>
        /// <param name="id">On success, the resolved element or flow identifier.</param>
        /// <param name="warnings">On return, non-blocking warnings for forced property overrides.</param>
        /// <param name="error">On failure, a message describing the blocking problem.</param>
        /// <returns><see langword="true"/> when the update was applied.</returns>
        public static bool Set(ThreatModel model, SetRequest request, out Guid id, out IReadOnlyList<string> warnings, out string? error)
        {
            id = Guid.Empty;
            List<string> warn = new List<string>();
            warnings = warn;
            error = null;

            if (string.IsNullOrEmpty(request.Id))
            {
                error = "An element reference is required.";
                return false;
            }

            if (string.IsNullOrEmpty(request.Name) && request.Properties.Count == 0)
            {
                error = "Nothing to set: supply a name and/or KEY=VALUE properties.";
                return false;
            }

            if (!AuthoringSupport.TryResolveElementId(model, null, request.Id, out id, out error))
            {
                return false;
            }

            Entity? target = null;
            if (string.IsNullOrEmpty(request.Page))
            {
                foreach (DrawingSurfaceModel diagram in model.DrawingSurfaceList)
                {
                    target = DiagramEditor.FindElement(diagram, id);
                    if (target != null)
                    {
                        break;
                    }
                }
            }
            else if (AuthoringSupport.TryResolveDiagram(model, request.Page!, out DrawingSurfaceModel? resolved, out string? pageError))
            {
                target = DiagramEditor.FindElement(resolved!, id);
            }
            else
            {
                error = pageError;
                return false;
            }

            if (target == null)
            {
                error = "Element not found: " + id;
                return false;
            }

            if (!string.IsNullOrEmpty(request.Name))
            {
                DiagramElementHelper.SetName(target, request.Name!);
            }

            if (!AuthoringSupport.TryApplyProperties(target, request.Properties, AuthoringSupport.SchemaBase(target), request.Force, out string? propertyError, out IReadOnlyList<string> propertyWarnings))
            {
                error = propertyError;
                return false;
            }

            warn.AddRange(propertyWarnings);
            return true;
        }

        /// <summary>
        /// Sets the display name of an existing element, searching every page by default.
        /// </summary>
        /// <param name="model">The model to mutate.</param>
        /// <param name="request">The rename inputs (reference, new name, page).</param>
        /// <param name="id">On success, the resolved element identifier.</param>
        /// <param name="error">On failure, a message describing the blocking problem.</param>
        /// <returns><see langword="true"/> when the element was renamed.</returns>
        public static bool Rename(ThreatModel model, RenameRequest request, out Guid id, out string? error)
        {
            id = Guid.Empty;
            error = null;

            if (string.IsNullOrEmpty(request.Id) || string.IsNullOrEmpty(request.Name))
            {
                error = "An element reference and a new name are required.";
                return false;
            }

            if (!AuthoringSupport.TryResolveElementId(model, null, request.Id, out id, out error))
            {
                return false;
            }

            DrawingSurfaceModel? diagram;
            if (string.IsNullOrEmpty(request.Page))
            {
                diagram = AuthoringSupport.FindDiagramContaining(model, id);
            }
            else if (AuthoringSupport.TryResolveDiagram(model, request.Page!, out DrawingSurfaceModel? resolved, out string? pageError))
            {
                diagram = resolved;
            }
            else
            {
                error = pageError;
                return false;
            }

            if (diagram == null || DiagramEditor.FindElement(diagram, id) == null)
            {
                error = "Element not found: " + id;
                return false;
            }

            DiagramEditor editor = new DiagramEditor(model);
            editor.SetElementName(diagram, id, request.Name);
            return true;
        }

        /// <summary>
        /// Removes an element (and any data flows attached to it), searching every page by default.
        /// </summary>
        /// <param name="model">The model to mutate.</param>
        /// <param name="request">The remove inputs (reference, page).</param>
        /// <param name="removed">On success, the identifiers that were removed (the element and its flows), ordered.</param>
        /// <param name="error">On failure, a message describing the blocking problem.</param>
        /// <returns><see langword="true"/> when the element was removed.</returns>
        public static bool Remove(ThreatModel model, RemoveRequest request, out IReadOnlyList<Guid> removed, out string? error)
        {
            removed = Array.Empty<Guid>();
            error = null;

            if (string.IsNullOrEmpty(request.Id))
            {
                error = "An element reference is required.";
                return false;
            }

            if (!AuthoringSupport.TryResolveElementId(model, null, request.Id, out Guid id, out error))
            {
                return false;
            }

            DrawingSurfaceModel? diagram;
            if (string.IsNullOrEmpty(request.Page))
            {
                diagram = AuthoringSupport.FindDiagramContaining(model, id);
            }
            else if (AuthoringSupport.TryResolveDiagram(model, request.Page!, out DrawingSurfaceModel? resolved, out string? pageError))
            {
                diagram = resolved;
            }
            else
            {
                error = pageError;
                return false;
            }

            if (diagram == null || DiagramEditor.FindElement(diagram, id) == null)
            {
                error = "Element not found: " + id;
                return false;
            }

            HashSet<Guid> before = new HashSet<Guid>(diagram.Borders.Keys);
            before.UnionWith(diagram.Lines.Keys);

            DiagramEditor editor = new DiagramEditor(model);
            editor.RemoveElement(diagram, id);

            before.ExceptWith(diagram.Borders.Keys);
            before.ExceptWith(diagram.Lines.Keys);
            removed = before.OrderBy(guid => guid).ToList();
            return true;
        }
    }
}
