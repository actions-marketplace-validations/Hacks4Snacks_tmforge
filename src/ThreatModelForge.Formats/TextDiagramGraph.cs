namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Builds an evidence-unknown DFD from a parsed text graph.</summary>
    internal sealed class TextDiagramGraph
    {
        private readonly string format;
        private readonly DiagramTextReader reader;
        private readonly Dictionary<string, Node> nodes = new Dictionary<string, Node>(StringComparer.Ordinal);
        private readonly List<Flow> flows = new List<Flow>();
        private readonly HashSet<string> flowIds = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>Initializes a new instance of the <see cref="TextDiagramGraph"/> class.</summary>
        /// <param name="format">The identity namespace.</param>
        /// <param name="reader">The parser's diagnostic source.</param>
        internal TextDiagramGraph(string format, DiagramTextReader reader)
        {
            this.format = format;
            this.reader = reader;
        }

        /// <summary>Gets or sets the model and diagram title.</summary>
        internal string Name { get; set; } = "Imported diagram";

        /// <summary>Adds a uniquely named trust-boundary subgraph.</summary>
        /// <param name="id">The source subgraph id.</param>
        /// <param name="label">The displayed title.</param>
        /// <param name="parent">The enclosing subgraph, if any.</param>
        /// <returns>The new boundary.</returns>
        internal Node Boundary(string id, string label, string? parent)
        {
            if (this.nodes.ContainsKey(id))
            {
                throw this.reader.Error($"Duplicate subgraph or node identifier '{id}'.");
            }

            Node boundary = this.NodeFor(id, parent);
            boundary.Kind = StencilKind.TrustBoundary;
            boundary.Label = label;
            return boundary;
        }

        /// <summary>Resolves a node and its innermost compatible subgraph membership.</summary>
        /// <param name="id">The source node id.</param>
        /// <param name="parent">The current subgraph, if any.</param>
        /// <returns>The existing or new node.</returns>
        internal Node NodeFor(string id, string? parent)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                throw this.reader.Error("Source identifiers cannot be empty.");
            }

            if (!this.nodes.TryGetValue(id, out Node? node))
            {
                if (this.nodes.Count >= 256)
                {
                    throw this.reader.Error("Text diagram import is limited to 256 nodes and boundaries.");
                }

                node = new Node { Id = id, Label = id, Parent = parent };
                this.nodes.Add(id, node);
                return node;
            }

            if (node.Kind == StencilKind.TrustBoundary)
            {
                throw this.reader.Error($"Subgraph endpoint '{id}' is unsupported. Connect to a node inside the subgraph.");
            }

            if (parent != null && parent != node.Parent)
            {
                if (node.Parent == null || this.IsAncestor(node.Parent, parent))
                {
                    node.Parent = parent;
                }
                else if (!this.IsAncestor(parent, node.Parent))
                {
                    throw this.reader.Error($"Node '{id}' belongs to overlapping subgraphs '{node.Parent}' and '{parent}'. Only disjoint or nested boundaries are supported.");
                }
            }

            return node;
        }

        /// <summary>Adds a directed flow between resolved nodes.</summary>
        /// <param name="source">The source node id.</param>
        /// <param name="target">The target node id.</param>
        /// <param name="label">The edge label.</param>
        /// <param name="id">An optional explicit edge identity.</param>
        internal void AddFlow(string source, string target, string label, string? id = null)
        {
            if (this.flows.Count >= 512)
            {
                throw this.reader.Error("Text diagram import is limited to 512 directed edges.");
            }

            if (id != null && (string.IsNullOrWhiteSpace(id) || !this.flowIds.Add(id)))
            {
                throw this.reader.Error($"Duplicate or empty edge id '{id}'.");
            }

            this.flows.Add(new Flow { Source = source, Target = target, Label = label, Id = id });
        }

        /// <summary>Constructs and deterministically lays out the complete parsed graph.</summary>
        /// <returns>A model with unknown control evidence and stable identities.</returns>
        internal ThreatModel Build()
        {
            ThreatModel model = new ThreatModel { MetaInformation = new MetaInformation { ThreatModelName = this.Name } };
            DrawingSurfaceModel surface = new DrawingSurfaceModel
            {
                Guid = DeterministicGuid.FromPageId(this.format + ":diagram"),
                Header = this.Name,
            };
            model.DrawingSurfaceList.Add(surface);
            DiagramEditor editor = new DiagramEditor(model);
            foreach (Node node in this.nodes.Values.OrderBy(node => node.Id, StringComparer.Ordinal))
            {
                Guid created = editor.AddElement(surface, node.Kind, 0, 0);
                DrawingElement element = (DrawingElement)surface.Borders[created];
                surface.Borders.Remove(created);
                element.Guid = this.NodeGuid(node);
                surface.Borders.Add(element.Guid, element);
                DiagramElementHelper.SetName(element, node.Label);
                DiagramElementHelper.SetCustomProperty(element, "Source.Format", this.format);
                DiagramElementHelper.SetCustomProperty(element, "Source.Id", node.Id);
                if (node.Parent != null)
                {
                    DiagramElementHelper.SetCustomProperty(element, "Boundary", this.NodeGuid(this.nodes[node.Parent]).ToString("D"));
                }

                string kind = node.Kind switch
                {
                    StencilKind.Process => "process",
                    StencilKind.DataStore => "datastore",
                    StencilKind.ExternalEntity => "external",
                    _ => "boundary",
                };
                SetUnknownProperties(element, kind);
            }

            this.SeedGroup(surface, null, 40, 40);
            Dictionary<string, int> occurrences = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (Flow flow in this.flows)
            {
                string pair = flow.Source.Length.ToString(CultureInfo.InvariantCulture) + ":" + flow.Source + ":" + flow.Target;
                occurrences.TryGetValue(pair, out int occurrence);
                occurrences[pair] = occurrence + 1;
                string key = flow.Id == null
                    ? ":edge-pair:" + pair + ":" + occurrence.ToString(CultureInfo.InvariantCulture)
                    : ":edge-id:" + flow.Id;
                Guid created = editor.AddConnector(surface, this.NodeGuid(this.nodes[flow.Source]), this.NodeGuid(this.nodes[flow.Target]));
                Connector connector = (Connector)surface.Lines[created];
                surface.Lines.Remove(created);
                connector.Guid = DeterministicGuid.FromStructuralKey(this.format + key);
                surface.Lines.Add(connector.Guid, connector);
                DiagramElementHelper.SetName(connector, flow.Label);
                DiagramElementHelper.SetCustomProperty(connector, "Source.Format", this.format);
                if (flow.Id != null)
                {
                    DiagramElementHelper.SetCustomProperty(connector, "Source.Id", flow.Id);
                }

                SetUnknownProperties(connector, "flow");
            }

            DiagramLayout.Apply(surface);
            return model;
        }

        private static void SetUnknownProperties(Entity entity, string kind)
        {
            foreach (PropertyDescriptor property in PropertySchemaCatalog.For(kind).Where(property => property.Values.Contains("Unknown", StringComparer.Ordinal)))
            {
                DiagramElementHelper.SetCustomProperty(entity, property.Name, "Unknown");
            }
        }

        private bool IsAncestor(string ancestor, string child)
        {
            string? current = this.nodes[child].Parent;
            while (current != null)
            {
                if (current == ancestor)
                {
                    return true;
                }

                current = this.nodes[current].Parent;
            }

            return false;
        }

        private Guid NodeGuid(Node node)
        {
            return node.Kind == StencilKind.TrustBoundary
                ? DeterministicGuid.FromStructuralKey(this.format + ":boundary:" + node.Id)
                : DeterministicGuid.FromElementId(this.format + ":node:" + node.Id);
        }

        private int SeedGroup(DrawingSurfaceModel surface, string? parent, int left, int top)
        {
            int nextTop = top;
            foreach (Node node in this.nodes.Values.Where(node => node.Parent == parent).OrderBy(node => node.Id, StringComparer.Ordinal))
            {
                DrawingElement element = (DrawingElement)surface.Borders[this.NodeGuid(node)];
                element.Left = left;
                element.Top = nextTop;
                if (node.Kind == StencilKind.TrustBoundary)
                {
                    int bottom = this.SeedGroup(surface, node.Id, left + 32, nextTop + 64);
                    element.Width = this.nodes.Values.Where(child => child.Parent == node.Id)
                        .Select(child => (DrawingElement)surface.Borders[this.NodeGuid(child)])
                        .Select(child => child.Left + child.Width - left + 32)
                        .DefaultIfEmpty(220).Max();
                    element.Height = Math.Max(160, bottom - nextTop + 32);
                }
                else
                {
                    element.Width = 160;
                    element.Height = 80;
                }

                nextTop += element.Height + 40;
            }

            return nextTop;
        }

        /// <summary>A source node or trust-boundary subgraph.</summary>
        internal sealed class Node
        {
            /// <summary>Gets or sets the source identity.</summary>
            internal string Id { get; set; } = string.Empty;

            /// <summary>Gets or sets the display label.</summary>
            internal string Label { get; set; } = string.Empty;

            /// <summary>Gets or sets the mapped DFD primitive.</summary>
            internal StencilKind Kind { get; set; } = StencilKind.Process;

            /// <summary>Gets or sets the innermost boundary identity.</summary>
            internal string? Parent { get; set; }

            /// <summary>Gets the effective DOT attributes, including first-use defaults.</summary>
            internal Dictionary<string, string> Attributes { get; } = new Dictionary<string, string>(StringComparer.Ordinal);
        }

        private sealed class Flow
        {
            internal string Source { get; set; } = string.Empty;

            internal string Target { get; set; } = string.Empty;

            internal string Label { get; set; } = string.Empty;

            internal string? Id { get; set; }
        }
    }
}
