namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;

    /// <summary>Imports a bounded subset of Graphviz DOT as starter threat models.</summary>
    public sealed class GraphvizDotFormat : IThreatModelFormat
    {
        /// <summary>The import provider's stable identifier.</summary>
        public const string FormatId = "dot";

        private static readonly FormatCapabilities ImportCapabilities = new FormatCapabilities(
            canRead: true,
            canWrite: false,
            roundTrips: false,
            fidelityNote: "Import-only directed DOT subset: nodes, edges, scoped defaults and nested cluster_* subgraphs. Clusters are interpreted as trust boundaries, not verified isolation. kind selects process/store/datastore/external; cylinder shapes become stores, otherwise process. Geometry is regenerated and controls are Unknown; supported presentation attributes are not retained. Undirected/strict graphs, ports, HTML labels and active attributes are refused.");

        /// <inheritdoc/>
        public string Id => FormatId;

        /// <inheritdoc/>
        public string DisplayName => "Graphviz DOT (.dot, .gv)";

        /// <inheritdoc/>
        public IReadOnlyList<string> Extensions => new[] { ".dot", ".gv" };

        /// <inheritdoc/>
        public FormatCapabilities Capabilities => ImportCapabilities;

        /// <inheritdoc/>
        public bool CanRead(Stream stream) => DiagramTextReader.Sniff(stream, dot: true);

        /// <inheritdoc/>
        public ThreatModel Read(Stream stream)
        {
            DiagramTextReader reader = new DiagramTextReader(DiagramTextReader.ReadText(stream), dot: true);
            TextDiagramGraph graph = new TextDiagramGraph(FormatId, reader);
            reader.SkipSpace(true);
            if (!reader.Word("digraph"))
            {
                throw reader.Error($"Unsupported DOT graph {reader.DescribeCurrent()}. Use a non-strict 'digraph' with directed '->' edges.");
            }

            reader.SkipSpace(true);
            if (!reader.At("{"))
            {
                graph.Name = reader.Identifier();
                reader.SkipSpace(true);
            }

            reader.Expect("{");
            int statements = 0;
            ReadScope(reader, graph, null, new Dictionary<string, string>(StringComparer.Ordinal), new Dictionary<string, string>(StringComparer.Ordinal), 0, ref statements);
            reader.SkipSpace(true);
            if (!reader.End)
            {
                throw reader.Error($"Unsupported trailing DOT content {reader.DescribeCurrent()}. Import one graph at a time.");
            }

            return graph.Build();
        }

        /// <inheritdoc/>
        public void Write(ThreatModel model, Stream stream)
        {
            throw new NotSupportedException("DOT is import-only. Save as tmforge-json or tm7 instead.");
        }

        private static void ReadScope(
            DiagramTextReader reader,
            TextDiagramGraph graph,
            TextDiagramGraph.Node? boundary,
            Dictionary<string, string> nodeDefaults,
            Dictionary<string, string> edgeDefaults,
            int depth,
            ref int statements,
            string? defaultLabel = null)
        {
            while (true)
            {
                reader.SkipSpace(true);
                if (reader.Take("}"))
                {
                    return;
                }

                if (reader.Take(";"))
                {
                    continue;
                }

                if (++statements > 10000)
                {
                    throw reader.Error("Text diagram import is limited to 10000 statements.");
                }

                if (reader.Word("subgraph"))
                {
                    if (depth >= 16)
                    {
                        throw reader.Error("Subgraph nesting is limited to 16 levels.");
                    }

                    reader.SkipSpace(true);
                    string id = reader.Identifier();
                    if (!id.StartsWith("cluster_", StringComparison.Ordinal))
                    {
                        throw reader.Error($"Unsupported DOT subgraph '{id}'. Trust boundary subgraphs must be named cluster_*.");
                    }

                    TextDiagramGraph.Node child = graph.Boundary(id, defaultLabel ?? id, boundary?.Id);
                    reader.SkipSpace(true);
                    reader.Expect("{");
                    ReadScope(reader, graph, child, new Dictionary<string, string>(nodeDefaults, StringComparer.Ordinal), new Dictionary<string, string>(edgeDefaults, StringComparer.Ordinal), depth + 1, ref statements, defaultLabel);
                    continue;
                }

                bool quoted = reader.Current == '"';
                string first = reader.Identifier(allowKeyword: true);
                string keyword = first.ToLowerInvariant();
                reader.SkipSpace(true);
                if (reader.Take("="))
                {
                    reader.SkipSpace(true);
                    string value = reader.Identifier(label: first == "label");
                    ValidateAttribute(reader, "graph", first, value);
                    SetGraphLabel(graph, boundary, first, value);
                    if (first == "label")
                    {
                        defaultLabel = value;
                    }

                    continue;
                }

                if (!quoted && (keyword == "node" || keyword == "edge" || keyword == "graph"))
                {
                    if (!reader.At("["))
                    {
                        throw reader.Error($"Expected an attribute list after DOT '{first}'. Quote reserved node identifiers.");
                    }

                    Dictionary<string, string> attributes = ReadAttributes(reader, keyword);
                    foreach (KeyValuePair<string, string> attribute in attributes)
                    {
                        if (keyword == "graph")
                        {
                            SetGraphLabel(graph, boundary, attribute.Key, attribute.Value);
                            if (attribute.Key == "label")
                            {
                                defaultLabel = attribute.Value;
                            }
                        }
                        else
                        {
                            (keyword == "node" ? nodeDefaults : edgeDefaults)[attribute.Key] = attribute.Value;
                        }
                    }

                    continue;
                }

                if (!quoted && (keyword == "strict" || keyword == "digraph"))
                {
                    throw reader.Error($"Reserved DOT keyword '{first}' must be double-quoted when used as an identifier.");
                }

                TextDiagramGraph.Node source = ReadNode(reader, graph, first, boundary?.Id, nodeDefaults);
                if (reader.At("->"))
                {
                    List<(string Source, string Target)> edges = new List<(string Source, string Target)>();
                    while (reader.Take("->"))
                    {
                        reader.SkipSpace(true);
                        string targetId = reader.Identifier();
                        TextDiagramGraph.Node target = ReadNode(reader, graph, targetId, boundary?.Id, nodeDefaults);
                        edges.Add((source.Id, target.Id));
                        if (edges.Count > 512)
                        {
                            throw reader.Error("Text diagram import is limited to 512 directed edges.");
                        }

                        source = target;
                    }

                    Dictionary<string, string> attributes = new Dictionary<string, string>(edgeDefaults, StringComparer.Ordinal);
                    foreach (KeyValuePair<string, string> attribute in ReadAttributes(reader, "edge"))
                    {
                        attributes[attribute.Key] = attribute.Value;
                    }

                    attributes.TryGetValue("id", out string? edgeId);
                    attributes.TryGetValue("label", out string? label);
                    if (edgeId != null && edges.Count != 1)
                    {
                        throw reader.Error("An explicit DOT edge 'id' cannot be shared by an edge chain. Split the chain into individually identified edges.");
                    }

                    foreach ((string from, string to) in edges)
                    {
                        graph.AddFlow(from, to, label ?? string.Empty, edgeId);
                    }
                }
                else
                {
                    foreach (KeyValuePair<string, string> attribute in ReadAttributes(reader, "node"))
                    {
                        source.Attributes[attribute.Key] = attribute.Value;
                    }

                    ApplyNodeAttributes(source);
                }

                if (reader.At(":"))
                {
                    throw reader.Error("Unsupported DOT port or compass point. Connect directly to a node id.");
                }

                if (reader.At("--"))
                {
                    throw reader.Error("Unsupported undirected DOT edge '--'. Use directed '->' edges.");
                }
            }
        }

        private static TextDiagramGraph.Node ReadNode(DiagramTextReader reader, TextDiagramGraph graph, string id, string? parent, Dictionary<string, string> defaults)
        {
            TextDiagramGraph.Node node = graph.NodeFor(id, parent);
            if (!node.Attributes.ContainsKey("label"))
            {
                foreach (KeyValuePair<string, string> attribute in defaults)
                {
                    node.Attributes[attribute.Key] = attribute.Value;
                }

                if (!node.Attributes.ContainsKey("label"))
                {
                    node.Attributes["label"] = id;
                }

                ApplyNodeAttributes(node);
            }

            reader.SkipSpace(true);
            return node;
        }

        private static Dictionary<string, string> ReadAttributes(DiagramTextReader reader, string scope)
        {
            Dictionary<string, string> attributes = new Dictionary<string, string>(StringComparer.Ordinal);
            int count = 0;
            reader.SkipSpace(true);
            while (reader.Take("["))
            {
                reader.SkipSpace(true);
                while (!reader.Take("]"))
                {
                    if (++count > 128)
                    {
                        throw reader.Error("An attribute list is limited to 128 assignments.");
                    }

                    string key = reader.Identifier();
                    reader.SkipSpace(true);
                    reader.Expect("=");
                    reader.SkipSpace(true);
                    if (reader.At("<"))
                    {
                        throw reader.Error("Unsupported DOT HTML label. Use a plain double-quoted label.");
                    }

                    string value = reader.Identifier(label: key == "label");
                    ValidateAttribute(reader, scope, key, value);
                    attributes[key] = value;
                    reader.SkipSpace(true);
                    if (reader.Take(",") || reader.Take(";"))
                    {
                        reader.SkipSpace(true);
                    }
                }

                reader.SkipSpace(true);
            }

            return attributes;
        }

        private static void ValidateAttribute(DiagramTextReader reader, string scope, string key, string value)
        {
            bool allowed = key == "label" || key == "color" || key == "fontname" || key == "fontsize" || key == "fontcolor" || key == "penwidth" || key == "style";
            allowed |= scope == "graph" && (key == "rankdir" || key == "ranksep" || key == "nodesep" || key == "bgcolor" || key == "labelloc" || key == "labeljust");
            allowed |= scope == "node" && (key == "shape" || key == "kind" || key == "fillcolor" || key == "width" || key == "height" || key == "fixedsize" || key == "margin");
            allowed |= scope == "edge" && (key == "id" || key == "dir" || key == "arrowhead" || key == "arrowsize" || key == "constraint" || key == "weight" || key == "minlen");
            if (!allowed)
            {
                throw reader.Error($"Unsupported DOT {scope} attribute '{key}'.");
            }

            if (key == "kind" && value != "process" && value != "store" && value != "datastore" && value != "external")
            {
                throw reader.Error($"Unsupported DOT kind '{value}'. Expected process, store, datastore or external.");
            }

            if (key == "shape" && value != "cylinder" && value != "box" && value != "rect" && value != "rectangle" && value != "ellipse" && value != "circle" && value != "doublecircle" && value != "diamond" && value != "hexagon" && value != "oval" && value != "plaintext" && value != "plain" && value != "none")
            {
                throw reader.Error($"Unsupported DOT shape '{value}'. Use a basic node shape and an explicit kind when needed.");
            }

            if (key == "dir" && value != "forward")
            {
                throw reader.Error($"Unsupported DOT edge direction '{value}'. Use separate forward-directed edges.");
            }

            if (key == "style" && value.Split(',').Any(part => part.Trim() == "invis"))
            {
                throw reader.Error("Unsupported DOT style 'invis'. Remove invisible layout-only nodes or edges before importing.");
            }
        }

        private static void SetGraphLabel(TextDiagramGraph graph, TextDiagramGraph.Node? boundary, string key, string value)
        {
            if (key == "label")
            {
                if (boundary == null)
                {
                    graph.Name = value;
                }
                else
                {
                    boundary.Label = value;
                }
            }
        }

        private static void ApplyNodeAttributes(TextDiagramGraph.Node node)
        {
            node.Label = node.Attributes["label"];
            node.Attributes.TryGetValue("kind", out string? kind);
            node.Attributes.TryGetValue("shape", out string? shape);
            node.Kind = kind switch
            {
                "external" => StencilKind.ExternalEntity,
                "store" or "datastore" => StencilKind.DataStore,
                "process" => StencilKind.Process,
                _ => shape == "cylinder" ? StencilKind.DataStore : StencilKind.Process,
            };
        }
    }
}
