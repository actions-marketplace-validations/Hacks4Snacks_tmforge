namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;

    /// <summary>Imports a bounded subset of Mermaid flowcharts as starter threat models.</summary>
    public sealed class MermaidFormat : IThreatModelFormat
    {
        /// <summary>The import provider's stable identifier.</summary>
        public const string FormatId = "mermaid";

        private static readonly FormatCapabilities ImportCapabilities = new FormatCapabilities(
            canRead: true,
            canWrite: false,
            roundTrips: false,
            fidelityNote: "Import-only Mermaid flowchart/graph subset: nodes, directed edges and nested named subgraphs. Subgraphs are interpreted as trust boundaries, not verified isolation. Cylinder nodes become stores; inline process/store/datastore/external classes select kinds, otherwise process. Geometry and link styling are regenerated; controls are Unknown. Styling directives, callbacks, Markdown labels and other diagram grammars are refused.");

        /// <inheritdoc/>
        public string Id => FormatId;

        /// <inheritdoc/>
        public string DisplayName => "Mermaid flowchart (.mmd, .mermaid)";

        /// <inheritdoc/>
        public IReadOnlyList<string> Extensions => new[] { ".mmd", ".mermaid" };

        /// <inheritdoc/>
        public FormatCapabilities Capabilities => ImportCapabilities;

        /// <inheritdoc/>
        public bool CanRead(Stream stream) => DiagramTextReader.Sniff(stream, dot: false);

        /// <inheritdoc/>
        public ThreatModel Read(Stream stream)
        {
            DiagramTextReader reader = new DiagramTextReader(DiagramTextReader.ReadText(stream), dot: false);
            TextDiagramGraph graph = new TextDiagramGraph(FormatId, reader);
            reader.SkipSpace(true);
            bool fenced = reader.Take("```mermaid");
            if (fenced)
            {
                EndStatement(reader);
                reader.SkipSpace(true);
            }

            if (!reader.Word("flowchart") && !reader.Word("graph"))
            {
                throw reader.Error($"Unsupported Mermaid diagram {reader.DescribeCurrent()}. Expected 'flowchart' or 'graph'.");
            }

            ReadDirection(reader);
            EndStatement(reader);
            Stack<string> boundaries = new Stack<string>();
            int statements = 0;
            while (true)
            {
                reader.SkipSpace(true);
                if (reader.Take(";"))
                {
                    continue;
                }

                if (reader.End || (fenced && reader.At("```")))
                {
                    break;
                }

                if (++statements > 10000)
                {
                    throw reader.Error("Text diagram import is limited to 10000 statements.");
                }

                string? parent = boundaries.Count == 0 ? null : boundaries.Peek();
                if (reader.Word("subgraph"))
                {
                    if (boundaries.Count >= 16)
                    {
                        throw reader.Error("Subgraph nesting is limited to 16 levels.");
                    }

                    reader.SkipSpace();
                    string id = reader.Identifier();
                    reader.SkipSpace();
                    string label = reader.Take("[") ? reader.Label("]") : id;
                    graph.Boundary(id, label, parent);
                    boundaries.Push(id);
                }
                else if (reader.Word("end"))
                {
                    if (boundaries.Count == 0)
                    {
                        throw reader.Error("Unexpected 'end' without a subgraph.");
                    }

                    boundaries.Pop();
                }
                else if (reader.Word("direction"))
                {
                    if (boundaries.Count == 0)
                    {
                        throw reader.Error("A 'direction' statement must be inside a subgraph.");
                    }

                    ReadDirection(reader);
                }
                else
                {
                    TextDiagramGraph.Node source = ReadNode(reader, graph, parent);
                    reader.SkipSpace();
                    while (reader.At("-->") || reader.At("-.->") || reader.At("==>") || reader.At("-- ") || reader.At("-. ") || reader.At("== "))
                    {
                        string label = string.Empty;
                        if (reader.Take("-->") || reader.Take("-.->") || reader.Take("==>"))
                        {
                            reader.SkipSpace();
                            if (reader.Take("|"))
                            {
                                label = reader.Label("|");
                            }
                        }
                        else
                        {
                            string closing = reader.Take("-- ") ? "-->" : reader.Take("-. ") ? ".->" : "==>";
                            if (closing == "==>")
                            {
                                reader.Expect("== ");
                            }

                            label = reader.Label(closing);
                        }

                        reader.SkipSpace();
                        TextDiagramGraph.Node target = ReadNode(reader, graph, parent);
                        graph.AddFlow(source.Id, target.Id, label);
                        source = target;
                        reader.SkipSpace();
                    }
                }

                EndStatement(reader);
            }

            if (boundaries.Count != 0)
            {
                throw reader.Error($"Subgraph '{boundaries.Peek()}' is missing 'end'.");
            }

            if (fenced)
            {
                reader.Expect("```");
                reader.SkipSpace(true);
            }

            if (!reader.End)
            {
                throw reader.Error($"Unsupported trailing content {reader.DescribeCurrent()}. Import one Mermaid block without surrounding Markdown.");
            }

            return graph.Build();
        }

        /// <inheritdoc/>
        public void Write(ThreatModel model, Stream stream)
        {
            throw new NotSupportedException("Mermaid is import-only. Save as tmforge-json or tm7 instead.");
        }

        private static void ReadDirection(DiagramTextReader reader)
        {
            reader.SkipSpace();
            string direction = reader.Identifier();
            if (direction != "LR" && direction != "RL" && direction != "TB" && direction != "TD" && direction != "BT")
            {
                throw reader.Error($"Unsupported Mermaid direction '{direction}'. Expected LR, RL, TB, TD or BT.");
            }
        }

        private static TextDiagramGraph.Node ReadNode(DiagramTextReader reader, TextDiagramGraph graph, string? parent)
        {
            string id = reader.Identifier();
            if (id == "click" || id == "style" || id == "classDef" || id == "class" || id == "linkStyle" || id == "accTitle" || id == "accDescr"
                || id == "end" || id == "subgraph" || id == "direction")
            {
                throw reader.Error($"Unsupported Mermaid directive '{id}'.");
            }

            TextDiagramGraph.Node node = graph.NodeFor(id, parent);
            reader.SkipSpace();
            if (reader.At("[/") || reader.At("[\\"))
            {
                throw reader.Error("Unsupported Mermaid parallelogram or trapezoid shape. Use a basic node shape.");
            }

            string? closing = null;
            StencilKind kind = StencilKind.Process;
            if (reader.Take("[("))
            {
                closing = ")]";
                kind = StencilKind.DataStore;
            }
            else if (reader.Take("(["))
            {
                closing = "])";
            }
            else if (reader.Take("(("))
            {
                closing = "))";
            }
            else if (reader.Take("[["))
            {
                closing = "]]";
            }
            else if (reader.Take("{{"))
            {
                closing = "}}";
            }
            else if (reader.Take("["))
            {
                closing = "]";
            }
            else if (reader.Take("("))
            {
                closing = ")";
            }
            else if (reader.Take("{"))
            {
                closing = "}";
            }

            if (closing != null)
            {
                node.Label = reader.Label(closing);
                if (!node.Attributes.ContainsKey("kind"))
                {
                    node.Kind = kind;
                }
            }

            reader.SkipSpace();
            if (reader.Take(":::"))
            {
                string className = reader.Identifier();
                node.Kind = className switch
                {
                    "process" => StencilKind.Process,
                    "store" or "datastore" => StencilKind.DataStore,
                    "external" => StencilKind.ExternalEntity,
                    _ => throw reader.Error($"Unsupported Mermaid class '{className}'. Supported kind classes: process, store, datastore, external."),
                };
                node.Attributes["kind"] = className;
            }

            return node;
        }

        private static void EndStatement(DiagramTextReader reader)
        {
            reader.SkipSpace();
            if (reader.End || reader.Take(";") || reader.Take("\n"))
            {
                return;
            }

            throw reader.Error($"Unsupported Mermaid syntax {reader.DescribeCurrent()}. Expected the end of a statement; use directed edges and separate statements with a newline or semicolon.");
        }
    }
}
