namespace ThreatModelForge.Formats
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Xml;
    using System.Xml.Linq;
    using ThreatModelForge.Editing;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// The <c>.drawio</c> / diagrams.net format provider. Reads and writes the canonical model as an
    /// mxGraph document (plain XML, no external dependency) that opens in draw.io / diagrams.net and
    /// can be exported to <c>.vsdx</c> from there. Import reconstructs the structural diagram
    /// (elements, flows, trust boundaries, names, geometry) via the UI-agnostic
    /// <see cref="DiagramEditor"/>; it recognizes the shapes this provider writes and the documented
    /// style convention. Knowledge-base attributes and generated threats are not represented, so the
    /// mapping is structural, not lossless.
    /// </summary>
    public sealed class DrawIoFormat : IThreatModelFormat
    {
        /// <summary>
        /// The stable format identifier.
        /// </summary>
        public const string FormatId = "drawio";

        private const string ProcessStyle = "ellipse;whiteSpace=wrap;html=1;fillColor=#e0e7ff;strokeColor=#4f46e5;";
        private const string StoreStyle = "shape=partialRectangle;top=1;bottom=1;left=0;right=0;whiteSpace=wrap;html=1;fillColor=#ecfdf5;strokeColor=#059669;";
        private const string ExternalStyle = "rounded=0;whiteSpace=wrap;html=1;fillColor=#fef3c7;strokeColor=#d97706;";
        private const string BoundaryStyle = "rounded=1;dashed=1;html=1;fillColor=none;strokeColor=#dc2626;fontColor=#dc2626;verticalAlign=top;";
        private const string BoundaryLineStyle = "endArrow=none;dashed=1;html=1;strokeColor=#dc2626;";
        private const string FlowStyle = "edgeStyle=orthogonalEdgeStyle;rounded=0;html=1;endArrow=block;strokeColor=#333333;";

        private static readonly IReadOnlyList<string> SupportedExtensions = new[] { ".drawio" };

        private static readonly FormatCapabilities DrawIoCapabilities = new FormatCapabilities(
            canRead: true,
            canWrite: true,
            roundTrips: false,
            fidelityNote: "Structural mapping to and from mxGraph: nodes, flows, trust boundaries, names, and geometry. Import recognizes the shapes this provider writes and the documented style convention; knowledge-base attributes and generated threats are not represented.");

        /// <inheritdoc/>
        public string Id => FormatId;

        /// <inheritdoc/>
        public string DisplayName => "draw.io / diagrams.net (.drawio)";

        /// <inheritdoc/>
        public IReadOnlyList<string> Extensions => SupportedExtensions;

        /// <inheritdoc/>
        public FormatCapabilities Capabilities => DrawIoCapabilities;

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
                    return prefix.IndexOf("<mxfile", StringComparison.Ordinal) >= 0
                        || prefix.IndexOf("<mxGraphModel", StringComparison.Ordinal) >= 0;
                }
            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        /// <inheritdoc/>
        public ThreatModel Read(Stream stream) => this.Read(stream, null);

        /// <summary>Reads the supported diagram structure and reports omitted or inferred content.</summary>
        /// <param name="stream">The source XML.</param>
        /// <param name="diagnostics">An optional collection for source-specific warnings.</param>
        /// <returns>The structural model, or an error rather than a partial model for malformed input.</returns>
        public ThreatModel Read(Stream stream, List<DocumentDiagnostic>? diagnostics)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            // XDocument.Load(Stream) applies the framework's hardened reader settings (DtdProcessing.Prohibit,
            // bounded entity expansion, no XmlResolver), mitigating XXE and entity-expansion attacks from
            // untrusted input. PreserveWhitespace matches the previous reader; the caller-owned stream is not
            // closed by XDocument.Load(Stream).
            XDocument document = XDocument.Load(stream, LoadOptions.PreserveWhitespace);
            if (document.Root?.Name.LocalName != "mxfile" && document.Root?.Name.LocalName != "mxGraphModel")
            {
                throw new InvalidDataException("/: Not a draw.io document. Expected mxfile or mxGraphModel.");
            }

            List<XElement> pages = document.Descendants().Where(e => e.Name.LocalName == "diagram").ToList();
            if (pages.Count == 0)
            {
                pages = document.Descendants().Where(e => e.Name.LocalName == "mxGraphModel").ToList();
            }

            if (pages.Count == 0 || pages.Count > 1024)
            {
                throw new InvalidDataException("/mxfile: Expected between 1 and 1024 diagram pages.");
            }

            ThreatModel model = new ThreatModel { Version = "1.0" };
            DiagramEditor editor = new DiagramEditor(model);

            foreach (XElement page in pages)
            {
                if (page.Name.LocalName == "diagram" && !page.Elements().Any(element => element.Name.LocalName == "mxGraphModel"))
                {
                    throw new NotSupportedException("/mxfile/diagram: Compressed or missing draw.io graph content is not supported. Export uncompressed XML from diagrams.net before importing.");
                }

                DrawingSurfaceModel surface = new DrawingSurfaceModel
                {
                    Guid = Guid.NewGuid(),
                    Header = page.Attribute("name")?.Value
                        ?? ("Diagram " + (model.DrawingSurfaceList.Count + 1).ToString(System.Globalization.CultureInfo.InvariantCulture)),
                };
                model.DrawingSurfaceList.Add(surface);
                ReadPage(editor, surface, page, diagnostics);
            }

            if (model.DrawingSurfaceList.Count == 0)
            {
                model.DrawingSurfaceList.Add(new DrawingSurfaceModel { Guid = Guid.NewGuid(), Header = "Diagram 1" });
            }

            return model;
        }

        /// <inheritdoc/>
        public void Write(ThreatModel model, Stream stream)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            XElement mxfile = new XElement("mxfile", new XAttribute("host", "ThreatModelForge"));

            int index = 0;
            for (int i = 0; i < model.DrawingSurfaceList.Count; i++)
            {
                mxfile.Add(BuildDiagram(model.DrawingSurfaceList[i], ++index));
            }

            if (index == 0)
            {
                mxfile.Add(BuildDiagram(new DrawingSurfaceModel { Header = "Diagram 1" }, 1));
            }

            XmlWriterSettings settings = new XmlWriterSettings
            {
                Indent = true,
                Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                CloseOutput = false,
            };

            using (XmlWriter writer = XmlWriter.Create(stream, settings))
            {
                new XDocument(mxfile).Save(writer);
            }
        }

        private static XElement BuildDiagram(DrawingSurfaceModel surface, int index)
        {
            XElement root = new XElement(
                "root",
                new XElement("mxCell", new XAttribute("id", "0")),
                new XElement("mxCell", new XAttribute("id", "1"), new XAttribute("parent", "0")));

            // Trust-boundary boxes first so they render behind the components.
            foreach (BorderBoundary boundary in surface.Borders.Values.OfType<BorderBoundary>())
            {
                string label = GetElementName(boundary);
                root.Add(Vertex(boundary.Guid, string.IsNullOrEmpty(label) ? "Trust boundary" : label, BoundaryStyle, boundary));
            }

            foreach (DrawingElement element in surface.Borders.Values.OfType<DrawingElement>().Where(e => !(e is BorderBoundary)))
            {
                root.Add(Vertex(element.Guid, GetElementName(element), StyleFor(element), element));
            }

            foreach (LineBoundary boundary in surface.Lines.Values.OfType<LineBoundary>())
            {
                root.Add(FreeEdge(boundary.Guid, BoundaryLineStyle, boundary));
            }

            foreach (Connector connector in surface.Lines.Values.OfType<Connector>())
            {
                root.Add(FlowEdge(connector, GetElementName(connector)));
            }

            return new XElement(
                "diagram",
                new XAttribute("id", "d" + index.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                new XAttribute("name", string.IsNullOrWhiteSpace(surface.Header) ? "Diagram " + index.ToString(System.Globalization.CultureInfo.InvariantCulture) : surface.Header!),
                new XElement(
                    "mxGraphModel",
                    new XAttribute("dx", 800),
                    new XAttribute("dy", 600),
                    new XAttribute("grid", 1),
                    new XAttribute("gridSize", 10),
                    new XAttribute("guides", 1),
                    new XAttribute("tooltips", 1),
                    new XAttribute("connect", 1),
                    new XAttribute("arrows", 1),
                    new XAttribute("fold", 1),
                    new XAttribute("page", 1),
                    new XAttribute("pageScale", 1),
                    new XAttribute("math", 0),
                    new XAttribute("shadow", 0),
                    root));
        }

        private static string StyleFor(DrawingElement element)
        {
            return element switch
            {
                StencilEllipse => ProcessStyle,
                StencilParallelLines => StoreStyle,
                _ => ExternalStyle,
            };
        }

        private static XElement Vertex(Guid id, string label, string style, DrawingElement element)
        {
            return new XElement(
                "mxCell",
                new XAttribute("id", id.ToString()),
                new XAttribute("value", label ?? string.Empty),
                new XAttribute("style", style),
                new XAttribute("vertex", 1),
                new XAttribute("parent", 1),
                new XElement(
                    "mxGeometry",
                    new XAttribute("x", element.Left),
                    new XAttribute("y", element.Top),
                    new XAttribute("width", Math.Max(1, element.Width)),
                    new XAttribute("height", Math.Max(1, element.Height)),
                    new XAttribute("as", "geometry")));
        }

        private static XElement FlowEdge(Connector connector, string label)
        {
            XElement cell = new XElement(
                "mxCell",
                new XAttribute("id", connector.Guid.ToString()),
                new XAttribute("value", label ?? string.Empty),
                new XAttribute("style", FlowStyle),
                new XAttribute("edge", 1),
                new XAttribute("parent", 1));

            if (connector.SourceGuid != Guid.Empty)
            {
                cell.Add(new XAttribute("source", connector.SourceGuid.ToString()));
            }

            if (connector.TargetGuid != Guid.Empty)
            {
                cell.Add(new XAttribute("target", connector.TargetGuid.ToString()));
            }

            cell.Add(new XElement("mxGeometry", new XAttribute("relative", 1), new XAttribute("as", "geometry")));
            return cell;
        }

        private static XElement FreeEdge(Guid id, string style, LineElement line)
        {
            bool straight = (line.HandleX == 0 && line.HandleY == 0)
                || (line.HandleX == (line.SourceX + line.TargetX) / 2 && line.HandleY == (line.SourceY + line.TargetY) / 2);

            XElement geometry = new XElement(
                "mxGeometry",
                new XAttribute("relative", 1),
                new XAttribute("as", "geometry"),
                new XElement("mxPoint", new XAttribute("x", line.SourceX), new XAttribute("y", line.SourceY), new XAttribute("as", "sourcePoint")),
                new XElement("mxPoint", new XAttribute("x", line.TargetX), new XAttribute("y", line.TargetY), new XAttribute("as", "targetPoint")));

            if (!straight)
            {
                // The handle is the quadratic control point; the on-curve waypoint the spline passes
                // through is at t = 0.5, i.e. (source + 2*handle + target) / 4.
                int waypointX = (line.SourceX + (2 * line.HandleX) + line.TargetX) / 4;
                int waypointY = (line.SourceY + (2 * line.HandleY) + line.TargetY) / 4;
                geometry.Add(new XElement(
                    "Array",
                    new XAttribute("as", "points"),
                    new XElement("mxPoint", new XAttribute("x", waypointX), new XAttribute("y", waypointY))));
            }

            return new XElement(
                "mxCell",
                new XAttribute("id", id.ToString()),
                new XAttribute("style", straight ? style : style + "curved=1;"),
                new XAttribute("edge", 1),
                new XAttribute("parent", 1),
                geometry);
        }

        private static string GetElementName(Entity element)
        {
            foreach (StringDisplayAttribute property in element.Properties.OfType<StringDisplayAttribute>()
                .Where(property => string.Equals(property.Name, "Name", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(property.DisplayName, "Name", StringComparison.OrdinalIgnoreCase)))
            {
                return property.Value as string ?? string.Empty;
            }

            return string.Empty;
        }

        private static void ReadPage(DiagramEditor editor, DrawingSurfaceModel surface, XElement page, List<DocumentDiagnostic>? diagnostics)
        {
            List<XElement> cells = page.Descendants().Where(e => e.Name.LocalName == "mxCell").ToList();
            Dictionary<string, Guid> idMap = new Dictionary<string, Guid>(StringComparer.Ordinal);
            HashSet<string> cellIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (XElement cell in cells)
            {
                string id = cell.Attribute("id")?.Value ?? string.Empty;
                if (string.IsNullOrWhiteSpace(id) || !cellIds.Add(id))
                {
                    throw new InvalidDataException("/mxCell/@id: Empty or duplicate draw.io cell id '" + id + "'.");
                }
            }

            foreach (XElement cell in cells)
            {
                if (cell.Attribute("vertex")?.Value != "1")
                {
                    continue;
                }

                string id = cell.Attribute("id")?.Value ?? string.Empty;

                XElement? geometry = cell.Elements().FirstOrDefault(e => e.Name.LocalName == "mxGeometry");
                int x = ParseCoord(geometry?.Attribute("x")?.Value);
                int y = ParseCoord(geometry?.Attribute("y")?.Value);
                int width = ParseCoord(geometry?.Attribute("width")?.Value);
                int height = ParseCoord(geometry?.Attribute("height")?.Value);

                string style = cell.Attribute("style")?.Value ?? string.Empty;
                StencilKind kind = KindFromStyle(style);
                if (diagnostics != null && kind == StencilKind.ExternalEntity
                    && style.IndexOf("rounded=0", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    JsonDocumentPreflight.Add(diagnostics, "import.inferred-kind", "/mxCell[@id='" + id + "']", "Shape '" + id + "' has no recognized DFD style and is mapped to an external entity. Confirm its kind after import.", "warning");
                }

                Guid guid = editor.AddElement(surface, kind, x, y);
                if (width > 0 && height > 0)
                {
                    editor.ResizeElement(surface, guid, x, y, width, height);
                }

                editor.SetElementName(surface, guid, cell.Attribute("value")?.Value ?? string.Empty);
                idMap[id] = guid;
            }

            foreach (XElement cell in cells)
            {
                if (cell.Attribute("edge")?.Value != "1")
                {
                    continue;
                }

                string? source = cell.Attribute("source")?.Value;
                string? target = cell.Attribute("target")?.Value;
                if (source == null || target == null)
                {
                    if (source != null || target != null)
                    {
                        throw new InvalidDataException("/mxCell[@id='" + cell.Attribute("id")?.Value + "']: Flow has only one attached endpoint.");
                    }

                    if (diagnostics != null)
                    {
                        JsonDocumentPreflight.Add(diagnostics, "import.omitted-edge", "/mxCell[@id='" + cell.Attribute("id")?.Value + "']", "This free-standing line or boundary is not represented by the draw.io reader and will be omitted. Keep the source document.", "warning");
                    }

                    continue;
                }

                if (!idMap.TryGetValue(source, out Guid sourceGuid) || !idMap.TryGetValue(target, out Guid targetGuid))
                {
                    throw new InvalidDataException("/mxCell[@id='" + cell.Attribute("id")?.Value + "']: Unresolved flow endpoint '" + source + "' or '" + target + "' on this page.");
                }

                Guid connector = editor.AddConnector(surface, sourceGuid, targetGuid);
                editor.SetElementName(surface, connector, cell.Attribute("value")?.Value ?? string.Empty);
            }
        }

        private static StencilKind KindFromStyle(string style)
        {
            if (style.IndexOf("ellipse", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return StencilKind.Process;
            }

            if (style.IndexOf("partialRectangle", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return StencilKind.DataStore;
            }

            if (style.IndexOf("dashed=1", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return StencilKind.TrustBoundary;
            }

            return StencilKind.ExternalEntity;
        }

        private static int ParseCoord(string? value)
        {
            return double.TryParse(
                value,
                System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture,
                out double result)
                ? (int)Math.Round(result)
                : 0;
        }
    }
}
