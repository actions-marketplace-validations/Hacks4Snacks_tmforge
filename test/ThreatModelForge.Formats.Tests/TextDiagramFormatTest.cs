namespace ThreatModelForge.Formats.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>Contracts for bounded text-diagram import and shared DFD construction.</summary>
    [TestClass]
    public class TextDiagramFormatTest
    {
        private const string Mermaid = """
            %% A README-sized service diagram
            flowchart LR
                caller[Caller]:::external
                subgraph cloud[Cloud]
                    api[API]
                    subgraph data[Data tier]
                        db[(Database)]
                    end
                    api -->|query| db
                end
                caller -->|request| api
            """;

        private const string Dot = """
            // A README-sized service diagram
            digraph Service {
                rankdir=LR;
                caller [label="Caller", kind=external];
                subgraph cluster_cloud {
                    label="Cloud";
                    api [label="API"];
                    subgraph cluster_data {
                        label="Data tier";
                        db [label="Database", shape=cylinder];
                    }
                    api -> db [label="query"];
                }
                caller -> api [label="request"];
            }
            """;

        /// <summary>Nested boundaries retain exactly their declared components and flow endpoints.</summary>
        /// <param name="format">The source format.</param>
        [TestMethod]
        [DataRow("mermaid")]
        [DataRow("dot")]
        public void PreservesNestedMembershipAndUnknownControls(string format)
        {
            DrawingSurfaceModel page = Read(format, Fixture(format)).DrawingSurfaceList.Single();
            Assert.HasCount(5, page.Borders);
            Assert.HasCount(2, page.Lines);
            DrawingElement caller = Element(page, "Caller");
            DrawingElement api = Element(page, "API");
            DrawingElement store = Element(page, "Database");
            DrawingElement cloud = Element(page, "Cloud");
            DrawingElement data = Element(page, "Data tier");
            Assert.AreEqual("GE.EI", caller.GenericTypeId);
            Assert.AreEqual("GE.P", api.GenericTypeId);
            Assert.AreEqual("GE.DS", store.GenericTypeId);
            Assert.IsInstanceOfType<BorderBoundary>(cloud);
            Assert.IsInstanceOfType<BorderBoundary>(data);
            Assert.IsTrue(Contains(cloud, api));
            Assert.IsTrue(Contains(cloud, store));
            Assert.IsTrue(Contains(cloud, data));
            Assert.IsTrue(Contains(data, store));
            Assert.IsFalse(Contains(data, api));
            Assert.IsFalse(Contains(cloud, caller));
            Assert.AreEqual("Unknown", DiagramElementHelper.GetCustomProperties(api)["AuthenticationScheme"]);
            Assert.AreEqual("Unknown", DiagramElementHelper.GetCustomProperties(store)["Encrypted"]);
            Assert.AreEqual("Unknown", DiagramElementHelper.GetCustomProperties(caller)["AuthenticatesItself"]);
            Assert.AreEqual("api", DiagramElementHelper.GetCustomProperties(api)["Source.Id"]);
            Connector request = page.Lines.Values.OfType<Connector>().Single(flow => DiagramElementHelper.GetName(flow) == "request");
            Connector query = page.Lines.Values.OfType<Connector>().Single(flow => DiagramElementHelper.GetName(flow) == "query");
            Assert.AreEqual(caller.Guid, request.SourceGuid);
            Assert.AreEqual(api.Guid, request.TargetGuid);
            Assert.AreEqual(api.Guid, query.SourceGuid);
            Assert.AreEqual(store.Guid, query.TargetGuid);
            Assert.AreEqual("Unknown", DiagramElementHelper.GetCustomProperties(request)["Protocol"]);
            Assert.AreEqual("Unknown", DiagramElementHelper.GetCustomProperties(request)["DataType"]);
        }

        /// <summary>Repeated imports produce byte-identical persisted models, not just matching counts.</summary>
        /// <param name="format">The source format.</param>
        /// <param name="destination">The persisted format.</param>
        [TestMethod]
        [DataRow("mermaid", "tmforge-json")]
        [DataRow("mermaid", "tm7")]
        [DataRow("dot", "tmforge-json")]
        [DataRow("dot", "tm7")]
        public void ReimportsAreByteIdenticalAndRoundTrip(string format, string destination)
        {
            ThreatModel first = Read(format, Fixture(format));
            byte[] original = Write(first, destination);
            CollectionAssert.AreEqual(original, Write(Read(format, Fixture(format)), destination));
            using MemoryStream stream = new MemoryStream(original);
            ThreatModel restored = Provider(destination).Read(stream);
            Assert.IsTrue(ModelDiff.Compare(first, restored).IsEmpty);
            Assert.AreEqual(first.DrawingSurfaceList.Single().Guid, restored.DrawingSurfaceList.Single().Guid);
            Assert.IsTrue(Contains(Element(restored.DrawingSurfaceList.Single(), "Cloud"), Element(restored.DrawingSurfaceList.Single(), "API")));
        }

        /// <summary>Labels and unrelated additions do not renumber existing objects.</summary>
        /// <param name="format">The source format.</param>
        [TestMethod]
        [DataRow("mermaid")]
        [DataRow("dot")]
        public void RenamingLabelsPreservesPageNodeAndFlowIdentity(string format)
        {
            ThreatModel first = Read(format, Fixture(format));
            ThreatModel renamed = Read(format, Fixture(format).Replace("API", "API v2").Replace("request", "request v2"));
            DrawingSurfaceModel before = first.DrawingSurfaceList.Single();
            DrawingSurfaceModel after = renamed.DrawingSurfaceList.Single();
            Assert.AreEqual(before.Guid, after.Guid);
            CollectionAssert.AreEquivalent(before.Borders.Keys.ToArray(), after.Borders.Keys.ToArray());
            CollectionAssert.AreEquivalent(before.Lines.Keys.ToArray(), after.Lines.Keys.ToArray());
            Assert.AreEqual(Element(before, "API").Guid, Element(after, "API v2").Guid);
            Assert.HasCount(0, ModelDiff.Compare(first, renamed).Added);
            Assert.HasCount(0, ModelDiff.Compare(first, renamed).Removed);
        }

        /// <summary>Header recognition disambiguates Mermaid graph from DOT graph and preserves offsets.</summary>
        /// <param name="format">The recognized provider.</param>
        /// <param name="source">The source header.</param>
        [TestMethod]
        [DataRow("mermaid", "graph LR\napi --> db")]
        [DataRow("mermaid", "\uFEFF%% heading\nflowchart TB\napi --> db")]
        [DataRow("mermaid", "```mermaid\nflowchart LR\napi --> db\n```")]
        [DataRow("dot", "/* heading */ digraph G { api -> db }")]
        [DataRow("dot", "graph G { api -- db }")]
        [DataRow("dot", "graph LR { api -- db }")]
        [DataRow("dot", "strict digraph G { api -> db }")]
        [DataRow("dot", "DiGraph G { api -> db }")]
        public void SniffsFormatWithoutConsumingStream(string format, string source)
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes("prefix" + source));
            stream.Position = 6;
            Assert.AreEqual(format, ThreatModelFormatRegistry.CreateDefault().Sniff(stream)?.Id);
            Assert.AreEqual(6L, stream.Position);
            Assert.IsTrue(stream.CanRead);
        }

        /// <summary>Common Mermaid shape and directed-link variants retain labels and chain topology.</summary>
        [TestMethod]
        public void MermaidReadsShapesChainsCommentsAndQuotedLabels()
        {
            string source = """
                ```mermaid
                graph LR;
                A["Caller; %% text"]:::external -->|"request | one"| B(API) --> C[(Database)]
                B-.->D{Allowed?}
                D ==> E([Complete]); E --> F[[Worker]]; F --> G((Queue)); G --> H{{Choice}}
                B -- "response" --> A
                B -. retry .-> C
                B == batch ==> C
                %% harmless comment
                ```
                """;
            DrawingSurfaceModel page = Read("mermaid", source).DrawingSurfaceList.Single();
            Assert.HasCount(8, page.Borders);
            Assert.HasCount(10, page.Lines);
            Assert.AreEqual("GE.EI", Element(page, "Caller; %% text").GenericTypeId);
            Assert.AreEqual("GE.DS", Element(page, "Database").GenericTypeId);
            CollectionAssert.IsSubsetOf(new[] { "request | one", "response", "retry", "batch" }, page.Lines.Values.OfType<Entity>().Select(DiagramElementHelper.GetName).ToArray());
        }

        /// <summary>Explicit Mermaid kind classes remain in force after a later label declaration.</summary>
        [TestMethod]
        public void MermaidKindSurvivesLabelUpdates()
        {
            DrawingSurfaceModel page = Read("mermaid", "flowchart LR\na[Old]:::external\na[New] --> b").DrawingSurfaceList.Single();
            Assert.AreEqual("GE.EI", Element(page, "New").GenericTypeId);
        }

        /// <summary>Ordinary punctuation is text, not an HTML or entity encoding.</summary>
        [TestMethod]
        public void MermaidPreservesPlainPunctuation()
        {
            DrawingSurfaceModel page = Read("mermaid", "flowchart LR\na[\"Read & write #1: cost > 0\"] -->|v1 & v2| b").DrawingSurfaceList.Single();
            Assert.IsNotNull(Element(page, "Read & write #1: cost > 0"));
            Assert.AreEqual("v1 & v2", DiagramElementHelper.GetName(page.Lines.Values.OfType<Connector>().Single()));
        }

        /// <summary>DOT statement keywords ignore case and subgraphs inherit graph labels at definition time.</summary>
        [TestMethod]
        public void DotPreservesKeywordCaseAndInheritedLabels()
        {
            const string Source = "DiGraph G { GRAPH[label=\"Shared\"]; NODE[shape=cylinder]; SUBGRAPH cluster_one { first; } graph[label=\"Updated\"]; subgraph cluster_two { NODE[kind=process]; second; } first -> second; }";
            ThreatModel model = Read("dot", Source);
            DrawingSurfaceModel page = model.DrawingSurfaceList.Single();
            Assert.AreEqual("Updated", model.MetaInformation?.ThreatModelName);
            Assert.IsTrue(Contains(Element(page, "Shared"), Element(page, "first")));
            Assert.IsTrue(Contains(Element(page, "Updated"), Element(page, "second")));
            Assert.AreEqual("GE.DS", Element(page, "first").GenericTypeId);
            Assert.AreEqual("GE.P", Element(page, "second").GenericTypeId);
        }

        /// <summary>DOT defaults apply on first use, are scoped, and explicit kinds override shapes.</summary>
        [TestMethod]
        public void DotReadsScopedDefaultsQuotedIdsAndEdgeIdentities()
        {
            string source = """
                digraph "Services" {
                    graph [label="Service model"];
                    node [shape=box, color=black];
                    edge [label="request"];
                    "caller-id" [kind=external];
                    subgraph cluster_zone {
                        graph [label="Service"];
                        node [shape=cylinder];
                        store;
                        api [kind=process, label="API"];
                    }
                    node [kind=external];
                    store [label="Database"];
                    "caller-id" -> api [id=primary, label="call"];
                    api -> store -> "caller-id";
                    1.5 -> -2 [label="numeric ids"];
                }
                """;
            ThreatModel model = Read("dot", source);
            DrawingSurfaceModel page = model.DrawingSurfaceList.Single();
            Assert.AreEqual("Service model", model.MetaInformation?.ThreatModelName);
            Assert.AreEqual("GE.DS", Element(page, "Database").GenericTypeId);
            Assert.AreEqual("GE.P", Element(page, "API").GenericTypeId);
            Assert.AreEqual("GE.EI", Element(page, "caller-id").GenericTypeId);
            Assert.HasCount(4, page.Lines);
            Connector primary = page.Lines.Values.OfType<Connector>().Single(flow => DiagramElementHelper.GetName(flow) == "call");
            Assert.AreEqual("primary", DiagramElementHelper.GetCustomProperties(primary)["Source.Id"]);
            DrawingSurfaceModel updated = Read("dot", source.Replace("\"caller-id\" -> api [id=primary", "\"caller-id\" -> store [id=primary")).DrawingSurfaceList.Single();
            Assert.AreEqual(primary.Guid, updated.Lines.Values.OfType<Connector>().Single(flow => DiagramElementHelper.GetName(flow) == "call").Guid);
        }

        /// <summary>Unsupported syntax is named and no partial model is returned.</summary>
        /// <param name="format">The source format.</param>
        /// <param name="source">The unsupported document.</param>
        /// <param name="reason">The diagnostic discriminator.</param>
        [TestMethod]
        [DataRow("mermaid", "sequenceDiagram\nA->>B: hello", "sequenceDiagram")]
        [DataRow("mermaid", "flowchart LR\na --> b\nclick a callback", "click")]
        [DataRow("mermaid", "flowchart LR\na --> b\nclassDef red fill:red", "classDef")]
        [DataRow("mermaid", "%%{init: {}}%%\nflowchart LR\na --> b", "initialization")]
        [DataRow("mermaid", "flowchart LR\na --> b\nstyle a fill:red", "style")]
        [DataRow("mermaid", "flowchart LR\na <--> b", "<-->")]
        [DataRow("mermaid", "flowchart LR\na --- b", "---")]
        [DataRow("mermaid", "flowchart LR\na & b --> c", "&")]
        [DataRow("mermaid", "flowchart LR\na:::red", "red")]
        [DataRow("mermaid", "flowchart LR\na[/Input/]", "shape")]
        [DataRow("mermaid", "flowchart LR\na[\"API<br/>v2\"]", "HTML")]
        [DataRow("mermaid", "flowchart LR\na[\"A #quot; quote\"]", "entity")]
        [DataRow("mermaid", "flowchart LR\na[\"A &amp; B\"]", "entity")]
        [DataRow("mermaid", "flowchart LR\na --> end", "end")]
        [DataRow("mermaid", "flowchart LR\na[\"`Markdown`\"]", "Markdown")]
        [DataRow("mermaid", "flowchart LR\nsubgraph zone\na --> b", "missing 'end'")]
        [DataRow("mermaid", "flowchart LR\nend", "Unexpected 'end'")]
        [DataRow("mermaid", "flowchart LR\nsubgraph first\na\nend\nsubgraph second\na\nend", "overlapping")]
        [DataRow("mermaid", "flowchart LR\nsubgraph zone\na\nend\nzone --> b", "Subgraph endpoint")]
        [DataRow("mermaid", "```mermaid\nflowchart LR\na --> b\n```\nOther prose", "trailing")]
        [DataRow("dot", "graph G { a -- b }", "digraph")]
        [DataRow("dot", "strict digraph G { a -> b }", "strict")]
        [DataRow("dot", "digraph G { a -- b }", "undirected")]
        [DataRow("dot", "digraph G { a:port -> b }", "port")]
        [DataRow("dot", "digraph G { a [label=<b>]; }", "HTML")]
        [DataRow("dot", "digraph G { a [URL=\"https://example.invalid\"]; }", "URL")]
        [DataRow("dot", "digraph G { a [shape=record]; }", "record")]
        [DataRow("dot", "digraph G { a [kind=server]; }", "server")]
        [DataRow("dot", "digraph G { a -> b [dir=both]; }", "direction")]
        [DataRow("dot", "digraph G { a -> b [style=invis]; }", "invis")]
        [DataRow("dot", "digraph G { a -> b -> c [id=duplicate]; }", "edge chain")]
        [DataRow("dot", "digraph G { a -> b [id=duplicate]; a -> b [id=duplicate]; }", "Duplicate")]
        [DataRow("dot", "digraph G { subgraph zone { a; } }", "cluster_*")]
        [DataRow("dot", "digraph G { subgraph cluster_one { a; } subgraph cluster_two { a; } }", "overlapping")]
        [DataRow("dot", "digraph G { subgraph cluster_one { a; } subgraph cluster_one { b; } }", "Duplicate")]
        [DataRow("dot", "digraph G { a [label=\"unterminated]; }", "Expected")]
        [DataRow("dot", "digraph G { a [label=\"\\N\"]; }", "escape")]
        [DataRow("dot", "digraph G { \"a\\n\" -> b; }", "identifier")]
        [DataRow("dot", "digraph G { a -> NODE; }", "Reserved")]
        [DataRow("dot", "digraph G { strict; }", "Reserved")]
        [DataRow("dot", "digraph G { a -> b; } extra", "trailing")]
        public void RejectsUnsupportedSyntaxWithLocations(string format, string source, string reason)
        {
            InvalidDataException error = Assert.Throws<InvalidDataException>(() => Read(format, source));
            StringAssert.Contains(error.Message, reason);
            StringAssert.Contains(error.Message, "line ");
            StringAssert.Contains(error.Message, "column ");
        }

        /// <summary>Input size, graph size, recursion and label budgets are enforced before layout.</summary>
        /// <param name="format">The source format.</param>
        [TestMethod]
        [DataRow("mermaid")]
        [DataRow("dot")]
        public void BoundsParsingWork(string format)
        {
            IThreatModelFormat provider = Provider(format);
            using MemoryStream oversized = new MemoryStream(new byte[(8 * 1024 * 1024) + 1]);
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => provider.Read(oversized)).Message, "8 MiB");
            string nodes = string.Join(";", Enumerable.Range(0, 257).Select(index => "node" + index));
            string source = format == "dot" ? "digraph {" + nodes + "}" : "flowchart LR\n" + nodes;
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(format, source)).Message, "256");
            string edges = string.Join(";", Enumerable.Repeat(format == "dot" ? "a -> b" : "a --> b", 513));
            source = format == "dot" ? "digraph {" + edges + "}" : "flowchart LR\n" + edges;
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(format, source)).Message, "512");
            string nested = string.Concat(Enumerable.Range(0, 17).Select(index => format == "dot" ? "subgraph cluster_" + index + " {" : "subgraph zone" + index + "\n"));
            source = format == "dot" ? "digraph {" + nested : "flowchart LR\n" + nested;
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(format, source)).Message, "16 levels");
            string label = new string('x', 2049);
            source = format == "dot" ? "digraph { a [label=\"" + label + "\"]; }" : "flowchart LR\na[\"" + label + "\"]";
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => Read(format, source)).Message, "2048");
        }

        /// <summary>Public stream contracts fail explicitly and writers cannot clobber a source.</summary>
        /// <param name="format">The source format.</param>
        [TestMethod]
        [DataRow("mermaid")]
        [DataRow("dot")]
        public void PreservesStreamOwnershipAndRefusesNativeWrites(string format)
        {
            IThreatModelFormat provider = Provider(format);
            using MemoryStream input = new MemoryStream(Encoding.UTF8.GetBytes(Fixture(format)));
            provider.Read(input);
            Assert.IsTrue(input.CanRead);
            Assert.Throws<ArgumentNullException>(() => provider.Read(null!));
            Assert.Throws<ArgumentNullException>(() => provider.CanRead(null!));
            using MemoryStream output = new MemoryStream();
            Assert.Throws<NotSupportedException>(() => provider.Write(new ThreatModel(), output));
            Assert.AreEqual(0L, output.Length);
            using MemoryStream invalid = new MemoryStream(new byte[] { 0xff, 0xfe, 0xff });
            StringAssert.Contains(Assert.Throws<InvalidDataException>(() => provider.Read(invalid)).Message, "UTF-8");
        }

        private static string Fixture(string format) => format == "mermaid" ? Mermaid : Dot;

        private static IThreatModelFormat Provider(string format) => ThreatModelFormatRegistry.CreateDefault().FindById(format)
            ?? throw new InvalidOperationException("Missing format " + format);

        private static ThreatModel Read(string format, string source)
        {
            using MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(source));
            return Provider(format).Read(stream);
        }

        private static byte[] Write(ThreatModel model, string format)
        {
            using MemoryStream stream = new MemoryStream();
            Provider(format).Write(model, stream);
            return stream.ToArray();
        }

        private static DrawingElement Element(DrawingSurfaceModel page, string label)
            => page.Borders.Values.OfType<DrawingElement>().Single(element => DiagramElementHelper.GetName(element) == label);

        private static bool Contains(DrawingElement boundary, DrawingElement member)
            => member.Left > boundary.Left && member.Top > boundary.Top
                && member.Left + member.Width < boundary.Left + boundary.Width
                && member.Top + member.Height < boundary.Top + boundary.Height;
    }
}
