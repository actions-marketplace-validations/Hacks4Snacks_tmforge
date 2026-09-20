namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc.Testing;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;

    /// <summary>
    /// Tests the hosted <c>/v1</c> surface over real HTTP. The rest of this project drives
    /// <c>EngineService</c> directly, which leaves everything the host itself owns unexercised:
    /// routing, status codes, model binding, query-string handling, content types, and download file
    /// names. Those are the parts a client actually depends on, and none of them are visible from a
    /// facade-level test.
    /// </summary>
    [TestClass]
    public class ApiEndpointsTest
    {
        /// <summary>A minimal but real model: one process, no flows.</summary>
        private const string Model =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[{\"id\":\"a\",\"kind\":\"process\",\"name\":\"Alpha\",\"x\":10,\"y\":10,\"width\":120,\"height\":60}]," +
            "\"flows\":[]}";

        /// <summary>
        /// A request body carrying a real authoring manifest. The manifest travels as a JSON string so
        /// its envelope is checked exactly as written, which is why it is escaped here rather than
        /// nested as an object.
        /// </summary>
        private const string ManifestRequest =
            "{\"manifest\":\"{" +
            "\\\"schema\\\":\\\"tmforge-manifest\\\",\\\"version\\\":1,\\\"name\\\":\\\"T\\\"," +
            "\\\"boundaries\\\":[{\\\"alias\\\":\\\"tb1\\\",\\\"name\\\":\\\"Edge\\\"}]," +
            "\\\"elements\\\":[" +
            "{\\\"alias\\\":\\\"a1\\\",\\\"kind\\\":\\\"external\\\",\\\"name\\\":\\\"User\\\",\\\"boundary\\\":\\\"tb1\\\"}," +
            "{\\\"alias\\\":\\\"p1\\\",\\\"kind\\\":\\\"process\\\",\\\"name\\\":\\\"Gateway\\\",\\\"boundary\\\":\\\"tb1\\\"}]," +
            "\\\"flows\\\":[{\\\"from\\\":\\\"a1\\\",\\\"to\\\":\\\"p1\\\",\\\"name\\\":\\\"Sign in\\\"}]" +
            "}\"}";

        /// <summary>
        /// The in-memory host. <c>Program</c> is a static class and cannot be a type argument, so the
        /// factory is anchored on a public type from the same assembly — it only uses the type to
        /// locate that assembly's entry point.
        /// </summary>
        private static WebApplicationFactory<HealthStatusDto>? factory;

        private static HttpClient? client;

        /// <summary>Gets the shared client.</summary>
        private static HttpClient Client => client ?? throw new InvalidOperationException("Host not started.");

        /// <summary>Starts one host for the whole class; booting it per test would dominate the run.</summary>
        /// <param name="context">The MSTest context.</param>
        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            factory = new WebApplicationFactory<HealthStatusDto>();
            client = factory.CreateClient();
        }

        /// <summary>Shuts the host down.</summary>
        [ClassCleanup]
        public static void ClassCleanup()
        {
            client?.Dispose();
            factory?.Dispose();
        }

        /// <summary>Verifies the health probe the container smoke test and orchestrators depend on.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Health_ReportsOk()
        {
            using HttpResponseMessage response = await Client.GetAsync("/v1/health");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual("ok", body.RootElement.GetProperty("status").GetString());
        }

        /// <summary>
        /// Verifies every catalog route serves a non-empty collection. A non-empty body is what
        /// separates "the route is wired" from "the engine is actually behind it".
        /// </summary>
        /// <param name="route">The catalog route.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("/v1/formats")]
        [DataRow("/v1/stencils")]
        [DataRow("/v1/stencil-packs")]
        [DataRow("/v1/rules")]
        [DataRow("/v1/rule-packs")]
        [DataRow("/v1/property-schema")]
        public async Task Catalogs_ServeNonEmptyCollections(string route)
        {
            using HttpResponseMessage response = await Client.GetAsync(route);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(JsonValueKind.Array, body.RootElement.ValueKind);
            Assert.IsTrue(body.RootElement.GetArrayLength() > 0, route + " served an empty catalog.");
        }

        /// <summary>
        /// Verifies the rule bundle is served with the shape the Studio reads. A default host loads no
        /// custom packs, so the pack list is legitimately empty here — <see cref="ApiCustomRulesTest"/>
        /// covers a host that has been given one.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task RuleBundle_IsServedWithNoCustomPacksByDefault()
        {
            using HttpResponseMessage response = await Client.GetAsync("/v1/rule-bundle");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(JsonValueKind.Array, body.RootElement.GetProperty("rulePacks").ValueKind);
            Assert.AreEqual(0, body.RootElement.GetProperty("rulePacks").GetArrayLength());
            Assert.AreEqual(0, body.RootElement.GetProperty("diagnostics").GetArrayLength());
        }

        /// <summary>Verifies the analysis routes accept a model and answer with JSON.</summary>
        /// <param name="route">The analysis route.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("/v1/model/analyze")]
        [DataRow("/v1/model/analysis")]
        [DataRow("/v1/model/analysis-document")]
        [DataRow("/v1/model/threats")]
        [DataRow("/v1/model/threat-register")]
        public async Task ModelRoutes_AcceptAModelAndAnswerJson(string route)
        {
            using HttpResponseMessage response = await PostJson(route, Model);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("application/json", response.Content.Headers.ContentType?.MediaType);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreNotEqual(JsonValueKind.Null, body.RootElement.ValueKind);
        }

        /// <summary>Verifies a three-way merge is accepted in the shape the Studio posts it.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Merge_AcceptsBaseOursAndTheirs()
        {
            string request = "{\"base\":" + Model + ",\"ours\":" + Model + ",\"theirs\":" + Model + "}";

            using HttpResponseMessage response = await PostJson("/v1/model/merge", request);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(JsonValueKind.Object, body.RootElement.ValueKind);
        }

        /// <summary>The comparison endpoint returns the same read-only review as the shared engine.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Compare_MatchesSharedEngineAndRejectsMissingSnapshots()
        {
            string request = "{\"baseline\":" + Model + ",\"proposed\":" + Model.Replace("Alpha", "Renamed Alpha") + "}";
            JsonSerializerOptions options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
            ModelCompareRequestDto input = JsonSerializer.Deserialize<ModelCompareRequestDto>(request, options) ?? new ModelCompareRequestDto();
            string expected = JsonSerializer.Serialize(EngineService.Compare(input, null), options);

            using HttpResponseMessage response = await PostJson("/v1/model/compare", request);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsTrue(JsonNode.DeepEquals(JsonNode.Parse(expected), JsonNode.Parse(await response.Content.ReadAsStringAsync())));
            using HttpResponseMessage invalid = await PostJson("/v1/model/compare", "{}");
            Assert.AreEqual(HttpStatusCode.OK, invalid.StatusCode);
            using JsonDocument result = JsonDocument.Parse(await invalid.Content.ReadAsStringAsync());
            Assert.IsFalse(result.RootElement.GetProperty("success").GetBoolean());
            Assert.AreEqual(0, result.RootElement.GetProperty("changes").GetArrayLength());
        }

        /// <summary>The HTTP layout route returns exactly the shared facade's author-id geometry.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Layout_MatchesTheSharedEngine()
        {
            string request = "{\"model\":" + Model + ",\"positions\":[{\"id\":\"a\",\"x\":100,\"y\":150,\"width\":240,\"height\":120}]}";
            JsonSerializerOptions options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
            LayoutRequestDto input = JsonSerializer.Deserialize<LayoutRequestDto>(request, options) ?? new LayoutRequestDto();
            string expected = JsonSerializer.Serialize(EngineService.Layout(input), options);

            using HttpResponseMessage response = await PostJson("/v1/model/layout", request);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(expected, await response.Content.ReadAsStringAsync());
        }

        /// <summary>The HTTP route validates a Tidy candidate without moving it into new layers.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Layout_PreservesProposedTidyPositions()
        {
            string request = "{\"model\":" + Model + ",\"positions\":[{\"id\":\"a\",\"x\":345,\"y\":678,\"width\":200,\"height\":120}]}";

            using HttpResponseMessage response = await PostJson("/v1/model/layout", request);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.IsTrue(body.RootElement.GetProperty("success").GetBoolean());
            JsonElement element = body.RootElement.GetProperty("elements")[0];
            Assert.AreEqual("a", element.GetProperty("id").GetString());
            Assert.AreEqual(345, element.GetProperty("x").GetInt32());
            Assert.AreEqual(678, element.GetProperty("y").GetInt32());
        }

        /// <summary>A refusal is explicit and carries no partial geometry.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Layout_ReportsInvalidInputWithoutPatches()
        {
            using HttpResponseMessage response = await PostJson("/v1/model/layout", "{}");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.IsFalse(body.RootElement.GetProperty("success").GetBoolean());
            Assert.AreEqual(0, body.RootElement.GetProperty("elements").GetArrayLength());
            Assert.IsFalse(string.IsNullOrWhiteSpace(body.RootElement.GetProperty("error").GetString()));
        }

        /// <summary>Verifies the .tm7 export is delivered as a downloadable XML document.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task ExportTm7_DownloadsXml()
        {
            using HttpResponseMessage response = await PostJson("/v1/model/export/tm7", Model);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("application/xml", response.Content.Headers.ContentType?.MediaType);
            Assert.AreEqual("model.tm7", response.Content.Headers.ContentDisposition?.FileName);

            // The MTMT root element, not merely well-formed XML: this is what makes the download a .tm7.
            StringAssert.StartsWith(await response.Content.ReadAsStringAsync(), "<ThreatModel");
        }

        /// <summary>
        /// Verifies each conversion target carries the content type and download name a browser needs.
        /// These pairings live only in the host, so nothing below it can catch them being swapped.
        /// </summary>
        /// <param name="format">The target format id.</param>
        /// <param name="contentType">The expected content type.</param>
        /// <param name="fileName">The expected download file name.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("tm7", "application/xml", "model.tm7")]
        [DataRow("drawio", "application/xml", "model.drawio")]
        [DataRow("vsdx", "application/vnd.ms-visio.drawing", "model.vsdx")]
        [DataRow("tmforge-json", "application/json", "model.tmforge.json")]
        public async Task Convert_LabelsEachTargetFormat(string format, string contentType, string fileName)
        {
            using HttpResponseMessage response = await PostJson("/v1/model/convert?to=" + format, Model);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(contentType, response.Content.Headers.ContentType?.MediaType);
            Assert.AreEqual(fileName, response.Content.Headers.ContentDisposition?.FileName);
        }

        /// <summary>Verifies the threat-model report is served as HTML or SVG on request.</summary>
        /// <param name="format">The report format.</param>
        /// <param name="contentType">The expected content type.</param>
        /// <param name="fileName">The expected download file name.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("html", "text/html", "report.html")]
        [DataRow("svg", "image/svg+xml", "report.svg")]
        public async Task Report_ServesTheRequestedRendering(string format, string contentType, string fileName)
        {
            using HttpResponseMessage response = await PostJson("/v1/model/report?format=" + format, Model);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(contentType, response.Content.Headers.ContentType?.MediaType);
            Assert.AreEqual(fileName, response.Content.Headers.ContentDisposition?.FileName);
        }

        /// <summary>
        /// Verifies the analysis evidence is named the way <c>tmforge analyze --reportFolder</c> names
        /// it, so a downloaded artifact drops straight into a review folder or a CI upload.
        /// </summary>
        /// <param name="format">The evidence format.</param>
        /// <param name="contentType">The expected content type.</param>
        /// <param name="fileName">The expected download file name.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("sarif", "application/sarif+json", "findings.sarif")]
        [DataRow("json", "application/json", "findings.json")]
        [DataRow("html", "text/html", "findings.html")]
        public async Task AnalysisReport_ServesTheRequestedEvidence(string format, string contentType, string fileName)
        {
            using HttpResponseMessage response = await PostJson("/v1/model/analysis-report?format=" + format, Model);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual(contentType, response.Content.Headers.ContentType?.MediaType);
            Assert.AreEqual(fileName, response.Content.Headers.ContentDisposition?.FileName);
        }

        /// <summary>Verifies SARIF served over HTTP is valid SARIF, not just bytes with a SARIF name.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task AnalysisReport_ServesRealSarif()
        {
            using HttpResponseMessage response = await PostJson("/v1/model/analysis-report?format=sarif", Model);

            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual("2.1.0", body.RootElement.GetProperty("version").GetString());
            Assert.IsTrue(body.RootElement.GetProperty("runs").GetArrayLength() > 0);
        }

        /// <summary>Verifies an uploaded model is decoded from base64 and read back as a model.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Read_DecodesAnUploadedModel()
        {
            string request = "{\"contentBase64\":\"" + Base64(Model) + "\",\"formatId\":\"tmforge-json\"}";

            using HttpResponseMessage response = await PostJson("/v1/model/read", request);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual("Alpha", body.RootElement.GetProperty("elements")[0].GetProperty("name").GetString());
        }

        /// <summary>HTTP import returns the shared model or an actionable caller-input error.</summary>
        /// <param name="variation">A valid file or an unsupported or malformed variant.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("valid")]
        [DataRow("dangling")]
        [DataRow("curved")]
        public async Task Read_ThreatDragonPreservesEvidenceOrReportsInputError(string variation)
        {
            string json = File.ReadAllText(Path.Join(AppContext.BaseDirectory, "Fixtures", "threat-dragon-v2.json"));
            JsonNode document = JsonNode.Parse(json) ?? throw new InvalidDataException("Missing fixture.");
            JsonNode cells = document["detail"]?["diagrams"]?[0]?["cells"]
                ?? throw new InvalidDataException("Missing fixture cells.");
            if (variation == "dangling")
            {
                JsonNode source = cells[4]?["source"] ?? throw new InvalidDataException("Missing source.");
                source["cell"] = "missing";
            }
            else if (variation == "curved")
            {
                JsonNode data = cells[3]?["data"] ?? throw new InvalidDataException("Missing boundary.");
                data["type"] = "tm.Boundary";
            }

            string request = JsonSerializer.Serialize(new { contentBase64 = Base64(document.ToJsonString()) });
            using HttpResponseMessage response = await PostJson("/v1/model/read", request);
            string body = await response.Content.ReadAsStringAsync();
            if (variation != "valid")
            {
                Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
                Assert.AreEqual("application/problem+json", response.Content.Headers.ContentType?.MediaType);
                StringAssert.Contains(body, variation == "dangling" ? "missing" : "curved trust boundary");
                return;
            }

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument model = JsonDocument.Parse(body);
            Assert.AreEqual("Model owner", model.RootElement.GetProperty("metadata").GetProperty("owner").GetString());
            JsonElement threats = model.RootElement.GetProperty("threats");
            Assert.AreEqual(3, threats.GetArrayLength());
            Assert.IsTrue(threats.EnumerateArray().All(threat => threat.GetProperty("source").GetProperty("format").GetString() == "threat-dragon"));
        }

        /// <summary>The HTTP preflight endpoint returns the same diagnostics as the shared service.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Preflight_ReturnsStructuredErrorsWithoutReadingAPartialModel()
        {
            const string Invalid = "{\"schema\":\"tmforge-json\",\"elements\":[],\"flows\":[{\"id\":\"broken\",\"source\":\"missing\",\"target\":\"also-missing\"}]}";
            string request = JsonSerializer.Serialize(new { contentBase64 = Base64(Invalid) });
            string expected = JsonSerializer.Serialize(DocumentPreflight.Inspect(Encoding.UTF8.GetBytes(Invalid), targetFormat: "tm7"), new JsonSerializerOptions(JsonSerializerDefaults.Web));

            using HttpResponseMessage response = await PostJson("/v1/model/preflight?to=tm7", request);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsTrue(JsonNode.DeepEquals(JsonNode.Parse(expected), JsonNode.Parse(await response.Content.ReadAsStringAsync())));
        }

        /// <summary>Verifies format detection answers with the format it recognized.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Detect_IdentifiesAKnownFormat()
        {
            using HttpResponseMessage response = await PostJson("/v1/detect", "{\"contentBase64\":\"" + Base64(Model) + "\"}");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual("tmforge-json", body.RootElement.GetProperty("id").GetString());
        }

        /// <summary>
        /// Verifies an authoring manifest is materialized into a model. A manifest is a threat model's
        /// reviewable source rather than a registered format, so it is unreachable through
        /// <c>/v1/detect</c> and <c>/v1/model/read</c> — this route is the only way a client can open
        /// one without shelling out to the CLI.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Manifest_BuildsAModelFromAnAuthoringManifest()
        {
            using HttpResponseMessage response = await PostJson("/v1/model/manifest", ManifestRequest);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.IsTrue(body.RootElement.GetProperty("success").GetBoolean());
            Assert.AreEqual(1, body.RootElement.GetProperty("boundaries").GetInt32());
            Assert.AreEqual(2, body.RootElement.GetProperty("elements").GetInt32());
            Assert.AreEqual(1, body.RootElement.GetProperty("flows").GetInt32());

            List<string?> names = body.RootElement
                .GetProperty("model")
                .GetProperty("elements")
                .EnumerateArray()
                .Select(element => element.GetProperty("name").GetString())
                .ToList();
            CollectionAssert.Contains(names, "Gateway");
            CollectionAssert.Contains(names, "User");
            Assert.AreEqual(
                "Sign in",
                body.RootElement.GetProperty("model").GetProperty("flows")[0].GetProperty("name").GetString());
        }

        /// <summary>
        /// Verifies a manifest that cannot be built answers 200 carrying the reason, not a 500. The
        /// manifest is the caller's document, so a refusal is a result the client renders — the
        /// endpoint only fails when the host does.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Manifest_ReportsARefusedManifestAsAResult()
        {
            const string Body =
                "{\"manifest\":\"{\\\"schema\\\":\\\"tmforge-json\\\",\\\"elements\\\":[]}\"}";

            using HttpResponseMessage response = await PostJson("/v1/model/manifest", Body);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.IsFalse(body.RootElement.GetProperty("success").GetBoolean());
            StringAssert.Contains(body.RootElement.GetProperty("error").GetString(), "tmforge-manifest");
        }

        /// <summary>
        /// Verifies unrecognized content is a 404 rather than a 200 carrying null. This is the only
        /// route with a two-result union, so it is the only one where that distinction can regress.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Detect_ReportsNotFoundForUnrecognizedContent()
        {
            using HttpResponseMessage response = await PostJson("/v1/detect", "{\"contentBase64\":\"" + Base64("not a model") + "\"}");

            Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
        }

        /// <summary>
        /// Verifies malformed input is refused as a client error. Without this the host could start
        /// answering 500 for a bad request body and nothing would notice.
        /// </summary>
        /// <param name="body">The request body.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("{ this is not json", DisplayName = "malformed JSON")]
        [DataRow("null", DisplayName = "null body")]
        public async Task Analyze_RejectsAnUnusableBody(string body)
        {
            using HttpResponseMessage response = await PostJson("/v1/model/analyze", body);

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        }

        /// <summary>Verifies a required query parameter is enforced by the host, not by the engine.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task Convert_RequiresATargetFormat()
        {
            using HttpResponseMessage response = await PostJson("/v1/model/convert", Model);

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        }

        /// <summary>
        /// Verifies the OpenAPI document is served, since the Studio's client types are generated from
        /// it and a host that stops publishing it breaks that generation silently.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task OpenApi_DocumentIsServed()
        {
            using HttpResponseMessage response = await Client.GetAsync("/openapi/v1.json");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.IsTrue(body.RootElement.GetProperty("paths").TryGetProperty("/v1/health", out _));
        }

        /// <summary>
        /// Verifies input the caller got wrong is reported as a client error, not a server error.
        /// A 500 says the server broke and invites a retry; none of these can succeed on retry, so
        /// each one has to be a 400 that names what was unusable.
        /// </summary>
        /// <param name="route">The route to call.</param>
        /// <param name="body">The request body.</param>
        /// <returns>A task.</returns>
        [TestMethod]
        [DataRow("/v1/model/convert?to=nonsense", Model, DisplayName = "unknown conversion target")]
        [DataRow("/v1/model/convert?to=", Model, DisplayName = "empty conversion target")]
        [DataRow("/v1/model/read", "{\"contentBase64\":\"eyJ9\",\"formatId\":\"nonsense\"}", DisplayName = "unknown read format")]
        [DataRow("/v1/model/read", "{\"contentBase64\":\"AQID\",\"formatId\":\"tmforge-json\"}", DisplayName = "bytes that are not the named format")]
        [DataRow("/v1/model/read", "{\"contentBase64\":\"!!not base64!!\"}", DisplayName = "malformed base64")]
        [DataRow("/v1/detect", "{\"contentBase64\":\"!!not base64!!\"}", DisplayName = "malformed base64 on detect")]
        public async Task CallerInputErrors_AreReportedAsBadRequest(string route, string body)
        {
            using HttpResponseMessage response = await PostJson(route, body);

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        }

        /// <summary>
        /// Verifies a bad request carries a problem document naming what went wrong, so the caller can
        /// correct the request instead of guessing which parameter the server disliked.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task ABadRequestExplainsWhatWasUnusable()
        {
            using HttpResponseMessage response = await PostJson("/v1/model/convert?to=nonsense", Model);

            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.AreEqual("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(400, body.RootElement.GetProperty("status").GetInt32());
            StringAssert.Contains(body.RootElement.GetProperty("detail").GetString(), "nonsense");
        }

        /// <summary>
        /// Verifies a genuine server fault is still a 500. The bad-request handling above classifies by
        /// exception type, so this guards the other side of that line: widening it until everything
        /// looks like the caller's fault would hide real breakage behind a 400.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task ReportFormatThatIsNotRecognized_StillRendersRatherThanFailing()
        {
            // An unknown report format is not an error at all: it falls back to HTML by design.
            using HttpResponseMessage response = await PostJson("/v1/model/report?format=nonsense", Model);

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        }

        /// <summary>
        /// Verifies a mistyped API path is answered as an API 404, not with the Studio's HTML shell.
        /// The SPA fallback is registered for every unmatched path, so without a dedicated <c>/v1</c>
        /// fallback a caller that misspells an endpoint receives 200 and an HTML document, and fails
        /// while parsing it rather than seeing the status it deserves.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task UnknownV1Route_IsAnsweredAsAnApiNotFound()
        {
            using HttpResponseMessage response = await Client.GetAsync("/v1/no-such-endpoint");

            Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
            Assert.AreEqual("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            Assert.AreNotEqual(
                "text/html",
                response.Content.Headers.ContentType?.MediaType,
                "a mistyped API path must not be answered with the SPA shell.");
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(404, body.RootElement.GetProperty("status").GetInt32());
        }

        /// <summary>
        /// Verifies the SPA fallback still works for everything that is not an API path, so fixing the
        /// <c>/v1</c> case above cannot have broken client-side routing.
        /// <para>
        /// An API-only build (<c>-p:BuildStudio=false</c>) has no <c>wwwroot</c> and answers 404, so the
        /// assertion only holds the SPA to account when it is actually present.
        /// </para>
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task NonApiRoute_StillReachesTheSpa()
        {
            using HttpResponseMessage response = await Client.GetAsync("/some-client-side-route");

            if (response.StatusCode == HttpStatusCode.OK)
            {
                Assert.AreEqual("text/html", response.Content.Headers.ContentType?.MediaType);
            }
            else
            {
                Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
            }
        }

        /// <summary>Base64-encodes UTF-8 text.</summary>
        /// <param name="text">The text.</param>
        /// <returns>The encoded text.</returns>
        private static string Base64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

        /// <summary>Posts a JSON body to a route.</summary>
        /// <param name="route">The route.</param>
        /// <param name="body">The JSON body.</param>
        /// <returns>The response.</returns>
        private static async Task<HttpResponseMessage> PostJson(string route, string body)
        {
            using StringContent content = new StringContent(body, Encoding.UTF8, "application/json");
            return await Client.PostAsync(route, content);
        }
    }
}
