namespace ThreatModelForge.Api.Tests
{
    using System.Linq;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;

    /// <summary>
    /// Unit tests for opening a declarative authoring manifest through the engine facade.
    /// <para>
    /// A manifest is a threat model's reviewable source, not one of the registered model formats, so
    /// content sniffing cannot claim it and the model readers cannot parse it. Every host that offers
    /// "open a file" (the Studio picker, <c>POST /v1/model/manifest</c>, the WASM shim) routes a
    /// manifest here instead of reporting an unreadable model.
    /// </para>
    /// </summary>
    [TestClass]
    public class EngineManifestTest
    {
        private const string SampleManifest = @"{
  ""schema"": ""tmforge-manifest"",
  ""version"": 1,
  ""name"": ""Certificate issuance"",
  ""boundaries"": [ { ""alias"": ""tb1"", ""name"": ""Cluster"" } ],
  ""elements"": [
    { ""alias"": ""a1"", ""kind"": ""external"", ""name"": ""Workload identity"", ""boundary"": ""tb1"" },
    { ""alias"": ""p1"", ""kind"": ""process"", ""name"": ""API server"", ""boundary"": ""tb1"" }
  ],
  ""flows"": [ { ""from"": ""a1"", ""to"": ""p1"", ""name"": ""Create a certificate"" } ]
}";

        /// <summary>
        /// Verifies that a manifest supplied as text builds the model it declares, so a host holding
        /// the raw bytes of a picked file can open it without shelling out to the CLI.
        /// </summary>
        [TestMethod]
        public void ApplyManifestJson_BuildsTheDeclaredModel()
        {
            ApplyResultDto result = AuthoringService.ApplyManifestJson(SampleManifest, force: false);

            Assert.IsTrue(result.Success, result.Error);
            Assert.AreEqual(1, result.Boundaries);
            Assert.AreEqual(2, result.Elements);
            Assert.AreEqual(1, result.Flows);

            Assert.IsNotNull(result.Model);
            Assert.IsNotNull(result.Model!.Elements);
            CollectionAssert.Contains(result.Model.Elements!.Select(e => e.Name).ToList(), "API server");
            Assert.IsNotNull(result.Model.Flows);
            Assert.AreEqual("Create a certificate", result.Model.Flows![0].Name);
        }

        /// <summary>Unknown manifest fields fail before their values can be silently discarded.</summary>
        [TestMethod]
        public void ApplyManifestJson_RejectsMisspelledPropertiesEvenWithForce()
        {
            string json = SampleManifest.Replace("\"name\": \"API server\"", "\"name\": \"API server\", \"properties\": { \"Isolation\": \"Container\" }");

            ApplyResultDto result = AuthoringService.ApplyManifestJson(json, force: true);

            Assert.IsFalse(result.Success);
            Assert.IsNull(result.Model);
            StringAssert.Contains(result.Error, "$.elements[1].properties");
            StringAssert.Contains(result.Error, "Use 'props'");
        }

        /// <summary>Preflight previews a manifest without inventing a format registration or evaluating rules.</summary>
        [TestMethod]
        public void Preflight_InspectsManifestAndReportsTargetLosses()
        {
            PreflightResultDto result = DocumentPreflight.Inspect(Encoding.UTF8.GetBytes(SampleManifest), targetFormat: "drawio");

            Assert.IsTrue(result.Success);
            Assert.AreEqual("tmforge-manifest", result.Format);
            Assert.AreEqual("drawio", result.TargetFormat);
            Assert.IsTrue(result.Diagnostics.Any(diagnostic => diagnostic.Code == "conversion.identity"));
        }

        /// <summary>Preflight returns machine-readable paths for misspelled manifest fields.</summary>
        [TestMethod]
        public void Preflight_ReportsManifestTypos()
        {
            string json = SampleManifest.Replace("\"name\": \"API server\"", "\"name\": \"API server\", \"properties\": {}");

            PreflightResultDto result = DocumentPreflight.Inspect(Encoding.UTF8.GetBytes(json));

            Assert.IsFalse(result.Success);
            Assert.IsTrue(result.Diagnostics.Any(diagnostic => diagnostic.Code == "input.unknown-field" && diagnostic.Path == "$.elements[1].properties"));
        }

        /// <summary>
        /// Verifies that applying the same manifest text twice produces the same element ids, so a
        /// model opened from a manifest carries the identities analysis and triage are keyed on.
        /// </summary>
        [TestMethod]
        public void ApplyManifestJson_IsDeterministic()
        {
            ApplyResultDto first = AuthoringService.ApplyManifestJson(SampleManifest, force: false);
            ApplyResultDto second = AuthoringService.ApplyManifestJson(SampleManifest, force: false);

            Assert.IsTrue(first.Success, first.Error);
            Assert.IsTrue(second.Success, second.Error);
            CollectionAssert.AreEqual(
                first.Model!.Elements!.Select(e => e.Id).ToList(),
                second.Model!.Elements!.Select(e => e.Id).ToList());
        }

        /// <summary>
        /// Verifies that a model document is refused rather than coerced. Every member of a manifest is
        /// optional, so binding first would deserialize a model into an empty-looking manifest and
        /// silently apply it as an empty model.
        /// </summary>
        [TestMethod]
        public void ApplyManifestJson_RefusesAModelDocument()
        {
            ApplyResultDto result = AuthoringService.ApplyManifestJson(
                @"{ ""schema"": ""tmforge-json"", ""version"": ""0.1"", ""elements"": [], ""flows"": [] }",
                force: false);

            Assert.IsFalse(result.Success);
            Assert.IsNull(result.Model);
            StringAssert.Contains(result.Error, "tmforge-manifest");
        }

        /// <summary>
        /// Verifies that malformed and empty input are reported on the result instead of thrown, so a
        /// UI can show the reason rather than a stack trace.
        /// </summary>
        /// <param name="json">The unusable document text.</param>
        [TestMethod]
        [DataRow("not json at all")]
        [DataRow("")]
        [DataRow("   ")]
        public void ApplyManifestJson_ReportsUnusableInput(string json)
        {
            ApplyResultDto result = AuthoringService.ApplyManifestJson(json, force: false);

            Assert.IsFalse(result.Success);
            Assert.IsNull(result.Model);
            Assert.IsFalse(string.IsNullOrWhiteSpace(result.Error));
        }

        /// <summary>
        /// Verifies that a manifest that names an element no flow can resolve is refused with the
        /// engine's own explanation, which is what a host shows the author.
        /// </summary>
        [TestMethod]
        public void ApplyManifestJson_ReportsAnUnresolvableReference()
        {
            ApplyResultDto result = AuthoringService.ApplyManifestJson(
                @"{ ""schema"": ""tmforge-manifest"", ""elements"": [ { ""alias"": ""p1"", ""kind"": ""process"", ""name"": ""API"" } ],
                    ""flows"": [ { ""from"": ""p1"", ""to"": ""nope"", ""name"": ""x"" } ] }",
                force: false);

            Assert.IsFalse(result.Success);
            StringAssert.Contains(result.Error, "nope");
        }

        /// <summary>
        /// Verifies the recognizer accepts a document that declares the manifest schema.
        /// </summary>
        [TestMethod]
        public void LooksLikeManifest_AcceptsADeclaredManifest()
        {
            Assert.IsTrue(ManifestSupport.LooksLikeManifest(SampleManifest));
        }

        /// <summary>
        /// Verifies the recognizer refuses documents that are not manifests, including the concise
        /// manifest form that declares no envelope.
        /// <para>
        /// The last case is the deliberate asymmetry with <see cref="ManifestSupport.TryRead"/>, which
        /// does accept it: <c>TryRead</c> is told the document is a manifest, while the recognizer
        /// decides. Since every manifest member is optional, accepting an absent envelope here would
        /// claim any JSON document and then build it into an empty model.
        /// </para>
        /// </summary>
        /// <param name="json">The document text that must not be recognized.</param>
        [TestMethod]
        [DataRow(@"{ ""schema"": ""tmforge-json"", ""elements"": [] }")]
        [DataRow(@"{ ""schema"": ""tmforge-rules"", ""version"": 2 }")]
        [DataRow(@"{ ""name"": ""concise"", ""elements"": [] }")]
        [DataRow(@"{ ""schema"": 7 }")]
        [DataRow(@"[ { ""schema"": ""tmforge-manifest"" } ]")]
        [DataRow("<ThreatModel />")]
        [DataRow("")]
        public void LooksLikeManifest_RefusesEverythingElse(string json)
        {
            Assert.IsFalse(ManifestSupport.LooksLikeManifest(json));
        }
    }
}
