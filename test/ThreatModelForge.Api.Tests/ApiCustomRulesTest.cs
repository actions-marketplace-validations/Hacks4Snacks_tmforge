namespace ThreatModelForge.Api.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Json;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Mvc.Testing;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Engine;

    /// <summary>
    /// Tests the host's startup rule loading. Custom packs are deployment configuration read once at
    /// boot, so nothing below the host can exercise them: these drive a host that has actually been
    /// given a pack, and one that has been given a path that does not exist.
    /// </summary>
    [TestClass]
    public class ApiCustomRulesTest
    {
        /// <summary>A data store that trips the pack's rule: it holds log data and states no retention.</summary>
        private const string Model =
            "{\"schema\":\"tmforge-json\",\"version\":\"0.1\"," +
            "\"elements\":[{\"id\":\"d\",\"kind\":\"datastore\",\"name\":\"Audit\",\"x\":10,\"y\":10,\"width\":120,\"height\":60," +
            "\"properties\":{\"StoresLogData\":\"Yes\"}}],\"flows\":[]}";

        /// <summary>A minimal but complete pack, shaped after examples/corporate-policy.tmrules.json.</summary>
        private const string PackTemplate = """
            {
              "schema": "tmforge-rules",
              "version": 2,
              "dialect": "urn:tmforge:rules:flat-v1",
              "pack": { "id": "PACK", "name": "Test pack PACK", "version": "1.0.0" },
              "elementTypes": [ { "id": "GE.DS", "name": "Data store", "parentId": "ROOT" } ],
              "properties": [ { "name": "RetentionDays", "elementTypeIds": ["GE.DS"] } ],
              "rules": [
                {
                  "id": "RULE",
                  "severity": "error",
                  "appliesTo": "datastore",
                  "message": "{name} states no RetentionDays.",
                  "fullDescription": "A test pack proving the host loads operator-supplied rules.",
                  "helpText": "Set RetentionDays on the store.",
                  "when": { "property": "StoresLogData", "equals": "Yes" },
                  "assert": { "property": "RetentionDays", "present": true }
                }
              ]
            }
            """;

        private string WorkingDirectory { get; set; } = string.Empty;

        /// <summary>Creates a directory to hold the pack file.</summary>
        [TestInitialize]
        public void Initialize()
        {
            this.WorkingDirectory = Path.Join(Path.GetTempPath(), "tmforge-api-rules-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(this.WorkingDirectory);
        }

        /// <summary>Removes the directory.</summary>
        [TestCleanup]
        public void Cleanup()
        {
            if (Directory.Exists(this.WorkingDirectory))
            {
                Directory.Delete(this.WorkingDirectory, recursive: true);
            }
        }

        /// <summary>
        /// Verifies a configured pack reaches every rule-reading endpoint: it is listed in the bundle,
        /// appears in the rule catalog, and actually fires during analysis. Listing without firing would
        /// mean the operator's policy is advertised but not enforced.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task AConfiguredPackIsListedAndEnforced()
        {
            string path = this.WritePack("test-pack", "TEST-1");
            using WebApplicationFactory<HealthStatusDto> factory = HostWithRules(path);
            using HttpClient client = factory.CreateClient();

            using (HttpResponseMessage bundle = await client.GetAsync("/v1/rule-bundle"))
            {
                using JsonDocument body = JsonDocument.Parse(await bundle.Content.ReadAsStringAsync());
                Assert.AreEqual(0, body.RootElement.GetProperty("diagnostics").GetArrayLength(), "the pack should load cleanly");
                Assert.AreEqual(1, body.RootElement.GetProperty("rulePacks").GetArrayLength());
                Assert.AreEqual("test-pack", body.RootElement.GetProperty("rulePacks")[0].GetProperty("id").GetString());
            }

            using (HttpResponseMessage rules = await client.GetAsync("/v1/rules"))
            {
                StringAssert.Contains(await rules.Content.ReadAsStringAsync(), "TEST-1");
            }

            using StringContent content = new StringContent(Model, Encoding.UTF8, "application/json");
            using HttpResponseMessage analyze = await client.PostAsync("/v1/model/analyze", content);
            Assert.AreEqual(HttpStatusCode.OK, analyze.StatusCode);
            StringAssert.Contains(await analyze.Content.ReadAsStringAsync(), "TEST-1");
        }

        /// <summary>
        /// Verifies a rule path that does not exist is reported rather than thrown. A host that fell
        /// back to the built-in rules in silence would analyze every caller's model against a policy
        /// nobody asked for, and report clean while doing it.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task AMissingPackIsReportedInsteadOfCrashingTheHost()
        {
            string missing = Path.Join(this.WorkingDirectory, "no-such-pack.tmrules.json");
            using WebApplicationFactory<HealthStatusDto> factory = HostWithRules(missing);
            using HttpClient client = factory.CreateClient();

            using HttpResponseMessage response = await client.GetAsync("/v1/rule-bundle");

            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.IsTrue(
                body.RootElement.GetProperty("diagnostics").GetArrayLength() > 0,
                "a misconfigured rule path must be visible through the bundle.");
        }

        /// <summary>
        /// Verifies the documented <c>;</c>-separated form loads every pack it names. This is how the
        /// setting is written as a single environment variable
        /// (<c>TmForge__Rules='/a.tmrules.json;/b.tmrules.json'</c>), which is the shape a container
        /// deployment uses — and it takes a different code path from the indexed array form.
        /// </summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task PacksCanBeNamedAsOneSemicolonSeparatedSetting()
        {
            string first = this.WritePack("pack-one", "ONE-1");
            string second = this.WritePack("pack-two", "TWO-1");
            using WebApplicationFactory<HealthStatusDto> factory = HostWithRulesSetting(first + ";" + second);
            using HttpClient client = factory.CreateClient();

            using HttpResponseMessage response = await client.GetAsync("/v1/rule-bundle");

            using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.AreEqual(0, body.RootElement.GetProperty("diagnostics").GetArrayLength());
            JsonElement packs = body.RootElement.GetProperty("rulePacks");
            Assert.AreEqual(2, packs.GetArrayLength(), "both packs in the separated list must load.");
            Assert.AreEqual("pack-one", packs[0].GetProperty("id").GetString());
            Assert.AreEqual("pack-two", packs[1].GetProperty("id").GetString());
        }

        /// <summary>The HTTP host evaluates added matchers identically to the shared engine.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task AdditionalMatchersMatchTheSharedEngine()
        {
            (TmForgeModelDto model, EngineRuleOptions rules) = EngineCustomRulesTest.AdditionalMatchers();
            string path = Path.Join(this.WorkingDirectory, "additional-matchers.tmrules.json");
            File.WriteAllText(path, rules.Sources![0].Json);
            using WebApplicationFactory<HealthStatusDto> factory = HostWithRules(path);
            using HttpClient client = factory.CreateClient();
            using HttpResponseMessage response = await client.PostAsJsonAsync("/v1/model/analysis", model);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            AnalysisResultDto? actual = await response.Content.ReadFromJsonAsync<AnalysisResultDto>();
            Assert.IsNotNull(actual);
            AnalysisResultDto expected = EngineService.RunAnalysis(model, rules);
            Assert.AreEqual(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual));
        }

        /// <summary>A trusted starter-pack directory contributes every example to HTTP analysis.</summary>
        /// <returns>A task.</returns>
        [TestMethod]
        public async Task StarterPackDirectoryIsListedAndEnforced()
        {
            string directory = Path.Join(AppContext.BaseDirectory, "Fixtures", "RulePacks");
            using WebApplicationFactory<HealthStatusDto> factory = HostWithRules(directory);
            using HttpClient client = factory.CreateClient();
            using HttpResponseMessage bundle = await client.GetAsync("/v1/rule-bundle");
            Assert.AreEqual(HttpStatusCode.OK, bundle.StatusCode);
            RuleBundleDto? loaded = await bundle.Content.ReadFromJsonAsync<RuleBundleDto>();
            Assert.IsNotNull(loaded);
            Assert.AreEqual(0, loaded.Diagnostics.Count);
            CollectionAssert.AreEquivalent(
                new[] { "example-pci", "example-hipaa", "example-internal-service" }, loaded.RulePacks.Select(pack => pack.Id).ToArray());
            using StringContent content = new StringContent(
                File.ReadAllText(Path.Join(directory, "starter-model.tmforge.json")), Encoding.UTF8, "application/json");
            using HttpResponseMessage response = await client.PostAsync("/v1/model/analysis", content);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            AnalysisResultDto? result = await response.Content.ReadFromJsonAsync<AnalysisResultDto>();
            Assert.IsNotNull(result);
            Assert.AreEqual(0, result.Diagnostics.Count);
            Assert.IsFalse(result.Findings.Any(finding => finding.Id == "engine-error"));
            CollectionAssert.AreEquivalent(
                new[]
                {
                    "example-pci/PAN-ENCRYPTION", "example-pci/AUDIT-RETENTION",
                    "example-hipaa/EPHI-TRANSPORT", "example-hipaa/EPHI-AUDIT",
                    "example-internal-service/SERVICE-NAME", "example-internal-service/AUDIT-CONNECTION",
                },
                result.Findings.Where(finding => finding.RuleId?.StartsWith("example-", StringComparison.Ordinal) == true).Select(finding => finding.RuleId).ToArray());
            Assert.AreEqual(5, result.Threats.Count(threat => threat.RuleId?.StartsWith("example-", StringComparison.Ordinal) == true));
            CollectionAssert.AreEquivalent(loaded.RulePacks.Select(pack => pack.Fingerprint).ToArray(), result.RulePacks.Select(pack => pack.Fingerprint).ToArray());
        }

        /// <summary>Builds a host that loads rule packs from the given paths.</summary>
        /// <param name="paths">The configured rule pack paths.</param>
        /// <returns>The factory.</returns>
        private static WebApplicationFactory<HealthStatusDto> HostWithRules(params string[] paths)
        {
            return new WebApplicationFactory<HealthStatusDto>().WithWebHostBuilder(builder =>
            {
                for (int index = 0; index < paths.Length; index++)
                {
                    builder.UseSetting($"TmForge:Rules:{index}", paths[index]);
                }
            });
        }

        /// <summary>Builds a host configured with one scalar setting, as an environment variable sets it.</summary>
        /// <param name="value">The raw setting value.</param>
        /// <returns>The factory.</returns>
        private static WebApplicationFactory<HealthStatusDto> HostWithRulesSetting(string value)
        {
            return new WebApplicationFactory<HealthStatusDto>()
                .WithWebHostBuilder(builder => builder.UseSetting("TmForge:Rules", value));
        }

        /// <summary>Writes a pack with the given pack and rule ids.</summary>
        /// <param name="packId">The pack id.</param>
        /// <param name="ruleId">The rule id.</param>
        /// <returns>The path written.</returns>
        private string WritePack(string packId, string ruleId)
        {
            string path = Path.Join(this.WorkingDirectory, packId + ".tmrules.json");
            File.WriteAllText(path, PackTemplate.Replace("PACK", packId, StringComparison.Ordinal)
                .Replace("RULE", ruleId, StringComparison.Ordinal));
            return path;
        }
    }
}
