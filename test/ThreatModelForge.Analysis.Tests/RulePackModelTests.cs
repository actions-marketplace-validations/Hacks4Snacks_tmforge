namespace ThreatModelForge.Analysis.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Tests deterministic rule-pack identity and the embedded version 2 JSON Schema.
    /// </summary>
    [TestClass]
    public class RulePackModelTests
    {
        /// <summary>A content fingerprint is the stable lowercase SHA-256 of the exact bytes.</summary>
        [TestMethod]
        public void FingerprintIsDeterministicSha256()
        {
            const string expected = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

            Assert.AreEqual(expected, RulePackIdentity.CreateFingerprint(Array.Empty<byte>()));
            Assert.AreEqual(expected, RulePackIdentity.CreateFingerprint(Array.Empty<byte>()));
        }

        /// <summary>Pack ids normalize the source name and include a short content fingerprint.</summary>
        [TestMethod]
        public void PackIdIncludesNormalizedNameAndFingerprint()
        {
            string id = RulePackIdentity.CreatePackId("Azure Threat Model Template", Array.Empty<byte>());

            Assert.AreEqual("azure-threat-model-template-e3b0c44298fc1c149afbf4c8996fb924", id);
            Assert.AreEqual(
                "azure-threat-model-template-e3b0c44298fc1c149afbf4c8996fb924/TH112",
                RulePackIdentity.CreateEffectiveRuleId(id, "TH112"));
        }

        /// <summary>Identity segments are printable ASCII and accepted values persist through TM7.</summary>
        [TestMethod]
        public void IdentitySegmentsAreTm7Safe()
        {
            Assert.IsTrue(RulePackIdentity.IsValidSegment("pack name:1"));
            Assert.IsFalse(RulePackIdentity.IsValidSegment("rule\nname"));
            Assert.IsFalse(RulePackIdentity.IsValidSegment("rule\u007fname"));
            Assert.IsFalse(RulePackIdentity.IsValidSegment("rul\0name"));
            Assert.IsFalse(RulePackIdentity.IsValidSegment("rul\u00e9"));

            string effectiveId = RulePackIdentity.CreateEffectiveRuleId("pack name:1", "rule.v2?check");
            string instanceKey = Guid.NewGuid().ToString("N") + ":" + effectiveId;
            ThreatModel model = new ThreatModel();
            model.AllThreatsDictionary[instanceKey] = new Threat
            {
                Id = 1,
                TypeId = effectiveId,
                InteractionKey = instanceKey,
            };
            using MemoryStream stream = new MemoryStream();

            model.Save(stream);
            stream.Position = 0;
            ThreatModel roundTripped = ThreatModel.Load(stream);

            Assert.AreEqual(effectiveId, roundTripped.AllThreatsDictionary[instanceKey].TypeId);
        }

        /// <summary>The packaged schema is valid JSON and identifies the v2 discriminator.</summary>
        [TestMethod]
        public void VersionTwoSchemaIsEmbeddedAndParseable()
        {
            using JsonDocument schema = JsonDocument.Parse(RulePackSchema.VersionTwo);
            JsonElement root = schema.RootElement;

            Assert.AreEqual("https://json-schema.org/draft/2020-12/schema", root.GetProperty("$schema").GetString());
            Assert.AreEqual("tmforge-rules", root.GetProperty("properties").GetProperty("schema").GetProperty("const").GetString());
            Assert.AreEqual(2, root.GetProperty("properties").GetProperty("version").GetProperty("const").GetInt32());
            Assert.IsFalse(root.GetProperty("additionalProperties").GetBoolean());
            JsonElement definitions = root.GetProperty("$defs");
            CollectionAssert.AreEquivalent(
                new[] { "High", "Medium", "Low" },
                definitions.GetProperty("threatPriority").GetProperty("enum")
                    .EnumerateArray().Select(value => value.GetString()).ToArray());
            Assert.AreEqual(
                "#/$defs/threatPriority",
                definitions.GetProperty("flatRule").GetProperty("properties")
                    .GetProperty("defaultPriority").GetProperty("$ref").GetString());
        }

        /// <summary>The published schema exposes the bounded property and connectivity matcher contracts.</summary>
        [TestMethod]
        public void VersionTwoSchemaDeclaresAdditionalMatchers()
        {
            using JsonDocument schema = JsonDocument.Parse(RulePackSchema.VersionTwo);
            JsonElement definitions = schema.RootElement.GetProperty("$defs");
            foreach (string shape in new[] { "condition", "nonRelationalCondition", "endpoint" })
            {
                JsonElement definition = definitions.GetProperty(shape);
                foreach (string matcher in new[] { "greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual", "matches" })
                {
                    Assert.IsTrue(definition.GetProperty("properties").TryGetProperty(matcher, out _), shape + ":" + matcher);
                    Assert.AreEqual("property", definition.GetProperty("dependentRequired").GetProperty(matcher)[0].GetString());
                }
            }

            JsonElement pattern = definitions.GetProperty("regexPattern");
            Assert.AreEqual(1, pattern.GetProperty("minLength").GetInt32());
            Assert.AreEqual(1024, pattern.GetProperty("maxLength").GetInt32());
            Assert.AreEqual(decimal.MinValue, definitions.GetProperty("decimal").GetProperty("minimum").GetDecimal());
            Assert.AreEqual(decimal.MaxValue, definitions.GetProperty("decimal").GetProperty("maximum").GetDecimal());
            string[] expressions = definitions.GetProperty("interactionExpression").GetProperty("oneOf").EnumerateArray()
                .Select(expression => expression.GetProperty("$ref").GetString() ?? string.Empty).ToArray();
            foreach (string expression in new[] { "numericExpression", "regexExpression", "kindExpression", "connectivityExpression" })
            {
                CollectionAssert.Contains(expressions, "#/$defs/" + expression);
            }

            CollectionAssert.AreEquivalent(
                new[] { "source", "target" },
                definitions.GetProperty("connectivityExpression").GetProperty("properties").GetProperty("subject")
                    .GetProperty("enum").EnumerateArray().Select(value => value.GetString()).ToArray());
        }
    }
}
