namespace ThreatModelForge.Analysis.Rules.Tests
{
    using System.Globalization;
    using System.Text;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using ThreatModelForge.Editing;

    /// <summary>
    /// Uses reflection to validate the rule classes for common criteria.
    /// </summary>
    [TestClass]
    public class ConformanceTests
    {
        /// <summary>
        /// Tests that all rules are public.
        /// </summary>
        [TestMethod]
        public void AllRulesArePublicTest()
        {
            var nonPublicRules = GetAllRules().Where(x => !x.IsPublic).ToArray();
            Assert.AreEqual(0, nonPublicRules.Length, $"The following rules should be public: {string.Join(",", nonPublicRules.Select(e => e.FullName))}");
        }

        /// <summary>
        /// Checks basic properties are populated for each rule type.
        /// </summary>
        [TestMethod]
        public void BasicPropertiesTest()
        {
            StringBuilder errors = new ();
            foreach (Rule r in GetInstancesOfEachRule())
            {
                if (string.IsNullOrWhiteSpace(r.HelpText))
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Missing HelpText for {r.GetType()}.");
                }

                if (string.IsNullOrWhiteSpace(r.FullDescription))
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Missing FullDescription for {r.GetType()}.");
                }

                if (r.HelpUri == null)
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Missing HelpUri for {r.GetType()}.");
                }
            }

            Assert.IsTrue(errors.Length == 0, errors.ToString());
        }

        /// <summary>
        /// Tests that each rule's threat identity is complete and self-contained: a rule that declares
        /// a STRIDE category (a threat-bearing rule) also carries at least one external reference, and
        /// references are never declared without a category. This is the anti-drift guard — because a
        /// rule owns its own STRIDE/references, adding a rule cannot silently forget to make it a
        /// threat, and there is no separate map to fall out of sync.
        /// </summary>
        [TestMethod]
        public void ThreatMetadataIsConsistentTest()
        {
            StringBuilder errors = new ();
            foreach (Rule rule in GetInstancesOfEachRule())
            {
                bool hasStride = rule.Stride.HasValue;
                bool hasReferences = rule.ThreatReferences.Count > 0;
                if (hasStride && !hasReferences)
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Rule {rule.GetType()} declares Stride {rule.Stride} but has no ThreatReferences.");
                }

                if (!hasStride && hasReferences)
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Rule {rule.GetType()} has ThreatReferences but no Stride category.");
                }
            }

            Assert.IsTrue(errors.Length == 0, errors.ToString());
        }

        /// <summary>
        /// Tests each rule has its own unique Help URI.
        /// </summary>
        [TestMethod]
        public void UniqueHelpUriPerRuleTest()
        {
            Dictionary<Uri, IList<Type>> map = new ();
            foreach (Rule r in GetInstancesOfEachRule())
            {
                if (r.HelpUri == null)
                {
                    continue; // different test.
                }

                if (!map.TryGetValue(r.HelpUri, out IList<Type>? entry))
                {
                    entry = new List<Type>();
                    map[r.HelpUri] = entry;
                }

                entry.Add(r.GetType());
            }

            StringBuilder errors = new ();
            foreach (Uri key in map.Keys)
            {
                IList<Type> entry = map[key];
                if (entry.Count > 1)
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Rules {string.Join(", ", entry)} have the same HelpUri {key}.");
                }
            }

            Assert.IsTrue(errors.Length == 0, errors.ToString());
        }

        /// <summary>
        /// Tests that built-in help links target the published rule guide and retain rule identity.
        /// </summary>
        [TestMethod]
        public void HelpUrisPointToAnalysisGuideTest()
        {
            foreach (Rule rule in GetInstancesOfEachRule())
            {
                Assert.AreEqual(
                    new Uri($"https://github.com/hacks4snacks/tmforge/blob/main/docs/analysis-rules.md?rule={rule.ID}"),
                    rule.HelpUri);
            }
        }

        /// <summary>
        /// Tests that each rule has its own ID.
        /// </summary>
        [TestMethod]
        public void UniqueIDPerRuleTest()
        {
            StringBuilder errors = new ();
            Dictionary<string, Type> map = new ();
            foreach (Rule rule in GetInstancesOfEachRule())
            {
                if (!map.TryGetValue(rule.ID, out Type? ruleType))
                {
                    map[rule.ID] = rule.GetType();
                }
                else
                {
                    errors.AppendLine(CultureInfo.InvariantCulture, $"Rule {rule.GetType()} has the same ID {rule.ID} as {ruleType}.");
                }
            }

            Assert.IsTrue(errors.Length == 0, errors.ToString());
        }

        /// <summary>
        /// Tests that every rule's property bindings reference a real schema property and flag only
        /// values allowed by that property, so the policy a rule declares cannot drift from the schema.
        /// </summary>
        [TestMethod]
        public void PropertyBindingsMatchSchemaTest()
        {
            StringBuilder errors = new ();
            foreach (Rule rule in GetInstancesOfEachRule())
            {
                foreach (PropertyBinding binding in rule.PropertyBindings)
                {
                    PropertyDescriptor? descriptor = PropertySchemaCatalog
                        .For(binding.AppliesTo)
                        .FirstOrDefault(d => string.Equals(d.Name, binding.PropertyName, StringComparison.OrdinalIgnoreCase));
                    if (descriptor is null)
                    {
                        errors.AppendLine(CultureInfo.InvariantCulture, $"{rule.GetType().Name} binds unknown property '{binding.AppliesTo}/{binding.PropertyName}'.");
                        continue;
                    }

                    foreach (string flagged in binding.FlaggedValues
                        .Where(flagged => !descriptor.Values.Contains(flagged, StringComparer.OrdinalIgnoreCase)))
                    {
                        errors.AppendLine(CultureInfo.InvariantCulture, $"{rule.GetType().Name} flags '{binding.AppliesTo}/{binding.PropertyName}={flagged}', which is not an allowed value.");
                    }
                }
            }

            Assert.IsTrue(errors.Length == 0, errors.ToString());
        }

        private static IEnumerable<Rule> GetInstancesOfEachRule() => GetAllRules().Select(e => Activator.CreateInstance(e)).Cast<Rule>();

        private static IEnumerable<Type> GetAllRules()
        {
            var asm = typeof(UnconnectedEdgesRule).Assembly;
            return asm.GetTypes().Where(e => typeof(Rule).IsAssignableFrom(e));
        }
    }
}
