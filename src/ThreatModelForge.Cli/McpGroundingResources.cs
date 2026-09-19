namespace ThreatModelForge.Cli
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Reflection;
    using System.Text;
    using ModelContextProtocol;
    using ModelContextProtocol.Server;
    using ThreatModelForge.Analysis;
    using ThreatModelForge.Engine;

    /// <summary>Versioned, fingerprinted grounding snapshots for MCP resource clients.</summary>
    [McpServerResourceType]
    public static class McpGroundingResources
    {
        private static readonly Lazy<string> FormatSnapshot = new Lazy<string>(
            () => Snapshot("formats", "application/json", CliJson.Serialize(McpGroundingTools.Formats())));

        private static readonly Lazy<string> PropertySnapshot = new Lazy<string>(
            () => Snapshot("property-schema", "application/json", CliJson.Serialize(McpGroundingTools.PropertySchema())));

        private static readonly Lazy<string> ManifestSnapshot = new Lazy<string>(
            () => Snapshot("manifest-schema", "text/plain", McpGroundingTools.ManifestSchema()));

        private static readonly Lazy<string> BuiltInPackSnapshot = new Lazy<string>(
            () => RulePackSnapshot(null));

        /// <summary>Reads the supported format catalog without invoking an MCP tool.</summary>
        /// <returns>The versioned format snapshot.</returns>
        [McpServerResource(Name = "formats", UriTemplate = "tmforge://grounding/v1/formats", MimeType = "application/json")]
        [Description("Versioned format catalog snapshot. The fingerprint covers the exact UTF-8 content string; existing formats tool clients remain supported.")]
        public static string Formats() => FormatSnapshot.Value;

        /// <summary>Reads the typed element and flow property catalog.</summary>
        /// <returns>The versioned property snapshot.</returns>
        [McpServerResource(Name = "property_schema", UriTemplate = "tmforge://grounding/v1/property-schema", MimeType = "application/json")]
        [Description("Typed property names, allowed values, and defaults with version and content fingerprint. Same catalog as the property_schema tool.")]
        public static string PropertySchema() => PropertySnapshot.Value;

        /// <summary>Reads the manifest authoring guide shared with the compatibility tool.</summary>
        /// <returns>A versioned text guide, not a JSON Schema validation document.</returns>
        [McpServerResource(Name = "manifest_schema", UriTemplate = "tmforge://grounding/v1/manifest-schema", MimeType = "application/json")]
        [Description("Versioned manifest authoring guide shared with manifest_schema. The enclosed content is text/plain guidance, not a JSON Schema validator.")]
        public static string ManifestSchema() => ManifestSnapshot.Value;

        /// <summary>Reads metadata for the built-in analysis rule packs.</summary>
        /// <returns>The versioned built-in rule-pack snapshot.</returns>
        [McpServerResource(Name = "rule_packs", UriTemplate = "tmforge://grounding/v1/rule-packs", MimeType = "application/json")]
        [Description("Built-in rule-pack catalog with an engine version and catalog fingerprint. No custom rules are selected by this resource.")]
        public static string RulePacks() => BuiltInPackSnapshot.Value;

        /// <summary>Reads effective pack metadata for one sandboxed custom rule file.</summary>
        /// <param name="services">The request services containing the workspace path policy.</param>
        /// <param name="rulesPath">The custom rule file inside the workspace root.</param>
        /// <param name="fingerprint">An optional expected snapshot fingerprint.</param>
        /// <returns>The current versioned metadata, or an error when a pin no longer matches.</returns>
        [McpServerResource(Name = "rule_packs_for_file", UriTemplate = "tmforge://grounding/v1/rule-packs/custom{?rulesPath,fingerprint}", MimeType = "application/json")]
        [Description("Effective built-in and custom rule-pack metadata for a workspace file. URI-encode rulesPath; optional fingerprint pins a previously read snapshot. Each read revalidates the file and sandbox; diagnostics are preserved.")]
        public static string CustomRulePacks(IServiceProvider services, string rulesPath, string? fingerprint = null)
        {
            McpToolSupport.ValidateArguments(new[] { rulesPath, fingerprint });
            if (string.IsNullOrWhiteSpace(rulesPath))
            {
                throw new ArgumentException("A custom rule file path is required.", nameof(rulesPath));
            }

            if (fingerprint != null && (fingerprint.Length != 71 || !fingerprint.StartsWith("sha256:", StringComparison.Ordinal) ||
                fingerprint.Skip(7).Any(character => !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))))
            {
                throw new ArgumentException("A snapshot fingerprint must be sha256: followed by 64 lowercase hexadecimal characters.", nameof(fingerprint));
            }

            return RulePackSnapshot(McpToolSupport.LoadRules(services, rulesPath), fingerprint);
        }

        private static string RulePackSnapshot(EngineRuleOptions? rules, string? fingerprint = null)
        {
            RuleBundleDto metadata = EngineService.DescribeRules(rules, out IReadOnlyList<RulePackDto> catalog);
            string content = CliJson.Serialize(new
            {
                rulePacks = catalog,
                customPacks = metadata.RulePacks,
                diagnostics = metadata.Diagnostics,
                sources = (rules?.Sources ?? Array.Empty<RuleSourceDto>()).Select(source => new
                {
                    name = source.Name,
                    fingerprint = RulePackIdentity.CreateFingerprint(Encoding.UTF8.GetBytes(source.Json ?? string.Empty)),
                }).ToArray(),
            });
            return Snapshot("rule-packs", "application/json", content, fingerprint);
        }

        private static string Snapshot(string kind, string contentType, string content, string? expectedFingerprint = null)
        {
            string fingerprint = RulePackIdentity.CreateFingerprint(Encoding.UTF8.GetBytes(content));
            if (expectedFingerprint != null && !string.Equals(fingerprint, expectedFingerprint, StringComparison.Ordinal))
            {
                throw new McpException($"Grounding snapshot fingerprint mismatch: expected '{expectedFingerprint}', current '{fingerprint}'. Read the unpinned resource to refresh.");
            }

            return McpToolSupport.ValidateResponse(CliJson.Serialize(new
            {
                schema = "tmforge-grounding",
                version = 1,
                kind,
                engineVersion = typeof(EngineService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? string.Empty,
                contentType,
                fingerprint,
                content,
            }));
        }
    }
}
