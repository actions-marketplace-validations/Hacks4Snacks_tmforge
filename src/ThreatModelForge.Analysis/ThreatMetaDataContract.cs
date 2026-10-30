namespace ThreatModelForge.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;

    /// <summary>
    /// Declares the threat metadata the Microsoft Threat Modeling Tool owns.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The tool resolves six of these properties by name while loading a model
    /// (<c>ThreatMetaData.FindIndices</c>) and throws
    /// <c>"KnowledgeBase is missing a required Threat Property in ThreatMetaData"</c> when any of them
    /// is absent, refusing to open the file. Omitting the whole metadata block is tolerated, but
    /// declaring a partial one is not, so a knowledge base that declares any threat metadata at all
    /// must declare the complete required set.
    /// </para>
    /// <para>
    /// These properties are tool-owned rather than authored: their identity is the name, and their
    /// values are the pickers the tool offers. A foreign template's own labels, identifiers, and value
    /// lists are therefore authoritative, and Threat Model Forge defers to them on merge instead of
    /// treating a difference as a conflict.
    /// </para>
    /// </remarks>
    internal static class ThreatMetaDataContract
    {
        /// <summary>The threat title.</summary>
        public const string TitleName = "Title";

        /// <summary>The author-visible threat category.</summary>
        public const string CategoryName = "UserThreatCategory";

        /// <summary>The short description shown in the threat list.</summary>
        public const string ShortDescriptionName = "UserThreatShortDescription";

        /// <summary>The long threat description.</summary>
        public const string DescriptionName = "UserThreatDescription";

        /// <summary>The triage justification.</summary>
        public const string StateInformationName = "StateInformation";

        /// <summary>The rendered source, flow, and target of the interaction.</summary>
        public const string InteractionName = "InteractionString";

        /// <summary>The threat priority.</summary>
        public const string PriorityName = "Priority";

        private static readonly HashSet<string> ToolOwnedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            TitleName,
            CategoryName,
            ShortDescriptionName,
            DescriptionName,
            StateInformationName,
            InteractionName,
            PriorityName,
        };

        /// <summary>
        /// Gets a value indicating whether the named property is owned by the tool rather than authored.
        /// </summary>
        /// <param name="name">The property name to test.</param>
        /// <returns><see langword="true"/> when the tool owns the property.</returns>
        public static bool IsToolOwned(string? name)
            => !string.IsNullOrEmpty(name) && ToolOwnedNames.Contains(name!);

        /// <summary>
        /// Builds the complete threat metadata block, declaring every property the tool requires plus
        /// the priority vocabulary.
        /// </summary>
        /// <param name="priorities">The priority vocabulary to offer.</param>
        /// <returns>A metadata block the tool can load.</returns>
        public static ThreatMetaData Create(IEnumerable<string> priorities)
        {
            ThreatMetaData metadata = new ThreatMetaData { IsPriorityUsed = true };
            metadata.PropertiesMetaData.Add(Datum(TitleName, "Title", "tmforge:title", 0, false));
            metadata.PropertiesMetaData.Add(Datum(CategoryName, "Category", "tmforge:category", 0, false));
            metadata.PropertiesMetaData.Add(
                Datum(ShortDescriptionName, "Short Description", "tmforge:short-description", 1, true));
            metadata.PropertiesMetaData.Add(Datum(DescriptionName, "Description", "tmforge:description", 0, false));
            metadata.PropertiesMetaData.Add(
                Datum(StateInformationName, "Justification", "tmforge:state-information", 0, false));
            metadata.PropertiesMetaData.Add(Datum(InteractionName, "Interaction", "tmforge:interaction", 0, false));

            ThreatMetaDatum priority = Datum(PriorityName, "Priority", "tmforge:priority", 1, false);
            priority.Description = "Generated threat priority.";
            foreach (string value in priorities)
            {
                priority.Values.Add(value);
            }

            metadata.PropertiesMetaData.Add(priority);
            return metadata;
        }

        /// <summary>Projects persisted findings into the identity and property contract MTMT actually loads.</summary>
        /// <param name="model">The model whose template has already been prepared.</param>
        public static void PrepareInstances(ThreatModel model)
        {
            ThreatMetaData metadata = model.KnowledgeBase!.ThreatMetaData!;
            foreach (KeyValuePair<string, Threat> entry in model.AllThreatsDictionary)
            {
                Threat threat = entry.Value;
                string key = string.IsNullOrEmpty(threat.InteractionKey) ? entry.Key : threat.InteractionKey!;
                if (ManualThreatId.IsManual(key) && string.IsNullOrEmpty(threat.TypeId))
                {
                    // Configure rejects null; IsUserDefined requires exactly BS plus a 36-character GUID.
                    threat.TypeId = ManualThreatId.ToNativeTypeId(key);
                }

                threat.Properties ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                Dictionary<string, string?> projected = new Dictionary<string, string?>
                {
                    [TitleName] = threat.Title,
                    [CategoryName] = threat.UserThreatCategory,
                    [ShortDescriptionName] = threat.UserThreatShortDescription,
                    [DescriptionName] = threat.UserThreatDescription,
                    [StateInformationName] = threat.StateInformation,
                    [InteractionName] = threat.InteractionString,
                    [PriorityName] = threat.Priority,
                };
                foreach (KeyValuePair<string, string?> property in projected.Where(property => property.Value != null))
                {
                    // MTMT ignores these legacy fields once a property bag exists. Keep native-only values
                    // when the legacy field is absent, rather than erasing a foreign tool's finding text.
                    threat.Properties[property.Key] = property.Value!;
                }

                foreach (string name in threat.Properties.Keys.OrderBy(name => name, StringComparer.Ordinal))
                {
                    if (!metadata.PropertiesMetaData.Any(datum => string.Equals(datum.Name, name, StringComparison.Ordinal)))
                    {
                        // MTMT initializes and saves only declared properties, including private override markers.
                        bool mitigation = string.Equals(name, "Mitigation", StringComparison.Ordinal);
                        metadata.PropertiesMetaData.Add(Datum(name, name, "tmforge:threat-property:" + name, mitigation ? 2 : 0, !mitigation));
                    }
                }
            }
        }

        private static ThreatMetaDatum Datum(string name, string label, string id, int attributeType, bool hideFromUI)
        {
            return new ThreatMetaDatum
            {
                Name = name,
                Label = label,
                Id = id,
                AttributeType = attributeType,
                HideFromUI = hideFromUI,
            };
        }
    }
}
