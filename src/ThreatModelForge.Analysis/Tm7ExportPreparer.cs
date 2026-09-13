namespace ThreatModelForge.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using ThreatModelForge.Editing;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Prepares an in-memory model for export to the Microsoft Threat Modeling Tool's <c>.tm7</c>
    /// format so any write path (the CLI authoring verbs, <c>convert</c>, and the engine's Studio/API
    /// export) produces a file that opens in the tool. It embeds Threat Model Forge's own knowledge
    /// base and projects the element property schema onto the model so known properties render as
    /// first-class, typed tool properties rather than free-form custom attributes.
    /// </summary>
    /// <remarks>
    /// A model that already carries a foreign knowledge base (for example, one loaded from a file
    /// authored in the tool, or supplied through <c>convert --knowledge-base</c>) is left untouched,
    /// because its attributes follow a different naming scheme. Only an absent or Threat Model
    /// Forge-authored knowledge base is rebuilt, which keeps the operation idempotent under iterative
    /// authoring: re-preparing an already-prepared model rebuilds the same default knowledge base and
    /// leaves the already-typed properties in place while typing any newly added ones.
    /// </remarks>
    public static class Tm7ExportPreparer
    {
        /// <summary>
        /// The smallest drawing coordinate the Microsoft Threat Modeling Tool accepts. The tool treats
        /// any element positioned below this as corrupted and silently "corrects" it on open, so the
        /// export normalizes coordinates to sit at or beyond it.
        /// </summary>
        private const int MinimumCoordinate = 10;

        /// <summary>
        /// The largest drawing coordinates the tool accepts, which it applies per element kind: borders
        /// are clamped to 1890 x 2090 and connector endpoints and handles to 1990 x 2190. Exceeding
        /// either is "corrected" on open exactly as an under-run is.
        /// </summary>
        private const int MaximumBorderX = 1890;

        /// <summary>The largest border ordinate the tool accepts.</summary>
        private const int MaximumBorderY = 2090;

        /// <summary>The largest connector abscissa the tool accepts.</summary>
        private const int MaximumLineX = 1990;

        /// <summary>The largest connector ordinate the tool accepts.</summary>
        private const int MaximumLineY = 2190;

        /// <summary>
        /// Ensures the model carries the default knowledge base and has its schema-backed properties
        /// typed, unless it already carries a foreign knowledge base.
        /// </summary>
        /// <param name="model">The model to prepare; it is mutated in place.</param>
        public static void Prepare(ThreatModel model)
        {
            using RuleSet ruleSet = AnalysisRuleSources.Create();
            Prepare(model, ruleSet);
        }

        /// <summary>
        /// Ensures the model carries a knowledge base built from the supplied effective rule set and
        /// has its schema-backed properties typed, unless it already carries a foreign knowledge base.
        /// </summary>
        /// <param name="model">The model to prepare; it is mutated in place.</param>
        /// <param name="ruleSet">The effective rules whose categories and threat types are embedded.</param>
        public static void Prepare(ThreatModel model, RuleSet ruleSet)
        {
            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            if (ruleSet == null)
            {
                throw new ArgumentNullException(nameof(ruleSet));
            }

            // Give any flow label that has no recorded position one, before the shift below, so the
            // normalization accounts for where the labels actually ended up. The tool prints a flow's
            // name on its connector, and a model arriving from a format that carries no connector
            // geometry — the canonical tmforge-json the API and Studio speak — has no positions at
            // all, so every label would otherwise land on its connector's midpoint and flows sharing a
            // pair of endpoints would print their names on top of each other. A label an author placed
            // is left exactly where it is.
            foreach (DrawingSurfaceModel surface in model.DrawingSurfaceList)
            {
                DiagramLabels.DeconflictUnplaced(surface);
            }

            // Shift each surface so no element sits below the tool's minimum drawing coordinate. This is
            // independent of the knowledge base, so it runs before the foreign-knowledge-base short
            // circuit below.
            NormalizeCoordinates(model);

            if (model.KnowledgeBase != null && !KnowledgeBaseCatalog.IsDefault(model.KnowledgeBase))
            {
                MergeThreatCatalog(model.KnowledgeBase, KnowledgeBaseCatalog.CreateDefault(ruleSet), true);
                return;
            }

            KnowledgeBaseData? existingKnowledgeBase = model.KnowledgeBase;
            KnowledgeBaseData knowledgeBase = KnowledgeBaseCatalog.CreateDefault(ruleSet);
            if (existingKnowledgeBase != null)
            {
                MergeThreatCatalog(knowledgeBase, existingKnowledgeBase, false);
            }

            SchemaBackedProperties.Apply(model, knowledgeBase);
            StencilSubtypeProjection.Apply(model, knowledgeBase);
            model.KnowledgeBase = knowledgeBase;
        }

        private static void MergeThreatCatalog(KnowledgeBaseData target, KnowledgeBaseData source, bool rejectConflicts)
        {
            ThreatMetaDatum? nativePriority = target.ThreatMetaData?.PropertiesMetaData.FirstOrDefault(IsPriorityMetadata);
            Dictionary<string, string> categoryIds = target.ThreatCategories
                .Where(category => !string.IsNullOrEmpty(category.Id))
                .ToDictionary(category => category.Id!, category => category.Id!, StringComparer.OrdinalIgnoreCase);
            foreach (ThreatCategory category in source.ThreatCategories)
            {
                ThreatCategory? existing = target.ThreatCategories.FirstOrDefault(candidate =>
                    string.Equals(candidate.Id, category.Id, StringComparison.OrdinalIgnoreCase));
                if (existing == null)
                {
                    target.ThreatCategories.Add(category);
                    if (!string.IsNullOrEmpty(category.Id))
                    {
                        categoryIds[category.Id!] = category.Id!;
                    }

                    continue;
                }

                if (rejectConflicts && !string.Equals(existing.Name, category.Name, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        $"Foreign knowledge base category '{category.Id}' conflicts with the effective rule set.");
                }

                if (!string.IsNullOrEmpty(category.Id) && !string.IsNullOrEmpty(existing.Id))
                {
                    categoryIds[category.Id!] = existing.Id!;
                }
            }

            foreach (ThreatType threatType in source.ThreatTypes)
            {
                string? categoryId = threatType.Category != null && categoryIds.TryGetValue(threatType.Category, out string? retainedId)
                    ? retainedId
                    : threatType.Category;
                ThreatType? existing = target.ThreatTypes.FirstOrDefault(candidate =>
                    string.Equals(candidate.Id, threatType.Id, StringComparison.OrdinalIgnoreCase));
                if (existing == null)
                {
                    threatType.Category = categoryId;
                    NormalizePriorityMetadata(threatType.PropertiesMetaData, nativePriority);
                    target.ThreatTypes.Add(threatType);
                    continue;
                }

                if (rejectConflicts &&
                    (!string.Equals(existing.Category, categoryId, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(existing.ShortTitle, threatType.ShortTitle, StringComparison.Ordinal) ||
                    !string.Equals(existing.Description, threatType.Description, StringComparison.Ordinal) ||
                    !string.Equals(existing.RelatedCategory, threatType.RelatedCategory, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(existing.GenerationFilters.Include, threatType.GenerationFilters.Include, StringComparison.Ordinal) ||
                    !string.Equals(existing.GenerationFilters.Exclude, threatType.GenerationFilters.Exclude, StringComparison.Ordinal)))
                {
                    throw new InvalidOperationException(
                        $"Foreign knowledge base threat type '{threatType.Id}' conflicts with the effective rule set.");
                }

                NormalizePriorityMetadata(existing.PropertiesMetaData, nativePriority);
                MergeThreatMetadata(
                    existing.PropertiesMetaData,
                    threatType.PropertiesMetaData,
                    rejectConflicts,
                    $"threat type '{threatType.Id}'",
                    nativePriority);
            }

            if (source.ThreatMetaData == null)
            {
                return;
            }

            if (target.ThreatMetaData == null)
            {
                target.ThreatMetaData = source.ThreatMetaData;
                return;
            }

            target.ThreatMetaData.IsPriorityUsed |= source.ThreatMetaData.IsPriorityUsed;
            MergeThreatMetadata(
                target.ThreatMetaData.PropertiesMetaData,
                source.ThreatMetaData.PropertiesMetaData,
                rejectConflicts,
                "global threat metadata",
                nativePriority,
                isGlobalVocabulary: true);
        }

        private static void MergeThreatMetadata(
            List<ThreatMetaDatum> target,
            IEnumerable<ThreatMetaDatum> source,
            bool rejectConflicts,
            string owner,
            ThreatMetaDatum? nativePriority,
            bool isGlobalVocabulary = false)
        {
            foreach (ThreatMetaDatum sourceDatum in source)
            {
                ThreatMetaDatum datum = NormalizePriorityMetadata(sourceDatum, nativePriority);
                List<ThreatMetaDatum> matches = string.IsNullOrEmpty(datum.Name)
                    ? new List<ThreatMetaDatum>()
                    : target.Where(existing =>
                        string.Equals(existing.Name, datum.Name, StringComparison.OrdinalIgnoreCase)).ToList();
                if (matches.Count == 0 && !string.IsNullOrEmpty(datum.Id))
                {
                    matches = target.Where(existing =>
                        string.Equals(existing.Id, datum.Id, StringComparison.OrdinalIgnoreCase)).ToList();
                }

                if (matches.Count == 0)
                {
                    target.Add(datum);
                    continue;
                }

                // Two knowledge bases can declare the tool's own threat metadata differently without
                // being in conflict: these properties are identified by name, and their values are the
                // pickers the tool offers, so the union is what lets every value either side can express
                // stay selectable. Rejecting the difference would fail the export outright, and taking
                // one side's list would leave threats carrying a value the tool no longer offers - the
                // silent downgrade this is here to prevent. The foreign template's own label and
                // identifier are authoritative, so only the values are folded in.
                if (isGlobalVocabulary && matches.Count == 1 && ThreatMetaDataContract.IsToolOwned(datum.Name))
                {
                    UnionValues(matches[0].Values, datum.Values);
                    continue;
                }

                if (rejectConflicts && (matches.Count != 1 || !ThreatMetadataMatches(matches[0], datum)))
                {
                    throw new InvalidOperationException(
                        $"Foreign knowledge base {owner} conflicts with metadata '{datum.Id ?? datum.Name}'.");
                }
            }
        }

        /// <summary>
        /// Adds any values the target does not already offer, keeping the target's own ordering so a
        /// foreign template's presentation is preserved and only genuinely new values are appended.
        /// </summary>
        /// <param name="target">The vocabulary to extend, in place.</param>
        /// <param name="source">The vocabulary to fold in.</param>
        private static void UnionValues(List<string> target, IEnumerable<string> source)
        {
            foreach (string value in source)
            {
                if (!target.Any(existing => string.Equals(existing, value, StringComparison.OrdinalIgnoreCase)))
                {
                    target.Add(value);
                }
            }
        }

        private static void NormalizePriorityMetadata(
            List<ThreatMetaDatum> metadata,
            ThreatMetaDatum? nativePriority)
        {
            if (nativePriority == null)
            {
                return;
            }

            for (int index = 0; index < metadata.Count; index++)
            {
                metadata[index] = NormalizePriorityMetadata(metadata[index], nativePriority);
            }
        }

        private static ThreatMetaDatum NormalizePriorityMetadata(
            ThreatMetaDatum datum,
            ThreatMetaDatum? nativePriority)
        {
            if (nativePriority == null || !IsPriorityMetadata(datum))
            {
                return datum;
            }

            ThreatMetaDatum normalized = new ThreatMetaDatum
            {
                Name = nativePriority.Name,
                Label = nativePriority.Label,
                HideFromUI = nativePriority.HideFromUI,
                Description = nativePriority.Description,
                Id = nativePriority.Id,
                AttributeType = nativePriority.AttributeType,
            };
            normalized.Values.AddRange(datum.Values);
            return normalized;
        }

        private static bool IsPriorityMetadata(ThreatMetaDatum datum)
            => string.Equals(datum.Name, "Priority", StringComparison.OrdinalIgnoreCase);

        private static bool ThreatMetadataMatches(ThreatMetaDatum left, ThreatMetaDatum right)
        {
            return string.Equals(left.Id, right.Id, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.Name, right.Name, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.Label, right.Label, StringComparison.Ordinal) &&
                string.Equals(left.Description, right.Description, StringComparison.Ordinal) &&
                left.HideFromUI == right.HideFromUI &&
                left.AttributeType == right.AttributeType &&
                left.Values.SequenceEqual(right.Values, StringComparer.Ordinal);
        }

        /// <summary>
        /// Translates each drawing surface as a whole so its element and connector coordinates sit
        /// inside the range the tool accepts. Shifting the surface rather than clamping each element
        /// individually preserves the relative layout and keeps connectors attached to their endpoints,
        /// which a per-element clamp (as the tool itself performs) would not.
        /// </summary>
        /// <param name="model">The model to normalize; it is mutated in place.</param>
        private static void NormalizeCoordinates(ThreatModel model)
        {
            foreach (DrawingSurfaceModel surface in model.DrawingSurfaceList)
            {
                int minX = int.MaxValue;
                int minY = int.MaxValue;
                int upperX = int.MaxValue;
                int upperY = int.MaxValue;

                foreach (DrawingElement element in surface.Borders.Values.OfType<DrawingElement>())
                {
                    minX = Math.Min(minX, element.Left);
                    minY = Math.Min(minY, element.Top);
                    upperX = Math.Min(upperX, MaximumBorderX - element.Left);
                    upperY = Math.Min(upperY, MaximumBorderY - element.Top);
                }

                foreach (LineElement line in surface.Lines.Values.OfType<LineElement>())
                {
                    int lineMinX = Math.Min(line.SourceX, Math.Min(line.TargetX, line.HandleX));
                    int lineMinY = Math.Min(line.SourceY, Math.Min(line.TargetY, line.HandleY));
                    int lineMaxX = Math.Max(line.SourceX, Math.Max(line.TargetX, line.HandleX));
                    int lineMaxY = Math.Max(line.SourceY, Math.Max(line.TargetY, line.HandleY));
                    minX = Math.Min(minX, lineMinX);
                    minY = Math.Min(minY, lineMinY);
                    upperX = Math.Min(upperX, MaximumLineX - lineMaxX);
                    upperY = Math.Min(upperY, MaximumLineY - lineMaxY);
                }

                if (minX == int.MaxValue)
                {
                    continue;
                }

                int deltaX = ShiftInto(minX, upperX);
                int deltaY = ShiftInto(minY, upperY);
                if (deltaX == 0 && deltaY == 0)
                {
                    continue;
                }

                foreach (DrawingElement element in surface.Borders.Values.OfType<DrawingElement>())
                {
                    element.Left += deltaX;
                    element.Top += deltaY;
                }

                foreach (LineElement line in surface.Lines.Values.OfType<LineElement>())
                {
                    // Shift the handle first: an unset handle reports the midpoint of its endpoints, so
                    // reading it before the endpoints move yields the original midpoint to offset.
                    line.HandleX += deltaX;
                    line.HandleY += deltaY;
                    line.SourceX += deltaX;
                    line.SourceY += deltaY;
                    line.TargetX += deltaX;
                    line.TargetY += deltaY;
                }
            }
        }

        /// <summary>
        /// Chooses the translation that brings one axis of a surface inside the tool's range, given the
        /// lowest coordinate on that axis and the largest shift its highest coordinates still allow.
        /// </summary>
        /// <remarks>
        /// A surface drawn wider than the tool's canvas cannot satisfy both bounds by translation. It is
        /// anchored at the low edge instead, because scaling it to fit would change the geometry that
        /// trust-boundary containment is derived from, which would alter the analysis rather than the
        /// drawing.
        /// </remarks>
        /// <param name="minimum">The lowest coordinate present on the axis.</param>
        /// <param name="headroom">The largest shift the highest coordinates on the axis permit.</param>
        /// <returns>The offset to add to every coordinate on the axis.</returns>
        private static int ShiftInto(int minimum, int headroom)
        {
            int required = MinimumCoordinate - minimum;
            if (required > headroom)
            {
                return Math.Max(required, 0);
            }

            return Math.Min(Math.Max(required, 0), headroom);
        }
    }
}
