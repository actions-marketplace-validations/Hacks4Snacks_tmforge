namespace ThreatModelForge.KnowledgeBase
{
    using System;
    using System.Globalization;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// The reserved identity namespace for manually-authored threats.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A rule-derived threat is keyed by what produced it, so re-running the analysis finds the same
    /// entry and updates it in place. A manually-authored threat has no rule to derive an id from, so
    /// the author owns it — and an author who cannot choose the id cannot reference the threat from
    /// anywhere else: a ticket, a control catalogue, a review document, or the script that authored it.
    /// </para>
    /// <para>
    /// The <c>manual:</c> prefix keeps the two apart. Rule generation can never collide with an
    /// author's id, and an author can never accidentally claim the key of a generated threat and have
    /// it silently overwritten on the next run.
    /// </para>
    /// </remarks>
    public static class ManualThreatId
    {
        /// <summary>The reserved prefix every manually-authored threat id carries.</summary>
        public const string Prefix = "manual:";

        /// <summary>
        /// The longest permitted author-chosen portion. Generous for a readable slug, bounded because
        /// the id becomes a dictionary key, an XML attribute, and a JSON property value.
        /// </summary>
        public const int MaxLocalLength = 128;

        /// <summary>Determines whether a register key denotes a manually-authored threat.</summary>
        /// <param name="key">The register key or interaction key.</param>
        /// <returns><see langword="true"/> when the key is in the manual namespace.</returns>
        public static bool IsManual(string? key) =>
            key != null && key.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

        /// <summary>Mints a fresh manual id, for an author who does not supply one.</summary>
        /// <returns>A new manual id.</returns>
        public static string Create() => Prefix + Guid.NewGuid().ToString("N");

        /// <summary>Derives MTMT's user-defined type identity without changing the author's register key.</summary>
        /// <param name="key">The manual register key.</param>
        /// <returns>The native <c>BS</c> prefix followed by a stable, hyphenated GUID.</returns>
        public static string ToNativeTypeId(string key)
        {
            if (!IsManual(key) || key.Length == Prefix.Length)
            {
                throw new ArgumentException("A manual threat register key is required.", nameof(key));
            }

            byte[] bytes = new byte[16];
            using (SHA256 hash = SHA256.Create())
            {
                Array.Copy(hash.ComputeHash(Encoding.UTF8.GetBytes("tmforge-mtmt-threat:" + key.ToUpperInvariant())), bytes, bytes.Length);
            }

            bytes[7] = (byte)((bytes[7] & 0x0f) | 0x50);
            bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
            return "BS" + new Guid(bytes).ToString("D");
        }

        /// <summary>Recognizes the native user-defined threat identity, not an analysis rule id.</summary>
        /// <param name="typeId">The serialized threat type id.</param>
        /// <returns>Whether the value is an MTMT user-defined type id.</returns>
        public static bool IsNativeTypeId(string? typeId) =>
            typeId != null && typeId.Length == 38 && typeId.StartsWith("BS", StringComparison.Ordinal)
            && Guid.TryParseExact(typeId.Substring(2), "D", out _);

        /// <summary>
        /// Normalizes an author-supplied id into the reserved namespace.
        /// </summary>
        /// <remarks>
        /// The prefix is optional on input, so <c>login-bypass</c> and <c>manual:login-bypass</c> are
        /// the same id rather than two. Anything a reader could mistake for a different id is refused
        /// rather than quietly rewritten: an author who mistypes an id and gets a second threat instead
        /// of an error has lost the identity they were trying to establish.
        /// </remarks>
        /// <param name="supplied">The author's id, with or without the prefix.</param>
        /// <param name="id">On success, the canonical id.</param>
        /// <param name="error">On failure, why the id was refused.</param>
        /// <returns><see langword="true"/> when the id is usable.</returns>
        public static bool TryCanonicalize(string? supplied, out string id, out string? error)
        {
            id = string.Empty;
            error = null;

            string local = (supplied ?? string.Empty).Trim();
            if (IsManual(local))
            {
                local = local.Substring(Prefix.Length);
            }

            if (local.Length == 0)
            {
                error = "A manual threat id cannot be empty.";
                return false;
            }

            if (local.Length > MaxLocalLength)
            {
                error = string.Format(
                    CultureInfo.CurrentCulture,
                    "A manual threat id can be at most {0} characters; '{1}' is {2}.",
                    MaxLocalLength,
                    local,
                    local.Length);
                return false;
            }

            foreach (char character in local)
            {
                if (!IsAllowed(character))
                {
                    error = string.Format(
                        CultureInfo.CurrentCulture,
                        "A manual threat id can contain only letters, digits, '-', '_', and '.'; '{0}' contains '{1}'.",
                        local,
                        character);
                    return false;
                }
            }

            id = Prefix + local;
            return true;
        }

        private static bool IsAllowed(char character)
        {
            // Deliberately narrow. ':' is the namespace separator, whitespace and punctuation make an
            // id ambiguous to quote in a shell or a report, and anything non-ASCII invites two ids that
            // look identical to a reviewer.
            return (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '-' ||
                character == '_' ||
                character == '.';
        }
    }
}
