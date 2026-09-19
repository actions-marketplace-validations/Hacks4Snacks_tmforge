namespace ThreatModelForge.Formats
{
    /// <summary>The custom pack identity expected by a canonical model's analysis settings.</summary>
    public sealed class TmForgeJsonExpectedPack
    {
        /// <summary>Gets the expected pack id.</summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>Gets the expected content fingerprint.</summary>
        public string Fingerprint { get; init; } = string.Empty;
    }
}
