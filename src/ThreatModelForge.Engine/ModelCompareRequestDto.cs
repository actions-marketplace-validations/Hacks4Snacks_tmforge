namespace ThreatModelForge.Engine
{
    /// <summary>The two immutable snapshots to review, without merging either one.</summary>
    public sealed class ModelCompareRequestDto
    {
        /// <summary>Gets the earlier model.</summary>
        public TmForgeModelDto? Baseline { get; init; }

        /// <summary>Gets the proposed model.</summary>
        public TmForgeModelDto? Proposed { get; init; }
    }
}
