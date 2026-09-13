namespace ThreatModelForge.Model.Abstracts
{
    using System;
    using System.Runtime.Serialization;

    /// <summary>
    /// Base type for connectors and boundary lines — elements defined by a source point, a target
    /// point, and a single curve handle rather than a bounding box.
    /// </summary>
    [DataContract(Namespace = "http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts")]
    public abstract class LineElement : Entity
    {
        private int handleX;
        private int handleY;
        private string? portSource;
        private string? portTarget;

        /// <summary>
        /// Gets or sets the x coordinate of the curve handle. When unset it serializes as the midpoint
        /// of the source and target so the line satisfies the Microsoft Threat Modeling Tool's
        /// coordinate validation (which rejects a handle below its minimum drawing coordinate).
        /// </summary>
        [DataMember]
        public int HandleX
        {
            get => this.handleX != 0 ? this.handleX : (this.SourceX + this.TargetX) / 2;
            set => this.handleX = value;
        }

        /// <summary>
        /// Gets or sets the y coordinate of the curve handle. When unset it serializes as the midpoint
        /// of the source and target so the line satisfies the tool's coordinate validation.
        /// </summary>
        [DataMember]
        public int HandleY
        {
            get => this.handleY != 0 ? this.handleY : (this.SourceY + this.TargetY) / 2;
            set => this.handleY = value;
        }

        /// <summary>
        /// Gets a value indicating whether the curve handle sits at the midpoint of the endpoints,
        /// which is where it lies when nobody has moved it: either because none was ever recorded, or
        /// because the midpoint was written eagerly when the line was created.
        /// </summary>
        /// <remarks>
        /// A caller that positions labels needs this to tell a deliberate placement from a default
        /// one. The handle is both the curve's control point and the point the label is drawn on, so a
        /// handle at the midpoint means a straight line carrying no placement intent, and a handle
        /// anywhere else is somebody's decision. It is deliberately not a
        /// <see cref="DataMemberAttribute"/> — it describes the stored state rather than adding to it.
        /// </remarks>
        public bool HandleIsAtMidpoint => (this.handleX == 0 && this.handleY == 0)
            || (this.HandleX == (this.SourceX + this.TargetX) / 2
                && this.HandleY == (this.SourceY + this.TargetY) / 2);

        /// <summary>
        /// Gets or sets the source connection port. It serializes as a <c>StencilConnectionPort</c>
        /// name (<c>None</c> when unset) because the Microsoft Threat Modeling Tool types this member
        /// as a non-nullable enum and cannot deserialize a nil value.
        /// </summary>
        [DataMember]
        public string PortSource
        {
            get => string.IsNullOrEmpty(this.portSource) ? "None" : this.portSource!;
            set => this.portSource = value;
        }

        /// <summary>
        /// Gets or sets the target connection port. It serializes as a <c>StencilConnectionPort</c>
        /// name (<c>None</c> when unset) for the same reason as <see cref="PortSource"/>.
        /// </summary>
        [DataMember]
        public string PortTarget
        {
            get => string.IsNullOrEmpty(this.portTarget) ? "None" : this.portTarget!;
            set => this.portTarget = value;
        }

        /// <summary>Gets or sets the identifier of the element the source end attaches to.</summary>
        [DataMember]
        public Guid SourceGuid { get; set; }

        /// <summary>Gets or sets the source endpoint x coordinate.</summary>
        [DataMember]
        public int SourceX { get; set; }

        /// <summary>Gets or sets the source endpoint y coordinate.</summary>
        [DataMember]
        public int SourceY { get; set; }

        /// <summary>Gets or sets the identifier of the element the target end attaches to.</summary>
        [DataMember]
        public Guid TargetGuid { get; set; }

        /// <summary>Gets or sets the target endpoint x coordinate.</summary>
        [DataMember]
        public int TargetX { get; set; }

        /// <summary>Gets or sets the target endpoint y coordinate.</summary>
        [DataMember]
        public int TargetY { get; set; }
    }
}
