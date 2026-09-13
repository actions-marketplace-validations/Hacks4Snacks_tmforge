namespace ThreatModelForge.Editing
{
    using System;

    /// <summary>
    /// One pair of drawing objects whose rendered text occupies the same space, reported by
    /// <see cref="DiagramLabels.Inspect"/>. A diagram that reports none is legible in the Microsoft
    /// Threat Modeling Tool; one that reports many is the smear of stacked text a large generated
    /// model produces by default.
    /// </summary>
    public sealed class LabelOverlap
    {
        /// <summary>Initializes a new instance of the <see cref="LabelOverlap"/> class.</summary>
        /// <param name="flow">The name of the flow whose label is obstructed.</param>
        /// <param name="obstructedBy">The name of the object it collides with.</param>
        /// <param name="kind">What the obstruction is: <c>flow</c> or <c>element</c>.</param>
        /// <param name="area">The area of the intersection, in square drawing units.</param>
        public LabelOverlap(string flow, string obstructedBy, string kind, int area)
        {
            this.Flow = flow ?? throw new ArgumentNullException(nameof(flow));
            this.ObstructedBy = obstructedBy ?? throw new ArgumentNullException(nameof(obstructedBy));
            this.Kind = kind ?? throw new ArgumentNullException(nameof(kind));
            this.Area = area;
        }

        /// <summary>Gets the name of the flow whose label is obstructed.</summary>
        public string Flow { get; }

        /// <summary>Gets the name of the object obstructing it.</summary>
        public string ObstructedBy { get; }

        /// <summary>Gets what the obstruction is: <c>flow</c> for another label, <c>element</c> for a shape.</summary>
        public string Kind { get; }

        /// <summary>Gets the area of the intersection, in square drawing units.</summary>
        public int Area { get; }
    }
}
