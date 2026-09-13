namespace ThreatModelForge.Editing
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using ThreatModelForge.KnowledgeBase;
    using ThreatModelForge.Model;
    using ThreatModelForge.Model.Abstracts;

    /// <summary>
    /// Provides UI-agnostic editing operations over a <see cref="ThreatModel"/> with snapshot-based
    /// undo and redo. Each logical edit should be preceded by a call to <see cref="BeginChange"/>,
    /// which records an undo checkpoint capturing the pre-edit state.
    /// </summary>
    public sealed class DiagramEditor
    {
        private const int MaxHistory = 50;
        private const int MinimumSize = 20;
        private const string ProcessTypeId = "GE.P";
        private const string ExternalEntityTypeId = "GE.EI";
        private const string DataStoreTypeId = "GE.DS";
        private const string TrustBoundaryTypeId = "GE.TB.B";
        private const string DataFlowTypeId = "GE.DF";

        private readonly List<byte[]> undoStack = new List<byte[]>();
        private readonly List<byte[]> redoStack = new List<byte[]>();

        /// <summary>
        /// Initializes a new instance of the <see cref="DiagramEditor"/> class.
        /// </summary>
        /// <param name="model">The model to edit.</param>
        public DiagramEditor(ThreatModel model)
        {
            this.Model = model ?? throw new ArgumentNullException(nameof(model));
        }

        /// <summary>
        /// Gets the model currently being edited. The reference is replaced by <see cref="Undo"/>
        /// and <see cref="Redo"/>, so callers should re-resolve diagrams and elements afterward.
        /// </summary>
        public ThreatModel Model { get; private set; }

        /// <summary>
        /// Gets a value indicating whether an undo checkpoint is available.
        /// </summary>
        public bool CanUndo => this.undoStack.Count > 0;

        /// <summary>
        /// Gets a value indicating whether a redo checkpoint is available.
        /// </summary>
        public bool CanRedo => this.redoStack.Count > 0;

        /// <summary>
        /// Finds an element (component, boundary, or line) by its unique identifier.
        /// </summary>
        /// <param name="diagram">The diagram to search.</param>
        /// <param name="guid">The element identifier.</param>
        /// <returns>The element, or <see langword="null"/> when it is not found.</returns>
        public static Entity? FindElement(DrawingSurfaceModel diagram, Guid guid)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Borders.TryGetValue(guid, out object? border) && border is Entity borderEntity)
            {
                return borderEntity;
            }

            if (diagram.Lines.TryGetValue(guid, out object? line) && line is Entity lineEntity)
            {
                return lineEntity;
            }

            return null;
        }

        /// <summary>
        /// Records an undo checkpoint capturing the current state. Call this once before a logical
        /// edit (for a drag gesture, call it at the start of the gesture, not per movement).
        /// </summary>
        public void BeginChange()
        {
            Push(this.undoStack, this.Model);
            this.redoStack.Clear();
        }

        /// <summary>
        /// Moves an element by a relative offset. When a component is moved, the endpoints of any
        /// connectors attached to it move with it. This is a raw mutation: call <see cref="BeginChange"/>
        /// once at the start of the drag gesture to make the whole gesture undoable.
        /// </summary>
        /// <param name="diagram">The diagram containing the element.</param>
        /// <param name="guid">The element identifier.</param>
        /// <param name="deltaX">The horizontal offset.</param>
        /// <param name="deltaY">The vertical offset.</param>
        public void MoveElementBy(DrawingSurfaceModel diagram, Guid guid, int deltaX, int deltaY)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Borders.TryGetValue(guid, out object? border) && border is DrawingElement component)
            {
                component.Left += deltaX;
                component.Top += deltaY;
                MoveAttachedConnectors(diagram, guid, deltaX, deltaY);
            }
            else if (diagram.Lines.TryGetValue(guid, out object? line) && line is LineElement lineElement)
            {
                lineElement.SourceX += deltaX;
                lineElement.SourceY += deltaY;
                lineElement.TargetX += deltaX;
                lineElement.TargetY += deltaY;
                lineElement.HandleX += deltaX;
                lineElement.HandleY += deltaY;
            }
        }

        /// <summary>
        /// Sets the display name of an element. This is a raw mutation: call <see cref="BeginChange"/>
        /// beforehand to make it undoable.
        /// </summary>
        /// <param name="diagram">The diagram containing the element.</param>
        /// <param name="guid">The element identifier.</param>
        /// <param name="name">The new name.</param>
        public void SetElementName(DrawingSurfaceModel diagram, Guid guid, string name)
        {
            Entity? element = FindElement(diagram, guid);
            if (element != null)
            {
                DiagramElementHelper.SetName(element, name);
            }
        }

        /// <summary>
        /// Removes an element from the diagram. Removing a component also removes any connectors
        /// attached to it. This is a raw mutation: call <see cref="BeginChange"/> beforehand to
        /// make it undoable.
        /// </summary>
        /// <param name="diagram">The diagram containing the element.</param>
        /// <param name="guid">The element identifier.</param>
        public void RemoveElement(DrawingSurfaceModel diagram, Guid guid)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Borders.Remove(guid))
            {
                List<Guid> attached = diagram.Lines
                    .Where(pair => pair.Value is LineElement line && (line.SourceGuid == guid || line.TargetGuid == guid))
                    .Select(pair => pair.Key)
                    .ToList();

                foreach (Guid attachedGuid in attached)
                {
                    diagram.Lines.Remove(attachedGuid);
                }
            }
            else
            {
                diagram.Lines.Remove(guid);
            }
        }

        /// <summary>
        /// Adds a new component or boundary of the given kind at the given position and returns its
        /// identifier. This is a raw mutation: call <see cref="BeginChange"/> beforehand.
        /// </summary>
        /// <param name="diagram">The diagram to add to.</param>
        /// <param name="kind">The kind of element to add.</param>
        /// <param name="x">The left coordinate.</param>
        /// <param name="y">The top coordinate.</param>
        /// <returns>The identifier of the new element.</returns>
        public Guid AddElement(DrawingSurfaceModel diagram, StencilKind kind, int x, int y)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            DrawingElement element = CreateStencil(kind);
            element.Guid = Guid.NewGuid();
            element.Left = x;
            element.Top = y;
            diagram.Borders[element.Guid] = element;
            DiagramElementHelper.SetName(element, DefaultName(kind));
            return element.Guid;
        }

        /// <summary>
        /// Adds a data-flow connector between two components, with endpoints at their centers, and
        /// returns its identifier. This is a raw mutation: call <see cref="BeginChange"/> beforehand.
        /// </summary>
        /// <param name="diagram">The diagram to add to.</param>
        /// <param name="sourceGuid">The source component identifier.</param>
        /// <param name="targetGuid">The target component identifier.</param>
        /// <returns>The identifier of the new connector.</returns>
        public Guid AddConnector(DrawingSurfaceModel diagram, Guid sourceGuid, Guid targetGuid)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            (int sourceCenterX, int sourceCenterY) = DiagramGeometry.CenterOf(diagram, sourceGuid);
            (int targetCenterX, int targetCenterY) = DiagramGeometry.CenterOf(diagram, targetGuid);
            (int sourceX, int sourceY) = DiagramGeometry.EdgePoint(diagram, sourceGuid, targetCenterX, targetCenterY);
            (int targetX, int targetY) = DiagramGeometry.EdgePoint(diagram, targetGuid, sourceCenterX, sourceCenterY);

            Connector connector = new Connector
            {
                Guid = Guid.NewGuid(),
                TypeId = DataFlowTypeId,
                GenericTypeId = DataFlowTypeId,
                SourceGuid = sourceGuid,
                TargetGuid = targetGuid,
                SourceX = sourceX,
                SourceY = sourceY,
                TargetX = targetX,
                TargetY = targetY,
                HandleX = (sourceX + targetX) / 2,
                HandleY = (sourceY + targetY) / 2,
            };

            connector.Properties.Add(new HeaderDisplayAttribute { DisplayName = "Generic Data Flow" });
            diagram.Lines[connector.Guid] = connector;
            DiagramElementHelper.SetName(connector, "Data Flow");
            return connector.Guid;
        }

        /// <summary>
        /// Sets the bounding box of a component or boundary, clamping width and height to a minimum.
        /// This is a raw mutation: call <see cref="BeginChange"/> once at the start of the gesture.
        /// </summary>
        /// <param name="diagram">The diagram containing the element.</param>
        /// <param name="guid">The element identifier.</param>
        /// <param name="left">The new left coordinate.</param>
        /// <param name="top">The new top coordinate.</param>
        /// <param name="width">The new width.</param>
        /// <param name="height">The new height.</param>
        public void ResizeElement(DrawingSurfaceModel diagram, Guid guid, int left, int top, int width, int height)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Borders.TryGetValue(guid, out object? value) && value is DrawingElement element)
            {
                element.Left = left;
                element.Top = top;
                element.Width = Math.Max(MinimumSize, width);
                element.Height = Math.Max(MinimumSize, height);
            }
        }

        /// <summary>
        /// Sets the curve handle (bend point) of a connector or line. This is a raw mutation: call
        /// <see cref="BeginChange"/> once at the start of the gesture.
        /// </summary>
        /// <param name="diagram">The diagram containing the line.</param>
        /// <param name="guid">The line identifier.</param>
        /// <param name="handleX">The handle x coordinate.</param>
        /// <param name="handleY">The handle y coordinate.</param>
        public void SetLineHandle(DrawingSurfaceModel diagram, Guid guid, int handleX, int handleY)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Lines.TryGetValue(guid, out object? value) && value is LineElement line)
            {
                line.HandleX = handleX;
                line.HandleY = handleY;
            }
        }

        /// <summary>
        /// Sets the position and attached element of a connector's source or target endpoint. This
        /// is a raw mutation: call <see cref="BeginChange"/> once at the start of the gesture.
        /// </summary>
        /// <param name="diagram">The diagram containing the connector.</param>
        /// <param name="guid">The connector identifier.</param>
        /// <param name="isSource">Whether to set the source endpoint (otherwise the target).</param>
        /// <param name="x">The endpoint x coordinate.</param>
        /// <param name="y">The endpoint y coordinate.</param>
        /// <param name="attachedGuid">The element the endpoint attaches to, or <see cref="Guid.Empty"/> to detach.</param>
        public void SetLineEndpoint(DrawingSurfaceModel diagram, Guid guid, bool isSource, int x, int y, Guid attachedGuid)
        {
            if (diagram == null)
            {
                throw new ArgumentNullException(nameof(diagram));
            }

            if (diagram.Lines.TryGetValue(guid, out object? value) && value is LineElement line)
            {
                bool wasStraight = IsHandleAtMidpoint(line);
                if (isSource)
                {
                    line.SourceX = x;
                    line.SourceY = y;
                    line.SourceGuid = attachedGuid;
                }
                else
                {
                    line.TargetX = x;
                    line.TargetY = y;
                    line.TargetGuid = attachedGuid;
                }

                if (wasStraight)
                {
                    line.HandleX = (line.SourceX + line.TargetX) / 2;
                    line.HandleY = (line.SourceY + line.TargetY) / 2;
                }
            }
        }

        /// <summary>
        /// Reverts to the most recent undo checkpoint.
        /// </summary>
        public void Undo()
        {
            if (this.undoStack.Count == 0)
            {
                return;
            }

            Push(this.redoStack, this.Model);
            this.Model = Pop(this.undoStack);
        }

        /// <summary>
        /// Re-applies the most recently undone change.
        /// </summary>
        public void Redo()
        {
            if (this.redoStack.Count == 0)
            {
                return;
            }

            Push(this.undoStack, this.Model);
            this.Model = Pop(this.redoStack);
        }

        /// <summary>
        /// Serializes the current model to the lossless TM7 byte representation.
        /// </summary>
        /// <returns>The serialized model.</returns>
        public byte[] ToBytes()
        {
            return Serialize(this.Model);
        }

        private static void MoveAttachedConnectors(DrawingSurfaceModel diagram, Guid nodeGuid, int deltaX, int deltaY)
        {
            foreach (object value in diagram.Lines.Values)
            {
                if (!(value is LineElement line))
                {
                    continue;
                }

                bool sourceMoved = line.SourceGuid == nodeGuid;
                bool targetMoved = line.TargetGuid == nodeGuid;
                if (!sourceMoved && !targetMoved)
                {
                    continue;
                }

                bool wasStraight = IsHandleAtMidpoint(line);
                if (sourceMoved)
                {
                    line.SourceX += deltaX;
                    line.SourceY += deltaY;
                }

                if (targetMoved)
                {
                    line.TargetX += deltaX;
                    line.TargetY += deltaY;
                }

                if (wasStraight)
                {
                    line.HandleX = (line.SourceX + line.TargetX) / 2;
                    line.HandleY = (line.SourceY + line.TargetY) / 2;
                }
            }
        }

        private static bool IsHandleAtMidpoint(LineElement line) => line.HandleIsAtMidpoint;

        private static DrawingElement CreateStencil(StencilKind kind)
        {
            switch (kind)
            {
                case StencilKind.Process:
                    return NewStencil(new StencilEllipse { Width = 100, Height = 60 }, ProcessTypeId, "Generic Process");
                case StencilKind.ExternalEntity:
                    return NewStencil(new StencilRectangle { Width = 120, Height = 60 }, ExternalEntityTypeId, "Generic External Interactor");
                case StencilKind.DataStore:
                    return NewStencil(new StencilParallelLines { Width = 120, Height = 50 }, DataStoreTypeId, "Generic Data Store");
                case StencilKind.TrustBoundary:
                    return NewStencil(new BorderBoundary { Width = 220, Height = 160 }, TrustBoundaryTypeId, "Generic Trust Boundary");
                default:
                    throw new ArgumentOutOfRangeException(nameof(kind));
            }
        }

        private static DrawingElement NewStencil(DrawingElement element, string typeId, string headerName)
        {
            // A generic element carries GenericTypeId == TypeId. The analysis classifies elements by
            // GenericTypeId (ThreatModelForge.Analysis.Extensions), and the header carries the
            // human-readable type shown in findings, so both must be set for authored elements to be
            // recognized (e.g. as external interactors) rather than "of unknown type".
            element.TypeId = typeId;
            element.GenericTypeId = typeId;
            element.Properties.Add(new HeaderDisplayAttribute { DisplayName = headerName });
            return element;
        }

        private static string DefaultName(StencilKind kind)
        {
            switch (kind)
            {
                case StencilKind.Process:
                    return "Process";
                case StencilKind.ExternalEntity:
                    return "External Entity";
                case StencilKind.DataStore:
                    return "Data Store";
                case StencilKind.TrustBoundary:
                    return "Trust Boundary";
                default:
                    return "Element";
            }
        }

        private static void Push(List<byte[]> stack, ThreatModel model)
        {
            stack.Add(Serialize(model));
            if (stack.Count > MaxHistory)
            {
                stack.RemoveAt(0);
            }
        }

        private static ThreatModel Pop(List<byte[]> stack)
        {
            byte[] state = stack[stack.Count - 1];
            stack.RemoveAt(stack.Count - 1);
            return Deserialize(state);
        }

        private static byte[] Serialize(ThreatModel model)
        {
            using (MemoryStream stream = new MemoryStream())
            {
                model.Save(stream);
                return stream.ToArray();
            }
        }

        private static ThreatModel Deserialize(byte[] state)
        {
            using (MemoryStream stream = new MemoryStream(state))
            {
                return ThreatModel.Load(stream);
            }
        }
    }
}
