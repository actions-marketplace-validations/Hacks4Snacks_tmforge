# ThreatModelForge.Formats

A pluggable format layer for reading and writing threat models. Consumers (CLIs, the web app,
generation) depend on this instead of calling `ThreatModel.Load`/`Save` directly, so new
formats plug in by implementing `IThreatModelFormat` and registering with
`ThreatModelFormatRegistry`.

The canonical in-memory model stays the `.tm7`-shaped `ThreatModelForge.Model.ThreatModel`.
`Tm7Format` is the first provider and wraps the byte-stable `.tm7` round-trip. Other formats map
to and from the canonical model and declare their fidelity through `FormatCapabilities`.

Readers and writers include canonical JSON, draw.io, Visio, and bounded Threat Dragon v2.
Threat Dragon export preserves imported identities and authored threats and refuses unsupported
content before writing. Mermaid and DOT remain import-only. See
[format capabilities and operation-specific fidelity](../../docs/formats.md).
Preserving native XML edits live in the engine's `SaveTm7` operation, not a structural format conversion.
