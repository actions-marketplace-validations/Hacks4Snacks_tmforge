# ThreatModelForge.Core

Core library for **Threat Model Forge**, the cross-platform toolkit for authoring
`.tm7`-compatible threat models.

This package provides the in-memory threat-model object graph and native serialization:

- **Model** (`ThreatModelForge.Model`): the `ThreatModel` graph (diagrams, elements, connectors,
  boundaries, threats, and metadata).
- **Knowledge base** (`ThreatModelForge.KnowledgeBase`): template/knowledge-base types and the
  `.tb7` serializer.
- **Abstractions** (`ThreatModelForge.Abstractions`): shared serialization contracts.

It reads and writes the Microsoft Threat Modeling Tool's `.tm7`/`.tb7` wire format via
`DataContractSerializer`, with byte-stable fixture coverage. On-disk names are pinned independently
of CLR namespaces. The engine's preserving native-save operation additionally retains original XML;
arbitrary edits and structural conversions are not byte-identical round-trips. See
[format fidelity](../../docs/formats.md#fidelity).

Higher-level capabilities live in companion packages: `ThreatModelForge.Formats` (pluggable format
providers), `ThreatModelForge.Analysis` (validation/linting), `ThreatModelForge.Reporting`
(HTML/SVG reports), and `ThreatModelForge.Editing` (UI-agnostic editing).

Licensed under the MIT License.
