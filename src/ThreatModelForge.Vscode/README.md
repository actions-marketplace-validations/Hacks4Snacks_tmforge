# Threat Model Forge for VS Code

View threat-model diagrams, review security findings, and edit model files without leaving VS Code.

## Get Started

1. Install **Threat Model Forge** by **hacks4snacks** from VS Code's Extensions view (`hacks4snacks.tmforge`).
2. Open a `.tm7` or `.tmforge.json` file to edit it in Studio.
3. Run **Threat Model Forge: New Model** to start a JSON model, or use **Open File** to open an existing model.

For offline installation, download the VSIX from the
[GitHub release](https://github.com/Hacks4Snacks/tmforge/releases) and run
**Extensions: Install from VSIX...** in the Command Palette. Reload the window after updating.

Use **Threat Model Forge: Open Studio** or **Reopen Editor With** to switch a model from the
text editor to Studio.

## Create with Copilot

With GitHub Copilot Chat enabled, use the normal **Agent** mode and invoke the bundled **tmforge-vscode** skill:

> /tmforge-vscode Create a draft threat model for this service. Use the current implementation as evidence and keep unknown controls explicit.

Copilot can also load the skill automatically when a request matches its description. There is no
separate Tmforge agent to select.

The agent queries the bundled schema and catalogs, creates a new unsaved JSON model,
opens it in Studio, and reads it back for analysis. New drafts appear in an **Untitled** tab without
an associated filesystem path. Review the diagram and findings, then use **Save** to choose a
location and a filename ending in `.tmforge.json`.

For updates, open a model and ask the agent to inspect or change it. Updates use the current document,
including unsaved changes, and are undoable. A revision check refuses edits based on stale content.
Native TM7 changes use the same source-preserving engine path as Studio. The tools do not explicitly
save files; VS Code's **Auto Save** setting still applies. Deleting objects can remove their dependent
threats and decisions, just as in Studio.

The four tools are available to Copilot's general agent: `#tmforgeCatalog`, `#tmforgeCreateModel`,
`#tmforgeInspectModel`, and `#tmforgeUpdateModel`. Inspection and updates only access already-open
model documents. Chat results are limited to 1 MiB; larger models remain available in Studio.

The skill instructs Copilot to use tmforge tools for model changes, but does not restrict the current
agent's available tools. Validation and revision checks apply to tmforge tool calls; generic file
edits can bypass them.

Set `tmforge.copilot.enabled` to `false` to disable these contributions. Studio and local analysis
continue to work without Copilot. If the skill is missing, check that Copilot Chat and agent mode are
available under your organization's policy, the workspace is trusted, and the integration is enabled.

## Review Findings

VS Code's **Problems** panel updates when you open or save a model. Choose **Analyze** in Studio to
review threats, select affected elements, and record triage on the current model.

After editing, save the file to refresh findings. To check unsaved changes, run
**Threat Model Forge: Analyze Model** from the Command Palette or choose **Analyze** in Studio.

Findings are attached to the model file rather than specific source lines. Rule and element IDs
help you identify the affected parts of the model.

## Edit Model Files

Studio supports stencil-based drawing, connections, properties, multiple pages, layout, analysis,
threat triage, comparison, and reports. See the
[Studio guide](https://github.com/Hacks4Snacks/tmforge/blob/HEAD/docs/studio-guide.md) for the editing controls.

Use VS Code's normal **Save**, **Save As**, **Undo**, and **Redo** commands. Canvas edits mark the
document as unsaved; opening or analyzing it does not change the file. **Open source** switches
to text editing. Source edits and changes in another editor update the canvas. Invalid source pauses
visual editing until the XML or JSON is corrected.

**Open File** opens `.tm7` and JSON models directly. Importing another format creates a separate
unsaved `.tmforge.json` model after conversion review, leaving the original untouched. **Export** and
**Report** let you choose a destination for a separate file. URL sharing is not supported in the extension.

## Native TM7 Files

Editing a `.tm7` keeps it in its original format. Saves preserve unrelated native content, including
the embedded template and existing threat data. New edits extend the template when needed. Deleting
an element, flow, or page also removes its dependent threats and decisions; **Undo** restores them.

Opening a native file or saving without changes leaves its bytes unchanged. Edited saves may change
XML formatting. Exporting a native `.tm7` copy retains the current document, including unsaved edits;
exporting to JSON or another format shows any conversion warnings.

Native line trust boundaries are retained but are not drawn on the Studio canvas. Models containing
them show a warning because canvas analysis may omit their crossings. Deleting a page removes its
hidden objects as well.

If opening a TM7 reports only unattached or cross-page flow endpoints, **Review recovery import**
offers **Import recovery copy**. The listed broken flows and their scoped threats are omitted from
a separate, unsaved JSON draft. The original TM7 stays unchanged; use **Save** to choose a new
`.tmforge.json` destination. The copy does not retain native-only data such as the embedded template
or full generated register. Review the warnings and the original before relying on its analysis.
Malformed XML, duplicate identities and input limits cannot be overridden.

## JSON Editing

JSON completion and structural validation are available for:

- Model manifests: `*.manifest.json` and `*.tm.json`.
- Rule packs: `*.tmrules.json`.
- Suppression files: `*.suppressions.json`.

Version 2 rule packs have full schema validation; older rule-only files have basic structural hints.
These editing hints do not run custom rules or apply suppressions to a model.

## Supported Workflows

Use desktop VS Code 1.138 or later in a trusted workspace, including remote development workspaces.
Browser-only VS Code and virtual workspaces are not supported.

Studio analysis uses tmforge's built-in rules and respects the model's disabled-rule selections.
In Studio, **Analysis Rules** can load a custom JSON rule pack for the current document session.
Reload that pack after restarting VS Code; packs are not automatically read from the workspace.
A model that expects an unavailable pack reports an error. Suppression files are not applied by
the extension; use the tmforge CLI for suppression workflows.

Models can contain up to 32 pages, 1,024 elements, and 2,048 diagram lines, with a maximum file size
of 8 MiB. More complex models may exceed processing limits. Analysis requests time out after
30 seconds; choose **Analyze** to retry.

## Privacy

Analysis runs on your computer or, when using remote development, on your remote host. The extension
does not send model contents to a separate analysis service.

When using Copilot, repository evidence, model content returned by tools, and findings become part
of the Copilot conversation and follow its data-handling policies. Local engine execution does not
make a Copilot conversation offline or prevent that context from reaching your selected model provider.
Use only material you are authorized to share. The extension does not make model-provider requests
itself, install software, or change Copilot's approval settings.

## Support

Report problems or request improvements in
[GitHub Issues](https://github.com/Hacks4Snacks/tmforge/issues). Include the extension version,
VS Code version, operating system, and the error message. Use a minimal, sanitized model when a
reproduction is needed; do not attach confidential architecture or credentials.
