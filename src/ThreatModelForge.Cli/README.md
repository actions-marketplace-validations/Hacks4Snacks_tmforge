# ThreatModelForge.Cli (`tmforge`)

The `tmforge` command-line tool: inspect, author, analyze, report on, and convert
`.tm7`-compatible threat models from a shell or CI pipeline. It is the headless, scriptable
face of the same engine the Studio UI uses, so agents and pipelines can drive threat models
without a GUI.

Model commands support `--json` for machine-readable output, and options take either
`--name value` or `--name=value`. Run `tmforge <command> --help` for command-specific options.
Help/version and git setup are text; the MCP server uses JSON-RPC over stdio.

## Common Commands

The [CLI reference](../../docs/cli-reference.md) covers the full command set, including preflight,
pages, layout, diff/merge, manifests, threat authoring, analysis documents, and MCP tools/resources.

### Inspect (read-only)

| Command | Purpose |
| --- | --- |
| `tmforge open [--json] <input>` | Summarize a model: counts of elements, flows, and threats. |
| `tmforge list <components\|flows\|boundaries\|threats\|diagrams> [--json] <input>` | List entities of the chosen kind. |
| `tmforge show --id <guid> [--json] <input>` | Show one element/flow: name, type, and custom properties. |
| `tmforge render [--plain] [--width <n>] [--height <n>] <file>` | Draw the diagram in the terminal (Unicode/ANSI; `--plain` for ASCII). |

### Discover (authoring aids)

| Command | Purpose |
| --- | --- |
| `tmforge stencils [--pack <id>] [--json]` | List the built-in stencils (ids for `add --stencil`). |
| `tmforge properties [--base <id>] [--json]` | List the typed custom-property schema the linter reads. |

### Author (mutating)

| Command | Purpose |
| --- | --- |
| `tmforge new [--name <title>] [--template <file>] [--format <id>] [--json] <file>` | Create a new model (empty or from a template). |
| `tmforge add <kind> [options] <file>` or `tmforge add --stencil <id> [options] <file>` | Add a generic process/store/external/boundary or a typed stencil; select another page with `--page`. Kind and stencil are alternatives. |
| `tmforge connect --source <guid> --target <guid> [--name <name>] [--property KEY=VALUE ...] [--json] <file>` | Add a data flow between two elements. |
| `tmforge set --id <guid> [--name <name>] [--property KEY=VALUE ...] [--json] <file>` | Set an element/flow's name and/or custom properties. |
| `tmforge remove --id <guid> [--json] <file>` | Remove an element (and its connected flows). |
| `tmforge rename --id <guid> --name <name> [--json] <file>` | Rename an element. |

### Analyze, report & convert

| Command | Purpose |
| --- | --- |
| `tmforge analyze [--ruleset <path>] [--suppressionFile <path>] [--reportFolder <dir>] [--define name=value ...] [--json] <model>` | Evaluate the analysis rules against the model. `--reportFolder` also emits SARIF + HTML findings reports. |
| `tmforge report [--format <html\|svg>] [--out <path>] [--json] <model>` | Generate a self-contained HTML threat report (enabled rule-backed + manual threats and triage), or a standalone SVG diagram. |
| `tmforge convert [--to <format>] [--out <path>] [--json] <input>` | Convert between formats (`tm7`, `tmforge-json`, `drawio`, `vsdx`). |

`analyze` exit codes: `0` = no findings at the selected threshold, `1` = tool error,
`2` = findings at or above `--max-severity` (default `error`; also accepts `warning` or `info`).
Lower-severity findings may still be present when the command exits `0`.

## Run

```bash
# From source
dotnet run --project src/ThreatModelForge.Cli -- analyze model.tm7 --json

# From the published container image (pulls on first run)
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli analyze model.tm7

# ...or build the image from source (see build/Dockerfile)
docker build -f build/Dockerfile -t tmforge-cli .
docker run --rm -v "$PWD:/work" tmforge-cli analyze model.tm7
```

## Examples

```bash
tmforge new payments.tm7 --name "Payments"
tmforge add process payments.tm7 --name "Checkout API"
tmforge stencils
tmforge list components payments.tm7 --json
tmforge show payments.tm7 --id <guid>
tmforge set payments.tm7 --id <flow-guid> --property Protocol=HTTPS --property Port=443
tmforge render payments.tm7 --plain
tmforge report payments.tm7 --out payments.html
tmforge convert payments.tm7 --to drawio --out payments.drawio
```

Prebuilt, self-contained `tmforge` binaries (no .NET runtime required) are attached to each
GitHub Release for six platforms; container images and the RID-agnostic global tool are also
available. See the [installation guide](../../docs/installation.md).
