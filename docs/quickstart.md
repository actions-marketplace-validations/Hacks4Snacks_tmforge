# Quick start

This guide takes you from nothing to a validated, reported threat model in a few minutes using
the `tmforge` CLI, then shows the same flow in the browser with Studio.

> **Just want to click around first?** Try the live, no-install browser demo at
> **[hacks4snacks.github.io/tmforge](https://hacks4snacks.github.io/tmforge/)**. The full engine
> runs client-side via WebAssembly, so there's nothing to install and your model never leaves the page.

## Prerequisites

Pick one:

- A prebuilt `tmforge` binary (no .NET runtime needed). See [Installation](installation.md).
- The published CLI container image, which needs Docker.
- The source tree, which needs the .NET SDK pinned in `global.json` (10.0.301).

The examples below assume `tmforge` is on your `PATH`. From a container, replace `tmforge` with
`docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli`. The image already supplies the
executable as its entrypoint. From source, replace `tmforge` with
`dotnet run --project src/ThreatModelForge.Cli --`.

Verify your install:

```bash
tmforge --version
```

## 1. Create a model

```bash
tmforge new payments.tm7 --name "Payments"
```

This writes an empty `.tm7` model titled "Payments". You can also start from another format (for
example `tmforge new payments.tmforge.json --format tmforge-json`) or from a template file with
`--template`.

## 2. Add elements

Add a process, an external entity, a data store, and a trust boundary. Each `add` prints the new
element's **GUID**, which you'll use to connect things.

```bash
tmforge add external payments.tm7 --name "Customer"
tmforge add process  payments.tm7 --name "Checkout API"
tmforge add store    payments.tm7 --name "Orders DB"
tmforge add boundary payments.tm7 --name "Azure VNet"
```

Prefer typed elements from the stencil catalog? List available stencils and use one:

```bash
tmforge stencils
tmforge add payments.tm7 --stencil azure-app-service --name "Checkout API"
```

Coordinates are auto-laid-out deterministically; override with `--left` / `--top` if you want
explicit placement.

## 3. Connect elements with data flows

Grab the GUIDs (from step 2's output, or list them), then connect. `connect` takes `--source` and
`--target` GUIDs:

```bash
tmforge list components payments.tm7          # find the GUIDs
tmforge connect payments.tm7 \
  --source <customer-guid> --target <checkout-guid> \
  --name "Place order" \
  --property Protocol=HTTPS --property Port=443
```

`--property KEY=VALUE` (repeatable) stamps the rule-checked custom properties (`Protocol`,
`Port`, `DataType`, `AuthenticationScheme`, and so on) that validation inspects.

## 4. Inspect it

```bash
tmforge open payments.tm7                 # summary: element / flow / threat counts
tmforge list flows payments.tm7           # enumerate the data flows
tmforge render payments.tm7 --plain       # draw the diagram in the terminal (ASCII)
```

Add `--json` to supported model commands for machine-readable output; help/version and terminal
rendering are text, while MCP uses JSON-RPC. See [JSON output](cli-reference.md#json-output).

## 5. Validate

```bash
tmforge analyze payments.tm7
```

`analyze` evaluates the built-in rule set and reports findings. Its exit code is meaningful:

| Exit code | Meaning |
| --- | --- |
| `0` | No findings at or above the selected severity threshold; lower-severity findings can still be present |
| `1` | Tool error (bad arguments, load failure) |
| `2` | Findings meet or exceed the selected threshold (`error` by default) |

Use `--max-severity warning` to gate on warnings as well as errors, or `info` for all finding levels.
That lets CI **fail on findings** while distinguishing them from a broken invocation. To also emit
SARIF + HTML reports:

```bash
tmforge analyze payments.tm7 --reportFolder ./findings
```

See [Analysis rules & CI](analysis-rules.md) for the full rule list, suppressions, and gating.

## 6. Report

Produce a self-contained HTML report (inline SVG diagram, no external assets):

```bash
tmforge report payments.tm7 --out payments.html
```

Open `payments.html` in any browser, or attach it to a pull request or review.

## 7. Convert (optional)

Export to another format for interoperability:

```bash
tmforge convert payments.tm7 --to drawio --out payments.drawio
tmforge convert payments.tm7 --to vsdx   --out payments.vsdx
```

See [Formats & interoperability](formats.md) for fidelity details.

## Do the same in the browser

Prefer a GUI? The quickest option is the hosted
**[browser demo](https://hacks4snacks.github.io/tmforge/)**: nothing to install, the engine runs
in your browser via WebAssembly. To run it yourself, start the engine API (which serves Studio)
and author visually:

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hacks4snacks/tmforge  # http://localhost:8080/
```

In Studio you can drag stencils, draw flows, edit flow properties in the inspector, click
**Analyze** to see findings overlaid on the diagram, and **Export tmforge-json** to round-trip
through the CLI. See the [Studio guide](studio-guide.md).

For local editing in VS Code, install the [extension](../src/ThreatModelForge.Vscode/README.md) and
open the model directly. Self-hosted shared APIs need an authenticated ingress; see the
[security posture](deployment.md#security-posture).

## A minimal CI gate

```bash
# Exit 2 if findings at or above --max-severity are reported (default: error-severity only);
# exit 1 on tool errors. Use --max-severity warning to also gate a build on warnings.
tmforge analyze payments.tm7 --max-severity warning --reportFolder "$CI_ARTIFACTS/threatmodel"
```

Full pipeline examples are in the [deployment guide](deployment.md#cicd).

## Where to go next

- [CLI reference](cli-reference.md): every command and option.
- [Overview & features](overview.md): concepts and the bigger picture.
- [Studio guide](studio-guide.md): browser authoring in depth.
