# Installation

Threat Model Forge ships through several channels. Pick the one that fits your environment.

> **Nothing to install?** Try the live browser demo at
> **[hacks4snacks.github.io/tmforge](https://hacks4snacks.github.io/tmforge/)**: the full engine
> runs client-side via WebAssembly, with no CLI or Docker installation. The browser downloads the app and runtime.

| Channel | Runtime needed on host? | Best for |
| --- | --- | --- |
| [Prebuilt binaries](#prebuilt-binaries) | No (self-contained) | Laptops, CI runners, agents |
| [Container: CLI](#container-cli) | Docker only | CI, reproducible shells |
| [Container: API + Studio](#container-api--studio) | Docker only | Hosting the browser app |
| [VS Code extension](../src/ThreatModelForge.Vscode/README.md) | Desktop VS Code 1.103+ | Editing native and JSON models alongside code |
| [.NET global tool](#net-global-tool) | .NET SDK/runtime | .NET developers |
| [From source](#from-source) | .NET SDK 10.0.301; Node.js 22.12+ for Studio | Contributors |

## Prebuilt binaries

**Self-contained, single-file** `tmforge` binaries (**no .NET runtime required on the host**)
are attached to each GitHub Release for six platforms:

| OS | x64 | arm64 |
| --- | --- | --- |
| Linux | `tmforge-<ver>-linux-x64.tar.gz` | `tmforge-<ver>-linux-arm64.tar.gz` |
| macOS | `tmforge-<ver>-osx-x64.tar.gz` | `tmforge-<ver>-osx-arm64.tar.gz` |
| Windows | `tmforge-<ver>-win-x64.zip` | `tmforge-<ver>-win-arm64.zip` |

### Linux / macOS

```bash
# Select a released version and the RID for your platform.
version=0.12.0
rid=linux-x64                     # use osx-arm64 or osx-x64 on macOS
archive="tmforge-${version}-${rid}.tar.gz"
base="https://github.com/hacks4snacks/tmforge/releases/download/v${version}"
curl -fsSLO "$base/$archive"
curl -fsSLO "$base/checksums.txt"
```

[Verify the download](#verify-the-download) before extracting or running it, then:

```bash
tar -xzf "$archive"
"./tmforge-${version}-${rid}/tmforge" --version
```

After verifying the download, move the binary to a directory on your `PATH`, such as `~/.local/bin/`.

### Windows (PowerShell)

```powershell
$version = "0.12.0"
$rid = "win-x64"                 # use win-arm64 on Windows ARM64
$archive = "tmforge-$version-$rid.zip"
$base = "https://github.com/hacks4snacks/tmforge/releases/download/v$version"
Invoke-WebRequest "$base/$archive" -OutFile $archive
Invoke-WebRequest "$base/checksums.txt" -OutFile checksums.txt
```

[Verify the download](#verify-the-download) before continuing:

```powershell
Expand-Archive $archive -DestinationPath tmforge
& ".\tmforge\tmforge-$version-$rid\tmforge.exe" --version
```

### Verify the download

Before extracting or running an archive, download `checksums.txt` from the **same release** and
compare the entry for that archive. Keep its published filename for automated verification:

```bash
# Run in the download directory with the archive variable from above.
grep -F "  $archive" checksums.txt | sha256sum -c -
```

On macOS, use `shasum -a 256 -c -` instead of `sha256sum -c -`. On Windows, compare
`(Get-FileHash $archive -Algorithm SHA256).Hash` with the archive's entry in `checksums.txt`.
Do not continue after a mismatch or a missing checksum entry.
Checksums detect changed downloads; they do not authenticate a compromised release publisher.
`release-metadata.json` records CLI archive hashes, sizes, version, tag, and commit. Stable releases
also attach the extension VSIX, whose hash is included in `checksums.txt`.

### Platform notes

- **Linux** binaries target a **glibc** baseline, not musl/Alpine. On Alpine, use the
  [container image](#container-cli) instead.
- **macOS** binaries are **not code-signed or notarized**. If Gatekeeper blocks a downloaded binary,
  verify its source and checksum first, then follow your organization's approval process. For a
  trusted binary where removing quarantine is explicitly permitted, the exception is per file:

  ```bash
  xattr -d com.apple.quarantine ./tmforge
  ```

## Container: CLI

Run the published image (pulls automatically on first use):

```bash
docker run --rm -v "$PWD:/work" ghcr.io/hacks4snacks/tmforge-cli analyze model.tm7
```

Or build it from source:

```bash
docker build -f build/Dockerfile -t tmforge-cli .
docker run --rm -v "$PWD:/work" tmforge-cli analyze model.tm7
```

The working directory is mounted at `/work`, so paths in your commands are relative to it.
The image entrypoint is `tmforge`; pass its subcommand directly. Published tags include `latest`,
the release version (e.g. `0.12.0`), `0.12`, and `edge`.

## Container: API + Studio

The engine API and the Studio SPA ship as one image. Run the published image:

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/hacks4snacks/tmforge  # http://localhost:8080/
```

Or build it from source:

```bash
docker build -f build/Dockerfile.api -t tmforge .
docker run --rm -p 127.0.0.1:8080:8080 tmforge  # http://localhost:8080/
```

Open `http://localhost:8080/` for Studio; the API is under `/v1`. See the
[deployment guide](deployment.md#security-posture) before shared hosting: the API is unauthenticated
and the operator must supply its access boundary.

## .NET global tool

The global tool is a source-build option, not an automated NuGet publication channel. With the
.NET SDK installed, pack the RID-agnostic tool locally:

```bash
dotnet pack src/ThreatModelForge.Cli -p:PackTools=true -o ./nupkg
dotnet tool install --global --add-source ./nupkg ThreatModelForge.Cli.PreRelease
tmforge --version
```

This path needs .NET present on the host (that's the trade-off vs. the self-contained binaries).

## From source

Requires the .NET SDK pinned in [`global.json`](../global.json) (10.0.301), plus Node.js 22.12+ and
npm for the default build, which includes Studio.

```bash
git clone https://github.com/Hacks4Snacks/tmforge.git
cd tmforge
dotnet build dirs.proj
dotnet test  dirs.proj --no-build

# Run the CLI without installing:
dotnet run --project src/ThreatModelForge.Cli -- --version

# Run the API + Studio locally:
dotnet run --project src/ThreatModelForge.Api -- --urls http://localhost:5205
```

Building `dirs.proj` builds the API **and** the Studio SPA into one hosted artifact. For .NET-only
iteration, pass `-p:BuildStudio=false`; the WASM engine and VSIX have separate opt-in builds. To work on
Studio with hot reload, see the [Studio guide](studio-guide.md#local-development).

## Next steps

- [Quick start](quickstart.md): your first model.
- [CLI reference](cli-reference.md): all commands and options.
- [Deployment](deployment.md): hosting the API + Studio.
