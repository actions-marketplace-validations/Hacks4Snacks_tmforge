import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const execute = promisify(execFile);
const sharedBuildFiles = new Set(['Directory.Build.props', 'Directory.Packages.props', 'global.json', 'NuGet.config']);

export function affectsExtension(path) {
  return /^src\/ThreatModelForge\.(?:Vscode|Studio|Wasm|Engine|Core|Editing|Formats|Analysis(?:\.Rules|\.Reporting)?|Reporting)\//.test(path)
    || sharedBuildFiles.has(path);
}

export async function extensionChangelog(changelog, expectedVersion, filesForCommit) {
  changelog = changelog.replace(/\r\n/g, '\n');
  const heading = /^##[ \t]+(.+)$/m.exec(changelog)?.[1].trim();
  const release = /^(?:\[(\d+\.\d+\.\d+)\](?:\([^)]*\))?|(\d+\.\d+\.\d+))(?:\s|$)/.exec(heading ?? '');
  const version = release?.[1] ?? release?.[2];
  if (version !== expectedVersion) {
    throw new Error(`The root changelog must start with release ${expectedVersion}; found ${heading ?? 'no release heading'}. Update the release-please release notes before packaging.`);
  }
  const relevantCommits = new Map();
  const output = ['# Changelog', 'Changes to the VS Code extension and its bundled Studio and engine components.'];
  const releases = changelog.split(/(?=^##[ \t]+)/m).slice(1);
  for (const [index, section] of releases.entries()) {
    const [title, ...body] = section.trimEnd().split('\n');
    const selected = [];
    let category = '';
    let emittedCategory = '';
    const blocks = body.join('\n').split(/(?=^###?[ \t]|^[*-][ \t])/m);
    for (const block of blocks) {
      const entry = block.trim();
      if (!entry) continue;
      if (/^###?[ \t]/.test(entry)) { category = entry; continue; }
      const commits = [...entry.matchAll(/\]\(https:\/\/github\.com\/Hacks4Snacks\/tmforge\/commit\/([a-f\d]{7,40})\)/gi)].map(match => match[1]);
      if (!/^[*-][ \t]/.test(entry) || commits.length === 0) {
        throw new Error(`Cannot scope release note without a tmforge commit link: ${entry.split('\n')[0]}`);
      }
      let relevant = false;
      for (const commit of commits) {
        if (!relevantCommits.has(commit)) {
          relevantCommits.set(commit, (await filesForCommit(commit)).some(affectsExtension));
        }
        relevant ||= relevantCommits.get(commit);
      }
      if (!relevant) continue;
      if (category && category !== emittedCategory) {
        selected.push(category);
        emittedCategory = category;
      }
      selected.push(entry);
    }
    if (selected.length) output.push(title, ...selected);
    else if (index === 0) output.push(title, 'No extension-related changes in this release.');
  }
  return output.join('\n\n') + '\n';
}

export async function stageChangelog(extensionRoot = root) {
  const repository = resolve(extensionRoot, '../..');
  const manifest = JSON.parse(await readFile(resolve(extensionRoot, 'package.json'), 'utf8'));
  const source = await readFile(resolve(repository, 'CHANGELOG.md'), 'utf8');
  const { stdout: shallow } = await execute('git', ['rev-parse', '--is-shallow-repository'], { cwd: repository });
  if (shallow.trim() !== 'false') {
    throw new Error('Extension changelog generation needs complete Git history. Use actions/checkout fetch-depth: 0 or git fetch --unshallow.');
  }
  const changelog = await extensionChangelog(source, manifest.version, async commit => {
    try {
      const { stdout } = await execute('git', ['diff-tree', '--root', '--no-commit-id', '--name-only', '--no-renames', '--first-parent', '-m', '-r', '-z', commit, '--'], { cwd: repository });
      return stdout.split('\0').filter(Boolean);
    } catch (error) {
      throw new Error(`Cannot scope extension notes for commit ${commit}. Fetch complete Git history (actions/checkout fetch-depth: 0) before packaging.`, { cause: error });
    }
  });
  await mkdir(resolve(extensionRoot, 'out'), { recursive: true });
  await writeFile(resolve(extensionRoot, 'out/CHANGELOG.md'), changelog);
}

async function checkPackage() {
  const manifest = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  for (const path of [manifest.main, 'out/engine-worker.mjs', 'engine/package.json', 'engine/_framework/dotnet.js', 'engine/_framework/dotnet.native.wasm', 'engine/_framework/ThreatModelForge.Wasm.wasm', 'engine/_framework/ThreatModelForge.Engine.wasm', 'media/studio/studio.js', 'media/studio/studio.css', 'schemas/tmforge-rules-v2.schema.json', 'LICENSE.md', 'NOTICE', ...manifest.contributes.jsonValidation.map(entry => entry.url), ...manifest.contributes.chatSkills.map(entry => entry.path)]) {
    await access(resolve(root, path));
  }
  if (manifest.dependencies && Object.keys(manifest.dependencies).length) throw new Error('Runtime dependencies require explicit VSIX packaging support.');
  if (/process\.env/.test(await readFile(resolve(root, 'media/studio/studio.js'), 'utf8'))) throw new Error('Studio must be bundled for the browser, without Node globals.');
  await stageChangelog();
  console.log('VSIX inputs verified; bundled WASM, Studio, Copilot resources, and version-matched extension release notes are present.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await checkPackage();
}
