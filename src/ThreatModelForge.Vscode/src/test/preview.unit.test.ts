import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { studioHtml } from '../preview';

test('Studio replaces preview commands and is the sole default editor for both formats', () => {
  const manifest = JSON.parse(readFileSync(resolve(__dirname, '../../package.json'), 'utf8')) as {
    contributes: { customEditors: { viewType: string; priority: string; selector: { filenamePattern: string }[] }[] };
  };
  assert.equal(manifest.contributes.customEditors.length, 1);
  const editor = manifest.contributes.customEditors[0];
  assert.equal(editor.viewType, 'tmforge.studio');
  assert.equal(editor.priority, 'default');
  assert.deepEqual(editor.selector.map(item => item.filenamePattern), ['*.tm7', '*.tmforge.json']);
  assert.ok(!JSON.stringify(manifest.contributes).includes('Preview'));
});

test('Studio allows local UI assets and dynamic styles but no network or arbitrary scripts', () => {
  const html = studioHtml('vscode-webview:', 'https://local/studio.js?x="bad"', 'https://local/studio.css', 'studioNonce');
  assert.match(html, /default-src 'none'/);
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /script-src 'nonce-studioNonce'/);
  assert.ok(!html.includes('unsafe-eval'));
  assert.match(html, /style-src vscode-webview: 'unsafe-inline'/);
  assert.match(html, /x=&quot;bad&quot;/);
});

test('Copilot ships an invocable extension-only skill and tools without a custom agent', async () => {
  const root = resolve(__dirname, '../..');
  const manifest = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  assert.equal(manifest.engines.vscode, '^1.138.0');
  assert.equal(manifest.extensionDependencies, undefined, 'Editing must not depend on a Copilot installation');
  assert.equal(manifest.enabledApiProposals, undefined, 'Marketplace builds must not require proposed APIs');
  assert.equal(manifest.contributes.chatAgents, undefined);
  assert.ok(!(await readdir(resolve(root, 'copilot'), { recursive: true })).some(path => path.endsWith('.agent.md')));
  assert.equal(manifest.contributes.chatSkills.length, 1);
  for (const contribution of manifest.contributes.chatSkills) {
    assert.match(contribution.path, /^\.\/copilot\//);
    const content = await readFile(resolve(root, contribution.path), 'utf8');
    for (const newline of ['\n', '\r\n']) {
      const skill = content.replace(/\r?\n/g, newline);
      assert.match(skill, /^---\r?\n/);
      assert.match(skill, /name: tmforge-vscode\r?\n/);
      assert.match(skill, /user-invocable: true\r?\n/);
    }
    assert.doesNotMatch(content, /scripts\/|threat-modeling-tmforge|name: Strider|plugins\/tmforge/);
    assert.ok(content.split('\n').length < 150, 'Keep the extension workflow focused');
    assert.match(contribution.when, /config\.tmforge\.copilot\.enabled/);
  }
  const skill = await readFile(resolve(root, manifest.contributes.chatSkills[0].path), 'utf8');
  assert.doesNotMatch(skill, /disable-model-invocation: true/);
  assert.match(skill, /only tmforge tools to create or modify models/);
  assert.match(skill, /## Completion/);
  assert.ok((await readFile(resolve(root, '.vscodeignore'), 'utf8')).includes('out/copilot/**'), 'Exclude any obsolete staged plugin assets');
  assert.equal(manifest.contributes.languageModelTools.length, 4);
  for (const tool of manifest.contributes.languageModelTools) {
    assert.ok(skill.includes(tool.toolReferenceName));
    assert.ok(skill.includes(tool.name));
    assert.equal(tool.canBeReferencedInPrompt, true);
    assert.equal(tool.inputSchema.additionalProperties, false);
  }
});

test('packaging scopes release-please notes by changed files and rejects stale or unverifiable notes', async () => {
  const { stageChangelog, affectsExtension } = await import(pathToFileURL(resolve(__dirname, '../../scripts/check-package.mjs')).href) as {
    stageChangelog(extensionRoot: string): Promise<void>;
    affectsExtension(path: string): boolean;
  };
  const repository = await mkdtemp(resolve(tmpdir(), 'tmforge-changelog-'));
  const extensionRoot = resolve(repository, 'src/extension');
  const staged = resolve(extensionRoot, 'out/CHANGELOG.md');
  try {
    await mkdir(resolve(extensionRoot, 'out'), { recursive: true });
    await writeFile(resolve(extensionRoot, 'package.json'), JSON.stringify({ version: '0.12.0' }));
    const git = (...args: string[]) => execFileSync('git', ['-c', 'user.name=Changelog Test', '-c', 'user.email=changelog@example.test', '-c', 'commit.gpgSign=false', '-c', 'core.hooksPath=/dev/null', ...args], { cwd: repository, encoding: 'utf8' }).trim();
    git('init', '-q');
    const commit = async (path: string) => {
      const file = resolve(repository, path);
      await mkdir(resolve(file, '..'), { recursive: true });
      await writeFile(file, 'test\n');
      git('add', '--', path);
      git('commit', '-qm', 'feat: test change');
      return git('rev-parse', 'HEAD');
    };
    const plugin = await commit('plugins/tmforge/plugin.json');
    const studio = await commit('src/ThreatModelForge.Studio/src/App.tsx');
    const engine = await commit('src/ThreatModelForge.Engine/EngineService.cs');
    const cli = await commit('src/ThreatModelForge.Cli/Program.cs');
    const link = (sha: string) => `([${sha.slice(0, 7)}](https://github.com/Hacks4Snacks/tmforge/commit/${sha}))`;
    const title = '## [0.12.0](https://example.test/compare/v0.11.0...v0.12.0) (2026-09-21)';
    const notes = `# Changelog\n\n${title}\n\n### Features\n\n* Plugin publication ${link(plugin)}\n* Studio editing ${link(studio)}\n  Preserves native files.\n\n### Bug Fixes\n\n* Shared engine fix ${link(engine)}\n\n### Miscellaneous\n\n* CLI-only change ${link(cli)}\n\n## [0.11.0](https://example.test/older)\n\n* Older plugin work ${link(plugin)}\n`;
    await writeFile(resolve(repository, 'CHANGELOG.md'), notes);
    await writeFile(staged, '# Change Log\n\n## [Unreleased]\n\nManual notes.\n');
    await stageChangelog(extensionRoot);
    const scoped = await readFile(staged, 'utf8');
    assert.ok(scoped.includes(title));
    assert.ok(scoped.includes(`* Studio editing ${link(studio)}\n  Preserves native files.`));
    assert.ok(scoped.includes(`* Shared engine fix ${link(engine)}`));
    assert.doesNotMatch(scoped, /Plugin publication|CLI-only|Miscellaneous|Older plugin|## \[0\.11\.0\]/);
    assert.equal(await readFile(resolve(repository, 'CHANGELOG.md'), 'utf8'), notes);
    await stageChangelog(extensionRoot);
    assert.equal(await readFile(staged, 'utf8'), scoped);
    for (const invalid of [notes.replaceAll('0.12.0', '0.13.0'), notes.replace('0.12.0', 'Unreleased'), '# Changelog\n', notes.replace('0.12.0', '0.12.0-rc.1')]) {
      await writeFile(resolve(repository, 'CHANGELOG.md'), invalid);
      await assert.rejects(stageChangelog(extensionRoot), /root changelog must start with release 0\.12\.0/);
      assert.equal(await readFile(staged, 'utf8'), scoped);
    }
    for (const [invalid, expected] of [
      [notes.replace(studio, 'f'.repeat(40)), /Fetch complete Git history/],
      [`# Changelog\n\n${title}\n\n* Note without a commit link.\n`, /without a tmforge commit link/],
    ] as const) {
      await writeFile(resolve(repository, 'CHANGELOG.md'), invalid);
      await assert.rejects(stageChangelog(extensionRoot), expected);
      assert.equal(await readFile(staged, 'utf8'), scoped);
    }
    const plainNotes = `# Changelog\r\n\r\n## 0.12.0 (2026-09-21)\r\n\r\n* Plugin-only release ${link(plugin)}\r\n`;
    await writeFile(resolve(repository, 'CHANGELOG.md'), plainNotes);
    await stageChangelog(extensionRoot);
    const empty = await readFile(staged, 'utf8');
    assert.match(empty, /## 0\.12\.0 \(2026-09-21\)/);
    assert.match(empty, /No extension-related changes/);
    assert.doesNotMatch(empty, /Plugin-only release/);
    assert.equal(await readFile(resolve(repository, 'CHANGELOG.md'), 'utf8'), plainNotes);
    const shallow = resolve(repository, 'shallow');
    git('clone', '-q', '--depth', '1', pathToFileURL(repository).href, shallow);
    const shallowExtension = resolve(shallow, 'src/extension');
    await mkdir(shallowExtension, { recursive: true });
    await writeFile(resolve(shallowExtension, 'package.json'), JSON.stringify({ version: '0.12.0' }));
    await writeFile(resolve(shallow, 'CHANGELOG.md'), notes);
    await assert.rejects(stageChangelog(shallowExtension), /complete Git history/);
    for (const path of ['src/ThreatModelForge.Vscode/src/extension.ts', 'src/ThreatModelForge.Wasm/Engine.cs', 'src/ThreatModelForge.Analysis.Rules/Rule.cs', 'src/ThreatModelForge.Analysis.Reporting/Report.cs', 'Directory.Packages.props']) assert.equal(affectsExtension(path), true, path);
    for (const path of ['src/ThreatModelForge.Api/Program.cs', 'src/ThreatModelForge.Cli/Program.cs', 'plugins/tmforge/plugin.json', 'plugins/tmforge/skills/threat-modeling/SKILL.md', 'plugins/tmforge/com.github.copilot/agents/strider.agent.md', '.github/plugin/marketplace.json', 'docs/deployment.md']) assert.equal(affectsExtension(path), false, path);
  } finally { await rm(repository, { recursive: true, force: true }); }
});
