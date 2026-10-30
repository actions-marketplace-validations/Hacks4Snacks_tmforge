import { access, copyFile, cp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(process.argv[2] ?? resolve(root, '../../artifacts/vscode-wasm/wwwroot/_framework'));
for (const file of ['dotnet.js', 'dotnet.native.wasm', 'ThreatModelForge.Wasm.wasm', 'ThreatModelForge.Engine.wasm']) {
  await access(resolve(source, file));
}
const destination = resolve(root, 'engine/_framework');
await rm(destination, { recursive: true, force: true });
await mkdir(destination, { recursive: true });
for (const file of await readdir(source)) {
  if (/\.(br|gz|map|pdb)$/.test(file)) continue;
  await cp(resolve(source, file), resolve(destination, file), { recursive: true });
}
await writeFile(resolve(root, 'engine/package.json'), JSON.stringify({ type: 'module' }) + '\n');
await mkdir(resolve(root, 'schemas'), { recursive: true });
await copyFile(resolve(root, '../ThreatModelForge.Analysis/Schemas/tmforge-rules-v2.schema.json'), resolve(root, 'schemas/tmforge-rules-v2.schema.json'));
await copyFile(resolve(root, '../../LICENSE.md'), resolve(root, 'LICENSE.md'));
await copyFile(resolve(root, '../../NOTICE'), resolve(root, 'NOTICE'));
console.log('Staged bundled WASM engine, rule schema and repository notices.');
