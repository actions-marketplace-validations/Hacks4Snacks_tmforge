import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import * as vscode from 'vscode';
import { EngineWorker, type Inspection } from '../engine';
import type { createCopilotTools } from '../copilot';

export async function run(): Promise<void> {
	console.log('Extension-host runtime:', JSON.stringify({ platform: process.platform, arch: process.arch, versions: process.versions }));
	const extension = vscode.extensions.getExtension<{
		inspect(document: vscode.TextDocument): Promise<Inspection>;
		diagnostics: vscode.DiagnosticCollection;
		tools: ReturnType<typeof createCopilotTools>;
		edit(document: vscode.TextDocument, version: number, previous: unknown, next: unknown): Promise<{ version: number; dirty: boolean }>;
		nativeSource(document: vscode.TextDocument): Promise<string>;
		recover(document: vscode.TextDocument, version: number): Promise<vscode.TextDocument>;
		waitUntilRendered(document: vscode.TextDocument): Promise<void>;
	}>('hacks4snacks.tmforge');
	assert.ok(extension, 'Extension was not loaded');
	const api = await extension.activate();
	const directory = await mkdtemp(join(tmpdir(), 'tmforge-vscode-test-'));
	try {
		await verifyCopilotTools(api, directory);
		if (process.env.TMFORGE_TEST_COPILOT === '1') return;
		const source = await readFile(resolve(__dirname, '../../../../examples/webshop.tm7'));
		const path = join(directory, 'webshop.tm7');
		await writeFile(path, source);
		const uri = vscode.Uri.file(path);
		const document = await vscode.workspace.openTextDocument(uri);
		const result = await api.inspect(document);
		assert.equal(result.pages.length, 1);
		assert.ok(api.diagnostics.get(uri)?.some(diagnostic => diagnostic.code === 'TM1029'));
		await vscode.commands.executeCommand('vscode.open', uri);
		assert.ok(vscode.window.tabGroups.all.flatMap(group => group.tabs).some(tab => tab.input instanceof vscode.TabInputCustom && tab.input.viewType === 'tmforge.studio'));
		assert.deepEqual(await readFile(path), source, 'Opening Studio mutated the source');
		await vscode.commands.executeCommand('tmforge.openStudio', uri);
		await api.waitUntilRendered(document);
		const worker = new EngineWorker(resolve(__dirname, '../../engine/_framework'));
		try {
			const broken = source.toString().replace(/(<Lines\b[\s\S]*?<TargetGuid\b[^>]*>)[^<]+(<\/TargetGuid>)/,
				(_match, opening, closing) => `${opening}00000000-0000-0000-0000-000000000000${closing}`);
			assert.ok(broken !== source.toString(), 'The fixture must detach a connector before testing recovery.');
			const brokenPath = join(directory, 'broken.tm7');
			await writeFile(brokenPath, broken);
			const brokenDocument = await vscode.workspace.openTextDocument(brokenPath);
			await vscode.commands.executeCommand('tmforge.openStudio', brokenDocument.uri);
			await assert.rejects(api.recover(brokenDocument, brokenDocument.version - 1), /source changed/);
			const recoveredDocument = await api.recover(brokenDocument, brokenDocument.version);
			assert.equal(recoveredDocument.isUntitled, true);
			assert.equal(recoveredDocument.isDirty, true);
			assert.match(recoveredDocument.uri.path, /^Untitled-\d+$/);
			assert.equal(JSON.parse(recoveredDocument.getText()).flows.length, 3);
			await api.waitUntilRendered(recoveredDocument);
			assert.equal(brokenDocument.getText(), broken);
			assert.equal(brokenDocument.isDirty, false);
			assert.equal(await readFile(brokenPath, 'utf8'), broken);
			await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor');
			await vscode.commands.executeCommand('tmforge.openStudio', document.uri);
			await api.waitUntilRendered(document);
			const originalText = document.getText();
			const baseline = JSON.parse(await worker.invoke('ReadFile', [source.toString('base64'), 'tm7']));
			await api.edit(document, document.version, baseline, baseline);
			assert.equal(document.getText(), originalText, 'A no-op native edit changed the XML');
			assert.equal(document.isDirty, false);
			const renamed = structuredClone(baseline);
			renamed.diagrams[0].elements.find((element: { name: string }) => element.name === 'Orders API').name = 'Native VS Code API';
			renamed.elements = renamed.diagrams[0].elements;
			const nativeVersion = document.version;
			await api.edit(document, nativeVersion, baseline, renamed);
			assert.equal(document.isDirty, true);
			const changed = document.getText();
			assert.match(changed, /Native VS Code API/);
			assert.equal(Buffer.from(await api.nativeSource(document), 'base64').toString(), changed, 'Native export did not include unsaved edits');
			assert.deepEqual(await readFile(path), source, 'An unsaved native edit wrote to disk');
			await assert.rejects(api.edit(document, nativeVersion, baseline, renamed), /another editor/);
			await vscode.commands.executeCommand('undo');
			await waitForText(document, originalText);
			await vscode.commands.executeCommand('redo');
			await waitForText(document, changed);
			await document.save();
			assert.equal(await readFile(path, 'utf8'), changed);
			const savedModel = JSON.parse(await worker.invoke('ReadFile', [Buffer.from(changed).toString('base64'), 'tm7']));
			await api.edit(document, document.version, savedModel, savedModel);
			assert.equal(document.getText(), changed, 'A repeated native save changed the document');
			await vscode.commands.executeCommand('undo');
			await waitForText(document, originalText);
			await document.save();
			assert.deepEqual(await readFile(path), source, 'Undo and save did not restore the native bytes');

			const auditId = baseline.elements.find((element: { name: string }) => element.name === 'Audit Log').id;
			const triaged = structuredClone(baseline);
			triaged.threats = [...(triaged.threats ?? []), {
				id: 'manual:vscode-native-decision', manual: true, state: 'Accepted', category: 'Tampering',
				title: 'Native scoped decision', justification: 'Regression decision', elementIds: [auditId],
			}];
			await api.edit(document, document.version, baseline, triaged);
			await document.save();
			const beforeDelete = document.getText();
			const withDecision = JSON.parse(await worker.invoke('ReadFile', [Buffer.from(beforeDelete).toString('base64'), 'tm7']));
			assert.ok(withDecision.threats.some((threat: { id: string }) => threat.id === 'manual:vscode-native-decision'));
			const removed = structuredClone(withDecision);
			const page = removed.diagrams[0];
			const deletedIds = new Set([auditId, ...page.flows.filter((flow: { source: string; target: string }) => flow.source === auditId || flow.target === auditId).map((flow: { id: string }) => flow.id)]);
			page.elements = page.elements.filter((element: { id: string }) => element.id !== auditId);
			page.flows = page.flows.filter((flow: { id: string }) => !deletedIds.has(flow.id));
			removed.elements = page.elements;
			removed.flows = page.flows;
			removed.threats = removed.threats.filter((threat: { elementIds?: string[] }) => !threat.elementIds?.some(id => deletedIds.has(id)));
			await api.edit(document, document.version, withDecision, removed);
			await document.save();
			const deletedText = document.getText();
			const afterDelete = JSON.parse(await worker.invoke('ReadFile', [Buffer.from(deletedText).toString('base64'), 'tm7']));
			assert.ok(!afterDelete.threats?.some((threat: { id: string }) => threat.id === 'manual:vscode-native-decision'));
			assert.ok(!afterDelete.elements.some((element: { id: string }) => element.id === auditId));
			await vscode.commands.executeCommand('undo');
			await waitForText(document, beforeDelete);
			await document.save();
			assert.equal(await readFile(path, 'utf8'), beforeDelete, 'Undo after save failed to restore deleted native decisions');
			await vscode.commands.executeCommand('redo');
			await waitForText(document, deletedText);
			await document.save();

			await vscode.commands.executeCommand('workbench.action.splitEditorRight');
			await api.waitUntilRendered(document);
			const sourceEdit = new vscode.WorkspaceEdit();
			sourceEdit.replace(uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), originalText.replace('Orders API', 'Source-edited API'));
			await vscode.workspace.applyEdit(sourceEdit);
			await api.waitUntilRendered(document);
			const externalModel = JSON.parse(await worker.invoke('ReadFile', [Buffer.from(document.getText()).toString('base64'), 'tm7']));
			assert.ok(externalModel.elements.some((element: { name: string }) => element.name === 'Source-edited API'));
			const restore = new vscode.WorkspaceEdit();
			restore.replace(uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), originalText);
			await vscode.workspace.applyEdit(restore);
			await document.save();
			await api.waitUntilRendered(document);
			assert.deepEqual(await readFile(path), source);
			await vscode.commands.executeCommand('tmforge.analyze');
			assert.ok(api.diagnostics.get(uri)?.some(diagnostic => diagnostic.code === 'TM1029'), 'Analyze Model did not use the active native Studio tab');
		} finally { worker.dispose(); }
		const jsonPath = join(directory, 'save.tmforge.json');
		const invalid = '{"schema":"tmforge-json","elements":[],"flows":[{"id":"broken","source":"missing","target":"missing"}]}';
		await writeFile(jsonPath, invalid);
		const jsonDocument = await vscode.workspace.openTextDocument(jsonPath);
		await api.inspect(jsonDocument);
		assert.ok(api.diagnostics.get(jsonDocument.uri)?.some(diagnostic => diagnostic.severity === vscode.DiagnosticSeverity.Error));
		const valid = '{"schema":"tmforge-json","elements":[{"id":"api","kind":"process","name":"API","x":10,"y":10}],"flows":[]}';
		const edits = new vscode.WorkspaceEdit();
		edits.replace(jsonDocument.uri, new vscode.Range(jsonDocument.positionAt(0), jsonDocument.positionAt(invalid.length)), valid);
		assert.ok(await vscode.workspace.applyEdit(edits));
		const updated = new Promise<void>((resolveUpdate, reject) => {
			const timer = setTimeout(() => { subscription.dispose(); reject(new Error('Save did not update Problems diagnostics')); }, 15000);
			const subscription = vscode.languages.onDidChangeDiagnostics(event => {
				if (event.uris.some(candidate => candidate.toString() === jsonDocument.uri.toString()) && api.diagnostics.get(jsonDocument.uri)?.some(diagnostic => String(diagnostic.code).startsWith('TM'))) {
					clearTimeout(timer); subscription.dispose(); resolveUpdate();
				}
			});
		});
		await jsonDocument.save();
		await updated;
		assert.ok(!api.diagnostics.get(jsonDocument.uri)?.some(diagnostic => String(diagnostic.code).startsWith('model.')));
		await vscode.commands.executeCommand('tmforge.openStudio', jsonDocument.uri);
		await api.waitUntilRendered(jsonDocument);
		assert.ok(vscode.window.tabGroups.all.flatMap(group => group.tabs).some(tab => tab.input instanceof vscode.TabInputCustom && tab.input.viewType === 'tmforge.studio'));
		assert.equal(jsonDocument.getText(), valid, 'Opening Studio changed the source');
		assert.equal(jsonDocument.isDirty, false);
		const previous = JSON.parse(valid);
		const next = structuredClone(previous);
		next.elements[0].name = 'Renamed in Studio';
		const version = jsonDocument.version;
		const edited = await api.edit(jsonDocument, version, previous, next);
		assert.equal(edited.dirty, true);
		assert.equal(JSON.parse(jsonDocument.getText()).elements[0].name, 'Renamed in Studio');
		await assert.rejects(api.edit(jsonDocument, version, previous, next), /another editor/);
		const editedText = jsonDocument.getText();
		await vscode.commands.executeCommand('undo');
		await waitForText(jsonDocument, valid);
		assert.equal(jsonDocument.getText(), valid, 'Undo did not restore the exact original text');
		await vscode.commands.executeCommand('redo');
		await waitForText(jsonDocument, editedText);
		assert.equal(JSON.parse(jsonDocument.getText()).elements[0].name, 'Renamed in Studio');
		await vscode.window.showTextDocument(jsonDocument);
		await vscode.commands.executeCommand('tmforge.openStudio', jsonDocument.uri);
		await api.waitUntilRendered(jsonDocument);
		assert.equal(jsonDocument.isDirty, true, 'Reopening Studio lost unsaved document state');
		assert.equal(JSON.parse(jsonDocument.getText()).elements[0].name, 'Renamed in Studio');
		const invalidEdit = { ...next, flows: [{ id: 'broken', source: 'api', target: 'missing' }] };
		await assert.rejects(api.edit(jsonDocument, jsonDocument.version, next, invalidEdit), /missing/i);
		assert.equal(JSON.parse(jsonDocument.getText()).flows.length, 0);
		await jsonDocument.save();
		assert.equal(JSON.parse(await readFile(jsonPath, 'utf8')).elements[0].name, 'Renamed in Studio');
		assert.equal(jsonDocument.isDirty, false);
		await vscode.commands.executeCommand('workbench.action.splitEditorRight');
		await api.waitUntilRendered(jsonDocument);
		const externalText = jsonDocument.getText().replace('Renamed in Studio', 'Changed from source');
		const externalEdit = new vscode.WorkspaceEdit();
		externalEdit.replace(jsonDocument.uri, new vscode.Range(jsonDocument.positionAt(0), jsonDocument.positionAt(jsonDocument.getText().length)), externalText);
		await vscode.workspace.applyEdit(externalEdit);
		await api.waitUntilRendered(jsonDocument);
		await jsonDocument.save();
		assert.equal(JSON.parse(await readFile(jsonPath, 'utf8')).elements[0].name, 'Changed from source');
		assert.deepEqual(await readFile(path), source, 'Studio modified the native TM7');
		const documentsBeforeNew = new Set(vscode.workspace.textDocuments);
		await vscode.commands.executeCommand('tmforge.newModel');
		const newModel = vscode.workspace.textDocuments.find(candidate => candidate.isUntitled && !documentsBeforeNew.has(candidate));
		assert.ok(newModel, 'New Model did not create an untitled JSON document');
		assert.match(newModel.uri.path, /^Untitled-\d+$/, 'New drafts must not have an associated filesystem path');
		await api.waitUntilRendered(newModel);
		assert.equal(newModel.isDirty, true);
		assert.deepEqual(JSON.parse(newModel.getText()).elements, []);
		await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor');

		const originalInspect = EngineWorker.prototype.inspect;
		let finish!: (inspection: Inspection) => void;
		EngineWorker.prototype.inspect = () => new Promise(resolveInspection => { finish = resolveInspection; });
		try {
			const stalePath = join(directory, 'stale.tmforge.json');
			await writeFile(stalePath, valid);
			const staleDocument = await vscode.workspace.openTextDocument(stalePath);
			const pending = api.inspect(staleDocument);
			const edit = new vscode.WorkspaceEdit();
			edit.insert(staleDocument.uri, new vscode.Position(0, 0), ' ');
			await vscode.workspace.applyEdit(edit);
			finish(result);
			await pending;
			assert.equal(api.diagnostics.get(staleDocument.uri)?.length ?? 0, 0, 'A stale analysis result reached Problems');
			const current = api.inspect(staleDocument);
			finish(result);
			await current;
			assert.ok(api.diagnostics.get(staleDocument.uri)?.length, 'A current result was not published');
			await staleDocument.save();
		} finally { EngineWorker.prototype.inspect = originalInspect; }

		await vscode.extensions.getExtension('vscode.json-language-features')?.activate();
		const schemaCases = [
			['example.manifest.json', '{"elements":[{"kind":"process","properties":{}}]}', 'properties'],
			['example.suppressions.json', '{"files":[{"file":"model.tm7","suppressions":[{"ruleID":"TM1021"}]}]}', 'ruleID'],
			['example.tmrules.json', '{"schema":"tmforge-rules","version":99,"dialect":"urn:tmforge:rules:flat-v1","pack":{"id":"example","name":"Example"},"rules":[]}', '2'],
		];
		for (const [name, text, expected] of schemaCases) {
			const path = join(directory, name);
			await writeFile(path, text);
			const document = await vscode.workspace.openTextDocument(path);
			await vscode.window.showTextDocument(document);
			await waitForDiagnostics(document.uri, messages => messages.some(message => message.message.includes(expected)));
		}
		console.log('Extension-host tests passed: native and JSON Studio, unchanged open, native byte-preserving undo/save, dirty edits, history, source synchronization, invalid/stale-edit rejection, save diagnostics, and local schemas.');
	} catch (error) {
		console.error('Tmforge extension test failure:', error);
		throw error;
	} finally {
		await vscode.commands.executeCommand('workbench.action.closeAllEditors');
		await rm(directory, { recursive: true, force: true });
	}
}

async function verifyCopilotTools(api: { tools: ReturnType<typeof createCopilotTools>; diagnostics: vscode.DiagnosticCollection; waitUntilRendered(document: vscode.TextDocument): Promise<void> }, directory: string): Promise<void> {
	const cancellation = new vscode.CancellationTokenSource();
	const invoke = async (name: string, input: object) => {
		const result = await vscode.lm.invokeTool(name, { input, toolInvocationToken: undefined }, cancellation.token);
		assert.ok(result.content[0] instanceof vscode.LanguageModelTextPart);
		return JSON.parse(result.content[0].value);
	};
	try {
		for (const name of Object.keys(api.tools)) assert.ok(vscode.lm.tools.some(tool => tool.name === name), `Missing registered tool: ${name}`);
		const manifestSchema = await invoke('tmforge_catalog', { section: 'manifest' });
		assert.ok(manifestSchema.properties.elements);
		assert.ok((await invoke('tmforge_catalog', { section: 'properties' })).some((property: { values?: string[] }) => property.values?.includes('Unknown')));
		const unrelated = await vscode.workspace.openTextDocument({ language: 'json', content: '{}' });
		await assert.rejects(invoke('tmforge_inspect_model', { uri: unrelated.uri.toString() }), /Open/i);
		await vscode.window.showTextDocument(unrelated);
		await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor');
		const manifest = {
			schema: 'tmforge-manifest', version: 1, name: 'Copilot draft',
			elements: [
				{ alias: 'api', kind: 'process', name: 'API', props: { AuthenticationScheme: 'Unknown' } },
				{ alias: 'data', kind: 'store', name: 'Data', props: { StoresCredentials: 'Yes', Encrypted: 'Unknown' } },
			],
			flows: [{ alias: 'write', from: 'api', to: 'data', name: 'Write', props: { Protocol: 'Unknown' } }],
		};
		const beforeCreate = vscode.workspace.textDocuments.filter(document => document.isUntitled).length;
		await assert.rejects(invoke('tmforge_create_model', { manifest: { ...manifest, flows: [{ from: 'api', to: 'missing' }] } }), /missing/i);
		assert.equal(vscode.workspace.textDocuments.filter(document => document.isUntitled).length, beforeCreate, 'Invalid creation opened a draft');
		const created = await invoke('tmforge_create_model', { manifest, name: 'copilot-draft' });
		assert.equal(created.lifecycle, 'draft');
		const document = vscode.workspace.textDocuments.find(document => document.uri.toString() === created.uri);
		assert.ok(document?.isUntitled);
		assert.match(document.uri.path, /^Untitled-\d+$/, 'Copilot drafts must not have an associated filesystem path');
		await api.waitUntilRendered(document);
		assert.equal(document.isDirty, true, `Created draft must retain unsaved content: ${JSON.stringify({ created, version: document.version, text: document.getText() })}`);
		await vscode.commands.executeCommand('tmforge.analyze', document.uri);
		assert.ok(api.diagnostics.get(document.uri)?.some(diagnostic => diagnostic.code === 'TM1003'));
		await vscode.commands.executeCommand('tmforge.openStudio', document.uri);
		await api.waitUntilRendered(document);
		const snapshot = await invoke('tmforge_inspect_model', { uri: created.uri });
		assert.ok(snapshot.analysis.findings.length > 0);
		assert.ok(snapshot.analysis.findings.some((finding: { message: string }) => /not evidenced/.test(finding.message)));
		assert.equal(snapshot.model.elements.length, 2);
		const preserved = { ...snapshot.model, extension: { owner: 'security' }, threats: [{
			id: 'manual:existing-decision', manual: true, state: 'Accepted', title: 'Existing decision',
			category: 'Tampering', justification: 'Approved by the reviewer', elementIds: [snapshot.model.elements[0].id],
		}] };
		const authorEdit = new vscode.WorkspaceEdit();
		authorEdit.replace(document.uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), JSON.stringify(preserved, null, 2));
		await vscode.workspace.applyEdit(authorEdit);
		const beforeRename = await invoke('tmforge_inspect_model', { uri: created.uri });
		const original = document.getText();
		const renamed = structuredClone(beforeRename.model);
		renamed.elements[0].name = 'Copilot renamed API';
		if (renamed.diagrams?.length) renamed.diagrams[0].elements[0].name = 'Copilot renamed API';
		const updated = await invoke('tmforge_update_model', { uri: created.uri, revision: beforeRename.revision, model: renamed });
		assert.notEqual(updated.revision, snapshot.revision);
		assert.equal(JSON.parse(document.getText()).elements[0].name, 'Copilot renamed API');
		assert.deepEqual(JSON.parse(document.getText()).threats, preserved.threats);
		assert.deepEqual(JSON.parse(document.getText()).extension, preserved.extension);
		assert.deepEqual(JSON.parse(document.getText()).elements.map((element: { id: string }) => element.id), snapshot.model.elements.map((element: { id: string }) => element.id));
		const changed = document.getText();
		await assert.rejects(invoke('tmforge_update_model', { uri: created.uri, revision: snapshot.revision, model: snapshot.model }), /changed/i);
		assert.equal(document.getText(), changed);
		const invalid = { ...renamed, flows: [{ id: 'broken', source: renamed.elements[0].id, target: 'missing' }] };
		if (invalid.diagrams?.length) invalid.diagrams[0].flows = invalid.flows;
		await assert.rejects(invoke('tmforge_update_model', { uri: created.uri, revision: updated.revision, model: invalid }), /missing/i);
		assert.equal(document.getText(), changed, 'Invalid topology changed the model');
		await vscode.commands.executeCommand('tmforge.openStudio', document.uri);
		await api.waitUntilRendered(document);
		await vscode.commands.executeCommand('workbench.action.focusActiveEditorGroup');
		await vscode.commands.executeCommand('undo');
		await waitForText(document, original);
		await api.waitUntilRendered(document);
		await vscode.commands.executeCommand('redo');
		await waitForText(document, changed);
		await api.waitUntilRendered(document);
		await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor');
		await assert.rejects(invoke('tmforge_inspect_model', { uri: vscode.Uri.file(join(directory, 'not-open.tm7')).toString() }), /open/i);
		await assert.rejects(invoke('tmforge_catalog', { section: 'constructor' }), /Choose/);

		console.log('Copilot native test: opening model');
		const nativePath = join(directory, 'copilot-native.tm7');
		const source = (await readFile(resolve(__dirname, '../../../../examples/webshop.tm7'), 'utf8')).replace('</ThreatModel>', '<Extension xmlns="urn:tmforge:test">kept</Extension></ThreatModel>');
		await writeFile(nativePath, source);
		const native = await vscode.workspace.openTextDocument(nativePath);
		await vscode.commands.executeCommand('vscode.openWith', native.uri, 'tmforge.studio');
		await api.waitUntilRendered(native);
		console.log('Copilot native test: model rendered');
		const baseline = await invoke('tmforge_inspect_model', { uri: native.uri.toString() });
		console.log('Copilot native test: model inspected');
		const next = structuredClone(baseline.model);
		next.elements.find((element: { name: string }) => element.name === 'Orders API').name = 'Copilot native API';
		next.diagrams[0].elements.find((element: { name: string }) => element.name === 'Orders API').name = 'Copilot native API';
		await invoke('tmforge_update_model', { uri: native.uri.toString(), revision: baseline.revision, model: next });
		console.log('Copilot native test: model updated');
		assert.match(native.getText(), /Copilot native API/);
		assert.match(native.getText(), /<Extension xmlns="urn:tmforge:test">kept<\/Extension>/);
		assert.equal(await readFile(nativePath, 'utf8'), source, 'Tool saved native edits without a save request');
		await vscode.commands.executeCommand('undo');
		await waitForText(native, source);
		await native.save();
		assert.equal(await readFile(nativePath, 'utf8'), source);

		const cancelled = new vscode.CancellationTokenSource();
		cancelled.cancel();
		try {
			await assert.rejects(async () => api.tools.tmforge_create_model.invoke({ input: { manifest }, toolInvocationToken: undefined }, cancelled.token), /Cancel/i);
		} finally { cancelled.dispose(); }
		const during = new vscode.CancellationTokenSource();
		const applyManifest = EngineWorker.prototype.applyManifest;
		EngineWorker.prototype.applyManifest = async function (input) {
			const candidate = await applyManifest.call(this, input);
			during.cancel();
			return candidate;
		};
		try {
			const untitledCount = vscode.workspace.textDocuments.filter(document => document.isUntitled && !document.isClosed).length;
			await assert.rejects(async () => api.tools.tmforge_create_model.invoke({ input: { manifest }, toolInvocationToken: undefined }, during.token), /Cancel/i);
			assert.equal(vscode.workspace.textDocuments.filter(document => document.isUntitled && !document.isClosed).length, untitledCount);
		} finally { EngineWorker.prototype.applyManifest = applyManifest; during.dispose(); }
		const configuration = vscode.workspace.getConfiguration('tmforge');
		await configuration.update('copilot.enabled', false, vscode.ConfigurationTarget.Global);
		try {
			await assert.rejects(async () => api.tools.tmforge_catalog.invoke({ input: { section: 'properties' }, toolInvocationToken: undefined }, cancellation.token), /disabled/);
			await vscode.commands.executeCommand('tmforge.newModel');
			const ordinary = vscode.workspace.textDocuments.find(document => document.isUntitled && !document.isClosed);
			assert.ok(ordinary, 'Disabling Copilot must not disable ordinary model creation');
			await api.waitUntilRendered(ordinary);
			await vscode.commands.executeCommand('workbench.action.revertAndCloseActiveEditor');
		} finally { await configuration.update('copilot.enabled', undefined, vscode.ConfigurationTarget.Global); }
		const confirmation = await api.tools.tmforge_update_model.prepareInvocation?.({ input: { uri: native.uri.toString(), revision: baseline.revision, model: next } }, cancellation.token);
		assert.match(String(confirmation?.confirmationMessages?.message), /undoable/);
		await vscode.commands.executeCommand('workbench.action.closeAllEditors');
		console.log('Copilot tools passed: real tool registration/invocation, catalogs, invalid-create refusal, unsaved draft, analysis, stable IDs, stale/invalid-edit rejection, undo/redo, native preservation, and cancellation.');
	} finally { cancellation.dispose(); }
}

function waitForText(document: vscode.TextDocument, expected: string): Promise<void> {
	if (document.getText() === expected) return Promise.resolve();
	return new Promise((resolveWait, reject) => {
		const timer = setTimeout(() => { subscription.dispose(); reject(new Error('Document did not reach the expected text: ' + document.getText())); }, 5000);
		const subscription = vscode.workspace.onDidChangeTextDocument(event => {
			if (event.document === document && document.getText() === expected) { clearTimeout(timer); subscription.dispose(); resolveWait(); }
		});
	});
}

function waitForDiagnostics(uri: vscode.Uri, predicate: (diagnostics: readonly vscode.Diagnostic[]) => boolean): Promise<void> {
	if (predicate(vscode.languages.getDiagnostics(uri))) return Promise.resolve();
	return new Promise((resolveWait, reject) => {
		const timer = setTimeout(() => {
			subscription.dispose();
			reject(new Error('Expected schema diagnostics for ' + uri.path + ': ' + JSON.stringify(vscode.languages.getDiagnostics(uri))));
		}, 15000);
		const subscription = vscode.languages.onDidChangeDiagnostics(event => {
			if (event.uris.some(candidate => candidate.toString() === uri.toString()) && predicate(vscode.languages.getDiagnostics(uri))) {
				clearTimeout(timer); subscription.dispose(); resolveWait();
			}
		});
	});
}
