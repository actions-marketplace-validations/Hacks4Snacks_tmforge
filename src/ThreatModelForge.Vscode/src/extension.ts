import * as vscode from 'vscode';
import { join } from 'node:path';
import { EngineWorker, MAX_DOCUMENT_BYTES, type Inspection } from './engine';
import { StudioEditors } from './studio';
import { createCopilotTools } from './copilot.js';

interface DocumentState {
	version: number;
	result?: Inspection;
	pending?: Promise<Inspection>;
}

export function sourceFormat(document: vscode.TextDocument, studio?: StudioEditors): string | undefined {
	const path = document.uri.path.toLowerCase();
	if (path.endsWith('.tm7')) return 'tm7';
	if (path.endsWith('.tmforge.json')) return 'tmforge-json';
	if (studio?.isDraft(document)) return 'tmforge-json';
	return undefined;
}

function activeModelUri(): vscode.Uri | undefined {
	const input = vscode.window.tabGroups.activeTabGroup.activeTab?.input;
	return input instanceof vscode.TabInputCustom || input instanceof vscode.TabInputText
		? input.uri : vscode.window.activeTextEditor?.document.uri;
}

export function activate(context: vscode.ExtensionContext) {
	const engine = new EngineWorker(join(context.extensionPath, 'engine', '_framework'));
	const diagnostics = vscode.languages.createDiagnosticCollection('tmforge');
	const states = new Map<string, DocumentState>();
	let disposed = false;
	const studio = new StudioEditors(context, document => { states.delete(document.uri.toString()); void inspect(document); }, engine);
	const tools = createCopilotTools(context, engine, studio, activeModelUri);
	for (const [name, tool] of Object.entries(tools)) context.subscriptions.push(vscode.lm.registerTool<unknown>(name, tool));
	context.subscriptions.push(engine, studio, diagnostics, { dispose: () => { disposed = true; states.clear(); } });

	const inspect = (document: vscode.TextDocument): Promise<Inspection> => {
		const key = document.uri.toString();
		const existing = states.get(key);
		if (existing?.version === document.version) {
			if (existing.pending) return existing.pending;
			if (existing.result) return Promise.resolve(existing.result);
		}
		const state: DocumentState = { version: document.version };
		states.set(key, state);
		diagnostics.delete(document.uri);
		state.pending = (async () => {
			let result: Inspection;
			try {
				if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before running model analysis.');
				const format = sourceFormat(document, studio);
				if (!format) throw new Error('Open a .tm7 or .tmforge.json model.');
				const text = document.getText();
				if (Buffer.byteLength(text, 'utf8') > MAX_DOCUMENT_BYTES) throw new Error('Model inspection is limited to 8 MiB.');
				result = await (studio.engineFor(document) ?? engine).inspect(Buffer.from(text, 'utf8'), format);
			} catch (error) {
				result = { pages: [], analysis: null, diagnostics: [{
					code: 'inspection.failed', severity: 'error', path: '$',
					message: error instanceof Error ? error.message : 'Model inspection failed.',
				}] };
			}
			if (!disposed && !document.isClosed && document.version === state.version && states.get(key) === state) {
				state.pending = undefined;
				state.result = result;
				diagnostics.set(document.uri, toDiagnostics(result, document));
			}
			return result;
		})();
		return state.pending;
	};

	context.subscriptions.push(
		vscode.window.registerCustomEditorProvider('tmforge.studio', studio, { supportsMultipleEditorsPerDocument: true }),
		vscode.commands.registerCommand('tmforge.newModel', () => studio.create()),
		vscode.commands.registerCommand('tmforge.openStudio', async (uri?: vscode.Uri) => {
			const target = uri ?? activeModelUri();
			const document = vscode.workspace.textDocuments.find(candidate => candidate.uri.toString() === target?.toString());
			if (!target || (!/\.(tm7|tmforge\.json)$/i.test(target.path) && (!document || !studio.isDraft(document)))) { void vscode.window.showInformationMessage('Open a .tm7 or .tmforge.json model to edit in Studio.'); return; }
			await vscode.commands.executeCommand('vscode.openWith', target, 'tmforge.studio');
		}),
		vscode.commands.registerCommand('tmforge.analyze', async (uri?: vscode.Uri) => {
			const target = uri ?? activeModelUri();
			const document = target ? await vscode.workspace.openTextDocument(target) : undefined;
			if (!document || !sourceFormat(document, studio)) { void vscode.window.showInformationMessage('Open a .tm7 or .tmforge.json model first.'); return; }
			states.delete(document.uri.toString());
			await inspect(document);
			await vscode.commands.executeCommand('workbench.actions.view.problems');
		}),
		vscode.workspace.onDidOpenTextDocument(document => { if (sourceFormat(document, studio)) void inspect(document); }),
		vscode.workspace.onDidSaveTextDocument(document => { if (sourceFormat(document, studio)) void inspect(document); }),
		vscode.workspace.onDidChangeTextDocument(event => {
			if (!sourceFormat(event.document, studio) || event.contentChanges.length === 0) return;
			const key = event.document.uri.toString();
			states.set(key, { version: event.document.version });
			diagnostics.delete(event.document.uri);
		}),
		vscode.workspace.onDidCloseTextDocument(document => {
			states.delete(document.uri.toString());
			diagnostics.delete(document.uri);
		}),
		vscode.workspace.onDidGrantWorkspaceTrust(() => {
			for (const document of vscode.workspace.textDocuments) if (sourceFormat(document, studio)) { states.delete(document.uri.toString()); void inspect(document); }
		}),
	);
	for (const document of vscode.workspace.textDocuments) if (sourceFormat(document, studio)) void inspect(document);
	return { inspect, diagnostics, tools, edit: studio.edit.bind(studio), recover: studio.recover.bind(studio), nativeSource: studio.nativeSource.bind(studio), waitUntilRendered: studio.waitUntilRendered.bind(studio) };
}

function toDiagnostics(result: Inspection, document: vscode.TextDocument): vscode.Diagnostic[] {
	const range = document.lineAt(0).range;
	const make = (message: string, severity: string, code: string) => {
		const diagnostic = new vscode.Diagnostic(range, message, severity === 'error' ? vscode.DiagnosticSeverity.Error
			: severity === 'warning' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information);
		diagnostic.source = 'tmforge';
		diagnostic.code = code;
		return diagnostic;
	};
	return [
		...result.diagnostics.map(item => make(`${item.path}: ${item.message}`, item.severity, item.code)),
		...(result.analysis?.diagnostics ?? []).map(message => make(message, 'error', 'analysis.incomplete')),
		...(result.analysis?.findings ?? []).map(finding => make(
			`${finding.message}${finding.elementIds.length ? '\nElements: ' + finding.elementIds.join(', ') : ''}`,
			finding.id === 'engine-error' || finding.ruleId === 'rule-pack-mismatch' ? 'error' : finding.severity,
			finding.ruleId ?? finding.id,
		)),
	];
}
