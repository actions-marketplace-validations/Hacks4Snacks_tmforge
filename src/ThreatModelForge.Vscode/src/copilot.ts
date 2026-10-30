import * as vscode from 'vscode';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { EngineWorker, MAX_DOCUMENT_BYTES } from './engine';
import { StudioEditors } from './studio';

interface ModelInput { uri?: string }
interface CreateInput { manifest: Record<string, unknown>; name?: string }
interface UpdateInput extends ModelInput { uri: string; revision: string; model: Record<string, unknown> }
type CatalogSection = 'manifest' | 'stencils' | 'properties' | 'rules' | 'formats';

function checkpoint(token: vscode.CancellationToken): void {
	if (token.isCancellationRequested) throw new vscode.CancellationError();
	if (!vscode.workspace.isTrusted) throw new Error('Trust this workspace before using tmforge tools.');
	if (!vscode.workspace.getConfiguration('tmforge').get('copilot.enabled', true)) throw new Error('tmforge Copilot integration is disabled.');
}

function reference(document: vscode.TextDocument) {
	return {
		uri: document.uri.toString(),
		revision: `${document.version}:${createHash('sha256').update(document.getText()).digest('hex')}`,
		dirty: document.isDirty,
	};
}

function tool<Input>(title: string, confirmation: (input: Input) => string, run: (input: Input, token: vscode.CancellationToken) => Promise<unknown>): vscode.LanguageModelTool<Input> {
	return {
		prepareInvocation(options, token) {
			checkpoint(token);
			return { invocationMessage: title, confirmationMessages: { title, message: confirmation(options.input) } };
		},
		async invoke(options, token) {
			checkpoint(token);
			if (Buffer.byteLength(JSON.stringify(options.input), 'utf8') > MAX_DOCUMENT_BYTES) throw new Error('Tool inputs are limited to 8 MiB.');
			const result = JSON.stringify(await run(options.input, token));
			if (Buffer.byteLength(result, 'utf8') > 1024 * 1024) throw new Error('The model or catalog exceeds the 1 MiB chat result limit. Review it in Studio or narrow the model.');
			return new vscode.LanguageModelToolResult([new vscode.LanguageModelTextPart(result)]);
		},
	};
}

export function createCopilotTools(context: vscode.ExtensionContext, engine: EngineWorker, studio: StudioEditors, activeUri: () => vscode.Uri | undefined) {
	const read = async (input: ModelInput, token: vscode.CancellationToken) => {
		const uri = input.uri ? vscode.Uri.parse(input.uri, true) : activeUri();
		const document = vscode.workspace.textDocuments.find(candidate => !candidate.isClosed && candidate.uri.toString() === uri?.toString());
		if (!document || (!studio.isDraft(document) && !/\.(tm7|tmforge\.json)$/i.test(document.uri.path))) {
			throw new Error('Open the .tm7 or .tmforge.json model in VS Code first. Tools only access open model documents; use its exact URI.');
		}
		if (!['file', 'untitled', 'vscode-remote'].includes(document.uri.scheme)) throw new Error('Virtual model documents are not supported.');
		const version = document.version;
		const text = document.getText();
		const format = document.uri.path.toLowerCase().endsWith('.tm7') ? 'tm7' : 'tmforge-json';
		const currentEngine = studio.engineFor(document) ?? engine;
		const candidate = await currentEngine.readModel(text, format);
		const ensureCurrent = () => {
			checkpoint(token);
			if (document.isClosed || document.version !== version) throw new Error('The document changed. Inspect the model again before continuing.');
		};
		ensureCurrent();
		return { document, version, text, format, engine: currentEngine, ...candidate, ensureCurrent };
	};
	return {
		tmforge_catalog: tool<{ section: CatalogSection }>('Read tmforge catalog', input => `Read the bundled ${input.section} catalog? No workspace files are read.`, async (input, token) => {
			if (input.section === 'manifest') {
				const schema = await readFile(join(context.extensionPath, 'schemas', 'manifest.schema.json'), 'utf8');
				checkpoint(token);
				return JSON.parse(schema);
			}
			const methods = { stencils: 'Stencils', properties: 'PropertySchema', rules: 'Rules', formats: 'Formats' };
			if (!Object.hasOwn(methods, input.section)) throw new Error('Choose manifest, stencils, properties, rules, or formats.');
			const result = await engine.invoke(methods[input.section]);
			checkpoint(token);
			return JSON.parse(result);
		}),
		tmforge_create_model: tool<CreateInput>('Create draft threat model', () => 'Create a new unsaved model in Studio from the supplied manifest? No existing model is replaced. The result is a draft, not a verified security assessment.', async (input, token) => {
			const candidate = await engine.applyManifest(input.manifest);
			checkpoint(token);
			const document = await studio.create(candidate.model, input.name, token);
			return { ...reference(document), lifecycle: 'draft', warnings: candidate.warnings, next: 'Inspect this URI to read back and analyze the draft. Review it in Studio and use Save to choose its location.' };
		}),
		tmforge_inspect_model: tool<ModelInput>('Inspect threat model', input => `Read and locally analyze ${input.uri ?? 'the active model'}? Model content and findings will be returned to this Copilot conversation. No changes are made.`, async (input, token) => {
			const snapshot = await read(input, token);
			const inspection = await snapshot.engine.inspect(Buffer.from(snapshot.text), snapshot.format);
			snapshot.ensureCurrent();
			return { ...reference(snapshot.document), format: snapshot.format, model: snapshot.model, warnings: snapshot.warnings, analysis: inspection.analysis, diagnostics: inspection.diagnostics };
		}),
		tmforge_update_model: tool<UpdateInput>('Update threat model', input => `Apply the proposed model changes to ${input.uri}? This is an undoable edit to the current document, including any proposed topology or triage changes. The tool does not save the file; VS Code Auto Save still applies.`, async (input, token) => {
			const snapshot = await read(input, token);
			if (input.revision !== reference(snapshot.document).revision) throw new Error('The document changed since inspection. Inspect it again and reapply only the intended changes.');
			await studio.edit(snapshot.document, snapshot.version, snapshot.model, input.model, undefined, token);
			return { ...reference(snapshot.document), next: 'Inspect the model again to verify the serialized result and review findings. Undo is available in Studio.' };
		}),
	};
}
