import { isDeepStrictEqual } from 'node:util';
import { MAX_DOCUMENT_BYTES } from './engine';

type JsonObject = Record<string, unknown>;

function object(value: unknown): value is JsonObject {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function keyed(values: unknown[]): values is (JsonObject & { id: string | number })[] {
	return values.every(value => object(value) && (typeof value.id === 'string' || typeof value.id === 'number'));
}

function mergeChange(current: unknown, previous: unknown, next: unknown): unknown {
	if (isDeepStrictEqual(previous, next)) return current;
	if (Array.isArray(previous) && Array.isArray(next) && keyed(previous) && keyed(next)) {
		const originals = new Map((Array.isArray(current) && keyed(current) ? current : []).map(value => [value.id, value]));
		const baseline = new Map(previous.map(value => [value.id, value]));
		return next.map(value => mergeChange(originals.get(value.id), baseline.get(value.id), value));
	}
	if ((object(previous) || previous === undefined) && (object(next) || next === undefined)) {
		const result: JsonObject = Object.assign(Object.create(null), object(current) ? current : {});
		const before = previous ?? {};
		const updated = next ?? {};
		for (const key of new Set([...Object.keys(before), ...Object.keys(updated)])) {
			if (isDeepStrictEqual(before[key], updated[key])) continue;
			const value = mergeChange(result[key], before[key], updated[key]);
			if (value === undefined) delete result[key];
			else result[key] = value;
		}
		return next === undefined && Object.keys(result).length === 0 ? undefined : result;
	}
	return next;
}

export function applyModelChange(text: string, previous: unknown, next: unknown): string {
	if (!object(previous) || previous.schema !== 'tmforge-json' || !object(next) || next.schema !== 'tmforge-json') {
		throw new Error('Studio edits require a tmforge-json model.');
	}
	if (isDeepStrictEqual(previous, next)) return text;
	const current: unknown = JSON.parse(text);
	if (!object(current) || current.schema !== 'tmforge-json') throw new Error('The source is not a tmforge-json model.');
	let baseline = previous;
	if (!previous.diagrams && Array.isArray(next.diagrams) && object(next.diagrams[0])) {
		const page = next.diagrams[0];
		current.diagrams = [{ ...page, elements: current.elements, flows: current.flows }];
		baseline = { ...previous, diagrams: [{ ...page, elements: previous.elements, flows: previous.flows }] };
	}
	const result = mergeChange(current, baseline, next) as JsonObject;
	const indent = /\n([\t ]+)"/.exec(text)?.[1] ?? (text.includes('\n') ? '  ' : undefined);
	const newline = text.includes('\r\n') ? '\r\n' : '\n';
	const serialized = JSON.stringify(result, null, indent).replace(/\n/g, newline) + (/\r?\n$/.test(text) ? newline : '');
	if (Buffer.byteLength(serialized, 'utf8') > MAX_DOCUMENT_BYTES) throw new Error('Model documents are limited to 8 MiB.');
	return serialized;
}

export function textChange(previous: string, next: string): { start: number; end: number; text: string } {
	let start = 0;
	while (start < previous.length && start < next.length && previous[start] === next[start]) start++;
	let end = previous.length;
	let nextEnd = next.length;
	while (end > start && nextEnd > start && previous[end - 1] === next[nextEnd - 1]) { end--; nextEnd--; }
	return { start, end, text: next.slice(start, nextEnd) };
}
