import assert from 'node:assert/strict';
import { test } from 'node:test';
import { applyModelChange, textChange } from '../document';

const model = () => ({ schema: 'tmforge-json', version: '0.1', elements: [{ id: 'api', kind: 'process', name: 'API', x: 10.25, y: 10 }], flows: [] });

test('canvas edits preserve unrepresented fields, untouched geometry and formatting conventions', () => {
	const original = { ...model(), extension: { owner: 'security' }, elements: [{ ...model().elements[0], extra: 'retained' }] };
	const previous = model();
	previous.elements[0].x = 10;
	const next = structuredClone(previous);
	next.elements[0].name = 'Renamed';
	const text = JSON.stringify(original, null, '\t').replace(/\n/g, '\r\n') + '\r\n';
	const changed = applyModelChange(text, previous, next);
	assert.deepEqual(JSON.parse(changed), { ...original, elements: [{ ...original.elements[0], name: 'Renamed' }] });
	assert.ok(changed.endsWith('\r\n'));
	assert.match(changed, /\r\n\t"/);
	assert.equal(applyModelChange(text, previous, previous), text);
	const edit = textChange(text, changed);
	assert.equal(text.slice(0, edit.start) + edit.text + text.slice(edit.end), changed);
});

test('model note edits preserve extra fields by native numeric identity', () => {
	const previous = { ...model(), notes: [
		{ id: 7, message: 'Remove this note', date: '2026-09-29T12:00:00Z' },
		{ id: 12, message: 'Original scope', date: '2026-09-30T12:00:00.1234567Z', addedBy: 'Reviewer' },
	] };
	const original = { ...previous, notes: previous.notes.map(note => ({ ...note, extra: `Evidence ${note.id}` })) };
	const added = { id: 13, message: 'New note', date: '2026-09-30T13:00:00Z' };
	const next = { ...previous, notes: [{ ...previous.notes[1], message: 'Updated\nScope' }, added] };
	const text = JSON.stringify(original, null, 2);
	const changed = JSON.parse(applyModelChange(text, previous, next));
	assert.deepEqual(changed.notes, [{ ...original.notes[1], message: 'Updated\nScope' }, added]);
	assert.deepEqual(changed.elements, original.elements);
	assert.equal(applyModelChange(text, previous, previous), text);
	assert.deepEqual(JSON.parse(applyModelChange(text, previous, { ...previous, notes: [] })).notes, []);
});

test('adding a page retains original fields on the implicit first page', () => {
	const previous = model();
	const original = { ...previous, elements: [{ ...previous.elements[0], extra: 'retained' }] };
	const next = { ...previous, diagrams: [
		{ id: 'first', name: 'Page 1', elements: previous.elements, flows: [] },
		{ id: 'second', name: 'Page 2', elements: [], flows: [] },
	] };
	const changed = JSON.parse(applyModelChange(JSON.stringify(original), previous, next));
	assert.equal(changed.diagrams[0].elements[0].extra, 'retained');
	assert.deepEqual(changed.elements, changed.diagrams[0].elements);
	assert.equal(changed.diagrams.length, 2);
});

test('page reordering preserves page-specific metadata and mirrored first-page fields', () => {
	const previous = { ...model(), diagrams: [
		{ id: 'first', name: 'First', elements: model().elements, flows: [] },
		{ id: 'second', name: 'Second', elements: [{ ...model().elements[0], id: 'store' }], flows: [] },
	] };
	const original = structuredClone(previous) as typeof previous & { diagrams: Record<string, unknown>[] };
	original.diagrams[1].custom = 'preserved';
	const next = { ...previous, diagrams: [...previous.diagrams].reverse(), elements: previous.diagrams[1].elements };
	const changed = JSON.parse(applyModelChange(JSON.stringify(original), previous, next));
	assert.equal(changed.diagrams[0].custom, 'preserved');
	assert.equal(changed.elements[0].id, 'store');
});

test('removing known settings leaves unknown settings intact', () => {
	const previous = { ...model(), analysis: { disabledPacks: ['network'] } };
	const original = { ...previous, analysis: { ...previous.analysis, custom: 'keep' } };
	const changed = JSON.parse(applyModelChange(JSON.stringify(original), previous, model()));
	assert.deepEqual(changed.analysis, { custom: 'keep' });
});

test('adding known settings leaves existing unrepresented settings intact', () => {
	const previous = model();
	const original = { ...previous, analysis: { custom: 'keep' } };
	const next = { ...previous, analysis: { disabledPacks: ['network'] } };
	const changed = JSON.parse(applyModelChange(JSON.stringify(original), previous, next));
	assert.deepEqual(changed.analysis, { custom: 'keep', disabledPacks: ['network'] });
});

test('editing a multi-page model retains unrepresented fields on both copies of its first page', () => {
	const previous = { ...model(), diagrams: [{ id: 'first', name: 'First', elements: model().elements, flows: [] }] };
	const original = { ...previous, elements: [{ ...previous.elements[0], extension: 'top level' }],
		diagrams: [{ ...previous.diagrams[0], elements: [{ ...previous.elements[0], extension: 'diagram' }] }] };
	const next = structuredClone(previous);
	next.elements[0].name = 'Updated';
	next.diagrams[0].elements[0].name = 'Updated';
	const changed = JSON.parse(applyModelChange(JSON.stringify(original), previous, next));
	assert.equal(changed.elements[0].extension, 'top level');
	assert.equal(changed.diagrams[0].elements[0].extension, 'diagram');
	assert.equal(changed.elements[0].name, 'Updated');
	assert.equal(changed.diagrams[0].elements[0].name, 'Updated');
});

test('invalid model edits are rejected', () => {
	assert.throws(() => applyModelChange('{}', model(), { ...model(), flows: [{}] }), /source/);
	assert.throws(() => applyModelChange('{}', model(), {}), /tmforge-json/);
});
