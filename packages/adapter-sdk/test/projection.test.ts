// Semantic projection validation: both authorized projections of the shared
// fixture pass; omission/value drift/unknown seat/unknown field, reclassified
// labels, authorization drift, missing/unknown visibility, and the
// hidden-leak mutant's exact AIPT_VISIBILITY_UNAUTHORIZED_FIELD rejection all
// fail closed with the stable AIPT_* reasons.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { loadFixtureJson } from './helpers.ts';

function seatIds(): string[] {
  const seats = loadFixtureJson('seats.json') as unknown as sdk.State;
  return (seats as unknown as { seats: Array<{ seat_id: string }> }).seats.map((seat) => seat.seat_id);
}

const state = loadFixtureJson('state.json');

test('both authorized projections pass the full-state projection gate', () => {
  const known = seatIds();
  assert.deepEqual(known, ['seat-a', 'seat-b']);
  for (const rel of ['projection-seat-a.json', 'projection-seat-b.json']) {
    const projection = loadFixtureJson(rel);
    const result = sdk.validateProjectionSemantics(state, projection, known);
    assert.equal(result.valid, true, `${rel} must be valid`);
    assert.deepEqual([...result.issues], []);
  }
});

test('projection omission of an authorized field is rejected (hidden data is not an optional field)', () => {
  const known = seatIds();
  const projection = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-a.json'))) as { fields: unknown[] };
  projection.fields = projection.fields.filter((field) => (field as { field_id: string }).field_id !== 'table-note');
  const result = sdk.validateProjectionSemantics(state, projection, known);
  assert.equal(result.valid, false);
  assert.deepEqual(result.issues.map((issue) => issue.code), ['AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD']);
});

test('projection value drift is rejected with AIPT_PROJECTION_VALUE_DRIFT', () => {
  const known = seatIds();
  const projection = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-a.json'))) as { fields: Array<{ field_id: string; value: number }> };
  projection.fields.find((field) => field.field_id === 'turn-count')!.value = 5;
  const result = sdk.validateProjectionSemantics(state, projection, known);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_PROJECTION_VALUE_DRIFT'));
});

test('unknown projection seat is rejected with AIPT_PROJECTION_UNKNOWN_SEAT', () => {
  const known = seatIds();
  const projection = loadFixtureJson('projection-seat-a.json');
  const drifted = { ...projection, seat_id: 'seat-ghost' };
  const result = sdk.validateProjectionSemantics(state, drifted, known);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_PROJECTION_UNKNOWN_SEAT' && issue.path === '$/seat_id'));
});

test('projecting an unknown field is rejected with AIPT_PROJECTION_UNKNOWN_FIELD', () => {
  const known = seatIds();
  const projection = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-b.json'))) as { fields: Array<Record<string, unknown>> };
  projection.fields.push({
    field_id: 'ghost-field',
    value: 0,
    visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-b'] },
  });
  const result = sdk.validateProjectionSemantics(state, projection, known);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_PROJECTION_UNKNOWN_FIELD'));
});

test('visibility reclassification and authorization drift are rejected', () => {
  const known = seatIds();
  const reclassified = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-a.json'))) as { fields: Array<{ visibility: { label: string; authorized_seat_ids: string[] } }> };
  reclassified.fields[0].visibility.label = 'TABLE_HIDDEN_REMOTE_ALLOWED';
  let result = sdk.validateProjectionSemantics(state, reclassified, known);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_VISIBILITY_RECLASSIFIED'));
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD' || issue.code === 'AIPT_VISIBILITY_RECLASSIFIED'));

  const drifted = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-a.json'))) as { fields: Array<{ visibility: { label: string; authorized_seat_ids: string[] } }> };
  drifted.fields[0].visibility.authorized_seat_ids = ['seat-b'];
  result = sdk.validateProjectionSemantics(state, drifted, known);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_VISIBILITY_AUTHORIZATION_DRIFT'));
});

test('missing and unknown visibility fail closed', () => {
  const known = seatIds();
  const missingVisibility = JSON.parse(JSON.stringify(state)) as { fields: Array<Record<string, unknown>> };
  delete (missingVisibility.fields[0] as Record<string, unknown>).visibility;
  const missingResult = sdk.validateStateShape(missingVisibility);
  assert.equal(missingResult.valid, false);
  assert.ok(missingResult.issues.some((issue) => issue.code === 'AIPT_MISSING_VISIBILITY'));

  const unknownLabel = JSON.parse(JSON.stringify(state)) as { fields: Array<{ visibility: { label: string } }> };
  unknownLabel.fields[0].visibility.label = 'TEAM_ONLY';
  const unknownResult = sdk.validateStateShape(unknownLabel);
  assert.equal(unknownResult.valid, false);
  assert.ok(unknownResult.issues.some((issue) => issue.code === 'AIPT_UNKNOWN_VISIBILITY'));
});

test('hidden-leak mutant is rejected with exactly AIPT_VISIBILITY_UNAUTHORIZED_FIELD', () => {
  const known = seatIds();
  const mutant = loadFixtureJson('mutants/hidden-leak.json') as unknown as { projection: unknown };
  const result = sdk.validateProjectionSemantics(state, mutant.projection, known);
  assert.equal(result.valid, false);
  assert.deepEqual(
    result.issues.map((issue) => issue.code),
    ['AIPT_VISIBILITY_UNAUTHORIZED_FIELD'],
    'the mutant must be rejected with exactly one reason: the unauthorized hidden field',
  );
  assert.equal(result.issues[0].code, 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD');
});

test('authorized_seat_ids compared as a set: reordering alone is not authorization drift', () => {
  const known = seatIds();
  const projection = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-a.json'))) as { fields: Array<{ visibility: { authorized_seat_ids: string[] } }> };
  projection.fields[0].visibility.authorized_seat_ids.reverse();
  const result = sdk.validateProjectionSemantics(state, projection, known);
  assert.equal(result.valid, true, 'reordering authorized_seat_ids must not be drift');
  assert.deepEqual([...result.issues], []);
});

test('projection fixture_id drift from the source state is rejected with AIPT_FIXTURE_IDENTITY_MISMATCH', () => {
  const known = seatIds();
  const projection = JSON.parse(JSON.stringify(loadFixtureJson('projection-seat-a.json'))) as { fixture_id: string };
  projection.fixture_id = 'drifted-fixture';
  const result = sdk.validateProjectionSemantics(state, projection, known);
  assert.equal(result.valid, false);
  assert.deepEqual(result.issues.map((issue) => issue.code), ['AIPT_FIXTURE_IDENTITY_MISMATCH']);
  assert.equal(result.issues[0].path, '$/fixture_id');
});

test('known seats must be well-formed identifiers and are rejected deterministically when invalid', () => {
  const projection = loadFixtureJson('projection-seat-a.json');
  const invalid = sdk.validateProjectionSemantics(state, projection, ['Seat-Bad!']);
  assert.equal(invalid.valid, false);
  assert.ok(invalid.issues.some((issue) => issue.code === 'AIPT_INVALID_IDENTIFIER' && issue.path === '$/known_seats/0'));
  assert.ok(invalid.issues.some((issue) => issue.code === 'AIPT_PROJECTION_UNKNOWN_SEAT'), 'the invalid seat never becomes a trusted known seat');

  const nonString = sdk.validateProjectionSemantics(state, projection, ['seat-a', 42 as unknown as string]);
  assert.equal(nonString.valid, false);
  assert.ok(nonString.issues.some((issue) => issue.code === 'AIPT_INVALID_IDENTIFIER' && issue.path === '$/known_seats/1'));
});

test('duplicate known seats are rejected deterministically at their later occurrence', () => {
  const projection = loadFixtureJson('projection-seat-a.json');
  const result = sdk.validateProjectionSemantics(state, projection, ['seat-a', 'seat-b', 'seat-a']);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_INVALID_VALUE' && issue.path === '$/known_seats/2' && issue.message.includes('seat-a')));
});

test('state/projection values pass the lossless JSON-value gate before semantic comparison', () => {
  const known = seatIds();
  const lossyState = JSON.parse(JSON.stringify(state)) as { fields: Array<{ value: number }> };
  lossyState.fields[0].value = Number.NaN;
  const projection = loadFixtureJson('projection-seat-a.json');
  const result = sdk.validateProjectionSemantics(lossyState, projection, known);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/fields/0/value'));
});
