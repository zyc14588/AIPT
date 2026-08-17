// Fixture compatibility helpers: pure validation over supplied parsed
// documents (manifest shape, path preflight, kind->schema_ref map, digests,
// canonical-schema instance validation, identity, inventory, mutant semantic
// proof) with digest/identity/schema drift rejections. The canonical schema
// document is loaded from the repository and passed in as the explicit
// validation boundary — the helpers never read the filesystem themselves.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { FIXTURE_DIR, loadFixtureJson, loadSchema } from './helpers.ts';
import fs from 'node:fs';
import path from 'node:path';

const schema = loadSchema();

function loadAllDocuments(): Map<string, unknown> {
  const manifest = loadFixtureJson('manifest.json') as unknown as sdk.FixtureManifest;
  const documents = new Map<string, unknown>();
  for (const entry of [...manifest.assets, ...manifest.mutants]) {
    documents.set(entry.path, loadFixtureJson(entry.path));
  }
  return documents;
}

const manifest = loadFixtureJson('manifest.json');

test('the shared fixture manifest validates', () => {
  const result = sdk.validateFixtureManifest(manifest);
  assert.equal(result.valid, true, JSON.stringify(result.issues));
  assert.deepEqual([...result.issues], []);
});

test('the shared fixture bundle validates (identity + digest + inventory + schema)', () => {
  const bundle = { manifest, documents: loadAllDocuments() };
  const result = sdk.validateFixtureBundle(bundle, schema);
  assert.equal(result.valid, true, JSON.stringify(result.issues));
  assert.deepEqual([...result.issues], []);
});

test('checkFixtureIdentity accepts a matching identity triple', () => {
  const result = sdk.checkFixtureIdentity(loadFixtureJson('state.json'));
  assert.equal(result.valid, true);
});

test('fixture digest drift is rejected with AIPT_FIXTURE_DIGEST_DRIFT', () => {
  const documents = loadAllDocuments();
  const tampered = JSON.parse(JSON.stringify(documents.get('state.json'))) as { fields: Array<{ value: number }> };
  tampered.fields[0].value = 999;
  documents.set('state.json', tampered);
  const result = sdk.validateFixtureBundle({ manifest, documents }, schema);
  assert.equal(result.valid, false);
  const digestIssues = result.issues.filter((issue) => issue.code === 'AIPT_FIXTURE_DIGEST_DRIFT');
  assert.equal(digestIssues.length, 1);
  assert.equal(digestIssues[0].path, '$/documents/state.json');
});

test('fixture identity drift is rejected with AIPT_FIXTURE_IDENTITY_MISMATCH', () => {
  const documents = loadAllDocuments();
  const drifted = JSON.parse(JSON.stringify(documents.get('state.json'))) as Record<string, unknown>;
  drifted.fixture_id = 'drifted-fixture-id';
  documents.set('state.json', drifted);
  const result = sdk.validateFixtureBundle({ manifest, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_IDENTITY_MISMATCH' && issue.path === '$/documents/state.json/fixture_id'));

  const expected = (manifest as unknown as sdk.FixtureManifest).fixture_id;
  const direct = sdk.checkFixtureIdentity(drifted, '$', expected);
  assert.equal(direct.valid, false);
  assert.deepEqual(direct.issues.map((issue) => issue.code), ['AIPT_FIXTURE_IDENTITY_MISMATCH']);
  const matching = sdk.checkFixtureIdentity(loadFixtureJson('state.json'), '$', expected);
  assert.equal(matching.valid, true);
});

test('mutant inner projection identity drift is rejected', () => {
  const documents = loadAllDocuments();
  const mutant = JSON.parse(JSON.stringify(documents.get('mutants/hidden-leak.json'))) as { projection: { fixture_id: string } };
  mutant.projection.fixture_id = 'drifted-fixture-id';
  documents.set('mutants/hidden-leak.json', mutant);
  const result = sdk.validateFixtureBundle({ manifest, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_IDENTITY_MISMATCH' && issue.path.includes('projection')));
});

test('a missing listed asset is rejected with AIPT_FIXTURE_MISSING_ASSET', () => {
  const documents = loadAllDocuments();
  documents.delete('seats.json');
  const result = sdk.validateFixtureBundle({ manifest, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_MISSING_ASSET' && issue.path === '$/documents/seats.json'));
});

test('an unlisted supplied document is rejected with AIPT_FIXTURE_UNLISTED_ASSET', () => {
  const documents = loadAllDocuments();
  documents.set('sneaky-extra.json', { protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic' });
  const result = sdk.validateFixtureBundle({ manifest, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_UNLISTED_ASSET' && issue.path === '$/documents/sneaky-extra.json'));
});

test('a malformed manifest fails closed', () => {
  const cases: unknown[] = [
    null,
    'not an object',
    { ...(manifest as object), assets: undefined },
    { ...(manifest as object), mutants: [] },
    { ...(manifest as object), fixture_id: 'BadFixtureId!' },
  ];
  for (const value of cases) {
    const result = sdk.validateFixtureManifest(value);
    assert.equal(result.valid, false, `accepted: ${JSON.stringify(value)}`);
    assert.ok(result.issues.length > 0);
  }
  const badBundle = { manifest: { hello: 'world' }, documents: new Map() };
  assert.equal(sdk.validateFixtureBundle(badBundle, schema).valid, false);
});

test('the SDK never reads the fixture filesystem: bundle validation works on supplied documents only', () => {
  // Build a bundle from in-memory values (no fixture paths involved in the
  // helper itself); the helper must not consult the repository.
  const inlineManifest = {
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'inline-fixture',
    fixture_name: 'inline',
    expected_final_state: 'final.json',
    replay_assertion: 'replay.json',
    assets: [{ path: 'a.json', kind: 'state', schema_ref: '#/$defs/state', sha256: '0'.repeat(64) }],
    mutants: [],
  };
  // mutants length 0 is rejected (the schema requires exactly one mutant).
  const result = sdk.validateFixtureManifest(inlineManifest);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.path === '$/mutants'));
});

test('every JSON file under the fixture directory is reachable through the manifest listing', () => {
  const parsed = manifest as unknown as sdk.FixtureManifest;
  const listed = new Set([...parsed.assets.map((asset) => asset.path), ...parsed.mutants.map((mutant) => mutant.path)]);
  listed.add('manifest.json');
  const files: string[] = [];
  const stack = [FIXTURE_DIR];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile() && entry.name.endsWith('.json')) files.push(path.relative(FIXTURE_DIR, full));
    }
  }
  for (const file of files) {
    assert.ok(listed.has(file), `unlisted fixture file: ${file}`);
  }
});

test('every newly exported fixture protocol type consumes its canonical document', () => {
  // Type-position exercises: each canonical manifest kind has a public SDK
  // type, and the shared fixture document parses into it (schema validation
  // is enforced separately by validateFixtureBundle).
  const seats = loadFixtureJson('seats.json') as unknown as sdk.SeatSet;
  assert.equal(seats.seats.length, 2);
  const firstSeat: sdk.Seat = seats.seats[0];
  assert.equal(typeof firstSeat.seat_id, 'string');
  assert.equal(typeof firstSeat.name, 'string');

  const check = loadFixtureJson('check-turn-increment.json') as unknown as sdk.DeterministicCheck;
  assert.equal(check.check_version, '1.0.0');
  assert.equal(check.kind, 'arithmetic');
  assert.equal(check.operator, 'add');

  const transition = loadFixtureJson('transition.json') as unknown as sdk.StateTransition;
  assert.equal(transition.applied_action.action, 'advance-turn');

  const assertion = loadFixtureJson('replay-assertion.json') as unknown as sdk.ReplayAssertion;
  assert.equal(assertion.hash_algorithm, 'sha256');
  assert.equal(assertion.final_state_ref, 'final-state.json');
  const replay: sdk.ReplayRecord = assertion.replays[0];
  assert.match(replay.final_state_hash, /^[0-9a-f]{64}$/);

  const mutant = loadFixtureJson('mutants/hidden-leak.json') as unknown as sdk.MutantSpecimen;
  assert.deepEqual([...mutant.markers], ['NON_CANON', 'MUTANT']);
  assert.equal(mutant.kind, 'hidden-leak');
  const inner: sdk.Projection = mutant.projection;
  assert.equal(inner.seat_id, 'seat-b');
});

// ---- iteration 4C bundle hardening ----

test('a schema-valid hidden-leak projection cannot replace an ordinary projection (digest updated)', () => {
  const documents = loadAllDocuments();
  const leaked = JSON.parse(JSON.stringify(documents.get('mutants/hidden-leak.json'))) as { projection: unknown };
  documents.set('projection-seat-b.json', leaked.projection);
  const mutated = JSON.parse(JSON.stringify(manifest)) as { assets: Array<{ path: string; sha256: string }> };
  mutated.assets.find((a) => a.path === 'projection-seat-b.json')!.sha256 = sdk.sha256Hex(leaked.projection);
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(
    result.issues.some((issue) => issue.code === 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD'),
    `hidden data must never pass as an ordinary projection, got ${JSON.stringify(result.issues.map((issue) => issue.code))}`,
  );
});

test('mutant wrapper metadata drift (seat_id / leaked_field_id, digest updated) fails the semantic proof', () => {
  const driftedSeat = JSON.parse(JSON.stringify(loadFixtureJson('mutants/hidden-leak.json'))) as { seat_id: string };
  driftedSeat.seat_id = 'seat-a';
  const mutatedSeat = JSON.parse(JSON.stringify(manifest)) as { mutants: Array<{ sha256: string }> };
  mutatedSeat.mutants[0].sha256 = sdk.sha256Hex(driftedSeat);
  const seatDocuments = loadAllDocuments();
  seatDocuments.set('mutants/hidden-leak.json', driftedSeat);
  let result = sdk.validateFixtureBundle({ manifest: mutatedSeat, documents: seatDocuments }, schema);
  assert.equal(result.valid, false);
  assert.ok(
    result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT' && issue.path === '$/mutants/0/seat_id'),
    `wrapper seat_id drift must fail, got ${JSON.stringify(result.issues.map((issue) => `${issue.code}@${issue.path}`))}`,
  );

  const driftedField = JSON.parse(JSON.stringify(loadFixtureJson('mutants/hidden-leak.json'))) as { leaked_field_id: string };
  driftedField.leaked_field_id = 'turn-count';
  const mutatedField = JSON.parse(JSON.stringify(manifest)) as { mutants: Array<{ sha256: string }> };
  mutatedField.mutants[0].sha256 = sdk.sha256Hex(driftedField);
  const fieldDocuments = loadAllDocuments();
  fieldDocuments.set('mutants/hidden-leak.json', driftedField);
  result = sdk.validateFixtureBundle({ manifest: mutatedField, documents: fieldDocuments }, schema);
  assert.equal(result.valid, false);
  assert.ok(
    result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT' && issue.path === '$/mutants/0/leaked_field_id'),
    `wrapper leaked_field_id drift must fail, got ${JSON.stringify(result.issues.map((issue) => `${issue.code}@${issue.path}`))}`,
  );
});

test('exact inventory: a supplied manifest.json documents entry is unlisted and rejected', () => {
  const documents = loadAllDocuments();
  documents.set('manifest.json', loadFixtureJson('manifest.json'));
  const result = sdk.validateFixtureBundle({ manifest, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_UNLISTED_ASSET' && issue.path === '$/documents/manifest.json'));
});

test('a failing manifest preflight stops before any supplied document is touched or invoked', () => {
  let getterCalls = 0;
  const hostileDocument = { protocol_version: '1.0.0' };
  Object.defineProperty(hostileDocument, 'schema_version', {
    get: () => { getterCalls += 1; return '1.0.0'; },
    enumerable: true,
  });
  const documents = loadAllDocuments();
  documents.set('state.json', hostileDocument);
  // Rewrite the state entry path so the manifest preflight itself fails.
  const mutated = JSON.parse(JSON.stringify(manifest)) as { assets: Array<{ path: string }> };
  mutated.assets.find((a) => a.path === 'state.json')!.path = '../escape.json';
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents }, schema);
  assert.equal(result.valid, false);
  assert.equal(getterCalls, 0, 'no document getter may be invoked when the manifest preflight fails');
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_UNSAFE_PATH'));
  assert.ok(
    !result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_DIGEST_DRIFT' || issue.code === 'AIPT_LOSSY_JSON_VALUE'),
    `preflight failure must return before hashing/interpreting documents, got ${JSON.stringify(result.issues.map((issue) => issue.code))}`,
  );
});

test('bundle wrapper and documents collection inspect descriptors only (no accessor invocation)', () => {
  let wrapperCalls = 0;
  let documentsCalls = 0;
  const bundle: Record<string, unknown> = {
    manifest,
    documents: loadAllDocuments(),
    schema,
  };
  Object.defineProperty(bundle, 'manifest', {
    get: () => { wrapperCalls += 1; return manifest; },
    enumerable: true,
  });
  let result = sdk.validateFixtureBundle(bundle, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_MANIFEST'));
  assert.equal(wrapperCalls, 0, 'wrapper accessors must never be invoked');

  const documentsObject: Record<string, unknown> = {};
  for (const [key, value] of loadAllDocuments()) documentsObject[key] = value;
  Object.defineProperty(documentsObject, 'state.json', {
    get: () => { documentsCalls += 1; return loadFixtureJson('state.json'); },
    enumerable: true,
  });
  result = sdk.validateFixtureBundle({ manifest, documents: documentsObject }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_MANIFEST'));
  assert.equal(documentsCalls, 0, 'documents-collection accessors must never be invoked');
});
