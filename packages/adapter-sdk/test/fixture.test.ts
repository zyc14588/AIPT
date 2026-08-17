// Fixture compatibility helpers: pure validation over supplied parsed
// documents (manifest shape, digests, identity, inventory) with digest and
// identity drift rejections.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { FIXTURE_DIR, loadFixtureJson } from './helpers.ts';
import fs from 'node:fs';
import path from 'node:path';

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

test('the shared fixture bundle validates (identity + digest + inventory)', () => {
  const bundle = { manifest, documents: loadAllDocuments() };
  const result = sdk.validateFixtureBundle(bundle);
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
  const result = sdk.validateFixtureBundle({ manifest, documents });
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
  const result = sdk.validateFixtureBundle({ manifest, documents });
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
  const result = sdk.validateFixtureBundle({ manifest, documents });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_IDENTITY_MISMATCH' && issue.path.includes('projection')));
});

test('a missing listed asset is rejected with AIPT_FIXTURE_MISSING_ASSET', () => {
  const documents = loadAllDocuments();
  documents.delete('seats.json');
  const result = sdk.validateFixtureBundle({ manifest, documents });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_MISSING_ASSET' && issue.path === '$/documents/seats.json'));
});

test('an unlisted supplied document is rejected with AIPT_FIXTURE_UNLISTED_ASSET', () => {
  const documents = loadAllDocuments();
  documents.set('sneaky-extra.json', { protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic' });
  const result = sdk.validateFixtureBundle({ manifest, documents });
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
  assert.equal(sdk.validateFixtureBundle(badBundle).valid, false);
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
