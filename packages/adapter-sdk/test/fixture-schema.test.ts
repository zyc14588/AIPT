// Iteration 4B fixture contract: manifest preflight (canonical consts, path
// form, duplicate paths, exact kind -> schema_ref map, mutant cardinality),
// per-document canonical-schema instance validation, and the mutant semantic
// proof — all pure over caller-supplied parsed data with the canonical
// schema passed in as the explicit validation boundary.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { loadFixtureJson, loadSchema } from './helpers.ts';

const schema = loadSchema();
const manifest = loadFixtureJson('manifest.json') as unknown as sdk.FixtureManifest;

function loadAllDocuments(): Map<string, unknown> {
  const documents = new Map<string, unknown>();
  for (const entry of [...manifest.assets, ...manifest.mutants]) {
    documents.set(entry.path, loadFixtureJson(entry.path));
  }
  return documents;
}

function tamper(fn: (copy: Record<string, unknown>) => void): Record<string, unknown> {
  const copy = JSON.parse(JSON.stringify(manifest)) as Record<string, unknown>;
  fn(copy);
  return copy;
}

function codesOf(result: sdk.ValidationResult): string[] {
  return result.issues.map((issue) => issue.code);
}

// ---- 1. Manifest preflight: canonical consts, paths, duplicates, ref map ----

test('manifest consts: expected_final_state and replay_assertion are frozen canonical values', () => {
  const wrongFinal = tamper((m) => { (m as { expected_final_state: string }).expected_final_state = 'other.json'; });
  let result = sdk.validateFixtureManifest(wrongFinal);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_INVALID_VALUE' && issue.path === '$/expected_final_state'));

  const wrongReplay = tamper((m) => { (m as { replay_assertion: string }).replay_assertion = 'other.json'; });
  result = sdk.validateFixtureManifest(wrongReplay);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_INVALID_VALUE' && issue.path === '$/replay_assertion'));
});

test('manifest path preflight rejects escape, absolute, backslash, empty-segment, and dot paths', () => {
  const cases: Array<[string, string]> = [
    ['../escape.json', '$/assets/1/path'],
    ['/etc/passwd', '$/assets/1/path'],
    ['a\\b.json', '$/assets/1/path'],
    ['a//b.json', '$/assets/1/path'],
    ['a/./b.json', '$/assets/1/path'],
    ['a/../b.json', '$/assets/1/path'],
    ['', '$/assets/1/path'],
  ];
  for (const [badPath, expectedPath] of cases) {
    const mutated = tamper((m) => {
      const assets = (m as { assets: Array<{ path: string }> }).assets;
      assets.find((a) => a.path === 'state.json')!.path = badPath;
    });
    const result = sdk.validateFixtureManifest(mutated);
    assert.equal(result.valid, false, `accepted path ${JSON.stringify(badPath)}`);
    assert.ok(
      result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_UNSAFE_PATH' && issue.path === expectedPath),
      `path ${JSON.stringify(badPath)} must be rejected with AIPT_FIXTURE_UNSAFE_PATH at ${expectedPath}, got ${JSON.stringify(codesOf(result))}`,
    );
  }
});

test('manifest kind -> schema_ref uses the exact canonical map (state -> projection rejected)', () => {
  const mutated = tamper((m) => {
    const assets = (m as { assets: Array<{ path: string; schema_ref: string }> }).assets;
    assets.find((a) => a.path === 'state.json')!.schema_ref = '#/$defs/projection';
  });
  const result = sdk.validateFixtureManifest(mutated);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH' && issue.path === '$/assets/1/schema_ref'));

  const mutantRef = tamper((m) => { (m as { mutants: Array<{ schema_ref: string }> }).mutants[0].schema_ref = '#/$defs/projection'; });
  const mutantResult = sdk.validateFixtureManifest(mutantRef);
  assert.equal(mutantResult.valid, false);
  assert.ok(mutantResult.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH' && issue.path === '$/mutants/0/schema_ref'));
});

test('manifest duplicate paths across assets and mutants are rejected deterministically', () => {
  const duplicated = tamper((m) => {
    const assets = (m as { assets: unknown[] }).assets;
    assets.push(JSON.parse(JSON.stringify(assets[0])));
  });
  const result = sdk.validateFixtureManifest(duplicated);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_DUPLICATE_PATH' && issue.path === '$/assets/14/path'));
});

test('manifest mutant cardinality and rejection const are exact', () => {
  const zeroMutants = tamper((m) => { (m as { mutants: unknown[] }).mutants = []; });
  assert.equal(sdk.validateFixtureManifest(zeroMutants).valid, false);

  const twoMutants = tamper((m) => {
    const mutants = (m as { mutants: unknown[] }).mutants;
    mutants.push(JSON.parse(JSON.stringify(mutants[0])));
  });
  assert.equal(sdk.validateFixtureManifest(twoMutants).valid, false);

  const wrongRejection = tamper((m) => { (m as { mutants: Array<{ expected_semantic_rejection: string }> }).mutants[0].expected_semantic_rejection = 'AIPT_OTHER'; });
  const rejectionResult = sdk.validateFixtureManifest(wrongRejection);
  assert.equal(rejectionResult.valid, false);
  assert.ok(rejectionResult.issues.some((issue) => issue.path === '$/mutants/0/expected_semantic_rejection'));
});

// ---- 2. Bundle attacks: every confirmed false acceptance fails closed ----

test('bundle attack (a): identity-triple-only state.json with an updated digest is rejected by schema validation', () => {
  const identityOnly = { protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic' };
  const mutated = tamper((m) => {
    const assets = (m as { assets: Array<{ path: string; sha256: string }> }).assets;
    assets.find((a) => a.path === 'state.json')!.sha256 = sdk.sha256Hex(identityOnly);
  });
  const documents = loadAllDocuments();
  documents.set('state.json', identityOnly);
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_VIOLATION' && issue.path.startsWith('$/documents/state.json')));
});

test('bundle attack (b): state entry schema_ref changed to projection fails preflight', () => {
  const mutated = tamper((m) => {
    const assets = (m as { assets: Array<{ path: string; schema_ref: string }> }).assets;
    assets.find((a) => a.path === 'state.json')!.schema_ref = '#/$defs/projection';
  });
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents: loadAllDocuments() }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH'));
});

test('bundle attack (c): duplicated manifest entry fails preflight', () => {
  const mutated = tamper((m) => {
    const assets = (m as { assets: unknown[] }).assets;
    assets.push(JSON.parse(JSON.stringify(assets[0])));
  });
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents: loadAllDocuments() }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_DUPLICATE_PATH'));
});

test('bundle attack (d): digest-correct neutral mutant (authorized seat-b projection) fails the semantic proof', () => {
  const neutral = JSON.parse(JSON.stringify(loadFixtureJson('mutants/hidden-leak.json'))) as { projection: unknown };
  neutral.projection = loadFixtureJson('projection-seat-b.json');
  const mutated = tamper((m) => {
    (m as { mutants: Array<{ sha256: string }> }).mutants[0].sha256 = sdk.sha256Hex(neutral);
  });
  const documents = loadAllDocuments();
  documents.set('mutants/hidden-leak.json', neutral);
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(
    result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT'),
    `neutral mutant must fail the semantic proof, got ${JSON.stringify(codesOf(result))}`,
  );
});

test('bundle attack (e): state path rewritten to ../escape.json fails preflight before any document processing', () => {
  const mutated = tamper((m) => {
    const assets = (m as { assets: Array<{ path: string }> }).assets;
    assets.find((a) => a.path === 'state.json')!.path = '../escape.json';
  });
  const documents = loadAllDocuments();
  documents.delete('state.json');
  documents.set('../escape.json', loadFixtureJson('state.json'));
  const result = sdk.validateFixtureBundle({ manifest: mutated, documents }, schema);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_UNSAFE_PATH'));
});

test('bundle validation requires the canonical schema boundary and stops before hashing on preflight failure', () => {
  const withoutSchema = sdk.validateFixtureBundle({ manifest, documents: loadAllDocuments() });
  assert.equal(withoutSchema.valid, false);
  assert.ok(withoutSchema.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  const lossyDocuments = loadAllDocuments();
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  lossyDocuments.set('state.json', cycle);
  const lossyResult = sdk.validateFixtureBundle({ manifest, documents: lossyDocuments }, schema);
  assert.equal(lossyResult.valid, false);
  assert.ok(lossyResult.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path.startsWith('$/documents/state.json')));
});

test('the bundle carries the schema boundary alternatively via the bundle.schema member', () => {
  const result = sdk.validateFixtureBundle({ manifest, documents: loadAllDocuments(), schema });
  assert.equal(result.valid, true, JSON.stringify(result.issues));
});

// ---- 3. Every fixture document validates against its expected $defs target ----

test('every shared fixture asset validates against its independently expected canonical $defs target', () => {
  for (const entry of [...manifest.assets, ...manifest.mutants]) {
    const document = loadFixtureJson(entry.path);
    const expectedRef = (sdk.CONTRACT_DESCRIPTOR.manifest_kind_schema_refs as Record<string, string>)[entry.kind];
    const result = sdk.validateSchemaInstance(schema, document, expectedRef, '$');
    assert.equal(result.valid, true, `${entry.path} must validate against ${expectedRef}: ${JSON.stringify(result.issues)}`);
  }
});

// ---- 4. Evaluator fail-closed behavior over the supported subset ----

test('the package-local evaluator implements the canonical subset deterministically', () => {
  const state = loadFixtureJson('state.json');
  // structural violations, each at a deterministic path
  const missingField = JSON.parse(JSON.stringify(state)) as Record<string, unknown>;
  (missingField as { fields: unknown[] }).fields = [];
  let result = sdk.validateSchemaInstance(schema, missingField, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_VIOLATION' && issue.path === '$/fields'));

  const extraMember = { ...state, sneaky: true };
  result = sdk.validateSchemaInstance(schema, extraMember, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_VIOLATION' && issue.path === '$/sneaky'));

  const badPattern = JSON.parse(JSON.stringify(state)) as { fields: Array<{ field_id: string }> };
  badPattern.fields[0].field_id = 'Bad Field!';
  result = sdk.validateSchemaInstance(schema, badPattern, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_VIOLATION' && issue.path === '$/fields/0/field_id'));

  // iteration 4C: the evaluator itself owns the lossless JSON-value gate for
  // its schema AND instance inputs — a lossy instance document fails closed
  // with AIPT_LOSSY_JSON_VALUE before any schema evaluation (and the
  // evaluator never crashes on it).
  const lossyDocument = { fields: [{ field_id: 'f-1', value: undefined, visibility: { label: 'PUBLIC', authorized_seat_ids: ['s'] } }], protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'f-1', state_id: 's-1' };
  result = sdk.validateSchemaInstance(schema, lossyDocument, '#/$defs/state', '$');
  assert.equal(result.valid, false, 'a lossy instance document must fail the evaluator input gate');
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/fields/0/value'));
});

test('the evaluator fails closed on unsupported keywords, unresolvable refs, and ref cycles', () => {
  const withFormat = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
  (withFormat.$defs as Record<string, unknown>).state = { type: 'object', format: 'anything' };
  let result = sdk.validateSchemaInstance(withFormat, {}, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  result = sdk.validateSchemaInstance(schema, {}, '#/$defs/not-a-def', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  const cyclic = {
    $defs: {
      a: { $ref: '#/$defs/b' },
      b: { $ref: '#/$defs/a' },
    },
  };
  result = sdk.validateSchemaInstance(cyclic, {}, '#/$defs/a', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  result = sdk.validateSchemaInstance(null, {}, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));
});

// ---- 5. Iteration 4C: canonical schema fingerprint binding ----

test('bundle validation binds the supplied schema to the exact canonical fingerprint', () => {
  const documents = loadAllDocuments();

  // A description-only schema edit (everything else identical) must fail
  // with AIPT_FIXTURE_INVALID_SCHEMA before any document processing.
  const drifted = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
  drifted.description = `${drifted.description} (drifted)`;
  let result = sdk.validateFixtureBundle({ manifest, documents }, drifted);
  assert.equal(result.valid, false);
  assert.deepEqual(
    result.issues.map((issue) => issue.code),
    ['AIPT_FIXTURE_INVALID_SCHEMA'],
    'fingerprint drift must be the single stable rejection',
  );
  assert.ok(result.issues[0].path === '$/schema');

  // A missing schema boundary fails the same way.
  result = sdk.validateFixtureBundle({ manifest, documents });
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  // A lossy schema document fails with AIPT_FIXTURE_INVALID_SCHEMA.
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  result = sdk.validateFixtureBundle({ manifest, documents }, cyclic);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA' && issue.path === '$/schema'));

  // validateSchemaInstance remains the general package-local evaluator: the
  // real schema still evaluates shared fixture documents.
  const stateResult = sdk.validateSchemaInstance(schema, loadFixtureJson('state.json'), '#/$defs/state', '$');
  assert.equal(stateResult.valid, true, JSON.stringify(stateResult.issues));
});

// ---- 6. Iteration 4C: deterministic schema-grammar preflight ----

test('the schema-grammar preflight rejects malformed keyword shapes anywhere in the document', () => {
  const state = loadFixtureJson('state.json');
  const cases: Array<[string, (s: Record<string, unknown>) => void]> = [
    ['format hidden in a passing anyOf branch', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      defs.state = { anyOf: [{ type: 'object', format: 'anything' }, { type: 'object' }] };
    }],
    ['format hidden inside not', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      defs.state = { type: 'object', not: { type: 'object', format: 'anything' } };
    }],
    ['minLength with a string value', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      defs.state = { type: 'object', properties: { state_id: { type: 'string', minLength: 'four' } } };
    }],
    ['properties as an array', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      defs.state = { type: 'object', properties: [{ type: 'string' }] };
    }],
    ['additionalProperties as a string', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      defs.state = { type: 'object', additionalProperties: 'nope' };
    }],
    ['unsupported type name', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      defs.state = { type: 'file' };
    }],
    ['malformed keyword in an unreferenced $defs child', (s) => {
      const defs = s.$defs as Record<string, Record<string, unknown>>;
      (defs.deterministic_check.properties as Record<string, Record<string, unknown>>).operator.type = 'file';
    }],
  ];
  for (const [label, mutate] of cases) {
    const malformed = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
    mutate(malformed);
    const result = sdk.validateSchemaInstance(malformed, state, '#/$defs/state', '$');
    assert.equal(result.valid, false, `accepted ${label}`);
    assert.ok(
      result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'),
      `${label} must be rejected with AIPT_FIXTURE_INVALID_SCHEMA, got ${JSON.stringify(result.issues.map((issue) => issue.code))}`,
    );
  }
});

test('the grammar preflight accepts the exact canonical schema and still rejects ref hazards', () => {
  const state = loadFixtureJson('state.json');
  const result = sdk.validateSchemaInstance(schema, state, '#/$defs/state', '$');
  assert.equal(result.valid, true, JSON.stringify(result.issues));

  // External refs, unresolvable refs, and ref cycles remain rejections.
  const external = { $defs: { state: { $ref: 'https://example.com/schema.json' } } };
  assert.equal(sdk.validateSchemaInstance(external, {}, '#/$defs/state', '$').valid, false);

  const unresolvable = { $defs: { state: { $ref: '#/$defs/ghost' } } };
  assert.equal(sdk.validateSchemaInstance(unresolvable, {}, '#/$defs/state', '$').valid, false);

  const cyclic = { $defs: { a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } } };
  const cyclicResult = sdk.validateSchemaInstance(cyclic, {}, '#/$defs/a', '$');
  assert.equal(cyclicResult.valid, false);
  assert.ok(cyclicResult.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));
});
