// Iteration 4D evaluator repair: focused regression tests for every
// confirmed original-implementation defect in the package-local canonical
// JSON Schema 2020-12 subset evaluator (validateSchemaInstance):
//
//   - the schema-grammar preflight observes caller mutations of the SAME
//     schema object (no object-identity preflight cache);
//   - local $ref cycles are rejected over the COMPLETE local-ref graph,
//     including cycles inside unused $defs children, while acyclic
//     shared-target refs and repeated non-ancestral JS object aliases stay
//     valid;
//   - the declared grammar is internally truthful: `required: []` is valid,
//     duplicate required members / type names / JSON-equal enum values are
//     malformed, annotation shapes are enforced, and `$schema`/`$id`/`$defs`
//     are structural root-only keywords ($schema exactly the 2020-12 URI);
//   - decimal `multipleOf` uses the independent oracle's deterministic
//     1e-9 tolerance;
//   - external/unresolvable refs remain deterministic invalid-schema
//     failures, and the canonical schema + shared fixture still pass.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { loadFixtureJson, loadSchema } from './helpers.ts';

const schema = loadSchema();
const state = loadFixtureJson('state.json');

function codesOf(result: sdk.ValidationResult): string[] {
  return result.issues.map((issue) => issue.code);
}

function withDef(target: unknown, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { $defs: { ...extra, x: target } };
}

// ---- 1. The preflight observes caller mutations of the same schema object ----

test('a malformed keyword shape mutated into the same schema object after a PASS is rejected by the next call', () => {
  const mutable = { $defs: { x: { type: 'string', minLength: 1 } } };
  const before = sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
  assert.equal(before.valid, true, JSON.stringify(before.issues));
  // Mutate the SAME object the first call just accepted.
  (mutable.$defs as Record<string, { minLength: unknown }>).x.minLength = 'not-a-number';
  const after = sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
  assert.equal(after.valid, false, 'the mutated keyword shape must be observed, not served from a stale cache');
  assert.ok(after.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'), JSON.stringify(after.issues));
});

test('an unsupported keyword added to an unreferenced definition after a PASS is rejected by the next call', () => {
  const mutable = { $defs: { x: { type: 'string' }, spare: { type: 'number' } } };
  const before = sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
  assert.equal(before.valid, true, JSON.stringify(before.issues));
  // Add an unsupported keyword under the SAME unreferenced spare object.
  (mutable.$defs as Record<string, Record<string, unknown>>).spare.format = 'uuid';
  const after = sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
  assert.equal(after.valid, false, 'the newly added unsupported keyword must be observed, not served from a stale cache');
  assert.ok(after.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'), JSON.stringify(after.issues));
});

// ---- 2. Whole-document local $ref cycle detection ----

test('a local $ref cycle inside an unused definition is rejected before instance evaluation', () => {
  // The requested target #/$defs/x is a plain object; the a -> b -> a cycle
  // lives in definitions the requested ref never reaches.
  const cyclic = { $defs: { x: { type: 'object' }, a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } } };
  const result = sdk.validateSchemaInstance(cyclic, {}, '#/$defs/x', '$');
  assert.equal(result.valid, false);
  assert.ok(codesOf(result).every((code) => code === 'AIPT_FIXTURE_INVALID_SCHEMA'), JSON.stringify(result.issues));
  assert.ok(
    result.issues.some((issue) => issue.message.includes('circular local $ref chain')),
    `the rejection must name the circular ref chain, got ${JSON.stringify(result.issues)}`,
  );

  // A direct self-reference is the same rejection.
  const selfRef = { $defs: { x: { $ref: '#/$defs/x' } } };
  const selfResult = sdk.validateSchemaInstance(selfRef, {}, '#/$defs/x', '$');
  assert.equal(selfResult.valid, false);
  assert.ok(selfResult.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));
});

test('acyclic shared-target refs and repeated non-ancestral JS object aliases stay valid', () => {
  const shared = { type: 'string' };
  const dag = {
    $defs: {
      target: { type: 'string' },
      a: { $ref: '#/$defs/target' },
      b: { $ref: '#/$defs/target' },
      props: { type: 'object', properties: { p1: shared, p2: shared } },
    },
  };
  // Diamond refs onto one shared target are an acyclic DAG, and the same
  // JS object appearing twice via ordinary containment is an alias, not a
  // cycle.
  assert.equal(sdk.validateSchemaInstance(dag, 's', '#/$defs/a', '$').valid, true);
  assert.equal(sdk.validateSchemaInstance(dag, 's', '#/$defs/b', '$').valid, true);
  const propsResult = sdk.validateSchemaInstance(dag, { p1: 'one', p2: 'two' }, '#/$defs/props', '$');
  assert.equal(propsResult.valid, true, JSON.stringify(propsResult.issues));
});

// ---- 3. Truthful declared grammar ----

test('required: [] is valid JSON Schema 2020-12 and is accepted', () => {
  const result = sdk.validateSchemaInstance(withDef({ type: 'object', required: [] }), {}, '#/$defs/x', '$');
  assert.equal(result.valid, true, JSON.stringify(result.issues));
});

test('duplicate required member names are rejected', () => {
  const result = sdk.validateSchemaInstance(withDef({ type: 'object', required: ['a', 'a'] }), { a: 1 }, '#/$defs/x', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA' && issue.message.includes('must not repeat member names')), JSON.stringify(result.issues));
});

test('type arrays must be non-empty, hold only supported type names, and contain no duplicates', () => {
  const duplicate = sdk.validateSchemaInstance(withDef({ type: ['string', 'string'] }), 'a', '#/$defs/x', '$');
  assert.equal(duplicate.valid, false, 'duplicate type names are malformed');
  assert.ok(duplicate.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA' && issue.message.includes('must not repeat type names')), JSON.stringify(duplicate.issues));

  const empty = sdk.validateSchemaInstance(withDef({ type: [] }), 'a', '#/$defs/x', '$');
  assert.equal(empty.valid, false, 'an empty type array is malformed');

  const unsupported = sdk.validateSchemaInstance(withDef({ type: 'file' }), 'a', '#/$defs/x', '$');
  assert.equal(unsupported.valid, false, 'an unsupported type name is malformed');

  // A valid supported union still evaluates.
  const union = sdk.validateSchemaInstance(withDef({ type: ['string', 'number'] }), 3, '#/$defs/x', '$');
  assert.equal(union.valid, true, JSON.stringify(union.issues));
});

test('enum must be non-empty and JSON-semantically unique', () => {
  const dupNumbers = sdk.validateSchemaInstance(withDef({ enum: [1, 1] }), 1, '#/$defs/x', '$');
  assert.equal(dupNumbers.valid, false);
  assert.ok(
    dupNumbers.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA' && issue.message.includes('entries 0 and 1')),
    `duplicate enum members must be rejected deterministically, got ${JSON.stringify(dupNumbers.issues)}`,
  );

  // JSON-semantic equality: key order inside object members is irrelevant.
  const dupObjects = sdk.validateSchemaInstance(withDef({ enum: [{ a: 1, b: 2 }, { b: 2, a: 1 }] }), { a: 1, b: 2 }, '#/$defs/x', '$');
  assert.equal(dupObjects.valid, false);
  assert.ok(dupObjects.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  const empty = sdk.validateSchemaInstance(withDef({ enum: [] }), 1, '#/$defs/x', '$');
  assert.equal(empty.valid, false, 'an empty enum is malformed');

  const unique = sdk.validateSchemaInstance(withDef({ enum: [1, 'one', null] }), 'one', '#/$defs/x', '$');
  assert.equal(unique.valid, true, JSON.stringify(unique.issues));
});

test('annotation shapes: title, description, and $comment must be strings', () => {
  for (const [keyword, bad] of [['title', 7], ['description', ['x']], ['$comment', null]] as Array<[string, unknown]>) {
    const result = sdk.validateSchemaInstance(withDef({ type: 'string', [keyword]: bad }), 'a', '#/$defs/x', '$');
    assert.equal(result.valid, false, `annotation ${keyword} must be a string`);
    assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'), JSON.stringify(result.issues));
  }
});

test('annotation shapes: examples must be an array, deprecated must be a boolean, default may be any lossless JSON value', () => {
  const badExamples = sdk.validateSchemaInstance(withDef({ type: 'string', examples: 'nope' }), 'a', '#/$defs/x', '$');
  assert.equal(badExamples.valid, false, 'examples must be an array');
  assert.ok(badExamples.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  const badDeprecated = sdk.validateSchemaInstance(withDef({ type: 'string', deprecated: 'yes' }), 'a', '#/$defs/x', '$');
  assert.equal(badDeprecated.valid, false, 'deprecated must be a boolean');
  assert.ok(badDeprecated.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));

  // default carries no validation semantics; any lossless JSON value is
  // accepted (and valid annotation shapes stay accepted).
  const good = sdk.validateSchemaInstance(
    withDef({ type: 'object', examples: [1, 'two'], deprecated: false, default: { nested: [1, 'x'] } }),
    {},
    '#/$defs/x',
    '$',
  );
  assert.equal(good.valid, true, JSON.stringify(good.issues));
});

test('structural keywords are root-only: nested $schema, $id, and $defs are rejected', () => {
  const nestedCases: Array<[string, Record<string, unknown>]> = [
    ['$schema', { type: 'object', $schema: 'https://json-schema.org/draft/2020-12/schema' }],
    ['$id', { type: 'object', $id: 'urn:test:x' }],
    ['$defs', { type: 'object', $defs: { y: { type: 'string' } } }],
  ];
  for (const [keyword, target] of nestedCases) {
    const result = sdk.validateSchemaInstance(withDef(target), {}, '#/$defs/x', '$');
    assert.equal(result.valid, false, `nested ${keyword} must be rejected, never silently ignored`);
    assert.ok(
      result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA' && issue.message.includes('root-only')),
      `nested ${keyword} rejection must name the root-only rule, got ${JSON.stringify(result.issues)}`,
    );
  }
});

test('root $schema must be the exact 2020-12 URI, root $id must be a string, and synthetic schemas need no $schema', () => {
  const wrongUri = sdk.validateSchemaInstance(
    { $schema: 'https://json-schema.org/draft-07/schema', $defs: { x: { type: 'string' } } },
    'a',
    '#/$defs/x',
    '$',
  );
  assert.equal(wrongUri.valid, false);
  assert.ok(wrongUri.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA' && issue.message.includes('https://json-schema.org/draft/2020-12/schema')));

  const badId = sdk.validateSchemaInstance({ $id: 7, $defs: { x: { type: 'string' } } }, 'a', '#/$defs/x', '$');
  assert.equal(badId.valid, false);

  const withMeta = sdk.validateSchemaInstance(
    { $schema: 'https://json-schema.org/draft/2020-12/schema', $id: 'urn:test:x', $defs: { x: { type: 'string' } } },
    'a',
    '#/$defs/x',
    '$',
  );
  assert.equal(withMeta.valid, true, JSON.stringify(withMeta.issues));

  const synthetic = sdk.validateSchemaInstance({ $defs: { x: { type: 'string' } } }, 'a', '#/$defs/x', '$');
  assert.equal(synthetic.valid, true, JSON.stringify(synthetic.issues));
});

// ---- 4. Decimal multipleOf ----

test('decimal multipleOf uses the deterministic 1e-9 tolerance', () => {
  const doc = { $defs: { x: { type: 'number', multipleOf: 0.1 } } };
  // 0.3 / 0.1 = 2.9999999999999996 in binary floating point; the exact
  // integer-division comparison used to reject it.
  const multiple = sdk.validateSchemaInstance(doc, 0.3, '#/$defs/x', '$');
  assert.equal(multiple.valid, true, `0.3 must be a multiple of 0.1, got ${JSON.stringify(multiple.issues)}`);
  assert.equal(sdk.validateSchemaInstance(doc, 1, '#/$defs/x', '$').valid, true);
  assert.equal(sdk.validateSchemaInstance(doc, 0, '#/$defs/x', '$').valid, true);

  // Nearby non-multiples must still fail: the tolerance must not turn
  // arbitrary values into passes.
  for (const nonMultiple of [0.35, 0.30000001]) {
    const result = sdk.validateSchemaInstance(doc, nonMultiple, '#/$defs/x', '$');
    assert.equal(result.valid, false, `${nonMultiple} must NOT be a multiple of 0.1`);
    assert.ok(result.issues.some((issue) => issue.code === 'AIPT_FIXTURE_SCHEMA_VIOLATION'), JSON.stringify(result.issues));
  }
});

// ---- 5. External/unresolved refs and the canonical PASS ----

test('external and unresolvable refs remain deterministic invalid-schema failures', () => {
  const external = { $defs: { x: { $ref: 'https://example.com/schema.json' } } };
  const externalFirst = sdk.validateSchemaInstance(external, {}, '#/$defs/x', '$');
  const externalSecond = sdk.validateSchemaInstance(external, {}, '#/$defs/x', '$');
  assert.equal(externalFirst.valid, false);
  assert.ok(externalFirst.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));
  assert.deepEqual(
    externalFirst.issues.map((issue) => [issue.path, issue.code, issue.message]),
    externalSecond.issues.map((issue) => [issue.path, issue.code, issue.message]),
    'repeated calls must produce the identical deterministic rejection',
  );

  const unresolvable = { $defs: { x: { $ref: '#/$defs/ghost' } } };
  const unresolvableFirst = sdk.validateSchemaInstance(unresolvable, {}, '#/$defs/x', '$');
  assert.equal(unresolvableFirst.valid, false);
  assert.ok(unresolvableFirst.issues.some((issue) => issue.code === 'AIPT_FIXTURE_INVALID_SCHEMA'));
  assert.deepEqual(
    unresolvableFirst.issues.map((issue) => [issue.path, issue.code, issue.message]),
    sdk.validateSchemaInstance(unresolvable, {}, '#/$defs/x', '$').issues.map((issue) => [issue.path, issue.code, issue.message]),
    'repeated calls must produce the identical deterministic rejection',
  );
});

test('the canonical schema and the shared fixture still pass the repaired evaluator', () => {
  const result = sdk.validateSchemaInstance(schema, state, '#/$defs/state', '$');
  assert.equal(result.valid, true, JSON.stringify(result.issues));
  // The full canonical schema document still passes the grammar preflight
  // (structural root keywords, annotations, and the whole $defs tree).
  const codes = codesOf(result);
  assert.deepEqual(codes, []);
});
