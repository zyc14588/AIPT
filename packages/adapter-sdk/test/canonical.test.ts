// Deterministic canonical JSON / SHA-256 tests against the shared fixture
// manifest digests, plus lossy-value rejections.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { loadFixtureJson, loadFixtureText } from './helpers.ts';

class Box {
  readonly value: number;
  constructor(value: number) {
    this.value = value;
  }
}

function lossyCode(fn: () => unknown): string {
  assert.throws(fn, sdk.ProtocolValidationError);
  try {
    fn();
  } catch (err) {
    if (err instanceof sdk.ProtocolValidationError) {
      assert.ok(err.issues.length > 0, 'lossy rejection must carry issues');
      return err.issues.map((issue) => issue.code).join(',');
    }
  }
  return 'no-throw';
}

test('canonical JSON serialization is deterministic and key-order independent', () => {
  const a = { z: [1, 2], a: { y: true, x: null } };
  const b = { a: { x: null, y: true }, z: [1, 2] };
  const first = sdk.canonicalJsonString(a);
  const second = sdk.canonicalJsonString(b);
  assert.equal(first, second);
  assert.equal(first, '{"a":{"x":null,"y":true},"z":[1,2]}');
  assert.deepEqual(JSON.parse(first) as unknown, JSON.parse(second) as unknown);
});

test('SHA-256 of every shared fixture asset matches the manifest digests', () => {
  const manifest = loadFixtureJson('manifest.json') as unknown as sdk.FixtureManifest;
  for (const entry of [...manifest.assets, ...manifest.mutants]) {
    const doc = loadFixtureJson(entry.path);
    const digest = sdk.sha256Hex(doc);
    assert.equal(digest, entry.sha256, `digest drift for ${entry.path}`);
    assert.match(digest, /^[0-9a-f]{64}$/);
  }
});

test('replay assertion final_state_hash equals the recomputed SHA-256', () => {
  const assertion = loadFixtureJson('replay-assertion.json');
  const finalState = loadFixtureJson('final-state.json');
  const computed = sdk.sha256Hex(finalState);
  assert.equal(computed, assertion.final_state_hash);
  for (const replay of assertion.replays as Array<{ final_state_hash: string }>) {
    assert.equal(replay.final_state_hash, computed);
  }
});

test('lossy canonical values are rejected, never silently coerced', () => {
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const arrayCycle: unknown[] = [];
  arrayCycle.push(arrayCycle);
  const accessor: Record<string, unknown> = {};
  Object.defineProperty(accessor, 'x', { get: () => 1, enumerable: true });
  const nonEnumerable = { x: 1 };
  Object.defineProperty(nonEnumerable, 'x', { value: 1, enumerable: false });
  const symbolKeyed = { [Symbol('k')]: 1 };
  const cases: Array<[string, unknown]> = [
    ['cycle', cycle],
    ['array cycle', arrayCycle],
    ['undefined', undefined],
    ['function', () => 0],
    ['symbol', Symbol('s')],
    ['bigint', 1n],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
    ['unsafe integer', Number.MAX_SAFE_INTEGER + 1],
    ['unsafe negative integer', -Number.MAX_SAFE_INTEGER - 1],
    ['-0', -0],
    ['class instance', new Box(1)],
    ['Date', new Date(0)],
    ['Map', new Map([['a', 1]])],
    ['Set', new Set([1])],
    ['accessor property', accessor],
    ['non-enumerable property', nonEnumerable],
    ['symbol-keyed property', symbolKeyed],
    ['nested unsafe integer', { deep: { value: Number.MAX_SAFE_INTEGER + 1 } }],
  ];
  for (const [label, value] of cases) {
    const code = lossyCode(() => sdk.canonicalJson(value));
    assert.equal(code, 'AIPT_LOSSY_JSON_VALUE', `${label} must be rejected with AIPT_LOSSY_JSON_VALUE`);
    const hashCode = lossyCode(() => sdk.sha256Hex(value));
    assert.equal(hashCode, 'AIPT_LOSSY_JSON_VALUE', `${label} must be rejected by sha256Hex too`);
  }
});

test('finite safe numbers and JSON values serialize faithfully', () => {
  const value = { n: 1.5, i: 0, s: 'text', b: false, n2: null, arr: [[1], 'a'], neg: -3.25 };
  const text = sdk.canonicalJsonString(value);
  assert.deepEqual(JSON.parse(text) as unknown, value);
  assert.equal(sdk.sha256Hex(value), sdk.sha256Hex(JSON.parse(text) as unknown));
});
