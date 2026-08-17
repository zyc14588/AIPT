// Lossless JSON-value gates at every trust boundary (iteration 4B).
//
// The canonical schema intentionally accepts ANY JSON value at
// `state_field.value` and `action_intent_params.proposal`, and parseJson
// returns JsonValue: each of those boundaries must reject every value JSON
// cannot faithfully represent — cycles, undefined/function/symbol/bigint,
// non-finite numbers, unsafe integers, -0, accessors/non-enumerables/symbol
// keys, non-plain objects, sparse arrays — with AIPT_LOSSY_JSON_VALUE, and
// must never mutate the caller's input.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';

function lossyCodes(fn: () => unknown): string[] {
  assert.throws(fn, sdk.ProtocolValidationError);
  try {
    fn();
  } catch (err) {
    if (err instanceof sdk.ProtocolValidationError) {
      return err.issues.map((issue) => issue.code);
    }
  }
  throw new Error('expected a ProtocolValidationError');
}

function makeRequest(params: unknown): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: 'probe-id',
    method: 'aipt.protocol.applyAction',
    params,
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'minimal-v1-arithmetic',
  };
}

test('validateJsonValue returns an invalid ValidationResult (never throws) for every lossy value', () => {
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const accessor: Record<string, unknown> = {};
  Object.defineProperty(accessor, 'x', { get: () => 1, enumerable: true });
  const nonEnumerable = { x: 1 };
  Object.defineProperty(nonEnumerable, 'x', { value: 1, enumerable: false });
  const symbolKeyed = { [Symbol('k')]: 1 };
  class Box { readonly value = 1; }
  const sparse: unknown[] = [];
  sparse.length = 2;
  sparse[1] = 'x';
  const extraProp = [1];
  (extraProp as Record<string, unknown>).extra = 'x';
  const cases: Array<[string, unknown, string]> = [
    ['cycle', cycle, '$/self'],
    ['undefined', undefined, '$'],
    ['function', () => 0, '$'],
    ['symbol', Symbol('s'), '$'],
    ['bigint', 1n, '$'],
    ['NaN', Number.NaN, '$'],
    ['Infinity', Number.POSITIVE_INFINITY, '$'],
    ['unsafe integer', Number.MAX_SAFE_INTEGER + 1, '$'],
    ['-0', -0, '$'],
    ['class instance', new Box(), '$'],
    ['Date', new Date(0), '$'],
    ['Map', new Map([['a', 1]]), '$'],
    ['accessor property', accessor, '$/x'],
    ['non-enumerable property', nonEnumerable, '$/x'],
    ['symbol-keyed property', symbolKeyed, '$'],
    ['sparse-array hole', sparse, '$/0'],
    ['non-index array property', extraProp, '$/extra'],
    ['nested unsafe integer', { deep: { n: Number.MAX_SAFE_INTEGER + 1 } }, '$/deep/n'],
  ];
  for (const [label, value, expectedPath] of cases) {
    const result = sdk.validateJsonValue(value);
    assert.equal(result.valid, false, `${label} must be invalid`);
    assert.ok(result.issues.length > 0, `${label} must carry issues`);
    assert.ok(result.issues.every((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE'), `${label} issues must all be AIPT_LOSSY_JSON_VALUE`);
    assert.ok(result.issues.some((issue) => issue.path === expectedPath), `${label} must address ${expectedPath}, got ${result.issues.map((issue) => issue.path).join(',')}`);
  }
});

test('validateJsonValue accepts ordinary JSON without mutation (shared references included)', () => {
  const shared = { n: 1 };
  const input = { a: [1, 'x', null, true, 1.5], b: shared, c: shared, empty: {}, arr: [] };
  const snapshot = JSON.stringify(input);
  const result = sdk.validateJsonValue(input);
  assert.equal(result.valid, true, JSON.stringify(result.issues));
  assert.deepEqual([...result.issues], []);
  assert.equal(JSON.stringify(input), snapshot, 'the caller input must not be mutated');
  const required = sdk.requireJsonValue(input);
  assert.deepEqual(required as unknown, input);
  assert.equal(JSON.stringify(input), snapshot, 'requireJsonValue must not mutate either');
});

test('toJsonRpcRequest rejects params.proposal undefined and function at the proposal path', () => {
  const withUndefined = makeRequest({ action: 'advance-turn', seat_id: 'seat-a', proposal: undefined });
  const codes = lossyCodes(() => sdk.toJsonRpcRequest(withUndefined));
  assert.deepEqual(codes, ['AIPT_LOSSY_JSON_VALUE']);
  try {
    sdk.toJsonRpcRequest(withUndefined);
  } catch (err) {
    assert.ok(err instanceof sdk.ProtocolValidationError);
    assert.equal(err.issues[0].path, '$/params/proposal');
  }
  const withFunction = makeRequest({ action: 'advance-turn', seat_id: 'seat-a', proposal: () => 0 });
  assert.deepEqual(lossyCodes(() => sdk.toJsonRpcRequest(withFunction)), ['AIPT_LOSSY_JSON_VALUE']);
});

test('toJsonRpcResponse rejects applied_fields value undefined at the value path', () => {
  const response = {
    jsonrpc: '2.0',
    id: 'probe-id',
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'minimal-v1-arithmetic',
    result: {
      accepted: true,
      transition_id: 'transition-turn-increment',
      applied_fields: [{ field_id: 'turn-count', value: undefined, visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-a'] } }],
    },
  };
  const codes = lossyCodes(() => sdk.toJsonRpcResponse(response));
  assert.deepEqual(codes, ['AIPT_LOSSY_JSON_VALUE']);
  try {
    sdk.toJsonRpcResponse(response);
  } catch (err) {
    assert.ok(err instanceof sdk.ProtocolValidationError);
    assert.equal(err.issues[0].path, '$/result/applied_fields/0/value');
  }
});

test('state field values and nested JSON values pass the lossless gate through shape validation', () => {
  const state = {
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'minimal-v1-arithmetic',
    state_id: 'initial',
    fields: [{ field_id: 'f-1', value: { deep: [undefined] }, visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-a'] } }],
  };
  const result = sdk.validateStateShape(state);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/fields/0/value/deep/0'));
});

test('parseJson rejects silently rounding and non-finite numbers; valid JSON still parses', () => {
  assert.deepEqual(lossyCodes(() => sdk.parseJson('9007199254740993')), ['AIPT_LOSSY_JSON_VALUE']);
  assert.deepEqual(lossyCodes(() => sdk.parseJson('-9007199254740993')), ['AIPT_LOSSY_JSON_VALUE']);
  assert.deepEqual(lossyCodes(() => sdk.parseJson('{"n":9007199254740993}')), ['AIPT_LOSSY_JSON_VALUE']);
  assert.deepEqual(lossyCodes(() => sdk.parseJson('1e400')), ['AIPT_LOSSY_JSON_VALUE']);
  assert.deepEqual(sdk.parseJson('9007199254740991'), 9007199254740991);
  assert.deepEqual(sdk.parseJson('-9007199254740991'), -9007199254740991);
  assert.deepEqual(sdk.parseJson('1.5'), 1.5);
  assert.deepEqual(sdk.parseJson('"text"'), 'text');
  assert.deepEqual(sdk.parseJson('[1,true,null]'), [1, true, null]);
  const decoded = sdk.decodeRequest('{"jsonrpc":"2.0","id":42,"method":"aipt.protocol.applyAction","params":{"action":"a","seat_id":"s","proposal":{"x":1}},"protocol_version":"1.0.0","schema_version":"1.0.0","fixture_id":"f-1"}');
  assert.equal(decoded.id, 42);
});

test('encodeRequest/encodeResponse/encodeNotification re-run the lossless gate', () => {
  const request = makeRequest({ action: 'advance-turn', seat_id: 'seat-a', proposal: () => 0 });
  assert.deepEqual(lossyCodes(() => sdk.encodeRequest(request)), ['AIPT_LOSSY_JSON_VALUE']);
  const response = {
    jsonrpc: '2.0',
    id: 'probe-id',
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'minimal-v1-arithmetic',
    result: {
      accepted: true,
      transition_id: 't-1',
      applied_fields: [{ field_id: 'f-1', value: Number.NaN, visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-a'] } }],
    },
  };
  assert.deepEqual(lossyCodes(() => sdk.encodeResponse(response)), ['AIPT_LOSSY_JSON_VALUE']);
});

test('typed builders reject lossy params values', () => {
  const codes = lossyCodes(() => sdk.buildRequest('id-1', { action: 'advance-turn', seat_id: 'seat-a', proposal: undefined }, 'minimal-v1-arithmetic'));
  assert.deepEqual(codes, ['AIPT_LOSSY_JSON_VALUE']);
});

// ---- iteration 4C: descriptor-only inspection, zero getter/setter calls ----

test('validateJsonValue rejects array symbol keys, non-enumerable extras, and accessor indices', () => {
  const symbolKeyed: unknown[] = [1];
  Object.defineProperty(symbolKeyed, Symbol('k'), { value: 1, enumerable: true });
  let result = sdk.validateJsonValue(symbolKeyed);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE'));

  const nonEnumerable = [1];
  Object.defineProperty(nonEnumerable, 'extra', { value: 1, enumerable: false });
  result = sdk.validateJsonValue(nonEnumerable);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/extra'));

  let getterCalls = 0;
  const accessorIndex = [1];
  Object.defineProperty(accessorIndex, 1, { get: () => { getterCalls += 1; return 2; }, enumerable: true });
  result = sdk.validateJsonValue(accessorIndex);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/1'));
  assert.equal(getterCalls, 0, 'array index accessors must never be invoked while validating');

  // The engine invariant makes an accessor `length` unrepresentable on a
  // real array (even via a Proxy trap), so the built-in length descriptor is
  // always a data descriptor; the walker still checks it defensively. A
  // dense ordinary array with only the built-in length descriptor passes.
  assert.equal(sdk.validateJsonValue([1, 2, 3]).valid, true);
});

test('validateJsonValue never invokes object getters/setters, even after detecting them', () => {
  let getterCalls = 0;
  let setterCalls = 0;
  const accessor: Record<string, unknown> = {};
  Object.defineProperty(accessor, 'x', {
    get: () => { getterCalls += 1; return 1; },
    set: () => { setterCalls += 1; },
    enumerable: true,
  });
  const result = sdk.validateJsonValue(accessor);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/x'));
  assert.equal(getterCalls, 0, 'the rejected accessor getter must never be invoked — not even once after detection');
  assert.equal(setterCalls, 0, 'the rejected accessor setter must never be invoked');

  // A rejected accessor nested inside an otherwise valid object.
  let nestedCalls = 0;
  const nested = { ok: 1, bad: 0 };
  Object.defineProperty(nested, 'bad', { get: () => { nestedCalls += 1; return 0; }, enumerable: true });
  const nestedResult = sdk.validateJsonValue(nested);
  assert.equal(nestedResult.valid, false);
  assert.equal(nestedCalls, 0, 'nested rejected accessors must never be invoked');
});

test('validateJsonValue accepts repeated non-ancestral shared references and ordinary JSON untouched', () => {
  const shared = { n: 1 };
  const input = { a: [1, 2], b: shared, c: shared };
  const snapshot = JSON.stringify(input);
  assert.equal(sdk.validateJsonValue(input).valid, true);
  assert.equal(JSON.stringify(input), snapshot, 'the caller input must not be mutated');
});

test('whole-value lossless gates reject symbol-keyed/non-enumerable/accessor envelope members without invocation', () => {
  const request = makeRequest({ action: 'advance-turn', seat_id: 'seat-a' });
  const symbolKeyed = { ...request };
  Object.defineProperty(symbolKeyed, Symbol('trace'), { value: 1, enumerable: true });
  let codes = lossyCodes(() => sdk.toJsonRpcRequest(symbolKeyed));
  assert.deepEqual(codes, ['AIPT_LOSSY_JSON_VALUE']);

  const nonEnumerable = { ...request };
  Object.defineProperty(nonEnumerable, 'trace', { value: 1, enumerable: false });
  codes = lossyCodes(() => sdk.toJsonRpcRequest(nonEnumerable));
  assert.deepEqual(codes, ['AIPT_LOSSY_JSON_VALUE']);

  let getterCalls = 0;
  const accessorMember = { ...request };
  Object.defineProperty(accessorMember, 'params', {
    get: () => { getterCalls += 1; return request.params; },
    enumerable: true,
  });
  codes = lossyCodes(() => sdk.toJsonRpcRequest(accessorMember));
  assert.deepEqual(codes, ['AIPT_LOSSY_JSON_VALUE']);
  assert.equal(getterCalls, 0, 'envelope accessor members must never be invoked while validating');
});

test('required-member bypass via explicit undefined own members fails the whole-value gate', () => {
  const request = makeRequest({ action: 'advance-turn', seat_id: 'seat-a' });
  const bypass = { ...request, params: undefined };
  try {
    sdk.toJsonRpcRequest(bypass);
    assert.fail('an explicit undefined params member must be rejected, not skipped');
  } catch (err) {
    assert.ok(err instanceof sdk.ProtocolValidationError);
    assert.ok(err.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/params'), JSON.stringify(err.issues));
  }

  const result = sdk.validateExecutableRoot(bypass);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/params'), JSON.stringify(result.issues));
});

test('id = -0 and unsafe-integer error.code fail closed at their exact paths', () => {
  const request = makeRequest({ action: 'advance-turn', seat_id: 'seat-a' });
  try {
    sdk.toJsonRpcRequest({ ...request, id: -0 });
    assert.fail('-0 id must be rejected');
  } catch (err) {
    assert.ok(err instanceof sdk.ProtocolValidationError);
    assert.ok(err.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/id'), JSON.stringify(err.issues));
  }

  const errorResponse = {
    jsonrpc: '2.0',
    id: 'probe-id',
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'minimal-v1-arithmetic',
    error: { code: Number.MAX_SAFE_INTEGER + 1, message: 'unsafe integer code' },
  };
  try {
    sdk.toJsonRpcErrorResponse(errorResponse);
    assert.fail('unsafe integer error.code must be rejected');
  } catch (err) {
    assert.ok(err instanceof sdk.ProtocolValidationError);
    assert.ok(err.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/error/code'), JSON.stringify(err.issues));
  }
});

test('validateFixtureManifest and validateSchemaInstance reject lossy inputs with AIPT_LOSSY_JSON_VALUE', () => {
  const manifest = {
    protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'f-1', fixture_name: 'inline',
    expected_final_state: 'final-state.json', replay_assertion: 'replay-assertion.json',
    assets: [], mutants: [],
  };
  const symbolKeyed = { ...manifest };
  Object.defineProperty(symbolKeyed, Symbol('sneak'), { value: 1, enumerable: true });
  let result = sdk.validateFixtureManifest(symbolKeyed);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE'));

  const cyclicSchema: Record<string, unknown> = {};
  cyclicSchema.self = cyclicSchema;
  result = sdk.validateSchemaInstance(cyclicSchema, {}, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE'));

  const lossyDocument = { x: undefined };
  result = sdk.validateSchemaInstance({ $defs: { state: { type: 'object' } } }, lossyDocument, '#/$defs/state', '$');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_LOSSY_JSON_VALUE' && issue.path === '$/x'));
});
