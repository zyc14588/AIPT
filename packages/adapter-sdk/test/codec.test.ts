// Codec tests: the four persisted wire envelopes, typed builders,
// parse/encode round trips, id preservation, and negative envelope cases.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { loadFixtureJson, loadFixtureText } from './helpers.ts';

const FIXTURE_ID = 'minimal-v1-arithmetic';
const WIRE = {
  request: 'requests/apply-action-request.json',
  result: 'responses/apply-action-result-response.json',
  error: 'responses/apply-action-protocol-error-response.json',
  notification: 'notifications/state-event-notification.json',
};

function codes(fn: () => unknown): string[] {
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

test('all four persisted wire envelopes validate against the executable root', () => {
  for (const rel of Object.values(WIRE)) {
    const doc = sdk.parseExecutableRoot(loadFixtureText(rel));
    assert.equal(doc.jsonrpc, '2.0', rel);
    assert.equal(doc.protocol_version, '1.0.0', rel);
    assert.equal(doc.schema_version, '1.0.0', rel);
    assert.equal(doc.fixture_id, FIXTURE_ID, rel);
  }
  const request = sdk.decodeRequest(loadFixtureText(WIRE.request));
  assert.equal(request.method, 'aipt.protocol.applyAction');
  const result = sdk.decodeResponse(loadFixtureText(WIRE.result));
  assert.ok('result' in result && !('error' in result), 'result response carries result, not error');
  const error = sdk.decodeResponse(loadFixtureText(WIRE.error));
  assert.ok('error' in error && !('result' in error), 'error response carries error, not result');
  assert.equal(error.error.data?.error_code, 'AIPT_ACTION_REJECTED');
  const notification = sdk.decodeNotification(loadFixtureText(WIRE.notification));
  assert.equal(notification.method, 'aipt.protocol.event');
  assert.ok(!('id' in notification), 'notification carries no id');
});

test('persisted request/response ids round-trip by value and JSON type', () => {
  const request = sdk.decodeRequest(loadFixtureText(WIRE.request));
  const result = sdk.decodeResponse(loadFixtureText(WIRE.result));
  const error = sdk.decodeResponse(loadFixtureText(WIRE.error));
  assert.equal(typeof request.id, 'string');
  assert.deepEqual(result.id, request.id);
  assert.equal(typeof result.id, typeof request.id);
  assert.deepEqual(error.id, request.id);
  assert.equal(typeof error.id, typeof request.id);
});

test('parse/encode round trip is deterministic for every persisted envelope', () => {
  for (const rel of Object.values(WIRE)) {
    const first = sdk.parseExecutableRoot(loadFixtureText(rel));
    const encoded = sdk.encodeExecutableRoot(first);
    const second = sdk.parseExecutableRoot(encoded);
    assert.deepEqual(JSON.parse(encoded) as unknown, JSON.parse(loadFixtureText(rel)) as unknown, `${rel} canonical re-encode must equal the persisted document`);
    assert.deepEqual(JSON.parse(sdk.encodeExecutableRoot(second)) as unknown, JSON.parse(encoded) as unknown, `${rel} second encode must be byte-identical in value`);
    assert.equal(sdk.encodeExecutableRoot(second), encoded, `${rel} encode must be deterministic`);
  }
});

test('typed builders produce contract-valid envelopes', () => {
  const fixture = loadFixtureJson(WIRE.request);
  const params = fixture.params as sdk.ActionIntentParams;
  const request = sdk.buildRequest(fixture.id as sdk.RequestId, params, FIXTURE_ID);
  assert.equal(request.method, 'aipt.protocol.applyAction');
  const roundTrip = sdk.decodeRequest(sdk.encodeRequest(request));
  assert.deepEqual(roundTrip.params, params);

  const resultDoc = loadFixtureJson(WIRE.result);
  const result = sdk.buildResultResponse(resultDoc.id as sdk.RequestId, resultDoc.result as sdk.ApplyActionResult, FIXTURE_ID);
  assert.ok('result' in result);
  assert.equal(sdk.decodeResponse(sdk.encodeResponse(result)).result.accepted, true);

  const errorDoc = loadFixtureJson(WIRE.error);
  const error = sdk.buildErrorResponse(errorDoc.id as sdk.RequestId, errorDoc.error as sdk.ErrorObject, FIXTURE_ID);
  assert.ok('error' in error);
  const decodedError = sdk.decodeResponse(sdk.encodeResponse(error));
  assert.ok('error' in decodedError);
  assert.equal(decodedError.error.code, -32000);
  assert.equal(decodedError.error.data?.error_code, 'AIPT_ACTION_REJECTED');

  const notificationDoc = loadFixtureJson(WIRE.notification);
  const event = (notificationDoc.params as { event: sdk.StateEvent }).event;
  const notification = sdk.buildNotification(event, FIXTURE_ID);
  assert.deepEqual(sdk.decodeNotification(sdk.encodeNotification(notification)).params.event, event);
});

test('string and numeric ids are preserved by value and JSON type', () => {
  for (const id of ['minimal-v1-arithmetic-request-1', 'id-0', 42, 0, -7]) {
    const request = sdk.buildRequest(id, { action: 'advance-turn', seat_id: 'seat-a' }, FIXTURE_ID);
    const decoded = sdk.decodeRequest(sdk.encodeRequest(request));
    assert.deepEqual(decoded.id, id, `id ${String(id)} round-trips by value`);
    assert.equal(typeof decoded.id, typeof id, `id ${String(id)} round-trips by JSON type`);
  }
});

test('both inclusive safe-integer id boundaries are accepted for request and response', () => {
  for (const id of [sdk.ID_MIN_SAFE_INTEGER, sdk.ID_MAX_SAFE_INTEGER, -9007199254740991, 9007199254740991]) {
    const request = sdk.buildRequest(id, { action: 'advance-turn', seat_id: 'seat-a' }, FIXTURE_ID);
    const decodedRequest = sdk.decodeRequest(sdk.encodeRequest(request));
    assert.deepEqual(decodedRequest.id, id);
    assert.equal(typeof decodedRequest.id, 'number');

    const response = sdk.buildResultResponse(id, {
      accepted: true,
      transition_id: 'transition-turn-increment',
      applied_fields: [{ field_id: 'turn-count', value: 1, visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-a', 'seat-b'] } }],
    }, FIXTURE_ID);
    const decodedResponse = sdk.decodeResponse(sdk.encodeResponse(response));
    assert.deepEqual(decodedResponse.id, id);
    assert.equal(typeof decodedResponse.id, 'number');
  }
});

test('malformed JSON fails closed with AIPT_MALFORMED_JSON', () => {
  assert.deepEqual(codes(() => sdk.decodeRequest('{ nope')), ['AIPT_MALFORMED_JSON']);
  assert.deepEqual(codes(() => sdk.parseExecutableRoot('')), ['AIPT_MALFORMED_JSON']);
});

test('arbitrary root objects fail the executable root', () => {
  const cases = [
    { hello: 'world', jsonrpc: '2.0' },
    {},
    { jsonrpc: '2.0' },
    { jsonrpc: '2.0', id: 1 },
    { jsonrpc: '2.0', method: 'aipt.protocol.applyAction' },
    'not an object',
    42,
    null,
  ];
  for (const value of cases) {
    const result = sdk.validateExecutableRoot(value);
    assert.equal(result.valid, false, `accepted: ${JSON.stringify(value)}`);
    assert.ok(result.issues.some((issue) => issue.code === 'AIPT_UNKNOWN_ENVELOPE'), `wrong reason for ${JSON.stringify(value)}`);
  }
});

test('unknown and missing versions fail closed', () => {
  const base = loadFixtureJson(WIRE.request);
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest({ ...base, protocol_version: '9.9.9' })), ['AIPT_UNKNOWN_VERSION']);
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest({ ...base, schema_version: '9.9.9' })), ['AIPT_UNKNOWN_VERSION']);
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest({ ...base, jsonrpc: '1.0' })), ['AIPT_UNKNOWN_VERSION']);
  const withoutProtocol = { ...base };
  delete withoutProtocol.protocol_version;
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest(withoutProtocol)), ['AIPT_MISSING_REQUIRED']);
  const withoutSchema = { ...base };
  delete withoutSchema.schema_version;
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest(withoutSchema)), ['AIPT_MISSING_REQUIRED']);
});

test('unknown methods fail closed', () => {
  const base = loadFixtureJson(WIRE.request);
  const badRequest = { ...base, method: 'aipt.protocol.workerLifecycle' };
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest(badRequest)), ['AIPT_UNKNOWN_METHOD']);
  const notification = loadFixtureJson(WIRE.notification);
  const badNotification = { ...notification, method: 'aipt.protocol.applyAction' };
  assert.deepEqual(codes(() => sdk.toJsonRpcNotification(badNotification)), ['AIPT_UNKNOWN_METHOD']);
});

test('unsafe and non-integer ids fail closed on request and response', () => {
  const base = loadFixtureJson(WIRE.request);
  const response = loadFixtureJson(WIRE.result);
  for (const id of [sdk.ID_MAX_SAFE_INTEGER + 1, -sdk.ID_MAX_SAFE_INTEGER - 1, 1.5, true, null, ['x']]) {
    assert.deepEqual(codes(() => sdk.toJsonRpcRequest({ ...base, id })), ['AIPT_INVALID_ID'], `request id ${JSON.stringify(id)}`);
    assert.deepEqual(codes(() => sdk.toJsonRpcResponse({ ...response, id })), ['AIPT_INVALID_ID'], `response id ${JSON.stringify(id)}`);
  }
});

test('result+error and neither-result-nor-error responses fail closed', () => {
  const response = loadFixtureJson(WIRE.result);
  const errorDoc = loadFixtureJson(WIRE.error);
  const both = { ...response, error: errorDoc.error };
  assert.deepEqual(codes(() => sdk.toJsonRpcResponse(both)), ['AIPT_RESPONSE_RESULT_ERROR_CONFLICT']);
  const neither = { ...response };
  delete neither.result;
  assert.deepEqual(codes(() => sdk.toJsonRpcResponse(neither)), ['AIPT_RESPONSE_MISSING_RESULT_ERROR']);
});

test('extra properties fail closed where the schema constrains them', () => {
  const base = loadFixtureJson(WIRE.request);
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest({ ...base, trace: 'x' })), ['AIPT_UNKNOWN_FIELD']);
  const withParamExtra = { ...base, params: { ...(base.params as object), trace: 'x' } };
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest(withParamExtra)), ['AIPT_UNKNOWN_FIELD']);
  const notification = loadFixtureJson(WIRE.notification);
  assert.deepEqual(codes(() => sdk.toJsonRpcNotification({ ...notification, id: 1 })), ['AIPT_UNKNOWN_FIELD']);
  const response = loadFixtureJson(WIRE.result);
  assert.deepEqual(codes(() => sdk.toJsonRpcResponse({ ...response, trace: 'x' })), ['AIPT_UNKNOWN_FIELD']);
});

test('missing required data fails closed', () => {
  const base = loadFixtureJson(WIRE.request);
  const withoutParams = { ...base };
  delete withoutParams.params;
  assert.deepEqual(codes(() => sdk.toJsonRpcRequest(withoutParams)), ['AIPT_MISSING_REQUIRED']);
  const response = loadFixtureJson(WIRE.result);
  const withoutJsonrpc = { ...response };
  delete withoutJsonrpc.jsonrpc;
  assert.deepEqual(codes(() => sdk.toJsonRpcResponse(withoutJsonrpc)), ['AIPT_MISSING_REQUIRED']);
  const notification = loadFixtureJson(WIRE.notification);
  const withoutMethod = { ...notification };
  delete withoutMethod.method;
  assert.deepEqual(codes(() => sdk.toJsonRpcNotification(withoutMethod)), ['AIPT_MISSING_REQUIRED']);
  const badError = { code: 1.5, message: '' };
  const errIssues = sdk.toJsonRpcResponse;
  assert.throws(() => errIssues({ ...response, result: undefined, error: badError } as unknown), sdk.ProtocolValidationError);
});

test('unknown visibility labels fail closed with AIPT_UNKNOWN_VISIBILITY', () => {
  const state = loadFixtureJson('state.json');
  const drifted = JSON.parse(JSON.stringify(state)) as { fields: Array<Record<string, unknown>> };
  (drifted.fields[0].visibility as Record<string, unknown>).label = 'TEAM_ONLY';
  const result = sdk.validateStateShape(drifted);
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((issue) => issue.code === 'AIPT_UNKNOWN_VISIBILITY' && issue.path === '$/fields/0/visibility/label'));
});
