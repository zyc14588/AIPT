// Canonical constants, descriptor contract, and public export surface.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';

test('canonical version constants match the contract', () => {
  assert.equal(sdk.PROTOCOL_VERSION, '1.0.0');
  assert.equal(sdk.SCHEMA_VERSION, '1.0.0');
  assert.equal(sdk.JSONRPC_VERSION, '2.0');
});

test('registered methods are exactly the canonical registry', () => {
  assert.deepEqual([...sdk.REQUEST_METHODS], ['aipt.protocol.applyAction']);
  assert.deepEqual([...sdk.NOTIFICATION_METHODS], ['aipt.protocol.event']);
  assert.deepEqual([...sdk.METHODS], ['aipt.protocol.applyAction', 'aipt.protocol.event']);
});

test('safe integer id bounds are the inclusive +-(2^53-1) range', () => {
  assert.equal(sdk.ID_MIN_SAFE_INTEGER, -9007199254740991);
  assert.equal(sdk.ID_MAX_SAFE_INTEGER, 9007199254740991);
  assert.equal(sdk.ID_MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
});

test('visibility labels are exactly the six frozen R4-F002 labels', () => {
  assert.deepEqual([...sdk.VISIBILITY_LABELS], [
    'PUBLIC',
    'UNRELEASED_REMOTE_ALLOWED',
    'TABLE_HIDDEN_REMOTE_ALLOWED',
    'LOCAL_ONLY_SECRET',
    'HUMAN_PRIVATE_DATA',
    'CREDENTIAL_SECRET',
  ]);
});

test('every exported AIPT error identifier matches the canonical wire pattern', () => {
  const pattern = /^AIPT_[A-Z0-9_]{1,63}$/;
  for (const code of sdk.AIPT_ERROR_CODES) {
    assert.match(code, pattern, `bad error identifier ${code}`);
  }
  assert.equal(new Set(sdk.AIPT_ERROR_CODES).size, sdk.AIPT_ERROR_CODES.length, 'identifiers must be unique');
  for (const required of ['AIPT_VISIBILITY_UNAUTHORIZED_FIELD', 'AIPT_ACTION_REJECTED', 'AIPT_FIXTURE_IDENTITY_MISMATCH']) {
    assert.ok(sdk.AIPT_ERROR_CODES.includes(required as (typeof sdk.AIPT_ERROR_CODES)[number]), `missing ${required}`);
  }
});

test('contract descriptor mirrors the canonical schema constants', () => {
  const d = sdk.CONTRACT_DESCRIPTOR;
  assert.equal(d.protocol_version, '1.0.0');
  assert.equal(d.schema_version, '1.0.0');
  assert.equal(d.jsonrpc_version, '2.0');
  assert.deepEqual([...d.envelope_variants], ['jsonrpc_request', 'jsonrpc_response', 'jsonrpc_notification']);
  for (const variant of d.envelope_variants) {
    const required = d.envelope_required[variant];
    for (const member of ['protocol_version', 'schema_version', 'fixture_id']) {
      assert.ok(required.includes(member), `${variant} must require ${member}`);
    }
  }
  assert.equal(d.response_result_error_exclusive, true);
  assert.equal(d.id_integer_minimum, -9007199254740991);
  assert.equal(d.id_integer_maximum, 9007199254740991);
  assert.deepEqual([...d.visibility_labels], [...sdk.VISIBILITY_LABELS]);
  assert.deepEqual([...d.manifest_kinds], [...sdk.MANIFEST_KINDS]);
  assert.equal(d.mutant_expected_semantic_rejection, 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD');
});

test('public export surface is present and functional', () => {
  const functions = [
    'parseJson', 'parseExecutableRoot', 'decodeRequest', 'decodeResponse', 'decodeNotification',
    'encodeExecutableRoot', 'encodeRequest', 'encodeResponse', 'encodeNotification',
    'toExecutableRoot', 'toJsonRpcRequest', 'toJsonRpcResponse', 'toJsonRpcResultResponse',
    'toJsonRpcErrorResponse', 'toJsonRpcNotification',
    'buildRequest', 'buildResultResponse', 'buildErrorResponse', 'buildNotification',
    'canonicalJson', 'canonicalJsonString', 'sha256Hex',
    'validateExecutableRoot', 'validateRequestId', 'validateStateShape', 'validateProjectionShape',
    'validateProjectionSemantics', 'validateFixtureManifest', 'validateFixtureBundle',
    'checkFixtureIdentity', 'isSafeIntegerId', 'issue', 'okResult', 'failResult',
  ];
  for (const name of functions) {
    assert.equal(typeof (sdk as unknown as Record<string, unknown>)[name], 'function', `${name} must be exported as a function`);
  }
  assert.equal(typeof sdk.ProtocolValidationError, 'function');
});

test('canonical fixture manifests use only descriptor-registered kinds', () => {
  const kinds = new Set(sdk.MANIFEST_KINDS);
  assert.equal(kinds.size, 11);
  for (const kind of ['seat_set', 'state', 'projection', 'action_intent', 'deterministic_check', 'state_transition', 'state_event', 'replay_assertion', 'jsonrpc_request', 'jsonrpc_response', 'jsonrpc_notification']) {
    assert.ok(kinds.has(kind as (typeof sdk.MANIFEST_KINDS)[number]), `missing kind ${kind}`);
  }
});
