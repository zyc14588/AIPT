// Wire error-code namespace (iteration 4B): ErrorObject.data.error_code is
// the OPEN canonical wire namespace (any string matching
// ^AIPT_[A-Z0-9_]{1,63}$, runtime-enforced), while ValidationIssue.code
// remains the FINITE stable SDK union. A canonical-valid future wire code
// such as AIPT_FUTURE_EXTENSION must decode and round-trip; non-pattern
// values must be rejected.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';

function makeErrorResponse(errorCode: unknown): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id: 'probe-id',
    protocol_version: '1.0.0',
    schema_version: '1.0.0',
    fixture_id: 'minimal-v1-arithmetic',
    error: { code: -32000, message: 'probe', data: { error_code: errorCode } },
  };
}

test('a canonical-valid future AIPT_* wire error code decodes and is preserved verbatim', () => {
  const decoded = sdk.decodeResponse(JSON.stringify(makeErrorResponse('AIPT_FUTURE_EXTENSION')));
  assert.ok('error' in decoded && !('result' in decoded));
  assert.equal(decoded.error.data?.error_code, 'AIPT_FUTURE_EXTENSION');
  const reEncoded = sdk.encodeResponse(decoded);
  const again = sdk.decodeResponse(reEncoded);
  assert.ok('error' in again);
  assert.equal(again.error.data?.error_code, 'AIPT_FUTURE_EXTENSION');
});

test('non-pattern wire error_code values are rejected with AIPT_INVALID_VALUE', () => {
  for (const bad of ['NOT_AIPT', 'AIPT_', 'aipt_action_rejected', 'AIPT_FUTURE!', 'AIPT_BAD CODE', 7, null, {}]) {
    assert.throws(
      () => sdk.decodeResponse(JSON.stringify(makeErrorResponse(bad))),
      (err: unknown) => {
        assert.ok(err instanceof sdk.ProtocolValidationError);
        return err.issues.some((issue) => issue.code === 'AIPT_INVALID_VALUE' && issue.path === '$/error/data/error_code');
      },
      `accepted bad error_code ${JSON.stringify(bad)}`,
    );
  }
});

test('a wire error code longer than the 63-suffix bound is rejected', () => {
  const tooLong = `AIPT_${'X'.repeat(64)}`;
  assert.ok(tooLong.length > 63);
  assert.throws(() => sdk.decodeResponse(JSON.stringify(makeErrorResponse(tooLong))), sdk.ProtocolValidationError);
});

test('isAiptWireErrorCode enforces the exact canonical pattern at runtime', () => {
  assert.equal(sdk.isAiptWireErrorCode('AIPT_FUTURE_EXTENSION'), true);
  assert.equal(sdk.isAiptWireErrorCode('AIPT_ACTION_REJECTED'), true);
  assert.equal(sdk.isAiptWireErrorCode('AIPT_1'), true);
  assert.equal(sdk.isAiptWireErrorCode('AIPT_'.padEnd(5 + 63, 'X')), true, '63-char suffix is allowed');
  assert.equal(sdk.isAiptWireErrorCode('AIPT_'.padEnd(5 + 64, 'X')), false, '64-char suffix exceeds the bound');
  assert.equal(sdk.isAiptWireErrorCode('NOT_AIPT'), false);
  assert.equal(sdk.isAiptWireErrorCode('AIPT_bad'), false);
  assert.equal(sdk.isAiptWireErrorCode(''), false);
  assert.equal(sdk.isAiptWireErrorCode(7), false);
  assert.equal(sdk.isAiptWireErrorCode(null), false);
  assert.equal(sdk.isAiptWireErrorCode(undefined), false);
});

test('ValidationIssue.code stays the finite SDK union and never widens to arbitrary strings', () => {
  // Runtime check: every exported SDK code is an element of the finite set;
  // a foreign wire code is NOT usable as a validation-issue code (the issue
  // helper is typed against the finite union, and the finite set never
  // contains the future wire code).
  const finite = new Set(sdk.AIPT_ERROR_CODES);
  for (const code of ['AIPT_MALFORMED_JSON', 'AIPT_LOSSY_JSON_VALUE', 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT']) {
    assert.ok(finite.has(code), `${code} must be a finite SDK code`);
  }
  assert.ok(!finite.has('AIPT_FUTURE_EXTENSION'), 'the future wire code is NOT an SDK validation-issue code');
  assert.equal(new Set(sdk.AIPT_ERROR_CODES).size, sdk.AIPT_ERROR_CODES.length, 'SDK codes stay unique');
  const issue = sdk.issue('$/x', 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH', 'probe');
  assert.deepEqual(issue, { path: '$/x', code: 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH', message: 'probe' });
});

test('the persisted deterministic protocol error response still decodes with its canonical code', async () => {
  const { loadFixtureText } = await import('./helpers.ts');
  const decoded = sdk.decodeResponse(loadFixtureText('responses/apply-action-protocol-error-response.json'));
  assert.ok('error' in decoded);
  assert.equal(decoded.error.data?.error_code, 'AIPT_ACTION_REJECTED');
  assert.equal(sdk.isAiptWireErrorCode(decoded.error.data.error_code), true);
});
