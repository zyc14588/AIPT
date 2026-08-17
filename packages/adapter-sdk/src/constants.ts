// Canonical AIPT protocol constants for the B002 adapter contract SDK.
//
// Every version/method/label/bound below derives from CONTRACT_DESCRIPTOR
// (src/contract/descriptor.ts), the fail-closed drift manifest of the single
// wire authority schemas/protocol/v1/aipt-protocol.schema.json. The machine
// gate scripts/ci/validate/adapter-sdk.mjs re-derives the same values from
// the canonical schema at gate time, so a constants/schema/type drift fails
// the gate instead of passing silently.
import { CONTRACT_DESCRIPTOR as D } from './contract/descriptor.ts';

export const PROTOCOL_VERSION = D.protocol_version;
export const SCHEMA_VERSION = D.schema_version;
export const JSONRPC_VERSION = D.jsonrpc_version;

export const REQUEST_METHODS = D.request_methods;
export const NOTIFICATION_METHODS = D.notification_methods;
export const METHODS = [...REQUEST_METHODS, ...NOTIFICATION_METHODS] as const;

export const ID_MIN_SAFE_INTEGER = D.id_integer_minimum;
export const ID_MAX_SAFE_INTEGER = D.id_integer_maximum;

export const VISIBILITY_LABELS = D.visibility_labels;
export const MANIFEST_KINDS = D.manifest_kinds;

// Stable AIPT validation-issue identifiers used by this contract SDK: the
// FINITE, stable SDK code union (ValidationIssue.code). Every entry satisfies
// the canonical wire error-code pattern ^AIPT_[A-Z0-9_]{1,63}$; the OPEN wire
// namespace itself (every pattern-valid AIPT_* string, e.g. a future
// AIPT_FUTURE_EXTENSION) is the separate branded type AiptWireErrorCode in
// src/types.ts, never widened into this finite union.
export const AIPT_ERROR_CODES = [
  'AIPT_MALFORMED_JSON',
  'AIPT_UNKNOWN_ENVELOPE',
  'AIPT_UNKNOWN_METHOD',
  'AIPT_UNKNOWN_VERSION',
  'AIPT_UNKNOWN_VISIBILITY',
  'AIPT_MISSING_VISIBILITY',
  'AIPT_INVALID_ID',
  'AIPT_INVALID_IDENTIFIER',
  'AIPT_INVALID_VALUE',
  'AIPT_MISSING_REQUIRED',
  'AIPT_UNKNOWN_FIELD',
  'AIPT_RESPONSE_RESULT_ERROR_CONFLICT',
  'AIPT_RESPONSE_MISSING_RESULT_ERROR',
  'AIPT_LOSSY_JSON_VALUE',
  'AIPT_STATE_INVALID',
  'AIPT_PROJECTION_INVALID',
  'AIPT_STATE_DUPLICATE_FIELD_ID',
  'AIPT_VISIBILITY_UNKNOWN_SEAT',
  'AIPT_PROJECTION_UNKNOWN_SEAT',
  'AIPT_PROJECTION_DUPLICATE_FIELD_ID',
  'AIPT_PROJECTION_UNKNOWN_FIELD',
  'AIPT_PROJECTION_VALUE_DRIFT',
  'AIPT_VISIBILITY_RECLASSIFIED',
  'AIPT_VISIBILITY_AUTHORIZATION_DRIFT',
  'AIPT_VISIBILITY_UNAUTHORIZED_FIELD',
  'AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD',
  'AIPT_FIXTURE_IDENTITY_MISMATCH',
  'AIPT_FIXTURE_DIGEST_DRIFT',
  'AIPT_FIXTURE_MISSING_ASSET',
  'AIPT_FIXTURE_UNLISTED_ASSET',
  'AIPT_FIXTURE_INVALID_MANIFEST',
  'AIPT_FIXTURE_UNSAFE_PATH',
  'AIPT_FIXTURE_DUPLICATE_PATH',
  'AIPT_FIXTURE_SCHEMA_REF_MISMATCH',
  'AIPT_FIXTURE_SCHEMA_VIOLATION',
  'AIPT_FIXTURE_INVALID_SCHEMA',
  'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT',
  'AIPT_ACTION_REJECTED',
  'AIPT_PROTOCOL_ERROR_MISMATCHED_ERROR_CODE',
] as const;
