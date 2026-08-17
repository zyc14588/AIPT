// Deterministic parse/decode/encode helpers for the executable canonical
// root and the typed JSON-RPC envelopes, plus typed builders.
//
// - decode* parse strict JSON and validate the parsed document before any
//   typed value is returned (fail closed, path-addressed diagnostics); the
//   parsed output also passes the lossless JSON-value gate, so values
//   JSON.parse would silently round (e.g. 9007199254740993) are rejected.
// - encode* validate then serialize canonically (sorted object keys, arrays
//   in order, no insignificant whitespace), so encode(decode(text)) is
//   deterministic.
// - Request ids round-trip by JSON value AND type (string stays string,
//   number stays number) and integer ids are bounded to the inclusive
//   JavaScript safe-integer range.
import { CONTRACT_DESCRIPTOR as D } from './contract/descriptor.ts';
import { canonicalJsonString } from './canonical-json.ts';
import { ProtocolValidationError, issue, type ValidationResult } from './errors.ts';
import { validateJsonValue } from './json-value.ts';
import type {
  ActionIntentParams,
  ApplyActionResult,
  ErrorObject,
  ExecutableRoot,
  JsonRpcErrorResponse,
  JsonRpcNotification,
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcResultResponse,
  JsonValue,
  RequestId,
  StateEvent,
} from './types.ts';
import {
  validateExecutableRoot,
  validateJsonRpcNotification,
  validateJsonRpcRequest,
  validateJsonRpcResponse,
} from './validate.ts';

function throwOnInvalid(message: string, result: ValidationResult): void {
  if (!result.valid) throw new ProtocolValidationError(message, result.issues);
}

export function parseJson(text: string): JsonValue {
  if (typeof text !== 'string') {
    throw new ProtocolValidationError('parseJson requires a string', [issue('$', 'AIPT_MALFORMED_JSON', 'input is not a string')]);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const detail = err instanceof Error ? err.message : 'unparseable input';
    throw new ProtocolValidationError(`malformed JSON: ${detail}`, [issue('$', 'AIPT_MALFORMED_JSON', `malformed JSON: ${detail}`)]);
  }
  // Fail closed before ANY typed value is returned: JSON.parse itself can
  // lose information silently (e.g. 9007199254740993 -> 9007199254740992,
  // 1e400 -> Infinity), so the parsed output must pass the lossless
  // JSON-value gate.
  const lossless = validateJsonValue(parsed, '$');
  if (!lossless.valid) {
    throw new ProtocolValidationError('parsed document is not a lossless JSON value', lossless.issues);
  }
  return parsed as JsonValue;
}

export function toExecutableRoot(value: unknown): ExecutableRoot {
  throwOnInvalid('executable root validation failed', validateExecutableRoot(value));
  return value as unknown as ExecutableRoot;
}

export function toJsonRpcRequest(value: unknown): JsonRpcRequest {
  throwOnInvalid('jsonrpc request validation failed', validateJsonRpcRequest(value));
  return value as unknown as JsonRpcRequest;
}

export function toJsonRpcResponse(value: unknown): JsonRpcResponse {
  throwOnInvalid('jsonrpc response validation failed', validateJsonRpcResponse(value));
  return value as unknown as JsonRpcResponse;
}

export function toJsonRpcResultResponse(value: unknown): JsonRpcResultResponse {
  const response = toJsonRpcResponse(value);
  if (!('result' in response)) {
    throw new ProtocolValidationError('expected a result response', [issue('$', 'AIPT_RESPONSE_MISSING_RESULT_ERROR', 'response carries no result member')]);
  }
  return response as unknown as JsonRpcResultResponse;
}

export function toJsonRpcErrorResponse(value: unknown): JsonRpcErrorResponse {
  const response = toJsonRpcResponse(value);
  if (!('error' in response)) {
    throw new ProtocolValidationError('expected an error response', [issue('$', 'AIPT_RESPONSE_RESULT_ERROR_CONFLICT', 'response carries no error member')]);
  }
  return response as unknown as JsonRpcErrorResponse;
}

export function toJsonRpcNotification(value: unknown): JsonRpcNotification {
  throwOnInvalid('jsonrpc notification validation failed', validateJsonRpcNotification(value));
  return value as unknown as JsonRpcNotification;
}

export function parseExecutableRoot(text: string): ExecutableRoot {
  return toExecutableRoot(parseJson(text));
}

export function decodeRequest(text: string): JsonRpcRequest {
  return toJsonRpcRequest(parseJson(text));
}

export function decodeResponse(text: string): JsonRpcResponse {
  return toJsonRpcResponse(parseJson(text));
}

export function decodeNotification(text: string): JsonRpcNotification {
  return toJsonRpcNotification(parseJson(text));
}

export function encodeExecutableRoot(value: unknown): string {
  return canonicalJsonString(toExecutableRoot(value));
}

export function encodeRequest(value: unknown): string {
  return canonicalJsonString(toJsonRpcRequest(value));
}

export function encodeResponse(value: unknown): string {
  return canonicalJsonString(toJsonRpcResponse(value));
}

export function encodeNotification(value: unknown): string {
  return canonicalJsonString(toJsonRpcNotification(value));
}

// Typed builders: every builder output is validated before it is returned,
// so a builder either yields a contract-valid envelope or throws.
export function buildRequest(id: RequestId, params: ActionIntentParams, fixtureId: string): JsonRpcRequest {
  return toJsonRpcRequest({
    jsonrpc: D.jsonrpc_version,
    id,
    method: D.request_methods[0],
    params,
    protocol_version: D.protocol_version,
    schema_version: D.schema_version,
    fixture_id: fixtureId,
  });
}

export function buildResultResponse(id: RequestId, result: ApplyActionResult, fixtureId: string): JsonRpcResultResponse {
  return toJsonRpcResultResponse({
    jsonrpc: D.jsonrpc_version,
    id,
    protocol_version: D.protocol_version,
    schema_version: D.schema_version,
    fixture_id: fixtureId,
    result,
  });
}

export function buildErrorResponse(id: RequestId, error: ErrorObject, fixtureId: string): JsonRpcErrorResponse {
  return toJsonRpcErrorResponse({
    jsonrpc: D.jsonrpc_version,
    id,
    protocol_version: D.protocol_version,
    schema_version: D.schema_version,
    fixture_id: fixtureId,
    error,
  });
}

export function buildNotification(event: StateEvent, fixtureId: string): JsonRpcNotification {
  return toJsonRpcNotification({
    jsonrpc: D.jsonrpc_version,
    method: D.notification_methods[0],
    params: { event },
    protocol_version: D.protocol_version,
    schema_version: D.schema_version,
    fixture_id: fixtureId,
  });
}

export { isSafeIntegerId } from './validate.ts';
