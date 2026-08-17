// @aipt/adapter-sdk — AIPT-M0-B002 TypeScript adapter contract SDK.
//
// Dependency-free (Node.js standard library only) public contract for the
// canonical AIPT protocol: constants, types, deterministic canonical JSON /
// SHA-256, strict JSON-RPC 2.0 request/result-response/error-response/
// notification envelopes, semantic projection validation, and fixture
// compatibility helpers. This is the B002 contract SDK, not the later B005
// Harness Adapter runtime.
export {
  PROTOCOL_VERSION,
  SCHEMA_VERSION,
  JSONRPC_VERSION,
  REQUEST_METHODS,
  NOTIFICATION_METHODS,
  METHODS,
  ID_MIN_SAFE_INTEGER,
  ID_MAX_SAFE_INTEGER,
  VISIBILITY_LABELS,
  MANIFEST_KINDS,
  AIPT_ERROR_CODES,
} from './constants.ts';
export { CONTRACT_DESCRIPTOR } from './contract/descriptor.ts';
export type { ContractDescriptor } from './contract/descriptor.ts';
export type {
  JsonPrimitive,
  JsonValue,
  JsonObject,
  ProtocolVersion,
  SchemaVersion,
  JsonRpcVersion,
  RequestMethod,
  NotificationMethod,
  Method,
  VisibilityLabel,
  AiptErrorCode,
  FixtureKind,
  SafeIntegerId,
  RequestId,
  Identifier,
  FixtureId,
  SeatId,
  FieldId,
  ProtocolIdentity,
  Visibility,
  StateField,
  State,
  Projection,
  ActionIntentParams,
  ActionIntent,
  ApplyActionResult,
  Result,
  ErrorObject,
  ProtocolError,
  JsonRpcRequest,
  JsonRpcResultResponse,
  JsonRpcErrorResponse,
  JsonRpcResponse,
  StateEvent,
  JsonRpcNotification,
  ExecutableRoot,
  ManifestAsset,
  ManifestMutant,
  FixtureManifest,
  FixtureBundle,
} from './types.ts';
export { ProtocolValidationError, issue, okResult, failResult } from './errors.ts';
export type { ValidationIssue, ValidationResult } from './errors.ts';
export { canonicalJson, canonicalJsonString, sha256Hex } from './canonical-json.ts';
export {
  isSafeIntegerId,
  validateRequestId,
  validateVisibility,
  validateStateField,
  validateStateShape,
  validateProjectionShape,
  validateExecutableRoot,
} from './validate.ts';
export { validateProjectionSemantics } from './projection.ts';
export { checkFixtureIdentity, validateFixtureManifest, validateFixtureBundle } from './fixture.ts';
export {
  parseJson,
  parseExecutableRoot,
  decodeRequest,
  decodeResponse,
  decodeNotification,
  encodeExecutableRoot,
  encodeRequest,
  encodeResponse,
  encodeNotification,
  toExecutableRoot,
  toJsonRpcRequest,
  toJsonRpcResponse,
  toJsonRpcResultResponse,
  toJsonRpcErrorResponse,
  toJsonRpcNotification,
  buildRequest,
  buildResultResponse,
  buildErrorResponse,
  buildNotification,
} from './codec.ts';
