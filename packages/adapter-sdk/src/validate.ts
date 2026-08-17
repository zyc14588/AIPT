// Runtime validation of the canonical AIPT wire contract.
//
// Dependency-free structured validation driven entirely by the contract
// descriptor (src/contract/descriptor.ts), which the machine gate binds
// byte-for-byte to schemas/protocol/v1/aipt-protocol.schema.json. Unknown
// versions, methods, visibility labels, fields, properties, or malformed
// input always fail closed with stable, path-addressed diagnostics; a failed
// validation never returns a partially trusted value. Every schema position
// that intentionally accepts ANY JSON value (`state_field.value`,
// `action_intent_params.proposal`) is gated by the lossless JSON-value
// validator (AIPT_LOSSY_JSON_VALUE), and the wire error namespace is gated
// by isAiptWireErrorCode (open canonical pattern, runtime-enforced).
import { CONTRACT_DESCRIPTOR as D } from './contract/descriptor.ts';
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';
import { validateJsonValue } from './json-value.ts';
import type { AiptErrorCode, AiptWireErrorCode } from './types.ts';

interface Sink {
  issues: ValidationIssue[];
}

function push(sink: Sink, path: string, code: AiptErrorCode, message: string): void {
  sink.issues.push(issue(path, code, message));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

const IDENTIFIER_RE = new RegExp(D.identifier_pattern, 'u');
const SHA256_RE = /^[0-9a-f]{64}$/u;
const ERROR_CODE_RE = new RegExp(D.error_code_pattern, 'u');
const SCHEMA_REF_RE = /^#\/\$defs\/[A-Za-z0-9_-]+$/u;

export function isSafeIntegerId(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= D.id_integer_minimum && value <= D.id_integer_maximum;
}

// The OPEN canonical wire AIPT error namespace: every string matching
// ^AIPT_[A-Z0-9_]{1,63}$ (runtime enforcement). A canonical-valid future
// wire code such as AIPT_FUTURE_EXTENSION is accepted; anything else is
// rejected. This is distinct from the finite SDK ValidationIssue.code union.
export function isAiptWireErrorCode(value: unknown): value is AiptWireErrorCode {
  return typeof value === 'string' && ERROR_CODE_RE.test(value);
}

export function validateRequestId(value: unknown, path = '$/id'): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (typeof value === 'string') {
    const length = [...value].length;
    if (length < D.id_string_min_length || length > D.id_string_max_length) {
      issues.push(issue(path, 'AIPT_INVALID_ID', `string id must be ${D.id_string_min_length}..${D.id_string_max_length} characters long, got ${length}`));
    }
  } else if (isSafeIntegerId(value)) {
    // valid: integer within the inclusive safe-integer range.
  } else {
    issues.push(issue(path, 'AIPT_INVALID_ID', `id must be a string or a safe integer within [${D.id_integer_minimum}, ${D.id_integer_maximum}], got ${typeof value === 'number' ? JSON.stringify(value) : typeof value}`));
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}

function checkIdentifier(value: unknown, path: string, sink: Sink, label: string): void {
  if (typeof value !== 'string' || !IDENTIFIER_RE.test(value)) {
    push(sink, path, 'AIPT_INVALID_IDENTIFIER', `${label} must match ${D.identifier_pattern}, got ${typeof value === 'string' ? JSON.stringify(value) : typeof value}`);
  }
}

function requireMember(sink: Sink, obj: Record<string, unknown>, key: string, path: string): void {
  if (!hasOwn(obj, key)) {
    push(sink, `${path}/${key}`, 'AIPT_MISSING_REQUIRED', `missing required member ${JSON.stringify(key)}`);
  }
}

function rejectExtraMembers(sink: Sink, obj: Record<string, unknown>, allowed: readonly string[], path: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      push(sink, `${path}/${key}`, 'AIPT_UNKNOWN_FIELD', `member ${JSON.stringify(key)} is not allowed (additionalProperties = false)`);
    }
  }
}

function checkProtocolIdentity(sink: Sink, obj: Record<string, unknown>, path: string): void {
  if (hasOwn(obj, 'protocol_version') && obj.protocol_version !== D.protocol_version) {
    push(sink, `${path}/protocol_version`, 'AIPT_UNKNOWN_VERSION', `protocol_version must be exactly ${JSON.stringify(D.protocol_version)}, got ${JSON.stringify(obj.protocol_version)}`);
  }
  if (hasOwn(obj, 'schema_version') && obj.schema_version !== D.schema_version) {
    push(sink, `${path}/schema_version`, 'AIPT_UNKNOWN_VERSION', `schema_version must be exactly ${JSON.stringify(D.schema_version)}, got ${JSON.stringify(obj.schema_version)}`);
  }
  if (hasOwn(obj, 'fixture_id')) {
    checkIdentifier(obj.fixture_id, `${path}/fixture_id`, sink, 'fixture_id');
  }
}

export function validateVisibility(value: unknown, path: string, sink: Sink): void {
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_MISSING_VISIBILITY', 'visibility must be an object');
    return;
  }
  for (const key of D.visibility_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, D.visibility_required, path);
  const label = value.label;
  if (label !== undefined && (!D.visibility_labels.includes(label as (typeof D.visibility_labels)[number]) || typeof label !== 'string')) {
    push(sink, `${path}/label`, 'AIPT_UNKNOWN_VISIBILITY', `unknown visibility label ${JSON.stringify(label)} (exactly ${D.visibility_labels.length} frozen labels exist)`);
  }
  const seats = value.authorized_seat_ids;
  if (seats !== undefined) {
    if (!Array.isArray(seats) || seats.length < D.authorized_seat_ids_min_items) {
      push(sink, `${path}/authorized_seat_ids`, 'AIPT_MISSING_VISIBILITY', `authorized_seat_ids must be an array with at least ${D.authorized_seat_ids_min_items} entry`);
    } else {
      const seen = new Set<string>();
      seats.forEach((seat, index) => {
        checkIdentifier(seat, `${path}/authorized_seat_ids/${index}`, sink, 'seat_id');
        if (typeof seat === 'string') {
          if (seen.has(seat)) push(sink, `${path}/authorized_seat_ids/${index}`, 'AIPT_INVALID_VALUE', `duplicate authorized seat ${JSON.stringify(seat)}`);
          else seen.add(seat);
        }
      });
    }
  }
}

export function validateStateField(value: unknown, path: string, sink: Sink): void {
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'state field must be an object');
    return;
  }
  for (const key of D.state_field_required) {
    if (key === 'visibility') {
      if (!hasOwn(value, key)) push(sink, `${path}/${key}`, 'AIPT_MISSING_VISIBILITY', 'missing required visibility classification (visibility is mandatory metadata, never an optional ordinary field)');
    } else {
      requireMember(sink, value, key, path);
    }
  }
  rejectExtraMembers(sink, value, D.state_field_required, path);
  checkIdentifier(value.field_id, `${path}/field_id`, sink, 'field_id');
  // The schema intentionally accepts ANY JSON value here: every supplied
  // value must pass the lossless JSON-value gate (fail closed, no coercion).
  if (hasOwn(value, 'value')) {
    sink.issues.push(...validateJsonValue(value.value, `${path}/value`).issues);
  }
  if (value.visibility !== undefined) validateVisibility(value.visibility, `${path}/visibility`, sink);
}

export function validateStateShape(value: unknown, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  const sink = { issues };
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_STATE_INVALID', 'state must be a JSON object');
    return failResult(issues);
  }
  for (const key of D.state_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, D.state_required, path);
  checkProtocolIdentity(sink, value, path);
  checkIdentifier(value.state_id, `${path}/state_id`, sink, 'state_id');
  const fields = value.fields;
  if (!Array.isArray(fields) || fields.length < D.fields_min_items) {
    push(sink, `${path}/fields`, 'AIPT_INVALID_VALUE', `fields must be an array with at least ${D.fields_min_items} entry`);
  } else {
    fields.forEach((field, index) => validateStateField(field, `${path}/fields/${index}`, sink));
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}

export function validateProjectionShape(value: unknown, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  const sink = { issues };
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_PROJECTION_INVALID', 'projection must be a JSON object');
    return failResult(issues);
  }
  for (const key of D.projection_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, D.projection_required, path);
  checkProtocolIdentity(sink, value, path);
  checkIdentifier(value.projection_id, `${path}/projection_id`, sink, 'projection_id');
  checkIdentifier(value.seat_id, `${path}/seat_id`, sink, 'seat_id');
  const fields = value.fields;
  if (!Array.isArray(fields) || fields.length < D.fields_min_items) {
    push(sink, `${path}/fields`, 'AIPT_INVALID_VALUE', `fields must be an array with at least ${D.fields_min_items} entry`);
  } else {
    fields.forEach((field, index) => validateStateField(field, `${path}/fields/${index}`, sink));
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}

export function validateActionIntentParams(value: unknown, path: string, sink: Sink): void {
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'params must be an object');
    return;
  }
  for (const key of D.action_intent_params_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, [...D.action_intent_params_required, 'proposal'], path);
  checkIdentifier(value.action, `${path}/action`, sink, 'action');
  checkIdentifier(value.seat_id, `${path}/seat_id`, sink, 'seat_id');
  // The schema intentionally accepts ANY JSON value here: the proposal must
  // pass the lossless JSON-value gate (undefined/function/cycle/unsafe
  // integer/etc. all fail closed).
  if (hasOwn(value, 'proposal')) {
    sink.issues.push(...validateJsonValue(value.proposal, `${path}/proposal`).issues);
  }
}

export function validateApplyActionResult(value: unknown, path: string, sink: Sink): void {
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'result must be an object');
    return;
  }
  for (const key of D.apply_action_result_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, D.apply_action_result_required, path);
  if (value.accepted !== D.apply_action_result_accepted) {
    push(sink, `${path}/accepted`, 'AIPT_INVALID_VALUE', `accepted must be exactly ${JSON.stringify(D.apply_action_result_accepted)}`);
  }
  checkIdentifier(value.transition_id, `${path}/transition_id`, sink, 'transition_id');
  const applied = value.applied_fields;
  if (!Array.isArray(applied) || applied.length < D.applied_fields_min_items) {
    push(sink, `${path}/applied_fields`, 'AIPT_INVALID_VALUE', `applied_fields must be an array with at least ${D.applied_fields_min_items} entry`);
  } else {
    applied.forEach((field, index) => validateStateField(field, `${path}/applied_fields/${index}`, sink));
  }
}

export function validateErrorObject(value: unknown, path: string, sink: Sink): void {
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'error must be an object');
    return;
  }
  for (const key of D.error_object_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, [...D.error_object_required, 'data'], path);
  if (typeof value.code !== 'number' || !Number.isInteger(value.code)) {
    push(sink, `${path}/code`, 'AIPT_INVALID_VALUE', 'error code must be an integer (the contract leaves the JSON-RPC reserved range unconstrained)');
  }
  if (typeof value.message !== 'string' || value.message.length < 1) {
    push(sink, `${path}/message`, 'AIPT_INVALID_VALUE', 'error message must be a non-empty string');
  }
  const data = value.data;
  if (data !== undefined) {
    if (!isRecord(data)) {
      push(sink, `${path}/data`, 'AIPT_INVALID_VALUE', 'error data must be an object');
      return;
    }
    requireMember(sink, data, 'error_code', `${path}/data`);
    rejectExtraMembers(sink, data, ['error_code'], `${path}/data`);
    if (!isAiptWireErrorCode(data.error_code)) {
      push(sink, `${path}/data/error_code`, 'AIPT_INVALID_VALUE', `error_code must match ${D.error_code_pattern} (the open canonical AIPT wire namespace)`);
    }
  }
}

export function validateStateEvent(value: unknown, path: string, sink: Sink): void {
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'event must be an object');
    return;
  }
  for (const key of D.state_event_required) requireMember(sink, value, key, path);
  rejectExtraMembers(sink, value, D.state_event_required, path);
  checkProtocolIdentity(sink, value, path);
  checkIdentifier(value.event_id, `${path}/event_id`, sink, 'event_id');
  checkIdentifier(value.transition_id, `${path}/transition_id`, sink, 'transition_id');
  if (value.event_type !== D.state_event_event_type) {
    push(sink, `${path}/event_type`, 'AIPT_INVALID_VALUE', `event_type must be exactly ${JSON.stringify(D.state_event_event_type)}`);
  }
  const payload = value.payload;
  if (!isRecord(payload)) {
    push(sink, `${path}/payload`, 'AIPT_INVALID_VALUE', 'payload must be an object');
    return;
  }
  for (const key of ['from_state_id', 'to_state_id']) requireMember(sink, payload, key, `${path}/payload`);
  rejectExtraMembers(sink, payload, ['from_state_id', 'to_state_id'], `${path}/payload`);
  checkIdentifier(payload.from_state_id, `${path}/payload/from_state_id`, sink, 'from_state_id');
  checkIdentifier(payload.to_state_id, `${path}/payload/to_state_id`, sink, 'to_state_id');
}

export function validateJsonRpcRequest(value: unknown, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  const sink = { issues };
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'jsonrpc request must be an object');
    return failResult(issues);
  }
  for (const key of D.envelope_required.jsonrpc_request) requireMember(sink, value, key, path);
  if (D.envelope_additional_properties.jsonrpc_request === false) {
    rejectExtraMembers(sink, value, D.envelope_required.jsonrpc_request, path);
  }
  if (hasOwn(value, 'jsonrpc') && value.jsonrpc !== D.jsonrpc_version) {
    push(sink, `${path}/jsonrpc`, 'AIPT_UNKNOWN_VERSION', `jsonrpc must be exactly ${JSON.stringify(D.jsonrpc_version)}, got ${JSON.stringify(value.jsonrpc)}`);
  }
  const idCheck = validateRequestId(value.id, `${path}/id`);
  issues.push(...idCheck.issues);
  if (hasOwn(value, 'method') && value.method !== D.request_methods[0]) {
    push(sink, `${path}/method`, 'AIPT_UNKNOWN_METHOD', `unknown request method ${JSON.stringify(value.method)} (registered: ${D.request_methods.join(', ')})`);
  }
  if (value.params !== undefined) validateActionIntentParams(value.params, `${path}/params`, sink);
  checkProtocolIdentity(sink, value, path);
  return issues.length === 0 ? okResult() : failResult(issues);
}

export function validateJsonRpcNotification(value: unknown, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  const sink = { issues };
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'jsonrpc notification must be an object');
    return failResult(issues);
  }
  for (const key of D.envelope_required.jsonrpc_notification) requireMember(sink, value, key, path);
  if (D.envelope_additional_properties.jsonrpc_notification === false) {
    rejectExtraMembers(sink, value, D.envelope_required.jsonrpc_notification, path);
  }
  if (hasOwn(value, 'jsonrpc') && value.jsonrpc !== D.jsonrpc_version) {
    push(sink, `${path}/jsonrpc`, 'AIPT_UNKNOWN_VERSION', `jsonrpc must be exactly ${JSON.stringify(D.jsonrpc_version)}, got ${JSON.stringify(value.jsonrpc)}`);
  }
  if (hasOwn(value, 'method') && value.method !== D.notification_methods[0]) {
    push(sink, `${path}/method`, 'AIPT_UNKNOWN_METHOD', `unknown notification method ${JSON.stringify(value.method)} (registered: ${D.notification_methods.join(', ')})`);
  }
  const params = value.params;
  if (params !== undefined) {
    if (!isRecord(params)) {
      push(sink, `${path}/params`, 'AIPT_INVALID_VALUE', 'notification params must be an object');
    } else {
      for (const key of D.notification_params_required) requireMember(sink, params, key, `${path}/params`);
      rejectExtraMembers(sink, params, D.notification_params_required, `${path}/params`);
      if (params.event !== undefined) validateStateEvent(params.event, `${path}/params/event`, sink);
    }
  }
  checkProtocolIdentity(sink, value, path);
  return issues.length === 0 ? okResult() : failResult(issues);
}

export function validateJsonRpcResponse(value: unknown, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  const sink = { issues };
  if (!isRecord(value)) {
    push(sink, path, 'AIPT_INVALID_VALUE', 'jsonrpc response must be an object');
    return failResult(issues);
  }
  for (const key of D.envelope_required.jsonrpc_response) requireMember(sink, value, key, path);
  if (D.envelope_additional_properties.jsonrpc_response === false) {
    rejectExtraMembers(sink, value, [...D.envelope_required.jsonrpc_response, 'result', 'error'], path);
  }
  if (hasOwn(value, 'jsonrpc') && value.jsonrpc !== D.jsonrpc_version) {
    push(sink, `${path}/jsonrpc`, 'AIPT_UNKNOWN_VERSION', `jsonrpc must be exactly ${JSON.stringify(D.jsonrpc_version)}, got ${JSON.stringify(value.jsonrpc)}`);
  }
  const idCheck = validateRequestId(value.id, `${path}/id`);
  issues.push(...idCheck.issues);
  const hasResult = hasOwn(value, 'result');
  const hasError = hasOwn(value, 'error');
  if (D.response_result_error_exclusive) {
    if (hasResult && hasError) {
      push(sink, path, 'AIPT_RESPONSE_RESULT_ERROR_CONFLICT', 'response must carry exactly one of result or error, never both');
    } else if (!hasResult && !hasError) {
      push(sink, path, 'AIPT_RESPONSE_MISSING_RESULT_ERROR', 'response must carry exactly one of result or error, never neither');
    } else if (hasResult) {
      validateApplyActionResult(value.result, `${path}/result`, sink);
    } else {
      validateErrorObject(value.error, `${path}/error`, sink);
    }
  }
  checkProtocolIdentity(sink, value, path);
  return issues.length === 0 ? okResult() : failResult(issues);
}

// The executable canonical root: exactly one of the three registered wire
// envelopes must validate. Zero or multiple matching envelopes fail closed
// with a single stable AIPT_UNKNOWN_ENVELOPE rejection.
export function validateExecutableRoot(value: unknown): ValidationResult {
  if (!isRecord(value)) {
    return failResult([issue('$', 'AIPT_UNKNOWN_ENVELOPE', 'executable root must be exactly one registered JSON-RPC envelope (request | response | notification)')]);
  }
  const branches = [
    validateJsonRpcRequest(value),
    validateJsonRpcResponse(value),
    validateJsonRpcNotification(value),
  ];
  const passing = branches.filter((branch) => branch.valid).length;
  if (passing !== 1) {
    return failResult([issue('$', 'AIPT_UNKNOWN_ENVELOPE', `executable root must satisfy exactly one registered envelope (request | response | notification), satisfied ${passing} of ${branches.length}`)]);
  }
  return okResult();
}
