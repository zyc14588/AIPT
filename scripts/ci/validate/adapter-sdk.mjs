// AIPT-M0-B002 iteration 4C/4D: @aipt/adapter-sdk machine gate.
//
// Independent, fail-closed comparison of the dependency-free TypeScript
// adapter contract SDK against the single canonical wire authority
// (schemas/protocol/v1/aipt-protocol.schema.json) and the existing shared
// minimal fixture. The SDK embeds a contract drift manifest
// (packages/adapter-sdk/src/contract/descriptor.ts); this gate RE-DERIVES the
// identical descriptor from the canonical schema and requires byte-identical
// canonical JSON (including a FULL canonical-schema content fingerprint, so
// every schema edit — even outside the projected fields — fails the gate
// until the SDK is reviewed). It then audits the ACTUAL declared public
// interface surface of src/types.ts against schema-derived member-shape
// expectations AND schema-derived member TYPE EXPRESSIONS (required/optional/
// discriminant members, declared type expressions, nested object shapes, and
// descriptor-derived const/discriminant types for every public wire and
// fixture interface), behavior-checks the SDK against the persisted wire
// envelopes and fixture assets (digests, projections, the hidden-leak
// mutant, per-document canonical-schema validation, the canonical schema
// fingerprint binding, the ordinary-projection semantic gate, mutant wrapper
// metadata binding, exact inventory), runs fail-closed negative probes for
// every repaired adversarial false acceptance plus in-memory drift probes
// that prove the audit detects previously uncovered schema/type edits,
// audits the SDK sources for ambient-capable imports / environment reads,
// and proves the package is a zero-dependency, side-effect-free import via a
// clean child-process probe.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { parseArgs } from '../lib/cli.mjs';

const SDK_PACKAGE = 'packages/adapter-sdk';
const SDK_INDEX = `${SDK_PACKAGE}/src/index.ts`;
const SDK_SRC_DIR = `${SDK_PACKAGE}/src`;
const SDK_TEST_DIR = `${SDK_PACKAGE}/test`;
const SCHEMA_PATH = 'schemas/protocol/v1/aipt-protocol.schema.json';
const FIXTURE_DIR = 'testdata/protocol/v1/minimal-fixture';
const WIRE_ENVELOPES = [
  'requests/apply-action-request.json',
  'responses/apply-action-result-response.json',
  'responses/apply-action-protocol-error-response.json',
  'notifications/state-event-notification.json',
];

// Independent canonical JSON copy (sorted keys), so a shared serializer
// defect cannot validate itself into PASS.
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function canonicalText(value) {
  return JSON.stringify(canonical(value));
}

// Independent SHA-256 (crypto over the gate's own canonical text): negative
// probes compute tampered digests here, never via the SDK's own hasher, so
// SDK validation can never validate itself into PASS.
function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

const selfSha256 = (value) => sha256Hex(canonicalText(value));

function get(schema, pointerPath) {
  let node = schema;
  for (const part of pointerPath) {
    if (node === null || typeof node !== 'object') return undefined;
    node = node[part];
  }
  return node;
}

// Re-derive the SDK contract descriptor from the canonical schema document.
// This function must be kept in lockstep with the descriptor fields the SDK
// embeds; canonical-JSON equality of the two objects is enforced below. The
// descriptor is a COMPLETE functional projection of the canonical schema for
// the SDK contract, and canonical_schema_sha256 fingerprints the whole
// schema document, so every canonical-schema edit forces explicit SDK review.
function deriveDescriptor(schema) {
  const defs = schema.$defs;
  const requestId = defs.request_id;
  const stringBranch = requestId.oneOf.find((branch) => branch?.type === 'string');
  const responseOneOf = defs.jsonrpc_response.oneOf;
  const exclusive =
    Array.isArray(responseOneOf) &&
    responseOneOf.length === 2 &&
    responseOneOf.some(
      (branch) =>
        Array.isArray(branch?.required) &&
        branch.required.includes('result') &&
        Array.isArray(branch?.not?.required) &&
        branch.not.required.includes('error'),
    ) &&
    responseOneOf.some(
      (branch) =>
        Array.isArray(branch?.required) &&
        branch.required.includes('error') &&
        Array.isArray(branch?.not?.required) &&
        branch.not.required.includes('result'),
    );
  const additional = {};
  for (const variant of ['jsonrpc_request', 'jsonrpc_response', 'jsonrpc_notification']) {
    if (defs[variant]?.additionalProperties === false) additional[variant] = false;
  }
  // Exact kind -> canonical schema_ref map (the manifest-supplied $ref is
  // never trusted; the canonical schema names every $defs target after its
  // kind, and mutant_specimen is the mutant kind's canonical target).
  const kindRefs = {};
  for (const kind of defs.manifest_asset.properties.kind.enum) kindRefs[kind] = `#/$defs/${kind}`;
  kindRefs[defs.manifest_mutant.properties.kind.const] = `#/$defs/${defs.manifest_mutant.properties.kind.const}`;
  return {
    canonical_schema_path: SCHEMA_PATH,
    canonical_schema_sha256: sha256Hex(canonicalText(schema)),
    protocol_version: defs.protocol_version.const,
    schema_version: defs.schema_version.const,
    jsonrpc_version: defs.jsonrpc_version.const,
    request_methods: [defs.jsonrpc_request.properties.method.const],
    notification_methods: [defs.jsonrpc_notification.properties.method.const],
    envelope_variants: schema.oneOf.map((branch) => branch.$ref.replace('#/$defs/', '')),
    envelope_required: {
      jsonrpc_request: defs.jsonrpc_request.required,
      jsonrpc_response: defs.jsonrpc_response.required,
      jsonrpc_notification: defs.jsonrpc_notification.required,
    },
    envelope_additional_properties: additional,
    response_result_error_exclusive: exclusive,
    id_integer_minimum: defs.request_id_integer.minimum,
    id_integer_maximum: defs.request_id_integer.maximum,
    id_string_min_length: stringBranch.minLength,
    id_string_max_length: stringBranch.maxLength,
    visibility_labels: defs.visibility_label.enum,
    error_code_pattern: defs.error_object.properties.data.properties.error_code.pattern,
    identifier_pattern: defs.seat_id.pattern,
    state_field_required: defs.state_field.required,
    visibility_required: defs.visibility.required,
    authorized_seat_ids_min_items: defs.authorized_seat_ids.minItems,
    fields_min_items: defs.state.properties.fields.minItems,
    applied_fields_min_items: defs.apply_action_result.properties.applied_fields.minItems,
    state_required: defs.state.required,
    projection_required: defs.projection.required,
    action_intent_params_required: defs.action_intent_params.required,
    notification_params_required: defs.jsonrpc_notification.properties.params.required,
    state_event_required: defs.state_event.required,
    state_event_event_type: defs.state_event.properties.event_type.const,
    apply_action_result_required: defs.apply_action_result.required,
    apply_action_result_accepted: defs.apply_action_result.properties.accepted.const,
    error_object_required: defs.error_object.required,
    fixture_manifest_required: defs.fixture_manifest.required,
    fixture_manifest_expected_final_state: defs.fixture_manifest.properties.expected_final_state.const,
    fixture_manifest_replay_assertion: defs.fixture_manifest.properties.replay_assertion.const,
    manifest_kinds: defs.manifest_asset.properties.kind.enum,
    manifest_kind_schema_refs: kindRefs,
    mutant_kind: defs.manifest_mutant.properties.kind.const,
    mutant_expected_semantic_rejection: defs.manifest_mutant.properties.expected_semantic_rejection.const,
    deterministic_check_check_version: defs.deterministic_check.properties.check_version.const,
    deterministic_check_kind: defs.deterministic_check.properties.kind.const,
    deterministic_check_operator: defs.deterministic_check.properties.operator.const,
    replay_assertion_hash_algorithm: defs.replay_assertion.properties.hash_algorithm.const,
    replay_assertion_final_state_ref: defs.replay_assertion.properties.final_state_ref.const,
    mutant_specimen_markers: defs.mutant_specimen.properties.markers.const,
    mutant_specimen_kind: defs.mutant_specimen.properties.kind.const,
  };
}

function diffDescriptorKeys(derived, embedded) {
  const diffs = [];
  const keys = new Set([...Object.keys(derived), ...Object.keys(embedded)]);
  for (const key of [...keys].sort()) {
    if (!(key in derived)) diffs.push(`embedded key ${JSON.stringify(key)} is not derivable from the canonical schema`);
    else if (!(key in embedded)) diffs.push(`embedded descriptor is missing schema-derivable key ${JSON.stringify(key)}`);
    else if (canonicalText(derived[key]) !== canonicalText(embedded[key])) {
      diffs.push(`key ${JSON.stringify(key)} drifted: schema says ${canonicalText(derived[key])}, SDK says ${canonicalText(embedded[key])}`);
    }
  }
  return diffs;
}

// ---------------------------------------------------------------------------
// Public type-shape audit: the ACTUAL declared interface surface of
// src/types.ts is parsed deterministically (the file is written in a fixed,
// single-line-member style) and compared against schema-derived
// required/optional/discriminant member expectations. A hand-edited member
// cannot pass silently.
// ---------------------------------------------------------------------------

function deriveTypeShapes(schema) {
  const defs = schema.$defs;
  const identity = ['protocol_version', 'schema_version', 'fixture_id'];
  const fromDef = (def, inheritsIdentity) => {
    const required = (def.required ?? []).filter((key) => !(inheritsIdentity && identity.includes(key)));
    const props = Object.keys(def.properties ?? {}).filter((key) => !(inheritsIdentity && identity.includes(key)));
    return { required, optional: props.filter((key) => !required.includes(key)), never: [] };
  };
  const shapes = {
    ProtocolIdentity: { required: [...identity], optional: [], never: [] },
    Seat: fromDef(defs.seat, false),
    SeatSet: fromDef(defs.seat_set, true),
    Visibility: fromDef(defs.visibility, false),
    StateField: fromDef(defs.state_field, false),
    State: fromDef(defs.state, true),
    Projection: fromDef(defs.projection, true),
    ActionIntentParams: fromDef(defs.action_intent_params, false),
    ActionIntent: fromDef(defs.action_intent, true),
    ApplyActionResult: fromDef(defs.apply_action_result, false),
    ErrorObject: fromDef(defs.error_object, false),
    JsonRpcRequest: fromDef(defs.jsonrpc_request, true),
    JsonRpcNotification: fromDef(defs.jsonrpc_notification, true),
    StateEvent: fromDef(defs.state_event, true),
    DeterministicCheck: fromDef(defs.deterministic_check, true),
    StateTransition: fromDef(defs.state_transition, true),
    ReplayRecord: fromDef(defs.replay_assertion.properties.replays.items, false),
    ReplayAssertion: fromDef(defs.replay_assertion, true),
    MutantSpecimen: fromDef(defs.mutant_specimen, false),
    ManifestAsset: fromDef(defs.manifest_asset, false),
    ManifestMutant: fromDef(defs.manifest_mutant, false),
    FixtureManifest: fromDef(defs.fixture_manifest, true),
    FixtureBundle: { required: ['manifest', 'documents'], optional: ['schema'], never: [] },
  };
  const responseDef = defs.jsonrpc_response;
  const baseRequired = (responseDef.required ?? []).filter((key) => !identity.includes(key));
  const resultBranch = responseDef.oneOf.find((branch) => Array.isArray(branch?.required) && branch.required.includes('result'));
  const errorBranch = responseDef.oneOf.find((branch) => Array.isArray(branch?.required) && branch.required.includes('error'));
  shapes.JsonRpcResultResponse = {
    required: [...baseRequired, ...(resultBranch?.required ?? ['result'])],
    optional: [],
    never: Array.isArray(resultBranch?.not?.required) ? resultBranch.not.required : ['error'],
  };
  shapes.JsonRpcErrorResponse = {
    required: [...baseRequired, ...(errorBranch?.required ?? ['error'])],
    optional: [],
    never: Array.isArray(errorBranch?.not?.required) ? errorBranch.not.required : ['result'],
  };
  return shapes;
}

function parseInterfaces(source) {
  const interfaces = {};
  const ifaceRe = /export\s+interface\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+extends\s+[A-Za-z_][A-Za-z0-9_]*)?\s*\{([\s\S]*?)\n\}/g;
  let match;
  while ((match = ifaceRe.exec(source)) !== null) {
    const name = match[1];
    const members = { required: [], optional: [], never: [], exprs: {}, nestedOwners: new Set() };
    // Brace-depth-aware member scan: nested object-type blocks (written
    // multi-line in the fixed style) contribute their own members as
    // flattened `owner.nested` entries.
    let depth = 0;
    let nestedOwner = null;
    for (const line of match[2].split('\n')) {
      const open = (line.match(/\{/g) ?? []).length;
      const close = (line.match(/\}/g) ?? []).length;
      if (nestedOwner !== null) {
        const nestedMember = /^\s*readonly\s+([A-Za-z_][A-Za-z0-9_]*)(\?)?:\s*(.*?)\s*;\s*$/.exec(line);
        if (nestedMember) {
          members.exprs[`${nestedOwner}.${nestedMember[1]}`] = {
            optional: nestedMember[2] === '?',
            expression: nestedMember[3].trim(),
          };
        }
        if (close > 0) {
          depth += open - close;
          if (depth <= 0) nestedOwner = null;
        }
        continue;
      }
      if (depth === 0) {
        const member = /^\s*readonly\s+([A-Za-z_][A-Za-z0-9_]*)(\?)?:\s*(.*)$/.exec(line);
        if (member) {
          const key = member[1];
          const optional = member[2] === '?';
          const rest = member[3].trim();
          if (rest === '' || rest.startsWith('{')) {
            // Nested object-type block (fixed multi-line style): the member
            // belongs to the enclosing interface at this depth.
            if (optional) members.optional.push(key);
            else members.required.push(key);
            if (rest.startsWith('{')) {
              nestedOwner = key;
              members.nestedOwners.add(key);
            }
          } else {
            const type = rest.replace(/;$/, '').trim();
            members.exprs[key] = { optional, expression: type };
            if (optional && type === 'never') members.never.push(key);
            else if (optional) members.optional.push(key);
            else members.required.push(key);
          }
        }
      }
      depth += open - close;
    }
    interfaces[name] = members;
  }
  return interfaces;
}

// ---------------------------------------------------------------------------
// Public type-EXPRESSION audit (iteration 4C): the schema-derived expected
// member type expressions for every public wire/fixture interface, including
// nested object shapes and descriptor-derived const/discriminant types. Each
// expectation is re-derived from the canonical schema node it represents
// (const equality with the already-verified descriptor projection, enum
// equality with the exported constant tuples, identifier patterns, refs,
// array item shapes, empty-any-value schemas, and the open error-code
// pattern), so a hand-edited type expression cannot pass silently.
// ---------------------------------------------------------------------------

function deriveTypeExpressions(schema, derived) {
  const defs = schema.$defs;
  const exprs = {};
  const problems = [];
  const at = (...pointer) => get(schema, pointer);
  const ok = (cond, label) => { if (!cond) problems.push(`type-expression derivation: ${label}`); };
  const desc = (key) => `(typeof CONTRACT_DESCRIPTOR)['${key}']`;
  const groundConst = (key, ...pointer) => {
    const node = at(...pointer);
    ok(node !== undefined && canonicalText(node.const) === canonicalText(derived[key]), `const ${pointer.join('/')} must equal the descriptor key ${key}`);
    return desc(key);
  };
  const groundEnum = (key, ...pointer) => {
    const node = at(...pointer);
    ok(node !== undefined && canonicalText(node.enum) === canonicalText(derived[key]), `enum ${pointer.join('/')} must equal the descriptor key ${key}`);
    return 'ENUM';
  };
  const groundIdentifierPattern = (...pointer) => {
    const node = at(...pointer);
    ok(node !== undefined && node.type === 'string' && node.pattern === derived.identifier_pattern, `identifier-pattern string at ${pointer.join('/')}`);
  };
  const groundPlainString = (...pointer) => {
    const node = at(...pointer);
    ok(node !== undefined && node.type === 'string', `string at ${pointer.join('/')}`);
  };
  const groundRef = (target, ...pointer) => {
    const node = at(...pointer);
    ok(node !== undefined && node.$ref === `#/$defs/${target}`, `$ref ${target} at ${pointer.join('/')}`);
  };
  const groundArrayOfRef = (target, ...pointer) => {
    const node = at(...pointer);
    ok(node !== undefined && node.type === 'array' && node.items?.$ref === `#/$defs/${target}`, `array of $ref ${target} at ${pointer.join('/')}`);
  };
  const set = (iface, member, expr) => { exprs[`${iface}.${member}`] = expr; };

  // Identity + descriptor-derived const/version aliases.
  groundConst('protocol_version', '$defs', 'protocol_version');
  groundConst('schema_version', '$defs', 'schema_version');
  groundConst('jsonrpc_version', '$defs', 'jsonrpc_version');
  set('ProtocolIdentity', 'protocol_version', 'ProtocolVersion');
  set('ProtocolIdentity', 'schema_version', 'SchemaVersion');
  set('ProtocolIdentity', 'fixture_id', 'FixtureId');
  groundIdentifierPattern('$defs', 'fixture_id');

  // Visibility model.
  groundEnum('visibility_labels', '$defs', 'visibility_label');
  set('Visibility', 'label', 'VisibilityLabel');
  groundArrayOfRef('seat_id', '$defs', 'authorized_seat_ids');
  set('Visibility', 'authorized_seat_ids', 'readonly SeatId[]');
  groundRef('seat_id', '$defs', 'seat', 'properties', 'seat_id');
  set('Seat', 'seat_id', 'SeatId');
  groundPlainString('$defs', 'seat', 'properties', 'name');
  set('Seat', 'name', 'string');
  groundArrayOfRef('seat', '$defs', 'seat_set', 'properties', 'seats');
  set('SeatSet', 'seats', 'readonly Seat[]');

  // State / projection / action intent.
  groundIdentifierPattern('$defs', 'state_field', 'properties', 'field_id');
  set('StateField', 'field_id', 'FieldId');
  ok(Object.keys(at('$defs', 'state_field', 'properties', 'value') ?? {}).length === 0, 'state_field.value must be the empty any-value schema');
  set('StateField', 'value', 'JsonValue');
  groundRef('visibility', '$defs', 'state_field', 'properties', 'visibility');
  set('StateField', 'visibility', 'Visibility');
  groundIdentifierPattern('$defs', 'state', 'properties', 'state_id');
  set('State', 'state_id', 'Identifier');
  groundArrayOfRef('state_field', '$defs', 'state', 'properties', 'fields');
  set('State', 'fields', 'readonly StateField[]');
  groundIdentifierPattern('$defs', 'projection', 'properties', 'projection_id');
  set('Projection', 'projection_id', 'Identifier');
  groundRef('seat_id', '$defs', 'projection', 'properties', 'seat_id');
  set('Projection', 'seat_id', 'SeatId');
  groundArrayOfRef('state_field', '$defs', 'projection', 'properties', 'fields');
  set('Projection', 'fields', 'readonly StateField[]');
  groundIdentifierPattern('$defs', 'action_intent_params', 'properties', 'action');
  set('ActionIntentParams', 'action', 'Identifier');
  groundRef('seat_id', '$defs', 'action_intent_params', 'properties', 'seat_id');
  set('ActionIntentParams', 'seat_id', 'SeatId');
  ok(Object.keys(at('$defs', 'action_intent_params', 'properties', 'proposal') ?? {}).length === 0, 'action_intent_params.proposal must be the empty any-value schema');
  set('ActionIntentParams', 'proposal', 'JsonValue');
  groundPlainString('$defs', 'message_id');
  set('ActionIntent', 'message_id', 'string');
  ok(canonicalText(at('$defs', 'action_intent', 'properties', 'method')?.const) === canonicalText(derived.request_methods[0]), 'action_intent.method const must equal the request method registry');
  set('ActionIntent', 'method', 'RequestMethod');
  groundRef('action_intent_params', '$defs', 'action_intent', 'properties', 'params');
  set('ActionIntent', 'params', 'ActionIntentParams');

  // ApplyActionResult / ErrorObject.
  set('ApplyActionResult', 'accepted', groundConst('apply_action_result_accepted', '$defs', 'apply_action_result', 'properties', 'accepted'));
  groundIdentifierPattern('$defs', 'apply_action_result', 'properties', 'transition_id');
  set('ApplyActionResult', 'transition_id', 'Identifier');
  groundArrayOfRef('state_field', '$defs', 'apply_action_result', 'properties', 'applied_fields');
  set('ApplyActionResult', 'applied_fields', 'readonly StateField[]');
  ok(at('$defs', 'error_object', 'properties', 'code')?.type === 'integer', 'error_object.code must be an unconstrained JSON-RPC integer');
  set('ErrorObject', 'code', 'number');
  groundPlainString('$defs', 'error_object', 'properties', 'message');
  set('ErrorObject', 'message', 'string');
  ok(canonicalText(at('$defs', 'error_object', 'properties', 'data', 'properties', 'error_code')?.pattern) === canonicalText(derived.error_code_pattern), 'error_object.data.error_code must carry the open canonical AIPT wire pattern');
  set('ErrorObject.data', 'error_code', 'AiptWireErrorCode');

  // Wire envelopes.
  set('JsonRpcRequest', 'jsonrpc', 'JsonRpcVersion');
  set('JsonRpcRequest', 'id', 'RequestId');
  ok(Array.isArray(at('$defs', 'request_id')?.oneOf) && at('$defs', 'request_id').oneOf.length === 2, 'request_id must be a two-branch oneOf');
  set('JsonRpcRequest', 'method', 'RequestMethod');
  ok(canonicalText(at('$defs', 'jsonrpc_request', 'properties', 'method')?.const) === canonicalText(derived.request_methods[0]), 'jsonrpc_request.method const must equal the request method registry');
  groundRef('action_intent_params', '$defs', 'jsonrpc_request', 'properties', 'params');
  set('JsonRpcRequest', 'params', 'ActionIntentParams');
  set('JsonRpcResultResponse', 'jsonrpc', 'JsonRpcVersion');
  set('JsonRpcResultResponse', 'id', 'RequestId');
  groundRef('apply_action_result', '$defs', 'jsonrpc_response', 'properties', 'result');
  set('JsonRpcResultResponse', 'result', 'ApplyActionResult');
  set('JsonRpcResultResponse', 'error', 'never');
  set('JsonRpcErrorResponse', 'jsonrpc', 'JsonRpcVersion');
  set('JsonRpcErrorResponse', 'id', 'RequestId');
  groundRef('error_object', '$defs', 'jsonrpc_response', 'properties', 'error');
  set('JsonRpcErrorResponse', 'error', 'ErrorObject');
  set('JsonRpcErrorResponse', 'result', 'never');
  set('JsonRpcNotification', 'jsonrpc', 'JsonRpcVersion');
  set('JsonRpcNotification', 'method', 'NotificationMethod');
  ok(canonicalText(at('$defs', 'jsonrpc_notification', 'properties', 'method')?.const) === canonicalText(derived.notification_methods[0]), 'jsonrpc_notification.method const must equal the notification method registry');
  groundRef('state_event', '$defs', 'jsonrpc_notification', 'properties', 'params', 'properties', 'event');
  set('JsonRpcNotification.params', 'event', 'StateEvent');

  // State event.
  groundIdentifierPattern('$defs', 'state_event', 'properties', 'event_id');
  set('StateEvent', 'event_id', 'Identifier');
  groundIdentifierPattern('$defs', 'state_event', 'properties', 'transition_id');
  set('StateEvent', 'transition_id', 'Identifier');
  set('StateEvent', 'event_type', groundConst('state_event_event_type', '$defs', 'state_event', 'properties', 'event_type'));
  groundIdentifierPattern('$defs', 'state_event', 'properties', 'payload', 'properties', 'from_state_id');
  set('StateEvent.payload', 'from_state_id', 'Identifier');
  groundIdentifierPattern('$defs', 'state_event', 'properties', 'payload', 'properties', 'to_state_id');
  set('StateEvent.payload', 'to_state_id', 'Identifier');

  // Deterministic check / state transition / replay.
  groundIdentifierPattern('$defs', 'deterministic_check', 'properties', 'check_id');
  set('DeterministicCheck', 'check_id', 'Identifier');
  set('DeterministicCheck', 'check_version', groundConst('deterministic_check_check_version', '$defs', 'deterministic_check', 'properties', 'check_version'));
  set('DeterministicCheck', 'kind', groundConst('deterministic_check_kind', '$defs', 'deterministic_check', 'properties', 'kind'));
  set('DeterministicCheck', 'operator', groundConst('deterministic_check_operator', '$defs', 'deterministic_check', 'properties', 'operator'));
  ok(at('$defs', 'deterministic_check', 'properties', 'inputs')?.type === 'array' && at('$defs', 'deterministic_check', 'properties', 'inputs')?.items?.type === 'number', 'deterministic_check.inputs must be an array of numbers');
  set('DeterministicCheck', 'inputs', 'readonly number[]');
  ok(at('$defs', 'deterministic_check', 'properties', 'output')?.type === 'number', 'deterministic_check.output must be a number');
  set('DeterministicCheck', 'output', 'number');
  groundIdentifierPattern('$defs', 'state_transition', 'properties', 'transition_id');
  set('StateTransition', 'transition_id', 'Identifier');
  groundIdentifierPattern('$defs', 'state_transition', 'properties', 'from_state_id');
  set('StateTransition', 'from_state_id', 'Identifier');
  groundIdentifierPattern('$defs', 'state_transition', 'properties', 'to_state_id');
  set('StateTransition', 'to_state_id', 'Identifier');
  groundIdentifierPattern('$defs', 'state_transition', 'properties', 'applied_action', 'properties', 'action');
  set('StateTransition.applied_action', 'action', 'Identifier');
  groundRef('seat_id', '$defs', 'state_transition', 'properties', 'applied_action', 'properties', 'seat_id');
  set('StateTransition.applied_action', 'seat_id', 'SeatId');
  groundArrayOfRef('state_field', '$defs', 'state_transition', 'properties', 'result');
  set('StateTransition', 'result', 'readonly StateField[]');
  groundIdentifierPattern('$defs', 'replay_assertion', 'properties', 'replays', 'items', 'properties', 'replay_id');
  set('ReplayRecord', 'replay_id', 'Identifier');
  groundRef('sha256_hex', '$defs', 'replay_assertion', 'properties', 'replays', 'items', 'properties', 'final_state_hash');
  set('ReplayRecord', 'final_state_hash', 'string');
  groundIdentifierPattern('$defs', 'replay_assertion', 'properties', 'assertion_id');
  set('ReplayAssertion', 'assertion_id', 'Identifier');
  set('ReplayAssertion', 'hash_algorithm', groundConst('replay_assertion_hash_algorithm', '$defs', 'replay_assertion', 'properties', 'hash_algorithm'));
  groundPlainString('$defs', 'replay_assertion', 'properties', 'canonical_json_rule');
  set('ReplayAssertion', 'canonical_json_rule', 'string');
  set('ReplayAssertion', 'final_state_ref', groundConst('replay_assertion_final_state_ref', '$defs', 'replay_assertion', 'properties', 'final_state_ref'));
  groundRef('sha256_hex', '$defs', 'replay_assertion', 'properties', 'final_state_hash');
  set('ReplayAssertion', 'final_state_hash', 'string');
  ok(at('$defs', 'replay_assertion', 'properties', 'replays')?.type === 'array' && at('$defs', 'replay_assertion', 'properties', 'replays')?.items?.type === 'object', 'replay_assertion.replays must be an array of inline replay records');
  set('ReplayAssertion', 'replays', 'readonly ReplayRecord[]');

  // Mutant specimen / manifest.
  set('MutantSpecimen', 'markers', groundConst('mutant_specimen_markers', '$defs', 'mutant_specimen', 'properties', 'markers'));
  set('MutantSpecimen', 'kind', groundConst('mutant_specimen_kind', '$defs', 'mutant_specimen', 'properties', 'kind'));
  groundIdentifierPattern('$defs', 'mutant_specimen', 'properties', 'mutant_id');
  set('MutantSpecimen', 'mutant_id', 'Identifier');
  groundRef('seat_id', '$defs', 'mutant_specimen', 'properties', 'seat_id');
  set('MutantSpecimen', 'seat_id', 'SeatId');
  groundIdentifierPattern('$defs', 'mutant_specimen', 'properties', 'leaked_field_id');
  set('MutantSpecimen', 'leaked_field_id', 'Identifier');
  groundRef('projection', '$defs', 'mutant_specimen', 'properties', 'projection');
  set('MutantSpecimen', 'projection', 'Projection');
  groundPlainString('$defs', 'manifest_asset', 'properties', 'path');
  set('ManifestAsset', 'path', 'string');
  groundEnum('manifest_kinds', '$defs', 'manifest_asset', 'properties', 'kind');
  set('ManifestAsset', 'kind', 'FixtureKind');
  groundPlainString('$defs', 'manifest_asset', 'properties', 'schema_ref');
  set('ManifestAsset', 'schema_ref', 'string');
  groundRef('sha256_hex', '$defs', 'manifest_asset', 'properties', 'sha256');
  set('ManifestAsset', 'sha256', 'string');
  groundPlainString('$defs', 'manifest_mutant', 'properties', 'path');
  set('ManifestMutant', 'path', 'string');
  set('ManifestMutant', 'kind', groundConst('mutant_kind', '$defs', 'manifest_mutant', 'properties', 'kind'));
  groundPlainString('$defs', 'manifest_mutant', 'properties', 'schema_ref');
  set('ManifestMutant', 'schema_ref', 'string');
  groundRef('sha256_hex', '$defs', 'manifest_mutant', 'properties', 'sha256');
  set('ManifestMutant', 'sha256', 'string');
  set('ManifestMutant', 'expected_semantic_rejection', groundConst('mutant_expected_semantic_rejection', '$defs', 'manifest_mutant', 'properties', 'expected_semantic_rejection'));
  groundPlainString('$defs', 'fixture_manifest', 'properties', 'fixture_name');
  set('FixtureManifest', 'fixture_name', 'string');
  groundArrayOfRef('manifest_asset', '$defs', 'fixture_manifest', 'properties', 'assets');
  set('FixtureManifest', 'assets', 'readonly ManifestAsset[]');
  set('FixtureManifest', 'expected_final_state', groundConst('fixture_manifest_expected_final_state', '$defs', 'fixture_manifest', 'properties', 'expected_final_state'));
  set('FixtureManifest', 'replay_assertion', groundConst('fixture_manifest_replay_assertion', '$defs', 'fixture_manifest', 'properties', 'replay_assertion'));
  groundArrayOfRef('manifest_mutant', '$defs', 'fixture_manifest', 'properties', 'mutants');
  set('FixtureManifest', 'mutants', 'readonly ManifestMutant[]');

  // FixtureBundle (synthetic validation boundary — no schema node).
  set('FixtureBundle', 'manifest', 'FixtureManifest');
  set('FixtureBundle', 'documents', 'ReadonlyMap<string, unknown>');
  set('FixtureBundle', 'schema', 'unknown');
  return { exprs, problems };
}

function auditTypeExpressions(source, derivedExpressions) {
  const problems = [...derivedExpressions.problems];
  const declared = parseInterfaces(source);
  for (const [key, expected] of Object.entries(derivedExpressions.exprs)) {
    const dot = key.indexOf('.');
    const iface = key.slice(0, dot);
    const member = key.slice(dot + 1);
    const actual = declared[iface]?.exprs?.[member];
    if (!actual) {
      problems.push(`member ${key} has no declared type expression in types.ts`);
      continue;
    }
    if (actual.expression !== expected) {
      problems.push(`member ${key} type expression drifted: declared ${JSON.stringify(actual.expression)}, schema-derived ${JSON.stringify(expected)}`);
    }
  }
  for (const [iface, members] of Object.entries(declared)) {
    for (const [member, info] of Object.entries(members.exprs ?? {})) {
      if (members.nestedOwners?.has(member)) continue;
      const key = `${iface}.${member}`;
      if (!(key in derivedExpressions.exprs)) {
        problems.push(`member ${key} has no schema-derived type-expression expectation (unreviewed public type surface)`);
      }
    }
  }
  return problems;
}

// Wire error-code type surface: the OPEN canonical namespace type
// (AiptWireErrorCode, branded + regex-enforced) must be used for
// ErrorObject.data.error_code, ValidationIssue.code stays the FINITE SDK
// union, and ManifestMutant.expected_semantic_rejection must be the EXACT
// descriptor-derived const literal — never the broad finite union.
function auditErrorCodeSurface(typesSource, errorsSource) {
  const problems = [];
  if (!/type\s+AiptWireErrorCode\s*=\s*string\s*&/.test(typesSource)) {
    problems.push('types.ts must declare the branded open wire namespace type AiptWireErrorCode (string & brand)');
  }
  if (!/error_code:\s*AiptWireErrorCode/.test(typesSource)) {
    problems.push('ErrorObject.data.error_code must be typed AiptWireErrorCode (the open canonical wire namespace, regex-enforced at runtime)');
  }
  if (!/expected_semantic_rejection:\s*\(typeof\s+CONTRACT_DESCRIPTOR\)\['mutant_expected_semantic_rejection'\]/.test(typesSource)) {
    problems.push("ManifestMutant.expected_semantic_rejection must be the exact descriptor-derived literal (typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection'], never the broad AiptErrorCode union");
  }
  if (!/code:\s*AiptErrorCode/.test(errorsSource)) {
    problems.push('ValidationIssue.code must stay the finite AiptErrorCode union');
  }
  return problems;
}

function auditTypeShapes(source, shapes) {
  const problems = [];
  const declared = parseInterfaces(source);
  const sorted = (list) => [...list].sort().join(',');
  for (const [name, expected] of Object.entries(shapes)) {
    const actual = declared[name];
    if (!actual) {
      problems.push(`public interface ${name} is not declared in types.ts`);
      continue;
    }
    if (sorted(actual.required) !== sorted(expected.required)) {
      problems.push(`interface ${name} required members drifted: declared [${sorted(actual.required)}], schema-derived [${sorted(expected.required)}]`);
    }
    if (sorted(actual.optional) !== sorted(expected.optional)) {
      problems.push(`interface ${name} optional members drifted: declared [${sorted(actual.optional)}], schema-derived [${sorted(expected.optional)}]`);
    }
    if (sorted(actual.never) !== sorted(expected.never)) {
      problems.push(`interface ${name} discriminant (never) members drifted: declared [${sorted(actual.never)}], schema-derived [${sorted(expected.never)}]`);
    }
  }
  for (const name of Object.keys(declared)) {
    if (!(name in shapes)) problems.push(`public interface ${name} has no schema-derived shape expectation (unreviewed public type surface)`);
  }
  return problems;
}

function walkFiles(root, filter) {
  const out = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (filter(full)) out.push(full);
    }
  }
  return out.sort();
}

const REQUIRED_EXPORTS = [
  'PROTOCOL_VERSION', 'SCHEMA_VERSION', 'JSONRPC_VERSION', 'REQUEST_METHODS', 'NOTIFICATION_METHODS', 'METHODS',
  'ID_MIN_SAFE_INTEGER', 'ID_MAX_SAFE_INTEGER', 'VISIBILITY_LABELS', 'MANIFEST_KINDS', 'AIPT_ERROR_CODES',
  'CONTRACT_DESCRIPTOR', 'ProtocolValidationError',
  'canonicalJson', 'canonicalJsonString', 'sha256Hex',
  'validateJsonValue', 'requireJsonValue', 'isAiptWireErrorCode', 'validateSchemaInstance',
  'parseJson', 'parseExecutableRoot', 'decodeRequest', 'decodeResponse', 'decodeNotification',
  'encodeExecutableRoot', 'encodeRequest', 'encodeResponse', 'encodeNotification',
  'toExecutableRoot', 'toJsonRpcRequest', 'toJsonRpcResponse', 'toJsonRpcResultResponse', 'toJsonRpcErrorResponse', 'toJsonRpcNotification',
  'buildRequest', 'buildResultResponse', 'buildErrorResponse', 'buildNotification',
  'validateExecutableRoot', 'validateRequestId', 'validateVisibility', 'validateStateField', 'validateStateShape',
  'validateProjectionShape', 'validateProjectionSemantics', 'validateFixtureManifest', 'validateFixtureBundle',
  'checkFixtureIdentity', 'isSafeIntegerId', 'issue', 'okResult', 'failResult',
];

const REQUIRED_FUNCTIONS = REQUIRED_EXPORTS.filter((name) =>
  !['PROTOCOL_VERSION', 'SCHEMA_VERSION', 'JSONRPC_VERSION', 'REQUEST_METHODS', 'NOTIFICATION_METHODS', 'METHODS',
    'ID_MIN_SAFE_INTEGER', 'ID_MAX_SAFE_INTEGER', 'VISIBILITY_LABELS', 'MANIFEST_KINDS', 'AIPT_ERROR_CODES',
    'CONTRACT_DESCRIPTOR'].includes(name));

export async function run(ctx) {
  const details = [];
  const probes = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');
  const readJson = (rel) => JSON.parse(read(rel));

  // ---- 1. canonical schema + independent descriptor derivation ----
  let schema;
  try {
    schema = readJson(SCHEMA_PATH);
  } catch (err) {
    fail(`canonical schema unreadable: ${err.message}`);
    return { name: 'adapter-sdk', result: 'FAIL', details, negative_probes: probes };
  }
  const derived = deriveDescriptor(schema);
  const derivedShapes = deriveTypeShapes(schema);

  // ---- 2. load the SDK (the subject under test) ----
  let sdk;
  try {
    sdk = await import(pathToFileURL(path.join(ctx.repo, SDK_INDEX)).href);
  } catch (err) {
    fail(`adapter-sdk module failed to load: ${err.message}`);
    return { name: 'adapter-sdk', result: 'FAIL', details, negative_probes: probes };
  }

  // ---- 3. drift manifest: byte-identical canonical JSON vs the schema ----
  const embedded = sdk.CONTRACT_DESCRIPTOR;
  if (!embedded || typeof embedded !== 'object') {
    fail('adapter-sdk exports no CONTRACT_DESCRIPTOR drift manifest');
  } else {
    const diffs = diffDescriptorKeys(derived, embedded);
    if (canonicalText(derived) !== canonicalText(embedded) || diffs.length > 0) {
      for (const diff of diffs.slice(0, 12)) fail(`contract drift manifest drifted from the canonical schema: ${diff}`);
      fail('CONTRACT_DESCRIPTOR canonical JSON != canonical-schema-derived descriptor (schema/type drift must not pass silently)');
    } else ok('CONTRACT_DESCRIPTOR is byte-identical (canonical JSON) to the descriptor re-derived from the canonical schema');
    if (embedded.canonical_schema_sha256 !== sha256Hex(canonicalText(schema))) {
      fail('canonical_schema_sha256 full-content fingerprint drifted from the canonical schema document');
    } else ok(`canonical schema full-content fingerprint matches (${embedded.canonical_schema_sha256.slice(0, 16)}...) — every schema edit forces explicit SDK review`);
  }

  // ---- 4. exported runtime constants equal the descriptor ----
  const constantPairs = [
    ['PROTOCOL_VERSION', sdk.PROTOCOL_VERSION, derived.protocol_version],
    ['SCHEMA_VERSION', sdk.SCHEMA_VERSION, derived.schema_version],
    ['JSONRPC_VERSION', sdk.JSONRPC_VERSION, derived.jsonrpc_version],
    ['REQUEST_METHODS', sdk.REQUEST_METHODS, derived.request_methods],
    ['NOTIFICATION_METHODS', sdk.NOTIFICATION_METHODS, derived.notification_methods],
    ['ID_MIN_SAFE_INTEGER', sdk.ID_MIN_SAFE_INTEGER, derived.id_integer_minimum],
    ['ID_MAX_SAFE_INTEGER', sdk.ID_MAX_SAFE_INTEGER, derived.id_integer_maximum],
    ['VISIBILITY_LABELS', sdk.VISIBILITY_LABELS, derived.visibility_labels],
    ['MANIFEST_KINDS', sdk.MANIFEST_KINDS, derived.manifest_kinds],
  ];
  let constantsOk = true;
  for (const [name, actual, expected] of constantPairs) {
    if (canonicalText(actual) !== canonicalText(expected)) {
      fail(`exported constant ${name} drifted from the canonical schema: ${canonicalText(actual)} != ${canonicalText(expected)}`);
      constantsOk = false;
    }
  }
  if (constantsOk) ok('all exported versions/methods/labels/id bounds/manifest kinds equal the canonical schema');

  // ---- 5. export surface + stable error identifiers ----
  const missing = REQUIRED_EXPORTS.filter((name) => !(name in sdk));
  if (missing.length > 0) fail(`adapter-sdk is missing public exports: ${missing.join(', ')}`);
  else ok(`${REQUIRED_EXPORTS.length} required public exports present`);
  const notFunctions = REQUIRED_FUNCTIONS.filter((name) => typeof sdk[name] !== 'function');
  if (notFunctions.length > 0) fail(`exports that must be functions: ${notFunctions.join(', ')}`);
  else ok(`${REQUIRED_FUNCTIONS.length} public helpers are functions`);
  if (typeof sdk.ProtocolValidationError !== 'function') fail('ProtocolValidationError must be exported');
  const codePattern = /^AIPT_[A-Z0-9_]{1,63}$/;
  const badCodes = (sdk.AIPT_ERROR_CODES ?? []).filter((code) => typeof code !== 'string' || !codePattern.test(code));
  if (badCodes.length > 0) fail(`exported AIPT error identifiers violate the canonical wire pattern: ${badCodes.join(', ')}`);
  else if ((sdk.AIPT_ERROR_CODES ?? []).length < 20) fail('exported AIPT error identifier set looks truncated (< 20)');
  else ok(`${sdk.AIPT_ERROR_CODES.length} stable AIPT error identifiers exported, all matching ${derived.error_code_pattern}`);
  for (const required of ['AIPT_VISIBILITY_UNAUTHORIZED_FIELD', 'AIPT_ACTION_REJECTED', 'AIPT_FIXTURE_IDENTITY_MISMATCH', 'AIPT_FIXTURE_UNSAFE_PATH', 'AIPT_FIXTURE_DUPLICATE_PATH', 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH', 'AIPT_FIXTURE_SCHEMA_VIOLATION', 'AIPT_FIXTURE_INVALID_SCHEMA', 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT']) {
    if (!(sdk.AIPT_ERROR_CODES ?? []).includes(required)) fail(`stable error identifier ${required} missing from the exported set`);
  }
  if (typeof sdk.isAiptWireErrorCode !== 'function') fail('isAiptWireErrorCode must be exported (runtime gate of the open wire namespace)');
  else if (sdk.isAiptWireErrorCode('AIPT_FUTURE_EXTENSION') !== true || sdk.isAiptWireErrorCode('AIPT_BAD!') !== false || sdk.isAiptWireErrorCode(7) !== false) {
    fail('isAiptWireErrorCode must accept canonical-valid future AIPT_* codes and reject non-pattern values');
  }

  // ---- 6. source hygiene: no ambient-capable imports, no env/network ----
  const anyType = /(:\s*any\b|<\s*any\b|\bas\s+any\b|=\s*any\b|\bany\s*\[|\bany\s*\||\(\s*any\b|\bArray\s*<\s*any\b)/;
  const forbiddenModules = new Set(['net', 'tls', 'http', 'https', 'http2', 'dgram', 'child_process', 'worker_threads', 'cluster', 'vm', 'inspector', 'sqlite']);
  let hygieneOk = true;
  for (const file of walkFiles(path.join(ctx.repo, SDK_SRC_DIR), (f) => f.endsWith('.ts'))) {
    const rel = path.relative(ctx.repo, file);
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/from\s+['"]node:([a-z_0-9]+)['"]/g)) {
      if (forbiddenModules.has(match[1])) {
        fail(`SDK source ${rel} imports ambient-capable node:${match[1]}`);
        hygieneOk = false;
      }
    }
    if (/process\.env/.test(text)) { fail(`SDK source ${rel} reads environment credentials (process.env)`); hygieneOk = false; }
    if (/\bfetch\s*\(/.test(text)) { fail(`SDK source ${rel} performs a network fetch`); hygieneOk = false; }
    if (/\bWebSocket\b/.test(text)) { fail(`SDK source ${rel} opens a socket`); hygieneOk = false; }
    if (anyType.test(text)) { fail(`SDK source ${rel} uses the forbidden any type`); hygieneOk = false; }
  }
  if (hygieneOk) ok('SDK sources: no ambient-capable imports, no process.env/fetch/socket, no any type');

  // The public literal unions must derive from the exported readonly
  // constants/descriptor — a hand-written literal union would silently drift.
  const typesSource = read(`${SDK_SRC_DIR}/types.ts`);
  const errorsSource = read(`${SDK_SRC_DIR}/errors.ts`);
  for (const [needle, label] of [
    ['typeof CONTRACT_DESCRIPTOR', 'descriptor-derived literal unions'],
    ['(typeof VISIBILITY_LABELS)[number]', 'visibility label union'],
    ['(typeof REQUEST_METHODS)[number]', 'request method union'],
    ['(typeof NOTIFICATION_METHODS)[number]', 'notification method union'],
    ['(typeof AIPT_ERROR_CODES)[number]', 'error code union'],
    ['(typeof MANIFEST_KINDS)[number]', 'manifest kind union'],
  ]) {
    if (!typesSource.includes(needle)) fail(`public types.ts no longer derives ${label} from the exported readonly constants/descriptor`);
  }
  ok('public literal unions are derived (typeof) from the exported readonly constants/descriptor');

  // ---- 6b. actual declared type surface vs schema-derived shape ----
  const shapeProblems = auditTypeShapes(typesSource, derivedShapes);
  if (shapeProblems.length > 0) {
    for (const problem of shapeProblems.slice(0, 12)) fail(`public type-shape drift: ${problem}`);
    fail('the ACTUAL declared interface surface of types.ts drifted from the schema-derived shape (required/optional/discriminant members)');
  } else ok(`public type-shape audit: ${Object.keys(derivedShapes).length} interfaces match the schema-derived required/optional/discriminant member expectations`);

  // ---- 6c. actual declared TYPE EXPRESSIONS vs schema-derived expressions ----
  const derivedExpressions = deriveTypeExpressions(schema, derived);
  const expressionProblems = auditTypeExpressions(typesSource, derivedExpressions);
  if (expressionProblems.length > 0) {
    for (const problem of expressionProblems.slice(0, 12)) fail(`public type-expression drift: ${problem}`);
    fail('the ACTUAL declared member type expressions of types.ts drifted from the schema-derived expectations (member types, nested object shapes, descriptor-derived const/discriminant types)');
  } else ok(`public type-expression audit: ${Object.keys(derivedExpressions.exprs).length} member type expressions match the schema-derived expectations (nested shapes and descriptor-derived literals included)`);

  const errorCodeSurfaceProblems = auditErrorCodeSurface(typesSource, errorsSource);
  if (errorCodeSurfaceProblems.length > 0) {
    for (const problem of errorCodeSurfaceProblems) fail(`wire error-code type surface: ${problem}`);
  } else ok('wire error-code type surface: ErrorObject.data.error_code is the open branded AiptWireErrorCode namespace; ValidationIssue.code stays the finite AiptErrorCode union; ManifestMutant.expected_semantic_rejection is the exact descriptor-derived literal');

  // ---- 7. zero-dependency package boundary ----
  const pkg = readJson(`${SDK_PACKAGE}/package.json`);
  if (pkg.name !== '@aipt/adapter-sdk') fail(`SDK package name must be @aipt/adapter-sdk, got ${JSON.stringify(pkg.name)}`);
  if (pkg.version !== '1.0.0') fail(`SDK package version must be 1.0.0, got ${JSON.stringify(pkg.version)}`);
  if (pkg.license !== 'MIT') fail(`SDK package license must be MIT, got ${JSON.stringify(pkg.license)}`);
  if (pkg.type !== 'module') fail('SDK package type must be module');
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    if (pkg[field] !== undefined) fail(`SDK package.json must not carry ${field} (dependency-free contract)`);
  }
  if (pkg.main !== 'src/index.ts' || pkg.exports?.['.'] !== './src/index.ts') fail('SDK entrypoint must be src/index.ts (Node 24 native erasable TypeScript)');
  if (!(pkg.scripts?.test ?? '').includes('node --test')) fail('SDK package must run its tests via node --test');
  ok('SDK package boundary: @aipt/adapter-sdk@1.0.0, MIT, module, zero dependency specifiers, src/index.ts entrypoint');

  // ---- 8. tests consume the shared canonical schema/fixture ----
  const testFiles = walkFiles(path.join(ctx.repo, SDK_TEST_DIR), (f) => f.endsWith('.ts'));
  if (testFiles.length === 0) fail('SDK carries no node:test files');
  else ok(`${testFiles.length} SDK test files present`);
  const fixtureReferencing = testFiles.filter((f) => fs.readFileSync(f, 'utf8').includes(FIXTURE_DIR));
  if (fixtureReferencing.length === 0) fail('SDK tests must consume the shared canonical fixture (testdata/protocol/v1/minimal-fixture)');
  else ok(`${fixtureReferencing.length} SDK test file(s) consume the shared minimal fixture`);
  const schemaPassing = testFiles.filter((f) => fs.readFileSync(f, 'utf8').includes(SCHEMA_PATH));
  if (schemaPassing.length === 0) fail('SDK tests must load and pass in the single canonical schema (schemas/protocol/v1/aipt-protocol.schema.json) as the bundle validation boundary');
  else ok(`${schemaPassing.length} SDK test file(s) load the canonical schema and pass it in as the validation boundary`);

  // ---- 9. fixture digest behavior: SDK sha256 must equal every manifest digest ----
  const manifest = readJson(`${FIXTURE_DIR}/manifest.json`);
  let digestOk = true;
  for (const entry of [...manifest.assets, ...manifest.mutants]) {
    const doc = readJson(`${FIXTURE_DIR}/${entry.path}`);
    const digest = sdk.sha256Hex(doc);
    if (digest !== entry.sha256) {
      fail(`SDK canonical SHA-256 of ${entry.path} drifted from the manifest digest (got ${digest}, manifest says ${entry.sha256})`);
      digestOk = false;
    }
  }
  if (digestOk) ok(`SDK canonical JSON SHA-256 matches every manifest digest (${manifest.assets.length + manifest.mutants.length} assets)`);

  // ---- 10. persisted wire envelopes: parse, kind, round trip ----
  let envelopeOk = true;
  for (const rel of WIRE_ENVELOPES) {
    const text = read(`${FIXTURE_DIR}/${rel}`);
    let doc;
    try {
      doc = sdk.parseExecutableRoot(text);
    } catch (err) {
      fail(`SDK rejected persisted envelope ${rel}: ${err.message}`);
      envelopeOk = false;
      continue;
    }
    const reEncoded = sdk.encodeExecutableRoot(doc);
    const reParsed = sdk.parseExecutableRoot(reEncoded);
    if (canonicalText(JSON.parse(reEncoded)) !== canonicalText(JSON.parse(text))) {
      fail(`SDK round trip of ${rel} drifted from the persisted document`);
      envelopeOk = false;
    } else if (canonicalText(reParsed) !== canonicalText(doc)) {
      fail(`SDK encode(decode(x)) of ${rel} is not value-stable`);
      envelopeOk = false;
    }
  }
  if (envelopeOk) ok('all 4 persisted wire envelopes parse, kind-resolve, and round-trip deterministically');
  const request = readJson(`${FIXTURE_DIR}/${WIRE_ENVELOPES[0]}`);
  const resultResponse = readJson(`${FIXTURE_DIR}/${WIRE_ENVELOPES[1]}`);
  const errorResponse = readJson(`${FIXTURE_DIR}/${WIRE_ENVELOPES[2]}`);
  const notification = readJson(`${FIXTURE_DIR}/${WIRE_ENVELOPES[3]}`);
  const decodedRequest = sdk.decodeRequest(JSON.stringify(request));
  const decodedResult = sdk.decodeResponse(JSON.stringify(resultResponse));
  const decodedError = sdk.decodeResponse(JSON.stringify(errorResponse));
  const decodedNotification = sdk.decodeNotification(JSON.stringify(notification));
  if (!('result' in decodedResult) || 'error' in decodedResult) fail('persisted result response must decode as a result response');
  if (!('error' in decodedError) || 'result' in decodedError) fail('persisted error response must decode as an error response');
  if ('id' in decodedNotification) fail('persisted notification must decode without an id');
  if (canonicalText(decodedResult.id) !== canonicalText(decodedRequest.id) || typeof decodedResult.id !== typeof decodedRequest.id) {
    fail('persisted result response id must round-trip the request id (value AND JSON type)');
  }
  if (canonicalText(decodedError.id) !== canonicalText(decodedRequest.id) || typeof decodedError.id !== typeof decodedRequest.id) {
    fail('persisted error response id must round-trip the request id (value AND JSON type)');
  }
  ok('persisted request/response ids round-trip by value and JSON type; result/error/notification kinds discriminated correctly');

  // ---- 11. projections + hidden-leak mutant behavior vs the shared fixture ----
  const seats = readJson(`${FIXTURE_DIR}/seats.json`);
  const state = readJson(`${FIXTURE_DIR}/state.json`);
  const knownSeats = seats.seats.map((seat) => seat.seat_id);
  let projectionOk = true;
  for (const rel of ['projection-seat-a.json', 'projection-seat-b.json']) {
    const result = sdk.validateProjectionSemantics(state, readJson(`${FIXTURE_DIR}/${rel}`), knownSeats);
    if (!result.valid) {
      fail(`SDK rejected authorized projection ${rel}: ${JSON.stringify(result.issues)}`);
      projectionOk = false;
    }
  }
  if (projectionOk) ok('SDK accepts both authorized projections of the shared fixture');
  const mutant = readJson(`${FIXTURE_DIR}/mutants/hidden-leak.json`);
  const mutantResult = sdk.validateProjectionSemantics(state, mutant.projection, knownSeats);
  const mutantCodes = mutantResult.issues.map((issue) => issue.code);
  if (mutantResult.valid || mutantCodes.length !== 1 || mutantCodes[0] !== 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD') {
    fail(`hidden-leak mutant must be rejected with exactly one reason AIPT_VISIBILITY_UNAUTHORIZED_FIELD, got ${JSON.stringify(mutantCodes)}`);
    probes.push({ label: 'hidden-leak mutant', result: 'FAIL', reason: JSON.stringify(mutantCodes) });
  } else {
    ok('hidden-leak mutant rejected with exactly AIPT_VISIBILITY_UNAUTHORIZED_FIELD');
    probes.push({ label: 'hidden-leak mutant', result: 'PASS', reason: 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD' });
  }

  // ---- 12. fixture bundle behavior (canonical schema passed in explicitly) ----
  const documents = new Map();
  for (const entry of [...manifest.assets, ...manifest.mutants]) {
    documents.set(entry.path, readJson(`${FIXTURE_DIR}/${entry.path}`));
  }
  const bundleResult = sdk.validateFixtureBundle({ manifest, documents }, schema);
  if (!bundleResult.valid) {
    fail(`SDK fixture bundle validation rejected the shared fixture: ${JSON.stringify(bundleResult.issues.slice(0, 5))}`);
  } else ok('SDK fixture bundle validation accepts the shared manifest + documents (digest/identity/inventory/schema-fingerprint/ordinary-projection/semantic-proof)');
  if (!sdk.validateFixtureManifest(manifest).valid) fail('SDK fixture manifest validation rejected the shared manifest');
  // The general package-local evaluator still accepts the canonical schema
  // and the shared documents without the bundle fingerprint binding.
  const schemaInstanceCheck = sdk.validateSchemaInstance(schema, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
  if (!schemaInstanceCheck.valid) fail(`SDK schema evaluator rejected the shared state against the canonical schema: ${JSON.stringify(schemaInstanceCheck.issues.slice(0, 3))}`);
  else ok('validateSchemaInstance (general supported-subset evaluator) accepts the canonical schema + shared state');

  // ---- 13. fail-closed negative behavior probes ----
  const makeRequest = (over) => ({
    jsonrpc: '2.0', id: 'probe-id', method: 'aipt.protocol.applyAction',
    params: { action: 'advance-turn', seat_id: 'seat-a' },
    protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic',
    ...over,
  });
  const makeResponse = (over) => ({
    jsonrpc: '2.0', id: 'probe-id',
    protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic',
    result: {
      accepted: true, transition_id: 'transition-turn-increment',
      applied_fields: [{ field_id: 'turn-count', value: 1, visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-a', 'seat-b'] } }],
    },
    ...over,
  });
  const makeNotification = (over) => ({
    jsonrpc: '2.0', method: 'aipt.protocol.event', params: { event: readJson(`${FIXTURE_DIR}/event.json`) },
    protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic',
    ...over,
  });
  const issueCodesOf = (fn) => {
    let outcome;
    try {
      outcome = fn();
    } catch (err) {
      if (!err?.issues) return ['NO_PROTOCOL_ERROR'];
      return err.issues.map((issue) => issue.code);
    }
    if (outcome && typeof outcome === 'object' && outcome.valid === false && Array.isArray(outcome.issues)) {
      return outcome.issues.map((issue) => issue.code);
    }
    return [];
  };
  const tamper = (value, fn) => {
    const copy = JSON.parse(JSON.stringify(value));
    fn(copy);
    return copy;
  };
  const identityOnlyState = { protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic' };
  const probeCases = [
    { label: 'malformed JSON', expected: ['AIPT_MALFORMED_JSON'], run: () => sdk.decodeRequest('{ nope') },
    { label: 'arbitrary root object', expected: ['AIPT_UNKNOWN_ENVELOPE'], run: () => sdk.toExecutableRoot({ hello: 'world' }) },
    { label: 'unknown protocol version', expected: ['AIPT_UNKNOWN_VERSION'], run: () => sdk.toJsonRpcRequest(makeRequest({ protocol_version: '9.9.9' })) },
    { label: 'unknown schema version', expected: ['AIPT_UNKNOWN_VERSION'], run: () => sdk.toJsonRpcRequest(makeRequest({ schema_version: '9.9.9' })) },
    { label: 'unknown request method', expected: ['AIPT_UNKNOWN_METHOD'], run: () => sdk.toJsonRpcRequest(makeRequest({ method: 'aipt.protocol.workerLifecycle' })) },
    { label: 'unknown notification method', expected: ['AIPT_UNKNOWN_METHOD'], run: () => sdk.toJsonRpcNotification(makeNotification({ method: 'aipt.protocol.applyAction' })) },
    { label: 'unsafe integer id above maximum', expected: ['AIPT_INVALID_ID'], run: () => sdk.toJsonRpcRequest(makeRequest({ id: sdk.ID_MAX_SAFE_INTEGER + 1 })) },
    { label: 'unsafe integer id below minimum', expected: ['AIPT_INVALID_ID'], run: () => sdk.toJsonRpcRequest(makeRequest({ id: -sdk.ID_MAX_SAFE_INTEGER - 1 })) },
    { label: 'non-integer id', expected: ['AIPT_INVALID_ID'], run: () => sdk.toJsonRpcRequest(makeRequest({ id: 1.5 })) },
    { label: 'result and error together', expected: ['AIPT_RESPONSE_RESULT_ERROR_CONFLICT'], run: () => sdk.toJsonRpcResponse({ ...makeResponse(), error: { code: -32603, message: 'boom' } }) },
    { label: 'neither result nor error', expected: ['AIPT_RESPONSE_MISSING_RESULT_ERROR'], run: () => { const r = makeResponse(); delete r.result; return sdk.toJsonRpcResponse(r); } },
    { label: 'extra property in request', expected: ['AIPT_UNKNOWN_FIELD'], run: () => sdk.toJsonRpcRequest(makeRequest({ trace: 'x' })) },
    { label: 'missing request params', expected: ['AIPT_MISSING_REQUIRED'], run: () => { const r = makeRequest(); delete r.params; return sdk.toJsonRpcRequest(r); } },
    { label: 'unknown visibility label', expected: ['AIPT_UNKNOWN_VISIBILITY'], run: () => sdk.validateStateShape({
      ...readJson(`${FIXTURE_DIR}/state.json`),
      fields: [{ field_id: 'x', value: 1, visibility: { label: 'TEAM_ONLY', authorized_seat_ids: ['seat-a'] } }],
    }) },
    { label: 'lossy canonical value (NaN)', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.canonicalJson({ x: Number.NaN }) },
    { label: 'lossy canonical value (cycle)', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => { const c = {}; c.self = c; return sdk.canonicalJson(c); } },
    // ---- iteration 4B repair probes: every confirmed false acceptance ----
    { label: 'request params.proposal undefined', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.toJsonRpcRequest(makeRequest({ params: { action: 'advance-turn', seat_id: 'seat-a', proposal: undefined } })) },
    { label: 'request params.proposal function', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.toJsonRpcRequest(makeRequest({ params: { action: 'advance-turn', seat_id: 'seat-a', proposal: () => 0 } })) },
    { label: 'response applied_fields value undefined', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.toJsonRpcResponse(makeResponse({ result: { accepted: true, transition_id: 't-1', applied_fields: [{ field_id: 'f-1', value: undefined, visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-a'] } }] } })) },
    { label: 'parseJson unsafe integer 9007199254740993', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.parseJson('9007199254740993') },
    { label: 'parseJson non-finite 1e400', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.parseJson('1e400') },
    { label: 'parseJson nested unsafe integer', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.parseJson('{"n":9007199254740993}') },
    { label: 'manifest expected_final_state drift', expected: ['AIPT_INVALID_VALUE'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.expected_final_state = 'other.json'; })) },
    { label: 'manifest replay_assertion drift', expected: ['AIPT_INVALID_VALUE'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.replay_assertion = 'other.json'; })) },
    { label: 'manifest kind/schema_ref mismatch (state -> projection)', expected: ['AIPT_FIXTURE_SCHEMA_REF_MISMATCH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.assets.find((a) => a.path === 'state.json').schema_ref = '#/$defs/projection'; })) },
    { label: 'manifest kind/schema_ref mismatch (mutant_specimen -> projection)', expected: ['AIPT_FIXTURE_SCHEMA_REF_MISMATCH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.mutants[0].schema_ref = '#/$defs/projection'; })) },
    { label: 'manifest duplicate path', expected: ['AIPT_FIXTURE_DUPLICATE_PATH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.assets.push(JSON.parse(JSON.stringify(m.assets[0]))); })) },
    { label: 'manifest unsafe ../escape path', expected: ['AIPT_FIXTURE_UNSAFE_PATH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.assets.find((a) => a.path === 'state.json').path = '../escape.json'; })) },
    { label: 'manifest unsafe backslash path', expected: ['AIPT_FIXTURE_UNSAFE_PATH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.assets.find((a) => a.path === 'state.json').path = 'a\\b.json'; })) },
    { label: 'manifest unsafe absolute path', expected: ['AIPT_FIXTURE_UNSAFE_PATH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.assets.find((a) => a.path === 'state.json').path = '/etc/passwd'; })) },
    { label: 'manifest unsafe empty segment', expected: ['AIPT_FIXTURE_UNSAFE_PATH'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.assets.find((a) => a.path === 'state.json').path = 'a//b.json'; })) },
    { label: 'manifest mutant cardinality drift', expected: ['AIPT_INVALID_VALUE'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.mutants = [...m.mutants, JSON.parse(JSON.stringify(m.mutants[0]))]; })) },
    { label: 'manifest mutant rejection const drift', expected: ['AIPT_INVALID_VALUE'], run: () => sdk.validateFixtureManifest(tamper(manifest, (m) => { m.mutants[0].expected_semantic_rejection = 'AIPT_OTHER'; })) },
    { label: 'bundle identity-only state (digest updated)', expected: ['AIPT_FIXTURE_SCHEMA_VIOLATION'], run: () => {
      const m = tamper(manifest, (mm) => { mm.assets.find((a) => a.path === 'state.json').sha256 = selfSha256(identityOnlyState); });
      const docs = new Map(documents);
      docs.set('state.json', identityOnlyState);
      return sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
    } },
    { label: 'bundle state schema_ref -> projection', expected: ['AIPT_FIXTURE_SCHEMA_REF_MISMATCH'], run: () => {
      const m = tamper(manifest, (mm) => { mm.assets.find((a) => a.path === 'state.json').schema_ref = '#/$defs/projection'; });
      return sdk.validateFixtureBundle({ manifest: m, documents }, schema);
    } },
    { label: 'bundle duplicate manifest entry', expected: ['AIPT_FIXTURE_DUPLICATE_PATH'], run: () => {
      const m = tamper(manifest, (mm) => { mm.assets.push(JSON.parse(JSON.stringify(mm.assets[0]))); });
      return sdk.validateFixtureBundle({ manifest: m, documents }, schema);
    } },
    { label: 'bundle neutral non-rejecting mutant (digest updated)', expected: ['AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT'], run: () => {
      const neutral = JSON.parse(JSON.stringify(documents.get('mutants/hidden-leak.json')));
      neutral.projection = readJson(`${FIXTURE_DIR}/projection-seat-b.json`);
      const m = tamper(manifest, (mm) => { mm.mutants[0].sha256 = selfSha256(neutral); });
      const docs = new Map(documents);
      docs.set('mutants/hidden-leak.json', neutral);
      return sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
    } },
    { label: 'bundle state path ../escape.json (map key supplied)', expected: ['AIPT_FIXTURE_UNSAFE_PATH'], run: () => {
      const m = tamper(manifest, (mm) => { mm.assets.find((a) => a.path === 'state.json').path = '../escape.json'; });
      const docs = new Map(documents);
      docs.delete('state.json');
      docs.set('../escape.json', readJson(`${FIXTURE_DIR}/state.json`));
      return sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
    } },
    { label: 'bundle missing canonical schema boundary', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateFixtureBundle({ manifest, documents }) },
    { label: 'projection fixture_id mismatch', expected: ['AIPT_FIXTURE_IDENTITY_MISMATCH'], run: () => sdk.validateProjectionSemantics(state, tamper(readJson(`${FIXTURE_DIR}/projection-seat-a.json`), (p) => { p.fixture_id = 'drifted-fixture'; }), knownSeats) },
    { label: 'known seats invalid identifier', expected: ['AIPT_INVALID_IDENTIFIER'], run: () => sdk.validateProjectionSemantics(state, readJson(`${FIXTURE_DIR}/projection-seat-a.json`), ['Seat-Bad!']) },
    { label: 'known seats duplicate', expected: ['AIPT_INVALID_VALUE'], run: () => sdk.validateProjectionSemantics(state, readJson(`${FIXTURE_DIR}/projection-seat-a.json`), ['seat-a', 'seat-b', 'seat-a']) },
    { label: 'wire error_code violating the pattern', expected: ['AIPT_INVALID_VALUE'], run: () => sdk.toJsonRpcErrorResponse({ jsonrpc: '2.0', id: 'probe-id', protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic', error: { code: -32000, message: 'boom', data: { error_code: 'NOT_AIPT' } } }) },
    // ---- iteration 4C repair probes: every confirmed false acceptance ----
    { label: 'request top-level symbol-keyed member', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => {
      const r = makeRequest();
      Object.defineProperty(r, Symbol('sneak'), { value: 1, enumerable: true });
      return sdk.toJsonRpcRequest(r);
    } },
    { label: 'request top-level non-enumerable member', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => {
      const r = makeRequest();
      Object.defineProperty(r, 'sneak', { value: 1, enumerable: false });
      return sdk.toJsonRpcRequest(r);
    } },
    { label: 'request id = -0', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.toJsonRpcRequest({ ...makeRequest(), id: -0 }) },
    { label: 'request explicit undefined params (required-member bypass)', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.toJsonRpcRequest({ ...makeRequest(), params: undefined }) },
    { label: 'response unsafe integer error.code', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.toJsonRpcErrorResponse({ jsonrpc: '2.0', id: 'probe-id', protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic', error: { code: Number.MAX_SAFE_INTEGER + 1, message: 'unsafe integer code' } }) },
    { label: 'manifest top-level symbol-keyed member', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => {
      const m = { ...manifest };
      Object.defineProperty(m, Symbol('sneak'), { value: 1, enumerable: true });
      return sdk.validateFixtureManifest(m);
    } },
    { label: 'validateSchemaInstance lossy instance document', expected: ['AIPT_LOSSY_JSON_VALUE'], run: () => sdk.validateSchemaInstance(schema, { x: undefined }, '#/$defs/state', '$') },
    { label: 'bundle schema fingerprint drift (description-only edit)', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const driftedSchema = JSON.parse(JSON.stringify(schema));
      driftedSchema.description = `${driftedSchema.description} (fingerprint drift probe)`;
      return sdk.validateFixtureBundle({ manifest, documents }, driftedSchema);
    } },
    { label: 'bundle lossy schema document (cycle)', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const cyclic = {}; cyclic.self = cyclic;
      return sdk.validateFixtureBundle({ manifest, documents }, cyclic);
    } },
    { label: 'schema grammar: format hidden in a passing anyOf branch', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const s = JSON.parse(JSON.stringify(schema));
      s.$defs.state = { anyOf: [{ type: 'object', format: 'anything' }, { type: 'object' }] };
      return sdk.validateSchemaInstance(s, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
    } },
    { label: 'schema grammar: format inside not', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const s = JSON.parse(JSON.stringify(schema));
      s.$defs.state = { type: 'object', not: { type: 'object', format: 'anything' } };
      return sdk.validateSchemaInstance(s, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
    } },
    { label: 'schema grammar: minLength with a string value', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const s = JSON.parse(JSON.stringify(schema));
      s.$defs.state.properties.state_id = { type: 'string', minLength: 'four' };
      return sdk.validateSchemaInstance(s, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
    } },
    { label: 'schema grammar: properties as an array', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const s = JSON.parse(JSON.stringify(schema));
      s.$defs.state = { type: 'object', properties: [{ type: 'string' }] };
      return sdk.validateSchemaInstance(s, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
    } },
    { label: 'schema grammar: additionalProperties as a string', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const s = JSON.parse(JSON.stringify(schema));
      s.$defs.state = { type: 'object', additionalProperties: 'nope' };
      return sdk.validateSchemaInstance(s, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
    } },
    { label: 'schema grammar: malformed keyword in an unreferenced $defs child', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const s = JSON.parse(JSON.stringify(schema));
      s.$defs.deterministic_check.properties.operator.type = 'file';
      return sdk.validateSchemaInstance(s, readJson(`${FIXTURE_DIR}/state.json`), '#/$defs/state', '$');
    } },
    { label: 'bundle ordinary projection replaced by the schema-valid hidden-leak projection (digest updated)', expected: ['AIPT_VISIBILITY_UNAUTHORIZED_FIELD'], run: () => {
      const leaked = JSON.parse(JSON.stringify(documents.get('mutants/hidden-leak.json'))).projection;
      const m = tamper(manifest, (mm) => { mm.assets.find((a) => a.path === 'projection-seat-b.json').sha256 = selfSha256(leaked); });
      const docs = new Map(documents);
      docs.set('projection-seat-b.json', leaked);
      return sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
    } },
    { label: 'bundle mutant wrapper seat_id drift (digest updated)', expected: ['AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT'], run: () => {
      const drifted = JSON.parse(JSON.stringify(documents.get('mutants/hidden-leak.json')));
      drifted.seat_id = 'seat-a';
      const m = tamper(manifest, (mm) => { mm.mutants[0].sha256 = selfSha256(drifted); });
      const docs = new Map(documents);
      docs.set('mutants/hidden-leak.json', drifted);
      return sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
    } },
    { label: 'bundle mutant wrapper leaked_field_id drift (digest updated)', expected: ['AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT'], run: () => {
      const drifted = JSON.parse(JSON.stringify(documents.get('mutants/hidden-leak.json')));
      drifted.leaked_field_id = 'turn-count';
      const m = tamper(manifest, (mm) => { mm.mutants[0].sha256 = selfSha256(drifted); });
      const docs = new Map(documents);
      docs.set('mutants/hidden-leak.json', drifted);
      return sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
    } },
    { label: 'bundle unlisted manifest.json documents entry (no exemption)', expected: ['AIPT_FIXTURE_UNLISTED_ASSET'], run: () => {
      const docs = new Map(documents);
      docs.set('manifest.json', readJson(`${FIXTURE_DIR}/manifest.json`));
      return sdk.validateFixtureBundle({ manifest, documents: docs }, schema);
    } },
    // ---- iteration 4D repair probes: every confirmed evaluator defect ----
    { label: 'schema grammar: same-object mutation to a malformed keyword shape after a PASS', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const mutable = { $defs: { x: { type: 'string', minLength: 1 } } };
      const before = sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
      if (!before.valid) return { valid: false, issues: [{ path: '$probe', code: 'PROBE_SETUP_FAILED', message: 'pre-mutation call must pass' }] };
      mutable.$defs.x.minLength = 'not-a-number';
      return sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
    } },
    { label: 'schema grammar: same-object mutation adding an unsupported keyword to an unreferenced $defs after a PASS', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => {
      const mutable = { $defs: { x: { type: 'string' }, spare: { type: 'number' } } };
      const before = sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
      if (!before.valid) return { valid: false, issues: [{ path: '$probe', code: 'PROBE_SETUP_FAILED', message: 'pre-mutation call must pass' }] };
      mutable.$defs.spare.format = 'uuid';
      return sdk.validateSchemaInstance(mutable, 'a', '#/$defs/x', '$');
    } },
    { label: 'schema grammar: local $ref cycle in an unused $defs child', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'object' }, a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: self-referential local $ref', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { $ref: '#/$defs/x' } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: duplicate required member names', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'object', required: ['a', 'a'] } } }, { a: 1 }, '#/$defs/x', '$') },
    { label: 'schema grammar: duplicate type names', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: ['string', 'string'] } } }, 'a', '#/$defs/x', '$') },
    { label: 'schema grammar: duplicate JSON-equal enum values', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { enum: [{ a: 1 }, { a: 1 }] } } }, { a: 1 }, '#/$defs/x', '$') },
    { label: 'schema grammar: non-array examples annotation', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'string', examples: 'nope' } } }, 'a', '#/$defs/x', '$') },
    { label: 'schema grammar: non-boolean deprecated annotation', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'string', deprecated: 'yes' } } }, 'a', '#/$defs/x', '$') },
    { label: 'schema grammar: non-string title annotation', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'string', title: 7 } } }, 'a', '#/$defs/x', '$') },
    { label: 'schema grammar: nested $schema structural keyword', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'object', $schema: 'https://json-schema.org/draft/2020-12/schema' } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: nested $id structural keyword', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'object', $id: 'urn:test:x' } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: nested $defs structural keyword', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'object', $defs: { y: { type: 'string' } } } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: root $schema must be the exact 2020-12 URI', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $schema: 'https://json-schema.org/draft-07/schema', $defs: { x: { type: 'string' } } }, 'a', '#/$defs/x', '$') },
    { label: 'schema grammar: root $id must be a string', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $id: 7, $defs: { x: { type: 'string' } } }, 'a', '#/$defs/x', '$') },
    { label: 'schema grammar: external $ref remains a rejection', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { $ref: 'https://example.com/schema.json' } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: unresolvable local $ref remains a rejection', expected: ['AIPT_FIXTURE_INVALID_SCHEMA'], run: () => sdk.validateSchemaInstance({ $defs: { x: { $ref: '#/$defs/ghost' } } }, {}, '#/$defs/x', '$') },
    { label: 'schema grammar: decimal multipleOf non-multiple (0.35 against 0.1)', expected: ['AIPT_FIXTURE_SCHEMA_VIOLATION'], run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'number', multipleOf: 0.1 } } }, 0.35, '#/$defs/x', '$') },
  ];
  let probeFailures = 0;
  for (const probe of probeCases) {
    let codes;
    try {
      codes = issueCodesOf(probe.run);
    } catch (err) {
      codes = ['CRASHED'];
      fail(`negative probe (${probe.label}) crashed: ${err.message}`);
      probeFailures += 1;
      probes.push({ label: probe.label, result: 'FAIL', reason: `crashed: ${err.message}` });
      continue;
    }
    const matched = codes.some((code) => probe.expected.includes(code));
    if (codes.length === 0 || !matched) {
      fail(`negative probe (${probe.label}) was not rejected with ${probe.expected.join('|')}, got ${JSON.stringify(codes)}`);
      probeFailures += 1;
      probes.push({ label: probe.label, result: 'FAIL', reason: JSON.stringify(codes) });
    } else {
      ok(`negative-probe PASS: ${probe.label} rejected with ${JSON.stringify(codes)}`);
      probes.push({ label: probe.label, result: 'PASS', reason: codes.join('|') });
    }
  }
  if (probeFailures === 0) ok(`all ${probeCases.length} fail-closed negative behavior probes rejected for the correct contract reasons`);

  // ---- 13d. zero getter/setter invocation probes (iteration 4C) ----
  {
    const invocationCases = [];
    const runCase = (label, fn, expectedCode, getterCalls) => {
      let codes;
      try {
        codes = issueCodesOf(fn);
      } catch (err) {
        codes = ['CRASHED'];
      }
      const matched = codes.includes(expectedCode);
      if (getterCalls !== 0) {
        fail(`zero-invocation probe (${label}) invoked accessors ${getterCalls} time(s)`);
        invocationCases.push({ label, result: 'FAIL', reason: `accessors invoked ${getterCalls} times` });
      } else if (!matched) {
        fail(`zero-invocation probe (${label}) was not rejected with ${expectedCode}, got ${JSON.stringify(codes)}`);
        invocationCases.push({ label, result: 'FAIL', reason: JSON.stringify(codes) });
      } else {
        ok(`zero-invocation PASS: ${label} rejected with ${expectedCode}, zero accessor calls`);
        invocationCases.push({ label, result: 'PASS', reason: `${expectedCode}, 0 accessor calls` });
      }
    };
    {
      let calls = 0;
      const obj = { x: 1 };
      Object.defineProperty(obj, 'x', { get: () => { calls += 1; return 1; }, enumerable: true });
      runCase('validateJsonValue object accessor', () => sdk.validateJsonValue(obj), 'AIPT_LOSSY_JSON_VALUE', calls);
    }
    {
      let calls = 0;
      const arr = [1];
      Object.defineProperty(arr, 1, { get: () => { calls += 1; return 2; }, enumerable: true });
      runCase('validateJsonValue array index accessor', () => sdk.validateJsonValue(arr), 'AIPT_LOSSY_JSON_VALUE', calls);
    }
    {
      let calls = 0;
      const r = makeRequest();
      const paramsValue = r.params;
      Object.defineProperty(r, 'params', { get: () => { calls += 1; return paramsValue; }, enumerable: true });
      runCase('toJsonRpcRequest accessor member', () => sdk.toJsonRpcRequest(r), 'AIPT_LOSSY_JSON_VALUE', calls);
    }
    {
      let calls = 0;
      const bundle = { manifest, documents, schema };
      Object.defineProperty(bundle, 'manifest', { get: () => { calls += 1; return manifest; }, enumerable: true });
      runCase('validateFixtureBundle wrapper accessor', () => sdk.validateFixtureBundle(bundle, schema), 'AIPT_FIXTURE_INVALID_MANIFEST', calls);
    }
    {
      let calls = 0;
      const documentsObject = {};
      for (const [key, value] of documents) documentsObject[key] = value;
      Object.defineProperty(documentsObject, 'state.json', { get: () => { calls += 1; return readJson(`${FIXTURE_DIR}/state.json`); }, enumerable: true });
      runCase('validateFixtureBundle documents accessor', () => sdk.validateFixtureBundle({ manifest, documents: documentsObject }, schema), 'AIPT_FIXTURE_INVALID_MANIFEST', calls);
    }
    {
      // Manifest-preflight no-document-touch ordering: a failing preflight
      // must return before any supplied document is read, traversed, or
      // invoked — and before any hashing.
      let calls = 0;
      const hostileDocument = { protocol_version: '1.0.0' };
      Object.defineProperty(hostileDocument, 'schema_version', { get: () => { calls += 1; return '1.0.0'; }, enumerable: true });
      const docs = new Map(documents);
      docs.set('state.json', hostileDocument);
      const m = tamper(manifest, (mm) => { mm.assets.find((a) => a.path === 'state.json').path = '../escape.json'; });
      const result = sdk.validateFixtureBundle({ manifest: m, documents: docs }, schema);
      const codes = result.issues.map((issue) => issue.code);
      const preflightOnly = codes.length > 0 && codes.every((code) => ['AIPT_FIXTURE_UNSAFE_PATH', 'AIPT_FIXTURE_DUPLICATE_PATH', 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH', 'AIPT_INVALID_VALUE', 'AIPT_MISSING_REQUIRED', 'AIPT_UNKNOWN_FIELD', 'AIPT_LOSSY_JSON_VALUE', 'AIPT_UNKNOWN_VERSION', 'AIPT_FIXTURE_IDENTITY_MISMATCH', 'AIPT_FIXTURE_INVALID_MANIFEST'].includes(code)) && !codes.includes('AIPT_FIXTURE_DIGEST_DRIFT');
      if (calls !== 0) {
        fail(`no-document-touch probe invoked document accessors ${calls} time(s)`);
        invocationCases.push({ label: 'manifest preflight no-document-touch', result: 'FAIL', reason: `document accessors invoked ${calls} times` });
      } else if (!preflightOnly) {
        fail(`no-document-touch probe returned non-preflight codes ${JSON.stringify(codes)}`);
        invocationCases.push({ label: 'manifest preflight no-document-touch', result: 'FAIL', reason: JSON.stringify(codes) });
      } else {
        ok('zero-invocation PASS: failing manifest preflight returns before any document touch/hash (preflight-only codes)');
        invocationCases.push({ label: 'manifest preflight no-document-touch', result: 'PASS', reason: `preflight-only: ${codes.join('|')}, 0 accessor calls` });
      }
    }
    probes.push(...invocationCases);
    if (invocationCases.every((p) => p.result === 'PASS')) ok(`all ${invocationCases.length} zero-invocation / no-document-touch probes passed with zero accessor calls`);
  }

  // ---- 13b. canonical-valid FUTURE AIPT_* wire error code (positive) ----
  {
    let futureCodeOk = true;
    try {
      const futureResponse = { jsonrpc: '2.0', id: 'probe-id', protocol_version: '1.0.0', schema_version: '1.0.0', fixture_id: 'minimal-v1-arithmetic', error: { code: -32000, message: 'future extension', data: { error_code: 'AIPT_FUTURE_EXTENSION' } } };
      const decoded = sdk.decodeResponse(JSON.stringify(futureResponse));
      if (!('error' in decoded) || decoded.error?.data?.error_code !== 'AIPT_FUTURE_EXTENSION') {
        fail('a canonical-valid future AIPT_* wire error code must decode and be preserved verbatim');
        futureCodeOk = false;
      }
      const invalid = JSON.parse(JSON.stringify(futureResponse));
      invalid.error.data.error_code = 'AIPT_BAD!CODE';
      try {
        sdk.decodeResponse(JSON.stringify(invalid));
        fail('a non-pattern wire error_code must be rejected at runtime');
        futureCodeOk = false;
      } catch (err) {
        if (!Array.isArray(err?.issues) || !err.issues.some((issue) => issue.code === 'AIPT_INVALID_VALUE')) {
          fail(`non-pattern wire error_code rejection must carry AIPT_INVALID_VALUE, got ${JSON.stringify(err?.issues)}`);
          futureCodeOk = false;
        }
      }
    } catch (err) {
      fail(`future wire error code probe crashed: ${err.message}`);
      futureCodeOk = false;
    }
    if (futureCodeOk) {
      ok('wire error-code namespace: canonical-valid future AIPT_FUTURE_EXTENSION accepted and preserved; non-pattern codes rejected with AIPT_INVALID_VALUE');
      probes.push({ label: 'future AIPT_* wire error code', result: 'PASS', reason: 'AIPT_FUTURE_EXTENSION accepted verbatim' });
    } else {
      probes.push({ label: 'future AIPT_* wire error code', result: 'FAIL', reason: 'future code not preserved or invalid code accepted' });
    }
  }

  // ---- 13c. in-memory drift negative probes: the gate's own drift detection
  // must actually detect previously uncovered schema/type edits ----
  {
    const driftCases = [
      {
        label: 'drift: ActionIntentParams.proposal optional -> required',
        run: () => {
          const mutated = typesSource.replace('readonly proposal?: JsonValue;', 'readonly proposal: JsonValue;');
          return auditTypeShapes(mutated, derivedShapes).length > 0;
        },
      },
      {
        label: 'drift: ApplyActionResult.applied_fields renamed',
        run: () => {
          const mutated = typesSource.replace('readonly applied_fields: readonly StateField[];', 'readonly applied_fields_renamed: readonly StateField[];');
          return auditTypeShapes(mutated, derivedShapes).length > 0;
        },
      },
      {
        label: 'drift: State gains an unreviewed member',
        run: () => {
          const mutated = typesSource.replace('export interface State extends ProtocolIdentity {\n  readonly state_id: Identifier;', 'export interface State extends ProtocolIdentity {\n  readonly state_id: Identifier;\n  readonly sneak: Identifier;');
          return auditTypeShapes(mutated, derivedShapes).length > 0;
        },
      },
      {
        label: 'drift: ErrorObject.data.error_code widened back to the finite union',
        run: () => {
          const mutated = typesSource.replace('readonly error_code: AiptWireErrorCode;', 'readonly error_code: AiptErrorCode;');
          return auditErrorCodeSurface(mutated, errorsSource).length > 0;
        },
      },
      {
        label: 'drift: schema nested required member (state_field.required + note)',
        run: () => {
          const mutatedSchema = JSON.parse(JSON.stringify(schema));
          mutatedSchema.$defs.state_field.required = [...mutatedSchema.$defs.state_field.required, 'note'];
          const diffs = diffDescriptorKeys(deriveDescriptor(mutatedSchema), embedded);
          return diffs.some((diff) => diff.includes('state_field_required'));
        },
      },
      {
        label: 'drift: schema manifest const (expected_final_state)',
        run: () => {
          const mutatedSchema = JSON.parse(JSON.stringify(schema));
          mutatedSchema.$defs.fixture_manifest.properties.expected_final_state.const = 'other.json';
          const diffs = diffDescriptorKeys(deriveDescriptor(mutatedSchema), embedded);
          return diffs.some((diff) => diff.includes('fixture_manifest_expected_final_state'));
        },
      },
      {
        label: 'drift: schema manifest ref map (kind enum loses state)',
        run: () => {
          const mutatedSchema = JSON.parse(JSON.stringify(schema));
          mutatedSchema.$defs.manifest_asset.properties.kind.enum = mutatedSchema.$defs.manifest_asset.properties.kind.enum.filter((kind) => kind !== 'state');
          const diffs = diffDescriptorKeys(deriveDescriptor(mutatedSchema), embedded);
          return diffs.some((diff) => diff.includes('manifest_kinds') || diff.includes('manifest_kind_schema_refs'));
        },
      },
      {
        label: 'drift: full schema fingerprint (description-only edit)',
        run: () => {
          const mutatedSchema = JSON.parse(JSON.stringify(schema));
          mutatedSchema.title = 'edited title (fingerprint drift)';
          const diffs = diffDescriptorKeys(deriveDescriptor(mutatedSchema), embedded);
          return diffs.some((diff) => diff.includes('canonical_schema_sha256'));
        },
      },
      // ---- iteration 4C type-EXPRESSION drift probes: member type edits,
      // nested shapes, and descriptor-literal widening cannot pass silently ----
      {
        label: 'drift: StateField.value narrowed from JsonValue to string',
        run: () => {
          const mutated = typesSource.replace('readonly value: JsonValue;', 'readonly value: string;');
          return auditTypeExpressions(mutated, derivedExpressions).some((p) => p.includes('StateField.value'));
        },
      },
      {
        label: 'drift: nested member type (StateEvent.payload.from_state_id -> string)',
        run: () => {
          const mutated = typesSource.replace('readonly from_state_id: Identifier;', 'readonly from_state_id: string;');
          return auditTypeExpressions(mutated, derivedExpressions).some((p) => p.includes('StateEvent.payload.from_state_id'));
        },
      },
      {
        label: 'drift: ManifestMutant.expected_semantic_rejection widened to AiptErrorCode',
        run: () => {
          const mutated = typesSource.replace("(typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection']", 'AiptErrorCode');
          return auditTypeExpressions(mutated, derivedExpressions).some((p) => p.includes('ManifestMutant.expected_semantic_rejection'))
            && auditErrorCodeSurface(mutated, errorsSource).length > 0;
        },
      },
    ];
    let driftFailures = 0;
    for (const driftCase of driftCases) {
      let detected;
      try {
        detected = driftCase.run();
      } catch (err) {
        detected = false;
        fail(`drift probe (${driftCase.label}) crashed: ${err.message}`);
      }
      if (detected !== true) {
        fail(`drift probe (${driftCase.label}) was NOT detected for its drift reason`);
        driftFailures += 1;
        probes.push({ label: driftCase.label, result: 'FAIL', reason: 'drift not detected' });
      } else {
        ok(`drift-probe PASS: ${driftCase.label} detected for its drift reason`);
        probes.push({ label: driftCase.label, result: 'PASS', reason: 'drift detected' });
      }
    }
    if (driftFailures === 0) ok(`all ${driftCases.length} in-memory drift negative probes detected their drift reason (schema content, nested required members, manifest ref map, public type shapes, type expressions, error-code surface)`);
  }

  // ---- 13f. iteration 4D positive grammar/evaluator probes: the repaired
  // grammar still accepts every valid declared form (empty required arrays,
  // decimal multipleOf tolerance, acyclic shared refs/aliases, synthetic
  // schemas without $schema) ----
  {
    const positiveCases = [
      { label: 'positive: required empty array is accepted', run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'object', required: [] } } }, {}, '#/$defs/x', '$') },
      { label: 'positive: decimal multipleOf accepts 0.3 against 0.1', run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'number', multipleOf: 0.1 } } }, 0.3, '#/$defs/x', '$') },
      {
        label: 'positive: acyclic shared-target refs and JS aliases are accepted',
        run: () => {
          const shared = { type: 'string' };
          const dag = {
            $defs: {
              target: { type: 'string' },
              a: { $ref: '#/$defs/target' },
              b: { $ref: '#/$defs/target' },
              props: { type: 'object', properties: { p1: shared, p2: shared } },
            },
          };
          return sdk.validateSchemaInstance(dag, { p1: 'one', p2: 'two' }, '#/$defs/props', '$');
        },
      },
      { label: 'positive: synthetic schema documents without $schema are accepted', run: () => sdk.validateSchemaInstance({ $defs: { x: { type: 'string' } } }, 'a', '#/$defs/x', '$') },
    ];
    let positiveFailures = 0;
    for (const positive of positiveCases) {
      let result;
      try {
        result = positive.run();
      } catch (err) {
        result = { valid: false, issues: [{ code: 'CRASHED', message: err.message }] };
      }
      if (!result.valid) {
        fail(`positive grammar probe (${positive.label}) was rejected: ${JSON.stringify(result.issues)}`);
        positiveFailures += 1;
        probes.push({ label: positive.label, result: 'FAIL', reason: JSON.stringify(result.issues) });
      } else {
        ok(`positive-probe PASS: ${positive.label}`);
        probes.push({ label: positive.label, result: 'PASS', reason: 'accepted' });
      }
    }
    if (positiveFailures === 0) ok(`all ${positiveCases.length} iteration 4D positive grammar probes accepted their valid declared forms`);
  }

  // ---- 14. clean import probe: no output, no ambient work, minimal env ----
  const probeScript = [
    `await import(${JSON.stringify(pathToFileURL(path.join(ctx.repo, SDK_INDEX)).href)})`,
    '.then((m) => {',
    '  if (typeof m.PROTOCOL_VERSION !== "string") process.exit(3);',
    '  if (typeof m.buildRequest !== "function") process.exit(4);',
    '});',
  ].join('');
  const probe = spawnSync(process.execPath, ['--input-type=module', '--eval', probeScript], {
    cwd: ctx.repo,
    env: { PATH: process.env.PATH ?? '' },
    encoding: 'utf8',
    timeout: 30_000,
  });
  if (probe.status !== 0) fail(`clean import probe failed (status ${probe.status}): ${probe.stderr}`);
  else if (probe.stdout !== '' || probe.stderr !== '') fail(`clean import probe must produce no output, got stdout=${JSON.stringify(probe.stdout)} stderr=${JSON.stringify(probe.stderr)}`);
  else ok('clean import probe: importing the SDK under a minimal environment exits 0 with zero output (no ambient work on import)');

  // ---- 15. deterministic canonical JSON/hash sanity ----
  const hashA = sdk.sha256Hex({ b: 1, a: [1, 2] });
  const hashB = sdk.sha256Hex({ a: [1, 2], b: 1 });
  if (hashA !== hashB || !/^[0-9a-f]{64}$/.test(hashA)) fail('SDK canonical SHA-256 is not deterministic over key insertion order');
  else ok('SDK canonical JSON/hash is deterministic (key-order independent, 64 lowercase hex)');

  return {
    name: 'adapter-sdk',
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: probes,
    summary: {
      sdk: `${pkg.name}@${pkg.version}`,
      descriptor: `canonical schema ${derived.protocol_version} / ${derived.schema_version} / jsonrpc ${derived.jsonrpc_version}; methods ${[...derived.request_methods, ...derived.notification_methods].join(', ')}; full-content fingerprint ${derived.canonical_schema_sha256.slice(0, 16)}...`,
      fixture: `${FIXTURE_DIR} (${manifest.assets.length + manifest.mutants.length} manifest entries, ${WIRE_ENVELOPES.length} wire envelopes)`,
      envelope_variants: derived.envelope_variants,
      id_bounds: [derived.id_integer_minimum, derived.id_integer_maximum],
      visibility_labels: derived.visibility_labels,
      type_shapes_audited: Object.keys(derivedShapes).length,
      type_expressions_audited: Object.keys(derivedExpressions.exprs).length,
    },
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  const ctx = { repo: path.resolve(args.repo || process.cwd()) };
  const report = await run(ctx);
  process.stdout.write(`${JSON.stringify({ schema: 'aipt.public.b001-validator-report/v1', name: 'adapter-sdk', ...report }, null, 2)}\n`);
  process.exitCode = report.result === 'PASS' ? 0 : 1;
}
