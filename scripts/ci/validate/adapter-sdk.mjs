// AIPT-M0-B002 iteration 4B: @aipt/adapter-sdk machine gate.
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
// expectations (required/optional/discriminant members for every public wire
// and fixture type), behavior-checks the SDK against the persisted wire
// envelopes and fixture assets (digests, projections, the hidden-leak
// mutant, per-document canonical-schema validation), runs fail-closed
// negative probes for every repaired adversarial false acceptance plus
// in-memory drift probes that prove the audit detects previously uncovered
// schema/type edits, audits the SDK sources for ambient-capable imports /
// environment reads, and proves the package is a zero-dependency,
// side-effect-free import via a clean child-process probe.
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
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonical(value[key]);
    return out;
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
    const members = { required: [], optional: [], never: [] };
    // Brace-depth-aware member scan: nested object-type blocks (written
    // multi-line in the fixed style) never contribute members.
    let depth = 0;
    for (const line of match[2].split('\n')) {
      const open = (line.match(/\{/g) ?? []).length;
      const close = (line.match(/\}/g) ?? []).length;
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
          } else {
            const type = rest.replace(/;$/, '').trim();
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

// Wire error-code type surface: the OPEN canonical namespace type
// (AiptWireErrorCode, branded + regex-enforced) must be used for
// ErrorObject.data.error_code, while ValidationIssue.code and
// ManifestMutant.expected_semantic_rejection stay the FINITE SDK union.
function auditErrorCodeSurface(typesSource, errorsSource) {
  const problems = [];
  if (!/type\s+AiptWireErrorCode\s*=\s*string\s*&/.test(typesSource)) {
    problems.push('types.ts must declare the branded open wire namespace type AiptWireErrorCode (string & brand)');
  }
  if (!/error_code:\s*AiptWireErrorCode/.test(typesSource)) {
    problems.push('ErrorObject.data.error_code must be typed AiptWireErrorCode (the open canonical wire namespace, regex-enforced at runtime)');
  }
  if (!/expected_semantic_rejection:\s*AiptErrorCode/.test(typesSource)) {
    problems.push('ManifestMutant.expected_semantic_rejection must stay the finite AiptErrorCode union');
  }
  if (!/code:\s*AiptErrorCode/.test(errorsSource)) {
    problems.push('ValidationIssue.code must stay the finite AiptErrorCode union');
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
  const errorCodeSurfaceProblems = auditErrorCodeSurface(typesSource, errorsSource);
  if (errorCodeSurfaceProblems.length > 0) {
    for (const problem of errorCodeSurfaceProblems) fail(`wire error-code type surface: ${problem}`);
  } else ok('wire error-code type surface: ErrorObject.data.error_code is the open branded AiptWireErrorCode namespace; ValidationIssue.code stays the finite AiptErrorCode union');

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
  } else ok('SDK fixture bundle validation accepts the shared manifest + documents (digest/identity/inventory/schema/semantic-proof)');
  if (!sdk.validateFixtureManifest(manifest).valid) fail('SDK fixture manifest validation rejected the shared manifest');

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
    if (driftFailures === 0) ok(`all ${driftCases.length} in-memory drift negative probes detected their drift reason (schema content, nested required members, manifest ref map, public type shapes, error-code surface)`);
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
