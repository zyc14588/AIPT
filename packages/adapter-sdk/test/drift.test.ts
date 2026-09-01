// Schema/type drift protection (iteration 4B): an independent in-package
// re-derivation of the complete contract descriptor — including the
// full-content canonical-schema fingerprint — from the single repository
// schema, compared against the exported CONTRACT_DESCRIPTOR byte-for-byte
// (canonical JSON). This mirrors the machine gate inside the test suite, so
// a canonical-schema edit or an SDK descriptor edit fails the package tests
// instead of passing silently. The derivation below is intentionally written
// independently of the SDK's own serializer.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';
import { loadSchema } from './helpers.ts';

const TYPES_SOURCE_PATH = path.resolve(import.meta.dirname, '../src/types.ts');

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, canonical(record[key])]));
  }
  return value;
}

function canonicalText(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function sha256Hex(text: string): string {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

function get(schema: Record<string, unknown>, pointer: string): unknown {
  let node: unknown = schema;
  for (const part of pointer.split('/')) {
    if (node === null || typeof node !== 'object') return undefined;
    const record = node as Record<string, unknown>;
    if (!(part in record)) return undefined;
    node = record[part];
  }
  return node;
}

function deriveDescriptor(schema: Record<string, unknown>): Record<string, unknown> {
  const getAt = (pointer: string): unknown => get(schema, `$defs/${pointer}`);
  const kinds = getAt('manifest_asset/properties/kind/enum') as string[];
  const mutantKind = getAt('manifest_mutant/properties/kind/const') as string;
  const kindRefs: Record<string, string> = {};
  for (const kind of kinds) kindRefs[kind] = `#/$defs/${kind}`;
  kindRefs[mutantKind] = `#/$defs/${mutantKind}`;
  const requestIdBranches = getAt('request_id/oneOf') as Array<{ type?: string; minLength?: number; maxLength?: number }>;
  const stringBranch = requestIdBranches.find((branch) => branch.type === 'string');
  return {
    canonical_schema_path: 'schemas/protocol/v1/aipt-protocol.schema.json',
    canonical_schema_sha256: sha256Hex(canonicalText(schema)),
    protocol_version: getAt('protocol_version/const'),
    schema_version: getAt('schema_version/const'),
    jsonrpc_version: getAt('jsonrpc_version/const'),
    request_methods: [getAt('jsonrpc_request/properties/method/const')],
    notification_methods: [getAt('jsonrpc_notification/properties/method/const')],
    envelope_variants: (schema.oneOf as Array<{ $ref: string }>).map((branch) => branch.$ref.replace('#/$defs/', '')),
    envelope_required: {
      jsonrpc_request: getAt('jsonrpc_request/required'),
      jsonrpc_response: getAt('jsonrpc_response/required'),
      jsonrpc_notification: getAt('jsonrpc_notification/required'),
    },
    envelope_additional_properties: {
      jsonrpc_request: getAt('jsonrpc_request/additionalProperties'),
      jsonrpc_response: getAt('jsonrpc_response/additionalProperties'),
      jsonrpc_notification: getAt('jsonrpc_notification/additionalProperties'),
    },
    response_result_error_exclusive: true,
    id_integer_minimum: getAt('request_id_integer/minimum'),
    id_integer_maximum: getAt('request_id_integer/maximum'),
    id_string_min_length: stringBranch?.minLength,
    id_string_max_length: stringBranch?.maxLength,
    visibility_labels: getAt('visibility_label/enum'),
    error_code_pattern: getAt('error_object/properties/data/properties/error_code/pattern'),
    identifier_pattern: getAt('seat_id/pattern'),
    state_field_required: getAt('state_field/required'),
    visibility_required: getAt('visibility/required'),
    authorized_seat_ids_min_items: getAt('authorized_seat_ids/minItems'),
    fields_min_items: getAt('state/properties/fields/minItems'),
    applied_fields_min_items: getAt('apply_action_result/properties/applied_fields/minItems'),
    state_required: getAt('state/required'),
    projection_required: getAt('projection/required'),
    action_intent_params_required: getAt('action_intent_params/required'),
    notification_params_required: getAt('jsonrpc_notification/properties/params/required'),
    state_event_required: getAt('state_event/required'),
    state_event_event_type: getAt('state_event/properties/event_type/const'),
    apply_action_result_required: getAt('apply_action_result/required'),
    apply_action_result_accepted: getAt('apply_action_result/properties/accepted/const'),
    error_object_required: getAt('error_object/required'),
    fixture_manifest_required: getAt('fixture_manifest/required'),
    fixture_manifest_expected_final_state: getAt('fixture_manifest/properties/expected_final_state/const'),
    fixture_manifest_replay_assertion: getAt('fixture_manifest/properties/replay_assertion/const'),
    manifest_kinds: kinds,
    manifest_kind_schema_refs: kindRefs,
    mutant_kind: mutantKind,
    mutant_expected_semantic_rejection: getAt('manifest_mutant/properties/expected_semantic_rejection/const'),
    deterministic_check_check_version: getAt('deterministic_check/properties/check_version/const'),
    deterministic_check_kind: getAt('deterministic_check/properties/kind/const'),
    deterministic_check_operator: getAt('deterministic_check/properties/operator/const'),
    replay_assertion_hash_algorithm: getAt('replay_assertion/properties/hash_algorithm/const'),
    replay_assertion_final_state_ref: getAt('replay_assertion/properties/final_state_ref/const'),
    mutant_specimen_markers: getAt('mutant_specimen/properties/markers/const'),
    mutant_specimen_kind: getAt('mutant_specimen/properties/kind/const'),
  };
}

test('the exported CONTRACT_DESCRIPTOR is byte-identical to an independent re-derivation from the canonical schema', () => {
  const schema = loadSchema();
  const derived = deriveDescriptor(schema);
  const embedded = sdk.CONTRACT_DESCRIPTOR as unknown as Record<string, unknown>;
  assert.deepEqual(Object.keys(derived).sort(), Object.keys(embedded).sort(), 'descriptor key sets must match');
  for (const key of Object.keys(derived)) {
    assert.equal(
      canonicalText(derived[key]),
      canonicalText(embedded[key]),
      `descriptor key ${JSON.stringify(key)} drifted from the canonical schema`,
    );
  }
});

test('the full-content canonical-schema fingerprint covers every schema edit (drift probe)', () => {
  const schema = loadSchema() as Record<string, unknown>;
  const originalFingerprint = sdk.CONTRACT_DESCRIPTOR.canonical_schema_sha256;
  assert.equal(originalFingerprint, sha256Hex(canonicalText(schema)));
  // a description-only edit (outside every projected field) must change the
  // fingerprint, forcing explicit SDK review
  const edited = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
  edited.title = 'edited title (drift probe)';
  assert.notEqual(sha256Hex(canonicalText(edited)), originalFingerprint, 'an edited schema must drift the fingerprint');
  // a semantic edit (nested required member) must also drift the projection
  const semanticEdit = JSON.parse(JSON.stringify(schema)) as Record<string, unknown>;
  const stateField = get(semanticEdit, '$defs/state_field') as { required: string[] };
  stateField.required = [...stateField.required, 'note'];
  const derived = deriveDescriptor(semanticEdit);
  assert.notEqual(
    canonicalText(derived.state_field_required),
    canonicalText((sdk.CONTRACT_DESCRIPTOR as unknown as Record<string, unknown>).state_field_required),
    'a nested required-member schema edit must drift the descriptor projection',
  );
});

// ---- iteration 4C: public type-expression audit (independent mini-audit) ----

function auditTypeExpressions(source: string): string[] {
  const problems: string[] = [];
  const interfaceBlock = (name: string): string => {
    const match = new RegExp(`export\\s+interface\\s+${name}(?:\\s+extends\\s+[A-Za-z_][A-Za-z0-9_]*)?\\s*\\{([\\s\\S]*?)\\n\\}`).exec(source);
    return match?.[1] ?? '';
  };
  const stateField = interfaceBlock('StateField');
  if (!/readonly\s+value:\s*JsonValue;/.test(stateField)) {
    problems.push('StateField.value is not the schema-any-value JsonValue type');
  }
  const stateEvent = interfaceBlock('StateEvent');
  if (!/readonly\s+from_state_id:\s*Identifier;/.test(stateEvent)) {
    problems.push('StateEvent.payload.from_state_id nested member type drifted from Identifier');
  }
  const manifestMutant = interfaceBlock('ManifestMutant');
  if (!/readonly\s+expected_semantic_rejection:\s*\(typeof\s+CONTRACT_DESCRIPTOR\)\['mutant_expected_semantic_rejection'\];/.test(manifestMutant)) {
    problems.push("ManifestMutant.expected_semantic_rejection is not the descriptor-derived literal (typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection']");
  }
  return problems;
}

test('ManifestMutant.expected_semantic_rejection is the exact descriptor-derived literal', () => {
  const declared: sdk.ManifestMutant['expected_semantic_rejection'] = sdk.CONTRACT_DESCRIPTOR.mutant_expected_semantic_rejection;
  assert.equal(declared, 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD');
  const source = fs.readFileSync(TYPES_SOURCE_PATH, 'utf8');
  assert.match(source, /readonly\s+expected_semantic_rejection:\s*\(typeof\s+CONTRACT_DESCRIPTOR\)\['mutant_expected_semantic_rejection'\];/);
});

test('the declared public type expressions pass the independent audit, and type edits cannot pass silently', () => {
  const source = fs.readFileSync(TYPES_SOURCE_PATH, 'utf8');
  assert.deepEqual(auditTypeExpressions(source), [], 'shipped types.ts must pass the independent type-expression audit');

  // (a) StateField.value narrowed from JsonValue to string must be detected.
  const narrowed = source.replace('readonly value: JsonValue;', 'readonly value: string;');
  assert.ok(auditTypeExpressions(narrowed).some((p) => p.includes('StateField.value')), 'StateField.value narrowing to string must be detected');

  // (b) a nested member type drift (StateEvent.payload.from_state_id
  //     Identifier -> string) must be detected.
  const nestedDrift = source.replace('readonly from_state_id: Identifier;', 'readonly from_state_id: string;');
  assert.ok(auditTypeExpressions(nestedDrift).some((p) => p.includes('from_state_id')), 'nested member type drift must be detected');

  // (c) ManifestMutant.expected_semantic_rejection widened away from the
  //     descriptor literal must be detected.
  const widened = source.replace("(typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection']", 'AiptErrorCode');
  assert.ok(auditTypeExpressions(widened).some((p) => p.includes('descriptor-derived literal')), 'widening the mutant literal to AiptErrorCode must be detected');
});
