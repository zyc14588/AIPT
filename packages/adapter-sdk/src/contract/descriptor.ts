// Fail-closed contract drift manifest for the AIPT adapter contract SDK.
//
// This object is the SINGLE in-package source of contract constants. Every
// value is a deterministic projection of the canonical wire authority
// schemas/protocol/v1/aipt-protocol.schema.json; scripts/ci/validate/adapter-sdk.mjs
// re-derives the identical descriptor from that schema at gate time and
// compares it byte-for-byte (canonical JSON), so a schema edit or a constant
// edit that drifts the two apart fails the machine gate instead of passing
// silently. canonical_schema_sha256 is a FULL content fingerprint of the
// canonical schema document (SHA-256 over its key-sorted canonical JSON),
// re-computed independently by the machine gate: every canonical-schema edit —
// even one outside every projected field — changes the fingerprint and
// forces explicit SDK review. The public TypeScript literal unions in
// src/types.ts derive from this descriptor (and from the exported constant
// tuples in src/constants.ts) via `typeof`, so types cannot drift
// independently of the runtime contract; the machine gate additionally
// audits the declared public interface shapes against schema-derived member
// expectations. The canonical schema is never copied into this package: the
// descriptor is only a bounded contract projection, and the schema remains
// the single wire-contract authority.
export const CONTRACT_DESCRIPTOR = {
  canonical_schema_path: 'schemas/protocol/v1/aipt-protocol.schema.json',
  canonical_schema_sha256: '571e4a4c1f42adeb2eda8aa466c4ea621e547775c2064a5cc1acf6d9b2d76814',
  protocol_version: '1.0.0',
  schema_version: '1.0.0',
  jsonrpc_version: '2.0',
  request_methods: ['aipt.protocol.applyAction'],
  notification_methods: ['aipt.protocol.event'],
  envelope_variants: ['jsonrpc_request', 'jsonrpc_response', 'jsonrpc_notification'],
  envelope_required: {
    jsonrpc_request: ['jsonrpc', 'id', 'method', 'params', 'protocol_version', 'schema_version', 'fixture_id'],
    jsonrpc_response: ['jsonrpc', 'id', 'protocol_version', 'schema_version', 'fixture_id'],
    jsonrpc_notification: ['jsonrpc', 'method', 'params', 'protocol_version', 'schema_version', 'fixture_id'],
  },
  envelope_additional_properties: {
    jsonrpc_request: false,
    jsonrpc_response: false,
    jsonrpc_notification: false,
  },
  response_result_error_exclusive: true,
  id_integer_minimum: -9007199254740991,
  id_integer_maximum: 9007199254740991,
  id_string_min_length: 1,
  id_string_max_length: 128,
  visibility_labels: [
    'PUBLIC',
    'UNRELEASED_REMOTE_ALLOWED',
    'TABLE_HIDDEN_REMOTE_ALLOWED',
    'LOCAL_ONLY_SECRET',
    'HUMAN_PRIVATE_DATA',
    'CREDENTIAL_SECRET',
  ],
  error_code_pattern: '^AIPT_[A-Z0-9_]{1,63}$',
  identifier_pattern: '^[a-z0-9][a-z0-9-]{0,63}$',
  state_field_required: ['field_id', 'value', 'visibility'],
  visibility_required: ['label', 'authorized_seat_ids'],
  authorized_seat_ids_min_items: 1,
  fields_min_items: 1,
  applied_fields_min_items: 1,
  state_required: ['protocol_version', 'schema_version', 'fixture_id', 'state_id', 'fields'],
  projection_required: ['protocol_version', 'schema_version', 'fixture_id', 'projection_id', 'seat_id', 'fields'],
  action_intent_params_required: ['action', 'seat_id'],
  notification_params_required: ['event'],
  state_event_required: ['protocol_version', 'schema_version', 'fixture_id', 'event_id', 'transition_id', 'event_type', 'payload'],
  state_event_event_type: 'state_transition_applied',
  apply_action_result_required: ['accepted', 'transition_id', 'applied_fields'],
  apply_action_result_accepted: true,
  error_object_required: ['code', 'message'],
  fixture_manifest_required: ['protocol_version', 'schema_version', 'fixture_id', 'fixture_name', 'assets', 'expected_final_state', 'replay_assertion', 'mutants'],
  fixture_manifest_expected_final_state: 'final-state.json',
  fixture_manifest_replay_assertion: 'replay-assertion.json',
  manifest_kinds: [
    'seat_set',
    'state',
    'projection',
    'action_intent',
    'deterministic_check',
    'state_transition',
    'state_event',
    'replay_assertion',
    'jsonrpc_request',
    'jsonrpc_response',
    'jsonrpc_notification',
  ],
  // Exact kind -> canonical schema_ref mapping. The manifest-supplied $ref is
  // never trusted: this table alone decides which subschema validates a kind.
  manifest_kind_schema_refs: {
    seat_set: '#/$defs/seat_set',
    state: '#/$defs/state',
    projection: '#/$defs/projection',
    action_intent: '#/$defs/action_intent',
    deterministic_check: '#/$defs/deterministic_check',
    state_transition: '#/$defs/state_transition',
    state_event: '#/$defs/state_event',
    replay_assertion: '#/$defs/replay_assertion',
    jsonrpc_request: '#/$defs/jsonrpc_request',
    jsonrpc_response: '#/$defs/jsonrpc_response',
    jsonrpc_notification: '#/$defs/jsonrpc_notification',
    mutant_specimen: '#/$defs/mutant_specimen',
  },
  mutant_kind: 'mutant_specimen',
  mutant_expected_semantic_rejection: 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD',
  deterministic_check_check_version: '1.0.0',
  deterministic_check_kind: 'arithmetic',
  deterministic_check_operator: 'add',
  replay_assertion_hash_algorithm: 'sha256',
  replay_assertion_final_state_ref: 'final-state.json',
  mutant_specimen_markers: ['NON_CANON', 'MUTANT'],
  mutant_specimen_kind: 'hidden-leak',
} as const;

export type ContractDescriptor = typeof CONTRACT_DESCRIPTOR;
