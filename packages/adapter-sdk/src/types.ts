// Public TypeScript types of the AIPT adapter contract SDK.
//
// Literal unions derive from the exported readonly constant tuples in
// src/constants.ts and from the contract drift manifest in
// src/contract/descriptor.ts via `typeof` — they can never drift
// independently of the runtime contract constants that the machine gate
// compares against the canonical schema. The machine gate additionally
// audits every public interface declared below against schema-derived
// member-shape expectations AND against schema-derived member TYPE
// EXPRESSIONS (including nested object shapes and descriptor-derived
// const/discriminant literals), so a hand-edited member name, optionality,
// or type expression cannot pass silently. The package exports no `any`;
// `unknown` appears only at validation boundaries (fixture documents and
// validator inputs).
import { AIPT_ERROR_CODES, MANIFEST_KINDS, NOTIFICATION_METHODS, REQUEST_METHODS, VISIBILITY_LABELS } from './constants.ts';
import { CONTRACT_DESCRIPTOR } from './contract/descriptor.ts';

export type ProtocolVersion = (typeof CONTRACT_DESCRIPTOR)['protocol_version'];
export type SchemaVersion = (typeof CONTRACT_DESCRIPTOR)['schema_version'];
export type JsonRpcVersion = (typeof CONTRACT_DESCRIPTOR)['jsonrpc_version'];
export type RequestMethod = (typeof REQUEST_METHODS)[number];
export type NotificationMethod = (typeof NOTIFICATION_METHODS)[number];
export type Method = RequestMethod | NotificationMethod;
export type VisibilityLabel = (typeof VISIBILITY_LABELS)[number];

// The FINITE, stable SDK validation-issue code union. Every entry is an
// exported identifier from src/constants.ts and satisfies the canonical wire
// error-code pattern, but this union deliberately does NOT cover the open
// wire namespace: a canonical-valid future wire code (e.g.
// AIPT_FUTURE_EXTENSION) is a wire value of type AiptWireErrorCode, never an
// SDK validation-issue code.
export type AiptErrorCode = (typeof AIPT_ERROR_CODES)[number];

// The OPEN canonical wire AIPT error namespace: every string matching
// ^AIPT_[A-Z0-9_]{1,63}$ (enforced at runtime by isAiptWireErrorCode /
// validateErrorObject). Branded so a plain string cannot be assigned without
// going through the runtime gate, and distinct from the finite
// ValidationIssue.code union.
export type AiptWireErrorCode = string & { readonly __aipt_wire_error_code_brand: 'AiptWireErrorCode' };

export type FixtureKind = (typeof MANIFEST_KINDS)[number];

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

// JSON-RPC request/response id: a string, or an integer within the inclusive
// JavaScript safe-integer range [-(2^53-1), +(2^53-1)] (enforced at runtime).
export type SafeIntegerId = number;
export type RequestId = string | SafeIntegerId;

// Identifier pattern from the canonical schema: ^[a-z0-9][a-z0-9-]{0,63}$.
export type Identifier = string;
export type FixtureId = Identifier;
export type SeatId = Identifier;
export type FieldId = Identifier;

export interface ProtocolIdentity {
  readonly protocol_version: ProtocolVersion;
  readonly schema_version: SchemaVersion;
  readonly fixture_id: FixtureId;
}

export interface Visibility {
  readonly label: VisibilityLabel;
  readonly authorized_seat_ids: readonly SeatId[];
}

export interface StateField {
  readonly field_id: FieldId;
  readonly value: JsonValue;
  readonly visibility: Visibility;
}

export interface State extends ProtocolIdentity {
  readonly state_id: Identifier;
  readonly fields: readonly StateField[];
}

export interface Projection extends ProtocolIdentity {
  readonly projection_id: Identifier;
  readonly seat_id: SeatId;
  readonly fields: readonly StateField[];
}

export interface ActionIntentParams {
  readonly action: Identifier;
  readonly seat_id: SeatId;
  readonly proposal?: JsonValue;
}

export interface ActionIntent extends ProtocolIdentity {
  readonly message_id: string;
  readonly method: RequestMethod;
  readonly params: ActionIntentParams;
}

export interface ApplyActionResult {
  readonly accepted: (typeof CONTRACT_DESCRIPTOR)['apply_action_result_accepted'];
  readonly transition_id: Identifier;
  readonly applied_fields: readonly StateField[];
}

export type Result = ApplyActionResult;

export interface ErrorObject {
  readonly code: number;
  readonly message: string;
  readonly data?: {
    readonly error_code: AiptWireErrorCode;
  };
}

export type ProtocolError = ErrorObject;

export interface JsonRpcRequest extends ProtocolIdentity {
  readonly jsonrpc: JsonRpcVersion;
  readonly id: RequestId;
  readonly method: RequestMethod;
  readonly params: ActionIntentParams;
}

export interface JsonRpcResultResponse extends ProtocolIdentity {
  readonly jsonrpc: JsonRpcVersion;
  readonly id: RequestId;
  readonly result: ApplyActionResult;
  readonly error?: never;
}

export interface JsonRpcErrorResponse extends ProtocolIdentity {
  readonly jsonrpc: JsonRpcVersion;
  readonly id: RequestId;
  readonly error: ErrorObject;
  readonly result?: never;
}

export type JsonRpcResponse = JsonRpcResultResponse | JsonRpcErrorResponse;

export interface StateEvent extends ProtocolIdentity {
  readonly event_id: Identifier;
  readonly transition_id: Identifier;
  readonly event_type: (typeof CONTRACT_DESCRIPTOR)['state_event_event_type'];
  readonly payload: {
    readonly from_state_id: Identifier;
    readonly to_state_id: Identifier;
  };
}

export interface JsonRpcNotification extends ProtocolIdentity {
  readonly jsonrpc: JsonRpcVersion;
  readonly method: NotificationMethod;
  readonly params: {
    readonly event: StateEvent;
  };
}

// The executable canonical root: exactly one of the three registered wire
// envelopes (validated at runtime; the union mirrors the schema oneOf).
export type ExecutableRoot = JsonRpcRequest | JsonRpcResponse | JsonRpcNotification;

// ---- Fixture protocol documents (every canonical manifest kind) ----

export interface Seat {
  readonly seat_id: SeatId;
  readonly name: string;
}

export interface SeatSet extends ProtocolIdentity {
  readonly seats: readonly Seat[];
}

export interface DeterministicCheck extends ProtocolIdentity {
  readonly check_id: Identifier;
  readonly check_version: (typeof CONTRACT_DESCRIPTOR)['deterministic_check_check_version'];
  readonly kind: (typeof CONTRACT_DESCRIPTOR)['deterministic_check_kind'];
  readonly operator: (typeof CONTRACT_DESCRIPTOR)['deterministic_check_operator'];
  readonly inputs: readonly number[];
  readonly output: number;
}

export interface StateTransition extends ProtocolIdentity {
  readonly transition_id: Identifier;
  readonly from_state_id: Identifier;
  readonly to_state_id: Identifier;
  readonly applied_action: {
    readonly action: Identifier;
    readonly seat_id: SeatId;
  };
  readonly result: readonly StateField[];
}

export interface ReplayRecord {
  readonly replay_id: Identifier;
  readonly final_state_hash: string;
}

export interface ReplayAssertion extends ProtocolIdentity {
  readonly assertion_id: Identifier;
  readonly hash_algorithm: (typeof CONTRACT_DESCRIPTOR)['replay_assertion_hash_algorithm'];
  readonly canonical_json_rule: string;
  readonly final_state_ref: (typeof CONTRACT_DESCRIPTOR)['replay_assertion_final_state_ref'];
  readonly final_state_hash: string;
  readonly replays: readonly ReplayRecord[];
}

export interface MutantSpecimen {
  readonly markers: (typeof CONTRACT_DESCRIPTOR)['mutant_specimen_markers'];
  readonly kind: (typeof CONTRACT_DESCRIPTOR)['mutant_specimen_kind'];
  readonly mutant_id: Identifier;
  readonly seat_id: SeatId;
  readonly leaked_field_id: Identifier;
  readonly projection: Projection;
}

// ---- Fixture manifest / bundle ----

export interface ManifestAsset {
  readonly path: string;
  readonly kind: FixtureKind;
  readonly schema_ref: string;
  readonly sha256: string;
}

export interface ManifestMutant {
  readonly path: string;
  readonly kind: (typeof CONTRACT_DESCRIPTOR)['mutant_kind'];
  readonly schema_ref: string;
  readonly sha256: string;
  // The exact canonical const, derived from the contract descriptor literal:
  // NOT the broader finite AiptErrorCode union. A widened hand edit fails
  // the machine gate's type-expression audit.
  readonly expected_semantic_rejection: (typeof CONTRACT_DESCRIPTOR)['mutant_expected_semantic_rejection'];
}

export interface FixtureManifest extends ProtocolIdentity {
  readonly fixture_name: string;
  readonly assets: readonly ManifestAsset[];
  readonly expected_final_state: (typeof CONTRACT_DESCRIPTOR)['fixture_manifest_expected_final_state'];
  readonly replay_assertion: (typeof CONTRACT_DESCRIPTOR)['fixture_manifest_replay_assertion'];
  readonly mutants: readonly ManifestMutant[];
}

// A supplied fixture bundle: the parsed manifest plus the parsed documents
// keyed by manifest path. `unknown` is a validation boundary only — the
// compatibility helpers validate every document (lossless JSON value gate,
// canonical digest, canonical-schema instance, identity, semantic mutant
// proof) before trusting it. The canonical schema document may be carried
// here or passed as the explicit second argument of validateFixtureBundle.
export interface FixtureBundle {
  readonly manifest: FixtureManifest;
  readonly documents: ReadonlyMap<string, unknown>;
  readonly schema?: unknown;
}
