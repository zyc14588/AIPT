// Public TypeScript types of the AIPT adapter contract SDK.
//
// Literal unions derive from the exported readonly constant tuples in
// src/constants.ts and from the contract drift manifest in
// src/contract/descriptor.ts via `typeof` — they can never drift
// independently of the runtime contract constants that the machine gate
// compares against the canonical schema. The package exports no `any`;
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
export type AiptErrorCode = (typeof AIPT_ERROR_CODES)[number];
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
    readonly error_code: AiptErrorCode;
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
  readonly expected_semantic_rejection: AiptErrorCode;
}

export interface FixtureManifest extends ProtocolIdentity {
  readonly fixture_name: string;
  readonly assets: readonly ManifestAsset[];
  readonly expected_final_state: string;
  readonly replay_assertion: string;
  readonly mutants: readonly ManifestMutant[];
}

// A supplied fixture bundle: the parsed manifest plus the parsed documents
// keyed by manifest path. `unknown` is a validation boundary only — the
// compatibility helpers validate every document before trusting it.
export interface FixtureBundle {
  readonly manifest: FixtureManifest;
  readonly documents: ReadonlyMap<string, unknown>;
}
