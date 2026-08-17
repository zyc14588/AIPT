package protocol

// Schema-derived wire constants. Every constant below is independently
// re-derived from the canonical schema's local $defs by the package tests
// (internal/protocol/schema_drift_test.go); a silent drift between these
// values and schemas/protocol/v1/aipt-protocol.schema.json fails the build.

const (
	// ProtocolVersion is the frozen wire protocol version
	// ($defs/protocol_version).
	ProtocolVersion = "1.0.0"
	// SchemaVersion is the frozen schema document version
	// ($defs/schema_version).
	SchemaVersion = "1.0.0"
	// JSONRPCVersion is the strict JSON-RPC transport version
	// ($defs/jsonrpc_version).
	JSONRPCVersion = "2.0"
)

// Method registry: exactly two registered methods exist.
const (
	// MethodRequest is the single registered JSON-RPC request method
	// ($defs/jsonrpc_request/properties/method).
	MethodRequest = "aipt.protocol.applyAction"
	// MethodNotification is the single registered JSON-RPC notification
	// method ($defs/jsonrpc_notification/properties/method).
	MethodNotification = "aipt.protocol.event"
)

// Cross-language-safe JSON-RPC integer id bounds
// ($defs/request_id_integer/minimum|maximum): the inclusive JavaScript
// safe-integer range, +-(2^53-1). Node JSON.parse reads every JSON number as
// an IEEE-754 double, so an integer id outside this range could silently
// round to a value a Go int64 consumer represents differently; the bounds
// keep the id identical across languages.
const (
	// SafeIntegerMin is the inclusive minimum for JSON integer values
	// (ids, error codes, and every integer anywhere in a document).
	SafeIntegerMin int64 = -9007199254740991
	// SafeIntegerMax is the inclusive maximum for JSON integer values.
	SafeIntegerMax int64 = 9007199254740991
)

// Frozen R4-F002 visibility labels ($defs/visibility_label/enum): exactly
// six labels exist; any other label fails closed.
const (
	VisibilityPublic                  = "PUBLIC"
	VisibilityUnreleasedRemoteAllowed = "UNRELEASED_REMOTE_ALLOWED"
	VisibilityTableHiddenRemote       = "TABLE_HIDDEN_REMOTE_ALLOWED"
	VisibilityLocalOnlySecret         = "LOCAL_ONLY_SECRET"
	VisibilityHumanPrivateData        = "HUMAN_PRIVATE_DATA"
	VisibilityCredentialSecret        = "CREDENTIAL_SECRET"
)

// VisibilityLabels returns the six frozen visibility labels in canonical
// schema order.
func VisibilityLabels() []string {
	return []string{
		VisibilityPublic,
		VisibilityUnreleasedRemoteAllowed,
		VisibilityTableHiddenRemote,
		VisibilityLocalOnlySecret,
		VisibilityHumanPrivateData,
		VisibilityCredentialSecret,
	}
}

// Frozen event / deterministic-check / mutant constants.
const (
	// EventTypeStateTransitionApplied is the only registered state event
	// type ($defs/state_event/properties/event_type).
	EventTypeStateTransitionApplied = "state_transition_applied"
	// CheckKindArithmetic is the only deterministic check kind
	// ($defs/deterministic_check/properties/kind).
	CheckKindArithmetic = "arithmetic"
	// CheckOperatorAdd is the only deterministic check operator
	// ($defs/deterministic_check/properties/operator).
	CheckOperatorAdd = "add"
	// CheckVersion is the frozen deterministic check version
	// ($defs/deterministic_check/properties/check_version).
	CheckVersion = "1.0.0"
	// HashAlgorithmSHA256 is the frozen replay hash algorithm
	// ($defs/replay_assertion/properties/hash_algorithm).
	HashAlgorithmSHA256 = "sha256"
	// FinalStateRef is the frozen manifest expected_final_state /
	// replay final_state_ref target.
	FinalStateRef = "final-state.json"
	// ReplayAssertionRef is the frozen manifest replay_assertion target.
	ReplayAssertionRef = "replay-assertion.json"
	// MutantKindHiddenLeak is the only mutant kind
	// ($defs/mutant_specimen/properties/kind).
	MutantKindHiddenLeak = "hidden-leak"
	// MutantMarkerNonCanon and MutantMarkerMutant are the exact frozen
	// mutant markers ($defs/mutant_specimen/properties/markers).
	MutantMarkerNonCanon = "NON_CANON"
	MutantMarkerMutant   = "MUTANT"
)

// Documented deterministic wire error example (B002_IMPLEMENTATION_CHOICE-009).
// The schema leaves JSON-RPC error `code` an unconstrained integer; the single
// persisted deterministic example uses the conventional server/application
// code -32000 with the generic stable data.error_code and a deterministic
// message describing rejection of the referenced advance-turn request.
const (
	// WireErrorExampleCode is the documented deterministic example code.
	WireErrorExampleCode int64 = -32000
	// WireErrorExampleDataCode is the documented generic stable
	// data.error_code carried by the example.
	WireErrorExampleDataCode = "AIPT_ACTION_REJECTED"
	// WireErrorExampleMessage is the documented deterministic example
	// message.
	WireErrorExampleMessage = "advance-turn action request from seat-a was rejected (AIPT_ACTION_REJECTED)"
)

// Identifier length bounds and frozen JSON Schema patterns (kept verbatim
// from the canonical schema so the schema-drift tests can compare them).
const (
	// MaxIdentifierLength bounds the 1..64 character identifiers
	// (fixture_id, seat_id, field_id, state_id, projection_id,
	// transition_id, event_id, replay_id, check_id, assertion_id,
	// mutant_id, action).
	MaxIdentifierLength = 64
	// MaxNameLength bounds the 1..64 character seat name.
	MaxNameLength = 64
	// MaxMessageIDLength bounds the 1..128 character message_id.
	MaxMessageIDLength = 128
	// MaxRequestIDStringLength bounds the 1..128 character string
	// JSON-RPC id alternative.
	MaxRequestIDStringLength = 128

	// PatternIdentifier is the frozen 1..64 lowercase machine-identity
	// pattern shared by the lowercase identifiers.
	PatternIdentifier = `^[a-z0-9][a-z0-9-]{0,63}$`
	// PatternMessageID is the frozen 1..128 message_id pattern.
	PatternMessageID = `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`
	// PatternSHA256Hex is the frozen 64-character lowercase SHA-256 hex
	// digest pattern.
	PatternSHA256Hex = `^[0-9a-f]{64}$`
	// PatternErrorCode is the frozen AIPT_* error code pattern.
	PatternErrorCode = `^AIPT_[A-Z0-9_]{1,63}$`
	// PatternSchemaRef is the frozen manifest schema_ref pattern.
	PatternSchemaRef = `^#/\$defs/[A-Za-z0-9_-]+$`
)

// Manifest fixture kinds and the exact kind -> schema_ref registry. The
// manifest-supplied $ref is never trusted: only this table decides which
// subschema a kind targets.
const (
	KindSeatSet             = "seat_set"
	KindState               = "state"
	KindProjection          = "projection"
	KindActionIntent        = "action_intent"
	KindDeterministicCheck  = "deterministic_check"
	KindStateTransition     = "state_transition"
	KindStateEvent          = "state_event"
	KindReplayAssertion     = "replay_assertion"
	KindMutantSpecimen      = "mutant_specimen"
	KindJSONRPCRequest      = "jsonrpc_request"
	KindJSONRPCResponse     = "jsonrpc_response"
	KindJSONRPCNotification = "jsonrpc_notification"
)

// ManifestKindSchemaRef is the exact kind -> canonical schema_ref mapping
// (the manifest-supplied schema_ref must equal this, never vice versa).
var ManifestKindSchemaRef = map[string]string{
	KindSeatSet:             "#/$defs/seat_set",
	KindState:               "#/$defs/state",
	KindProjection:          "#/$defs/projection",
	KindActionIntent:        "#/$defs/action_intent",
	KindDeterministicCheck:  "#/$defs/deterministic_check",
	KindStateTransition:     "#/$defs/state_transition",
	KindStateEvent:          "#/$defs/state_event",
	KindReplayAssertion:     "#/$defs/replay_assertion",
	KindMutantSpecimen:      "#/$defs/mutant_specimen",
	KindJSONRPCRequest:      "#/$defs/jsonrpc_request",
	KindJSONRPCResponse:     "#/$defs/jsonrpc_response",
	KindJSONRPCNotification: "#/$defs/jsonrpc_notification",
}

// FixtureIDMinimalArithmetic is the frozen fixture identity carried by every
// shared minimal-fixture asset and envelope.
const FixtureIDMinimalArithmetic = "minimal-v1-arithmetic"
