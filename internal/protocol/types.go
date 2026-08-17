package protocol

// Minimal wire/fixture types needed to consume every shared fixture
// document. Arbitrary JSON fields (state field values, action proposals,
// and the lossless JSON boundary) are carried as json.RawMessage — never
// interface{} followed by unchecked coercion. All raw values are strictly
// validated (duplicates, unsafe integers, negative zero, non-finite numbers)
// before they are ever stored.

import "encoding/json"

// Identity is the frozen protocol/schema/fixture identity triple carried by
// every fixture asset and every persisted envelope.
type Identity struct {
	ProtocolVersion string
	SchemaVersion   string
	FixtureID       string
}

// Seat is a seat identity record ($defs/seat).
type Seat struct {
	SeatID string `json:"seat_id"`
	Name   string `json:"name"`
}

// SeatSet is the fixture seat set document ($defs/seat_set).
type SeatSet struct {
	ProtocolVersion string `json:"protocol_version"`
	SchemaVersion   string `json:"schema_version"`
	FixtureID       string `json:"fixture_id"`
	Seats           []Seat `json:"seats"`
}

// Identity returns the identity triple of the seat set.
func (s *SeatSet) Identity() Identity {
	return Identity{ProtocolVersion: s.ProtocolVersion, SchemaVersion: s.SchemaVersion, FixtureID: s.FixtureID}
}

// Visibility is the mandatory per-field classification plus the non-empty
// authorized seat set ($defs/visibility).
type Visibility struct {
	Label             string   `json:"label"`
	AuthorizedSeatIDs []string `json:"authorized_seat_ids"`
}

// StateField is a classified state field; Value is the lossless arbitrary
// JSON boundary ($defs/state_field).
type StateField struct {
	FieldID    string          `json:"field_id"`
	Value      json.RawMessage `json:"value"`
	Visibility Visibility      `json:"visibility"`
}

// State is the deterministic game state (generic) ($defs/state).
type State struct {
	ProtocolVersion string       `json:"protocol_version"`
	SchemaVersion   string       `json:"schema_version"`
	FixtureID       string       `json:"fixture_id"`
	StateID         string       `json:"state_id"`
	Fields          []StateField `json:"fields"`
}

// Identity returns the identity triple of the state.
func (s *State) Identity() Identity {
	return Identity{ProtocolVersion: s.ProtocolVersion, SchemaVersion: s.SchemaVersion, FixtureID: s.FixtureID}
}

// Projection is the authorized per-seat projection of a state
// ($defs/projection).
type Projection struct {
	ProtocolVersion string       `json:"protocol_version"`
	SchemaVersion   string       `json:"schema_version"`
	FixtureID       string       `json:"fixture_id"`
	ProjectionID    string       `json:"projection_id"`
	SeatID          string       `json:"seat_id"`
	Fields          []StateField `json:"fields"`
}

// Identity returns the identity triple of the projection.
func (p *Projection) Identity() Identity {
	return Identity{ProtocolVersion: p.ProtocolVersion, SchemaVersion: p.SchemaVersion, FixtureID: p.FixtureID}
}

// ActionIntentParams is the generic action intent params ($defs/
// action_intent_params). Proposal is the optional lossless arbitrary JSON
// boundary (nil when absent).
type ActionIntentParams struct {
	Action   string          `json:"action"`
	SeatID   string          `json:"seat_id"`
	Proposal json.RawMessage `json:"proposal,omitempty"`
}

// ActionIntent is the generic action intent document ($defs/action_intent).
type ActionIntent struct {
	ProtocolVersion string             `json:"protocol_version"`
	SchemaVersion   string             `json:"schema_version"`
	FixtureID       string             `json:"fixture_id"`
	MessageID       string             `json:"message_id"`
	Method          string             `json:"method"`
	Params          ActionIntentParams `json:"params"`
}

// Identity returns the identity triple of the action intent.
func (a *ActionIntent) Identity() Identity {
	return Identity{ProtocolVersion: a.ProtocolVersion, SchemaVersion: a.SchemaVersion, FixtureID: a.FixtureID}
}

// ApplyActionResult is the applyAction response result
// ($defs/apply_action_result).
type ApplyActionResult struct {
	Accepted      bool         `json:"accepted"`
	TransitionID  string       `json:"transition_id"`
	AppliedFields []StateField `json:"applied_fields"`
}

// ErrorData is the optional protocol error data ($defs/error_object/data).
type ErrorData struct {
	ErrorCode string `json:"error_code"`
}

// ErrorObject is the protocol error object ($defs/error_object).
type ErrorObject struct {
	Code    int64      `json:"code"`
	Message string     `json:"message"`
	Data    *ErrorData `json:"data,omitempty"`
}

// Request is a strict JSON-RPC 2.0 request ($defs/jsonrpc_request).
type Request struct {
	JSONRPC         string             `json:"jsonrpc"`
	ID              RequestID          `json:"id"`
	Method          string             `json:"method"`
	Params          ActionIntentParams `json:"params"`
	ProtocolVersion string             `json:"protocol_version"`
	SchemaVersion   string             `json:"schema_version"`
	FixtureID       string             `json:"fixture_id"`
}

// Identity returns the identity triple of the request.
func (r *Request) Identity() Identity {
	return Identity{ProtocolVersion: r.ProtocolVersion, SchemaVersion: r.SchemaVersion, FixtureID: r.FixtureID}
}

// NotificationParams is the notification params object
// ($defs/jsonrpc_notification/properties/params).
type NotificationParams struct {
	Event *StateEvent `json:"event"`
}

// Notification is a strict JSON-RPC 2.0 notification
// ($defs/jsonrpc_notification).
type Notification struct {
	JSONRPC         string             `json:"jsonrpc"`
	Method          string             `json:"method"`
	Params          NotificationParams `json:"params"`
	ProtocolVersion string             `json:"protocol_version"`
	SchemaVersion   string             `json:"schema_version"`
	FixtureID       string             `json:"fixture_id"`
}

// Identity returns the identity triple of the notification.
func (n *Notification) Identity() Identity {
	return Identity{ProtocolVersion: n.ProtocolVersion, SchemaVersion: n.SchemaVersion, FixtureID: n.FixtureID}
}

// Response is a strict JSON-RPC 2.0 response ($defs/jsonrpc_response).
// Exactly one of Result / Error is non-nil.
type Response struct {
	JSONRPC         string             `json:"jsonrpc"`
	ID              RequestID          `json:"id"`
	ProtocolVersion string             `json:"protocol_version"`
	SchemaVersion   string             `json:"schema_version"`
	FixtureID       string             `json:"fixture_id"`
	Result          *ApplyActionResult `json:"result,omitempty"`
	Error           *ErrorObject       `json:"error,omitempty"`
}

// Identity returns the identity triple of the response.
func (r *Response) Identity() Identity {
	return Identity{ProtocolVersion: r.ProtocolVersion, SchemaVersion: r.SchemaVersion, FixtureID: r.FixtureID}
}

// EnvelopeKind discriminates the three registered wire envelopes.
type EnvelopeKind uint8

const (
	// EnvelopeRequest marks a jsonrpc_request envelope.
	EnvelopeRequest EnvelopeKind = iota + 1
	// EnvelopeResponse marks a jsonrpc_response envelope.
	EnvelopeResponse
	// EnvelopeNotification marks a jsonrpc_notification envelope.
	EnvelopeNotification
)

// Envelope is the discriminated root envelope: exactly one of the three
// registered wire envelope kinds, decoded into its exact Go type.
type Envelope struct {
	Kind         EnvelopeKind
	Request      *Request
	Response     *Response
	Notification *Notification
}

// DeterministicCheck is the versioned deterministic check
// ($defs/deterministic_check).
type DeterministicCheck struct {
	ProtocolVersion string    `json:"protocol_version"`
	SchemaVersion   string    `json:"schema_version"`
	FixtureID       string    `json:"fixture_id"`
	CheckID         string    `json:"check_id"`
	CheckVersion    string    `json:"check_version"`
	Kind            string    `json:"kind"`
	Operator        string    `json:"operator"`
	Inputs          []float64 `json:"inputs"`
	Output          float64   `json:"output"`
}

// Identity returns the identity triple of the check.
func (c *DeterministicCheck) Identity() Identity {
	return Identity{ProtocolVersion: c.ProtocolVersion, SchemaVersion: c.SchemaVersion, FixtureID: c.FixtureID}
}

// AppliedAction is the action reference of a state transition
// ($defs/state_transition/applied_action).
type AppliedAction struct {
	Action string `json:"action"`
	SeatID string `json:"seat_id"`
}

// StateTransition is the deterministic state transition
// ($defs/state_transition).
type StateTransition struct {
	ProtocolVersion string        `json:"protocol_version"`
	SchemaVersion   string        `json:"schema_version"`
	FixtureID       string        `json:"fixture_id"`
	TransitionID    string        `json:"transition_id"`
	FromStateID     string        `json:"from_state_id"`
	ToStateID       string        `json:"to_state_id"`
	AppliedAction   AppliedAction `json:"applied_action"`
	Result          []StateField  `json:"result"`
}

// Identity returns the identity triple of the transition.
func (t *StateTransition) Identity() Identity {
	return Identity{ProtocolVersion: t.ProtocolVersion, SchemaVersion: t.SchemaVersion, FixtureID: t.FixtureID}
}

// StateEventPayload is the event payload ($defs/state_event/payload).
type StateEventPayload struct {
	FromStateID string `json:"from_state_id"`
	ToStateID   string `json:"to_state_id"`
}

// StateEvent is the transition emission event ($defs/state_event).
type StateEvent struct {
	ProtocolVersion string            `json:"protocol_version"`
	SchemaVersion   string            `json:"schema_version"`
	FixtureID       string            `json:"fixture_id"`
	EventID         string            `json:"event_id"`
	TransitionID    string            `json:"transition_id"`
	EventType       string            `json:"event_type"`
	Payload         StateEventPayload `json:"payload"`
}

// Identity returns the identity triple of the event.
func (e *StateEvent) Identity() Identity {
	return Identity{ProtocolVersion: e.ProtocolVersion, SchemaVersion: e.SchemaVersion, FixtureID: e.FixtureID}
}

// ReplayRecord is one replay record ($defs/replay_assertion/replays/*).
type ReplayRecord struct {
	ReplayID       string `json:"replay_id"`
	FinalStateHash string `json:"final_state_hash"`
}

// ReplayAssertion asserts that replays over the same initial state yield the
// same final state hash ($defs/replay_assertion).
type ReplayAssertion struct {
	ProtocolVersion   string         `json:"protocol_version"`
	SchemaVersion     string         `json:"schema_version"`
	FixtureID         string         `json:"fixture_id"`
	AssertionID       string         `json:"assertion_id"`
	HashAlgorithm     string         `json:"hash_algorithm"`
	CanonicalJSONRule string         `json:"canonical_json_rule"`
	FinalStateRef     string         `json:"final_state_ref"`
	FinalStateHash    string         `json:"final_state_hash"`
	Replays           []ReplayRecord `json:"replays"`
}

// Identity returns the identity triple of the replay assertion.
func (r *ReplayAssertion) Identity() Identity {
	return Identity{ProtocolVersion: r.ProtocolVersion, SchemaVersion: r.SchemaVersion, FixtureID: r.FixtureID}
}

// ManifestAsset is one fixture asset manifest entry ($defs/manifest_asset).
type ManifestAsset struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	SchemaRef string `json:"schema_ref"`
	SHA256    string `json:"sha256"`
}

// ManifestMutant is one fixture mutant manifest entry
// ($defs/manifest_mutant).
type ManifestMutant struct {
	Path                      string `json:"path"`
	Kind                      string `json:"kind"`
	SchemaRef                 string `json:"schema_ref"`
	SHA256                    string `json:"sha256"`
	ExpectedSemanticRejection string `json:"expected_semantic_rejection"`
}

// Manifest is the minimal fixture manifest ($defs/fixture_manifest).
type Manifest struct {
	ProtocolVersion    string           `json:"protocol_version"`
	SchemaVersion      string           `json:"schema_version"`
	FixtureID          string           `json:"fixture_id"`
	FixtureName        string           `json:"fixture_name"`
	ExpectedFinalState string           `json:"expected_final_state"`
	ReplayAssertion    string           `json:"replay_assertion"`
	Assets             []ManifestAsset  `json:"assets"`
	Mutants            []ManifestMutant `json:"mutants"`
}

// Identity returns the identity triple of the manifest.
func (m *Manifest) Identity() Identity {
	return Identity{ProtocolVersion: m.ProtocolVersion, SchemaVersion: m.SchemaVersion, FixtureID: m.FixtureID}
}

// MutantSpecimen is the non-canonical hidden-leak mutant wrapper
// ($defs/mutant_specimen). The wrapped projection is schema-valid; the
// semantic rejection reason is produced by the projection gate, never by
// JSON syntax.
type MutantSpecimen struct {
	Markers       []string   `json:"markers"`
	Kind          string     `json:"kind"`
	MutantID      string     `json:"mutant_id"`
	SeatID        string     `json:"seat_id"`
	LeakedFieldID string     `json:"leaked_field_id"`
	Projection    Projection `json:"projection"`
}
