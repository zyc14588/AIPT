package protocol

// Strict typed decoding. Every decoder runs over the strict parser tree, so
// duplicate keys at any depth, trailing input, unsafe integers, negative
// zero, and non-finite numbers are already rejected before any typed member
// is read. On top of that, each decoder enforces: unknown members, missing
// required members (explicit-null and zero-value bypasses included), JSON
// types, frozen const/version/enum values, identifier patterns and length
// bounds, and the exact method registry.

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
)

var (
	reIdentifier = regexp.MustCompile(PatternIdentifier)
	reMessageID  = regexp.MustCompile(PatternMessageID)
	reSHA256Hex  = regexp.MustCompile(PatternSHA256Hex)
	reErrorCode  = regexp.MustCompile(PatternErrorCode)
	reSchemaRef  = regexp.MustCompile(PatternSchemaRef)
)

// ---------------------------------------------------------------------------
// Member-set reader.
// ---------------------------------------------------------------------------

// memberSet is a strict object-member reader over a parsed object node.
type memberSet struct {
	n       *jsonNode
	path    string
	present map[string]*jsonNode
}

// newMemberSet requires n to be an object carrying only the allowed members.
func newMemberSet(n *jsonNode, path string, allowed ...string) (*memberSet, error) {
	if n.kind != kindObject {
		return nil, newContractError(ReasonJSONInvalidType, path, "expected a JSON object")
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = true
	}
	ms := &memberSet{n: n, path: path, present: make(map[string]*jsonNode, len(n.members))}
	for _, m := range n.members {
		if !allowedSet[m.key] {
			return nil, newContractError(ReasonJSONUnknownMember, path+"/"+m.key,
				fmt.Sprintf("unknown member %q", m.key))
		}
		ms.present[m.key] = m.val
	}
	return ms, nil
}

func (ms *memberSet) get(key string) (*jsonNode, bool) {
	v, ok := ms.present[key]
	return v, ok
}

// required returns the non-null node of a required member, or a typed error
// for a missing member (including explicit-null bypasses).
func (ms *memberSet) required(key string) (*jsonNode, error) {
	v, ok := ms.present[key]
	if !ok {
		return nil, newContractError(ReasonJSONMissingMember, ms.path+"/"+key,
			fmt.Sprintf("missing required member %q", key))
	}
	if v.kind == kindNull {
		return nil, newContractError(ReasonJSONNullMember, ms.path+"/"+key,
			fmt.Sprintf("required member %q must not be null", key))
	}
	return v, nil
}

// optional returns the non-null node of an optional member: (node, true,
// nil) when present, (nil, false, nil) when absent, and an error when
// present but explicitly null (typed optionals never accept null).
func (ms *memberSet) optional(key string) (*jsonNode, bool, error) {
	v, ok := ms.present[key]
	if !ok {
		return nil, false, nil
	}
	if v.kind == kindNull {
		return nil, false, newContractError(ReasonJSONNullMember, ms.path+"/"+key,
			fmt.Sprintf("member %q must not be null", key))
	}
	return v, true, nil
}

func (ms *memberSet) requiredString(key string, validators ...stringValidator) (string, error) {
	v, err := ms.required(key)
	if err != nil {
		return "", err
	}
	if v.kind != kindString {
		return "", newContractError(ReasonJSONInvalidType, ms.path+"/"+key,
			fmt.Sprintf("member %q must be a string", key))
	}
	return ms.applyValidators(key, v.str, validators...)
}

func (ms *memberSet) applyValidators(key, value string, validators ...stringValidator) (string, error) {
	for _, vd := range validators {
		if err := vd(value, ms.path+"/"+key); err != nil {
			return "", err
		}
	}
	return value, nil
}

// requiredRaw returns the exact raw JSON of a required member. Null is a
// legal raw JSON value, so it is not rejected here (the schema's {}
// boundary accepts null).
func (ms *memberSet) requiredRaw(key string) (json.RawMessage, error) {
	v, ok := ms.present[key]
	if !ok {
		return nil, newContractError(ReasonJSONMissingMember, ms.path+"/"+key,
			fmt.Sprintf("missing required member %q", key))
	}
	return v.raw(), nil
}

// optionalRaw returns the exact raw JSON of an optional member; absent
// members yield (nil, false, nil) and an explicit null yields ("null",
// true, nil) because the schema's {} boundary accepts null.
func (ms *memberSet) optionalRaw(key string) (json.RawMessage, bool, error) {
	v, ok := ms.present[key]
	if !ok {
		return nil, false, nil
	}
	return v.raw(), true, nil
}

// ---------------------------------------------------------------------------
// String validators.
// ---------------------------------------------------------------------------

type stringValidator func(value, path string) error

func validateExact(want, reason string) stringValidator {
	return func(value, path string) error {
		if value != want {
			return newContractError(reason, path,
				fmt.Sprintf("value must be exactly %q, got %q", want, value))
		}
		return nil
	}
}

func makePatternValidator(re *regexp.Regexp, reason, what string) stringValidator {
	return func(value, path string) error {
		if !re.MatchString(value) {
			return newContractError(reason, path,
				fmt.Sprintf("%s must match %q, got %q", what, re.String(), value))
		}
		return nil
	}
}

func validateIdentifier(value, path string) error {
	if !reIdentifier.MatchString(value) {
		return newContractError(ReasonIdentifierInvalid, path,
			fmt.Sprintf("identifier must match %q, got %q", PatternIdentifier, value))
	}
	return nil
}

func validateSeatName(value, path string) error {
	if value == "" {
		return newContractError(ReasonIdentifierInvalid, path, "name must not be empty")
	}
	if len([]rune(value)) > MaxNameLength {
		return newContractError(ReasonIdentifierInvalid, path,
			fmt.Sprintf("name exceeds %d characters", MaxNameLength))
	}
	return nil
}

func validateNonEmpty(value, path string) error {
	if value == "" {
		return newContractError(ReasonIdentifierInvalid, path, "string must not be empty")
	}
	return nil
}

func validateVisibilityLabel(value, path string) error {
	for _, label := range VisibilityLabels() {
		if value == label {
			return nil
		}
	}
	return newContractError(ReasonVisibilityLabelInvalid, path,
		fmt.Sprintf("visibility label must be one of the six frozen R4-F002 labels, got %q", value))
}

func validateAuthorizedSeatIDs(ids []string, path string) error {
	if len(ids) == 0 {
		return newContractError(ReasonVisibilityAuthorizationInvalid, path,
			"authorized_seat_ids must never be empty")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !reIdentifier.MatchString(id) {
			return newContractError(ReasonVisibilityAuthorizationInvalid, path,
				fmt.Sprintf("authorized seat id must match %q, got %q", PatternIdentifier, id))
		}
		if seen[id] {
			return newContractError(ReasonVisibilityAuthorizationInvalid, path,
				fmt.Sprintf("authorized_seat_ids carries duplicate seat id %q", id))
		}
		seen[id] = true
	}
	return nil
}

// ---------------------------------------------------------------------------
// Identity / shared sub-documents.
// ---------------------------------------------------------------------------

// decodeIdentity decodes protocol_version / schema_version / fixture_id with
// the frozen consts and the fixture_id pattern. Version failures carry their
// own distinguishable reasons.
func decodeIdentity(ms *memberSet) (Identity, error) {
	pv, err := ms.requiredString("protocol_version",
		validateExact(ProtocolVersion, ReasonProtocolVersionInvalid))
	if err != nil {
		return Identity{}, err
	}
	sv, err := ms.requiredString("schema_version",
		validateExact(SchemaVersion, ReasonSchemaVersionInvalid))
	if err != nil {
		return Identity{}, err
	}
	fid, err := ms.requiredString("fixture_id",
		makePatternValidator(reIdentifier, ReasonFixtureIDInvalid, "fixture_id"))
	if err != nil {
		return Identity{}, err
	}
	return Identity{ProtocolVersion: pv, SchemaVersion: sv, FixtureID: fid}, nil
}

func decodeVisibility(n *jsonNode, path string) (Visibility, error) {
	ms, err := newMemberSet(n, path, "label", "authorized_seat_ids")
	if err != nil {
		return Visibility{}, err
	}
	label, err := ms.requiredString("label", validateVisibilityLabel)
	if err != nil {
		return Visibility{}, err
	}
	idsNode, err := ms.required("authorized_seat_ids")
	if err != nil {
		return Visibility{}, err
	}
	if idsNode.kind != kindArray {
		return Visibility{}, newContractError(ReasonJSONInvalidType, path+"/authorized_seat_ids",
			"authorized_seat_ids must be an array")
	}
	ids := make([]string, 0, len(idsNode.arr))
	for i, item := range idsNode.arr {
		if item.kind != kindString {
			return Visibility{}, newContractError(ReasonJSONInvalidType,
				fmt.Sprintf("%s/authorized_seat_ids/%d", path, i), "authorized seat id must be a string")
		}
		ids = append(ids, item.str)
	}
	if err := validateAuthorizedSeatIDs(ids, path+"/authorized_seat_ids"); err != nil {
		return Visibility{}, err
	}
	return Visibility{Label: label, AuthorizedSeatIDs: ids}, nil
}

func decodeStateField(n *jsonNode, path string) (StateField, error) {
	ms, err := newMemberSet(n, path, "field_id", "value", "visibility")
	if err != nil {
		return StateField{}, err
	}
	fieldID, err := ms.requiredString("field_id", validateIdentifier)
	if err != nil {
		return StateField{}, err
	}
	value, err := ms.requiredRaw("value")
	if err != nil {
		return StateField{}, err
	}
	visNode, err := ms.required("visibility")
	if err != nil {
		return StateField{}, err
	}
	vis, err := decodeVisibility(visNode, path+"/visibility")
	if err != nil {
		return StateField{}, err
	}
	return StateField{FieldID: fieldID, Value: value, Visibility: vis}, nil
}

func decodeStateFields(arr *jsonNode, path string) ([]StateField, error) {
	if arr.kind != kindArray {
		return nil, newContractError(ReasonJSONInvalidType, path, "expected an array")
	}
	if len(arr.arr) == 0 {
		return nil, newContractError(ReasonStateMissingFields, path, "fields must not be empty")
	}
	fields := make([]StateField, 0, len(arr.arr))
	for i, item := range arr.arr {
		f, err := decodeStateField(item, fmt.Sprintf("%s/%d", path, i))
		if err != nil {
			return nil, err
		}
		fields = append(fields, f)
	}
	return fields, nil
}

// ---------------------------------------------------------------------------
// Fixture documents.
// ---------------------------------------------------------------------------

// DecodeSeatSet strictly decodes a seat set document ($defs/seat_set).
func DecodeSeatSet(data []byte) (*SeatSet, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "seats")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	seatsNode, err := ms.required("seats")
	if err != nil {
		return nil, err
	}
	if seatsNode.kind != kindArray {
		return nil, newContractError(ReasonJSONInvalidType, "$/seats", "seats must be an array")
	}
	if len(seatsNode.arr) == 0 {
		return nil, newContractError(ReasonSeatSetInvalid, "$/seats", "seats must not be empty")
	}
	seats := make([]Seat, 0, len(seatsNode.arr))
	for i, item := range seatsNode.arr {
		sms, err := newMemberSet(item, fmt.Sprintf("$/seats/%d", i), "seat_id", "name")
		if err != nil {
			return nil, err
		}
		seatID, err := sms.requiredString("seat_id", validateIdentifier)
		if err != nil {
			return nil, err
		}
		name, err := sms.requiredString("name", validateSeatName)
		if err != nil {
			return nil, err
		}
		seats = append(seats, Seat{SeatID: seatID, Name: name})
	}
	return &SeatSet{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		Seats:           seats,
	}, nil
}

// DecodeState strictly decodes a state document ($defs/state).
func DecodeState(data []byte) (*State, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "state_id", "fields")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	stateID, err := ms.requiredString("state_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	fieldsNode, err := ms.required("fields")
	if err != nil {
		return nil, err
	}
	fields, err := decodeStateFields(fieldsNode, "$/fields")
	if err != nil {
		return nil, err
	}
	return &State{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		StateID:         stateID,
		Fields:          fields,
	}, nil
}

// DecodeProjection strictly decodes a projection document ($defs/projection).
func DecodeProjection(data []byte) (*Projection, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	return decodeProjectionFromNode(root, "$")
}

// decodeActionIntentParamsFromNode decodes the params object shared by
// action_intent documents and jsonrpc_request envelopes.
func decodeActionIntentParamsFromNode(n *jsonNode, path string) (ActionIntentParams, error) {
	ms, err := newMemberSet(n, path, "action", "seat_id", "proposal")
	if err != nil {
		return ActionIntentParams{}, err
	}
	action, err := ms.requiredString("action", validateIdentifier)
	if err != nil {
		return ActionIntentParams{}, err
	}
	seatID, err := ms.requiredString("seat_id", validateIdentifier)
	if err != nil {
		return ActionIntentParams{}, err
	}
	proposal, _, err := ms.optionalRaw("proposal")
	if err != nil {
		return ActionIntentParams{}, err
	}
	return ActionIntentParams{Action: action, SeatID: seatID, Proposal: proposal}, nil
}

// DecodeActionIntent strictly decodes an action intent document
// ($defs/action_intent).
func DecodeActionIntent(data []byte) (*ActionIntent, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "message_id", "method", "params")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	messageID, err := ms.requiredString("message_id",
		makePatternValidator(reMessageID, ReasonIdentifierInvalid, "message_id"))
	if err != nil {
		return nil, err
	}
	method, err := ms.requiredString("method", validateExact(MethodRequest, ReasonMethodInvalid))
	if err != nil {
		return nil, err
	}
	paramsNode, err := ms.required("params")
	if err != nil {
		return nil, err
	}
	params, err := decodeActionIntentParamsFromNode(paramsNode, "$/params")
	if err != nil {
		return nil, err
	}
	return &ActionIntent{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		MessageID:       messageID,
		Method:          method,
		Params:          params,
	}, nil
}

// DecodeDeterministicCheck strictly decodes a deterministic check document
// ($defs/deterministic_check).
func DecodeDeterministicCheck(data []byte) (*DeterministicCheck, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "check_id", "check_version", "kind", "operator", "inputs", "output")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	checkID, err := ms.requiredString("check_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	checkVersion, err := ms.requiredString("check_version", validateExact(CheckVersion, ReasonCheckInvalid))
	if err != nil {
		return nil, err
	}
	kind, err := ms.requiredString("kind", validateExact(CheckKindArithmetic, ReasonCheckInvalid))
	if err != nil {
		return nil, err
	}
	operator, err := ms.requiredString("operator", validateExact(CheckOperatorAdd, ReasonCheckInvalid))
	if err != nil {
		return nil, err
	}
	inputsNode, err := ms.required("inputs")
	if err != nil {
		return nil, err
	}
	if inputsNode.kind != kindArray {
		return nil, newContractError(ReasonJSONInvalidType, "$/inputs", "inputs must be an array")
	}
	if len(inputsNode.arr) < 2 || len(inputsNode.arr) > 8 {
		return nil, newContractError(ReasonCheckInvalid, "$/inputs",
			fmt.Sprintf("inputs must carry 2..8 numbers, got %d", len(inputsNode.arr)))
	}
	inputs := make([]float64, 0, len(inputsNode.arr))
	for i, item := range inputsNode.arr {
		if item.kind == kindNull {
			return nil, newContractError(ReasonJSONNullMember, fmt.Sprintf("$/inputs/%d", i), "input must be a number, not null")
		}
		if item.kind != kindNumber {
			return nil, newContractError(ReasonJSONInvalidType, fmt.Sprintf("$/inputs/%d", i), "input must be a number")
		}
		inputs = append(inputs, item.float64Value())
	}
	outputNode, err := ms.required("output")
	if err != nil {
		return nil, err
	}
	if outputNode.kind == kindNull {
		return nil, newContractError(ReasonJSONNullMember, "$/output", "output must be a number, not null")
	}
	if outputNode.kind != kindNumber {
		return nil, newContractError(ReasonJSONInvalidType, "$/output", "output must be a number")
	}
	return &DeterministicCheck{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		CheckID:         checkID,
		CheckVersion:    checkVersion,
		Kind:            kind,
		Operator:        operator,
		Inputs:          inputs,
		Output:          outputNode.float64Value(),
	}, nil
}

// DecodeStateTransition strictly decodes a state transition document
// ($defs/state_transition).
func DecodeStateTransition(data []byte) (*StateTransition, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "transition_id", "from_state_id", "to_state_id", "applied_action", "result")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	transitionID, err := ms.requiredString("transition_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	fromStateID, err := ms.requiredString("from_state_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	toStateID, err := ms.requiredString("to_state_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	appliedNode, err := ms.required("applied_action")
	if err != nil {
		return nil, err
	}
	ams, err := newMemberSet(appliedNode, "$/applied_action", "action", "seat_id")
	if err != nil {
		return nil, err
	}
	action, err := ams.requiredString("action", validateIdentifier)
	if err != nil {
		return nil, err
	}
	actionSeat, err := ams.requiredString("seat_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	resultNode, err := ms.required("result")
	if err != nil {
		return nil, err
	}
	result, err := decodeStateFields(resultNode, "$/result")
	if err != nil {
		return nil, err
	}
	return &StateTransition{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		TransitionID:    transitionID,
		FromStateID:     fromStateID,
		ToStateID:       toStateID,
		AppliedAction:   AppliedAction{Action: action, SeatID: actionSeat},
		Result:          result,
	}, nil
}

// DecodeStateEvent strictly decodes a state event document
// ($defs/state_event).
func DecodeStateEvent(data []byte) (*StateEvent, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	return decodeStateEventFromNode(root, "$")
}

func decodeStateEventFromNode(n *jsonNode, path string) (*StateEvent, error) {
	ms, err := newMemberSet(n, path, "protocol_version", "schema_version", "fixture_id", "event_id", "transition_id", "event_type", "payload")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	eventID, err := ms.requiredString("event_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	transitionID, err := ms.requiredString("transition_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	eventType, err := ms.requiredString("event_type",
		validateExact(EventTypeStateTransitionApplied, ReasonStateEventInvalid))
	if err != nil {
		return nil, err
	}
	payloadNode, err := ms.required("payload")
	if err != nil {
		return nil, err
	}
	pms, err := newMemberSet(payloadNode, path+"/payload", "from_state_id", "to_state_id")
	if err != nil {
		return nil, err
	}
	fromStateID, err := pms.requiredString("from_state_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	toStateID, err := pms.requiredString("to_state_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	return &StateEvent{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		EventID:         eventID,
		TransitionID:    transitionID,
		EventType:       eventType,
		Payload:         StateEventPayload{FromStateID: fromStateID, ToStateID: toStateID},
	}, nil
}

// DecodeReplayAssertion strictly decodes a replay assertion document
// ($defs/replay_assertion).
func DecodeReplayAssertion(data []byte) (*ReplayAssertion, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "assertion_id", "hash_algorithm", "canonical_json_rule", "final_state_ref", "final_state_hash", "replays")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	assertionID, err := ms.requiredString("assertion_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	hashAlgorithm, err := ms.requiredString("hash_algorithm",
		validateExact(HashAlgorithmSHA256, ReasonReplayAssertionInvalid))
	if err != nil {
		return nil, err
	}
	canonicalRule, err := ms.requiredString("canonical_json_rule", validateNonEmpty)
	if err != nil {
		return nil, err
	}
	finalStateRef, err := ms.requiredString("final_state_ref",
		validateExact(FinalStateRef, ReasonReplayAssertionInvalid))
	if err != nil {
		return nil, err
	}
	finalStateHash, err := ms.requiredString("final_state_hash",
		makePatternValidator(reSHA256Hex, ReasonReplayAssertionInvalid, "final_state_hash"))
	if err != nil {
		return nil, err
	}
	replaysNode, err := ms.required("replays")
	if err != nil {
		return nil, err
	}
	if replaysNode.kind != kindArray {
		return nil, newContractError(ReasonJSONInvalidType, "$/replays", "replays must be an array")
	}
	if len(replaysNode.arr) != 2 {
		return nil, newContractError(ReasonReplayAssertionInvalid, "$/replays",
			fmt.Sprintf("replay assertion must carry exactly two replay records, got %d", len(replaysNode.arr)))
	}
	replays := make([]ReplayRecord, 0, 2)
	for i, item := range replaysNode.arr {
		rms, err := newMemberSet(item, fmt.Sprintf("$/replays/%d", i), "replay_id", "final_state_hash")
		if err != nil {
			return nil, err
		}
		replayID, err := rms.requiredString("replay_id", validateIdentifier)
		if err != nil {
			return nil, err
		}
		hash, err := rms.requiredString("final_state_hash",
			makePatternValidator(reSHA256Hex, ReasonReplayAssertionInvalid, "final_state_hash"))
		if err != nil {
			return nil, err
		}
		replays = append(replays, ReplayRecord{ReplayID: replayID, FinalStateHash: hash})
	}
	return &ReplayAssertion{
		ProtocolVersion:   identity.ProtocolVersion,
		SchemaVersion:     identity.SchemaVersion,
		FixtureID:         identity.FixtureID,
		AssertionID:       assertionID,
		HashAlgorithm:     hashAlgorithm,
		CanonicalJSONRule: canonicalRule,
		FinalStateRef:     finalStateRef,
		FinalStateHash:    finalStateHash,
		Replays:           replays,
	}, nil
}

// DecodeManifest strictly decodes a fixture manifest document
// ($defs/fixture_manifest).
func DecodeManifest(data []byte) (*Manifest, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "protocol_version", "schema_version", "fixture_id", "fixture_name", "expected_final_state", "replay_assertion", "assets", "mutants")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	fixtureName, err := ms.requiredString("fixture_name", validateNonEmpty)
	if err != nil {
		return nil, err
	}
	expectedFinal, err := ms.requiredString("expected_final_state",
		validateExact(FinalStateRef, ReasonManifestInvalid))
	if err != nil {
		return nil, err
	}
	replayRef, err := ms.requiredString("replay_assertion",
		validateExact(ReplayAssertionRef, ReasonManifestInvalid))
	if err != nil {
		return nil, err
	}
	assetsNode, err := ms.required("assets")
	if err != nil {
		return nil, err
	}
	if assetsNode.kind != kindArray {
		return nil, newContractError(ReasonJSONInvalidType, "$/assets", "assets must be an array")
	}
	if len(assetsNode.arr) == 0 {
		return nil, newContractError(ReasonManifestInvalid, "$/assets", "assets must not be empty")
	}
	assets := make([]ManifestAsset, 0, len(assetsNode.arr))
	for i, item := range assetsNode.arr {
		ams, err := newMemberSet(item, fmt.Sprintf("$/assets/%d", i), "path", "kind", "schema_ref", "sha256")
		if err != nil {
			return nil, err
		}
		p, err := ams.requiredString("path", validateNonEmpty)
		if err != nil {
			return nil, err
		}
		kind, err := ams.requiredString("kind", validateManifestKind)
		if err != nil {
			return nil, err
		}
		schemaRef, err := ams.requiredString("schema_ref",
			makePatternValidator(reSchemaRef, ReasonManifestInvalid, "schema_ref"))
		if err != nil {
			return nil, err
		}
		sha, err := ams.requiredString("sha256",
			makePatternValidator(reSHA256Hex, ReasonManifestInvalid, "sha256"))
		if err != nil {
			return nil, err
		}
		assets = append(assets, ManifestAsset{Path: p, Kind: kind, SchemaRef: schemaRef, SHA256: sha})
	}
	mutantsNode, err := ms.required("mutants")
	if err != nil {
		return nil, err
	}
	if mutantsNode.kind != kindArray {
		return nil, newContractError(ReasonJSONInvalidType, "$/mutants", "mutants must be an array")
	}
	if len(mutantsNode.arr) != 1 {
		return nil, newContractError(ReasonManifestInvalid, "$/mutants",
			fmt.Sprintf("manifest must carry exactly one mutant entry, got %d", len(mutantsNode.arr)))
	}
	mm := mutantsNode.arr[0]
	mms, err := newMemberSet(mm, "$/mutants/0", "path", "kind", "schema_ref", "sha256", "expected_semantic_rejection")
	if err != nil {
		return nil, err
	}
	mPath, err := mms.requiredString("path", validateNonEmpty)
	if err != nil {
		return nil, err
	}
	mKind, err := mms.requiredString("kind", validateExact(KindMutantSpecimen, ReasonManifestInvalid))
	if err != nil {
		return nil, err
	}
	mSchemaRef, err := mms.requiredString("schema_ref",
		makePatternValidator(reSchemaRef, ReasonManifestInvalid, "schema_ref"))
	if err != nil {
		return nil, err
	}
	mSHA, err := mms.requiredString("sha256",
		makePatternValidator(reSHA256Hex, ReasonManifestInvalid, "sha256"))
	if err != nil {
		return nil, err
	}
	mRejection, err := mms.requiredString("expected_semantic_rejection",
		validateExact(ReasonVisibilityUnauthorizedField, ReasonManifestInvalid))
	if err != nil {
		return nil, err
	}
	return &Manifest{
		ProtocolVersion:    identity.ProtocolVersion,
		SchemaVersion:      identity.SchemaVersion,
		FixtureID:          identity.FixtureID,
		FixtureName:        fixtureName,
		ExpectedFinalState: expectedFinal,
		ReplayAssertion:    replayRef,
		Assets:             assets,
		Mutants: []ManifestMutant{{
			Path:                      mPath,
			Kind:                      mKind,
			SchemaRef:                 mSchemaRef,
			SHA256:                    mSHA,
			ExpectedSemanticRejection: mRejection,
		}},
	}, nil
}

func validateManifestKind(value, path string) error {
	if _, ok := ManifestKindSchemaRef[value]; !ok {
		return newContractError(ReasonManifestInvalid, path,
			fmt.Sprintf("unknown manifest kind %q", value))
	}
	return nil
}

// DecodeMutantSpecimen strictly decodes a mutant specimen wrapper document
// ($defs/mutant_specimen).
func DecodeMutantSpecimen(data []byte) (*MutantSpecimen, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	ms, err := newMemberSet(root, "$", "markers", "kind", "mutant_id", "seat_id", "leaked_field_id", "projection")
	if err != nil {
		return nil, err
	}
	markersNode, err := ms.required("markers")
	if err != nil {
		return nil, err
	}
	if markersNode.kind != kindArray || len(markersNode.arr) != 2 ||
		markersNode.arr[0].kind != kindString || markersNode.arr[0].str != MutantMarkerNonCanon ||
		markersNode.arr[1].kind != kindString || markersNode.arr[1].str != MutantMarkerMutant {
		return nil, newContractError(ReasonMutantSpecimenInvalid, "$/markers",
			`markers must be exactly ["NON_CANON", "MUTANT"]`)
	}
	kind, err := ms.requiredString("kind", validateExact(MutantKindHiddenLeak, ReasonMutantSpecimenInvalid))
	if err != nil {
		return nil, err
	}
	mutantID, err := ms.requiredString("mutant_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	seatID, err := ms.requiredString("seat_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	leakedFieldID, err := ms.requiredString("leaked_field_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	projectionNode, err := ms.required("projection")
	if err != nil {
		return nil, err
	}
	proj, err := decodeProjectionFromNode(projectionNode, "$/projection")
	if err != nil {
		return nil, err
	}
	return &MutantSpecimen{
		Markers:       []string{MutantMarkerNonCanon, MutantMarkerMutant},
		Kind:          kind,
		MutantID:      mutantID,
		SeatID:        seatID,
		LeakedFieldID: leakedFieldID,
		Projection:    *proj,
	}, nil
}

func decodeProjectionFromNode(n *jsonNode, path string) (*Projection, error) {
	ms, err := newMemberSet(n, path, "protocol_version", "schema_version", "fixture_id", "projection_id", "seat_id", "fields")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	projectionID, err := ms.requiredString("projection_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	seatID, err := ms.requiredString("seat_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	fieldsNode, err := ms.required("fields")
	if err != nil {
		return nil, err
	}
	fields, err := decodeStateFields(fieldsNode, path+"/fields")
	if err != nil {
		return nil, err
	}
	return &Projection{
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		ProjectionID:    projectionID,
		SeatID:          seatID,
		Fields:          fields,
	}, nil
}

// ---------------------------------------------------------------------------
// JSON-RPC wire envelopes.
// ---------------------------------------------------------------------------

func decodeApplyActionResultFromNode(n *jsonNode, path string) (*ApplyActionResult, error) {
	ms, err := newMemberSet(n, path, "accepted", "transition_id", "applied_fields")
	if err != nil {
		return nil, err
	}
	acceptedNode, err := ms.required("accepted")
	if err != nil {
		return nil, err
	}
	if acceptedNode.kind != kindBool || !acceptedNode.boolVal {
		return nil, newContractError(ReasonApplyResultInvalid, path+"/accepted",
			"accepted must be exactly true")
	}
	transitionID, err := ms.requiredString("transition_id", validateIdentifier)
	if err != nil {
		return nil, err
	}
	fieldsNode, err := ms.required("applied_fields")
	if err != nil {
		return nil, err
	}
	fields, err := decodeStateFields(fieldsNode, path+"/applied_fields")
	if err != nil {
		return nil, err
	}
	return &ApplyActionResult{Accepted: true, TransitionID: transitionID, AppliedFields: fields}, nil
}

func decodeErrorObjectFromNode(n *jsonNode, path string) (*ErrorObject, error) {
	ms, err := newMemberSet(n, path, "code", "message", "data")
	if err != nil {
		return nil, err
	}
	codeNode, err := ms.required("code")
	if err != nil {
		return nil, err
	}
	code, err := safeIntegerValue(codeNode, path+"/code", ReasonErrorCodeInvalid, "error code")
	if err != nil {
		return nil, err
	}
	message, err := ms.requiredString("message", validateNonEmpty)
	if err != nil {
		return nil, err
	}
	dataNode, present, err := ms.optional("data")
	if err != nil {
		return nil, err
	}
	var data *ErrorData
	if present {
		dms, err := newMemberSet(dataNode, path+"/data", "error_code")
		if err != nil {
			return nil, err
		}
		errorCode, err := dms.requiredString("error_code",
			makePatternValidator(reErrorCode, ReasonErrorDataInvalid, "error_code"))
		if err != nil {
			return nil, err
		}
		data = &ErrorData{ErrorCode: errorCode}
	}
	return &ErrorObject{Code: code, Message: message, Data: data}, nil
}

// safeIntegerValue requires an integer-typed JSON number whose value lies in
// the inclusive cross-language safe range, and returns it exactly.
func safeIntegerValue(n *jsonNode, path, reason, what string) (int64, error) {
	if n.kind == kindNull {
		return 0, newContractError(ReasonJSONNullMember, path, what+" must be an integer, not null")
	}
	if n.kind != kindNumber {
		return 0, newContractError(ReasonJSONInvalidType, path, what+" must be an integer")
	}
	var v int64
	if n.isInt {
		v = n.ival
	} else {
		f := n.fval
		if math.Trunc(f) != f {
			return 0, newContractError(reason, path, what+" must be an integer, not a fraction")
		}
		if f < float64(SafeIntegerMin) || f > float64(SafeIntegerMax) {
			return 0, newContractError(reason, path,
				what+" outside the cross-language safe range [-9007199254740991, 9007199254740991]")
		}
		v = int64(f)
	}
	if v < SafeIntegerMin || v > SafeIntegerMax {
		return 0, newContractError(reason, path,
			what+" outside the cross-language safe range [-9007199254740991, 9007199254740991]")
	}
	return v, nil
}

// DecodeRequest strictly decodes a JSON-RPC request envelope
// ($defs/jsonrpc_request).
func DecodeRequest(data []byte) (*Request, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	return decodeRequestFromNode(root)
}

func decodeRequestFromNode(root *jsonNode) (*Request, error) {
	ms, err := newMemberSet(root, "$", "jsonrpc", "id", "method", "params",
		"protocol_version", "schema_version", "fixture_id")
	if err != nil {
		return nil, err
	}
	jsonrpc, err := ms.requiredString("jsonrpc",
		validateExact(JSONRPCVersion, ReasonJSONRPCVersionInvalid))
	if err != nil {
		return nil, err
	}
	idNode, err := ms.required("id")
	if err != nil {
		return nil, err
	}
	id, err := requestIDFromNode(idNode, "$/id")
	if err != nil {
		return nil, err
	}
	method, err := ms.requiredString("method", validateExact(MethodRequest, ReasonMethodInvalid))
	if err != nil {
		return nil, err
	}
	paramsNode, err := ms.required("params")
	if err != nil {
		return nil, err
	}
	params, err := decodeActionIntentParamsFromNode(paramsNode, "$/params")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	return &Request{
		JSONRPC:         jsonrpc,
		ID:              id,
		Method:          method,
		Params:          params,
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
	}, nil
}

// DecodeResponse strictly decodes a JSON-RPC response envelope
// ($defs/jsonrpc_response). Exactly one of result/error is required.
func DecodeResponse(data []byte) (*Response, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	return decodeResponseFromNode(root)
}

func decodeResponseFromNode(root *jsonNode) (*Response, error) {
	ms, err := newMemberSet(root, "$", "jsonrpc", "id", "protocol_version", "schema_version",
		"fixture_id", "result", "error")
	if err != nil {
		return nil, err
	}
	jsonrpc, err := ms.requiredString("jsonrpc",
		validateExact(JSONRPCVersion, ReasonJSONRPCVersionInvalid))
	if err != nil {
		return nil, err
	}
	idNode, err := ms.required("id")
	if err != nil {
		return nil, err
	}
	id, err := requestIDFromNode(idNode, "$/id")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	resultNode, hasResult, err := ms.optional("result")
	if err != nil {
		return nil, err
	}
	errorNode, hasError, err := ms.optional("error")
	if err != nil {
		return nil, err
	}
	switch {
	case hasResult && hasError:
		return nil, newContractError(ReasonResponseResultErrorBoth, "$",
			"response must carry exactly one of result or error, not both")
	case !hasResult && !hasError:
		return nil, newContractError(ReasonResponseResultErrorNeither, "$",
			"response must carry exactly one of result or error, not neither")
	}
	var result *ApplyActionResult
	var errObj *ErrorObject
	if hasResult {
		result, err = decodeApplyActionResultFromNode(resultNode, "$/result")
		if err != nil {
			return nil, err
		}
	} else {
		errObj, err = decodeErrorObjectFromNode(errorNode, "$/error")
		if err != nil {
			return nil, err
		}
	}
	return &Response{
		JSONRPC:         jsonrpc,
		ID:              id,
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
		Result:          result,
		Error:           errObj,
	}, nil
}

// DecodeNotification strictly decodes a JSON-RPC notification envelope
// ($defs/jsonrpc_notification).
func DecodeNotification(data []byte) (*Notification, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	return decodeNotificationFromNode(root)
}

func decodeNotificationFromNode(root *jsonNode) (*Notification, error) {
	ms, err := newMemberSet(root, "$", "jsonrpc", "method", "params",
		"protocol_version", "schema_version", "fixture_id")
	if err != nil {
		return nil, err
	}
	jsonrpc, err := ms.requiredString("jsonrpc",
		validateExact(JSONRPCVersion, ReasonJSONRPCVersionInvalid))
	if err != nil {
		return nil, err
	}
	method, err := ms.requiredString("method", validateExact(MethodNotification, ReasonMethodInvalid))
	if err != nil {
		return nil, err
	}
	paramsNode, err := ms.required("params")
	if err != nil {
		return nil, err
	}
	pms, err := newMemberSet(paramsNode, "$/params", "event")
	if err != nil {
		return nil, err
	}
	eventNode, err := pms.required("event")
	if err != nil {
		return nil, err
	}
	event, err := decodeStateEventFromNode(eventNode, "$/params/event")
	if err != nil {
		return nil, err
	}
	identity, err := decodeIdentity(ms)
	if err != nil {
		return nil, err
	}
	return &Notification{
		JSONRPC:         jsonrpc,
		Method:          method,
		Params:          NotificationParams{Event: event},
		ProtocolVersion: identity.ProtocolVersion,
		SchemaVersion:   identity.SchemaVersion,
		FixtureID:       identity.FixtureID,
	}, nil
}

// DecodeEnvelope strictly parses a document and discriminates the root
// against the executable schema root: exactly one of the three registered
// wire envelopes (jsonrpc_request, jsonrpc_response, jsonrpc_notification).
// Arbitrary root objects are rejected with ReasonEnvelopeUnknownRoot, and
// unknown methods with ReasonMethodInvalid.
func DecodeEnvelope(data []byte) (*Envelope, error) {
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	if root.kind != kindObject {
		return nil, newContractError(ReasonEnvelopeUnknownRoot, "$",
			"root must be exactly one of the three registered JSON-RPC envelopes")
	}
	if methodNode := root.member("method"); methodNode != nil {
		if methodNode.kind != kindString {
			return nil, newContractError(ReasonMethodInvalid, "$/method", "method must be a string")
		}
		switch methodNode.str {
		case MethodRequest:
			req, err := decodeRequestFromNode(root)
			if err != nil {
				return nil, err
			}
			return &Envelope{Kind: EnvelopeRequest, Request: req}, nil
		case MethodNotification:
			notif, err := decodeNotificationFromNode(root)
			if err != nil {
				return nil, err
			}
			return &Envelope{Kind: EnvelopeNotification, Notification: notif}, nil
		default:
			return nil, newContractError(ReasonMethodInvalid, "$/method",
				fmt.Sprintf("unknown method %q (registry: %q, %q)", methodNode.str, MethodRequest, MethodNotification))
		}
	}
	if root.hasMember("id") {
		resp, err := decodeResponseFromNode(root)
		if err != nil {
			return nil, err
		}
		return &Envelope{Kind: EnvelopeResponse, Response: resp}, nil
	}
	return nil, newContractError(ReasonEnvelopeUnknownRoot, "$",
		"root must be exactly one of the three registered JSON-RPC envelopes")
}
