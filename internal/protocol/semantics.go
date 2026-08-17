package protocol

// Pure semantic helpers for the shared fixture contract: identity,
// identifiers, visibility labels, seats, state/projection semantics, the
// deterministic arithmetic check, declared state transitions, and the
// hidden-leak mutant binding. All functions are pure data transformations or
// validators over already-strictly-decoded values; no game rules, no
// runtime, no I/O.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// IsVisibilityLabel reports whether label is one of the six frozen
// visibility labels. Missing/unknown labels never default public.
func IsVisibilityLabel(label string) bool {
	for _, l := range VisibilityLabels() {
		if label == l {
			return true
		}
	}
	return false
}

// ValidateIdentity validates the identity triple: protocol/schema versions
// must equal the frozen constants exactly. It returns a typed contract error
// distinguishing protocol-version, schema-version, and fixture-id failures.
func ValidateIdentity(identity Identity) error {
	if identity.ProtocolVersion != ProtocolVersion {
		return newContractError(ReasonProtocolVersionInvalid, "$/protocol_version",
			fmt.Sprintf("protocol_version must be %q, got %q", ProtocolVersion, identity.ProtocolVersion))
	}
	if identity.SchemaVersion != SchemaVersion {
		return newContractError(ReasonSchemaVersionInvalid, "$/schema_version",
			fmt.Sprintf("schema_version must be %q, got %q", SchemaVersion, identity.SchemaVersion))
	}
	if err := ValidateIdentifier(identity.FixtureID); err != nil {
		return newContractError(ReasonFixtureIDInvalid, "$/fixture_id", err.Error())
	}
	return nil
}

// ValidateFixtureIdentity requires the identity triple to equal the frozen
// fixture identity (1.0.0 / 1.0.0 / minimal-v1-arithmetic). Any drift — in an
// ordinary asset or the mutant wrapper's inner projection — is the stable
// explicit reason ReasonFixtureIdentityMismatch.
func ValidateFixtureIdentity(identity Identity) error {
	if identity.ProtocolVersion != ProtocolVersion ||
		identity.SchemaVersion != SchemaVersion ||
		identity.FixtureID != FixtureIDMinimalArithmetic {
		return newContractError(ReasonFixtureIdentityMismatch, "$",
			fmt.Sprintf("fixture identity drifted: %q / %q / %q (expected %q / %q / %q)",
				identity.ProtocolVersion, identity.SchemaVersion, identity.FixtureID,
				ProtocolVersion, SchemaVersion, FixtureIDMinimalArithmetic))
	}
	return nil
}

// ValidateIdentifier validates the shared 1..64 lowercase machine-identity
// pattern used by fixture_id, seat_id, field_id, state_id, projection_id,
// transition_id, event_id, replay_id, check_id, assertion_id, mutant_id,
// and action names.
func ValidateIdentifier(value string) error {
	if !reIdentifier.MatchString(value) {
		return newContractError(ReasonIdentifierInvalid, "$",
			fmt.Sprintf("identifier must match %q, got %q", PatternIdentifier, value))
	}
	return nil
}

// ValidateMessageID validates the 1..128 message_id pattern.
func ValidateMessageID(value string) error {
	if !reMessageID.MatchString(value) {
		return newContractError(ReasonIdentifierInvalid, "$",
			fmt.Sprintf("message_id must match %q, got %q", PatternMessageID, value))
	}
	return nil
}

// ValidateSHA256Hex validates the 64-character lowercase hex digest pattern.
func ValidateSHA256Hex(value string) error {
	if !reSHA256Hex.MatchString(value) {
		return newContractError(ReasonIdentifierInvalid, "$",
			fmt.Sprintf("digest must match %q, got %q", PatternSHA256Hex, value))
	}
	return nil
}

// ValidateSeatIDs validates the non-empty, unique, well-formed seat id list
// of a visibility entry.
func ValidateSeatIDs(ids []string) error {
	return validateAuthorizedSeatIDs(ids, "$")
}

// ValidateSeatSet requires a non-empty seat set whose seat ids are all valid
// and pairwise unique.
func ValidateSeatSet(seats *SeatSet) error {
	if seats == nil || len(seats.Seats) == 0 {
		return newContractError(ReasonSeatSetInvalid, "$/seats", "seat set must not be empty")
	}
	seen := make(map[string]bool, len(seats.Seats))
	for i, s := range seats.Seats {
		if err := ValidateIdentifier(s.SeatID); err != nil {
			return newContractError(ReasonSeatSetInvalid, fmt.Sprintf("$/seats/%d/seat_id", i), err.Error())
		}
		if seen[s.SeatID] {
			return newContractError(ReasonSeatSetInvalid, fmt.Sprintf("$/seats/%d/seat_id", i),
				fmt.Sprintf("duplicate seat id %q", s.SeatID))
		}
		seen[s.SeatID] = true
	}
	return nil
}

// KnownSeats returns the known-seat set of a decoded seat set. A nil seat
// set yields an empty set (never panics), which fails every authorization
// lookup closed.
func KnownSeats(seats *SeatSet) map[string]bool {
	known := make(map[string]bool)
	if seats == nil {
		return known
	}
	for _, s := range seats.Seats {
		known[s.SeatID] = true
	}
	return known
}

// CheckStateMetadata validates state field identity + authorization metadata
// against the known seats: missing fields (nil or an empty fields slice —
// the canonical state schema requires fields.minItems = 1), duplicate
// field_id values, and visibility entries authorizing unknown seats are
// rejected with the stable oracle reasons. A valid state returns no reasons.
func CheckStateMetadata(state *State, knownSeats map[string]bool) []string {
	reasons := []string{}
	if state == nil || len(state.Fields) == 0 {
		return []string{ReasonStateMissingFields}
	}
	seen := make(map[string]bool, len(state.Fields))
	for _, field := range state.Fields {
		if seen[field.FieldID] {
			reasons = append(reasons, ReasonStateDuplicateFieldID)
		} else {
			seen[field.FieldID] = true
		}
		for _, seat := range field.Visibility.AuthorizedSeatIDs {
			if !knownSeats[seat] {
				reasons = append(reasons, ReasonVisibilityUnknownSeat)
			}
		}
	}
	return reasons
}

// CheckProjection runs the full-state projection gate over a projection and
// its source state (exact oracle semantics). Source-state metadata is gated
// FIRST and deterministically (iteration 5C): missing fields
// (AIPT_STATE_MISSING_FIELDS), duplicate source field ids
// (AIPT_STATE_DUPLICATE_FIELD_ID), and source visibility references to
// unknown seats (AIPT_VISIBILITY_UNKNOWN_SEAT) can never be masked by a
// projection copied from the same defective state. The projection itself is
// then gated with the projection-specific reasons:
//   - the projection seat must be a known seat
//     (AIPT_PROJECTION_UNKNOWN_SEAT);
//   - no duplicate field_id in the projection
//     (AIPT_PROJECTION_DUPLICATE_FIELD_ID);
//   - every projected field must exist in the state
//     (AIPT_PROJECTION_UNKNOWN_FIELD);
//   - every projected field value must deep-equal the source value
//     (AIPT_PROJECTION_VALUE_DRIFT);
//   - the visibility label must not be reclassified
//     (AIPT_VISIBILITY_RECLASSIFIED);
//   - authorized_seat_ids is compared as a mathematical SET
//     (AIPT_VISIBILITY_AUTHORIZATION_DRIFT);
//   - the projection seat must be authorized for the field
//     (AIPT_VISIBILITY_UNAUTHORIZED_FIELD);
//   - no field authorized to the projection seat may be omitted
//     (AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD).
//
// A valid projection over a valid state returns no reasons. A nil state or
// nil projection returns exactly [AIPT_PROJECTION_INVALID] deterministically
// — caller-controlled nil inputs never panic.
func CheckProjection(state *State, projection *Projection, knownSeats map[string]bool) []string {
	reasons := []string{}
	if state == nil || projection == nil {
		return []string{ReasonProjectionInvalid}
	}
	reasons = append(reasons, CheckStateMetadata(state, knownSeats)...)
	if !knownSeats[projection.SeatID] {
		reasons = append(reasons, ReasonProjectionUnknownSeat)
	}
	stateByID := make(map[string]*StateField, len(state.Fields))
	for i := range state.Fields {
		if _, ok := stateByID[state.Fields[i].FieldID]; !ok {
			stateByID[state.Fields[i].FieldID] = &state.Fields[i]
		}
	}
	seen := make(map[string]bool, len(projection.Fields))
	for _, field := range projection.Fields {
		if seen[field.FieldID] {
			reasons = append(reasons, ReasonProjectionDuplicateFieldID)
		} else {
			seen[field.FieldID] = true
		}
		src, ok := stateByID[field.FieldID]
		if !ok {
			reasons = append(reasons, ReasonProjectionUnknownField)
			continue
		}
		if !JSONEqual(src.Value, field.Value) {
			reasons = append(reasons, ReasonProjectionValueDrift)
		}
		if src.Visibility.Label != field.Visibility.Label {
			reasons = append(reasons, ReasonVisibilityReclassified)
		}
		srcSet := append([]string(nil), src.Visibility.AuthorizedSeatIDs...)
		projSet := append([]string(nil), field.Visibility.AuthorizedSeatIDs...)
		sort.Strings(srcSet)
		sort.Strings(projSet)
		if !stringSlicesEqual(srcSet, projSet) {
			reasons = append(reasons, ReasonVisibilityAuthorizationDrift)
		}
		if !containsString(field.Visibility.AuthorizedSeatIDs, projection.SeatID) {
			reasons = append(reasons, ReasonVisibilityUnauthorizedField)
		}
	}
	for i := range state.Fields {
		field := &state.Fields[i]
		if containsString(field.Visibility.AuthorizedSeatIDs, projection.SeatID) && !seen[field.FieldID] {
			reasons = append(reasons, ReasonProjectionMissingAuthorizedField)
		}
	}
	return reasons
}

// ValidateProjection is the pure projection validator: identity must match
// the source state, the projection seat must be known, and the full-state
// projection gate must pass (source-state metadata reasons come first). It
// returns nil for a valid projection and a typed contract error carrying the
// first stable rejection reason otherwise.
func ValidateProjection(state *State, projection *Projection, knownSeats map[string]bool) error {
	if state == nil || projection == nil {
		return newContractError(ReasonProjectionInvalid, "$", "state and projection are required")
	}
	if state.Identity() != projection.Identity() {
		return newContractError(ReasonFixtureIdentityMismatch, "$",
			"projection identity must equal the source state identity")
	}
	for _, reason := range CheckProjection(state, projection, knownSeats) {
		return newContractError(reason, "$", "projection violates the full-state projection gate")
	}
	return nil
}

func containsString(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// JSONEqual reports semantic deep equality of two lossless JSON values:
// objects compare by member regardless of order, arrays in order, numbers
// numerically, strings/booleans/null exactly. Both values must be strictly
// valid JSON (they come from already-validated documents); invalid input
// compares unequal.
func JSONEqual(a, b json.RawMessage) bool {
	na, err := parseStrictJSON(a)
	if err != nil {
		return false
	}
	nb, err := parseStrictJSON(b)
	if err != nil {
		return false
	}
	return jsonNodesEqual(na, nb)
}

func jsonNodesEqual(a, b *jsonNode) bool {
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case kindNull:
		return true
	case kindBool:
		return a.boolVal == b.boolVal
	case kindString:
		return unitsEqual(a.units, b.units)
	case kindNumber:
		return a.float64Value() == b.float64Value()
	case kindArray:
		if len(a.arr) != len(b.arr) {
			return false
		}
		for i := range a.arr {
			if !jsonNodesEqual(a.arr[i], b.arr[i]) {
				return false
			}
		}
		return true
	case kindObject:
		if len(a.members) != len(b.members) {
			return false
		}
		byKey := make(map[string]*jsonNode, len(b.members))
		for _, m := range b.members {
			byKey[unitsKeyString(m.key)] = m.val
		}
		for _, m := range a.members {
			other, ok := byKey[unitsKeyString(m.key)]
			if !ok || !jsonNodesEqual(m.val, other) {
				return false
			}
		}
		return true
	}
	return false
}

// ApplyTransition applies a declared state transition as a pure data
// transformation: the result fields replace the matching source fields by
// field_id (unknown field ids are appended), and the state moves to the
// transition's to_state_id. The source state is never mutated. This is a
// fixture-determinism helper, not a rules engine.
func ApplyTransition(state *State, transition *StateTransition) *State {
	next := &State{
		ProtocolVersion: state.ProtocolVersion,
		SchemaVersion:   state.SchemaVersion,
		FixtureID:       state.FixtureID,
		StateID:         transition.ToStateID,
		Fields:          make([]StateField, 0, len(state.Fields)+len(transition.Result)),
	}
	for i := range state.Fields {
		next.Fields = append(next.Fields, cloneStateField(state.Fields[i]))
	}
	for _, patch := range transition.Result {
		patched := false
		for i := range next.Fields {
			if next.Fields[i].FieldID == patch.FieldID {
				next.Fields[i] = cloneStateField(patch)
				patched = true
				break
			}
		}
		if !patched {
			next.Fields = append(next.Fields, cloneStateField(patch))
		}
	}
	return next
}

func cloneStateField(f StateField) StateField {
	f.Value = append(json.RawMessage(nil), f.Value...)
	f.Visibility.AuthorizedSeatIDs = append([]string(nil), f.Visibility.AuthorizedSeatIDs...)
	return f
}

// CheckArithmetic verifies the declared deterministic arithmetic check:
// versioned kind/operator must be the frozen arithmetic add check and the
// declared output must equal the sum of the declared inputs (in order, IEEE
// double addition exactly like the Node oracle). It returns a typed contract
// error on any mismatch.
func CheckArithmetic(check *DeterministicCheck) error {
	if check == nil {
		return newContractError(ReasonCheckInvalid, "$", "deterministic check is required")
	}
	if check.CheckVersion != CheckVersion || check.Kind != CheckKindArithmetic || check.Operator != CheckOperatorAdd {
		return newContractError(ReasonCheckInvalid, "$",
			"deterministic check must be the versioned arithmetic add check")
	}
	if len(check.Inputs) < 2 || len(check.Inputs) > 8 {
		return newContractError(ReasonCheckInvalid, "$/inputs",
			fmt.Sprintf("arithmetic check must carry 2..8 inputs, got %d", len(check.Inputs)))
	}
	sum := 0.0
	for _, input := range check.Inputs {
		sum += input
	}
	if sum != check.Output {
		return newContractError(ReasonCheckOutputMismatch, "$/output",
			fmt.Sprintf("declared output %v does not equal the deterministic input sum %v", check.Output, sum))
	}
	return nil
}

// CheckWireErrorCoherence validates the documented deterministic protocol
// error against the request it references: an applyAction rejection must
// carry the deterministic numeric code -32000 (WireErrorExampleCode), the
// generic stable AIPT_ACTION_REJECTED data.error_code, and the
// deterministic rejection message. The mutant visibility code is never a
// wire error code. Returns [] when coherent, else the stable mismatch
// reason(s).
func CheckWireErrorCoherence(method string, errObj *ErrorObject) []string {
	reasons := []string{}
	if method != MethodRequest {
		return []string{ReasonProtocolErrorMismatchedCode}
	}
	if errObj == nil || errObj.Code != WireErrorExampleCode {
		reasons = append(reasons, ReasonProtocolErrorMismatchedCode)
	}
	if errObj == nil || errObj.Data == nil || errObj.Data.ErrorCode != WireErrorExampleDataCode {
		reasons = append(reasons, ReasonProtocolErrorMismatchedCode)
	}
	if errObj == nil || errObj.Message != WireErrorExampleMessage {
		reasons = append(reasons, ReasonProtocolErrorMismatchedCode)
	}
	return reasons
}

// MutantSemanticRejection proves the semantic rejection of a schema-valid
// hidden-leak mutant: the wrapped projection identity must equal the
// supplied source-state identity, the wrapper seat_id must equal
// projection.seat_id, the leaked_field_id must be exactly the single field
// producing the authorization rejection, and the projection gate must
// produce exactly one reason — AIPT_VISIBILITY_UNAUTHORIZED_FIELD. Metadata
// drift (a wrapper whose seat_id/leaked_field_id does not bind to the actual
// offending field, or any other reason set) fails with
// ReasonFixtureMutantSemanticDrift; inner projection identity drift fails
// with ReasonFixtureIdentityMismatch, so drifted identity can never
// masquerade as the canonical fixture. Nil/missing specimen, state, or
// projection inputs return a typed fail-closed error and never panic. On
// success it returns the stable rejection reason and nil.
func MutantSemanticRejection(m *MutantSpecimen, state *State, knownSeats map[string]bool) (string, error) {
	if m == nil {
		return "", newContractError(ReasonFixtureMutantSemanticDrift, "$", "mutant specimen is required")
	}
	if state == nil {
		return "", newContractError(ReasonFixtureMutantSemanticDrift, "$", "source state is required")
	}
	if state.Identity() != m.Projection.Identity() {
		return "", newContractError(ReasonFixtureIdentityMismatch, "$/projection",
			fmt.Sprintf("mutant projection identity %q / %q / %q must equal the supplied source-state identity %q / %q / %q",
				m.Projection.ProtocolVersion, m.Projection.SchemaVersion, m.Projection.FixtureID,
				state.ProtocolVersion, state.SchemaVersion, state.FixtureID))
	}
	if m.SeatID != m.Projection.SeatID {
		return "", newContractError(ReasonFixtureMutantSemanticDrift, "$/seat_id",
			fmt.Sprintf("wrapper seat_id %q must equal projection.seat_id %q", m.SeatID, m.Projection.SeatID))
	}
	reasons := CheckProjection(state, &m.Projection, knownSeats)
	if len(reasons) != 1 || reasons[0] != ReasonVisibilityUnauthorizedField {
		return "", newContractError(ReasonFixtureMutantSemanticDrift, "$/projection",
			fmt.Sprintf("mutant must be rejected with exactly one reason %s, got %v",
				ReasonVisibilityUnauthorizedField, reasons))
	}
	offending := []string{}
	for _, field := range m.Projection.Fields {
		if !containsString(field.Visibility.AuthorizedSeatIDs, m.Projection.SeatID) {
			offending = append(offending, field.FieldID)
		}
	}
	if len(offending) != 1 || offending[0] != m.LeakedFieldID {
		return "", newContractError(ReasonFixtureMutantSemanticDrift, "$/leaked_field_id",
			fmt.Sprintf("leaked_field_id %q must be the single unauthorized field, got %v",
				m.LeakedFieldID, offending))
	}
	return ReasonVisibilityUnauthorizedField, nil
}

// ManifestPathProblem reports why a manifest entry path is unsafe, or ""
// when the path is safe: it must be a non-empty relative, normalized POSIX
// path free of absolute forms, dot segments, backslashes, NULs, and empty
// segments.
func ManifestPathProblem(p string) string {
	if p == "" {
		return "unsafe manifest path: path must be a non-empty string"
	}
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return fmt.Sprintf("unsafe manifest path: NUL byte in %q", p)
		}
	}
	if p[0] == '/' {
		return fmt.Sprintf("unsafe manifest path: absolute path %q", p)
	}
	if containsByte(p, '\\') {
		return fmt.Sprintf("unsafe manifest path: backslash separator in %q", p)
	}
	parts := splitSlash(p)
	for _, seg := range parts {
		if seg == "" {
			return fmt.Sprintf("unsafe manifest path: empty segment in %q", p)
		}
		if seg == "." || seg == ".." {
			return fmt.Sprintf("unsafe manifest path: dot segment in %q", p)
		}
	}
	cleaned := cleanSlashPath(p)
	if cleaned != p {
		return fmt.Sprintf("unsafe manifest path: non-normalized path %q", p)
	}
	return ""
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}

func splitSlash(s string) []string {
	parts := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '/' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return parts
}

// cleanSlashPath normalizes a POSIX path without consulting the filesystem.
// It is only used for the non-normalization equality check after dot/empty
// segments have already been rejected, so dropping empty and "." segments
// yields a faithful comparison.
func cleanSlashPath(s string) string {
	parts := splitSlash(s)
	out := make([]string, 0, len(parts))
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		out = append(out, seg)
	}
	return strings.Join(out, "/")
}
