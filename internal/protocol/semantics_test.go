package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

func fixtureStateAndSeats(t *testing.T) (*protocol.State, *protocol.SeatSet, map[string]bool) {
	t.Helper()
	state := mustDecodeState(t, readFixture(t, "state.json"))
	seats := mustDecodeSeatSet(t, readFixture(t, "seats.json"))
	return state, seats, protocol.KnownSeats(seats)
}

// probeState builds a minimal valid state from the given fields.
func probeState(fields ...protocol.StateField) *protocol.State {
	return &protocol.State{
		ProtocolVersion: protocol.ProtocolVersion,
		SchemaVersion:   protocol.SchemaVersion,
		FixtureID:       protocol.FixtureIDMinimalArithmetic,
		StateID:         "probe-state",
		Fields:          fields,
	}
}

func probeField(fieldID string, value any, label string, seats ...string) protocol.StateField {
	raw, _ := json.Marshal(value)
	return protocol.StateField{
		FieldID: fieldID,
		Value:   raw,
		Visibility: protocol.Visibility{
			Label:             label,
			AuthorizedSeatIDs: append([]string(nil), seats...),
		},
	}
}

func probeProjection(seatID string, fields ...protocol.StateField) *protocol.Projection {
	return &protocol.Projection{
		ProtocolVersion: protocol.ProtocolVersion,
		SchemaVersion:   protocol.SchemaVersion,
		FixtureID:       protocol.FixtureIDMinimalArithmetic,
		ProjectionID:    "probe-projection",
		SeatID:          seatID,
		Fields:          fields,
	}
}

func TestValidateIdentityDistinguishesFailures(t *testing.T) {
	ok := protocol.Identity{ProtocolVersion: "1.0.0", SchemaVersion: "1.0.0", FixtureID: protocol.FixtureIDMinimalArithmetic}
	wantNoReason(t, protocol.ValidateIdentity(ok))
	wantReason(t, protocol.ValidateIdentity(protocol.Identity{ProtocolVersion: "9.9.9", SchemaVersion: "1.0.0", FixtureID: "x"}),
		protocol.ReasonProtocolVersionInvalid)
	wantReason(t, protocol.ValidateIdentity(protocol.Identity{ProtocolVersion: "1.0.0", SchemaVersion: "9.9.9", FixtureID: "x"}),
		protocol.ReasonSchemaVersionInvalid)
	wantReason(t, protocol.ValidateIdentity(protocol.Identity{ProtocolVersion: "1.0.0", SchemaVersion: "1.0.0", FixtureID: "BAD ID!"}),
		protocol.ReasonFixtureIDInvalid)
}

func TestValidateFixtureIdentityDrift(t *testing.T) {
	wantNoReason(t, protocol.ValidateFixtureIdentity(protocol.Identity{
		ProtocolVersion: protocol.ProtocolVersion, SchemaVersion: protocol.SchemaVersion,
		FixtureID: protocol.FixtureIDMinimalArithmetic}))
	drifted := protocol.Identity{ProtocolVersion: "1.0.0", SchemaVersion: "1.0.0", FixtureID: "drifted-fixture-id"}
	wantReason(t, protocol.ValidateFixtureIdentity(drifted), protocol.ReasonFixtureIdentityMismatch)
}

func TestValidateIdentifier(t *testing.T) {
	for _, valid := range []string{"a", "seat-a", "x0", "a-b-c", strings.Repeat("a", 64)} {
		wantNoReason(t, protocol.ValidateIdentifier(valid))
	}
	for _, invalid := range []string{"", "A", "Seat-A", "a_b", "a b", "-a", "a.", strings.Repeat("a", 65), "a/b"} {
		if err := protocol.ValidateIdentifier(invalid); err == nil {
			t.Fatalf("identifier %q must be rejected", invalid)
		}
	}
}

func TestValidateMessageID(t *testing.T) {
	wantNoReason(t, protocol.ValidateMessageID("minimal-v1-arithmetic-applyAction-0001"))
	wantNoReason(t, protocol.ValidateMessageID("A.B_C:d-e"))
	for _, invalid := range []string{"", "-x", "x!", strings.Repeat("m", 129)} {
		if err := protocol.ValidateMessageID(invalid); err == nil {
			t.Fatalf("message_id %q must be rejected", invalid)
		}
	}
}

func TestValidateSHA256Hex(t *testing.T) {
	wantNoReason(t, protocol.ValidateSHA256Hex(strings.Repeat("a", 64)))
	wantNoReason(t, protocol.ValidateSHA256Hex(strings.Repeat("0", 64)))
	for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), "g" + strings.Repeat("0", 63)} {
		if err := protocol.ValidateSHA256Hex(invalid); err == nil {
			t.Fatalf("digest %q must be rejected", invalid)
		}
	}
}

func TestVisibilityLabelsExactlySix(t *testing.T) {
	labels := protocol.VisibilityLabels()
	if len(labels) != 6 {
		t.Fatalf("must be exactly six frozen visibility labels, got %d: %v", len(labels), labels)
	}
	for _, label := range labels {
		if !protocol.IsVisibilityLabel(label) {
			t.Fatalf("frozen label %q must be recognized", label)
		}
	}
	for _, unknown := range []string{"", "TEAM_ONLY", "public", "Public", "NONE"} {
		if protocol.IsVisibilityLabel(unknown) {
			t.Fatalf("non-frozen label %q must not be recognized (never defaults public)", unknown)
		}
	}
}

func TestValidateSeatIDs(t *testing.T) {
	wantNoReason(t, protocol.ValidateSeatIDs([]string{"seat-a", "seat-b"}))
	wantReason(t, protocol.ValidateSeatIDs(nil), protocol.ReasonVisibilityAuthorizationInvalid)
	wantReason(t, protocol.ValidateSeatIDs([]string{}), protocol.ReasonVisibilityAuthorizationInvalid)
	wantReason(t, protocol.ValidateSeatIDs([]string{"seat-a", "seat-a"}), protocol.ReasonVisibilityAuthorizationInvalid)
	wantReason(t, protocol.ValidateSeatIDs([]string{"Seat-A"}), protocol.ReasonVisibilityAuthorizationInvalid)
}

func TestValidateSeatSet(t *testing.T) {
	seats := mustDecodeSeatSet(t, readFixture(t, "seats.json"))
	wantNoReason(t, protocol.ValidateSeatSet(seats))
	dupe := &protocol.SeatSet{
		ProtocolVersion: protocol.ProtocolVersion, SchemaVersion: protocol.SchemaVersion,
		FixtureID: protocol.FixtureIDMinimalArithmetic,
		Seats:     []protocol.Seat{{SeatID: "seat-a", Name: "A"}, {SeatID: "seat-a", Name: "A2"}},
	}
	wantReason(t, protocol.ValidateSeatSet(dupe), protocol.ReasonSeatSetInvalid)
	empty := &protocol.SeatSet{}
	wantReason(t, protocol.ValidateSeatSet(empty), protocol.ReasonSeatSetInvalid)
}

func TestCheckStateMetadataCleanFixture(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	reasons := protocol.CheckStateMetadata(state, known)
	if len(reasons) != 0 {
		t.Fatalf("fixture state must pass metadata gate, got %v", reasons)
	}
}

func TestCheckStateMetadataDuplicateField(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)
	state := probeState(
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("turn-count", 1, protocol.VisibilityPublic, "seat-a", "seat-b"),
	)
	reasons := protocol.CheckStateMetadata(state, known)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonStateDuplicateFieldID {
		t.Fatalf("duplicate state field must be rejected with %s, got %v", protocol.ReasonStateDuplicateFieldID, reasons)
	}
}

func TestCheckStateMetadataUnknownSeat(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)
	state := probeState(probeField("turn-count", 0, protocol.VisibilityPublic, "seat-ghost"))
	reasons := protocol.CheckStateMetadata(state, known)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonVisibilityUnknownSeat {
		t.Fatalf("unknown authorized seat must be rejected with %s, got %v", protocol.ReasonVisibilityUnknownSeat, reasons)
	}
}

func TestCheckProjectionBothFixtureProjectionsPass(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	for _, rel := range []string{"projection-seat-a.json", "projection-seat-b.json"} {
		proj := mustDecodeProjection(t, readFixture(t, rel))
		if reasons := protocol.CheckProjection(state, proj, known); len(reasons) != 0 {
			t.Fatalf("%s must pass the full-state projection gate, got %v", rel, reasons)
		}
		if err := protocol.ValidateProjection(state, proj, known); err != nil {
			t.Fatalf("%s must validate: %v", rel, err)
		}
	}
}

func TestCheckProjectionUnknownSeat(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-ghost", probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"))
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonProjectionUnknownSeat) {
		t.Fatalf("unknown projection seat must be rejected with %s, got %v", protocol.ReasonProjectionUnknownSeat, reasons)
	}
}

func TestCheckProjectionDuplicateField(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
	)
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonProjectionDuplicateFieldID) {
		t.Fatalf("duplicate projection field must be rejected with %s, got %v", protocol.ReasonProjectionDuplicateFieldID, reasons)
	}
}

func TestCheckProjectionUnknownField(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a", probeField("no-such-field", 0, protocol.VisibilityPublic, "seat-a"))
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonProjectionUnknownField) {
		t.Fatalf("unknown projected field must be rejected with %s, got %v", protocol.ReasonProjectionUnknownField, reasons)
	}
}

func TestCheckProjectionValueDrift(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a",
		probeField("turn-count", 5, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("table-note", "alpha", protocol.VisibilityTableHiddenRemote, "seat-a"),
	)
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonProjectionValueDrift) {
		t.Fatalf("value drift must be rejected with %s, got %v", protocol.ReasonProjectionValueDrift, reasons)
	}
}

func TestCheckProjectionReclassified(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a",
		probeField("turn-count", 0, protocol.VisibilityLocalOnlySecret, "seat-a", "seat-b"),
		probeField("table-note", "alpha", protocol.VisibilityTableHiddenRemote, "seat-a"),
	)
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonVisibilityReclassified) {
		t.Fatalf("reclassification must be rejected with %s, got %v", protocol.ReasonVisibilityReclassified, reasons)
	}
}

func TestCheckProjectionAuthorizationDrift(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b", "seat-c"),
		probeField("table-note", "alpha", protocol.VisibilityTableHiddenRemote, "seat-a"),
	)
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonVisibilityAuthorizationDrift) {
		t.Fatalf("authorization drift must be rejected with %s, got %v", protocol.ReasonVisibilityAuthorizationDrift, reasons)
	}
}

func TestCheckProjectionAuthorizedSetReorderIsNotDrift(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-b", "seat-a"), // reordered set
		probeField("table-note", "alpha", protocol.VisibilityTableHiddenRemote, "seat-a"),
	)
	reasons := protocol.CheckProjection(state, proj, known)
	if containsReason(reasons, protocol.ReasonVisibilityAuthorizationDrift) {
		t.Fatalf("authorized_seat_ids is a mathematical set: reordering alone must not be authorization drift, got %v", reasons)
	}
	if len(reasons) != 0 {
		t.Fatalf("reordered projection must pass, got %v", reasons)
	}
}

func TestCheckProjectionUnauthorizedField(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-b",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("table-note", "alpha", protocol.VisibilityTableHiddenRemote, "seat-a"),
	)
	reasons := protocol.CheckProjection(state, proj, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("hidden-leak projection must be rejected with exactly %s, got %v",
			protocol.ReasonVisibilityUnauthorizedField, reasons)
	}
}

func TestCheckProjectionMissingAuthorizedField(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := probeProjection("seat-a", probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"))
	reasons := protocol.CheckProjection(state, proj, known)
	if !containsReason(reasons, protocol.ReasonProjectionMissingAuthorizedField) {
		t.Fatalf("omitted authorized field must be rejected with %s, got %v",
			protocol.ReasonProjectionMissingAuthorizedField, reasons)
	}
}

func TestValidateProjectionIdentityMustMatchState(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-b.json"))
	proj.FixtureID = "drifted-fixture-id"
	wantReason(t, protocol.ValidateProjection(state, proj, known), protocol.ReasonFixtureIdentityMismatch)
}

func TestJSONEqualSemantics(t *testing.T) {
	equal := [][2]string{
		{`{"a":1,"b":[2,3]}`, `{"b":[2,3],"a":1}`}, // key order irrelevant
		{`1`, `1.0`}, // numeric equality
		{`0`, `0e0`},
		{`"x"`, `"\u0078"`},
		{`null`, `null`},
		{`{"nested":{"x":[1,{"y":2}]}}`, `{"nested":{"x":[1,{"y":2}]}}`},
	}
	for _, pair := range equal {
		if !protocol.JSONEqual(json.RawMessage(pair[0]), json.RawMessage(pair[1])) {
			t.Fatalf("JSONEqual(%s, %s) must be true", pair[0], pair[1])
		}
	}
	unequal := [][2]string{
		{`1`, `2`},
		{`[1,2]`, `[2,1]`}, // arrays are ordered
		{`{"a":1}`, `{"a":2}`},
		{`{"a":1}`, `{"a":1,"b":2}`},
		{`1`, `"1"`},
		{`true`, `1`},
		{`null`, `0`},
	}
	for _, pair := range unequal {
		if protocol.JSONEqual(json.RawMessage(pair[0]), json.RawMessage(pair[1])) {
			t.Fatalf("JSONEqual(%s, %s) must be false", pair[0], pair[1])
		}
	}
	if protocol.JSONEqual(json.RawMessage(`{"a":`), json.RawMessage(`{"a":`)) {
		t.Fatal("invalid JSON must compare unequal")
	}
}

func TestApplyTransitionIsPureAndDeterministic(t *testing.T) {
	state := mustDecodeState(t, readFixture(t, "state.json"))
	transition := mustDecodeTransition(t, readFixture(t, "transition.json"))
	finalState := mustDecodeState(t, readFixture(t, "final-state.json"))
	next := protocol.ApplyTransition(state, transition)
	if next.StateID != "final" {
		t.Fatalf("transitioned state must move to final, got %q", next.StateID)
	}
	if !protocol.JSONEqual(mustMarshal(t, next.Fields), mustMarshal(t, finalState.Fields)) {
		t.Fatalf("transition result applied to the initial state must equal final-state.json fields")
	}
	// Purity: the source state must be untouched.
	if state.StateID != "initial" || state.Fields[0].FieldID != "turn-count" {
		t.Fatalf("ApplyTransition mutated the source state")
	}
	again := protocol.ApplyTransition(state, transition)
	if !protocol.JSONEqual(mustMarshal(t, next), mustMarshal(t, again)) {
		t.Fatal("two transition applications must be identical (deterministic)")
	}
}

func TestCheckArithmeticFixture(t *testing.T) {
	checkBytes := readFixture(t, "check-turn-increment.json")
	check, err := protocol.DecodeDeterministicCheck(checkBytes)
	wantNoReason(t, err)
	wantNoReason(t, protocol.CheckArithmetic(check))
	if check.CheckVersion != "1.0.0" || check.Kind != "arithmetic" || check.Operator != "add" {
		t.Fatalf("check constants drifted: %+v", check)
	}
	if len(check.Inputs) != 2 || check.Inputs[0] != 0 || check.Inputs[1] != 1 || check.Output != 1 {
		t.Fatalf("check inputs/output drifted: %+v", check)
	}
}

func TestCheckArithmeticRejectsMismatchedOutput(t *testing.T) {
	check, err := protocol.DecodeDeterministicCheck(readFixture(t, "check-turn-increment.json"))
	wantNoReason(t, err)
	check.Output = 2
	wantReason(t, protocol.CheckArithmetic(check), protocol.ReasonCheckOutputMismatch)
}

func TestCheckArithmeticRejectsUnknownOperator(t *testing.T) {
	check, err := protocol.DecodeDeterministicCheck(readFixture(t, "check-turn-increment.json"))
	wantNoReason(t, err)
	check.Operator = "mul"
	wantReason(t, protocol.CheckArithmetic(check), protocol.ReasonCheckInvalid)
}

func TestCheckWireErrorCoherence(t *testing.T) {
	coherent := &protocol.ErrorObject{
		Code:    protocol.WireErrorExampleCode,
		Message: protocol.WireErrorExampleMessage,
		Data:    &protocol.ErrorData{ErrorCode: protocol.WireErrorExampleDataCode},
	}
	if reasons := protocol.CheckWireErrorCoherence(protocol.MethodRequest, coherent); len(reasons) != 0 {
		t.Fatalf("coherent error must pass, got %v", reasons)
	}
	// The mutant visibility code is never a wire error code.
	bad := &protocol.ErrorObject{
		Code:    -32000,
		Message: "table-note is not authorized for seat-b (AIPT_VISIBILITY_UNAUTHORIZED_FIELD)",
		Data:    &protocol.ErrorData{ErrorCode: protocol.ReasonVisibilityUnauthorizedField},
	}
	reasons := protocol.CheckWireErrorCoherence(protocol.MethodRequest, bad)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonProtocolErrorMismatchedCode {
		t.Fatalf("mutant visibility code as wire error must be rejected with %s, got %v",
			protocol.ReasonProtocolErrorMismatchedCode, reasons)
	}
	// Unknown referenced method.
	if reasons := protocol.CheckWireErrorCoherence("aipt.protocol.other", coherent); len(reasons) == 0 {
		t.Fatal("coherence must fail for a non-applyAction referenced method")
	}
}

func TestMutantSemanticRejectionFixture(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	reason, err := protocol.MutantSemanticRejection(mutant, state, known)
	wantNoReason(t, err)
	if reason != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("mutant rejection reason must be %s, got %s", protocol.ReasonVisibilityUnauthorizedField, reason)
	}
	// The projection gate itself must produce exactly the one reason.
	reasons := protocol.CheckProjection(state, &mutant.Projection, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("mutant projection must be rejected with exactly %s, got %v",
			protocol.ReasonVisibilityUnauthorizedField, reasons)
	}
}

func TestMutantMetadataDriftSeatID(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	mutant.SeatID = "seat-a" // wrapper no longer binds to projection.seat_id
	_, err = protocol.MutantSemanticRejection(mutant, state, known)
	wantReason(t, err, protocol.ReasonFixtureMutantSemanticDrift)
}

func TestMutantMetadataDriftLeakedFieldID(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	mutant.LeakedFieldID = "turn-count" // wrapper no longer binds to the offending field
	_, err = protocol.MutantSemanticRejection(mutant, state, known)
	wantReason(t, err, protocol.ReasonFixtureMutantSemanticDrift)
}

func TestManifestPathProblem(t *testing.T) {
	for _, safe := range []string{"seats.json", "requests/apply-action-request.json", "mutants/hidden-leak.json", "a/b/c.json"} {
		if problem := protocol.ManifestPathProblem(safe); problem != "" {
			t.Fatalf("safe path %q flagged: %s", safe, problem)
		}
	}
	for _, unsafe := range []string{"", "/etc/passwd.json", "../escape.json", "a/../b.json", "a//b.json", `a\b.json`, "a/./b.json", "./a.json", "a/b/..", ".."} {
		if problem := protocol.ManifestPathProblem(unsafe); problem == "" {
			t.Fatalf("unsafe path %q must be flagged", unsafe)
		}
	}
}

func containsReason(reasons []string, reason string) bool {
	for _, r := range reasons {
		if r == reason {
			return true
		}
	}
	return false
}
