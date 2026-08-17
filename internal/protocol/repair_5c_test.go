package protocol_test

// Iteration-5C repair regression tests: one focused probe (or probe group)
// per failure reproduced by the independent Codex adversarial review against
// 0e170f3. Every test encodes the WRITTEN cross-language contract — exact
// request/response id value AND JSON type round-trip (lone UTF-16 surrogate
// code units included), deterministic rejection of invalid UTF-8 in
// NewStringID, state fields.minItems = 1 metadata, and the full-state
// projection gate covering source-state metadata — not the previous
// implementation's behavior.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// ---------------------------------------------------------------------------
// Finding 1: schema-valid lone-surrogate string RequestIDs must preserve the
// exact JSON string value: MarshalJSON emits the Node-compatible canonical
// string, Equal compares exact string values, and String() is the documented
// lossy Go Unicode view only.
// ---------------------------------------------------------------------------

func TestRequestIDPreservesLoneHighSurrogateExactJSONValue(t *testing.T) {
	var lone, replacement protocol.RequestID
	wantNoReason(t, json.Unmarshal([]byte(`"\ud800"`), &lone))
	wantNoReason(t, json.Unmarshal([]byte(`"\ufffd"`), &replacement))

	got, err := json.Marshal(lone)
	wantNoReason(t, err)
	if string(got) != `"\ud800"` {
		t.Fatalf("lone high surrogate must marshal as the exact Node canonical string %s, got %s", `"\ud800"`, got)
	}

	// The exact value is a lone UTF-16 code unit, never U+FFFD.
	if lone.Equal(replacement) {
		t.Fatal(`lone surrogate "\ud800" must never equal the replacement character "\ufffd"`)
	}
	if replacement.Equal(lone) {
		t.Fatal("equality must be symmetric and keep the two values distinct")
	}

	// String() is the documented Go Unicode view: the lone surrogate cannot
	// be represented in valid Go UTF-8 and appears as U+FFFD — it is NOT the
	// exact wire value, and Equal/MarshalJSON remain exact.
	if lone.String() != "\uFFFD" {
		t.Fatalf("String() must expose the documented Go Unicode view U+FFFD, got %q", lone.String())
	}

	// Round-trip the canonical text back and compare: same exact value.
	var back protocol.RequestID
	wantNoReason(t, json.Unmarshal(got, &back))
	if !back.Equal(lone) || back.Kind() != protocol.IDString {
		t.Fatalf("round-trip drifted: %+v != %+v", back, lone)
	}
	again, err := json.Marshal(back)
	wantNoReason(t, err)
	if string(again) != `"\ud800"` {
		t.Fatalf("round-tripped lone surrogate re-marshaled as %s", again)
	}
}

func TestRequestIDPreservesLoneLowSurrogateExactJSONValue(t *testing.T) {
	for _, doc := range []string{`"\udc00"`, `"\udfff"`} {
		var id protocol.RequestID
		wantNoReason(t, json.Unmarshal([]byte(doc), &id))
		got, err := json.Marshal(id)
		wantNoReason(t, err)
		if string(got) != doc {
			t.Fatalf("lone low surrogate %s must marshal to itself, got %s", doc, got)
		}
		var replacement protocol.RequestID
		wantNoReason(t, json.Unmarshal([]byte(`"\ufffd"`), &replacement))
		if id.Equal(replacement) {
			t.Fatalf("lone low surrogate %s must never equal U+FFFD", doc)
		}
	}
}

func TestRequestIDEscapedPairAndLiteralScalarCompareEqual(t *testing.T) {
	var escaped, literal protocol.RequestID
	wantNoReason(t, json.Unmarshal([]byte(`"\ud83d\ude00"`), &escaped))
	wantNoReason(t, json.Unmarshal([]byte("\"\U0001F600\""), &literal))
	if !escaped.Equal(literal) || !literal.Equal(escaped) {
		t.Fatal("an escaped valid surrogate pair and the literal scalar are the same string value and must compare equal")
	}
	// Both canonicalize to the same Node-compatible text (the scalar).
	gotEscaped, err := json.Marshal(escaped)
	wantNoReason(t, err)
	gotLiteral, err := json.Marshal(literal)
	wantNoReason(t, err)
	if string(gotEscaped) != string(gotLiteral) || string(gotEscaped) != "\"\U0001F600\"" {
		t.Fatalf("pair and scalar must share one canonical text, got %s vs %s", gotEscaped, gotLiteral)
	}
}

func TestRequestIDAlternateEscapeSpellingsCompareEqual(t *testing.T) {
	equal := [][2]string{
		{`"a"`, `"\u0061"`},
		{`"A"`, `"\u0041"`},
		{`"\ud800"`, `"\uD800"`}, // escape hex case is not part of the value
		{`"a\nb"`, `"a\u000ab"`}, // short escape vs \u spelling of the same code unit
		{`"\/"`, `"/"`},          // escaped solidus vs literal slash
	}
	for _, pair := range equal {
		var left, right protocol.RequestID
		wantNoReason(t, json.Unmarshal([]byte(pair[0]), &left))
		wantNoReason(t, json.Unmarshal([]byte(pair[1]), &right))
		if !left.Equal(right) {
			t.Fatalf("spelling variants %s and %s carry the same string value and must compare equal", pair[0], pair[1])
		}
		gotLeft, err := json.Marshal(left)
		wantNoReason(t, err)
		gotRight, err := json.Marshal(right)
		wantNoReason(t, err)
		if string(gotLeft) != string(gotRight) {
			t.Fatalf("spelling variants %s and %s must share one canonical text, got %s vs %s", pair[0], pair[1], gotLeft, gotRight)
		}
	}
}

func TestRequestIDStringVersusNumberRemainUnequal(t *testing.T) {
	str, err := protocol.NewStringID("1")
	wantNoReason(t, err)
	num, err := protocol.NewNumberID(1)
	wantNoReason(t, err)
	if str.Equal(num) {
		t.Fatal(`string "1" must not equal number 1: JSON type is part of id identity`)
	}
}

func TestRequestID128CharacterBoundaryBMPLoneUnitsAndAstralPairs(t *testing.T) {
	// The 1..128 CHARACTER contract follows the accepted TypeScript
	// validator ([...jsString].length): BMP scalars, astral pairs, and lone
	// surrogate units each count as ONE character.

	// 128 lone high surrogates: 128 characters, accepted; 129: rejected.
	acceptIDDoc(t, `"`+strings.Repeat(`\ud800`, 128)+`"`)
	rejectIDDoc(t, `"`+strings.Repeat(`\ud800`, 129)+`"`)

	// 128 lone low surrogates: accepted.
	acceptIDDoc(t, `"`+strings.Repeat(`\udc00`, 128)+`"`)
	rejectIDDoc(t, `"`+strings.Repeat(`\udc00`, 129)+`"`)

	// 128 astral pairs: 128 characters (256 code units), accepted; 129
	// pairs: rejected. The accepted id marshals as 128 literal scalars.
	pairs128 := strings.Repeat(`\ud83d\ude00`, 128)
	var id protocol.RequestID
	wantNoReason(t, json.Unmarshal([]byte(`"`+pairs128+`"`), &id))
	got, err := json.Marshal(id)
	wantNoReason(t, err)
	want128 := `"` + strings.Repeat("\U0001F600", 128) + `"`
	if string(got) != want128 {
		t.Fatalf("128 astral pairs must marshal as their 128 scalars, got %s", got)
	}
	rejectIDDoc(t, `"`+strings.Repeat(`\ud83d\ude00`, 129)+`"`)

	// Mixed: 64 BMP + 64 pairs = 128 characters, accepted; one more BMP
	// character makes 129.
	acceptIDDoc(t, `"`+strings.Repeat("x", 64)+strings.Repeat(`\ud83d\ude00`, 64)+`"`)
	rejectIDDoc(t, `"`+strings.Repeat("x", 65)+strings.Repeat(`\ud83d\ude00`, 64)+`"`)
}

func acceptIDDoc(t *testing.T, doc string) {
	t.Helper()
	var id protocol.RequestID
	if err := json.Unmarshal([]byte(doc), &id); err != nil {
		t.Fatalf("boundary id %s must be accepted: %v", doc, err)
	}
}

func rejectIDDoc(t *testing.T, doc string) {
	t.Helper()
	var id protocol.RequestID
	wantReason(t, json.Unmarshal([]byte(doc), &id), protocol.ReasonIDInvalid)
}

func TestRequestIDNumberStringReturnsDecimalForm(t *testing.T) {
	for _, n := range []int64{0, 1, -32000, protocol.SafeIntegerMin, protocol.SafeIntegerMax} {
		id, err := protocol.NewNumberID(n)
		wantNoReason(t, err)
		if got, want := id.String(), mustDecimal(t, n); got != want {
			t.Fatalf("String() of number id %d must be its decimal form %q, got %q", n, want, got)
		}
	}
}

func mustDecimal(t *testing.T, n int64) string {
	t.Helper()
	data, err := json.Marshal(n)
	wantNoReason(t, err)
	return string(data)
}

func TestRequestIDStringGoUnicodeViewIsDocumentedLossyOnly(t *testing.T) {
	id, err := protocol.NewStringID("probe-1")
	wantNoReason(t, err)
	if id.String() != "probe-1" {
		t.Fatalf("String() of a BMP string id must be the string value, got %q", id.String())
	}
	// A real U+FFFD and a lone surrogate share the SAME Go Unicode view but
	// are DIFFERENT exact values: String() is deliberately not equality.
	var ffdd, lone protocol.RequestID
	wantNoReason(t, json.Unmarshal([]byte(`"\ufffd"`), &ffdd))
	wantNoReason(t, json.Unmarshal([]byte(`"\ud800"`), &lone))
	if ffdd.String() != lone.String() {
		t.Fatalf("Go Unicode views must coincide (both U+FFFD), got %q vs %q", ffdd.String(), lone.String())
	}
	if ffdd.Equal(lone) {
		t.Fatal("equal String() views must never make distinct exact values compare equal")
	}
	// The zero value carries no JSON type and renders empty.
	var zero protocol.RequestID
	if zero.String() != "" {
		t.Fatalf("zero-value id String() must be empty, got %q", zero.String())
	}
}

func TestRequestIDMarshalDoesNotExposeMutableBackingState(t *testing.T) {
	id, err := protocol.NewStringID("probe-1")
	wantNoReason(t, err)
	first, err := json.Marshal(id)
	wantNoReason(t, err)
	// Mutate the returned bytes: the id itself must be unaffected.
	for i := range first {
		first[i] = 'X'
	}
	second, err := json.Marshal(id)
	wantNoReason(t, err)
	if string(second) != `"probe-1"` {
		t.Fatalf("mutating MarshalJSON output must never mutate the id, got %s", second)
	}
}

func TestRequestIDEnvelopeRoundTripPreservesLoneSurrogateID(t *testing.T) {
	// A full jsonrpc_request envelope whose id is a lone surrogate must
	// decode and re-marshal with the exact id value.
	doc := replaceOnce(string(readFixture(t, "requests/apply-action-request.json")),
		`"id": "minimal-v1-arithmetic-request-1"`, `"id": "\ud800"`)
	req, err := protocol.DecodeRequest([]byte(doc))
	wantNoReason(t, err)
	if req.ID.Kind() != protocol.IDString {
		t.Fatal("lone-surrogate id must stay a string id")
	}
	data, err := json.Marshal(req.ID)
	wantNoReason(t, err)
	if string(data) != `"\ud800"` {
		t.Fatalf("request envelope id re-marshaled as %s", data)
	}
	// Full envelope round-trip: marshal the decoded request and decode again.
	full, err := json.Marshal(req)
	wantNoReason(t, err)
	again, err := protocol.DecodeRequest(full)
	wantNoReason(t, err)
	if !again.ID.Equal(req.ID) {
		t.Fatal("full request envelope round-trip drifted the id")
	}

	// Same guarantee for a jsonrpc_response envelope id.
	respDoc := replaceOnce(string(readFixture(t, "responses/apply-action-result-response.json")),
		`"id": "minimal-v1-arithmetic-request-1"`, `"id": "\udc00"`)
	resp, err := protocol.DecodeResponse([]byte(respDoc))
	wantNoReason(t, err)
	respData, err := json.Marshal(resp.ID)
	wantNoReason(t, err)
	if string(respData) != `"\udc00"` {
		t.Fatalf("response envelope id re-marshaled as %s", respData)
	}
}

// ---------------------------------------------------------------------------
// Finding 2: NewStringID must deterministically reject caller-supplied
// invalid UTF-8 with a typed AIPT_ID_INVALID — never silently rewrite bytes.
// ---------------------------------------------------------------------------

func TestNewStringIDRejectsInvalidUTF8Deterministically(t *testing.T) {
	cases := []string{
		string([]byte{0xff}),
		"a" + string([]byte{0xff}) + "b",
		string([]byte{0xc3, 0x28}),       // truncated 2-byte sequence
		string([]byte{0xed, 0xa0, 0x80}), // CESU-8 lone surrogate encoding
	}
	for _, s := range cases {
		id, err := protocol.NewStringID(s)
		if err == nil {
			t.Fatalf("NewStringID(%q) must reject invalid UTF-8, accepted %+v", s, id)
		}
		if got := protocol.ContractReason(err); got != protocol.ReasonIDInvalid {
			t.Fatalf("invalid UTF-8 must carry the typed reason %s, got %s (%v)",
				protocol.ReasonIDInvalid, got, err)
		}
	}
}

func TestNewStringIDAcceptsRealReplacementCharacter(t *testing.T) {
	id, err := protocol.NewStringID("\uFFFD")
	wantNoReason(t, err)
	data, err := json.Marshal(id)
	wantNoReason(t, err)
	if string(data) != "\"\uFFFD\"" {
		t.Fatalf("a real U+FFFD must marshal as itself, got %s", data)
	}
	// NewStringID-created ids share the exact/canonical representation and
	// equality rules of parsed ids.
	var parsed protocol.RequestID
	wantNoReason(t, json.Unmarshal([]byte(`"\ufffd"`), &parsed))
	if !id.Equal(parsed) {
		t.Fatal("NewStringID(\"\\uFFFD\") must equal the parsed \"\\ufffd\" value")
	}
}

func TestNewStringIDCanonicalExactRepresentation(t *testing.T) {
	equal := [][2]string{
		{"a\nb", `"a\nb"`},               // control characters use short escapes
		{"\U0001F600", "\"\U0001F600\""}, // astral scalar stays literal
		{"\x01", `"\u0001"`},
		{"a\"b\\c", `"a\"b\\c"`},
	}
	for _, pair := range equal {
		id, err := protocol.NewStringID(pair[0])
		wantNoReason(t, err)
		data, err := json.Marshal(id)
		wantNoReason(t, err)
		if string(data) != pair[1] {
			t.Fatalf("NewStringID(%q) must marshal to the Node-compatible %s, got %s", pair[0], pair[1], data)
		}
		var parsed protocol.RequestID
		wantNoReason(t, json.Unmarshal([]byte(pair[1]), &parsed))
		if !id.Equal(parsed) {
			t.Fatalf("NewStringID(%q) must equal the parsed value %s", pair[0], pair[1])
		}
	}
}

func TestNewStringIDAstralCharacterBoundary(t *testing.T) {
	if _, err := protocol.NewStringID(strings.Repeat("\U0001F600", 128)); err != nil {
		t.Fatalf("128 astral characters (256 code units) must be accepted: %v", err)
	}
	wantReason(t, newStringIDErr(strings.Repeat("\U0001F600", 129)), protocol.ReasonIDInvalid)
}

func newStringIDErr(s string) error {
	_, err := protocol.NewStringID(s)
	return err
}

// ---------------------------------------------------------------------------
// Finding 3: CheckStateMetadata treats a present-but-empty fields slice as
// missing fields (the canonical state schema requires fields.minItems = 1).
// ---------------------------------------------------------------------------

func TestCheckStateMetadataEmptyFieldsSliceIsMissingFields(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)

	reasons := protocol.CheckStateMetadata(nil, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonStateMissingFields {
		t.Fatalf("nil state must yield exactly %s, got %v", protocol.ReasonStateMissingFields, reasons)
	}

	reasons = protocol.CheckStateMetadata(&protocol.State{}, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonStateMissingFields {
		t.Fatalf("nil fields must yield exactly %s, got %v", protocol.ReasonStateMissingFields, reasons)
	}

	// The reproduced fail-open: a present-but-empty (non-nil) fields slice.
	reasons = protocol.CheckStateMetadata(&protocol.State{Fields: []protocol.StateField{}}, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonStateMissingFields {
		t.Fatalf("empty non-nil fields must yield exactly %s, got %v", protocol.ReasonStateMissingFields, reasons)
	}

	// One well-formed field still passes.
	state := probeState(probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"))
	if reasons := protocol.CheckStateMetadata(state, known); len(reasons) != 0 {
		t.Fatalf("one-field state must pass the metadata gate, got %v", reasons)
	}
}

func TestCheckStateMetadataCollectsDuplicateAndUnknownSeatReasons(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)
	state := probeState(
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a"),
		probeField("turn-count", 1, protocol.VisibilityPublic, "seat-ghost"),
	)
	reasons := protocol.CheckStateMetadata(state, known)
	if len(reasons) != 2 || reasons[0] != protocol.ReasonStateDuplicateFieldID || reasons[1] != protocol.ReasonVisibilityUnknownSeat {
		t.Fatalf("duplicate field + unknown seat must yield exactly [%s %s], got %v",
			protocol.ReasonStateDuplicateFieldID, protocol.ReasonVisibilityUnknownSeat, reasons)
	}
}

// ---------------------------------------------------------------------------
// Finding 4: CheckProjection / ValidateProjection must gate source-state
// metadata — a projection copied from the same defective state can never
// mask the source defect.
// ---------------------------------------------------------------------------

func TestCheckProjectionRejectsDuplicateSourceField(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	// Append a duplicate copy of state.Fields[0] to the SOURCE only; the
	// projection itself stays well-formed and consistent with the first copy.
	dup := state.Fields[0]
	state.Fields = append(state.Fields, dup)
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))

	reasons := protocol.CheckProjection(state, proj, known)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonStateDuplicateFieldID {
		t.Fatalf("duplicate source field must yield %s first, got %v",
			protocol.ReasonStateDuplicateFieldID, reasons)
	}
	wantReason(t, protocol.ValidateProjection(state, proj, known), protocol.ReasonStateDuplicateFieldID)
}

func TestCheckProjectionRejectsUnknownSourceAuthorizedSeat(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	// Append seat-ghost to the SAME source field and the MATCHING projection
	// field (sets still match, so no projection-specific reason fires): the
	// unknown source authorization alone must fail the gate.
	state.Fields[0].Visibility.AuthorizedSeatIDs = append(state.Fields[0].Visibility.AuthorizedSeatIDs, "seat-ghost")
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))
	proj.Fields[0].Visibility.AuthorizedSeatIDs = append([]string(nil), state.Fields[0].Visibility.AuthorizedSeatIDs...)

	reasons := protocol.CheckProjection(state, proj, known)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonVisibilityUnknownSeat {
		t.Fatalf("unknown source authorization must yield %s first, got %v",
			protocol.ReasonVisibilityUnknownSeat, reasons)
	}
	wantReason(t, protocol.ValidateProjection(state, proj, known), protocol.ReasonVisibilityUnknownSeat)
}

func TestCheckProjectionRejectsEmptySourceFields(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))

	for _, fields := range [][]protocol.StateField{nil, {}} {
		state := probeState(fields...)
		reasons := protocol.CheckProjection(state, proj, known)
		if len(reasons) == 0 || reasons[0] != protocol.ReasonStateMissingFields {
			t.Fatalf("empty source fields must yield %s first, got %v", protocol.ReasonStateMissingFields, reasons)
		}
		wantReason(t, protocol.ValidateProjection(state, proj, known), protocol.ReasonStateMissingFields)
	}
}

func TestCheckProjectionSourceDefectsNotMaskedByCopiedProjection(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)

	// A projection copied VERBATIM from a duplicate-field source state: the
	// source duplicate must be the first reason even though source and
	// projection are perfectly consistent with each other.
	dupState := probeState(
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("turn-count", 1, protocol.VisibilityPublic, "seat-a", "seat-b"),
	)
	copied := probeProjection("seat-a",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("turn-count", 1, protocol.VisibilityPublic, "seat-a", "seat-b"),
	)
	reasons := protocol.CheckProjection(dupState, copied, known)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonStateDuplicateFieldID {
		t.Fatalf("copied duplicate-field projection must still fail with the SOURCE reason first, got %v", reasons)
	}
	wantReason(t, protocol.ValidateProjection(dupState, copied, known), protocol.ReasonStateDuplicateFieldID)

	// A projection copied verbatim from a state that authorizes an unknown
	// seat: set comparison matches, but the source reference is unknown.
	ghostState := probeState(probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-ghost"))
	ghostCopied := probeProjection("seat-a",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-ghost"))
	reasons = protocol.CheckProjection(ghostState, ghostCopied, known)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonVisibilityUnknownSeat {
		t.Fatalf("copied unknown-seat projection must still fail with the SOURCE reason first, got %v", reasons)
	}
	wantReason(t, protocol.ValidateProjection(ghostState, ghostCopied, known), protocol.ReasonVisibilityUnknownSeat)
}

func TestCheckProjectionSourceReasonsPrecedeProjectionReasons(t *testing.T) {
	_, _, known := fixtureStateAndSeats(t)
	// BOTH a duplicate source field AND an unknown projection seat: the
	// source metadata reason is the deterministic first stable reason.
	state := probeState(
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"),
		probeField("turn-count", 1, protocol.VisibilityPublic, "seat-a", "seat-b"),
	)
	proj := probeProjection("seat-ghost",
		probeField("turn-count", 0, protocol.VisibilityPublic, "seat-a", "seat-b"))
	reasons := protocol.CheckProjection(state, proj, known)
	if len(reasons) < 2 || reasons[0] != protocol.ReasonStateDuplicateFieldID {
		t.Fatalf("source metadata reasons must precede projection reasons, got %v", reasons)
	}
	if !containsReason(reasons, protocol.ReasonProjectionUnknownSeat) {
		t.Fatalf("projection-specific reason must still be reported, got %v", reasons)
	}
	wantReason(t, protocol.ValidateProjection(state, proj, known), protocol.ReasonStateDuplicateFieldID)
}

func TestCheckProjectionCleanStateBehaviorPreserved(t *testing.T) {
	// The clean fixture state still passes, and the hidden-leak mutant still
	// yields EXACTLY the single unauthorized-field reason (5B contract).
	state, _, known := fixtureStateAndSeats(t)
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))
	if reasons := protocol.CheckProjection(state, proj, known); len(reasons) != 0 {
		t.Fatalf("clean fixture projection must pass, got %v", reasons)
	}
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	reasons := protocol.CheckProjection(state, &mutant.Projection, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("hidden-leak mutant on the clean state must yield exactly %s, got %v",
			protocol.ReasonVisibilityUnauthorizedField, reasons)
	}
	if reason, err := protocol.MutantSemanticRejection(mutant, state, known); err != nil ||
		reason != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("mutant semantic rejection drifted: %q, %v", reason, err)
	}
	// Nil inputs still fail closed with exactly the projection-invalid reason.
	got := protocol.CheckProjection(nil, proj, known)
	if len(got) != 1 || got[0] != protocol.ReasonProjectionInvalid {
		t.Fatalf("nil state must yield exactly %s, got %v", protocol.ReasonProjectionInvalid, got)
	}
}
