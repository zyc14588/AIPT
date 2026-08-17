package protocol_test

// Iteration-5B repair regression tests: one focused probe (or probe group)
// per failure reproduced by the independent Codex adversarial review. Every
// test encodes the WRITTEN cross-language contract — Node 24 byte-compatible
// canonical JSON, the JavaScript safe-integer lossless gate, the
// deterministic -32000 wire error, the hidden-leak mutant identity binding,
// nil-safe semantic helpers, and the trusted manifest kind->schema_ref
// authority — not the previous implementation's behavior.

import (
	"encoding/json"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// ---------------------------------------------------------------------------
// Finding 1: integer-valued unsafe decimal/exponent spellings must fail
// closed with AIPT_JSON_UNSAFE_INTEGER before any RawMessage is trusted or a
// canonical hash is produced.
// ---------------------------------------------------------------------------

func TestValidateJSONRejectsUnsafeIntegerValuedDecimalAndExponentForms(t *testing.T) {
	docs := []string{
		`9007199254740993.0`, // IEEE-754 rounds to 2^53
		`9007199254740992e0`, // exactly 2^53
		`-9007199254740993.0`,
		`9007199254740992.0`,
		`-9007199254740992e0`,
		`9007199254740991.5`, // rounds to 9007199254740992
		`1e20`,               // 100000000000000000000
		`-1e20`,
		`1e21`,
		`-1e21`,
		`1e308`,
		`1.2345678901234568e20`, // integral value, unsafe
	}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONUnsafeInteger)
	}
}

func TestValidateJSONRejectsUnsafeIntegerValuedFormsAtNestedPaths(t *testing.T) {
	docs := []string{
		`{"n":9007199254740993.0}`,
		`{"deep":{"m":9007199254740992e0}}`,
		`[-9007199254740993.0]`,
		`{"n":1e20}`,
		`{"n":-1e20}`,
		`{"arr":[1,2,{"x":9007199254740992.0}]}`,
	}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONUnsafeInteger)
	}
}

func TestCanonicalJSONRejectsUnsafeIntegerValuedSpellingsBeforeHashing(t *testing.T) {
	for _, doc := range []string{`1e20`, `-1e20`, `9007199254740993.0`, `{"n":9007199254740992e0}`} {
		_, err := protocol.CanonicalJSON([]byte(doc))
		wantReason(t, err, protocol.ReasonJSONUnsafeInteger)
		_, err = protocol.CanonicalSHA256([]byte(doc))
		wantReason(t, err, protocol.ReasonJSONUnsafeInteger)
	}
}

func TestValidateJSONAcceptsSafeIntegerValuedDecimalAndExponentForms(t *testing.T) {
	docs := []string{
		`9007199254740991.0`,  // inclusive upper boundary, fraction spelling
		`-9007199254740991.0`, // inclusive lower boundary, fraction spelling
		`9007199254740991e0`,
		`-9007199254740991e0`,
		`0.0`, `0e0`, `1.0`, `100.0`, `1e1`, `-32000.0`, `32000e0`,
	}
	for _, doc := range docs {
		if err := protocol.ValidateJSON([]byte(doc)); err != nil {
			t.Fatalf("ValidateJSON(%s) rejected a safe integer-valued number: %v", doc, err)
		}
	}
	got, err := protocol.CanonicalJSON([]byte(`{"a":9007199254740991.0,"b":100.0,"c":0e0}`))
	if err != nil {
		t.Fatalf("CanonicalJSON of safe integer-valued spellings: %v", err)
	}
	if got != `{"a":9007199254740991,"b":100,"c":0}` {
		t.Fatalf("canonical safe integer-valued formatting drifted: %s", got)
	}
}

func TestValidateJSONAcceptsFiniteNonIntegralValues(t *testing.T) {
	docs := []string{
		`1.5e0`, `2.5`, `3.14`, `5e-324`, `1e-7`, `0.0000001`, `-2.5e-8`,
		`1e-999`, `0.30000000000000004`, `9007199254740990.5`,
	}
	for _, doc := range docs {
		if err := protocol.ValidateJSON([]byte(doc)); err != nil {
			t.Fatalf("ValidateJSON(%s) rejected a finite non-integral number: %v", doc, err)
		}
	}
}

func TestValidateJSONStillRejectsNegativeZeroIncludingExponentUnderflow(t *testing.T) {
	docs := []string{`-0`, `-0.0`, `-0e0`, `-0E5`, `-0.0e10`, `-1e-999`, `{"n":-0}`, `[-0.00]`, `{"n":-1e-999}`}
	for _, doc := range docs {
		wantReason(t, protocol.ValidateJSON([]byte(doc)), protocol.ReasonJSONNegativeZero)
	}
	_, err := protocol.CanonicalJSON([]byte(`-1e-999`))
	wantReason(t, err, protocol.ReasonJSONNegativeZero)
}

// ---------------------------------------------------------------------------
// Finding 2: Node-byte-compatible lone UTF-16 surrogates. Node 24
// JSON.parse('"\\ud800"') keeps code unit D800 and JSON.stringify returns
// the lowercase "\ud800" escape; a valid pair recombines into the scalar;
// keys sort by UTF-16 code unit order; lone surrogates are never conflated
// with U+FFFD.
// ---------------------------------------------------------------------------

func TestCanonicalJSONPreservesLoneHighSurrogateValues(t *testing.T) {
	cases := map[string]string{
		`"\ud800"`:   `"\ud800"`,
		`"x\ud800y"`: `"x\ud800y"`,
	}
	for in, want := range cases {
		got, err := protocol.CanonicalJSON([]byte(in))
		if err != nil {
			t.Fatalf("CanonicalJSON(%s): %v", in, err)
		}
		if got != want {
			t.Fatalf("lone high surrogate drifted: got %s, want %s (Node)", got, want)
		}
	}
}

func TestCanonicalJSONPreservesLoneLowSurrogateValues(t *testing.T) {
	cases := map[string]string{
		`"\udc00"`: `"\udc00"`,
		`"\udfff"`: `"\udfff"`,
	}
	for in, want := range cases {
		got, err := protocol.CanonicalJSON([]byte(in))
		if err != nil {
			t.Fatalf("CanonicalJSON(%s): %v", in, err)
		}
		if got != want {
			t.Fatalf("lone low surrogate drifted: got %s, want %s (Node)", got, want)
		}
	}
}

func TestCanonicalJSONHighSurrogateWithoutLowPairStaysLone(t *testing.T) {
	// Node: "\ud800x\udc00" round-trips with BOTH surrogates escaped — the
	// intervening 'x' breaks pairing.
	in := `"\ud800x\udc00"`
	want := `"\ud800x\udc00"`
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON(%s): %v", in, err)
	}
	if got != want {
		t.Fatalf("mixed lone surrogates drifted: got %s, want %s (Node)", got, want)
	}
}

func TestCanonicalJSONCombinesValidSurrogatePairs(t *testing.T) {
	cases := map[string]string{
		`"\ud83d\ude00"`: "\"\U0001F600\"", // U+1F600
		`"\ud800\udc00"`: "\"\U00010000\"", // U+10000
	}
	for in, want := range cases {
		got, err := protocol.CanonicalJSON([]byte(in))
		if err != nil {
			t.Fatalf("CanonicalJSON(%s): %v", in, err)
		}
		if got != want {
			t.Fatalf("surrogate pair must serialize as its scalar: got %s, want %s", got, want)
		}
	}
}

func TestCanonicalJSONLoneSurrogateKeysSortAndSerializeLikeNode(t *testing.T) {
	// UTF-16 code-unit order: D800 < FFFD (JavaScript default sort).
	in := `{"\ufffd":1,"\ud800":2}`
	want := "{\"\\ud800\":2,\"\uFFFD\":1}"
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if got != want {
		t.Fatalf("lone surrogate key handling drifted: got %s, want %s (Node)", got, want)
	}
}

func TestCanonicalJSONSurrogateKeyOrderingMatchesJavaScript(t *testing.T) {
	// UTF-16 code-unit order: D800 < D83D(DE00 pair) < DC00 < E000 — the
	// JavaScript default sort, verified against Node 24 for these exact keys.
	in := `{"\ue000":4,"\udc00":1,"\ud83d\ude00":3,"\ud800":2}`
	want := "{\"\\ud800\":2,\"\U0001F600\":3,\"\\udc00\":1,\"\uE000\":4}"
	got, err := protocol.CanonicalJSON([]byte(in))
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if got != want {
		t.Fatalf("surrogate key ordering drifted: got %s, want %s (JavaScript UTF-16 order)", got, want)
	}
}

func TestValidateJSONDoesNotConflateLoneSurrogateKeysWithReplacement(t *testing.T) {
	// "\ud800" and "\ufffd" are DIFFERENT JavaScript strings, not duplicates.
	if err := protocol.ValidateJSON([]byte(`{"\ud800":1,"\ufffd":2}`)); err != nil {
		t.Fatalf("lone surrogate key must not conflate with U+FFFD: %v", err)
	}
	// True duplicates of each value still fail closed.
	wantReason(t, protocol.ValidateJSON([]byte(`{"\ud800":1,"\ud800":2}`)), protocol.ReasonJSONDuplicateKey)
	wantReason(t, protocol.ValidateJSON([]byte(`{"\ufffd":1,"\ufffd":2}`)), protocol.ReasonJSONDuplicateKey)
	// A surrogate pair and the literal scalar are the same JavaScript key.
	wantReason(t, protocol.ValidateJSON([]byte("{\"\\ud83d\\ude00\":1,\"\U0001F600\":2}")), protocol.ReasonJSONDuplicateKey)
}

func TestJSONEqualSurrogateSemantics(t *testing.T) {
	equal := [][2]string{
		{`"\ud800"`, `"\ud800"`},
		{`"\ud83d\ude00"`, "\"\U0001F600\""}, // pair == scalar
		{`{"\ud800":1}`, `{"\ud800":1}`},
	}
	for _, pair := range equal {
		if !protocol.JSONEqual(json.RawMessage(pair[0]), json.RawMessage(pair[1])) {
			t.Fatalf("JSONEqual(%s, %s) must be true", pair[0], pair[1])
		}
	}
	unequal := [][2]string{
		{`"\ud800"`, "\"\uFFFD\""}, // lone surrogate != U+FFFD
		{`"\udc00"`, `"\ud800"`},   // distinct code units
		{`"\ud800"`, `"\ud83d\ude00"`},
		{`{"\ud800":1}`, `{"\ufffd":1}`},
	}
	for _, pair := range unequal {
		if protocol.JSONEqual(json.RawMessage(pair[0]), json.RawMessage(pair[1])) {
			t.Fatalf("JSONEqual(%s, %s) must be false", pair[0], pair[1])
		}
	}
}

// ---------------------------------------------------------------------------
// Finding 3: the deterministic wire-error coherence gate must validate the
// numeric error.code (-32000) in addition to method/message/data.
// ---------------------------------------------------------------------------

func TestCheckWireErrorCoherenceRejectsDriftedNumericCode(t *testing.T) {
	coherent := &protocol.ErrorObject{
		Code:    protocol.WireErrorExampleCode,
		Message: protocol.WireErrorExampleMessage,
		Data:    &protocol.ErrorData{ErrorCode: protocol.WireErrorExampleDataCode},
	}
	if reasons := protocol.CheckWireErrorCoherence(protocol.MethodRequest, coherent); len(reasons) != 0 {
		t.Fatalf("coherent example must pass, got %v", reasons)
	}
	// Drift ONLY the numeric code; method/message/data stay canonical.
	driftedCode := *coherent
	driftedCode.Code = -32001
	reasons := protocol.CheckWireErrorCoherence(protocol.MethodRequest, &driftedCode)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonProtocolErrorMismatchedCode {
		t.Fatalf("drifted numeric wire code must be rejected with %s, got %v",
			protocol.ReasonProtocolErrorMismatchedCode, reasons)
	}
	// A positive code with the same magnitude is still drift.
	positiveCode := *coherent
	positiveCode.Code = 32000
	reasons = protocol.CheckWireErrorCoherence(protocol.MethodRequest, &positiveCode)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonProtocolErrorMismatchedCode {
		t.Fatalf("sign-drifted numeric wire code must be rejected with %s, got %v",
			protocol.ReasonProtocolErrorMismatchedCode, reasons)
	}
}

func TestCheckWireErrorCoherenceRejectsEachDriftedFieldIndependently(t *testing.T) {
	coherent := &protocol.ErrorObject{
		Code:    protocol.WireErrorExampleCode,
		Message: protocol.WireErrorExampleMessage,
		Data:    &protocol.ErrorData{ErrorCode: protocol.WireErrorExampleDataCode},
	}
	// Referenced method drift.
	if reasons := protocol.CheckWireErrorCoherence("aipt.protocol.other", coherent); len(reasons) == 0 {
		t.Fatal("method drift must fail coherence")
	}
	// Message drift (code/data stay canonical).
	badMessage := *coherent
	badMessage.Message = "drifted message"
	reasons := protocol.CheckWireErrorCoherence(protocol.MethodRequest, &badMessage)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonProtocolErrorMismatchedCode {
		t.Fatalf("message drift must fail coherence, got %v", reasons)
	}
	// Data drift (code/message stay canonical), including the mutant
	// visibility code never being a wire error code.
	badData := *coherent
	badData.Data = &protocol.ErrorData{ErrorCode: protocol.ReasonVisibilityUnauthorizedField}
	reasons = protocol.CheckWireErrorCoherence(protocol.MethodRequest, &badData)
	if len(reasons) == 0 || reasons[0] != protocol.ReasonProtocolErrorMismatchedCode {
		t.Fatalf("data drift must fail coherence, got %v", reasons)
	}
	// Nil error object.
	if reasons := protocol.CheckWireErrorCoherence(protocol.MethodRequest, nil); len(reasons) == 0 {
		t.Fatal("nil error object must fail coherence")
	}
}

// ---------------------------------------------------------------------------
// Findings 4 & 5: inner mutant identity drift and nil semantic inputs.
// ---------------------------------------------------------------------------

func TestMutantSemanticRejectionRejectsProjectionIdentityDrift(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	// Change ONLY the wrapped projection's fixture identity to another
	// schema-valid identifier. This drift must never masquerade as the
	// canonical hidden-leak fixture.
	drifted := *mutant
	drifted.Projection.FixtureID = "minimal-v1-arithmetic-drifted"
	reason, err := protocol.MutantSemanticRejection(&drifted, state, known)
	if err == nil {
		t.Fatalf("inner projection identity drift must fail closed, got success with %q", reason)
	}
	wantReason(t, err, protocol.ReasonFixtureIdentityMismatch)
	if reason != "" {
		t.Fatalf("drifted mutant must not return a rejection reason: %q", reason)
	}
}

func TestMutantSemanticRejectionNilInputsFailClosedWithoutPanic(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	_, err = protocol.MutantSemanticRejection(nil, state, known)
	wantReason(t, err, protocol.ReasonFixtureMutantSemanticDrift)
	_, err = protocol.MutantSemanticRejection(mutant, nil, known)
	wantReason(t, err, protocol.ReasonFixtureMutantSemanticDrift)
}

func TestCheckProjectionNilStateOrProjectionReturnsInvalidReason(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))
	got := protocol.CheckProjection(nil, proj, known)
	if len(got) != 1 || got[0] != protocol.ReasonProjectionInvalid {
		t.Fatalf("nil state must yield exactly %s, got %v", protocol.ReasonProjectionInvalid, got)
	}
	got = protocol.CheckProjection(state, nil, known)
	if len(got) != 1 || got[0] != protocol.ReasonProjectionInvalid {
		t.Fatalf("nil projection must yield exactly %s, got %v", protocol.ReasonProjectionInvalid, got)
	}
}

func TestSemanticHelpersRejectNilCallerInputsWithoutPanic(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	proj := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))
	wantReason(t, protocol.ValidateProjection(nil, proj, known), protocol.ReasonProjectionInvalid)
	wantReason(t, protocol.ValidateProjection(state, nil, known), protocol.ReasonProjectionInvalid)
	wantReason(t, protocol.ValidateProjection(nil, nil, known), protocol.ReasonProjectionInvalid)
	// KnownSeats(nil) must not panic; the empty seat set fails
	// authorizations closed.
	empty := protocol.KnownSeats(nil)
	if len(empty) != 0 {
		t.Fatalf("KnownSeats(nil) must be empty, got %v", empty)
	}
	if reasons := protocol.CheckProjection(state, proj, empty); !containsReason(reasons, protocol.ReasonProjectionUnknownSeat) {
		t.Fatalf("empty known seats must fail closed, got %v", reasons)
	}
}

// ---------------------------------------------------------------------------
// Finding 6: DecodeManifest semantic preflight and the caller-immutable
// kind->schema_ref authority.
// ---------------------------------------------------------------------------

func TestDecodeManifestRejectsKindSchemaRefDrift(t *testing.T) {
	data := readFixture(t, "manifest.json")
	// seat_set's schema_ref drifted to another valid $defs target.
	doc := replaceOnce(string(data), `"schema_ref": "#/$defs/seat_set"`, `"schema_ref": "#/$defs/state"`)
	err := decodeManifestErr([]byte(doc))
	wantReason(t, err, protocol.ReasonManifestInvalid)
	if path := protocol.ContractPath(err); path != "$/assets/0/schema_ref" {
		t.Fatalf("schema_ref drift must be addressed at $/assets/0/schema_ref, got %q", path)
	}
}

func TestDecodeManifestRejectsUnsafeAssetPath(t *testing.T) {
	data := readFixture(t, "manifest.json")
	doc := replaceOnce(string(data), `"path": "seats.json"`, `"path": "../escape.json"`)
	err := decodeManifestErr([]byte(doc))
	wantReason(t, err, protocol.ReasonManifestPathUnsafe)
	if path := protocol.ContractPath(err); path != "$/assets/0/path" {
		t.Fatalf("unsafe path must be addressed at $/assets/0/path, got %q", path)
	}
}

func TestDecodeManifestRejectsDuplicateAssetPaths(t *testing.T) {
	data := readFixture(t, "manifest.json")
	// state.json renamed onto the already-declared seats.json path.
	doc := replaceOnce(string(data), `"path": "state.json"`, `"path": "seats.json"`)
	err := decodeManifestErr([]byte(doc))
	wantReason(t, err, protocol.ReasonManifestInvalid)
	if path := protocol.ContractPath(err); path != "$/assets/1/path" {
		t.Fatalf("duplicate path must be addressed at $/assets/1/path, got %q", path)
	}
}

func TestDecodeManifestRejectsDuplicateMutantAssetPath(t *testing.T) {
	data := readFixture(t, "manifest.json")
	// The mutant path collides with an already-declared asset path.
	doc := replaceOnce(string(data), `"path": "mutants/hidden-leak.json"`, `"path": "seats.json"`)
	err := decodeManifestErr([]byte(doc))
	wantReason(t, err, protocol.ReasonManifestInvalid)
	if path := protocol.ContractPath(err); path != "$/mutants/0/path" {
		t.Fatalf("duplicate mutant path must be addressed at $/mutants/0/path, got %q", path)
	}
}

func TestDecodeManifestRejectsMutantPathOutsideMutants(t *testing.T) {
	data := readFixture(t, "manifest.json")
	doc := replaceOnce(string(data), `"path": "mutants/hidden-leak.json"`, `"path": "hidden-leak.json"`)
	err := decodeManifestErr([]byte(doc))
	wantReason(t, err, protocol.ReasonManifestInvalid)
	if path := protocol.ContractPath(err); path != "$/mutants/0/path" {
		t.Fatalf("mutant outside mutants/ must be addressed at $/mutants/0/path, got %q", path)
	}
}

func TestDecodeManifestRejectsMutantSchemaRefDrift(t *testing.T) {
	data := readFixture(t, "manifest.json")
	doc := replaceOnce(string(data), `"schema_ref": "#/$defs/mutant_specimen"`, `"schema_ref": "#/$defs/state"`)
	err := decodeManifestErr([]byte(doc))
	wantReason(t, err, protocol.ReasonManifestInvalid)
	if path := protocol.ContractPath(err); path != "$/mutants/0/schema_ref" {
		t.Fatalf("mutant schema_ref drift must be addressed at $/mutants/0/schema_ref, got %q", path)
	}
}

func TestManifestRegistrySnapshotMutationCannotInfluenceDecoding(t *testing.T) {
	wantRef, ok := protocol.ManifestKindSchemaRefFor(protocol.KindSeatSet)
	if !ok || wantRef != "#/$defs/seat_set" {
		t.Fatalf("registry query drifted: %q, %v", wantRef, ok)
	}
	snapshot := protocol.ManifestKindSchemaRefSnapshot()
	if len(snapshot) == 0 || snapshot[protocol.KindSeatSet] != wantRef {
		t.Fatalf("registry snapshot must mirror the authority, got %v", snapshot)
	}
	// Mutate the returned snapshot: drift, inject, and delete entries.
	snapshot[protocol.KindSeatSet] = "#/$defs/state"
	snapshot["injected-kind"] = "#/$defs/state"
	delete(snapshot, protocol.KindState)
	// The authority is untouched: queries still return the frozen mapping.
	got, ok := protocol.ManifestKindSchemaRefFor(protocol.KindSeatSet)
	if !ok || got != "#/$defs/seat_set" {
		t.Fatalf("snapshot mutation leaked into the registry: %q, %v", got, ok)
	}
	if _, ok := protocol.ManifestKindSchemaRefFor("injected-kind"); ok {
		t.Fatal("snapshot injection leaked into the registry")
	}
	if _, ok := protocol.ManifestKindSchemaRefFor(protocol.KindState); !ok {
		t.Fatal("snapshot deletion leaked into the registry")
	}
	// Decoding still uses the unexported authority: the shared manifest
	// decodes, and a manifest with a drifted schema_ref still fails.
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	if len(manifest.Assets) == 0 {
		t.Fatal("manifest must still decode after snapshot mutation")
	}
	drifted := replaceOnce(string(readFixture(t, "manifest.json")),
		`"schema_ref": "#/$defs/seat_set"`, `"schema_ref": "#/$defs/state"`)
	wantReason(t, decodeManifestErr([]byte(drifted)), protocol.ReasonManifestInvalid)
	// A fresh snapshot is pristine again.
	fresh := protocol.ManifestKindSchemaRefSnapshot()
	if fresh[protocol.KindSeatSet] != "#/$defs/seat_set" {
		t.Fatalf("fresh snapshot drifted: %v", fresh[protocol.KindSeatSet])
	}
	if _, ok := fresh["injected-kind"]; ok {
		t.Fatal("fresh snapshot carries an injected kind")
	}
	if _, ok := fresh[protocol.KindState]; !ok {
		t.Fatal("fresh snapshot lost a registered kind")
	}
}

func decodeManifestErr(doc []byte) error {
	_, err := protocol.DecodeManifest(doc)
	return err
}
