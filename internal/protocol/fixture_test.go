package protocol_test

// Cross-language shared-fixture tests. Every test reads the SAME repository
// files as the accepted TypeScript SDK and the independent Node
// protocol-assets oracle (schemas/protocol/v1/aipt-protocol.schema.json and
// testdata/protocol/v1/minimal-fixture/**), never a second Go-only truth.
// Manifest digests were computed by the Node oracle; recomputing them here
// from the same bytes is the cross-language canonicalization proof.

import (
	"encoding/json"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

func listFixtureJSONFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(fixtureDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && filepath.Ext(p) == ".json" {
			rel, relErr := filepath.Rel(fixtureDir, p)
			if relErr != nil {
				return relErr
			}
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("cannot walk the shared fixture dir: %v", err)
	}
	sort.Strings(files)
	return files
}

func TestFixtureManifestIdentityAndFrozenRefs(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	if manifest.ProtocolVersion != protocol.ProtocolVersion ||
		manifest.SchemaVersion != protocol.SchemaVersion ||
		manifest.FixtureID != protocol.FixtureIDMinimalArithmetic {
		t.Fatalf("manifest identity drifted: %+v", manifest.Identity())
	}
	if manifest.ExpectedFinalState != protocol.FinalStateRef {
		t.Fatalf("manifest expected_final_state drifted: %q", manifest.ExpectedFinalState)
	}
	if manifest.ReplayAssertion != protocol.ReplayAssertionRef {
		t.Fatalf("manifest replay_assertion drifted: %q", manifest.ReplayAssertion)
	}
	if manifest.FixtureName == "" {
		t.Fatal("manifest fixture_name must not be empty")
	}
}

func TestFixtureManifestPathsSafeAndUnique(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	seen := map[string]bool{}
	count := 0
	for _, asset := range manifest.Assets {
		count++
		if problem := protocol.ManifestPathProblem(asset.Path); problem != "" {
			t.Fatalf("manifest asset path %q is unsafe: %s", asset.Path, problem)
		}
		if seen[asset.Path] {
			t.Fatalf("duplicate manifest asset path %q", asset.Path)
		}
		seen[asset.Path] = true
	}
	for _, mutant := range manifest.Mutants {
		count++
		if problem := protocol.ManifestPathProblem(mutant.Path); problem != "" {
			t.Fatalf("manifest mutant path %q is unsafe: %s", mutant.Path, problem)
		}
		if seen[mutant.Path] {
			t.Fatalf("duplicate manifest mutant path %q", mutant.Path)
		}
		seen[mutant.Path] = true
		if !stringsHasPrefix(mutant.Path, "mutants/") {
			t.Fatalf("mutant must live only under mutants/, got %q", mutant.Path)
		}
	}
	if count == 0 {
		t.Fatal("manifest carries no entries")
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestFixtureManifestExactKindSchemaRefMapping(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	for _, asset := range manifest.Assets {
		want, ok := protocol.ManifestKindSchemaRef[asset.Kind]
		if !ok {
			t.Fatalf("manifest kind %q has no canonical schema_ref mapping", asset.Kind)
		}
		if asset.SchemaRef != want {
			t.Fatalf("manifest kind %q must map to exactly %s, got %s", asset.Kind, want, asset.SchemaRef)
		}
	}
	for _, mutant := range manifest.Mutants {
		if mutant.Kind != protocol.KindMutantSpecimen {
			t.Fatalf("mutant kind drifted: %q", mutant.Kind)
		}
		if mutant.SchemaRef != protocol.ManifestKindSchemaRef[protocol.KindMutantSpecimen] {
			t.Fatalf("mutant schema_ref drifted: %q", mutant.SchemaRef)
		}
		if mutant.ExpectedSemanticRejection != protocol.ReasonVisibilityUnauthorizedField {
			t.Fatalf("mutant expected_semantic_rejection drifted: %q", mutant.ExpectedSemanticRejection)
		}
	}
}

func TestFixtureManifestSHA256ValuesLowercaseHex(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	for _, asset := range manifest.Assets {
		if err := protocol.ValidateSHA256Hex(asset.SHA256); err != nil {
			t.Fatalf("asset %s digest is not lowercase hex SHA-256: %v", asset.Path, err)
		}
	}
	for _, mutant := range manifest.Mutants {
		if err := protocol.ValidateSHA256Hex(mutant.SHA256); err != nil {
			t.Fatalf("mutant %s digest is not lowercase hex SHA-256: %v", mutant.Path, err)
		}
	}
}

func TestFixtureInventoryExact(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	listed := []string{"manifest.json"}
	for _, asset := range manifest.Assets {
		listed = append(listed, asset.Path)
	}
	for _, mutant := range manifest.Mutants {
		listed = append(listed, mutant.Path)
	}
	sort.Strings(listed)
	onDisk := listFixtureJSONFiles(t)
	if len(onDisk) != len(listed) {
		t.Fatalf("fixture inventory size drift: %d on disk != %d listed", len(onDisk), len(listed))
	}
	for i := range onDisk {
		if onDisk[i] != listed[i] {
			t.Fatalf("fixture inventory drift at index %d: on disk %q, listed %q (unlisted/missing assets fail closed)",
				i, onDisk[i], listed[i])
		}
	}
}

func TestFixtureAssetDigestsRecomputedFromSameFiles(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	for _, asset := range manifest.Assets {
		data := readFixture(t, asset.Path)
		got, err := protocol.CanonicalSHA256(data)
		if err != nil {
			t.Fatalf("asset %s fails strict canonicalization: %v", asset.Path, err)
		}
		if got != asset.SHA256 {
			t.Fatalf("asset %s digest drift: Go canonical SHA-256 %s != Node oracle manifest digest %s",
				asset.Path, got, asset.SHA256)
		}
	}
	for _, mutant := range manifest.Mutants {
		data := readFixture(t, mutant.Path)
		got, err := protocol.CanonicalSHA256(data)
		if err != nil {
			t.Fatalf("mutant %s fails strict canonicalization: %v", mutant.Path, err)
		}
		if got != mutant.SHA256 {
			t.Fatalf("mutant %s digest drift: Go canonical SHA-256 %s != Node oracle manifest digest %s",
				mutant.Path, got, mutant.SHA256)
		}
	}
}

func TestFixtureEveryAssetDecodesIntoItsGoType(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	for _, asset := range manifest.Assets {
		data := readFixture(t, asset.Path)
		var err error
		switch asset.Kind {
		case protocol.KindSeatSet:
			_, err = protocol.DecodeSeatSet(data)
		case protocol.KindState:
			_, err = protocol.DecodeState(data)
		case protocol.KindProjection:
			_, err = protocol.DecodeProjection(data)
		case protocol.KindActionIntent:
			_, err = protocol.DecodeActionIntent(data)
		case protocol.KindDeterministicCheck:
			_, err = protocol.DecodeDeterministicCheck(data)
		case protocol.KindStateTransition:
			_, err = protocol.DecodeStateTransition(data)
		case protocol.KindStateEvent:
			_, err = protocol.DecodeStateEvent(data)
		case protocol.KindReplayAssertion:
			_, err = protocol.DecodeReplayAssertion(data)
		case protocol.KindJSONRPCRequest:
			_, err = protocol.DecodeRequest(data)
		case protocol.KindJSONRPCResponse:
			_, err = protocol.DecodeResponse(data)
		case protocol.KindJSONRPCNotification:
			_, err = protocol.DecodeNotification(data)
		default:
			t.Fatalf("unhandled manifest kind %q", asset.Kind)
		}
		if err != nil {
			t.Fatalf("asset %s (kind %s) must decode into its Go type: %v", asset.Path, asset.Kind, err)
		}
	}
	for _, mutant := range manifest.Mutants {
		data := readFixture(t, mutant.Path)
		if _, err := protocol.DecodeMutantSpecimen(data); err != nil {
			t.Fatalf("mutant %s must decode into MutantSpecimen: %v", mutant.Path, err)
		}
	}
}

func TestFixtureEveryAssetCarriesFrozenIdentity(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	for _, asset := range manifest.Assets {
		data := readFixture(t, asset.Path)
		var identity protocol.Identity
		var err error
		switch asset.Kind {
		case protocol.KindSeatSet:
			var v *protocol.SeatSet
			v, err = protocol.DecodeSeatSet(data)
			identity = v.Identity()
		case protocol.KindState:
			var v *protocol.State
			v, err = protocol.DecodeState(data)
			identity = v.Identity()
		case protocol.KindProjection:
			var v *protocol.Projection
			v, err = protocol.DecodeProjection(data)
			identity = v.Identity()
		case protocol.KindActionIntent:
			var v *protocol.ActionIntent
			v, err = protocol.DecodeActionIntent(data)
			identity = v.Identity()
		case protocol.KindDeterministicCheck:
			var v *protocol.DeterministicCheck
			v, err = protocol.DecodeDeterministicCheck(data)
			identity = v.Identity()
		case protocol.KindStateTransition:
			var v *protocol.StateTransition
			v, err = protocol.DecodeStateTransition(data)
			identity = v.Identity()
		case protocol.KindStateEvent:
			var v *protocol.StateEvent
			v, err = protocol.DecodeStateEvent(data)
			identity = v.Identity()
		case protocol.KindReplayAssertion:
			var v *protocol.ReplayAssertion
			v, err = protocol.DecodeReplayAssertion(data)
			identity = v.Identity()
		case protocol.KindJSONRPCRequest:
			var v *protocol.Request
			v, err = protocol.DecodeRequest(data)
			identity = v.Identity()
		case protocol.KindJSONRPCResponse:
			var v *protocol.Response
			v, err = protocol.DecodeResponse(data)
			identity = v.Identity()
		case protocol.KindJSONRPCNotification:
			var v *protocol.Notification
			v, err = protocol.DecodeNotification(data)
			identity = v.Identity()
		}
		if err != nil {
			t.Fatalf("asset %s must decode: %v", asset.Path, err)
		}
		if err := protocol.ValidateFixtureIdentity(identity); err != nil {
			t.Fatalf("asset %s identity drifted: %v", asset.Path, err)
		}
	}
	for _, mutant := range manifest.Mutants {
		v, err := protocol.DecodeMutantSpecimen(readFixture(t, mutant.Path))
		if err != nil {
			t.Fatalf("mutant %s must decode: %v", mutant.Path, err)
		}
		if err := protocol.ValidateFixtureIdentity(v.Projection.Identity()); err != nil {
			t.Fatalf("mutant %s inner projection identity drifted: %v", mutant.Path, err)
		}
	}
}

func TestFixtureSeatsExactlyTwoDistinct(t *testing.T) {
	seats := mustDecodeSeatSet(t, readFixture(t, "seats.json"))
	if len(seats.Seats) != 2 {
		t.Fatalf("fixture must carry exactly two seats, got %d", len(seats.Seats))
	}
	ids := []string{seats.Seats[0].SeatID, seats.Seats[1].SeatID}
	sort.Strings(ids)
	if ids[0] != "seat-a" || ids[1] != "seat-b" {
		t.Fatalf("seats must be exactly seat-a and seat-b, got %v", ids)
	}
	if seats.Seats[0].SeatID == seats.Seats[1].SeatID {
		t.Fatal("seats must be distinct")
	}
}

func TestFixtureProjectionsSemantics(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	projA := mustDecodeProjection(t, readFixture(t, "projection-seat-a.json"))
	projB := mustDecodeProjection(t, readFixture(t, "projection-seat-b.json"))
	if projA.SeatID != "seat-a" || projB.SeatID != "seat-b" {
		t.Fatalf("projection seats drifted: %q / %q", projA.SeatID, projB.SeatID)
	}
	aIDs := fieldIDs(projA.Fields)
	bIDs := fieldIDs(projB.Fields)
	if len(aIDs) != 2 || aIDs[0] != "table-note" || aIDs[1] != "turn-count" {
		t.Fatalf("seat-a projection must project exactly [table-note, turn-count], got %v", aIDs)
	}
	if len(bIDs) != 1 || bIDs[0] != "turn-count" {
		t.Fatalf("seat-b projection must project exactly [turn-count], got %v", bIDs)
	}
	for _, proj := range []*protocol.Projection{projA, projB} {
		if err := protocol.ValidateProjection(state, proj, known); err != nil {
			t.Fatalf("projection %s must pass semantics: %v", proj.ProjectionID, err)
		}
	}
	if reasons := protocol.CheckStateMetadata(state, known); len(reasons) != 0 {
		t.Fatalf("state metadata gate must pass: %v", reasons)
	}

}

func fieldIDs(fields []protocol.StateField) []string {
	ids := make([]string, 0, len(fields))
	for _, f := range fields {
		ids = append(ids, f.FieldID)
	}
	sort.Strings(ids)
	return ids
}

func TestFixtureActionIntentAndRequestParamsDeepEqual(t *testing.T) {
	intent, err := protocol.DecodeActionIntent(readFixture(t, "action-intent.json"))
	wantNoReason(t, err)
	if intent.Method != protocol.MethodRequest {
		t.Fatalf("action intent method drifted: %q", intent.Method)
	}
	if intent.Params.Action != "advance-turn" || intent.Params.SeatID != "seat-a" {
		t.Fatalf("action intent params drifted: %+v", intent.Params)
	}
	req, err := protocol.DecodeRequest(readFixture(t, "requests/apply-action-request.json"))
	wantNoReason(t, err)
	if req.Method != intent.Method {
		t.Fatalf("request method must match action intent method: %q != %q", req.Method, intent.Method)
	}
	if !protocol.JSONEqual(mustMarshal(t, req.Params), mustMarshal(t, intent.Params)) {
		t.Fatal("persisted request params must deep-equal action-intent.json params")
	}
	if !protocol.JSONEqual(intent.Params.Proposal, json.RawMessage(`{"delta":1}`)) {
		t.Fatalf("proposal payload drifted: %s", intent.Params.Proposal)
	}
}

func TestFixtureRequestResponseIDRoundTripsValueAndType(t *testing.T) {
	req, err := protocol.DecodeRequest(readFixture(t, "requests/apply-action-request.json"))
	wantNoReason(t, err)
	resultResp, err := protocol.DecodeResponse(readFixture(t, "responses/apply-action-result-response.json"))
	wantNoReason(t, err)
	errorResp, err := protocol.DecodeResponse(readFixture(t, "responses/apply-action-protocol-error-response.json"))
	wantNoReason(t, err)
	if req.ID.Kind() != protocol.IDString {
		t.Fatalf("persisted request id must be a string, got kind %d", req.ID.Kind())
	}
	if !resultResp.ID.Equal(req.ID) {
		t.Fatalf("result response id must round-trip the request id by value AND JSON type: %+v != %+v",
			resultResp.ID, req.ID)
	}
	if !errorResp.ID.Equal(req.ID) {
		t.Fatalf("error response id must round-trip the request id by value AND JSON type: %+v != %+v",
			errorResp.ID, req.ID)
	}
}

func TestFixtureResultResponseCrossLinks(t *testing.T) {
	req, err := protocol.DecodeRequest(readFixture(t, "requests/apply-action-request.json"))
	wantNoReason(t, err)
	resp, err := protocol.DecodeResponse(readFixture(t, "responses/apply-action-result-response.json"))
	wantNoReason(t, err)
	transition := mustDecodeTransition(t, readFixture(t, "transition.json"))
	if resp.Result == nil {
		t.Fatal("result response must carry a result")
	}
	if !resp.Result.Accepted {
		t.Fatal("result.accepted must be true")
	}
	if resp.Result.TransitionID != transition.TransitionID {
		t.Fatalf("result transition_id must cross-link to transition.json: %q != %q",
			resp.Result.TransitionID, transition.TransitionID)
	}
	if !protocol.JSONEqual(mustMarshal(t, resp.Result.AppliedFields), mustMarshal(t, transition.Result)) {
		t.Fatal("result applied_fields must deep-equal transition.json result")
	}
	finalState := mustDecodeState(t, readFixture(t, "final-state.json"))
	finalByID := map[string]protocol.StateField{}
	for _, f := range finalState.Fields {
		finalByID[f.FieldID] = f
	}
	for _, applied := range resp.Result.AppliedFields {
		ff, ok := finalByID[applied.FieldID]
		if !ok || !protocol.JSONEqual(ff.Value, applied.Value) ||
			ff.Visibility.Label != applied.Visibility.Label ||
			!equalSet(ff.Visibility.AuthorizedSeatIDs, applied.Visibility.AuthorizedSeatIDs) {
			t.Fatalf("applied field %s must match final-state.json value and visibility", applied.FieldID)
		}
	}
	_ = req
}

func equalSet(a, b []string) bool {
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	if len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

func TestFixtureProtocolErrorCoherent(t *testing.T) {
	req, err := protocol.DecodeRequest(readFixture(t, "requests/apply-action-request.json"))
	wantNoReason(t, err)
	resp, err := protocol.DecodeResponse(readFixture(t, "responses/apply-action-protocol-error-response.json"))
	wantNoReason(t, err)
	if resp.Error == nil {
		t.Fatal("error response must carry an error")
	}
	if resp.Error.Code != protocol.WireErrorExampleCode {
		t.Fatalf("persisted protocol error code must be the documented -32000, got %d", resp.Error.Code)
	}
	if resp.Error.Data == nil || resp.Error.Data.ErrorCode != protocol.WireErrorExampleDataCode {
		t.Fatalf("persisted protocol error must carry %s in data.error_code, got %+v",
			protocol.WireErrorExampleDataCode, resp.Error.Data)
	}
	if resp.Error.Data.ErrorCode == protocol.ReasonVisibilityUnauthorizedField {
		t.Fatal("wire error must never reuse the mutant visibility code")
	}
	if resp.Error.Message != protocol.WireErrorExampleMessage {
		t.Fatalf("persisted protocol error message drifted: %q", resp.Error.Message)
	}
	if reasons := protocol.CheckWireErrorCoherence(req.Method, resp.Error); len(reasons) != 0 {
		t.Fatalf("persisted protocol error must be coherent with the request it references: %v", reasons)
	}
}

func TestFixtureNotificationEmbedsExactEvent(t *testing.T) {
	event, err := protocol.DecodeStateEvent(readFixture(t, "event.json"))
	wantNoReason(t, err)
	notif, err := protocol.DecodeNotification(readFixture(t, "notifications/state-event-notification.json"))
	wantNoReason(t, err)
	if notif.Method != protocol.MethodNotification {
		t.Fatalf("notification method drifted: %q", notif.Method)
	}
	if !protocol.JSONEqual(mustMarshal(t, notif.Params.Event), mustMarshal(t, event)) {
		t.Fatal("notification must wrap the exact existing event.json")
	}
	transition := mustDecodeTransition(t, readFixture(t, "transition.json"))
	if event.TransitionID != transition.TransitionID || event.EventType != protocol.EventTypeStateTransitionApplied {
		t.Fatalf("event must reference the transition with the frozen event type: %+v", event)
	}
	if event.Payload.FromStateID != "initial" || event.Payload.ToStateID != "final" {
		t.Fatalf("event payload must record initial -> final: %+v", event.Payload)
	}
}

func TestFixtureDeterministicArithmeticOutput(t *testing.T) {
	check, err := protocol.DecodeDeterministicCheck(readFixture(t, "check-turn-increment.json"))
	wantNoReason(t, err)
	wantNoReason(t, protocol.CheckArithmetic(check))
	if check.Output != 1 {
		t.Fatalf("declared arithmetic output must be 1, got %v", check.Output)
	}
}

func TestFixtureTransitionInitialToFinal(t *testing.T) {
	state := mustDecodeState(t, readFixture(t, "state.json"))
	finalState := mustDecodeState(t, readFixture(t, "final-state.json"))
	transition := mustDecodeTransition(t, readFixture(t, "transition.json"))
	if transition.FromStateID != state.StateID || transition.ToStateID != finalState.StateID {
		t.Fatalf("transition must move initial -> final: %q -> %q (state %q -> %q)",
			transition.FromStateID, transition.ToStateID, state.StateID, finalState.StateID)
	}
	intent, err := protocol.DecodeActionIntent(readFixture(t, "action-intent.json"))
	wantNoReason(t, err)
	if transition.AppliedAction.Action != intent.Params.Action || transition.AppliedAction.SeatID != "seat-a" {
		t.Fatalf("transition applied_action must match the action intent: %+v", transition.AppliedAction)
	}
	if len(transition.Result) != 1 || transition.Result[0].FieldID != "turn-count" {
		t.Fatalf("transition result must update exactly turn-count, got %+v", transition.Result)
	}
	next := protocol.ApplyTransition(state, transition)
	if !protocol.JSONEqual(mustMarshal(t, next), mustMarshal(t, finalState)) {
		t.Fatal("transition result applied to the initial state must equal final-state.json exactly")
	}
}

func TestFixtureReplayAssertionHashesDeterministic(t *testing.T) {
	state := mustDecodeState(t, readFixture(t, "state.json"))
	transition := mustDecodeTransition(t, readFixture(t, "transition.json"))
	assertion, err := protocol.DecodeReplayAssertion(readFixture(t, "replay-assertion.json"))
	wantNoReason(t, err)
	if assertion.HashAlgorithm != protocol.HashAlgorithmSHA256 ||
		assertion.FinalStateRef != protocol.FinalStateRef {
		t.Fatalf("replay assertion frozen refs drifted: %+v", assertion)
	}
	// Recompute final-state.json's canonical hash from the SAME shared file.
	computed, err := protocol.CanonicalSHA256(readFixture(t, "final-state.json"))
	wantNoReason(t, err)
	if assertion.FinalStateHash != computed {
		t.Fatalf("replay assertion final_state_hash drifted: asserted %s != recomputed %s",
			assertion.FinalStateHash, computed)
	}
	if len(assertion.Replays) != 2 {
		t.Fatalf("replay assertion must carry exactly two replay records, got %d", len(assertion.Replays))
	}
	for i, replay := range assertion.Replays {
		if replay.FinalStateHash != computed {
			t.Fatalf("replay record %d must equal the recomputed final state hash", i)
		}
	}
	// Two independent replays of the declared transition must agree.
	r1 := protocol.ApplyTransition(state, transition)
	r2 := protocol.ApplyTransition(state, transition)
	if !protocol.JSONEqual(mustMarshal(t, r1), mustMarshal(t, r2)) {
		t.Fatal("two replays of the same transition must yield the same final state")
	}
	h1, err := protocol.CanonicalSHA256(mustMarshal(t, r1))
	wantNoReason(t, err)
	h2, err := protocol.CanonicalSHA256(mustMarshal(t, r2))
	wantNoReason(t, err)
	if h1 != h2 || h1 != computed {
		t.Fatalf("replay hashes diverged: %s / %s / recomputed %s", h1, h2, computed)
	}
}

func TestFixtureMutantMarkersKindAndBinding(t *testing.T) {
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	if len(mutant.Markers) != 2 || mutant.Markers[0] != "NON_CANON" || mutant.Markers[1] != "MUTANT" {
		t.Fatalf("mutant markers must be exactly [NON_CANON, MUTANT], got %v", mutant.Markers)
	}
	if mutant.Kind != protocol.MutantKindHiddenLeak {
		t.Fatalf("mutant kind must be hidden-leak, got %q", mutant.Kind)
	}
	if mutant.SeatID != "seat-b" || mutant.Projection.SeatID != "seat-b" {
		t.Fatalf("hidden-leak mutant must be a seat-b projection: wrapper %q, projection %q",
			mutant.SeatID, mutant.Projection.SeatID)
	}
	if mutant.LeakedFieldID != "table-note" {
		t.Fatalf("mutant leaked_field_id must be table-note, got %q", mutant.LeakedFieldID)
	}
	leakPresent := false
	for _, f := range mutant.Projection.Fields {
		if f.FieldID == "table-note" {
			leakPresent = true
		}
	}
	if !leakPresent {
		t.Fatal("mutant must actually place table-note in the seat-b projection")
	}
}

func TestFixtureMutantRejectedForAuthorizationOnly(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	reasons := protocol.CheckProjection(state, &mutant.Projection, known)
	if len(reasons) != 1 || reasons[0] != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("mutant must be semantically rejected with exactly %s (never JSON/schema syntax reasons), got %v",
			protocol.ReasonVisibilityUnauthorizedField, reasons)
	}
	reason, err := protocol.MutantSemanticRejection(mutant, state, known)
	wantNoReason(t, err)
	if reason != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("mutant rejection reason drifted: %q", reason)
	}
}

func TestFixtureMutantWrapperMetadataBound(t *testing.T) {
	state, _, known := fixtureStateAndSeats(t)
	mutant, err := protocol.DecodeMutantSpecimen(readFixture(t, "mutants/hidden-leak.json"))
	wantNoReason(t, err)
	// Drift the wrapper seat_id so metadata cannot masquerade as the fixture.
	driftedSeat := *mutant
	driftedSeat.SeatID = "seat-a"
	if _, err := protocol.MutantSemanticRejection(&driftedSeat, state, known); err == nil {
		t.Fatal("wrapper seat_id drift must fail closed")
	}
	// Drift the leaked_field_id binding.
	driftedField := *mutant
	driftedField.LeakedFieldID = "turn-count"
	if _, err := protocol.MutantSemanticRejection(&driftedField, state, known); err == nil {
		t.Fatal("leaked_field_id drift must fail closed")
	}
}

func TestFixtureReplayManifestExpectedFinalStatePresent(t *testing.T) {
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	if manifest.ExpectedFinalState != "final-state.json" {
		t.Fatalf("expected_final_state drifted: %q", manifest.ExpectedFinalState)
	}
	files := listFixtureJSONFiles(t)
	has := false
	for _, f := range files {
		if f == "final-state.json" {
			has = true
		}
	}
	if !has {
		t.Fatal("final-state.json must exist in the fixture inventory")
	}
}

func TestSchemaFileIsOutsideFixtureManifest(t *testing.T) {
	// The canonical schema file itself is outside the fixture manifest.
	manifest := mustDecodeManifest(t, readFixture(t, "manifest.json"))
	for _, asset := range manifest.Assets {
		if path.Base(asset.Path) == "aipt-protocol.schema.json" {
			t.Fatal("the canonical schema file must not be a manifest-listed fixture asset")
		}
	}
}
