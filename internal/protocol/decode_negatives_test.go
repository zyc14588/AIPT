package protocol_test

// Focused decode-level negatives for fixture documents: visibility
// fail-closed behavior and the lossless arbitrary-JSON boundary.

import (
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

func stateDocWithField(fieldJSON string) string {
	return `{"protocol_version":"1.0.0","schema_version":"1.0.0","fixture_id":"minimal-v1-arithmetic",` +
		`"state_id":"probe","fields":[` + fieldJSON + `]}`
}

const goodField = `{"field_id":"turn-count","value":0,` +
	`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a","seat-b"]}}`

func TestDecodeStateRejectsMissingVisibility(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONMissingMember)
}

func TestDecodeStateRejectsUnknownVisibilityLabel(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1,` +
		`"visibility":{"label":"TEAM_ONLY","authorized_seat_ids":["seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonVisibilityLabelInvalid)
}

func TestDecodeStateRejectsEmptyVisibilityLabel(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1,` +
		`"visibility":{"label":"","authorized_seat_ids":["seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonVisibilityLabelInvalid)
}

func TestDecodeStateRejectsEmptyAuthorizedSeats(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1,` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":[]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonVisibilityAuthorizationInvalid)
}

func TestDecodeStateRejectsDuplicateAuthorizedSeats(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1,` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a","seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonVisibilityAuthorizationInvalid)
}

func TestDecodeStateRejectsUnknownVisibilityMember(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1,` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"],"extra":1}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONUnknownMember)
}

func TestDecodeStateRejectsNullVisibility(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"x-field","value":1,"visibility":null}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONNullMember)
}

func TestDecodeStateRejectsUnsafeIntegerInsideFieldValue(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"turn-count","value":9007199254740992,` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONUnsafeInteger)
}

func TestDecodeStateRejectsNegativeZeroInsideFieldValue(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"turn-count","value":-0,` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONNegativeZero)
}

func TestDecodeStateRejectsDuplicateKeysInsideFieldValue(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"turn-count","value":{"a":1,"a":2},` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONDuplicateKey)
}

func TestDecodeStateRejectsNonFiniteInsideFieldValue(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"turn-count","value":[1e999],` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"]}}`)
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONNonFiniteNumber)
}

func TestDecodeStateRejectsTrailingInsideFieldValue(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"turn-count","value":{"ok":1},`+
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"]}}`) + ` junk`
	wantReason(t, decodeStateErr(doc), protocol.ReasonJSONTrailing)
}

func TestDecodeStatePreservesLosslessFieldValues(t *testing.T) {
	doc := stateDocWithField(`{"field_id":"nested","value":{"arr":[1,2.5,"x",null,true,{"k":-3}]},` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a"]}}`)
	state, err := protocol.DecodeState([]byte(doc))
	wantNoReason(t, err)
	if len(state.Fields) != 1 {
		t.Fatalf("expected one field, got %d", len(state.Fields))
	}
	// The raw value is preserved exactly (no re-encoding, no coercion).
	if string(state.Fields[0].Value) != `{"arr":[1,2.5,"x",null,true,{"k":-3}]}` {
		t.Fatalf("lossless field value drifted: %s", state.Fields[0].Value)
	}
}

func TestDecodeSeatSetRejectsEmptySeats(t *testing.T) {
	doc := `{"protocol_version":"1.0.0","schema_version":"1.0.0","fixture_id":"minimal-v1-arithmetic","seats":[]}`
	wantReason(t, decodeSeatSetErr(doc), protocol.ReasonSeatSetInvalid)
}

func TestDecodeProjectionRejectsUnknownMember(t *testing.T) {
	doc := `{"protocol_version":"1.0.0","schema_version":"1.0.0","fixture_id":"minimal-v1-arithmetic",` +
		`"projection_id":"p","seat_id":"seat-a","fields":[` + goodField + `],"sneaky":1}`
	wantReason(t, decodeProjectionErr(doc), protocol.ReasonJSONUnknownMember)
}

func TestDecodeMutantSpecimenRejectsDriftedMarkers(t *testing.T) {
	doc := `{"markers":["NON_CANON"],"kind":"hidden-leak","mutant_id":"m","seat_id":"seat-b",` +
		`"leaked_field_id":"table-note","projection":{"protocol_version":"1.0.0","schema_version":"1.0.0",` +
		`"fixture_id":"minimal-v1-arithmetic","projection_id":"p","seat_id":"seat-b","fields":[` + goodField + `]}}`
	wantReason(t, decodeMutantErr(doc), protocol.ReasonMutantSpecimenInvalid)
}

func TestDecodeMutantSpecimenRejectsDriftedKind(t *testing.T) {
	doc := `{"markers":["NON_CANON","MUTANT"],"kind":"other-leak","mutant_id":"m","seat_id":"seat-b",` +
		`"leaked_field_id":"table-note","projection":{"protocol_version":"1.0.0","schema_version":"1.0.0",` +
		`"fixture_id":"minimal-v1-arithmetic","projection_id":"p","seat_id":"seat-b","fields":[` + goodField + `]}}`
	wantReason(t, decodeMutantErr(doc), protocol.ReasonMutantSpecimenInvalid)
}

func decodeStateErr(doc string) error {
	_, err := protocol.DecodeState([]byte(doc))
	return err
}

func decodeSeatSetErr(doc string) error {
	_, err := protocol.DecodeSeatSet([]byte(doc))
	return err
}

func decodeProjectionErr(doc string) error {
	_, err := protocol.DecodeProjection([]byte(doc))
	return err
}

func decodeMutantErr(doc string) error {
	_, err := protocol.DecodeMutantSpecimen([]byte(doc))
	return err
}
