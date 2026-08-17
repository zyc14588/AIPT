package protocol_test

// Schema-drift tests: the canonical schema
// schemas/protocol/v1/aipt-protocol.schema.json is the single wire
// authority. These tests read it and independently derive the protocol
// constants, registries, bounds, and visibility labels from its local $defs,
// then compare them against the Go package constants — no hand-written
// constant may drift silently. No general JSON Schema evaluator is
// implemented or copied here; only the needed $defs nodes are projected
// into tiny typed structs.

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

type constString struct {
	Const string `json:"const"`
}

type enumString struct {
	Enum []string `json:"enum"`
}

type minMaxNumber struct {
	Minimum float64 `json:"minimum"`
	Maximum float64 `json:"maximum"`
}

type stringBounds struct {
	MinLength int    `json:"minLength"`
	MaxLength int    `json:"maxLength"`
	Pattern   string `json:"pattern"`
}

type stringPattern struct {
	Pattern string `json:"pattern"`
}

type refStruct struct {
	Ref string `json:"$ref"`
}

type requiredList struct {
	Required []string `json:"required"`
}

type minItemsUnique struct {
	MinItems    int  `json:"minItems"`
	UniqueItems bool `json:"uniqueItems"`
}

type idOneOf struct {
	OneOf []json.RawMessage `json:"oneOf"`
}

type objectType struct {
	Type string `json:"type"`
}

func schemaDef(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("canonical schema unparseable: %v", err)
	}
	if len(doc.Defs) == 0 {
		t.Fatal("canonical schema must carry local $defs")
	}
	return doc.Defs
}

func defAs[T any](t *testing.T, defs map[string]json.RawMessage, name string) T {
	t.Helper()
	var out T
	raw, ok := defs[name]
	if !ok {
		t.Fatalf("canonical schema is missing $defs/%s", name)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("cannot derive $defs/%s: %v", name, err)
	}
	return out
}

func TestSchemaDerivesProtocolVersionConstants(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	if got := defAs[constString](t, defs, "protocol_version").Const; got != protocol.ProtocolVersion {
		t.Fatalf("protocol.ProtocolVersion drifted from schema const: %q != %q", protocol.ProtocolVersion, got)
	}
	if got := defAs[constString](t, defs, "schema_version").Const; got != protocol.SchemaVersion {
		t.Fatalf("protocol.SchemaVersion drifted from schema const: %q != %q", protocol.SchemaVersion, got)
	}
	if got := defAs[constString](t, defs, "jsonrpc_version").Const; got != protocol.JSONRPCVersion {
		t.Fatalf("protocol.JSONRPCVersion drifted from schema const: %q != %q", protocol.JSONRPCVersion, got)
	}
}

func TestSchemaDerivesMethodRegistry(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	var reqDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["jsonrpc_request"], &reqDef)
	var reqMethod constString
	json.Unmarshal(reqDef.Properties["method"], &reqMethod)
	if reqMethod.Const != protocol.MethodRequest {
		t.Fatalf("protocol.MethodRequest drifted from schema: %q != %q", protocol.MethodRequest, reqMethod.Const)
	}
	var notifDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["jsonrpc_notification"], &notifDef)
	var notifMethod constString
	json.Unmarshal(notifDef.Properties["method"], &notifMethod)
	if notifMethod.Const != protocol.MethodNotification {
		t.Fatalf("protocol.MethodNotification drifted from schema: %q != %q", protocol.MethodNotification, notifMethod.Const)
	}
}

func TestSchemaDerivesVisibilityLabels(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	labels := defAs[enumString](t, defs, "visibility_label").Enum
	want := protocol.VisibilityLabels()
	if len(labels) != len(want) {
		t.Fatalf("visibility label count drifted: schema %v != Go %v", labels, want)
	}
	for i := range labels {
		if labels[i] != want[i] {
			t.Fatalf("visibility label %d drifted: schema %q != Go %q", i, labels[i], want[i])
		}
	}
}

func TestSchemaDerivesSafeIntegerBounds(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	bounds := defAs[minMaxNumber](t, defs, "request_id_integer")
	if bounds.Minimum != float64(protocol.SafeIntegerMin) {
		t.Fatalf("SafeIntegerMin drifted from schema minimum: %d != %v", protocol.SafeIntegerMin, bounds.Minimum)
	}
	if bounds.Maximum != float64(protocol.SafeIntegerMax) {
		t.Fatalf("SafeIntegerMax drifted from schema maximum: %d != %v", protocol.SafeIntegerMax, bounds.Maximum)
	}
	if bounds.Minimum != -9007199254740991 || bounds.Maximum != 9007199254740991 {
		t.Fatalf("safe-integer bounds must be +-(2^53-1), got [%v, %v]", bounds.Minimum, bounds.Maximum)
	}
}

func TestSchemaDerivesRequestIDAlternatives(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	oneOf := defAs[idOneOf](t, defs, "request_id").OneOf
	if len(oneOf) != 2 {
		t.Fatalf("request_id must be a oneOf string|integer, got %d branches", len(oneOf))
	}
	var stringBranch stringBounds
	var intRef refStruct
	foundString, foundInt := false, false
	for _, raw := range oneOf {
		var probe struct {
			Type string          `json:"type"`
			Ref  string          `json:"$ref"`
			B    stringBounds    `json:"-"`
			Raw  json.RawMessage `json:"-"`
		}
		json.Unmarshal(raw, &probe)
		if probe.Type == "string" {
			json.Unmarshal(raw, &stringBranch)
			foundString = true
		}
		if probe.Ref == "#/$defs/request_id_integer" {
			intRef.Ref = probe.Ref
			foundInt = true
		}
	}
	if !foundString || !foundInt {
		t.Fatalf("request_id oneOf must carry a string branch and the request_id_integer ref")
	}
	if stringBranch.MinLength != 1 || stringBranch.MaxLength != protocol.MaxRequestIDStringLength {
		t.Fatalf("request id string bounds drifted: %d..%d != 1..%d",
			stringBranch.MinLength, stringBranch.MaxLength, protocol.MaxRequestIDStringLength)
	}
}

func TestSchemaDerivesIdentifierPatterns(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	cases := []struct {
		def, goPattern string
	}{
		{"fixture_id", protocol.PatternIdentifier},
		{"seat_id", protocol.PatternIdentifier},
		{"message_id", protocol.PatternMessageID},
		{"sha256_hex", protocol.PatternSHA256Hex},
	}
	for _, c := range cases {
		got := defAs[stringPattern](t, defs, c.def).Pattern
		if got != c.goPattern {
			t.Fatalf("pattern for $defs/%s drifted: schema %q != Go %q", c.def, got, c.goPattern)
		}
	}
	// state_field.field_id shares the identifier pattern.
	var fieldDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["state_field"], &fieldDef)
	var fieldID stringPattern
	json.Unmarshal(fieldDef.Properties["field_id"], &fieldID)
	if fieldID.Pattern != protocol.PatternIdentifier {
		t.Fatalf("field_id pattern drifted: schema %q != Go %q", fieldID.Pattern, protocol.PatternIdentifier)
	}
	// error_object.data.error_code pattern.
	var errDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["error_object"], &errDef)
	var dataDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(errDef.Properties["data"], &dataDef)
	var errorCode stringPattern
	json.Unmarshal(dataDef.Properties["error_code"], &errorCode)
	if errorCode.Pattern != protocol.PatternErrorCode {
		t.Fatalf("error_code pattern drifted: schema %q != Go %q", errorCode.Pattern, protocol.PatternErrorCode)
	}
	// manifest_asset.schema_ref pattern.
	var assetDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["manifest_asset"], &assetDef)
	var schemaRef stringPattern
	json.Unmarshal(assetDef.Properties["schema_ref"], &schemaRef)
	if schemaRef.Pattern != protocol.PatternSchemaRef {
		t.Fatalf("schema_ref pattern drifted: schema %q != Go %q", schemaRef.Pattern, protocol.PatternSchemaRef)
	}
}

func TestSchemaDerivesManifestKindRegistry(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	var assetDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["manifest_asset"], &assetDef)
	var kindEnum enumString
	json.Unmarshal(assetDef.Properties["kind"], &kindEnum)
	schemaKinds := append([]string(nil), kindEnum.Enum...)
	// The mutant entry adds exactly mutant_specimen on top of the asset enum.
	schemaKinds = append(schemaKinds, protocol.KindMutantSpecimen)
	sort.Strings(schemaKinds)
	goRegistry := protocol.ManifestKindSchemaRefSnapshot()
	goKinds := make([]string, 0, len(goRegistry))
	for k := range goRegistry {
		goKinds = append(goKinds, k)
	}
	sort.Strings(goKinds)
	if len(schemaKinds) != len(goKinds) {
		t.Fatalf("manifest kind registry drifted: schema %v != Go %v", schemaKinds, goKinds)
	}
	for i := range schemaKinds {
		if schemaKinds[i] != goKinds[i] {
			t.Fatalf("manifest kind %d drifted: schema %q != Go %q", i, schemaKinds[i], goKinds[i])
		}
	}
	// mutant manifest entry kind is exactly mutant_specimen.
	var mutantDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["manifest_mutant"], &mutantDef)
	var mutantKind constString
	json.Unmarshal(mutantDef.Properties["kind"], &mutantKind)
	if mutantKind.Const != protocol.KindMutantSpecimen {
		t.Fatalf("mutant kind drifted: schema %q != Go %q", mutantKind.Const, protocol.KindMutantSpecimen)
	}
}

func TestSchemaDerivesMutantConstants(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	var mutantDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["mutant_specimen"], &mutantDef)
	var markers struct {
		Const []string `json:"const"`
	}
	json.Unmarshal(mutantDef.Properties["markers"], &markers)
	if len(markers.Const) != 2 || markers.Const[0] != protocol.MutantMarkerNonCanon || markers.Const[1] != protocol.MutantMarkerMutant {
		t.Fatalf("mutant markers drifted: schema %v != [%q %q]", markers.Const,
			protocol.MutantMarkerNonCanon, protocol.MutantMarkerMutant)
	}
	var kind constString
	json.Unmarshal(mutantDef.Properties["kind"], &kind)
	if kind.Const != protocol.MutantKindHiddenLeak {
		t.Fatalf("mutant kind drifted: schema %q != Go %q", kind.Const, protocol.MutantKindHiddenLeak)
	}
	var manifestMutantDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["manifest_mutant"], &manifestMutantDef)
	var rejection constString
	json.Unmarshal(manifestMutantDef.Properties["expected_semantic_rejection"], &rejection)
	if rejection.Const != protocol.ReasonVisibilityUnauthorizedField {
		t.Fatalf("expected_semantic_rejection drifted: schema %q != Go %q",
			rejection.Const, protocol.ReasonVisibilityUnauthorizedField)
	}
}

func TestSchemaDerivesVisibilityShape(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	required := defAs[requiredList](t, defs, "visibility").Required
	want := []string{"label", "authorized_seat_ids"}
	if len(required) != 2 || required[0] != want[0] || required[1] != want[1] {
		t.Fatalf("visibility required members drifted: %v != %v", required, want)
	}
	auth := defAs[minItemsUnique](t, defs, "authorized_seat_ids")
	if auth.MinItems != 1 || !auth.UniqueItems {
		t.Fatalf("authorized_seat_ids must be non-empty and unique, got minItems=%d uniqueItems=%v",
			auth.MinItems, auth.UniqueItems)
	}
	fieldRequired := defAs[requiredList](t, defs, "state_field").Required
	if !containsStr(fieldRequired, "visibility") {
		t.Fatalf("state_field must require visibility, got %v", fieldRequired)
	}
}

func TestSchemaDerivesEnvelopeIdentityRequirements(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	for _, name := range []string{"jsonrpc_request", "jsonrpc_response", "jsonrpc_notification"} {
		required := defAs[requiredList](t, defs, name).Required
		for _, member := range []string{"protocol_version", "schema_version", "fixture_id"} {
			if !containsStr(required, member) {
				t.Fatalf("$defs/%s must require %s, got %v", name, member, required)
			}
		}
	}
	// request and response share the same request_id bound.
	var reqDef, respDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["jsonrpc_request"], &reqDef)
	json.Unmarshal(defs["jsonrpc_response"], &respDef)
	for name, props := range map[string]map[string]json.RawMessage{"jsonrpc_request": reqDef.Properties, "jsonrpc_response": respDef.Properties} {
		var idRef refStruct
		json.Unmarshal(props["id"], &idRef)
		if idRef.Ref != "#/$defs/request_id" {
			t.Fatalf("%s.id must reference #/$defs/request_id, got %q", name, idRef.Ref)
		}
	}
	// Response result/error exclusivity.
	if len(defAs[idOneOf](t, defs, "jsonrpc_response").OneOf) != 2 {
		t.Fatal("jsonrpc_response must enforce result/error exclusivity via oneOf")
	}
}

func TestSchemaDerivesCheckAndReplayConstants(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	var checkDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["deterministic_check"], &checkDef)
	wantConsts := map[string]string{
		"check_version": protocol.CheckVersion,
		"kind":          protocol.CheckKindArithmetic,
		"operator":      protocol.CheckOperatorAdd,
	}
	for member, goValue := range wantConsts {
		var c constString
		json.Unmarshal(checkDef.Properties[member], &c)
		if c.Const != goValue {
			t.Fatalf("deterministic_check.%s drifted: schema %q != Go %q", member, c.Const, goValue)
		}
	}
	var replayDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["replay_assertion"], &replayDef)
	var hashAlg constString
	json.Unmarshal(replayDef.Properties["hash_algorithm"], &hashAlg)
	if hashAlg.Const != protocol.HashAlgorithmSHA256 {
		t.Fatalf("hash_algorithm drifted: schema %q != Go %q", hashAlg.Const, protocol.HashAlgorithmSHA256)
	}
	var finalRef constString
	json.Unmarshal(replayDef.Properties["final_state_ref"], &finalRef)
	if finalRef.Const != protocol.FinalStateRef {
		t.Fatalf("final_state_ref drifted: schema %q != Go %q", finalRef.Const, protocol.FinalStateRef)
	}
	// Event type.
	var eventDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["state_event"], &eventDef)
	var eventType constString
	json.Unmarshal(eventDef.Properties["event_type"], &eventType)
	if eventType.Const != protocol.EventTypeStateTransitionApplied {
		t.Fatalf("event_type drifted: schema %q != Go %q", eventType.Const, protocol.EventTypeStateTransitionApplied)
	}
	// Manifest frozen refs.
	var manifestDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["fixture_manifest"], &manifestDef)
	var expectedFinal constString
	json.Unmarshal(manifestDef.Properties["expected_final_state"], &expectedFinal)
	if expectedFinal.Const != protocol.FinalStateRef {
		t.Fatalf("manifest expected_final_state drifted: schema %q != Go %q", expectedFinal.Const, protocol.FinalStateRef)
	}
	var replayRef constString
	json.Unmarshal(manifestDef.Properties["replay_assertion"], &replayRef)
	if replayRef.Const != protocol.ReplayAssertionRef {
		t.Fatalf("manifest replay_assertion drifted: schema %q != Go %q", replayRef.Const, protocol.ReplayAssertionRef)
	}
	// Error code is a plain integer (no reserved range).
	var errDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["error_object"], &errDef)
	var errCode objectType
	json.Unmarshal(errDef.Properties["code"], &errCode)
	if errCode.Type != "integer" {
		t.Fatalf("error_object.code must be a plain integer, got type %q", errCode.Type)
	}
}

func TestSchemaRootIsExecutable(t *testing.T) {
	var doc struct {
		OneOf []json.RawMessage `json:"oneOf"`
	}
	if err := json.Unmarshal(readSchema(t), &doc); err != nil {
		t.Fatalf("schema unparseable: %v", err)
	}
	var refs []string
	for _, raw := range doc.OneOf {
		var r refStruct
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("root oneOf branch is not a $ref: %v", err)
		}
		refs = append(refs, r.Ref)
	}
	sort.Strings(refs)
	want := []string{"#/$defs/jsonrpc_notification", "#/$defs/jsonrpc_request", "#/$defs/jsonrpc_response"}
	sort.Strings(want)
	if len(refs) != 3 || refs[0] != want[0] || refs[1] != want[1] || refs[2] != want[2] {
		t.Fatalf("root oneOf must accept exactly the three registered wire envelopes, got %v", refs)
	}
}

func containsStr(list []string, value string) bool {
	for _, s := range list {
		if s == value {
			return true
		}
	}
	return false
}

func TestSchemaDerivesIdentifierLengthBounds(t *testing.T) {
	defs := schemaDef(t, readSchema(t))
	// Identifier bounds live inside the frozen patterns; the length
	// constants are re-derived from the schema maxLength facets.
	cases := []struct {
		def       string
		goMax     int
		goPattern string
	}{
		{"fixture_id", protocol.MaxIdentifierLength, protocol.PatternIdentifier},
		{"seat_id", protocol.MaxIdentifierLength, protocol.PatternIdentifier},
		{"message_id", protocol.MaxMessageIDLength, protocol.PatternMessageID},
	}
	for _, c := range cases {
		got := defAs[stringBounds](t, defs, c.def)
		if got.MaxLength != c.goMax {
			t.Fatalf("$defs/%s maxLength drifted: schema %d != Go %d", c.def, got.MaxLength, c.goMax)
		}
		if got.Pattern != c.goPattern {
			t.Fatalf("$defs/%s pattern drifted: schema %q != Go %q", c.def, got.Pattern, c.goPattern)
		}
	}
	// seat.name has no pattern, only the 1..64 character bound.
	var seatDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["seat"], &seatDef)
	var nameBounds stringBounds
	json.Unmarshal(seatDef.Properties["name"], &nameBounds)
	if nameBounds.MinLength != 1 || nameBounds.MaxLength != protocol.MaxNameLength {
		t.Fatalf("seat.name bounds drifted: %d..%d != 1..%d",
			nameBounds.MinLength, nameBounds.MaxLength, protocol.MaxNameLength)
	}
	// state_field.field_id maxLength.
	var fieldDef struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	json.Unmarshal(defs["state_field"], &fieldDef)
	var fieldBounds stringBounds
	json.Unmarshal(fieldDef.Properties["field_id"], &fieldBounds)
	if fieldBounds.MaxLength != protocol.MaxIdentifierLength {
		t.Fatalf("field_id maxLength drifted: %d != %d", fieldBounds.MaxLength, protocol.MaxIdentifierLength)
	}
}
