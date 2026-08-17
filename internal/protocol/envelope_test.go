package protocol_test

import (
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const probeIdentity = `"protocol_version":"1.0.0","schema_version":"1.0.0","fixture_id":"minimal-v1-arithmetic"`

func probeRequest(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"aipt.protocol.applyAction",` +
		`"params":{"action":"advance-turn","seat_id":"seat-a","proposal":{"delta":1}},` + probeIdentity + `}`
}

func probeResultResponse(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,` + probeIdentity + `,` +
		`"result":{"accepted":true,"transition_id":"transition-turn-increment",` +
		`"applied_fields":[{"field_id":"turn-count","value":1,` +
		`"visibility":{"label":"PUBLIC","authorized_seat_ids":["seat-a","seat-b"]}}]}}`
}

func probeErrorResponse(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,` + probeIdentity + `,` +
		`"error":{"code":-32000,"message":"advance-turn action request from seat-a was rejected (AIPT_ACTION_REJECTED)",` +
		`"data":{"error_code":"AIPT_ACTION_REJECTED"}}}`
}

func probeNotification() string {
	return `{"jsonrpc":"2.0","method":"aipt.protocol.event","params":{"event":{` +
		`"protocol_version":"1.0.0","schema_version":"1.0.0","fixture_id":"minimal-v1-arithmetic",` +
		`"event_id":"event-turn-increment-0001","transition_id":"transition-turn-increment",` +
		`"event_type":"state_transition_applied","payload":{"from_state_id":"initial","to_state_id":"final"}}},` +
		probeIdentity + `}`
}

func TestDecodeRequestValidProbe(t *testing.T) {
	req, err := protocol.DecodeRequest([]byte(probeRequest(`"probe-1"`)))
	wantNoReason(t, err)
	if req.Method != protocol.MethodRequest || req.JSONRPC != protocol.JSONRPCVersion {
		t.Fatalf("request envelope decoded wrong: %+v", req)
	}
	if req.ID.Kind() != protocol.IDString || req.ID.String() != "probe-1" {
		t.Fatalf("request id drifted: %+v", req.ID)
	}
	if req.Params.Action != "advance-turn" || req.Params.SeatID != "seat-a" {
		t.Fatalf("request params drifted: %+v", req.Params)
	}
	if string(req.Params.Proposal) != `{"delta":1}` {
		t.Fatalf("request proposal raw value drifted: %s", req.Params.Proposal)
	}
}

func TestDecodeResponseValidResultProbe(t *testing.T) {
	resp, err := protocol.DecodeResponse([]byte(probeResultResponse(`42`)))
	wantNoReason(t, err)
	if resp.Result == nil || resp.Error != nil {
		t.Fatalf("result response must carry exactly result: %+v", resp)
	}
	if !resp.Result.Accepted || resp.Result.TransitionID != "transition-turn-increment" {
		t.Fatalf("result drifted: %+v", resp.Result)
	}
	if len(resp.Result.AppliedFields) != 1 || resp.Result.AppliedFields[0].FieldID != "turn-count" {
		t.Fatalf("applied_fields drifted: %+v", resp.Result.AppliedFields)
	}
	if resp.ID.Kind() != protocol.IDNumber {
		t.Fatalf("number id type not preserved: %+v", resp.ID)
	}
}

func TestDecodeResponseValidErrorProbe(t *testing.T) {
	resp, err := protocol.DecodeResponse([]byte(probeErrorResponse(`"probe-1"`)))
	wantNoReason(t, err)
	if resp.Error == nil || resp.Result != nil {
		t.Fatalf("error response must carry exactly error: %+v", resp)
	}
	if resp.Error.Code != -32000 || resp.Error.Data == nil ||
		resp.Error.Data.ErrorCode != "AIPT_ACTION_REJECTED" {
		t.Fatalf("error object drifted: %+v", resp.Error)
	}
}

func TestDecodeNotificationValidProbe(t *testing.T) {
	notif, err := protocol.DecodeNotification([]byte(probeNotification()))
	wantNoReason(t, err)
	if notif.Method != protocol.MethodNotification || notif.Params.Event == nil {
		t.Fatalf("notification drifted: %+v", notif)
	}
	if notif.Params.Event.EventID != "event-turn-increment-0001" {
		t.Fatalf("notification event drifted: %+v", notif.Params.Event)
	}
	if notif.Params.Event.Payload.FromStateID != "initial" || notif.Params.Event.Payload.ToStateID != "final" {
		t.Fatalf("notification event payload drifted: %+v", notif.Params.Event.Payload)
	}
}

func TestDecodeEnvelopeDiscriminatesAllThreeKinds(t *testing.T) {
	env, err := protocol.DecodeEnvelope([]byte(probeRequest(`"r"`)))
	wantNoReason(t, err)
	if env.Kind != protocol.EnvelopeRequest || env.Request == nil {
		t.Fatalf("request root discriminated wrong: %+v", env)
	}
	env, err = protocol.DecodeEnvelope([]byte(probeResultResponse(`"r"`)))
	wantNoReason(t, err)
	if env.Kind != protocol.EnvelopeResponse || env.Response == nil {
		t.Fatalf("response root discriminated wrong: %+v", env)
	}
	env, err = protocol.DecodeEnvelope([]byte(probeNotification()))
	wantNoReason(t, err)
	if env.Kind != protocol.EnvelopeNotification || env.Notification == nil {
		t.Fatalf("notification root discriminated wrong: %+v", env)
	}
}

func TestDecodeRequestRejectsMalformedJSONRPC(t *testing.T) {
	doc := probeRequest(`"r"`)
	doc = replaceMember(t, doc, `"jsonrpc":"2.0"`, `"jsonrpc":"1.0"`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONRPCVersionInvalid)
}

func TestDecodeRequestRejectsUnknownProtocolVersion(t *testing.T) {
	doc := replaceMember(t, probeRequest(`"r"`), `"protocol_version":"1.0.0"`, `"protocol_version":"9.9.9"`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonProtocolVersionInvalid)
}

func TestDecodeRequestRejectsUnknownSchemaVersion(t *testing.T) {
	doc := replaceMember(t, probeRequest(`"r"`), `"schema_version":"1.0.0"`, `"schema_version":"9.9.9"`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonSchemaVersionInvalid)
}

func TestDecodeRequestRejectsMissingParams(t *testing.T) {
	doc := probeRequest(`"r"`)
	doc = removeMember(t, doc, `"params":{"action":"advance-turn","seat_id":"seat-a","proposal":{"delta":1}}`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONMissingMember)
}

func TestDecodeRequestRejectsNullParams(t *testing.T) {
	doc := probeRequest(`"r"`)
	doc = replaceMember(t, doc, `"params":{"action":"advance-turn","seat_id":"seat-a","proposal":{"delta":1}}`, `"params":null`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONNullMember)
}

func TestDecodeRequestRejectsUnknownMethod(t *testing.T) {
	doc := replaceMember(t, probeRequest(`"r"`), `"method":"aipt.protocol.applyAction"`, `"method":"aipt.protocol.workerLifecycle"`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonMethodInvalid)
}

func TestDecodeNotificationRejectsUnknownMethod(t *testing.T) {
	doc := replaceMember(t, probeNotification(), `"method":"aipt.protocol.event"`, `"method":"aipt.protocol.workerLifecycle"`)
	wantReason(t, decodeNotificationErr(doc), protocol.ReasonMethodInvalid)
}

func TestDecodeResponseRejectsResultAndErrorTogether(t *testing.T) {
	doc := insertMember(t, probeResultResponse(`"r"`), `,"error":{"code":-32603,"message":"internal error"}`)
	wantReason(t, decodeResponseErr(doc), protocol.ReasonResponseResultErrorBoth)
}

func TestDecodeResponseRejectsNeitherResultNorError(t *testing.T) {
	doc := `{"jsonrpc":"2.0","id":"r",` + probeIdentity + `}`
	wantReason(t, decodeResponseErr(doc), protocol.ReasonResponseResultErrorNeither)
}

func TestDecodeResponseRejectsNullResult(t *testing.T) {
	doc := `{"jsonrpc":"2.0","id":"r",` + probeIdentity + `,"result":null}`
	wantReason(t, decodeResponseErr(doc), protocol.ReasonJSONNullMember)
}

func TestDecodeEnvelopeRejectsArbitraryRootObject(t *testing.T) {
	wantReason(t, decodeEnvelopeErr(`{"hello":"world","jsonrpc":"2.0"}`), protocol.ReasonEnvelopeUnknownRoot)
	wantReason(t, decodeEnvelopeErr(`{"jsonrpc":"2.0"}`), protocol.ReasonEnvelopeUnknownRoot)
	wantReason(t, decodeEnvelopeErr(`{}`), protocol.ReasonEnvelopeUnknownRoot)
}

func TestDecodeEnvelopeRejectsNonObjectRoot(t *testing.T) {
	wantReason(t, decodeEnvelopeErr(`[1,2,3]`), protocol.ReasonEnvelopeUnknownRoot)
	wantReason(t, decodeEnvelopeErr(`"just a string"`), protocol.ReasonEnvelopeUnknownRoot)
}

func TestDecodeEnvelopeRejectsUnknownMethodRoot(t *testing.T) {
	wantReason(t, decodeEnvelopeErr(`{"jsonrpc":"2.0","method":"nope","id":1,"params":{},`+probeIdentity+`}`),
		protocol.ReasonMethodInvalid)
}

func TestDecodeRequestRejectsUnknownField(t *testing.T) {
	doc := insertMember(t, probeRequest(`"r"`), `,"extra":true`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONUnknownMember)
}

func TestDecodeRequestRejectsUnknownNestedField(t *testing.T) {
	doc := replaceMember(t, probeRequest(`"r"`), `"proposal":{"delta":1}`, `"proposal":{"delta":1},"sneaky":1`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONUnknownMember)
}

func TestDecodeRequestRejectsDuplicateTopLevelKey(t *testing.T) {
	doc := insertMember(t, probeRequest(`"r"`), `,"jsonrpc":"2.0"`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONDuplicateKey)
}

func TestDecodeRequestRejectsDuplicateNestedKey(t *testing.T) {
	doc := replaceMember(t, probeRequest(`"r"`), `"proposal":{"delta":1}`, `"proposal":{"delta":1,"delta":2}`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonJSONDuplicateKey)
}

func TestDecodeRequestRejectsTrailingJSON(t *testing.T) {
	wantReason(t, decodeRequestErr(probeRequest(`"r"`)+` {}`), protocol.ReasonJSONTrailing)
	wantReason(t, decodeRequestErr(probeRequest(`"r"`)+` 42`), protocol.ReasonJSONTrailing)
}

func TestDecodeRequestRejectsEmptyAndMalformed(t *testing.T) {
	wantReason(t, decodeRequestErr(``), protocol.ReasonJSONMalformed)
	wantReason(t, decodeRequestErr(`{"jsonrpc":"2.0",`), protocol.ReasonJSONMalformed)
}

func TestDecodeRequestRejectsInvalidIDs(t *testing.T) {
	for _, id := range []string{`null`, `true`, `[1]`, `{}`, `1.5`, `9007199254740992`, `-0`, `""`} {
		doc := probeRequest(id)
		_, err := protocol.DecodeRequest([]byte(doc))
		if err == nil {
			t.Fatalf("request with id %s must be rejected", id)
		}
	}
}

func TestDecodeResponseRejectsInvalidErrorCodes(t *testing.T) {
	for _, code := range []string{`9007199254740992`, `1.5`, `null`, `true`} {
		doc := replaceMember(t, probeErrorResponse(`"r"`), `"code":-32000`, `"code":`+code)
		_, err := protocol.DecodeResponse([]byte(doc))
		if err == nil {
			t.Fatalf("response with error code %s must be rejected", code)
		}
	}
}

func TestDecodeResponseRejectsInvalidErrorData(t *testing.T) {
	// Unknown member inside error data.
	doc := replaceMember(t, probeErrorResponse(`"r"`), `"data":{"error_code":"AIPT_ACTION_REJECTED"}`,
		`"data":{"error_code":"AIPT_ACTION_REJECTED","extra":1}`)
	wantReason(t, decodeResponseErr(doc), protocol.ReasonJSONUnknownMember)
	// error_code failing the frozen pattern.
	doc = replaceMember(t, probeErrorResponse(`"r"`), `"error_code":"AIPT_ACTION_REJECTED"`, `"error_code":"not-an-aipt-code"`)
	wantReason(t, decodeResponseErr(doc), protocol.ReasonErrorDataInvalid)
	// null data.
	doc = replaceMember(t, probeErrorResponse(`"r"`), `"data":{"error_code":"AIPT_ACTION_REJECTED"}`, `"data":null`)
	wantReason(t, decodeResponseErr(doc), protocol.ReasonJSONNullMember)
	// missing error message.
	doc = removeMember(t, probeErrorResponse(`"r"`),
		`"message":"advance-turn action request from seat-a was rejected (AIPT_ACTION_REJECTED)"`)
	wantReason(t, decodeResponseErr(doc), protocol.ReasonJSONMissingMember)
}

func TestDecodeResponseRejectsUnsafeErrorCode(t *testing.T) {
	doc := replaceMember(t, probeErrorResponse(`"r"`), `"code":-32000`, `"code":9007199254740993`)
	wantReason(t, decodeResponseErr(doc), protocol.ReasonJSONUnsafeInteger)
}

func TestDecodeRequestRejectsInvalidFixtureID(t *testing.T) {
	doc := replaceMember(t, probeRequest(`"r"`), `"fixture_id":"minimal-v1-arithmetic"`, `"fixture_id":"Not A Valid Id!"`)
	wantReason(t, decodeRequestErr(doc), protocol.ReasonFixtureIDInvalid)
}

func TestDecodeNotificationRejectsIDMember(t *testing.T) {
	doc := insertMember(t, probeNotification(), `,"id":7`)
	wantReason(t, decodeNotificationErr(doc), protocol.ReasonJSONUnknownMember)
}

func TestDecodeResponseRejectsInvalidIDType(t *testing.T) {
	doc := probeResultResponse(`null`)
	_, err := protocol.DecodeResponse([]byte(doc))
	if err == nil {
		t.Fatal("response with null id must be rejected")
	}
}

// --- tiny deterministic document editors (string surgery on probe docs) ---

func replaceMember(t *testing.T, doc, old, new string) string {
	t.Helper()
	out := replaceOnce(doc, old, new)
	if out == doc {
		t.Fatalf("replaceMember: %q not found in probe document", old)
	}
	return out
}

func removeMember(t *testing.T, doc, member string) string {
	t.Helper()
	out := replaceOnce(doc, ","+member, "")
	if out == doc {
		t.Fatalf("removeMember: %q not found in probe document", member)
	}
	return out
}

func insertMember(t *testing.T, doc, member string) string {
	t.Helper()
	return doc[:len(doc)-1] + member + "}"
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func decodeRequestErr(doc string) error {
	_, err := protocol.DecodeRequest([]byte(doc))
	return err
}

func decodeResponseErr(doc string) error {
	_, err := protocol.DecodeResponse([]byte(doc))
	return err
}

func decodeNotificationErr(doc string) error {
	_, err := protocol.DecodeNotification([]byte(doc))
	return err
}

func decodeEnvelopeErr(doc string) error {
	_, err := protocol.DecodeEnvelope([]byte(doc))
	return err
}
