package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStructuredActionControlsStateAndCommitsOnce(t *testing.T) {
	runID := "run-protocol-valid"
	seatID := SeatPlayer1
	clock := newFakeClock()
	action := actionProposal(runID, seatID, "action-1", 1)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{
		response: responseBytes(t, "invoke-1", runID, seatID, "session-"+runID+"-PLAYER_1", "I increment.", &action),
	}}}
	submitter := &recordingSubmitter{}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, submitter)
	result, err := engine.InvokeSeat(context.Background(), seatID, "invoke-1", input)
	if err != nil {
		t.Fatalf("InvokeSeat: %v", err)
	}
	if result.Receipt == nil || result.Receipt.ActionID != "action-1" || submitter.count() != 1 {
		t.Fatalf("turn = %+v, submissions=%d", result, submitter.count())
	}
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-1", input); !errors.Is(err, Sentinel(CodeDuplicateAction)) {
		t.Fatalf("duplicate invocation accepted: %v", err)
	}
	if submitter.count() != 1 {
		t.Fatalf("duplicate invocation resubmitted action: %d", submitter.count())
	}
	for _, event := range engine.Events() {
		if event.Type == EventActionAccepted && event.ActionID == "action-1" {
			return
		}
	}
	t.Fatal("ACTION_ACCEPTED event missing")
}

func TestSemanticRepairUsesSameAuthorizedContextAndFirstValidResponse(t *testing.T) {
	runID := "run-semantic-repair"
	seatID := SeatPlayer1
	clock := newFakeClock()
	valid := responseBytes(t, "invoke-repair", runID, seatID, "session-"+runID+"-PLAYER_1", "valid speech", nil)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{
		{response: []byte(`{"schema":"aipt.agent-response/v1","unknown":true}`)},
		{response: valid},
		{response: []byte(`{"should":"never be selected"}`)},
	}}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, &recordingSubmitter{})
	result, err := engine.InvokeSeat(context.Background(), seatID, "invoke-repair", input)
	if err != nil || result.Response.Speech != "valid speech" {
		t.Fatalf("InvokeSeat = %+v, %v", result, err)
	}
	requests := invoker.capturedRequests()
	if len(requests) != 2 {
		t.Fatalf("attempts = %d; best-of-N or missing repair", len(requests))
	}
	if requests[0].Kind != InvocationOriginal || requests[1].Kind != InvocationRepair ||
		requests[0].Context.ContextHash != requests[1].Context.ContextHash ||
		requests[0].Context.AuthorizedProjectionHash != requests[1].Context.AuthorizedProjectionHash {
		t.Fatalf("repair context widened or retry class drifted: %+v", requests)
	}
	if strings.Contains(requests[1].FailureCode.String(), "Ignore previous instructions") {
		t.Fatal("repair metadata copied untrusted payload")
	}
}

func TestAgentCannotMutateAuthorizedContextAcrossRepairBoundary(t *testing.T) {
	runID := "run-context-mutation"
	seatID := SeatPlayer1
	clock := newFakeClock()
	valid := responseBytes(t, "invoke-context-mutation", runID, seatID, "session-"+runID+"-PLAYER_1", "speech", nil)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{
		response: valid,
		mutateRequest: func(request *InvocationRequest) {
			request.Context.Trusted.AvailableTools[0].ToolID = "tool-injected"
		},
	}}}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, &recordingSubmitter{})
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-context-mutation", input); !errors.Is(err, Sentinel(CodeContextInvariantFailed)) {
		t.Fatalf("Agent-mutated context accepted: %v", err)
	}
	phase, _ := engine.Floor().State()
	if phase != PhaseTerminated {
		t.Fatalf("context mutation did not terminate orchestration: %s", phase)
	}
}

func (c Code) String() string { return string(c) }

func TestSpeechActionConflictRepairAndExhaustion(t *testing.T) {
	runID := "run-speech-conflict"
	seatID := SeatPlayer1
	clock := newFakeClock()
	action := actionProposal(runID, seatID, "action-conflict", 1)
	conflict := AgentResponse{
		Schema: AgentResponseSchema, InvocationID: "invoke-conflict", RunID: runID, SeatID: seatID,
		SessionID: "session-" + runID + "-PLAYER_1", Speech: "I do something else.", Action: &action,
		Metadata: ProtocolMetadata{ProtocolVersion: "v1", SpeechActionClaim: &SpeechActionClaim{ActionID: "different", ActionType: action.ActionType}},
	}
	conflictRaw, _ := json.Marshal(conflict)
	validRaw := responseBytes(t, "invoke-conflict", runID, seatID, conflict.SessionID, "I increment.", &action)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{response: conflictRaw}, {response: validRaw}}}
	submitter := &recordingSubmitter{}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, submitter)
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-conflict", input); err != nil {
		t.Fatalf("conflict repair: %v", err)
	}
	if submitter.count() != 1 {
		t.Fatalf("conflicting response affected state: submissions=%d", submitter.count())
	}

	policy := fixturePolicy()
	policy.SemanticRepairBudget = 0
	clock2 := newFakeClock()
	invoker2 := &scriptedInvoker{clock: clock2, steps: []invokeStep{{response: conflictRaw}}}
	engine2, input2 := fixtureEngine(t, runID+"-exhaust", seatID, policy, invoker2, &recordingSubmitter{})
	// Rebind the raw response to the second Run so only the claim conflict is invalid.
	secondAction := actionProposal(runID+"-exhaust", seatID, "action-conflict-2", 1)
	secondConflict := conflict
	secondConflict.RunID = runID + "-exhaust"
	secondConflict.InvocationID = "invoke-exhaust"
	secondConflict.SessionID = "session-" + secondConflict.RunID + "-PLAYER_1"
	secondConflict.Action = &secondAction
	secondConflict.Metadata.SpeechActionClaim = &SpeechActionClaim{ActionID: "different", ActionType: secondAction.ActionType}
	invoker2.steps[0].response, _ = json.Marshal(secondConflict)
	if _, err := engine2.InvokeSeat(context.Background(), seatID, "invoke-exhaust", input2); !errors.Is(err, Sentinel(CodeAgentProtocolFailed)) {
		t.Fatalf("repair exhaustion result = %v", err)
	}
	phase, _ := engine2.Floor().State()
	if phase != PhaseTerminated {
		t.Fatalf("exhausted Run phase = %s", phase)
	}
}

func TestTransportRetryClassificationTimeoutAndNoDoubleCommit(t *testing.T) {
	runID := "run-transport"
	seatID := SeatPlayer1
	clock := newFakeClock()
	action := actionProposal(runID, seatID, "action-transport", 1)
	valid := responseBytes(t, "invoke-transport", runID, seatID, "session-"+runID+"-PLAYER_1", "commit", &action)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{
		{err: NewInvocationFailure(CodeAgentTransportFailed)}, {response: valid},
	}}
	submitter := &recordingSubmitter{}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, submitter)
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-transport", input); err != nil {
		t.Fatalf("transport retry: %v", err)
	}
	if submitter.count() != 1 {
		t.Fatalf("transport retry submissions=%d", submitter.count())
	}
	requests := invoker.capturedRequests()
	if len(requests) != 2 || requests[0].Kind != InvocationOriginal || requests[1].Kind != InvocationOriginal {
		t.Fatalf("transport classified as semantic: %+v", requests)
	}

	clock2 := newFakeClock()
	timeoutRun := "run-timeout"
	timeoutValid := responseBytes(t, "invoke-timeout", timeoutRun, seatID, "session-"+timeoutRun+"-PLAYER_1", "on time", nil)
	invoker2 := &scriptedInvoker{clock: clock2, steps: []invokeStep{
		{response: timeoutValid, advance: 2 * time.Second}, {response: timeoutValid},
	}}
	engine2, input2 := fixtureEngine(t, timeoutRun, seatID, fixturePolicy(), invoker2, &recordingSubmitter{})
	if _, err := engine2.InvokeSeat(context.Background(), seatID, "invoke-timeout", input2); err != nil {
		t.Fatalf("injected timeout retry: %v", err)
	}
	seenTimeout := false
	for _, event := range engine2.Events() {
		if event.Type == EventInvocationTimeout {
			seenTimeout = true
		}
	}
	if !seenTimeout {
		t.Fatal("timeout outcome not audited")
	}
}

func TestStaleInvocationResultIsNeverReused(t *testing.T) {
	runID := "run-stale-result"
	seatID := SeatPlayer1
	clock := newFakeClock()
	valid := responseBytes(t, "invoke-stale-result", runID, seatID,
		"session-"+runID+"-PLAYER_1", "stale response", nil)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{
		response: valid, completedAt: clock.Now().Add(-time.Second),
	}}}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, &recordingSubmitter{})
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-stale-result", input); !errors.Is(err, Sentinel(CodeRetryClassInvalid)) {
		t.Fatalf("stale invocation result accepted: %v", err)
	}
	phase, _ := engine.Floor().State()
	if phase != PhaseTerminated {
		t.Fatalf("stale invocation did not terminate orchestration: %s", phase)
	}
}

func TestRetryMisclassificationAndUnrecordedFailureRejected(t *testing.T) {
	probes := []struct {
		name string
		err  error
	}{
		{"untyped", errors.New("network-looking but unclassified")},
		{"semantic-labelled-by-provider", NewInvocationFailure(CodeInvalidAgentResponse)},
		{"repair-labelled-as-transport", NewInvocationFailure(CodeRepairBudgetExhausted)},
	}
	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			runID := "run-retry-class-" + probe.name
			clock := newFakeClock()
			invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{err: probe.err}}}
			engine, input := fixtureEngine(t, runID, SeatPlayer1, fixturePolicy(), invoker, &recordingSubmitter{})
			if _, err := engine.InvokeSeat(context.Background(), SeatPlayer1, "invoke-class", input); !errors.Is(err, Sentinel(CodeRetryClassInvalid)) {
				t.Fatalf("misclassification accepted: %v", err)
			}
		})
	}
}

func TestSessionRecoverySuccessAndBindingFailures(t *testing.T) {
	runID := "run-recovery"
	seatID := SeatPlayer1
	oldID := "session-" + runID + "-PLAYER_1"
	newSession := Session{
		Schema: SessionSchema, SessionID: "session-recovered-p1", RunID: runID, SeatID: seatID,
		Generation: 2, ParentSessionID: oldID,
	}
	clock := newFakeClock()
	valid := responseBytes(t, "invoke-recovery", runID, seatID, newSession.SessionID, "recovered", nil)
	invoker := &scriptedInvoker{
		clock:      clock,
		steps:      []invokeStep{{err: NewInvocationFailure(CodeAgentSessionFailed)}, {response: valid}},
		recoveries: []recoveryStep{{session: newSession}},
	}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, &recordingSubmitter{})
	result, err := engine.InvokeSeat(context.Background(), seatID, "invoke-recovery", input)
	if err != nil {
		t.Fatalf("Session recovery: %v", err)
	}
	if result.Context.SessionID != newSession.SessionID || ValidateContextHash(result.Context) != nil {
		t.Fatalf("recovered context = %+v", result.Context)
	}
	requests := invoker.capturedRequests()
	if len(requests) != 2 || requests[0].SessionID != oldID || requests[1].SessionID != newSession.SessionID {
		t.Fatalf("Session transition requests = %+v", requests)
	}
	seenRecovery := false
	for _, event := range engine.Events() {
		if event.Type != EventSessionRecovery {
			continue
		}
		seenRecovery = true
		if event.Outcome != string(CodeAgentSessionFailed) || event.AttemptClass != AttemptSessionRecovery ||
			event.OldSessionID != oldID || event.NewSessionID != newSession.SessionID {
			t.Fatalf("Session recovery audit event = %+v", event)
		}
	}
	if !seenRecovery {
		t.Fatal("SESSION_RECOVERY event missing")
	}

	for _, probe := range []struct {
		name   string
		mutate func(*Session)
	}{
		{"wrong-run", func(session *Session) { session.RunID = "run-other" }},
		{"wrong-seat", func(session *Session) { session.SeatID = SeatPlayer2 }},
		{"alias-old", func(session *Session) { session.SessionID = session.ParentSessionID }},
		{"bad-generation", func(session *Session) { session.Generation = 4 }},
	} {
		t.Run(probe.name, func(t *testing.T) {
			probeRun := "run-recovery-" + probe.name
			probeOld := "session-" + probeRun + "-PLAYER_1"
			next := Session{Schema: SessionSchema, SessionID: "next-" + probe.name, RunID: probeRun, SeatID: seatID, Generation: 2, ParentSessionID: probeOld}
			probe.mutate(&next)
			probeClock := newFakeClock()
			probeInvoker := &scriptedInvoker{
				clock: probeClock, steps: []invokeStep{{err: NewInvocationFailure(CodeAgentSessionFailed)}},
				recoveries: []recoveryStep{{session: next}},
			}
			probeEngine, probeInput := fixtureEngine(t, probeRun, seatID, fixturePolicy(), probeInvoker, &recordingSubmitter{})
			if _, err := probeEngine.InvokeSeat(context.Background(), seatID, "invoke-invalid-recovery", probeInput); !errors.Is(err, Sentinel(CodeSessionRecoveryFailed)) {
				t.Fatalf("invalid recovery accepted: %v", err)
			}
		})
	}
}

func TestSessionRecoveryBudgetExhausted(t *testing.T) {
	runID := "run-recovery-exhaust"
	seatID := SeatPlayer1
	oldID := "session-" + runID + "-PLAYER_1"
	newSession := Session{Schema: SessionSchema, SessionID: "session-recovery-once", RunID: runID, SeatID: seatID, Generation: 2, ParentSessionID: oldID}
	clock := newFakeClock()
	invoker := &scriptedInvoker{
		clock:      clock,
		steps:      []invokeStep{{err: NewInvocationFailure(CodeAgentSessionFailed)}, {err: NewInvocationFailure(CodeAgentSessionFailed)}},
		recoveries: []recoveryStep{{session: newSession}},
	}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, &recordingSubmitter{})
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-recovery-exhaust", input); !errors.Is(err, Sentinel(CodeSessionRecoveryFailed)) {
		t.Fatalf("recovery exhaustion = %v", err)
	}
	phase, _ := engine.Floor().State()
	if phase != PhaseTerminated {
		t.Fatalf("unrecoverable Run phase=%s", phase)
	}
}

func TestStrictAgentResponseNegativeMatrix(t *testing.T) {
	runID := "run-decode"
	seatID := SeatPlayer1
	sessionID := "session-run-decode-PLAYER_1"
	action := actionProposal(runID, seatID, "action-decode", 1)
	valid := responseBytes(t, "invoke-decode", runID, seatID, sessionID, "speech", &action)
	var validObject map[string]any
	_ = json.Unmarshal(valid, &validObject)
	probes := []struct {
		name string
		raw  []byte
	}{
		{"malformed", []byte(`{"schema":`)},
		{"unknown-version", mutateJSON(t, validObject, func(value map[string]any) { value["schema"] = "aipt.agent-response/v2" })},
		{"unknown-field", mutateJSON(t, validObject, func(value map[string]any) { value["extra"] = true })},
		{"wrong-run", mutateJSON(t, validObject, func(value map[string]any) { value["run_id"] = "other" })},
		{"wrong-seat", mutateJSON(t, validObject, func(value map[string]any) { value["seat_id"] = "PLAYER_2" })},
		{"wrong-session", mutateJSON(t, validObject, func(value map[string]any) { value["session_id"] = "other" })},
		{"speech-action-conflict", mutateJSON(t, validObject, func(value map[string]any) {
			value["metadata"].(map[string]any)["speech_action_claim"].(map[string]any)["action_id"] = "other"
		})},
		{"trailing", append(append([]byte(nil), valid...), []byte(` {}`)...)},
	}
	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			if _, err := decodeAgentResponse(probe.raw, "invoke-decode", runID, seatID, sessionID); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	if response, err := decodeAgentResponse(valid, "invoke-decode", runID, seatID, sessionID); err != nil || !reflect.DeepEqual(response.Action, &action) {
		t.Fatalf("valid response rejected: %+v, %v", response, err)
	}
}

func mutateJSON(t *testing.T, original map[string]any, mutate func(map[string]any)) []byte {
	t.Helper()
	raw, _ := json.Marshal(original)
	var copy map[string]any
	_ = json.Unmarshal(raw, &copy)
	mutate(copy)
	result, err := json.Marshal(copy)
	if err != nil {
		t.Fatalf("mutate JSON: %v", err)
	}
	return result
}
