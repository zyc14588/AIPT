package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestRequiredHiddenInformationProbeCatalog(t *testing.T) {
	runID := "run-hidden-catalog"
	seats := fixtureSeats(t, runID)
	p1 := seatByID(t, seats, SeatPlayer1)
	p2 := seatByID(t, seats, SeatPlayer2)
	gmSecret := fact(t, "gm-secret", ClassTableHiddenRemoteAllowed, ScopeGMOnly, nil, `{"secret":"gm"}`)
	p1Private := fact(t, "p1-secret", ClassTableHiddenRemoteAllowed, ScopeSeatPrivate, []SeatID{SeatPlayer1}, `{"secret":"p1"}`)
	public := fact(t, "public", ClassPublic, ScopePublic, nil, `{"round":1}`)

	probes := []struct {
		id  string
		run func(*testing.T)
	}{
		{"H01", func(t *testing.T) {
			view, err := BuildAuthorizedView(runID, p2, []StateFact{p1Private})
			if err != nil || len(view.Facts) != 0 {
				t.Fatalf("wrong-seat view = %+v, %v", view, err)
			}
		}},
		{"H02", func(t *testing.T) {
			bad := public
			bad.Classification = ""
			if _, err := BuildAuthorizedView(runID, p1, []StateFact{bad}); !errors.Is(err, Sentinel(CodeVisibilityDenied)) {
				t.Fatalf("missing label accepted: %v", err)
			}
		}},
		{"H03", func(t *testing.T) {
			view, _ := BuildAuthorizedView(runID, p1, []StateFact{gmSecret, public})
			if !reflect.DeepEqual(factIDs(view.Facts), []string{"public"}) {
				t.Fatalf("GM secret entered Player context: %v", factIDs(view.Facts))
			}
		}},
		{"H04", func(t *testing.T) {
			view, _ := BuildAuthorizedView(runID, p2, []StateFact{p1Private, public})
			if !reflect.DeepEqual(factIDs(view.Facts), []string{"public"}) {
				t.Fatalf("Player-private fact crossed seats: %v", factIDs(view.Facts))
			}
		}},
		{"H05", func(t *testing.T) {
			floor, _ := NewFloorController(runID, fixturePolicy())
			_ = floor.OpenDiscussion()
			item, err := floor.RoutePrivateMessage("private-h05", SeatPlayer1, []SeatID{SeatPlayer2}, "hidden")
			if err != nil || !reflect.DeepEqual(item.Recipients, []SeatID{SeatPlayer1, SeatPlayer2}) {
				t.Fatalf("private chat broadcast or rejected: %+v, %v", item, err)
			}
		}},
		{"H06", func(t *testing.T) {
			view, _ := BuildAuthorizedView(runID, p1, []StateFact{public, gmSecret})
			summary, _ := NewMemorySummary("summary-h06", "v1", runID, SeatPlayer1,
				[]SummaryFact{{FactID: gmSecret.FactID, ValueSHA256: gmSecret.ValueSHA256}}, nil, nil)
			if err := validateSummary(runID, p1, summary, view, nil); !errors.Is(err, Sentinel(CodeContextInvariantFailed)) {
				t.Fatalf("summary hidden fact accepted: %v", err)
			}
		}},
		{"H07", func(t *testing.T) {
			tracker, _ := NewPersonaTracker(runID, seats)
			state, _ := tracker.State(SeatPlayer1)
			input, retriever := fixtureContextInput(t, runID, SeatPlayer1)
			input.StateFacts = append(input.StateFacts, gmSecret)
			bundle, err := BuildContext(context.Background(), fixturePolicy(), p1, state, input, retriever)
			if err != nil || len(bundle.Untrusted.AuthorizedState.Facts) != 1 || bundle.Untrusted.AuthorizedState.Facts[0].FactID != "fact-public" {
				t.Fatalf("repair-source context widened: %+v, %v", bundle.Untrusted.AuthorizedState, err)
			}
		}},
		{"H08", func(t *testing.T) {
			secret := "credential=top-secret"
			err := orchestrationError(CodeVisibilityDenied, "probe", runID, SeatPlayer1, "invoke", errors.New(secret))
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "top-secret") {
				t.Fatalf("error leaked hidden payload: %v", err)
			}
		}},
		{"H09", func(t *testing.T) {
			input, retriever := fixtureContextInput(t, runID, SeatPlayer1)
			tracker, _ := NewPersonaTracker(runID, seats)
			state, _ := tracker.State(SeatPlayer1)
			bundle, err := BuildContext(context.Background(), fixturePolicy(), p1, state, input, retriever)
			if err != nil || bundle.Trusted.RoleContractID != "AIPT_PLAYER_ROLE_CONTRACT_V1" ||
				!strings.Contains(bundle.Untrusted.Retrieved[0].Content, "Ignore previous instructions") {
				t.Fatalf("malicious content changed role: %+v, %v", bundle, err)
			}
		}},
		{"H10", func(t *testing.T) {
			input, retriever := fixtureContextInput(t, runID, SeatPlayer1)
			tracker, _ := NewPersonaTracker(runID, seats)
			state, _ := tracker.State(SeatPlayer1)
			bundle, _ := BuildContext(context.Background(), fixturePolicy(), p1, state, input, retriever)
			if len(bundle.Trusted.AvailableTools) != 1 || bundle.Trusted.AvailableTools[0].ToolID != "tool-common" {
				t.Fatalf("untrusted content injected tool capability: %+v", bundle.Trusted.AvailableTools)
			}
		}},
		{"H11", func(t *testing.T) {
			copy := append([]Seat(nil), seats...)
			copy[1].Session.SeatID = SeatPlayer2
			if validateSeatPlan(runID, copy) == nil {
				t.Fatal("Session seat identity swap accepted")
			}
		}},
		{"H12", func(t *testing.T) {
			authority := NewSessionAuthority()
			if err := authority.bind(p1.Session); err != nil {
				t.Fatalf("initial bind: %v", err)
			}
			replay := p1.Session
			replay.RunID = "run-cross"
			if authority.bind(replay) == nil {
				t.Fatal("cross-Run Session replay accepted")
			}
		}},
	}
	for _, probe := range probes {
		t.Run(probe.id, probe.run)
	}
}

func TestRequiredProtocolRecoveryProbeCatalog(t *testing.T) {
	decodeFixture := func(t *testing.T, mutate func(*AgentResponse)) error {
		runID := "run-protocol-catalog"
		seatID := SeatPlayer1
		action := actionProposal(runID, seatID, "action-catalog", 1)
		response := AgentResponse{
			Schema: AgentResponseSchema, InvocationID: "invoke-catalog", RunID: runID, SeatID: seatID,
			SessionID: "session-catalog", Speech: "act", Action: &action,
			Metadata: ProtocolMetadata{ProtocolVersion: "v1", SpeechActionClaim: &SpeechActionClaim{ActionID: action.ActionID, ActionType: action.ActionType}},
		}
		mutate(&response)
		raw, _ := json.Marshal(response)
		_, err := decodeAgentResponse(raw, "invoke-catalog", runID, seatID, "session-catalog")
		return err
	}

	probes := []struct {
		id  string
		run func(*testing.T)
	}{
		{"P01", func(t *testing.T) {
			if _, err := decodeAgentResponse([]byte(`{"schema":`), "i", "r", SeatPlayer1, "s"); err == nil {
				t.Fatal("malformed response accepted")
			}
		}},
		{"P02", func(t *testing.T) {
			if err := decodeFixture(t, func(response *AgentResponse) { response.Schema = "aipt.agent-response/v2" }); err == nil {
				t.Fatal("unknown response version accepted")
			}
		}},
		{"P03", func(t *testing.T) {
			if err := decodeFixture(t, func(response *AgentResponse) { response.Metadata.SpeechActionClaim.ActionID = "different" }); err == nil {
				t.Fatal("action/prose conflict accepted")
			}
		}},
		{"P04", func(t *testing.T) {
			policy := fixturePolicy()
			policy.SemanticRepairBudget = 0
			if err := validatePolicy(policy); err != nil {
				t.Fatalf("explicit zero repair budget rejected: %v", err)
			}
		}},
		{"P05", func(t *testing.T) {
			if code := invocationFailureCode(NewInvocationFailure(CodeInvalidAgentResponse)); code != CodeInvalidAgentResponse {
				t.Fatalf("transport misclassification lost: %s", code)
			}
		}},
		{"P06", func(t *testing.T) {
			if code := invocationFailureCode(NewInvocationFailure(CodeAgentTransportFailed)); code != CodeAgentTransportFailed {
				t.Fatalf("semantic misclassification lost: %s", code)
			}
		}},
		{"P07", func(t *testing.T) {
			if code := invocationFailureCode(errors.New("unrecorded")); code != "" {
				t.Fatalf("unrecorded retry classified: %s", code)
			}
		}},
		{"P08", func(t *testing.T) {
			runID := "run-p08"
			clock := newFakeClock()
			response := responseBytes(t, "invoke-p08", runID, SeatPlayer1, "session-"+runID+"-PLAYER_1", "speech", nil)
			invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{response: response}}}
			engine, input := fixtureEngine(t, runID, SeatPlayer1, fixturePolicy(), invoker, &recordingSubmitter{})
			if _, err := engine.InvokeSeat(context.Background(), SeatPlayer1, "invoke-p08", input); err != nil {
				t.Fatalf("first response: %v", err)
			}
			if _, err := engine.InvokeSeat(context.Background(), SeatPlayer1, "invoke-p08", input); !errors.Is(err, Sentinel(CodeDuplicateAction)) {
				t.Fatalf("duplicate accepted response result: %v", err)
			}
		}},
		{"P09", func(t *testing.T) {
			runID := "run-p09"
			clock := newFakeClock()
			action := actionProposal(runID, SeatPlayer1, "action-p09", 1)
			first := responseBytes(t, "invoke-p09-a", runID, SeatPlayer1, "session-"+runID+"-PLAYER_1", "a", &action)
			second := responseBytes(t, "invoke-p09-b", runID, SeatPlayer1, "session-"+runID+"-PLAYER_1", "b", &action)
			invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{response: first}, {response: second}}}
			submitter := &recordingSubmitter{}
			engine, input := fixtureEngine(t, runID, SeatPlayer1, fixturePolicy(), invoker, submitter)
			_, _ = engine.InvokeSeat(context.Background(), SeatPlayer1, "invoke-p09-a", input)
			if _, err := engine.InvokeSeat(context.Background(), SeatPlayer1, "invoke-p09-b", input); !errors.Is(err, Sentinel(CodeDuplicateAction)) || submitter.count() != 1 {
				t.Fatalf("action replay result=%v submissions=%d", err, submitter.count())
			}
		}},
		{"P10", func(t *testing.T) {
			policy := fixturePolicy()
			policy.SessionRecoveryBudget = 0
			if err := validatePolicy(policy); err != nil {
				t.Fatalf("explicit zero recovery budget rejected: %v", err)
			}
		}},
		{"P11", func(t *testing.T) {
			seats := fixtureSeats(t, "run-p11")
			registry, _ := newSessionRegistry("run-p11", seats, NewSessionAuthority())
			old, _ := registry.get(SeatPlayer1)
			next := Session{Schema: SessionSchema, SessionID: "next-p11", RunID: old.RunID, SeatID: SeatPlayer2, Generation: 2, ParentSessionID: old.SessionID}
			if registry.recover(old, next) == nil {
				t.Fatal("wrong-seat recovery accepted")
			}
		}},
		{"P12", func(t *testing.T) {
			seats := fixtureSeats(t, "run-p12")
			registry, _ := newSessionRegistry("run-p12", seats, NewSessionAuthority())
			old, _ := registry.get(SeatPlayer1)
			next := Session{Schema: SessionSchema, SessionID: "next-p12", RunID: "wrong-run", SeatID: old.SeatID, Generation: 2, ParentSessionID: old.SessionID}
			if registry.recover(old, next) == nil {
				t.Fatal("wrong-Run recovery accepted")
			}
		}},
		{"P13", func(t *testing.T) {
			floor, _ := NewFloorController("run-p13", fixturePolicy())
			if err := floor.AdvanceDiscussion(SeatGM); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
				t.Fatalf("invalid floor transition accepted: %v", err)
			}
		}},
		{"P14", func(t *testing.T) {
			floor, _ := NewFloorController("run-p14", fixturePolicy())
			_ = floor.OpenDiscussion()
			if _, err := floor.ResolveInterruptions([]InterruptionRequest{{RequestID: "self", SeatID: SeatGM, ReasonCode: "SELF"}}); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
				t.Fatalf("invalid interruption accepted: %v", err)
			}
		}},
		{"P15", func(t *testing.T) {
			floor, _ := NewFloorController("run-p15", fixturePolicy())
			_ = floor.OpenDiscussion()
			if _, err := floor.RoutePrivateMessage("p15", SeatPlayer1, []SeatID{"PLAYER_99"}, "private"); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
				t.Fatalf("invalid private recipient accepted: %v", err)
			}
		}},
		{"P16", func(t *testing.T) {
			resolve := func(requests []InterruptionRequest) SeatID {
				floor, _ := NewFloorController("run-p16", fixturePolicy())
				_ = floor.OpenDiscussion()
				winner, _ := floor.ResolveInterruptions(requests)
				return winner.SeatID
			}
			left := []InterruptionRequest{{RequestID: "p1", SeatID: SeatPlayer1, ReasonCode: "A"}, {RequestID: "p3", SeatID: SeatPlayer3, ReasonCode: "B"}}
			right := []InterruptionRequest{left[1], left[0]}
			if resolve(left) != SeatPlayer3 || resolve(right) != SeatPlayer3 {
				t.Fatal("tie ordering depended on request arrival")
			}
		}},
	}
	for _, probe := range probes {
		t.Run(probe.id, probe.run)
	}
}
