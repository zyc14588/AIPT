package pilot

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcore"
)

type task0FrameFixtureProvider struct {
	response []byte
	calls    int
}

func (p *task0FrameFixtureProvider) Invoke(context.Context, orchestrator.Session, orchestrator.InvocationRequest) (orchestrator.InvocationResult, error) {
	p.calls++
	return orchestrator.InvocationResult{Response: p.response, CompletedAt: time.Now().UTC()}, nil
}
func (*task0FrameFixtureProvider) Recover(context.Context, orchestrator.Session, orchestrator.RecoveryRequest) (orchestrator.Session, error) {
	return orchestrator.Session{}, ErrTask0
}

func task0ModelFrameFixture(t *testing.T) (context.Context, orchestrator.Session, orchestrator.InvocationRequest, orchestrator.AgentResponse) {
	t.Helper()
	seat := orchestrator.SeatPlayer1
	run := "NON-CANON-frame-gateway"
	persona, err := orchestrator.NewPersonaBaseline("NON-CANON-persona", "v1", []orchestrator.PersonaTrait{{Name: "deliberation", Value: 50}})
	if err != nil {
		t.Fatal(err)
	}
	character, err := orchestrator.NewCharacter("UNR-CHAR-0001", "v1", []byte(`{"non_canon":true}`))
	if err != nil {
		t.Fatal(err)
	}
	s := orchestrator.Seat{SeatID: seat, RunID: run, Role: orchestrator.RolePlayer, RoleContractID: "AIPT_PLAYER_ROLE_CONTRACT_V1", VisibilityID: "NON-CANON-visibility", Persona: persona, Character: &character, Session: orchestrator.Session{Schema: orchestrator.SessionSchema, SessionID: "NON-CANON-session", RunID: run, SeatID: seat, Generation: 1}}
	summary, err := orchestrator.NewMemorySummary("NON-CANON-summary", "v1", run, seat, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := orchestrator.OrchestrationPolicy{Schema: orchestrator.PolicySchema, PolicyID: "NON-CANON-policy", SeatOrder: orchestrator.BaselineSeats(), InterruptionOrder: orchestrator.BaselineSeats(), InvocationTimeoutMillis: 1000}
	bundle, err := orchestrator.BuildContext(context.Background(), policy, s, orchestrator.PersonaState{Version: "v1", PersonaID: persona.PersonaID, RunID: run, SeatID: seat}, orchestrator.ContextInput{Summary: summary}, nil)
	if err != nil {
		t.Fatal(err)
	}
	inv := orchestrator.InvocationRequest{InvocationID: "NON-CANON-invocation", RunID: run, SeatID: seat, SessionID: s.Session.SessionID, Kind: orchestrator.InvocationOriginal, Attempt: 1, Context: bundle}
	ctx, err := task0TurnContext(context.Background(), seat, run, "NON-CANON-action", 1)
	if err != nil {
		t.Fatal(err)
	}
	outer := orchestrator.AgentResponse{Schema: orchestrator.AgentResponseSchema, InvocationID: inv.InvocationID, RunID: run, SeatID: seat, SessionID: s.Session.SessionID,
		Speech: `{"actor_id":"UNR-CHAR-0001","action_type":"PLAYER_INTENT","payload":{"kind":"NON_CANON"}}`, Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"}}
	return ctx, s.Session, inv, outer
}

func TestTask0FrameGatewayPreservesFixedWorkerEnvelopeAndRejectsProviderAuthority(t *testing.T) {
	for _, scenario := range []string{"valid", "bare_frame_outer", "wrong_schema", "other_invocation", "other_run", "other_seat", "other_session", "provider_action", "provider_claim", "foreign_actor", "inner_principal", "inner_rng", "inner_duplicate_actor", "outer_case_alias", "outer_duplicate_schema", "outer_trailing_json", "over_output_cap", "missing_turn", "changed_context_hash", "recovery_attempt"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, session, inv, outer := task0ModelFrameFixture(t)
			switch scenario {
			case "wrong_schema":
				outer.Schema = "fixture/v1"
			case "other_invocation":
				outer.InvocationID = "NON-CANON-foreign-invocation"
			case "other_run":
				outer.RunID = "NON-CANON-other-run"
			case "other_seat":
				outer.SeatID = orchestrator.SeatPlayer2
			case "other_session":
				outer.SessionID = "NON-CANON-other-session"
			case "provider_action":
				outer.Action = &runcore.ActionProposal{}
			case "provider_claim":
				outer.Metadata.SpeechActionClaim = &orchestrator.SpeechActionClaim{ActionID: "untrusted", ActionType: "UNTRUSTED"}
			case "foreign_actor":
				outer.Speech = strings.ReplaceAll(outer.Speech, "UNR-CHAR-0001", "UNR-CHAR-0002")
			case "inner_principal", "inner_rng":
				field := map[string]string{"inner_principal": "principal", "inner_rng": "rng_requests"}[scenario]
				outer.Speech = strings.TrimSuffix(outer.Speech, "}") + `,"` + field + `":[]}`
			case "inner_duplicate_actor":
				outer.Speech = strings.TrimSuffix(outer.Speech, "}") + `,"actor_id":"UNR-CHAR-0001"}`
			case "missing_turn":
				ctx = context.Background()
			case "changed_context_hash":
				inv.Context.ContextHash = strings.Repeat("0", 64)
			case "recovery_attempt":
				inv.Kind = orchestrator.InvocationRepair
				inv.Attempt = 2
			}
			raw, _ := json.Marshal(outer)
			switch scenario {
			case "bare_frame_outer":
				raw = []byte(outer.Speech)
			case "outer_case_alias":
				raw = []byte(strings.Replace(string(raw), `"schema"`, `"Schema"`, 1))
			case "outer_duplicate_schema":
				raw = append(raw[:len(raw)-1], []byte(`,"schema":"aipt.agent-response/v1"}`)...)
			case "outer_trailing_json":
				raw = append(raw, []byte(`{}`)...)
			case "over_output_cap":
				raw = append(raw, []byte(strings.Repeat(" ", 1024))...)
			}
			provider := &task0FrameFixtureProvider{response: raw}
			g := &task0FrameGateway{upstream: provider}
			result, err := g.Invoke(ctx, session, inv)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("model frame admission differs", scenario)
			}
			if err == nil && string(result.Response) != `{"action_type":"PLAYER_INTENT","actor_id":"UNR-CHAR-0001","payload":{"kind":"NON_CANON"}}` {
				t.Fatal("trusted frame normalization changed payload")
			}
			if (scenario == "missing_turn" || scenario == "changed_context_hash" || scenario == "recovery_attempt") && provider.calls != 0 {
				t.Fatal("untrusted invocation dispatched provider")
			}
		})
	}
}
