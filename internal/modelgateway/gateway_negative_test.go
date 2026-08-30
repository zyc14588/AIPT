package modelgateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcore"
)

type fakeHarnessTransport struct {
	invoke func(context.Context, ModelProfile, SamplingProfile, HarnessRequest) (HarnessResult, error)
}

func (f fakeHarnessTransport) Probe(_ context.Context, profile ModelProfile, _ SamplingProfile) (HarnessProbe, error) {
	return HarnessProbe{
		HarnessIdentity: profile.Harness.BindingID(), ProtocolIdentity: profile.Harness.ProtocolIdentity,
		ProtocolVersion: profile.Harness.ProtocolVersion, ObservedModelID: profile.ModelID,
		CapabilityFingerprint: profile.Harness.CapabilityFingerprint, RouteAvailable: true,
	}, nil
}

func (f fakeHarnessTransport) Invoke(ctx context.Context, profile ModelProfile, sampling SamplingProfile, request HarnessRequest) (HarnessResult, error) {
	if f.invoke == nil {
		return HarnessResult{}, newError(CodeHarnessTransport, "fake_invoke", request.RequestID, errors.New("unconfigured fixture"))
	}
	return f.invoke(ctx, profile, sampling, request)
}

func (fakeHarnessTransport) Recover(context.Context, ModelProfile, orchestrator.Session, orchestrator.RecoveryRequest) error {
	return nil
}

func (fakeHarnessTransport) Close(context.Context) error { return nil }

func fixtureHarnessResult(profile ModelProfile, request HarnessRequest, response []byte) HarnessResult {
	digest := sha256.Sum256(response)
	return HarnessResult{
		Schema: HarnessResponseSchema, ProtocolVersion: "1", RequestID: request.RequestID,
		HarnessIdentity: profile.Harness.BindingID(), ObservedModelID: profile.ModelID,
		CapabilityFingerprint: profile.Harness.CapabilityFingerprint,
		RawResponse:           response, ResponseSHA256: hex.EncodeToString(digest[:]), CompletedAt: time.Now().UTC(),
	}
}

func fixtureGateway(t *testing.T, transport HarnessTransport) (*Gateway, gatewayFixture) {
	t.Helper()
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	gateway, err := NewGateway(fixture.registry, fixture.binding, transport, &memoryEvidenceSink{}, GatewayOptions{
		RunID: fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-public-ci-v1", Mode: GatewayModeFormal,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return gateway, fixture
}

func TestGatewayNegativeMatrixM25AndM27ToM30(t *testing.T) {
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	profile := fixture.profiles[0]
	request := HarnessRequest{RequestID: "invocation-negative-v1"}
	valid := []byte(`{"schema":"aipt.agent-response/v1"}`)

	t.Run("M25 retry changes model silently REJECT", func(t *testing.T) {
		result := fixtureHarnessResult(profile, request, valid)
		result.ObservedModelID = "latest"
		_, err := validateHarnessResult(profile, request, result)
		requireCode(t, err, CodeModelIdentityMismatch)
	})

	t.Run("M27 unknown Harness response REJECT", func(t *testing.T) {
		result := fixtureHarnessResult(profile, request, valid)
		result.Schema = "aipt.harness-agent-response/v999"
		_, err := validateHarnessResult(profile, request, result)
		requireCode(t, err, CodeHarnessProtocolMismatch)
	})

	t.Run("M28 oversized malformed Harness frame REJECT", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("x"), maxAdapterFrameBytes+1)
		oversized = append(oversized, '\n')
		_, err := readAdapterFrame(bufio.NewReaderSize(bytes.NewReader(oversized), 4096))
		if CodeOf(err) != CodeHarnessFrameTooLarge {
			t.Fatalf("oversized frame error = %v", err)
		}
		if _, err := readAdapterFrame(bufio.NewReader(strings.NewReader("{malformed}\n"))); err == nil {
			t.Fatal("malformed Harness frame accepted")
		}
	})

	t.Run("M29 Harness timeout stale response accepted REJECT", func(t *testing.T) {
		transport := fakeHarnessTransport{invoke: func(ctx context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest) (HarnessResult, error) {
			<-ctx.Done()
			// A faulty transport races a response after cancellation. Gateway must
			// consult its deadline again and never accept this stale result.
			return fixtureHarnessResult(profile, request, validAgentResponse(request)), nil
		}}
		gateway, gatewayData := fixtureGateway(t, transport)
		seat := fixtureSeat(t, gatewayData.frozen.Manifest.RunID, orchestrator.SeatGM)
		invocation := orchestrator.InvocationRequest{
			InvocationID: "invocation-timeout-v1", RunID: seat.RunID, SeatID: seat.SeatID,
			SessionID: seat.Session.SessionID, Kind: orchestrator.InvocationOriginal, Attempt: 1,
			Deadline: time.Now().Add(20 * time.Millisecond),
			Context:  fixtureContext(t, seat.RunID, seat.SeatID),
		}
		_, err := gateway.Invoke(context.Background(), seat.Session, invocation)
		var failure *orchestrator.InvocationFailure
		if !errors.As(err, &failure) || failure.Class != orchestrator.CodeInvocationTimeout {
			t.Fatalf("stale timeout response = %v", err)
		}
	})

	t.Run("M30 model response directly mutates state REJECT", func(t *testing.T) {
		transport := fakeHarnessTransport{invoke: func(_ context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest) (HarnessResult, error) {
			response := map[string]any{
				"schema": orchestrator.AgentResponseSchema, "invocation_id": request.Invocation.InvocationID,
				"run_id": request.Invocation.RunID, "seat_id": request.Invocation.SeatID,
				"session_id": request.Session.SessionID, "speech": "attempt direct mutation",
				"metadata": map[string]any{"protocol_version": "v1"},
				"state":    map[string]any{"hp": 999999},
			}
			raw, _ := json.Marshal(response)
			return fixtureHarnessResult(profile, request, raw), nil
		}}
		gateway, gatewayData := fixtureGateway(t, transport)
		seats := baselineSeatsForGatewayTest(t, gatewayData.frozen.Manifest.RunID)
		submitter := &countingSubmitter{}
		policy := fixturePolicy()
		policy.SemanticRepairBudget = 0
		engine, err := orchestrator.NewEngine(orchestrator.EngineConfig{
			RunID: gatewayData.frozen.Manifest.RunID, Policy: policy, Seats: seats,
			SessionAuthority: orchestrator.NewSessionAuthority(), Invoker: gateway,
			Retriever: fixtureRetriever{content: map[string]orchestrator.RetrievedContent{}},
			Submitter: submitter, Clock: wallClock{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := engine.Floor().OpenDiscussion(); err != nil {
			t.Fatal(err)
		}
		input := contextInputForGatewayEngine(t, gatewayData.frozen.Manifest.RunID, orchestrator.SeatGM)
		if _, err := engine.InvokeSeat(context.Background(), orchestrator.SeatGM, "invocation-direct-state-v1", input); err == nil {
			t.Fatal("B003 protocol accepted a direct state mutation member")
		}
		if submitter.Count() != 0 {
			t.Fatalf("model response reached mutation submitter directly: %d calls", submitter.Count())
		}
	})
}

func validAgentResponse(request HarnessRequest) []byte {
	raw, _ := json.Marshal(orchestrator.AgentResponse{
		Schema: orchestrator.AgentResponseSchema, InvocationID: request.Invocation.InvocationID,
		RunID: request.Invocation.RunID, SeatID: request.Invocation.SeatID, SessionID: request.Session.SessionID,
		Speech: "synthetic response", Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"},
	})
	return raw
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now().UTC() }

type countingSubmitter struct {
	mu    sync.Mutex
	count int
}

func (s *countingSubmitter) Submit(context.Context, runcore.ActionProposal) (runcore.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	return runcore.Receipt{}, errors.New("synthetic submitter rejects all proposals")
}

func (s *countingSubmitter) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

func baselineSeatsForGatewayTest(t *testing.T, runID string) []orchestrator.Seat {
	t.Helper()
	identities := orchestrator.BaselineIdentitySet{
		SessionIDs: map[orchestrator.SeatID]string{},
		Personas:   map[orchestrator.SeatID]orchestrator.PersonaBaseline{},
		Characters: map[orchestrator.SeatID]orchestrator.Character{},
		GMProfile:  orchestrator.GMProfileRulesFaithful,
	}
	for _, seatID := range orchestrator.BaselineSeats() {
		identities.SessionIDs[seatID] = "session-" + strings.ToLower(string(seatID))
		persona, err := orchestrator.NewPersonaBaseline("persona-"+strings.ToLower(string(seatID)), "v1", []orchestrator.PersonaTrait{{Name: "stress", Value: 10}})
		if err != nil {
			t.Fatal(err)
		}
		identities.Personas[seatID] = persona
		if seatID != orchestrator.SeatGM {
			character, err := orchestrator.NewCharacter("character-"+strings.ToLower(string(seatID)), "v1", []byte(`{"hp":10}`))
			if err != nil {
				t.Fatal(err)
			}
			identities.Characters[seatID] = character
		}
	}
	seats, err := orchestrator.NewBaselineSeats(runID, identities)
	if err != nil {
		t.Fatal(err)
	}
	return seats
}

func contextInputForGatewayEngine(t *testing.T, runID string, seatID orchestrator.SeatID) orchestrator.ContextInput {
	t.Helper()
	fact := fixtureStateFact(t, "fact-engine-public", orchestrator.ClassPublic, `{"round":1}`)
	summary, err := orchestrator.NewMemorySummary(
		"summary-engine-public", "v1", runID, seatID,
		[]orchestrator.SummaryFact{{FactID: fact.FactID, ValueSHA256: fact.ValueSHA256}},
		[]string{fact.FactID}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return orchestrator.ContextInput{StateFacts: []orchestrator.StateFact{fact}, Summary: summary}
}

func TestGatewayPositiveProbeInvocationAndEvidence(t *testing.T) {
	evidence := &memoryEvidenceSink{}
	transport := fakeHarnessTransport{invoke: func(_ context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest) (HarnessResult, error) {
		return fixtureHarnessResult(profile, request, validAgentResponse(request)), nil
	}}
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	gateway, err := NewGateway(fixture.registry, fixture.binding, transport, evidence, GatewayOptions{
		RunID: fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-positive-v1", Mode: GatewayModeFormal,
	})
	if err != nil {
		t.Fatal(err)
	}
	probes, err := gateway.ProbeAll(context.Background())
	if err != nil || len(probes) != 5 {
		t.Fatalf("ProbeAll = %d, %v", len(probes), err)
	}
	seat := fixtureSeat(t, fixture.frozen.Manifest.RunID, orchestrator.SeatPlayer1)
	request := orchestrator.InvocationRequest{
		InvocationID: "invocation-positive-v1", RunID: seat.RunID, SeatID: seat.SeatID,
		SessionID: seat.Session.SessionID, Kind: orchestrator.InvocationOriginal, Attempt: 1,
		Deadline: time.Now().Add(time.Second), Context: fixtureContext(t, seat.RunID, seat.SeatID),
	}
	result, err := gateway.Invoke(context.Background(), seat.Session, request)
	if err != nil || len(result.Response) == 0 {
		t.Fatalf("Gateway.Invoke: %v", err)
	}
	if evidence.Count() != 1 || evidence.Last().CleanBaselineEligible {
		t.Fatalf("synthetic public-CI evidence acquired formal clean eligibility: %+v", evidence.Last())
	}
	if err := gateway.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type memoryEvidenceSink struct {
	mu       sync.Mutex
	values   []InvocationEvidence
	consumed map[string]BreakGlassConsumption
}

func (*memoryEvidenceSink) authoritativeBreakGlassConsumption() {}

func (s *memoryEvidenceSink) RecordInvocation(_ context.Context, value InvocationEvidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value.RunClassification == "QUALIFICATION" {
		for _, consumption := range s.consumed {
			if consumption.RunID == value.RunID && consumption.RunDisqualified {
				return newError(CodeBreakGlassAudit, "record_model_invocation", value.InvocationID, errors.New("Run is irreversibly disqualified"))
			}
		}
	}
	s.values = append(s.values, value)
	return nil
}

func (s *memoryEvidenceSink) ConsumeBreakGlass(_ context.Context, value BreakGlassConsumption) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed == nil {
		s.consumed = make(map[string]BreakGlassConsumption)
	}
	if _, exists := s.consumed[value.GrantID]; exists {
		return newError(CodeBreakGlassReplay, "consume_break_glass", value.GrantID, errors.New("grant already consumed"))
	}
	s.consumed[value.GrantID] = value
	return nil
}

func (s *memoryEvidenceSink) BreakGlassDisqualified(_ context.Context, runID, diagnosticID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, value := range s.consumed {
		if value.RunID == runID && value.RunDisqualified {
			return true, nil
		}
	}
	return false, nil
}

func (s *memoryEvidenceSink) ConsumptionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.consumed)
}

func (s *memoryEvidenceSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.values)
}

func (s *memoryEvidenceSink) Last() InvocationEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values) == 0 {
		return InvocationEvidence{}
	}
	return s.values[len(s.values)-1]
}
