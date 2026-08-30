package modelgateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/testplan"
)

var breakGlassTestNow = time.Now().UTC().Truncate(time.Second)

func diagnosticBreakGlassFixture(t *testing.T) gatewayFixture {
	t.Helper()
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	for index := range fixture.profiles {
		profile := fixture.profiles[index]
		profile.SHA256 = ""
		profile.DataEgressPolicy.BreakGlassAllowed = true
		bound, err := BindModelProfile(profile)
		if err != nil {
			t.Fatalf("bind break-glass profile: %v", err)
		}
		fixture.profiles[index] = bound
	}
	registry, err := NewSyntheticRegistry(fixture.samplings, fixture.profiles, fixture.certifications)
	if err != nil {
		t.Fatalf("diagnostic registry: %v", err)
	}
	manifest := fixture.frozen.Manifest
	manifest.CanonicalSHA256 = ""
	manifest.Classification = "DIAGNOSTIC"
	manifest.QualificationEligible = false
	manifest.VisibilityProfileID = "AIPT_VISIBILITY_DIAGNOSTIC_V1"
	manifest.SafetyProfileID = "AIPT_SAFETY_DIAGNOSTIC_V1"
	frozen, err := testplan.BindRunManifest(manifest)
	if err != nil {
		t.Fatalf("bind diagnostic manifest: %v", err)
	}
	binding, err := BindManifestModels(frozen, registry)
	if err != nil {
		t.Fatalf("bind diagnostic models: %v", err)
	}
	fixture.registry = registry
	fixture.frozen = frozen
	fixture.binding = binding
	return fixture
}

func breakGlassInvocation(t *testing.T, fixture gatewayFixture, seatID orchestrator.SeatID, id string) (orchestrator.Session, orchestrator.InvocationRequest) {
	t.Helper()
	seat := fixtureSeat(t, fixture.frozen.Manifest.RunID, seatID)
	request := orchestrator.InvocationRequest{
		InvocationID: id, RunID: seat.RunID, SeatID: seat.SeatID, SessionID: seat.Session.SessionID,
		Kind: orchestrator.InvocationOriginal, Attempt: 1, Deadline: breakGlassTestNow.Add(time.Minute),
		Context: fixtureContext(t, seat.RunID, seat.SeatID, orchestrator.ClassLocalOnlySecret),
	}
	return seat.Session, request
}

func assignmentForSeat(t *testing.T, fixture gatewayFixture, seatID orchestrator.SeatID) RoleAssignment {
	t.Helper()
	for _, assignment := range fixture.binding.Assignments {
		if assignment.SeatID == seatID {
			return assignment
		}
	}
	t.Fatalf("missing assignment for %s", seatID)
	return RoleAssignment{}
}

func signedBreakGlassFixture(
	t *testing.T,
	fixture gatewayFixture,
	request orchestrator.InvocationRequest,
) (BreakGlassGrant, BreakGlassVerifier) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	assignment := assignmentForSeat(t, fixture, request.SeatID)
	profile, err := fixture.registry.Profile(assignment.ProfileBinding)
	if err != nil {
		t.Fatalf("resolve profile: %v", err)
	}
	sampling, err := fixture.registry.Sampling(assignment.SamplingBinding)
	if err != nil {
		t.Fatalf("resolve sampling: %v", err)
	}
	session := fixtureSeat(t, fixture.frozen.Manifest.RunID, request.SeatID).Session
	_, harnessRequest, err := buildHarnessRequest(profile, sampling, session, request)
	if err != nil {
		t.Fatalf("build signed request identity: %v", err)
	}
	grant := BreakGlassGrant{
		Schema: BreakGlassGrantSchema, GrantID: "grant-diagnostic-once-v1", OneTime: true, DiagnosticOnly: true,
		AuthorizedOperation: BreakGlassRemoteEgressLocalOnlySecret,
		RunID:               fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-break-glass-v1",
		ManifestSHA256: fixture.binding.ManifestSHA256, SeatID: request.SeatID,
		InvocationID: request.InvocationID, ProfileBinding: assignment.ProfileBinding,
		ContextSHA256: request.Context.ContextHash, RequestSHA256: harnessRequest.RequestSHA256,
		SourceClassification: orchestrator.ClassLocalOnlySecret,
		DestinationBackend:   BackendRemoteDeepSeek, IssuerAuthorityID: "owner-authority-v1",
		IssuedAt: breakGlassTestNow.Add(-time.Minute), ExpiresAt: breakGlassTestNow.Add(time.Hour),
		Nonce: "nonce-diagnostic-once-v1",
	}
	grant, err = signBreakGlassGrant(grant, privateKey)
	if err != nil {
		t.Fatalf("sign grant: %v", err)
	}
	verifier, err := NewEd25519BreakGlassVerifier(map[string]ed25519.PublicKey{
		"owner-authority-v1": publicKey,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return grant, verifier
}

func successfulBreakGlassTransport(calls *atomic.Int64) HarnessTransport {
	return fakeHarnessTransport{invoke: func(_ context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest) (HarnessResult, error) {
		calls.Add(1)
		return fixtureHarnessResult(profile, request, validAgentResponse(request)), nil
	}}
}

func newDiagnosticGateway(
	t *testing.T,
	fixture gatewayFixture,
	transport HarnessTransport,
	audit AuditSink,
	grant *BreakGlassGrant,
	verifier BreakGlassVerifier,
) (*Gateway, error) {
	t.Helper()
	return NewGateway(fixture.registry, fixture.binding, transport, audit, GatewayOptions{
		RunID: fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-break-glass-v1",
		Mode: GatewayModeDiagnostic, BreakGlass: grant, BreakGlassVerifier: verifier,
	})
}

func TestBreakGlassFirstConsumptionPassesAndReplayRejects(t *testing.T) {
	fixture := diagnosticBreakGlassFixture(t)
	session, request := breakGlassInvocation(t, fixture, orchestrator.SeatGM, "invocation-break-glass-once-v1")
	grant, verifier := signedBreakGlassFixture(t, fixture, request)
	audit := &memoryEvidenceSink{}
	var calls atomic.Int64
	gateway, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&calls), audit, &grant, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := gateway.Invoke(context.Background(), session, request); err != nil || len(result.Response) == 0 {
		t.Fatalf("first legal consumption: result=%+v err=%v", result, err)
	}
	if calls.Load() != 1 || audit.ConsumptionCount() != 1 || audit.Count() != 1 ||
		!audit.Last().BreakGlassUsed || audit.Last().CleanBaselineEligible || audit.Last().BreakGlassGrantSHA256 == "" {
		t.Fatalf("first consumption audit mismatch: calls=%d consumption=%d evidence=%+v", calls.Load(), audit.ConsumptionCount(), audit.Last())
	}
	if _, err := gateway.Invoke(context.Background(), session, request); err == nil {
		t.Fatal("same grant replay accepted")
	}
	if calls.Load() != 1 || audit.ConsumptionCount() != 1 {
		t.Fatalf("replay reached transport or consumed twice: calls=%d consumption=%d", calls.Load(), audit.ConsumptionCount())
	}
}

func TestBreakGlassConcurrentDoubleConsumptionHasExactlyOneWinner(t *testing.T) {
	fixture := diagnosticBreakGlassFixture(t)
	session, request := breakGlassInvocation(t, fixture, orchestrator.SeatGM, "invocation-break-glass-race-v1")
	grant, verifier := signedBreakGlassFixture(t, fixture, request)
	audit := &memoryEvidenceSink{}
	var calls atomic.Int64
	gateway, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&calls), audit, &grant, verifier)
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 16
	var successes atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, invokeErr := gateway.Invoke(context.Background(), session, request); invokeErr == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || calls.Load() != 1 || audit.ConsumptionCount() != 1 {
		t.Fatalf("concurrent grant results: successes=%d calls=%d consumptions=%d", successes.Load(), calls.Load(), audit.ConsumptionCount())
	}
}

func TestBreakGlassScopeSignatureFormalAndRestartRejections(t *testing.T) {
	fixture := diagnosticBreakGlassFixture(t)
	session, request := breakGlassInvocation(t, fixture, orchestrator.SeatGM, "invocation-break-glass-scope-v1")
	grant, verifier := signedBreakGlassFixture(t, fixture, request)

	t.Run("modified signed payload REJECT", func(t *testing.T) {
		modified := grant
		modified.ContextSHA256 = fixtureSHA("modified-context")
		_, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&atomic.Int64{}), &memoryEvidenceSink{}, &modified, verifier)
		requireCode(t, err, CodeBreakGlassInvalid)
	})

	t.Run("modified invocation payload REJECT before transport", func(t *testing.T) {
		modified := request
		modified.Attempt++
		var calls atomic.Int64
		gateway, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&calls), &memoryEvidenceSink{}, &grant, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gateway.Invoke(context.Background(), session, modified); err == nil {
			t.Fatal("modified request payload accepted")
		}
		if calls.Load() != 0 {
			t.Fatal("modified request payload reached transport")
		}
	})

	t.Run("cross Run REJECT", func(t *testing.T) {
		modified := grant
		modified.RunID = "different-run-v1"
		privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
		modified, _ = signBreakGlassGrant(modified, privateKey)
		_, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&atomic.Int64{}), &memoryEvidenceSink{}, &modified, verifier)
		requireCode(t, err, CodeBreakGlassInvalid)
	})

	t.Run("cross seat and profile scope REJECT", func(t *testing.T) {
		otherSession, otherRequest := breakGlassInvocation(t, fixture, orchestrator.SeatPlayer1, request.InvocationID)
		var calls atomic.Int64
		gateway, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&calls), &memoryEvidenceSink{}, &grant, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gateway.Invoke(context.Background(), otherSession, otherRequest); err == nil {
			t.Fatal("cross-seat grant accepted")
		}
		if calls.Load() != 0 {
			t.Fatal("cross-seat grant reached transport")
		}
	})

	t.Run("formal qualification mode REJECT", func(t *testing.T) {
		formal := newGatewayFixture(t, BackendRemoteDeepSeek)
		formalGrant := grant
		formalGrant.ManifestSHA256 = formal.binding.ManifestSHA256
		formalGrant.RunID = formal.frozen.Manifest.RunID
		privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
		formalGrant, _ = signBreakGlassGrant(formalGrant, privateKey)
		_, err := NewGateway(formal.registry, formal.binding, successfulBreakGlassTransport(&atomic.Int64{}), &memoryEvidenceSink{}, GatewayOptions{
			RunID: formal.frozen.Manifest.RunID, DiagnosticID: formalGrant.DiagnosticID, Mode: GatewayModeFormal,
			BreakGlass: &formalGrant, BreakGlassVerifier: verifier,
		})
		requireCode(t, err, CodeBreakGlassInvalid)
	})

	t.Run("new Gateway after consumption observes durable replay", func(t *testing.T) {
		audit := &memoryEvidenceSink{}
		var firstCalls, resumedCalls atomic.Int64
		first, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&firstCalls), audit, &grant, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := first.Invoke(context.Background(), session, request); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		resumed, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&resumedCalls), audit, &grant, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resumed.Invoke(context.Background(), session, request); err == nil {
			t.Fatal("restart replay accepted")
		}
		if firstCalls.Load() != 1 || resumedCalls.Load() != 0 || audit.ConsumptionCount() != 1 {
			t.Fatalf("restart replay reached transport: first=%d resumed=%d", firstCalls.Load(), resumedCalls.Load())
		}
	})

	t.Run("different diagnostic identity remains run-disqualified", func(t *testing.T) {
		audit := &memoryEvidenceSink{}
		var calls atomic.Int64
		gateway, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&calls), audit, &grant, verifier)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := gateway.Invoke(context.Background(), session, request); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		disqualified, err := audit.BreakGlassDisqualified(context.Background(), fixture.frozen.Manifest.RunID, "different-diagnostic-v1")
		if err != nil || !disqualified {
			t.Fatalf("cross-diagnostic run disqualification=%t err=%v", disqualified, err)
		}
	})
}

func TestBreakGlassFailedTransportStillConsumesAndDisqualifies(t *testing.T) {
	fixture := diagnosticBreakGlassFixture(t)
	session, request := breakGlassInvocation(t, fixture, orchestrator.SeatGM, "invocation-break-glass-failed-transport-v1")
	grant, verifier := signedBreakGlassFixture(t, fixture, request)
	audit := &memoryEvidenceSink{}
	var failedCalls atomic.Int64
	failing := fakeHarnessTransport{invoke: func(_ context.Context, _ ModelProfile, _ SamplingProfile, _ HarnessRequest) (HarnessResult, error) {
		failedCalls.Add(1)
		return HarnessResult{}, newError(CodeHarnessTransport, "fixture", request.InvocationID, errors.New("synthetic transport failure"))
	}}
	gateway, err := newDiagnosticGateway(t, fixture, failing, audit, &grant, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Invoke(context.Background(), session, request); err == nil {
		t.Fatal("failed transport unexpectedly succeeded")
	}
	if failedCalls.Load() != 1 || audit.ConsumptionCount() != 1 {
		t.Fatalf("failed transport did not retain consumption: calls=%d consumed=%d", failedCalls.Load(), audit.ConsumptionCount())
	}
	var retryCalls atomic.Int64
	retry, err := newDiagnosticGateway(t, fixture, successfulBreakGlassTransport(&retryCalls), audit, &grant, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retry.Invoke(context.Background(), session, request); err == nil || retryCalls.Load() != 0 {
		t.Fatalf("spent grant reached retry transport: err=%v calls=%d", err, retryCalls.Load())
	}
}

type untrustedModelAuditSink struct{}

func (*untrustedModelAuditSink) RecordInvocation(context.Context, InvocationEvidence) error {
	return nil
}
func (*untrustedModelAuditSink) ConsumeBreakGlass(context.Context, BreakGlassConsumption) error {
	return nil
}
func (*untrustedModelAuditSink) BreakGlassDisqualified(context.Context, string, string) (bool, error) {
	return false, nil
}

func TestEveryGatewayRequiresAuthoritativeRunAuditSink(t *testing.T) {
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	_, err := NewGateway(
		fixture.registry,
		fixture.binding,
		successfulBreakGlassTransport(&atomic.Int64{}),
		&untrustedModelAuditSink{},
		GatewayOptions{
			RunID: fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-untrusted-audit-v1",
			Mode: GatewayModeFormal,
		},
	)
	requireCode(t, err, CodeBreakGlassAudit)
}

type interlockedRunAuditSink struct {
	base              *memoryEvidenceSink
	reads             atomic.Int32
	secondReadDone    chan struct{}
	releaseSecondRead chan struct{}
}

func (*interlockedRunAuditSink) authoritativeBreakGlassConsumption() {}

func (s *interlockedRunAuditSink) RecordInvocation(ctx context.Context, value InvocationEvidence) error {
	return s.base.RecordInvocation(ctx, value)
}

func (s *interlockedRunAuditSink) ConsumeBreakGlass(ctx context.Context, value BreakGlassConsumption) error {
	return s.base.ConsumeBreakGlass(ctx, value)
}

func (s *interlockedRunAuditSink) BreakGlassDisqualified(ctx context.Context, runID, diagnosticID string) (bool, error) {
	disqualified, err := s.base.BreakGlassDisqualified(ctx, runID, diagnosticID)
	if s.reads.Add(1) == 2 {
		close(s.secondReadDone)
		<-s.releaseSecondRead
	}
	return disqualified, err
}

func TestFormalInvocationAuditRejectsConcurrentRunDisqualificationAfterFinalRead(t *testing.T) {
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	audit := &interlockedRunAuditSink{
		base: &memoryEvidenceSink{}, secondReadDone: make(chan struct{}), releaseSecondRead: make(chan struct{}),
	}
	var calls atomic.Int64
	gateway, err := NewGateway(
		fixture.registry,
		fixture.binding,
		successfulBreakGlassTransport(&calls),
		audit,
		GatewayOptions{
			RunID: fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-formal-interleave-v1",
			Mode: GatewayModeFormal,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	seat := fixtureSeat(t, fixture.frozen.Manifest.RunID, orchestrator.SeatGM)
	request := orchestrator.InvocationRequest{
		InvocationID: "invocation-formal-interleave-v1", RunID: seat.RunID, SeatID: seat.SeatID,
		SessionID: seat.Session.SessionID, Kind: orchestrator.InvocationOriginal, Attempt: 1,
		Deadline: time.Now().Add(time.Second), Context: fixtureContext(t, seat.RunID, seat.SeatID),
	}
	result := make(chan error, 1)
	go func() {
		_, invokeErr := gateway.Invoke(context.Background(), seat.Session, request)
		result <- invokeErr
	}()
	select {
	case <-audit.secondReadDone:
	case <-time.After(time.Second):
		t.Fatal("formal invocation did not reach the final disqualification read")
	}
	consumption := BreakGlassConsumption{
		Schema: BreakGlassConsumptionSchema, ConsumptionID: "consume-formal-interleave-v1",
		GrantID: "grant-formal-interleave-v1", GrantSHA256: fixtureSHA("grant-formal-interleave"),
		AuthorizedOperation: BreakGlassRemoteEgressLocalOnlySecret,
		RunID:               fixture.frozen.Manifest.RunID, DiagnosticID: "diagnostic-concurrent-consumer-v1",
		ManifestSHA256: fixture.binding.ManifestSHA256, SeatID: orchestrator.SeatGM,
		InvocationID: "invocation-concurrent-consumer-v1", ProfileBinding: fixture.binding.Assignments[0].ProfileBinding,
		ContextSHA256: fixtureSHA("context-formal-interleave"), RequestSHA256: fixtureSHA("request-formal-interleave"),
		SourceClassification: orchestrator.ClassLocalOnlySecret, DestinationBackend: BackendRemoteDeepSeek,
		IssuerAuthorityID: "owner-authority-v1", NonceSHA256: fixtureSHA("nonce-formal-interleave"),
		ConsumedAt: time.Now().UTC(), RunDisqualified: true,
	}
	if err := audit.ConsumeBreakGlass(context.Background(), consumption); err != nil {
		t.Fatal(err)
	}
	close(audit.releaseSecondRead)
	if err := <-result; err == nil {
		t.Fatal("formal invocation returned success after concurrent irreversible Run disqualification")
	}
	if calls.Load() != 1 || audit.base.Count() != 0 {
		t.Fatalf("formal interleave result: transport_calls=%d evidence_count=%d", calls.Load(), audit.base.Count())
	}
}
