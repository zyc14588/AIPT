package pilot

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

func task0CertificationRequest(runID string, entry task0DispatchProfile) (modelgateway.HarnessRequest, error) {
	identities, err := task0BaselineIdentities(runID)
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	seats, err := orchestrator.NewBaselineSeats(runID, identities)
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	var seat orchestrator.Seat
	for _, candidate := range seats {
		if candidate.SeatID == entry.Seat {
			seat = candidate
		}
	}
	if seat.SeatID == "" {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	if entry.Profile.BackendKind == modelgateway.BackendLocalLlamaCPP {
		seat.Session.SessionID += "-local-cert"
	}
	requestID, err := task0InvocationNonce()
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	summary, err := orchestrator.NewMemorySummary("b007-cert-summary-"+task0WireSeat(seat.SeatID), "1", runID, seat.SeatID, nil, nil, nil)
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	raw := json.RawMessage(`{"classification":"PUBLIC","probe":"Return one speech-only acknowledgement in the required invocation response envelope."}`)
	fact := orchestrator.StateFact{FactID: "b007-certification-ack", Classification: orchestrator.ClassPublic, Scope: orchestrator.ScopePublic, Value: raw, ValueSHA256: inputSHA(raw)}
	state := orchestrator.PersonaState{Version: "v1", PersonaID: seat.Persona.PersonaID, RunID: runID, SeatID: seat.SeatID}
	bundle, err := orchestrator.BuildContext(context.Background(), task0TablePolicy(), seat, state, orchestrator.ContextInput{StateFacts: []orchestrator.StateFact{fact}, Summary: summary}, nil)
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	invocation := orchestrator.InvocationRequest{InvocationID: requestID, RunID: runID, SeatID: seat.SeatID, SessionID: seat.Session.SessionID, Kind: orchestrator.InvocationOriginal, Attempt: 1, Context: bundle}
	p, s := entry.Profile, entry.Sampling
	prepared, reduction, err := modelgateway.PrepareContext(bundle, p.ContextPolicy)
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	request := modelgateway.HarnessRequest{Schema: modelgateway.HarnessRequestSchema, ProtocolVersion: "1", RequestID: requestID, ProfileBinding: p.BindingID(), SamplingBinding: s.BindingID(), ExpectedModelID: p.ModelID,
		HarnessIdentity: p.Harness.BindingID(), BackendKind: p.BackendKind, ProviderIdentity: p.ProviderIdentity, StructuredMode: p.StructuredOutputMode, ToolMode: p.ToolCallMode, SamplingProfile: s,
		Session: seat.Session, Invocation: invocation, PreparedContext: prepared, ContextReduction: reduction}
	encoded, err := json.Marshal(request)
	if err != nil {
		return modelgateway.HarnessRequest{}, ErrTask0
	}
	request.RequestSHA256 = inputSHA(encoded)
	return request, nil
}

func task0MinimumClaims() []modelgateway.CapabilityClaim {
	return []modelgateway.CapabilityClaim{
		{Name: modelgateway.CapabilityBasicCompletion, Status: modelgateway.ClaimCertified},
		{Name: modelgateway.CapabilityStructuredOutputNative, Status: modelgateway.ClaimNotCertified},
		{Name: modelgateway.CapabilityStructuredOutputPrompted, Status: modelgateway.ClaimCertified},
		{Name: modelgateway.CapabilityStructuredOutputRepair, Status: modelgateway.ClaimUntested},
		{Name: modelgateway.CapabilityToolCallNative, Status: modelgateway.ClaimNotCertified},
		{Name: modelgateway.CapabilityToolCallEmulated, Status: modelgateway.ClaimUntested},
		{Name: modelgateway.CapabilityContextBudget, Status: modelgateway.ClaimUntested},
		{Name: modelgateway.CapabilityRoleInvocation, Status: modelgateway.ClaimCertified},
		{Name: modelgateway.CapabilityTransportStability, Status: modelgateway.ClaimUntested},
		{Name: modelgateway.CapabilityVisibilityPolicyCompatible, Status: modelgateway.ClaimUntested},
		{Name: modelgateway.CapabilityPromptInjectionBoundaryCompatible, Status: modelgateway.ClaimUntested},
	}
}

// Called on a result obtained from the concrete, budget-reserved transport.
// This observation certifies only the three existing minimum capabilities;
// it cannot turn a diagnostic call into production or qualification approval.
func task0CertificationFromResult(entry task0DispatchProfile, request modelgateway.HarnessRequest, result modelgateway.HarnessResult, observed time.Time) (modelgateway.Certification, error) {
	p, s := entry.Profile, entry.Sampling
	if result.Schema != modelgateway.HarnessResponseSchema || result.ProtocolVersion != "1" || result.RequestID != request.RequestID ||
		result.HarnessIdentity != p.Harness.BindingID() || result.ObservedModelID != p.ModelID || result.CapabilityFingerprint != p.Harness.CapabilityFingerprint ||
		result.RequestedSamplingSHA256 != s.SHA256 || !task0SameJSON(result.UnsupportedSamplingParameters, s.UnsupportedParameters) || result.RouteRecoveryOccurred ||
		!digest(result.BackendSerializedRequestSHA256) || len(result.RawResponse) < 1 || len(result.RawResponse) > 1024 || len(result.StructuredResponse) > 1024 ||
		result.ResponseSHA256 != inputSHA(result.RawResponse) || observed.IsZero() {
		return modelgateway.Certification{}, ErrTask0
	}
	if !task0ExactEffectiveSampling(s, result.EffectiveSampling) || result.CompletedAt.IsZero() || !observed.Equal(result.CompletedAt) {
		return modelgateway.Certification{}, ErrTask0
	}
	responseRaw := result.RawResponse
	if len(result.StructuredResponse) > 0 {
		responseRaw = result.StructuredResponse
	}
	var response orchestrator.AgentResponse
	if decodeFrozenJSON(responseRaw, 1024, &response) != nil || response.Schema != orchestrator.AgentResponseSchema || response.InvocationID != request.RequestID ||
		response.RunID != request.Invocation.RunID || response.SeatID != entry.Seat || response.SessionID != request.Session.SessionID ||
		response.Metadata.ProtocolVersion != "v1" || response.Metadata.SpeechActionClaim != nil || response.Action != nil || response.Speech == "" {
		return modelgateway.Certification{}, ErrTask0
	}
	tuple, err := modelgateway.BindExecutionTuple(modelgateway.ExecutionTuple{Schema: modelgateway.ExecutionTupleSchema, BackendKind: p.BackendKind, ProviderIdentity: p.ProviderIdentity, ModelID: p.ModelID,
		ModelProfileBinding: p.BindingID(), SamplingProfileBinding: s.BindingID(), RequestedSamplingSHA256: result.RequestedSamplingSHA256, EffectiveSampling: result.EffectiveSampling,
		UnsupportedSamplingParameters: result.UnsupportedSamplingParameters, BackendSerializedRequestSHA256: result.BackendSerializedRequestSHA256, HarnessIdentity: p.Harness.BindingID(), HarnessProtocolIdentity: p.Harness.ProtocolIdentity, HarnessProtocolVersion: p.Harness.ProtocolVersion,
		StructuredOutputMode: p.StructuredOutputMode, ToolCallMode: p.ToolCallMode, RequestContractVersion: "1", CapabilityFingerprint: p.Harness.CapabilityFingerprint,
		EnvironmentIdentity: "AIPT-B007-ACCEPTED-PRIVATE-PREPARATION-V1", LocalRuntimeIdentity: p.LocalRuntimeIdentity})
	if err != nil {
		return modelgateway.Certification{}, ErrTask0
	}
	id, version, ok := strings.Cut(p.CertificationIdentity, "@")
	if !ok {
		return modelgateway.Certification{}, ErrTask0
	}
	eligibility := "NOT_CLAIMED"
	if p.BackendKind == modelgateway.BackendLocalLlamaCPP {
		eligibility = "NOT_GRANTED_DEFER_003"
	}
	cert, err := modelgateway.BindCertification(modelgateway.Certification{Schema: modelgateway.CertificationSchema, CertificationID: id, CertificationVersion: version, ProfileBinding: p.BindingID(), SamplingBinding: s.BindingID(), Result: "PASS",
		Kind: modelgateway.CertificationControlledReal, MinimumCertification: true, RealModelCalls: 1, EvidenceIdentity: "b007-role-cert-" + inputSHA([]byte(request.Invocation.RunID + "\x00" + request.RequestID))[:24],
		ProductionRoleEligibility: eligibility, Claims: task0MinimumClaims(), ExecutionTuple: tuple, ObservedAt: observed.UTC()}, p, s)
	if err != nil {
		return modelgateway.Certification{}, ErrTask0
	}
	return cert, nil
}

func runTask0RoleCertification(ctx context.Context, transport *task0BudgetTransport, entry task0DispatchProfile) (modelgateway.Certification, error) {
	if ctx == nil || ctx.Err() != nil || transport == nil || transport.grant == nil {
		return modelgateway.Certification{}, ErrTask0
	}
	budget, ok := transport.reservations.(*GlobalBudget)
	if !ok || budget.pool == nil || budget.checkRoot() != nil {
		return modelgateway.Certification{}, ErrTask0
	}
	bound, ok := transport.grant.profiles[entry.Profile.BindingID()]
	if !ok || !task0SameJSON(bound, entry) || transport.backend != entry.Profile.BackendKind {
		return modelgateway.Certification{}, ErrTask0
	}
	request, err := task0CertificationRequest(budget.manifest.Manifest.RunID, entry)
	if err != nil {
		return modelgateway.Certification{}, ErrTask0
	}
	cert := modelgateway.Certification{}
	// Intent and terminal observations share one original request ID. Raw
	// model speech and operator paths never enter this control-only ledger.
	appendObservation := func(observationCtx context.Context, kind string, cert modelgateway.Certification) error {
		payload, err := json.Marshal(map[string]any{"schema": "aipt.private.b007-role-certification-observation/v1", "run_id": budget.manifest.Manifest.RunID, "request_id": request.RequestID, "profile_binding": entry.Profile.BindingID(),
			"request_sha256": request.RequestSHA256, "manifest_sha256": transport.grant.binding.ManifestSHA, "event": kind, "certification": cert})
		if err != nil {
			return ErrTask0
		}
		_, err = storagepostgres.Append(observationCtx, budget.pool, storagepostgres.AppendInput{StreamID: "aipt.b007-role-certification:" + budget.manifest.Manifest.RunID, EventID: request.RequestID + "-" + kind, EventType: "AIPT_B007_ROLE_CERTIFICATION_" + kind, PayloadJSON: payload})
		return err
	}
	if appendObservation(ctx, "INTENT", cert) != nil {
		return cert, ErrTask0
	}
	terminalRecorded := false
	defer func() {
		if !terminalRecorded {
			failCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = appendObservation(failCtx, "FAILED_NO_RETRY", modelgateway.Certification{})
		}
	}()
	probe, err := transport.Probe(ctx, entry.Profile, entry.Sampling)
	if err != nil || probe.HarnessIdentity != entry.Profile.Harness.BindingID() || probe.ProtocolIdentity != entry.Profile.Harness.ProtocolIdentity || probe.ProtocolVersion != "1" ||
		probe.ObservedModelID != entry.Profile.ModelID || probe.CapabilityFingerprint != entry.Profile.Harness.CapabilityFingerprint || !probe.RouteAvailable || probe.DirectProviderBypassAvailable {
		return cert, ErrTask0
	}
	result, err := transport.Invoke(ctx, entry.Profile, entry.Sampling, request)
	if err != nil {
		return cert, ErrTask0
	}
	observed := result.CompletedAt.UTC()
	cert, err = task0CertificationFromResult(entry, request, result, observed)
	if err != nil {
		return modelgateway.Certification{}, ErrTask0
	}
	if appendObservation(ctx, "PASS", cert) != nil {
		return modelgateway.Certification{}, ErrTask0
	}
	terminalRecorded = true
	return cert, nil
}
