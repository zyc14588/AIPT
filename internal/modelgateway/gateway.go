package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

// HarnessTransport is the only model execution seam. Implementations speak to
// an external Harness runtime; no transport method exposes a provider or
// llama.cpp inference endpoint to AIPT Core.
type HarnessTransport interface {
	Probe(context.Context, ModelProfile, SamplingProfile) (HarnessProbe, error)
	Invoke(context.Context, ModelProfile, SamplingProfile, HarnessRequest) (HarnessResult, error)
	Recover(context.Context, ModelProfile, orchestrator.Session, orchestrator.RecoveryRequest) error
	Close(context.Context) error
}

type GatewayOptions struct {
	RunID              string
	DiagnosticID       string
	Mode               GatewayMode
	BreakGlass         *BreakGlassGrant
	BreakGlassVerifier BreakGlassVerifier
}

type Gateway struct {
	registry           *Registry
	binding            ManifestBinding
	assignments        map[orchestrator.SeatID]RoleAssignment
	transport          HarnessTransport
	audit              AuditSink
	runID              string
	diagnosticID       string
	breakGlass         *BreakGlassGrant
	breakGlassVerifier breakGlassGrantAuthority
	mode               GatewayMode
	mu                 sync.Mutex
	closeMu            sync.Mutex
	closed             bool
	closeComplete      bool
}

func NewGateway(registry *Registry, binding ManifestBinding, transport HarnessTransport, audit AuditSink, options GatewayOptions) (*Gateway, error) {
	if registry == nil || transport == nil || audit == nil || options.RunID == "" || options.DiagnosticID == "" {
		return nil, newError(CodeInvalidProfile, "new_gateway", options.DiagnosticID, errors.New("registry, transport, run, and diagnostic identities are required"))
	}
	if options.Mode != GatewayModeFormal && options.Mode != GatewayModeDiagnostic {
		return nil, newError(CodeInvalidProfile, "new_gateway", options.DiagnosticID, errors.New("explicit gateway mode required"))
	}
	authoritativeAudit, auditOK := audit.(breakGlassConsumptionAuthority)
	if !auditOK {
		return nil, newError(CodeBreakGlassAudit, "new_gateway", options.DiagnosticID, errors.New("authoritative Run-level model audit sink required"))
	}
	if err := validIdentity("run_id", options.RunID); err != nil {
		return nil, newError(CodeInvalidProfile, "new_gateway", options.DiagnosticID, err)
	}
	if err := validIdentity("diagnostic_id", options.DiagnosticID); err != nil {
		return nil, newError(CodeInvalidProfile, "new_gateway", options.DiagnosticID, err)
	}
	if err := validateManifestBinding(binding); err != nil {
		return nil, err
	}
	if options.RunID != binding.RunID {
		return nil, newError(CodeManifestBindingInvalid, "new_gateway", binding.ManifestID, errors.New("gateway run differs from immutable Manifest binding"))
	}
	if (options.Mode == GatewayModeFormal && (binding.RunClassification != "QUALIFICATION" || !binding.QualificationEligible)) ||
		(options.Mode == GatewayModeDiagnostic && (binding.RunClassification != "DIAGNOSTIC" || binding.QualificationEligible)) {
		return nil, newError(CodeManifestBindingInvalid, "new_gateway", binding.ManifestID, errors.New("gateway mode differs from immutable Run classification"))
	}
	if options.BreakGlass != nil {
		verifier, verifierOK := options.BreakGlassVerifier.(breakGlassGrantAuthority)
		if options.Mode != GatewayModeDiagnostic || !verifierOK {
			return nil, newError(CodeBreakGlassInvalid, "new_gateway", options.DiagnosticID, errors.New("break-glass is diagnostic-only and requires a trusted verifier"))
		}
		grant := *options.BreakGlass
		if err := verifier.Verify(grant); err != nil {
			return nil, err
		}
		if grant.RunID != options.RunID || grant.DiagnosticID != options.DiagnosticID ||
			grant.ManifestSHA256 != binding.ManifestSHA256 {
			return nil, newError(CodeBreakGlassInvalid, "new_gateway", options.DiagnosticID, errors.New("grant run or manifest scope mismatch"))
		}
		options.BreakGlass = &grant
		options.BreakGlassVerifier = verifier
	}
	assignments := make(map[orchestrator.SeatID]RoleAssignment, len(binding.Assignments))
	for _, assignment := range binding.Assignments {
		profile, err := registry.Profile(assignment.ProfileBinding)
		if err != nil {
			return nil, err
		}
		if assignment.SamplingBinding != profile.SamplingProfileID ||
			assignment.BackendKind != profile.BackendKind ||
			assignment.CertificationIdentity != profile.CertificationIdentity {
			return nil, newError(CodeManifestBindingInvalid, "new_gateway", binding.ManifestID, errors.New("role assignment drift"))
		}
		assignments[assignment.SeatID] = assignment
	}
	var trustedVerifier breakGlassGrantAuthority
	if options.BreakGlass != nil {
		trustedVerifier = options.BreakGlassVerifier.(breakGlassGrantAuthority)
	}
	return &Gateway{
		registry: registry, binding: binding, assignments: assignments,
		transport: transport, audit: authoritativeAudit, runID: options.RunID,
		diagnosticID: options.DiagnosticID, mode: options.Mode, breakGlass: options.BreakGlass,
		breakGlassVerifier: trustedVerifier,
	}, nil
}

func validateManifestBinding(binding ManifestBinding) error {
	if binding.Schema != ManifestBindingSchema || binding.ManifestID == "" ||
		binding.RunID == "" || binding.ManifestSHA256 == "" || binding.SHA256 == "" || len(binding.Assignments) == 0 ||
		(binding.RunClassification != "QUALIFICATION" && binding.RunClassification != "DIAGNOSTIC") ||
		(binding.RunClassification == "QUALIFICATION") != binding.QualificationEligible {
		return newError(CodeManifestBindingInvalid, "validate_manifest_binding", binding.ManifestID, errors.New("required binding data missing"))
	}
	if err := validIdentity("run_id", binding.RunID); err != nil {
		return newError(CodeManifestBindingInvalid, "validate_manifest_binding", binding.ManifestID, err)
	}
	if err := validSHA("manifest_sha256", binding.ManifestSHA256); err != nil {
		return newError(CodeManifestBindingInvalid, "validate_manifest_binding", binding.ManifestID, err)
	}
	want := binding.SHA256
	copy := binding
	copy.SHA256 = ""
	got, err := canonicalDigest(copy)
	if err != nil || want != got {
		return newError(CodeManifestImmutable, "validate_manifest_binding", binding.ManifestID, errors.New("binding digest mismatch"))
	}
	seen := map[orchestrator.SeatID]bool{}
	for _, assignment := range binding.Assignments {
		if !baselineSeat(assignment.SeatID) || seen[assignment.SeatID] {
			return newError(CodeManifestBindingInvalid, "validate_manifest_binding", binding.ManifestID, errors.New("seat binding invalid"))
		}
		seen[assignment.SeatID] = true
	}
	return nil
}

func (g *Gateway) assignment(seatID orchestrator.SeatID) (RoleAssignment, ModelProfile, SamplingProfile, error) {
	assignment, exists := g.assignments[seatID]
	if !exists {
		return RoleAssignment{}, ModelProfile{}, SamplingProfile{}, newError(CodeManifestBindingInvalid, "resolve_role_assignment", string(seatID), errors.New("seat assignment missing"))
	}
	profile, err := g.registry.Profile(assignment.ProfileBinding)
	if err != nil {
		return RoleAssignment{}, ModelProfile{}, SamplingProfile{}, err
	}
	sampling, err := g.registry.Sampling(assignment.SamplingBinding)
	if err != nil {
		return RoleAssignment{}, ModelProfile{}, SamplingProfile{}, err
	}
	certification, err := g.registry.Certification(assignment.CertificationIdentity)
	if err != nil || certification.Result != "PASS" || !certification.MinimumCertification {
		if err == nil {
			err = errors.New("certification is not a minimum PASS")
		}
		return RoleAssignment{}, ModelProfile{}, SamplingProfile{}, newError(CodeCertificationMissing, "resolve_role_assignment", assignment.ProfileBinding, err)
	}
	return assignment, profile, sampling, nil
}

func (g *Gateway) ProbeAll(ctx context.Context) ([]HarnessProbe, error) {
	if ctx == nil {
		return nil, newError(CodeHarnessTransport, "probe_all", g.diagnosticID, errors.New("nil context"))
	}
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return nil, newError(CodeHarnessSession, "probe_all", g.diagnosticID, errors.New("gateway closed"))
	}
	seen := map[string]bool{}
	result := make([]HarnessProbe, 0, len(g.assignments))
	for _, seatID := range orchestrator.BaselineSeats() {
		_, profile, sampling, err := g.assignment(seatID)
		if err != nil {
			return nil, err
		}
		if seen[profile.BindingID()] {
			continue
		}
		seen[profile.BindingID()] = true
		probe, err := g.transport.Probe(ctx, profile, sampling)
		if err != nil {
			return nil, err
		}
		if err := validateProbe(profile, probe); err != nil {
			return nil, err
		}
		result = append(result, probe)
	}
	return result, nil
}

func validateProbe(profile ModelProfile, probe HarnessProbe) error {
	if probe.DirectProviderBypassAvailable {
		return newError(CodeDirectProviderBypass, "validate_probe", profile.BindingID(), errors.New("direct bypass advertised"))
	}
	if !probe.RouteAvailable {
		return newError(CodeHarnessTransport, "validate_probe", profile.BindingID(), errors.New("route unavailable"))
	}
	if probe.HarnessIdentity != profile.Harness.BindingID() ||
		probe.ProtocolIdentity != profile.Harness.ProtocolIdentity ||
		probe.ProtocolVersion != profile.Harness.ProtocolVersion ||
		probe.CapabilityFingerprint != profile.Harness.CapabilityFingerprint {
		return newError(CodeHarnessIdentityMismatch, "validate_probe", profile.BindingID(), errors.New("Harness identity drift"))
	}
	if probe.ObservedModelID != "" && probe.ObservedModelID != profile.ModelID {
		return newError(CodeModelIdentityMismatch, "validate_probe", profile.BindingID(), errors.New("observed model drift"))
	}
	return nil
}

func (g *Gateway) Invoke(ctx context.Context, session orchestrator.Session, invocation orchestrator.InvocationRequest) (orchestrator.InvocationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeInvocationTimeout)
	}
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	if session.RunID != g.runID || invocation.RunID != g.runID || session.SeatID != invocation.SeatID ||
		session.SessionID != invocation.SessionID || invocation.Context.RunID != g.runID ||
		invocation.Context.SeatID != invocation.SeatID || invocation.Context.SessionID != session.SessionID {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	assignment, profile, sampling, err := g.assignment(invocation.SeatID)
	if err != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	decision, request, err := buildHarnessRequest(profile, sampling, session, invocation)
	if err != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	deadline := invocation.Deadline
	if deadline.IsZero() {
		deadline = time.Now().UTC().Add(time.Minute)
	}
	callContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	disqualified, err := g.audit.BreakGlassDisqualified(callContext, g.runID, g.diagnosticID)
	if err != nil || (g.mode == GatewayModeFormal && disqualified) {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	breakGlassDigest := ""
	if decision.BreakGlassRequired {
		breakGlassDigest, err = g.consumeBreakGlass(callContext, profile, invocation, request, time.Now().UTC())
		if err != nil {
			return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
		}
		disqualified = true
	}
	result, transportErr := g.transport.Invoke(callContext, profile, sampling, request)
	if transportErr != nil {
		return orchestrator.InvocationResult{}, transportFailure(transportErr)
	}
	if callContext.Err() != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeInvocationTimeout)
	}
	response, err := validateHarnessResult(profile, request, result)
	if err != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	completed := result.CompletedAt.UTC()
	if completed.IsZero() {
		completed = time.Now().UTC()
	}
	persistedDisqualification, err := g.audit.BreakGlassDisqualified(callContext, g.runID, g.diagnosticID)
	if err != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	disqualified = disqualified || persistedDisqualification
	evidence := InvocationEvidence{
		Schema: InvocationEvidenceSchema, DiagnosticID: g.diagnosticID,
		RunID: g.runID, RunClassification: g.binding.RunClassification,
		SeatID: invocation.SeatID, SessionID: session.SessionID,
		InvocationID: invocation.InvocationID, ProfileBinding: assignment.ProfileBinding,
		SamplingBinding: assignment.SamplingBinding, BackendKind: profile.BackendKind,
		ProviderIdentity: profile.ProviderIdentity, ModelID: profile.ModelID,
		HarnessIdentity: profile.Harness.BindingID(), StructuredOutputMode: profile.StructuredOutputMode,
		ToolCallMode: profile.ToolCallMode, ContextHash: invocation.Context.ContextHash,
		RequestSHA256: request.RequestSHA256, ResponseSHA256: result.ResponseSHA256,
		RetryIdentity:         fmt.Sprintf("%s:%d", invocation.Kind, invocation.Attempt),
		CapabilityFingerprint: result.CapabilityFingerprint, CompletedAt: completed,
		CleanBaselineEligible: decision.CleanBaselineEligible && !disqualified && g.binding.CleanBaselineEligible && !result.RouteRecoveryOccurred,
		BreakGlassUsed:        breakGlassDigest != "", BreakGlassGrantSHA256: breakGlassDigest,
	}
	if err := EvidenceSafe(evidence); err != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	if err := g.audit.RecordInvocation(callContext, evidence); err != nil {
		return orchestrator.InvocationResult{}, orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	}
	return orchestrator.InvocationResult{Response: response, CompletedAt: completed}, nil
}

func buildHarnessRequest(
	profile ModelProfile,
	sampling SamplingProfile,
	session orchestrator.Session,
	invocation orchestrator.InvocationRequest,
) (EgressDecision, HarnessRequest, error) {
	decision, err := ValidateEgress(profile, invocation.Context)
	if err != nil {
		return EgressDecision{}, HarnessRequest{}, err
	}
	prepared, reduction, err := PrepareContext(invocation.Context, profile.ContextPolicy)
	if err != nil {
		return EgressDecision{}, HarnessRequest{}, err
	}
	if len(prepared) > sampling.MaxContextTokens {
		return EgressDecision{}, HarnessRequest{}, newError(CodeContextBudgetExceeded, "apply_sampling_context_budget", invocation.InvocationID, errors.New("prepared context exceeds the conservative governed token-equivalent byte ceiling"))
	}
	request := HarnessRequest{
		Schema: HarnessRequestSchema, ProtocolVersion: "1", RequestID: invocation.InvocationID,
		ProfileBinding: profile.BindingID(), SamplingBinding: sampling.BindingID(),
		ExpectedModelID: profile.ModelID, HarnessIdentity: profile.Harness.BindingID(),
		BackendKind: profile.BackendKind, ProviderIdentity: profile.ProviderIdentity,
		StructuredMode: profile.StructuredOutputMode, ToolMode: profile.ToolCallMode,
		SamplingProfile: sampling,
		Session:         session, Invocation: invocation, PreparedContext: prepared, ContextReduction: reduction,
	}
	request.RequestSHA256, err = requestDigest(request)
	if err != nil {
		return EgressDecision{}, HarnessRequest{}, err
	}
	requestBytes, err := json.Marshal(request)
	if err != nil || len(requestBytes) > profile.ContextPolicy.MaxRequestBytes {
		return EgressDecision{}, HarnessRequest{}, newError(CodeContextBudgetExceeded, "build_harness_request", invocation.InvocationID, errors.New("request exceeds governed byte bound"))
	}
	return decision, request, nil
}

func requestDigest(request HarnessRequest) (string, error) {
	request.RequestSHA256 = ""
	return canonicalDigest(request)
}

func validateHarnessResult(profile ModelProfile, request HarnessRequest, result HarnessResult) ([]byte, error) {
	if result.Schema != HarnessResponseSchema || result.ProtocolVersion != "1" || result.RequestID != request.RequestID {
		return nil, newError(CodeHarnessProtocolMismatch, "validate_result", request.RequestID, errors.New("unknown response identity/schema/version"))
	}
	if result.HarnessIdentity != profile.Harness.BindingID() || result.CapabilityFingerprint != profile.Harness.CapabilityFingerprint {
		return nil, newError(CodeHarnessIdentityMismatch, "validate_result", request.RequestID, errors.New("Harness identity drift"))
	}
	if result.ObservedModelID != profile.ModelID {
		return nil, newError(CodeModelIdentityMismatch, "validate_result", request.RequestID, errors.New("model identity drift"))
	}
	if result.RequestedSamplingSHA256 != request.SamplingProfile.SHA256 ||
		strings.Join(result.UnsupportedSamplingParameters, "\x00") != strings.Join(request.SamplingProfile.UnsupportedParameters, "\x00") ||
		validSHA("backend_serialized_request_sha256", result.BackendSerializedRequestSHA256) != nil ||
		validateEffectiveSampling(request.SamplingProfile, result.EffectiveSampling) != nil {
		return nil, newError(CodeSamplingDrift, "validate_effective_sampling", request.RequestID, errors.New("Harness sampling application evidence drift"))
	}
	if len(result.RawResponse) > 1<<20 || len(result.StructuredResponse) > 1<<20 {
		return nil, newError(CodeHarnessFrameTooLarge, "validate_result", request.RequestID, errors.New("response exceeds bound"))
	}
	if len(result.RawResponse) > request.SamplingProfile.MaxOutputTokens ||
		len(result.StructuredResponse) > request.SamplingProfile.MaxOutputTokens {
		return nil, newError(CodeContextBudgetExceeded, "apply_sampling_output_budget", request.RequestID, errors.New("Harness response exceeds the conservative governed token-equivalent byte ceiling"))
	}
	computed := sha256.Sum256(result.RawResponse)
	if result.ResponseSHA256 != hex.EncodeToString(computed[:]) {
		return nil, newError(CodeHarnessResponseInvalid, "validate_result", request.RequestID, errors.New("raw response digest mismatch"))
	}
	response := result.RawResponse
	if profile.StructuredOutputMode == StructuredNative {
		if len(result.StructuredResponse) == 0 {
			return nil, newError(CodeHarnessResponseInvalid, "validate_result", request.RequestID, errors.New("native structured response absent"))
		}
		response = result.StructuredResponse
	} else if len(result.StructuredResponse) != 0 {
		response = result.StructuredResponse
	}
	if len(response) == 0 {
		return nil, newError(CodeHarnessResponseInvalid, "validate_result", request.RequestID, errors.New("empty response"))
	}
	return append([]byte(nil), response...), nil
}

func transportFailure(err error) error {
	switch CodeOf(err) {
	case CodeHarnessTimeout, CodeHarnessCancelled:
		return orchestrator.NewInvocationFailure(orchestrator.CodeInvocationTimeout)
	case CodeHarnessSession, CodeHarnessIdentityMismatch, CodeHarnessProtocolMismatch,
		CodeHarnessResponseInvalid, CodeModelIdentityMismatch:
		return orchestrator.NewInvocationFailure(orchestrator.CodeAgentSessionFailed)
	default:
		return orchestrator.NewInvocationFailure(orchestrator.CodeAgentTransportFailed)
	}
}

func (g *Gateway) Recover(ctx context.Context, session orchestrator.Session, request orchestrator.RecoveryRequest) (orchestrator.Session, error) {
	if ctx == nil || ctx.Err() != nil {
		return orchestrator.Session{}, errors.New("AIPT_MODEL_SESSION_RECOVERY_REJECTED")
	}
	g.mu.Lock()
	closed := g.closed
	g.mu.Unlock()
	if closed {
		return orchestrator.Session{}, errors.New("AIPT_MODEL_SESSION_RECOVERY_REJECTED")
	}
	_, profile, _, err := g.assignment(session.SeatID)
	if err != nil || request.RunID != g.runID || request.SeatID != session.SeatID ||
		request.OldSessionID != session.SessionID || request.RecoveryOrdinal != 1 {
		return orchestrator.Session{}, errors.New("AIPT_MODEL_SESSION_RECOVERY_REJECTED")
	}
	if err := g.transport.Recover(ctx, profile, session, request); err != nil {
		return orchestrator.Session{}, errors.New("AIPT_MODEL_SESSION_RECOVERY_REJECTED")
	}
	seed := sha256.Sum256([]byte(g.runID + "\x00" + string(session.SeatID) + "\x00" + session.SessionID + "\x00" + fmt.Sprint(request.RecoveryOrdinal)))
	return orchestrator.Session{
		Schema:    orchestrator.SessionSchema,
		SessionID: "session-recovered-" + hex.EncodeToString(seed[:8]),
		RunID:     g.runID, SeatID: session.SeatID,
		Generation: session.Generation + 1, ParentSessionID: session.SessionID,
	}, nil
}

func (g *Gateway) Close(ctx context.Context) error {
	g.closeMu.Lock()
	defer g.closeMu.Unlock()
	g.mu.Lock()
	if g.closeComplete {
		g.mu.Unlock()
		return nil
	}
	// Once shutdown starts, no new probe/invoke operation may enter even if
	// transport cleanup needs another attempt. closeComplete, not closed,
	// decides whether the owned transport still needs to be called.
	g.closed = true
	g.mu.Unlock()
	if err := g.transport.Close(ctx); err != nil {
		return err
	}
	g.mu.Lock()
	g.closeComplete = true
	g.mu.Unlock()
	return nil
}
