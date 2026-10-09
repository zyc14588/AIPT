package pilot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/testplan"
)

type task0DispatchProfile struct {
	Seat     orchestrator.SeatID          `json:"seat_id"`
	Profile  modelgateway.ModelProfile    `json:"model_profile"`
	Sampling modelgateway.SamplingProfile `json:"sampling_profile"`
}

// This B007 companion only fixes canonical Base64 context representation;
// the frozen B004 Worker and accepted Q002 Harness remain exact.
const task0ModelWorkerSHA = "acb4852b8a67a3777f1da970f5e8c194169540de42af84e0916e671f3e74e2a5"

// This is a role-specific preparation bound, not the governed upstream wire
// or token ceiling. Q002 still enforces the complete serialized 8192-byte
// request before every send; the global 8192/1024 reservation is unchanged.
func task0RoleContextCeiling(seat orchestrator.SeatID) int {
	if seat == orchestrator.SeatGM {
		return 6150
	}
	return 5500
}

// This private input is authenticated by the preparation executable's build
// binding, after independent review and exact online CI origin acceptance.
// Receipt digests are references to that acceptance, not standalone proof.
type task0DispatchBinding struct {
	Schema             string                    `json:"schema"`
	AuthoritySHA       string                    `json:"authority_sha256"`
	Implementation     testplan.RepositorySource `json:"accepted_implementation"`
	ManifestSHA        string                    `json:"frozen_manifest_sha256"`
	ModelWorkerSHA     string                    `json:"model_worker_sha256"`
	RuntimeManifestSHA string                    `json:"runtime_manifest_sha256"`
	FullReviewSHA      string                    `json:"full_independent_review_sha256"`
	OnlineCIReceiptSHA string                    `json:"immutable_online_ci_receipt_sha256"`
	Proof              WireProof                 `json:"wire_proof"`
	Profiles           []task0DispatchProfile    `json:"role_profiles"`
}

type acceptedTask0DispatchGrant struct {
	identity string
	binding  task0DispatchBinding
	manifest testplan.FrozenManifest
	profiles map[string]task0DispatchProfile
}

func task0GitIdentity(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 20 && hex.EncodeToString(raw) == s
}

func decodeTask0DispatchGrant(raw []byte, expectedSHA string, manifest testplan.FrozenManifest) (*acceptedTask0DispatchGrant, error) {
	var b task0DispatchBinding
	if !digest(expectedSHA) || inputSHA(raw) != expectedSHA || decodeFrozenJSON(raw, 1<<20, &b) != nil ||
		b.Schema != "aipt.private.b007-task0-accepted-dispatch/v1" || b.AuthoritySHA != BudgetAuthority ||
		b.ManifestSHA != hex.EncodeToString(manifest.Digest[:]) || b.ModelWorkerSHA != task0ModelWorkerSHA || !digest(b.RuntimeManifestSHA) || !digest(b.FullReviewSHA) ||
		!digest(b.OnlineCIReceiptSHA) || !task0GitIdentity(b.Implementation.Commit) || !task0GitIdentity(b.Implementation.Tree) ||
		!b.Proof.valid() || b.Proof.CompleteInputCeiling != 8192 || b.Proof.ClosureSHA != b007BundleSHA ||
		b.Proof.ReportSHA != b.FullReviewSHA || len(b.Profiles) != 6 {
		return nil, ErrBudget
	}
	if _, err := task0CoreBinding(manifest, b.Implementation); err != nil {
		return nil, ErrBudget
	}
	frozen, err := testplan.DecodeRunManifest(manifest.Canonical)
	if err != nil {
		return nil, ErrBudget
	}
	g := &acceptedTask0DispatchGrant{identity: expectedSHA, binding: b, manifest: frozen, profiles: map[string]task0DispatchProfile{}}
	remoteSeats := map[orchestrator.SeatID]bool{}
	local := 0
	for _, entry := range b.Profiles {
		p, s := entry.Profile, entry.Sampling
		if _, valid := task0Actor(entry.Seat); !valid || modelgateway.ValidateModelProfile(p) != nil || modelgateway.ValidateSamplingProfile(s) != nil ||
			p.SamplingProfileID != s.BindingID() || s.MaxOutputTokens != 1024 || s.MaxContextTokens != 8192 ||
			p.ContextPolicy.MaxContextBytes > task0RoleContextCeiling(entry.Seat) || p.Harness.RuntimeClosureSHA256 != b007BundleSHA ||
			p.StructuredOutputMode != modelgateway.StructuredPrompted || p.ToolCallMode != modelgateway.ToolCallDisabled ||
			p.DataEgressPolicy.BreakGlassAllowed || !task0MinimumRequirements(p.CapabilityRequirements) || g.profiles[p.BindingID()].Profile.ProfileID != "" {
			return nil, ErrBudget
		}
		classes := map[orchestrator.DataClassification]bool{}
		for _, class := range p.DataEgressPolicy.AllowedClassifications {
			if class != orchestrator.ClassPublic && class != orchestrator.ClassUnreleasedRemoteAllowed && class != orchestrator.ClassTableHiddenRemoteAllowed || classes[class] {
				return nil, ErrBudget
			}
			classes[class] = true
		}
		if len(classes) != 3 {
			return nil, ErrBudget
		}
		switch p.BackendKind {
		case modelgateway.BackendRemoteDeepSeek:
			if p.ModelID != modelgateway.RemoteDeepSeekModelID || remoteSeats[entry.Seat] || p.CredentialReference == nil ||
				p.CredentialReference.Kind != modelgateway.CredentialEnvironment || p.CredentialReference.Locator != "DEEPSEEK_API_KEY" {
				return nil, ErrBudget
			}
			remoteSeats[entry.Seat] = true
		case modelgateway.BackendLocalLlamaCPP:
			if entry.Seat != orchestrator.SeatPlayer1 || p.ModelID != "gguf-04" || p.LocalRuntimeIdentity == nil ||
				p.LocalRuntimeIdentity.GGUFSHA256 != b007GGUFSHA || p.LocalRuntimeIdentity.TemplateSHA256 != b007TemplateSHA {
				return nil, ErrBudget
			}
			local++
		default:
			return nil, ErrBudget
		}
		g.profiles[p.BindingID()] = entry
	}
	if len(remoteSeats) != 5 || local != 1 {
		return nil, ErrBudget
	}
	assignments := map[string]string{}
	for _, assignment := range frozen.Manifest.ModelAssignments {
		if assignments[assignment.AssignmentID] != "" {
			return nil, ErrBudget
		}
		assignments[assignment.AssignmentID] = assignment.ModelProfileID
	}
	seenAssignments := map[string]bool{}
	for _, seat := range frozen.Manifest.SeatRoster {
		entry, ok := g.profiles[assignments[seat.ModelAssignmentID]]
		if !ok || entry.Seat != orchestrator.SeatID(seat.SeatID) || entry.Profile.BackendKind != modelgateway.BackendRemoteDeepSeek || seenAssignments[seat.ModelAssignmentID] {
			return nil, ErrBudget
		}
		seenAssignments[seat.ModelAssignmentID] = true
	}
	return g, nil
}

func task0MinimumRequirements(requirements []modelgateway.CapabilityName) bool {
	if len(requirements) != 3 {
		return false
	}
	wanted := map[modelgateway.CapabilityName]bool{modelgateway.CapabilityBasicCompletion: true, modelgateway.CapabilityStructuredOutputPrompted: true, modelgateway.CapabilityRoleInvocation: true}
	for _, requirement := range requirements {
		if !wanted[requirement] {
			return false
		}
		delete(wanted, requirement)
	}
	return len(wanted) == 0
}

type task0ReservationStore interface {
	ReserveRemote(context.Context, string, WireProof) error
	ReserveLocal(context.Context, string, WireProof) error
}

// Only the concrete accepted adapter and concrete database budget enter the
// production constructor. The interfaces below support model-free fixtures
// inside this package; they are never launch options or public constructors.
type task0BudgetTransport struct {
	mu           sync.Mutex
	upstream     modelgateway.HarnessTransport
	reservations task0ReservationStore
	grant        *acceptedTask0DispatchGrant
	backend      modelgateway.BackendKind
	local        *preparedPilotLocal
	closed       bool
}

func task0CheckBudgetTransport(ctx context.Context, budget *GlobalBudget, grant *acceptedTask0DispatchGrant) error {
	if ctx == nil || ctx.Err() != nil || budget == nil || budget.pool == nil || grant == nil ||
		!digest(grant.identity) || budget.checkRoot() != nil || !bytes.Equal(budget.manifest.Canonical, grant.manifest.Canonical) || budget.manifest.Digest != grant.manifest.Digest {
		return ErrBudget
	}
	if _, err := budget.Totals(ctx); err != nil {
		return ErrBudget
	}
	return nil
}

func newTask0BudgetTransport(ctx context.Context, budget *GlobalBudget, adapter *task0FrozenRemoteTransport, grant *acceptedTask0DispatchGrant) (*task0BudgetTransport, error) {
	if adapter == nil || task0CheckBudgetTransport(ctx, budget, grant) != nil {
		return nil, ErrBudget
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.closed || adapter.grant != grant || adapter.lifetime == nil || adapter.lifetime.Err() != nil || len(adapter.routes) != 5 {
		return nil, ErrBudget
	}
	return &task0BudgetTransport{upstream: adapter, reservations: budget, grant: grant, backend: modelgateway.BackendRemoteDeepSeek}, nil
}

func newTask0LocalBudgetTransport(ctx context.Context, budget *GlobalBudget, local *preparedPilotLocal, grant *acceptedTask0DispatchGrant) (*task0BudgetTransport, error) {
	if local == nil {
		return nil, ErrBudget
	}
	local.mu.Lock()
	defer local.mu.Unlock()
	if local.grant == nil || local.transport == nil || local.revoked || grant == nil || budget == nil {
		return nil, ErrBudget
	}
	entry, ok := grant.profiles[local.grant.binding.Profile.BindingID()]
	binding := local.grant.binding
	if !ok || entry.Profile.BackendKind != modelgateway.BackendLocalLlamaCPP || !task0SameJSON(entry.Profile, binding.Profile) || !task0SameJSON(entry.Sampling, binding.Sampling) ||
		binding.Adapter.AdapterEntrypointSHA256 != task0ModelWorkerSHA ||
		binding.FullIndependentReviewSHA256 != grant.binding.FullReviewSHA || binding.ImmutableOnlineCIReceiptSHA256 != grant.binding.OnlineCIReceiptSHA ||
		binding.RuntimeManifestSHA256 != grant.binding.RuntimeManifestSHA || binding.AcceptedImplementationCommit != grant.binding.Implementation.Commit {
		return nil, ErrBudget
	}
	if task0CheckBudgetTransport(ctx, budget, grant) != nil {
		return nil, ErrBudget
	}
	t := &task0BudgetTransport{upstream: local.transport, reservations: budget, grant: grant, backend: modelgateway.BackendLocalLlamaCPP, local: local}
	return t, nil
}

func task0SameJSON(a, b any) bool {
	x, xe := json.Marshal(a)
	y, ye := json.Marshal(b)
	return xe == nil && ye == nil && bytes.Equal(x, y)
}

func (t *task0BudgetTransport) boundProfile(p modelgateway.ModelProfile, s modelgateway.SamplingProfile) (task0DispatchProfile, bool) {
	if t == nil || t.grant == nil || t.upstream == nil || t.reservations == nil || t.closed {
		return task0DispatchProfile{}, false
	}
	entry, ok := t.grant.profiles[p.BindingID()]
	return entry, ok && entry.Profile.BackendKind == t.backend && task0SameJSON(entry.Profile, p) && task0SameJSON(entry.Sampling, s)
}

func (t *task0BudgetTransport) Probe(ctx context.Context, p modelgateway.ModelProfile, s modelgateway.SamplingProfile) (modelgateway.HarnessProbe, error) {
	if t == nil || ctx == nil || ctx.Err() != nil {
		return modelgateway.HarnessProbe{}, ErrBudget
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.boundProfile(p, s); !ok {
		return modelgateway.HarnessProbe{}, ErrBudget
	}
	return t.upstream.Probe(ctx, p, s)
}

func (t *task0BudgetTransport) Invoke(ctx context.Context, p modelgateway.ModelProfile, s modelgateway.SamplingProfile, request modelgateway.HarnessRequest) (modelgateway.HarnessResult, error) {
	if t == nil || ctx == nil || ctx.Err() != nil {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.boundProfile(p, s)
	if !ok || !runPattern.MatchString(request.RequestID) || request.Schema != modelgateway.HarnessRequestSchema || request.ProtocolVersion != "1" ||
		request.ProfileBinding != p.BindingID() || request.SamplingBinding != s.BindingID() || request.ExpectedModelID != p.ModelID ||
		request.HarnessIdentity != p.Harness.BindingID() || request.BackendKind != p.BackendKind || request.ProviderIdentity != p.ProviderIdentity ||
		request.StructuredMode != p.StructuredOutputMode || request.ToolMode != p.ToolCallMode || !task0SameJSON(request.SamplingProfile, s) ||
		request.Session.Schema != orchestrator.SessionSchema || request.Session.Generation != 1 || request.Session.ParentSessionID != "" ||
		request.Session.RunID != t.grant.manifest.Manifest.RunID || request.Session.SeatID != entry.Seat ||
		request.Invocation.Kind != orchestrator.InvocationOriginal || request.Invocation.Attempt != 1 ||
		request.Invocation.InvocationID != request.RequestID || request.Invocation.SessionID != request.Session.SessionID ||
		request.Invocation.RunID != request.Session.RunID || request.Invocation.SeatID != entry.Seat ||
		request.Invocation.Context.RunID != request.Session.RunID || request.Invocation.Context.SessionID != request.Session.SessionID ||
		request.Invocation.Context.SeatID != entry.Seat || orchestrator.ValidateContextHash(request.Invocation.Context) != nil {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	if _, err := modelgateway.ValidateEgress(p, request.Invocation.Context); err != nil {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	prepared, reduction, err := modelgateway.PrepareContext(request.Invocation.Context, p.ContextPolicy)
	if err != nil || !bytes.Equal(prepared, request.PreparedContext) || !task0SameJSON(reduction, request.ContextReduction) || len(prepared) > s.MaxContextTokens {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	want := request.RequestSHA256
	request.RequestSHA256 = ""
	raw, err := json.Marshal(request)
	_, canonErr := protocol.CanonicalJSON(raw)
	request.RequestSHA256 = want
	complete, marshalErr := json.Marshal(request)
	// Preserve B004's exact typed JSON serialization digest. Its profile and
	// request identities do not use the Run Core canonical-key encoding.
	if err != nil || canonErr != nil || !digest(want) || inputSHA(raw) != want || marshalErr != nil || len(complete) > p.ContextPolicy.MaxRequestBytes {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	if p.BackendKind == modelgateway.BackendRemoteDeepSeek {
		err = t.reservations.ReserveRemote(ctx, request.RequestID, t.grant.binding.Proof)
	} else if p.BackendKind == modelgateway.BackendLocalLlamaCPP {
		err = t.reservations.ReserveLocal(ctx, request.RequestID, t.grant.binding.Proof)
	} else {
		err = ErrBudget
	}
	if err != nil || ctx.Err() != nil {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	// Concrete production construction always carries the database budget.
	// Package-private NON_CANON reservation fixtures own no body persistence.
	captureBudget, capture := t.reservations.(*GlobalBudget)
	if capture && task0CaptureModelIntent(captureBudget, t.grant, request) != nil {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	// No release, refund, recovery, second transport or retry follows this
	// committed reservation, including cancelled and uncertain responses.
	result, err := t.upstream.Invoke(ctx, p, s, request)
	if err != nil {
		if capture {
			_ = task0CaptureModelTerminal(captureBudget, t.grant, request, nil)
		}
		return modelgateway.HarnessResult{}, err
	}
	if capture && task0CaptureModelTerminal(captureBudget, t.grant, request, &result) != nil {
		return modelgateway.HarnessResult{}, ErrBudget
	}
	if t.backend == modelgateway.BackendLocalLlamaCPP {
		if t.local == nil {
			return modelgateway.HarnessResult{}, ErrBudget
		}
		proof, err := t.local.readNativeProof(ctx)
		if err != nil || p.LocalRuntimeIdentity == nil || validateCompletedNativeProof(proof, t.grant.binding.RuntimeManifestSHA, p.LocalRuntimeIdentity.BinarySHA256, result.BackendSerializedRequestSHA256) != nil {
			return modelgateway.HarnessResult{}, ErrNativeInputProof
		}
		budget, ok := t.reservations.(*GlobalBudget)
		if !ok || budget.checkRoot() != nil || persistTask0PrivateRecord(budget, "task0-native-input-proof.private.jsonl", proof) != nil {
			return modelgateway.HarnessResult{}, ErrNativeInputProof
		}
	}
	return result, nil
}

func (t *task0BudgetTransport) Recover(context.Context, modelgateway.ModelProfile, orchestrator.Session, orchestrator.RecoveryRequest) error {
	return ErrBudget
}

func (t *task0BudgetTransport) Close(ctx context.Context) error {
	if t == nil || ctx == nil {
		return ErrBudget
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.upstream == nil {
		return nil
	}
	return t.upstream.Close(ctx)
}
