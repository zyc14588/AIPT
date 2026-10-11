package pilot

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// NON_CANON profile and dispatch fixtures use no credentials, adapters,
// registered runtime, actual database claim or provider requests.
func task0DispatchProfileFixture(t *testing.T, seat orchestrator.SeatID, local bool) task0DispatchProfile {
	t.Helper()
	id := "NON-CANON-remote-" + string(seat)
	if local {
		id = "NON-CANON-local"
	}
	sampling, err := modelgateway.BindSamplingProfile(modelgateway.SamplingProfile{Schema: modelgateway.SamplingProfileSchema,
		SamplingID: id + "-sampling", SamplingVersion: "1.0.0", TopP: 1, MaxOutputTokens: 1024, MaxContextTokens: 8192,
		AppliedParameters: []string{"max_context_tokens", "max_output_tokens"}, UnsupportedParameters: []string{"temperature", "top_p"}})
	if err != nil {
		t.Fatal(err)
	}
	p := modelgateway.ModelProfile{Schema: modelgateway.ModelProfileSchema, ProfileID: id, ProfileVersion: "1.0.0",
		BackendKind: modelgateway.BackendRemoteDeepSeek, ProviderIdentity: "deepseek-official", ModelID: modelgateway.RemoteDeepSeekModelID,
		Harness: modelgateway.HarnessIdentity{Implementation: "deepseek-harness", Version: "0.1.0-rc.8", Commit: "141eb6fef83422698aef7a981029e843e8161534",
			PackageSHA256: strings.Repeat("1", 64), ProtocolIdentity: modelgateway.HarnessProtocolACP, ProtocolVersion: "1", CapabilityFingerprint: strings.Repeat("2", 64),
			RuntimeClosureKind: modelgateway.HarnessRuntimeClosureKind, RuntimeClosureSHA256: b007BundleSHA},
		SamplingProfileID: sampling.BindingID(), StructuredOutputMode: modelgateway.StructuredPrompted, ToolCallMode: modelgateway.ToolCallDisabled,
		ContextPolicy: modelgateway.ContextPolicy{PolicyID: id + "-context", PolicyVersion: "1.0.0", MaxRequestBytes: 262144, MaxContextBytes: task0RoleContextCeiling(seat), ReductionPolicyID: "AIPT_CONTEXT_BUDGET_REDUCE_V1"},
		DataEgressPolicy: modelgateway.DataEgressPolicy{PolicyID: id + "-egress", PolicyVersion: "1.0.0", AllowedClassifications: []orchestrator.DataClassification{
			orchestrator.ClassPublic, orchestrator.ClassUnreleasedRemoteAllowed, orchestrator.ClassTableHiddenRemoteAllowed}},
		CredentialReference:    &modelgateway.CredentialReference{ReferenceID: "NON-CANON-no-credentials", Kind: modelgateway.CredentialEnvironment, Locator: "DEEPSEEK_API_KEY"},
		CapabilityRequirements: []modelgateway.CapabilityName{modelgateway.CapabilityBasicCompletion, modelgateway.CapabilityStructuredOutputPrompted, modelgateway.CapabilityRoleInvocation},
		CertificationIdentity:  id + "-certification@1.0.0"}
	if local {
		args, err := modelgateway.GovernedLaunchParameters(b007NativeArguments)
		if err != nil {
			t.Fatal(err)
		}
		p.BackendKind, p.ProviderIdentity, p.ModelID, p.CredentialReference = modelgateway.BackendLocalLlamaCPP, "llama.cpp", "gguf-04", nil
		p.LocalRuntimeIdentity = &modelgateway.LocalRuntimeIdentity{ExecutableReference: "NON-CANON-native", BinarySHA256: strings.Repeat("3", 64), Version: "1.0.0", Commit: strings.Repeat("4", 40),
			GGUFReference: "NON-CANON-GGUF", GGUFSHA256: b007GGUFSHA, GGUFModelIdentity: "NON-CANON", QuantizationIdentity: "Q8_0", TemplateIdentity: "NON-CANON-template", TemplateSHA256: b007TemplateSHA,
			IsolationIdentity: modelgateway.LocalIsolationIdentity, IsolationHelperReference: "NON-CANON-helper", IsolationHelperSHA256: strings.Repeat("5", 64), LaunchParameters: args,
			Hardware: modelgateway.HardwareIdentity{Architecture: "amd64", CPUClass: "NON-CANON", GPUBackend: "none", MemoryClass: "NON-CANON"}}
	}
	p, err = modelgateway.BindModelProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	return task0DispatchProfile{seat, p, sampling}
}

func task0DispatchBindingFixture(t *testing.T) (task0DispatchBinding, testplan.FrozenManifest) {
	t.Helper()
	f := task0ManifestFixture(t)
	m := f.Manifest
	m.ModelAssignments = nil
	b := task0DispatchBinding{Schema: "aipt.private.b007-task0-accepted-dispatch/v1", AuthoritySHA: BudgetAuthority, Implementation: m.Source.AIPT,
		ModelWorkerSHA:     task0ModelWorkerSHA,
		RuntimeManifestSHA: strings.Repeat("a", 64), FullReviewSHA: strings.Repeat("b", 64), OnlineCIReceiptSHA: strings.Repeat("c", 64),
		Proof: WireProof{"141eb6fef83422698aef7a981029e843e8161534", b007BundleSHA, strings.Repeat("b", 64), 8192, 1024, 1, true}}
	for i, seat := range orchestrator.BaselineSeats() {
		entry := task0DispatchProfileFixture(t, seat, false)
		b.Profiles = append(b.Profiles, entry)
		assignment := "NON-CANON-assignment-" + string(seat)
		m.ModelAssignments = append(m.ModelAssignments, testplan.ModelAssignment{AssignmentID: assignment, ModelProfileID: entry.Profile.BindingID()})
		m.SeatRoster[i].ModelAssignmentID = assignment
	}
	b.Profiles = append(b.Profiles, task0DispatchProfileFixture(t, orchestrator.SeatPlayer1, true))
	m.CanonicalSHA256 = ""
	var err error
	f, err = testplan.BindRunManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	b.ManifestSHA = hex.EncodeToString(f.Digest[:])
	return b, f
}

func TestTask0DispatchGrantPinsSixIndependentProfilesAndExactManifest(t *testing.T) {
	for _, scenario := range []string{"valid", "changed_digest", "missing_review", "missing_ci", "another_implementation", "small_claimed_wire_cap", "wrong_closure", "wrong_worker", "missing_role", "foreign_class", "profile_without_manifest_assignment", "wrong_profile_seat", "extra_local", "duplicate_profile"} {
		t.Run(scenario, func(t *testing.T) {
			b, f := task0DispatchBindingFixture(t)
			switch scenario {
			case "missing_review":
				b.FullReviewSHA = ""
			case "missing_ci":
				b.OnlineCIReceiptSHA = ""
			case "another_implementation":
				b.Implementation.Commit = strings.Repeat("d", 40)
			case "small_claimed_wire_cap":
				b.Proof.CompleteInputCeiling = 1000
			case "wrong_closure":
				b.Proof.ClosureSHA = strings.Repeat("e", 64)
			case "wrong_worker":
				b.ModelWorkerSHA = strings.Repeat("1", 64)
			case "missing_role":
				b.Profiles = b.Profiles[1:]
			case "foreign_class":
				b.Profiles[0].Profile.DataEgressPolicy.AllowedClassifications[0] = orchestrator.ClassHumanPrivateData
				b.Profiles[0].Profile, _ = modelgateway.BindModelProfile(b.Profiles[0].Profile)
			case "profile_without_manifest_assignment":
				b.Profiles[0].Profile.ProfileID += "-other"
				b.Profiles[0].Profile, _ = modelgateway.BindModelProfile(b.Profiles[0].Profile)
			case "wrong_profile_seat":
				b.Profiles[0].Seat, b.Profiles[1].Seat = b.Profiles[1].Seat, b.Profiles[0].Seat
			case "extra_local":
				b.Profiles[4] = task0DispatchProfileFixture(t, orchestrator.SeatPlayer4, true)
			case "duplicate_profile":
				b.Profiles[4] = b.Profiles[3]
			}
			raw, _ := json.Marshal(b)
			digest := inputSHA(raw)
			if scenario == "changed_digest" {
				digest = strings.Repeat("f", 64)
			}
			_, err := decodeTask0DispatchGrant(raw, digest, f)
			if (err == nil) != (scenario == "valid") {
				t.Fatal("dispatch grant acceptance differs", scenario, err)
			}
		})
	}
}

type task0DispatchTestBudget struct {
	seen  map[string]bool
	order *[]string
	deny  bool
}

func (b *task0DispatchTestBudget) reserve(id, kind string) error {
	*b.order = append(*b.order, "reserve-"+kind)
	if b.deny || b.seen[id] {
		return ErrBudget
	}
	b.seen[id] = true
	return nil
}
func (b *task0DispatchTestBudget) ReserveRemote(_ context.Context, id string, _ WireProof) error {
	return b.reserve(id, "remote")
}
func (b *task0DispatchTestBudget) ReserveLocal(_ context.Context, id string, _ WireProof) error {
	return b.reserve(id, "local")
}

type task0DispatchTestTransport struct {
	order *[]string
	fail  bool
}

func (t *task0DispatchTestTransport) Probe(context.Context, modelgateway.ModelProfile, modelgateway.SamplingProfile) (modelgateway.HarnessProbe, error) {
	return modelgateway.HarnessProbe{}, nil
}
func (t *task0DispatchTestTransport) Invoke(context.Context, modelgateway.ModelProfile, modelgateway.SamplingProfile, modelgateway.HarnessRequest) (modelgateway.HarnessResult, error) {
	*t.order = append(*t.order, "wire")
	if t.fail {
		return modelgateway.HarnessResult{}, errors.New("NON_CANON_UNCERTAIN_DISPATCH")
	}
	return modelgateway.HarnessResult{}, nil
}
func (*task0DispatchTestTransport) Recover(context.Context, modelgateway.ModelProfile, orchestrator.Session, orchestrator.RecoveryRequest) error {
	panic("recovery must never execute")
}
func (*task0DispatchTestTransport) Close(context.Context) error { return nil }

func task0DispatchRequestFixture(t *testing.T) (*task0BudgetTransport, task0DispatchProfile, modelgateway.HarnessRequest, *[]string) {
	t.Helper()
	_, session, invocation, _ := task0ModelFrameFixture(t)
	entry := task0DispatchProfileFixture(t, session.SeatID, false)
	prepared, reduction, err := modelgateway.PrepareContext(invocation.Context, entry.Profile.ContextPolicy)
	if err != nil {
		t.Fatal(err)
	}
	p, s := entry.Profile, entry.Sampling
	req := modelgateway.HarnessRequest{Schema: modelgateway.HarnessRequestSchema, ProtocolVersion: "1", RequestID: invocation.InvocationID,
		ProfileBinding: p.BindingID(), SamplingBinding: s.BindingID(), ExpectedModelID: p.ModelID, HarnessIdentity: p.Harness.BindingID(), BackendKind: p.BackendKind,
		ProviderIdentity: p.ProviderIdentity, StructuredMode: p.StructuredOutputMode, ToolMode: p.ToolCallMode, SamplingProfile: s, Session: session, Invocation: invocation,
		PreparedContext: prepared, ContextReduction: reduction}
	raw, _ := json.Marshal(req)
	req.RequestSHA256 = inputSHA(raw)
	order := []string{}
	grant := &acceptedTask0DispatchGrant{manifest: testplan.FrozenManifest{Manifest: testplan.RunManifest{RunID: session.RunID}}, profiles: map[string]task0DispatchProfile{p.BindingID(): entry},
		binding: task0DispatchBinding{Proof: WireProof{"141eb6fef83422698aef7a981029e843e8161534", b007BundleSHA, strings.Repeat("a", 64), 8192, 1024, 1, true}}}
	transport := &task0BudgetTransport{grant: grant, backend: modelgateway.BackendRemoteDeepSeek, reservations: &task0DispatchTestBudget{seen: map[string]bool{}, order: &order}, upstream: &task0DispatchTestTransport{order: &order}}
	return transport, entry, req, &order
}

func TestTask0DispatchReservesBeforeWireAndRetainsUncertainAttempt(t *testing.T) {
	transport, entry, req, order := task0DispatchRequestFixture(t)
	transport.upstream.(*task0DispatchTestTransport).fail = true
	if _, err := transport.Invoke(context.Background(), entry.Profile, entry.Sampling, req); err == nil {
		t.Fatal("uncertain fixture response accepted")
	}
	if strings.Join(*order, ",") != "reserve-remote,wire" {
		t.Fatal("wire preceded durable reservation")
	}
	if _, err := transport.Invoke(context.Background(), entry.Profile, entry.Sampling, req); err == nil {
		t.Fatal("same uncertain attempt was retried")
	}
	if strings.Join(*order, ",") != "reserve-remote,wire,reserve-remote" {
		t.Fatal("duplicate dispatched a second request")
	}
	if err := transport.Recover(context.Background(), entry.Profile, req.Session, orchestrator.RecoveryRequest{}); err == nil {
		t.Fatal("automatic recovery authorized")
	}
}

func TestTask0DispatchRejectsUnboundOrAlteredRequestBeforeReservation(t *testing.T) {
	for _, scenario := range []string{"profile", "sampling", "run", "seat", "invocation", "request_digest", "prepared", "context_hash", "reduction", "retry", "session_generation", "closed", "budget_denied"} {
		t.Run(scenario, func(t *testing.T) {
			transport, entry, req, order := task0DispatchRequestFixture(t)
			switch scenario {
			case "profile":
				entry.Profile.ModelID = "another-model"
			case "sampling":
				entry.Sampling.MaxOutputTokens++
			case "run":
				req.Session.RunID += "-other"
			case "seat":
				req.Session.SeatID = orchestrator.SeatPlayer2
			case "invocation":
				req.Invocation.InvocationID += "-other"
			case "request_digest":
				req.RequestSHA256 = strings.Repeat("a", 64)
			case "prepared":
				req.PreparedContext = []byte(`{"NON_CANON":true}`)
			case "context_hash":
				req.Invocation.Context.ContextHash = strings.Repeat("b", 64)
			case "reduction":
				req.ContextReduction.PreparedBytes++
			case "retry":
				req.Invocation.Attempt = 2
			case "session_generation":
				req.Session.Generation = 2
			case "closed":
				transport.Close(context.Background())
			case "budget_denied":
				transport.reservations.(*task0DispatchTestBudget).deny = true
			}
			if _, err := transport.Invoke(context.Background(), entry.Profile, entry.Sampling, req); err == nil {
				t.Fatal("invalid request was dispatched")
			}
			want := ""
			if scenario == "budget_denied" {
				want = "reserve-remote"
			}
			if strings.Join(*order, ",") != want {
				t.Fatal("rejected request invoked reservation or wire unexpectedly", *order)
			}
		})
	}
}
