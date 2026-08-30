package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const fixtureHarnessCommit = "141eb6fef83422698aef7a981029e843e8161534"

func fixtureSHA(marker string) string {
	digest := sha256.Sum256([]byte(marker))
	return hex.EncodeToString(digest[:])
}

func fixtureHarness() HarnessIdentity {
	return HarnessIdentity{
		Implementation: "deepseek-harness", Version: "0.1.0-rc.8", Commit: fixtureHarnessCommit,
		PackageSHA256:    fixtureSHA("deepseek-harness-rc8-package"),
		ProtocolIdentity: HarnessProtocolACP, ProtocolVersion: HarnessProtocolVersionACP,
		CapabilityFingerprint: fixtureSHA("deepseek-harness-rc8-acp-capabilities"),
	}
}

func fixtureSampling(t *testing.T, id string) SamplingProfile {
	t.Helper()
	profile, err := BindSamplingProfile(SamplingProfile{
		Schema: SamplingProfileSchema, SamplingID: id, SamplingVersion: "1.0.0",
		Temperature: 0.2, TopP: 0.9, MaxOutputTokens: 1024, MaxContextTokens: 8192,
		// ACP v1 does not expose temperature/top_p/seed application. They remain
		// desired governed values without a false backend-application claim.
		AppliedParameters: []string{"max_context_tokens", "max_output_tokens"},
	})
	if err != nil {
		t.Fatalf("BindSamplingProfile: %v", err)
	}
	return profile
}

func fixtureLocalIdentity(t *testing.T, binaryDigest, ggufDigest, templateDigest string) *LocalRuntimeIdentity {
	t.Helper()
	parameters, err := GovernedLaunchParameters([]string{"--ctx-size", "8192", "--n-predict", "1024"})
	if err != nil {
		t.Fatalf("GovernedLaunchParameters: %v", err)
	}
	return &LocalRuntimeIdentity{
		ExecutableReference: "llama-server-registered-v1", BinarySHA256: binaryDigest,
		Version: "1.0.0", Commit: strings.Repeat("2", 40),
		GGUFReference: "operator-selected-gguf-v1", GGUFSHA256: ggufDigest,
		GGUFModelIdentity: "fixture-local-model-v1", QuantizationIdentity: "Q4_K_M",
		TemplateIdentity: "registered-chat-template-v1", TemplateSHA256: templateDigest,
		LaunchParameters: parameters,
		Hardware: HardwareIdentity{
			Architecture: "amd64", CPUClass: "synthetic-ci", GPUBackend: "none", MemoryClass: "ci-bounded",
		},
	}
}

func fixtureProfile(t *testing.T, seat orchestrator.SeatID, backend BackendKind, sampling SamplingProfile, certificationID string) ModelProfile {
	t.Helper()
	role := strings.ToLower(strings.ReplaceAll(string(seat), "_", "-"))
	profile := ModelProfile{
		Schema: ModelProfileSchema, ProfileID: "model-" + role, ProfileVersion: "1.0.0",
		BackendKind: backend, Harness: fixtureHarness(), SamplingProfileID: sampling.BindingID(),
		StructuredOutputMode: StructuredPrompted, ToolCallMode: ToolCallDisabled,
		ContextPolicy: ContextPolicy{
			PolicyID: "context-" + role, PolicyVersion: "1.0.0", MaxRequestBytes: 1 << 20,
			MaxContextBytes: 64 << 10, ReductionPolicyID: "AIPT_CONTEXT_BUDGET_REDUCE_V1",
		},
		DataEgressPolicy: DataEgressPolicy{
			PolicyID: "egress-" + role, PolicyVersion: "1.0.0",
			AllowedClassifications: []orchestrator.DataClassification{
				orchestrator.ClassPublic, orchestrator.ClassUnreleasedRemoteAllowed,
				orchestrator.ClassTableHiddenRemoteAllowed,
			},
		},
		CapabilityRequirements: []CapabilityName{
			CapabilityBasicCompletion, CapabilityStructuredOutputPrompted, CapabilityContextBudget,
			CapabilityRoleInvocation, CapabilityVisibilityPolicyCompatible,
			CapabilityPromptInjectionBoundaryCompatible,
		},
		CertificationIdentity: certificationID,
	}
	if backend == BackendRemoteDeepSeek {
		profile.ProviderIdentity = "deepseek-official"
		profile.ModelID = RemoteDeepSeekModelID
		profile.CredentialReference = &CredentialReference{
			ReferenceID: "deepseek-controlled-reference-v1", Kind: CredentialEnvironment,
			Locator: "AIPT_DEEPSEEK_CONTROLLED_KEY",
		}
	} else {
		profile.ProviderIdentity = "llama.cpp"
		profile.ModelID = "fixture-local-model-v1"
		profile.DataEgressPolicy.AllowedClassifications = append(
			profile.DataEgressPolicy.AllowedClassifications,
			orchestrator.ClassLocalOnlySecret, orchestrator.ClassSystemInternal,
		)
		profile.LocalRuntimeIdentity = fixtureLocalIdentity(
			t, fixtureSHA("fixture-llama-binary"), fixtureSHA("fixture-gguf"), fixtureSHA("fixture-template"),
		)
	}
	bound, err := BindModelProfile(profile)
	if err != nil {
		t.Fatalf("BindModelProfile: %v", err)
	}
	return bound
}

func fixtureClaims() []CapabilityClaim {
	statuses := map[CapabilityName]ClaimStatus{
		CapabilityBasicCompletion:                   ClaimCertified,
		CapabilityStructuredOutputNative:            ClaimNotCertified,
		CapabilityStructuredOutputPrompted:          ClaimCertified,
		CapabilityStructuredOutputRepair:            ClaimUntested,
		CapabilityToolCallNative:                    ClaimNotCertified,
		CapabilityToolCallEmulated:                  ClaimUntested,
		CapabilityContextBudget:                     ClaimCertified,
		CapabilityRoleInvocation:                    ClaimCertified,
		CapabilityTransportStability:                ClaimCertified,
		CapabilityVisibilityPolicyCompatible:        ClaimCertified,
		CapabilityPromptInjectionBoundaryCompatible: ClaimCertified,
	}
	order := []CapabilityName{
		CapabilityBasicCompletion, CapabilityStructuredOutputNative,
		CapabilityStructuredOutputPrompted, CapabilityStructuredOutputRepair,
		CapabilityToolCallNative, CapabilityToolCallEmulated, CapabilityContextBudget,
		CapabilityRoleInvocation, CapabilityTransportStability,
		CapabilityVisibilityPolicyCompatible, CapabilityPromptInjectionBoundaryCompatible,
	}
	claims := make([]CapabilityClaim, 0, len(order))
	for _, capability := range order {
		claims = append(claims, CapabilityClaim{Name: capability, Status: statuses[capability]})
	}
	return claims
}

func fixtureCertification(t *testing.T, profile ModelProfile, sampling SamplingProfile, id string, kind CertificationKind) Certification {
	t.Helper()
	tuple, err := BindExecutionTuple(ExecutionTuple{
		Schema: ExecutionTupleSchema, BackendKind: profile.BackendKind,
		ProviderIdentity: profile.ProviderIdentity, ModelID: profile.ModelID,
		ModelProfileBinding: profile.BindingID(), SamplingProfileBinding: sampling.BindingID(),
		HarnessIdentity: profile.Harness.BindingID(), HarnessProtocolIdentity: profile.Harness.ProtocolIdentity,
		HarnessProtocolVersion: profile.Harness.ProtocolVersion,
		StructuredOutputMode:   profile.StructuredOutputMode, ToolCallMode: profile.ToolCallMode,
		RequestContractVersion: "1", CapabilityFingerprint: profile.Harness.CapabilityFingerprint,
		EnvironmentIdentity: "synthetic-public-ci-v1", LocalRuntimeIdentity: profile.LocalRuntimeIdentity,
	})
	if err != nil {
		t.Fatalf("BindExecutionTuple: %v", err)
	}
	realCalls := 0
	if kind == CertificationControlledReal {
		realCalls = 1
	}
	eligibility := "NOT_CLAIMED"
	if profile.BackendKind == BackendLocalLlamaCPP {
		eligibility = "NOT_GRANTED_DEFER_003"
	}
	certification, err := BindCertification(Certification{
		Schema: CertificationSchema, CertificationID: id, CertificationVersion: "1.0.0",
		ProfileBinding: profile.BindingID(), SamplingBinding: sampling.BindingID(),
		Result: "PASS", Kind: kind, MinimumCertification: true, RealModelCalls: realCalls,
		EvidenceIdentity: "evidence-" + id, ProductionRoleEligibility: eligibility,
		Claims: fixtureClaims(), ExecutionTuple: tuple,
		ObservedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}, profile, sampling)
	if err != nil {
		t.Fatalf("BindCertification: %v", err)
	}
	return certification
}

type gatewayFixture struct {
	registry       *Registry
	profiles       []ModelProfile
	samplings      []SamplingProfile
	certifications []Certification
	binding        ManifestBinding
	frozen         testplan.FrozenManifest
}

func newGatewayFixture(t *testing.T, backend BackendKind) gatewayFixture {
	t.Helper()
	seats := orchestrator.BaselineSeats()
	samplings := make([]SamplingProfile, 0, len(seats))
	profiles := make([]ModelProfile, 0, len(seats))
	certifications := make([]Certification, 0, len(seats))
	assignments := make([]testplan.ModelAssignment, 0, len(seats))
	roster := make([]testplan.Seat, 0, len(seats))
	for _, seat := range seats {
		role := strings.ToLower(strings.ReplaceAll(string(seat), "_", "-"))
		sampling := fixtureSampling(t, "sampling-"+role)
		certificationID := "cert-" + role + "@1.0.0"
		profile := fixtureProfile(t, seat, backend, sampling, certificationID)
		certification := fixtureCertification(t, profile, sampling, "cert-"+role, CertificationSyntheticCI)
		assignmentID := "assignment-" + role
		samplings = append(samplings, sampling)
		profiles = append(profiles, profile)
		certifications = append(certifications, certification)
		assignments = append(assignments, testplan.ModelAssignment{AssignmentID: assignmentID, ModelProfileID: profile.BindingID()})
		roleID := "PLAYER"
		if seat == orchestrator.SeatGM {
			roleID = "GM"
		}
		roster = append(roster, testplan.Seat{SeatID: string(seat), RoleID: roleID, ModelAssignmentID: assignmentID})
	}
	registry, err := NewSyntheticRegistry(samplings, profiles, certifications)
	if err != nil {
		t.Fatalf("NewSyntheticRegistry: %v", err)
	}
	frozen, err := testplan.BindRunManifest(testplan.RunManifest{
		Schema: testplan.RunManifestSchema, ManifestID: "manifest-model-gateway-v1", RunID: "run-model-gateway-v1",
		Ancestry: testplan.Ancestry{CampaignID: "campaign-contract", SuiteID: "suite-contract", CaseID: "case-contract"},
		RunType:  testplan.TaskRegression,
		Source: testplan.SourceBinding{
			AIPT: testplan.RepositorySource{Repository: "zyc14588/AIPT", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)},
			Game: testplan.RepositorySource{Repository: "example/game", Commit: strings.Repeat("c", 40), Tree: strings.Repeat("d", 40)},
		},
		ModelAssignments:    assignments,
		PromptAssets:        []testplan.PromptAsset{{AssetID: "public-prompt-reference-v1", SHA256: fixtureSHA("public-prompt-reference")}},
		SeatRoster:          roster,
		Budget:              testplan.BudgetBinding{PolicyID: "budget-policy-v1", LimitsID: "budget-limits-v1", MaxInputTokens: 8192, MaxOutputTokens: 1024, MaxDurationSeconds: 60},
		Evidence:            testplan.EvidenceBinding{ProfileID: "evidence-profile-v1", ConfigID: "evidence-config-v1"},
		VisibilityProfileID: "AIPT_VISIBILITY_STANDARD_V1", SafetyApplicable: true,
		SafetyProfileID: "AIPT_SAFETY_STANDARD_V1", Classification: "QUALIFICATION", QualificationEligible: true,
	})
	if err != nil {
		t.Fatalf("BindRunManifest: %v", err)
	}
	binding, err := BindManifestModels(frozen, registry)
	if err != nil {
		t.Fatalf("BindManifestModels: %v", err)
	}
	return gatewayFixture{registry, profiles, samplings, certifications, binding, frozen}
}

func fixturePolicy() orchestrator.OrchestrationPolicy {
	return orchestrator.OrchestrationPolicy{
		Schema: orchestrator.PolicySchema, PolicyID: "model-gateway-policy-v1",
		SeatOrder: orchestrator.BaselineSeats(),
		InterruptionOrder: []orchestrator.SeatID{
			orchestrator.SeatPlayer3, orchestrator.SeatPlayer1, orchestrator.SeatPlayer4,
			orchestrator.SeatPlayer2, orchestrator.SeatGM,
		},
		SemanticRepairBudget: 2, TransportRetryBudget: 2, SessionRecoveryBudget: 1,
		InvocationTimeoutMillis: 1000, MaxContextSources: 16, MaxEventWindow: 32,
	}
}

func fixtureSeat(t *testing.T, runID string, seatID orchestrator.SeatID) orchestrator.Seat {
	t.Helper()
	persona, err := orchestrator.NewPersonaBaseline("persona-"+strings.ToLower(string(seatID)), "v1", []orchestrator.PersonaTrait{{Name: "stress", Value: 10}})
	if err != nil {
		t.Fatalf("NewPersonaBaseline: %v", err)
	}
	identities := orchestrator.BaselineIdentitySet{
		SessionIDs: map[orchestrator.SeatID]string{}, Personas: map[orchestrator.SeatID]orchestrator.PersonaBaseline{},
		Characters: map[orchestrator.SeatID]orchestrator.Character{}, GMProfile: orchestrator.GMProfileRulesFaithful,
	}
	for _, current := range orchestrator.BaselineSeats() {
		identities.SessionIDs[current] = "session-" + strings.ToLower(string(current))
		if current == seatID {
			identities.Personas[current] = persona
		} else {
			other, buildErr := orchestrator.NewPersonaBaseline("persona-"+strings.ToLower(string(current)), "v1", []orchestrator.PersonaTrait{{Name: "stress", Value: 10}})
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			identities.Personas[current] = other
		}
		if current != orchestrator.SeatGM {
			character, buildErr := orchestrator.NewCharacter("character-"+strings.ToLower(string(current)), "v1", []byte(`{"hp":10}`))
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			identities.Characters[current] = character
		}
	}
	seats, err := orchestrator.NewBaselineSeats(runID, identities)
	if err != nil {
		t.Fatalf("NewBaselineSeats: %v", err)
	}
	for _, seat := range seats {
		if seat.SeatID == seatID {
			return seat
		}
	}
	t.Fatal("fixture seat missing")
	return orchestrator.Seat{}
}

func fixtureStateFact(t *testing.T, id string, classification orchestrator.DataClassification, content string) orchestrator.StateFact {
	t.Helper()
	var raw json.RawMessage = []byte(content)
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(normalized)
	return orchestrator.StateFact{
		FactID: id, Classification: classification, Scope: orchestrator.ScopePublic,
		Value: raw, ValueSHA256: fixtureSHA(string(raw)),
	}
}

type fixtureRetriever struct {
	content map[string]orchestrator.RetrievedContent
}

func (r fixtureRetriever) Retrieve(_ context.Context, sources []orchestrator.AuthorizedSource) ([]orchestrator.RetrievedContent, error) {
	result := make([]orchestrator.RetrievedContent, 0, len(sources))
	for _, source := range sources {
		content, ok := r.content[source.SourceID]
		if !ok {
			return nil, fmt.Errorf("missing synthetic source")
		}
		result = append(result, content)
	}
	return result, nil
}

func fixtureContext(t *testing.T, runID string, seatID orchestrator.SeatID, classifications ...orchestrator.DataClassification) orchestrator.ContextBundle {
	t.Helper()
	seat := fixtureSeat(t, runID, seatID)
	state := orchestrator.PersonaState{Version: "v1", PersonaID: seat.Persona.PersonaID, RunID: runID, SeatID: seatID}
	if len(classifications) == 0 {
		classifications = []orchestrator.DataClassification{orchestrator.ClassPublic}
	}
	facts := make([]orchestrator.StateFact, 0, len(classifications))
	for index := range classifications {
		// First build through the real B003 authority using PUBLIC inputs. Some
		// negative tests then reseal a deliberately hostile adapter input below,
		// proving B004 independently enforces egress even if its caller is faulty.
		facts = append(facts, fixtureStateFact(t, fmt.Sprintf("fact-%02d", index), orchestrator.ClassPublic, fmt.Sprintf(`{"index":%d}`, index)))
	}
	summaryFacts := make([]orchestrator.SummaryFact, 0, len(facts))
	required := make([]string, 0, len(facts))
	for _, fact := range facts {
		summaryFacts = append(summaryFacts, orchestrator.SummaryFact{FactID: fact.FactID, ValueSHA256: fact.ValueSHA256})
		required = append(required, fact.FactID)
	}
	summary, err := orchestrator.NewMemorySummary("summary-model-gateway-v1", "v1", runID, seatID, summaryFacts, required, nil)
	if err != nil {
		t.Fatalf("NewMemorySummary: %v", err)
	}
	bundle, err := orchestrator.BuildContext(context.Background(), fixturePolicy(), seat, state, orchestrator.ContextInput{
		StateFacts: facts, Summary: summary,
		Tools: []orchestrator.ToolDescriptor{{ToolID: "tool-public", Version: "v1"}},
	}, fixtureRetriever{content: map[string]orchestrator.RetrievedContent{}})
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}
	for index, classification := range classifications {
		bundle.Untrusted.AuthorizedState.Facts[index].Classification = classification
	}
	rehashFixtureContext(t, &bundle)
	return bundle
}

func rehashFixtureContext(t *testing.T, bundle *orchestrator.ContextBundle) {
	t.Helper()
	hashInput := struct {
		Schema                   string                        `json:"schema"`
		ContextVersion           string                        `json:"context_version"`
		RunID                    string                        `json:"run_id"`
		SeatID                   orchestrator.SeatID           `json:"seat_id"`
		SessionID                string                        `json:"session_id"`
		AuthorizedProjectionHash string                        `json:"authorized_projection_hash"`
		PersonaID                string                        `json:"persona_id"`
		CharacterID              string                        `json:"character_id,omitempty"`
		EventWindowID            string                        `json:"event_window_id"`
		SummaryID                string                        `json:"summary_id"`
		ToolCapabilityID         string                        `json:"tool_capability_id"`
		Trusted                  orchestrator.TrustedContext   `json:"trusted"`
		Untrusted                orchestrator.UntrustedContext `json:"untrusted"`
	}{
		bundle.Schema, bundle.ContextVersion, bundle.RunID, bundle.SeatID, bundle.SessionID,
		bundle.AuthorizedProjectionHash, bundle.PersonaID, bundle.CharacterID, bundle.EventWindowID,
		bundle.SummaryID, bundle.ToolCapabilityID, bundle.Trusted, bundle.Untrusted,
	}
	raw, err := json.Marshal(hashInput)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ContextHash = fixtureSHA(canonical)
	if err := orchestrator.ValidateContextHash(*bundle); err != nil {
		t.Fatalf("reseal hostile B004 input fixture: %v", err)
	}
}
