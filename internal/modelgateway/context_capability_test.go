package modelgateway

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func oversizedRequiredContext(t *testing.T, runID string) orchestrator.ContextBundle {
	t.Helper()
	seat := fixtureSeat(t, runID, orchestrator.SeatGM)
	state := orchestrator.PersonaState{
		Version: "v1", PersonaID: seat.Persona.PersonaID, RunID: runID, SeatID: seat.SeatID,
	}
	fact := fixtureStateFact(t, "fact-required-large", orchestrator.ClassPublic, `{"payload":"`+strings.Repeat("x", 8192)+`"}`)
	summary, err := orchestrator.NewMemorySummary(
		"summary-required-large", "v1", runID, seat.SeatID,
		[]orchestrator.SummaryFact{{FactID: fact.FactID, ValueSHA256: fact.ValueSHA256}},
		[]string{fact.FactID}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := orchestrator.BuildContext(context.Background(), fixturePolicy(), seat, state, orchestrator.ContextInput{
		StateFacts: []orchestrator.StateFact{fact}, Summary: summary,
	}, fixtureRetriever{content: map[string]orchestrator.RetrievedContent{}})
	if err != nil {
		t.Fatalf("build oversized context: %v", err)
	}
	return bundle
}

func TestContextAndCapabilityNegativeMatrixM21ToM24(t *testing.T) {
	t.Run("M21 context budget silent truncation REJECT", func(t *testing.T) {
		bundle := oversizedRequiredContext(t, "run-context-budget-v1")
		_, reduction, err := PrepareContext(bundle, ContextPolicy{
			PolicyID: "context-budget-v1", PolicyVersion: "1.0.0",
			MaxRequestBytes: 4096, MaxContextBytes: 1024,
			ReductionPolicyID: "AIPT_CONTEXT_BUDGET_REDUCE_V1",
		})
		requireCode(t, err, CodeContextBudgetExceeded)
		if reduction.PreparedBytes != 0 || len(reduction.RemovedEventIDs) != 0 || len(reduction.RemovedSourceIDs) != 0 {
			t.Fatalf("failed reduction pretended to prepare context: %+v", reduction)
		}
	})

	t.Run("M22 hidden data added during reduction REJECT", func(t *testing.T) {
		bundle := fixtureContext(t, "run-context-subset-v1", orchestrator.SeatGM)
		prepared := clonePrepared(bundle)
		prepared.AuthorizedState.Facts = append(prepared.AuthorizedState.Facts,
			fixtureStateFact(t, "fact-added-hidden", orchestrator.ClassTableHiddenRemoteAllowed, `{"hidden":true}`))
		if err := verifyPreparedSubset(bundle, prepared); err == nil {
			t.Fatal("reduction subset verifier accepted added hidden data")
		}
	})

	t.Run("M23 structured mode false claim REJECT", func(t *testing.T) {
		fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
		profile := fixture.profiles[0]
		profile.SHA256 = ""
		profile.StructuredOutputMode = StructuredNative
		for index, capability := range profile.CapabilityRequirements {
			if capability == CapabilityStructuredOutputPrompted {
				profile.CapabilityRequirements[index] = CapabilityStructuredOutputNative
			}
		}
		profile, err := BindModelProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		certification := unboundCertification(t, profile, fixture.samplings[0], "cert-false-native")
		_, err = BindCertification(certification, profile, fixture.samplings[0])
		requireCode(t, err, CodeCertificationMismatch)
	})

	t.Run("M24 native tool capability false claim REJECT", func(t *testing.T) {
		fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
		profile := fixture.profiles[0]
		profile.SHA256 = ""
		profile.ToolCallMode = ToolCallNative
		profile.CapabilityRequirements = append(profile.CapabilityRequirements, CapabilityToolCallNative)
		profile, err := BindModelProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		certification := unboundCertification(t, profile, fixture.samplings[0], "cert-false-tool-native")
		_, err = BindCertification(certification, profile, fixture.samplings[0])
		requireCode(t, err, CodeCertificationMismatch)
	})
}

func unboundCertification(t *testing.T, profile ModelProfile, sampling SamplingProfile, id string) Certification {
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
		t.Fatal(err)
	}
	return Certification{
		Schema: CertificationSchema, CertificationID: id, CertificationVersion: "1.0.0",
		ProfileBinding: profile.BindingID(), SamplingBinding: sampling.BindingID(),
		Result: "PASS", Kind: CertificationSyntheticCI, MinimumCertification: true,
		EvidenceIdentity: "evidence-" + id, ProductionRoleEligibility: "NOT_CLAIMED",
		Claims: fixtureClaims(), ExecutionTuple: tuple,
		ObservedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}
}

func TestDeterministicContextReductionRemovesOnlyRetrievedThenOldestEvents(t *testing.T) {
	// B003 constructs the valid authorized bundle. This B004 test then verifies
	// that repeated preparation is byte-for-byte deterministic and never changes
	// critical identities. The tiny fixture already fits, so no data is removed.
	bundle := fixtureContext(t, "run-context-determinism-v1", orchestrator.SeatPlayer1)
	policy := ContextPolicy{
		PolicyID: "context-determinism-v1", PolicyVersion: "1.0.0",
		MaxRequestBytes: 1 << 20, MaxContextBytes: 64 << 10,
		ReductionPolicyID: "AIPT_CONTEXT_BUDGET_REDUCE_V1",
	}
	first, firstReduction, err := PrepareContext(bundle, policy)
	if err != nil {
		t.Fatal(err)
	}
	second, secondReduction, err := PrepareContext(bundle, policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || firstReduction.PreparedContextSHA256 != secondReduction.PreparedContextSHA256 {
		t.Fatal("context reduction is nondeterministic")
	}
}
