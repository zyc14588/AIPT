package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func controlledRemoteFixture(t *testing.T) ControlledCertificationSpec {
	t.Helper()
	sampling, err := BindSamplingProfile(SamplingProfile{
		Schema: SamplingProfileSchema, SamplingID: "b004-controlled-remote-sampling",
		SamplingVersion: "1.0.0", Temperature: 0, TopP: 1, MaxOutputTokens: 1024,
		MaxContextTokens: 8192, AppliedParameters: []string{"max_context_tokens", "max_output_tokens"},
		UnsupportedParameters: []string{"temperature", "top_p"},
	})
	if err != nil {
		t.Fatalf("BindSamplingProfile: %v", err)
	}
	profile, err := BindModelProfile(ModelProfile{
		Schema: ModelProfileSchema, ProfileID: "b004-controlled-remote", ProfileVersion: "1.0.0",
		BackendKind: BackendRemoteDeepSeek, ProviderIdentity: "deepseek-official", ModelID: RemoteDeepSeekModelID,
		Harness: HarnessIdentity{
			Implementation: controlledHarnessImplementation, Version: controlledHarnessVersion,
			Commit: controlledHarnessCommit, PackageSHA256: fixtureSHA("controlled-harness-package"),
			ProtocolIdentity: HarnessProtocolACP, ProtocolVersion: HarnessProtocolVersionACP,
			CapabilityFingerprint: fixtureSHA("controlled-harness-capability"),
			RuntimeClosureKind:    HarnessRuntimeClosureKind, RuntimeClosureSHA256: fixtureSHA("controlled-harness-runtime-closure"),
		},
		SamplingProfileID: sampling.BindingID(), StructuredOutputMode: StructuredPrompted,
		ToolCallMode: ToolCallDisabled,
		ContextPolicy: ContextPolicy{
			PolicyID: "b004-controlled-context", PolicyVersion: "1.0.0", MaxRequestBytes: 1 << 20,
			MaxContextBytes: 64 << 10, ReductionPolicyID: "AIPT_CONTEXT_BUDGET_REDUCE_V1",
		},
		DataEgressPolicy: DataEgressPolicy{
			PolicyID: "b004-controlled-egress", PolicyVersion: "1.0.0",
			AllowedClassifications: []orchestrator.DataClassification{orchestrator.ClassPublic},
		},
		CredentialReference: &CredentialReference{
			ReferenceID: "deepseek-b004-owner", Kind: CredentialEnvironment,
			Locator: controlledCredentialLocator,
		},
		CapabilityRequirements: []CapabilityName{
			CapabilityBasicCompletion, CapabilityStructuredOutputPrompted, CapabilityRoleInvocation,
		},
		CertificationIdentity: "b004-controlled-remote-certification@1.0.0",
	})
	if err != nil {
		t.Fatalf("BindModelProfile: %v", err)
	}
	return ControlledCertificationSpec{
		Schema:          ControlledCertificationSpecSchema,
		CertificationID: "b004-controlled-remote-certification", CertificationVersion: "1.0.0",
		EvidenceIdentity: "b004-controlled-remote-evidence", EnvironmentIdentity: "b004-controlled-environment",
		Sampling: sampling, Profile: profile,
	}
}

func controlledSuccessTransport(secretMarker string) HarnessTransport {
	return fakeHarnessTransport{invoke: func(
		_ context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest,
	) (HarnessResult, error) {
		response, _ := json.Marshal(orchestrator.AgentResponse{
			Schema: orchestrator.AgentResponseSchema, InvocationID: request.RequestID,
			RunID: request.Invocation.RunID, SeatID: request.Invocation.SeatID,
			SessionID: request.Session.SessionID, Speech: "controlled acknowledgement " + secretMarker,
			Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"},
		})
		return fixtureHarnessResult(profile, request, response), nil
	}}
}

func TestObserveControlledCertificationProducesFormalSecretFreeResult(t *testing.T) {
	spec := controlledRemoteFixture(t)
	secretMarker := strings.Join([]string{"dsk", "must", "not", "escape"}, "-")
	credential := &CredentialValidation{
		ReferenceID: spec.Profile.CredentialReference.ReferenceID, Kind: CredentialEnvironment,
		State: "VALID", Metadata: map[string]string{"source": "environment", "exposure": "write-only"},
	}
	result, err := observeControlledCertification(
		context.Background(), spec, controlledSuccessTransport(secretMarker), credential,
		func() time.Time { return time.Date(2026, 8, 30, 1, 2, 3, 0, time.UTC) },
	)
	if err != nil {
		t.Fatalf("observeControlledCertification: %v", err)
	}
	if result.Result != "PASS" || result.Certification.RealModelCalls != 1 ||
		result.Certification.Kind != CertificationControlledReal || result.ResponseProtocolVersion != "v1" ||
		result.CredentialValuesRecorded || result.PrivatePathsRecorded {
		t.Fatalf("unexpected controlled result: %#v", result)
	}
	registry, err := NewRegistry(
		[]SamplingProfile{result.Sampling}, []ModelProfile{result.Profile}, []Certification{result.Certification},
	)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if err := ValidateFormalCertification(result.Certification, registry); err != nil {
		t.Fatalf("ValidateFormalCertification: %v", err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secretMarker)) || bytes.Contains(raw, []byte("must-not-escape")) {
		t.Fatal("controlled certification result retained model-returned secret material")
	}
}

func TestObserveControlledCertificationRejectsNonV1AgentResponse(t *testing.T) {
	spec := controlledRemoteFixture(t)
	transport := fakeHarnessTransport{invoke: func(
		_ context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest,
	) (HarnessResult, error) {
		response, _ := json.Marshal(orchestrator.AgentResponse{
			Schema: orchestrator.AgentResponseSchema, InvocationID: request.RequestID,
			RunID: request.Invocation.RunID, SeatID: request.Invocation.SeatID,
			SessionID: request.Session.SessionID, Speech: "wrong protocol",
			Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "1"},
		})
		return fixtureHarnessResult(profile, request, response), nil
	}}
	_, err := observeControlledCertification(context.Background(), spec, transport, nil, time.Now)
	requireCode(t, err, CodeHarnessResponseInvalid)
}

func TestNormalizeControlledCertificationFreezesOwnerBindings(t *testing.T) {
	spec := controlledRemoteFixture(t)
	temporary := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argument := filepath.Join(temporary, "harness-entrypoint.js")
	if err := os.WriteFile(argument, []byte("// fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec.AdapterExecutablePath = executable
	spec.AdapterExecutableSHA256 = fileSHA256(t, executable)
	spec.AdapterEntrypointPath = argument
	spec.AdapterEntrypointSHA256 = fileSHA256(t, argument)
	spec.AdapterWorkingDirectory = temporary
	spec.AdapterStartupTimeoutMS = 1_000
	spec.AdapterShutdownTimeoutMS = 3_000
	spec.HarnessChild = HarnessChildProcessSpec{
		ExecutablePath: executable, ExecutableSHA256: fileSHA256(t, executable),
		Arguments:           []string{argument},
		ArgumentFileDigests: []HarnessChildArgumentDigest{{Index: 0, SHA256: fileSHA256(t, argument)}},
		RuntimeClosure: HarnessRuntimeClosure{
			Schema: HarnessRuntimeClosureSchema, Kind: HarnessRuntimeClosureKind,
			EntrypointArgumentIndex: 0, SHA256: fileSHA256(t, argument),
		},
		WorkingDirectory: temporary, EnvironmentAllowlist: []string{
			controlledHarnessHomeEnvironment, controlledPersistenceEnvironment, controlledCredentialLocator,
		},
		StartupTimeoutMS: 1_000, RequestTimeoutMS: 1_000, ShutdownTimeoutMS: 1_000,
		OutputBudget: ACPOutputBudget{
			Schema: ACPOutputBudgetSchema, MaxStdoutProtocolBytes: 8 << 20,
			MaxNotificationBytes: 4 << 20, MaxResponseAndNotificationBytes: 8 << 20,
			MaxStderrBytes: 1 << 20,
		},
	}
	spec.Profile.SHA256 = ""
	spec.Profile.Harness.RuntimeClosureSHA256 = spec.HarnessChild.RuntimeClosure.SHA256
	spec.Profile, err = BindModelProfile(spec.Profile)
	if err != nil {
		t.Fatalf("bind controlled closure profile: %v", err)
	}
	if _, err := normalizeControlledProfiles(spec); err != nil {
		t.Fatalf("Owner-approved controlled spec rejected: %v", err)
	}

	t.Run("Harness commit drift", func(t *testing.T) {
		candidate := spec
		candidate.Profile.Harness.Commit = strings.Repeat("f", 40)
		candidate.Profile.SHA256 = ""
		_, err := normalizeControlledProfiles(candidate)
		requireCode(t, err, CodeHarnessIdentityMismatch)
	})

	t.Run("credential locator drift", func(t *testing.T) {
		candidate := spec
		reference := *candidate.Profile.CredentialReference
		reference.Locator = "UNAPPROVED_PROVIDER_KEY"
		candidate.Profile.CredentialReference = &reference
		candidate.Profile.SHA256 = ""
		_, err := normalizeControlledProfiles(candidate)
		requireCode(t, err, CodeCredentialPolicy)
	})
}
