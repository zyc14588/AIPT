package modelgateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func requireCode(t *testing.T, err error, code Code) {
	t.Helper()
	if err == nil || CodeOf(err) != code || !errors.Is(err, Sentinel(code)) {
		t.Fatalf("error = %v (code %q), want %s", err, CodeOf(err), code)
	}
}

func TestModelProfileAndRegistryNegativeMatrixM01ToM10(t *testing.T) {
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)

	t.Run("M01 unknown backend REJECT", func(t *testing.T) {
		candidate := fixture.profiles[0]
		candidate.SHA256 = ""
		candidate.BackendKind = BackendKind("UNREGISTERED_BACKEND")
		_, err := BindModelProfile(candidate)
		requireCode(t, err, CodeUnknownBackend)
	})

	t.Run("M02 unknown Model Profile version REJECT", func(t *testing.T) {
		_, err := fixture.registry.Profile("model-gm@9.9.9")
		requireCode(t, err, CodeUnknownProfileVersion)
	})

	t.Run("M03 model ID mismatch REJECT", func(t *testing.T) {
		profile := fixture.profiles[0]
		err := validateProbe(profile, HarnessProbe{
			HarnessIdentity: profile.Harness.BindingID(), ProtocolIdentity: profile.Harness.ProtocolIdentity,
			ProtocolVersion: profile.Harness.ProtocolVersion, ObservedModelID: "latest",
			CapabilityFingerprint: profile.Harness.CapabilityFingerprint, RouteAvailable: true,
		})
		requireCode(t, err, CodeModelIdentityMismatch)
	})

	t.Run("M04 Harness identity mismatch REJECT", func(t *testing.T) {
		profile := fixture.profiles[0]
		err := validateProbe(profile, HarnessProbe{
			HarnessIdentity:  "deepseek-harness@0.0.0+" + strings.Repeat("0", 40),
			ProtocolIdentity: profile.Harness.ProtocolIdentity, ProtocolVersion: profile.Harness.ProtocolVersion,
			ObservedModelID: profile.ModelID, CapabilityFingerprint: profile.Harness.CapabilityFingerprint,
			RouteAvailable: true,
		})
		requireCode(t, err, CodeHarnessIdentityMismatch)
	})

	t.Run("M05 Sampling Profile drift REJECT", func(t *testing.T) {
		candidate := fixture.samplings[0]
		candidate.Temperature = 1.5
		requireCode(t, ValidateSamplingProfile(candidate), CodeSamplingDrift)
	})

	t.Run("M06 missing certification identity REJECT", func(t *testing.T) {
		_, err := NewSyntheticRegistry(fixture.samplings, fixture.profiles, nil)
		requireCode(t, err, CodeCertificationMissing)
	})

	t.Run("M07 direct provider bypass REJECT", func(t *testing.T) {
		profile := fixture.profiles[0]
		err := validateProbe(profile, HarnessProbe{
			HarnessIdentity: profile.Harness.BindingID(), ProtocolIdentity: profile.Harness.ProtocolIdentity,
			ProtocolVersion: profile.Harness.ProtocolVersion, ObservedModelID: profile.ModelID,
			CapabilityFingerprint: profile.Harness.CapabilityFingerprint,
			RouteAvailable:        true, DirectProviderBypassAvailable: true,
		})
		requireCode(t, err, CodeDirectProviderBypass)
	})

	t.Run("M08 silent backend fallback REJECT", func(t *testing.T) {
		requested := fixture.profiles[0].BindingID()
		available := map[string]bool{fixture.profiles[1].BindingID(): true}
		_, err := fixture.registry.ExactProfile(requested, available)
		requireCode(t, err, CodeSilentFallback)
	})

	t.Run("M09 role Profile mutation after Manifest REJECT", func(t *testing.T) {
		mutated := fixture.binding
		mutated.Assignments = append([]RoleAssignment(nil), fixture.binding.Assignments...)
		mutated.Assignments[0].ProfileBinding = fixture.profiles[1].BindingID()
		requireCode(t, validateManifestBinding(mutated), CodeManifestImmutable)

		replacement := fixture.profiles[1]
		updated, event, err := ApplyExplicitReplacement(
			fixture.binding, "replacement-event-v1", fixture.binding.Assignments[0].SeatID,
			replacement, "OPERATOR_EXPLICIT_REPLACEMENT",
		)
		if err != nil {
			t.Fatalf("explicit replacement: %v", err)
		}
		if updated.CleanBaselineEligible || event.CleanBaselineEligible || event.PreviousProfile == event.ReplacementProfile {
			t.Fatalf("replacement did not irreversibly disqualify clean baseline: %+v %+v", updated, event)
		}
	})

	t.Run("M10 unverified local backend formal eligibility REJECT", func(t *testing.T) {
		local := newGatewayFixture(t, BackendLocalLlamaCPP)
		err := ValidateFormalCertification(local.certifications[0], local.registry)
		requireCode(t, err, CodeCertificationMissing)
		if _, err := NewRegistry(local.samplings, local.profiles, local.certifications); err == nil {
			t.Fatal("formal registry accepted synthetic local certification")
		}
	})
}

func TestDataSecurityNegativeMatrixM11ToM15(t *testing.T) {
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	profile := fixture.profiles[0]

	t.Run("M11 remote egress LOCAL_ONLY_SECRET REJECT", func(t *testing.T) {
		bundle := fixtureContext(t, fixture.frozen.Manifest.RunID, orchestrator.SeatGM, orchestrator.ClassLocalOnlySecret)
		_, err := ValidateEgress(profile, bundle)
		requireCode(t, err, CodeEgressDenied)
	})

	t.Run("M12 remote egress CREDENTIAL_SECRET REJECT", func(t *testing.T) {
		bundle := fixtureContext(t, fixture.frozen.Manifest.RunID, orchestrator.SeatGM, orchestrator.ClassCredentialSecret)
		_, err := ValidateEgress(profile, bundle)
		requireCode(t, err, CodeEgressDenied)
	})

	t.Run("M13 credential appears in log REJECT", func(t *testing.T) {
		secret := strings.Join([]string{"dsk", "controlled", "not-for-output"}, "-")
		err := newError(CodeHarnessTransport, "remote_call", "diagnostic-v1", errors.New(secret))
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "not-for-output") {
			t.Fatalf("redacted error exposed its cause: %s", err)
		}
		requireCode(t, err, CodeHarnessTransport)
	})

	t.Run("M14 credential appears in evidence REJECT", func(t *testing.T) {
		secret := strings.Join([]string{"dsk", "evidence", "not-for-output"}, "-")
		err := EvidenceSafe(map[string]string{"credential_value": secret})
		requireCode(t, err, CodeEvidenceUnsafe)
	})

	t.Run("M15 private absolute path exported REJECT", func(t *testing.T) {
		err := EvidenceSafe(map[string]string{"asset_reference": "/private/aipt/operator/model.gguf"})
		requireCode(t, err, CodeEvidenceUnsafe)
	})
}

func TestBreakGlassEgressRequiresAuthoritativeDiagnosticConsumption(t *testing.T) {
	fixture := newGatewayFixture(t, BackendRemoteDeepSeek)
	profile := fixture.profiles[0]
	profile.SHA256 = ""
	profile.DataEgressPolicy.BreakGlassAllowed = true
	bound, err := BindModelProfile(profile)
	if err != nil {
		t.Fatalf("bind break-glass profile: %v", err)
	}
	bundle := fixtureContext(t, fixture.frozen.Manifest.RunID, orchestrator.SeatGM, orchestrator.ClassLocalOnlySecret)
	decision, err := ValidateEgress(bound, bundle)
	if err != nil || decision.CleanBaselineEligible || !decision.BreakGlassRequired {
		t.Fatalf("diagnostic break-glass decision = %+v err:%v", decision, err)
	}
}
