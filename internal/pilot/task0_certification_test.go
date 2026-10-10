package pilot

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func TestTask0CertificationRejectsForgedOrRecoveredResultAndKeepsLimitedClaims(t *testing.T) {
	for _, scenario := range []string{"valid", "foreign_request", "foreign_model", "foreign_harness", "wrong_sampling", "raw_digest", "recovery", "provider_action", "foreign_session", "sampling_projection", "over_output", "local_valid", "zero_completed", "different_completed"} {
		t.Run(scenario, func(t *testing.T) {
			entry := task0DispatchProfileFixture(t, orchestrator.SeatPlayer1, scenario == "local_valid")
			request, err := task0CertificationRequest("NON-CANON-certification-no-model", entry)
			if err != nil {
				t.Fatal(err)
			}
			outer := orchestrator.AgentResponse{Schema: orchestrator.AgentResponseSchema, InvocationID: request.RequestID, RunID: request.Invocation.RunID, SeatID: entry.Seat, SessionID: request.Session.SessionID, Speech: "NON_CANON_FAKE_ACK_NO_MODEL_CALL", Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"}}
			if scenario == "provider_action" {
				_, _, proposal := task0AuthenticationFixture()
				outer.Action = &proposal
			}
			if scenario == "foreign_session" {
				outer.SessionID += "-other"
			}
			raw, _ := json.Marshal(outer)
			result := modelgateway.HarnessResult{Schema: modelgateway.HarnessResponseSchema, ProtocolVersion: "1", RequestID: request.RequestID, HarnessIdentity: entry.Profile.Harness.BindingID(), ObservedModelID: entry.Profile.ModelID,
				CapabilityFingerprint: entry.Profile.Harness.CapabilityFingerprint, RawResponse: raw, ResponseSHA256: inputSHA(raw), RequestedSamplingSHA256: entry.Sampling.SHA256, UnsupportedSamplingParameters: entry.Sampling.UnsupportedParameters,
				BackendSerializedRequestSHA256: strings.Repeat("a", 64), CompletedAt: time.Now().UTC(), EffectiveSampling: modelgateway.EffectiveSamplingProjection{Schema: modelgateway.EffectiveSamplingSchema, EnforcementIdentity: modelgateway.SamplingEnforcementIdentity,
					MaxContextTokens: 8192, MaxOutputTokens: 1024, ContextUTF8ByteCeiling: 8192, OutputUTF8ByteCeiling: 1024, AppliedParameters: entry.Sampling.AppliedParameters, UnsupportedParameters: entry.Sampling.UnsupportedParameters}}
			observed := result.CompletedAt
			switch scenario {
			case "zero_completed":
				result.CompletedAt = time.Time{}
			case "different_completed":
				observed = observed.Add(time.Second)
			case "foreign_request":
				result.RequestID += "-other"
			case "foreign_model":
				result.ObservedModelID = "NON-CANON-foreign"
			case "foreign_harness":
				result.HarnessIdentity = "NON-CANON-foreign"
			case "wrong_sampling":
				result.RequestedSamplingSHA256 = strings.Repeat("b", 64)
			case "raw_digest":
				result.ResponseSHA256 = strings.Repeat("c", 64)
			case "recovery":
				result.RouteRecoveryOccurred = true
			case "sampling_projection":
				result.EffectiveSampling.MaxOutputTokens = 2048
			case "over_output":
				result.RawResponse = append(result.RawResponse, []byte(strings.Repeat(" ", 1024))...)
				result.ResponseSHA256 = inputSHA(result.RawResponse)
			}
			cert, err := task0CertificationFromResult(entry, request, result, observed)
			valid := scenario == "valid" || scenario == "local_valid"
			if (err == nil) != valid {
				t.Fatal("certification result admission differs", scenario)
			}
			if valid {
				registry, err := modelgateway.NewRegistry([]modelgateway.SamplingProfile{entry.Sampling}, []modelgateway.ModelProfile{entry.Profile}, []modelgateway.Certification{cert})
				if err != nil || modelgateway.ValidateCertification(cert, registry) != nil {
					t.Fatal("limited observation drifted from unchanged B004 contracts", err)
				}
				for _, claim := range cert.Claims {
					if claim.Name == modelgateway.CapabilityVisibilityPolicyCompatible && claim.Status != modelgateway.ClaimUntested {
						t.Fatal("minimum observation promoted privacy claims")
					}
				}
			}
		})
	}
}
