package pilot

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func task0ModelEvidenceFixture(t *testing.T) (*GlobalBudget, *acceptedTask0DispatchGrant, modelgateway.HarnessRequest, modelgateway.HarnessResult) {
	t.Helper()
	budget, _ := task0SeedFixture(t)
	b, f := task0DispatchBindingFixture(t)
	raw, _ := json.Marshal(b)
	g, err := decodeTask0DispatchGrant(raw, inputSHA(raw), f)
	if err != nil {
		t.Fatal(err)
	}
	budget.manifest = f
	entry := b.Profiles[0]
	request, err := task0CertificationRequest(f.Manifest.RunID, entry)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(orchestrator.AgentResponse{Schema: orchestrator.AgentResponseSchema, InvocationID: request.RequestID, RunID: f.Manifest.RunID, SeatID: entry.Seat, SessionID: request.Session.SessionID,
		Speech: "NON_CANON_PRIVATE_MODEL_BODY_CANARY", Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"}})
	result := modelgateway.HarnessResult{Schema: modelgateway.HarnessResponseSchema, ProtocolVersion: "1", RequestID: request.RequestID, HarnessIdentity: entry.Profile.Harness.BindingID(), ObservedModelID: entry.Profile.ModelID,
		CapabilityFingerprint: entry.Profile.Harness.CapabilityFingerprint, RawResponse: body, ResponseSHA256: inputSHA(body), RequestedSamplingSHA256: entry.Sampling.SHA256, UnsupportedSamplingParameters: entry.Sampling.UnsupportedParameters,
		BackendSerializedRequestSHA256: strings.Repeat("a", 64), CompletedAt: time.Now().UTC(),
		EffectiveSampling: modelgateway.EffectiveSamplingProjection{Schema: modelgateway.EffectiveSamplingSchema, EnforcementIdentity: modelgateway.SamplingEnforcementIdentity,
			AppliedParameters: entry.Sampling.AppliedParameters, UnsupportedParameters: entry.Sampling.UnsupportedParameters, MaxContextTokens: 8192, MaxOutputTokens: 1024,
			ContextUTF8ByteCeiling: 8192, OutputUTF8ByteCeiling: 1024}}
	return budget, g, request, result
}

func TestTask0ModelEvidencePrivateExactBodiesAndExclusiveHistory(t *testing.T) {
	b, g, request, result := task0ModelEvidenceFixture(t)
	if !task0ValidateModelEvidenceRequest(g, request) || task0CaptureModelIntent(b, g, request) != nil || task0CaptureModelTerminal(b, g, request, &result) != nil {
		t.Fatal("synthetic private capture rejected")
	}
	inName, outName, err := task0ModelEvidenceNames(request.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	intent, terminal, inRaw, outRaw, err := task0ReadModelEvidence(b, g, request.RequestID)
	if err != nil || !task0SameJSON(intent.Request, request) || !task0SameJSON(*terminal.Result, result) || !bytes.Contains(outRaw, []byte("raw_response")) {
		t.Fatal("exact private request/response pair lost", err)
	}
	if !bytes.Equal(terminal.Result.RawResponse, result.RawResponse) || len(inRaw) == 0 {
		t.Fatal("provider body was reconstructed")
	}
	for _, name := range []string{inName, outName} {
		i, err := os.Lstat(filepath.Join(b.rootPath, name))
		if err != nil || i.Mode().Perm() != 0400 {
			t.Fatal("body record permissions changed")
		}
	}
	if task0CaptureModelIntent(b, g, request) == nil || task0CaptureModelTerminal(b, g, request, &result) == nil {
		t.Fatal("capture history overwritten")
	}
	_, _, _, after, err := task0ReadModelEvidence(b, g, request.RequestID)
	if err != nil || !bytes.Equal(after, outRaw) {
		t.Fatal("failed overwrite changed original evidence")
	}
}

func TestTask0ModelEvidenceFailedAndUncertainResponseCannotComplete(t *testing.T) {
	b, g, request, _ := task0ModelEvidenceFixture(t)
	if task0CaptureModelIntent(b, g, request) != nil || task0CaptureModelTerminal(b, g, request, nil) != nil {
		t.Fatal("failure capture rejected")
	}
	if _, _, _, _, err := task0ReadModelEvidence(b, g, request.RequestID); err == nil {
		t.Fatal("failed response claimed complete body evidence")
	}
	_, name, _ := task0ModelEvidenceNames(request.RequestID)
	body, err := task0ReadPrivateRecord(b, name)
	if err != nil || !bytes.Contains(body, []byte("FAILED_NO_RETRY")) || bytes.Contains(body, []byte("provider_error")) {
		t.Fatal("private failure record copied an untrusted cause")
	}
}

func TestTask0ModelEvidenceTamperAliasesAndForeignBindingsRefused(t *testing.T) {
	for _, attack := range []string{"wrong_request_digest", "wrong_prepared", "wrong_profile", "wrong_run", "wrong_result_digest", "wrong_result_model", "wrong_result_harness", "wrong_effective_schema", "wrong_enforcement", "wrong_context_ceiling", "wrong_output_ceiling", "wrong_applied_parameters", "wrong_unsupported_parameters", "wrong_context_tokens", "wrong_output_tokens", "zero_completed_at", "route_recovery", "foreign_manifest", "foreign_grant", "case_alias", "unknown_field", "symlink", "hardlink", "fifo", "writable_mode", "missing_member", "root_substitution"} {
		t.Run(attack, func(t *testing.T) {
			b, g, request, result := task0ModelEvidenceFixture(t)
			if task0CaptureModelIntent(b, g, request) != nil || task0CaptureModelTerminal(b, g, request, &result) != nil {
				t.Fatal("fixture capture failed")
			}
			inName, outName, _ := task0ModelEvidenceNames(request.RequestID)
			inPath, outPath := filepath.Join(b.rootPath, inName), filepath.Join(b.rootPath, outName)
			var intent task0ModelIntent
			var terminal task0ModelTerminal
			inRaw, _ := os.ReadFile(inPath)
			outRaw, _ := os.ReadFile(outPath)
			json.Unmarshal(inRaw, &intent)
			json.Unmarshal(outRaw, &terminal)
			rewrite := func(path string, v any) {
				body, err := task0PrivateCanonicalLine(v)
				if err != nil {
					t.Fatal(err)
				}
				if os.Chmod(path, 0600) != nil || os.WriteFile(path, body, 0600) != nil || os.Chmod(path, 0400) != nil {
					t.Fatal("fixture rewrite failed")
				}
			}
			switch attack {
			case "wrong_request_digest":
				intent.Request.RequestSHA256 = strings.Repeat("b", 64)
				terminal.RequestSHA = intent.Request.RequestSHA256
				rewrite(inPath, intent)
				rewrite(outPath, terminal)
			case "wrong_prepared":
				intent.Request.PreparedContext = []byte(`{}`)
				rewrite(inPath, intent)
			case "wrong_profile":
				intent.Request.ProfileBinding = "NON-CANON-other"
				rewrite(inPath, intent)
			case "wrong_run":
				intent.Request.Invocation.RunID += "-other"
				rewrite(inPath, intent)
			case "wrong_result_digest":
				terminal.Result.ResponseSHA256 = strings.Repeat("b", 64)
				rewrite(outPath, terminal)
			case "wrong_result_model":
				terminal.Result.ObservedModelID = "NON-CANON-other"
				rewrite(outPath, terminal)
			case "wrong_result_harness":
				terminal.Result.HarnessIdentity = "NON-CANON-other"
				rewrite(outPath, terminal)
			case "wrong_effective_schema":
				terminal.Result.EffectiveSampling.Schema += "-other"
				rewrite(outPath, terminal)
			case "wrong_enforcement":
				terminal.Result.EffectiveSampling.EnforcementIdentity += "-other"
				rewrite(outPath, terminal)
			case "wrong_context_ceiling":
				terminal.Result.EffectiveSampling.ContextUTF8ByteCeiling = 16384
				rewrite(outPath, terminal)
			case "wrong_output_ceiling":
				terminal.Result.EffectiveSampling.OutputUTF8ByteCeiling++
				rewrite(outPath, terminal)
			case "wrong_applied_parameters":
				terminal.Result.EffectiveSampling.AppliedParameters = nil
				rewrite(outPath, terminal)
			case "wrong_unsupported_parameters":
				terminal.Result.EffectiveSampling.UnsupportedParameters = []string{"NON_CANON"}
				rewrite(outPath, terminal)
			case "wrong_context_tokens":
				terminal.Result.EffectiveSampling.MaxContextTokens++
				rewrite(outPath, terminal)
			case "wrong_output_tokens":
				terminal.Result.EffectiveSampling.MaxOutputTokens++
				rewrite(outPath, terminal)
			case "zero_completed_at":
				terminal.Result.CompletedAt = time.Time{}
				rewrite(outPath, terminal)
			case "route_recovery":
				terminal.Result.RouteRecoveryOccurred = true
				rewrite(outPath, terminal)
			case "foreign_manifest":
				terminal.ManifestSHA = strings.Repeat("b", 64)
				rewrite(outPath, terminal)
			case "foreign_grant":
				terminal.GrantSHA = strings.Repeat("b", 64)
				rewrite(outPath, terminal)
			case "case_alias":
				outRaw = bytes.Replace(outRaw, []byte(`"request_id"`), []byte(`"Request_ID"`), 1)
				if os.Chmod(outPath, 0600) != nil || os.WriteFile(outPath, outRaw, 0600) != nil || os.Chmod(outPath, 0400) != nil {
					t.Fatal("case fixture failed")
				}
			case "unknown_field":
				var m map[string]any
				json.Unmarshal(outRaw, &m)
				m["secret"] = true
				rewrite(outPath, m)
			case "symlink":
				if os.Remove(outPath) != nil || os.Symlink(inPath, outPath) != nil {
					t.Fatal("alias fixture failed")
				}
			case "hardlink":
				if os.Link(outPath, outPath+".alias") != nil {
					t.Fatal("hardlink fixture failed")
				}
			case "fifo":
				if os.Remove(outPath) != nil || syscall.Mkfifo(outPath, 0400) != nil {
					t.Fatal("FIFO fixture failed")
				}
			case "writable_mode":
				if os.Chmod(outPath, 0600) != nil {
					t.Fatal("mode fixture failed")
				}
			case "missing_member":
				if os.Remove(outPath) != nil {
					t.Fatal("missing fixture failed")
				}
			case "root_substitution":
				if os.Rename(b.rootPath, b.rootPath+"-retained") != nil || os.Mkdir(b.rootPath, 0700) != nil {
					t.Fatal("root fixture failed")
				}
			}
			if _, _, _, _, err := task0ReadModelEvidence(b, g, request.RequestID); err == nil {
				t.Fatal("tampered model body evidence accepted", attack)
			}
		})
	}
}
