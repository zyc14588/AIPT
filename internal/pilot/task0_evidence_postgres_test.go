package pilot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcore"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
)

// NON_CANON synthetic bodies/observations are committed to an isolated real
// PostgreSQL database solely to exercise collection and cross-stream binding.
// The six fixture certifications are derived from fake responses, not model
// calls. No registry grants production access, no Game/Core action or seed is
// selected, and no runtime/DIAG/qualification acceptance is claimed.
func TestPostgresTask0EvidenceCollectsExactModelLedgersBudgetAndLocalGates(t *testing.T) {
	ctx := context.Background()
	pool := pilotPool(t)
	binding, f := task0DispatchBindingFixture(t)
	raw, _ := json.Marshal(binding)
	g, err := decodeTask0DispatchGrant(raw, inputSHA(raw), f)
	if err != nil {
		t.Fatal(err)
	}
	pilotEnqueue(t, pool, f)
	price := Pricing{"deepseek-v4-pro", 1320, 3960, strings.Repeat("1", 64), time.Now().UTC()}
	budget, err := OpenGlobalBudget(ctx, pool, privateRoot(t), f, price)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	makeBody := func(entry task0DispatchProfile) (modelgateway.HarnessRequest, modelgateway.HarnessResult) {
		t.Helper()
		request, err := task0CertificationRequest(f.Manifest.RunID, entry)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(orchestrator.AgentResponse{Schema: orchestrator.AgentResponseSchema, InvocationID: request.RequestID, RunID: f.Manifest.RunID, SeatID: entry.Seat,
			SessionID: request.Session.SessionID, Speech: "NON_CANON_FAKE_BODY_NO_MODEL_CALL", Metadata: orchestrator.ProtocolMetadata{ProtocolVersion: "v1"}})
		result := modelgateway.HarnessResult{Schema: modelgateway.HarnessResponseSchema, ProtocolVersion: "1", RequestID: request.RequestID, HarnessIdentity: entry.Profile.Harness.BindingID(), ObservedModelID: entry.Profile.ModelID,
			CapabilityFingerprint: entry.Profile.Harness.CapabilityFingerprint, RawResponse: body, ResponseSHA256: inputSHA(body), CompletedAt: time.Now().UTC(), RequestedSamplingSHA256: entry.Sampling.SHA256,
			UnsupportedSamplingParameters: entry.Sampling.UnsupportedParameters, BackendSerializedRequestSHA256: strings.Repeat("c", 64),
			EffectiveSampling: modelgateway.EffectiveSamplingProjection{Schema: modelgateway.EffectiveSamplingSchema, EnforcementIdentity: modelgateway.SamplingEnforcementIdentity, MaxContextTokens: 8192, MaxOutputTokens: 1024,
				ContextUTF8ByteCeiling: 8192, OutputUTF8ByteCeiling: 1024, AppliedParameters: entry.Sampling.AppliedParameters, UnsupportedParameters: entry.Sampling.UnsupportedParameters}}
		if entry.Profile.BackendKind == modelgateway.BackendLocalLlamaCPP {
			err = budget.ReserveLocal(ctx, request.RequestID, g.binding.Proof)
		} else {
			err = budget.ReserveRemote(ctx, request.RequestID, g.binding.Proof)
		}
		if err != nil || task0CaptureModelIntent(budget, g, request) != nil || task0CaptureModelTerminal(budget, g, request, &result) != nil {
			t.Fatal("synthetic body persistence", err)
		}
		return request, result
	}
	entries := append([]task0DispatchProfile{binding.Profiles[5]}, binding.Profiles[:5]...)
	var localCompleted time.Time
	for _, entry := range entries {
		request, result := makeBody(entry)
		if entry.Profile.BackendKind == modelgateway.BackendLocalLlamaCPP {
			localCompleted = result.CompletedAt
		}
		cert, err := task0CertificationFromResult(entry, request, result, result.CompletedAt)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"INTENT", "PASS"} {
			observation := task0CertificationObservation{Schema: "aipt.private.b007-role-certification-observation/v1", RunID: f.Manifest.RunID, RequestID: request.RequestID,
				ProfileBinding: entry.Profile.BindingID(), RequestSHA: request.RequestSHA256, ManifestSHA: g.binding.ManifestSHA, Event: kind}
			if kind == "PASS" {
				observation.Certification = cert
			}
			raw, _ := json.Marshal(observation)
			if _, err := postgres.Append(ctx, pool, postgres.AppendInput{StreamID: "aipt.b007-role-certification:" + f.Manifest.RunID, EventID: request.RequestID + "-" + kind, EventType: "AIPT_B007_ROLE_CERTIFICATION_" + kind, PayloadJSON: raw}); err != nil {
				t.Fatal(err)
			}
		}
	}
	receipts := []runcore.Receipt{{ActionID: "RUN_STARTED"}}
	sink, err := modelgateway.NewPostgreSQLAuditSink(pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range binding.Profiles[:5] {
		request, result := makeBody(entry)
		observed := modelgateway.InvocationEvidence{Schema: modelgateway.InvocationEvidenceSchema, DiagnosticID: "B007-task0-" + g.binding.ManifestSHA[:24], RunID: f.Manifest.RunID, RunClassification: "DIAGNOSTIC",
			SeatID: entry.Seat, SessionID: request.Session.SessionID, InvocationID: request.RequestID, ProfileBinding: entry.Profile.BindingID(), SamplingBinding: entry.Sampling.BindingID(), BackendKind: entry.Profile.BackendKind,
			ProviderIdentity: entry.Profile.ProviderIdentity, ModelID: entry.Profile.ModelID, HarnessIdentity: entry.Profile.Harness.BindingID(), StructuredOutputMode: entry.Profile.StructuredOutputMode, ToolCallMode: entry.Profile.ToolCallMode,
			ContextHash: request.Invocation.Context.ContextHash, RequestSHA256: request.RequestSHA256, ResponseSHA256: result.ResponseSHA256, RetryIdentity: "ORIGINAL:1", CapabilityFingerprint: result.CapabilityFingerprint, CompletedAt: result.CompletedAt}
		if sink.RecordInvocation(ctx, observed) != nil {
			t.Fatal("unchanged B004 audit fixture")
		}
		receipts = append(receipts, runcore.Receipt{ActionID: request.RequestID})
	}
	models, assets, err := task0CollectPrivateModelEvidence(ctx, budget, g, receipts)
	if err != nil || len(models) != 11 || len(assets) != 35 {
		t.Fatal("actual ledgers/body binding rejected", len(models), len(assets), err)
	}
	defer task0ClearEvidenceAssets(assets)
	// Keep the original request, provider body/digest and PG audit untouched.
	// A contradictory terminal must fail collection across those exact streams.
	_, terminalName, _ := task0ModelEvidenceNames(receipts[1].ActionID)
	terminalPath := filepath.Join(budget.rootPath, terminalName)
	originalTerminal, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, attack := range []string{"context_ceiling", "enforcement", "zero_completed", "different_completed"} {
		t.Run(attack, func(t *testing.T) {
			var terminal task0ModelTerminal
			if json.Unmarshal(originalTerminal, &terminal) != nil {
				t.Fatal("fixture decode")
			}
			switch attack {
			case "context_ceiling":
				terminal.Result.EffectiveSampling.ContextUTF8ByteCeiling = 16384
			case "enforcement":
				terminal.Result.EffectiveSampling.EnforcementIdentity += "-foreign"
			case "zero_completed":
				terminal.Result.CompletedAt = time.Time{}
			case "different_completed":
				terminal.Result.CompletedAt = terminal.Result.CompletedAt.Add(time.Second)
			}
			body, err := task0PrivateCanonicalLine(terminal)
			if err != nil {
				t.Fatal(err)
			}
			rewrite := func(raw []byte) {
				if os.Chmod(terminalPath, 0600) != nil || os.WriteFile(terminalPath, raw, 0600) != nil || os.Chmod(terminalPath, 0400) != nil {
					t.Fatal("fixture rewrite")
				}
			}
			defer rewrite(originalTerminal)
			rewrite(body)
			models, badAssets, err := task0CollectPrivateModelEvidence(ctx, budget, g, receipts)
			task0ClearEvidenceAssets(badAssets)
			if err == nil || len(models) != 0 {
				t.Fatal("contradictory terminal crossed ledger closure")
			}
		})
	}
	asset, err := task0CapturePrivateBudgetEvidence(ctx, budget, g, models)
	if err != nil {
		t.Fatal(err)
	}
	var budgetProof task0PrivateBudgetEvidence
	if decodeFrozenJSON(asset.Data[:len(asset.Data)-1], 1<<20, &budgetProof) != nil || len(budgetProof.Reservations) != 11 || budgetProof.Totals.RemoteAttempts != 10 || budgetProof.Totals.LocalCalls != 1 {
		t.Fatal("actual budget evidence incomplete")
	}
	clear(asset.Data)
	changed := append([]runcore.Receipt(nil), receipts...)
	changed[1].ActionID += "-foreign"
	if _, _, err := task0CollectPrivateModelEvidence(ctx, budget, g, changed); err == nil {
		t.Fatal("foreign action observation accepted")
	}
	duplicate := slices.Clone(models)
	duplicate[1].ExecutionID = duplicate[0].ExecutionID
	if _, err := task0CapturePrivateBudgetEvidence(ctx, budget, g, duplicate); err == nil {
		t.Fatal("duplicate model reservation accepted")
	}
	local := &acceptedPilotLocalGrant{binding: pilotLocalBinding{Profile: entries[0].Profile}}
	memory, err := newTask0MemoryReceiptWriter(budget, local)
	if err != nil {
		t.Fatal(err)
	}
	_, memoryReceipts := task0MemoryEvidenceFixture(t)
	for i := range memoryReceipts {
		memoryReceipts[i].Before.ObservedAt = localCompleted.Add(time.Duration(2*i-3) * time.Second)
		memoryReceipts[i].After.ObservedAt = memoryReceipts[i].Before.ObservedAt.Add(time.Second)
		if _, err := memory.Write(task0MemoryLines(t, memoryReceipts[i:i+1])); err != nil {
			t.Fatal(err)
		}
	}
	if memory.Close() != nil {
		t.Fatal("synthetic memory evidence seal")
	}
	proof := nonCanonCompletedNativeProof(t, func(rows []NativeInputReceipt) {
		for i := range rows {
			rows[i].ClosureSHA256 = g.binding.RuntimeManifestSHA
			rows[i].NativeSHA256 = local.binding.Profile.LocalRuntimeIdentity.BinarySHA256
		}
	})
	if persistTask0PrivateRecord(budget, "task0-native-input-proof.private.jsonl", proof) != nil {
		t.Fatal("synthetic native proof seal")
	}
	gates, err := task0CollectPrivateLocalGates(budget, g, models)
	if err != nil || len(gates) != 2 {
		t.Fatal("local gated evidence incomplete", err)
	}
	task0ClearEvidenceAssets(gates)
}
