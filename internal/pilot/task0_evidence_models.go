package pilot

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/runcore"
)

type task0PrivateLedgerEvent struct {
	Sequence         int64     `json:"sequence"`
	EventID          string    `json:"event_id"`
	EventType        string    `json:"event_type"`
	PayloadCanonical string    `json:"payload_canonical"`
	PayloadSHA       string    `json:"payload_sha256"`
	PreviousHash     *string   `json:"previous_event_hash"`
	EventHash        string    `json:"event_hash"`
	CommittedAt      time.Time `json:"committed_at"`
}
type task0PrivateLedger struct {
	Schema       string                    `json:"schema"`
	StreamID     string                    `json:"stream_id"`
	EventCount   int64                     `json:"event_count"`
	TailSequence int64                     `json:"tail_sequence"`
	TailHash     *string                   `json:"tail_event_hash"`
	Events       []task0PrivateLedgerEvent `json:"events"`
}

func task0HashPointer(value *[32]byte) *string {
	if value == nil {
		return nil
	}
	s := hex.EncodeToString(value[:])
	return &s
}
func task0LedgerEnvelope(snapshot evidence.LedgerSnapshot) task0PrivateLedger {
	result := task0PrivateLedger{Schema: "aipt.private.b007-ledger-snapshot/v1", StreamID: snapshot.StreamID, EventCount: snapshot.EventCount, TailSequence: snapshot.TailSequence, TailHash: task0HashPointer(snapshot.TailHash), Events: []task0PrivateLedgerEvent{}}
	for _, event := range snapshot.Events {
		result.Events = append(result.Events, task0PrivateLedgerEvent{event.Sequence, event.EventID, event.EventType, event.PayloadCanonical, hex.EncodeToString(event.PayloadSHA256[:]), task0HashPointer(event.PrevEventHash), hex.EncodeToString(event.EventHash[:]), event.CommittedAt})
	}
	return result
}

type task0CertificationObservation struct {
	Schema         string                     `json:"schema"`
	RunID          string                     `json:"run_id"`
	RequestID      string                     `json:"request_id"`
	ProfileBinding string                     `json:"profile_binding"`
	RequestSHA     string                     `json:"request_sha256"`
	ManifestSHA    string                     `json:"manifest_sha256"`
	Event          string                     `json:"event"`
	Certification  modelgateway.Certification `json:"certification"`
}
type task0ModelBodyProof struct {
	Schema               string                     `json:"schema"`
	ManifestSHA          string                     `json:"manifest_sha256"`
	GrantSHA             string                     `json:"dispatch_grant_sha256"`
	RequestID            string                     `json:"request_id"`
	ProfileBinding       string                     `json:"profile_binding"`
	Request              evidence.EvidenceReference `json:"request"`
	Result               evidence.EvidenceReference `json:"result"`
	ObservationSHA       string                     `json:"postgres_observation_sha256"`
	ObservationEventHash string                     `json:"postgres_observation_event_hash"`
}

func task0CollectPrivateModelEvidence(ctx context.Context, budget *GlobalBudget, grant *acceptedTask0DispatchGrant, receipts []runcore.Receipt) ([]evidence.ModelExecutionReference, []evidence.LogicalAssetInput, error) {
	fail := func(assets []evidence.LogicalAssetInput) ([]evidence.ModelExecutionReference, []evidence.LogicalAssetInput, error) {
		task0ClearEvidenceAssets(assets)
		return nil, nil, ErrTask0
	}
	if ctx == nil || ctx.Err() != nil || task0CheckBudgetTransport(ctx, budget, grant) != nil || len(receipts) < 6 {
		return fail(nil)
	}
	source := evidence.NewPostgresSource(budget.pool)
	runID := grant.manifest.Manifest.RunID
	certs, err := source.Capture(ctx, "aipt.b007-role-certification:"+runID)
	if err != nil || certs.EventCount != 12 || len(certs.Events) != 12 {
		return fail(nil)
	}
	models := []evidence.ModelExecutionReference{}
	assets := []evidence.LogicalAssetInput{}
	seenRequests, seenProfiles := map[string]bool{}, map[string]bool{}
	appendBody := func(requestID string, observation evidence.LedgerEvent) (task0ModelIntent, task0ModelTerminal, error) {
		if seenRequests[requestID] {
			return task0ModelIntent{}, task0ModelTerminal{}, ErrTask0
		}
		intent, terminal, inRaw, outRaw, e := task0ReadModelEvidence(budget, grant, requestID)
		if e != nil {
			return intent, terminal, ErrTask0
		}
		seenRequests[requestID] = true
		hash := inputSHA([]byte(requestID))
		inPath, outPath := "private/model-"+hash+".request.json", "private/model-"+hash+".result.json"
		inRef, outRef := evidence.EvidenceReference{ID: "request-" + hash, Path: inPath, SHA256: inputSHA(inRaw)}, evidence.EvidenceReference{ID: "result-" + hash, Path: outPath, SHA256: inputSHA(outRaw)}
		assets = append(assets, evidence.LogicalAssetInput{Path: inPath, MediaType: "application/json", Classification: evidence.ContentTableHiddenRemote, ContentKind: evidence.ContentKindPrivatePrompt, Data: inRaw}, evidence.LogicalAssetInput{Path: outPath, MediaType: "application/json", Classification: evidence.ContentTableHiddenRemote, ContentKind: evidence.ContentKindGameBody, Data: outRaw})
		proof := task0ModelBodyProof{"aipt.private.b007-model-body-proof/v1", grant.binding.ManifestSHA, grant.identity, requestID, intent.Request.ProfileBinding, inRef, outRef, hex.EncodeToString(observation.PayloadSHA256[:]), hex.EncodeToString(observation.EventHash[:])}
		asset, ref, e := task0PrivateEvidenceAsset("private/model-"+hash+".proof.json", "proof-"+hash, proof)
		if e != nil {
			return intent, terminal, e
		}
		assets = append(assets, asset)
		models = append(models, evidence.ModelExecutionReference{ExecutionID: requestID, ModelProfile: intent.Request.ProfileBinding, HarnessIdentity: intent.Request.HarnessIdentity, EvidenceSHA256: ref.SHA256})
		return intent, terminal, nil
	}
	for i := 0; i < 12; i += 2 {
		before, after := certs.Events[i], certs.Events[i+1]
		var intent, pass task0CertificationObservation
		if decodeFrozenJSON([]byte(before.PayloadCanonical), 1<<20, &intent) != nil || decodeFrozenJSON([]byte(after.PayloadCanonical), 1<<20, &pass) != nil ||
			before.EventType != "AIPT_B007_ROLE_CERTIFICATION_INTENT" || after.EventType != "AIPT_B007_ROLE_CERTIFICATION_PASS" ||
			intent.Schema != "aipt.private.b007-role-certification-observation/v1" || pass.Schema != intent.Schema || intent.RunID != runID || pass.RunID != runID ||
			intent.ManifestSHA != grant.binding.ManifestSHA || pass.ManifestSHA != intent.ManifestSHA || intent.Event != "INTENT" || pass.Event != "PASS" ||
			intent.RequestID != pass.RequestID || intent.ProfileBinding != pass.ProfileBinding || intent.RequestSHA != pass.RequestSHA ||
			before.EventID != intent.RequestID+"-INTENT" || after.EventID != pass.RequestID+"-PASS" || !task0SameJSON(intent.Certification, modelgateway.Certification{}) || seenProfiles[pass.ProfileBinding] {
			return fail(assets)
		}
		entry, ok := grant.profiles[pass.ProfileBinding]
		if !ok {
			return fail(assets)
		}
		body, terminal, e := appendBody(pass.RequestID, after)
		if e != nil || body.Request.ProfileBinding != pass.ProfileBinding || body.Request.RequestSHA256 != pass.RequestSHA {
			return fail(assets)
		}
		rebound, e := task0CertificationFromResult(entry, body.Request, *terminal.Result, pass.Certification.ObservedAt)
		if e != nil || !task0SameJSON(rebound, pass.Certification) {
			return fail(assets)
		}
		seenProfiles[pass.ProfileBinding] = true
	}
	if len(seenProfiles) != 6 {
		return fail(assets)
	}
	ledgerAsset, _, err := task0PrivateEvidenceAsset("private/role-certification-ledger.json", "b007-role-certification-ledger", task0LedgerEnvelope(certs))
	if err != nil {
		return fail(assets)
	}
	assets = append(assets, ledgerAsset)
	game, err := source.Capture(ctx, "aipt-model-run-audit-v1-"+inputSHA([]byte(runID)))
	if err != nil || game.EventCount != int64(len(receipts)-1) || len(game.Events) != len(receipts)-1 {
		return fail(assets)
	}
	for i, event := range game.Events {
		var observed modelgateway.InvocationEvidence
		if event.EventType != "AIPT_MODEL_INVOCATION_V1" || decodeFrozenJSON([]byte(event.PayloadCanonical), 1<<20, &observed) != nil ||
			observed.Schema != modelgateway.InvocationEvidenceSchema || observed.RunID != runID || observed.DiagnosticID != "B007-task0-"+grant.binding.ManifestSHA[:24] ||
			observed.RunClassification != "DIAGNOSTIC" || observed.CleanBaselineEligible || observed.BreakGlassUsed || observed.BreakGlassGrantSHA256 != "" ||
			observed.InvocationID != receipts[i+1].ActionID || observed.RetryIdentity != "ORIGINAL:1" || modelgateway.EvidenceSafe(observed) != nil {
			return fail(assets)
		}
		body, terminal, e := appendBody(observed.InvocationID, event)
		if e != nil || body.Request.BackendKind != modelgateway.BackendRemoteDeepSeek || observed.SeatID != body.Request.Session.SeatID || observed.SessionID != body.Request.Session.SessionID ||
			observed.ProfileBinding != body.Request.ProfileBinding || observed.SamplingBinding != body.Request.SamplingBinding || observed.RequestSHA256 != body.Request.RequestSHA256 || observed.ResponseSHA256 != terminal.Result.ResponseSHA256 ||
			observed.ContextHash != body.Request.Invocation.Context.ContextHash || observed.BackendKind != body.Request.BackendKind || observed.ProviderIdentity != body.Request.ProviderIdentity || observed.ModelID != body.Request.ExpectedModelID ||
			observed.HarnessIdentity != body.Request.HarnessIdentity || observed.StructuredOutputMode != body.Request.StructuredMode || observed.ToolCallMode != body.Request.ToolMode || observed.CapabilityFingerprint != terminal.Result.CapabilityFingerprint ||
			terminal.Result.CompletedAt.IsZero() || !observed.CompletedAt.Equal(terminal.Result.CompletedAt) {
			return fail(assets)
		}
	}
	ledgerAsset, _, err = task0PrivateEvidenceAsset("private/model-invocation-ledger.json", "b007-model-invocation-ledger", task0LedgerEnvelope(game))
	if err != nil || len(models) != len(receipts)+5 {
		return fail(assets)
	}
	assets = append(assets, ledgerAsset)
	return models, assets, nil
}

type task0PrivateReservation struct {
	RequestID  string    `json:"request_id"`
	Kind       string    `json:"kind"`
	Input      int       `json:"input_reserved_tokens"`
	Output     int       `json:"output_reserved_tokens"`
	Cost       int64     `json:"reserved_nanodollars"`
	ProofSHA   string    `json:"wire_proof_sha256"`
	ClosureSHA string    `json:"runtime_closure_sha256"`
	ReservedAt time.Time `json:"reserved_at"`
}
type task0PrivateBudgetEvidence struct {
	Schema       string                    `json:"schema"`
	AuthoritySHA string                    `json:"authority_sha256"`
	RunID        string                    `json:"run_id"`
	ManifestSHA  string                    `json:"manifest_sha256"`
	Pricing      Pricing                   `json:"pricing"`
	Totals       BudgetTotals              `json:"totals"`
	Reservations []task0PrivateReservation `json:"reservations"`
}

func task0CapturePrivateBudgetEvidence(ctx context.Context, budget *GlobalBudget, grant *acceptedTask0DispatchGrant, models []evidence.ModelExecutionReference) (evidence.LogicalAssetInput, error) {
	if task0CheckBudgetTransport(ctx, budget, grant) != nil {
		return evidence.LogicalAssetInput{}, ErrTask0
	}
	totals, err := budget.Totals(ctx)
	if err != nil || len(models) != totals.RemoteAttempts+totals.LocalCalls {
		return evidence.LogicalAssetInput{}, ErrTask0
	}
	rows, err := budget.pool.Query(ctx, `SELECT attempt_id,kind,input_tokens,output_tokens,nanodollars,proof_sha,closure_sha,reserved_at FROM aipt.b007_budget_reservations WHERE authority_sha=$1 ORDER BY reserved_at,attempt_id LIMIT 34`, BudgetAuthority)
	if err != nil {
		return evidence.LogicalAssetInput{}, ErrTask0
	}
	defer rows.Close()
	bound := make(map[string]task0DispatchProfile, len(models))
	for _, model := range models {
		entry, ok := grant.profiles[model.ModelProfile]
		if !ok || bound[model.ExecutionID].Profile.ProfileID != "" {
			return evidence.LogicalAssetInput{}, ErrTask0
		}
		bound[model.ExecutionID] = entry
	}
	result := task0PrivateBudgetEvidence{"aipt.private.b007-budget-evidence/v1", BudgetAuthority, grant.manifest.Manifest.RunID, grant.binding.ManifestSHA, budget.price, totals, []task0PrivateReservation{}}
	computed := BudgetTotals{}
	for rows.Next() {
		var row task0PrivateReservation
		if rows.Scan(&row.RequestID, &row.Kind, &row.Input, &row.Output, &row.Cost, &row.ProofSHA, &row.ClosureSHA, &row.ReservedAt) != nil {
			return evidence.LogicalAssetInput{}, ErrTask0
		}
		entry, ok := bound[row.RequestID]
		if !ok || row.Input != 8192 || row.Output != 1024 || row.ProofSHA != grant.binding.FullReviewSHA || row.ClosureSHA != b007BundleSHA || row.ReservedAt.IsZero() {
			return evidence.LogicalAssetInput{}, ErrTask0
		}
		delete(bound, row.RequestID)
		cost := int64(0)
		if row.Kind == "REMOTE" && entry.Profile.BackendKind == modelgateway.BackendRemoteDeepSeek {
			computed.RemoteAttempts++
			cost = 8192*budget.price.InputNanodollars + 1024*budget.price.OutputNanodollars
		} else if row.Kind == "LOCAL" && entry.Profile.BackendKind == modelgateway.BackendLocalLlamaCPP {
			computed.LocalCalls++
		} else {
			return evidence.LogicalAssetInput{}, ErrTask0
		}
		if row.Cost != cost {
			return evidence.LogicalAssetInput{}, ErrTask0
		}
		computed.InputTokens += row.Input
		computed.OutputTokens += row.Output
		computed.ReservedNanodollars += row.Cost
		result.Reservations = append(result.Reservations, row)
	}
	if rows.Err() != nil || len(bound) != 0 || !task0SameJSON(computed, totals) || !task0SameJSON(result.Totals, totals) {
		return evidence.LogicalAssetInput{}, ErrTask0
	}
	after, err := budget.Totals(ctx)
	if err != nil || !task0SameJSON(after, totals) {
		return evidence.LogicalAssetInput{}, ErrTask0
	}
	asset, _, err := task0PrivateEvidenceAsset("private/budget-evidence.json", fmt.Sprintf("b007-budget-evidence-%s", grant.binding.ManifestSHA[:16]), result)
	return asset, err
}
