package pilot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcore"
)

// NON_CANON contract assembly. This fixture is explicitly not a decrypted
// proof, PostgreSQL execution, controlled-real model call or completed Run.
func task0PrivateEvidenceFixture(t *testing.T) (*acceptedTask0DispatchGrant, evidence.Verification, []runcore.Receipt, runcore.ReplayResult, []orchestrator.SeatID, BudgetTotals, []evidence.ModelExecutionReference, []evidence.LogicalAssetInput) {
	t.Helper()
	b, f := task0DispatchBindingFixture(t)
	rawGrant, _ := json.Marshal(b)
	g, err := decodeTask0DispatchGrant(rawGrant, inputSHA(rawGrant), f)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := task0CoreBinding(f, b.Implementation)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]runcore.Receipt, 6)
	for i := range receipts {
		id := fmt.Sprintf("NON-CANON-action-%d", i)
		if i == 0 {
			id = "RUN_STARTED"
		}
		receipts[i] = runcore.Receipt{Schema: runcore.ActionReceiptSchema, RunID: f.Manifest.RunID, ActionID: id, Sequence: int64(i + 1), EventHash: inputSHA([]byte(fmt.Sprintf("event-%d", i))), StateHash: inputSHA([]byte(fmt.Sprintf("state-%d", i))), ProjectionHash: inputSHA([]byte(fmt.Sprintf("projection-%d", i))), RNGDraws: []runcore.RNGDraw{}}
	}
	last := receipts[5]
	source := evidence.SourceIdentity{Repository: task0EvidenceRepository, Commit: b.Implementation.Commit, Tree: b.Implementation.Tree}
	raw := evidence.Verification{Root: strings.Repeat("a", 64), Manifest: evidence.RawCaptureManifest{Schema: evidence.SchemaID, Version: evidence.SchemaVersion, Stage: evidence.RawCaptureStage, Source: source, StreamID: "aipt.run-core:" + f.Manifest.RunID, EventCount: 6, TailSequence: 6, TailEventHash: &last.EventHash, NormalizationVersion: evidence.NormalizationVersion}}
	replay := runcore.ReplayResult{State: runcore.RunState{Schema: runcore.RunStateSchema, Binding: binding, Sequence: 6, RNGVersion: runcore.RNGVersionV1, CommitmentVersion: runcore.SeedCommitmentV1, SeedCommitment: strings.Repeat("b", 64), RNGCursors: map[string]int64{}, DomainState: json.RawMessage(`{"NON_CANON":true}`)}, StateHash: last.StateHash, EventCount: 6, ProjectionHash: last.ProjectionHash}
	totals := BudgetTotals{RemoteAttempts: 10, LocalCalls: 1, InputTokens: 11 * 8192, OutputTokens: 11 * 1024, ReservedNanodollars: 1000}
	models := []evidence.ModelExecutionReference{}
	assets := []evidence.LogicalAssetInput{}
	for i := 0; i < 11; i++ {
		profile := b.Profiles[i%6].Profile
		id := fmt.Sprintf("NON-CANON-model-%d", i)
		asset, ref, err := task0PrivateEvidenceAsset("private/"+id+".json", id, map[string]string{"classification": "NON_CANON_PRIVATE_MODEL_BODY_CANARY"})
		if err != nil {
			t.Fatal(err)
		}
		models = append(models, evidence.ModelExecutionReference{ExecutionID: id, ModelProfile: profile.BindingID(), HarnessIdentity: profile.Harness.BindingID(), EvidenceSHA256: ref.SHA256})
		assets = append(assets, asset)
	}
	return g, raw, receipts, replay, orchestrator.BaselineSeats(), totals, models, assets
}

func TestTask0PrivateEvidenceInputBindsFullReceiptsReplayBudgetAndBodies(t *testing.T) {
	g, raw, receipts, replay, visited, totals, models, assets := task0PrivateEvidenceFixture(t)
	input, err := task0BuildPrivateEvidenceInput(g, raw, receipts, replay, visited, totals, models, assets, "key-"+strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	if input.Disclosure.Profile != evidence.DisclosurePrivateFull || !input.Disclosure.ContainsUnpublishedContent || input.Disclosure.Encryption.Status != evidence.EncryptionEncrypted || input.Report.QualificationEligible || input.Report.AuditorVerdictClaimed || input.Report.Lifecycle != evidence.ReportProvisional {
		t.Fatal("private/nonqualification boundary changed")
	}
	if len(input.Closure.ActionReceipts) != len(receipts) || len(input.Closure.ModelExecutionReferences) != len(models) || len(input.Report.ModelExecution.ReferenceIDs) != len(models) || input.Closure.Replay.LiveFinalStateHash != receipts[5].StateHash || input.Report.Coverage.Total != 5 || input.Report.Coverage.Covered != 5 {
		t.Fatal("full closure missing")
	}
	if input.Closure.RNG.Used || input.Closure.RNG.SeedCommitment != "" {
		t.Fatal("unused RNG seed disclosed")
	}
	for _, asset := range input.Supplemental {
		if asset.Classification != evidence.ContentTableHiddenRemote || bytes.Contains(asset.Data, []byte("root_seed_hex")) || bytes.Contains(asset.Data, []byte("/home/")) {
			t.Fatal("seed or private locator entered bundle")
		}
	}
	for i, receipt := range receipts {
		ref := input.Closure.ActionReceipts[i].Evidence
		found := false
		for _, asset := range input.Supplemental {
			if asset.Path == ref.Path {
				body, err := task0PrivateCanonicalLine(receipt)
				if err != nil || !bytes.Equal(body, asset.Data) || ref.SHA256 != inputSHA(body) {
					t.Fatal("receipt reconstructed or binding changed")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("receipt body absent")
		}
	}
}

func TestTask0PrivateEvidenceClosureRootIncludesCanonicalRecordTerminator(t *testing.T) {
	g, raw, receipts, replay, visited, totals, models, assets := task0PrivateEvidenceFixture(t)
	input, err := task0BuildPrivateEvidenceInput(g, raw, receipts, replay, visited, totals, models, assets, "key-"+strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(input.Closure)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// The existing B005 contract hashes the complete canonical JSONL record,
	// including its newline. A canonical JSON digest alone is a different root.
	record := sha256.Sum256(append([]byte(canonical), '\n'))
	unterminated := sha256.Sum256([]byte(canonical))
	found := false
	for _, root := range input.Report.EvidenceRoots {
		if root.Kind == "RUN_EVIDENCE_CLOSURE" {
			found = true
			if root.SHA256 != hex.EncodeToString(record[:]) || root.SHA256 == hex.EncodeToString(unterminated[:]) {
				t.Fatal("report closure root omitted its existing canonical record terminator")
			}
		}
	}
	if !found {
		t.Fatal("report closure root absent")
	}
}

func TestTask0PrivateEvidenceInputRejectsForeignSourceTruncationFalseReplayAndBudget(t *testing.T) {
	for _, attack := range []string{"short_repository", "source_commit", "source_tree", "stream", "missing_genesis", "receipt_schema", "receipt_run", "receipt_sequence", "receipt_event_hash", "raw_count", "raw_tail", "raw_hash", "replay_manifest", "replay_source", "replay_state_hash", "replay_projection", "replay_count", "replay_sequence", "missing_model", "duplicate_model", "missing_seat", "local_zero", "remote_count", "input_count", "output_count", "cost_ceiling"} {
		t.Run(attack, func(t *testing.T) {
			g, raw, receipts, replay, visited, totals, models, assets := task0PrivateEvidenceFixture(t)
			switch attack {
			case "short_repository":
				raw.Manifest.Source.Repository = "zyc14588/AIPT"
			case "source_commit":
				raw.Manifest.Source.Commit = strings.Repeat("e", 40)
			case "source_tree":
				raw.Manifest.Source.Tree = strings.Repeat("e", 40)
			case "stream":
				raw.Manifest.StreamID += "-foreign"
			case "missing_genesis":
				receipts[0].ActionID = "NON-CANON-action"
			case "receipt_schema":
				receipts[0].Schema = "aipt.receipt/v999"
			case "receipt_run":
				receipts[0].RunID += "-foreign"
			case "receipt_sequence":
				receipts[1].Sequence = 1
			case "receipt_event_hash":
				receipts[1].EventHash = "invalid"
			case "raw_count":
				raw.Manifest.EventCount--
			case "raw_tail":
				raw.Manifest.TailSequence--
			case "raw_hash":
				s := strings.Repeat("e", 64)
				raw.Manifest.TailEventHash = &s
			case "replay_manifest":
				replay.State.Binding.Manifest.ID += "-foreign"
			case "replay_source":
				replay.State.Binding.SourcePackage.Commit = strings.Repeat("e", 40)
			case "replay_state_hash":
				replay.StateHash = strings.Repeat("e", 64)
			case "replay_projection":
				replay.ProjectionHash = strings.Repeat("e", 64)
			case "replay_count":
				replay.EventCount--
			case "replay_sequence":
				replay.State.Sequence--
			case "missing_model":
				models = models[1:]
			case "duplicate_model":
				models[1].ExecutionID = models[0].ExecutionID
			case "missing_seat":
				visited = visited[1:]
			case "local_zero":
				totals.LocalCalls = 0
			case "remote_count":
				totals.RemoteAttempts++
			case "input_count":
				totals.InputTokens--
			case "output_count":
				totals.OutputTokens--
			case "cost_ceiling":
				totals.ReservedNanodollars = MaxNanodollars + 1
			}
			if _, err := task0BuildPrivateEvidenceInput(g, raw, receipts, replay, visited, totals, models, assets, "key-"+strings.Repeat("c", 32)); err == nil {
				t.Fatal("false closure accepted", attack)
			}
		})
	}
}

func TestTask0PrivateEvidenceInputRNGUsesCommitmentAndCompleteReceipts(t *testing.T) {
	g, raw, receipts, replay, visited, totals, models, assets := task0PrivateEvidenceFixture(t)
	receipts[3].RNGDraws = []runcore.RNGDraw{{Version: runcore.RNGVersionV1, StreamID: "NON-CANON-test", DrawIndex: 0, ValueHex: "00"}}
	input, err := task0BuildPrivateEvidenceInput(g, raw, receipts, replay, visited, totals, models, assets, "key-"+strings.Repeat("c", 32))
	if err != nil || !input.Closure.RNG.Used || input.Closure.RNG.SeedCommitment != replay.State.SeedCommitment || input.Closure.RNG.SeedDisclosureStatus != "COMMITTED_NOT_DISCLOSED" {
		t.Fatal("RNG commitment lost", err)
	}
}
