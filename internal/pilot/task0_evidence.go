package pilot

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"syscall"

	"github.com/zyc14588/AIPT/internal/evidence"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/runcore"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
)

// Publication is a one-shot private authority held by the trusted preparation
// process. Neither a model frame nor a Web/RPC command selects these roots,
// a key, a source verifier, the RAW stream or the completion implementation.
type task0EvidencePublisher struct {
	mu        sync.Mutex
	budget    *GlobalBudget
	grant     *acceptedTask0DispatchGrant
	root      *os.File
	rootState syscall.Stat_t
	key       *evidence.PrivateAuditKey
	consumed  bool
	closed    bool
}

func newTask0EvidencePublisher(ctx context.Context, budget *GlobalBudget, grant *acceptedTask0DispatchGrant, rootPath string, key *evidence.PrivateAuditKey) (*task0EvidencePublisher, error) {
	if task0CheckBudgetTransport(ctx, budget, grant) != nil || key == nil || len(key.Reference()) != 36 || !task0SeparatePrivatePaths(rootPath, budget.rootPath) {
		return nil, ErrTask0
	}
	root, state, err := task0OpenPrivateReportRoot(rootPath)
	if err != nil {
		return nil, ErrTask0
	}
	return &task0EvidencePublisher{budget: budget, grant: grant, root: root, rootState: state, key: key}, nil
}

func (p *task0EvidencePublisher) stable() bool {
	if p == nil || p.closed || p.root == nil || p.key == nil || p.budget == nil || p.budget.checkRoot() != nil {
		return false
	}
	var state syscall.Stat_t
	return syscall.Fstat(int(p.root.Fd()), &state) == nil && task0SameReportDirectory(p.rootState, state)
}

// The final completion is produced only after the unchanged RAW exporter,
// Q011 authenticated encryption, a fresh independent GitHub/AEAD verifier,
// and the concrete B007 Reports adapter all agree on the same ciphertext root.
// Partial RAW/publication history survives failure and never authorizes retry.
func (p *task0EvidencePublisher) publish(ctx context.Context, table *task0Table, result task0TableResult, reports *task0PrivateReports) (runcontrol.Completion, error) {
	var zero runcontrol.Completion
	if p == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrTask0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.consumed || !p.stable() || reports == nil || reports.budget != p.budget || reports.grant != p.grant || reports.rootState.Dev != p.rootState.Dev || reports.rootState.Ino != p.rootState.Ino ||
		table == nil || table.budget != p.budget || table.core == nil || table.store == nil || table.kernel == nil || table.run == nil || table.seed == nil || !table.started || !table.finished ||
		result.turns < 5 || result.turns+5 > MaxRemoteAttempts || len(table.receipts) != result.turns+1 || !task0SameJSON(table.last, result.finalReceipt) || !task0SameJSON(table.receipts[len(table.receipts)-1], table.last) ||
		result.replay.StateHash != table.last.StateHash || result.replay.ProjectionHash != table.last.ProjectionHash || result.replay.EventCount != result.turns+1 {
		return zero, ErrTask0
	}
	p.consumed = true
	if !slices.Equal(result.visited, []orchestrator.SeatID{orchestrator.SeatGM, orchestrator.SeatPlayer1, orchestrator.SeatPlayer2, orchestrator.SeatPlayer3, orchestrator.SeatPlayer4}) {
		return zero, ErrTask0
	}
	name := inputSHA([]byte(p.grant.manifest.Manifest.RunID))
	if syscall.Mkdirat(int(p.root.Fd()), name, 0700) != nil || p.root.Sync() != nil {
		return zero, ErrTask0
	}
	runDir, runState, err := task0OpenReportDirectoryAt(p.root, name)
	if err != nil {
		return zero, ErrTask0
	}
	defer runDir.Close()
	// The terminal parent is a real held directory, while the intermediate
	// proc FD anchor prevents mutable ancestor paths from selecting a new root.
	// No proc path is serialized into an evidence member or public response.
	heldPath := fmt.Sprintf("/proc/self/fd/%d/%s", p.root.Fd(), name)
	rawPath := filepath.Join(heldPath, "raw-capture")
	source := evidence.SourceIdentity{Repository: task0EvidenceRepository, Commit: p.grant.binding.Implementation.Commit, Tree: p.grant.binding.Implementation.Tree}
	raw, err := evidence.ExportRawCapture(ctx, evidence.NewPostgresSource(p.budget.pool), evidence.ExportInput{Destination: rawPath, Source: source, StreamID: "aipt.run-core:" + p.grant.manifest.Manifest.RunID})
	if err != nil || raw.Manifest.EventCount != int64(result.turns+1) || raw.Manifest.TailSequence != table.last.Sequence || raw.Manifest.TailEventHash == nil || *raw.Manifest.TailEventHash != table.last.EventHash {
		return zero, ErrTask0
	}
	events, err := table.store.Load(ctx, raw.Manifest.StreamID)
	if err != nil || len(events) != result.turns+1 {
		return zero, ErrTask0
	}
	for i, event := range events {
		if event.Sequence != table.receipts[i].Sequence || hex.EncodeToString(event.EventHash[:]) != table.receipts[i].EventHash {
			return zero, ErrTask0
		}
	}
	seed, err := table.seed.replaySeed()
	if err != nil {
		return zero, ErrTask0
	}
	replay, err := table.core.Replay(ctx, runcore.ReplayInput{Binding: table.kernel.binding, Seed: seed, Events: events, ExpectedFinalStateHash: table.last.StateHash})
	clear(seed)
	if err != nil || replay.StateHash != table.last.StateHash || replay.ProjectionHash != table.last.ProjectionHash || replay.EventCount != len(events) || !bytes.Equal(replay.State.DomainState, table.run.State().DomainState) {
		return zero, ErrTask0
	}
	models, assets, err := task0CollectPrivateModelEvidence(ctx, p.budget, p.grant, table.receipts)
	if err != nil {
		return zero, ErrTask0
	}
	defer func() { task0ClearEvidenceAssets(assets) }()
	localGates, err := task0CollectPrivateLocalGates(p.budget, p.grant, models)
	if err != nil {
		return zero, ErrTask0
	}
	assets = append(assets, localGates...)
	// B003 orchestration and floor streams are retained in addition to, never
	// instead of, the complete authoritative Core RAW stream.
	for _, suffix := range []string{"engine", "floor"} {
		stream := "aipt.b007-task0-" + suffix + ":" + p.grant.manifest.Manifest.RunID
		snapshot, e := evidence.NewPostgresSource(p.budget.pool).Capture(ctx, stream)
		if e != nil || snapshot.EventCount < 1 || (suffix == "engine" && snapshot.EventCount != int64(table.engineEvents)) || (suffix == "floor" && snapshot.EventCount != int64(table.floorEvents)) {
			return zero, ErrTask0
		}
		asset, _, e := task0PrivateEvidenceAsset("private/"+suffix+"-ledger.json", "b007-"+suffix+"-ledger", task0LedgerEnvelope(snapshot))
		if e != nil {
			return zero, ErrTask0
		}
		assets = append(assets, asset)
	}
	budgetAsset, err := task0CapturePrivateBudgetEvidence(ctx, p.budget, p.grant, models)
	if err != nil {
		return zero, ErrTask0
	}
	assets = append(assets, budgetAsset)
	totals, err := p.budget.Totals(ctx)
	if err != nil || !task0SameJSON(totals, result.budget) || totals.RemoteAttempts != result.turns+5 || totals.LocalCalls != 1 {
		return zero, ErrTask0
	}
	input, err := task0BuildPrivateEvidenceInput(p.grant, raw, table.receipts, replay, result.visited, totals, models, assets, p.key.Reference())
	if err != nil {
		return zero, ErrTask0
	}
	defer task0ClearEvidenceAssets(input.Supplemental)
	rawDir, rawState, err := task0OpenReportDirectoryAt(runDir, "raw-capture")
	if err != nil {
		return zero, ErrTask0
	}
	defer rawDir.Close()
	// The Q011 generator owns descriptor-relative acquisition, full RAW byte
	// verification and an absent exclusive child; no proc pathname is accepted
	// as a substitute for its original anti-symlink path entry.
	generated, err := evidence.GeneratePrivateAuditReadyAt(ctx, runDir, "audit-ready", rawDir, input, p.key)
	if err != nil {
		return zero, ErrTask0
	}
	defer func() {
		for _, member := range generated.LogicalAssets {
			clear(member)
		}
	}()
	if !p.stable() || !task0ReportDirectoryMatches(p.root, name, runState) || !task0ReportDirectoryMatches(runDir, "raw-capture", rawState) {
		return zero, ErrTask0
	}
	f := p.grant.manifest
	record := postgres.RunRecord{RunID: f.Manifest.RunID, ManifestID: f.Manifest.ManifestID, Classification: "DIAGNOSTIC", QualificationEligible: false, ManifestCanonical: f.Canonical, ManifestSHA256: f.Digest}
	view, err := reports.Inspect(ctx, record)
	if err != nil || view.Root != generated.Root || view.ExecutionStatus != "COMPLETED" || view.QualificationEligible || ctx.Err() != nil || !p.stable() || !task0ReportDirectoryMatches(p.root, name, runState) {
		return zero, ErrTask0
	}
	root, err := hex.DecodeString(view.Root)
	if err != nil || len(root) != 32 {
		return zero, ErrTask0
	}
	copy(zero.AuditReadyRoot[:], root)
	return zero, nil
}

func (p *task0EvidencePublisher) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.root != nil {
		return p.root.Close()
	}
	return nil
}

func task0PrivateEvidenceAsset(path, id string, value any) (evidence.LogicalAssetInput, evidence.EvidenceReference, error) {
	body, err := task0PrivateCanonicalLine(value)
	if err != nil {
		return evidence.LogicalAssetInput{}, evidence.EvidenceReference{}, ErrTask0
	}
	return evidence.LogicalAssetInput{Path: path, MediaType: "application/json", Classification: evidence.ContentTableHiddenRemote, ContentKind: evidence.ContentKindContract, Data: body}, evidence.EvidenceReference{ID: id, Path: path, SHA256: inputSHA(body)}, nil
}

func task0ClearEvidenceAssets(assets []evidence.LogicalAssetInput) {
	for _, asset := range assets {
		clear(asset.Data)
	}
}

func task0BuildPrivateEvidenceInput(grant *acceptedTask0DispatchGrant, raw evidence.Verification, receipts []runcore.Receipt, replay runcore.ReplayResult, visited []orchestrator.SeatID, totals BudgetTotals, models []evidence.ModelExecutionReference, supplemental []evidence.LogicalAssetInput, keyReference string) (evidence.GenerateAuditReadyInput, error) {
	fail := func() (evidence.GenerateAuditReadyInput, error) { return evidence.GenerateAuditReadyInput{}, ErrTask0 }
	if grant == nil || len(receipts) < 6 || len(receipts) > 27 || len(models) != len(receipts)+5 || !digest(raw.Root) || len(keyReference) != 36 ||
		totals.RemoteAttempts != len(receipts)+4 || totals.LocalCalls != 1 || totals.InputTokens != (totals.RemoteAttempts+1)*8192 || totals.OutputTokens != (totals.RemoteAttempts+1)*1024 ||
		totals.InputTokens > MaxInputTokens || totals.OutputTokens > MaxOutputTokens || totals.ReservedNanodollars < 0 || totals.ReservedNanodollars > MaxNanodollars ||
		!slices.Equal(visited, []orchestrator.SeatID{orchestrator.SeatGM, orchestrator.SeatPlayer1, orchestrator.SeatPlayer2, orchestrator.SeatPlayer3, orchestrator.SeatPlayer4}) {
		return fail()
	}
	source := evidence.SourceIdentity{Repository: task0EvidenceRepository, Commit: grant.binding.Implementation.Commit, Tree: grant.binding.Implementation.Tree}
	f := grant.manifest
	manifest := evidence.ArtifactIdentity{ID: f.Manifest.ManifestID, Schema: "aipt.run-manifest/v1", CanonicalSHA256: hex.EncodeToString(f.Digest[:])}
	last := receipts[len(receipts)-1]
	if raw.Manifest.Source != source || raw.Manifest.StreamID != "aipt.run-core:"+f.Manifest.RunID || raw.Manifest.EventCount != int64(len(receipts)) || raw.Manifest.TailSequence != last.Sequence || raw.Manifest.TailEventHash == nil ||
		*raw.Manifest.TailEventHash != last.EventHash || replay.State.Binding.Manifest.ID != manifest.ID || replay.State.Binding.Manifest.CanonicalSHA256 != manifest.CanonicalSHA256 ||
		replay.StateHash != last.StateHash || replay.ProjectionHash != last.ProjectionHash || replay.EventCount != len(receipts) || replay.State.Sequence != last.Sequence || replay.State.Binding.SourcePackage != task0PrototypeSourceBinding {
		return fail()
	}
	assets := slices.Clone(supplemental)
	closure := evidence.RunEvidenceClosure{Schema: evidence.RunClosureSchema, Version: evidence.ContractVersion, RunID: f.Manifest.RunID, RunManifest: manifest, Source: source, StateAuthority: "POSTGRESQL_APPEND_ONLY_HASH_CHAIN",
		Ledger:              evidence.LedgerIdentity{StreamID: raw.Manifest.StreamID, EventCount: raw.Manifest.EventCount, TailSequence: raw.Manifest.TailSequence, TailEventHash: raw.Manifest.TailEventHash},
		Projection:          evidence.ProjectionEvidence{Schema: runcore.RunProjectionSchema, CanonicalSHA256: last.ProjectionHash, FinalStateHash: last.StateHash},
		RuleCitations:       []evidence.RuleCitation{{RuleID: "B007-Q009-ACCEPTED-SOURCE-PACKAGE", SourceSHA256: task0PrototypeSourceBinding.CanonicalSHA256}, {RuleID: "B007-TASK0-ACTION-CONTRACT", SourceSHA256: "6fa75e95fd1508958c551aaa507a07deffeb8d8ccf8485de1c98478f2d20c7d9"}},
		DefectOccurrenceIDs: []string{}, AnomalyCodes: []string{}, GateEligibilityFacts: []evidence.GateEligibilityFact{{Gate: "QUALIFICATION", Eligible: false, ReasonCode: "OWNER_DIAGNOSTIC_NONQUALIFICATION_ONLY"}}, ModelExecutionReferences: slices.Clone(models)}
	rngUsed := false
	for i, receipt := range receipts {
		if receipt.Schema != runcore.ActionReceiptSchema || receipt.RunID != f.Manifest.RunID || receipt.Sequence != int64(i+1) || !digest(receipt.EventHash) || !digest(receipt.StateHash) || !digest(receipt.ProjectionHash) || (i == 0 && receipt.ActionID != "RUN_STARTED") {
			return fail()
		}
		asset, ref, err := task0PrivateEvidenceAsset(fmt.Sprintf("private/receipt-%03d.json", i), fmt.Sprintf("b007-receipt-%03d", i), receipt)
		if err != nil {
			return fail()
		}
		assets = append(assets, asset)
		closure.ActionReceipts = append(closure.ActionReceipts, evidence.ActionReceiptEvidence{ActionID: receipt.ActionID, Sequence: receipt.Sequence, EventHash: receipt.EventHash, StateHash: receipt.StateHash, ProjectionHash: receipt.ProjectionHash, Evidence: ref})
		rngUsed = rngUsed || len(receipt.RNGDraws) > 0
	}
	closure.RNG = evidence.RNGEvidence{Used: false, Version: "NONE", SeedDisclosureStatus: "NOT_APPLICABLE"}
	if rngUsed {
		closure.RNG = evidence.RNGEvidence{Used: true, Version: runcore.RNGVersionV1, SeedCommitment: replay.State.SeedCommitment, SeedDisclosureStatus: "COMMITTED_NOT_DISCLOSED"}
	}
	implementationAsset, implementationRef, err := task0PrivateEvidenceAsset("private/implementation-binding.json", "b007-implementation-binding", struct {
		Schema string               `json:"schema"`
		Grant  task0DispatchBinding `json:"dispatch"`
	}{"aipt.private.b007-task0-implementation-evidence/v1", grant.binding})
	if err != nil {
		return fail()
	}
	// This binding contains credential *references*, never credential values.
	// Keep it encrypted and reject private locator content at the Q011 boundary.
	assets = append(assets, implementationAsset)
	closure.Replay = evidence.ReplayEvidence{Schema: evidence.ReplayEvidenceSchema, Version: evidence.ContractVersion, RunID: f.Manifest.RunID, RunManifestSHA256: manifest.CanonicalSHA256,
		LedgerStreamID: closure.Ledger.StreamID, LedgerTailSequence: closure.Ledger.TailSequence, LedgerTailHash: closure.Ledger.TailEventHash, LiveFinalStateHash: last.StateHash, ReplayedFinalStateHash: replay.StateHash, HashMatch: true,
		Implementation: evidence.ReplayImplementation{ID: "AIPT-B007-TASK0-CORE-REPLAY", Version: "1", SHA256: implementationRef.SHA256}, RNG: closure.RNG}
	coverageAsset, coverageRef, err := task0PrivateEvidenceAsset("private/seat-coverage.json", "b007-seat-coverage", struct {
		Schema    string                `json:"schema"`
		Seats     []orchestrator.SeatID `json:"visited_seats"`
		TurnCount int                   `json:"turn_count"`
	}{"aipt.private.b007-task0-seat-coverage/v1", slices.Clone(visited), len(receipts) - 1})
	if err != nil {
		return fail()
	}
	assets = append(assets, coverageAsset)
	closure.CoverageReferences = []evidence.EvidenceReference{coverageRef}
	closure, err = evidence.NormalizeRunEvidenceClosure(closure)
	if err != nil {
		return fail()
	}
	closureBody, err := task0PrivateCanonicalLine(closure)
	if err != nil {
		return fail()
	}
	ids := make([]string, len(closure.ModelExecutionReferences))
	for i, model := range closure.ModelExecutionReferences {
		ids[i] = model.ExecutionID
	}
	report, err := evidence.NormalizeRunReport(evidence.RunReport{Schema: evidence.RunReportSchema, Version: evidence.ContractVersion, ReportID: "b007-private-" + inputSHA([]byte(f.Manifest.RunID)), Revision: 1, Lifecycle: evidence.ReportProvisional,
		RunID: f.Manifest.RunID, Source: source, RunManifest: manifest, ExecutionStatus: "COMPLETED", Coverage: evidence.CoverageSummary{Total: 5, Covered: 5, References: closure.CoverageReferences}, Replay: closure.Replay,
		ModelExecution: evidence.ModelExecutionFacts{RemoteDeepSeekRealCalls: int64(totals.RemoteAttempts), LocalLlamaCPPRealCalls: 1, ProviderModelNetworkCalls: int64(totals.RemoteAttempts), ReferenceIDs: ids}, GateEligibilityFacts: closure.GateEligibilityFacts, QualificationEligible: false,
		EvidenceRoots: []evidence.EvidenceRootIdentity{{Kind: "RAW_CAPTURE", SHA256: raw.Root}, {Kind: "RUN_EVIDENCE_CLOSURE", SHA256: inputSHA(closureBody)}}})
	if err != nil {
		return fail()
	}
	private := evidence.ContentTableHiddenRemote
	return evidence.GenerateAuditReadyInput{ExpectedRepository: task0EvidenceRepository, Disclosure: evidence.Disclosure{Profile: evidence.DisclosurePrivateFull, ContainsUnpublishedContent: true, Encryption: evidence.Encryption{Status: evidence.EncryptionEncrypted, Scheme: evidence.PrivateAuditEncryption, KeyReference: keyReference}},
		CoreClassifications: evidence.CoreEvidenceClassifications{Schema: evidence.CoreClassificationSchema, Version: evidence.ContractVersion, RawCapture: private, RunEvidenceClosure: private, ReplayEvidence: private, DefectFamily: private, DefectOccurrence: private, RunReport: private, ReportDerivatives: private},
		Closure:             closure, DefectFamilies: []evidence.DefectFamily{}, DefectOccurrences: []evidence.DefectOccurrence{}, Report: report, Supplemental: assets,
		ExportProfile: evidence.ExportProfile{ProfileID: "AIPT-B007-Q011-PRIVATE-FULL-V1", InlineThreshold: 65536, ChunkSize: 65536, MaxAssetBytes: 128 << 20, MaxTotalBytes: 256 << 20, MaxAssets: 10000, MaxChunks: 100000}}, nil
}
