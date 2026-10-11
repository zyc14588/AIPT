package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/runcore"
)

type privateAuditFixtureSeed []byte

func (s privateAuditFixtureSeed) RootSeed(context.Context, runcore.RunBinding) ([]byte, error) {
	return bytes.Clone(s), nil
}

type privateAuditFixtureState struct {
	Counter  int    `json:"counter"`
	Hidden   string `json:"hidden"`
	LastDraw string `json:"last_draw"`
}
type privateAuditFixtureHandler struct{}

func (privateAuditFixtureHandler) ValidatePayload(p runcore.ActionProposal) error {
	if !bytes.Equal(p.Payload, []byte(`{"delta":1}`)) {
		return ErrPrivateAudit
	}
	return nil
}
func (privateAuditFixtureHandler) ValidatePrecondition(context.Context, runcore.RunState, runcore.ActionProposal) error {
	return nil
}
func (privateAuditFixtureHandler) Apply(_ context.Context, s runcore.RunState, _ runcore.ActionProposal, draws []runcore.RNGDraw) (json.RawMessage, error) {
	var state privateAuditFixtureState
	if json.Unmarshal(s.DomainState, &state) != nil {
		return nil, ErrPrivateAudit
	}
	state.Counter++
	if len(draws) == 1 {
		state.LastDraw = draws[0].ValueHex
	}
	return json.Marshal(state)
}

// NON_CANON integration. It executes the unchanged real Core/PostgreSQL and
// complete RAW exporter with private synthetic domain data, then authenticates
// every encrypted core member and performs exact replay. Its source verifier
// is the existing package-private offline seam; no model or GitHub is called.
func TestPostgresIntegrationPrivateAuditActualCoreRawEncryptedReplay(t *testing.T) {
	fixture := newEvidenceIntegrationFixture(t)
	pool := fixture.pool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := runcore.NewPostgreSQLStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x27}, 32)
	binding := runcore.RunBinding{Schema: runcore.RunBindingSchema, RunID: "NON-CANON-private-core",
		Manifest:            runcore.ArtifactBinding{ID: "NON-CANON-private-manifest", Schema: "aipt.run-manifest/v1", CanonicalSHA256: repeatSHA("3")},
		RuntimeAdapterInput: runcore.ArtifactBinding{ID: "NON-CANON-private-adapter", Schema: "aipt.synthetic-adapter/v1", CanonicalSHA256: repeatSHA("4")},
		SourcePackage:       runcore.SourcePackageBinding{PackageID: "NON-CANON-private-source", Schema: "aipt.synthetic-source/v1", Repository: "synthetic/fixture", Commit: strings.Repeat("5", 40), Tree: strings.Repeat("6", 40), CanonicalSHA256: repeatSHA("7")}}
	core, err := runcore.New(runcore.Config{Store: store, SeedSource: privateAuditFixtureSeed(seed),
		Authorizer: runcore.AuthorizerFunc(func(context.Context, runcore.RunState, runcore.ActionProposal) error { return nil }),
		Rules:      runcore.RuleValidatorFunc(func(context.Context, runcore.RunState, runcore.ActionProposal) error { return nil }),
		Handlers:   map[string]runcore.ActionHandler{"NON_CANON_INCREMENT": privateAuditFixtureHandler{}},
		Invariants: []runcore.Invariant{runcore.InvariantFunc(func(s runcore.RunState) error {
			var domain privateAuditFixtureState
			if json.Unmarshal(s.DomainState, &domain) != nil || domain.Hidden != "NON_CANON_PRIVATE_CORE_BODY_CANARY" {
				return ErrPrivateAudit
			}
			return nil
		})}})
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := json.Marshal(privateAuditFixtureState{Hidden: "NON_CANON_PRIVATE_CORE_BODY_CANARY"})
	run, genesis, err := core.StartRun(ctx, runcore.StartRunInput{Binding: binding, InitialState: initial})
	if err != nil {
		t.Fatal(err)
	}
	receipts := []runcore.Receipt{genesis}
	for i := 0; i < 2; i++ {
		requests := []runcore.RNGRequest{}
		if i == 1 {
			requests = append(requests, runcore.RNGRequest{StreamID: "NON-CANON-private-draw", Count: 1})
		}
		p := runcore.ActionProposal{Schema: runcore.ActionProposalSchema, RunID: binding.RunID, ActionID: fmt.Sprintf("NON-CANON-action-%d", i), ActorID: "NON-CANON-actor", ActionType: "NON_CANON_INCREMENT", ExpectedSequence: run.State().Sequence,
			Source: runcore.RuleSource{Kind: runcore.RuleSourceExplicit, Reference: "NON-CANON-rule"}, Payload: json.RawMessage(`{"delta":1}`), RNGRequests: requests}
		raw, _ := json.Marshal(p)
		receipt, err := run.Execute(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
	}
	events, err := store.Load(ctx, "aipt.run-core:"+binding.RunID)
	if err != nil || len(events) != 3 {
		t.Fatal("actual complete Core trace missing", err)
	}
	final := receipts[len(receipts)-1]
	replayed, err := core.Replay(ctx, runcore.ReplayInput{Binding: binding, Seed: seed, Events: events, ExpectedFinalStateHash: final.StateHash})
	if err != nil || !bytes.Equal(replayed.State.DomainState, run.State().DomainState) || replayed.ProjectionHash != final.ProjectionHash {
		t.Fatal("actual Core replay differs", err)
	}
	rawPath := filepath.Join(privateTempDir(t), "raw-capture")
	source := fixtureSourceIdentity()
	source.Repository = privateAuditRepositoryURL
	rawCapture, err := ExportRawCapture(ctx, NewPostgresSource(pool), ExportInput{Destination: rawPath, Source: source, StreamID: "aipt.run-core:" + binding.RunID})
	if err != nil {
		t.Fatal(err)
	}
	input, verifier := fixtureAuditInputForRaw(t, rawPath, fixtureExportProfile())
	key, err := CreatePrivateAuditKey(privateTempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	input.Destination = filepath.Join(privateTempDir(t), "private-audit")
	input.Disclosure = Disclosure{Profile: DisclosurePrivateFull, ContainsUnpublishedContent: true, Encryption: Encryption{Status: EncryptionEncrypted, Scheme: PrivateAuditEncryption, KeyReference: key.Reference()}}
	input.CoreClassifications.RawCapture = ContentTableHiddenRemote
	input.CoreClassifications.RunEvidenceClosure = ContentTableHiddenRemote
	input.CoreClassifications.ReplayEvidence = ContentTableHiddenRemote
	input.CoreClassifications.RunReport = ContentTableHiddenRemote
	input.CoreClassifications.ReportDerivatives = ContentTableHiddenRemote
	closure := input.Closure
	closure.RunID = binding.RunID
	closure.RunManifest = ArtifactIdentity{ID: binding.Manifest.ID, Schema: binding.Manifest.Schema, CanonicalSHA256: binding.Manifest.CanonicalSHA256}
	closure.Projection = ProjectionEvidence{Schema: runcore.RunProjectionSchema, CanonicalSHA256: final.ProjectionHash, FinalStateHash: final.StateHash}
	closure.ActionReceipts = nil
	for i, receipt := range receipts {
		body, err := canonicalLine(receipt)
		if err != nil {
			t.Fatal(err)
		}
		ref := EvidenceReference{ID: fmt.Sprintf("NON-CANON-receipt-%d", i), Path: fmt.Sprintf("private/receipt-%d.json", i), SHA256: digestText(body)}
		input.Supplemental = append(input.Supplemental, LogicalAssetInput{Path: ref.Path, MediaType: "application/json", Classification: ContentTableHiddenRemote, ContentKind: ContentKindContract, Data: body})
		closure.ActionReceipts = append(closure.ActionReceipts, ActionReceiptEvidence{ActionID: receipt.ActionID, Sequence: receipt.Sequence, EventHash: receipt.EventHash, StateHash: receipt.StateHash, ProjectionHash: receipt.ProjectionHash, Evidence: ref})
	}
	closure.RNG = RNGEvidence{Used: true, Version: runcore.RNGVersionV1, SeedCommitment: run.State().SeedCommitment, SeedDisclosureStatus: "COMMITTED_NOT_DISCLOSED"}
	closure.Replay.RunID = binding.RunID
	closure.Replay.RunManifestSHA256 = binding.Manifest.CanonicalSHA256
	closure.Replay.LiveFinalStateHash = closure.Projection.FinalStateHash
	closure.Replay.ReplayedFinalStateHash = closure.Projection.FinalStateHash
	closure.Replay.RNG = closure.RNG
	closure.DefectOccurrenceIDs = []string{}
	input.DefectOccurrences = []DefectOccurrence{}
	input.DefectFamilies = []DefectFamily{}
	closure, err = NormalizeRunEvidenceClosure(closure)
	if err != nil {
		t.Fatal(err)
	}
	input.Closure = closure
	input.Report.RunID = binding.RunID
	input.Report.RunManifest = closure.RunManifest
	input.Report.Replay = closure.Replay
	input.Report.DefectFamilyReferences = []string{}
	input.Report.DefectOccurrenceReferences = []string{}
	closureSHA, err := canonicalDigest(closure)
	if err != nil {
		t.Fatal(err)
	}
	input.Report.EvidenceRoots = []EvidenceRootIdentity{{Kind: "RUN_EVIDENCE_CLOSURE", SHA256: closureSHA}, {Kind: "RAW_CAPTURE", SHA256: rawCapture.Root}}
	generated, err := generatePrivateAuditReady(ctx, input, key, verifier)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(input.Destination)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	independent := &staticSourceVerifier{expected: source}
	verified, err := verifyPrivateAuditReadyAt(ctx, dir, key, independent)
	if err != nil || verified.Root != generated.Root || independent.proofRequests != 1 {
		t.Fatal("independent encrypted Core proof rejected", err)
	}
	plain := verified.LogicalAssets[RawEventsAssetName]
	lines := bytes.Split(bytes.TrimSpace(plain), []byte{'\n'})
	if len(lines) != len(events) || !bytes.Contains(plain, []byte("NON_CANON_PRIVATE_CORE_BODY_CANARY")) {
		t.Fatal("private Core RAW data lost")
	}
	for i, line := range lines {
		var record struct {
			Payload string `json:"payload_canonical"`
		}
		if json.Unmarshal(line, &record) != nil || record.Payload != events[i].PayloadCanonical {
			t.Fatal("Core RAW payload reconstructed or changed")
		}
	}
	if verified.Manifest.RawCaptureRoot != rawCapture.Root || verified.Closure.Projection.FinalStateHash != final.StateHash || !verified.Closure.Replay.HashMatch {
		t.Fatal("private evidence is not the actual Core closure")
	}
	for _, name := range mustPrivateFiles(t, input.Destination) {
		body, err := os.ReadFile(filepath.Join(input.Destination, name))
		if err != nil || bytes.Contains(body, []byte("NON_CANON_PRIVATE_CORE_BODY_CANARY")) {
			t.Fatal("plaintext Core body outside encryption")
		}
	}
	after, err := store.Load(ctx, "aipt.run-core:"+binding.RunID)
	if err != nil || len(after) != len(events) {
		t.Fatal("evidence operation changed Core ledger")
	}
	for i := range after {
		if after[i].PayloadCanonical != events[i].PayloadCanonical || after[i].EventHash != events[i].EventHash {
			t.Fatal("private closure mutated PostgreSQL evidence")
		}
	}
}
