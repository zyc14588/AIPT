package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

type staticSourceVerifier struct {
	expected SourceIdentity
	hook     func(int)
	err      error
	calls    int
}

func (verifier *staticSourceVerifier) Verify(_ context.Context, source SourceIdentity) (RemoteVerification, error) {
	verifier.calls++
	if verifier.hook != nil {
		verifier.hook(verifier.calls)
	}
	if verifier.err != nil {
		return RemoteVerification{}, verifier.err
	}
	if source != verifier.expected {
		return RemoteVerification{}, ErrSourceUnverified
	}
	return RemoteVerification{
		Remote: source.Repository, Commit: source.Commit, Status: remoteVerificationStatus,
	}, nil
}

func digestText(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func repeatSHA(value string) string { return strings.Repeat(value, 64) }

func fixtureActionReceipts(t *testing.T, rawPath string, reference EvidenceReference, finalStateHash, finalProjectionHash string) []ActionReceiptEvidence {
	t.Helper()
	raw, err := VerifyRawCapture(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	events, err := os.ReadFile(filepath.Join(rawPath, EventsName))
	if err != nil {
		t.Fatal(err)
	}
	hashes, err := verifiedRawEventHashes(events, raw.Manifest.StreamID)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]ActionReceiptEvidence, 0, len(hashes))
	for sequence := int64(1); sequence <= int64(len(hashes)); sequence++ {
		eventHash, exists := hashes[sequence]
		if !exists {
			t.Fatalf("fixture RAW_CAPTURE misses sequence %d", sequence)
		}
		receipts = append(receipts, ActionReceiptEvidence{
			ActionID: fmt.Sprintf("SYNTH-ACTION-%06d", sequence), Sequence: sequence, EventHash: eventHash,
			StateHash: finalStateHash, ProjectionHash: finalProjectionHash, Evidence: reference,
		})
	}
	return receipts
}

func fixtureAuditInput(t *testing.T, profile ExportProfile) (GenerateAuditReadyInput, *staticSourceVerifier) {
	t.Helper()
	rawPath := exportFixture(t)
	return fixtureAuditInputForRaw(t, rawPath, profile)
}

func fixtureAuditInputForRaw(t *testing.T, rawPath string, profile ExportProfile) (GenerateAuditReadyInput, *staticSourceVerifier) {
	t.Helper()
	raw, err := VerifyRawCapture(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	actionBytes := []byte("synthetic action receipt evidence\n")
	coverageBytes := []byte("synthetic coverage evidence\n")
	defectBytes := []byte("synthetic defect observation\n")
	reproductionBytes := []byte("synthetic reproduction recipe\n")
	actionReference := EvidenceReference{ID: "SYNTH-ACTION-EVIDENCE", Path: "supplemental/action.txt", SHA256: digestText(actionBytes)}
	coverageReference := EvidenceReference{ID: "SYNTH-COVERAGE-EVIDENCE", Path: "supplemental/coverage.txt", SHA256: digestText(coverageBytes)}
	defectReference := EvidenceReference{ID: "SYNTH-DEFECT-EVIDENCE", Path: "supplemental/defect.txt", SHA256: digestText(defectBytes)}
	reproductionReference := EvidenceReference{ID: "SYNTH-REPRODUCTION", Path: "supplemental/reproduction.txt", SHA256: digestText(reproductionBytes)}

	projection := DefectFingerprintProjection{
		Version: DefectFingerprintVersion, RootCauseDomain: RootCauseAIPT,
		SemanticKey: "SYNTHETIC-STATE-PROJECTION-MISMATCH",
		RuleIDs:     []string{"RULE-SYNTH-001"}, InvariantIDs: []string{"INV-SYNTH-001"},
	}
	fingerprint, projection, err := DefectFingerprint(projection)
	if err != nil {
		t.Fatal(err)
	}
	family := DefectFamily{
		Schema: DefectFamilySchema, Version: ContractVersion, FamilyID: "SYNTH-FAMILY-001",
		FingerprintVersion: DefectFingerprintVersion, Fingerprint: fingerprint, Projection: projection,
		RootCauseDomain: RootCauseAIPT, Severity: "LOW", Confidence: "HIGH",
		Reproducibility: "ALWAYS", Scope: []string{"SYNTHETIC-RUN"}, Priority: "P4",
	}
	occurrence := DefectOccurrence{
		Schema: DefectOccurrenceSchema, Version: ContractVersion, OccurrenceID: "SYNTH-OCCURRENCE-001",
		FamilyFingerprint: fingerprint, RunID: "SYNTH-RUN-001", Source: raw.Manifest.Source,
		RootCauseDomain: RootCauseAIPT, Severity: "LOW", Confidence: "HIGH",
		Reproducibility: "ALWAYS", Scope: []string{"SYNTHETIC-RUN"}, Priority: "P4",
		EvidenceReferences: []EvidenceReference{defectReference}, ReproductionReference: reproductionReference,
		ObservedContextSHA256: repeatSHA("9"),
	}
	runManifest := ArtifactIdentity{ID: "SYNTH-RUN-MANIFEST-001", Schema: "aipt.run-manifest/v1", CanonicalSHA256: repeatSHA("3")}
	rng := RNGEvidence{Used: false, Version: "NONE", SeedDisclosureStatus: "NOT_APPLICABLE"}
	replay := ReplayEvidence{
		Schema: ReplayEvidenceSchema, Version: ContractVersion, RunID: "SYNTH-RUN-001",
		RunManifestSHA256: runManifest.CanonicalSHA256, LedgerStreamID: raw.Manifest.StreamID,
		LedgerTailSequence: raw.Manifest.TailSequence, LedgerTailHash: raw.Manifest.TailEventHash,
		LiveFinalStateHash: repeatSHA("5"), ReplayedFinalStateHash: repeatSHA("5"), HashMatch: true,
		Implementation: ReplayImplementation{ID: "SYNTH-REPLAY", Version: "1.0.0", SHA256: repeatSHA("6")}, RNG: rng,
	}
	gateFacts := []GateEligibilityFact{{Gate: "QUALIFICATION", Eligible: false, ReasonCode: "SYNTHETIC_DOES_NOT_QUALIFY"}}
	actionReceipts := fixtureActionReceipts(t, rawPath, actionReference, repeatSHA("5"), repeatSHA("4"))
	closure := RunEvidenceClosure{
		Schema: RunClosureSchema, Version: ContractVersion, RunID: "SYNTH-RUN-001", RunManifest: runManifest,
		Source: raw.Manifest.Source, StateAuthority: "POSTGRESQL_APPEND_ONLY_HASH_CHAIN",
		Ledger:         LedgerIdentity{StreamID: raw.Manifest.StreamID, EventCount: raw.Manifest.EventCount, TailSequence: raw.Manifest.TailSequence, TailEventHash: raw.Manifest.TailEventHash},
		ActionReceipts: actionReceipts,
		Projection:     ProjectionEvidence{Schema: "aipt.synthetic-projection/v1", CanonicalSHA256: repeatSHA("4"), FinalStateHash: repeatSHA("5")},
		RuleCitations:  []RuleCitation{{RuleID: "RULE-SYNTH-001", SourceSHA256: repeatSHA("7")}}, RNG: rng, Replay: replay,
		CoverageReferences: []EvidenceReference{coverageReference}, DefectOccurrenceIDs: []string{occurrence.OccurrenceID},
		AnomalyCodes: []string{"SYNTH-ANOMALY-001"}, GateEligibilityFacts: gateFacts,
		ModelExecutionReferences: []ModelExecutionReference{},
	}
	closure, err = NormalizeRunEvidenceClosure(closure)
	if err != nil {
		t.Fatal(err)
	}
	closureHash, err := canonicalDigest(closure)
	if err != nil {
		t.Fatal(err)
	}
	report := RunReport{
		Schema: RunReportSchema, Version: ContractVersion, ReportID: "SYNTH-REPORT-001", Revision: 1,
		Lifecycle: ReportProvisional, RunID: closure.RunID, Source: closure.Source, RunManifest: closure.RunManifest,
		ExecutionStatus: "SYNTHETIC_COMPLETED", Coverage: CoverageSummary{References: []EvidenceReference{coverageReference}, Total: 1, Covered: 1},
		Replay: closure.Replay, DefectFamilyReferences: []string{family.FamilyID},
		DefectOccurrenceReferences: []string{occurrence.OccurrenceID}, AnomalyCodes: append([]string(nil), closure.AnomalyCodes...),
		SecurityFindings: []FindingReference{}, VisibilityFindings: []FindingReference{},
		ModelExecution: ModelExecutionFacts{ReferenceIDs: []string{}}, GateEligibilityFacts: append([]GateEligibilityFact(nil), gateFacts...),
		QualificationEligible: false,
		EvidenceRoots:         []EvidenceRootIdentity{{Kind: "RUN_EVIDENCE_CLOSURE", SHA256: closureHash}, {Kind: "RAW_CAPTURE", SHA256: raw.Root}},
		AuditorVerdictClaimed: false,
	}
	verifier := &staticSourceVerifier{expected: raw.Manifest.Source}
	input := GenerateAuditReadyInput{
		RawCapture: rawPath, SourceVerifier: verifier,
		Disclosure:          Disclosure{Profile: DisclosurePublic, Encryption: Encryption{Status: EncryptionUnencrypted}},
		CoreClassifications: publicCoreEvidenceClassifications(),
		Closure:             closure, DefectFamilies: []DefectFamily{family}, DefectOccurrences: []DefectOccurrence{occurrence}, Report: report,
		Supplemental: []LogicalAssetInput{
			{Path: actionReference.Path, MediaType: "text/plain", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: actionBytes},
			{Path: coverageReference.Path, MediaType: "text/plain", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: coverageBytes},
			{Path: defectReference.Path, MediaType: "text/plain", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: defectBytes},
			{Path: reproductionReference.Path, MediaType: "text/plain", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: reproductionBytes},
		},
		ExportProfile: profile,
	}
	return input, verifier
}

func fixtureExportProfile() ExportProfile {
	return ExportProfile{ProfileID: "SYNTHETIC-PUBLIC", InlineThreshold: 1 << 20, ChunkSize: 64 << 10, MaxAssetBytes: 8 << 20, MaxTotalBytes: 32 << 20, MaxAssets: 256, MaxChunks: 4096}
}

func publicCoreEvidenceClassifications() CoreEvidenceClassifications {
	return CoreEvidenceClassifications{
		Schema: CoreClassificationSchema, Version: ContractVersion,
		RawCapture: ContentPublic, RunEvidenceClosure: ContentPublic, ReplayEvidence: ContentPublic,
		DefectFamily: ContentPublic, DefectOccurrence: ContentPublic, RunReport: ContentPublic, ReportDerivatives: ContentPublic,
	}
}

func compareFlatDirectories(t *testing.T, left, right string) {
	t.Helper()
	leftEntries, err := os.ReadDir(left)
	if err != nil {
		t.Fatal(err)
	}
	rightEntries, err := os.ReadDir(right)
	if err != nil {
		t.Fatal(err)
	}
	leftNames := make([]string, len(leftEntries))
	rightNames := make([]string, len(rightEntries))
	for index := range leftEntries {
		leftNames[index] = leftEntries[index].Name()
	}
	for index := range rightEntries {
		rightNames[index] = rightEntries[index].Name()
	}
	if !equalStrings(leftNames, rightNames) {
		t.Fatalf("bundle file sets differ: %v != %v", leftNames, rightNames)
	}
	for _, name := range leftNames {
		leftBytes, leftErr := os.ReadFile(filepath.Join(left, name))
		rightBytes, rightErr := os.ReadFile(filepath.Join(right, name))
		if leftErr != nil || rightErr != nil || string(leftBytes) != string(rightBytes) {
			t.Fatalf("bundle member %s differs: left=%v right=%v", name, leftErr, rightErr)
		}
	}
}

func TestAuditReadyDeterministicRoundTrip(t *testing.T) {
	profile := fixtureExportProfile()
	first, firstVerifier := fixtureAuditInput(t, profile)
	second, secondVerifier := fixtureAuditInput(t, profile)
	first.Destination = filepath.Join(privateTempDir(t), "audit-ready-a")
	second.Destination = filepath.Join(privateTempDir(t), "audit-ready-b")
	// Exercise set normalization and input enumeration independence.
	second.Supplemental[0], second.Supplemental[3] = second.Supplemental[3], second.Supplemental[0]
	second.Closure.RuleCitations = append([]RuleCitation(nil), second.Closure.RuleCitations...)

	firstResult, err := GenerateAuditReady(context.Background(), first)
	if err != nil {
		t.Fatalf("first GenerateAuditReady: %v", err)
	}
	secondResult, err := GenerateAuditReady(context.Background(), second)
	if err != nil {
		t.Fatalf("second GenerateAuditReady: %v", err)
	}
	if firstResult.Root != secondResult.Root {
		t.Fatalf("roots differ: %s != %s", firstResult.Root, secondResult.Root)
	}
	compareFlatDirectories(t, first.Destination, second.Destination)
	verified, err := VerifyAuditReady(context.Background(), first.Destination, firstVerifier)
	if err != nil {
		t.Fatalf("VerifyAuditReady: %v", err)
	}
	if verified.Root != firstResult.Root || verified.Manifest.Stage != AuditReadyStage || verified.Report.AuditorVerdictClaimed || verified.Report.AuditResult != nil {
		t.Fatalf("unexpected verified AUDIT_READY result: %+v", verified)
	}
	if firstVerifier.calls < 5 || secondVerifier.calls < 4 {
		t.Fatalf("source identity was not repeatedly verified: first=%d second=%d", firstVerifier.calls, secondVerifier.calls)
	}
}

func assertCoreClassificationRejected(t *testing.T, mutate func(*GenerateAuditReadyInput), wanted error) {
	t.Helper()
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "rejected-classification")
	mutate(&input)
	if _, err := GenerateAuditReady(context.Background(), input); !errors.Is(err, wanted) {
		t.Fatalf("classification error = %v, want %v", err, wanted)
	}
	if _, err := os.Lstat(input.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected classification left a final bundle: %v", err)
	}
}

func TestF1N01RawCaptureClassificationAbsentOrUnknownRejected(t *testing.T) {
	for _, test := range []struct {
		name  string
		value ContentClassification
	}{
		{"absent", ""},
		{"unknown", ContentClassification("UNKNOWN")},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertCoreClassificationRejected(t, func(input *GenerateAuditReadyInput) {
				input.CoreClassifications.RawCapture = test.value
			}, ErrAuditReadyInvalid)
		})
	}
}

func TestF1N02NonPublicRawCaptureRejectedByPublicProfile(t *testing.T) {
	assertCoreClassificationRejected(t, func(input *GenerateAuditReadyInput) {
		input.CoreClassifications.RawCapture = ContentUnreleasedRemote
	}, ErrDisclosureViolation)
}

func TestF1N03NonPublicRunReportRejectedByPublicProfile(t *testing.T) {
	assertCoreClassificationRejected(t, func(input *GenerateAuditReadyInput) {
		input.CoreClassifications.RunReport = ContentUnreleasedRemote
		input.CoreClassifications.ReportDerivatives = ContentUnreleasedRemote
	}, ErrDisclosureViolation)
}

func TestF1N04ReportDerivativeCannotBypassParentClassification(t *testing.T) {
	assertCoreClassificationRejected(t, func(input *GenerateAuditReadyInput) {
		input.CoreClassifications.RunReport = ContentUnreleasedRemote
		input.CoreClassifications.ReportDerivatives = ContentPublic
	}, ErrDisclosureViolation)
}

func TestF1N05MarkerFreeNonPublicCorePayloadRejected(t *testing.T) {
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	events, err := os.ReadFile(filepath.Join(input.RawCapture, EventsName))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOneDisclosure(ContentPublic, ContentKindRawCapture, events, input.Disclosure); err != nil {
		t.Fatalf("fixture unexpectedly triggered defense-in-depth content scanning: %v", err)
	}
	input.CoreClassifications.RawCapture = ContentUnreleasedRemote
	input.Destination = filepath.Join(privateTempDir(t), "marker-free-rejected")
	if _, err := GenerateAuditReady(context.Background(), input); !errors.Is(err, ErrDisclosureViolation) {
		t.Fatalf("marker-free non-PUBLIC RAW_CAPTURE error = %v", err)
	}
}

func TestF1N06ClassificationMutationChangesDeterministicRoot(t *testing.T) {
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	input.Destination = filepath.Join(privateTempDir(t), "classification-root")
	result, err := GenerateAuditReady(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	mutatedIndex := result.BundleIndex
	mutatedIndex.LogicalAssets = append([]LogicalAsset(nil), result.BundleIndex.LogicalAssets...)
	mutatedIndex.CoreEvidenceClassifications.RawCapture = ContentUnreleasedRemote
	for index := range mutatedIndex.LogicalAssets {
		switch mutatedIndex.LogicalAssets[index].Path {
		case RawManifestAssetName, RawEventsAssetName, RawRootAssetName:
			mutatedIndex.LogicalAssets[index].Classification = ContentUnreleasedRemote
		}
	}
	indexBytes, err := canonicalLine(mutatedIndex)
	if err != nil {
		t.Fatal(err)
	}
	mutatedManifest := result.Manifest
	mutatedManifest.NormalizedAssets = append([]Asset(nil), result.Manifest.NormalizedAssets...)
	found := false
	for index := range mutatedManifest.NormalizedAssets {
		if mutatedManifest.NormalizedAssets[index].Path != BundleIndexName {
			continue
		}
		mutatedManifest.NormalizedAssets[index].Bytes = int64(len(indexBytes))
		mutatedManifest.NormalizedAssets[index].SHA256 = digestText(indexBytes)
		found = true
	}
	if !found {
		t.Fatal("generated manifest does not bind the bundle index")
	}
	manifestBytes, err := canonicalLine(mutatedManifest)
	if err != nil {
		t.Fatal(err)
	}
	mutatedRoot := digestText(manifestBytes)
	if mutatedRoot == result.Root {
		t.Fatal("core classification mutation preserved the AUDIT_READY root")
	}
	secondManifestBytes, err := canonicalLine(mutatedManifest)
	if err != nil || digestText(secondManifestBytes) != mutatedRoot {
		t.Fatalf("classification-bound root is not deterministic: %v", err)
	}
}

func TestAuditReadyContentAddressedChunksDeduplicateAndReassemble(t *testing.T) {
	profile := fixtureExportProfile()
	profile.InlineThreshold = 8
	profile.ChunkSize = 7
	input, verifier := fixtureAuditInput(t, profile)
	shared := []byte("same content chunked byte for byte")
	input.Supplemental = append(input.Supplemental,
		LogicalAssetInput{Path: "supplemental/duplicate-a.bin", MediaType: "application/octet-stream", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: shared},
		LogicalAssetInput{Path: "supplemental/duplicate-b.bin", MediaType: "application/octet-stream", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: shared},
	)
	input.Destination = filepath.Join(privateTempDir(t), "audit-ready-chunked")
	result, err := GenerateAuditReady(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.LogicalAssets["supplemental/duplicate-a.bin"]) != string(shared) ||
		string(result.LogicalAssets["supplemental/duplicate-b.bin"]) != string(shared) {
		t.Fatal("chunk reassembly dropped or changed required content")
	}
	var firstChunks, secondChunks []ChunkReference
	for _, asset := range result.BundleIndex.LogicalAssets {
		switch asset.Path {
		case "supplemental/duplicate-a.bin":
			firstChunks = asset.Storage.Chunks
		case "supplemental/duplicate-b.bin":
			secondChunks = asset.Storage.Chunks
		}
	}
	if len(firstChunks) == 0 || !canonicalEqual(firstChunks, secondChunks) {
		t.Fatalf("identical logical assets were not safely deduplicated: %v / %v", firstChunks, secondChunks)
	}
	if _, err := VerifyAuditReady(context.Background(), input.Destination, verifier); err != nil {
		t.Fatal(err)
	}
}

func TestDefectFingerprintGroupingAndStateDecisionChain(t *testing.T) {
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	family := input.DefectFamilies[0]
	occurrence := input.DefectOccurrences[0]
	grouping, err := ClassifyDefectGrouping(occurrence, []DefectFamily{family})
	if err != nil || grouping.Disposition != "EXACT_FINGERPRINT_MATCH" || grouping.FamilyID != family.FamilyID {
		t.Fatalf("exact grouping = %+v, %v", grouping, err)
	}
	mutated := occurrence
	mutated.FamilyFingerprint = repeatSHA("d")
	grouping, err = ClassifyDefectGrouping(mutated, []DefectFamily{family})
	if err != nil || grouping.Disposition != "SEMANTIC_DUPLICATE_CANDIDATE" || grouping.FamilyID != "" {
		t.Fatalf("semantic candidate grouping = %+v, %v", grouping, err)
	}
	policy := DefectStatePolicy{
		Schema: DefectStatePolicySchema, Version: ContractVersion, PolicyID: "SYNTH-AUTHORITY-POLICY",
		States: []string{"S0", "S1", "S2"}, InitialState: "S0", TerminalStates: []string{"S2"},
		Transitions: []DefectStateTransition{{From: "S0", To: "S1"}, {From: "S1", To: "S2"}},
	}
	first := DefectDecision{
		Schema: DefectDecisionSchema, Version: ContractVersion, DecisionID: "SYNTH-DECISION-001", Sequence: 1,
		FamilyFingerprint: family.Fingerprint, FromState: "S0", ToState: "S1", AuthorityID: "SYNTH-AUTHORITY", RationaleSHA256: repeatSHA("e"),
	}
	firstHash, err := canonicalDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	second := DefectDecision{
		Schema: DefectDecisionSchema, Version: ContractVersion, DecisionID: "SYNTH-DECISION-002", Sequence: 2,
		PredecessorDecisionHash: &firstHash, FamilyFingerprint: family.Fingerprint, FromState: "S1", ToState: "S2",
		AuthorityID: "SYNTH-AUTHORITY", RationaleSHA256: repeatSHA("f"),
	}
	state, err := ResolveDefectDecisionChain(policy, family.Fingerprint, []DefectDecision{first, second})
	if err != nil || state != "S2" {
		t.Fatalf("decision state = %q, %v", state, err)
	}
	first.ToState = "S2"
	if _, err := ResolveDefectDecisionChain(policy, family.Fingerprint, []DefectDecision{first}); !errors.Is(err, ErrDefectInvalid) {
		t.Fatalf("unauthorized transition accepted: %v", err)
	}
}

func TestReportLifecycleIsAppendOnlyAndSealedIsTerminal(t *testing.T) {
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	provisional, err := NormalizeRunReport(input.Report)
	if err != nil {
		t.Fatal(err)
	}
	provisionalHash, _ := canonicalDigest(provisional)
	finalizing := provisional
	finalizing.Revision = 2
	finalizing.PredecessorReportSHA256 = &provisionalHash
	finalizing.Lifecycle = ReportFinalizing
	if err := ValidateReportTransition(provisional, finalizing); err != nil {
		t.Fatal(err)
	}
	finalizingHash, _ := canonicalDigest(finalizing)
	sealed := finalizing
	sealed.Revision = 3
	sealed.PredecessorReportSHA256 = &finalizingHash
	sealed.Lifecycle = ReportSealed
	if err := ValidateReportTransition(finalizing, sealed); err != nil {
		t.Fatal(err)
	}
	successor := sealed
	successor.Revision++
	sealedHash, _ := canonicalDigest(sealed)
	successor.PredecessorReportSHA256 = &sealedHash
	successor.Lifecycle = ReportProvisional
	if !errors.Is(ValidateReportTransition(sealed, successor), ErrReportTransition) {
		t.Fatal("SEALED report was implicitly unsealed")
	}
	mutated := sealed
	mutated.ExecutionStatus = "MUTATED"
	if !errors.Is(ValidateReportTransition(sealed, mutated), ErrReportTransition) {
		t.Fatal("in-place SEALED report mutation was accepted")
	}
	firstAddendum := ReportAddendum{
		Schema: ReportAddendumSchema, Version: ContractVersion, AddendumID: "SYNTH-ADDENDUM-001",
		SealedReportSHA256: sealedHash, Sequence: 1, ContentSHA256: repeatSHA("1"),
		EvidenceReferences: []EvidenceReference{sealed.Coverage.References[0]},
	}
	firstAddendumHash, err := canonicalDigest(firstAddendum)
	if err != nil {
		t.Fatal(err)
	}
	secondAddendum := ReportAddendum{
		Schema: ReportAddendumSchema, Version: ContractVersion, AddendumID: "SYNTH-ADDENDUM-002",
		SealedReportSHA256: sealedHash, Sequence: 2, PredecessorAddendumHash: &firstAddendumHash,
		ContentSHA256: repeatSHA("2"), EvidenceReferences: []EvidenceReference{sealed.Coverage.References[0]},
	}
	if err := ValidateReportAddendumChain(sealed, []ReportAddendum{firstAddendum, secondAddendum}); err != nil {
		t.Fatalf("valid report addendum chain: %v", err)
	}
	secondAddendum.PredecessorAddendumHash = nil
	if !errors.Is(ValidateReportAddendumChain(sealed, []ReportAddendum{firstAddendum, secondAddendum}), ErrReportTransition) {
		t.Fatal("broken report addendum chain was accepted")
	}
}

func TestAuditReadyDisclosureAndEncryptionFailClosed(t *testing.T) {
	tests := []struct {
		name           string
		profile        DisclosureProfile
		unpublished    bool
		classification ContentClassification
		kind           ContentKind
		data           []byte
		wanted         error
	}{
		{"public unpublished classification", DisclosurePublic, false, ContentUnreleasedRemote, ContentKindSupplemental, []byte("synthetic"), ErrDisclosureViolation},
		{"public unpublished flag", DisclosurePublic, true, ContentPublic, ContentKindSupplemental, []byte("synthetic"), ErrDisclosureViolation},
		{"public credential classification", DisclosurePublic, false, ContentCredentialSecret, ContentKindSupplemental, []byte("synthetic"), ErrDisclosureViolation},
		{"public credential kind", DisclosurePublic, false, ContentPublic, ContentKindCredential, []byte("synthetic"), ErrDisclosureViolation},
		{"public credential marker", DisclosurePublic, false, ContentPublic, ContentKindSupplemental, []byte("API_" + "KEY=synthetic"), ErrDisclosureViolation},
		{"public standalone key", DisclosurePublic, false, ContentPublic, ContentKindSupplemental, []byte("s" + "k-" + strings.Repeat("A", 20)), ErrDisclosureViolation},
		{"public bearer token", DisclosurePublic, false, ContentPublic, ContentKindSupplemental, []byte("Bear" + "er " + strings.Repeat("a", 20)), ErrDisclosureViolation},
		{"public private key", DisclosurePublic, false, ContentPublic, ContentKindSupplemental, []byte("-----" + "BEGIN PRIVATE KEY-----"), ErrDisclosureViolation},
		{"public absolute path", DisclosurePublic, false, ContentPublic, ContentKindSupplemental, []byte("/" + "home/synthetic/private"), ErrDisclosureViolation},
		{"public root path", DisclosurePublic, false, ContentPublic, ContentKindSupplemental, []byte("/" + "root/synthetic/private"), ErrDisclosureViolation},
		{"public private prompt", DisclosurePublic, false, ContentPublic, ContentKindPrivatePrompt, []byte("synthetic"), ErrDisclosureViolation},
		{"public game body", DisclosurePublic, false, ContentPublic, ContentKindGameBody, []byte("synthetic"), ErrDisclosureViolation},
		{"external published-only hidden classification", DisclosureExternalAuditor, false, ContentTableHiddenRemote, ContentKindSupplemental, []byte("synthetic"), ErrDisclosureViolation},
		{"external unpublished plaintext", DisclosureExternalAuditor, true, ContentUnreleasedRemote, ContentKindSupplemental, []byte("synthetic"), ErrEncryptionRequired},
		{"private plaintext", DisclosurePrivateFull, true, ContentHumanPrivateData, ContentKindSupplemental, []byte("synthetic"), ErrEncryptionRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, _ := fixtureAuditInput(t, fixtureExportProfile())
			input.Destination = filepath.Join(privateTempDir(t), "rejected")
			input.Disclosure.Profile = test.profile
			input.Disclosure.ContainsUnpublishedContent = test.unpublished
			input.Supplemental = append(input.Supplemental, LogicalAssetInput{
				Path: "supplemental/policy-probe.txt", MediaType: "text/plain", Classification: test.classification, ContentKind: test.kind, Data: test.data,
			})
			_, err := GenerateAuditReady(context.Background(), input)
			if !errors.Is(err, test.wanted) {
				t.Fatalf("error = %v, want %v", err, test.wanted)
			}
			if _, statErr := os.Lstat(input.Destination); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("rejected export left final bundle: %v", statErr)
			}
		})
	}
	t.Run("public private metadata path", func(t *testing.T) {
		input, _ := fixtureAuditInput(t, fixtureExportProfile())
		input.Destination = filepath.Join(privateTempDir(t), "rejected")
		input.Supplemental = append(input.Supplemental, LogicalAssetInput{
			Path: "private_prompt/synthetic.txt", MediaType: "text/plain", Classification: ContentPublic,
			ContentKind: ContentKindSupplemental, Data: []byte("synthetic"),
		})
		if _, err := GenerateAuditReady(context.Background(), input); !errors.Is(err, ErrDisclosureViolation) {
			t.Fatalf("metadata path error = %v, want %v", err, ErrDisclosureViolation)
		}
	})
}

func TestAuditReadyCrossContractClaimsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *GenerateAuditReadyInput)
	}{
		{"qualification gate mismatch", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Report.QualificationEligible = true
		}},
		{"unknown model execution reference", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Report.ModelExecution.ReferenceIDs = []string{"SYNTH-UNKNOWN-EXECUTION"}
		}},
		{"finding references unknown evidence", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Report.SecurityFindings = []FindingReference{{FindingID: "SYNTH-FINDING", EvidenceID: "SYNTH-UNKNOWN-EVIDENCE", Severity: "LOW"}}
		}},
		{"report bypasses provisional start", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Report.Lifecycle = ReportSealed
		}},
		{"action receipt event hash differs from RAW_CAPTURE", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Closure.ActionReceipts[0].EventHash = repeatSHA("f")
		}},
		{"action receipt sequence is duplicated", func(_ *testing.T, input *GenerateAuditReadyInput) {
			if len(input.Closure.ActionReceipts) < 2 {
				return
			}
			input.Closure.ActionReceipts[1].Sequence = input.Closure.ActionReceipts[0].Sequence
		}},
		{"action receipt coverage is incomplete", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Closure.ActionReceipts = input.Closure.ActionReceipts[:len(input.Closure.ActionReceipts)-1]
		}},
		{"final action receipt does not bind projection", func(_ *testing.T, input *GenerateAuditReadyInput) {
			input.Closure.ActionReceipts[len(input.Closure.ActionReceipts)-1].StateHash = repeatSHA("f")
		}},
		{"duplicate defect family id", func(t *testing.T, input *GenerateAuditReadyInput) {
			duplicate := input.DefectFamilies[0]
			duplicate.Projection.SemanticKey = "SYNTHETIC-DIFFERENT-DEFECT"
			fingerprint, projection, err := DefectFingerprint(duplicate.Projection)
			if err != nil {
				t.Fatal(err)
			}
			duplicate.Fingerprint = fingerprint
			duplicate.Projection = projection
			input.DefectFamilies = append(input.DefectFamilies, duplicate)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, _ := fixtureAuditInput(t, fixtureExportProfile())
			input.Destination = filepath.Join(privateTempDir(t), "rejected")
			test.mutate(t, &input)
			if _, err := GenerateAuditReady(context.Background(), input); err == nil {
				t.Fatal("cross-contract mutation was accepted")
			}
			if _, statErr := os.Lstat(input.Destination); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("rejected export left final bundle: %v", statErr)
			}
		})
	}
}

func TestAuditReadyOutputSafetyAndInputRace(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run("existing "+kind, func(t *testing.T) {
			input, verifier := fixtureAuditInput(t, fixtureExportProfile())
			parent := privateTempDir(t)
			input.Destination = filepath.Join(parent, "occupied")
			switch kind {
			case "file":
				if err := os.WriteFile(input.Destination, []byte("occupied"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(input.Destination, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(parent, "missing"), input.Destination); err != nil {
					t.Fatal(err)
				}
			}
			_, err := GenerateAuditReady(context.Background(), input)
			if !errors.Is(err, ErrTargetExists) || verifier.calls != 0 {
				t.Fatalf("existing target error/calls = %v/%d", err, verifier.calls)
			}
		})
	}
	t.Run("symlink parent", func(t *testing.T) {
		input, verifier := fixtureAuditInput(t, fixtureExportProfile())
		parent := privateTempDir(t)
		realParent := filepath.Join(parent, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(parent, "linked")
		if err := os.Symlink(realParent, linked); err != nil {
			t.Fatal(err)
		}
		input.Destination = filepath.Join(linked, "audit")
		_, err := GenerateAuditReady(context.Background(), input)
		if !errors.Is(err, ErrUnsafePath) || verifier.calls != 0 {
			t.Fatalf("symlink parent error/calls = %v/%d", err, verifier.calls)
		}
	})
	t.Run("symlink ancestor", func(t *testing.T) {
		input, verifier := fixtureAuditInput(t, fixtureExportProfile())
		root := privateTempDir(t)
		realParent := filepath.Join(root, "real")
		if err := os.MkdirAll(filepath.Join(realParent, "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
		linked := filepath.Join(root, "linked")
		if err := os.Symlink(realParent, linked); err != nil {
			t.Fatal(err)
		}
		input.Destination = filepath.Join(linked, "nested", "audit")
		_, err := GenerateAuditReady(context.Background(), input)
		if !errors.Is(err, ErrUnsafePath) || verifier.calls != 0 {
			t.Fatalf("symlink ancestor error/calls = %v/%d", err, verifier.calls)
		}
	})
	t.Run("RAW_CAPTURE symlink ancestor", func(t *testing.T) {
		input, _ := fixtureAuditInput(t, fixtureExportProfile())
		root := privateTempDir(t)
		linked := filepath.Join(root, "linked")
		if err := os.Symlink(filepath.Dir(input.RawCapture), linked); err != nil {
			t.Fatal(err)
		}
		input.RawCapture = filepath.Join(linked, filepath.Base(input.RawCapture))
		input.Destination = filepath.Join(privateTempDir(t), "rejected")
		if _, err := GenerateAuditReady(context.Background(), input); err == nil {
			t.Fatal("RAW_CAPTURE symlink ancestor was accepted")
		}
	})
	t.Run("RAW_CAPTURE changes after held verification", func(t *testing.T) {
		input, verifier := fixtureAuditInput(t, fixtureExportProfile())
		input.Destination = filepath.Join(privateTempDir(t), "raced")
		verifier.hook = func(call int) {
			if call != 1 {
				return
			}
			path := filepath.Join(input.RawCapture, EventsName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data[0] ^= 1
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := GenerateAuditReady(context.Background(), input)
		if !errors.Is(err, ErrStreamChanged) {
			t.Fatalf("input race error = %v, want ErrStreamChanged", err)
		}
		if _, statErr := os.Lstat(input.Destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("input race left final bundle: %v", statErr)
		}
	})
	t.Run("normalized input changes after snapshot", func(t *testing.T) {
		input, verifier := fixtureAuditInput(t, fixtureExportProfile())
		input.Destination = filepath.Join(privateTempDir(t), "raced")
		verifier.hook = func(call int) {
			if call == 1 {
				input.Supplemental[0].Data[0] ^= 1
			}
		}
		_, err := GenerateAuditReady(context.Background(), input)
		if !errors.Is(err, ErrStreamChanged) {
			t.Fatalf("normalized input race error = %v, want ErrStreamChanged", err)
		}
		if _, statErr := os.Lstat(input.Destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("normalized input race left final bundle: %v", statErr)
		}
	})
	t.Run("normalized input changes after atomic rename", func(t *testing.T) {
		input, verifier := fixtureAuditInput(t, fixtureExportProfile())
		input.Destination = filepath.Join(privateTempDir(t), "rolled-back")
		verifier.hook = func(call int) {
			// Calls 2/3 verify staging and call 4 is the explicit pre-publish
			// recheck. Call 5 therefore occurs while verifying the renamed inode.
			if call == 5 {
				input.Supplemental[0].Data[0] ^= 1
			}
		}
		_, err := GenerateAuditReady(context.Background(), input)
		if !errors.Is(err, ErrStreamChanged) {
			t.Fatalf("post-rename input race error = %v, want ErrStreamChanged", err)
		}
		if _, statErr := os.Lstat(input.Destination); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("post-rename failure left successful-looking final bundle: %v", statErr)
		}
	})
}

func TestAuditReadyVerifierRejectsTamperingAndContractConfusion(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{"missing physical asset", func(t *testing.T, directory string) {
			manifest := readAuditManifest(t, directory)
			if err := os.Remove(filepath.Join(directory, manifest.NormalizedAssets[0].Path)); err != nil {
				t.Fatal(err)
			}
		}},
		{"chunk bytes changed", func(t *testing.T, directory string) {
			manifest := readAuditManifest(t, directory)
			for _, asset := range manifest.NormalizedAssets {
				if strings.HasPrefix(asset.Path, "chunk-") {
					data, err := os.ReadFile(filepath.Join(directory, asset.Path))
					if err != nil {
						t.Fatal(err)
					}
					data[0] ^= 1
					if err := os.WriteFile(filepath.Join(directory, asset.Path), data, 0o600); err != nil {
						t.Fatal(err)
					}
					return
				}
			}
			t.Fatal("fixture has no chunk")
		}},
		{"chunk truncated", func(t *testing.T, directory string) {
			manifest := readAuditManifest(t, directory)
			for _, asset := range manifest.NormalizedAssets {
				if strings.HasPrefix(asset.Path, "chunk-") {
					data, err := os.ReadFile(filepath.Join(directory, asset.Path))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(directory, asset.Path), data[:len(data)-1], 0o600); err != nil {
						t.Fatal(err)
					}
					return
				}
			}
			t.Fatal("fixture has no chunk")
		}},
		{"manifest unknown field", func(t *testing.T, directory string) {
			body := readJSONMap(t, filepath.Join(directory, ManifestName))
			body["unexpected"] = true
			writeCanonicalManifestAndRoot(t, directory, body)
		}},
		{"unknown schema version", func(t *testing.T, directory string) {
			body := readJSONMap(t, filepath.Join(directory, ManifestName))
			body["version"] = "99.0.0"
			writeCanonicalManifestAndRoot(t, directory, body)
		}},
		{"AUDIT_RESULT stage confusion", func(t *testing.T, directory string) {
			body := readJSONMap(t, filepath.Join(directory, ManifestName))
			body["stage"] = "AUDIT_RESULT"
			body["verdict"] = "PASS"
			writeCanonicalManifestAndRoot(t, directory, body)
		}},
		{"bundle index missing core classification authority", func(t *testing.T, directory string) {
			rewriteBundleIndexAndRoot(t, directory, func(index map[string]any) {
				delete(index, "core_evidence_classifications")
			})
		}},
		{"core descriptor classification bypass", func(t *testing.T, directory string) {
			rewriteBundleIndexAndRoot(t, directory, func(index map[string]any) {
				assets, ok := index["logical_assets"].([]any)
				if !ok {
					t.Fatal("bundle index logical_assets is not an array")
				}
				for _, value := range assets {
					asset, ok := value.(map[string]any)
					if ok && asset["path"] == RawEventsAssetName {
						asset["classification"] = string(ContentUnreleasedRemote)
						return
					}
				}
				t.Fatal("bundle index misses RAW events descriptor")
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := fixtureExportProfile()
			profile.InlineThreshold = 8
			input, verifier := fixtureAuditInput(t, profile)
			input.Destination = filepath.Join(privateTempDir(t), "audit")
			if _, err := GenerateAuditReady(context.Background(), input); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, input.Destination)
			if _, err := VerifyAuditReady(context.Background(), input.Destination, verifier); err == nil {
				t.Fatal("tampered/confused bundle was accepted")
			}
		})
	}
}

func readAuditManifest(t *testing.T, directory string) AuditReadyManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(directory, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest AuditReadyManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func readJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func rewriteBundleIndexAndRoot(t *testing.T, directory string, mutate func(map[string]any)) {
	t.Helper()
	index := readJSONMap(t, filepath.Join(directory, BundleIndexName))
	mutate(index)
	indexBytes, err := canonicalLine(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, BundleIndexName), indexBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := readJSONMap(t, filepath.Join(directory, ManifestName))
	assets, ok := manifest["normalized_assets"].([]any)
	if !ok {
		t.Fatal("manifest normalized_assets is not an array")
	}
	for _, value := range assets {
		asset, ok := value.(map[string]any)
		if ok && asset["path"] == BundleIndexName {
			asset["bytes"] = len(indexBytes)
			asset["sha256"] = digestText(indexBytes)
			writeCanonicalManifestAndRoot(t, directory, manifest)
			return
		}
	}
	t.Fatal("manifest does not bind bundle-index.json")
}

func writeCanonicalManifestAndRoot(t *testing.T, directory string, manifest map[string]any) {
	t.Helper()
	data, err := canonicalLine(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ManifestName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	root := digestText(data) + "\n"
	if err := os.WriteFile(filepath.Join(directory, RootName), []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReplayMismatchFingerprintMutationAndContractConflationReject(t *testing.T) {
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	badReplay := input.Closure
	badReplay.Replay.ReplayedFinalStateHash = repeatSHA("8")
	if _, err := NormalizeRunEvidenceClosure(badReplay); !errors.Is(err, ErrReplayMismatch) {
		t.Fatalf("replay mismatch error = %v", err)
	}
	badFamily := input.DefectFamilies[0]
	badFamily.Projection.SemanticKey = "MUTATED-SEMANTIC-KEY"
	if _, err := NormalizeDefectFamily(badFamily); !errors.Is(err, ErrDefectInvalid) {
		t.Fatalf("fingerprint mutation error = %v", err)
	}
	conflated := input.DefectOccurrences[0]
	conflated.FamilyFingerprint = repeatSHA("8")
	if _, _, err := NormalizeDefects(input.DefectFamilies, []DefectOccurrence{conflated}); !errors.Is(err, ErrDefectInvalid) {
		t.Fatalf("family/occurrence conflation error = %v", err)
	}
	wrongSource := input.Closure
	wrongSource.Source.Commit = strings.Repeat("8", 40)
	input.Closure = wrongSource
	input.Destination = filepath.Join(privateTempDir(t), "wrong-source")
	if _, err := GenerateAuditReady(context.Background(), input); err == nil {
		t.Fatal("wrong source binding accepted")
	}
}

func TestGitMirrorVerifierBindsRemoteCommitAndTree(t *testing.T) {
	source, verifier := syntheticGitMirror(t)
	result, err := verifier.Verify(context.Background(), source)
	if err != nil || result.Commit != source.Commit || result.Remote != source.Repository {
		t.Fatalf("valid mirror verification = %+v, %v", result, err)
	}
	wrongCommit := source
	wrongCommit.Commit = strings.Repeat("f", 40)
	if _, err := verifier.Verify(context.Background(), wrongCommit); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("wrong commit error = %v", err)
	}
	wrongTree := source
	wrongTree.Tree = strings.Repeat("f", 40)
	if _, err := verifier.Verify(context.Background(), wrongTree); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("wrong tree error = %v", err)
	}
	wrongRepository := source
	wrongRepository.Repository = "https://example.invalid/other.git"
	if _, err := verifier.Verify(context.Background(), wrongRepository); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("unverified repository error = %v", err)
	}
	root := privateTempDir(t)
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(filepath.Dir(verifier.MirrorPath), linked); err != nil {
		t.Fatal(err)
	}
	linkedVerifier := verifier
	linkedVerifier.MirrorPath = filepath.Join(linked, filepath.Base(verifier.MirrorPath))
	if _, err := linkedVerifier.Verify(context.Background(), source); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("mirror symlink ancestor error = %v", err)
	}
}

func assertUnsafeAuditReadyRepository(t *testing.T, repository string) {
	t.Helper()
	if err := ValidateAuditReadyRepositoryIdentity(repository); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("unsafe repository was accepted: %v", err)
	} else if strings.Contains(err.Error(), repository) || strings.Contains(err.Error(), "probe-value") {
		t.Fatalf("repository validation error disclosed its input: %v", err)
	}
}

func TestF2N01PasswordUserinfoRepositoryRejected(t *testing.T) {
	assertUnsafeAuditReadyRepository(t, "https://"+"probe-user:probe-value"+"@example.invalid/aipt.git")
	assertUnsafeAuditReadyRepository(t, "https://"+"probe-user%3Aprobe-value"+"@example.invalid/aipt.git")
}

func TestF2N02TokenStyleUserinfoRepositoryRejected(t *testing.T) {
	assertUnsafeAuditReadyRepository(t, "https://"+"probe-value"+"@example.invalid/aipt.git")
}

func TestF2N03QueryCredentialRepositoryRejected(t *testing.T) {
	assertUnsafeAuditReadyRepository(t, "https://example.invalid/aipt.git"+"?access=probe-value")
	assertUnsafeAuditReadyRepository(t, "https://example.invalid/aipt.git?")
}

func TestF2N04FragmentCredentialRepositoryRejected(t *testing.T) {
	assertUnsafeAuditReadyRepository(t, "https://example.invalid/aipt.git"+"#access=probe-value")
	assertUnsafeAuditReadyRepository(t, "https://example.invalid/aipt.git#")
}

func TestF2RepositoryParserRejectsMissingHostAndDecodedControls(t *testing.T) {
	assertUnsafeAuditReadyRepository(t, "https:///missing-host.git")
	assertUnsafeAuditReadyRepository(t, "https://example.invalid/aipt.git%0aescaped-control")
}

func TestF2N05CredentialBearingMirrorRemoteRejected(t *testing.T) {
	source, verifier := syntheticGitMirror(t)
	injected := "https://" + "mirror-probe-value" + "@example.invalid/aipt.git"
	runGitTest(t, "--git-dir", verifier.MirrorPath, "remote", "set-url", "origin", injected)
	if _, err := verifier.Verify(context.Background(), source); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("credential-bearing mirror remote was accepted: %v", err)
	} else if strings.Contains(err.Error(), "mirror-probe-value") {
		t.Fatalf("mirror validation error disclosed credential material: %v", err)
	}
}

func TestF2N06CredentialBearingExpectedRepositoryRejected(t *testing.T) {
	source, verifier := syntheticGitMirror(t)
	injected := "https://" + "expected-probe-value" + "@example.invalid/aipt.git"
	verifier.ExpectedRepository = injected
	if _, err := verifier.Verify(context.Background(), source); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("credential-bearing expected repository was accepted: %v", err)
	} else if strings.Contains(err.Error(), "expected-probe-value") {
		t.Fatalf("expected-repository error disclosed credential material: %v", err)
	}
}

func TestF2N07CredentialBearingRawCaptureCannotEnterAuditReadyBundleOrErrors(t *testing.T) {
	source := fixtureSourceIdentity()
	sentinel := "raw-probe-value"
	source.Repository = "https://" + sentinel + "@example.invalid/aipt.git"
	rawPath := filepath.Join(privateTempDir(t), "legacy-raw-capture")
	if _, err := ExportRawCapture(context.Background(), &staticSource{snapshot: fixtureSnapshot()}, ExportInput{
		Destination: rawPath, Source: source, StreamID: "synthetic-ledger",
	}); err != nil {
		t.Fatalf("frozen RAW_CAPTURE v1 fixture setup failed: %v", err)
	}
	input, _ := fixtureAuditInput(t, fixtureExportProfile())
	verifier := &staticSourceVerifier{expected: source}
	input.RawCapture = rawPath
	input.SourceVerifier = verifier
	input.Destination = filepath.Join(privateTempDir(t), "must-not-exist")
	if _, err := GenerateAuditReady(context.Background(), input); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("credential-bearing RAW_CAPTURE source error = %v", err)
	} else if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("AUDIT_READY error disclosed repository credential material: %v", err)
	}
	if verifier.calls != 0 {
		t.Fatalf("untrusted source verifier was invoked %d time(s) before B005 identity validation", verifier.calls)
	}
	if _, err := os.Lstat(input.Destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential-bearing source entered an AUDIT_READY bundle: %v", err)
	}
}

func TestF3N01GitMirrorVerifierPromisorMissingObjectNeverFetches(t *testing.T) {
	source, _ := syntheticGitMirror(t)
	var requests atomic.Int64
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.NotFound(writer, nil)
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: handler},
	}
	server.StartTLS()
	defer server.Close()

	mirror := filepath.Join(privateTempDir(t), "promisor.git")
	runGitTest(t, "init", "--quiet", "--bare", "--object-format=sha1", mirror)
	if err := os.Chmod(mirror, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := server.URL + "/aipt.git"
	runGitTest(t, "--git-dir", mirror, "config", "remote.origin.url", repository)
	runGitTest(t, "--git-dir", mirror, "config", "remote.origin.promisor", "true")
	runGitTest(t, "--git-dir", mirror, "config", "remote.origin.partialclonefilter", "blob:none")
	runGitTest(t, "--git-dir", mirror, "config", "extensions.partialClone", "origin")
	runGitTest(t, "--git-dir", mirror, "config", "http.sslVerify", "false")
	source.Repository = repository

	if gitObjectExistsWithoutFetch(mirror, source.Commit) {
		t.Fatal("promisor fixture unexpectedly contains the target commit")
	}
	objectsBefore := snapshotObjectStore(t, mirror)
	verifier := GitMirrorVerifier{MirrorPath: mirror, ExpectedRepository: repository}
	if _, err := verifier.Verify(context.Background(), source); !errors.Is(err, ErrSourceUnverified) {
		t.Fatalf("missing promised commit error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("offline verifier contacted the promisor remote %d time(s)", got)
	}
	objectsAfter := snapshotObjectStore(t, mirror)
	if !canonicalEqual(objectsAfter, objectsBefore) {
		t.Fatalf("promisor object store changed: before=%v after=%v", objectsBefore, objectsAfter)
	}
	if gitObjectExistsWithoutFetch(mirror, source.Commit) {
		t.Fatal("missing promised commit appeared in the local object database")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("local absence recheck contacted the promisor remote %d time(s)", got)
	}
}

func gitObjectExistsWithoutFetch(mirror, object string) bool {
	command := exec.Command(trustedGitExecutable, "--no-replace-objects", "--git-dir="+mirror, "cat-file", "-e", object+"^{commit}")
	command.Env = []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	}
	return command.Run() == nil
}

func snapshotObjectStore(t *testing.T, mirror string) map[string]string {
	t.Helper()
	root := filepath.Join(mirror, "objects")
	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		identity := fmt.Sprintf("mode=%s;size=%d;mtime=%d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		switch {
		case entry.IsDir():
			snapshot[filepath.ToSlash(relative)] = "directory;" + identity
			return nil
		case info.Mode().IsRegular():
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			snapshot[filepath.ToSlash(relative)] = "file;" + identity + ";sha256=" + digestText(data)
			return nil
		case info.Mode()&os.ModeSymlink != 0:
			target, readErr := os.Readlink(path)
			if readErr != nil {
				return readErr
			}
			snapshot[filepath.ToSlash(relative)] = "symlink;" + identity + ";target=" + target
			return nil
		default:
			snapshot[filepath.ToSlash(relative)] = "other;" + identity
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func syntheticGitMirror(t *testing.T) (SourceIdentity, GitMirrorVerifier) {
	t.Helper()
	root := privateTempDir(t)
	sourceDirectory := filepath.Join(root, "source")
	mirrorDirectory := filepath.Join(root, "mirror.git")
	runGitTest(t, "init", "--quiet", "--object-format=sha1", sourceDirectory)
	if err := os.WriteFile(filepath.Join(sourceDirectory, "fixture.txt"), []byte("synthetic public fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, "-C", sourceDirectory, "add", "fixture.txt")
	runGitTest(t, "-C", sourceDirectory, "-c", "user.name=AIPT Synthetic", "-c", "user.email=synthetic@example.invalid", "commit", "--quiet", "-m", "synthetic fixture")
	commit := strings.TrimSpace(runGitTest(t, "-C", sourceDirectory, "rev-parse", "HEAD"))
	tree := strings.TrimSpace(runGitTest(t, "-C", sourceDirectory, "rev-parse", "HEAD^{tree}"))
	runGitTest(t, "clone", "--quiet", "--bare", sourceDirectory, mirrorDirectory)
	if err := os.Chmod(mirrorDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	repository := "https://example.invalid/aipt-synthetic.git"
	runGitTest(t, "--git-dir", mirrorDirectory, "remote", "set-url", "origin", repository)
	verifier := GitMirrorVerifier{MirrorPath: mirrorDirectory, ExpectedRepository: repository}
	source := SourceIdentity{Repository: repository, Commit: commit, Tree: tree}
	return source, verifier
}

func runGitTest(t *testing.T, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}

func TestReassemblyRejectsChunkReorderUnexpectedContentAndDuplicatePaths(t *testing.T) {
	profile := fixtureExportProfile()
	profile.InlineThreshold = 0
	profile.ChunkSize = 4
	inputs := []LogicalAssetInput{
		{Path: "a.bin", MediaType: "application/octet-stream", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: []byte("abcdefgh")},
		{Path: "b.bin", MediaType: "application/octet-stream", Classification: ContentPublic, ContentKind: ContentKindSupplemental, Data: []byte("abcdefgh")},
	}
	index, physicalAssets, err := materializeLogicalAssets(inputs, profile, publicCoreEvidenceClassifications())
	if err != nil {
		t.Fatal(err)
	}
	physical := map[string][]byte{}
	physicalMedia := map[string]string{}
	for name, asset := range physicalAssets {
		physical[name] = append([]byte(nil), asset.data...)
		physicalMedia[name] = asset.mediaType
	}
	if logical, err := reassembleLogicalAssets(index, physical, physicalMedia); err != nil || string(logical["a.bin"]) != "abcdefgh" {
		t.Fatalf("valid reassembly = %q, %v", logical["a.bin"], err)
	}
	t.Run("reorder", func(t *testing.T) {
		mutated := index
		mutated.LogicalAssets = append([]LogicalAsset(nil), index.LogicalAssets...)
		mutated.LogicalAssets[0].Storage.Chunks = append([]ChunkReference(nil), index.LogicalAssets[0].Storage.Chunks...)
		sort.Slice(mutated.LogicalAssets[0].Storage.Chunks, func(i, j int) bool { return i > j })
		if _, err := reassembleLogicalAssets(mutated, physical, physicalMedia); !errors.Is(err, ErrChunkInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unexpected", func(t *testing.T) {
		mutated := cloneLogicalAssetMap(physical)
		mutated["chunk-"+repeatSHA("9")+".bin"] = []byte("extra")
		if _, err := reassembleLogicalAssets(index, mutated, physicalMedia); !errors.Is(err, ErrChunkInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("chunk media type", func(t *testing.T) {
		mutatedMedia := make(map[string]string, len(physicalMedia))
		for name, mediaType := range physicalMedia {
			mutatedMedia[name] = mediaType
		}
		for name := range mutatedMedia {
			mutatedMedia[name] = "text/plain"
			break
		}
		if _, err := reassembleLogicalAssets(index, physical, mutatedMedia); !errors.Is(err, ErrChunkInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate logical path", func(t *testing.T) {
		mutated := index
		mutated.LogicalAssets = append([]LogicalAsset(nil), index.LogicalAssets...)
		mutated.LogicalAssets[1].Path = mutated.LogicalAssets[0].Path
		if _, err := reassembleLogicalAssets(mutated, physical, physicalMedia); !errors.Is(err, ErrChunkInvalid) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestB005NegativeMatrixIsExactAndBackedByExecutableTests(t *testing.T) {
	type probe struct {
		ID        string `json:"id"`
		Attack    string `json:"attack"`
		Expected  string `json:"expected"`
		CoveredBy string `json:"covered_by"`
	}
	type matrix struct {
		Schema string  `json:"schema"`
		TaskID string  `json:"task_id"`
		Probes []probe `json:"probes"`
	}
	path := filepath.Join("..", "..", "testdata", "evidence", "v1", "b005-negative-matrix.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var registered matrix
	if err := decoder.Decode(&registered); err != nil {
		t.Fatal(err)
	}
	if registered.Schema != "aipt.b005.negative-matrix/v1" || registered.TaskID != "AIPT-MVP-B005" || len(registered.Probes) != 50 {
		t.Fatalf("negative matrix identity/count = %s/%s/%d", registered.Schema, registered.TaskID, len(registered.Probes))
	}
	sourceFiles := []string{"audit_ready_test.go", "export_test.go", "postgres_integration_test.go", filepath.Join("..", "..", "cmd", "aipt-audit-ready", "main_test.go")}
	var source strings.Builder
	for _, name := range sourceFiles {
		content, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		source.Write(content)
	}
	for index, item := range registered.Probes {
		wantID := "N" + fmt.Sprintf("%02d", index+1)
		if item.ID != wantID || item.Attack == "" || item.CoveredBy == "" ||
			(item.Expected != "REJECT" && item.Expected != "FLAG_ONLY" && item.Expected != "MATCH_REQUIRED" && item.Expected != "ZERO_REQUIRED") {
			t.Fatalf("negative matrix probe %d is invalid: %+v", index, item)
		}
		selector := strings.Split(item.CoveredBy, "/")[0]
		if !strings.Contains(source.String(), "func "+selector+"(") {
			t.Fatalf("%s cites missing executable test %s", item.ID, selector)
		}
	}
}
