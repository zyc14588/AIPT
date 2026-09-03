package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"unsafe"
)

const (
	maxAuditReadyManifestBytes = int64(8 << 20)
	maxAuditReadyIndexBytes    = int64(16 << 20)
	maxAuditReadyAssetBytes    = int64(128 << 20)
	maxAuditReadyTotalBytes    = int64(256 << 20)
	maxAuditReadyAssets        = 10_000
	maxAuditReadyChunks        = 100_000
)

var (
	safeBundleMember          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$`)
	credentialContentPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:^|[^a-z0-9])sk-[a-z0-9_-]{8,}`),
		regexp.MustCompile(`(?i)\b(?:gh[pousr]_[a-z0-9]{20,}|AKIA[A-Z0-9]{16})\b`),
		regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/-]{12,}`),
		regexp.MustCompile(`(?i)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\b(?:api[_-]?key|token|secret|password|credential)[a-z0-9_-]*\s*[:=]\s*["']?[a-z0-9_+./=-]{8,}`),
	}
)

type physicalAsset struct {
	data      []byte
	mediaType string
}

// GenerateAuditReady builds an offline deterministic AUDIT_READY directory.
// It verifies RAW_CAPTURE and source Git identity before normalization, writes
// only a private sibling staging directory, self-verifies, and publishes with
// RENAME_NOREPLACE. It never calls a model, network, ledger, or source writer.
func GenerateAuditReady(ctx context.Context, input GenerateAuditReadyInput) (AuditReadyVerification, error) {
	if ctx == nil || input.SourceVerifier == nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: generator dependencies", ErrAuditReadyInvalid)
	}
	if err := validateDisclosure(input.Disclosure); err != nil {
		return AuditReadyVerification{}, err
	}
	preflightProfile, err := validateExportProfile(input.ExportProfile)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	if err := validateCoreEvidenceClassifications(input.CoreClassifications); err != nil {
		return AuditReadyVerification{}, err
	}
	if err := preflightGenerateInput(input, preflightProfile); err != nil {
		return AuditReadyVerification{}, err
	}
	originalInput := input
	ownedInput, inputDigest, err := snapshotGenerateInput(input)
	if err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: snapshot generator input", ErrAuditReadyInvalid)
	}
	input = ownedInput
	inputUnchanged := func() bool {
		current, digestErr := digestGenerateInput(originalInput)
		return digestErr == nil && current == inputDigest
	}
	if err := ctx.Err(); err != nil {
		return AuditReadyVerification{}, classifyError(ErrAuditReadyInvalid, "generate audit bundle", err)
	}
	if err := validateDisclosure(input.Disclosure); err != nil {
		return AuditReadyVerification{}, err
	}
	profile, err := validateExportProfile(input.ExportProfile)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	if err := validateCoreEvidenceClassifications(input.CoreClassifications); err != nil {
		return AuditReadyVerification{}, err
	}
	finalPath, parent, err := validateAbsentDestination(input.Destination)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	parentFile, parentState, err := openOwnerControlledDirectoryPath(parent)
	if err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: open destination parent", ErrUnsafePath)
	}
	defer parentFile.Close()

	raw, err := holdVerifiedRawCapture(input.RawCapture)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	defer raw.Close()
	source := raw.material.Verification.Manifest.Source
	if err := validateAuditReadySourceIdentity(source); err != nil {
		return AuditReadyVerification{}, classifyError(ErrSourceUnverified, "verify source identity before normalization", err)
	}
	remote, err := input.SourceVerifier.Verify(ctx, source)
	if err != nil || validateRemoteVerification(remote, source) != nil {
		return AuditReadyVerification{}, classifyError(ErrSourceUnverified, "verify source before normalization", errOrFixed(err))
	}
	if !inputUnchanged() {
		return AuditReadyVerification{}, fmt.Errorf("%w: generator input changed before normalization", ErrStreamChanged)
	}

	eventHashes, err := verifiedRawEventHashes(raw.material.EventsBytes, raw.material.Verification.Manifest.StreamID)
	if err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: RAW_CAPTURE event identity inventory", ErrAuditReadyInvalid)
	}
	closure, families, occurrences, report, err := normalizeAuditContracts(
		raw.material.Verification, eventHashes, input.Closure, input.DefectFamilies, input.DefectOccurrences, input.Report,
	)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	logical, err := buildCoreLogicalAssets(raw.material, closure, families, occurrences, report, input.CoreClassifications)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	logical = append(logical, cloneLogicalAssetInputs(input.Supplemental)...)
	if err := validateLogicalAssetInputs(logical, input.Disclosure, profile); err != nil {
		return AuditReadyVerification{}, err
	}
	if err := validateContractEvidenceReferences(logical, closure, occurrences, report); err != nil {
		return AuditReadyVerification{}, err
	}

	index, physical, err := materializeLogicalAssets(logical, profile, input.CoreClassifications)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	indexBytes, err := canonicalLine(index)
	if err != nil || int64(len(indexBytes)) > maxAuditReadyIndexBytes {
		return AuditReadyVerification{}, fmt.Errorf("%w: bundle index canonicalization", ErrAuditReadyInvalid)
	}
	physical[BundleIndexName] = physicalAsset{data: indexBytes, mediaType: "application/json"}
	manifest := AuditReadyManifest{
		Schema: SchemaID, Version: SchemaVersion, Stage: AuditReadyStage,
		RawCaptureRoot: raw.material.Verification.Root, Source: source,
		RemoteVerification: remote, Disclosure: input.Disclosure,
		NormalizationVersion: AuditReadyNormalizationVersion,
		NormalizedAssets:     describePhysicalAssets(physical),
	}
	manifestBytes, err := canonicalLine(manifest)
	if err != nil || int64(len(manifestBytes)) > maxAuditReadyManifestBytes {
		return AuditReadyVerification{}, fmt.Errorf("%w: manifest canonicalization", ErrAuditReadyInvalid)
	}
	manifestHash := sha256.Sum256(manifestBytes)
	rootBytes := []byte(hex.EncodeToString(manifestHash[:]) + "\n")

	tempName, tempDirectory, tempState, err := createPrivateStagingDirectory(parentFile)
	if err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: create audit staging directory", ErrWriteFailed)
	}
	defer tempDirectory.Close()
	keepTemp := true
	defer func() {
		if keepTemp {
			removePrivateAuditStaging(parentFile, tempName)
		}
	}()
	for _, name := range sortedPhysicalNames(physical) {
		if err := writePrivateFileAt(tempDirectory, name, physical[name].data); err != nil {
			return AuditReadyVerification{}, err
		}
	}
	if err := writePrivateFileAt(tempDirectory, ManifestName, manifestBytes); err != nil {
		return AuditReadyVerification{}, err
	}
	if err := writePrivateFileAt(tempDirectory, RootName, rootBytes); err != nil {
		return AuditReadyVerification{}, err
	}
	if err := tempDirectory.Sync(); err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: sync audit staging directory", ErrWriteFailed)
	}
	if err := syscall.Fstat(int(tempDirectory.Fd()), &tempState); err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: retain audit staging identity", ErrWriteFailed)
	}
	verification, err := verifyHeldAuditReady(ctx, tempDirectory, tempState, input.SourceVerifier)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	if !raw.Stable() || !inputUnchanged() {
		return AuditReadyVerification{}, fmt.Errorf("%w: input changed during generation", ErrStreamChanged)
	}
	remoteAfter, err := input.SourceVerifier.Verify(ctx, source)
	if err != nil || !canonicalEqual(remoteAfter, remote) {
		return AuditReadyVerification{}, classifyError(ErrSourceUnverified, "verify source after normalization", errOrFixed(err))
	}
	if !directoryPathMatchesNoSymlinks(parent, parentState, false) {
		return AuditReadyVerification{}, fmt.Errorf("%w: destination parent identity changed", ErrUnsafePath)
	}
	finalName := filepath.Base(finalPath)
	if err := renameat2NoReplace(int(parentFile.Fd()), tempName, int(parentFile.Fd()), finalName); err != nil {
		if errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOTEMPTY) {
			return AuditReadyVerification{}, fmt.Errorf("%w: final path appeared before publication", ErrTargetExists)
		}
		return AuditReadyVerification{}, fmt.Errorf("%w: publish verified audit bundle", ErrWriteFailed)
	}
	keepTemp = false
	rollback := func(cause error) (AuditReadyVerification, error) {
		// Publication does not become successful until every post-rename identity,
		// source/input-stability and parent durability check has passed. Moving the
		// verified inode back to its private random staging name makes any failure
		// look incomplete to readers and lets the existing cleanup remove it.
		if err := renameat2NoReplace(int(parentFile.Fd()), finalName, int(parentFile.Fd()), tempName); err != nil {
			return AuditReadyVerification{}, fmt.Errorf("%w: audit publication rollback failed", ErrWriteFailed)
		}
		keepTemp = true
		if err := parentFile.Sync(); err != nil {
			return AuditReadyVerification{}, fmt.Errorf("%w: audit publication rollback sync failed", ErrWriteFailed)
		}
		return AuditReadyVerification{}, cause
	}
	finalDirectory, finalState, err := openPrivateDirectoryAt(parentFile, finalName)
	if err != nil {
		return rollback(fmt.Errorf("%w: open published audit bundle", ErrWriteFailed))
	}
	defer finalDirectory.Close()
	if !samePrivateBundleDirectory(tempState, finalState) {
		return rollback(fmt.Errorf("%w: published audit object identity mismatch", ErrWriteFailed))
	}
	published, err := verifyHeldAuditReady(ctx, finalDirectory, finalState, input.SourceVerifier)
	if err != nil || published.Root != verification.Root {
		return rollback(fmt.Errorf("%w: published audit bundle verification", ErrWriteFailed))
	}
	if !raw.Stable() || !inputUnchanged() || !directoryPathMatchesNoSymlinks(parent, parentState, false) {
		return rollback(fmt.Errorf("%w: input or destination identity changed during publication", ErrStreamChanged))
	}
	if err := parentFile.Sync(); err != nil {
		return rollback(fmt.Errorf("%w: sync audit destination parent", ErrWriteFailed))
	}
	return published, nil
}

func removePrivateAuditStaging(parent *os.File, name string) {
	directory, _, err := openPrivateDirectoryAt(parent, name)
	if err != nil {
		return
	}
	entries, readErr := directory.ReadDir(maxAuditReadyAssets + 3)
	if readErr == nil || errors.Is(readErr, io.EOF) {
		for _, entry := range entries {
			if safeBundleMember.MatchString(entry.Name()) {
				_ = syscall.Unlinkat(int(directory.Fd()), entry.Name())
			}
		}
	}
	_ = directory.Close()
	pointer, pointerErr := syscall.BytePtrFromString(name)
	if pointerErr == nil {
		const atRemoveDir = uintptr(0x200)
		_, _, _ = syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(parent.Fd()), uintptr(unsafe.Pointer(pointer)), atRemoveDir)
	}
	_ = parent.Sync()
}

// VerifyAuditReady independently verifies a B005 AUDIT_READY directory and
// revalidates its immutable source commit/tree against the supplied mirror.
func VerifyAuditReady(ctx context.Context, directory string, verifier SourceVerifier) (AuditReadyVerification, error) {
	if ctx == nil || verifier == nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: verifier dependencies", ErrAuditReadyInvalid)
	}
	directoryFile, directoryState, err := openPrivateDirectoryPath(directory)
	if err != nil {
		return AuditReadyVerification{}, fmt.Errorf("%w: open audit bundle", ErrAuditReadyInvalid)
	}
	defer directoryFile.Close()
	return verifyHeldAuditReady(ctx, directoryFile, directoryState, verifier)
}

func verifyHeldAuditReady(ctx context.Context, directory *os.File, directoryState syscall.Stat_t, verifier SourceVerifier) (AuditReadyVerification, error) {
	fail := func(operation string) (AuditReadyVerification, error) {
		return AuditReadyVerification{}, fmt.Errorf("%w: %s", ErrAuditReadyInvalid, operation)
	}
	entries, err := directory.ReadDir(maxAuditReadyAssets + 3)
	if err != nil && !errors.Is(err, io.EOF) {
		return fail("read bundle inventory")
	}
	if len(entries) < 3 || len(entries) > maxAuditReadyAssets+2 {
		return fail("bundle member count exceeds bounds")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !safeBundleMember.MatchString(entry.Name()) {
			return fail("unsafe bundle member name")
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	read := func(name string, maximum int64) ([]byte, error) {
		file, state, openErr := openHeldPrivateFile(directory, name, maximum)
		if openErr != nil {
			return nil, openErr
		}
		defer file.Close()
		return readHeldPrivateFile(file, state, maximum)
	}
	manifestBytes, err := read(ManifestName, maxAuditReadyManifestBytes)
	if err != nil {
		return fail("read manifest")
	}
	manifestBody, err := canonicalBody(manifestBytes)
	if err != nil {
		return fail("manifest is not canonical")
	}
	var manifest AuditReadyManifest
	if err := strictDecode(manifestBody, &manifest); err != nil || validateAuditReadyManifest(manifest) != nil {
		return fail("manifest contract")
	}
	rootBytes, err := read(RootName, maxRawCaptureRootBytes)
	if err != nil || len(rootBytes) != 65 || rootBytes[64] != '\n' || !lowerSHA256.Match(rootBytes[:64]) {
		return fail("root contract")
	}
	manifestHash := sha256.Sum256(manifestBytes)
	root := hex.EncodeToString(manifestHash[:])
	if string(rootBytes[:64]) != root {
		return fail("root digest mismatch")
	}
	remote, err := verifier.Verify(ctx, manifest.Source)
	if err != nil || validateRemoteVerification(remote, manifest.Source) != nil || !canonicalEqual(remote, manifest.RemoteVerification) {
		return AuditReadyVerification{}, classifyError(ErrSourceUnverified, "verify audit bundle source", errOrFixed(err))
	}

	wantedNames := []string{ManifestName, RootName}
	physical := make(map[string][]byte, len(manifest.NormalizedAssets))
	physicalMedia := make(map[string]string, len(manifest.NormalizedAssets))
	var totalBytes int64
	for _, asset := range manifest.NormalizedAssets {
		data, readErr := read(asset.Path, maxAuditReadyAssetBytes)
		if readErr != nil {
			return fail("read normalized asset")
		}
		if int64(len(data)) != asset.Bytes {
			return fail("normalized asset size mismatch")
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != asset.SHA256 {
			return fail("normalized asset digest mismatch")
		}
		if totalBytes > maxAuditReadyTotalBytes-int64(len(data)) {
			return fail("normalized asset total exceeds bound")
		}
		totalBytes += int64(len(data))
		physical[asset.Path] = data
		physicalMedia[asset.Path] = asset.MediaType
		wantedNames = append(wantedNames, asset.Path)
	}
	sort.Strings(wantedNames)
	if !equalStrings(names, wantedNames) {
		return fail("bundle inventory differs from manifest")
	}
	indexBytes, exists := physical[BundleIndexName]
	if !exists || int64(len(indexBytes)) > maxAuditReadyIndexBytes || physicalMedia[BundleIndexName] != "application/json" {
		return fail("bundle index missing or oversized")
	}
	indexBody, err := canonicalBody(indexBytes)
	if err != nil {
		return fail("bundle index is not canonical")
	}
	var index BundleIndex
	if err := strictDecode(indexBody, &index); err != nil {
		return fail("bundle index decode")
	}
	profile, err := validateExportProfile(index.ExportProfile)
	if err != nil || index.Schema != BundleIndexSchema || index.Version != ContractVersion {
		return fail("bundle index contract")
	}
	index.ExportProfile = profile
	if err := validateCoreEvidenceClassifications(index.CoreEvidenceClassifications); err != nil {
		return AuditReadyVerification{}, err
	}
	if err := validateCoreLogicalAssetDescriptors(index.LogicalAssets, index.CoreEvidenceClassifications); err != nil {
		return AuditReadyVerification{}, err
	}
	logical, err := reassembleLogicalAssets(index, physical, physicalMedia)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	if err := validateLogicalDisclosure(logical, index.LogicalAssets, manifest.Disclosure); err != nil {
		return AuditReadyVerification{}, err
	}
	closure, report, err := verifyCoreLogicalAssets(manifest, logical)
	if err != nil {
		return AuditReadyVerification{}, err
	}
	remoteAfter, err := verifier.Verify(ctx, manifest.Source)
	if err != nil || !canonicalEqual(remoteAfter, remote) {
		return AuditReadyVerification{}, classifyError(ErrSourceUnverified, "verify stable audit bundle source", errOrFixed(err))
	}
	var directoryAfter syscall.Stat_t
	if err := syscall.Fstat(int(directory.Fd()), &directoryAfter); err != nil || !sameFileState(directoryState, directoryAfter) {
		return fail("bundle directory changed during verification")
	}
	return AuditReadyVerification{
		Root: root, Manifest: manifest, BundleIndex: index, Closure: closure, Report: report, LogicalAssets: cloneLogicalAssetMap(logical),
	}, nil
}

func normalizeAuditContracts(raw Verification, eventHashes map[int64]string, closure RunEvidenceClosure, families []DefectFamily, occurrences []DefectOccurrence, report RunReport) (RunEvidenceClosure, []DefectFamily, []DefectOccurrence, RunReport, error) {
	normalizedClosure, err := NormalizeRunEvidenceClosure(closure)
	if err != nil {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, err
	}
	manifest := raw.Manifest
	if normalizedClosure.Source != manifest.Source || normalizedClosure.Ledger.StreamID != manifest.StreamID ||
		normalizedClosure.Ledger.EventCount != manifest.EventCount || normalizedClosure.Ledger.TailSequence != manifest.TailSequence ||
		!equalStringPointers(normalizedClosure.Ledger.TailEventHash, manifest.TailEventHash) {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: closure RAW_CAPTURE binding", ErrAuditReadyInvalid)
	}
	if int64(len(eventHashes)) != manifest.EventCount {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: RAW_CAPTURE event identity count", ErrAuditReadyInvalid)
	}
	for _, receipt := range normalizedClosure.ActionReceipts {
		if expected, exists := eventHashes[receipt.Sequence]; !exists || expected != receipt.EventHash {
			return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: action receipt ledger event binding", ErrAuditReadyInvalid)
		}
	}
	normalizedFamilies, normalizedOccurrences, err := NormalizeDefects(families, occurrences)
	if err != nil {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, err
	}
	occurrenceIDs := make([]string, len(normalizedOccurrences))
	for index, occurrence := range normalizedOccurrences {
		if occurrence.RunID != normalizedClosure.RunID || occurrence.Source != normalizedClosure.Source {
			return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: defect occurrence Run/source binding", ErrDefectInvalid)
		}
		occurrenceIDs[index] = occurrence.OccurrenceID
	}
	if !equalStrings(occurrenceIDs, normalizedClosure.DefectOccurrenceIDs) {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: closure defect occurrence references", ErrDefectInvalid)
	}
	normalizedReport, err := NormalizeRunReport(report)
	if err != nil {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, err
	}
	familyIDs := make([]string, len(normalizedFamilies))
	for index, family := range normalizedFamilies {
		familyIDs[index] = family.FamilyID
	}
	sort.Strings(familyIDs)
	closureDigest, digestErr := canonicalDigest(normalizedClosure)
	if digestErr != nil {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: closure identity", ErrAuditReadyInvalid)
	}
	reportRoots := make(map[string]string, len(normalizedReport.EvidenceRoots))
	for _, identity := range normalizedReport.EvidenceRoots {
		reportRoots[identity.Kind] = identity.SHA256
	}
	if normalizedReport.RunID != normalizedClosure.RunID || normalizedReport.Source != normalizedClosure.Source ||
		normalizedReport.RunManifest != normalizedClosure.RunManifest || !canonicalEqual(normalizedReport.Replay, normalizedClosure.Replay) ||
		!canonicalEqual(normalizedReport.Coverage.References, normalizedClosure.CoverageReferences) ||
		!canonicalEqual(normalizedReport.GateEligibilityFacts, normalizedClosure.GateEligibilityFacts) ||
		!equalStrings(normalizedReport.DefectFamilyReferences, familyIDs) ||
		!equalStrings(normalizedReport.DefectOccurrenceReferences, occurrenceIDs) ||
		!equalStrings(normalizedReport.AnomalyCodes, normalizedClosure.AnomalyCodes) ||
		reportRoots["RAW_CAPTURE"] != raw.Root || reportRoots["RUN_EVIDENCE_CLOSURE"] != closureDigest ||
		normalizedReport.AuditorVerdictClaimed || normalizedReport.AuditResult != nil ||
		normalizedReport.Lifecycle != ReportProvisional || normalizedReport.Revision != 1 || normalizedReport.PredecessorReportSHA256 != nil {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: report closure binding or AUDIT_RESULT boundary", ErrReportInvalid)
	}
	modelReferenceIDs := make([]string, len(normalizedClosure.ModelExecutionReferences))
	for index, reference := range normalizedClosure.ModelExecutionReferences {
		modelReferenceIDs[index] = reference.ExecutionID
	}
	sort.Strings(modelReferenceIDs)
	if !equalStrings(normalizedReport.ModelExecution.ReferenceIDs, modelReferenceIDs) {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: report model execution references", ErrReportInvalid)
	}
	qualificationFound := false
	qualificationEligible := false
	for _, fact := range normalizedClosure.GateEligibilityFacts {
		if fact.Gate == "QUALIFICATION" {
			qualificationFound = true
			qualificationEligible = fact.Eligible
			break
		}
	}
	if !qualificationFound || normalizedReport.QualificationEligible != qualificationEligible {
		return RunEvidenceClosure{}, nil, nil, RunReport{}, fmt.Errorf("%w: qualification eligibility does not bind gate facts", ErrReportInvalid)
	}
	return normalizedClosure, normalizedFamilies, normalizedOccurrences, normalizedReport, nil
}

func buildCoreLogicalAssets(raw rawCaptureMaterial, closure RunEvidenceClosure, families []DefectFamily, occurrences []DefectOccurrence, report RunReport, classifications CoreEvidenceClassifications) ([]LogicalAssetInput, error) {
	encode := func(path string, classification ContentClassification, value any) (LogicalAssetInput, error) {
		line, err := canonicalLine(value)
		return LogicalAssetInput{Path: path, MediaType: "application/json", Classification: classification, ContentKind: ContentKindContract, Data: line}, err
	}
	closureAsset, err := encode(RunClosureName, classifications.RunEvidenceClosure, closure)
	if err != nil {
		return nil, err
	}
	replayAsset, err := encode(ReplayEvidenceName, classifications.ReplayEvidence, closure.Replay)
	if err != nil {
		return nil, err
	}
	familyAsset, err := encode(DefectFamiliesName, classifications.DefectFamily, defectFamilyEnvelope{Schema: "aipt.defect-families/v1", Version: ContractVersion, Families: families})
	if err != nil {
		return nil, err
	}
	occurrenceAsset, err := encode(DefectOccurrencesName, classifications.DefectOccurrence, defectOccurrenceEnvelope{Schema: "aipt.defect-occurrences/v1", Version: ContractVersion, Occurrences: occurrences})
	if err != nil {
		return nil, err
	}
	reportAsset, err := encode(RunReportName, classifications.RunReport, report)
	if err != nil {
		return nil, err
	}
	derivatives, err := RenderRunReport(report)
	if err != nil {
		return nil, err
	}
	return []LogicalAssetInput{
		{Path: RawManifestAssetName, MediaType: "application/json", Classification: classifications.RawCapture, ContentKind: ContentKindRawCapture, Data: append([]byte(nil), raw.ManifestBytes...)},
		{Path: RawEventsAssetName, MediaType: "application/x-ndjson", Classification: classifications.RawCapture, ContentKind: ContentKindRawCapture, Data: append([]byte(nil), raw.EventsBytes...)},
		{Path: RawRootAssetName, MediaType: "text/plain", Classification: classifications.RawCapture, ContentKind: ContentKindRawCapture, Data: append([]byte(nil), raw.RootBytes...)},
		closureAsset, replayAsset, familyAsset, occurrenceAsset, reportAsset,
		{Path: RunReportMarkdownName, MediaType: "text/markdown", Classification: classifications.ReportDerivatives, ContentKind: ContentKindReportDerivative, Data: derivatives.Markdown},
		{Path: RunReportCSVName, MediaType: "text/csv", Classification: classifications.ReportDerivatives, ContentKind: ContentKindReportDerivative, Data: derivatives.CSV},
		{Path: RunReportJUnitName, MediaType: "application/xml", Classification: classifications.ReportDerivatives, ContentKind: ContentKindReportDerivative, Data: derivatives.JUnit},
		{Path: RunReportHTMLName, MediaType: "text/html", Classification: classifications.ReportDerivatives, ContentKind: ContentKindReportDerivative, Data: derivatives.HTML},
	}, nil
}

func validateCoreEvidenceClassifications(classifications CoreEvidenceClassifications) error {
	values := []ContentClassification{
		classifications.RawCapture,
		classifications.RunEvidenceClosure,
		classifications.ReplayEvidence,
		classifications.DefectFamily,
		classifications.DefectOccurrence,
		classifications.RunReport,
		classifications.ReportDerivatives,
	}
	if classifications.Schema != CoreClassificationSchema || classifications.Version != ContractVersion {
		return fmt.Errorf("%w: core evidence classification schema/version", ErrAuditReadyInvalid)
	}
	for _, classification := range values {
		if !validContentClassification(classification) {
			return fmt.Errorf("%w: missing or unknown core evidence classification", ErrAuditReadyInvalid)
		}
	}
	if classifications.ReportDerivatives != classifications.RunReport {
		return fmt.Errorf("%w: report derivatives must inherit the Run Report classification", ErrDisclosureViolation)
	}
	return nil
}

func validateCoreLogicalAssetDescriptors(descriptors []LogicalAsset, classifications CoreEvidenceClassifications) error {
	type expectedDescriptor struct {
		classification ContentClassification
		kind           ContentKind
	}
	expected := map[string]expectedDescriptor{
		RawManifestAssetName:  {classifications.RawCapture, ContentKindRawCapture},
		RawEventsAssetName:    {classifications.RawCapture, ContentKindRawCapture},
		RawRootAssetName:      {classifications.RawCapture, ContentKindRawCapture},
		RunClosureName:        {classifications.RunEvidenceClosure, ContentKindContract},
		ReplayEvidenceName:    {classifications.ReplayEvidence, ContentKindContract},
		DefectFamiliesName:    {classifications.DefectFamily, ContentKindContract},
		DefectOccurrencesName: {classifications.DefectOccurrence, ContentKindContract},
		RunReportName:         {classifications.RunReport, ContentKindContract},
		RunReportMarkdownName: {classifications.ReportDerivatives, ContentKindReportDerivative},
		RunReportCSVName:      {classifications.ReportDerivatives, ContentKindReportDerivative},
		RunReportJUnitName:    {classifications.ReportDerivatives, ContentKindReportDerivative},
		RunReportHTMLName:     {classifications.ReportDerivatives, ContentKindReportDerivative},
	}
	for _, descriptor := range descriptors {
		want, core := expected[descriptor.Path]
		if !core {
			continue
		}
		if descriptor.Classification != want.classification || descriptor.ContentKind != want.kind {
			return fmt.Errorf("%w: core logical asset classification or kind mismatch", ErrDisclosureViolation)
		}
		delete(expected, descriptor.Path)
	}
	if len(expected) != 0 {
		return fmt.Errorf("%w: core logical asset classification binding is incomplete", ErrAuditReadyInvalid)
	}
	return nil
}

func validateExportProfile(profile ExportProfile) (ExportProfile, error) {
	if err := validContractIdentifier("export_profile.profile_id", profile.ProfileID); err != nil ||
		profile.InlineThreshold < 0 || profile.ChunkSize < 1 || profile.MaxAssetBytes < 1 || profile.MaxTotalBytes < 1 ||
		profile.MaxAssets < 1 || profile.MaxChunks < 1 || profile.InlineThreshold > profile.MaxAssetBytes || profile.ChunkSize > profile.MaxAssetBytes ||
		profile.MaxAssetBytes > maxAuditReadyAssetBytes || profile.MaxTotalBytes > maxAuditReadyTotalBytes ||
		profile.MaxAssets > maxAuditReadyAssets || profile.MaxChunks > maxAuditReadyChunks {
		return ExportProfile{}, fmt.Errorf("%w: invalid deployment export profile", ErrAuditReadyInvalid)
	}
	return profile, nil
}

func validateDisclosure(disclosure Disclosure) error {
	if disclosure.Encryption.Status == EncryptionEncrypted || disclosure.Profile == DisclosurePrivateFull ||
		(disclosure.Profile == DisclosureExternalAuditor && disclosure.ContainsUnpublishedContent) {
		return ErrEncryptionRequired
	}
	if disclosure.Encryption.Status != EncryptionUnencrypted || disclosure.Encryption.Scheme != "" || disclosure.Encryption.KeyReference != "" {
		return fmt.Errorf("%w: encryption metadata", ErrAuditReadyInvalid)
	}
	if disclosure.Profile == DisclosurePublic && disclosure.ContainsUnpublishedContent {
		return ErrDisclosureViolation
	}
	if disclosure.Profile != DisclosurePublic && disclosure.Profile != DisclosureExternalAuditor {
		return fmt.Errorf("%w: disclosure profile", ErrAuditReadyInvalid)
	}
	return nil
}

func validateLogicalAssetInputs(inputs []LogicalAssetInput, disclosure Disclosure, profile ExportProfile) error {
	if len(inputs) == 0 || len(inputs) > profile.MaxAssets {
		return fmt.Errorf("%w: logical asset count", ErrAuditReadyInvalid)
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
	var total int64
	for index, input := range inputs {
		if err := validLogicalPath("logical asset path", input.Path); err != nil || !mediaTypePattern.MatchString(input.MediaType) {
			return fmt.Errorf("%w: logical asset identity", ErrAuditReadyInvalid)
		}
		if index > 0 && input.Path == inputs[index-1].Path {
			return fmt.Errorf("%w: duplicate logical asset path", ErrAuditReadyInvalid)
		}
		if int64(len(input.Data)) > profile.MaxAssetBytes || total > profile.MaxTotalBytes-int64(len(input.Data)) {
			return fmt.Errorf("%w: logical asset byte budget", ErrAuditReadyInvalid)
		}
		total += int64(len(input.Data))
		if !validContentClassification(input.Classification) || !validContentKind(input.ContentKind) {
			return fmt.Errorf("%w: logical asset classification", ErrAuditReadyInvalid)
		}
		if err := validateOneDisclosure(input.Classification, input.ContentKind, input.Data, disclosure); err != nil {
			return err
		}
		if err := validateOneDisclosure(input.Classification, input.ContentKind, []byte(input.Path), disclosure); err != nil {
			return err
		}
	}
	return nil
}

func validContentClassification(value ContentClassification) bool {
	switch value {
	case ContentPublic, ContentUnreleasedRemote, ContentTableHiddenRemote, ContentLocalOnlySecret, ContentHumanPrivateData, ContentCredentialSecret:
		return true
	default:
		return false
	}
}

func validContentKind(value ContentKind) bool {
	switch value {
	case ContentKindContract, ContentKindRawCapture, ContentKindReportDerivative, ContentKindSupplemental,
		ContentKindPrivatePrompt, ContentKindCredential, ContentKindPrivateAssetLocator, ContentKindGameBody:
		return true
	default:
		return false
	}
}

func validateContractEvidenceReferences(inputs []LogicalAssetInput, closure RunEvidenceClosure, occurrences []DefectOccurrence, report RunReport) error {
	assets := make(map[string]string, len(inputs))
	for _, input := range inputs {
		digest := sha256.Sum256(input.Data)
		assets[input.Path] = hex.EncodeToString(digest[:])
	}
	evidenceIDs := make(map[string]EvidenceReference)
	check := func(reference EvidenceReference) error {
		if digest, exists := assets[reference.Path]; !exists || digest != reference.SHA256 {
			return fmt.Errorf("%w: evidence reference does not bind a logical asset", ErrAuditReadyInvalid)
		}
		if previous, exists := evidenceIDs[reference.ID]; exists && previous != reference {
			return fmt.Errorf("%w: evidence id has conflicting bindings", ErrAuditReadyInvalid)
		}
		evidenceIDs[reference.ID] = reference
		return nil
	}
	for _, receipt := range closure.ActionReceipts {
		if err := check(receipt.Evidence); err != nil {
			return err
		}
	}
	for _, reference := range closure.CoverageReferences {
		if err := check(reference); err != nil {
			return err
		}
	}
	for _, occurrence := range occurrences {
		for _, reference := range occurrence.EvidenceReferences {
			if err := check(reference); err != nil {
				return err
			}
		}
		if err := check(occurrence.ReproductionReference); err != nil {
			return err
		}
	}
	for _, finding := range append(append([]FindingReference(nil), report.SecurityFindings...), report.VisibilityFindings...) {
		if _, exists := evidenceIDs[finding.EvidenceID]; !exists {
			return fmt.Errorf("%w: finding references unknown evidence id", ErrReportInvalid)
		}
	}
	return nil
}

func validateOneDisclosure(classification ContentClassification, kind ContentKind, data []byte, disclosure Disclosure) error {
	if (disclosure.Profile == DisclosurePublic ||
		(disclosure.Profile == DisclosureExternalAuditor && !disclosure.ContainsUnpublishedContent)) && classification != ContentPublic {
		return ErrDisclosureViolation
	}
	if kind == ContentKindPrivatePrompt || kind == ContentKindCredential || kind == ContentKindPrivateAssetLocator || kind == ContentKindGameBody {
		return ErrDisclosureViolation
	}
	lower := bytes.ToLower(data)
	markers := [][]byte{
		[]byte("local_only_secret"), []byte("human_private_data"), []byte("credential_secret"),
		[]byte("private_prompt"), []byte("prompt_body"), []byte("game_body"), []byte("private_asset_locator"),
		[]byte("api_" + "key="), []byte("api-" + "key:"), []byte("authorization:" + " bearer"), []byte("pass" + "word="),
		[]byte("/" + "home/"), []byte("/" + "users/"), []byte("/" + "root/"), []byte(":\\users\\"),
	}
	for _, marker := range markers {
		if bytes.Contains(lower, marker) {
			return ErrDisclosureViolation
		}
	}
	for _, pattern := range credentialContentPatterns {
		if pattern.Find(data) != nil {
			return ErrDisclosureViolation
		}
	}
	return nil
}

func materializeLogicalAssets(inputs []LogicalAssetInput, profile ExportProfile, classifications CoreEvidenceClassifications) (BundleIndex, map[string]physicalAsset, error) {
	ordered := cloneLogicalAssetInputs(inputs)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	index := BundleIndex{
		Schema: BundleIndexSchema, Version: ContractVersion, CoreEvidenceClassifications: classifications,
		ExportProfile: profile, LogicalAssets: make([]LogicalAsset, 0, len(ordered)),
	}
	physical := map[string]physicalAsset{}
	chunkCount := 0
	for _, input := range ordered {
		digest := sha256.Sum256(input.Data)
		logical := LogicalAsset{
			Path: input.Path, MediaType: input.MediaType, Bytes: int64(len(input.Data)), SHA256: hex.EncodeToString(digest[:]),
			Classification: input.Classification, ContentKind: input.ContentKind,
		}
		if int64(len(input.Data)) <= profile.InlineThreshold {
			pathHash := sha256.Sum256([]byte(input.Path))
			physicalName := "inline-" + hex.EncodeToString(pathHash[:]) + ".asset"
			logical.Storage = AssetStorage{Kind: "INLINE", Path: physicalName}
			physical[physicalName] = physicalAsset{data: append([]byte(nil), input.Data...), mediaType: input.MediaType}
		} else {
			logical.Storage = AssetStorage{Kind: "CONTENT_ADDRESSED_CHUNKS", Chunks: []ChunkReference{}}
			for offset, ordinal := int64(0), int64(0); offset < int64(len(input.Data)); offset, ordinal = offset+profile.ChunkSize, ordinal+1 {
				end := offset + profile.ChunkSize
				if end > int64(len(input.Data)) {
					end = int64(len(input.Data))
				}
				chunk := append([]byte(nil), input.Data[offset:end]...)
				chunkHash := sha256.Sum256(chunk)
				chunkDigest := hex.EncodeToString(chunkHash[:])
				chunkPath := "chunk-" + chunkDigest + ".bin"
				if existing, exists := physical[chunkPath]; exists && !bytes.Equal(existing.data, chunk) {
					return BundleIndex{}, nil, fmt.Errorf("%w: content address collision", ErrChunkInvalid)
				}
				if _, exists := physical[chunkPath]; !exists {
					physical[chunkPath] = physicalAsset{data: chunk, mediaType: "application/octet-stream"}
					chunkCount++
					if chunkCount > profile.MaxChunks {
						return BundleIndex{}, nil, fmt.Errorf("%w: chunk count exceeds profile", ErrChunkInvalid)
					}
				}
				logical.Storage.Chunks = append(logical.Storage.Chunks, ChunkReference{Ordinal: ordinal, Path: chunkPath, Bytes: int64(len(chunk)), SHA256: chunkDigest})
			}
		}
		index.LogicalAssets = append(index.LogicalAssets, logical)
	}
	if len(physical)+1 > profile.MaxAssets+profile.MaxChunks+1 || len(physical)+1 > maxAuditReadyAssets {
		return BundleIndex{}, nil, fmt.Errorf("%w: physical asset count exceeds bound", ErrChunkInvalid)
	}
	return index, physical, nil
}

func reassembleLogicalAssets(index BundleIndex, physical map[string][]byte, physicalMedia map[string]string) (map[string][]byte, error) {
	if len(index.LogicalAssets) == 0 || len(index.LogicalAssets) > index.ExportProfile.MaxAssets {
		return nil, fmt.Errorf("%w: logical asset count", ErrChunkInvalid)
	}
	logical := make(map[string][]byte, len(index.LogicalAssets))
	used := map[string]struct{}{BundleIndexName: {}}
	chunkPaths := map[string]struct{}{}
	var total int64
	previousPath := ""
	for logicalIndex, asset := range index.LogicalAssets {
		if err := validLogicalPath("logical asset path", asset.Path); err != nil || !mediaTypePattern.MatchString(asset.MediaType) ||
			asset.Bytes < 0 || asset.Bytes > index.ExportProfile.MaxAssetBytes || validSHA("logical asset sha256", asset.SHA256) != nil ||
			(logicalIndex > 0 && asset.Path <= previousPath) {
			return nil, fmt.Errorf("%w: logical asset contract", ErrChunkInvalid)
		}
		previousPath = asset.Path
		var data []byte
		switch asset.Storage.Kind {
		case "INLINE":
			pathHash := sha256.Sum256([]byte(asset.Path))
			expectedPath := "inline-" + hex.EncodeToString(pathHash[:]) + ".asset"
			if asset.Storage.Path == "" || len(asset.Storage.Chunks) != 0 || !safeBundleMember.MatchString(asset.Storage.Path) ||
				asset.Storage.Path != expectedPath || physicalMedia[asset.Storage.Path] != asset.MediaType {
				return nil, fmt.Errorf("%w: inline storage descriptor", ErrChunkInvalid)
			}
			if _, duplicate := used[asset.Storage.Path]; duplicate {
				return nil, fmt.Errorf("%w: duplicate inline physical path", ErrChunkInvalid)
			}
			stored, exists := physical[asset.Storage.Path]
			if !exists {
				return nil, fmt.Errorf("%w: missing inline asset", ErrChunkInvalid)
			}
			data = append([]byte(nil), stored...)
			used[asset.Storage.Path] = struct{}{}
		case "CONTENT_ADDRESSED_CHUNKS":
			if asset.Storage.Path != "" || len(asset.Storage.Chunks) == 0 || len(asset.Storage.Chunks) > index.ExportProfile.MaxChunks {
				return nil, fmt.Errorf("%w: chunk storage descriptor", ErrChunkInvalid)
			}
			for chunkIndex, reference := range asset.Storage.Chunks {
				if reference.Ordinal != int64(chunkIndex) || reference.Bytes < 1 || reference.Bytes > index.ExportProfile.ChunkSize ||
					validSHA("chunk sha256", reference.SHA256) != nil || reference.Path != "chunk-"+reference.SHA256+".bin" {
					return nil, fmt.Errorf("%w: chunk reference", ErrChunkInvalid)
				}
				stored, exists := physical[reference.Path]
				if !exists || int64(len(stored)) != reference.Bytes {
					return nil, fmt.Errorf("%w: missing or wrong-size chunk", ErrChunkInvalid)
				}
				if physicalMedia[reference.Path] != "application/octet-stream" {
					return nil, fmt.Errorf("%w: chunk media type", ErrChunkInvalid)
				}
				digest := sha256.Sum256(stored)
				if hex.EncodeToString(digest[:]) != reference.SHA256 {
					return nil, fmt.Errorf("%w: chunk digest mismatch", ErrChunkInvalid)
				}
				if int64(len(data)) > index.ExportProfile.MaxAssetBytes-int64(len(stored)) {
					return nil, fmt.Errorf("%w: chunk reassembly exceeds bound", ErrChunkInvalid)
				}
				data = append(data, stored...)
				used[reference.Path] = struct{}{}
				chunkPaths[reference.Path] = struct{}{}
			}
		default:
			return nil, fmt.Errorf("%w: unknown storage kind", ErrChunkInvalid)
		}
		if int64(len(data)) != asset.Bytes {
			return nil, fmt.Errorf("%w: reassembled byte count mismatch", ErrChunkInvalid)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != asset.SHA256 {
			return nil, fmt.Errorf("%w: reassembled digest mismatch", ErrChunkInvalid)
		}
		if total > index.ExportProfile.MaxTotalBytes-int64(len(data)) {
			return nil, fmt.Errorf("%w: reassembled total exceeds bound", ErrChunkInvalid)
		}
		total += int64(len(data))
		logical[asset.Path] = data
	}
	if len(chunkPaths) > index.ExportProfile.MaxChunks {
		return nil, fmt.Errorf("%w: unique chunk count exceeds profile", ErrChunkInvalid)
	}
	for path := range physical {
		if _, exists := used[path]; !exists {
			return nil, fmt.Errorf("%w: unexpected physical asset", ErrChunkInvalid)
		}
	}
	return logical, nil
}

func verifyCoreLogicalAssets(manifest AuditReadyManifest, logical map[string][]byte) (RunEvidenceClosure, RunReport, error) {
	required := []string{
		RawManifestAssetName, RawEventsAssetName, RawRootAssetName, RunClosureName, ReplayEvidenceName,
		DefectFamiliesName, DefectOccurrencesName, RunReportName, RunReportMarkdownName, RunReportCSVName,
		RunReportJUnitName, RunReportHTMLName,
	}
	for _, name := range required {
		if _, exists := logical[name]; !exists {
			return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: required logical asset missing", ErrAuditReadyInvalid)
		}
	}
	raw, err := verifyRawCaptureBytes(logical[RawManifestAssetName], logical[RawEventsAssetName], logical[RawRootAssetName])
	if err != nil || raw.Root != manifest.RawCaptureRoot || raw.Manifest.Source != manifest.Source {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: embedded RAW_CAPTURE binding", ErrAuditReadyInvalid)
	}
	eventHashes, err := verifiedRawEventHashes(logical[RawEventsAssetName], raw.Manifest.StreamID)
	if err != nil {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: embedded RAW_CAPTURE event identities", ErrAuditReadyInvalid)
	}
	decodeCanonical := func(name string, destination any) error {
		body, decodeErr := canonicalBody(logical[name])
		if decodeErr != nil {
			return decodeErr
		}
		return strictDecode(body, destination)
	}
	var closure RunEvidenceClosure
	if err := decodeCanonical(RunClosureName, &closure); err != nil {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: closure decode", ErrAuditReadyInvalid)
	}
	var replay ReplayEvidence
	if err := decodeCanonical(ReplayEvidenceName, &replay); err != nil {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: replay decode", ErrAuditReadyInvalid)
	}
	var families defectFamilyEnvelope
	if err := decodeCanonical(DefectFamiliesName, &families); err != nil || families.Schema != "aipt.defect-families/v1" || families.Version != ContractVersion {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: defect families decode", ErrDefectInvalid)
	}
	var occurrences defectOccurrenceEnvelope
	if err := decodeCanonical(DefectOccurrencesName, &occurrences); err != nil || occurrences.Schema != "aipt.defect-occurrences/v1" || occurrences.Version != ContractVersion {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: defect occurrences decode", ErrDefectInvalid)
	}
	var report RunReport
	if err := decodeCanonical(RunReportName, &report); err != nil {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: report decode", ErrReportInvalid)
	}
	normalizedClosure, normalizedFamilies, normalizedOccurrences, normalizedReport, err := normalizeAuditContracts(raw, eventHashes, closure, families.Families, occurrences.Occurrences, report)
	if err != nil || !canonicalEqual(normalizedClosure, closure) || !canonicalEqual(normalizedFamilies, families.Families) ||
		!canonicalEqual(normalizedOccurrences, occurrences.Occurrences) || !canonicalEqual(normalizedReport, report) || !canonicalEqual(replay, closure.Replay) {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: normalized contract mismatch", ErrAuditReadyInvalid)
	}
	derivatives, err := RenderRunReport(normalizedReport)
	if err != nil || !bytes.Equal(logical[RunReportMarkdownName], derivatives.Markdown) ||
		!bytes.Equal(logical[RunReportCSVName], derivatives.CSV) || !bytes.Equal(logical[RunReportJUnitName], derivatives.JUnit) ||
		!bytes.Equal(logical[RunReportHTMLName], derivatives.HTML) {
		return RunEvidenceClosure{}, RunReport{}, fmt.Errorf("%w: derivative report mismatch", ErrReportInvalid)
	}
	return normalizedClosure, normalizedReport, nil
}

func validateAuditReadyManifest(manifest AuditReadyManifest) error {
	if manifest.Schema != SchemaID || manifest.Version != SchemaVersion || manifest.Stage != AuditReadyStage ||
		manifest.NormalizationVersion != AuditReadyNormalizationVersion || validSHA("raw_capture_root", manifest.RawCaptureRoot) != nil ||
		validateAuditReadySourceIdentity(manifest.Source) != nil || validateRemoteVerification(manifest.RemoteVerification, manifest.Source) != nil ||
		validateDisclosure(manifest.Disclosure) != nil || len(manifest.NormalizedAssets) == 0 || len(manifest.NormalizedAssets) > maxAuditReadyAssets {
		return ErrAuditReadyInvalid
	}
	previous := ""
	seen := map[string]struct{}{}
	for index, asset := range manifest.NormalizedAssets {
		if !safeBundleMember.MatchString(asset.Path) || !mediaTypePattern.MatchString(asset.MediaType) || asset.Bytes < 0 ||
			asset.Bytes > maxAuditReadyAssetBytes || validSHA("asset sha256", asset.SHA256) != nil ||
			(index > 0 && asset.Path <= previous) {
			return ErrAuditReadyInvalid
		}
		if _, exists := seen[asset.Path]; exists {
			return ErrAuditReadyInvalid
		}
		seen[asset.Path] = struct{}{}
		previous = asset.Path
	}
	return nil
}

func validateLogicalDisclosure(logical map[string][]byte, descriptors []LogicalAsset, disclosure Disclosure) error {
	if err := validateDisclosure(disclosure); err != nil {
		return err
	}
	for _, descriptor := range descriptors {
		data, exists := logical[descriptor.Path]
		if !exists || !validContentClassification(descriptor.Classification) || !validContentKind(descriptor.ContentKind) {
			return ErrDisclosureViolation
		}
		if err := validateOneDisclosure(descriptor.Classification, descriptor.ContentKind, data, disclosure); err != nil {
			return err
		}
		if err := validateOneDisclosure(descriptor.Classification, descriptor.ContentKind, []byte(descriptor.Path), disclosure); err != nil {
			return err
		}
	}
	return nil
}

func describePhysicalAssets(physical map[string]physicalAsset) []Asset {
	names := sortedPhysicalNames(physical)
	assets := make([]Asset, 0, len(names))
	for _, name := range names {
		value := physical[name]
		digest := sha256.Sum256(value.data)
		assets = append(assets, Asset{Path: name, MediaType: value.mediaType, Bytes: int64(len(value.data)), SHA256: hex.EncodeToString(digest[:])})
	}
	return assets
}

func sortedPhysicalNames(physical map[string]physicalAsset) []string {
	names := make([]string, 0, len(physical))
	for name := range physical {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloneLogicalAssetInputs(inputs []LogicalAssetInput) []LogicalAssetInput {
	out := make([]LogicalAssetInput, len(inputs))
	for index, input := range inputs {
		out[index] = input
		out[index].Data = append([]byte(nil), input.Data...)
	}
	return out
}

func cloneLogicalAssetMap(input map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(input))
	for name, data := range input {
		out[name] = append([]byte(nil), data...)
	}
	return out
}

func errOrFixed(err error) error {
	if err != nil {
		return err
	}
	return errors.New("verification mismatch")
}

type supplementalInputSnapshot struct {
	Path           string                `json:"path"`
	MediaType      string                `json:"media_type"`
	Classification ContentClassification `json:"classification"`
	ContentKind    ContentKind           `json:"content_kind"`
	Data           []byte                `json:"data"`
}

type semanticGenerateInput struct {
	Destination         string                      `json:"destination"`
	RawCapture          string                      `json:"raw_capture"`
	Disclosure          Disclosure                  `json:"disclosure"`
	CoreClassifications CoreEvidenceClassifications `json:"core_evidence_classifications"`
	Closure             RunEvidenceClosure          `json:"closure"`
	DefectFamilies      []DefectFamily              `json:"defect_families"`
	DefectOccurrences   []DefectOccurrence          `json:"defect_occurrences"`
	Report              RunReport                   `json:"report"`
	Supplemental        []supplementalInputSnapshot `json:"supplemental"`
	ExportProfile       ExportProfile               `json:"export_profile"`
}

func preflightGenerateInput(input GenerateAuditReadyInput, profile ExportProfile) error {
	if len(input.Supplemental) > profile.MaxAssets || len(input.DefectFamilies) > maxContractItems ||
		len(input.DefectOccurrences) > maxContractItems || len(input.Closure.ActionReceipts) > maxActionReceipts ||
		len(input.Closure.RuleCitations) > maxContractItems || len(input.Closure.CoverageReferences) > maxContractItems ||
		len(input.Closure.DefectOccurrenceIDs) > maxContractItems || len(input.Closure.AnomalyCodes) > maxContractItems ||
		len(input.Closure.GateEligibilityFacts) > maxGateFacts || len(input.Closure.ModelExecutionReferences) > maxContractItems {
		return fmt.Errorf("%w: generator contract collection exceeds bound", ErrAuditReadyInvalid)
	}
	var total int64
	for _, asset := range input.Supplemental {
		length := int64(len(asset.Data))
		if length > profile.MaxAssetBytes || total > profile.MaxTotalBytes-length {
			return fmt.Errorf("%w: supplemental byte budget", ErrAuditReadyInvalid)
		}
		total += length
	}
	return nil
}

func semanticInput(input GenerateAuditReadyInput) semanticGenerateInput {
	supplemental := make([]supplementalInputSnapshot, len(input.Supplemental))
	for index, asset := range input.Supplemental {
		supplemental[index] = supplementalInputSnapshot{
			Path: asset.Path, MediaType: asset.MediaType, Classification: asset.Classification,
			ContentKind: asset.ContentKind, Data: append([]byte(nil), asset.Data...),
		}
	}
	return semanticGenerateInput{
		Destination: input.Destination, RawCapture: input.RawCapture, Disclosure: input.Disclosure,
		CoreClassifications: input.CoreClassifications,
		Closure:             input.Closure, DefectFamilies: input.DefectFamilies, DefectOccurrences: input.DefectOccurrences,
		Report: input.Report, Supplemental: supplemental, ExportProfile: input.ExportProfile,
	}
}

func digestGenerateInput(input GenerateAuditReadyInput) (string, error) {
	line, err := canonicalLine(semanticInput(input))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(line)
	return hex.EncodeToString(digest[:]), nil
}

func snapshotGenerateInput(input GenerateAuditReadyInput) (GenerateAuditReadyInput, string, error) {
	snapshot := semanticInput(input)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return GenerateAuditReadyInput{}, "", err
	}
	var owned semanticGenerateInput
	if err := json.Unmarshal(raw, &owned); err != nil {
		return GenerateAuditReadyInput{}, "", err
	}
	supplemental := make([]LogicalAssetInput, len(owned.Supplemental))
	for index, asset := range owned.Supplemental {
		supplemental[index] = LogicalAssetInput{
			Path: asset.Path, MediaType: asset.MediaType, Classification: asset.Classification,
			ContentKind: asset.ContentKind, Data: asset.Data,
		}
	}
	copy := GenerateAuditReadyInput{
		Destination: owned.Destination, RawCapture: owned.RawCapture, SourceVerifier: input.SourceVerifier,
		Disclosure: owned.Disclosure, CoreClassifications: owned.CoreClassifications,
		Closure: owned.Closure, DefectFamilies: owned.DefectFamilies,
		DefectOccurrences: owned.DefectOccurrences, Report: owned.Report, Supplemental: supplemental,
		ExportProfile: owned.ExportProfile,
	}
	digest, err := digestGenerateInput(copy)
	return copy, digest, err
}
