package evidence

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

const privateAuditRepositoryURL = "https://github.com/zyc14588/AIPT"

type privatePlainIdentity struct {
	Schema         string           `json:"schema"`
	Source         SourceIdentity   `json:"source"`
	RunID          string           `json:"run_id"`
	RunManifest    ArtifactIdentity `json:"run_manifest"`
	Ledger         LedgerIdentity   `json:"ledger"`
	RawCaptureRoot string           `json:"raw_capture_root"`
	Assets         []Asset          `json:"assets"`
}

type privateMemberAAD struct {
	Schema               string           `json:"schema"`
	NormalizationVersion string           `json:"normalization_version"`
	Source               SourceIdentity   `json:"source"`
	RunID                string           `json:"run_id"`
	RunManifest          ArtifactIdentity `json:"run_manifest"`
	Ledger               LedgerIdentity   `json:"ledger"`
	RawCaptureRoot       string           `json:"raw_capture_root"`
	PlaintextRoot        string           `json:"plaintext_root"`
	KeyReference         string           `json:"key_reference"`
	Ordinal              int64            `json:"ordinal"`
	CipherPath           string           `json:"cipher_path"`
	Plaintext            Asset            `json:"plaintext"`
}

func privateAAD(m PrivateAuditManifest, a PrivateCipherMember) ([]byte, error) {
	return canonicalLine(privateMemberAAD{PrivateAuditSchema, PrivateAuditNormalization, m.Source, m.RunID, m.RunManifest, m.Ledger, m.RawCaptureRoot, m.PlaintextRoot, m.Disclosure.Encryption.KeyReference, a.Ordinal, a.Path, a.Plaintext})
}

func privatePlainRoot(m PrivateAuditManifest) (string, error) {
	assets := make([]Asset, len(m.Members))
	for i, member := range m.Members {
		assets[i] = member.Plaintext
	}
	line, err := canonicalLine(privatePlainIdentity{PrivateAuditSchema, m.Source, m.RunID, m.RunManifest, m.Ledger, m.RawCaptureRoot, assets})
	if err != nil {
		return "", ErrPrivateAudit
	}
	digest := sha256.Sum256(line)
	return hex.EncodeToString(digest[:]), nil
}

// Production callers cannot provide source proof, transport, URL, CA, cache,
// cipher implementation, nonce or key bytes. Existing PUBLIC B005 is unchanged.
func GeneratePrivateAuditReady(ctx context.Context, input GenerateAuditReadyInput, key *PrivateAuditKey) (PrivateAuditReadyVerification, error) {
	return generatePrivateAuditReady(ctx, input, key, githubSourceVerifier{})
}

// GeneratePrivateAuditReadyAt is the trusted preparation descriptor form.
// No pathname, source verifier, credential, cipher or nonce can be supplied.
// The destination is one absent child of an owner-private held directory;
// RAW and key directories remain separate held objects. The path entry keeps
// its original rejection of all symlink ancestors, including proc FD paths.
func GeneratePrivateAuditReadyAt(ctx context.Context, parent *os.File, name string, rawDirectory *os.File, input GenerateAuditReadyInput, key *PrivateAuditKey) (PrivateAuditReadyVerification, error) {
	return generatePrivateAuditReadyAt(ctx, parent, name, rawDirectory, input, key, githubSourceVerifier{})
}

func generatePrivateAuditReadyAt(ctx context.Context, parent *os.File, name string, rawDirectory *os.File, input GenerateAuditReadyInput, key *PrivateAuditKey, verifier sourceVerifier) (PrivateAuditReadyVerification, error) {
	fail := func() (PrivateAuditReadyVerification, error) { return PrivateAuditReadyVerification{}, ErrPrivateAudit }
	if ctx == nil || ctx.Err() != nil || key == nil || verifier == nil || !safeBundleMember.MatchString(name) ||
		input.Destination != "" || input.RawCapture != "" || input.MirrorPath != "" || input.MirrorRemoteName != "" || input.Report.QualificationEligible || !privateDisclosure(input.Disclosure, key.Reference()) {
		return fail()
	}
	profile, err := validateExportProfile(input.ExportProfile)
	if err != nil || validateCoreEvidenceClassifications(input.CoreClassifications) != nil || !privateCoreClassifications(input.CoreClassifications) || preflightGenerateInput(input, profile) != nil {
		return fail()
	}
	retained, state, err := copyPrivateAuditDirectory(parent)
	if err != nil {
		return fail()
	}
	defer retained.Close()
	if !key.separateHeldDirectory(retained) || !key.separateHeldDirectory(rawDirectory) || !privateAuditChildAbsent(retained, name) {
		return fail()
	}
	raw, rawStable, err := holdPrivateRawCaptureAt(rawDirectory)
	if err != nil || sameDirectoryIdentity(state, raw.state) {
		if raw != nil {
			raw.Close()
		}
		return fail()
	}
	defer raw.Close()
	defer clear(raw.material.EventsBytes)
	original := input
	input, expectedInput, err := snapshotGenerateInput(input)
	if err != nil {
		return fail()
	}
	return generatePrivateAuditReadyHeld(ctx, input, key, verifier, profile, privateAuditGenerationTarget{
		parent: retained, finalName: name, raw: raw.material, rawStable: rawStable,
		inputStable: func() bool {
			digest, err := digestGenerateInput(original)
			return err == nil && digest == expectedInput
		},
		parentStable: func() bool {
			var current syscall.Stat_t
			return syscall.Fstat(int(retained.Fd()), &current) == nil && samePrivateBundleDirectory(state, current) && privateAuditDirectoryState(current) && key.separateHeldDirectory(retained)
		},
	})
}

func privateAuditChildAbsent(parent *os.File, name string) bool {
	if parent == nil || !safeBundleMember.MatchString(name) {
		return false
	}
	// O_PATH acquires metadata only: existing files, symlinks, directories and
	// special files all reject without opening a stream or blocking on a FIFO.
	const pathOnly = 0x200000
	fd, err := syscall.Openat(int(parent.Fd()), name, pathOnly|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if fd >= 0 {
		syscall.Close(fd)
	}
	return errors.Is(err, syscall.ENOENT)
}

// First use the unchanged independent RAW byte verifier, then independently
// hold and verify all three members. Directory streams and names stay relative
// to the retained object; no proc path or mutable ancestor is resolved.
func holdPrivateRawCaptureAt(directory *os.File) (*heldRawCapture, func() bool, error) {
	first, firstState, err := copyPrivateAuditDirectory(directory)
	if err != nil {
		return nil, nil, ErrPrivateAudit
	}
	initial, err := verifyHeldRawCapture(first, firstState)
	first.Close()
	if err != nil {
		return nil, nil, ErrPrivateAudit
	}
	dir, state, err := copyPrivateAuditDirectory(directory)
	if err != nil {
		return nil, nil, ErrPrivateAudit
	}
	held := &heldRawCapture{directory: dir, state: state}
	failure := func() (*heldRawCapture, func() bool, error) { held.Close(); return nil, nil, ErrPrivateAudit }
	entries, err := dir.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return failure()
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wanted := []string{EventsName, ManifestName, RootName}
	sort.Strings(wanted)
	if !equalStrings(names, wanted) {
		return failure()
	}
	read := func(name string, maximum int64) ([]byte, error) {
		f, fs, e := openHeldPrivateFile(dir, name, maximum)
		if e != nil {
			return nil, e
		}
		data, e := readHeldPrivateFile(f, fs, maximum)
		if e != nil {
			f.Close()
			return nil, e
		}
		held.members = append(held.members, heldRawMember{file: f, state: fs})
		return data, nil
	}
	manifest, err := read(ManifestName, maxRawCaptureManifestBytes)
	if err != nil {
		return failure()
	}
	root, err := read(RootName, maxRawCaptureRootBytes)
	if err != nil {
		return failure()
	}
	events, err := read(EventsName, maxRawCaptureEventsBytes)
	if err != nil {
		return failure()
	}
	verified, err := verifyRawCaptureBytes(manifest, events, root)
	if err != nil || verified.Root != initial.Root || !canonicalEqual(verified.Manifest, initial.Manifest) {
		clear(events)
		return failure()
	}
	held.material = rawCaptureMaterial{Verification: verified, ManifestBytes: manifest, RootBytes: root, EventsBytes: events}
	stable := func() bool {
		var current syscall.Stat_t
		if syscall.Fstat(int(dir.Fd()), &current) != nil || !sameFileState(state, current) || !privateAuditDirectoryState(current) {
			return false
		}
		for i, member := range held.members {
			if syscall.Fstat(int(member.file.Fd()), &current) != nil || !sameFileState(member.state, current) {
				return false
			}
			name := []string{ManifestName, RootName, EventsName}[i]
			f, fs, e := openHeldPrivateFile(dir, name, member.state.Size)
			if e != nil {
				return false
			}
			f.Close()
			if !sameFileState(member.state, fs) {
				return false
			}
		}
		return true
	}
	if !stable() {
		clear(events)
		return failure()
	}
	return held, stable, nil
}

// The verifier parameter is package-private and used only by offline tests.
func generatePrivateAuditReady(ctx context.Context, input GenerateAuditReadyInput, key *PrivateAuditKey, verifier sourceVerifier) (PrivateAuditReadyVerification, error) {
	fail := func() (PrivateAuditReadyVerification, error) { return PrivateAuditReadyVerification{}, ErrPrivateAudit }
	if ctx == nil || ctx.Err() != nil || key == nil || verifier == nil || input.Report.QualificationEligible || input.MirrorPath != "" || input.MirrorRemoteName != "" ||
		!key.separateFrom(input.Destination) || !key.separateFrom(input.RawCapture) || !privateDisclosure(input.Disclosure, key.Reference()) {
		return fail()
	}
	profile, err := validateExportProfile(input.ExportProfile)
	if err != nil || validateCoreEvidenceClassifications(input.CoreClassifications) != nil || !privateCoreClassifications(input.CoreClassifications) || preflightGenerateInput(input, profile) != nil {
		return fail()
	}
	original := input
	input, expectedInput, err := snapshotGenerateInput(input)
	if err != nil {
		return fail()
	}
	unchanged := func() bool {
		digest, err := digestGenerateInput(original)
		return err == nil && digest == expectedInput
	}
	finalPath, parent, err := validateAbsentDestination(input.Destination)
	if err != nil {
		return fail()
	}
	parentFile, parentState, err := openOwnerControlledDirectoryPath(parent)
	if err != nil {
		return fail()
	}
	defer parentFile.Close()
	raw, err := holdVerifiedRawCapture(input.RawCapture)
	if err != nil {
		return fail()
	}
	defer raw.Close()
	return generatePrivateAuditReadyHeld(ctx, input, key, verifier, profile, privateAuditGenerationTarget{
		parent: parentFile, finalName: filepath.Base(finalPath), raw: raw.material, rawStable: raw.Stable, inputStable: unchanged,
		parentStable: func() bool { return directoryPathMatchesNoSymlinks(parent, parentState, false) },
	})
}

type privateAuditGenerationTarget struct {
	parent                               *os.File
	finalName                            string
	raw                                  rawCaptureMaterial
	rawStable, parentStable, inputStable func() bool
}

// The path and descriptor entries share the exact same canonical contracts,
// fresh encryption and fixed anonymous source-verification pipeline.
func generatePrivateAuditReadyHeld(ctx context.Context, input GenerateAuditReadyInput, key *PrivateAuditKey, verifier sourceVerifier, profile ExportProfile, target privateAuditGenerationTarget) (PrivateAuditReadyVerification, error) {
	fail := func() (PrivateAuditReadyVerification, error) { return PrivateAuditReadyVerification{}, ErrPrivateAudit }
	source := target.raw.Verification.Manifest.Source
	if source.Repository != privateAuditRepositoryURL || MatchAuditReadyRepositoryIdentity(privateAuditRepositoryURL, source.Repository) != nil || validateAuditReadySourceIdentity(source) != nil ||
		(input.ExpectedRepository != "" && MatchAuditReadyRepositoryIdentity(input.ExpectedRepository, source.Repository) != nil) {
		return fail()
	}
	eventHashes, err := verifiedRawEventHashes(target.raw.EventsBytes, target.raw.Verification.Manifest.StreamID)
	if err != nil {
		return fail()
	}
	closure, families, occurrences, report, err := normalizeAuditContracts(target.raw.Verification, eventHashes, input.Closure, input.DefectFamilies, input.DefectOccurrences, input.Report)
	if err != nil {
		return fail()
	}
	material, err := key.read(true)
	if err != nil {
		return fail()
	}
	defer clear(material)
	remote, err := verifier.Verify(ctx, source)
	if err != nil || validateRemoteProvenanceReceipt(remote, source) != nil {
		return PrivateAuditReadyVerification{}, ErrSourceUnverified
	}
	operationVerifier := operationReceiptVerifier{source: source, receipt: remote}
	if observer, ok := verifier.(sourceBoundaryObserver); ok {
		operationVerifier.observer = observer
	}
	if !target.inputStable() || !target.rawStable() {
		return fail()
	}
	logical, err := buildCoreLogicalAssets(target.raw, closure, families, occurrences, report, input.CoreClassifications, remote)
	if err != nil {
		return fail()
	}
	logical = append(logical, cloneLogicalAssetInputs(input.Supplemental)...)
	if validatePrivateLogicalInputs(logical, profile) != nil || validateContractEvidenceReferences(logical, closure, occurrences, report) != nil {
		return fail()
	}
	index, physical, err := materializeLogicalAssets(logical, profile, input.CoreClassifications)
	if err != nil {
		return fail()
	}
	indexBytes, err := canonicalLine(index)
	if err != nil || int64(len(indexBytes)) > maxAuditReadyIndexBytes {
		return fail()
	}
	physical[BundleIndexName] = physicalAsset{data: indexBytes, mediaType: "application/json"}
	m := PrivateAuditManifest{Schema: PrivateAuditSchema, Version: ContractVersion, Stage: AuditReadyStage, NormalizationVersion: PrivateAuditNormalization,
		Source: source, RunID: closure.RunID, RunManifest: closure.RunManifest, Ledger: closure.Ledger, RawCaptureRoot: target.raw.Verification.Root,
		Disclosure: input.Disclosure, RemoteVerification: remoteVerificationFromReceipt(remote, source), Members: []PrivateCipherMember{}}
	plainAssets := describePhysicalAssets(physical)
	for i, asset := range plainAssets {
		m.Members = append(m.Members, PrivateCipherMember{Ordinal: int64(i), Path: fmt.Sprintf("encrypted-%05d.bin", i), Plaintext: asset})
	}
	m.PlaintextRoot, err = privatePlainRoot(m)
	if err != nil {
		return fail()
	}
	block, err := aes.NewCipher(material)
	if err != nil {
		return fail()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fail()
	}
	encrypted := map[string][]byte{}
	usedNonces := map[string]bool{}
	for i := range m.Members {
		member := &m.Members[i]
		nonce := make([]byte, aead.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return fail()
		}
		member.Nonce = hex.EncodeToString(nonce)
		if usedNonces[member.Nonce] {
			return fail()
		}
		usedNonces[member.Nonce] = true
		aad, err := privateAAD(m, *member)
		if err != nil {
			return fail()
		}
		body := aead.Seal(nil, nonce, physical[member.Plaintext.Path].data, aad)
		digest := sha256.Sum256(body)
		member.Bytes = int64(len(body))
		member.SHA256 = hex.EncodeToString(digest[:])
		encrypted[member.Path] = body
	}
	if validatePrivateManifest(m, key.Reference()) != nil {
		return fail()
	}
	manifestBytes, err := canonicalLine(m)
	if err != nil || int64(len(manifestBytes)) > maxAuditReadyManifestBytes {
		return fail()
	}
	digest := sha256.Sum256(manifestBytes)
	rootBytes := []byte(hex.EncodeToString(digest[:]) + "\n")
	tempName, tempDir, tempState, err := createPrivateStagingDirectory(target.parent)
	if err != nil {
		return fail()
	}
	defer tempDir.Close()
	keepTemp := true
	defer func() {
		if keepTemp {
			removePrivateAuditStaging(target.parent, tempName)
		}
	}()
	for _, member := range m.Members {
		if writePrivateAuditFile(tempDir, member.Path, encrypted[member.Path]) != nil {
			return fail()
		}
	}
	if writePrivateAuditFile(tempDir, ManifestName, manifestBytes) != nil || writePrivateAuditFile(tempDir, RootName, rootBytes) != nil || tempDir.Sync() != nil || syscall.Fstat(int(tempDir.Fd()), &tempState) != nil {
		return fail()
	}
	verified, err := verifyHeldPrivateAudit(ctx, tempDir, tempState, key, operationVerifier)
	if err != nil || !target.rawStable() || !target.inputStable() || !target.parentStable() {
		return fail()
	}
	if renameat2NoReplace(int(target.parent.Fd()), tempName, int(target.parent.Fd()), target.finalName) != nil {
		return fail()
	}
	keepTemp = false
	rollback := func() (PrivateAuditReadyVerification, error) {
		if renameat2NoReplace(int(target.parent.Fd()), target.finalName, int(target.parent.Fd()), tempName) == nil {
			keepTemp = true
			_ = target.parent.Sync()
		}
		return fail()
	}
	finalDir, finalState, err := openPrivateDirectoryAt(target.parent, target.finalName)
	if err != nil {
		return rollback()
	}
	defer finalDir.Close()
	if !samePrivateBundleDirectory(tempState, finalState) {
		return rollback()
	}
	published, err := verifyHeldPrivateAudit(ctx, finalDir, finalState, key, operationVerifier)
	if err != nil || published.Root != verified.Root || !target.rawStable() || !target.inputStable() || !target.parentStable() || target.parent.Sync() != nil {
		return rollback()
	}
	return published, nil
}

func VerifyPrivateAuditReady(ctx context.Context, directory string, key *PrivateAuditKey) (PrivateAuditReadyVerification, error) {
	return verifyPrivateAuditReady(ctx, directory, key, githubSourceVerifier{})
}

// VerifyPrivateAuditReadyAt operates only on the retained bundle directory,
// with an independent directory stream per request. Production source proof
// remains the original anonymous GitHub verifier, never a caller callback.
func VerifyPrivateAuditReadyAt(ctx context.Context, directory *os.File, key *PrivateAuditKey) (PrivateAuditReadyVerification, error) {
	return verifyPrivateAuditReadyAt(ctx, directory, key, githubSourceVerifier{})
}

func verifyPrivateAuditReadyAt(ctx context.Context, directory *os.File, key *PrivateAuditKey, verifier sourceVerifier) (PrivateAuditReadyVerification, error) {
	if ctx == nil || ctx.Err() != nil || key == nil || verifier == nil {
		return PrivateAuditReadyVerification{}, ErrPrivateAudit
	}
	dir, state, err := copyPrivateAuditDirectory(directory)
	if err != nil {
		return PrivateAuditReadyVerification{}, ErrPrivateAudit
	}
	defer dir.Close()
	if !key.separateDirectory(state) {
		return PrivateAuditReadyVerification{}, ErrPrivateAudit
	}
	return verifyHeldPrivateAudit(ctx, dir, state, key, verifier)
}

func verifyPrivateAuditReady(ctx context.Context, directory string, key *PrivateAuditKey, verifier sourceVerifier) (PrivateAuditReadyVerification, error) {
	if ctx == nil || ctx.Err() != nil || key == nil || verifier == nil || !key.separateFrom(directory) {
		return PrivateAuditReadyVerification{}, ErrPrivateAudit
	}
	dir, state, err := openPrivateDirectoryPath(directory)
	if err != nil {
		return PrivateAuditReadyVerification{}, ErrPrivateAudit
	}
	defer dir.Close()
	result, err := verifyHeldPrivateAudit(ctx, dir, state, key, verifier)
	if err != nil || !directoryPathMatchesNoSymlinks(directory, state, true) {
		return PrivateAuditReadyVerification{}, ErrPrivateAudit
	}
	return result, nil
}

func verifyHeldPrivateAudit(ctx context.Context, dir *os.File, state syscall.Stat_t, key *PrivateAuditKey, verifier sourceVerifier) (PrivateAuditReadyVerification, error) {
	fail := func() (PrivateAuditReadyVerification, error) { return PrivateAuditReadyVerification{}, ErrPrivateAudit }
	if ctx == nil || ctx.Err() != nil || dir == nil || key == nil || verifier == nil {
		return fail()
	}
	entries, err := dir.ReadDir(maxAuditReadyAssets + 3)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) < 3 || len(entries) > maxAuditReadyAssets+2 {
		return fail()
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		if !safeBundleMember.MatchString(e.Name()) {
			return fail()
		}
		names[i] = e.Name()
	}
	sort.Strings(names)
	retained := []heldRawMember{}
	defer func() {
		for _, member := range retained {
			member.file.Close()
		}
	}()
	read := func(name string, max int64) ([]byte, error) {
		f, fs, err := openPrivateAuditFile(dir, name, max)
		if err != nil {
			return nil, ErrPrivateAudit
		}
		body, err := readHeldPrivateFile(f, fs, max)
		if err != nil {
			f.Close()
			return nil, ErrPrivateAudit
		}
		retained = append(retained, heldRawMember{file: f, state: fs})
		return body, nil
	}
	manifestBytes, err := read(ManifestName, maxAuditReadyManifestBytes)
	if err != nil {
		return fail()
	}
	body, err := canonicalBody(manifestBytes)
	if err != nil {
		return fail()
	}
	var m PrivateAuditManifest
	if strictDecode(body, &m) != nil || validatePrivateManifest(m, key.Reference()) != nil {
		return fail()
	}
	expectedBytes, err := canonicalLine(m)
	if err != nil || !bytes.Equal(expectedBytes, manifestBytes) {
		return fail()
	}
	rootBytes, err := read(RootName, maxRawCaptureRootBytes)
	digest := sha256.Sum256(manifestBytes)
	root := hex.EncodeToString(digest[:])
	if err != nil || !bytes.Equal(rootBytes, []byte(root+"\n")) {
		return fail()
	}
	material, err := key.read(false)
	if err != nil {
		return fail()
	}
	defer clear(material)
	block, err := aes.NewCipher(material)
	if err != nil {
		return fail()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fail()
	}
	physical := map[string][]byte{}
	defer func() {
		for _, plaintext := range physical {
			clear(plaintext)
		}
	}()
	media := map[string]string{}
	wanted := []string{ManifestName, RootName}
	for _, member := range m.Members {
		ciphertext, err := read(member.Path, maxAuditReadyAssetBytes+int64(aead.Overhead()))
		if err != nil || int64(len(ciphertext)) != member.Bytes {
			return fail()
		}
		digest := sha256.Sum256(ciphertext)
		if hex.EncodeToString(digest[:]) != member.SHA256 {
			return fail()
		}
		nonce, err := hex.DecodeString(member.Nonce)
		if err != nil {
			return fail()
		}
		aad, err := privateAAD(m, member)
		if err != nil {
			return fail()
		}
		plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil || int64(len(plaintext)) != member.Plaintext.Bytes {
			return fail()
		}
		digest = sha256.Sum256(plaintext)
		if hex.EncodeToString(digest[:]) != member.Plaintext.SHA256 {
			clear(plaintext)
			return fail()
		}
		physical[member.Plaintext.Path] = plaintext
		media[member.Plaintext.Path] = member.Plaintext.MediaType
		wanted = append(wanted, member.Path)
	}
	sort.Strings(wanted)
	if !equalStrings(names, wanted) {
		return fail()
	}
	indexBytes, exists := physical[BundleIndexName]
	if !exists || int64(len(indexBytes)) > maxAuditReadyIndexBytes || media[BundleIndexName] != "application/json" {
		return fail()
	}
	indexBody, err := canonicalBody(indexBytes)
	if err != nil {
		return fail()
	}
	var index BundleIndex
	if strictDecode(indexBody, &index) != nil || index.Schema != BundleIndexSchema || index.Version != ContractVersion {
		return fail()
	}
	canonicalIndex, err := canonicalLine(index)
	if err != nil || !bytes.Equal(canonicalIndex, indexBytes) {
		return fail()
	}
	profile, err := validateExportProfile(index.ExportProfile)
	if err != nil || validateCoreEvidenceClassifications(index.CoreEvidenceClassifications) != nil || !privateCoreClassifications(index.CoreEvidenceClassifications) || validateCoreLogicalAssetDescriptors(index.LogicalAssets, index.CoreEvidenceClassifications) != nil {
		return fail()
	}
	index.ExportProfile = profile
	logical, err := reassembleLogicalAssets(index, physical, media)
	if err != nil {
		return fail()
	}
	inputs := make([]LogicalAssetInput, 0, len(index.LogicalAssets))
	for _, asset := range index.LogicalAssets {
		inputs = append(inputs, LogicalAssetInput{Path: asset.Path, MediaType: asset.MediaType, Classification: asset.Classification, ContentKind: asset.ContentKind, Data: logical[asset.Path]})
	}
	if validatePrivateLogicalInputs(inputs, profile) != nil {
		return fail()
	}
	closure, report, err := verifyCoreLogicalAssets(AuditReadyManifest{Source: m.Source, RawCaptureRoot: m.RawCaptureRoot}, logical)
	if err != nil || closure.RunID != m.RunID || closure.RunManifest != m.RunManifest || !canonicalEqual(closure.Ledger, m.Ledger) || report.QualificationEligible {
		return fail()
	}
	for path, value := range map[string]any{RunClosureName: closure, RunReportName: report, ReplayEvidenceName: closure.Replay} {
		canonical, err := canonicalLine(value)
		if err != nil || !bytes.Equal(canonical, logical[path]) {
			return fail()
		}
	}
	var occurrences defectOccurrenceEnvelope
	occurrenceBody, err := canonicalBody(logical[DefectOccurrencesName])
	if err != nil || strictDecode(occurrenceBody, &occurrences) != nil || validateContractEvidenceReferences(inputs, closure, occurrences.Occurrences, report) != nil {
		return fail()
	}
	var families defectFamilyEnvelope
	familyBody, err := canonicalBody(logical[DefectFamiliesName])
	if err != nil || strictDecode(familyBody, &families) != nil {
		return fail()
	}
	for path, value := range map[string]any{DefectOccurrencesName: occurrences, DefectFamiliesName: families} {
		canonical, err := canonicalLine(value)
		if err != nil || !bytes.Equal(canonical, logical[path]) {
			return fail()
		}
	}
	remote, err := verifier.Verify(ctx, m.Source)
	if err != nil || validateRemoteProvenanceReceipt(remote, m.Source) != nil || !canonicalEqual(remoteVerificationFromReceipt(remote, m.Source), m.RemoteVerification) {
		return PrivateAuditReadyVerification{}, ErrSourceUnverified
	}
	if observeSourceBoundary(ctx, verifier, m.Source) != nil {
		return fail()
	}
	var after syscall.Stat_t
	if syscall.Fstat(int(dir.Fd()), &after) != nil || !sameFileState(state, after) {
		return fail()
	}
	for _, member := range retained {
		if syscall.Fstat(int(member.file.Fd()), &after) != nil || !sameFileState(member.state, after) {
			return fail()
		}
	}
	check, err := key.read(false)
	clear(check)
	if err != nil {
		return fail()
	}
	return PrivateAuditReadyVerification{Root: root, Manifest: m, BundleIndex: index, Closure: closure, Report: report, LogicalAssets: cloneLogicalAssetMap(logical)}, nil
}

func privateDisclosure(d Disclosure, reference string) bool {
	return d.Profile == DisclosurePrivateFull && d.ContainsUnpublishedContent && d.Encryption.Status == EncryptionEncrypted && d.Encryption.Scheme == PrivateAuditEncryption && d.Encryption.KeyReference == reference && privateKeyReference(reference)
}

func writePrivateAuditFile(dir *os.File, name string, body []byte) error {
	if writePrivateFileAt(dir, name, body) != nil {
		return ErrPrivateAudit
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrPrivateAudit
	}
	f := os.NewFile(uintptr(fd), "private ciphertext publication")
	if f == nil {
		syscall.Close(fd)
		return ErrPrivateAudit
	}
	defer f.Close()
	var s syscall.Stat_t
	if syscall.Fstat(fd, &s) != nil || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&0777 != 0600 || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) || s.Size != int64(len(body)) || f.Chmod(0400) != nil || f.Sync() != nil {
		return ErrPrivateAudit
	}
	return nil
}

func privateCoreClassifications(c CoreEvidenceClassifications) bool {
	if c.RawCapture != ContentUnreleasedRemote && c.RawCapture != ContentTableHiddenRemote {
		return false
	}
	for _, class := range []ContentClassification{c.RawCapture, c.RunEvidenceClosure, c.ReplayEvidence, c.DefectFamily, c.DefectOccurrence, c.RunReport, c.ReportDerivatives} {
		if class != ContentPublic && class != ContentUnreleasedRemote && class != ContentTableHiddenRemote {
			return false
		}
	}
	return true
}

func validatePrivateLogicalInputs(inputs []LogicalAssetInput, p ExportProfile) error {
	if len(inputs) < 1 || len(inputs) > p.MaxAssets {
		return ErrPrivateAudit
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Path < inputs[j].Path })
	var total int64
	for i, a := range inputs {
		if validLogicalPath("private member", a.Path) != nil || !mediaTypePattern.MatchString(a.MediaType) || (i > 0 && a.Path == inputs[i-1].Path) || int64(len(a.Data)) > p.MaxAssetBytes || total > p.MaxTotalBytes-int64(len(a.Data)) {
			return ErrPrivateAudit
		}
		total += int64(len(a.Data))
		if (a.Classification != ContentPublic && a.Classification != ContentUnreleasedRemote && a.Classification != ContentTableHiddenRemote) || !validContentKind(a.ContentKind) || a.ContentKind == ContentKindCredential || a.ContentKind == ContentKindPrivateAssetLocator {
			return ErrPrivateAudit
		}
		if a.Classification == ContentPublic {
			if validateOneDisclosure(a.Classification, a.ContentKind, a.Data, Disclosure{Profile: DisclosurePublic, Encryption: Encryption{Status: EncryptionUnencrypted}}) != nil {
				return ErrPrivateAudit
			}
		}
		for _, pattern := range credentialContentPatterns {
			if pattern.Find(a.Data) != nil {
				return ErrPrivateAudit
			}
		}
	}
	return nil
}

func validatePrivateManifest(m PrivateAuditManifest, reference string) error {
	if m.Schema != PrivateAuditSchema || m.Version != ContractVersion || m.Stage != AuditReadyStage || m.NormalizationVersion != PrivateAuditNormalization ||
		m.Source.Repository != privateAuditRepositoryURL || m.RunManifest.Schema != "aipt.run-manifest/v1" || validateAuditReadySourceIdentity(m.Source) != nil || MatchAuditReadyRepositoryIdentity(privateAuditRepositoryURL, m.Source.Repository) != nil || validContractIdentifier("private run", m.RunID) != nil || validateArtifactIdentity("private manifest", m.RunManifest) != nil ||
		validSHA("private raw root", m.RawCaptureRoot) != nil || validSHA("private plaintext root", m.PlaintextRoot) != nil || !privateDisclosure(m.Disclosure, reference) || validateRemoteVerification(m.RemoteVerification, m.Source) != nil ||
		validateLedgerText("private ledger", m.Ledger.StreamID) != nil || m.Ledger.EventCount < 1 || m.Ledger.EventCount > maxRawCaptureEventCount || m.Ledger.TailSequence != m.Ledger.EventCount || m.Ledger.TailEventHash == nil || validSHA("private tail", *m.Ledger.TailEventHash) != nil || len(m.Members) < 1 || len(m.Members) > maxAuditReadyAssets {
		return ErrPrivateAudit
	}
	var total int64
	previous := ""
	nonces := map[string]bool{}
	for i, a := range m.Members {
		nonce, err := hex.DecodeString(a.Nonce)
		if a.Ordinal != int64(i) || a.Path != fmt.Sprintf("encrypted-%05d.bin", i) || a.Plaintext.Bytes < 0 || a.Plaintext.Bytes > maxAuditReadyAssetBytes || a.Bytes != a.Plaintext.Bytes+16 || validSHA("private cipher", a.SHA256) != nil || validSHA("private plain", a.Plaintext.SHA256) != nil ||
			!safeBundleMember.MatchString(a.Plaintext.Path) || a.Plaintext.Path <= previous || !mediaTypePattern.MatchString(a.Plaintext.MediaType) || err != nil || len(nonce) != 12 || hex.EncodeToString(nonce) != a.Nonce || nonces[a.Nonce] || total > maxAuditReadyTotalBytes-a.Plaintext.Bytes {
			return ErrPrivateAudit
		}
		previous = a.Plaintext.Path
		total += a.Plaintext.Bytes
		nonces[a.Nonce] = true
	}
	root, err := privatePlainRoot(m)
	if err != nil || root != m.PlaintextRoot {
		return ErrPrivateAudit
	}
	return nil
}
