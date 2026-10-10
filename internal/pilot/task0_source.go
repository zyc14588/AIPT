package pilot

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcore"
)

// These control identities are populated only from the independently accepted
// Q009 source/CI catalogue. An unfinished build cannot open the new source.
// Loading game data grants no runtime, model, certification or budget access.
const (
	Task0PrototypeAnnexSHA          = "0dba7a660e147dec4536f7b272b73a2e768b2a04986be6a4e71880eb316229cc"
	Task0PrototypeAuthoritySHA      = "1d6c9600cbd3ff2917146c8c4a80647c70f9e17641f565944e4c948dc541e032"
	Task0PrototypeAdoptionReviewSHA = "4732a423d5235780eb8e560c7d523f3846f4c4b59a4f8548caca0b6c5fd93024"
	Task0PrototypeCIEvidenceSHA     = "508d65a46b8ff87dc9edb3153bc4f635147d391dfed20e48e80842f39158c1c2"
)

var task0PrototypeSourceBinding = runcore.SourcePackageBinding{
	PackageID:       "UNREGISTERED-TASK0-PROTOTYPE-V2",
	Schema:          "unregistered.task0-prototype-package/v2",
	Repository:      "zyc14588/UNREGISTERED",
	Commit:          "d37ae9b38bce84f8bfc164306fee2bebf73178b7",
	Tree:            "d802d28c7275e3e75ada5d6ef3edeb7fb57eb7b9",
	CanonicalSHA256: "f87f011f8c57c3eef371ad1e8f5569effd035957158fd17ba7fa63655c86e13d",
}

type prototypeSourceBaseline struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
}

type prototypeSourceManifest struct {
	Schema                    string                  `json:"schema"`
	PackageID                 string                  `json:"package_id"`
	Lifecycle                 string                  `json:"lifecycle"`
	Canonical                 bool                    `json:"canonical"`
	SourceBaseline            prototypeSourceBaseline `json:"source_baseline"`
	ContainingRevisionBinding string                  `json:"containing_revision_binding"`
	Entries                   []pinnedInput           `json:"entries"`
}

type prototypeInputAnnex struct {
	Schema                   string                       `json:"schema"`
	DecisionID               string                       `json:"decision_id"`
	AuthorityPath            string                       `json:"authority_path"`
	AuthoritySHA256          string                       `json:"authority_sha256"`
	RetainedQ003AuthoritySHA string                       `json:"retained_q003_authority_sha256"`
	RetainedQ003AnnexSHA     string                       `json:"retained_q003_annex_sha256"`
	SourceAdoptionReviewSHA  string                       `json:"source_adoption_review_sha256"`
	OnlineCIEvidenceSHA      string                       `json:"online_ci_evidence_sha256"`
	SourcePackage            runcore.SourcePackageBinding `json:"source_package"`
	SourceManifest           prototypeSourceManifest      `json:"source_manifest"`
	RuntimeReady             bool                         `json:"runtime_ready"`
	QualificationEligible    bool                         `json:"qualification_eligible"`
}

type prototypeInputExpectations struct {
	AnnexSHA, AuthoritySHA, RetainedAnnexSHA, AdoptionReviewSHA, CIEvidenceSHA string
	SourcePackage                                                              runcore.SourcePackageBinding
}

// Task0PrototypeSources owns the exact new 45-source closure. The Q003
// projection is compiled from the same held bytes and retains its permissions;
// source scripts and internal registries have no model-context accessor.
type Task0PrototypeSources struct {
	identity string
	binding  runcore.SourcePackageBinding
	files    map[string][]byte
	manifest []byte
	legacy   *InputSources
}

func LoadTask0PrototypeInputs(privateRoot string, annex, retainedQ003Annex []byte) (*Task0PrototypeSources, error) {
	expected := prototypeInputExpectations{
		AnnexSHA: Task0PrototypeAnnexSHA, AuthoritySHA: Task0PrototypeAuthoritySHA,
		RetainedAnnexSHA: Task0InputAnnexSHA, AdoptionReviewSHA: Task0PrototypeAdoptionReviewSHA,
		CIEvidenceSHA: Task0PrototypeCIEvidenceSHA, SourcePackage: task0PrototypeSourceBinding,
	}
	m, files, err := loadPrototypeInputClosure(privateRoot, annex, retainedQ003Annex, expected)
	if err != nil {
		return nil, ErrInput
	}
	// The accepted package also holds licensing/identity and source scripts.
	// Their presence must not extend the independently accepted Q003 model
	// projection: compile its exact original seventeen-file subset only.
	var retained struct {
		Base       []pinnedInput `json:"preserved_base_files"`
		Additional []pinnedInput `json:"supplemental_inputs"`
	}
	if json.Unmarshal(retainedQ003Annex, &retained) != nil {
		return nil, ErrInput
	}
	legacyFiles := make(map[string][]byte, 17)
	for _, item := range append(slices.Clone(retained.Base), retained.Additional...) {
		legacyFiles[item.Path] = files[item.Path]
	}
	legacy, err := compileInputSources(legacyFiles)
	if err != nil {
		return nil, ErrInput
	}
	manifestJSON, err := json.Marshal(m.SourceManifest)
	if err != nil {
		return nil, ErrInput
	}
	manifestCanonical, err := protocol.CanonicalJSON(manifestJSON)
	if err != nil || inputSHA([]byte(manifestCanonical)) != m.SourcePackage.CanonicalSHA256 {
		return nil, ErrInput
	}
	return &Task0PrototypeSources{identity: expected.AnnexSHA, binding: m.SourcePackage, files: files, manifest: []byte(manifestCanonical), legacy: legacy}, nil
}

// The expectations are an internal verification dependency, not a production
// argument, environment variable or test selector. The exported loader always
// supplies the compiled Owner-accepted identities above.
func loadPrototypeInputClosure(privateRoot string, raw, retained []byte, expected prototypeInputExpectations) (prototypeInputAnnex, map[string][]byte, error) {
	var a prototypeInputAnnex
	for _, d := range []string{expected.AnnexSHA, expected.AuthoritySHA, expected.RetainedAnnexSHA, expected.AdoptionReviewSHA, expected.CIEvidenceSHA} {
		if !digest(d) {
			return a, nil, ErrInput
		}
	}
	if inputSHA(raw) != expected.AnnexSHA || inputSHA(retained) != expected.RetainedAnnexSHA || decodeFrozenJSON(raw, 1<<20, &a) != nil {
		return a, nil, ErrInput
	}
	if a.Schema != "aipt.public.b007-task0-prototype-input-annex/v2" || a.DecisionID != "AIPT-MVP-B007-OWNER-Q009" ||
		a.AuthorityPath != "docs/pilot/authorities/task0-prototype-source-successor-q009.json" || a.AuthoritySHA256 != expected.AuthoritySHA ||
		a.RetainedQ003AuthoritySHA != Task0InputAuthoritySHA || a.RetainedQ003AnnexSHA != expected.RetainedAnnexSHA ||
		a.SourceAdoptionReviewSHA != expected.AdoptionReviewSHA || a.OnlineCIEvidenceSHA != expected.CIEvidenceSHA ||
		a.SourcePackage != expected.SourcePackage || a.RuntimeReady || a.QualificationEligible {
		return a, nil, ErrInput
	}
	m := a.SourceManifest
	if m.Schema != a.SourcePackage.Schema || m.PackageID != a.SourcePackage.PackageID || m.Lifecycle != "PROTOTYPE" || m.Canonical ||
		m.SourceBaseline != (prototypeSourceBaseline{Repository: "zyc14588/UNREGISTERED", Commit: "fe0965977447caf8cd7b6e58252bc1b991b7cc6f", Tree: "34597e79c586fb034256daa32d67640692ec589d"}) ||
		m.ContainingRevisionBinding != "EXTERNAL_ACCEPTED_COMMIT_TREE_AND_DIGEST_REQUIRED" || len(m.Entries) != 45 {
		return a, nil, ErrInput
	}
	manifestRaw, err := json.Marshal(m)
	if err != nil {
		return a, nil, ErrInput
	}
	canonical, err := protocol.CanonicalJSON(manifestRaw)
	if err != nil || inputSHA([]byte(canonical)) != a.SourcePackage.CanonicalSHA256 {
		return a, nil, ErrInput
	}
	byPath := make(map[string]pinnedInput, len(m.Entries))
	previous, total := "", 0
	for _, item := range m.Entries {
		if !validInputPath(item.Path) || item.Path <= previous || !digest(item.SHA256) || item.Bytes < 1 || item.Bytes > 4<<20 || total > (8<<20)-item.Bytes {
			return a, nil, ErrInput
		}
		byPath[item.Path] = item
		previous = item.Path
		total += item.Bytes
	}
	var old struct {
		Schema     string        `json:"schema"`
		Decision   string        `json:"decision_id"`
		Base       []pinnedInput `json:"preserved_base_files"`
		Additional []pinnedInput `json:"supplemental_inputs"`
		Count      int           `json:"supplemental_input_count"`
	}
	if _, err := protocol.CanonicalJSON(retained); err != nil || json.Unmarshal(retained, &old) != nil || old.Schema != "aipt.public.b007-task0-input-annex/v1" ||
		old.Decision != "B007-TASK0-SUPPLEMENTAL-INPUT-ANNEX-Q003=A" || len(old.Base) != 5 || len(old.Additional) != 12 || old.Count != 12 {
		return a, nil, ErrInput
	}
	seen := map[string]bool{}
	for _, item := range append(slices.Clone(old.Base), old.Additional...) {
		got, exists := byPath[item.Path]
		if !exists || seen[item.Path] || !digest(item.SHA256) || got.SHA256 != item.SHA256 || item.Bytes != 0 && got.Bytes != item.Bytes {
			return a, nil, ErrInput
		}
		seen[item.Path] = true
	}
	files, err := loadPinnedInputs(privateRoot, m.Entries)
	if err != nil {
		return a, nil, ErrInput
	}
	return a, files, nil
}

func (s *Task0PrototypeSources) SourcePackageBinding() (runcore.SourcePackageBinding, error) {
	if s == nil || !digest(s.identity) || s.binding != task0PrototypeSourceBinding {
		return runcore.SourcePackageBinding{}, ErrInput
	}
	return s.binding, nil
}

func (s *Task0PrototypeSources) ProjectLegacy(principal string, ids []string, releases map[string]bool) ([]ProjectedInput, error) {
	if s == nil || s.legacy == nil {
		return nil, ErrInput
	}
	return s.legacy.Project(principal, ids, releases)
}

// Capsule assembly can use held copies without reopening mutable source paths.
// This is private package plumbing and never a model-context operation.
func (s *Task0PrototypeSources) copyHeldSource(name string) ([]byte, error) {
	if s == nil || !digest(s.identity) || !validInputPath(name) || s.files[name] == nil {
		return nil, ErrInput
	}
	return bytes.Clone(s.files[name]), nil
}

// The containing manifest cannot list its own bytes. Derive its canonical
// file from the accepted annex, rather than read a new path beside the 45
// inputs. The resulting file has the accepted canonical package identity.
func (s *Task0PrototypeSources) copyHeldManifest() ([]byte, error) {
	if s == nil || s.binding != task0PrototypeSourceBinding || !digest(s.identity) || inputSHA(s.manifest) != s.binding.CanonicalSHA256 {
		return nil, ErrInput
	}
	return bytes.Clone(s.manifest), nil
}
