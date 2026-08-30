package modelgateway

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// Registry is immutable after construction. Every lookup uses the full
// versioned binding identity; display names and latest/auto aliases do not
// exist in this API.
type Registry struct {
	samplings      map[string]SamplingProfile
	profiles       map[string]ModelProfile
	certifications map[string]Certification
	formal         bool
}

func NewRegistry(samplings []SamplingProfile, profiles []ModelProfile, certifications []Certification) (*Registry, error) {
	return newRegistry(samplings, profiles, certifications, false)
}

// NewSyntheticRegistry exists only for deterministic, secret-free contract
// tests. Its synthetic certifications remain ineligible for formal startup.
func NewSyntheticRegistry(samplings []SamplingProfile, profiles []ModelProfile, certifications []Certification) (*Registry, error) {
	return newRegistry(samplings, profiles, certifications, true)
}

func newRegistry(samplings []SamplingProfile, profiles []ModelProfile, certifications []Certification, allowSynthetic bool) (*Registry, error) {
	registry := &Registry{
		samplings:      make(map[string]SamplingProfile, len(samplings)),
		profiles:       make(map[string]ModelProfile, len(profiles)),
		certifications: make(map[string]Certification, len(certifications)),
		formal:         !allowSynthetic,
	}
	for _, sampling := range samplings {
		if err := ValidateSamplingProfile(sampling); err != nil {
			return nil, err
		}
		key := sampling.BindingID()
		if _, exists := registry.samplings[key]; exists {
			return nil, newError(CodeSamplingDrift, "register_sampling", key, errors.New("duplicate binding"))
		}
		registry.samplings[key] = sampling
	}
	for _, profile := range profiles {
		if err := ValidateModelProfile(profile); err != nil {
			return nil, err
		}
		key := profile.BindingID()
		if _, exists := registry.profiles[key]; exists {
			return nil, newError(CodeInvalidProfile, "register_profile", key, errors.New("duplicate binding"))
		}
		if _, exists := registry.samplings[profile.SamplingProfileID]; !exists {
			return nil, newError(CodeSamplingDrift, "register_profile", key, errors.New("sampling binding not registered"))
		}
		registry.profiles[key] = profile
	}
	for _, certification := range certifications {
		if err := ValidateCertification(certification, registry); err != nil {
			return nil, err
		}
		if !allowSynthetic && certification.Kind != CertificationControlledReal {
			return nil, newError(CodeCertificationMissing, "register_certification", certification.BindingID(), errors.New("synthetic evidence has no formal eligibility"))
		}
		key := certification.BindingID()
		if _, exists := registry.certifications[key]; exists {
			return nil, newError(CodeCertificationMismatch, "register_certification", key, errors.New("duplicate binding"))
		}
		registry.certifications[key] = certification
	}
	for key, profile := range registry.profiles {
		certification, exists := registry.certifications[profile.CertificationIdentity]
		if !exists {
			return nil, newError(CodeCertificationMissing, "register_profile", key, errors.New("certification binding not registered"))
		}
		if certification.ProfileBinding != key {
			return nil, newError(CodeCertificationMismatch, "register_profile", key, errors.New("certification profile mismatch"))
		}
	}
	return registry, nil
}

func (r *Registry) Profile(binding string) (ModelProfile, error) {
	if r == nil {
		return ModelProfile{}, newError(CodeUnknownProfileVersion, "resolve_profile", binding, errors.New("nil registry"))
	}
	profile, exists := r.profiles[binding]
	if !exists {
		return ModelProfile{}, newError(CodeUnknownProfileVersion, "resolve_profile", binding, errors.New("exact binding absent"))
	}
	return profile, nil
}

func (r *Registry) Sampling(binding string) (SamplingProfile, error) {
	if r == nil {
		return SamplingProfile{}, newError(CodeSamplingDrift, "resolve_sampling", binding, errors.New("nil registry"))
	}
	profile, exists := r.samplings[binding]
	if !exists {
		return SamplingProfile{}, newError(CodeSamplingDrift, "resolve_sampling", binding, errors.New("exact binding absent"))
	}
	return profile, nil
}

func (r *Registry) Certification(binding string) (Certification, error) {
	if r == nil {
		return Certification{}, newError(CodeCertificationMissing, "resolve_certification", binding, errors.New("nil registry"))
	}
	certification, exists := r.certifications[binding]
	if !exists {
		return Certification{}, newError(CodeCertificationMissing, "resolve_certification", binding, errors.New("exact binding absent"))
	}
	return certification, nil
}

// ExactProfile never substitutes a model. The available argument is only an
// availability observation; it cannot select a different binding.
func (r *Registry) ExactProfile(binding string, available map[string]bool) (ModelProfile, error) {
	profile, err := r.Profile(binding)
	if err != nil {
		return ModelProfile{}, err
	}
	if available != nil && !available[binding] {
		return ModelProfile{}, newError(CodeSilentFallback, "resolve_exact_profile", binding, errors.New("requested binding unavailable"))
	}
	return profile, nil
}

func BindManifestModels(frozen testplan.FrozenManifest, registry *Registry) (ManifestBinding, error) {
	manifest := frozen.Manifest
	if registry == nil || manifest.ManifestID == "" || manifest.CanonicalSHA256 == "" {
		return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("manifest and registry are required"))
	}
	assignments := make(map[string]testplan.ModelAssignment, len(manifest.ModelAssignments))
	for _, assignment := range manifest.ModelAssignments {
		if _, exists := assignments[assignment.AssignmentID]; exists {
			return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("duplicate assignment"))
		}
		assignments[assignment.AssignmentID] = assignment
	}
	if len(manifest.SeatRoster) != len(orchestrator.BaselineSeats()) {
		return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("MVP role roster must contain exactly five seats"))
	}
	seenSeat := map[orchestrator.SeatID]bool{}
	seenAssignment := map[string]bool{}
	seenProfile := map[string]bool{}
	result := ManifestBinding{
		Schema: ManifestBindingSchema, ManifestID: manifest.ManifestID, RunID: manifest.RunID,
		ManifestSHA256: manifest.CanonicalSHA256, RunClassification: manifest.Classification,
		QualificationEligible: manifest.QualificationEligible, CleanBaselineEligible: manifest.QualificationEligible,
	}
	for _, seat := range manifest.SeatRoster {
		seatID := orchestrator.SeatID(strings.ToUpper(seat.SeatID))
		if !baselineSeat(seatID) || seenSeat[seatID] || seenAssignment[seat.ModelAssignmentID] {
			return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("seat or assignment is not independently bound"))
		}
		assignment, exists := assignments[seat.ModelAssignmentID]
		if !exists {
			return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("seat references unknown assignment"))
		}
		profile, err := registry.Profile(assignment.ModelProfileID)
		if err != nil {
			return ManifestBinding{}, err
		}
		if seenProfile[profile.BindingID()] {
			return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("each role requires an independent profile identity"))
		}
		certification, err := registry.Certification(profile.CertificationIdentity)
		if err != nil {
			return ManifestBinding{}, err
		}
		if certification.Result != "PASS" || !certification.MinimumCertification {
			return ManifestBinding{}, newError(CodeCertificationMissing, "bind_manifest", profile.BindingID(), errors.New("minimum certification is not PASS"))
		}
		if !registry.formal || certification.Kind != CertificationControlledReal {
			result.CleanBaselineEligible = false
		}
		seenSeat[seatID] = true
		seenAssignment[seat.ModelAssignmentID] = true
		seenProfile[profile.BindingID()] = true
		result.Assignments = append(result.Assignments, RoleAssignment{
			AssignmentID: seat.ModelAssignmentID, SeatID: seatID, RoleID: seat.RoleID,
			ProfileBinding: profile.BindingID(), SamplingBinding: profile.SamplingProfileID,
			BackendKind: profile.BackendKind, CertificationIdentity: profile.CertificationIdentity,
		})
	}
	for _, seatID := range orchestrator.BaselineSeats() {
		if !seenSeat[seatID] {
			return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, errors.New("baseline seat missing"))
		}
	}
	sort.Slice(result.Assignments, func(i, j int) bool { return result.Assignments[i].SeatID < result.Assignments[j].SeatID })
	digestTarget := result
	digestTarget.SHA256 = ""
	digest, err := canonicalDigest(digestTarget)
	if err != nil {
		return ManifestBinding{}, newError(CodeManifestBindingInvalid, "bind_manifest", manifest.ManifestID, err)
	}
	result.SHA256 = digest
	return result, nil
}

func baselineSeat(seatID orchestrator.SeatID) bool {
	for _, expected := range orchestrator.BaselineSeats() {
		if seatID == expected {
			return true
		}
	}
	return false
}

func ApplyExplicitReplacement(binding ManifestBinding, eventID string, seatID orchestrator.SeatID, replacement ModelProfile, reason string) (ManifestBinding, ReplacementEvent, error) {
	if binding.Schema != ManifestBindingSchema || binding.SHA256 == "" || !baselineSeat(seatID) {
		return ManifestBinding{}, ReplacementEvent{}, newError(CodeManifestBindingInvalid, "replace_profile", binding.ManifestID, errors.New("invalid binding"))
	}
	if err := validIdentity("event_id", eventID); err != nil {
		return ManifestBinding{}, ReplacementEvent{}, newError(CodeManifestBindingInvalid, "replace_profile", binding.ManifestID, err)
	}
	if err := validIdentity("reason_code", reason); err != nil {
		return ManifestBinding{}, ReplacementEvent{}, newError(CodeManifestBindingInvalid, "replace_profile", binding.ManifestID, err)
	}
	if err := ValidateModelProfile(replacement); err != nil {
		return ManifestBinding{}, ReplacementEvent{}, err
	}
	copy := binding
	copy.Assignments = append([]RoleAssignment(nil), binding.Assignments...)
	var previous string
	for index := range copy.Assignments {
		if copy.Assignments[index].SeatID != seatID {
			continue
		}
		previous = copy.Assignments[index].ProfileBinding
		copy.Assignments[index].ProfileBinding = replacement.BindingID()
		copy.Assignments[index].SamplingBinding = replacement.SamplingProfileID
		copy.Assignments[index].BackendKind = replacement.BackendKind
		copy.Assignments[index].CertificationIdentity = replacement.CertificationIdentity
	}
	if previous == "" || previous == replacement.BindingID() {
		return ManifestBinding{}, ReplacementEvent{}, newError(CodeManifestImmutable, "replace_profile", binding.ManifestID, errors.New("replacement is absent or unchanged"))
	}
	copy.CleanBaselineEligible = false
	copy.SHA256 = ""
	digest, err := canonicalDigest(copy)
	if err != nil {
		return ManifestBinding{}, ReplacementEvent{}, newError(CodeManifestImmutable, "replace_profile", binding.ManifestID, err)
	}
	copy.SHA256 = digest
	event := ReplacementEvent{
		Schema: ReplacementEventSchema, EventID: eventID, ManifestSHA256: binding.ManifestSHA256,
		SeatID: seatID, PreviousProfile: previous, ReplacementProfile: replacement.BindingID(),
		ReasonCode: reason, CleanBaselineEligible: false,
	}
	return copy, event, nil
}

func (r *Registry) Describe() string {
	if r == nil {
		return "model-registry:nil"
	}
	return fmt.Sprintf("model-registry: profiles=%d samplings=%d certifications=%d", len(r.profiles), len(r.samplings), len(r.certifications))
}
