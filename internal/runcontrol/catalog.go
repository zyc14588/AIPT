package runcontrol

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/zyc14588/AIPT/internal/storage/postgres"
)

type ControlConfig struct {
	Definitions   []Definition
	EvidenceRoot  string
	HolderID      string
	LeaseDuration time.Duration
	Capabilities  postgres.CapabilitySet
}

// LoadControlConfig is a separate, explicit private construction input. It
// cannot alter the frozen shared Config or expose secrets in public errors.
func LoadControlConfig(path string) (ControlConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return ControlConfig{}, ErrInvalid
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MaxRequestBytes+1))
	if err != nil {
		return ControlConfig{}, ErrInvalid
	}
	var input struct {
		Schema          string            `json:"schema"`
		EvidenceRoot    string            `json:"evidence_root"`
		HolderID        string            `json:"holder_id"`
		LeaseDurationMS int64             `json:"lease_duration_ms"`
		Capabilities    json.RawMessage   `json:"capabilities"`
		Registrations   []json.RawMessage `json:"registrations"`
	}
	if err := DecodeObject(raw, &input, "schema", "evidence_root", "holder_id", "lease_duration_ms", "capabilities", "registrations"); err != nil {
		return ControlConfig{}, err
	}
	if input.Schema != "aipt.control-config/v1" || !filepath.IsAbs(input.EvidenceRoot) || filepath.Clean(input.EvidenceRoot) != input.EvidenceRoot || input.EvidenceRoot == "/" || !identityPattern.MatchString(input.HolderID) || input.LeaseDurationMS < 3000 || input.LeaseDurationMS > 300000 || input.Registrations == nil || len(input.Registrations) > 64 {
		return ControlConfig{}, ErrInvalid
	}
	var caps struct {
		ResourceIDs      []string `json:"resource_ids"`
		ModelIDs         []string `json:"model_ids"`
		CertificationIDs []string `json:"certification_ids"`
		Labels           []string `json:"labels"`
	}
	if err := DecodeObject(input.Capabilities, &caps, "resource_ids", "model_ids", "certification_ids", "labels"); err != nil {
		return ControlConfig{}, err
	}
	for _, values := range [][]string{caps.ResourceIDs, caps.ModelIDs, caps.CertificationIDs, caps.Labels} {
		if values == nil || len(values) > 64 {
			return ControlConfig{}, ErrInvalid
		}
		seen := map[string]bool{}
		for _, value := range values {
			if !identityPattern.MatchString(value) || seen[value] {
				return ControlConfig{}, ErrInvalid
			}
			seen[value] = true
		}
	}
	result := ControlConfig{Definitions: []Definition{}, EvidenceRoot: input.EvidenceRoot, HolderID: input.HolderID, LeaseDuration: time.Duration(input.LeaseDurationMS) * time.Millisecond, Capabilities: postgres.CapabilitySet{ResourceIDs: caps.ResourceIDs, ModelIDs: caps.ModelIDs, CertificationIDs: caps.CertificationIDs, Labels: caps.Labels}}
	for _, rawDefinition := range input.Registrations {
		var d struct {
			ID              string                 `json:"registration_id"`
			Manifest        string                 `json:"manifest_canonical"`
			CampaignName    string                 `json:"campaign_name"`
			SuiteName       string                 `json:"suite_name"`
			CaseName        string                 `json:"case_name"`
			Priority        postgres.PriorityClass `json:"priority"`
			ResourceID      string                 `json:"required_resource_id"`
			ModelID         string                 `json:"required_model_id"`
			CertificationID string                 `json:"required_certification_id"`
			Labels          []string               `json:"required_labels"`
			Dependencies    []string               `json:"dependency_run_ids"`
			EligibleAfter   *time.Time             `json:"eligible_after"`
		}
		if err := DecodeObject(rawDefinition, &d, "registration_id", "manifest_canonical", "campaign_name", "suite_name", "case_name", "priority", "required_resource_id", "required_model_id", "required_certification_id", "required_labels", "dependency_run_ids", "eligible_after"); err != nil {
			return ControlConfig{}, err
		}
		if d.Labels == nil || d.Dependencies == nil {
			return ControlConfig{}, ErrInvalid
		}
		result.Definitions = append(result.Definitions, Definition{ID: d.ID, Input: postgres.EnqueueRunInput{ManifestBytes: []byte(d.Manifest), CampaignName: d.CampaignName, SuiteName: d.SuiteName, CaseName: d.CaseName, Priority: d.Priority, RequiredResourceID: d.ResourceID, RequiredModelID: d.ModelID, RequiredCertificationID: d.CertificationID, RequiredLabels: d.Labels, DependencyRunIDs: d.Dependencies, EligibleAfter: d.EligibleAfter}})
	}
	if _, _, err := checkedRegistrations(result.Definitions); err != nil {
		return ControlConfig{}, err
	}
	return result, nil
}
