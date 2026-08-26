// Package testplan implements the pure, model-free AIPT Test Plan and Run
// Manifest contracts. It does not generate plans, dispatch workers, call a
// model, or execute a playtest.
package testplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const (
	TestPlanSchema    = "aipt.test-plan/v1"
	RunManifestSchema = "aipt.run-manifest/v1"
)

type TaskType string

const (
	TaskSystemQualification TaskType = "SYSTEM_QUALIFICATION"
	TaskRule                TaskType = "RULE"
	TaskProse               TaskType = "PROSE"
	TaskOracle              TaskType = "ORACLE"
	TaskHumanSimulation     TaskType = "HUMAN_SIMULATION"
	TaskAdversarial         TaskType = "ADVERSARIAL"
	TaskPackageBuild        TaskType = "PACKAGE_BUILD"
	TaskCalibration         TaskType = "CALIBRATION"
	TaskRegression          TaskType = "REGRESSION"
)

var taskTypes = map[TaskType]struct{}{
	TaskSystemQualification: {}, TaskRule: {}, TaskProse: {}, TaskOracle: {},
	TaskHumanSimulation: {}, TaskAdversarial: {}, TaskPackageBuild: {},
	TaskCalibration: {}, TaskRegression: {},
}

var (
	ErrInvalidTestPlan    = errors.New("AIPT_TEST_PLAN_INVALID")
	ErrInvalidManifest    = errors.New("AIPT_RUN_MANIFEST_INVALID")
	ErrManifestDigest     = errors.New("AIPT_RUN_MANIFEST_DIGEST_MISMATCH")
	ErrManifestProhibited = errors.New("AIPT_RUN_MANIFEST_PROHIBITED_DATA")
)

type ContractError struct {
	Code  error
	Field string
	Why   string
}

func (e *ContractError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Field, e.Why)
}

func (e *ContractError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Code
}

type TestPlan struct {
	Schema    string     `json:"schema"`
	PlanID    string     `json:"plan_id"`
	Campaigns []Campaign `json:"campaigns"`
}

type Campaign struct {
	CampaignID string  `json:"campaign_id"`
	Name       string  `json:"name"`
	Suites     []Suite `json:"suites"`
}

type Suite struct {
	SuiteID string     `json:"suite_id"`
	Name    string     `json:"name"`
	Cases   []CaseSpec `json:"cases"`
}

type CaseSpec struct {
	CaseID   string    `json:"case_id"`
	Name     string    `json:"name"`
	TaskType TaskType  `json:"task_type"`
	Runs     []RunSpec `json:"runs"`
}

type RunSpec struct {
	RunID         string        `json:"run_id"`
	RunType       TaskType      `json:"run_type"`
	ManifestID    string        `json:"manifest_id"`
	AttemptPolicy AttemptPolicy `json:"attempt_policy"`
}

type AttemptPolicy struct {
	Scope       string `json:"scope"`
	MaxAttempts int    `json:"max_attempts"`
}

type RunManifest struct {
	Schema                string            `json:"schema"`
	ManifestID            string            `json:"manifest_id"`
	RunID                 string            `json:"run_id"`
	Ancestry              Ancestry          `json:"ancestry"`
	RunType               TaskType          `json:"run_type"`
	Source                SourceBinding     `json:"source"`
	ModelAssignments      []ModelAssignment `json:"model_assignments"`
	PromptAssets          []PromptAsset     `json:"prompt_assets"`
	SeatRoster            []Seat            `json:"seat_roster"`
	Budget                BudgetBinding     `json:"budget"`
	Evidence              EvidenceBinding   `json:"evidence"`
	VisibilityProfileID   string            `json:"visibility_profile_id"`
	SafetyApplicable      bool              `json:"safety_applicable"`
	SafetyProfileID       string            `json:"safety_profile_id"`
	Classification        string            `json:"classification"`
	QualificationEligible bool              `json:"qualification_eligible"`
	CanonicalSHA256       string            `json:"canonical_sha256"`
}

type Ancestry struct {
	CampaignID string `json:"campaign_id"`
	SuiteID    string `json:"suite_id"`
	CaseID     string `json:"case_id"`
}

type SourceBinding struct {
	AIPT RepositorySource `json:"aipt"`
	Game RepositorySource `json:"game"`
}

type RepositorySource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
}

type ModelAssignment struct {
	AssignmentID   string `json:"assignment_id"`
	ModelProfileID string `json:"model_profile_id"`
}

type PromptAsset struct {
	AssetID string `json:"asset_id"`
	SHA256  string `json:"sha256"`
}

type Seat struct {
	SeatID            string `json:"seat_id"`
	RoleID            string `json:"role_id"`
	ModelAssignmentID string `json:"model_assignment_id"`
}

type BudgetBinding struct {
	PolicyID           string `json:"policy_id"`
	LimitsID           string `json:"limits_id"`
	MaxInputTokens     int64  `json:"max_input_tokens"`
	MaxOutputTokens    int64  `json:"max_output_tokens"`
	MaxDurationSeconds int64  `json:"max_duration_seconds"`
}

type EvidenceBinding struct {
	ProfileID string `json:"profile_id"`
	ConfigID  string `json:"config_id"`
}

type FrozenManifest struct {
	Manifest  RunManifest
	Canonical []byte
	Digest    [32]byte
}

var (
	identityRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/\-]{0,127}$`)
	repositoryRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	gitOIDRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	windowsAbsRE = regexp.MustCompile(`^[A-Za-z]:[\\/]`)
	secretRE     = regexp.MustCompile(`(?i)(api[_-]?key|authorization|bearer|credential|password|\bdsn\b|prompt[_-]?(body|text)|human[_-]?private|(^|[^a-z])(sk|dsk)-[a-z0-9_-]{8,})`)
)

func DecodeTestPlan(raw []byte) (TestPlan, error) {
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return TestPlan{}, cerror(ErrInvalidTestPlan, "$", err.Error())
	}
	var plan TestPlan
	if err := decodeExact([]byte(canonical), &plan); err != nil {
		return TestPlan{}, cerror(ErrInvalidTestPlan, "$", err.Error())
	}
	if err := validatePlan(plan); err != nil {
		return TestPlan{}, err
	}
	return plan, nil
}

// BindRunManifest computes the versioned projection digest and returns the
// exact canonical bytes storage must freeze. The caller cannot supply its own
// digest through this API.
func BindRunManifest(manifest RunManifest) (FrozenManifest, error) {
	manifest.CanonicalSHA256 = ""
	if err := validateManifest(manifest, false); err != nil {
		return FrozenManifest{}, err
	}
	digest, err := manifestProjectionDigest(manifest)
	if err != nil {
		return FrozenManifest{}, err
	}
	manifest.CanonicalSHA256 = hex.EncodeToString(digest[:])
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return FrozenManifest{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	canonical, err := protocol.CanonicalJSON(encoded)
	if err != nil {
		return FrozenManifest{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	return FrozenManifest{Manifest: manifest, Canonical: []byte(canonical), Digest: digest}, nil
}

// DecodeRunManifest requires canonical bytes and verifies every binding,
// including canonical_sha256. Equivalent but non-canonical JSON is rejected.
func DecodeRunManifest(raw []byte) (FrozenManifest, error) {
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return FrozenManifest{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	if !bytes.Equal(raw, []byte(canonical)) {
		return FrozenManifest{}, cerror(ErrInvalidManifest, "$", "manifest bytes are not canonical")
	}
	var manifest RunManifest
	if err := decodeExact(raw, &manifest); err != nil {
		return FrozenManifest{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	if err := validateManifest(manifest, true); err != nil {
		return FrozenManifest{}, err
	}
	digest, err := manifestProjectionDigest(manifest)
	if err != nil {
		return FrozenManifest{}, err
	}
	if manifest.CanonicalSHA256 != hex.EncodeToString(digest[:]) {
		return FrozenManifest{}, cerror(ErrManifestDigest, "canonical_sha256", "digest does not bind canonical projection")
	}
	return FrozenManifest{Manifest: manifest, Canonical: append([]byte(nil), raw...), Digest: digest}, nil
}

func decodeExact(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}

func validatePlan(plan TestPlan) error {
	if plan.Schema != TestPlanSchema {
		return cerror(ErrInvalidTestPlan, "schema", "unknown schema")
	}
	if err := validIdentity(ErrInvalidTestPlan, "plan_id", plan.PlanID); err != nil {
		return err
	}
	if len(plan.Campaigns) == 0 {
		return cerror(ErrInvalidTestPlan, "campaigns", "at least one Campaign is required")
	}
	seen := map[string]string{}
	for ci, campaign := range plan.Campaigns {
		cp := fmt.Sprintf("campaigns[%d]", ci)
		if err := uniqueIdentity(seen, ErrInvalidTestPlan, cp+".campaign_id", campaign.CampaignID); err != nil {
			return err
		}
		if err := validName(ErrInvalidTestPlan, cp+".name", campaign.Name); err != nil {
			return err
		}
		if len(campaign.Suites) == 0 {
			return cerror(ErrInvalidTestPlan, cp+".suites", "at least one Suite is required")
		}
		for si, suite := range campaign.Suites {
			sp := fmt.Sprintf("%s.suites[%d]", cp, si)
			if err := uniqueIdentity(seen, ErrInvalidTestPlan, sp+".suite_id", suite.SuiteID); err != nil {
				return err
			}
			if err := validName(ErrInvalidTestPlan, sp+".name", suite.Name); err != nil {
				return err
			}
			if len(suite.Cases) == 0 {
				return cerror(ErrInvalidTestPlan, sp+".cases", "at least one Case is required")
			}
			for ki, testCase := range suite.Cases {
				kp := fmt.Sprintf("%s.cases[%d]", sp, ki)
				if err := uniqueIdentity(seen, ErrInvalidTestPlan, kp+".case_id", testCase.CaseID); err != nil {
					return err
				}
				if err := validName(ErrInvalidTestPlan, kp+".name", testCase.Name); err != nil {
					return err
				}
				if !isTaskType(testCase.TaskType) {
					return cerror(ErrInvalidTestPlan, kp+".task_type", "unknown task type")
				}
				if len(testCase.Runs) == 0 {
					return cerror(ErrInvalidTestPlan, kp+".runs", "at least one Run is required")
				}
				for ri, run := range testCase.Runs {
					rp := fmt.Sprintf("%s.runs[%d]", kp, ri)
					if err := uniqueIdentity(seen, ErrInvalidTestPlan, rp+".run_id", run.RunID); err != nil {
						return err
					}
					if err := validIdentity(ErrInvalidTestPlan, rp+".manifest_id", run.ManifestID); err != nil {
						return err
					}
					if !isTaskType(run.RunType) || run.RunType != testCase.TaskType {
						return cerror(ErrInvalidTestPlan, rp+".run_type", "unknown or Case-mismatched task type")
					}
					if run.AttemptPolicy.Scope != "RUN_INTERNAL_ONLY" || run.AttemptPolicy.MaxAttempts < 1 || run.AttemptPolicy.MaxAttempts > 1000 {
						return cerror(ErrInvalidTestPlan, rp+".attempt_policy", "Attempt must remain internal to Run and bounded")
					}
				}
			}
		}
	}
	return nil
}

func validateManifest(m RunManifest, requireDigest bool) error {
	if m.Schema != RunManifestSchema {
		return cerror(ErrInvalidManifest, "schema", "unknown schema")
	}
	identities := []struct{ field, value string }{
		{"manifest_id", m.ManifestID}, {"run_id", m.RunID},
		{"ancestry.campaign_id", m.Ancestry.CampaignID}, {"ancestry.suite_id", m.Ancestry.SuiteID},
		{"ancestry.case_id", m.Ancestry.CaseID}, {"budget.policy_id", m.Budget.PolicyID},
		{"budget.limits_id", m.Budget.LimitsID}, {"evidence.profile_id", m.Evidence.ProfileID},
		{"evidence.config_id", m.Evidence.ConfigID},
	}
	for _, item := range identities {
		if err := validIdentity(ErrInvalidManifest, item.field, item.value); err != nil {
			return err
		}
	}
	if !isTaskType(m.RunType) {
		return cerror(ErrInvalidManifest, "run_type", "unknown task type")
	}
	sources := []struct {
		field string
		value RepositorySource
	}{{"source.aipt", m.Source.AIPT}, {"source.game", m.Source.Game}}
	for _, item := range sources {
		if !repositoryRE.MatchString(item.value.Repository) {
			return cerror(ErrInvalidManifest, item.field+".repository", "must be owner/name")
		}
		if !gitOIDRE.MatchString(item.value.Commit) || !gitOIDRE.MatchString(item.value.Tree) {
			return cerror(ErrInvalidManifest, item.field, "commit/tree must be lowercase 40-hex")
		}
	}
	if len(m.ModelAssignments) < 1 || len(m.ModelAssignments) > 64 {
		return cerror(ErrInvalidManifest, "model_assignments", "must contain 1..64")
	}
	assignments := map[string]struct{}{}
	for i, assignment := range m.ModelAssignments {
		p := fmt.Sprintf("model_assignments[%d]", i)
		if err := validIdentity(ErrInvalidManifest, p+".assignment_id", assignment.AssignmentID); err != nil {
			return err
		}
		if err := validIdentity(ErrInvalidManifest, p+".model_profile_id", assignment.ModelProfileID); err != nil {
			return err
		}
		if _, exists := assignments[assignment.AssignmentID]; exists {
			return cerror(ErrInvalidManifest, p+".assignment_id", "duplicate")
		}
		assignments[assignment.AssignmentID] = struct{}{}
	}
	if len(m.PromptAssets) < 1 || len(m.PromptAssets) > 256 {
		return cerror(ErrInvalidManifest, "prompt_assets", "must contain 1..256")
	}
	prompts := map[string]struct{}{}
	for i, asset := range m.PromptAssets {
		p := fmt.Sprintf("prompt_assets[%d]", i)
		if err := validIdentity(ErrInvalidManifest, p+".asset_id", asset.AssetID); err != nil {
			return err
		}
		if !sha256RE.MatchString(asset.SHA256) {
			return cerror(ErrInvalidManifest, p+".sha256", "must be lowercase SHA-256")
		}
		if _, exists := prompts[asset.AssetID]; exists {
			return cerror(ErrInvalidManifest, p+".asset_id", "duplicate")
		}
		prompts[asset.AssetID] = struct{}{}
	}
	if len(m.SeatRoster) < 1 || len(m.SeatRoster) > 64 {
		return cerror(ErrInvalidManifest, "seat_roster", "must contain 1..64")
	}
	seats := map[string]struct{}{}
	for i, seat := range m.SeatRoster {
		p := fmt.Sprintf("seat_roster[%d]", i)
		for _, item := range []struct{ field, value string }{{"seat_id", seat.SeatID}, {"role_id", seat.RoleID}, {"model_assignment_id", seat.ModelAssignmentID}} {
			if err := validIdentity(ErrInvalidManifest, p+"."+item.field, item.value); err != nil {
				return err
			}
		}
		if _, exists := seats[seat.SeatID]; exists {
			return cerror(ErrInvalidManifest, p+".seat_id", "duplicate")
		}
		seats[seat.SeatID] = struct{}{}
		if _, exists := assignments[seat.ModelAssignmentID]; !exists {
			return cerror(ErrInvalidManifest, p+".model_assignment_id", "unknown assignment")
		}
	}
	if m.Budget.MaxInputTokens < 1 || m.Budget.MaxInputTokens > 1_000_000_000 || m.Budget.MaxOutputTokens < 1 || m.Budget.MaxOutputTokens > 1_000_000_000 || m.Budget.MaxDurationSeconds < 1 || m.Budget.MaxDurationSeconds > 604800 {
		return cerror(ErrInvalidManifest, "budget", "limits must be positive and bounded")
	}
	if m.VisibilityProfileID != "AIPT_VISIBILITY_STANDARD_V1" && m.VisibilityProfileID != "AIPT_VISIBILITY_DIAGNOSTIC_V1" {
		return cerror(ErrInvalidManifest, "visibility_profile_id", "unknown")
	}
	if m.SafetyApplicable {
		if m.SafetyProfileID != "AIPT_SAFETY_STANDARD_V1" && m.SafetyProfileID != "AIPT_SAFETY_DIAGNOSTIC_V1" {
			return cerror(ErrInvalidManifest, "safety_profile_id", "unknown applicable SafetyProfile")
		}
	} else if m.SafetyProfileID != "NOT_APPLICABLE" {
		return cerror(ErrInvalidManifest, "safety_profile_id", "must be NOT_APPLICABLE")
	}
	if (m.Classification == "QUALIFICATION" && !m.QualificationEligible) || (m.Classification == "DIAGNOSTIC" && m.QualificationEligible) {
		return cerror(ErrInvalidManifest, "qualification_eligible", "classification mismatch")
	}
	if m.Classification != "QUALIFICATION" && m.Classification != "DIAGNOSTIC" {
		return cerror(ErrInvalidManifest, "classification", "unknown")
	}
	if requireDigest && !sha256RE.MatchString(m.CanonicalSHA256) {
		return cerror(ErrInvalidManifest, "canonical_sha256", "must be lowercase SHA-256")
	}
	if !requireDigest && m.CanonicalSHA256 != "" {
		return cerror(ErrInvalidManifest, "canonical_sha256", "computed by BindRunManifest")
	}
	return nil
}

func manifestProjectionDigest(m RunManifest) ([32]byte, error) {
	m.CanonicalSHA256 = ""
	raw, err := json.Marshal(m)
	if err != nil {
		return [32]byte{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal(raw, &projection); err != nil {
		return [32]byte{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	delete(projection, "canonical_sha256")
	raw, err = json.Marshal(projection)
	if err != nil {
		return [32]byte{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return [32]byte{}, cerror(ErrInvalidManifest, "$", err.Error())
	}
	return sha256.Sum256([]byte(canonical)), nil
}

func isTaskType(value TaskType) bool { _, ok := taskTypes[value]; return ok }
func cerror(code error, field, why string) error {
	return &ContractError{Code: code, Field: field, Why: why}
}

func validIdentity(code error, field, value string) error {
	if !utf8.ValidString(value) || !identityRE.MatchString(value) {
		return cerror(code, field, "invalid bounded identity")
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || strings.HasPrefix(strings.ToLower(value), "file:") || windowsAbsRE.MatchString(value) {
		return cerror(ErrManifestProhibited, field, "absolute private path prohibited")
	}
	if secretRE.MatchString(value) {
		return cerror(ErrManifestProhibited, field, "secret/credential/DSN/Prompt/private marker prohibited")
	}
	return nil
}

func uniqueIdentity(seen map[string]string, code error, field, value string) error {
	if err := validIdentity(code, field, value); err != nil {
		return err
	}
	if previous, exists := seen[value]; exists {
		return cerror(code, field, "duplicates "+previous)
	}
	seen[value] = field
	return nil
}

func validName(code error, field, value string) error {
	if !utf8.ValidString(value) || strings.TrimSpace(value) == "" || len([]rune(value)) > 200 {
		return cerror(code, field, "must be nonempty and <=200 Unicode scalars")
	}
	return nil
}

func SortedTaskTypes() []TaskType {
	out := make([]TaskType, 0, len(taskTypes))
	for value := range taskTypes {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
