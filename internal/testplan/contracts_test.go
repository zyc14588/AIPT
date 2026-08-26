package testplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func validManifest() RunManifest {
	return RunManifest{
		Schema: manifestSchemaForTest(), ManifestID: "manifest-001", RunID: "run-001",
		Ancestry: Ancestry{CampaignID: "campaign-001", SuiteID: "suite-001", CaseID: "case-001"},
		RunType:  TaskRule,
		Source: SourceBinding{
			AIPT: RepositorySource{Repository: "zyc14588/AIPT", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40)},
			Game: RepositorySource{Repository: "example/game", Commit: strings.Repeat("c", 40), Tree: strings.Repeat("d", 40)},
		},
		ModelAssignments:    []ModelAssignment{{AssignmentID: "model-assignment-001", ModelProfileID: "model-profile-v1"}},
		PromptAssets:        []PromptAsset{{AssetID: "prompt-asset-001", SHA256: strings.Repeat("e", 64)}},
		SeatRoster:          []Seat{{SeatID: "gm", RoleID: "GM", ModelAssignmentID: "model-assignment-001"}},
		Budget:              BudgetBinding{PolicyID: "budget-policy-v1", LimitsID: "budget-limits-v1", MaxInputTokens: 1000, MaxOutputTokens: 500, MaxDurationSeconds: 60},
		Evidence:            EvidenceBinding{ProfileID: "evidence-profile-v1", ConfigID: "evidence-config-v1"},
		VisibilityProfileID: "AIPT_VISIBILITY_STANDARD_V1",
		SafetyApplicable:    true, SafetyProfileID: "AIPT_SAFETY_STANDARD_V1",
		Classification: "QUALIFICATION", QualificationEligible: true,
	}
}

// A tiny helper keeps the fixture's schema assignment visually distinct from
// the TestPlanSchema constant next to it in mutation tests.
func manifestSchemaForTest() string { return RunManifestSchema }

func validPlanJSON() []byte {
	return []byte(`{
      "schema":"aipt.test-plan/v1",
      "plan_id":"plan-001",
      "campaigns":[{"campaign_id":"campaign-001","name":"Campaign",
        "suites":[{"suite_id":"suite-001","name":"Suite",
          "cases":[{"case_id":"case-001","name":"Case","task_type":"RULE",
            "runs":[{"run_id":"run-001","run_type":"RULE","manifest_id":"manifest-001",
              "attempt_policy":{"scope":"RUN_INTERNAL_ONLY","max_attempts":3}}]}]}]}]
    }`)
}

func TestPlanFourLevelHierarchyAndAttemptInternal(t *testing.T) {
	plan, err := DecodeTestPlan(validPlanJSON())
	if err != nil {
		t.Fatalf("DecodeTestPlan: %v", err)
	}
	run := plan.Campaigns[0].Suites[0].Cases[0].Runs[0]
	if run.AttemptPolicy.Scope != "RUN_INTERNAL_ONLY" {
		t.Fatalf("scope = %q", run.AttemptPolicy.Scope)
	}

	for name, mutated := range map[string][]byte{
		"unknown task type":   bytes.Replace(validPlanJSON(), []byte(`"task_type":"RULE"`), []byte(`"task_type":"UNKNOWN"`), 1),
		"Attempt fifth level": bytes.Replace(validPlanJSON(), []byte(`"attempt_policy"`), []byte(`"attempts":[],"attempt_policy"`), 1),
		"mismatched Run type": bytes.Replace(validPlanJSON(), []byte(`"run_type":"RULE"`), []byte(`"run_type":"PROSE"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTestPlan(mutated); !errors.Is(err, ErrInvalidTestPlan) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if got := len(SortedTaskTypes()); got != 9 {
		t.Fatalf("task type count = %d, want 9", got)
	}
}

func TestManifestBindingDeterministicAndSelfVerifying(t *testing.T) {
	first, err := BindRunManifest(validManifest())
	if err != nil {
		t.Fatalf("BindRunManifest: %v", err)
	}
	second, err := BindRunManifest(validManifest())
	if err != nil {
		t.Fatalf("BindRunManifest second: %v", err)
	}
	if !bytes.Equal(first.Canonical, second.Canonical) || first.Digest != second.Digest {
		t.Fatal("binding is not deterministic")
	}
	if first.Manifest.CanonicalSHA256 == "" || !bytes.Contains(first.Canonical, []byte(first.Manifest.CanonicalSHA256)) {
		t.Fatal("canonical digest not embedded")
	}
	decoded, err := DecodeRunManifest(first.Canonical)
	if err != nil {
		t.Fatalf("DecodeRunManifest: %v", err)
	}
	if decoded.Digest != first.Digest || decoded.Manifest.RunID != "run-001" {
		t.Fatal("decoded binding drifted")
	}

	var raw map[string]any
	if err := json.Unmarshal(first.Canonical, &raw); err != nil {
		t.Fatal(err)
	}
	raw["run_id"] = "run-002"
	mutated, _ := json.Marshal(raw)
	if _, err := DecodeRunManifest(mutated); !errors.Is(err, ErrManifestDigest) {
		t.Fatalf("digest mutation error = %v", err)
	}

	nonCanonical := append([]byte(" "), first.Canonical...)
	if _, err := DecodeRunManifest(nonCanonical); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("noncanonical error = %v", err)
	}
}

func TestManifestSecurityAndReferenceMutationsReject(t *testing.T) {
	tests := map[string]func(*RunManifest){
		"private absolute path":   func(m *RunManifest) { m.PromptAssets[0].AssetID = "/private/prompt.txt" },
		"credential marker":       func(m *RunManifest) { m.ModelAssignments[0].ModelProfileID = "api_key-secret-value" },
		"unknown visibility":      func(m *RunManifest) { m.VisibilityProfileID = "UNKNOWN" },
		"unknown safety":          func(m *RunManifest) { m.SafetyProfileID = "UNKNOWN" },
		"diagnostic eligible":     func(m *RunManifest) { m.Classification = "DIAGNOSTIC" },
		"unknown task type":       func(m *RunManifest) { m.RunType = "UNKNOWN" },
		"unknown seat assignment": func(m *RunManifest) { m.SeatRoster[0].ModelAssignmentID = "missing" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest()
			mutate(&manifest)
			if _, err := BindRunManifest(manifest); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}

	frozen, err := BindRunManifest(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	withPromptBody := bytes.Replace(frozen.Canonical, []byte(`"prompt_assets":`), []byte(`"prompt_body":"private text","prompt_assets":`), 1)
	if _, err := DecodeRunManifest(withPromptBody); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("Prompt body error = %v", err)
	}
}
