package runcontrol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateConfigRejectsBadManifestAndQueueRegistrationBeforeStartup(t *testing.T) {
	d := definition(t, "run-config", false)
	registration := map[string]any{"registration_id": d.ID, "manifest_canonical": string(d.Input.ManifestBytes), "campaign_name": d.Input.CampaignName, "suite_name": d.Input.SuiteName, "case_name": d.Input.CaseName, "priority": d.Input.Priority, "required_resource_id": d.Input.RequiredResourceID, "required_model_id": d.Input.RequiredModelID, "required_certification_id": d.Input.RequiredCertificationID, "required_labels": []string{}, "dependency_run_ids": []string{}, "eligible_after": nil}
	input := map[string]any{"schema": "aipt.control-config/v1", "evidence_root": filepath.Join(t.TempDir(), "evidence"), "holder_id": "holder-config", "lease_duration_ms": 3000, "capabilities": map[string]any{"resource_ids": []string{}, "model_ids": []string{}, "certification_ids": []string{}, "labels": []string{}}, "registrations": []any{registration}}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "control.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControlConfig(path); err != nil {
		t.Fatal("valid private input rejected", err)
	}
	cases := []struct {
		name   string
		mutate func(map[string]any, map[string]any)
	}{
		{"manifest-casing", func(_ map[string]any, r map[string]any) {
			r["manifest_canonical"] = strings.Replace(r["manifest_canonical"].(string), `"run_id"`, `"Run_id"`, 1)
		}},
		{"invalid-manifest", func(_ map[string]any, r map[string]any) {
			r["manifest_canonical"] = `{"private":"CONFIG_SECRET_SENTINEL"}`
		}},
		{"duplicate-registration", func(i map[string]any, r map[string]any) { i["registrations"] = []any{r, r} }},
		{"duplicate-run", func(i map[string]any, r map[string]any) {
			other := map[string]any{}
			for k, v := range r {
				other[k] = v
			}
			other["registration_id"] = "other-registration"
			i["registrations"] = []any{r, other}
		}},
		{"missing-name", func(_ map[string]any, r map[string]any) { r["campaign_name"] = "  " }},
		{"unknown-priority", func(_ map[string]any, r map[string]any) { r["priority"] = "OVERRIDE" }},
		{"invalid-resource", func(_ map[string]any, r map[string]any) { r["required_resource_id"] = "" }},
		{"self-dependency", func(_ map[string]any, r map[string]any) { r["dependency_run_ids"] = []string{"run-config"} }},
		{"duplicate-dependency", func(_ map[string]any, r map[string]any) { r["dependency_run_ids"] = []string{"run-a", "run-a"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			r := value["registrations"].([]any)[0].(map[string]any)
			c.mutate(value, r)
			bad, _ := json.Marshal(value)
			if err := os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadControlConfig(path); err != ErrInvalid {
				t.Fatalf("CONFIG mutation accepted or leaked private cause: %v", err)
			}
		})
	}
}
