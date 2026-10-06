package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

type testOutput struct{ bytes.Buffer }

func (testOutput) Close() error { return nil }
func TestPlanIsDeclarativeAndDoesNotClaimRuntimeOrQualification(t *testing.T) {
	output := &testOutput{}
	stderr := &bytes.Buffer{}
	if code := execute([]string{"plan"}, io.NopCloser(strings.NewReader("")), output, stderr); code != 0 {
		t.Fatal(code)
	}
	var plan struct {
		RuntimeReady  bool   `json:"runtime_ready"`
		Readiness     string `json:"readiness"`
		GameDriver    string `json:"game_driver"`
		Qualification bool   `json:"qualification_execution_authorized"`
		Gates         []struct {
			Gate     string `json:"gate"`
			Position int    `json:"position"`
		} `json:"gates"`
	}
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.RuntimeReady || plan.Qualification || plan.Readiness != "STARTUP_NOT_VERIFIED" || plan.GameDriver != "B007_CONFIGURATION_REQUIRED" {
		t.Fatal("plan promoted to readiness")
	}
	expected := []string{"CONFIG", "POSTGRESQL", "MIGRATIONS", "MODEL", "HARNESS", "CORE", "IPC", "WEB"}
	if len(plan.Gates) != len(expected) {
		t.Fatal("missing mandatory gate")
	}
	for i, gate := range plan.Gates {
		if gate.Gate != expected[i] || gate.Position != i+1 {
			t.Fatal("gate reordered")
		}
	}
}
func TestPrivateConfigFailureUsesStderrAndNoUnframedStdout(t *testing.T) {
	output := &testOutput{}
	stderr := &bytes.Buffer{}
	code := execute([]string{"run", "--config", "/PRIVATE_PATH_PASSWORD_SENTINEL", "--control-config", "/OTHER_PRIVATE_SENTINEL"}, io.NopCloser(strings.NewReader("")), output, stderr)
	if code != 1 || output.Len() != 0 || strings.Contains(stderr.String(), "SENTINEL") {
		t.Fatalf("unsafe CLI output code=%d stdout=%s stderr=%s", code, output.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), `"gate":"CONFIG"`) {
		t.Fatal("failed CONFIG not identified")
	}
}
