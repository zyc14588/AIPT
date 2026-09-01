package modelgateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestEnvironmentCredentialBrokerIsWriteOnlyAndRedacted(t *testing.T) {
	secret := strings.Join([]string{"dsk", "controlled", "write-only-fixture"}, "-")
	reference := CredentialReference{
		ReferenceID: "deepseek-controlled-reference-v1", Kind: CredentialEnvironment,
		Locator: "AIPT_DEEPSEEK_CONTROLLED_KEY",
	}
	broker := EnvironmentCredentialBroker{Lookup: func(name string) (string, bool) {
		return secret, name == reference.Locator
	}}
	validation, err := broker.Validate(context.Background(), reference)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(validation)
	if err != nil {
		t.Fatal(err)
	}
	if validation.State != "VALID" || strings.Contains(string(raw), secret) || strings.Contains(string(raw), "write-only-fixture") {
		t.Fatalf("credential validation exposed a value: %s", raw)
	}
	base := map[string]string{
		"LANG": "C.UTF-8", "PATH": "/usr/bin", "DSH_AMBIENT": "must-not-pass",
		"AIPT_API_KEY_SHADOW":     "must-not-pass",
		harnessRouteFDEnvironment: "5",
	}
	bound, err := broker.BindChildEnvironment(context.Background(), reference, base)
	if err != nil {
		t.Fatal(err)
	}
	if bound[remoteCredentialEnvironment] != secret || bound[harnessRouteFDEnvironment] != "5" ||
		bound["DSH_AMBIENT"] != "" || bound["AIPT_API_KEY_SHADOW"] != "" {
		t.Fatal("child environment did not enforce exact write-only credential binding")
	}
	if _, mutated := base["DEEPSEEK_API_KEY"]; mutated {
		t.Fatal("credential broker mutated caller environment")
	}
}

func TestRuntimeEnvironmentInjectionCannotBypassVerifiedExecutables(t *testing.T) {
	for _, name := range []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "PYTHONPATH", "DYLD_INSERT_LIBRARIES"} {
		if err := validateManagedLlamaEnvironment(map[string]string{name: "synthetic-injection-value"}); err == nil {
			t.Fatalf("managed llama accepted process-loader environment %s", name)
		}
		if isConfiguredHarnessEnvironment(name) {
			t.Fatalf("adapter route allowlist accepted process-loader environment %s", name)
		}
		remote := map[string]string{
			"LANG": "C.UTF-8", harnessRouteFDEnvironment: "5", remoteCredentialEnvironment: "synthetic-secret-value", name: "synthetic-injection-value",
		}
		if err := validateAdapterProcessEnvironment(remote, BackendRemoteDeepSeek, ""); err == nil {
			t.Fatalf("final remote child environment accepted process-loader environment %s", name)
		}
	}
}

func TestCredentialFailuresAndAdapterSpecificationsNeverEchoSecrets(t *testing.T) {
	secret := strings.Join([]string{"dsk", "missing", "not-for-output"}, "-")
	reference := CredentialReference{
		ReferenceID: "missing-controlled-reference-v1", Kind: CredentialEnvironment,
		Locator: "AIPT_DEEPSEEK_CONTROLLED_KEY",
	}
	broker := EnvironmentCredentialBroker{Lookup: func(string) (string, bool) { return secret, false }}
	_, err := broker.Validate(context.Background(), reference)
	requireCode(t, err, CodeCredentialUnavailable)
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "not-for-output") {
		t.Fatalf("credential failure leaked secret material: %v", err)
	}

	if err := validateAdapterRouteSpec(AdapterRouteSpec{
		ProfileBinding: "model-gm@1.0.0", ExecutablePath: "missing",
		Arguments: []string{"--api-key=" + secret},
	}); err == nil {
		t.Fatal("credential-bearing adapter argument accepted")
	}
}

func TestCredentialReferenceRejectsPathsAndUnknownProviders(t *testing.T) {
	for _, reference := range []CredentialReference{
		{ReferenceID: "reference-v1", Kind: CredentialEnvironment, Locator: "lowercase_name"},
		{ReferenceID: "reference-v1", Kind: CredentialEncryptedFile, Locator: "/private/key.enc"},
		{ReferenceID: "reference-v1", Kind: CredentialReferenceKind("UNKNOWN"), Locator: "opaque-v1"},
	} {
		if err := validateCredentialReference(reference); err == nil {
			t.Fatalf("unsafe credential reference accepted: %+v", reference)
		}
	}
}
