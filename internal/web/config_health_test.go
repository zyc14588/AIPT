package web

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/config"
)

func webTestConfig(t *testing.T) *config.Config {
	t.Helper()
	value, err := config.Load([]byte(`{
  "schema":"aipt.config/v1",
  "profile":"development",
  "database":{
    "dsn":"postgres://web_unique_user:web_unique_password@localhost/aipt_development",
    "identity":"aipt_development",
    "namespace":"aipt_dev",
    "ping_timeout_ms":1000
  },
  "evidence":{"namespace":"aipt.evidence.development"}
}`))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestConfigHealthUsesCredentialFreeSharedConfigProjection(t *testing.T) {
	configPanel, healthPanel, err := ConfigHealth(webTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if configPanel != (ConfigPanel{
		Schema:            "aipt.config/v1",
		Profile:           "development",
		DatabaseIdentity:  "aipt_development",
		DatabaseNamespace: "aipt_dev",
		EvidenceNamespace: "aipt.evidence.development",
	}) {
		t.Fatalf("unexpected config projection: %#v", configPanel)
	}
	if healthPanel != (HealthPanel{ServingStatus: "SERVING", RuntimeReadiness: "NOT_ASSERTED"}) {
		t.Fatalf("unexpected health projection: %#v", healthPanel)
	}
	encoded, err := json.Marshal(struct {
		Config ConfigPanel `json:"config"`
		Health HealthPanel `json:"health"`
	}{configPanel, healthPanel})
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"dsn", "web_unique_user", "web_unique_password", "credential", "secret", "token"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("Web projection contains forbidden value/member %q: %s", forbidden, encoded)
		}
	}
}

func TestConfigHealthRejectsNilWithoutDetails(t *testing.T) {
	configPanel, healthPanel, err := ConfigHealth(nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
	if configPanel != (ConfigPanel{}) || healthPanel != (HealthPanel{}) {
		t.Fatal("nil config returned a partial projection")
	}
}
