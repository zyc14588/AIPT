package config

// Credential redaction tests: the raw DSN must never appear through Error,
// fmt, String, JSON marshal, or redacted diagnostics; every diagnostic
// surface emits [REDACTED] in its place (positive redaction), and errors
// produced from documents that carry secrets must never echo them (negative
// redaction).

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func assertRedacted(t *testing.T, surface string, secrets ...string) {
	t.Helper()
	if !strings.Contains(surface, redactedValue) {
		t.Errorf("redacted surface %q does not contain %q", surface, redactedValue)
	}
	for _, secret := range secrets {
		if strings.Contains(surface, secret) {
			t.Errorf("redacted surface leaks secret %q: %s", secret, surface)
		}
	}
}

func TestRedactionStringFmtRedacted(t *testing.T) {
	c := mustLoad(t, devDoc())
	secrets := []string{devDSN, "dev-secret", "aipt@127.0.0.1"}

	surfaces := map[string]string{
		"String":          c.String(),
		"Redacted":        c.Redacted(),
		"fmt %v":          fmt.Sprintf("%v", c),
		"fmt %+v":         fmt.Sprintf("%+v", c),
		"fmt %#v":         fmt.Sprintf("%#v", c),
		"fmt value %#v":   fmt.Sprintf("%#v", *c),
		"fmt %s":          fmt.Sprintf("%s", c),
		"fmt %q":          fmt.Sprintf("%q", c),
		"database %v":     fmt.Sprintf("%v", c.Database()),
		"database %#v":    fmt.Sprintf("%#v", c.Database()),
		"database %+q":    fmt.Sprintf("%+q", c.Database()),
		"database String": c.Database().String(),
	}
	for name, surface := range surfaces {
		t.Run(name, func(t *testing.T) {
			assertRedacted(t, surface, secrets...)
		})
	}

	// The diagnostic rendering is deterministic.
	if c.String() != c.Redacted() {
		t.Errorf("String() and Redacted() differ:\n%q\n%q", c.String(), c.Redacted())
	}
	if c.String() != c.String() {
		t.Error("String() is not deterministic")
	}

	evidenceSurface := fmt.Sprintf("%#v", c.Evidence())
	for _, secret := range secrets {
		if strings.Contains(evidenceSurface, secret) {
			t.Errorf("evidence rendering leaks secret %q: %s", secret, evidenceSurface)
		}
	}
}

func TestRedactionJSONMarshal(t *testing.T) {
	c := mustLoad(t, devDoc())

	b1, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal(c) = %v", err)
	}
	b2, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("json.Marshal(c) second = %v", err)
	}
	if string(b1) != string(b2) {
		t.Error("json.Marshal is not deterministic")
	}
	assertRedacted(t, string(b1), devDSN, "dev-secret")

	valueBytes, err := json.Marshal(*c)
	if err != nil {
		t.Fatalf("json.Marshal(*c) = %v", err)
	}
	assertRedacted(t, string(valueBytes), devDSN, "dev-secret")

	var decoded map[string]any
	if err := json.Unmarshal(b1, &decoded); err != nil {
		t.Fatalf("redacted JSON does not parse: %v", err)
	}
	if decoded["schema"] != SchemaMarker {
		t.Errorf("redacted schema = %v", decoded["schema"])
	}
	if decoded["profile"] != string(ProfileDevelopment) {
		t.Errorf("redacted profile = %v", decoded["profile"])
	}
	db, _ := decoded["database"].(map[string]any)
	if db == nil {
		t.Fatal("redacted database missing")
	}
	if db["dsn"] != redactedValue {
		t.Errorf("redacted dsn = %v, want %q", db["dsn"], redactedValue)
	}
	if db["identity"] != "aipt_development" || db["namespace"] != "aipt_dev" || db["ping_timeout_ms"] != float64(5000) {
		t.Errorf("redacted database fields drifted: %v", db)
	}
	ev, _ := decoded["evidence"].(map[string]any)
	if ev == nil || ev["namespace"] != "aipt.evidence.development" {
		t.Errorf("redacted evidence drifted: %v", ev)
	}

	// The database value alone marshals redacted too.
	dbBytes, err := json.Marshal(c.Database())
	if err != nil {
		t.Fatal(err)
	}
	assertRedacted(t, string(dbBytes), devDSN, "dev-secret")
	var dbDecoded map[string]any
	if err := json.Unmarshal(dbBytes, &dbDecoded); err != nil {
		t.Fatal(err)
	}
	if dbDecoded["dsn"] != redactedValue {
		t.Errorf("database dsn = %v, want %q", dbDecoded["dsn"], redactedValue)
	}

	// Evidence carries no credentials and marshals intact.
	evBytes, err := json.Marshal(c.Evidence())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(evBytes), redactedValue) {
		t.Errorf("evidence must not be redacted: %s", evBytes)
	}
	if !strings.Contains(string(evBytes), "aipt.evidence.development") {
		t.Errorf("evidence namespace missing: %s", evBytes)
	}
}

func TestRedactionNilConfig(t *testing.T) {
	var c *Config
	if got := c.String(); got != "<nil>" {
		t.Errorf("nil Config String() = %q, want <nil>", got)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "null" {
		t.Errorf("nil Config marshals to %s, want null", b)
	}
	if got := fmt.Sprintf("%#v", c); got != "<nil>" {
		t.Errorf("nil Config fmt = %q, want <nil>", got)
	}
}

func TestRedactionNegative(t *testing.T) {
	// Every failure class must produce errors that never echo the secret
	// values carried by the rejected document.
	tests := []struct {
		name   string
		doc    string
		secret string
	}{
		{
			"invalid-identity",
			replace(t, replace(t, devDoc(), fmt.Sprintf(`"dsn":%q`, devDSN),
				`"dsn":"postgres://u:hunter2pw@h:5432/aipt_development?sslmode=disable"`),
				`"identity":"aipt_development"`, `"identity":"SECRETIDENT"`),
			"hunter2pw",
		},
		{
			"invalid-profile",
			replace(t, devDoc(), `"profile":"development"`, `"profile":"supersecretprofile"`),
			"supersecretprofile",
		},
		{
			"invalid-ping",
			replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":123456789`),
			"123456789",
		},
		{
			"dsn-database-mismatch",
			replace(t, devDoc(), fmt.Sprintf(`"dsn":%q`, devDSN),
				`"dsn":"postgres://u:leakme@h:5432/otherdb?sslmode=disable"`),
			"leakme",
		},
		{
			"unknown-field-with-dsn-value",
			replace(t, devDoc(), `"evidence":{"namespace":"aipt.evidence.development"}}`,
				`"evidence":{"namespace":"aipt.evidence.development"},"extra":{"dsn":"postgres://leak:leakpw@h/x"}}`),
			"leakpw",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadErr(t, tt.doc)
			if strings.Contains(err.Error(), tt.secret) {
				t.Fatalf("error echoes secret %q: %v", tt.secret, err)
			}
			if strings.Contains(err.Error(), "postgres://") {
				t.Fatalf("error echoes a DSN-shaped value: %v", err)
			}
		})
	}
}
