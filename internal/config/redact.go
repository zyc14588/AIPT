package config

// Redacted renderings. The raw DSN is private to the database value; every
// diagnostic surface below emits the constant [REDACTED] in its place, so
// credentials can never leak through Error, fmt, String, json.Marshal, or
// redacted diagnostics.

import (
	"encoding/json"
	"fmt"
	"io"
)

// redactedValue is the deterministic placeholder emitted wherever the raw DSN
// would otherwise appear in a diagnostic rendering.
const redactedValue = "[REDACTED]"

// String returns a deterministic redacted human-readable rendering of the
// configuration. It implements fmt.Stringer, so fmt, %v, and %s renderings of
// a configuration are redacted too.
func (c *Config) String() string {
	if c == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s profile=%s database=%s evidence=%s",
		c.schema, c.profile, c.database.String(), c.evidence.String())
}

// Redacted returns the redacted diagnostic rendering of the configuration
// (identical to String): safe for logs, errors, and any diagnostic output.
func (c *Config) Redacted() string {
	return c.String()
}

// Format keeps every fmt verb, including Go-syntax verbs such as %#v, on a
// redacted diagnostic surface. Without Formatter, %#v would reflect private
// struct fields and expose the raw DSN.
func (c Config) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, (&c).String())
}

// MarshalJSON renders the configuration as its public JSON shape with the DSN
// replaced by [REDACTED]. The output is deterministic: the same configuration
// always marshals to the same bytes, and no credential appears in it.
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Schema   string   `json:"schema"`
		Profile  Profile  `json:"profile"`
		Database Database `json:"database"`
		Evidence Evidence `json:"evidence"`
	}{
		Schema:   c.schema,
		Profile:  c.profile,
		Database: c.database,
		Evidence: c.evidence,
	})
}

// String returns a deterministic redacted rendering of the database value.
func (d Database) String() string {
	return fmt.Sprintf("database{identity=%s namespace=%s ping_timeout_ms=%d dsn=%s}",
		d.identity, d.namespace, d.pingTimeoutMS, redactedValue)
}

// Format keeps every fmt verb on the redacted database rendering.
func (d Database) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, d.String())
}

// MarshalJSON renders the database value with the DSN replaced by [REDACTED].
func (d Database) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		DSN           string `json:"dsn"`
		Identity      string `json:"identity"`
		Namespace     string `json:"namespace"`
		PingTimeoutMS int64  `json:"ping_timeout_ms"`
	}{
		DSN:           redactedValue,
		Identity:      d.identity,
		Namespace:     d.namespace,
		PingTimeoutMS: d.pingTimeoutMS,
	})
}

// String returns a deterministic rendering of the evidence value (it carries
// no credentials).
func (e Evidence) String() string {
	return fmt.Sprintf("evidence{namespace=%s}", e.namespace)
}

// Format renders the non-secret evidence value consistently for every fmt
// verb, matching Config and Database diagnostic behavior.
func (e Evidence) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.String())
}

// MarshalJSON renders the evidence value (it carries no credentials).
func (e Evidence) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Namespace string `json:"namespace"`
	}{Namespace: e.namespace})
}
