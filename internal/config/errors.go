package config

import (
	"errors"
	"fmt"
)

// Stable AIPT_CONFIG_* reason codes carried by ConfigError. Every rejection
// path in this package returns a typed *ConfigError with exactly one of these
// reasons, so tests and consumers can distinguish failure modes without
// parsing free-form messages. Codes follow the frozen AIPT_* error-code
// pattern and never contain input values.
const (
	// --- strict JSON layer ---
	ReasonJSONMalformed       = "AIPT_CONFIG_JSON_MALFORMED"
	ReasonJSONTrailing        = "AIPT_CONFIG_JSON_TRAILING"
	ReasonJSONDuplicateKey    = "AIPT_CONFIG_JSON_DUPLICATE_KEY"
	ReasonJSONUnsafeInteger   = "AIPT_CONFIG_JSON_UNSAFE_INTEGER"
	ReasonJSONNonFiniteNumber = "AIPT_CONFIG_JSON_NON_FINITE_NUMBER"
	ReasonInputTooLarge       = "AIPT_CONFIG_INPUT_TOO_LARGE"

	// --- typed document layer ---
	ReasonUnknownField        = "AIPT_CONFIG_UNKNOWN_FIELD"
	ReasonMissingField        = "AIPT_CONFIG_MISSING_FIELD"
	ReasonNullField           = "AIPT_CONFIG_NULL_FIELD"
	ReasonInvalidType         = "AIPT_CONFIG_INVALID_TYPE"
	ReasonInvalidSchemaMarker = "AIPT_CONFIG_INVALID_SCHEMA_MARKER"
	ReasonInvalidProfile      = "AIPT_CONFIG_INVALID_PROFILE"
	ReasonInvalidIdentity     = "AIPT_CONFIG_INVALID_IDENTITY"
	ReasonInvalidNamespace    = "AIPT_CONFIG_INVALID_NAMESPACE"

	// --- DSN layer ---
	ReasonInvalidDSN          = "AIPT_CONFIG_INVALID_DSN"
	ReasonDSNSchemeMismatch   = "AIPT_CONFIG_DSN_SCHEME_MISMATCH"
	ReasonDSNHostMismatch     = "AIPT_CONFIG_DSN_HOST_MISMATCH"
	ReasonDSNDatabaseMismatch = "AIPT_CONFIG_DSN_DATABASE_MISMATCH"

	// --- value bounds and isolation ---
	ReasonInvalidPingTimeout = "AIPT_CONFIG_INVALID_PING_TIMEOUT"
	ReasonIsolationViolation = "AIPT_CONFIG_ISOLATION_VIOLATION"

	// --- I/O layer (LoadFile) ---
	ReasonIO = "AIPT_CONFIG_IO_ERROR"
)

// ConfigError is the deterministic typed error returned by every fail-closed
// rejection in this package. Reason is a stable AIPT_CONFIG_* reason code,
// Path is the JSON path of the offending member when practical ("" when not
// applicable), and Detail is a deterministic explanation. Detail and Path
// never contain the value of any input field: in particular the DSN and any
// credential never appear in error text; member names appear in Path only as
// structural location, never the values they carry.
type ConfigError struct {
	Reason string
	Path   string
	Detail string
}

// Error implements error and always embeds the stable reason code.
func (e *ConfigError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Path != "" {
		return fmt.Sprintf("%s at %s: %s", e.Reason, e.Path, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
}

// newConfigError builds a *ConfigError.
func newConfigError(reason, path, detail string) error {
	return &ConfigError{Reason: reason, Path: path, Detail: detail}
}

// ConfigReason returns the stable AIPT_CONFIG_* reason code of err when err
// is a *ConfigError, and "" otherwise. It never inspects message text.
func ConfigReason(err error) string {
	var ce *ConfigError
	if !errors.As(err, &ce) || ce == nil {
		return ""
	}
	return ce.Reason
}

// ConfigPath returns the JSON path carried by err when err is a
// *ConfigError.
func ConfigPath(err error) string {
	var ce *ConfigError
	if !errors.As(err, &ce) || ce == nil {
		return ""
	}
	return ce.Path
}
