package config

// Frozen configuration contract values (aipt.config/v1). Every constant is
// independently re-derived from the canonical schema
// (schemas/config/v1/aipt-config.schema.json) by the package tests
// (internal/config/schema_contract_test.go); a silent drift between these
// values and the schema artifact fails the build.

const (
	// SchemaMarker is the frozen strict JSON object schema marker required
	// at the root of every configuration document
	// (properties/schema/const).
	SchemaMarker = "aipt.config/v1"

	// MaxConfigBytes is the maximum accepted configuration input size in
	// bytes. Larger documents fail closed with AIPT_CONFIG_INPUT_TOO_LARGE
	// before any parsing.
	MaxConfigBytes = 64 * 1024

	// MaxDSNLength bounds the URI-form PostgreSQL DSN string
	// ($defs/database/properties/dsn/maxLength).
	MaxDSNLength = 512

	// MaxEvidenceNamespaceLength bounds evidence namespace identifiers.
	MaxEvidenceNamespaceLength = 128
)

// ping_timeout_ms bounds ($defs/database/properties/ping_timeout_ms): the
// value must be a positive integer within the inclusive range below.
const (
	// MinPingTimeoutMS is the inclusive minimum ping_timeout_ms.
	MinPingTimeoutMS int64 = 1
	// MaxPingTimeoutMS is the inclusive maximum ping_timeout_ms.
	MaxPingTimeoutMS int64 = 600000
)

// Frozen JSON Schema patterns kept verbatim from the canonical schema so the
// schema-drift tests can compare them.
const (
	// PatternIdentity is the frozen database identity pattern
	// ($defs/database/properties/identity/pattern): a lowercase unquoted
	// PostgreSQL identifier (the identity is the canonical database name
	// the DSN must name).
	PatternIdentity = `^[a-z_][a-z0-9_]{0,62}$`
	// PatternNamespace is the frozen SQL namespace pattern
	// ($defs/database/properties/namespace/pattern): a lowercase unquoted
	// PostgreSQL identifier (schema).
	PatternNamespace = `^[a-z_][a-z0-9_]{0,62}$`
	// PatternEvidenceNamespace is the frozen evidence namespace pattern
	// ($defs/evidence/properties/namespace/pattern): a lowercase namespace
	// identifier that may use dots, underscores, and hyphens as separators.
	PatternEvidenceNamespace = `^[a-z][a-z0-9_]*([.-][a-z0-9_]+)*$`
)

// Profile is the frozen two-value profile enum
// (properties/profile/enum).
type Profile string

const (
	// ProfileDevelopment is the development profile.
	ProfileDevelopment Profile = "development"
	// ProfileProduction is the production profile.
	ProfileProduction Profile = "production"
)

// String returns the profile value.
func (p Profile) String() string { return string(p) }

// Config is an immutable validated shared configuration. All fields are
// private: values are only produced by Load/LoadFile and read through the
// accessors below, so a validated configuration can never be mutated after
// construction. The raw DSN stays private to the database value and is
// exposed only through Database.DSN (launcher-only); every other rendering
// emits [REDACTED].
type Config struct {
	schema   string
	profile  Profile
	database Database
	evidence Evidence
}

// Schema returns the frozen schema marker.
func (c *Config) Schema() string {
	if c == nil {
		return ""
	}
	return c.schema
}

// Profile returns the validated profile.
func (c *Config) Profile() Profile {
	if c == nil {
		return ""
	}
	return c.profile
}

// Database returns the validated database configuration value.
func (c *Config) Database() Database {
	if c == nil {
		return Database{}
	}
	return c.database
}

// Evidence returns the validated evidence configuration value.
func (c *Config) Evidence() Evidence {
	if c == nil {
		return Evidence{}
	}
	return c.evidence
}

// Database is the validated database configuration. The raw URI-form
// PostgreSQL DSN is private; Database.DSN is the explicit launcher-only
// accessor. Every other rendering (String, fmt, json.Marshal) emits
// [REDACTED] in place of the DSN.
type Database struct {
	identity      string
	namespace     string
	dsn           string
	pingTimeoutMS int64
}

// Identity returns the explicit database identity (the canonical database
// name the DSN must name).
func (d Database) Identity() string { return d.identity }

// Namespace returns the SQL namespace (schema) of the database.
func (d Database) Namespace() string { return d.namespace }

// DSN returns the raw URI-form PostgreSQL DSN. It is the explicit
// launcher-only accessor: the launcher (and the storage layer it drives) is
// the only consumer that may read the raw credentials. All diagnostic
// renderings of the configuration redact this value.
func (d Database) DSN() string { return d.dsn }

// PingTimeoutMS returns the positive bounded ping timeout in milliseconds.
func (d Database) PingTimeoutMS() int64 { return d.pingTimeoutMS }

// Evidence is the validated evidence configuration.
type Evidence struct {
	namespace string
}

// Namespace returns the explicit evidence namespace.
func (e Evidence) Namespace() string { return e.namespace }
