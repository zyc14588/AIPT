package config

// Strict typed loading. Load parses and validates a complete configuration
// document (see doc.go for the frozen contract); LoadFile reads a bounded
// config file and delegates to Load. Loading applies no implicit defaults:
// every required member must be present in the document, so a production
// document never inherits development values. All rejections return a typed
// *ConfigError carrying a stable AIPT_CONFIG_* reason code.

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
)

var (
	reIdentity          = regexp.MustCompile(PatternIdentity)
	reNamespace         = regexp.MustCompile(PatternNamespace)
	reEvidenceNamespace = regexp.MustCompile(PatternEvidenceNamespace)
)

// Load parses and validates exactly one configuration document. It fails
// closed on oversized input, malformed or trailing JSON, duplicate members,
// unknown fields, missing/null required fields, invalid types, an invalid
// schema marker or profile, invalid identity/namespace formats, invalid DSN
// scheme/host/database, and out-of-range ping_timeout_ms — always with a
// typed *ConfigError whose text never contains input values (in particular
// never the DSN or any credential).
func Load(data []byte) (*Config, error) {
	if len(data) > MaxConfigBytes {
		return nil, newConfigError(ReasonInputTooLarge, "$",
			"configuration input exceeds the maximum accepted size")
	}
	root, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	return decodeConfig(root)
}

// LoadFile reads the configuration file at path (bounded to MaxConfigBytes)
// and delegates to Load. Read failures return AIPT_CONFIG_IO_ERROR; oversized
// files fail closed with AIPT_CONFIG_INPUT_TOO_LARGE.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, newConfigError(ReasonIO, "$",
			"cannot open configuration file")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, newConfigError(ReasonIO, "$",
			"cannot read configuration file")
	}
	if len(data) > MaxConfigBytes {
		return nil, newConfigError(ReasonInputTooLarge, "$",
			"configuration file exceeds the maximum accepted size")
	}
	return Load(data)
}

// memberSet is a strict object-member reader over a parsed object node.
type memberSet struct {
	n       *jsonNode
	path    string
	present map[string]*jsonNode
}

// newMemberSet requires n to be an object carrying only the allowed members.
func newMemberSet(n *jsonNode, path string, allowed ...string) (*memberSet, error) {
	if n.kind != kindObject {
		return nil, newConfigError(ReasonInvalidType, path, "expected a JSON object")
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = true
	}
	ms := &memberSet{n: n, path: path, present: make(map[string]*jsonNode, len(n.members))}
	for _, m := range n.members {
		if !allowedSet[m.key] {
			return nil, newConfigError(ReasonUnknownField, path+"/<unknown>",
				"unknown field")
		}
		ms.present[m.key] = m.val
	}
	return ms, nil
}

// required returns the non-null node of a required member, or a typed error
// for a missing member (including explicit-null bypasses).
func (ms *memberSet) required(key string) (*jsonNode, error) {
	v, ok := ms.present[key]
	if !ok {
		return nil, newConfigError(ReasonMissingField, ms.path+"/"+key,
			fmt.Sprintf("missing required field %q", key))
	}
	if v.kind == kindNull {
		return nil, newConfigError(ReasonNullField, ms.path+"/"+key,
			fmt.Sprintf("required field %q must not be null", key))
	}
	return v, nil
}

func (ms *memberSet) requiredString(key string) (string, error) {
	v, err := ms.required(key)
	if err != nil {
		return "", err
	}
	if v.kind != kindString {
		return "", newConfigError(ReasonInvalidType, ms.path+"/"+key,
			fmt.Sprintf("field %q must be a string", key))
	}
	return v.sval, nil
}

func (ms *memberSet) requiredInt64(key string) (int64, error) {
	v, err := ms.required(key)
	if err != nil {
		return 0, err
	}
	if v.kind != kindNumber || !v.isInt {
		return 0, newConfigError(ReasonInvalidType, ms.path+"/"+key,
			fmt.Sprintf("field %q must be an integer", key))
	}
	return v.ival, nil
}

func decodeConfig(root *jsonNode) (*Config, error) {
	ms, err := newMemberSet(root, "$", "schema", "profile", "database", "evidence")
	if err != nil {
		return nil, err
	}
	schema, err := ms.requiredString("schema")
	if err != nil {
		return nil, err
	}
	if schema != SchemaMarker {
		return nil, newConfigError(ReasonInvalidSchemaMarker, "$/schema",
			"schema marker must be aipt.config/v1")
	}
	profileStr, err := ms.requiredString("profile")
	if err != nil {
		return nil, err
	}
	profile, err := parseProfile(profileStr)
	if err != nil {
		return nil, err
	}
	dbNode, err := ms.required("database")
	if err != nil {
		return nil, err
	}
	database, err := decodeDatabase(dbNode)
	if err != nil {
		return nil, err
	}
	evNode, err := ms.required("evidence")
	if err != nil {
		return nil, err
	}
	evidence, err := decodeEvidence(evNode)
	if err != nil {
		return nil, err
	}
	return &Config{schema: schema, profile: profile, database: database, evidence: evidence}, nil
}

// parseProfile validates the frozen two-value profile enum. The error text
// is constant: it never echoes the offending value.
func parseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileDevelopment, ProfileProduction:
		return Profile(s), nil
	default:
		return "", newConfigError(ReasonInvalidProfile, "$/profile",
			"profile must be one of development|production")
	}
}

func decodeDatabase(n *jsonNode) (Database, error) {
	ms, err := newMemberSet(n, "$/database", "dsn", "identity", "namespace", "ping_timeout_ms")
	if err != nil {
		return Database{}, err
	}
	dsn, err := ms.requiredString("dsn")
	if err != nil {
		return Database{}, err
	}
	identity, err := ms.requiredString("identity")
	if err != nil {
		return Database{}, err
	}
	namespace, err := ms.requiredString("namespace")
	if err != nil {
		return Database{}, err
	}
	ping, err := ms.requiredInt64("ping_timeout_ms")
	if err != nil {
		return Database{}, err
	}
	if !reIdentity.MatchString(identity) {
		return Database{}, newConfigError(ReasonInvalidIdentity, "$/database/identity",
			"database identity must be a lowercase PostgreSQL identifier")
	}
	if !reNamespace.MatchString(namespace) {
		return Database{}, newConfigError(ReasonInvalidNamespace, "$/database/namespace",
			"database namespace must be a lowercase PostgreSQL identifier")
	}
	if ping < MinPingTimeoutMS || ping > MaxPingTimeoutMS {
		return Database{}, newConfigError(ReasonInvalidPingTimeout, "$/database/ping_timeout_ms",
			"ping_timeout_ms must be within the positive bounded range")
	}
	if err := validateDSN(dsn, identity); err != nil {
		return Database{}, err
	}
	return Database{identity: identity, namespace: namespace, dsn: dsn, pingTimeoutMS: ping}, nil
}

// validateDSN enforces the URI-form PostgreSQL DSN contract: the URI must
// parse, the scheme must be postgres or postgresql, a host must be present,
// a database must be named, and that database must equal the explicit
// database identity. The DSN string itself never appears in any returned
// error text.
func validateDSN(dsn, identity string) error {
	if len(dsn) > MaxDSNLength {
		return newConfigError(ReasonInvalidDSN, "$/database/dsn",
			"dsn exceeds the maximum supported length")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return newConfigError(ReasonInvalidDSN, "$/database/dsn",
			"dsn must be a valid URI")
	}
	switch u.Scheme {
	case "postgres", "postgresql":
	default:
		return newConfigError(ReasonDSNSchemeMismatch, "$/database/dsn",
			"dsn scheme must be postgres or postgresql")
	}
	if u.Hostname() == "" {
		return newConfigError(ReasonDSNHostMismatch, "$/database/dsn",
			"dsn must name a host")
	}
	if u.Fragment != "" {
		return newConfigError(ReasonInvalidDSN, "$/database/dsn",
			"dsn must not contain a fragment")
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return newConfigError(ReasonDSNDatabaseMismatch, "$/database/dsn",
			"dsn must name a database")
	}
	if db != identity {
		return newConfigError(ReasonDSNDatabaseMismatch, "$/database/dsn",
			"dsn database must match the declared database identity")
	}
	return nil
}

func decodeEvidence(n *jsonNode) (Evidence, error) {
	ms, err := newMemberSet(n, "$/evidence", "namespace")
	if err != nil {
		return Evidence{}, err
	}
	namespace, err := ms.requiredString("namespace")
	if err != nil {
		return Evidence{}, err
	}
	if len(namespace) > MaxEvidenceNamespaceLength || !reEvidenceNamespace.MatchString(namespace) {
		return Evidence{}, newConfigError(ReasonInvalidNamespace, "$/evidence/namespace",
			"evidence namespace must be a lowercase namespace identifier")
	}
	return Evidence{namespace: namespace}, nil
}

// ValidateIsolation checks one development and one production configuration
// and rejects any collision of database identity, database namespace, or
// evidence namespace (R7-Q007: development and production use independent
// profiles, databases, and evidence namespaces). The returned error is a
// typed *ConfigError with reason AIPT_CONFIG_ISOLATION_VIOLATION; its text is
// deterministic and never echoes the colliding values.
func ValidateIsolation(development, production *Config) error {
	if development == nil || production == nil {
		return newConfigError(ReasonIsolationViolation, "",
			"development and production configurations are both required")
	}
	if development.profile != ProfileDevelopment || production.profile != ProfileProduction {
		return newConfigError(ReasonIsolationViolation, "",
			"isolation requires development then production configurations")
	}
	if development.database.identity == production.database.identity {
		return newConfigError(ReasonIsolationViolation, "",
			"development and production must use different database identities")
	}
	if development.database.namespace == production.database.namespace {
		return newConfigError(ReasonIsolationViolation, "",
			"development and production must use different database namespaces")
	}
	if development.evidence.namespace == production.evidence.namespace {
		return newConfigError(ReasonIsolationViolation, "",
			"development and production must use different evidence namespaces")
	}
	return nil
}
