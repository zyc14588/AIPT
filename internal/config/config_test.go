package config

// Comprehensive tests for the strict shared configuration service
// (AIPT-M0-B004, leaf 2): valid development/production loading, unknown
// fields at every level, every missing/null required field, trailing input,
// oversized input, enum/format/range validation, URI/identity validation,
// profile/database/evidence isolation, production no-default inheritance,
// and stable typed errors that never echo input values.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	devDSN  = "postgres://aipt:dev-secret@127.0.0.1:5432/aipt_development?sslmode=disable"
	prodDSN = "postgres://aipt:prod-secret@127.0.0.1:5432/aipt_production?sslmode=disable"
)

func devDoc() string {
	return fmt.Sprintf(`{"schema":"aipt.config/v1","profile":"development","database":{"dsn":%q,"identity":"aipt_development","namespace":"aipt_dev","ping_timeout_ms":5000},"evidence":{"namespace":"aipt.evidence.development"}}`, devDSN)
}

func prodDoc() string {
	return fmt.Sprintf(`{"schema":"aipt.config/v1","profile":"production","database":{"dsn":%q,"identity":"aipt_production","namespace":"aipt_prod","ping_timeout_ms":1000},"evidence":{"namespace":"aipt.evidence.production"}}`, prodDSN)
}

func dbObj() string {
	return fmt.Sprintf(`"database":{"dsn":%q,"identity":"aipt_development","namespace":"aipt_dev","ping_timeout_ms":5000}`, devDSN)
}

// replace returns doc with exactly one occurrence of old replaced by new,
// failing the test when old is absent (test-authoring guard).
func replace(t *testing.T, doc, old, new string) string {
	t.Helper()
	out := strings.Replace(doc, old, new, 1)
	if out == doc {
		t.Fatal("test authoring error: replacement pattern not found")
	}
	return out
}

func mustLoad(t *testing.T, doc string) *Config {
	t.Helper()
	c, err := Load([]byte(doc))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	return c
}

func loadErr(t *testing.T, doc string) error {
	t.Helper()
	_, err := Load([]byte(doc))
	if err == nil {
		t.Fatal("Load succeeded, want error")
	}
	return err
}

func wantReason(t *testing.T, err error, reason, path string) {
	t.Helper()
	if got := ConfigReason(err); got != reason {
		t.Fatalf("ConfigReason = %q, want %q (err: %v)", got, reason, err)
	}
	if got := ConfigPath(err); got != path {
		t.Fatalf("ConfigPath = %q, want %q", got, path)
	}
}

func TestLoadValidDevelopment(t *testing.T) {
	c := mustLoad(t, devDoc())
	if c.Schema() != SchemaMarker {
		t.Errorf("Schema() = %q, want %q", c.Schema(), SchemaMarker)
	}
	if c.Profile() != ProfileDevelopment {
		t.Errorf("Profile() = %q, want development", c.Profile())
	}
	db := c.Database()
	if db.Identity() != "aipt_development" {
		t.Errorf("Identity() = %q", db.Identity())
	}
	if db.Namespace() != "aipt_dev" {
		t.Errorf("Namespace() = %q", db.Namespace())
	}
	if db.DSN() != devDSN {
		t.Errorf("DSN() = %q, want the exact raw DSN", db.DSN())
	}
	if db.PingTimeoutMS() != 5000 {
		t.Errorf("PingTimeoutMS() = %d, want 5000", db.PingTimeoutMS())
	}
	if c.Evidence().Namespace() != "aipt.evidence.development" {
		t.Errorf("evidence namespace = %q", c.Evidence().Namespace())
	}
}

func TestLoadValidProduction(t *testing.T) {
	c := mustLoad(t, prodDoc())
	if c.Profile() != ProfileProduction {
		t.Errorf("Profile() = %q, want production", c.Profile())
	}
	if db := c.Database(); db.Identity() != "aipt_production" || db.Namespace() != "aipt_prod" ||
		db.DSN() != prodDSN || db.PingTimeoutMS() != 1000 {
		t.Errorf("database value drifted: %s", db.String())
	}
	if c.Evidence().Namespace() != "aipt.evidence.production" {
		t.Errorf("evidence namespace = %q", c.Evidence().Namespace())
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		path string
	}{
		{"root", replace(t, devDoc(), `"evidence":{"namespace":"aipt.evidence.development"}}`,
			`"evidence":{"namespace":"aipt.evidence.development"},"extra":1}`), "$/<unknown>"},
		{"database", replace(t, devDoc(), `"ping_timeout_ms":5000}`,
			`"ping_timeout_ms":5000,"extra":1}`), "$/database/<unknown>"},
		{"evidence", replace(t, devDoc(), `"namespace":"aipt.evidence.development"}`,
			`"namespace":"aipt.evidence.development","extra":1}`), "$/evidence/<unknown>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadErr(t, tt.doc)
			wantReason(t, err, ReasonUnknownField, tt.path)
		})
	}
}

func TestLoadRejectsMissingRequiredField(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		path string
	}{
		{"schema", replace(t, devDoc(), `"schema":"aipt.config/v1",`, ""), "$/schema"},
		{"profile", replace(t, devDoc(), `"profile":"development",`, ""), "$/profile"},
		{"database", replace(t, devDoc(), ","+dbObj(), ""), "$/database"},
		{"evidence", replace(t, devDoc(), `,"evidence":{"namespace":"aipt.evidence.development"}`, ""), "$/evidence"},
		{"database.dsn", replace(t, devDoc(), fmt.Sprintf(`"dsn":%q,`, devDSN), ""), "$/database/dsn"},
		{"database.identity", replace(t, devDoc(), `"identity":"aipt_development",`, ""), "$/database/identity"},
		{"database.namespace", replace(t, devDoc(), `"namespace":"aipt_dev",`, ""), "$/database/namespace"},
		{"database.ping_timeout_ms", replace(t, devDoc(), `,"ping_timeout_ms":5000`, ""), "$/database/ping_timeout_ms"},
		{"evidence.namespace", replace(t, devDoc(), `"namespace":"aipt.evidence.development"`, ""), "$/evidence/namespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadErr(t, tt.doc)
			wantReason(t, err, ReasonMissingField, tt.path)
		})
	}
}

func TestLoadRejectsNullRequiredField(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		path string
	}{
		{"schema", replace(t, devDoc(), `"schema":"aipt.config/v1"`, `"schema":null`), "$/schema"},
		{"profile", replace(t, devDoc(), `"profile":"development"`, `"profile":null`), "$/profile"},
		{"database", replace(t, devDoc(), dbObj(), `"database":null`), "$/database"},
		{"evidence", replace(t, devDoc(), `"evidence":{"namespace":"aipt.evidence.development"}`, `"evidence":null`), "$/evidence"},
		{"database.dsn", replace(t, devDoc(), fmt.Sprintf(`"dsn":%q`, devDSN), `"dsn":null`), "$/database/dsn"},
		{"database.identity", replace(t, devDoc(), `"identity":"aipt_development"`, `"identity":null`), "$/database/identity"},
		{"database.namespace", replace(t, devDoc(), `"namespace":"aipt_dev"`, `"namespace":null`), "$/database/namespace"},
		{"database.ping_timeout_ms", replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":null`), "$/database/ping_timeout_ms"},
		{"evidence.namespace", replace(t, devDoc(), `"namespace":"aipt.evidence.development"`, `"namespace":null`), "$/evidence/namespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadErr(t, tt.doc)
			wantReason(t, err, ReasonNullField, tt.path)
		})
	}
}

func TestLoadRejectsTrailingJSON(t *testing.T) {
	docs := []string{
		devDoc() + " x",
		devDoc() + " {}",
		devDoc() + devDoc(),
	}
	for i, doc := range docs {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			err := loadErr(t, doc)
			wantReason(t, err, ReasonJSONTrailing, "$")
		})
	}
}

func TestLoadAcceptsTrailingWhitespace(t *testing.T) {
	mustLoad(t, devDoc()+"\n\t ")
}

func TestLoadRejectsOversizedInput(t *testing.T) {
	// The size gate runs before parsing: even non-JSON garbage beyond the
	// bound fails closed with AIPT_CONFIG_INPUT_TOO_LARGE.
	big := strings.Repeat(" ", MaxConfigBytes+1)
	err := loadErr(t, big)
	wantReason(t, err, ReasonInputTooLarge, "$")

	// A huge JSON document that would otherwise be valid is also rejected.
	huge := replace(t, devDoc(), `"ping_timeout_ms":5000`,
		fmt.Sprintf(`"ping_timeout_ms":5000,"padding":%q`, strings.Repeat("a", MaxConfigBytes)))
	err = loadErr(t, huge)
	wantReason(t, err, ReasonInputTooLarge, "$")
}

func TestLoadRejectsDuplicateKey(t *testing.T) {
	doc := replace(t, devDoc(), `"profile":"development"`, `"profile":"development","profile":"development"`)
	err := loadErr(t, doc)
	wantReason(t, err, ReasonJSONDuplicateKey, "$/profile")
}

func TestLoadRejectsInvalidProfile(t *testing.T) {
	for _, value := range []string{`"staging"`, `""`, `"Production"`, `"development "`} {
		doc := replace(t, devDoc(), `"profile":"development"`, `"profile":`+value)
		err := loadErr(t, doc)
		wantReason(t, err, ReasonInvalidProfile, "$/profile")
	}
}

func TestLoadRejectsInvalidSchemaMarker(t *testing.T) {
	for _, value := range []string{`"aipt.config/v2"`, `""`, `"aipt.config/v1 "`} {
		doc := replace(t, devDoc(), `"schema":"aipt.config/v1"`, `"schema":`+value)
		err := loadErr(t, doc)
		wantReason(t, err, ReasonInvalidSchemaMarker, "$/schema")
	}
}

func TestLoadRejectsInvalidType(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		path string
	}{
		{"root.array", `[1,2,3]`, "$"},
		{"root.string", `"hello"`, "$"},
		{"root.null", `null`, "$"},
		{"root.number", `5`, "$"},
		{"schema", replace(t, devDoc(), `"schema":"aipt.config/v1"`, `"schema":5`), "$/schema"},
		{"profile", replace(t, devDoc(), `"profile":"development"`, `"profile":5`), "$/profile"},
		{"database", replace(t, devDoc(), dbObj(), `"database":"x"`), "$/database"},
		{"database.array", replace(t, devDoc(), dbObj(), `"database":[1]`), "$/database"},
		{"evidence", replace(t, devDoc(), `"evidence":{"namespace":"aipt.evidence.development"}`, `"evidence":[]`), "$/evidence"},
		{"database.dsn", replace(t, devDoc(), fmt.Sprintf(`"dsn":%q`, devDSN), `"dsn":5`), "$/database/dsn"},
		{"database.identity", replace(t, devDoc(), `"identity":"aipt_development"`, `"identity":5`), "$/database/identity"},
		{"database.namespace", replace(t, devDoc(), `"namespace":"aipt_dev"`, `"namespace":5`), "$/database/namespace"},
		{"database.ping_string", replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":"5000"`), "$/database/ping_timeout_ms"},
		{"database.ping_float", replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":1.5`), "$/database/ping_timeout_ms"},
		{"database.ping_bool", replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":true`), "$/database/ping_timeout_ms"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadErr(t, tt.doc)
			wantReason(t, err, ReasonInvalidType, tt.path)
		})
	}
}

func TestLoadRejectsInvalidIdentity(t *testing.T) {
	for _, value := range []string{`"AIPT_DEVELOPMENT"`, `"aipt-development"`, `"1aipt"`, `""`} {
		doc := replace(t, devDoc(), `"identity":"aipt_development"`, `"identity":`+value)
		err := loadErr(t, doc)
		wantReason(t, err, ReasonInvalidIdentity, "$/database/identity")
	}
}

func TestLoadRejectsInvalidNamespace(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		path string
	}{
		{"database.upper", replace(t, devDoc(), `"namespace":"aipt_dev"`, `"namespace":"AIPT_DEV"`), "$/database/namespace"},
		{"database.dot", replace(t, devDoc(), `"namespace":"aipt_dev"`, `"namespace":"aipt.dev"`), "$/database/namespace"},
		{"database.empty", replace(t, devDoc(), `"namespace":"aipt_dev"`, `"namespace":""`), "$/database/namespace"},
		{"evidence.space", replace(t, devDoc(), `"namespace":"aipt.evidence.development"`, `"namespace":"Bad Namespace!"`), "$/evidence/namespace"},
		{"evidence.digit", replace(t, devDoc(), `"namespace":"aipt.evidence.development"`, `"namespace":"9aipt"`), "$/evidence/namespace"},
		{"evidence.empty", replace(t, devDoc(), `"namespace":"aipt.evidence.development"`, `"namespace":""`), "$/evidence/namespace"},
		{"evidence.upper", replace(t, devDoc(), `"namespace":"aipt.evidence.development"`, `"namespace":"AIPT.EVIDENCE.DEV"`), "$/evidence/namespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadErr(t, tt.doc)
			wantReason(t, err, ReasonInvalidNamespace, tt.path)
		})
	}
}

func TestLoadRejectsInvalidDSN(t *testing.T) {
	tests := []struct {
		name   string
		dsn    string
		reason string
	}{
		{"unparseable", `"postgres://u:p@%zz:5432/db"`, ReasonInvalidDSN},
		{"wrong-scheme", `"mysql://u:p@h:5432/aipt_development"`, ReasonDSNSchemeMismatch},
		{"relative-reference", `"not a uri"`, ReasonDSNSchemeMismatch},
		{"empty", `""`, ReasonDSNSchemeMismatch},
		{"missing-host", `"postgres:///aipt_development"`, ReasonDSNHostMismatch},
		{"opaque-dsn", `"postgres:aipt_development"`, ReasonDSNHostMismatch},
		{"missing-database", `"postgres://h"`, ReasonDSNDatabaseMismatch},
		{"empty-database", `"postgres://h/"`, ReasonDSNDatabaseMismatch},
		{"database-mismatch", `"postgres://u:p@h:5432/otherdb"`, ReasonDSNDatabaseMismatch},
		{"database-mismatch-space", `"postgres://u:p@h:5432/aipt_development "`, ReasonDSNDatabaseMismatch},
		{"too-long", `"postgres://h/` + strings.Repeat("a", 513) + `"`, ReasonInvalidDSN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := replace(t, devDoc(), fmt.Sprintf(`"dsn":%q`, devDSN), `"dsn":`+tt.dsn)
			err := loadErr(t, doc)
			wantReason(t, err, tt.reason, "$/database/dsn")
		})
	}
}

func TestLoadRejectsInvalidPingTimeout(t *testing.T) {
	for _, value := range []string{"0", "-1", "-5000", "600001"} {
		doc := replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":`+value)
		err := loadErr(t, doc)
		wantReason(t, err, ReasonInvalidPingTimeout, "$/database/ping_timeout_ms")
	}
	// Huge integers fail at the parser layer before the range check.
	doc := replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":99999999999999999999`)
	err := loadErr(t, doc)
	wantReason(t, err, ReasonJSONUnsafeInteger, "$/database/ping_timeout_ms")
}

func TestLoadPingTimeoutBoundaries(t *testing.T) {
	for _, value := range []int64{1, 600000} {
		doc := replace(t, devDoc(), `"ping_timeout_ms":5000`, fmt.Sprintf(`"ping_timeout_ms":%d`, value))
		c := mustLoad(t, doc)
		if got := c.Database().PingTimeoutMS(); got != value {
			t.Errorf("PingTimeoutMS() = %d, want %d", got, value)
		}
	}
}

func TestLoadRejectsNonFiniteNumber(t *testing.T) {
	doc := replace(t, devDoc(), `"ping_timeout_ms":5000`, `"ping_timeout_ms":1e999`)
	err := loadErr(t, doc)
	wantReason(t, err, ReasonJSONNonFiniteNumber, "$/database/ping_timeout_ms")
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	docs := []string{"", "   ", "{", `{"schema":`, `{"schema":"aipt.config/v1",}`, "tru", "01", `{"a":1 "b":2}`}
	for i, doc := range docs {
		t.Run(fmt.Sprintf("case%d", i), func(t *testing.T) {
			err := loadErr(t, doc)
			path := "$"
			if i == 3 {
				path = "$/schema"
			}
			wantReason(t, err, ReasonJSONMalformed, path)
		})
	}
}

func TestValidateIsolation(t *testing.T) {
	dev := mustLoad(t, devDoc())
	prod := mustLoad(t, prodDoc())

	if err := ValidateIsolation(dev, prod); err != nil {
		t.Fatalf("ValidateIsolation(dev, prod) = %v, want nil", err)
	}

	tests := []struct {
		name string
		doc  string
	}{
		{"database-identity", replace(t,
			replace(t, prodDoc(), fmt.Sprintf(`"dsn":%q`, prodDSN), fmt.Sprintf(`"dsn":%q`, devDSN)),
			`"identity":"aipt_production"`, `"identity":"aipt_development"`)},
		{"database-namespace", replace(t, prodDoc(), `"namespace":"aipt_prod"`, `"namespace":"aipt_dev"`)},
		{"evidence-namespace", replace(t, prodDoc(), `"namespace":"aipt.evidence.production"`, `"namespace":"aipt.evidence.development"`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The colliding value must still load as a valid production
			// document before the isolation check can reject it.
			prod2 := mustLoad(t, tt.doc)
			err := ValidateIsolation(dev, prod2)
			if ConfigReason(err) != ReasonIsolationViolation {
				t.Fatalf("ValidateIsolation = %v, want AIPT_CONFIG_ISOLATION_VIOLATION", err)
			}
		})
	}

	if err := ValidateIsolation(nil, prod); ConfigReason(err) != ReasonIsolationViolation {
		t.Fatalf("ValidateIsolation(nil, prod) = %v, want isolation violation", err)
	}
	if err := ValidateIsolation(dev, nil); ConfigReason(err) != ReasonIsolationViolation {
		t.Fatalf("ValidateIsolation(dev, nil) = %v, want isolation violation", err)
	}
	if err := ValidateIsolation(prod, dev); ConfigReason(err) != ReasonIsolationViolation {
		t.Fatalf("ValidateIsolation(prod, dev) = %v, want role isolation violation", err)
	}
	if err := ValidateIsolation(dev, dev); ConfigReason(err) != ReasonIsolationViolation {
		t.Fatalf("ValidateIsolation(dev, dev) = %v, want role isolation violation", err)
	}
}

func TestProductionDoesNotInheritDevelopmentDefaults(t *testing.T) {
	// A production document missing any required field fails closed: nothing
	// is filled in from the development profile or from any implicit default.
	missingEvidence := replace(t, prodDoc(), `,"evidence":{"namespace":"aipt.evidence.production"}`, "")
	err := loadErr(t, missingEvidence)
	wantReason(t, err, ReasonMissingField, "$/evidence")

	missingPing := replace(t, prodDoc(), `,"ping_timeout_ms":1000`, "")
	err = loadErr(t, missingPing)
	wantReason(t, err, ReasonMissingField, "$/database/ping_timeout_ms")

	missingIdentity := replace(t, prodDoc(), `"identity":"aipt_production",`, "")
	err = loadErr(t, missingIdentity)
	wantReason(t, err, ReasonMissingField, "$/database/identity")

	// A complete production document loads exactly as given: no default is
	// injected anywhere.
	c := mustLoad(t, prodDoc())
	if c.Profile() != ProfileProduction {
		t.Errorf("Profile() = %q", c.Profile())
	}
	db := c.Database()
	if db.Identity() != "aipt_production" || db.Namespace() != "aipt_prod" ||
		db.PingTimeoutMS() != 1000 || db.DSN() != prodDSN {
		t.Errorf("production values drifted: %s", db.String())
	}
	if c.Evidence().Namespace() != "aipt.evidence.production" {
		t.Errorf("evidence namespace = %q", c.Evidence().Namespace())
	}
}

func TestStableErrors(t *testing.T) {
	// The same document fails with the identical error text on every load.
	bad := replace(t, devDoc(), `"profile":"development"`, `"profile":"staging"`)
	e1 := loadErr(t, bad)
	e2 := loadErr(t, bad)
	if e1.Error() != e2.Error() {
		t.Fatalf("same input produced different errors:\n%v\n%v", e1, e2)
	}
	wantReason(t, e1, ReasonInvalidProfile, "$/profile")

	// Different secret-bearing values in the same failure class produce the
	// identical error text: no input value is ever echoed.
	docA := replace(t, devDoc(), `"identity":"aipt_development"`, `"identity":"Aaa"`)
	docB := replace(t, devDoc(), `"identity":"aipt_development"`, `"identity":"Bbb"`)
	errA := loadErr(t, docA)
	errB := loadErr(t, docB)
	if errA.Error() != errB.Error() {
		t.Fatalf("different values of one failure class produced different errors:\n%v\n%v", errA, errB)
	}
	wantReason(t, errA, ReasonInvalidIdentity, "$/database/identity")

	// Credentials embedded in a rejected document never reach error text.
	secretDSN := "postgres://u:supersecretpw@h:5432/aipt_development?sslmode=disable"
	docS := replace(t, devDoc(), fmt.Sprintf(`"dsn":%q`, devDSN), fmt.Sprintf(`"dsn":%q`, secretDSN))
	docS = replace(t, docS, `"identity":"aipt_development"`, `"identity":"BADID"`)
	errS := loadErr(t, docS)
	for _, secret := range []string{"supersecretpw", secretDSN, "BADID"} {
		if strings.Contains(errS.Error(), secret) {
			t.Fatalf("error echoes secret %q: %v", secret, errS)
		}
	}

	// Helper functions on non-ConfigError values.
	if got := ConfigReason(errors.New("plain")); got != "" {
		t.Errorf("ConfigReason(plain) = %q, want empty", got)
	}
	if got := ConfigPath(errors.New("plain")); got != "" {
		t.Errorf("ConfigPath(plain) = %q, want empty", got)
	}
	if got := ConfigReason(nil); got != "" {
		t.Errorf("ConfigReason(nil) = %q, want empty", got)
	}
	if got := ConfigReason(fmt.Errorf("wrapped: %w", errS)); got != ReasonInvalidIdentity {
		t.Errorf("ConfigReason(wrapped) = %q, want %q", got, ReasonInvalidIdentity)
	}
	if got := ConfigPath(fmt.Errorf("wrapped: %w", errS)); got != "$/database/identity" {
		t.Errorf("ConfigPath(wrapped) = %q", got)
	}

	// errors.As yields the typed ConfigError.
	var ce *ConfigError
	if !errors.As(errS, &ce) {
		t.Fatalf("errors.As failed for %v", errS)
	}
	if ce.Reason != ReasonInvalidIdentity || ce.Path != "$/database/identity" || ce.Detail == "" {
		t.Errorf("typed fields unexpected: %+v", ce)
	}
	if got := (&ConfigError{}).Error(); got == "" {
		t.Error("ConfigError.Error() must not be empty")
	}
	var nilErr *ConfigError
	if got := nilErr.Error(); got != "<nil>" {
		t.Errorf("nil ConfigError.Error() = %q, want <nil>", got)
	}
}

func TestLoadRejectsInvalidUnicodeEscape(t *testing.T) {
	valid := replace(t, devDoc(),
		"\"schema\":\"aipt.config/v1\"",
		"\"schema\":\"aipt.config/v\\u0031\"")
	mustLoad(t, valid)

	for _, escape := range []string{"\\uZZZZ", "\\u12G4", "\\u000Z"} {
		doc := replace(t, devDoc(),
			"\"schema\":\"aipt.config/v1\"",
			"\"schema\":\"aipt.config/v"+escape+"\"")
		err := loadErr(t, doc)
		wantReason(t, err, ReasonJSONMalformed, "$/schema")
		if strings.Contains(err.Error(), escape) {
			t.Fatalf("unicode error echoes rejected input: %v", err)
		}
	}
}

func TestErrorPathsDoNotEchoUnknownMemberNames(t *testing.T) {
	secretKey := "postgres://user:key-secret@host/aipt_development"
	base := strings.TrimSuffix(devDoc(), "}")

	doc := base + fmt.Sprintf(",%q:1}", secretKey)
	err := loadErr(t, doc)
	wantReason(t, err, ReasonUnknownField, "$/<unknown>")
	if strings.Contains(err.Error(), secretKey) || strings.Contains(err.Error(), "key-secret") {
		t.Fatalf("unknown-field error echoes member name: %v", err)
	}

	doc = base + fmt.Sprintf(",%q:1,%q:2}", secretKey, secretKey)
	err = loadErr(t, doc)
	wantReason(t, err, ReasonJSONDuplicateKey, "$/<unknown>")
	if strings.Contains(err.Error(), secretKey) || strings.Contains(err.Error(), "key-secret") {
		t.Fatalf("duplicate-key error echoes member name: %v", err)
	}
}

func TestEvidenceNamespaceLengthBound(t *testing.T) {
	old := "\"namespace\":\"aipt.evidence.development\""
	valid := strings.Repeat("a", MaxEvidenceNamespaceLength)
	mustLoad(t, replace(t, devDoc(), old, "\"namespace\":"+fmt.Sprintf("%q", valid)))

	tooLong := strings.Repeat("a", MaxEvidenceNamespaceLength+1)
	err := loadErr(t, replace(t, devDoc(), old, "\"namespace\":"+fmt.Sprintf("%q", tooLong)))
	wantReason(t, err, ReasonInvalidNamespace, "$/evidence/namespace")
}

func TestLoadRejectsDSNEdgeCasesWithoutEcho(t *testing.T) {
	tests := []struct {
		dsn    string
		reason string
	}{
		{"postgres://:5432/aipt_development", ReasonDSNHostMismatch},
		{"postgres://host/aipt_development#fragment-secret", ReasonInvalidDSN},
	}
	for _, tt := range tests {
		doc := replace(t, devDoc(),
			fmt.Sprintf("\"dsn\":%q", devDSN),
			fmt.Sprintf("\"dsn\":%q", tt.dsn))
		err := loadErr(t, doc)
		wantReason(t, err, tt.reason, "$/database/dsn")
		if strings.Contains(err.Error(), tt.dsn) || strings.Contains(err.Error(), "fragment-secret") {
			t.Fatalf("DSN error echoes rejected input: %v", err)
		}
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "config.json")
	if err := os.WriteFile(valid, []byte(devDoc()), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(valid)
	if err != nil {
		t.Fatalf("LoadFile(valid) = %v", err)
	}
	want := mustLoad(t, devDoc())
	if c.Schema() != want.Schema() || c.Profile() != want.Profile() ||
		c.Database().DSN() != want.Database().DSN() ||
		c.Database().Identity() != want.Database().Identity() ||
		c.Database().Namespace() != want.Database().Namespace() ||
		c.Database().PingTimeoutMS() != want.Database().PingTimeoutMS() ||
		c.Evidence().Namespace() != want.Evidence().Namespace() {
		t.Errorf("LoadFile value differs from Load value: %s vs %s", c.Redacted(), want.Redacted())
	}

	missing := filepath.Join(dir, "missing.json")
	if _, err := LoadFile(missing); ConfigReason(err) != ReasonIO {
		t.Fatalf("LoadFile(missing) = %v, want AIPT_CONFIG_IO_ERROR", err)
	} else if strings.Contains(err.Error(), missing) || strings.Contains(err.Error(), dir) {
		t.Fatalf("LoadFile error leaks the input path: %v", err)
	}

	if _, err := LoadFile(dir); ConfigReason(err) != ReasonIO {
		t.Fatalf("LoadFile(directory) = %v, want AIPT_CONFIG_IO_ERROR", err)
	} else if strings.Contains(err.Error(), dir) {
		t.Fatalf("LoadFile read error leaks the input path: %v", err)
	}

	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat(" ", MaxConfigBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(oversized); ConfigReason(err) != ReasonInputTooLarge {
		t.Fatalf("LoadFile(oversized) = %v, want AIPT_CONFIG_INPUT_TOO_LARGE", err)
	}
}
