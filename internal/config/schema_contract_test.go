package config

// Schema contract tests: the canonical JSON Schema 2020-12 artifact
// (schemas/config/v1/aipt-config.schema.json) must match the frozen Go
// contract exactly — marker const, profile enum, required members,
// additionalProperties=false recursively, identifier patterns, DSN length,
// and ping bounds — and must stay inside the dependency-free subset the
// repository's own schema tooling implements (scripts/ci/lib/json-schema.mjs).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const schemaPath = "../../schemas/config/v1/aipt-config.schema.json"

const metaSchemaURI = "https://json-schema.org/draft/2020-12/schema"

// supportedKeywords is the explicit B002 subset (validation keywords) plus
// the permitted annotations and structural keywords; the artifact may use no
// other keyword.
var supportedKeywords = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true,
	"title": true, "description": true,
	"type": true, "const": true, "enum": true,
	"properties": true, "required": true, "additionalProperties": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true,
}

func loadSchemaDoc(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(schemaPath))
	if err != nil {
		t.Fatalf("read schema artifact: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("schema artifact is not valid JSON: %v", err)
	}
	return doc
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON object, got %T", v)
	}
	return m
}

func asString(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("expected a string, got %T", v)
	}
	return s
}

func asFloat(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("expected a number, got %T", v)
	}
	return f
}

// walkSchemas visits schema objects, not the name-to-schema container maps
// under properties and $defs.
func walkSchemas(v any, visit func(map[string]any)) {
	node, ok := v.(map[string]any)
	if !ok {
		return
	}
	visit(node)
	for _, containerKey := range []string{"properties", "$defs"} {
		container, ok := node[containerKey].(map[string]any)
		if !ok {
			continue
		}
		for _, child := range container {
			walkSchemas(child, visit)
		}
	}
}

func TestSchemaArtifactRootContract(t *testing.T) {
	doc := loadSchemaDoc(t)

	if got := asString(t, doc["$schema"]); got != metaSchemaURI {
		t.Errorf("$schema = %q, want %q", got, metaSchemaURI)
	}
	if got := asString(t, doc["$id"]); got != "https://github.com/zyc14588/AIPT/schemas/config/v1/aipt-config.schema.json" {
		t.Errorf("$id = %q", got)
	}
	if got := asString(t, doc["type"]); got != "object" {
		t.Errorf("root type = %q, want object", got)
	}
	if doc["additionalProperties"] != false {
		t.Errorf("root additionalProperties = %v, want false", doc["additionalProperties"])
	}

	rootRequired := []any{"schema", "profile", "database", "evidence"}
	if got := doc["required"]; !reflect.DeepEqual(got, rootRequired) {
		t.Errorf("root required = %v, want %v", got, rootRequired)
	}

	props := asMap(t, doc["properties"])
	if got := asMap(t, props["schema"])["const"]; got != SchemaMarker {
		t.Errorf("schema const = %v, want %q", got, SchemaMarker)
	}
	profile := asMap(t, props["profile"])
	wantEnum := []any{string(ProfileDevelopment), string(ProfileProduction)}
	if got := profile["enum"]; !reflect.DeepEqual(got, wantEnum) {
		t.Errorf("profile enum = %v, want %v", got, wantEnum)
	}
	if got := asMap(t, props["database"])["$ref"]; got != "#/$defs/database" {
		t.Errorf("database $ref = %v", got)
	}
	if got := asMap(t, props["evidence"])["$ref"]; got != "#/$defs/evidence" {
		t.Errorf("evidence $ref = %v", got)
	}
}

func TestSchemaArtifactDefsContract(t *testing.T) {
	doc := loadSchemaDoc(t)
	defs := asMap(t, doc["$defs"])

	db := asMap(t, defs["database"])
	if got := asString(t, db["type"]); got != "object" {
		t.Errorf("database type = %q", got)
	}
	if db["additionalProperties"] != false {
		t.Errorf("database additionalProperties = %v, want false", db["additionalProperties"])
	}
	wantRequired := []any{"dsn", "identity", "namespace", "ping_timeout_ms"}
	if got := db["required"]; !reflect.DeepEqual(got, wantRequired) {
		t.Errorf("database required = %v, want %v", got, wantRequired)
	}
	dbProps := asMap(t, db["properties"])

	dsn := asMap(t, dbProps["dsn"])
	if got := asString(t, dsn["type"]); got != "string" {
		t.Errorf("dsn type = %q", got)
	}
	if got := asFloat(t, dsn["minLength"]); got != 1 {
		t.Errorf("dsn minLength = %v", got)
	}
	if got := asFloat(t, dsn["maxLength"]); got != float64(MaxDSNLength) {
		t.Errorf("dsn maxLength = %v, want %d", got, MaxDSNLength)
	}

	identity := asMap(t, dbProps["identity"])
	if got := asString(t, identity["pattern"]); got != PatternIdentity {
		t.Errorf("identity pattern = %q, want %q", got, PatternIdentity)
	}
	namespace := asMap(t, dbProps["namespace"])
	if got := asString(t, namespace["pattern"]); got != PatternNamespace {
		t.Errorf("namespace pattern = %q, want %q", got, PatternNamespace)
	}

	ping := asMap(t, dbProps["ping_timeout_ms"])
	if got := asString(t, ping["type"]); got != "integer" {
		t.Errorf("ping_timeout_ms type = %q, want integer", got)
	}
	if got := asFloat(t, ping["minimum"]); got != float64(MinPingTimeoutMS) {
		t.Errorf("ping_timeout_ms minimum = %v, want %d", got, MinPingTimeoutMS)
	}
	if got := asFloat(t, ping["maximum"]); got != float64(MaxPingTimeoutMS) {
		t.Errorf("ping_timeout_ms maximum = %v, want %d", got, MaxPingTimeoutMS)
	}

	ev := asMap(t, defs["evidence"])
	if got := asString(t, ev["type"]); got != "object" {
		t.Errorf("evidence type = %q", got)
	}
	if ev["additionalProperties"] != false {
		t.Errorf("evidence additionalProperties = %v, want false", ev["additionalProperties"])
	}
	if got := ev["required"]; !reflect.DeepEqual(got, []any{"namespace"}) {
		t.Errorf("evidence required = %v, want [namespace]", got)
	}
	evNamespace := asMap(t, asMap(t, ev["properties"])["namespace"])
	if got := asString(t, evNamespace["pattern"]); got != PatternEvidenceNamespace {
		t.Errorf("evidence namespace pattern = %q, want %q", got, PatternEvidenceNamespace)
	}
	if got := asFloat(t, evNamespace["minLength"]); got != 1 {
		t.Errorf("evidence namespace minLength = %v", got)
	}
	if got := asFloat(t, evNamespace["maxLength"]); got != float64(MaxEvidenceNamespaceLength) {
		t.Errorf("evidence namespace maxLength = %v", got)
	}
}

// TestSchemaArtifactRecursiveAdditionalProperties walks every object node of
// the artifact: each node that declares properties (an object schema) must
// also declare additionalProperties=false and type=object, so unknown fields
// fail closed recursively at every level.
func TestSchemaArtifactRecursiveAdditionalProperties(t *testing.T) {
	doc := loadSchemaDoc(t)
	walkSchemas(doc, func(node map[string]any) {
		if _, hasProps := node["properties"]; !hasProps {
			return
		}
		if got := node["additionalProperties"]; got != false {
			t.Errorf("object schema with properties has additionalProperties = %v, want false (node: %v)", got, node)
		}
		if got := node["type"]; got != "object" {
			t.Errorf("object schema with properties has type = %v, want object", got)
		}
	})
}

// TestSchemaArtifactSupportedKeywords proves the artifact stays inside the
// dependency-free subset the repository's own schema tooling implements:
// any unsupported functional keyword would be rejected by that tooling and
// fails this test.
func TestSchemaArtifactSupportedKeywords(t *testing.T) {
	doc := loadSchemaDoc(t)
	walkSchemas(doc, func(node map[string]any) {
		for key := range node {
			if !supportedKeywords[key] {
				t.Errorf("schema artifact uses unsupported keyword %q", key)
			}
		}
	})
}

// TestSchemaArtifactGoPatternsMatchSchema proves the frozen Go pattern
// constants accept exactly the documented shape and reject a representative
// battery of invalid values, so the Go contract and the schema artifact
// cannot drift apart in behavior.
func TestSchemaArtifactGoPatternsMatchSchema(t *testing.T) {
	valid := []string{
		"aipt_development", "aipt_prod", "aipt", "a", "_x",
	}
	invalid := []string{
		"", "AIPT_DEV", "aipt-dev", "1aipt", "aipt.dev", "a b", "a.",
	}
	for _, s := range valid {
		if !reIdentity.MatchString(s) {
			t.Errorf("reIdentity rejects valid %q", s)
		}
	}
	for _, s := range invalid {
		if reIdentity.MatchString(s) {
			t.Errorf("reIdentity accepts invalid %q", s)
		}
	}

	evValid := []string{
		"aipt.evidence.development", "aipt_evidence_dev", "a", "a-b.c_d",
	}
	evInvalid := []string{
		"", "AIPT.EVIDENCE.DEV", "9aipt", "a b", "Bad Namespace!", ".a", "a..", "a-", "a.-b",
	}
	for _, s := range evValid {
		if !reEvidenceNamespace.MatchString(s) {
			t.Errorf("reEvidenceNamespace rejects valid %q", s)
		}
	}
	for _, s := range evInvalid {
		if reEvidenceNamespace.MatchString(s) {
			t.Errorf("reEvidenceNamespace accepts invalid %q", s)
		}
	}
	if got := strings.Repeat("a", MaxEvidenceNamespaceLength+1); !reEvidenceNamespace.MatchString(got) {
		t.Fatalf("test precondition: semantic regexp should leave length enforcement to the explicit bound")
	}
}
