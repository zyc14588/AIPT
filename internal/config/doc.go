// Package config is the dependency-free strict shared configuration service
// of AIPT (AIPT-M0-B004, leaf 2). It implements the frozen configuration
// contract that the Web UI and the CLI/Launcher share (R7-Q001) and the
// development/production isolation rules (R7-Q007).
//
// # Frozen contract (aipt.config/v1)
//
// Every configuration document is a strict JSON object carrying the schema
// marker "aipt.config/v1", a profile from the frozen two-value enum
// development|production, a required database object, and a required evidence
// object. The database object carries a URI-form PostgreSQL DSN, an explicit
// database identity, an SQL namespace, and a positive bounded
// ping_timeout_ms. The evidence object carries an explicit namespace. The
// canonical schema artifact is
// schemas/config/v1/aipt-config.schema.json (JSON Schema 2020-12,
// additionalProperties=false recursively); internal/config is its Go
// consumer and the schema-drift test keeps the two in lockstep.
//
// # Fail-closed loading
//
// Load and LoadFile validate the whole document before producing a value.
// Unknown fields at every level, missing/null required fields, trailing JSON,
// malformed or duplicate JSON members, invalid enum/format/range values, DSN
// scheme/host/database mismatches, and oversized input all fail closed with a
// typed *ConfigError carrying a stable AIPT_CONFIG_* reason code, the JSON
// path of the offending member, and a deterministic detail. Error text never
// contains the value of any input field — in particular the DSN and any
// credential never appear in any error, String, JSON, or redacted rendering
// (member names appear in paths only as structural location). Load applies no
// implicit defaults: every required field must be present in the document,
// and a production document never inherits development values.
//
// # DSN privacy and the launcher accessor
//
// The raw DSN is private to the database value. The only way to read it is
// the explicit Database.DSN method, reserved for the launcher; every other
// rendering (Config.String, fmt, json.Marshal, Config.Redacted) emits
// [REDACTED] in its place.
//
// # Isolation
//
// ValidateIsolation checks one development and one production configuration
// and rejects any collision of database identity, database namespace, or
// evidence namespace.
//
// The package is deliberately pure: no file I/O except LoadFile, no
// environment access, no network, no database, no goroutines, and no
// dependencies beyond the Go standard library.
package config
