// Package protocol is the dependency-free Go consumer of the canonical AIPT
// wire contract (AIPT-M0-B002, iterations 5/5B/5C).
//
// It is a bounded, pure protocol package: it decodes and validates documents
// against the canonical schema at
// schemas/protocol/v1/aipt-protocol.schema.json (the single wire authority,
// which this package never copies or edits), provides strict fail-closed
// JSON-RPC 2.0 envelope decoding, deterministic canonical JSON / SHA-256
// hashing compatible with the independent Node protocol-assets oracle, and
// the pure semantic helpers of the shared minimal fixture contract
// (visibility, projection, deterministic check, state transition, replay).
//
// It deliberately contains no runtime, authorization/rules engine, service,
// launcher, or adapter code: no file I/O, environment access, process
// spawning, network or sockets, database, service loop, goroutine worker,
// model call, ledger, persistence, or UI. All functions take bytes or typed
// values and return typed values or typed contract errors carrying stable
// AIPT reason codes.
//
// Iteration 5C exactness guarantees: string RequestIDs keep their exact
// JavaScript string value (lone UTF-16 surrogate units included) as their
// canonical quoted JSON text, NewStringID rejects invalid UTF-8 instead of
// rewriting it, and CheckProjection gates source-state metadata
// (missing/duplicate fields, unknown authorized seats) before any
// projection-specific reason.
package protocol
