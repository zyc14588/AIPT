// Package protocol is the dependency-free Go consumer of the canonical AIPT
// wire contract (AIPT-M0-B002, iteration 5B).
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
package protocol
