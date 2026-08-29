// Package runcore implements the game-neutral AIPT deterministic Run Core.
//
// Callers submit versioned action proposals only. The Core owns validation,
// authorization, rule/source checks, optimistic state preconditions,
// invariants, deterministic RNG consumption, authoritative ledger commits,
// projections, receipts, and replay. It contains no Agent orchestration,
// model gateway, persistent session, game-specific Rule ID, or real-playtest
// path.
package runcore
