// Package orchestrator implements the provider-neutral, deterministic Agent
// orchestration layer for one game-neutral Run. It owns seat, session, floor,
// visibility, context, retry, and recovery protocol state only. Gameplay state
// remains authoritative in runcore and can change only through ActionProposal.
package orchestrator
