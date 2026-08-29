package runcore

import (
	"context"
	"errors"
	"fmt"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

// Replay verifies the ledger chain and every Run-level transition before
// returning a final state. It never attempts repair or partial recovery.
func (c *Core) Replay(ctx context.Context, input ReplayInput) (ReplayResult, error) {
	const operation = "replay"
	runID := input.Binding.RunID
	if c == nil || ctx == nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", errors.New("nil Core or context"))
	}
	if err := ctx.Err(); err != nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
	}
	if err := validateBinding(input.Binding); err != nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
	}
	if err := validSeed(input.Seed); err != nil {
		return ReplayResult{}, coreError(CodeRNGInvalid, operation, runID, "", err)
	}
	if err := validSHA256("expected_final_state_hash", input.ExpectedFinalStateHash); err != nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
	}
	events := cloneLedgerEvents(input.Events)
	if err := storagepostgres.VerifyLedgerEvents(events); err != nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
	}
	expectedStream := runStreamID(runID)
	seenActions := make(map[string]struct{}, len(events))
	var state RunState
	for index, stored := range events {
		if err := ctx.Err(); err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
		}
		if stored.StreamID != expectedStream {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", errors.New("wrong Run stream"))
		}
		event, err := decodeRunEvent(stored.PayloadCanonical)
		if err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
		}
		if err := validateEventEnvelope(event); err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", err)
		}
		if event.Sequence != stored.Sequence || event.RunID != runID || !equalCanonical(event.Binding, input.Binding) ||
			event.AfterState.Binding.RunID != runID || !equalCanonical(event.Binding, event.AfterState.Binding) {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", errors.New("event binding or sequence mismatch"))
		}
		if event.SeedCommitment != event.AfterState.SeedCommitment || event.RNGVersion != event.AfterState.RNGVersion ||
			event.CommitmentVersion != event.AfterState.CommitmentVersion {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", errors.New("event algorithm binding mismatch"))
		}
		if index == 0 {
			if stored.EventID != startEventID(runID) || stored.EventType != RunStartedEventType ||
				event.Kind != RunStartedEventType || event.Sequence != 1 || event.Action != nil || event.BeforeStateHash != "" {
				return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", errors.New("invalid genesis event"))
			}
			if !VerifySeedCommitment(input.Binding, input.Seed, event.SeedCommitment) {
				return ReplayResult{}, coreError(CodeRNGCommitmentMismatch, operation, runID, "", errors.New("seed commitment mismatch"))
			}
			if err := c.validateReplayState(event.AfterState, event.AfterStateHash); err != nil {
				return ReplayResult{}, coreError(CodeInvariantViolation, operation, runID, "", err)
			}
			state = cloneState(event.AfterState)
			continue
		}

		if event.Kind != ActionEventType || stored.EventType != ActionEventType || event.Action == nil ||
			event.Sequence != state.Sequence+1 {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, "", errors.New("invalid action event envelope"))
		}
		action := event.Action
		proposal := action.Proposal
		if err := validateProposal(proposal); err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, err)
		}
		if err := validateRuleSource(proposal.Source); err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, err)
		}
		if proposal.RunID != runID || proposal.ExpectedSequence != state.Sequence {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, errors.New("proposal Run or sequence mismatch"))
		}
		if stored.EventID != actionEventID(runID, proposal.ActionID) {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, errors.New("event/action identity mismatch"))
		}
		if _, duplicate := seenActions[proposal.ActionID]; duplicate {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, errors.New("duplicate action"))
		}
		seenActions[proposal.ActionID] = struct{}{}
		proposalCanonical, err := canonicalValue(proposal)
		if err != nil || action.ProposalSHA256 != hashBytes(proposalCanonical) {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, errors.New("proposal digest mismatch"))
		}
		beforeHash, _ := stateHash(state)
		if event.BeforeStateHash != beforeHash {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, errors.New("before-state hash mismatch"))
		}
		handler, exists := c.handlers[proposal.ActionType]
		if !exists {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, errors.New("unknown replay action type"))
		}
		if err := handler.ValidatePayload(cloneProposal(proposal)); err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, err)
		}
		if err := handler.ValidatePrecondition(ctx, cloneState(state), cloneProposal(proposal)); err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, err)
		}
		draws, cursors, err := consumeRNG(input.Seed, state, proposal.RNGRequests)
		if err != nil {
			return ReplayResult{}, coreError(CodeRNGInvalid, operation, runID, proposal.ActionID, err)
		}
		if !equalCanonical(draws, action.RNGDraws) {
			return ReplayResult{}, coreError(CodeRNGInvalid, operation, runID, proposal.ActionID, errors.New("RNG evidence mismatch"))
		}
		for _, draw := range action.RNGDraws {
			if err := validateDraw(draw); err != nil {
				return ReplayResult{}, coreError(CodeRNGInvalid, operation, runID, proposal.ActionID, err)
			}
		}
		domain, err := handler.Apply(ctx, cloneState(state), cloneProposal(proposal), append([]RNGDraw(nil), draws...))
		if err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, err)
		}
		domain, err = canonicalRaw(domain)
		if err != nil {
			return ReplayResult{}, coreError(CodeReplayInvalid, operation, runID, proposal.ActionID, err)
		}
		expected := RunState{
			Schema: RunStateSchema, Binding: state.Binding, Sequence: state.Sequence + 1,
			RNGVersion: state.RNGVersion, CommitmentVersion: state.CommitmentVersion,
			SeedCommitment: state.SeedCommitment, RNGCursors: cursors, DomainState: domain,
		}
		if !equalCanonical(expected, event.AfterState) {
			return ReplayResult{}, coreError(CodeReplayStateMismatch, operation, runID, proposal.ActionID, errors.New("replayed transition differs from event state"))
		}
		if err := c.validateReplayState(expected, event.AfterStateHash); err != nil {
			return ReplayResult{}, coreError(CodeInvariantViolation, operation, runID, proposal.ActionID, err)
		}
		state = cloneState(expected)
	}
	finalHash, err := stateHash(state)
	if err != nil || finalHash != input.ExpectedFinalStateHash {
		return ReplayResult{}, coreError(CodeReplayStateMismatch, operation, runID, "", fmt.Errorf("final state mismatch"))
	}
	projection, err := Project(state)
	if err != nil {
		return ReplayResult{}, coreError(CodeInvariantViolation, operation, runID, "", err)
	}
	return ReplayResult{State: cloneState(state), StateHash: finalHash, EventCount: len(events), ProjectionHash: projection.SHA256}, nil
}

func (c *Core) validateReplayState(state RunState, claimedHash string) error {
	if err := c.validateInvariants(state); err != nil {
		return err
	}
	actual, err := stateHash(state)
	if err != nil {
		return err
	}
	if actual != claimedHash {
		return errors.New("claimed state hash mismatch")
	}
	return nil
}

// ReplayStored loads the complete authoritative PostgreSQL/event-store stream
// and then runs the same strict replay gate.
func (c *Core) ReplayStored(ctx context.Context, binding RunBinding, seed []byte, expectedFinalStateHash string) (ReplayResult, error) {
	if c == nil || c.store == nil || ctx == nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, "replay_stored", binding.RunID, "", errors.New("nil Core, store, or context"))
	}
	if err := ctx.Err(); err != nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, "replay_stored", binding.RunID, "", err)
	}
	events, err := c.store.Load(ctx, runStreamID(binding.RunID))
	if err != nil {
		return ReplayResult{}, coreError(CodeReplayInvalid, "replay_stored", binding.RunID, "", err)
	}
	return c.Replay(ctx, ReplayInput{Binding: binding, Seed: seed, Events: events, ExpectedFinalStateHash: expectedFinalStateHash})
}

func cloneLedgerEvents(events []storagepostgres.LedgerEvent) []storagepostgres.LedgerEvent {
	out := make([]storagepostgres.LedgerEvent, len(events))
	copy(out, events)
	for i := range out {
		if events[i].PrevEventHash != nil {
			previous := *events[i].PrevEventHash
			out[i].PrevEventHash = &previous
		}
	}
	return out
}
