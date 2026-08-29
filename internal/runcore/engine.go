package runcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
)

const eventVersion = 1

type committedAction struct {
	Proposal       ActionProposal `json:"proposal"`
	ProposalSHA256 string         `json:"proposal_sha256"`
	RNGDraws       []RNGDraw      `json:"rng_draws"`
}

type runEvent struct {
	Schema            string           `json:"schema"`
	Version           int              `json:"version"`
	Kind              string           `json:"kind"`
	RunID             string           `json:"run_id"`
	Sequence          int64            `json:"sequence"`
	Binding           RunBinding       `json:"binding"`
	RNGVersion        string           `json:"rng_version"`
	CommitmentVersion string           `json:"commitment_version"`
	SeedCommitment    string           `json:"seed_commitment"`
	BeforeStateHash   string           `json:"before_state_hash,omitempty"`
	AfterState        RunState         `json:"after_state"`
	AfterStateHash    string           `json:"after_state_hash"`
	Action            *committedAction `json:"action,omitempty"`
}

// Core is immutable configuration shared by Runs.
type Core struct {
	store      EventStore
	seeds      SeedSource
	authorizer Authorizer
	rules      RuleValidator
	handlers   map[string]ActionHandler
	invariants []Invariant
}

// Run holds only a derived in-memory state and private seed copy. The event
// store remains authoritative; state changes only after a successful append.
type Run struct {
	mu    sync.Mutex
	core  *Core
	state RunState
	seed  []byte
}

func New(config Config) (*Core, error) {
	if config.Store == nil || config.Authorizer == nil || config.Rules == nil {
		return nil, coreError(CodeInvalidAction, "new", "", "", errors.New("store, authorizer, and rules are required"))
	}
	if config.SeedSource == nil {
		config.SeedSource = CryptoSeedSource{}
	}
	if len(config.Handlers) == 0 {
		return nil, coreError(CodeInvalidAction, "new", "", "", errors.New("at least one action handler is required"))
	}
	handlers := make(map[string]ActionHandler, len(config.Handlers))
	for actionType, handler := range config.Handlers {
		if err := validIdentity("action_type", actionType); err != nil || handler == nil {
			return nil, coreError(CodeInvalidAction, "new", "", "", errors.New("invalid handler registration"))
		}
		handlers[actionType] = handler
	}
	invariants := append([]Invariant(nil), config.Invariants...)
	for _, invariant := range invariants {
		if invariant == nil {
			return nil, coreError(CodeInvalidAction, "new", "", "", errors.New("nil invariant"))
		}
	}
	return &Core{
		store: config.Store, seeds: config.SeedSource, authorizer: config.Authorizer,
		rules: config.Rules, handlers: handlers, invariants: invariants,
	}, nil
}

// StartRun binds immutable inputs, obtains an injected root seed, fixes its
// commitment before any draw, and commits the complete initial state as the
// genesis authoritative event.
func (c *Core) StartRun(ctx context.Context, input StartRunInput) (*Run, Receipt, error) {
	const operation = "start_run"
	if c == nil || ctx == nil {
		return nil, Receipt{}, coreError(CodeInvalidAction, operation, input.Binding.RunID, "", errors.New("nil Core or context"))
	}
	if err := ctx.Err(); err != nil {
		return nil, Receipt{}, coreError(CodeStateConflict, operation, input.Binding.RunID, "", err)
	}
	if err := validateBinding(input.Binding); err != nil {
		return nil, Receipt{}, coreError(CodeInvalidAction, operation, input.Binding.RunID, "", err)
	}
	initial, err := canonicalRaw(input.InitialState)
	if err != nil {
		return nil, Receipt{}, coreError(CodeInvalidAction, operation, input.Binding.RunID, "", err)
	}
	seed, err := c.seeds.RootSeed(ctx, input.Binding)
	if err != nil {
		return nil, Receipt{}, coreError(CodeRNGInvalid, operation, input.Binding.RunID, "", err)
	}
	if err := validSeed(seed); err != nil {
		return nil, Receipt{}, coreError(CodeRNGInvalid, operation, input.Binding.RunID, "", err)
	}
	seed = append([]byte(nil), seed...)
	commitment, err := seedCommitment(input.Binding, seed)
	if err != nil {
		return nil, Receipt{}, coreError(CodeRNGInvalid, operation, input.Binding.RunID, "", err)
	}
	state := RunState{
		Schema: RunStateSchema, Binding: input.Binding, Sequence: 1,
		RNGVersion: RNGVersionV1, CommitmentVersion: SeedCommitmentV1,
		SeedCommitment: commitment, RNGCursors: map[string]int64{}, DomainState: initial,
	}
	if err := c.validateInvariants(state); err != nil {
		return nil, Receipt{}, coreError(CodeInvariantViolation, operation, input.Binding.RunID, "", err)
	}
	afterHash, err := stateHash(state)
	if err != nil {
		return nil, Receipt{}, coreError(CodeInvariantViolation, operation, input.Binding.RunID, "", err)
	}
	event := runEvent{
		Schema: RunEventSchema, Version: eventVersion, Kind: RunStartedEventType,
		RunID: input.Binding.RunID, Sequence: 1, Binding: input.Binding,
		RNGVersion: RNGVersionV1, CommitmentVersion: SeedCommitmentV1,
		SeedCommitment: commitment, AfterState: cloneState(state), AfterStateHash: afterHash,
	}
	payload, err := canonicalValue(event)
	if err != nil {
		return nil, Receipt{}, coreError(CodeInvalidAction, operation, input.Binding.RunID, "", err)
	}
	stored, err := c.store.Append(ctx, AppendRequest{
		StreamID: runStreamID(input.Binding.RunID), ExpectedSequence: 0,
		EventID: startEventID(input.Binding.RunID), EventType: RunStartedEventType, Payload: payload,
	})
	if err != nil {
		return nil, Receipt{}, c.appendError(operation, input.Binding.RunID, "", err)
	}
	if stored.Sequence != 1 || stored.EventType != RunStartedEventType || stored.PayloadCanonical != string(payload) {
		return nil, Receipt{}, coreError(CodeLedgerCommitFailed, operation, input.Binding.RunID, "", errors.New("event store returned inconsistent genesis"))
	}
	projection, err := Project(state)
	if err != nil {
		return nil, Receipt{}, coreError(CodeInvariantViolation, operation, input.Binding.RunID, "", err)
	}
	run := &Run{core: c, state: cloneState(state), seed: seed}
	receipt := receiptFor(input.Binding.RunID, "RUN_STARTED", stored.Sequence, stored.EventHash, afterHash, projection.SHA256, nil)
	return run, receipt, nil
}

// Execute runs the complete fail-closed action transaction. No derived state,
// RNG cursor, projection, or receipt is advanced unless the authoritative
// append succeeds.
func (r *Run) Execute(ctx context.Context, rawProposal []byte) (Receipt, error) {
	const operation = "execute_action"
	if r == nil || r.core == nil || ctx == nil {
		return Receipt{}, coreError(CodeInvalidAction, operation, "", "", errors.New("nil Run or context"))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current := cloneState(r.state)
	if err := ctx.Err(); err != nil {
		return Receipt{}, coreError(CodeStateConflict, operation, current.Binding.RunID, "", err)
	}
	proposal, proposalCanonical, err := decodeProposal(rawProposal)
	if err != nil {
		return Receipt{}, coreError(CodeInvalidAction, operation, current.Binding.RunID, "", err)
	}
	if proposal.RunID != current.Binding.RunID {
		return Receipt{}, coreError(CodeStateConflict, operation, current.Binding.RunID, proposal.ActionID, errors.New("cross-Run proposal"))
	}
	handler, exists := r.core.handlers[proposal.ActionType]
	if !exists {
		return Receipt{}, coreError(CodeInvalidAction, operation, current.Binding.RunID, proposal.ActionID, errors.New("unknown action type"))
	}
	if err := handler.ValidatePayload(cloneProposal(proposal)); err != nil {
		return Receipt{}, coreError(CodeInvalidAction, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if err := r.core.authorizer.Authorize(ctx, cloneState(current), cloneProposal(proposal)); err != nil {
		return Receipt{}, coreError(CodeUnauthorizedAction, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if err := validateRuleSource(proposal.Source); err != nil {
		return Receipt{}, coreError(CodeRuleReferenceRequired, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if err := r.core.rules.ValidateRuleSource(ctx, cloneState(current), cloneProposal(proposal)); err != nil {
		return Receipt{}, coreError(CodeRuleValidationFailed, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if proposal.ExpectedSequence != current.Sequence {
		return Receipt{}, coreError(CodeStateConflict, operation, current.Binding.RunID, proposal.ActionID, errors.New("stale authoritative sequence"))
	}
	if err := handler.ValidatePrecondition(ctx, cloneState(current), cloneProposal(proposal)); err != nil {
		return Receipt{}, coreError(CodeStateConflict, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if err := r.core.validateInvariants(current); err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}

	draws, nextCursors, err := consumeRNG(r.seed, current, proposal.RNGRequests)
	if err != nil {
		return Receipt{}, coreError(CodeRNGInvalid, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, coreError(CodeStateConflict, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	nextDomain, err := handler.Apply(ctx, cloneState(current), cloneProposal(proposal), append([]RNGDraw(nil), draws...))
	if err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	nextDomain, err = canonicalRaw(nextDomain)
	if err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	next := RunState{
		Schema: RunStateSchema, Binding: current.Binding, Sequence: current.Sequence + 1,
		RNGVersion: current.RNGVersion, CommitmentVersion: current.CommitmentVersion,
		SeedCommitment: current.SeedCommitment, RNGCursors: nextCursors, DomainState: nextDomain,
	}
	if err := r.core.validateInvariants(next); err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	beforeHash, _ := stateHash(current)
	afterHash, err := stateHash(next)
	if err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	event := runEvent{
		Schema: RunEventSchema, Version: eventVersion, Kind: ActionEventType,
		RunID: current.Binding.RunID, Sequence: next.Sequence, Binding: current.Binding,
		RNGVersion: current.RNGVersion, CommitmentVersion: current.CommitmentVersion,
		SeedCommitment: current.SeedCommitment, BeforeStateHash: beforeHash,
		AfterState: cloneState(next), AfterStateHash: afterHash,
		Action: &committedAction{Proposal: cloneProposal(proposal), ProposalSHA256: hashBytes(proposalCanonical), RNGDraws: append([]RNGDraw(nil), draws...)},
	}
	payload, err := canonicalValue(event)
	if err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	stored, err := r.core.store.Append(ctx, AppendRequest{
		StreamID: runStreamID(current.Binding.RunID), ExpectedSequence: current.Sequence,
		EventID: actionEventID(current.Binding.RunID, proposal.ActionID), EventType: ActionEventType, Payload: payload,
	})
	if err != nil {
		return Receipt{}, r.core.appendError(operation, current.Binding.RunID, proposal.ActionID, err)
	}
	if stored.Sequence != next.Sequence || stored.EventType != ActionEventType || stored.PayloadCanonical != string(payload) {
		return Receipt{}, coreError(CodeLedgerCommitFailed, operation, current.Binding.RunID, proposal.ActionID, errors.New("event store returned inconsistent append"))
	}
	projection, err := Project(next)
	if err != nil {
		return Receipt{}, coreError(CodeInvariantViolation, operation, current.Binding.RunID, proposal.ActionID, err)
	}
	// This is the only live-state mutation and it occurs after commit.
	r.state = cloneState(next)
	return receiptFor(current.Binding.RunID, proposal.ActionID, stored.Sequence, stored.EventHash, afterHash, projection.SHA256, draws), nil
}

func (r *Run) State() RunState {
	if r == nil {
		return RunState{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneState(r.state)
}

// ResumeRun reconstructs a live derived state from the authoritative store.
// The expected final hash makes truncation fail closed, and the supplied seed
// must verify the committed seed commitment before the Run can consume draws.
func (c *Core) ResumeRun(ctx context.Context, binding RunBinding, seed []byte, expectedFinalStateHash string) (*Run, error) {
	replayed, err := c.ReplayStored(ctx, binding, seed, expectedFinalStateHash)
	if err != nil {
		return nil, err
	}
	return &Run{core: c, state: cloneState(replayed.State), seed: append([]byte(nil), seed...)}, nil
}

func (c *Core) validateInvariants(state RunState) error {
	if err := validateState(state); err != nil {
		return err
	}
	for _, invariant := range c.invariants {
		if err := invariant.Validate(cloneState(state)); err != nil {
			return err
		}
	}
	return nil
}

func consumeRNG(seed []byte, state RunState, requests []RNGRequest) ([]RNGDraw, map[string]int64, error) {
	if state.RNGVersion != RNGVersionV1 {
		return nil, nil, errors.New("unknown RNG version")
	}
	if err := validateRNGRequests(requests); err != nil {
		return nil, nil, err
	}
	cursors := make(map[string]int64, len(state.RNGCursors)+len(requests))
	for key, value := range state.RNGCursors {
		cursors[key] = value
	}
	var draws []RNGDraw
	for _, request := range requests {
		cursor := cursors[request.StreamID]
		if cursor > maxSafeJSONInteger-int64(request.Count) {
			return nil, nil, errors.New("RNG cursor exhausted")
		}
		for range request.Count {
			cursor++
			value, err := deterministicDraw(seed, state.Binding.RunID, request.StreamID, cursor)
			if err != nil {
				return nil, nil, err
			}
			draws = append(draws, RNGDraw{Version: RNGVersionV1, StreamID: request.StreamID, DrawIndex: cursor, ValueHex: value})
		}
		cursors[request.StreamID] = cursor
	}
	return draws, cursors, nil
}

func receiptFor(runID, actionID string, sequence int64, eventHash [32]byte, stateHashValue, projectionHash string, draws []RNGDraw) Receipt {
	return Receipt{
		Schema: ActionReceiptSchema, RunID: runID, ActionID: actionID,
		Sequence: sequence, EventHash: hex.EncodeToString(eventHash[:]), StateHash: stateHashValue,
		ProjectionHash: projectionHash, RNGDraws: append([]RNGDraw(nil), draws...),
	}
}

func (c *Core) appendError(operation, runID, actionID string, err error) error {
	if errors.Is(err, errStoreConflict) {
		return coreError(CodeStateConflict, operation, runID, actionID, err)
	}
	return coreError(CodeLedgerCommitFailed, operation, runID, actionID, err)
}

func cloneProposal(proposal ActionProposal) ActionProposal {
	copy := proposal
	copy.Payload = append(json.RawMessage(nil), proposal.Payload...)
	copy.RNGRequests = append([]RNGRequest(nil), proposal.RNGRequests...)
	if proposal.TemporaryRuling != nil {
		ruling := *proposal.TemporaryRuling
		copy.TemporaryRuling = &ruling
	}
	return copy
}

func runStreamID(runID string) string { return "aipt.run-core:" + runID }

func startEventID(runID string) string {
	return eventID("RUN_STARTED", runID, "")
}

func actionEventID(runID, actionID string) string {
	return eventID("ACTION_COMMITTED", runID, actionID)
}

// eventID uses length-delimited, domain-separated fields rather than string
// concatenation. Caller-controlled ':' characters therefore cannot create an
// identity collision between a Run-start event and an action from another
// Run, or between two different (Run, action) pairs.
func eventID(kind, runID, actionID string) string {
	h := sha256.New()
	writeCommitmentField(h, []byte("AIPT_RUN_EVENT_ID_SHA256_V1"))
	writeCommitmentField(h, []byte(kind))
	writeCommitmentField(h, []byte(runID))
	writeCommitmentField(h, []byte(actionID))
	return "aipt.run-core:event:v1:" + hex.EncodeToString(h.Sum(nil))
}

func decodeRunEvent(payload string) (runEvent, error) {
	canonical, err := canonicalRaw(json.RawMessage(payload))
	if err != nil || !bytes.Equal(canonical, []byte(payload)) {
		return runEvent{}, errors.New("event payload is not canonical")
	}
	var event runEvent
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return runEvent{}, err
	}
	return event, nil
}

func validateEventEnvelope(event runEvent) error {
	if event.Schema != RunEventSchema || event.Version != eventVersion {
		return errors.New("unknown event schema or version")
	}
	if event.Kind != RunStartedEventType && event.Kind != ActionEventType {
		return errors.New("unknown event kind")
	}
	if event.Sequence < 1 || event.Sequence > maxSafeJSONInteger || event.RunID == "" {
		return errors.New("invalid event identity or sequence")
	}
	if event.RNGVersion != RNGVersionV1 || event.CommitmentVersion != SeedCommitmentV1 {
		return errors.New("unknown event RNG or commitment version")
	}
	if err := validSHA256("seed_commitment", event.SeedCommitment); err != nil {
		return err
	}
	if err := validSHA256("after_state_hash", event.AfterStateHash); err != nil {
		return err
	}
	if event.BeforeStateHash != "" {
		if err := validSHA256("before_state_hash", event.BeforeStateHash); err != nil {
			return err
		}
	}
	return nil
}
