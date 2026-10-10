package pilot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcore"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const (
	Task0RuntimeAdapterSHA          = "2d8346b616726c1466d0abe48510d657008a1447712e789dc47ae94f4b941133"
	Task0RuntimeAdapterCanonicalSHA = "b8eb4801b58d6e340165ece8035f9af972db792be71f7aeecfe45439e19a8f31"
	Task0GameGatewaySHA             = "805e82a71d16f974e209ab0d3b8d8ae3d5f273239b1f96e3f31bc6d4cfb648a2"
)

var ErrTask0 = errors.New("B007 authenticated Task0 operation rejected")

// This seam belongs to private capsule plumbing and model-free tests. The
// enclosing production entry must construct its concrete accepted runtime;
// neither CLI input nor a model response can provide an executor.
type task0GameExecutor interface {
	invoke(context.Context, string, map[string]any) (json.RawMessage, error)
}

type task0Frame struct {
	ActorID    string          `json:"actor_id"`
	ActionType string          `json:"action_type"`
	Payload    json.RawMessage `json:"payload"`
}

func task0Actor(seat orchestrator.SeatID) (string, bool) {
	switch seat {
	case orchestrator.SeatGM:
		return "GM", true
	case orchestrator.SeatPlayer1:
		return "UNR-CHAR-0001", true
	case orchestrator.SeatPlayer2:
		return "UNR-CHAR-0002", true
	case orchestrator.SeatPlayer3:
		return "UNR-CHAR-0003", true
	case orchestrator.SeatPlayer4:
		return "UNR-CHAR-0004", true
	default:
		return "", false
	}
}

func task0ActorSeat(actor string) (orchestrator.SeatID, bool) {
	for _, seat := range orchestrator.BaselineSeats() {
		if expected, _ := task0Actor(seat); expected == actor {
			return seat, true
		}
	}
	return "", false
}

type task0TurnKey struct{}
type task0AuthenticatedTurn struct {
	seat     orchestrator.SeatID
	runID    string
	actionID string
	sequence int64
}

// Only the trusted enclosing B003 driver creates this context, before an
// invocation. Model frames contain no seat, Run, action or sequence selector.
func task0TurnContext(ctx context.Context, seat orchestrator.SeatID, runID, actionID string, sequence int64) (context.Context, error) {
	if ctx == nil || ctx.Err() != nil || !runPattern.MatchString(runID) || !runPattern.MatchString(actionID) || sequence < 1 || sequence >= 9_007_199_254_740_991 {
		return nil, ErrTask0
	}
	if _, ok := task0Actor(seat); !ok {
		return nil, ErrTask0
	}
	return context.WithValue(ctx, task0TurnKey{}, task0AuthenticatedTurn{seat, runID, actionID, sequence}), nil
}

// Every action and genesis copies these immutable Run bindings. This helper
// binds the new containing game revision and a separate additive adapter
// input, preserving the historical INT001 adapter and Q003 annex bytes.
func task0CoreBinding(f testplan.FrozenManifest, acceptedAIPT testplan.RepositorySource) (runcore.RunBinding, error) {
	decoded, err := testplan.DecodeRunManifest(f.Canonical)
	if err != nil || decoded.Digest != f.Digest || decoded.Manifest.CanonicalSHA256 != f.Manifest.CanonicalSHA256 || !bytes.Equal(decoded.Canonical, f.Canonical) {
		return runcore.RunBinding{}, ErrTask0
	}
	claimed, err := json.Marshal(f.Manifest)
	if err != nil {
		return runcore.RunBinding{}, ErrTask0
	}
	claimedCanonical, err := protocol.CanonicalJSON(claimed)
	if err != nil || claimedCanonical != string(f.Canonical) {
		return runcore.RunBinding{}, ErrTask0
	}
	m := decoded.Manifest
	game := testplan.RepositorySource{Repository: task0PrototypeSourceBinding.Repository, Commit: task0PrototypeSourceBinding.Commit, Tree: task0PrototypeSourceBinding.Tree}
	if m.Classification != "DIAGNOSTIC" || m.QualificationEligible || m.Source.Game != game || m.Source.AIPT != acceptedAIPT ||
		acceptedAIPT.Repository != "zyc14588/AIPT" || m.Budget.MaxInputTokens != MaxInputTokens || m.Budget.MaxOutputTokens != MaxOutputTokens || m.Budget.MaxDurationSeconds != 1800 || len(m.SeatRoster) != 5 {
		return runcore.RunBinding{}, ErrTask0
	}
	seen := map[orchestrator.SeatID]bool{}
	for _, seat := range m.SeatRoster {
		id := orchestrator.SeatID(seat.SeatID)
		if _, ok := task0Actor(id); !ok || seen[id] || id == orchestrator.SeatGM && seat.RoleID != "GM" || id != orchestrator.SeatGM && seat.RoleID != "PLAYER" {
			return runcore.RunBinding{}, ErrTask0
		}
		seen[id] = true
	}
	assets := map[string]string{}
	for _, asset := range m.PromptAssets {
		assets[asset.AssetID] = asset.SHA256
	}
	for id, identity := range map[string]string{"b007-task0-input-annex-q003": Task0InputAnnexSHA, "b007-task0-input-annex-q009": Task0PrototypeAnnexSHA,
		"b007-task0-runtime-adapter-v2": Task0RuntimeAdapterSHA} {
		if assets[id] != identity {
			return runcore.RunBinding{}, ErrTask0
		}
	}
	return runcore.RunBinding{Schema: runcore.RunBindingSchema, RunID: m.RunID,
		Manifest:            runcore.ArtifactBinding{ID: m.ManifestID, Schema: testplan.RunManifestSchema, CanonicalSHA256: hex.EncodeToString(f.Digest[:])},
		RuntimeAdapterInput: runcore.ArtifactBinding{ID: "AIPT-B007-UNREGISTERED-TASK0-ADAPTER-V2", Schema: "aipt.public.b007-task0-runtime-adapter-input/v2", CanonicalSHA256: Task0RuntimeAdapterCanonicalSHA},
		SourcePackage:       task0PrototypeSourceBinding}, nil
}

type task0KernelCore struct {
	game    task0GameExecutor
	binding runcore.RunBinding
	types   map[string]bool
}

func configureTask0Core(store runcore.EventStore, seeds runcore.SeedSource, game task0GameExecutor, binding runcore.RunBinding, contract []byte) (*runcore.Core, *task0KernelCore, error) {
	if store == nil || game == nil || binding.SourcePackage != task0PrototypeSourceBinding || inputSHA(contract) != "6fa75e95fd1508958c551aaa507a07deffeb8d8ccf8485de1c98478f2d20c7d9" {
		return nil, nil, ErrTask0
	}
	var c struct {
		ActionTypes map[string]json.RawMessage `json:"action_types"`
	}
	if _, err := protocol.CanonicalJSON(contract); err != nil || json.Unmarshal(contract, &c) != nil || len(c.ActionTypes) != 12 {
		return nil, nil, ErrTask0
	}
	k := &task0KernelCore{game: game, binding: binding, types: map[string]bool{}}
	handlers := make(map[string]runcore.ActionHandler, len(c.ActionTypes))
	for kind := range c.ActionTypes {
		k.types[kind] = true
		handlers[kind] = k
	}
	core, err := runcore.New(runcore.Config{Store: store, SeedSource: seeds, Authorizer: runcore.AuthorizerFunc(k.authorize), Rules: runcore.RuleValidatorFunc(k.checkProposal),
		Handlers: handlers, Invariants: []runcore.Invariant{runcore.InvariantFunc(k.validateState)}})
	if err != nil {
		return nil, nil, ErrTask0
	}
	return core, k, nil
}

func (k *task0KernelCore) authorize(ctx context.Context, state runcore.RunState, p runcore.ActionProposal) error {
	if k == nil || ctx == nil || state.Binding != k.binding || p.RunID != k.binding.RunID {
		return ErrTask0
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	actor, valid := task0Actor(turn.seat)
	if !ok || !valid || turn.runID != p.RunID || turn.actionID != p.ActionID || turn.sequence != state.Sequence || p.ExpectedSequence != turn.sequence || p.ActorID != actor {
		return ErrTask0
	}
	return nil
}

func (k *task0KernelCore) ValidatePayload(p runcore.ActionProposal) error {
	if k == nil || !k.types[p.ActionType] || len(p.Payload) < 2 || len(p.Payload) > 1024 || p.TemporaryRuling != nil {
		return ErrTask0
	}
	if _, ok := task0ActorSeat(p.ActorID); !ok {
		return ErrTask0
	}
	if _, err := protocol.CanonicalJSON(p.Payload); err != nil {
		return ErrTask0
	}
	return nil
}

func (k *task0KernelCore) checkProposal(ctx context.Context, state runcore.RunState, p runcore.ActionProposal) error {
	if k.ValidatePayload(p) != nil || ctx == nil || ctx.Err() != nil || state.Binding != k.binding || p.RunID != k.binding.RunID || p.ExpectedSequence != state.Sequence ||
		p.Source != (runcore.RuleSource{Kind: runcore.RuleSourceExplicit, Reference: task0PrototypeSourceBinding.PackageID}) {
		return ErrTask0
	}
	seat, _ := task0ActorSeat(p.ActorID)
	raw, err := k.game.invoke(ctx, "CHECK_PROPOSAL", map[string]any{"state": state.DomainState, "seat": seat, "proposal": p})
	var result struct {
		Valid bool `json:"valid"`
	}
	if err != nil || decodeFrozenJSON(raw, 4096, &result) != nil || !result.Valid {
		return ErrTask0
	}
	return nil
}

func (k *task0KernelCore) ValidatePrecondition(ctx context.Context, state runcore.RunState, p runcore.ActionProposal) error {
	// Replay checks the same source, payload and exact game-derived RNG arity.
	// It does not pretend to authenticate a historical live model session.
	return k.checkProposal(ctx, state, p)
}

func (k *task0KernelCore) Apply(ctx context.Context, state runcore.RunState, p runcore.ActionProposal, draws []runcore.RNGDraw) (json.RawMessage, error) {
	if k == nil || ctx == nil || state.Binding != k.binding || k.ValidatePayload(p) != nil {
		return nil, ErrTask0
	}
	seat, _ := task0ActorSeat(p.ActorID)
	// Core's empty draw slice may be nil at this interface; integer-JSON wire
	// arrays remain explicit empty arrays, including the retained B002 repair.
	exactDraws := append([]runcore.RNGDraw{}, draws...)
	if len(exactDraws) > 32 {
		return nil, ErrTask0
	}
	frame := task0Frame{p.ActorID, p.ActionType, bytes.Clone(p.Payload)}
	raw, err := k.game.invoke(ctx, "APPLY", map[string]any{"state": state.DomainState, "seat": seat, "frame": frame, "draws": exactDraws})
	if err != nil {
		return nil, ErrTask0
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil || len(canonical) > 1<<20 {
		return nil, ErrTask0
	}
	return json.RawMessage(canonical), nil
}

func (k *task0KernelCore) validateState(state runcore.RunState) error {
	if k == nil || state.Binding != k.binding {
		return ErrTask0
	}
	raw, err := k.game.invoke(context.Background(), "INVARIANT", map[string]any{"state": state.DomainState})
	var result struct {
		Valid    bool `json:"valid"`
		Complete bool `json:"complete"`
	}
	if err != nil || decodeFrozenJSON(raw, 4096, &result) != nil || !result.Valid {
		return ErrTask0
	}
	return nil
}

func (k *task0KernelCore) normalizeFrame(ctx context.Context, state runcore.RunState, raw []byte) (runcore.ActionProposal, error) {
	var frame task0Frame
	if k == nil || ctx == nil || state.Binding != k.binding || decodeFrozenJSON(raw, 2048, &frame) != nil || len(frame.Payload) > 1024 {
		return runcore.ActionProposal{}, ErrTask0
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	actor, valid := task0Actor(turn.seat)
	if !ok || !valid || turn.runID != state.Binding.RunID || turn.sequence != state.Sequence || frame.ActorID != actor {
		return runcore.ActionProposal{}, ErrTask0
	}
	trusted := struct {
		Seat     orchestrator.SeatID `json:"seat"`
		RunID    string              `json:"run_id"`
		ActionID string              `json:"action_id"`
		Sequence int64               `json:"expected_sequence"`
	}{turn.seat, turn.runID, turn.actionID, turn.sequence}
	proposalRaw, err := k.game.invoke(ctx, "PROPOSE", map[string]any{"state": state.DomainState, "trusted": trusted, "frame": frame})
	var p runcore.ActionProposal
	if err != nil || decodeFrozenJSON(proposalRaw, 16<<10, &p) != nil || p.Schema != runcore.ActionProposalSchema || k.authorize(ctx, state, p) != nil || k.ValidatePayload(p) != nil ||
		p.Source != (runcore.RuleSource{Kind: runcore.RuleSourceExplicit, Reference: task0PrototypeSourceBinding.PackageID}) || len(p.RNGRequests) > 1 || p.RNGRequests == nil {
		return runcore.ActionProposal{}, ErrTask0
	}
	if len(p.RNGRequests) == 1 && (p.RNGRequests[0].StreamID != "UNR-T0-ROLL" || p.RNGRequests[0].Count < 1 || p.RNGRequests[0].Count > 32) {
		return runcore.ActionProposal{}, ErrTask0
	}
	p.Payload = bytes.Clone(p.Payload)
	p.RNGRequests = slices.Clone(p.RNGRequests)
	return p, nil
}
