package pilot

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/runcore"
	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

type task0TableClock struct{}

func (task0TableClock) Now() time.Time { return time.Now().UTC() }

func task0BaselineIdentities(runID string) (orchestrator.BaselineIdentitySet, error) {
	if !runPattern.MatchString(runID) {
		return orchestrator.BaselineIdentitySet{}, ErrTask0
	}
	ids := orchestrator.BaselineIdentitySet{SessionIDs: map[orchestrator.SeatID]string{}, Personas: map[orchestrator.SeatID]orchestrator.PersonaBaseline{}, Characters: map[orchestrator.SeatID]orchestrator.Character{}, GMProfile: orchestrator.GMProfileRulesFaithful}
	for _, seat := range orchestrator.BaselineSeats() {
		// Short identities preserve the same seat, session generation and
		// persona contents while leaving space for actual authorized game data.
		ids.SessionIDs[seat] = runID + "." + string(seat)
		persona, err := orchestrator.NewPersonaBaseline("t0-"+string(seat), "1", []orchestrator.PersonaTrait{{Name: "deliberation", Value: 50}})
		if err != nil {
			return orchestrator.BaselineIdentitySet{}, ErrTask0
		}
		ids.Personas[seat] = persona
		if seat != orchestrator.SeatGM {
			actor, _ := task0Actor(seat)
			// Private character text belongs exclusively to authorized untrusted
			// projections. The trusted character slot carries only its identity.
			raw, _ := json.Marshal(map[string]string{"character_id": actor})
			character, err := orchestrator.NewCharacter(actor, "1", raw)
			if err != nil {
				return orchestrator.BaselineIdentitySet{}, ErrTask0
			}
			ids.Characters[seat] = character
		}
	}
	return ids, nil
}

func task0TablePolicy() orchestrator.OrchestrationPolicy {
	return orchestrator.OrchestrationPolicy{Schema: orchestrator.PolicySchema, PolicyID: "AIPT-B007-TASK0-SERIAL-NO-RETRY-V1",
		SeatOrder: orchestrator.BaselineSeats(), InterruptionOrder: orchestrator.BaselineSeats(), InvocationTimeoutMillis: 90000, MaxContextSources: 128, MaxEventWindow: 0,
		SemanticRepairBudget: 0, TransportRetryBudget: 0, SessionRecoveryBudget: 0}
}

type task0Table struct {
	budget                    *GlobalBudget
	pool                      *pgxpool.Pool
	core                      *runcore.Core
	store                     *runcore.PostgreSQLStore
	run                       *runcore.Run
	kernel                    *task0KernelCore
	seed                      *task0SeedSource
	syntax                    *task0Syntax
	refs                      *task0ReferenceSlot
	engine                    *orchestrator.Engine
	gateway                   *modelgateway.Gateway
	last                      runcore.Receipt
	receipts                  []runcore.Receipt
	engineEvents, floorEvents int
	started, finished         bool
}

// task0TableGameOwnership accepts the same concrete game ownership proof used
// for each game invocation. A delegated GAME belongs to the remote routes'
// exact live SETUP owner; a legacy direct process cannot disguise that owner.
func task0TableGameOwnership(game *task0OwnedGameHelper, transport *task0BudgetTransport) error {
	if game == nil || game.wire == nil || game.wire.lifetime == nil || game.wire.lifetime.Err() != nil || transport == nil {
		return ErrTask0
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.closed || transport.grant == nil {
		return ErrTask0
	}
	if game.delegated != nil {
		if game.process != nil || game.delegated.role.Role != "GAME" || game.delegated.owner == nil || !game.delegated.owner.live() {
			return ErrTask0
		}
		remote, ok := transport.upstream.(*task0FrozenRemoteTransport)
		if !ok || remote == nil {
			return ErrTask0
		}
		remote.mu.Lock()
		valid := !remote.closed && remote.lifetime != nil && remote.lifetime.Err() == nil && remote.setup == game.delegated.owner && remote.grant == transport.grant
		remote.mu.Unlock()
		if !valid {
			return ErrTask0
		}
	}
	if game.checkOwned() != nil {
		return ErrTask0
	}
	return nil
}

// Construction has no model calls. Every production boundary is concrete:
// the database-enrolled budget, owned sealed game helper, accepted six-profile
// dispatch grant, fresh controlled-real registry and PostgreSQL audit sink.
// No executor, event store, completion rule or retry policy is CLI input.
func newTask0Table(ctx context.Context, budget *GlobalBudget, game *task0OwnedGameHelper, transport *task0BudgetTransport, registry *modelgateway.Registry, sources *Task0PrototypeSources) (*task0Table, error) {
	if ctx == nil || ctx.Err() != nil || budget == nil || budget.pool == nil || budget.checkRoot() != nil || game == nil || transport == nil || registry == nil || sources == nil ||
		transport.reservations != budget || transport.grant == nil || transport.grant.manifest.Digest != budget.manifest.Digest ||
		task0TableGameOwnership(game, transport) != nil {
		return nil, ErrTask0
	}
	grant := transport.grant
	binding, err := task0CoreBinding(grant.manifest, grant.binding.Implementation)
	if err != nil {
		return nil, ErrTask0
	}
	syntax, err := task0HeldSyntax(sources)
	if err != nil {
		return nil, ErrTask0
	}
	modelBinding, err := modelgateway.BindManifestModels(grant.manifest, registry)
	if err != nil || modelBinding.RunClassification != "DIAGNOSTIC" || modelBinding.QualificationEligible {
		return nil, ErrTask0
	}
	for _, entry := range grant.profiles {
		cert, err := registry.Certification(entry.Profile.CertificationIdentity)
		if err != nil || cert.Kind != modelgateway.CertificationControlledReal || cert.RealModelCalls != 1 || cert.Result != "PASS" || !cert.MinimumCertification {
			return nil, ErrTask0
		}
	}
	audit, err := modelgateway.NewPostgreSQLAuditSink(budget.pool)
	if err != nil {
		return nil, ErrTask0
	}
	gateway, err := modelgateway.NewGateway(registry, modelBinding, transport, audit, modelgateway.GatewayOptions{RunID: binding.RunID, DiagnosticID: "B007-task0-" + grant.binding.ManifestSHA[:24], Mode: modelgateway.GatewayModeDiagnostic})
	if err != nil {
		return nil, ErrTask0
	}
	store, err := runcore.NewPostgreSQLStore(budget.pool)
	if err != nil {
		return nil, ErrTask0
	}
	// The source loader's held copy pins the exact contract used by this Core.
	contract, err := sources.copyHeldSource("aipt/task0-v2/action-contract.json")
	if err != nil {
		return nil, ErrTask0
	}
	seed, err := newTask0SeedSource(ctx, budget, binding)
	if err != nil {
		return nil, ErrTask0
	}
	core, kernel, err := configureTask0Core(store, seed, game, binding, contract)
	if err != nil {
		seed.Close()
		return nil, ErrTask0
	}
	return &task0Table{budget: budget, pool: budget.pool, core: core, store: store, kernel: kernel, seed: seed, syntax: syntax, refs: &task0ReferenceSlot{}, gateway: gateway}, nil
}

func (t *task0Table) start(ctx context.Context) error {
	if t == nil || t.started || t.finished || t.kernel == nil || t.gateway == nil || t.seed == nil || ctx == nil || ctx.Err() != nil {
		return ErrTask0
	}
	// Set before any durable write; an unsuccessful genesis is never retried
	// through this table object or overwritten by another initial state.
	t.started = true
	initial, err := t.kernel.game.invoke(ctx, "INITIAL", map[string]any{})
	if err != nil {
		return ErrTask0
	}
	run, receipt, err := t.core.StartRun(ctx, runcore.StartRunInput{Binding: t.kernel.binding, InitialState: initial})
	if err != nil {
		return ErrTask0
	}
	t.run, t.last = run, receipt
	t.receipts = []runcore.Receipt{receipt}
	identities, err := task0BaselineIdentities(t.kernel.binding.RunID)
	if err != nil {
		return ErrTask0
	}
	seats, err := orchestrator.NewBaselineSeats(t.kernel.binding.RunID, identities)
	if err != nil {
		return ErrTask0
	}
	frames, err := task0ModelFrameGateway(t.gateway)
	if err != nil {
		return ErrTask0
	}
	engine, err := orchestrator.NewEngine(orchestrator.EngineConfig{RunID: t.kernel.binding.RunID, Policy: task0TablePolicy(), Seats: seats, SessionAuthority: orchestrator.NewSessionAuthority(),
		Invoker: &task0B003Invoker{upstream: frames, run: run, kernel: t.kernel}, Retriever: t.refs, Submitter: task0B003Submitter{run: run, kernel: t.kernel}, Clock: task0TableClock{}})
	if err != nil {
		return ErrTask0
	}
	t.engine = engine
	if engine.Floor().OpenDiscussion() != nil {
		return ErrTask0
	}
	return t.persistOrchestration(ctx)
}

func (t *task0Table) persistOrchestration(ctx context.Context) error {
	if t == nil || t.pool == nil || t.engine == nil || ctx == nil {
		return ErrTask0
	}
	for _, stream := range []struct {
		kind   string
		events []orchestrator.OrchestrationEvent
		cursor *int
	}{
		{"engine", t.engine.Events(), &t.engineEvents}, {"floor", t.engine.Floor().Events(), &t.floorEvents},
	} {
		for *stream.cursor < len(stream.events) {
			index := *stream.cursor
			event := stream.events[index]
			if event.Sequence != int64(index+1) || event.RunID != t.kernel.binding.RunID {
				return ErrTask0
			}
			raw, err := json.Marshal(event)
			if err != nil {
				return ErrTask0
			}
			expected := int64(index)
			stored, err := storagepostgres.Append(ctx, t.pool, storagepostgres.AppendInput{StreamID: "aipt.b007-task0-" + stream.kind + ":" + event.RunID,
				EventID: fmt.Sprintf("b007-%s-%s-%d", stream.kind, event.RunID, event.Sequence), EventType: string(event.Type), PayloadJSON: raw, ExpectedSequence: &expected})
			if err != nil || stored.Sequence != expected+1 {
				return ErrTask0
			}
			*stream.cursor++
		}
	}
	return nil
}

func task0InvocationNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrTask0
	}
	// Preserve all 128 bits of fresh randomness with a shorter ASCII identity;
	// it remains an opaque original invocation, never a model-selected action.
	return "t0-" + base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

type task0TableResult struct {
	finalReceipt runcore.Receipt
	replay       runcore.ReplayResult
	visited      []orchestrator.SeatID
	turns        int
	budget       BudgetTotals
}

func (t *task0Table) execute(ctx context.Context) (task0TableResult, error) {
	result := task0TableResult{}
	if t == nil || t.finished || ctx == nil || ctx.Err() != nil {
		return result, ErrTask0
	}
	defer func() { t.finished = true }()
	if t.start(ctx) != nil {
		return result, ErrTask0
	}
	visited := map[orchestrator.SeatID]bool{}
	complete := false
	// The durable shared budget is the tighter bound after certification;
	// this fixed loop ceiling also prevents unbounded table-side work.
	for turnNumber := 0; turnNumber < MaxRemoteAttempts; turnNumber++ {
		phase, seat := t.engine.Floor().State()
		if phase != orchestrator.PhaseDiscussion {
			return result, ErrTask0
		}
		nonce, err := task0InvocationNonce()
		if err != nil {
			return result, ErrTask0
		}
		before := t.run.State()
		turn, err := task0TurnContext(ctx, seat, t.kernel.binding.RunID, nonce, before.Sequence)
		if err != nil {
			return result, ErrTask0
		}
		input, refs, err := t.kernel.turnContextInput(turn, before, t.syntax)
		if err != nil || t.refs.activate(turn, refs) != nil {
			return result, ErrTask0
		}
		response, invokeErr := t.engine.InvokeSeat(turn, seat, nonce, input)
		retireErr := t.refs.retire(refs)
		// Retain B003 failure events even when the request context expires.
		persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		persistErr := t.persistOrchestration(persistCtx)
		cancel()
		if invokeErr != nil || retireErr != nil || persistErr != nil || response.Receipt == nil || response.Receipt.RunID != before.Binding.RunID ||
			response.Receipt.ActionID != nonce || response.Receipt.Sequence != before.Sequence+1 || t.run.State().Sequence != before.Sequence+1 {
			return result, ErrTask0
		}
		t.last = *response.Receipt
		retained := *response.Receipt
		retained.RNGDraws = slices.Clone(retained.RNGDraws)
		t.receipts = append(t.receipts, retained)
		visited[seat] = true
		result.turns++
		check, err := t.kernel.game.invoke(ctx, "INVARIANT", map[string]any{"state": t.run.State().DomainState})
		var invariant struct {
			Valid    bool `json:"valid"`
			Complete bool `json:"complete"`
		}
		if err != nil || decodeFrozenJSON(check, 4096, &invariant) != nil || !invariant.Valid {
			return result, ErrTask0
		}
		if invariant.Complete {
			complete = true
			break
		}
		if task0AdvanceTableFloor(t.engine.Floor(), seat, t.run.State().DomainState) != nil || t.persistOrchestration(ctx) != nil {
			return result, ErrTask0
		}
	}
	if !complete || len(visited) != 5 {
		return result, ErrTask0
	}
	events, err := t.store.Load(ctx, "aipt.run-core:"+t.kernel.binding.RunID)
	if err != nil || len(events) != result.turns+1 {
		return result, ErrTask0
	}
	seed, err := t.seed.replaySeed()
	if err != nil {
		return result, ErrTask0
	}
	defer clear(seed)
	replay, err := t.core.Replay(ctx, runcore.ReplayInput{Binding: t.kernel.binding, Seed: seed, Events: events, ExpectedFinalStateHash: t.last.StateHash})
	if err != nil || replay.State.Sequence != t.run.State().Sequence || replay.EventCount != len(events) || replay.ProjectionHash != t.last.ProjectionHash {
		return result, ErrTask0
	}
	totals, err := t.budget.Totals(ctx)
	if err != nil || totals.LocalCalls != 1 || totals.RemoteAttempts != 5+result.turns {
		return result, ErrTask0
	}
	result.finalReceipt, result.replay, result.budget = t.last, replay, totals
	for seat := range visited {
		result.visited = append(result.visited, seat)
	}
	slices.Sort(result.visited)
	return result, nil
}

// Once all four players have signed and finished their rest choices, the
// accepted game can require several GM-only rest-risk/note actions in a row.
// Keeping the existing GM floor avoids asking a finished player for an
// impossible action. It selects no action, roll, note or mission outcome.
func task0AdvanceTableFloor(floor *orchestrator.FloorController, seat orchestrator.SeatID, domain json.RawMessage) error {
	if floor == nil {
		return ErrTask0
	}
	phase, owner := floor.State()
	if phase != orchestrator.PhaseDiscussion || owner != seat {
		return ErrTask0
	}
	if seat == orchestrator.SeatGM {
		var state struct {
			Schema  string          `json:"schema"`
			Mission string          `json:"mission"`
			Ledger  json.RawMessage `json:"ledger"`
			Rest    json.RawMessage `json:"rest_event"`
			Risk    []string        `json:"risk_queue"`
			Actors  map[string]struct {
				Signed bool `json:"signed"`
				Rest   int  `json:"rest_points"`
				Notes  []struct {
					Text *string `json:"text"`
				} `json:"pollution_notes"`
			} `json:"actors"`
		}
		if json.Unmarshal(domain, &state) != nil || state.Schema != "unregistered.task0-state/v2" || len(state.Actors) != 4 {
			return ErrTask0
		}
		playersDone, pendingNotes := true, false
		for _, player := range orchestrator.BaselineSeats()[1:] {
			actor, ok := task0Actor(player)
			value, found := state.Actors[actor]
			if !ok || !found {
				return ErrTask0
			}
			playersDone = playersDone && value.Signed && value.Rest == 0
			for _, note := range value.Notes {
				pendingNotes = pendingNotes || note.Text == nil
			}
		}
		if playersDone && state.Mission != "OPEN" && !task0Null(state.Ledger) && (task0Null(state.Rest) || len(state.Risk) > 0 || pendingNotes) {
			return nil
		}
	}
	return floor.AdvanceDiscussion(seat)
}

func (t *task0Table) retire() error {
	if t == nil {
		return nil
	}
	var gatewayErr, seedErr error
	if t.gateway != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		gatewayErr = t.gateway.Close(ctx)
		cancel()
	}
	if t.seed != nil {
		seedErr = t.seed.Close()
	}
	return errors.Join(gatewayErr, seedErr)
}
