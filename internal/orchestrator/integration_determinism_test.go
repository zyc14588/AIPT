package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/zyc14588/AIPT/internal/runcore"
)

func newRunCoreFixture(t *testing.T, runID string) (*runcoreFixture, []byte) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, 32)
	store := newMemoryEventStore()
	core, err := runcore.New(runcore.Config{
		Store: store, SeedSource: fixedSeedSource{seed: seed},
		Authorizer: runcore.AuthorizerFunc(func(_ context.Context, _ runcore.RunState, proposal runcore.ActionProposal) error {
			if !containsSeat(BaselineSeatIDs, SeatID(proposal.ActorID)) {
				return errors.New("unknown seat actor")
			}
			return nil
		}),
		Rules: runcore.RuleValidatorFunc(func(_ context.Context, _ runcore.RunState, proposal runcore.ActionProposal) error {
			if proposal.Source.Reference != "RULE-SYNTHETIC-001" {
				return errors.New("unknown synthetic rule")
			}
			return nil
		}),
		Handlers: map[string]runcore.ActionHandler{"fixture.increment/v1": counterHandler{}},
		Invariants: []runcore.Invariant{runcore.InvariantFunc(func(state runcore.RunState) error {
			var domain struct {
				Counter int `json:"counter"`
			}
			if err := json.Unmarshal(state.DomainState, &domain); err != nil {
				return err
			}
			if domain.Counter < 0 || domain.Counter > 5 {
				return errors.New("counter invariant")
			}
			return nil
		})},
	})
	if err != nil {
		t.Fatalf("runcore.New: %v", err)
	}
	binding := runBinding(runID)
	run, _, err := core.StartRun(context.Background(), runcore.StartRunInput{Binding: binding, InitialState: json.RawMessage(`{"counter":0}`)})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	return &runcoreFixture{core: core, run: run, store: store, binding: binding}, seed
}

type runcoreFixture struct {
	core    *runcore.Core
	run     *runcore.Run
	store   *memoryEventStore
	binding runcore.RunBinding
}

func TestB002ActionProposalIntegrationReplayAndRejectionPropagation(t *testing.T) {
	runID := "run-core-integration"
	fixture, seed := newRunCoreFixture(t, runID)
	clock := newFakeClock()
	seatID := SeatPlayer1
	action := actionProposal(runID, seatID, "action-core-1", 1)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{response: responseBytes(
		t, "invoke-core-1", runID, seatID, "session-"+runID+"-PLAYER_1", "commit action", &action,
	)}}}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, RunCoreSubmitter{Run: fixture.run})
	result, err := engine.InvokeSeat(context.Background(), seatID, "invoke-core-1", input)
	if err != nil || result.Receipt == nil {
		t.Fatalf("InvokeSeat: %+v, %v", result, err)
	}
	state := fixture.run.State()
	var domain struct {
		Counter int `json:"counter"`
	}
	_ = json.Unmarshal(state.DomainState, &domain)
	if domain.Counter != 1 || fixture.store.count() != 2 {
		t.Fatalf("Run Core state/events = %+v/%d", domain, fixture.store.count())
	}
	replayed, err := fixture.core.ReplayStored(context.Background(), fixture.binding, seed, result.Receipt.StateHash)
	if err != nil || replayed.StateHash != result.Receipt.StateHash {
		t.Fatalf("ReplayStored = %+v, %v", replayed, err)
	}
	if _, err := engine.InvokeSeat(context.Background(), seatID, "invoke-core-1", input); !errors.Is(err, Sentinel(CodeDuplicateAction)) {
		t.Fatalf("action replay accepted: %v", err)
	}
	if fixture.store.count() != 2 {
		t.Fatalf("action replay appended event: %d", fixture.store.count())
	}

	rejectRun := "run-core-reject"
	rejectFixture, _ := newRunCoreFixture(t, rejectRun)
	rejectClock := newFakeClock()
	stale := actionProposal(rejectRun, seatID, "action-stale", 99)
	rejectInvoker := &scriptedInvoker{clock: rejectClock, steps: []invokeStep{{response: responseBytes(
		t, "invoke-stale", rejectRun, seatID, "session-"+rejectRun+"-PLAYER_1", "stale", &stale,
	)}}}
	rejectEngine, rejectInput := fixtureEngine(t, rejectRun, seatID, fixturePolicy(), rejectInvoker, RunCoreSubmitter{Run: rejectFixture.run})
	if _, err := rejectEngine.InvokeSeat(context.Background(), seatID, "invoke-stale", rejectInput); !errors.Is(err, Sentinel(CodeActionRejectedByCore)) {
		t.Fatalf("B002 rejection not propagated: %v", err)
	}
	if rejectFixture.store.count() != 1 {
		t.Fatalf("rejected action appended event: %d", rejectFixture.store.count())
	}
	if _, err := rejectEngine.InvokeSeat(context.Background(), seatID, "invoke-stale", rejectInput); !errors.Is(err, Sentinel(CodeDuplicateAction)) {
		t.Fatalf("rejected invocation was replayable without an audited retry: %v", err)
	}
	if rejectFixture.store.count() != 1 {
		t.Fatalf("replayed rejected invocation appended event: %d", rejectFixture.store.count())
	}
}

func TestConcurrentDuplicateInvocationAndExpectedSequenceCannotDoubleCommit(t *testing.T) {
	runID := "run-concurrent-invocation"
	fixture, _ := newRunCoreFixture(t, runID)
	clock := newFakeClock()
	seatID := SeatPlayer1
	action := actionProposal(runID, seatID, "action-concurrent", 1)
	valid := responseBytes(t, "invoke-concurrent", runID, seatID, "session-"+runID+"-PLAYER_1", "commit", &action)
	invoker := &scriptedInvoker{clock: clock, steps: []invokeStep{{response: valid}}}
	engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, RunCoreSubmitter{Run: fixture.run})
	var wg sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := engine.InvokeSeat(context.Background(), seatID, "invoke-concurrent", input)
			errorsSeen <- err
		}()
	}
	wg.Wait()
	close(errorsSeen)
	successes, duplicates := 0, 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, Sentinel(CodeDuplicateAction)):
			duplicates++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if successes != 1 || duplicates != 1 || fixture.store.count() != 2 {
		t.Fatalf("successes=%d duplicates=%d events=%d", successes, duplicates, fixture.store.count())
	}
	phase, owner := engine.Floor().State()
	if phase != PhaseDiscussion || owner != seatID {
		t.Fatalf("concurrency created invalid floor state: %s/%s", phase, owner)
	}
}

func TestPrivateMessageConcurrencyPreservesRecipientSets(t *testing.T) {
	floor, _ := NewFloorController("run-private-concurrent", fixturePolicy())
	_ = floor.OpenDiscussion()
	type request struct {
		id     string
		sender SeatID
		to     SeatID
	}
	requests := []request{
		{"m1", SeatPlayer1, SeatPlayer2}, {"m2", SeatPlayer2, SeatGM},
		{"m3", SeatGM, SeatPlayer4}, {"m4", SeatPlayer3, SeatPlayer1},
	}
	items := make(chan EventWindowItem, len(requests))
	var wg sync.WaitGroup
	for _, value := range requests {
		value := value
		wg.Add(1)
		go func() {
			defer wg.Done()
			item, err := floor.RoutePrivateMessage(value.id, value.sender, []SeatID{value.to}, "payload-"+value.id)
			if err != nil {
				t.Errorf("RoutePrivateMessage: %v", err)
				return
			}
			items <- item
		}()
	}
	wg.Wait()
	close(items)
	for item := range items {
		if len(item.Recipients) != 2 {
			t.Fatalf("recipient crossing: %+v", item)
		}
	}
}

func TestSyntheticRunDeterminismStress(t *testing.T) {
	const repetitions = 100
	var baseline []byte
	for iteration := range repetitions {
		runID := "run-determinism-stress"
		fixture, _ := newRunCoreFixture(t, runID)
		clock := newFakeClock()
		seatID := SeatPlayer1
		oldID := "session-" + runID + "-PLAYER_1"
		newSession := Session{
			Schema: SessionSchema, SessionID: "session-stress-recovered", RunID: runID,
			SeatID: seatID, Generation: 2, ParentSessionID: oldID,
		}
		action := actionProposal(runID, seatID, "action-stress", 1)
		valid := responseBytes(t, "invoke-stress", runID, seatID, newSession.SessionID, "commit", &action)
		invoker := &scriptedInvoker{
			clock: clock,
			steps: []invokeStep{
				{err: NewInvocationFailure(CodeAgentSessionFailed)},
				{response: []byte(`{"malformed":true}`)},
				{response: valid},
			},
			recoveries: []recoveryStep{{session: newSession}},
		}
		engine, input := fixtureEngine(t, runID, seatID, fixturePolicy(), invoker, RunCoreSubmitter{Run: fixture.run})
		result, err := engine.InvokeSeat(context.Background(), seatID, "invoke-stress", input)
		if err != nil || result.Receipt == nil {
			t.Fatalf("iteration %d: InvokeSeat = %+v, %v", iteration, result, err)
		}
		snapshot := struct {
			EngineEvents []OrchestrationEvent `json:"engine_events"`
			FloorEvents  []OrchestrationEvent `json:"floor_events"`
			ContextHash  string               `json:"context_hash"`
			StateHash    string               `json:"state_hash"`
			ActionID     string               `json:"action_id"`
		}{engine.Events(), engine.Floor().Events(), result.Context.ContextHash, result.Receipt.StateHash, result.Receipt.ActionID}
		canonical, err := canonicalValue(snapshot)
		if err != nil {
			t.Fatalf("iteration %d: canonical snapshot: %v", iteration, err)
		}
		if iteration == 0 {
			baseline = canonical
		} else if !bytes.Equal(baseline, canonical) {
			t.Fatalf("iteration %d nondeterministic\nwant %s\ngot  %s", iteration, baseline, canonical)
		}
	}
}

func TestPolicyRequiresExplicitFiniteBoundsAndOrders(t *testing.T) {
	valid := fixturePolicy()
	probes := []struct {
		name   string
		mutate func(*OrchestrationPolicy)
	}{
		{"unknown-version", func(policy *OrchestrationPolicy) { policy.Schema = "aipt.orchestration-policy/v2" }},
		{"negative-semantic", func(policy *OrchestrationPolicy) { policy.SemanticRepairBudget = -1 }},
		{"negative-transport", func(policy *OrchestrationPolicy) { policy.TransportRetryBudget = -1 }},
		{"negative-recovery", func(policy *OrchestrationPolicy) { policy.SessionRecoveryBudget = -1 }},
		{"excessive-semantic", func(policy *OrchestrationPolicy) { policy.SemanticRepairBudget = 65 }},
		{"excessive-transport", func(policy *OrchestrationPolicy) { policy.TransportRetryBudget = 65 }},
		{"excessive-recovery", func(policy *OrchestrationPolicy) { policy.SessionRecoveryBudget = 65 }},
		{"missing-timeout", func(policy *OrchestrationPolicy) { policy.InvocationTimeoutMillis = 0 }},
		{"duplicate-order", func(policy *OrchestrationPolicy) { policy.SeatOrder[4] = SeatPlayer3 }},
		{"missing-interruption-order", func(policy *OrchestrationPolicy) { policy.InterruptionOrder = nil }},
	}
	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			copy := clonePolicy(valid)
			probe.mutate(&copy)
			if err := validatePolicy(copy); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	if err := validatePolicy(valid); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}

func TestOrchestrationErrorsNeverRenderCauses(t *testing.T) {
	secret := "postgres://admin:secret@example.invalid/aipt root_seed=001122"
	err := orchestrationError(CodeVisibilityDenied, "test", "run-safe", SeatPlayer1, "invoke-safe", fmt.Errorf("hidden %s", secret))
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "root_seed") || strings.Contains(err.Error(), "postgres://") {
		t.Fatalf("structured error leaked cause: %v", err)
	}
	want := "VISIBILITY_DENIED: operation=test run_id=run-safe seat_id=PLAYER_1 invocation_id=invoke-safe"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, Sentinel(CodeVisibilityDenied)) {
		t.Fatal("structured error lost stable classification")
	}
}

func TestSameInputsProduceSameFloorAndContextIdentity(t *testing.T) {
	run := func() ([]OrchestrationEvent, string) {
		runID := "run-repeat-small"
		seats := fixtureSeats(t, runID)
		tracker, _ := NewPersonaTracker(runID, seats)
		state, _ := tracker.State(SeatPlayer2)
		input, retriever := fixtureContextInput(t, runID, SeatPlayer2)
		bundle, err := BuildContext(context.Background(), fixturePolicy(), seatByID(t, seats, SeatPlayer2), state, input, retriever)
		if err != nil {
			t.Fatalf("BuildContext: %v", err)
		}
		floor, _ := NewFloorController(runID, fixturePolicy())
		_ = floor.OpenDiscussion()
		_, owner := floor.State()
		_ = floor.AdvanceDiscussion(owner)
		_, owner = floor.State()
		_ = floor.AdvanceDiscussion(owner)
		return floor.Events(), bundle.ContextHash
	}
	firstEvents, firstHash := run()
	secondEvents, secondHash := run()
	if !reflect.DeepEqual(firstEvents, secondEvents) || firstHash != secondHash {
		t.Fatal("same input produced different orchestration result")
	}
}
