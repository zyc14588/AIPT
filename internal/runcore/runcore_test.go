package runcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/zyc14588/AIPT/internal/protocol"
	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

type fixedSeedSource struct{ seed []byte }

func (s fixedSeedSource) RootSeed(context.Context, RunBinding) ([]byte, error) {
	return append([]byte(nil), s.seed...), nil
}

type memoryStore struct {
	mu       sync.Mutex
	streams  map[string][]storagepostgres.LedgerEvent
	eventIDs map[string]struct{}
	failNext error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{streams: map[string][]storagepostgres.LedgerEvent{}, eventIDs: map[string]struct{}{}}
}

func (s *memoryStore) Append(_ context.Context, request AppendRequest) (storagepostgres.LedgerEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext != nil {
		err := s.failNext
		s.failNext = nil
		return storagepostgres.LedgerEvent{}, err
	}
	stream := s.streams[request.StreamID]
	if int64(len(stream)) != request.ExpectedSequence {
		return storagepostgres.LedgerEvent{}, errStoreConflict
	}
	if _, exists := s.eventIDs[request.EventID]; exists {
		return storagepostgres.LedgerEvent{}, errStoreConflict
	}
	canonical, err := protocol.CanonicalJSON(request.Payload)
	if err != nil {
		return storagepostgres.LedgerEvent{}, err
	}
	payloadHash := sha256.Sum256([]byte(canonical))
	var previous *[32]byte
	if len(stream) > 0 {
		value := stream[len(stream)-1].EventHash
		previous = &value
	}
	sequence := int64(len(stream) + 1)
	eventHash, err := storagepostgres.ComputeLedgerEventHash(request.StreamID, sequence, request.EventID, request.EventType, payloadHash, previous)
	if err != nil {
		return storagepostgres.LedgerEvent{}, err
	}
	event := storagepostgres.LedgerEvent{
		StreamID: request.StreamID, Sequence: sequence, EventID: request.EventID,
		EventType: request.EventType, PayloadCanonical: canonical, PayloadHash: payloadHash,
		PrevEventHash: previous, EventHash: eventHash,
	}
	s.streams[request.StreamID] = append(stream, event)
	s.eventIDs[request.EventID] = struct{}{}
	return event, nil
}

func (s *memoryStore) Load(_ context.Context, streamID string) ([]storagepostgres.LedgerEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneLedgerEvents(s.streams[streamID]), nil
}

func (s *memoryStore) events(runID string) []storagepostgres.LedgerEvent {
	events, _ := s.Load(context.Background(), runStreamID(runID))
	return events
}

type eventRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *eventRecorder) add(value string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, value)
}

func (r *eventRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = nil
}

func (r *eventRecorder) values() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type counterHandler struct {
	recorder      *eventRecorder
	rejectApply   bool
	rejectPrecond bool
}

type counterState struct {
	Counter int    `json:"counter"`
	LastRNG string `json:"last_rng"`
}

type counterPayload struct {
	Delta int `json:"delta"`
}

func (h counterHandler) ValidatePayload(proposal ActionProposal) error {
	h.recorder.add("schema")
	var payload counterPayload
	decoder := json.NewDecoder(bytes.NewReader(proposal.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Delta == 0 {
		return errors.New("invalid counter payload")
	}
	return nil
}

func (h counterHandler) ValidatePrecondition(_ context.Context, _ RunState, _ ActionProposal) error {
	h.recorder.add("precondition")
	if h.rejectPrecond {
		return errors.New("synthetic precondition rejected")
	}
	return nil
}

func (h counterHandler) Apply(_ context.Context, state RunState, proposal ActionProposal, draws []RNGDraw) (json.RawMessage, error) {
	h.recorder.add("apply")
	if h.rejectApply {
		return nil, errors.New("synthetic apply failure")
	}
	var current counterState
	if err := json.Unmarshal(state.DomainState, &current); err != nil {
		return nil, err
	}
	var payload counterPayload
	if err := json.Unmarshal(proposal.Payload, &payload); err != nil {
		return nil, err
	}
	current.Counter += payload.Delta
	if len(draws) > 0 {
		current.LastRNG = draws[len(draws)-1].ValueHex
	}
	raw, err := json.Marshal(current)
	return raw, err
}

func fixtureBinding(runID string) RunBinding {
	return RunBinding{
		Schema: RunBindingSchema, RunID: runID,
		Manifest:            ArtifactBinding{ID: "manifest-1", Schema: "aipt.run-manifest/v1", CanonicalSHA256: strings.Repeat("1", 64)},
		RuntimeAdapterInput: ArtifactBinding{ID: "adapter-input-1", Schema: "aipt.runtime-adapter-input/v1", CanonicalSHA256: strings.Repeat("2", 64)},
		SourcePackage: SourcePackageBinding{
			PackageID: "package-1", Schema: "aipt.playtest-package/v1", Repository: "fixture/game",
			Commit: strings.Repeat("3", 40), Tree: strings.Repeat("4", 40), CanonicalSHA256: strings.Repeat("5", 64),
		},
	}
}

func fixtureSeed() []byte { return bytes.Repeat([]byte{0x42}, 32) }

func fixtureCore(t *testing.T, store EventStore, handler counterHandler, recorder *eventRecorder, maxCounter int) *Core {
	t.Helper()
	core, err := New(Config{
		Store: store, SeedSource: fixedSeedSource{seed: fixtureSeed()},
		Authorizer: AuthorizerFunc(func(context.Context, RunState, ActionProposal) error {
			recorder.add("authorize")
			return nil
		}),
		Rules: RuleValidatorFunc(func(context.Context, RunState, ActionProposal) error {
			recorder.add("rule")
			return nil
		}),
		Handlers: map[string]ActionHandler{"fixture.increment/v1": handler},
		Invariants: []Invariant{InvariantFunc(func(state RunState) error {
			recorder.add("invariant")
			var domain counterState
			if err := json.Unmarshal(state.DomainState, &domain); err != nil {
				return err
			}
			if domain.Counter < 0 || domain.Counter > maxCounter {
				return errors.New("counter invariant")
			}
			return nil
		})},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return core
}

func startFixtureRun(t *testing.T, core *Core, runID string) (*Run, Receipt) {
	t.Helper()
	run, receipt, err := core.StartRun(context.Background(), StartRunInput{
		Binding: fixtureBinding(runID), InitialState: json.RawMessage(`{"counter":0,"last_rng":""}`),
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	return run, receipt
}

func proposalBytes(t *testing.T, runID, actionID string, expected int64, delta int, requests []RNGRequest, ruling *TemporaryRuling) []byte {
	t.Helper()
	raw, err := json.Marshal(ActionProposal{
		Schema: ActionProposalSchema, ActionID: actionID, RunID: runID,
		ActorID: "actor-1", ActionType: "fixture.increment/v1", ExpectedSequence: expected,
		Source:  RuleSource{Kind: RuleSourceRuleID, Reference: "RULE-SYNTHETIC-001"},
		Payload: json.RawMessage(fmt.Sprintf(`{"delta":%d}`, delta)), RNGRequests: requests,
		TemporaryRuling: ruling,
	})
	if err != nil {
		t.Fatalf("marshal proposal: %v", err)
	}
	return raw
}

func TestActionPipelineHappyPathRNGProjectionAndReplay(t *testing.T) {
	store := newMemoryStore()
	recorder := &eventRecorder{}
	core := fixtureCore(t, store, counterHandler{recorder: recorder}, recorder, 10)
	run, _ := startFixtureRun(t, core, "run-happy")
	recorder.reset()
	ruling := &TemporaryRuling{RulingID: "ruling-1", Scope: "synthetic-scope", Reason: "synthetic reason", Reversible: true, ValidThroughSequence: 5}
	receipt, err := run.Execute(context.Background(), proposalBytes(t, "run-happy", "action-1", 1, 2,
		[]RNGRequest{{StreamID: "checks", Count: 2}}, ruling))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	wantPipeline := []string{"schema", "authorize", "rule", "precondition", "invariant", "apply", "invariant"}
	if got := recorder.values(); fmt.Sprint(got) != fmt.Sprint(wantPipeline) {
		t.Fatalf("pipeline = %v, want %v", got, wantPipeline)
	}
	if receipt.Sequence != 2 || len(receipt.RNGDraws) != 2 || receipt.RNGDraws[0].DrawIndex != 1 || receipt.RNGDraws[1].DrawIndex != 2 {
		t.Fatalf("receipt = %+v", receipt)
	}
	state := run.State()
	var domain counterState
	if err := json.Unmarshal(state.DomainState, &domain); err != nil || domain.Counter != 2 || domain.LastRNG != receipt.RNGDraws[1].ValueHex {
		t.Fatalf("domain = %+v, err=%v", domain, err)
	}
	if state.RNGCursors["checks"] != 2 {
		t.Fatalf("RNG cursor = %d", state.RNGCursors["checks"])
	}
	projection1, err := Project(state)
	if err != nil {
		t.Fatalf("Project: %v", err)
	}
	projection2, _ := Project(state)
	if !bytes.Equal(projection1.Canonical, projection2.Canonical) || projection1.SHA256 != projection2.SHA256 || projection1.SHA256 != receipt.ProjectionHash {
		t.Fatal("projection is not deterministic")
	}
	seedHex := strings.Repeat("42", 32)
	for _, public := range []string{string(projection1.Canonical), fmt.Sprint(receipt), store.events("run-happy")[0].PayloadCanonical} {
		if strings.Contains(public, seedHex) {
			t.Fatal("root seed leaked into ordinary projection/event/receipt")
		}
	}
	replayed, err := core.Replay(context.Background(), ReplayInput{
		Binding: fixtureBinding("run-happy"), Seed: fixtureSeed(), Events: store.events("run-happy"),
		ExpectedFinalStateHash: receipt.StateHash,
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.StateHash != receipt.StateHash || replayed.ProjectionHash != receipt.ProjectionHash || !equalCanonical(replayed.State, state) {
		t.Fatalf("replay = %+v, live state = %+v", replayed, state)
	}
	const goldenFinalStateHash = "660680c18d5c7febf2120decb07040a6c10fb04c06d67ec61d774ac72ba498ff"
	if receipt.StateHash != goldenFinalStateHash {
		t.Fatalf("final state hash = %s, want golden %s", receipt.StateHash, goldenFinalStateHash)
	}
	t.Logf("live_final_state_hash=%s replayed_final_state_hash=%s", receipt.StateHash, replayed.StateHash)
	if !strings.Contains(store.events("run-happy")[1].PayloadCanonical, `"ruling_id":"ruling-1"`) {
		t.Fatal("temporary ruling evidence was not committed")
	}
}

func TestFailuresAreStructuredAndAtomic(t *testing.T) {
	t.Run("schema and unknown fields", func(t *testing.T) {
		store := newMemoryStore()
		core := fixtureCore(t, store, counterHandler{}, nil, 10)
		run, _ := startFixtureRun(t, core, "run-schema")
		for _, raw := range [][]byte{[]byte(`{"schema":`), []byte(`{"schema":"aipt.action-proposal/v1","unknown":true}`)} {
			if _, err := run.Execute(context.Background(), raw); ErrorCode(err) != CodeInvalidAction {
				t.Fatalf("error = %v", err)
			}
		}
		if len(store.events("run-schema")) != 1 || run.State().Sequence != 1 {
			t.Fatal("schema rejection mutated authority")
		}
	})

	t.Run("authorization rule and source", func(t *testing.T) {
		for _, tc := range []struct {
			name             string
			code             Code
			authErr, ruleErr error
			mutate           func(*ActionProposal)
		}{
			{"unauthorized", CodeUnauthorizedAction, errors.New("private authorization detail"), nil, nil},
			{"missing source", CodeRuleReferenceRequired, nil, nil, func(p *ActionProposal) { p.Source = RuleSource{} }},
			{"rule invalid", CodeRuleValidationFailed, nil, errors.New("private rule detail"), nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				store := newMemoryStore()
				core, err := New(Config{
					Store: store, SeedSource: fixedSeedSource{fixtureSeed()},
					Authorizer: AuthorizerFunc(func(context.Context, RunState, ActionProposal) error { return tc.authErr }),
					Rules:      RuleValidatorFunc(func(context.Context, RunState, ActionProposal) error { return tc.ruleErr }),
					Handlers:   map[string]ActionHandler{"fixture.increment/v1": counterHandler{}},
				})
				if err != nil {
					t.Fatal(err)
				}
				run, _ := startFixtureRun(t, core, "run-boundary-"+strings.ReplaceAll(tc.name, " ", "-"))
				var proposal ActionProposal
				raw := proposalBytes(t, run.State().Binding.RunID, "action-1", 1, 1, nil, nil)
				_ = json.Unmarshal(raw, &proposal)
				if tc.mutate != nil {
					tc.mutate(&proposal)
				}
				raw, _ = json.Marshal(proposal)
				_, gotErr := run.Execute(context.Background(), raw)
				if ErrorCode(gotErr) != tc.code || strings.Contains(gotErr.Error(), "private") {
					t.Fatalf("error = %v, code=%s", gotErr, ErrorCode(gotErr))
				}
				if run.State().Sequence != 1 || len(store.events(run.State().Binding.RunID)) != 1 {
					t.Fatal("rejection mutated state")
				}
			})
		}
	})

	t.Run("unknown action payload precondition and apply", func(t *testing.T) {
		cases := []struct {
			name       string
			handler    counterHandler
			mutate     func(*ActionProposal)
			wantCode   Code
			privateTag string
		}{
			{
				name: "unknown action", wantCode: CodeInvalidAction,
				mutate: func(proposal *ActionProposal) { proposal.ActionType = "fixture.unknown/v1" },
			},
			{
				name: "invalid payload", wantCode: CodeInvalidAction,
				mutate: func(proposal *ActionProposal) { proposal.Payload = json.RawMessage(`{"delta":0}`) },
			},
			{name: "precondition", handler: counterHandler{rejectPrecond: true}, wantCode: CodeStateConflict, privateTag: "synthetic precondition"},
			{name: "apply", handler: counterHandler{rejectApply: true}, wantCode: CodeInvariantViolation, privateTag: "synthetic apply"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				store := newMemoryStore()
				core := fixtureCore(t, store, tc.handler, nil, 10)
				runID := "run-handler-" + strings.ReplaceAll(tc.name, " ", "-")
				run, _ := startFixtureRun(t, core, runID)
				var proposal ActionProposal
				if err := json.Unmarshal(proposalBytes(t, runID, "action-1", 1, 1, nil, nil), &proposal); err != nil {
					t.Fatal(err)
				}
				if tc.mutate != nil {
					tc.mutate(&proposal)
				}
				raw, err := json.Marshal(proposal)
				if err != nil {
					t.Fatal(err)
				}
				_, gotErr := run.Execute(context.Background(), raw)
				if ErrorCode(gotErr) != tc.wantCode {
					t.Fatalf("error = %v, code=%s want=%s", gotErr, ErrorCode(gotErr), tc.wantCode)
				}
				if tc.privateTag != "" && strings.Contains(gotErr.Error(), tc.privateTag) {
					t.Fatalf("private handler detail leaked: %v", gotErr)
				}
				if run.State().Sequence != 1 || len(store.events(runID)) != 1 || len(run.State().RNGCursors) != 0 {
					t.Fatal("handler rejection mutated authority")
				}
			})
		}
	})

	t.Run("stale invariant RNG handler ledger and cancellation", func(t *testing.T) {
		cases := []struct {
			name    string
			code    Code
			prepare func(*memoryStore, *counterHandler, *Core, *Run)
			raw     func(*testing.T, string) []byte
			cancel  bool
		}{
			{"stale", CodeStateConflict, nil, func(t *testing.T, id string) []byte { return proposalBytes(t, id, "a-stale", 2, 1, nil, nil) }, false},
			{"rng invalid", CodeRNGInvalid, nil, func(t *testing.T, id string) []byte {
				return proposalBytes(t, id, "a-rng", 1, 1, []RNGRequest{{StreamID: "bad stream", Count: 1}}, nil)
			}, false},
			{"invariant", CodeInvariantViolation, nil, func(t *testing.T, id string) []byte { return proposalBytes(t, id, "a-invariant", 1, 99, nil, nil) }, false},
			{"ledger", CodeLedgerCommitFailed, func(s *memoryStore, _ *counterHandler, _ *Core, _ *Run) { s.failNext = errors.New("DSN=private") }, func(t *testing.T, id string) []byte { return proposalBytes(t, id, "a-ledger", 1, 1, nil, nil) }, false},
			{"cancel", CodeStateConflict, nil, func(t *testing.T, id string) []byte { return proposalBytes(t, id, "a-cancel", 1, 1, nil, nil) }, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				store := newMemoryStore()
				handler := counterHandler{}
				core := fixtureCore(t, store, handler, nil, 10)
				runID := "run-atomic-" + strings.ReplaceAll(tc.name, " ", "-")
				run, _ := startFixtureRun(t, core, runID)
				if tc.prepare != nil {
					tc.prepare(store, &handler, core, run)
				}
				ctx := context.Background()
				if tc.cancel {
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				}
				_, err := run.Execute(ctx, tc.raw(t, runID))
				if ErrorCode(err) != tc.code || strings.Contains(err.Error(), "DSN") {
					t.Fatalf("error = %v code=%s", err, ErrorCode(err))
				}
				if run.State().Sequence != 1 || len(store.events(runID)) != 1 || len(run.State().RNGCursors) != 0 {
					t.Fatal("failed transaction advanced state, ledger, or RNG")
				}
			})
		}
	})
}

func TestMutationBoundaryDuplicateCrossRunAndConcurrency(t *testing.T) {
	store := newMemoryStore()
	core := fixtureCore(t, store, counterHandler{}, nil, 100)
	run, initial := startFixtureRun(t, core, "run-boundaries")
	if startEventID("run-boundaries") == actionEventID("run-boundaries", "start:v1") ||
		actionEventID("x", "y:action:z") == actionEventID("x:action:y", "z") {
		t.Fatal("length-delimited Run/action event identities collided")
	}
	exposed := run.State()
	exposed.Sequence = 99
	exposed.RNGCursors["forged"] = 99
	exposed.DomainState[0] = '['
	if actual := run.State(); actual.Sequence != 1 || len(actual.RNGCursors) != 0 || actual.DomainState[0] != '{' {
		t.Fatal("caller mutated authoritative state through returned view")
	}

	if _, err := run.Execute(context.Background(), proposalBytes(t, "another-run", "cross", 1, 1, nil, nil)); ErrorCode(err) != CodeStateConflict {
		t.Fatalf("cross-Run error = %v", err)
	}
	if _, err := run.Execute(context.Background(), proposalBytes(t, "run-boundaries", "dup", 1, 1, nil, nil)); err != nil {
		t.Fatalf("first duplicate probe action: %v", err)
	}
	if _, err := run.Execute(context.Background(), proposalBytes(t, "run-boundaries", "dup", 2, 1, nil, nil)); ErrorCode(err) != CodeStateConflict {
		t.Fatalf("duplicate event error = %v", err)
	}
	if len(store.events("run-boundaries")) != 2 || run.State().Sequence != 2 {
		t.Fatal("duplicate action double-committed")
	}

	concurrentStore := newMemoryStore()
	concurrentCore := fixtureCore(t, concurrentStore, counterHandler{}, nil, 100)
	_, startReceipt := startFixtureRun(t, concurrentCore, "run-race")
	left, err := concurrentCore.ResumeRun(context.Background(), fixtureBinding("run-race"), fixtureSeed(), startReceipt.StateHash)
	if err != nil {
		t.Fatal(err)
	}
	right, err := concurrentCore.ResumeRun(context.Background(), fixtureBinding("run-race"), fixtureSeed(), startReceipt.StateHash)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, candidate := range []*Run{left, right} {
		go func(n int, value *Run) {
			<-start
			_, err := value.Execute(context.Background(), proposalBytes(t, "run-race", fmt.Sprintf("race-%d", n), 1, 1, nil, nil))
			results <- err
		}(index, candidate)
	}
	close(start)
	var success, conflict int
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else if ErrorCode(err) == CodeStateConflict {
			conflict++
		} else {
			t.Fatalf("race error = %v", err)
		}
	}
	if success != 1 || conflict != 1 || len(concurrentStore.events("run-race")) != 2 {
		t.Fatalf("success=%d conflict=%d events=%d", success, conflict, len(concurrentStore.events("run-race")))
	}
	_ = initial
}

func TestRNGDeterminismDomainSeparationAndCommitment(t *testing.T) {
	binding := fixtureBinding("run-rng")
	commitment1, err := seedCommitment(binding, fixtureSeed())
	if err != nil {
		t.Fatal(err)
	}
	commitment2, _ := seedCommitment(binding, fixtureSeed())
	if commitment1 != commitment2 || !VerifySeedCommitment(binding, fixtureSeed(), commitment1) {
		t.Fatal("seed commitment is not stable/verifiable")
	}
	wrong := append([]byte(nil), fixtureSeed()...)
	wrong[0] ^= 1
	if VerifySeedCommitment(binding, wrong, commitment1) {
		t.Fatal("wrong seed verified")
	}
	a1, _ := deterministicDraw(fixtureSeed(), binding.RunID, "domain-a", 1)
	a1Again, _ := deterministicDraw(fixtureSeed(), binding.RunID, "domain-a", 1)
	b1, _ := deterministicDraw(fixtureSeed(), binding.RunID, "domain-b", 1)
	a2, _ := deterministicDraw(fixtureSeed(), binding.RunID, "domain-a", 2)
	b1Again, _ := deterministicDraw(fixtureSeed(), binding.RunID, "domain-b", 1)
	if a1 != a1Again || b1 != b1Again || a1 == b1 || a1 == a2 {
		t.Fatalf("draws a1=%s a2=%s b1=%s", a1, a2, b1)
	}
}

func TestReplayIntegrityFailures(t *testing.T) {
	store := newMemoryStore()
	core := fixtureCore(t, store, counterHandler{}, nil, 100)
	run, _ := startFixtureRun(t, core, "run-replay")
	if _, err := run.Execute(context.Background(), proposalBytes(t, "run-replay", "a1", 1, 1, []RNGRequest{{StreamID: "checks", Count: 1}}, nil)); err != nil {
		t.Fatal(err)
	}
	finalReceipt, err := run.Execute(context.Background(), proposalBytes(t, "run-replay", "a2", 2, 1, []RNGRequest{{StreamID: "checks", Count: 1}}, nil))
	if err != nil {
		t.Fatal(err)
	}
	original := store.events("run-replay")
	expectFailure := func(name string, input ReplayInput, code Code) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, err := core.Replay(context.Background(), input); ErrorCode(err) != code {
				t.Fatalf("error = %v, code=%s want=%s", err, ErrorCode(err), code)
			}
		})
	}
	base := ReplayInput{Binding: fixtureBinding("run-replay"), Seed: fixtureSeed(), Events: original, ExpectedFinalStateHash: finalReceipt.StateHash}

	missingMiddle := cloneLedgerEvents(original)
	missingMiddle = append(missingMiddle[:1], missingMiddle[2:]...)
	expectFailure("missing middle", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: missingMiddle, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
	expectFailure("missing tail", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: original[:2], ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayStateMismatch)
	reordered := cloneLedgerEvents(original)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	expectFailure("reordered", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: reordered, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
	mutated := cloneLedgerEvents(original)
	mutated[1].PayloadCanonical = strings.Replace(mutated[1].PayloadCanonical, `"counter":1`, `"counter":9`, 1)
	expectFailure("payload mutation", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: mutated, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
	wrongSeed := append([]byte(nil), fixtureSeed()...)
	wrongSeed[0] ^= 1
	expectFailure("seed mismatch", ReplayInput{Binding: base.Binding, Seed: wrongSeed, Events: original, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeRNGCommitmentMismatch)
	wrongBinding := fixtureBinding("run-replay")
	wrongBinding.Manifest.CanonicalSHA256 = strings.Repeat("9", 64)
	expectFailure("manifest substitution", ReplayInput{Binding: wrongBinding, Seed: base.Seed, Events: original, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
	wrongAdapter := fixtureBinding("run-replay")
	wrongAdapter.RuntimeAdapterInput.CanonicalSHA256 = strings.Repeat("8", 64)
	expectFailure("adapter substitution", ReplayInput{Binding: wrongAdapter, Seed: base.Seed, Events: original, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
	wrongSource := fixtureBinding("run-replay")
	wrongSource.SourcePackage.Tree = strings.Repeat("7", 40)
	expectFailure("source substitution", ReplayInput{Binding: wrongSource, Seed: base.Seed, Events: original, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
	expectFailure("final hash", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: original, ExpectedFinalStateHash: strings.Repeat("0", 64)}, CodeReplayStateMismatch)

	duplicateSequence := cloneLedgerEvents(original)
	duplicateSequence[2].Sequence = duplicateSequence[1].Sequence
	expectFailure("duplicate sequence", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: duplicateSequence, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)

	rngTampered := cloneLedgerEvents(original)
	event, _ := decodeRunEvent(rngTampered[1].PayloadCanonical)
	event.Action.RNGDraws[0].ValueHex = "0000000000000000"
	rngTampered[1].PayloadCanonical = string(mustCanonicalValue(t, event))
	rehashLedgerEvents(t, rngTampered)
	expectFailure("RNG evidence", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: rngTampered, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeRNGInvalid)

	unknownVersion := cloneLedgerEvents(original)
	event, _ = decodeRunEvent(unknownVersion[1].PayloadCanonical)
	event.Version = 99
	unknownVersion[1].PayloadCanonical = string(mustCanonicalValue(t, event))
	rehashLedgerEvents(t, unknownVersion)
	expectFailure("unknown event version", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: unknownVersion, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)

	unknownRNGVersion := cloneLedgerEvents(original)
	event, _ = decodeRunEvent(unknownRNGVersion[1].PayloadCanonical)
	event.RNGVersion = "AIPT_RNG_UNKNOWN_V99"
	event.AfterState.RNGVersion = "AIPT_RNG_UNKNOWN_V99"
	unknownRNGVersion[1].PayloadCanonical = string(mustCanonicalValue(t, event))
	rehashLedgerEvents(t, unknownRNGVersion)
	expectFailure("unknown RNG version", ReplayInput{Binding: base.Binding, Seed: base.Seed, Events: unknownRNGVersion, ExpectedFinalStateHash: base.ExpectedFinalStateHash}, CodeReplayInvalid)
}

func TestMalformedExternalInputsFailClosedWithoutPanic(t *testing.T) {
	store := newMemoryStore()
	core := fixtureCore(t, store, counterHandler{}, nil, 10)
	run, _ := startFixtureRun(t, core, "run-malicious")
	valid := string(proposalBytes(t, "run-malicious", "action-1", 1, 1, nil, nil))
	inputs := [][]byte{
		nil,
		[]byte(`null`),
		[]byte(`{"schema":"aipt.action-proposal/v1","schema":"aipt.action-proposal/v1"}`),
		[]byte(strings.Replace(valid, `"expected_sequence":1`, `"expected_sequence":9007199254740992`, 1)),
		[]byte(strings.Replace(valid, `"action_id":"action-1"`, `"action_id":"`+strings.Repeat("a", 129)+`"`, 1)),
		append([]byte(valid), 0xff),
	}
	for index, raw := range inputs {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("input %d panicked: %v", index, recovered)
				}
			}()
			if _, err := run.Execute(context.Background(), raw); ErrorCode(err) != CodeInvalidAction {
				t.Fatalf("input %d error=%v code=%s", index, err, ErrorCode(err))
			}
		}()
	}
	if run.State().Sequence != 1 || len(store.events("run-malicious")) != 1 {
		t.Fatal("malformed external input mutated authority")
	}
	var nilCore *Core
	if _, err := nilCore.ReplayStored(context.Background(), fixtureBinding("run-malicious"), fixtureSeed(), strings.Repeat("0", 64)); ErrorCode(err) != CodeReplayInvalid {
		t.Fatalf("nil Core ReplayStored error=%v code=%s", err, ErrorCode(err))
	}
	if _, err := core.ReplayStored(nil, fixtureBinding("run-malicious"), fixtureSeed(), strings.Repeat("0", 64)); ErrorCode(err) != CodeReplayInvalid {
		t.Fatalf("nil context ReplayStored error=%v code=%s", err, ErrorCode(err))
	}
}

func TestProjectionIsDerivedAndDeterminismStress(t *testing.T) {
	var baselineEvents []storagepostgres.LedgerEvent
	var baselineState, baselineProjection string
	for iteration := 0; iteration < 20; iteration++ {
		store := newMemoryStore()
		core := fixtureCore(t, store, counterHandler{}, nil, 100)
		run, _ := startFixtureRun(t, core, "run-stress")
		var receipt Receipt
		for action := 1; action <= 4; action++ {
			var err error
			receipt, err = run.Execute(context.Background(), proposalBytes(t, "run-stress", fmt.Sprintf("action-%d", action), int64(action), 1,
				[]RNGRequest{{StreamID: "domain-a", Count: 1}, {StreamID: "domain-b", Count: 1}}, nil))
			if err != nil {
				t.Fatal(err)
			}
		}
		events := store.events("run-stress")
		projection, _ := Project(run.State())
		if iteration == 0 {
			baselineEvents = events
			baselineState = receipt.StateHash
			baselineProjection = projection.SHA256
			projection.Canonical[0] ^= 1
			again, _ := Project(run.State())
			if again.SHA256 != baselineProjection {
				t.Fatal("projection tamper changed authority")
			}
			continue
		}
		if receipt.StateHash != baselineState || projection.SHA256 != baselineProjection || len(events) != len(baselineEvents) {
			t.Fatalf("iteration %d identities drifted", iteration)
		}
		for i := range events {
			if events[i].PayloadCanonical != baselineEvents[i].PayloadCanonical || events[i].EventHash != baselineEvents[i].EventHash {
				t.Fatalf("iteration %d event %d drifted", iteration, i)
			}
		}
	}
}

func mustCanonicalValue(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicalValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rehashLedgerEvents(t *testing.T, events []storagepostgres.LedgerEvent) {
	t.Helper()
	var previous *[32]byte
	for i := range events {
		events[i].Sequence = int64(i + 1)
		events[i].PayloadHash = sha256.Sum256([]byte(events[i].PayloadCanonical))
		events[i].PrevEventHash = previous
		hash, err := storagepostgres.ComputeLedgerEventHash(events[i].StreamID, events[i].Sequence, events[i].EventID, events[i].EventType, events[i].PayloadHash, previous)
		if err != nil {
			t.Fatal(err)
		}
		events[i].EventHash = hash
		value := hash
		previous = &value
	}
}
