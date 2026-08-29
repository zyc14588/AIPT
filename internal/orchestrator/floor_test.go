package orchestrator

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestDeterministicDiscussionAndInterruption(t *testing.T) {
	policy := fixturePolicy()
	floor, err := NewFloorController("run-floor", policy)
	if err != nil {
		t.Fatalf("NewFloorController: %v", err)
	}
	if err := floor.OpenDiscussion(); err != nil {
		t.Fatalf("OpenDiscussion: %v", err)
	}
	owners := []SeatID{}
	for range 7 {
		phase, owner := floor.State()
		if phase != PhaseDiscussion {
			t.Fatalf("phase = %s", phase)
		}
		owners = append(owners, owner)
		if err := floor.AdvanceDiscussion(owner); err != nil {
			t.Fatalf("AdvanceDiscussion: %v", err)
		}
	}
	want := []SeatID{SeatGM, SeatPlayer1, SeatPlayer2, SeatPlayer3, SeatPlayer4, SeatGM, SeatPlayer1}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners = %v, want %v", owners, want)
	}

	_, current := floor.State()
	winner, err := floor.ResolveInterruptions([]InterruptionRequest{
		{RequestID: "interrupt-p1", SeatID: SeatPlayer1, ReasonCode: "QUESTION"},
		{RequestID: "interrupt-p3", SeatID: SeatPlayer3, ReasonCode: "SAFETY"},
		{RequestID: "interrupt-p4", SeatID: SeatPlayer4, ReasonCode: "CORRECTION"},
	})
	if err != nil {
		t.Fatalf("ResolveInterruptions: %v", err)
	}
	if winner.SeatID != SeatPlayer3 {
		t.Fatalf("winner = %+v", winner)
	}
	phase, owner := floor.State()
	if phase != PhaseInterruption || owner != SeatPlayer3 {
		t.Fatalf("interruption state = %s/%s", phase, owner)
	}
	if err := floor.EndInterruption(SeatPlayer3); err != nil {
		t.Fatalf("EndInterruption: %v", err)
	}
	phase, owner = floor.State()
	if phase != PhaseDiscussion || owner != current {
		t.Fatalf("restored floor = %s/%s, want %s", phase, owner, current)
	}
	if _, err := floor.ResolveInterruptions([]InterruptionRequest{{RequestID: "self", SeatID: current, ReasonCode: "SELF"}}); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
		t.Fatalf("current owner interruption accepted: %v", err)
	}
}

func TestPrivateChatRoutingIsolation(t *testing.T) {
	floor, _ := NewFloorController("run-private", fixturePolicy())
	_ = floor.OpenDiscussion()
	probes := []struct {
		id         string
		sender     SeatID
		recipients []SeatID
	}{
		{"p1-to-p2", SeatPlayer1, []SeatID{SeatPlayer2}},
		{"p1-to-gm", SeatPlayer1, []SeatID{SeatGM}},
		{"gm-to-p4", SeatGM, []SeatID{SeatPlayer4}},
	}
	for _, probe := range probes {
		item, err := floor.RoutePrivateMessage(probe.id, probe.sender, probe.recipients, "private:"+probe.id)
		if err != nil {
			t.Fatalf("RoutePrivateMessage(%s): %v", probe.id, err)
		}
		for _, seatID := range BaselineSeatIDs {
			shouldSee := seatID == probe.sender || containsSeat(probe.recipients, seatID)
			seat := seatByID(t, fixtureSeats(t, "run-private"), seatID)
			window, _, err := authorizeEventWindow("run-private", seat, []EventWindowItem{item}, 10)
			if err != nil {
				t.Fatalf("authorizeEventWindow(%s): %v", seatID, err)
			}
			if (len(window) == 1) != shouldSee {
				t.Fatalf("%s visibility for %s = %d, shouldSee=%t", probe.id, seatID, len(window), shouldSee)
			}
		}
	}
	if _, err := floor.RoutePrivateMessage("bad", SeatPlayer1, []SeatID{SeatPlayer1}, "private"); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
		t.Fatalf("self private recipient accepted: %v", err)
	}
	if _, err := floor.RoutePrivateMessage("bad2", SeatPlayer1, []SeatID{"PLAYER_99"}, "private"); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
		t.Fatalf("unknown private recipient accepted: %v", err)
	}
	for _, event := range floor.Events() {
		if event.ReferenceID != "" && event.Outcome != "" && (event.Outcome == "private:p1-to-p2" || event.Outcome == "private:p1-to-gm") {
			t.Fatalf("private payload leaked into event: %+v", event)
		}
	}
}

func TestGroupDecisionDeterministicAcrossArrivalOrders(t *testing.T) {
	run := func(order []SeatID) (GroupDecisionResult, []OrchestrationEvent) {
		floor, _ := NewFloorController("run-group", fixturePolicy())
		_ = floor.OpenDiscussion()
		spec := GroupDecisionSpec{
			DecisionID: "decision-1", Participants: []SeatID{SeatPlayer4, SeatPlayer2, SeatPlayer1, SeatPlayer3},
			ChoiceOrder: []string{"NORTH", "SOUTH"}, TiePolicy: TieExplicitOrder,
		}
		if err := floor.OpenGroupDecision(spec); err != nil {
			t.Fatalf("OpenGroupDecision: %v", err)
		}
		votes := map[SeatID]string{SeatPlayer1: "NORTH", SeatPlayer2: "SOUTH", SeatPlayer3: "NORTH", SeatPlayer4: "SOUTH"}
		var wg sync.WaitGroup
		for _, seatID := range order {
			seatID := seatID
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := floor.RecordGroupVote("decision-1", seatID, votes[seatID]); err != nil {
					t.Errorf("RecordGroupVote(%s): %v", seatID, err)
				}
			}()
		}
		wg.Wait()
		result, err := floor.ResolveGroupDecision("decision-1")
		if err != nil {
			t.Fatalf("ResolveGroupDecision: %v", err)
		}
		return result, floor.Events()
	}
	first, firstEvents := run([]SeatID{SeatPlayer4, SeatPlayer1, SeatPlayer3, SeatPlayer2})
	second, secondEvents := run([]SeatID{SeatPlayer2, SeatPlayer3, SeatPlayer1, SeatPlayer4})
	if first.Outcome != "NORTH" || first.GMClarificationNeeded || !reflect.DeepEqual(first, second) || !reflect.DeepEqual(firstEvents, secondEvents) {
		t.Fatalf("group decision drift: first=%+v second=%+v", first, second)
	}
}

func TestGroupDecisionTieAndExplicitGMClarification(t *testing.T) {
	floor, _ := NewFloorController("run-clarification", fixturePolicy())
	_ = floor.OpenDiscussion()
	if err := floor.OpenGroupDecision(GroupDecisionSpec{
		DecisionID: "decision-tie", Participants: []SeatID{SeatPlayer1, SeatPlayer2},
		ChoiceOrder: []string{"A", "B"}, TiePolicy: TieGMClarification,
	}); err != nil {
		t.Fatalf("OpenGroupDecision: %v", err)
	}
	_ = floor.RecordGroupVote("decision-tie", SeatPlayer2, "B")
	_ = floor.RecordGroupVote("decision-tie", SeatPlayer1, "A")
	result, err := floor.ResolveGroupDecision("decision-tie")
	if err != nil || !result.GMClarificationNeeded || result.Outcome != "" {
		t.Fatalf("tie result = %+v, %v", result, err)
	}
	phase, owner := floor.State()
	if phase != PhaseGMClarification || owner != SeatGM {
		t.Fatalf("tie floor = %s/%s", phase, owner)
	}
	if err := floor.RespondGMClarification("decision-tie", SeatGM); err != nil {
		t.Fatalf("RespondGMClarification: %v", err)
	}

	floor2, _ := NewFloorController("run-clarification-2", fixturePolicy())
	_ = floor2.OpenDiscussion()
	if err := floor2.RequestGMClarification("clarify-1", SeatPlayer2); err != nil {
		t.Fatalf("RequestGMClarification: %v", err)
	}
	if err := floor2.RespondGMClarification("clarify-1", SeatPlayer1); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
		t.Fatalf("non-GM clarification accepted: %v", err)
	}
	if err := floor2.RespondGMClarification("clarify-other", SeatGM); !errors.Is(err, Sentinel(CodeFloorControlRejected)) {
		t.Fatalf("mismatched clarification response accepted: %v", err)
	}
	if err := floor2.RespondGMClarification("clarify-1", SeatGM); err != nil {
		t.Fatalf("GM response: %v", err)
	}
}

func TestObserverSignalAndDeterministicNoProgress(t *testing.T) {
	events := []OrchestrationEvent{
		{Type: EventTurnResolved}, {Type: EventMessageEmitted}, {Type: EventTurnResolved},
	}
	noProgress, err := DeterministicNoProgress(events, 3)
	if err != nil || !noProgress {
		t.Fatalf("no-progress = %t, %v", noProgress, err)
	}
	events[1].Type = EventActionAccepted
	noProgress, err = DeterministicNoProgress(events, 3)
	if err != nil || noProgress {
		t.Fatalf("progress = %t, %v", noProgress, err)
	}
	if err := ValidateObserverSignal(ObserverSignal{
		Schema: ObserverSchema, SignalID: "observer-signal-1", RunID: "run-observer", WindowID: "window-1", Kind: "STALL_HINT",
	}, "run-observer"); err != nil {
		t.Fatalf("ValidateObserverSignal: %v", err)
	}
	if err := ValidateObserverSignal(ObserverSignal{Schema: ObserverSchema, SignalID: "signal", RunID: "wrong", WindowID: "window", Kind: "HINT"}, "run-observer"); err == nil {
		t.Fatal("cross-Run Observer signal accepted")
	}
}
