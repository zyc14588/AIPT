package orchestrator

import (
	"errors"
	"sort"
	"sync"
	"unicode/utf8"
)

type groupDecisionState struct {
	spec  GroupDecisionSpec
	votes map[SeatID]string
}

type FloorController struct {
	mu                     sync.Mutex
	runID                  string
	policy                 OrchestrationPolicy
	phase                  FloorPhase
	owner                  SeatID
	discussionIndex        int
	interruptedOwner       SeatID
	group                  *groupDecisionState
	clarificationRequester SeatID
	clarificationReference string
	events                 []OrchestrationEvent
}

func NewFloorController(runID string, policy OrchestrationPolicy) (*FloorController, error) {
	if err := validIdentity("run_id", runID); err != nil {
		return nil, err
	}
	if err := validatePolicy(policy); err != nil {
		return nil, err
	}
	return &FloorController{runID: runID, policy: clonePolicy(policy), phase: PhaseIdle}, nil
}

func clonePolicy(policy OrchestrationPolicy) OrchestrationPolicy {
	copy := policy
	copy.SeatOrder = cloneSeatIDs(policy.SeatOrder)
	copy.InterruptionOrder = cloneSeatIDs(policy.InterruptionOrder)
	return copy
}

func (f *FloorController) State() (FloorPhase, SeatID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.phase, f.owner
}

func (f *FloorController) Events() []OrchestrationEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	copy := make([]OrchestrationEvent, len(f.events))
	for index := range f.events {
		copy[index] = f.events[index]
		copy[index].Recipients = cloneSeatIDs(f.events[index].Recipients)
	}
	return copy
}

func (f *FloorController) emit(event OrchestrationEvent) {
	event.Schema = EventSchema
	event.Version = 1
	event.Sequence = int64(len(f.events) + 1)
	event.RunID = f.runID
	event.Recipients = sortSeatIDs(event.Recipients, f.policy.SeatOrder)
	f.events = append(f.events, event)
}

func (f *FloorController) OpenDiscussion() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseIdle {
		return f.floorError("open_discussion", "discussion can open only from IDLE")
	}
	f.phase = PhaseDiscussion
	f.discussionIndex = 0
	f.owner = f.policy.SeatOrder[0]
	f.emit(OrchestrationEvent{Type: EventTurnOpened, SeatID: f.owner, ReferenceID: "discussion", Outcome: string(PhaseDiscussion)})
	return nil
}

func (f *FloorController) AdvanceDiscussion(owner SeatID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseDiscussion || f.owner != owner {
		return f.floorError("advance_discussion", "only the current discussion owner may resolve the turn")
	}
	f.emit(OrchestrationEvent{Type: EventTurnResolved, SeatID: owner, ReferenceID: "discussion"})
	f.discussionIndex = (f.discussionIndex + 1) % len(f.policy.SeatOrder)
	f.owner = f.policy.SeatOrder[f.discussionIndex]
	f.emit(OrchestrationEvent{Type: EventTurnOpened, SeatID: f.owner, ReferenceID: "discussion", Outcome: string(PhaseDiscussion)})
	return nil
}

func (f *FloorController) ResolveInterruptions(requests []InterruptionRequest) (InterruptionRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseDiscussion || len(requests) == 0 {
		return InterruptionRequest{}, f.floorError("resolve_interruption", "interruption requires an active discussion and request")
	}
	seenIDs := map[string]struct{}{}
	seenSeats := map[SeatID]struct{}{}
	copy := append([]InterruptionRequest(nil), requests...)
	rank := make(map[SeatID]int, len(f.policy.InterruptionOrder))
	for index, seatID := range f.policy.InterruptionOrder {
		rank[seatID] = index
	}
	for _, request := range copy {
		if err := validIdentity("interruption.request_id", request.RequestID); err != nil ||
			validIdentity("interruption.reason_code", request.ReasonCode) != nil || !containsSeat(baselineSeatIDs(), request.SeatID) ||
			request.SeatID == f.owner {
			return InterruptionRequest{}, f.floorError("resolve_interruption", "invalid interruption request")
		}
		if _, exists := seenIDs[request.RequestID]; exists {
			return InterruptionRequest{}, f.floorError("resolve_interruption", "duplicate interruption request")
		}
		if _, exists := seenSeats[request.SeatID]; exists {
			return InterruptionRequest{}, f.floorError("resolve_interruption", "a seat may have one pending interruption")
		}
		seenIDs[request.RequestID] = struct{}{}
		seenSeats[request.SeatID] = struct{}{}
	}
	sort.Slice(copy, func(i, j int) bool {
		if rank[copy[i].SeatID] != rank[copy[j].SeatID] {
			return rank[copy[i].SeatID] < rank[copy[j].SeatID]
		}
		return copy[i].RequestID < copy[j].RequestID
	})
	for _, request := range copy {
		f.emit(OrchestrationEvent{Type: EventInterruptionRequested, SeatID: request.SeatID, ReferenceID: request.RequestID})
	}
	winner := copy[0]
	for index, request := range copy {
		outcome := "REJECTED"
		if index == 0 {
			outcome = "ACCEPTED"
		}
		f.emit(OrchestrationEvent{Type: EventInterruptionResolved, SeatID: request.SeatID, ReferenceID: request.RequestID, Outcome: outcome})
	}
	f.interruptedOwner = f.owner
	f.phase = PhaseInterruption
	f.owner = winner.SeatID
	return winner, nil
}

func (f *FloorController) EndInterruption(owner SeatID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseInterruption || f.owner != owner || f.interruptedOwner == "" {
		return f.floorError("end_interruption", "invalid interruption completion")
	}
	f.emit(OrchestrationEvent{Type: EventTurnResolved, SeatID: owner, ReferenceID: "interruption"})
	f.owner = f.interruptedOwner
	f.interruptedOwner = ""
	f.phase = PhaseDiscussion
	return nil
}

func (f *FloorController) RoutePrivateMessage(messageID string, sender SeatID, recipients []SeatID, content string) (EventWindowItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase == PhaseTerminated || !containsSeat(baselineSeatIDs(), sender) || validIdentity("private_message.message_id", messageID) != nil ||
		len(recipients) == 0 || len(content) == 0 || !utf8.ValidString(content) || len([]rune(content)) > 20_000 {
		return EventWindowItem{}, f.floorError("route_private_message", "invalid private message")
	}
	seen := map[SeatID]struct{}{}
	for _, recipient := range recipients {
		if !containsSeat(baselineSeatIDs(), recipient) || recipient == sender {
			return EventWindowItem{}, f.floorError("route_private_message", "invalid private recipient")
		}
		if _, exists := seen[recipient]; exists {
			return EventWindowItem{}, f.floorError("route_private_message", "duplicate private recipient")
		}
		seen[recipient] = struct{}{}
	}
	ordered := sortSeatIDs(recipients, f.policy.SeatOrder)
	previous := f.phase
	f.phase = PhasePrivateChat
	f.emit(OrchestrationEvent{
		Type: EventPrivateMessageRouted, SeatID: sender, Recipients: ordered, ReferenceID: messageID, Outcome: "ROUTED",
	})
	f.phase = previous
	visibleTo := append([]SeatID{sender}, ordered...)
	visibleTo = sortSeatIDs(visibleTo, f.policy.SeatOrder)
	return EventWindowItem{
		EventID: messageID, Classification: ClassTableHiddenRemoteAllowed, Scope: ScopeSeatPrivate,
		Recipients: visibleTo, Content: content, ContentSHA256: sha256String(content),
	}, nil
}

func (f *FloorController) OpenGroupDecision(spec GroupDecisionSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseDiscussion || validIdentity("group_decision.decision_id", spec.DecisionID) != nil ||
		len(spec.Participants) == 0 || len(spec.ChoiceOrder) < 2 ||
		(spec.TiePolicy != TieExplicitOrder && spec.TiePolicy != TieGMClarification) {
		return f.floorError("open_group_decision", "invalid group-decision contract")
	}
	participants := sortSeatIDs(spec.Participants, f.policy.SeatOrder)
	if !sameUniqueSeatList(participants) {
		return f.floorError("open_group_decision", "group participants are invalid")
	}
	choices := append([]string(nil), spec.ChoiceOrder...)
	choiceSeen := map[string]struct{}{}
	for _, choice := range choices {
		if err := validIdentity("group_decision.choice", choice); err != nil {
			return f.floorError("open_group_decision", "group choice identity invalid")
		}
		if _, exists := choiceSeen[choice]; exists {
			return f.floorError("open_group_decision", "duplicate group choice")
		}
		choiceSeen[choice] = struct{}{}
	}
	spec.Participants = participants
	spec.ChoiceOrder = choices
	f.group = &groupDecisionState{spec: spec, votes: map[SeatID]string{}}
	f.phase = PhaseGroupDecision
	f.owner = ""
	return nil
}

func sameUniqueSeatList(values []SeatID) bool {
	seen := map[SeatID]struct{}{}
	for _, value := range values {
		if !containsSeat(baselineSeatIDs(), value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (f *FloorController) RecordGroupVote(decisionID string, seatID SeatID, choice string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseGroupDecision || f.group == nil || f.group.spec.DecisionID != decisionID ||
		!containsSeat(f.group.spec.Participants, seatID) || !containsString(f.group.spec.ChoiceOrder, choice) {
		return f.floorError("record_group_vote", "invalid group vote")
	}
	if _, exists := f.group.votes[seatID]; exists {
		return f.floorError("record_group_vote", "duplicate group vote")
	}
	f.group.votes[seatID] = choice
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (f *FloorController) ResolveGroupDecision(decisionID string) (GroupDecisionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseGroupDecision || f.group == nil || f.group.spec.DecisionID != decisionID ||
		len(f.group.votes) != len(f.group.spec.Participants) {
		return GroupDecisionResult{}, f.floorError("resolve_group_decision", "group decision is incomplete")
	}
	responded := sortSeatIDs(f.group.spec.Participants, f.policy.SeatOrder)
	counts := make(map[string]int, len(f.group.spec.ChoiceOrder))
	for _, seatID := range responded {
		choice := f.group.votes[seatID]
		counts[choice]++
		f.emit(OrchestrationEvent{Type: EventGroupVoteRecorded, SeatID: seatID, ReferenceID: decisionID, Outcome: choice})
	}
	bestCount := -1
	winners := make([]string, 0, len(f.group.spec.ChoiceOrder))
	for _, choice := range f.group.spec.ChoiceOrder {
		count := counts[choice]
		switch {
		case count > bestCount:
			bestCount = count
			winners = []string{choice}
		case count == bestCount:
			winners = append(winners, choice)
		}
	}
	result := GroupDecisionResult{DecisionID: decisionID, Responded: responded}
	if len(winners) > 1 && f.group.spec.TiePolicy == TieGMClarification {
		result.GMClarificationNeeded = true
		f.phase = PhaseGMClarification
		f.owner = SeatGM
		f.clarificationRequester = SeatGM
		f.clarificationReference = decisionID
		f.emit(OrchestrationEvent{Type: EventGroupDecisionResolved, SeatID: SeatGM, ReferenceID: decisionID, Outcome: "GM_CLARIFICATION_REQUIRED"})
	} else {
		result.Outcome = winners[0]
		f.phase = PhaseDiscussion
		f.owner = f.policy.SeatOrder[f.discussionIndex]
		f.emit(OrchestrationEvent{Type: EventGroupDecisionResolved, ReferenceID: decisionID, Outcome: result.Outcome})
	}
	f.group = nil
	return result, nil
}

func (f *FloorController) RequestGMClarification(requestID string, requester SeatID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseDiscussion || requester == SeatGM || !containsSeat(baselineSeatIDs(), requester) ||
		validIdentity("clarification.request_id", requestID) != nil {
		return f.floorError("request_gm_clarification", "invalid GM clarification request")
	}
	f.phase = PhaseGMClarification
	f.owner = SeatGM
	f.clarificationRequester = requester
	f.clarificationReference = requestID
	f.emit(OrchestrationEvent{Type: EventGMClarificationRequested, SeatID: requester, Recipients: []SeatID{SeatGM}, ReferenceID: requestID})
	return nil
}

func (f *FloorController) RespondGMClarification(requestID string, responder SeatID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase != PhaseGMClarification || f.owner != SeatGM || responder != SeatGM || requestID != f.clarificationReference ||
		validIdentity("clarification.request_id", requestID) != nil {
		return f.floorError("respond_gm_clarification", "invalid GM clarification response")
	}
	recipients := []SeatID{}
	if f.clarificationRequester != SeatGM && f.clarificationRequester != "" {
		recipients = []SeatID{f.clarificationRequester}
	}
	f.emit(OrchestrationEvent{Type: EventGMClarificationResponded, SeatID: SeatGM, Recipients: recipients, ReferenceID: requestID})
	f.phase = PhaseDiscussion
	f.owner = f.policy.SeatOrder[f.discussionIndex]
	f.clarificationRequester = ""
	f.clarificationReference = ""
	return nil
}

func (f *FloorController) Terminate(referenceID string, code Code) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.phase == PhaseTerminated {
		return
	}
	f.phase = PhaseTerminated
	f.owner = ""
	f.emit(OrchestrationEvent{Type: EventRunTerminated, ReferenceID: referenceID, Outcome: string(code)})
}

func (f *FloorController) floorError(operation, reason string) error {
	return orchestrationError(CodeFloorControlRejected, operation, f.runID, f.owner, "", errors.New(reason))
}

func DeterministicNoProgress(events []OrchestrationEvent, window int) (bool, error) {
	if window <= 0 || window > len(events) {
		return false, errors.New("invalid no-progress window")
	}
	for _, event := range events[len(events)-window:] {
		if event.Type == EventActionAccepted {
			return false, nil
		}
	}
	return true, nil
}

func ValidateObserverSignal(signal ObserverSignal, runID string) error {
	if signal.Schema != ObserverSchema || signal.RunID != runID {
		return errors.New("Observer signal binding invalid")
	}
	for _, item := range []struct{ field, value string }{
		{"signal_id", signal.SignalID}, {"window_id", signal.WindowID}, {"kind", signal.Kind},
	} {
		if err := validIdentity(item.field, item.value); err != nil {
			return err
		}
	}
	return nil
}
