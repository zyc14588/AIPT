package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/runcore"
)

type EngineConfig struct {
	RunID            string
	Policy           OrchestrationPolicy
	Seats            []Seat
	SessionAuthority *SessionAuthority
	Invoker          AgentInvoker
	Retriever        Retriever
	Submitter        ActionSubmitter
	Clock            Clock
}

type TurnResult struct {
	Response AgentResponse
	Receipt  *runcore.Receipt
	Context  ContextBundle
}

type Engine struct {
	mu          sync.Mutex
	runID       string
	policy      OrchestrationPolicy
	seats       map[SeatID]Seat
	sessions    *sessionRegistry
	personas    *PersonaTracker
	floor       *FloorController
	invoker     AgentInvoker
	retriever   Retriever
	submitter   ActionSubmitter
	clock       Clock
	events      []OrchestrationEvent
	invocations map[string]struct{}
	actions     map[string]struct{}
	terminated  bool
}

func NewEngine(config EngineConfig) (*Engine, error) {
	if err := validIdentity("run_id", config.RunID); err != nil {
		return nil, err
	}
	if err := validatePolicy(config.Policy); err != nil {
		return nil, orchestrationError(CodeInvalidPolicy, "new_engine", config.RunID, "", "", err)
	}
	if err := validateSeatPlan(config.RunID, config.Seats); err != nil {
		return nil, orchestrationError(CodeInvalidSeat, "new_engine", config.RunID, "", "", err)
	}
	if config.Invoker == nil || config.Submitter == nil || config.Clock == nil || config.SessionAuthority == nil {
		return nil, orchestrationError(CodeInvalidPolicy, "new_engine", config.RunID, "", "", errors.New("Invoker, Submitter, Clock, and SessionAuthority are required"))
	}
	sessions, err := newSessionRegistry(config.RunID, config.Seats, config.SessionAuthority)
	if err != nil {
		return nil, orchestrationError(CodeSessionBindingInvalid, "new_engine", config.RunID, "", "", err)
	}
	personas, err := NewPersonaTracker(config.RunID, config.Seats)
	if err != nil {
		return nil, orchestrationError(CodeInvalidSeat, "new_engine", config.RunID, "", "", err)
	}
	floor, err := NewFloorController(config.RunID, config.Policy)
	if err != nil {
		return nil, err
	}
	engine := &Engine{
		runID: config.RunID, policy: clonePolicy(config.Policy), seats: map[SeatID]Seat{},
		sessions: sessions, personas: personas, floor: floor, invoker: config.Invoker,
		retriever: config.Retriever, submitter: config.Submitter, clock: config.Clock,
		invocations: map[string]struct{}{}, actions: map[string]struct{}{},
	}
	for _, seatID := range config.Policy.SeatOrder {
		for _, candidate := range config.Seats {
			if candidate.SeatID == seatID {
				candidate.Persona = clonePersona(candidate.Persona)
				candidate.Character = cloneCharacter(candidate.Character)
				engine.seats[seatID] = candidate
				engine.emit(OrchestrationEvent{Type: EventSessionCreated, SeatID: seatID, ReferenceID: candidate.Session.SessionID})
				break
			}
		}
	}
	return engine, nil
}

func (e *Engine) Floor() *FloorController { return e.floor }

func (e *Engine) Personas() *PersonaTracker { return e.personas }

func (e *Engine) Events() []OrchestrationEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	copy := make([]OrchestrationEvent, len(e.events))
	for index := range e.events {
		copy[index] = e.events[index]
		copy[index].Recipients = cloneSeatIDs(e.events[index].Recipients)
	}
	return copy
}

func (e *Engine) emit(event OrchestrationEvent) {
	event.Schema = EventSchema
	event.Version = 1
	event.Sequence = int64(len(e.events) + 1)
	event.RunID = e.runID
	event.Recipients = sortSeatIDs(event.Recipients, e.policy.SeatOrder)
	e.events = append(e.events, event)
}

func (e *Engine) InvokeSeat(ctx context.Context, seatID SeatID, invocationID string, input ContextInput) (TurnResult, error) {
	const operation = "invoke_seat"
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.terminated {
		return TurnResult{}, orchestrationError(CodeRunTerminated, operation, e.runID, seatID, invocationID, errors.New("Run orchestration terminated"))
	}
	if ctx == nil || ctx.Err() != nil || validIdentity("invocation_id", invocationID) != nil {
		return TurnResult{}, orchestrationError(CodeInvalidAgentResponse, operation, e.runID, seatID, invocationID, errors.New("invalid invocation input"))
	}
	seat, exists := e.seats[seatID]
	if !exists {
		return TurnResult{}, orchestrationError(CodeSeatUnauthorized, operation, e.runID, seatID, invocationID, errors.New("unknown seat"))
	}
	phase, owner := e.floor.State()
	if phase == PhaseTerminated || owner != seatID || (phase != PhaseDiscussion && phase != PhaseInterruption && phase != PhaseGMClarification) {
		return TurnResult{}, orchestrationError(CodeFloorControlRejected, operation, e.runID, seatID, invocationID, errors.New("seat does not own the floor"))
	}
	if _, exists := e.invocations[invocationID]; exists {
		return TurnResult{}, orchestrationError(CodeDuplicateAction, operation, e.runID, seatID, invocationID, errors.New("invocation already resolved"))
	}
	session, exists := e.sessions.get(seatID)
	if !exists || session.RunID != e.runID || session.SeatID != seatID {
		return TurnResult{}, orchestrationError(CodeSessionBindingInvalid, operation, e.runID, seatID, invocationID, errors.New("Session binding invalid"))
	}
	seat.Session = session
	state, exists := e.personas.State(seatID)
	if !exists {
		return TurnResult{}, orchestrationError(CodeContextInvariantFailed, operation, e.runID, seatID, invocationID, errors.New("Persona state missing"))
	}
	bundle, err := BuildContext(ctx, e.policy, seat, state, input, e.retriever)
	if err != nil {
		return TurnResult{}, err
	}
	// An invocation identity becomes single-use at the first audited Agent
	// attempt. All permitted retry/recovery paths stay inside this method, so a
	// rejected Core action or failed protocol cannot be replayed as an
	// unrecorded second top-level invocation.
	e.invocations[invocationID] = struct{}{}
	e.emit(OrchestrationEvent{Type: EventSeatInvoked, SeatID: seatID, ReferenceID: invocationID, AttemptClass: AttemptOriginal, Ordinal: 1, ContextHash: bundle.ContextHash})

	semanticRepairs := 0
	transportRetries := 0
	recoveries := 0
	attempt := 1
	kind := InvocationOriginal
	failureCode := Code("")
	responseHash := ""
	for {
		started := e.clock.Now().UTC()
		deadline := started.Add(time.Duration(e.policy.InvocationTimeoutMillis) * time.Millisecond)
		request := InvocationRequest{
			InvocationID: invocationID, RunID: e.runID, SeatID: seatID, SessionID: session.SessionID,
			Kind: kind, Attempt: attempt, Deadline: deadline, Context: bundle,
			FailureCode: failureCode, ResponseHash: responseHash,
		}
		result, invokeErr := e.invoker.Invoke(ctx, session, request)
		if contextErr := ValidateContextHash(bundle); contextErr != nil {
			e.terminate(invocationID, CodeContextInvariantFailed)
			return TurnResult{}, orchestrationError(CodeContextInvariantFailed, operation, e.runID, seatID, invocationID, contextErr)
		}
		if invokeErr != nil {
			class := invocationFailureCode(invokeErr)
			switch class {
			case CodeAgentTransportFailed, CodeInvocationTimeout:
				if class == CodeInvocationTimeout {
					e.emit(OrchestrationEvent{Type: EventInvocationTimeout, SeatID: seatID, ReferenceID: invocationID, AttemptClass: attemptClass(kind), Ordinal: attempt})
				}
				if transportRetries >= e.policy.TransportRetryBudget {
					e.terminate(invocationID, class)
					return TurnResult{}, orchestrationError(CodeAgentProtocolFailed, operation, e.runID, seatID, invocationID, invokeErr)
				}
				transportRetries++
				attempt++
				e.emit(OrchestrationEvent{Type: EventTransportRetry, SeatID: seatID, ReferenceID: invocationID, AttemptClass: AttemptTransportRetry, Ordinal: transportRetries})
				continue
			case CodeAgentSessionFailed:
				if recoveries >= e.policy.SessionRecoveryBudget {
					e.terminate(invocationID, CodeSessionRecoveryFailed)
					return TurnResult{}, orchestrationError(CodeSessionRecoveryFailed, operation, e.runID, seatID, invocationID, invokeErr)
				}
				recoveries++
				next, recoveryErr := e.invoker.Recover(ctx, session, RecoveryRequest{
					RunID: e.runID, SeatID: seatID, OldSessionID: session.SessionID,
					ReasonCode: class, RecoveryOrdinal: recoveries,
				})
				if recoveryErr != nil || e.sessions.recover(session, next) != nil {
					e.terminate(invocationID, CodeSessionRecoveryFailed)
					return TurnResult{}, orchestrationError(CodeSessionRecoveryFailed, operation, e.runID, seatID, invocationID, errors.New("bounded Session recovery rejected"))
				}
				oldID := session.SessionID
				session = next
				seat.Session = next
				e.seats[seatID] = seat
				bundle, err = rebindContextSession(bundle, next)
				if err != nil {
					e.terminate(invocationID, CodeSessionRecoveryFailed)
					return TurnResult{}, orchestrationError(CodeSessionRecoveryFailed, operation, e.runID, seatID, invocationID, err)
				}
				attempt++
				e.emit(OrchestrationEvent{
					Type: EventSessionRecovery, SeatID: seatID, ReferenceID: invocationID,
					Outcome: string(class), AttemptClass: AttemptSessionRecovery, Ordinal: recoveries,
					OldSessionID: oldID, NewSessionID: next.SessionID,
				})
				continue
			default:
				e.terminate(invocationID, CodeRetryClassInvalid)
				return TurnResult{}, orchestrationError(CodeRetryClassInvalid, operation, e.runID, seatID, invocationID, invokeErr)
			}
		}
		completed := result.CompletedAt.UTC()
		if result.CompletedAt.IsZero() {
			completed = e.clock.Now().UTC()
		}
		if completed.Before(started) {
			e.terminate(invocationID, CodeRetryClassInvalid)
			return TurnResult{}, orchestrationError(CodeRetryClassInvalid, operation, e.runID, seatID, invocationID, errors.New("invocation result predates its audited attempt"))
		}
		if completed.After(deadline) {
			e.emit(OrchestrationEvent{Type: EventInvocationTimeout, SeatID: seatID, ReferenceID: invocationID, AttemptClass: attemptClass(kind), Ordinal: attempt})
			if transportRetries >= e.policy.TransportRetryBudget {
				e.terminate(invocationID, CodeInvocationTimeout)
				return TurnResult{}, orchestrationError(CodeAgentProtocolFailed, operation, e.runID, seatID, invocationID, errors.New("invocation completed after deadline"))
			}
			transportRetries++
			attempt++
			e.emit(OrchestrationEvent{Type: EventTransportRetry, SeatID: seatID, ReferenceID: invocationID, AttemptClass: AttemptTransportRetry, Ordinal: transportRetries})
			continue
		}
		response, decodeErr := decodeAgentResponse(result.Response, invocationID, e.runID, seatID, session.SessionID)
		if decodeErr != nil {
			responseHash = sha256Bytes(result.Response)
			if semanticRepairs >= e.policy.SemanticRepairBudget {
				e.emit(OrchestrationEvent{Type: EventProtocolRepairResult, SeatID: seatID, ReferenceID: invocationID, Outcome: string(CodeRepairBudgetExhausted), AttemptClass: attemptClass(kind), Ordinal: attempt})
				e.terminate(invocationID, CodeAgentProtocolFailed)
				return TurnResult{}, orchestrationError(CodeAgentProtocolFailed, operation, e.runID, seatID, invocationID, decodeErr)
			}
			semanticRepairs++
			attempt++
			kind = InvocationRepair
			failureCode = CodeInvalidAgentResponse
			e.emit(OrchestrationEvent{Type: EventProtocolRepairRequested, SeatID: seatID, ReferenceID: invocationID, Outcome: string(CodeInvalidAgentResponse), AttemptClass: AttemptSemanticRetry, Ordinal: semanticRepairs, ContextHash: bundle.ContextHash})
			continue
		}
		if kind == InvocationRepair {
			e.emit(OrchestrationEvent{Type: EventProtocolRepairResult, SeatID: seatID, ReferenceID: invocationID, Outcome: "ACCEPTED", AttemptClass: AttemptSemanticRetry, Ordinal: semanticRepairs, ContextHash: bundle.ContextHash})
		}
		turn := TurnResult{Response: response, Context: bundle}
		if response.Action != nil {
			if _, exists := e.actions[response.Action.ActionID]; exists {
				return TurnResult{}, orchestrationError(CodeDuplicateAction, operation, e.runID, seatID, invocationID, errors.New("action already submitted"))
			}
			e.emit(OrchestrationEvent{Type: EventActionProposed, SeatID: seatID, ReferenceID: invocationID, ActionID: response.Action.ActionID})
			receipt, submitErr := e.submitter.Submit(ctx, *response.Action)
			if submitErr != nil {
				e.emit(OrchestrationEvent{Type: EventActionRejected, SeatID: seatID, ReferenceID: invocationID, ActionID: response.Action.ActionID, Outcome: string(CodeActionRejectedByCore)})
				return TurnResult{}, orchestrationError(CodeActionRejectedByCore, operation, e.runID, seatID, invocationID, submitErr)
			}
			e.actions[response.Action.ActionID] = struct{}{}
			turn.Receipt = &receipt
			e.emit(OrchestrationEvent{Type: EventActionAccepted, SeatID: seatID, ReferenceID: invocationID, ActionID: response.Action.ActionID, Outcome: "COMMITTED"})
		} else {
			e.emit(OrchestrationEvent{Type: EventMessageEmitted, SeatID: seatID, ReferenceID: invocationID, Outcome: "SPEECH_ONLY"})
		}
		e.emit(OrchestrationEvent{Type: EventTurnResolved, SeatID: seatID, ReferenceID: invocationID})
		return turn, nil
	}
}

func attemptClass(kind InvocationKind) AttemptClass {
	if kind == InvocationRepair {
		return AttemptSemanticRetry
	}
	return AttemptOriginal
}

func (e *Engine) terminate(invocationID string, code Code) {
	if e.terminated {
		return
	}
	e.terminated = true
	e.emit(OrchestrationEvent{Type: EventRunTerminated, ReferenceID: invocationID, Outcome: string(code)})
	e.floor.Terminate(invocationID, code)
}

func decodeAgentResponse(raw []byte, invocationID, runID string, seatID SeatID, sessionID string) (AgentResponse, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return AgentResponse{}, errors.New("Agent response is empty or exceeds the bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response AgentResponse
	if err := decoder.Decode(&response); err != nil {
		return AgentResponse{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return AgentResponse{}, errors.New("Agent response has trailing content")
	}
	if response.Schema != AgentResponseSchema || response.Metadata.ProtocolVersion != "v1" {
		return AgentResponse{}, errors.New("unknown Agent response or protocol version")
	}
	if response.InvocationID != invocationID || response.RunID != runID || response.SeatID != seatID || response.SessionID != sessionID {
		return AgentResponse{}, errors.New("Agent response identity binding mismatch")
	}
	if !utf8.ValidString(response.Speech) || len([]rune(response.Speech)) > 20_000 {
		return AgentResponse{}, errors.New("Agent speech is invalid or exceeds the bound")
	}
	if response.Speech == "" && response.Action == nil {
		return AgentResponse{}, errors.New("Agent response contains neither speech nor action")
	}
	if response.Action == nil {
		if response.Metadata.SpeechActionClaim != nil {
			return AgentResponse{}, errors.New("speech-only response cannot claim an action")
		}
		return response, nil
	}
	action := response.Action
	if action.Schema != runcore.ActionProposalSchema || action.RunID != runID || action.ActorID != string(seatID) {
		return AgentResponse{}, errors.New("structured action binding is invalid")
	}
	if err := validIdentity("action_id", action.ActionID); err != nil || validIdentity("action_type", action.ActionType) != nil {
		return AgentResponse{}, errors.New("structured action identity is invalid")
	}
	if response.Speech != "" {
		claim := response.Metadata.SpeechActionClaim
		if claim == nil || claim.ActionID != action.ActionID || claim.ActionType != action.ActionType {
			return AgentResponse{}, errors.New("speech/action semantic claim conflicts with structured action")
		}
	}
	return response, nil
}

// RunCoreSubmitter is the sole production integration adapter. It has no
// state mutation capability of its own and delegates exactly one validated
// ActionProposal to the accepted B002 Run Core transaction pipeline.
type RunCoreSubmitter struct {
	Run *runcore.Run
}

func (s RunCoreSubmitter) Submit(ctx context.Context, proposal runcore.ActionProposal) (runcore.Receipt, error) {
	if s.Run == nil {
		return runcore.Receipt{}, errors.New("nil Run Core Run")
	}
	// B002 hashes the decoded proposal before cloning it into the event. Keep
	// zero-length collections in their canonical nil form so the event replay
	// representation is byte-equivalent to the originally hashed proposal.
	if len(proposal.RNGRequests) == 0 {
		proposal.RNGRequests = nil
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return runcore.Receipt{}, fmt.Errorf("marshal ActionProposal: %w", err)
	}
	return s.Run.Execute(ctx, raw)
}
