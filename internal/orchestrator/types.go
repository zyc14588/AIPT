package orchestrator

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zyc14588/AIPT/internal/runcore"
)

const (
	PolicySchema        = "aipt.orchestration-policy/v1"
	SessionSchema       = "aipt.agent-session/v1"
	PersonaEventSchema  = "aipt.persona-event/v1"
	ContextSchema       = "aipt.context-bundle/v1"
	AgentResponseSchema = "aipt.agent-response/v1"
	EventSchema         = "aipt.orchestration-event/v1"
	ObserverSchema      = "aipt.observer-signal/v1"
)

type SeatID string

const (
	SeatGM      SeatID = "GM"
	SeatPlayer1 SeatID = "PLAYER_1"
	SeatPlayer2 SeatID = "PLAYER_2"
	SeatPlayer3 SeatID = "PLAYER_3"
	SeatPlayer4 SeatID = "PLAYER_4"
)

var BaselineSeatIDs = baselineSeatIDs()

// BaselineSeats returns a fresh copy of the versioned MVP table identities.
// Engine authority never depends on the exported convenience slice, which a
// caller could otherwise mutate in place.
func BaselineSeats() []SeatID { return baselineSeatIDs() }

func baselineSeatIDs() []SeatID {
	return []SeatID{SeatGM, SeatPlayer1, SeatPlayer2, SeatPlayer3, SeatPlayer4}
}

type Role string

const (
	RoleGM     Role = "GM"
	RolePlayer Role = "PLAYER"
)

type GMProfile string

const (
	GMProfileNeutral       GMProfile = "neutral"
	GMProfileSkilled       GMProfile = "skilled"
	GMProfileRulesFaithful GMProfile = "rules-faithful"
)

type OrchestrationPolicy struct {
	Schema                  string   `json:"schema"`
	PolicyID                string   `json:"policy_id"`
	SeatOrder               []SeatID `json:"seat_order"`
	InterruptionOrder       []SeatID `json:"interruption_order"`
	SemanticRepairBudget    int      `json:"semantic_repair_budget"`
	TransportRetryBudget    int      `json:"transport_retry_budget"`
	SessionRecoveryBudget   int      `json:"session_recovery_budget"`
	InvocationTimeoutMillis int64    `json:"invocation_timeout_millis"`
	MaxContextSources       int      `json:"max_context_sources"`
	MaxEventWindow          int      `json:"max_event_window"`
}

type Session struct {
	Schema          string `json:"schema"`
	SessionID       string `json:"session_id"`
	RunID           string `json:"run_id"`
	SeatID          SeatID `json:"seat_id"`
	Generation      int    `json:"generation"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
}

type PersonaTrait struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

type PersonaBaseline struct {
	PersonaID string         `json:"persona_id"`
	Version   string         `json:"version"`
	Traits    []PersonaTrait `json:"traits"`
	SHA256    string         `json:"sha256"`
}

type PersonaState struct {
	Version                  string `json:"version"`
	PersonaID                string `json:"persona_id"`
	RunID                    string `json:"run_id"`
	SeatID                   SeatID `json:"seat_id"`
	Misunderstanding         int    `json:"misunderstanding"`
	Forgetting               int    `json:"forgetting"`
	Stress                   int    `json:"stress"`
	SuboptimalDecisionBias   int    `json:"suboptimal_decision_bias"`
	LastPersonaEventSequence int64  `json:"last_persona_event_sequence"`
}

type PersonaEventKind string

const (
	PersonaMisunderstanding       PersonaEventKind = "MISUNDERSTANDING"
	PersonaForgetting             PersonaEventKind = "FORGETTING"
	PersonaStress                 PersonaEventKind = "STRESS"
	PersonaSuboptimalDecisionBias PersonaEventKind = "SUBOPTIMAL_DECISION_BIAS"
)

type PersonaEvent struct {
	Schema    string           `json:"schema"`
	EventID   string           `json:"event_id"`
	RunID     string           `json:"run_id"`
	SeatID    SeatID           `json:"seat_id"`
	PersonaID string           `json:"persona_id"`
	Sequence  int64            `json:"sequence"`
	Kind      PersonaEventKind `json:"kind"`
	Delta     int              `json:"delta"`
}

type Character struct {
	CharacterID      string          `json:"character_id"`
	Version          string          `json:"version"`
	Projection       json.RawMessage `json:"projection"`
	ProjectionSHA256 string          `json:"projection_sha256"`
}

type Seat struct {
	SeatID         SeatID          `json:"seat_id"`
	RunID          string          `json:"run_id"`
	Role           Role            `json:"role"`
	RoleContractID string          `json:"role_contract_id"`
	VisibilityID   string          `json:"visibility_id"`
	Session        Session         `json:"session"`
	Persona        PersonaBaseline `json:"persona"`
	Character      *Character      `json:"character,omitempty"`
	GMProfile      GMProfile       `json:"gm_profile,omitempty"`
}

type VisibilityScope string

const (
	ScopePublic         VisibilityScope = "PUBLIC"
	ScopeGMOnly         VisibilityScope = "GM_ONLY"
	ScopeSeatPrivate    VisibilityScope = "SEAT_PRIVATE"
	ScopeSystemInternal VisibilityScope = "SYSTEM_INTERNAL"
)

type DataClassification string

const (
	ClassPublic                   DataClassification = "PUBLIC"
	ClassUnreleasedRemoteAllowed  DataClassification = "UNRELEASED_REMOTE_ALLOWED"
	ClassTableHiddenRemoteAllowed DataClassification = "TABLE_HIDDEN_REMOTE_ALLOWED"
	ClassLocalOnlySecret          DataClassification = "LOCAL_ONLY_SECRET"
	ClassHumanPrivateData         DataClassification = "HUMAN_PRIVATE_DATA"
	ClassCredentialSecret         DataClassification = "CREDENTIAL_SECRET"
	ClassSystemInternal           DataClassification = "SYSTEM_INTERNAL"
)

type StateFact struct {
	FactID         string             `json:"fact_id"`
	Classification DataClassification `json:"classification"`
	Scope          VisibilityScope    `json:"scope"`
	AllowedSeats   []SeatID           `json:"allowed_seats"`
	Value          json.RawMessage    `json:"value"`
	ValueSHA256    string             `json:"value_sha256"`
}

type AuthorizedView struct {
	RunID  string      `json:"run_id"`
	SeatID SeatID      `json:"seat_id"`
	Facts  []StateFact `json:"facts"`
	SHA256 string      `json:"sha256"`
}

type SourceDescriptor struct {
	SourceID       string             `json:"source_id"`
	Classification DataClassification `json:"classification"`
	Scope          VisibilityScope    `json:"scope"`
	AllowedSeats   []SeatID           `json:"allowed_seats"`
	ExpectedSHA256 string             `json:"expected_sha256"`
}

type AuthorizedSource struct {
	SourceID       string             `json:"source_id"`
	Classification DataClassification `json:"classification"`
	ExpectedSHA256 string             `json:"expected_sha256"`
}

type RetrievedContent struct {
	SourceID       string             `json:"source_id"`
	Classification DataClassification `json:"classification"`
	Content        string             `json:"content"`
	ContentSHA256  string             `json:"content_sha256"`
}

type Retriever interface {
	Retrieve(context.Context, []AuthorizedSource) ([]RetrievedContent, error)
}

type SummaryFact struct {
	FactID      string `json:"fact_id"`
	ValueSHA256 string `json:"value_sha256"`
}

type MemorySummary struct {
	SummaryID       string        `json:"summary_id"`
	Version         string        `json:"version"`
	RunID           string        `json:"run_id"`
	SeatID          SeatID        `json:"seat_id"`
	Facts           []SummaryFact `json:"facts"`
	RequiredFactIDs []string      `json:"required_fact_ids"`
	SourceIDs       []string      `json:"source_ids"`
	SHA256          string        `json:"sha256"`
}

type EventWindowItem struct {
	EventID        string             `json:"event_id"`
	Classification DataClassification `json:"classification"`
	Scope          VisibilityScope    `json:"scope"`
	Recipients     []SeatID           `json:"recipients"`
	Content        string             `json:"content"`
	ContentSHA256  string             `json:"content_sha256"`
}

type ToolDescriptor struct {
	ToolID       string   `json:"tool_id"`
	Version      string   `json:"version"`
	AllowedRoles []Role   `json:"allowed_roles"`
	AllowedSeats []SeatID `json:"allowed_seats"`
}

type AvailableTool struct {
	ToolID  string `json:"tool_id"`
	Version string `json:"version"`
}

type TrustedContext struct {
	RoleContractID string          `json:"role_contract_id"`
	PolicyID       string          `json:"policy_id"`
	Persona        PersonaBaseline `json:"persona"`
	PersonaState   PersonaState    `json:"persona_state"`
	Character      *Character      `json:"character,omitempty"`
	GMProfile      GMProfile       `json:"gm_profile,omitempty"`
	AvailableTools []AvailableTool `json:"available_tools"`
}

type UntrustedContext struct {
	AuthorizedState AuthorizedView     `json:"authorized_state"`
	EventWindow     []EventWindowItem  `json:"event_window"`
	MemorySummary   MemorySummary      `json:"memory_summary"`
	Retrieved       []RetrievedContent `json:"retrieved"`
}

type ContextBundle struct {
	Schema                   string           `json:"schema"`
	ContextVersion           string           `json:"context_version"`
	RunID                    string           `json:"run_id"`
	SeatID                   SeatID           `json:"seat_id"`
	SessionID                string           `json:"session_id"`
	AuthorizedProjectionHash string           `json:"authorized_projection_hash"`
	PersonaID                string           `json:"persona_id"`
	CharacterID              string           `json:"character_id,omitempty"`
	EventWindowID            string           `json:"event_window_id"`
	SummaryID                string           `json:"summary_id"`
	ToolCapabilityID         string           `json:"tool_capability_id"`
	Trusted                  TrustedContext   `json:"trusted"`
	Untrusted                UntrustedContext `json:"untrusted"`
	ContextHash              string           `json:"context_hash"`
}

type ContextInput struct {
	StateFacts       []StateFact
	RequestedSources []SourceDescriptor
	EventWindow      []EventWindowItem
	Summary          MemorySummary
	Tools            []ToolDescriptor
}

type SpeechActionClaim struct {
	ActionID   string `json:"action_id"`
	ActionType string `json:"action_type"`
}

type ProtocolMetadata struct {
	ProtocolVersion   string             `json:"protocol_version"`
	SpeechActionClaim *SpeechActionClaim `json:"speech_action_claim,omitempty"`
}

type AgentResponse struct {
	Schema       string                  `json:"schema"`
	InvocationID string                  `json:"invocation_id"`
	RunID        string                  `json:"run_id"`
	SeatID       SeatID                  `json:"seat_id"`
	SessionID    string                  `json:"session_id"`
	Speech       string                  `json:"speech"`
	Action       *runcore.ActionProposal `json:"action,omitempty"`
	Metadata     ProtocolMetadata        `json:"metadata"`
}

type InvocationKind string

const (
	InvocationOriginal InvocationKind = "ORIGINAL"
	InvocationRepair   InvocationKind = "SEMANTIC_REPAIR"
)

type InvocationRequest struct {
	InvocationID string         `json:"invocation_id"`
	RunID        string         `json:"run_id"`
	SeatID       SeatID         `json:"seat_id"`
	SessionID    string         `json:"session_id"`
	Kind         InvocationKind `json:"kind"`
	Attempt      int            `json:"attempt"`
	Deadline     time.Time      `json:"deadline"`
	Context      ContextBundle  `json:"context"`
	FailureCode  Code           `json:"failure_code,omitempty"`
	ResponseHash string         `json:"response_hash,omitempty"`
}

type InvocationResult struct {
	Response    []byte
	CompletedAt time.Time
}

type RecoveryRequest struct {
	RunID           string `json:"run_id"`
	SeatID          SeatID `json:"seat_id"`
	OldSessionID    string `json:"old_session_id"`
	ReasonCode      Code   `json:"reason_code"`
	RecoveryOrdinal int    `json:"recovery_ordinal"`
}

type AgentInvoker interface {
	Invoke(context.Context, Session, InvocationRequest) (InvocationResult, error)
	Recover(context.Context, Session, RecoveryRequest) (Session, error)
}

type Clock interface {
	Now() time.Time
}

type ActionSubmitter interface {
	Submit(context.Context, runcore.ActionProposal) (runcore.Receipt, error)
}

type FloorPhase string

const (
	PhaseIdle            FloorPhase = "IDLE"
	PhaseDiscussion      FloorPhase = "DISCUSSION"
	PhaseInterruption    FloorPhase = "INTERRUPTION"
	PhasePrivateChat     FloorPhase = "PRIVATE_CHAT"
	PhaseGroupDecision   FloorPhase = "GROUP_DECISION"
	PhaseGMClarification FloorPhase = "GM_CLARIFICATION"
	PhaseTerminated      FloorPhase = "TERMINATED"
)

type EventType string

const (
	EventSessionCreated           EventType = "SESSION_CREATED"
	EventTurnOpened               EventType = "TURN_OPENED"
	EventSeatInvoked              EventType = "SEAT_INVOKED"
	EventMessageEmitted           EventType = "MESSAGE_EMITTED"
	EventPrivateMessageRouted     EventType = "PRIVATE_MESSAGE_ROUTED"
	EventActionProposed           EventType = "ACTION_PROPOSED"
	EventActionAccepted           EventType = "ACTION_ACCEPTED"
	EventActionRejected           EventType = "ACTION_REJECTED"
	EventProtocolRepairRequested  EventType = "PROTOCOL_REPAIR_REQUESTED"
	EventProtocolRepairResult     EventType = "PROTOCOL_REPAIR_RESULT"
	EventTransportRetry           EventType = "TRANSPORT_RETRY"
	EventInvocationTimeout        EventType = "INVOCATION_TIMEOUT"
	EventSessionRecovery          EventType = "SESSION_RECOVERY"
	EventInterruptionRequested    EventType = "INTERRUPTION_REQUESTED"
	EventInterruptionResolved     EventType = "INTERRUPTION_RESOLVED"
	EventGroupVoteRecorded        EventType = "GROUP_VOTE_RECORDED"
	EventGroupDecisionResolved    EventType = "GROUP_DECISION_RESOLVED"
	EventGMClarificationRequested EventType = "GM_CLARIFICATION_REQUESTED"
	EventGMClarificationResponded EventType = "GM_CLARIFICATION_RESPONDED"
	EventTurnResolved             EventType = "TURN_RESOLVED"
	EventRunTerminated            EventType = "RUN_ORCHESTRATION_TERMINATED"
)

type AttemptClass string

const (
	AttemptOriginal        AttemptClass = "ORIGINAL"
	AttemptTransportRetry  AttemptClass = "TRANSPORT_RETRY"
	AttemptSemanticRetry   AttemptClass = "SEMANTIC_RETRY"
	AttemptSessionRecovery AttemptClass = "SESSION_RECOVERY"
)

type OrchestrationEvent struct {
	Schema       string       `json:"schema"`
	Version      int          `json:"version"`
	Sequence     int64        `json:"sequence"`
	Type         EventType    `json:"type"`
	RunID        string       `json:"run_id"`
	SeatID       SeatID       `json:"seat_id,omitempty"`
	Recipients   []SeatID     `json:"recipients"`
	ReferenceID  string       `json:"reference_id,omitempty"`
	Outcome      string       `json:"outcome,omitempty"`
	AttemptClass AttemptClass `json:"attempt_class,omitempty"`
	Ordinal      int          `json:"ordinal,omitempty"`
	ContextHash  string       `json:"context_hash,omitempty"`
	ActionID     string       `json:"action_id,omitempty"`
	OldSessionID string       `json:"old_session_id,omitempty"`
	NewSessionID string       `json:"new_session_id,omitempty"`
}

type InterruptionRequest struct {
	RequestID  string `json:"request_id"`
	SeatID     SeatID `json:"seat_id"`
	ReasonCode string `json:"reason_code"`
}

type TiePolicy string

const (
	TieExplicitOrder   TiePolicy = "EXPLICIT_ORDER"
	TieGMClarification TiePolicy = "GM_CLARIFICATION"
)

type GroupDecisionSpec struct {
	DecisionID   string    `json:"decision_id"`
	Participants []SeatID  `json:"participants"`
	ChoiceOrder  []string  `json:"choice_order"`
	TiePolicy    TiePolicy `json:"tie_policy"`
}

type GroupDecisionResult struct {
	DecisionID            string   `json:"decision_id"`
	Responded             []SeatID `json:"responded"`
	Outcome               string   `json:"outcome,omitempty"`
	GMClarificationNeeded bool     `json:"gm_clarification_needed"`
}

type ObserverSignal struct {
	Schema   string `json:"schema"`
	SignalID string `json:"signal_id"`
	RunID    string `json:"run_id"`
	WindowID string `json:"window_id"`
	Kind     string `json:"kind"`
}
