package orchestrator

import (
	"errors"
	"fmt"
)

type Code string

const (
	CodeInvalidPolicy          Code = "INVALID_ORCHESTRATION_POLICY"
	CodeInvalidSeat            Code = "INVALID_SEAT"
	CodeSeatUnauthorized       Code = "SEAT_UNAUTHORIZED"
	CodeSessionBindingInvalid  Code = "SESSION_BINDING_INVALID"
	CodeVisibilityDenied       Code = "VISIBILITY_DENIED"
	CodeContextInvariantFailed Code = "CONTEXT_INVARIANT_FAILED"
	CodeFloorControlRejected   Code = "FLOOR_CONTROL_REJECTED"
	CodeInvalidAgentResponse   Code = "INVALID_AGENT_RESPONSE"
	CodeAgentProtocolFailed    Code = "AGENT_PROTOCOL_FAILED"
	CodeAgentTransportFailed   Code = "AGENT_TRANSPORT_FAILED"
	CodeRepairBudgetExhausted  Code = "REPAIR_BUDGET_EXHAUSTED"
	CodeRetryClassInvalid      Code = "RETRY_CLASSIFICATION_INVALID"
	CodeAgentSessionFailed     Code = "AGENT_SESSION_FAILED"
	CodeSessionRecoveryFailed  Code = "SESSION_RECOVERY_FAILED"
	CodeInvocationTimeout      Code = "AGENT_INVOCATION_TIMEOUT"
	CodeActionRejectedByCore   Code = "ACTION_REJECTED_BY_CORE"
	CodeDuplicateAction        Code = "DUPLICATE_ACTION"
	CodeRunTerminated          Code = "RUN_ORCHESTRATION_TERMINATED"
)

var sentinels = map[Code]error{}

func init() {
	for _, code := range []Code{
		CodeInvalidPolicy, CodeInvalidSeat, CodeSeatUnauthorized,
		CodeSessionBindingInvalid, CodeVisibilityDenied, CodeContextInvariantFailed,
		CodeFloorControlRejected, CodeInvalidAgentResponse, CodeAgentProtocolFailed, CodeAgentTransportFailed,
		CodeRepairBudgetExhausted, CodeRetryClassInvalid, CodeAgentSessionFailed,
		CodeSessionRecoveryFailed, CodeInvocationTimeout, CodeActionRejectedByCore,
		CodeDuplicateAction, CodeRunTerminated,
	} {
		sentinels[code] = errors.New(string(code))
	}
}

type Error struct {
	Code         Code   `json:"code"`
	Operation    string `json:"operation"`
	RunID        string `json:"run_id,omitempty"`
	SeatID       SeatID `json:"seat_id,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	cause        error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("%s: operation=%s", e.Code, e.Operation)
	if e.RunID != "" {
		message += " run_id=" + e.RunID
	}
	if e.SeatID != "" {
		message += " seat_id=" + string(e.SeatID)
	}
	if e.InvocationID != "" {
		message += " invocation_id=" + e.InvocationID
	}
	return message
}

func (e *Error) Is(target error) bool {
	return e != nil && target == sentinels[e.Code]
}

func Sentinel(code Code) error { return sentinels[code] }

func ErrorCode(err error) Code {
	var structured *Error
	if errors.As(err, &structured) {
		return structured.Code
	}
	return ""
}

func orchestrationError(code Code, operation, runID string, seatID SeatID, invocationID string, cause error) error {
	return &Error{Code: code, Operation: operation, RunID: runID, SeatID: seatID, InvocationID: invocationID, cause: cause}
}

type InvocationFailure struct {
	Class Code
}

func (e *InvocationFailure) Error() string {
	if e == nil {
		return "<nil>"
	}
	return string(e.Class)
}

func NewInvocationFailure(class Code) error {
	return &InvocationFailure{Class: class}
}

func invocationFailureCode(err error) Code {
	var failure *InvocationFailure
	if errors.As(err, &failure) {
		return failure.Class
	}
	return ""
}
