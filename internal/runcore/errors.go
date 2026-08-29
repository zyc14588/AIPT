package runcore

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable Run Core error category. Error strings
// deliberately contain bounded identities only and never render the private
// cause, action payload, seed, DSN, credential, or filesystem path.
type Code string

const (
	CodeInvalidAction         Code = "INVALID_ACTION"
	CodeUnauthorizedAction    Code = "UNAUTHORIZED_ACTION"
	CodeRuleReferenceRequired Code = "RULE_REFERENCE_REQUIRED"
	CodeRuleValidationFailed  Code = "RULE_VALIDATION_FAILED"
	CodeStateConflict         Code = "STATE_CONFLICT"
	CodeInvariantViolation    Code = "INVARIANT_VIOLATION"
	CodeRNGInvalid            Code = "RNG_INVALID"
	CodeRNGCommitmentMismatch Code = "RNG_COMMITMENT_MISMATCH"
	CodeLedgerCommitFailed    Code = "LEDGER_COMMIT_FAILED"
	CodeReplayInvalid         Code = "REPLAY_INVALID"
	CodeReplayStateMismatch   Code = "REPLAY_STATE_MISMATCH"
)

var codeSentinels = map[Code]error{
	CodeInvalidAction:         errors.New(string(CodeInvalidAction)),
	CodeUnauthorizedAction:    errors.New(string(CodeUnauthorizedAction)),
	CodeRuleReferenceRequired: errors.New(string(CodeRuleReferenceRequired)),
	CodeRuleValidationFailed:  errors.New(string(CodeRuleValidationFailed)),
	CodeStateConflict:         errors.New(string(CodeStateConflict)),
	CodeInvariantViolation:    errors.New(string(CodeInvariantViolation)),
	CodeRNGInvalid:            errors.New(string(CodeRNGInvalid)),
	CodeRNGCommitmentMismatch: errors.New(string(CodeRNGCommitmentMismatch)),
	CodeLedgerCommitFailed:    errors.New(string(CodeLedgerCommitFailed)),
	CodeReplayInvalid:         errors.New(string(CodeReplayInvalid)),
	CodeReplayStateMismatch:   errors.New(string(CodeReplayStateMismatch)),
}

// Sentinel returns the stable errors.Is target for a code.
func Sentinel(code Code) error { return codeSentinels[code] }

// Error is the structured public failure surface. cause is retained for
// internal classification but is intentionally neither rendered nor unwrapped.
type Error struct {
	Code      Code   `json:"code"`
	Operation string `json:"operation"`
	RunID     string `json:"run_id,omitempty"`
	ActionID  string `json:"action_id,omitempty"`
	cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := fmt.Sprintf("%s: operation=%s", e.Code, e.Operation)
	if e.RunID != "" {
		message += " run_id=" + e.RunID
	}
	if e.ActionID != "" {
		message += " action_id=" + e.ActionID
	}
	return message
}

func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}
	return target == codeSentinels[e.Code]
}

func coreError(code Code, operation, runID, actionID string, cause error) error {
	return &Error{Code: code, Operation: operation, RunID: runID, ActionID: actionID, cause: cause}
}

// ErrorCode returns a stable category without requiring message parsing.
func ErrorCode(err error) Code {
	var structured *Error
	if errors.As(err, &structured) {
		return structured.Code
	}
	return ""
}
