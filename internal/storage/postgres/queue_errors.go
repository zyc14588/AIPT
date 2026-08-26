package postgres

import (
	"errors"
	"fmt"
)

var (
	ErrQueueInvalidInput  = errors.New("AIPT_QUEUE_INVALID_INPUT")
	ErrQueueRunExists     = errors.New("AIPT_QUEUE_RUN_EXISTS")
	ErrQueueRunNotFound   = errors.New("AIPT_QUEUE_RUN_NOT_FOUND")
	ErrQueueStateConflict = errors.New("AIPT_QUEUE_STATE_CONFLICT")
	ErrQueuePaused        = errors.New("AIPT_QUEUE_PAUSED")
	ErrQueueNoEligibleRun = errors.New("AIPT_QUEUE_NO_ELIGIBLE_RUN")
	ErrLeaseStale         = errors.New("AIPT_LEASE_STALE")
	ErrLeaseExpired       = errors.New("AIPT_LEASE_EXPIRED")
	ErrLeaseTokenSource   = errors.New("AIPT_LEASE_TOKEN_SOURCE_FAILURE")
	ErrAttemptConflict    = errors.New("AIPT_ATTEMPT_CONFLICT")
	ErrQueueStorage       = errors.New("AIPT_QUEUE_STORAGE_FAILURE")
)

// QueueError is the stable, typed error returned by every B001 mutating API.
// Error deliberately omits the underlying database error so a DSN, credential
// or private path can never enter a public diagnostic string.
type QueueError struct {
	Code      error
	Operation string
	RunID     string
	cause     error
}

func (e *QueueError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.RunID == "" {
		return fmt.Sprintf("%s: operation=%s", e.Code, e.Operation)
	}
	return fmt.Sprintf("%s: operation=%s run_id=%s", e.Code, e.Operation, e.RunID)
}

// Unwrap exposes only the stable AIPT_* code. The private cause is retained
// for internal classification but is never rendered or transitively exposed.
func (e *QueueError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Code
}

func queueError(code error, operation, runID string, cause error) error {
	return &QueueError{Code: code, Operation: operation, RunID: runID, cause: cause}
}
