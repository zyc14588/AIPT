package launcher

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable machine-readable launcher error code.
type ErrorCode string

const (
	CodeInvalidOptions     ErrorCode = "AIPT_LAUNCH_INVALID_OPTIONS"
	CodeCancelled          ErrorCode = "AIPT_LAUNCH_CANCELLED"
	CodeGateFailed         ErrorCode = "AIPT_LAUNCH_GATE_FAILED"
	CodeGateNotImplemented ErrorCode = "AIPT_LAUNCH_GATE_NOT_IMPLEMENTED"
	CodeShutdownFailed     ErrorCode = "AIPT_LAUNCH_SHUTDOWN_FAILED"
	CodeShutdownTimeout    ErrorCode = "AIPT_LAUNCH_SHUTDOWN_TIMEOUT"
)

var (
	ErrInvalidOptions     = errors.New(string(CodeInvalidOptions))
	ErrCancelled          = errors.New(string(CodeCancelled))
	ErrGateFailed         = errors.New(string(CodeGateFailed))
	ErrGateNotImplemented = errors.New(string(CodeGateNotImplemented))
	ErrShutdownFailed     = errors.New(string(CodeShutdownFailed))
	ErrShutdownTimeout    = errors.New(string(CodeShutdownTimeout))
)

// GateError retains the original cause for errors.Is/errors.As while its own
// deterministic Error string omits cause text. This prevents a provider or
// PostgreSQL driver error from reflecting a credential-bearing DSN into logs.
type GateError struct {
	Code      ErrorCode
	Gate      Gate
	Operation string
	Cause     error
}

func (e *GateError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := string(e.Code)
	if e.Gate != "" {
		message += ": gate=" + string(e.Gate)
	}
	if e.Operation != "" {
		message += " operation=" + e.Operation
	}
	return message
}

func (e *GateError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *GateError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch e.Code {
	case CodeInvalidOptions:
		return target == ErrInvalidOptions
	case CodeCancelled:
		return target == ErrCancelled
	case CodeGateFailed:
		return target == ErrGateFailed
	case CodeGateNotImplemented:
		return target == ErrGateNotImplemented
	case CodeShutdownFailed:
		return target == ErrShutdownFailed
	case CodeShutdownTimeout:
		return target == ErrShutdownTimeout
	default:
		return false
	}
}

func newGateError(code ErrorCode, gate Gate, operation string, cause error) error {
	if cause == nil {
		cause = fmt.Errorf("%s", operation)
	}
	return &GateError{Code: code, Gate: gate, Operation: operation, Cause: cause}
}

// CodeOf returns the first launcher error code in err's unwrap tree.
func CodeOf(err error) ErrorCode {
	var gateError *GateError
	if !errors.As(err, &gateError) || gateError == nil {
		return ""
	}
	return gateError.Code
}

// GateOf returns the first launcher gate in err's unwrap tree.
func GateOf(err error) Gate {
	var gateError *GateError
	if !errors.As(err, &gateError) || gateError == nil {
		return ""
	}
	return gateError.Gate
}
