package core

import (
	"errors"
	"fmt"
)

// Code is a stable machine-readable core lifecycle error code.
type Code string

const (
	CodeInvalidOptions    Code = "AIPT_CORE_INVALID_OPTIONS"
	CodeInvalidTransition Code = "AIPT_CORE_INVALID_TRANSITION"
	CodeStartCancelled    Code = "AIPT_CORE_START_CANCELLED"
	CodeDependencyStart   Code = "AIPT_CORE_DEPENDENCY_START"
	CodeDependencyReady   Code = "AIPT_CORE_DEPENDENCY_READY"
	CodeDependencyStop    Code = "AIPT_CORE_DEPENDENCY_STOP"
	CodeShutdownTimeout   Code = "AIPT_CORE_SHUTDOWN_TIMEOUT"
)

var (
	ErrInvalidOptions    = errors.New(string(CodeInvalidOptions))
	ErrInvalidTransition = errors.New(string(CodeInvalidTransition))
	ErrStartCancelled    = errors.New(string(CodeStartCancelled))
	ErrDependencyStart   = errors.New(string(CodeDependencyStart))
	ErrDependencyReady   = errors.New(string(CodeDependencyReady))
	ErrDependencyStop    = errors.New(string(CodeDependencyStop))
	ErrShutdownTimeout   = errors.New(string(CodeShutdownTimeout))
)

// LifecycleError carries a stable code and bounded lifecycle metadata while
// retaining the original dependency/context error through errors.Is/As.
type LifecycleError struct {
	Code       Code
	Operation  string
	Dependency string
	State      State
	Cause      error
}

func (e *LifecycleError) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := string(e.Code) + ": operation=" + e.Operation
	if e.Dependency != "" {
		message += " dependency=" + e.Dependency
	}
	if e.State != "" {
		message += " state=" + string(e.State)
	}
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *LifecycleError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *LifecycleError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch e.Code {
	case CodeInvalidOptions:
		return target == ErrInvalidOptions
	case CodeInvalidTransition:
		return target == ErrInvalidTransition
	case CodeStartCancelled:
		return target == ErrStartCancelled
	case CodeDependencyStart:
		return target == ErrDependencyStart
	case CodeDependencyReady:
		return target == ErrDependencyReady
	case CodeDependencyStop:
		return target == ErrDependencyStop
	case CodeShutdownTimeout:
		return target == ErrShutdownTimeout
	default:
		return false
	}
}

func lifecycleError(code Code, operation, dependency string, state State, cause error) error {
	if cause == nil {
		cause = fmt.Errorf("%s failed", operation)
	}
	return &LifecycleError{
		Code:       code,
		Operation:  operation,
		Dependency: dependency,
		State:      state,
		Cause:      cause,
	}
}
