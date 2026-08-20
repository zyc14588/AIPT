package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/launcher"
)

type fakeRuntime struct {
	run func(context.Context) error
}

func (r fakeRuntime) Run(ctx context.Context) error {
	return r.run(ctx)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func unusedContextFactory(t *testing.T) processContextFactory {
	t.Helper()
	return func() (context.Context, func()) {
		t.Fatal("process context must not be created")
		return nil, nil
	}
}

func unusedRuntimeFactory(t *testing.T) runtimeFactory {
	t.Helper()
	return func(string) (runtime, error) {
		t.Fatal("runtime must not be created")
		return nil, nil
	}
}

func TestPlanIsDeterministicAndDoesNotStartRuntime(t *testing.T) {
	run := func() string {
		t.Helper()
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := execute(
			[]string{"plan"},
			&stdout,
			&stderr,
			unusedRuntimeFactory(t),
			unusedContextFactory(t),
		)
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("plan exit=%d stderr=%q", code, stderr.String())
		}
		var plan launcher.LaunchPlan
		if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
			t.Fatalf("plan JSON: %v", err)
		}
		if plan.RuntimeReady || plan.FirstBlockingGate != launcher.GateModel {
			t.Fatalf("plan claims readiness: %+v", plan)
		}
		return stdout.String()
	}
	first := run()
	second := run()
	if first != second {
		t.Fatalf("plan output is not deterministic:\n%s\n%s", first, second)
	}
}

func TestHelpAndUsage(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := execute(
				[]string{arg},
				&stdout,
				&stderr,
				unusedRuntimeFactory(t),
				unusedContextFactory(t),
			)
			if code != 0 || stdout.String() != usage || stderr.Len() != 0 {
				t.Fatalf("help exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}

	tests := [][]string{
		nil,
		{"unknown"},
		{"run"},
		{"run", "--config"},
		{"run", "--config", ""},
		{"run", "--config", "config.json", "extra"},
		{"plan", "extra"},
	}
	for index, args := range tests {
		t.Run("invalid-"+string(rune('a'+index)), func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := execute(
				args,
				&stdout,
				&stderr,
				unusedRuntimeFactory(t),
				unusedContextFactory(t),
			)
			if code != 2 || stdout.Len() != 0 ||
				!strings.Contains(stderr.String(), codeUsage) ||
				!strings.HasSuffix(stderr.String(), usage) {
				t.Fatalf("usage exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunEmitsOnlyStableLauncherClassification(t *testing.T) {
	secretCause := errors.New("postgres://user:password-secret@host/database")
	runtimeError := &launcher.GateError{
		Code:      launcher.CodeGateNotImplemented,
		Gate:      launcher.GateModel,
		Operation: "start",
		Cause:     secretCause,
	}
	var stopCalls atomic.Int32
	contextFactory := func() (context.Context, func()) {
		return context.Background(), func() { stopCalls.Add(1) }
	}
	factory := func(path string) (runtime, error) {
		if path != "/safe/config.json" {
			t.Errorf("config path = %q", path)
		}
		return fakeRuntime{run: func(context.Context) error {
			return runtimeError
		}}, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := execute(
		[]string{"run", "--config", "/safe/config.json"},
		&stdout,
		&stderr,
		factory,
		contextFactory,
	)
	if code != 1 || stdout.Len() != 0 || stopCalls.Load() != 1 {
		t.Fatalf("run exit=%d stdout=%q stop_calls=%d", code, stdout.String(), stopCalls.Load())
	}
	if strings.Contains(stderr.String(), "password-secret") ||
		strings.Contains(stderr.String(), "postgres://") {
		t.Fatalf("stderr leaks runtime cause: %s", stderr.String())
	}
	var report map[string]string
	if err := json.Unmarshal(stderr.Bytes(), &report); err != nil {
		t.Fatalf("stderr JSON: %v", err)
	}
	if report["schema"] != cliErrorSchema ||
		report["error_code"] != string(launcher.CodeGateNotImplemented) ||
		report["gate"] != string(launcher.GateModel) {
		t.Fatalf("error report = %v", report)
	}
}

func TestRunPropagatesProcessContextAndStopsNotification(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stopCalls atomic.Int32
	contextFactory := func() (context.Context, func()) {
		return ctx, func() { stopCalls.Add(1) }
	}
	var sawCancellation atomic.Bool
	factory := func(string) (runtime, error) {
		return fakeRuntime{run: func(runContext context.Context) error {
			if errors.Is(runContext.Err(), context.Canceled) {
				sawCancellation.Store(true)
			}
			return nil
		}}, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := execute(
		[]string{"run", "--config", "config.json"},
		&stdout,
		&stderr,
		factory,
		contextFactory,
	)
	if code != 0 || !sawCancellation.Load() || stopCalls.Load() != 1 || stderr.Len() != 0 {
		t.Fatalf("run exit=%d cancelled=%v stop_calls=%d stderr=%q",
			code, sawCancellation.Load(), stopCalls.Load(), stderr.String())
	}
	var result map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["schema"] != cliResultSchema || result["result"] != "STOPPED" {
		t.Fatalf("result = %v", result)
	}
}

func TestRuntimeConstructionFailureDoesNotCreateSignalContext(t *testing.T) {
	constructorError := &launcher.GateError{
		Code:      launcher.CodeInvalidOptions,
		Operation: "new",
		Cause:     errors.New("constructor detail"),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := execute(
		[]string{"run", "--config", "config.json"},
		&stdout,
		&stderr,
		func(string) (runtime, error) { return nil, constructorError },
		unusedContextFactory(t),
	)
	if code != 1 || stdout.Len() != 0 ||
		!strings.Contains(stderr.String(), string(launcher.CodeInvalidOptions)) ||
		strings.Contains(stderr.String(), "constructor detail") {
		t.Fatalf("constructor failure exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestProcessContextReceivesSIGTERM(t *testing.T) {
	ctx, stop := processContext()
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("signal context error = %v", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SIGTERM did not cancel process context")
	}
}

func TestOutputFailureIsFailClosed(t *testing.T) {
	var stderr bytes.Buffer
	code := execute(
		[]string{"plan"},
		failingWriter{},
		&stderr,
		unusedRuntimeFactory(t),
		unusedContextFactory(t),
	)
	if code != 1 || !strings.Contains(stderr.String(), codeOutput) {
		t.Fatalf("output failure exit=%d stderr=%q", code, stderr.String())
	}
}

func TestWriteJSONPropagatesWriterError(t *testing.T) {
	if err := writeJSON(failingWriter{}, map[string]string{"x": "y"}); err == nil {
		t.Fatal("writeJSON succeeded with failing writer")
	}
	if err := writeJSON(io.Discard, map[string]string{"x": "y"}); err != nil {
		t.Fatalf("writeJSON(io.Discard) = %v", err)
	}
}
