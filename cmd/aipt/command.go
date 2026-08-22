package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zyc14588/AIPT/internal/launcher"
)

const usage = "usage: aipt plan | aipt run --config <path>\n"

const (
	cliErrorSchema  = "aipt.cli.error/v1"
	cliResultSchema = "aipt.launch.result/v1"
	codeUsage       = "AIPT_CLI_USAGE"
	codeRuntime     = "AIPT_CLI_RUNTIME_FAILED"
	codeOutput      = "AIPT_CLI_OUTPUT_FAILED"
)

type runtime interface {
	Run(context.Context) error
}

type runtimeFactory func(string) (runtime, error)
type processContextFactory func() (context.Context, func())

func newDefaultRuntime(configPath string) (runtime, error) {
	return launcher.NewDefault(configPath)
}

func processContext() (context.Context, func()) {
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	return ctx, stop
}

func execute(
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	newRuntime runtimeFactory,
	newProcessContext processContextFactory,
) int {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		_, _ = io.WriteString(stdout, usage)
		return 0
	}
	if len(args) == 1 && args[0] == "plan" {
		if err := writeJSON(stdout, launcher.Plan()); err != nil {
			writeCLIError(stderr, codeOutput, "")
			return 1
		}
		return 0
	}
	if len(args) != 3 || args[0] != "run" || args[1] != "--config" || args[2] == "" {
		writeCLIError(stderr, codeUsage, "")
		_, _ = io.WriteString(stderr, usage)
		return 2
	}

	instance, err := newRuntime(args[2])
	if err != nil {
		writeLauncherError(stderr, err)
		return 1
	}
	ctx, stop := newProcessContext()
	defer stop()
	if err := instance.Run(ctx); err != nil {
		writeLauncherError(stderr, err)
		return 1
	}
	if err := writeJSON(stdout, map[string]string{
		"schema": cliResultSchema,
		"result": "STOPPED",
	}); err != nil {
		writeCLIError(stderr, codeOutput, "")
		return 1
	}
	return 0
}

func writeLauncherError(writer io.Writer, err error) {
	code := string(launcher.CodeOf(err))
	if code == "" {
		code = codeRuntime
	}
	writeCLIError(writer, code, string(launcher.GateOf(err)))
}

func writeCLIError(writer io.Writer, code, gate string) {
	value := map[string]string{
		"schema":     cliErrorSchema,
		"error_code": code,
	}
	if gate != "" {
		value["gate"] = gate
	}
	_ = writeJSON(writer, value)
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
