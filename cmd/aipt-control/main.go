package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zyc14588/AIPT/internal/launcher"
	"github.com/zyc14588/AIPT/internal/operational"
)

const usage = "usage: aipt-control plan | aipt-control run --config <path> --control-config <path>\n"

func main() { os.Exit(execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
func execute(args []string, input io.ReadCloser, output io.WriteCloser, diagnostics io.Writer) int {
	if len(args) == 1 && args[0] == "plan" {
		if err := json.NewEncoder(output).Encode(operational.Plan()); err != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help") {
		_, _ = io.WriteString(output, usage)
		return 0
	}
	if len(args) != 5 || args[0] != "run" || args[1] != "--config" || args[2] == "" || args[3] != "--control-config" || args[4] == "" {
		_, _ = io.WriteString(diagnostics, usage)
		return 2
	}
	runtime, err := operational.NewProduction(args[2], args[4], input, output, diagnostics)
	if err != nil {
		writeError(diagnostics, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runtime.Run(ctx); err != nil {
		writeError(diagnostics, err)
		return 1
	}
	return 0
}
func writeError(writer io.Writer, err error) {
	_ = json.NewEncoder(writer).Encode(struct {
		Schema string        `json:"schema"`
		Code   string        `json:"code"`
		Gate   launcher.Gate `json:"gate"`
	}{"aipt.control-cli-error/v1", string(launcher.CodeOf(err)), launcher.GateOf(err)})
}
