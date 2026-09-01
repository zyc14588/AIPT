package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

const publicErrorSchema = "aipt.public.controlled-model-certification-error/v1"

func fail(code, phase string) {
	if code == "" {
		code = string(modelgateway.CodeCertificationMismatch)
	}
	if phase == "" {
		phase = "SETUP"
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"schema": publicErrorSchema,
		"result": "FAIL",
		"code":   code,
		"phase":  phase,
	})
	os.Exit(1)
}

func failurePhase(err error) string {
	var structured *modelgateway.Error
	if !errors.As(err, &structured) || structured == nil {
		return "SETUP"
	}
	if strings.HasPrefix(structured.Identity, "probe:") {
		return "PROBE"
	}
	if strings.HasPrefix(structured.Identity, "invoke-b004-") {
		return "INVOKE"
	}
	if strings.Contains(structured.Operation, "close") || strings.Contains(structured.Operation, "stop") ||
		strings.Contains(structured.Operation, "shutdown") {
		return "CLEANUP"
	}
	return "SETUP"
}

func main() {
	flags := flag.NewFlagSet("aipt-model-certify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	specPath := flags.String("spec", "", "private controlled-certification spec")
	if err := flags.Parse(os.Args[1:]); err != nil || *specPath == "" || flags.NArg() != 0 {
		fail(string(modelgateway.CodeCertificationMismatch), "SETUP")
	}
	raw, err := os.ReadFile(*specPath)
	if err != nil {
		fail(string(modelgateway.CodeCertificationMismatch), "SETUP")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var spec modelgateway.ControlledCertificationSpec
	if err := decoder.Decode(&spec); err != nil {
		fail(string(modelgateway.CodeCertificationMismatch), "SETUP")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		fail(string(modelgateway.CodeCertificationMismatch), "SETUP")
	}
	result, err := modelgateway.RunControlledCertification(
		context.Background(), spec, modelgateway.EnvironmentCredentialBroker{}, nil,
	)
	if err != nil {
		fail(string(modelgateway.CodeOf(err)), failurePhase(err))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		os.Exit(1)
	}
}
