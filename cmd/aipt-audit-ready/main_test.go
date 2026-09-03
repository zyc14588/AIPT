package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/evidence"
)

func TestCommandRejectsUnknownOperationsAndSpecFields(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}, {"verify"}, {"generate"}} {
		if err := run(context.Background(), arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("arguments %v unexpectedly succeeded", arguments)
		}
	}
	directory := t.TempDir()
	spec := filepath.Join(directory, "spec.json")
	if err := os.WriteFile(spec, []byte(`{"unexpected":"field"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"generate", "--spec", spec}, &bytes.Buffer{}); !errors.Is(err, evidence.ErrAuditReadyInvalid) {
		t.Fatalf("unknown spec field error = %v", err)
	}
}

func TestStableErrorCodesNeverEchoUntrustedCauses(t *testing.T) {
	cause := errors.New("/" + "home/private API_" + "KEY=never-echo")
	err := errors.Join(evidence.ErrSourceUnverified, cause)
	code := stableErrorCode(err)
	if code != evidence.ErrSourceUnverified.Error() || strings.Contains(code, "never-echo") || strings.Contains(code, "/"+"home/") {
		t.Fatalf("unstable or leaking error code %q", code)
	}
}

func TestF2N08CredentialRepositoryNeverReachesCLIStdoutOrStderr(t *testing.T) {
	sentinel := "injected-user:injected-value"
	repository := "https://" + sentinel + "@example.invalid/aipt.git"
	directory := t.TempDir()
	spec := filepath.Join(directory, "credential-spec.json")
	if err := os.WriteFile(spec, []byte(`{"expected_repository":"`+repository+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := [][]string{
		{"generate", "--spec", spec},
		{"verify", "--bundle", filepath.Join(directory, "missing-bundle"), "--mirror", filepath.Join(directory, "missing-mirror"), "--repository", repository},
	}
	for _, arguments := range tests {
		stdout := &bytes.Buffer{}
		err := run(context.Background(), arguments, stdout)
		if !errors.Is(err, evidence.ErrSourceUnverified) {
			t.Fatalf("arguments %v error = %v", arguments, err)
		}
		stderr := stableErrorCode(err)
		if stdout.Len() != 0 || strings.Contains(stdout.String(), sentinel) || strings.Contains(stderr, sentinel) || strings.Contains(err.Error(), sentinel) {
			t.Fatalf("credential reached CLI output: stdout=%q stderr=%q error=%q", stdout.String(), stderr, err.Error())
		}
	}

	stdout := &bytes.Buffer{}
	err := writeResult(stdout, evidence.AuditReadyVerification{
		Manifest: evidence.AuditReadyManifest{Source: evidence.SourceIdentity{Repository: repository}},
	})
	if !errors.Is(err, evidence.ErrSourceUnverified) || stdout.Len() != 0 || strings.Contains(stdout.String(), sentinel) {
		t.Fatalf("writeResult accepted credential-bearing source: error=%v stdout=%q", err, stdout.String())
	}
}
