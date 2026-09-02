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
