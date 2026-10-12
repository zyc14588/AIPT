package pilot

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// Negative helper invocations never carry an accepted binding or PREP image.
// Descriptor cases run in a joined child so they cannot replace a test runner FD.
func TestTask0ParentPrefixNegativeHelper(t *testing.T) {
	scenario, helper := os.LookupEnv("AIPT_Q025_NEGATIVE_HELPER")
	if !helper {
		return
	}
	os.Args = []string{"fixed-negative-prefix-test"}
	if scenario == "missing_fd" {
		_ = syscall.Close(3)
	}
	var output bytes.Buffer
	expected := strings.Repeat("a", 64)
	if scenario == "bad_identity" {
		expected = ""
	}
	if scenario == "extra_argument" {
		os.Args = append(os.Args, "forbidden")
	}
	if scenario == "nil_production_writer" {
		if runTask0Parent(expected, nil) != ErrRuntimeLaunch {
			os.Exit(21)
		}
		os.Exit(0)
	}
	if runTask0Parent(expected, &output) != ErrRuntimeLaunch {
		os.Exit(22)
	}
	if _, err := os.Stdout.Write(output.Bytes()); err != nil {
		os.Exit(23)
	}
	os.Exit(0)
}

func task0PrefixNegativeCommand(t *testing.T, scenario string, credential *string, input *os.File) []byte {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestTask0ParentPrefixNegativeHelper$")
	command.Env = []string{"AIPT_Q025_NEGATIVE_HELPER=" + scenario}
	if credential != nil {
		command.Env = append(command.Env, "DEEPSEEK_API_KEY="+*credential)
	}
	if input != nil {
		command.ExtraFiles = []*os.File{input}
	}
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("joined negative helper failed: %v; %s", err, diagnostic.Bytes())
	}
	if diagnostic.Len() != 0 {
		t.Fatalf("unexpected helper diagnostic: %s", diagnostic.Bytes())
	}
	return output.Bytes()
}

func task0PrefixRejectedRecord(t *testing.T, raw []byte, stage string) {
	t.Helper()
	var actual map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&actual); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("observation must be exactly one record")
	}
	want := map[string]any{
		"schema": "aipt.private.b007-parent-prefix-observation/v1",
		"stage":  stage, "outcome": "REJECTED", "preparation_spawn_attempted": false,
	}
	if len(actual) != len(want) {
		t.Fatalf("unexpected public fields: %v", actual)
	}
	for key, value := range want {
		if actual[key] != value {
			t.Fatalf("unexpected %s: %v", key, actual[key])
		}
	}
}

func TestTask0ParentPrefixRejectsIdentityBeforeInput(t *testing.T) {
	for _, scenario := range []string{"bad_identity", "extra_argument"} {
		t.Run(scenario, func(t *testing.T) {
			task0PrefixRejectedRecord(t, task0PrefixNegativeCommand(t, scenario, nil, nil), "ENTRY_IDENTITY")
		})
	}
}

func TestTask0ParentPrefixRejectsPresentCredentialBeforeInput(t *testing.T) {
	for _, value := range []string{"", "synthetic-not-a-secret", " \ninvalid\r"} {
		raw := task0PrefixNegativeCommand(t, "credential", &value, nil)
		task0PrefixRejectedRecord(t, raw, "CREDENTIAL_POLICY")
		if value != "" && bytes.Contains(raw, []byte(value)) {
			t.Fatal("credential reflected in observation")
		}
	}
}

func TestTask0ParentPrefixRejectsMissingBindingDescriptor(t *testing.T) {
	task0PrefixRejectedRecord(t, task0PrefixNegativeCommand(t, "missing_fd", nil, nil), "PARENT_BINDING_FD_BORROW")
}

func TestTask0ParentPrefixRejectsSizeAndUnsealedFiles(t *testing.T) {
	for _, scenario := range []struct{ name, body, stage string }{
		{"empty_file", "", "PARENT_BINDING_FD_SIZE"},
		{"unsealed_file", "{}", "PARENT_BINDING_FD_SEALS"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "unaccepted-negative-binding-")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := io.WriteString(file, scenario.body); err != nil {
				t.Fatal(err)
			}
			task0PrefixRejectedRecord(t, task0PrefixNegativeCommand(t, scenario.name, nil, file), scenario.stage)
		})
	}
}

func TestTask0ParentPrefixProductionNilStillRequiresCredential(t *testing.T) {
	if raw := task0PrefixNegativeCommand(t, "nil_production_writer", nil, nil); len(raw) != 0 {
		t.Fatal("production nil branch emitted a prefix observation")
	}
}

type task0PrefixFailedWriter struct{ calls int }

func (w *task0PrefixFailedWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, errors.New("synthetic private writer error must not be reflected")
}

func TestTask0ParentPrefixObservationWriteFailureRejects(t *testing.T) {
	writer := &task0PrefixFailedWriter{}
	if err := runTask0Parent("", writer); err != ErrRuntimeLaunch || writer.calls != 1 {
		t.Fatalf("output failure not rejected: %v, calls=%d", err, writer.calls)
	}
}
