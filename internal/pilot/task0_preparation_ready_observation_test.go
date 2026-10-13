package pilot

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These are unaccepted negative entries and ordinary joined protocol peers.
// They never carry the registered binding/image or create a namespace.
func TestTask0ReadyNegativeHelper(t *testing.T) {
	scenario, active := os.LookupEnv("AIPT_Q026_NEGATIVE_HELPER")
	if !active {
		return
	}
	os.Args = []string{"fixed-negative-ready-test"}
	expected := strings.Repeat("a", 64)
	if scenario == "bad_identity" {
		expected = ""
	}
	if scenario == "extra_argument" {
		os.Args = append(os.Args, "forbidden")
	}
	observer := &task0PreparationReadyObserver{output: os.Stdout}
	if runTask0ParentMode(expected, nil, observer) != ErrRuntimeLaunch {
		os.Exit(22)
	}
	os.Exit(0)
}

func task0ReadyNegativeCommand(t *testing.T, scenario string, credential *string) []byte {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTask0ReadyNegativeHelper$")
	cmd.Env = []string{"AIPT_Q026_NEGATIVE_HELPER=" + scenario}
	if credential != nil {
		cmd.Env = append(cmd.Env, "DEEPSEEK_API_KEY="+*credential)
	}
	var output, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil || diagnostic.Len() != 0 {
		t.Fatalf("negative helper did not join cleanly: %v", err)
	}
	return output.Bytes()
}

func task0ReadyRecord(t *testing.T, raw []byte) task0PreparationReadyObservation {
	t.Helper()
	var record task0PreparationReadyObservation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&record); err != nil {
		t.Fatal(err)
	}
	if d.Decode(new(any)) != io.EOF {
		t.Fatal("not exactly one fixed record")
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 9 || record.Schema != "aipt.private.b007-preparation-ready-observation/v1" {
		t.Fatal("unexpected observation field set")
	}
	return record
}

func TestTask0ReadyRejectsIdentityAndInheritedProviderBeforeInput(t *testing.T) {
	for _, scenario := range []string{"bad_identity", "extra_argument"} {
		r := task0ReadyRecord(t, task0ReadyNegativeCommand(t, scenario, nil))
		if r.Stage != "ENTRY_IDENTITY" || r.Outcome != "REJECTED" || r.PreparationSpawnAttempted || r.ReadyObserved || r.DirectChildWaitCompleted {
			t.Fatal("identity did not reject before any input or spawn")
		}
	}
	for _, value := range []string{"", "synthetic-never-a-key", task0ReadyObservationMarker} {
		raw := task0ReadyNegativeCommand(t, "credential", &value)
		r := task0ReadyRecord(t, raw)
		if r.Stage != "CREDENTIAL_POLICY" || r.Outcome != "REJECTED" || r.PreparationSpawnAttempted || (value != "" && bytes.Contains(raw, []byte(value))) {
			t.Fatal("inherited provider field accepted or reflected")
		}
	}
}

func TestTask0ReadyChildEnvironmentIsFixedAndNeverInherited(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "synthetic-never-a-key")
	t.Setenv("HTTP_PROXY", "http://never.invalid")
	want := []string{"DEEPSEEK_API_KEY=" + task0ReadyObservationMarker, "LANG=C.UTF-8", "TZ=UTC"}
	if !reflect.DeepEqual(task0ReadyObservationEnvironment(), want) {
		t.Fatal("child environment inherited caller fields")
	}
}

func TestTask0ReadyAcceptsOnlyExactOriginalFrame(t *testing.T) {
	binding := strings.Repeat("a", 64)
	exact := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: binding}
	if !task0PreparationReadyFrameValid(exact, binding) {
		t.Fatal("original READY rejected")
	}
	for _, mutate := range []func(*task0CAFrame){
		func(f *task0CAFrame) { f.Schema = freshPreparationSchema },
		func(f *task0CAFrame) { f.Operation = "ADMITTED" },
		func(f *task0CAFrame) { f.BindingSHA = strings.Repeat("b", 64) },
		func(f *task0CAFrame) { f.Generation = binding },
		func(f *task0CAFrame) { f.Nonce = binding },
		func(f *task0CAFrame) { f.Proof = &task0CAProof{} },
		func(f *task0CAFrame) { f.Result = &task0PreparationResult{} },
	} {
		frame := exact
		mutate(&frame)
		if task0PreparationReadyFrameValid(frame, binding) {
			t.Fatal("non-READY or admission-bearing frame accepted")
		}
	}
	if task0PreparationReadyFrameValid(exact, "") {
		t.Fatal("invalid binding identity accepted")
	}
}

func TestTask0ReadyReadNeverSendsAdmission(t *testing.T) {
	control, child, err := task0PrivateControlPair()
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	peer, err := net.FileConn(child)
	child.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	binding := strings.Repeat("a", 64)
	frame := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: binding}
	if task0CAPacket(peer.(*net.UnixConn), &frame, true) != nil || receiveTask0PreparationReady(control, binding) != nil {
		t.Fatal("original READY observation failed")
	}
	control.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var raw [4097]byte
	if n, err := peer.Read(raw[:]); n != 0 || err != io.EOF {
		t.Fatal("observer sent a frame or failed to close its own control")
	}
}

func TestTask0ReadyUnknownOrNilOwnerIsNeverJoined(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	for _, p := range []*freshPreparationProcess{nil, {}, {command: &exec.Cmd{}, exit: closed}, {command: &exec.Cmd{}, exit: make(chan struct{})}} {
		o := &task0PreparationReadyObserver{}
		o.observeDirectJoin(p)
		if o.record.DirectChildWaitCompleted || o.record.DirectChildExitCode != -1 {
			t.Fatal("nil owner or closed channel substituted for actual Wait status")
		}
	}
}

func TestTask0ReadyObservesActualJoinAfterHeldGate(t *testing.T) {
	p, gate := task0NonCanonJoinGate(t, "HELD_JOIN")
	o := &task0PreparationReadyObserver{}
	o.observeDirectJoin(p)
	if o.record.DirectChildWaitCompleted {
		t.Fatal("live child accepted as joined")
	}
	task0ReleaseNonCanonJoinGate(t, p, gate)
	o.observeDirectJoin(p)
	if !o.record.DirectChildWaitCompleted || o.record.DirectChildExitCode != 0 || o.record.DirectChildWaitFailed {
		t.Fatal("actual direct Wait status not observed")
	}
}

func TestTask0ReadyNonCanonExitPeer(t *testing.T) {
	if os.Getenv("AIPT_Q026_NON_CANON_WAIT_ONLY") == "exit7" {
		os.Exit(7)
	}
}

func TestTask0ReadyPreservesNonzeroChildWaitWithoutAdmission(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestTask0ReadyNonCanonExitPeer$")
	cmd.Env = []string{"AIPT_Q026_NON_CANON_WAIT_ONLY=exit7"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatal("ordinary fixture did not really Wait with exit7")
	}
	p := &freshPreparationProcess{command: cmd, exit: make(chan struct{}), waitErr: err}
	close(p.exit) // After this test's actual Cmd.Wait, never a protocol substitute.
	var output bytes.Buffer
	o := &task0PreparationReadyObserver{output: &output}
	o.record.PreparationSpawnAttempted, o.record.PreparationStarted, o.record.ReadyObserved = true, true, true
	o.observeDirectJoin(p)
	if o.publish("READY_BEFORE_ADMISSION", nil) != nil {
		t.Fatal("could not publish fixed observation")
	}
	r := task0ReadyRecord(t, output.Bytes())
	if r.Outcome != "READY_STOPPED_BEFORE_ADMISSION" || !r.DirectChildWaitCompleted || !r.DirectChildWaitFailed || r.DirectChildExitCode != 7 || bytes.Contains(output.Bytes(), []byte(err.Error())) {
		t.Fatal("child's nonzero Wait was hidden, reflected or treated as admission")
	}
}

type task0ReadyFailedWriter struct{}

func (*task0ReadyFailedWriter) Write([]byte) (int, error) {
	return 0, errors.New("private synthetic output error")
}

func TestTask0ReadyOutputFailureAndNilInputsReject(t *testing.T) {
	o := &task0PreparationReadyObserver{output: &task0ReadyFailedWriter{}}
	if runTask0ParentMode("", nil, o) != ErrRuntimeLaunch || o.publish("ENTRY_IDENTITY", ErrRuntimeLaunch) != ErrRuntimeLaunch {
		t.Fatal("output failure accepted")
	}
	var owner *freshPreparationProcess
	if observeTask0PreparationReady(nil, nil, task0ParentBinding{}, nil, nil, &owner, o) != ErrRuntimeLaunch || owner != nil || o.record.PreparationSpawnAttempted {
		t.Fatal("invalid input reached a spawn")
	}
}

func TestTask0ReadyLauncherCannotCallFullLaunchersOrWriteControl(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "task0_preparation_ready_observation.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "launchTask0CAPreparation" || id.Name == "launchFreshPreparation") {
			t.Fatal("full admission launcher reachable")
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "task0CAPacket" {
			flag, ok := call.Args[2].(*ast.Ident)
			if !ok || flag.Name != "false" {
				t.Fatal("observation can write an admission packet")
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "CommandContext" || sel.Sel.Name == "Dial" || sel.Sel.Name == "Mount") {
			t.Fatal("automatic kill, network or mount outside bounded observation")
		}
		return true
	})
}
