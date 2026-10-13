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

// Negative entry fixtures never carry the registered bindings or create a
// namespace. Protocol fixtures below are ordinary joined local socket peers.
func TestTask0AdmittedNegativeHelper(t *testing.T) {
	scenario, active := os.LookupEnv("AIPT_Q027_NEGATIVE_HELPER")
	if !active {
		return
	}
	os.Args = []string{"fixed-negative-admitted-test"}
	expected := strings.Repeat("a", 64)
	if scenario == "bad_identity" {
		expected = ""
	}
	if scenario == "extra_argument" {
		os.Args = append(os.Args, "forbidden")
	}
	if runTask0ParentObservationMode(expected, nil, nil, &task0PreparationAdmittedObserver{output: os.Stdout}) != ErrRuntimeLaunch {
		os.Exit(22)
	}
	os.Exit(0)
}

func task0AdmittedRecord(t *testing.T, raw []byte) task0PreparationAdmittedObservation {
	t.Helper()
	var record task0PreparationAdmittedObservation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("not exactly one fixed typed record")
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 13 || record.Schema != "aipt.private.b007-preparation-admitted-observation/v1" {
		t.Fatal("unexpected observation fields")
	}
	return record
}

func TestTask0AdmittedRejectsIdentityAndCredentialBeforeInput(t *testing.T) {
	for _, scenario := range []string{"bad_identity", "extra_argument", "missing_binding", "credential_empty", "credential_marker", "credential_fake"} {
		t.Run(scenario, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTask0AdmittedNegativeHelper$")
			cmd.Env = []string{"AIPT_Q027_NEGATIVE_HELPER=" + scenario}
			value := ""
			if strings.HasPrefix(scenario, "credential_") {
				if scenario == "credential_marker" {
					value = task0AdmittedObservationMarker
				} else if scenario == "credential_fake" {
					value = "synthetic-not-a-provider-key"
				}
				cmd.Env = append(cmd.Env, "DEEPSEEK_API_KEY="+value)
			}
			var output, diagnostic bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &diagnostic
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil || diagnostic.Len() != 0 {
				t.Fatal("negative child did not really join")
			}
			r := task0AdmittedRecord(t, output.Bytes())
			stage := "ENTRY_IDENTITY"
			if strings.HasPrefix(scenario, "credential_") {
				stage = "CREDENTIAL_POLICY"
			} else if scenario == "missing_binding" {
				stage = "PARENT_BINDING_FD_BORROW"
			}
			if r.Stage != stage || r.Outcome != "REJECTED" || r.PreparationSpawnAttempted || r.AdmissionSendAttempted || r.ConfirmedSent || r.DirectChildWaitCompleted || (value != "" && bytes.Contains(output.Bytes(), []byte(value))) {
				t.Fatal("negative entry reached input/spawn/admission or leaked a value")
			}
		})
	}
}

func TestTask0AdmittedEnvironmentNeverInherits(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "synthetic-not-a-key")
	t.Setenv("HTTPS_PROXY", "http://never.invalid")
	want := []string{"DEEPSEEK_API_KEY=" + task0AdmittedObservationMarker, "LANG=C.UTF-8", "TZ=UTC"}
	if !reflect.DeepEqual(task0AdmittedObservationEnvironment(), want) {
		t.Fatal("child environment is not the fixed noncredential marker")
	}
}

// Exercise the actual limited handshake with a bounded ordinary peer. The
// peer returns its received frame, so nonce freshness and absence of any
// CONFIRMED/control continuation are observed independently of the record.
func task0AdmittedProtocolFixture(t *testing.T, readyChange, admittedChange func(*task0CAFrame), failVerificationAt int, closeBeforeAdmitted bool) (task0PreparationAdmittedObserver, string, error, task0CAFrame) {
	t.Helper()
	control, child, err := task0PrivateControlPair()
	if err != nil {
		t.Fatal(err)
	}
	peerConn, err := net.FileConn(child)
	child.Close()
	if err != nil {
		control.Close()
		t.Fatal(err)
	}
	peer := peerConn.(*net.UnixConn)
	defer peer.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	peer.SetDeadline(time.Now().Add(3 * time.Second))
	binding, generation := strings.Repeat("a", 64), strings.Repeat("b", 64)
	frames := make(chan task0CAFrame, 1)
	peerErrors := make(chan error, 1)
	go func() {
		ready := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: binding}
		if readyChange != nil {
			readyChange(&ready)
		}
		if task0CAPacket(peer, &ready, true) != nil {
			peerErrors <- errors.New("peer could not write READY")
			return
		}
		var admission task0CAFrame
		if task0CAPacket(peer, &admission, false) != nil {
			frames <- task0CAFrame{}
			peerErrors <- nil // Expected EOF when READY/precheck is rejected.
			return
		}
		frames <- admission
		if !task0CAFrameValid(admission, "ADMIT", binding, generation, admission.Nonce) || admission.Proof != nil || admission.Result != nil {
			peerErrors <- errors.New("peer received an invalid ADMIT")
			return
		}
		if closeBeforeAdmitted {
			peer.Close()
			peerErrors <- nil
			return
		}
		admission.Operation = "ADMITTED"
		if admittedChange != nil {
			admittedChange(&admission)
		}
		if task0CAPacket(peer, &admission, true) != nil {
			peerErrors <- errors.New("peer could not write ADMITTED")
			return
		}
		var extra [4097]byte
		n, err := peer.Read(extra[:])
		if n != 0 || err != io.EOF {
			peerErrors <- errors.New("observer sent a continuation or did not close")
			return
		}
		peerErrors <- nil
	}()
	verificationCalls := 0
	verify := func() error {
		verificationCalls++
		if verificationCalls == failVerificationAt {
			return ErrRuntimeLaunch
		}
		return nil
	}
	o := task0PreparationAdmittedObserver{}
	stage := "UNREACHED"
	err = receiveTask0PreparationAdmitted(control, binding, generation, verify, &o, &stage)
	control.Close()
	if e := <-peerErrors; e != nil {
		t.Fatal(e)
	}
	frame := <-frames
	if failVerificationAt == 0 && readyChange == nil && admittedChange == nil && !closeBeforeAdmitted && verificationCalls != 2 {
		t.Fatal("fixed verification did not run before and after ADMIT")
	}
	return o, stage, err, frame
}

func TestTask0AdmittedOneOriginalAdmissionThenEOFWithFreshNonce(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		o, stage, err, frame := task0AdmittedProtocolFixture(t, nil, nil, 0, false)
		if err != nil || stage != "ADMITTED_BEFORE_CONFIRMED" || !o.record.ReadyObserved || !o.record.AdmissionSendAttempted || !o.record.AdmissionSent || !o.record.AdmittedObserved || o.record.ConfirmedSent || !digest(frame.Nonce) || seen[frame.Nonce] {
			t.Fatal("limited handshake did not stop or generate a fresh original nonce")
		}
		seen[frame.Nonce] = true
	}
}

func TestTask0AdmittedRejectsEveryResponseFieldMismatch(t *testing.T) {
	for name, change := range map[string]func(*task0CAFrame){
		"schema":     func(f *task0CAFrame) { f.Schema = freshPreparationSchema },
		"operation":  func(f *task0CAFrame) { f.Operation = "CONFIRMED" },
		"binding":    func(f *task0CAFrame) { f.BindingSHA = strings.Repeat("c", 64) },
		"generation": func(f *task0CAFrame) { f.Generation = strings.Repeat("c", 64) },
		"nonce":      func(f *task0CAFrame) { f.Nonce = strings.Repeat("c", 64) },
		"proof":      func(f *task0CAFrame) { f.Proof = &task0CAProof{} },
		"result":     func(f *task0CAFrame) { f.Result = &task0PreparationResult{} },
	} {
		t.Run(name, func(t *testing.T) {
			o, stage, err, _ := task0AdmittedProtocolFixture(t, nil, change, 0, false)
			if err != ErrRuntimeLaunch || stage != "ADMITTED_RECEIVE" || !o.record.AdmissionSent || o.record.AdmittedObserved || o.record.ConfirmedSent {
				t.Fatal("unbound ADMITTED response accepted or continued")
			}
		})
	}
}

func TestTask0AdmittedRejectsBadREADYWithoutADMIT(t *testing.T) {
	o, stage, err, frame := task0AdmittedProtocolFixture(t, func(f *task0CAFrame) { f.Generation = strings.Repeat("c", 64) }, nil, 0, false)
	if err != ErrRuntimeLaunch || stage != "READY_RECEIVE" || o.record.ReadyObserved || o.record.AdmissionSendAttempted || frame.Operation != "" {
		t.Fatal("nonexact READY permitted an ADMIT")
	}
}

func TestTask0AdmittedRejectsBeforeAndAfterVerificationAndPeerEOF(t *testing.T) {
	for _, attempt := range []int{1, 2} {
		o, stage, err, frame := task0AdmittedProtocolFixture(t, nil, nil, attempt, false)
		want := "ADMIT_PRECHECK"
		if attempt == 2 {
			want = "ADMITTED_RECHECK"
		}
		if err != ErrRuntimeLaunch || stage != want || o.record.ConfirmedSent || (attempt == 1 && (o.record.AdmissionSendAttempted || frame.Operation != "")) {
			t.Fatal("failed verification did not stop at its actual boundary")
		}
	}
	o, stage, err, _ := task0AdmittedProtocolFixture(t, nil, nil, 0, true)
	if err != ErrRuntimeLaunch || stage != "ADMITTED_RECEIVE" || !o.record.AdmissionSent || o.record.AdmittedObserved {
		t.Fatal("peer EOF accepted as ADMITTED")
	}
}

func TestTask0AdmittedRequiresActualDirectWaitAndPreservesNonzeroStatus(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	for _, p := range []*freshPreparationProcess{nil, {}, {command: &exec.Cmd{}, exit: closed}, {command: &exec.Cmd{}, exit: make(chan struct{})}} {
		o := &task0PreparationAdmittedObserver{}
		o.observeDirectJoin(p)
		if o.record.DirectChildWaitCompleted || o.record.DirectChildExitCode != -1 {
			t.Fatal("nil owner or channel substituted for actual Wait")
		}
	}
	p, gate := task0NonCanonJoinGate(t, "HELD_JOIN")
	o := &task0PreparationAdmittedObserver{}
	o.observeDirectJoin(p)
	if o.record.DirectChildWaitCompleted {
		t.Fatal("live owned child accepted as joined")
	}
	task0ReleaseNonCanonJoinGate(t, p, gate)
	o.observeDirectJoin(p)
	if !o.record.DirectChildWaitCompleted || o.record.DirectChildWaitFailed {
		t.Fatal("actual joined child was not observed")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestTask0ReadyNonCanonExitPeer$")
	cmd.Env = []string{"AIPT_Q026_NON_CANON_WAIT_ONLY=exit7"}
	if cmd.Start() != nil {
		t.Fatal("fixture could not start")
	}
	err := cmd.Wait()
	if err == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatal("fixture did not really Wait with exit7")
	}
	p = &freshPreparationProcess{command: cmd, exit: make(chan struct{}), waitErr: err}
	close(p.exit)
	var output bytes.Buffer
	o = &task0PreparationAdmittedObserver{output: &output}
	o.record.PreparationSpawnAttempted, o.record.PreparationStarted, o.record.ReadyObserved = true, true, true
	o.record.AdmissionSendAttempted, o.record.AdmissionSent, o.record.AdmittedObserved = true, true, true
	o.observeDirectJoin(p)
	if o.publish("ADMITTED_BEFORE_CONFIRMED", nil) != nil {
		t.Fatal("fixed record publication failed")
	}
	r := task0AdmittedRecord(t, output.Bytes())
	if r.Outcome != "ADMITTED_STOPPED_BEFORE_CONFIRMED" || !r.DirectChildWaitCompleted || !r.DirectChildWaitFailed || r.DirectChildExitCode != 7 || bytes.Contains(output.Bytes(), []byte(err.Error())) {
		t.Fatal("actual nonzero Wait concealed or private error reflected")
	}
}

func TestTask0AdmittedNilInputsAndWriterFailureReject(t *testing.T) {
	o := &task0PreparationAdmittedObserver{output: &task0ReadyFailedWriter{}}
	if runTask0ParentObservationMode("", nil, nil, o) != ErrRuntimeLaunch || o.publish("ENTRY_IDENTITY", ErrRuntimeLaunch) != ErrRuntimeLaunch {
		t.Fatal("output failure accepted")
	}
	var owner *freshPreparationProcess
	stage := "ENTRY"
	if observeTask0PreparationAdmitted(nil, nil, task0ParentBinding{}, nil, nil, &owner, o, &stage) != ErrRuntimeLaunch || owner != nil || o.record.PreparationSpawnAttempted {
		t.Fatal("nil fixed input reached Start")
	}
	if receiveTask0PreparationAdmitted(nil, "", "", nil, nil, nil) != ErrRuntimeLaunch {
		t.Fatal("nil handshake input accepted")
	}
}

func TestTask0AdmittedNoFullLauncherOrContinuationAndOwnerBeforeStart(t *testing.T) {
	raw, err := os.ReadFile("task0_preparation_admitted_observation.go")
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "task0_preparation_admitted_observation.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok {
			if id.Name == "launchTask0CAPreparation" || id.Name == "launchFreshPreparation" || id.Name == "executeTask0Preparation" {
				t.Fatal("full continuation reachable")
			}
			if id.Name == "task0CAPacket" {
				flag, ok := call.Args[2].(*ast.Ident)
				if !ok || (flag.Name != "true" && flag.Name != "false") {
					t.Fatal("dynamic control write selector")
				}
				if flag.Name == "true" {
					writes++
				}
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "CommandContext" || sel.Sel.Name == "Dial" || sel.Sel.Name == "Mount" || sel.Sel.Name == "admitCA") {
			t.Fatal("automatic kill, network, mount or CA continuation reachable")
		}
		return true
	})
	if writes != 1 || !bytes.Contains(raw, []byte("Operation: \"ADMIT\"")) || bytes.Contains(raw, []byte("Operation: \"CONFIRMED\"")) || bytes.Index(raw, []byte("*owner = p")) > bytes.Index(raw, []byte("err = cmd.Start()")) {
		t.Fatal("write range or strong ownership ordering changed")
	}
}
