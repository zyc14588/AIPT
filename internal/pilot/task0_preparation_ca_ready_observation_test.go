package pilot

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTask0CAReadyWaitEvidenceRejectsClaimsAndPreservesFailures(t *testing.T) {
	valid := []task0CAReadySetupWait{
		{NoSpawn: true, ExitCode: -1},
		{NoSpawn: true, SpawnAttempted: true, ExitCode: -1},
		{SpawnAttempted: true, Started: true, WaitCompleted: true, ExitCode: 7, WaitFailed: true},
		{SpawnAttempted: true, Started: true, WaitCompleted: true, ExitCode: -1, WaitFailed: true},
		{SpawnAttempted: true, Started: true, WaitCompleted: true, ExitCode: 0, WaitFailed: true},
	}
	for _, w := range valid {
		if !task0CAReadySetupWaitValid(w) {
			t.Fatal("actual NoSpawn/nonzero/signal/Wait error was concealed")
		}
	}
	for _, w := range []task0CAReadySetupWait{
		{}, {Started: true}, {SpawnAttempted: true, Started: true, ExitCode: -1},
		{NoSpawn: true, Started: true, ExitCode: -1}, {NoSpawn: true, WaitCompleted: true, ExitCode: -1},
		{SpawnAttempted: true, Started: true, WaitCompleted: true, ExitCode: 7},
		{NoSpawn: true, ExitCode: -1, Created: 1}, {NoSpawn: true, ExitCode: -1, Joined: 1},
	} {
		if task0CAReadySetupWaitValid(w) {
			t.Fatal("label, process exit, or business child fabricated a Wait proof")
		}
	}
}

func TestTask0CAReadyRetirementBindsBothLayersAndCA(t *testing.T) {
	d := func(c string) string { return strings.Repeat(c, 64) }
	b := task0ParentBinding{PreparationSHA: d("a"), ExecutableSHA: d("b"), SystemCA: task0SystemCABinding{task0SystemCAPolicy, task0Q013AuthoritySHA, task0SetupPolicy, task0Q014AuthoritySHA}}
	original, source, root, materialized := task0SetupFDIdentity{1, 2}, task0SetupFDIdentity{3, 4}, task0SetupFDIdentity{5, 6}, task0SetupFDIdentity{7, 8}
	r := task0CAReadyRetirement{Schema: task0CAReadyRetirementSchema, BindingSHA: b.PreparationSHA, ExecutableSHA: b.ExecutableSHA,
		Generation: d("c"), Nonce: d("d"), SetupSHA: d("e"), SetupBindingSHA: d("f"), CA: b.SystemCA,
		Original: original, Source: source, Root: root, Materialized: materialized, CAReadySent: true,
		Setup: task0CAReadySetupWait{SpawnAttempted: true, Started: true, Admitted: true, AdmissionNonce: d("1"),
			ShutdownAttempted: true, ShutdownNonce: d("2"), ShutdownAcknowledged: true, WaitCompleted: true}}
	check := func(v task0CAReadyRetirement) bool {
		return task0CAReadyRetirementValid(v, b, d("e"), d("f"), d("c"), d("d"), original, source, root, &task0CAProof{Materialized: materialized})
	}
	if !check(r) {
		t.Fatal("bound actual retirement rejected")
	}
	for _, change := range []func(*task0CAReadyRetirement){
		func(v *task0CAReadyRetirement) { v.Schema = "foreign" }, func(v *task0CAReadyRetirement) { v.BindingSHA = d("1") },
		func(v *task0CAReadyRetirement) { v.ExecutableSHA = d("1") }, func(v *task0CAReadyRetirement) { v.Generation = d("1") },
		func(v *task0CAReadyRetirement) { v.Nonce = d("1") }, func(v *task0CAReadyRetirement) { v.SetupSHA = d("1") },
		func(v *task0CAReadyRetirement) { v.SetupBindingSHA = d("1") }, func(v *task0CAReadyRetirement) { v.Root.Ino++ },
		func(v *task0CAReadyRetirement) { v.Original.Ino++ }, func(v *task0CAReadyRetirement) { v.Source.Ino++ },
		func(v *task0CAReadyRetirement) { v.Materialized.Ino++ }, func(v *task0CAReadyRetirement) { v.CA.SetupPolicy = "foreign" },
		func(v *task0CAReadyRetirement) { v.CAReadySent = false }, func(v *task0CAReadyRetirement) { v.Setup.WaitCompleted = false },
		func(v *task0CAReadyRetirement) { v.Setup.NoSpawn = true }, func(v *task0CAReadyRetirement) { v.Setup.Created = 1 },
		func(v *task0CAReadyRetirement) { v.Setup.ShutdownNonce = v.Setup.AdmissionNonce },
	} {
		bad := r
		change(&bad)
		if check(bad) {
			t.Fatal("cross-layer, replay, CA or role mutation accepted")
		}
	}
}

func TestTask0CAReadyEnvironmentAndNegativeEntry(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "NON_CANON_SYNTHETIC_NOT_A_KEY")
	t.Setenv("HTTPS_PROXY", "http://never.invalid")
	want := []string{"DEEPSEEK_API_KEY=" + task0CAReadyObservationMarker, "LANG=C.UTF-8", "TZ=UTC"}
	if !reflect.DeepEqual(task0CAReadyObservationEnvironment(), want) {
		t.Fatal("fixed PREP marker environment inherited ambient values")
	}
	var output bytes.Buffer
	o := &task0PreparationCAReadyObserver{context: context.Background(), output: &output}
	if runTask0ParentCAReadyMode("", nil, nil, nil, o) != ErrRuntimeLaunch {
		t.Fatal("unbound entry accepted")
	}
	var record task0PreparationCAReadyObservation
	if json.Unmarshal(output.Bytes(), &record) != nil || record.Stage != "ENTRY_IDENTITY" || record.Outcome != "REJECTED" || record.PreparationSpawnAttempted || record.Retirement != nil {
		t.Fatal("negative entry reached a runtime or leaked a record")
	}
	if RunObserveTask0CAReadyPreparation("") != ErrRuntimeLaunch {
		t.Fatal("unbound PREP accepted")
	}
}

func TestTask0CAReadySetupFinishPreservesActualFailedWait(t *testing.T) {
	f := task0CAReadyTestInput(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestTask0CAReadyNonCanonOwnedWaitChild$")
	cmd.Env = []string{"AIPT_Q028_NON_CANON_WAIT_ONLY=exit7"}
	o := task0CAReadyCommand(cmd, nil, []*os.File{f})
	s := &task0CAReadySetupOwner{owner: o, wait: task0CAReadySetupWait{SpawnAttempted: true, ExitCode: -1}}
	if o.start() != nil {
		t.Fatal("NON_CANON child not started")
	}
	s.wait.Started = true
	if s.finish() != ErrRuntimeLaunch || !s.wait.WaitCompleted || s.wait.ExitCode != 7 || !s.wait.WaitFailed || !task0CAReadySetupWaitValid(s.wait) {
		t.Fatal("SETUP retirement normalized or lost actual failed Wait")
	}
	if _, err := f.Stat(); err == nil {
		t.Fatal("joined input was not released")
	}
}

func TestTask0CAReadyHalfCloseCarriesLaterWaitReceipt(t *testing.T) {
	parent, child := task0SetupSocketFixture(t)
	if parent.SetDeadline(time.Now().Add(3*time.Second)) != nil || child.SetDeadline(time.Now().Add(3*time.Second)) != nil || parent.CloseWrite() != nil {
		t.Fatal("owned fixed half-close failed")
	}
	if body, eof, err := task0CAReadyPacket(child); err != nil || !eof || len(body) != 0 {
		t.Fatal("kernel write-half close was not observed")
	}
	receipt := []byte(`{"NON_CANON":"later actual Wait receipt control"}`)
	if n, err := child.Write(receipt); err != nil || n != len(receipt) {
		t.Fatal("child-to-parent receipt half was closed")
	}
	if body, eof, err := task0CAReadyPacket(parent); err != nil || eof || !bytes.Equal(body, receipt) {
		t.Fatal("later child receipt was not preserved")
	}
}

func TestTask0CAReadyEmptyPacketAndDeadlineAreNotEOF(t *testing.T) {
	for _, scenario := range []string{"empty", "deadline", "rights"} {
		t.Run(scenario, func(t *testing.T) {
			parent, child := task0SetupSocketFixture(t)
			if child.SetReadDeadline(time.Now().Add(100*time.Millisecond)) != nil {
				t.Fatal("fixed deadline failed")
			}
			if scenario == "empty" {
				if _, err := parent.Write([]byte{}); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "rights" {
				f := task0CAReadyTestInput(t)
				if _, _, err := parent.WriteMsgUnix([]byte("NON_CANON"), syscall.UnixRights(int(f.Fd())), nil); err != nil {
					t.Fatal(err)
				}
			}
			if _, eof, err := task0CAReadyPacket(child); err == nil || eof {
				t.Fatal("empty packet, soft deadline or unsolicited rights became EOF")
			}
		})
	}
}

// This test-only fixed child has no namespace, CA, credential, database, model
// or production entry. It cannot be interpreted as the real max-once claim.
func TestTask0CAReadyNonCanonOwnedWaitChild(t *testing.T) {
	if os.Getenv("AIPT_Q028_NON_CANON_WAIT_ONLY") != "exit7" {
		return
	}
	os.Exit(7)
}

func task0CAReadyTestInput(t *testing.T) *os.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "NON-CANON-held-input")
	if err := os.WriteFile(p, []byte("NON-CANON, no secret or model"), 0400); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestTask0CAReadyRetainsInputsBeforeStartAndUnknownJoin(t *testing.T) {
	f := task0CAReadyTestInput(t)
	o := task0CAReadyCommand(exec.Command("/NON-CANON-never-called"), nil, []*os.File{f})
	if o.joinedOrNoSpawn() || o.releaseInputs() != ErrRuntimeLaunch {
		t.Fatal("not-started owner fabricated a join")
	}
	o.startAttempted = true // Simulate an unresolved Start; do not execute it.
	if o.joinedOrNoSpawn() || o.releaseInputs() != ErrRuntimeLaunch {
		t.Fatal("unknown Start released holders")
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("held input closed on an unknown owner")
	}
}

func TestTask0CAReadyOwnedFailedStartProvesNoSpawn(t *testing.T) {
	f := task0CAReadyTestInput(t)
	cmd := exec.Command(filepath.Join(t.TempDir(), "NON-CANON-absent-image"))
	cmd.Env = []string{"LANG=C.UTF-8"}
	o := task0CAReadyCommand(cmd, nil, []*os.File{f})
	if o.start() != ErrRuntimeLaunch || cmd.Process != nil || !o.noSpawn || !o.joinedOrNoSpawn() {
		t.Fatal("failed exec did not preserve its exact NoSpawn result")
	}
	if o.start() != ErrRuntimeLaunch {
		t.Fatal("owner accepted a second Start")
	}
	if o.releaseInputs() != nil {
		t.Fatal("NoSpawn inputs could not be retired")
	}
}

func TestTask0CAReadyActualNonzeroWaitBeforeInputRelease(t *testing.T) {
	f := task0CAReadyTestInput(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestTask0CAReadyNonCanonOwnedWaitChild$")
	cmd.Env = []string{"LANG=C.UTF-8", "AIPT_Q028_NON_CANON_WAIT_ONLY=exit7"}
	o := task0CAReadyCommand(cmd, nil, []*os.File{f})
	if o.start() != nil || o.noSpawn {
		t.Fatal("fixed NON_CANON child not started")
	}
	select {
	case <-o.process.exit:
	case <-time.After(10 * time.Second):
		t.Fatal("test child did not actually Wait")
	}
	if !o.joinedOrNoSpawn() || o.process.command.ProcessState == nil || o.process.command.ProcessState.ExitCode() != 7 || o.process.waitErr == nil {
		t.Fatal("nonzero actual Wait concealed")
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("input retired before the owner explicitly released it")
	}
	if o.releaseInputs() != nil {
		t.Fatal("joined input release failed")
	}
}
