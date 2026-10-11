package pilot

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// These own ordinary test processes and actual command.Wait. No production
// entry, namespace, execution role, model, DB or application network is used.
func task0NonCanonJoinGate(t *testing.T, mode string) (*freshPreparationProcess, *os.File) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestTask0SetupNonCanonProtocolPeer$")
	cmd.Env = frozenEnvironment(map[string]string{"AIPT_Q014_NON_CANON_PROTOCOL_PEER": mode})
	cmd.ExtraFiles = []*os.File{input}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err = cmd.Start(); err != nil {
		input.Close()
		release.Close()
		t.Fatal(err)
	}
	input.Close()
	p := &freshPreparationProcess{command: cmd, exit: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exit) }()
	t.Cleanup(func() {
		release.Close()
		if p.retire() != nil {
			t.Error("test's actual directly owned join missing")
		}
		WaitAcceptedTask0InputRetirements()
	})
	return p, release
}

func task0NonCanonHeldFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "held-input-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func task0ReleaseNonCanonJoinGate(t *testing.T, p *freshPreparationProcess, release *os.File) {
	t.Helper()
	if _, err := release.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	<-p.exit
	if p.waitErr != nil || !task0DirectJoinCompleted(p) {
		t.Fatal("actual direct command.Wait failed")
	}
	WaitAcceptedTask0InputRetirements()
}

func TestTask0SetupClosedObservationSynchronized(t *testing.T) {
	p, release := task0NonCanonJoinGate(t, "HELD_JOIN")
	s := &task0SetupClient{process: p, grant: &acceptedTask0Setup{}}
	start := make(chan struct{})
	var work sync.WaitGroup
	for i := 0; i < 64; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			<-start
			for j := 0; j < 128; j++ {
				_ = s.live()
			}
		}()
	}
	close(start)
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	work.Wait()
	if s.live() {
		t.Fatal("revoked owner remained live")
	}
	task0ReleaseNonCanonJoinGate(t, p, release)
}

func TestTask0SetupCompleteProcessCheckSynchronizedWithRealHandleRelease(t *testing.T) {
	owned, release := task0NonCanonJoinGate(t, "HELD_JOIN")
	pid := owned.command.Process.Pid
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	fd, _, errno := syscall.Syscall(434, uintptr(pid), 0, 0)
	if errno != 0 {
		process.Release()
		t.Fatal("owned test pidfd unavailable", errno)
	}
	pidfd := os.NewFile(fd, "NON_CANON observed test process pidfd")
	s := &task0SetupClient{process: owned, shutdownOK: true}
	p := &task0DelegatedProcess{owner: s, process: process, pid: pid, pidfd: pidfd}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var work sync.WaitGroup
	for i := 0; i < 64; i++ {
		work.Add(1)
		go func() {
			defer work.Done()
			<-start
			for j := 0; j < 128; j++ {
				// This is an ordinary negative fixture with no SETUP ownership
				// or namespace authority. Exercise check/Release, never accept it.
				if p.check(self) == nil {
					t.Error("ordinary fixture accepted as an execution role")
				}
			}
		}()
	}
	close(start)
	runtime.Gosched()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if p.retire() != nil {
		t.Fatal("test handle Release failed")
	}
	work.Wait()
	if p.pid != pid || process.Pid != -1 {
		t.Fatal("actual Release or immutable observed identity missing")
	}
	task0ReleaseNonCanonJoinGate(t, owned, release)
}

func TestTask0SetupPartialLocalNoHandleRetainsInputsWithoutRetirementReceipt(t *testing.T) {
	p, release := task0NonCanonJoinGate(t, "HELD_JOIN")
	held := task0NonCanonHeldFile(t)
	var receipts bytes.Buffer
	l := &task0DelegatedLocal{owner: &task0SetupClient{process: p}, createAttempted: true, helper: held, record: &receipts}
	if l.retire() == nil || l.process != nil || task0DirectJoinCompleted(p) {
		t.Fatal("uncertain creation relabelled a successful retirement")
	}
	runtime.GC()
	if _, err := held.Stat(); err != nil || receipts.Len() != 0 {
		t.Fatal("partial owner or input lost before real Wait, or false cache receipt")
	}
	task0ReleaseNonCanonJoinGate(t, p, release)
	if _, err := held.Stat(); err == nil || receipts.Len() != 0 {
		t.Fatal("late actual join did not release input, or fabricated retirement receipt")
	}
}

func TestTask0SetupPreparationFailureRetainsCAInputUntilActualWait(t *testing.T) {
	p, release := task0NonCanonJoinGate(t, "HELD_JOIN")
	held := task0NonCanonHeldFile(t)
	s := &task0SetupClient{process: p, invalid: true, closed: true, retireError: ErrRuntimeLaunch}
	r := &task0AcceptedPreparationRuntime{setup: s, source: held}
	if r.retire() == nil || task0DirectJoinCompleted(p) {
		t.Fatal("missing direct Wait accepted")
	}
	runtime.GC()
	if _, err := held.Stat(); err != nil {
		t.Fatal("accepted input closed before actual direct Wait")
	}
	task0ReleaseNonCanonJoinGate(t, p, release)
	if _, err := held.Stat(); err == nil {
		t.Fatal("held input not released after actual direct Wait")
	}
}

func TestTask0SetupRoleInputCopiesRetainOnlyRegularFiles(t *testing.T) {
	original := task0NonCanonHeldFile(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	copies, err := task0CopyHeldRoleInputs([]*os.File{original, reader, writer})
	if err != nil || len(copies) != 1 {
		t.Fatal("wrong selected inputs or child peers retained")
	}
	defer task0CloseInputFiles(copies)
	a, _ := original.Stat()
	b, err := copies[0].Stat()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, copies[0].Fd(), syscall.F_GETFD, 0)
	if err != nil || !os.SameFile(a, b) || errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("copied input differs or lacks CLOEXEC")
	}
	original.Close()
	if _, err := copies[0].Stat(); err != nil {
		t.Fatal("exact copied input lost with original FD")
	}
}

func TestTask0ParentPublishesOnlyAfterActualJoinAndEmptyDirectoryRemoval(t *testing.T) {
	for _, mutation := range []string{"LIVE_CHILD", "NONEMPTY_DIRECTORY", "CLEAN"} {
		t.Run(mutation, func(t *testing.T) {
			p, release := task0NonCanonJoinGate(t, "HELD_JOIN")
			outer := filepath.Join(t.TempDir(), "own-empty-outer")
			root := filepath.Join(outer, "ca-root")
			if os.Mkdir(outer, 0700) != nil || os.Mkdir(root, 0700) != nil {
				t.Fatal("own directories unavailable")
			}
			o, err := task0ReadOnlyFile(outer)
			if err != nil {
				t.Fatal(err)
			}
			r, err := task0ReadOnlyFile(root)
			if err != nil {
				o.Close()
				t.Fatal(err)
			}
			d := &task0CAParentDirectory{outer: outer, root: root, outerFD: o, rootFD: r}
			defer d.close()
			if syscall.Fstat(int(o.Fd()), &d.outerState) != nil || syscall.Fstat(int(r.Fd()), &d.rootState) != nil {
				t.Fatal("held directory identity unavailable")
			}
			if mutation != "LIVE_CHILD" {
				task0ReleaseNonCanonJoinGate(t, p, release)
			}
			if mutation == "NONEMPTY_DIRECTORY" {
				if os.WriteFile(filepath.Join(root, "unexpected"), []byte("preserve"), 0600) != nil {
					t.Fatal("fixture mutation failed")
				}
			}
			var output bytes.Buffer
			removed, err := task0PublishJoinedParentResult(&output, p, d, &task0PreparationResult{Schema: strings.Repeat("a", 16)})
			if mutation != "CLEAN" {
				if err == nil || removed || output.Len() != 0 {
					t.Fatal("successful output escaped before join or cleanup")
				}
			} else if err != nil || !removed || output.Len() == 0 {
				t.Fatal("joined, fully cleaned result not published")
			} else if _, err := os.Lstat(outer); !os.IsNotExist(err) {
				t.Fatal("output published while own empty directories remain")
			}
		})
	}
}
