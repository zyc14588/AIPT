package pilot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// This exact 3..13/self-exec/ExtraFiles protocol fixture executes only the
// Go test executable and NON_CANON markers. It never invokes the accepted
// helper entry, Node, native libraries, GGUF, driver or model endpoint.
func TestFrozenHelperSelfExecDescriptorsDoNotLeakIntoChildren(t *testing.T) {
	role := os.Getenv("AIPT_NONCANON_DESCRIPTOR_FIXTURE")
	if role == "child" {
		markerInfo, e := os.Stat("/proc/self/fd/4")
		if e != nil {
			t.Fatal(e)
		}
		pipe := os.Getenv("AIPT_NONCANON_PIPE_INODE")
		for fd := 5; fd < 4096; fd++ {
			var st syscall.Stat_t
			if syscall.Fstat(fd, &st) != nil {
				continue
			}
			info, e := os.Stat("/proc/self/fd/" + strconv.Itoa(fd))
			if e == nil && (os.SameFile(markerInfo, info) || fmt.Sprint(st.Ino) == pipe) {
				t.Fatal("unlisted original descriptor inherited", fd)
			}
		}
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	if role == "first-exec" {
		for fd := 3; fd <= 13; fd++ {
			if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); e != 0 {
				t.Fatal(e)
			}
		}
		if e := syscall.Exec("/proc/self/fd/3", []string{"NON_CANON_DESCRIPTOR_FIXTURE", "-test.run=^TestFrozenHelperSelfExecDescriptorsDoNotLeakIntoChildren$"}, []string{"AIPT_NONCANON_DESCRIPTOR_FIXTURE=second-exec"}); e != nil {
			t.Fatal(e)
		}
		return
	}
	if role == "second-exec" {
		if restoreFrozenInheritedCloseOnExec() != nil {
			t.Fatal("restore inherited CLOEXEC")
		}
		for fd := 3; fd <= 13; fd++ {
			flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
			if e != 0 || flags&syscall.FD_CLOEXEC == 0 {
				t.Fatal("original not CLOEXEC", fd, e)
			}
		}
		var pipeStat syscall.Stat_t
		if syscall.Fstat(11, &pipeStat) != nil {
			t.Fatal("missing fixture writer")
		}
		exe := os.NewFile(3, "own test executable")
		marker := os.NewFile(5, "non-canon marker")
		read := os.NewFile(10, "non-canon read pipe")
		write := os.NewFile(11, "non-canon write pipe")
		defer exe.Close()
		defer marker.Close()
		defer read.Close()
		inRead, inWrite, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		defer inRead.Close()
		defer inWrite.Close()
		cmd := exec.Command("/proc/self/fd/3", "-test.run=^TestFrozenHelperSelfExecDescriptorsDoNotLeakIntoChildren$")
		cmd.ExtraFiles = []*os.File{exe, marker}
		cmd.Env = []string{"AIPT_NONCANON_DESCRIPTOR_FIXTURE=child", "AIPT_NONCANON_PIPE_INODE=" + fmt.Sprint(pipeStat.Ino)}
		cmd.Stdin = inRead
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		wait := make(chan error, 1)
		go func() { wait <- cmd.Wait() }()
		defer func() {
			_ = cmd.Process.Kill()
			select {
			case <-wait:
			case <-time.After(time.Second):
				t.Error("own child did not retire")
			}
		}()
		if e = write.Close(); e != nil {
			t.Fatal(e)
		}
		eof := make(chan error, 1)
		go func() { var b [1]byte; _, e := read.Read(b[:]); eof <- e }()
		select {
		case e = <-eof:
			if !errors.Is(e, io.EOF) {
				t.Fatal("unlisted pipe unexpectedly readable", e)
			}
		case <-time.After(time.Second):
			t.Fatal("alive child retained unlisted output pipe writer")
		}
		if cmd.Process.Signal(syscall.Signal(0)) != nil {
			t.Fatal("EOF was only obtained after child death")
		}
		_ = inWrite.Close()
		select {
		case e = <-wait:
			if e != nil {
				t.Fatal("descriptor child", e, output.String())
			}
		case <-time.After(3*time.Second):
			t.Fatal("child did not complete descriptor inspection")
		}
		// Wait has already been consumed; prevent the deferred waiter timeout.
		wait <- nil
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(exe)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	marker, e := os.CreateTemp(t.TempDir(), "NON_CANON_FD_MARKER_")
	if e != nil {
		t.Fatal(e)
	}
	defer marker.Close()
	if _, e = marker.WriteString("NON_CANON_NOT_A_MODEL"); e != nil {
		t.Fatal(e)
	}
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestFrozenHelperSelfExecDescriptorsDoNotLeakIntoChildren$")
	cmd.ExtraFiles = []*os.File{f, marker, marker, marker, marker, marker, marker, read, write, marker, marker}
	cmd.Env = append(os.Environ(), "AIPT_NONCANON_DESCRIPTOR_FIXTURE=first-exec")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil { t.Fatal(e) }
	// The first parent must relinquish its original writer too; otherwise it
	// would independently prevent EOF even when the later child is isolated.
	_ = write.Close()
	_ = read.Close()
	if e = cmd.Wait(); e != nil { t.Fatal("own descriptor protocol fixture", e, output.String()) }

}

func nonCanonControlPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	convert := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "own fixture control")
		c, e := net.FileConn(f)
		_ = f.Close()
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c.(*net.UnixConn)
	}
	return convert(fds[0]), convert(fds[1])
}

func TestFrozenSupervisorUnexpectedAdapterExitRevokesLoop(t *testing.T) {
	for _, atStart := range []bool{false, true} {
		t.Run(strconv.FormatBool(atStart), func(t *testing.T) {
			control, _ := nonCanonControlPair(t)
			exit := make(chan struct{})
			nativeExit := make(chan struct{})
			s := &frozenSupervisor{control: control, native: &frozenOwnedProcess{exit: nativeExit}, adapter: &frozenOwnedProcess{exit: exit}, httpExit: make(chan struct{}), proofExit: make(chan struct{})}
			if atStart {
				close(exit)
			}
			done := make(chan error, 1)
			go func() { done <- s.loop() }()
			if !atStart {
				select {
				case <-done:
					t.Fatal("live idle adapter spuriously retired")
				case <-time.After(25 * time.Millisecond):
				}
				close(exit)
			}
			select {
			case e := <-done:
				if !errors.Is(e, ErrRuntimeLaunch) {
					t.Fatal("unexpected exit did not fail loop", e)
				}
			case <-time.After(time.Second):
				t.Fatal("unexpected adapter exit left helper control waiting")
			}
		})
	}
}

func TestFrozenSupervisorAbsentAdapterDoesNotRetainPriorExit(t *testing.T) {
	control, peer := nonCanonControlPair(t)
	s := &frozenSupervisor{control: control, native: &frozenOwnedProcess{exit: make(chan struct{})}, httpExit: make(chan struct{}), proofExit: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- s.loop() }()
	select {
	case <-done:
		t.Fatal("retired adapter retained an exit monitor")
	case <-time.After(25 * time.Millisecond):
	}
	_ = peer.Close()
	select {
	case e := <-done:
		if !errors.Is(e, ErrRuntimeLaunch) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("control closure did not revoke idle loop")
	}
}
