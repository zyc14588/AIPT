package pilot

import (
	"context"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestTask0SetupRejectsExtraRoleOrExecutionSelector(t *testing.T) {
	for _, role := range []string{"GAME", "GM", "PLAYER_1", "PLAYER_2", "PLAYER_3", "PLAYER_4", "LOCAL"} {
		if !task0SetupRoleName(role) {
			t.Fatal("fixed role rejected", role)
		}
	}
	for _, role := range []string{"", "SETUP", "PREP", "MAPPER", "PLAYER_5", "gm", "GM ", "/proc/self/fd/3", "LOCAL --caller-argument"} {
		if task0SetupRoleName(role) {
			t.Fatal("unregistered role/selector accepted")
		}
	}
	for _, raw := range []string{"{}", "{\"schema\":\"caller\"}", "{\"schema\":\"a\",\"Schema\":\"a\"}"} {
		if _, err := decodeTask0Setup([]byte(raw), inputSHA([]byte(raw))); err == nil {
			t.Fatal("unaccepted SETUP binding accepted")
		}
	}
	if RunAcceptedTask0Setup("") == nil {
		t.Fatal("unbound build entered SETUP")
	}
}

func TestTask0SetupFreshFramesRejectReplayAndCrossGeneration(t *testing.T) {
	binding, generation, nonce := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	frame := task0SetupFrame{Schema: task0SetupControlSchema, Operation: "CREATE", BindingSHA: binding, Generation: generation, Nonce: nonce, Role: "GM"}
	s := &task0SetupOwner{grant: &acceptedTask0Setup{identity: binding}, generation: generation, usedNonces: map[string]bool{}}
	if !s.requestValid(frame) || s.requestValid(frame) {
		t.Fatal("fresh request rejected or repeated nonce accepted")
	}
	for _, change := range []func(*task0SetupFrame){func(f *task0SetupFrame) { f.Generation = strings.Repeat("d", 64) },
		func(f *task0SetupFrame) { f.BindingSHA = strings.Repeat("d", 64) }, func(f *task0SetupFrame) { f.Schema = "foreign" },
		func(f *task0SetupFrame) { f.Nonce = "missing" }, func(f *task0SetupFrame) { f.Sequence = 35 }, func(f *task0SetupFrame) { f.Sequence = -1 },
		func(f *task0SetupFrame) { f.Role = "SETUP" }, func(f *task0SetupFrame) { f.Waited = true }, func(f *task0SetupFrame) { f.Joined = 1 },
		func(f *task0SetupFrame) { f.ExitCode = 17 }, func(f *task0SetupFrame) { f.Forbidden = []task0SetupFDIdentity{{Dev: 1, Ino: 2}} }} {
		bad := frame
		bad.Nonce = strings.Repeat("e", 64)
		change(&bad)
		if s.requestValid(bad) {
			t.Fatal("stale, cross-generation or unsolicited control fields accepted")
		}
	}
}

func TestTask0SetupRoleBudgetsRejectBeforeAnyCreate(t *testing.T) {
	for _, scenario := range []string{"slot35", "second_game", "second_local", "remote33", "out_of_order", "new_role"} {
		t.Run(scenario, func(t *testing.T) {
			s := &task0SetupOwner{}
			frame := task0SetupFrame{Role: "GM"}
			switch scenario {
			case "slot35":
				s.created, frame.Sequence = 34, 34
			case "second_game":
				s.game, frame.Role = true, "GAME"
			case "second_local":
				s.local, frame.Role = true, "LOCAL"
			case "remote33":
				s.remote = 32
			case "out_of_order":
				frame.Sequence = 1
			case "new_role":
				frame.Role = "MAPPER"
			}
			if s.create(context.Background(), frame, nil) == nil || s.created != frame.Sequence && scenario != "out_of_order" {
				t.Fatal("role limit consumed or bypassed before any input/program")
			}
		})
	}
}

func task0SetupSocketFixture(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	a, child, err := task0PrivateControlPair()
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.FileConn(child)
	child.Close()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	b := connection.(*net.UnixConn)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestTask0SetupDescriptorTransferRestoresCloseOnExec(t *testing.T) {
	a, b := task0SetupSocketFixture(t)
	f, err := os.CreateTemp(t.TempDir(), "NON-CANON-transfer-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	frame := task0SetupFrame{Schema: task0SetupControlSchema, Operation: "CREATE", BindingSHA: strings.Repeat("a", 64), Generation: strings.Repeat("b", 64), Nonce: strings.Repeat("c", 64), Role: "GM"}
	if task0SetupWrite(a, frame, []*os.File{f}) != nil {
		t.Fatal("private rights write")
	}
	got, files, err := task0SetupRead(b)
	if err != nil || len(files) != 1 || !task0SameJSON(got, frame) {
		t.Fatal("exact rights frame read")
	}
	defer files[0].Close()
	before, _ := f.Stat()
	after, _ := files[0].Stat()
	flags, _, e := syscall.Syscall(syscall.SYS_FCNTL, files[0].Fd(), syscall.F_GETFD, 0)
	if !os.SameFile(before, after) || e != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("received descriptor identity or CLOEXEC missing")
	}
	if _, err := task0PIDFDProcess(files[0]); err == nil {
		t.Fatal("regular input substituted for pidfd")
	}
}

func TestTask0SetupRejectedFramesCloseEveryReceivedDescriptor(t *testing.T) {
	a, b := task0SetupSocketFixture(t)
	f, err := os.CreateTemp(t.TempDir(), "NON-CANON-rejection-control-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := count()
	for i := 0; i < 64; i++ {
		raw := []byte("{\"schema\":\"caller\",\"extra_field\":true}")
		if i%2 == 1 {
			raw = []byte(strings.Repeat("x", 4096))
		}
		if _, _, err := a.WriteMsgUnix(raw, syscall.UnixRights(int(f.Fd())), nil); err != nil {
			t.Fatal(err)
		}
		if _, files, err := task0SetupRead(b); err == nil || len(files) != 0 {
			t.Fatal("malformed/truncated frame accepted or rights returned")
		}
	}
	if after := count(); after != before {
		t.Fatalf("rejected rights leaked descriptors: %d to %d", before, after)
	}
}
