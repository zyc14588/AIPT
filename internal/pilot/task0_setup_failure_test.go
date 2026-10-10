package pilot

import (
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A private test executable peer only; no production entry, namespace,
// execution role, application network, DB, registered program or model.
func TestTask0SetupNonCanonProtocolPeer(t *testing.T) {
	mode := os.Getenv("AIPT_Q014_NON_CANON_PROTOCOL_PEER")
	if mode == "" {
		return
	}
	if mode == "JOIN_ONLY" {
		os.Exit(0)
	}
	if mode == "HELD_JOIN" {
		input := os.NewFile(3, "NON_CANON owned join gate")
		var raw [1]byte
		if _, err := input.Read(raw[:]); err != nil {
			os.Exit(26)
		}
		input.Close()
		os.Exit(0)
	}
	socket := os.NewFile(3, "NON_CANON test peer")
	c, err := net.FileConn(socket)
	socket.Close()
	if err != nil {
		os.Exit(21)
	}
	control := c.(*net.UnixConn)
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	frame, rights, err := task0SetupRead(control)
	for _, f := range rights {
		f.Close()
	}
	if err != nil || frame.Operation != "CREATE" || len(rights) != 0 {
		os.Exit(22)
	}
	if mode == "EOF" {
		control.Close()
		os.Exit(0)
	}
	if mode != "MALFORMED" {
		os.Exit(23)
	}
	if _, err = control.Write([]byte(`{"schema":"caller","foreign_field":true}`)); err != nil {
		os.Exit(24)
	}
	var raw [1]byte
	if _, err = control.Read(raw[:]); err == nil {
		os.Exit(25)
	}
	os.Exit(0)
}

func TestTask0SetupAmbiguousReplyPermanentlyRevokesAndDirectlyJoinsOwner(t *testing.T) {
	for _, mode := range []string{"EOF", "MALFORMED"} {
		t.Run(mode, func(t *testing.T) {
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			control, child, err := task0PrivateControlPair()
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			defer child.Close()
			cmd := exec.Command(self, "-test.run=^TestTask0SetupNonCanonProtocolPeer$")
			cmd.Env = frozenEnvironment(map[string]string{"AIPT_Q014_NON_CANON_PROTOCOL_PEER": mode})
			cmd.ExtraFiles = []*os.File{child}
			cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
			pidfd := -1
			cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			child.Close()
			if pidfd >= 0 {
				syscall.Close(pidfd)
			}
			p := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
			go func() { p.waitErr = cmd.Wait(); close(p.exit) }()
			defer p.retire()
			s := &task0SetupClient{process: p, grant: &acceptedTask0Setup{identity: strings.Repeat("a", 64), roles: map[string]task0SetupRole{"GM": {Role: "GM"}}}, generation: strings.Repeat("b", 64), roles: map[int]*task0DelegatedProcess{}}
			if role, err := s.create("GM", nil); err == nil || role != nil {
				t.Fatal("ambiguous response accepted")
			}
			if !s.invalid || !s.closed || !s.abortJoined || s.shutdownOK || s.retireError == nil || s.created != 0 || p.waitErr != nil {
				t.Fatal("generation remained live/reusable or missing real direct Wait")
			}
			if role, err := s.create("GM", nil); err == nil || role != nil || s.created != 0 {
				t.Fatal("uncertain slot retried")
			}
			if s.retire() == nil {
				t.Fatal("failed protocol relabelled successful shutdown")
			}
		})
	}
}
