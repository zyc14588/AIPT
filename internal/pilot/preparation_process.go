package pilot

import (
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const freshPreparationSchema = "aipt.private.b007-fresh-preparation-admission/v1"

type freshPreparationFrame struct {
	Schema     string `json:"schema"`
	Operation  string `json:"operation"`
	BindingSHA string `json:"binding_sha256"`
	Nonce      string `json:"nonce,omitempty"`
}

// Admission belongs to the trusted parent that owns the exact sealed static
// preparation executable. Namespace properties alone never supply this grant.
// The full accepted binding still has to pass all runtime/review/CI gates before
// any constructor or model use; this protocol itself performs no model work.
type freshPreparationProcess struct {
	command *exec.Cmd
	control *net.UnixConn
	exit    chan struct{}
	waitErr error
}

func staticPreparationFile(f *os.File) bool {
	if f == nil {
		return false
	}
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() < 64 || s.Size() > 128<<20 {
		return false
	}
	image, e := elf.NewFile(io.NewSectionReader(f, 0, s.Size()))
	if e != nil {
		return false
	}
	defer image.Close()
	if image.Class != elf.ELFCLASS64 || image.Data != elf.ELFDATA2LSB || image.Machine != elf.EM_X86_64 || (image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN) {
		return false
	}
	for _, p := range image.Progs {
		if p.Type == elf.PT_INTERP {
			return false
		}
	}
	d, e := readNativeDynamic(image, s.Size())
	return e == nil && len(d.needed) == 0
}

func preparationPacket(c *net.UnixConn, frame *freshPreparationFrame, write bool) error {
	if c == nil || frame == nil {
		return ErrRuntimeLaunch
	}
	if write {
		raw, e := json.Marshal(frame)
		if e != nil || len(raw) > 1024 {
			return ErrRuntimeLaunch
		}
		n, e := c.Write(raw)
		if e != nil || n != len(raw) {
			return ErrRuntimeLaunch
		}
		return nil
	}
	var raw [1025]byte
	n, e := c.Read(raw[:])
	if e != nil || n < 1 || n > 1024 || decodeFrozenJSON(raw[:n], 1024, frame) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func verifiedPreparationChild(command *exec.Cmd, heldSelf *os.File) error {
	if command == nil || command.Process == nil || heldSelf == nil || command.Process.Signal(syscall.Signal(0)) != nil {
		return ErrRuntimeLaunch
	}
	hasHandle := false
	if command.Process.WithHandle(func(uintptr) { hasHandle = true }) != nil || !hasHandle {
		return ErrRuntimeLaunch
	}
	info, e := heldSelf.Stat()
	actual, ae := os.Stat("/proc/" + strconv.Itoa(command.Process.Pid) + "/exe")
	if e != nil || ae != nil || !os.SameFile(info, actual) {
		return ErrRuntimeLaunch
	}
	base := "/proc/" + strconv.Itoa(command.Process.Pid)
	for _, mapping := range []struct {
		name string
		id   int
	}{{"uid_map", os.Getuid()}, {"gid_map", os.Getgid()}} {
		raw, e := os.ReadFile(base + "/" + mapping.name)
		if e != nil || !singleRootIDMapping(raw) || strings.Fields(string(raw))[1] != strconv.Itoa(mapping.id) {
			return ErrRuntimeLaunch
		}
	}
	for _, kind := range []string{"user", "pid", "mnt", "net"} {
		parent, e := os.Stat("/proc/self/ns/" + kind)
		child, ce := os.Stat(base + "/ns/" + kind)
		if e != nil || ce != nil || (kind == "net") != os.SameFile(parent, child) {
			return ErrRuntimeLaunch
		}
	}
	status, e := os.ReadFile(base + "/status")
	if e != nil || len(status) > 65536 {
		return ErrRuntimeLaunch
	}
	ownedPID1 := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "NSpid:" && fields[len(fields)-1] == "1" {
			ownedPID1 = true
		}
	}
	if !ownedPID1 || command.Process.Signal(syscall.Signal(0)) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

// Only this exact parent function creates the production USER/PID/MNT child.
// NET deliberately stays with the parent for the later approved remote route.
// There are no caller-selectable clone flags, model paths or runtime selectors.
func launchFreshPreparation(ctx context.Context, heldSelf, heldBinding *os.File, bindingSHA string, arguments, environment []string, diagnostics io.Writer) (*freshPreparationProcess, error) {
	if ctx == nil || ctx.Err() != nil || heldSelf == nil || heldBinding == nil || !digest(bindingSHA) || diagnostics == nil {
		return nil, ErrRuntimeLaunch
	}
	for _, f := range []*os.File{heldSelf, heldBinding} {
		seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
		if errno != 0 || seals&0xf != 0xf {
			return nil, ErrRuntimeLaunch
		}
	}
	if !staticPreparationFile(heldSelf) || inputSHAFileMetadata(heldBinding) != bindingSHA {
		return nil, ErrRuntimeLaunch
	}
	fds, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	parentFile, childFile := os.NewFile(uintptr(fds[0]), "own preparation parent control"), os.NewFile(uintptr(fds[1]), "own preparation child control")
	defer parentFile.Close()
	defer childFile.Close()
	connection, e := net.FileConn(parentFile)
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, ErrRuntimeLaunch
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", arguments...)
	cmd.Env = append([]string(nil), environment...)
	cmd.ExtraFiles = []*os.File{heldSelf, heldBinding, childFile}
	cmd.Stdout, cmd.Stderr = diagnostics, diagnostics
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	if e = cmd.Start(); e != nil {
		if pidfd >= 0 {
			_ = syscall.Close(pidfd)
		}
		control.Close()
		return nil, fmt.Errorf("%w: fresh child creation: %w", ErrRuntimeLaunch, e)
	}
	childFile.Close()
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	p := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exit) }()
	fail := func() (*freshPreparationProcess, error) { _ = p.retire(); return nil, ErrRuntimeLaunch }
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil || verifiedPreparationChild(cmd, heldSelf) != nil {
		return fail()
	}
	var hello freshPreparationFrame
	if preparationPacket(control, &hello, false) != nil || hello != (freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: bindingSHA}) || verifiedPreparationChild(cmd, heldSelf) != nil {
		return fail()
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return fail()
	}
	admission := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "ADMIT", BindingSHA: bindingSHA, Nonce: hex.EncodeToString(nonce[:])}
	if preparationPacket(control, &admission, true) != nil {
		return fail()
	}
	var ack freshPreparationFrame
	if preparationPacket(control, &ack, false) != nil || ack.Schema != admission.Schema || ack.Operation != "ADMITTED" || ack.BindingSHA != admission.BindingSHA || ack.Nonce != admission.Nonce || verifiedPreparationChild(cmd, heldSelf) != nil || control.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	return p, nil
}

func (p *freshPreparationProcess) retire() error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	if p.control != nil {
		p.control.Close()
	}
	select {
	case <-p.exit:
		return nil
	default:
	}
	_ = p.command.Process.Kill() // Retained Go pidfd; only this owned PID namespace.
	select {
	case <-p.exit:
		return nil
	case <-time.After(5 * time.Second):
		return ErrRuntimeLaunch
	}
}

// The child cannot admit itself by merely presenting namespace properties.
// It requires the exact sealed self/binding and an outside-parent admission on
// its inherited private socket. It returns only authenticated binding bytes.
func receiveFreshPreparationAdmission(ctx context.Context, bindingSHA string) ([]byte, *net.UnixConn, error) {
	if ctx == nil || ctx.Err() != nil || !digest(bindingSHA) || os.Getpid() != 1 || !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return nil, nil, ErrRuntimeLaunch
	}
	for fd := 3; fd <= 5; fd++ {
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 {
			return nil, nil, ErrRuntimeLaunch
		}
		if _, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, flags|syscall.FD_CLOEXEC); errno != 0 {
			return nil, nil, ErrRuntimeLaunch
		}
	}
	self := os.NewFile(3, "held preparation executable")
	defer self.Close()
	info, e := self.Stat()
	actual, ae := os.Stat("/proc/self/exe")
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, self.Fd(), 0x40a, 0)
	if e != nil || ae != nil || !os.SameFile(info, actual) || errno != 0 || seals&0xf != 0xf || !staticPreparationFile(self) {
		return nil, nil, ErrRuntimeLaunch
	}
	binding := os.NewFile(4, "held accepted preparation binding")
	defer binding.Close()
	bi, e := binding.Stat()
	seals, _, errno = syscall.Syscall(syscall.SYS_FCNTL, binding.Fd(), 0x40a, 0)
	if e != nil || !bi.Mode().IsRegular() || bi.Size() < 1 || bi.Size() > 1<<20 || errno != 0 || seals&0xf != 0xf {
		return nil, nil, ErrRuntimeLaunch
	}
	raw, e := io.ReadAll(io.NewSectionReader(binding, 0, bi.Size()))
	if e != nil || inputSHA(raw) != bindingSHA {
		return nil, nil, ErrRuntimeLaunch
	}
	typeValue, e := syscall.GetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_TYPE)
	peer, pe := syscall.GetsockoptUcred(5, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if e != nil || pe != nil || typeValue != syscall.SOCK_SEQPACKET || peer.Pid != 0 || peer.Uid != 0 || peer.Gid != 0 {
		return nil, nil, ErrRuntimeLaunch
	}
	socket := os.NewFile(5, "owned preparation admission socket")
	connection, e := net.FileConn(socket)
	socket.Close()
	if e != nil {
		return nil, nil, ErrRuntimeLaunch
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, nil, ErrRuntimeLaunch
	}
	fail := func() ([]byte, *net.UnixConn, error) { control.Close(); return nil, nil, ErrRuntimeLaunch }
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return fail()
	}
	hello := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: bindingSHA}
	if preparationPacket(control, &hello, true) != nil {
		return fail()
	}
	var admission freshPreparationFrame
	if preparationPacket(control, &admission, false) != nil || admission.Schema != hello.Schema || admission.Operation != "ADMIT" || admission.BindingSHA != hello.BindingSHA || !digest(admission.Nonce) || ctx.Err() != nil {
		return fail()
	}
	admission.Operation = "ADMITTED"
	if preparationPacket(control, &admission, true) != nil || control.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	// Mounting proc for this owned PID namespace precedes every manager lookup.
	// This trusted preparation process must write its own nested children's
	// uid_map/gid_map/setgroups while Go creates their user namespaces. A
	// read-only proc mount prevents Start before the child can exec or admit.
	// Models still receive their separate frozen root with read-only proc; no
	// host proc mount, unrelated PID or model/source FD enters this setup.
	if syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "") != nil || syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil {
		return fail()
	}
	return raw, control, nil
}
