package pilot

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"syscall"
	"time"
)

func task0SetupNoAmbientInputs(self, binding *os.File, control *net.UnixConn) bool {
	ss, se := task0CAFileState(self)
	bs, be := task0CAFileState(binding)
	if se != nil || be != nil || control == nil {
		return false
	}
	var socketFD int
	raw, err := control.SyscallConn()
	if err != nil || raw.Control(func(fd uintptr) { socketFD = int(fd) }) != nil {
		return false
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			return false
		}
		var state syscall.Stat_t
		err = syscall.Fstat(fd, &state)
		if err == syscall.EBADF {
			continue // The closed directory enumeration descriptor.
		}
		if err != nil {
			return false
		}
		switch state.Mode & syscall.S_IFMT {
		case syscall.S_IFREG:
			if !((fd == int(self.Fd()) && state.Dev == ss.Dev && state.Ino == ss.Ino) || (fd == int(binding.Fd()) && state.Dev == bs.Dev && state.Ino == bs.Ino)) {
				return false
			}
		case syscall.S_IFSOCK:
			if fd != socketFD {
				return false
			}
		case syscall.S_IFDIR:
			return false
		}
	}
	return true
}

type task0SetupOwnedChild struct {
	command *exec.Cmd
	role    string
	exit    chan struct{}
	waitErr error
	joined  bool
}

type task0SetupOwner struct {
	grant      *acceptedTask0Setup
	control    *net.UnixConn
	generation string
	forbidden  []task0SetupFDIdentity
	usedNonces map[string]bool
	children   map[int]*task0SetupOwnedChild
	created    int
	joined     int
	remote     int
	game       bool
	local      bool
}

func (s *task0SetupOwner) stopAndWait(slot *task0SetupOwnedChild) error {
	if s == nil || slot == nil || slot.command == nil || slot.command.Process == nil || slot.joined {
		return ErrRuntimeLaunch
	}
	select {
	case <-slot.exit:
	default:
		_ = slot.command.Process.Kill() // Go retains the directly owned pidfd.
	}
	select {
	case <-slot.exit:
		// The goroutine below actually called this owner's command.Wait().
		// Forced retirement may have a signal exit; the reply preserves it.
		slot.joined = true
		s.joined++
		return nil
	case <-time.After(5 * time.Second):
		return ErrRuntimeLaunch
	}
}

func (s *task0SetupOwner) stopAll() error {
	if s == nil {
		return ErrRuntimeLaunch
	}
	// Signal all directly owned children first. A sequential wait cannot
	// delay another child's stop or leave a live sibling using private inputs.
	for _, slot := range s.children {
		if !slot.joined {
			select {
			case <-slot.exit:
			default:
				_ = slot.command.Process.Kill()
			}
		}
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for _, slot := range s.children {
		if !slot.joined {
			select {
			case <-slot.exit:
				slot.joined = true
				s.joined++
			case <-deadline.C:
				return ErrRuntimeLaunch
			}
		}
	}
	if s.joined != s.created {
		return ErrRuntimeLaunch
	}
	return nil
}

func (s *task0SetupOwner) requestValid(frame task0SetupFrame) bool {
	if s == nil || s.grant == nil || !task0SetupFrameValid(frame, frame.Operation, s.grant.identity, s.generation, frame.Nonce, frame.Sequence, frame.Role) ||
		s.usedNonces[frame.Nonce] || len(frame.Forbidden) != 0 || frame.Waited || frame.ExitCode != 0 || frame.Joined != 0 {
		return false
	}
	s.usedNonces[frame.Nonce] = true
	return true
}

func (s *task0SetupOwner) create(ctx context.Context, frame task0SetupFrame, files []*os.File) error {
	if s == nil || frame.Sequence != s.created || s.created >= 34 || !task0SetupRoleName(frame.Role) ||
		(frame.Role == "GAME" && s.game) || (frame.Role == "LOCAL" && s.local) ||
		(frame.Role != "GAME" && frame.Role != "LOCAL" && s.remote >= 32) {
		return ErrRuntimeLaunch
	}
	role, ok := s.grant.roles[frame.Role]
	if !ok {
		return ErrRuntimeLaunch
	}
	credential, err := task0SetupInputs(s.grant, role, files, s.forbidden)
	if err != nil {
		return ErrRuntimeLaunch
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3")
	cmd.Stderr, cmd.Stdout = io.Discard, io.Discard
	flags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS)
	if role.Role == "LOCAL" {
		flags |= syscall.CLONE_NEWNET
		cmd.Env = frozenEnvironment(map[string]string{"AIPT_RUNTIME_ISOLATOR": "1"})
		cmd.ExtraFiles = files
	} else {
		cmd.Stdin, cmd.Stdout = files[2], files[3]
		cmd.ExtraFiles = files[:2]
		if role.Role == "GAME" {
			flags |= syscall.CLONE_NEWNET
			cmd.Env = frozenEnvironment(map[string]string{"AIPT_TASK0_GAME_CAPSULE": "1"})
		} else {
			cmd.Env = frozenEnvironment(map[string]string{"AIPT_TASK0_REMOTE_CAPSULE": "1", "DEEPSEEK_API_KEY": credential})
		}
	}
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: flags, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	if err = cmd.Start(); err != nil {
		if pidfd >= 0 {
			syscall.Close(pidfd)
		}
		return ErrRuntimeLaunch // No new role or permission fallback, no retry.
	}
	// The child's environment is inherited at Start. The owner does not keep
	// the credential in an exec.Cmd for the remaining generation lifetime.
	cmd.Env = nil
	owned := &task0SetupOwnedChild{command: cmd, role: frame.Role, exit: make(chan struct{})}
	s.children[frame.Sequence] = owned
	s.created++
	if frame.Role == "GAME" {
		s.game = true
	} else if frame.Role == "LOCAL" {
		s.local = true
	} else {
		s.remote++
	}
	go func() { owned.waitErr = cmd.Wait(); close(owned.exit) }()
	// The server must release every child-side peer/pipe after successful
	// Start, before responding, so an early child exit produces real EOF.
	for _, f := range files {
		f.Close()
	}
	if pidfd < 0 {
		return ErrRuntimeLaunch
	}
	heldPID := os.NewFile(uintptr(pidfd), "directly owned role pidfd")
	defer heldPID.Close()
	frame.Operation = "CREATED"
	return task0SetupWrite(s.control, frame, []*os.File{heldPID})
}

func (s *task0SetupOwner) serve(ctx context.Context) (err error) {
	defer func() {
		if s.stopAll() != nil {
			err = ErrRuntimeLaunch
		}
	}()
	for {
		frame, files, readErr := task0SetupRead(s.control)
		if readErr != nil {
			return ErrRuntimeLaunch
		}
		if !s.requestValid(frame) {
			for _, f := range files {
				f.Close()
			}
			return ErrRuntimeLaunch
		}
		if _, e := task0PrivilegeThreads("/proc/self", task0SetupCapabilityMask, 0, 0); e != nil {
			for _, f := range files {
				f.Close()
			}
			return ErrRuntimeLaunch
		}
		switch frame.Operation {
		case "CREATE":
			err = s.create(ctx, frame, files)
			for _, f := range files {
				f.Close()
			}
			if err != nil {
				return ErrRuntimeLaunch
			}
		case "JOIN":
			slot := s.children[frame.Sequence]
			if len(files) != 0 || slot == nil || slot.role != frame.Role || s.stopAndWait(slot) != nil {
				for _, f := range files {
					f.Close()
				}
				return ErrRuntimeLaunch
			}
			frame.Operation, frame.Waited, frame.ExitCode, frame.Joined = "JOINED", true, slot.command.ProcessState.ExitCode(), s.joined
			if task0SetupWrite(s.control, frame, nil) != nil {
				return ErrRuntimeLaunch
			}
		case "SHUTDOWN":
			if len(files) != 0 || frame.Role != "" || frame.Sequence != s.created || s.stopAll() != nil {
				for _, f := range files {
					f.Close()
				}
				return ErrRuntimeLaunch
			}
			frame.Operation, frame.Waited, frame.Joined = "SHUTDOWN_JOINED", true, s.joined
			if task0SetupWrite(s.control, frame, nil) != nil {
				return ErrRuntimeLaunch
			}
			return nil
		default:
			for _, f := range files {
				f.Close()
			}
			return ErrRuntimeLaunch
		}
	}
}

// The separately bound static entrypoint has no CLI/env selection, application
// network calls, verifier, database or report operations. Its only env is LANG
// and TZ; a role credential arrives on a short-lived sealed role input.
func RunAcceptedTask0Setup(expectedBindingSHA string) error {
	if !digest(expectedBindingSHA) || len(os.Args) != 1 || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return ErrRuntimeLaunch
	}
	for fd := 3; fd <= 5; fd++ {
		syscall.CloseOnExec(fd)
	}
	self, binding := os.NewFile(3, "held exact SETUP self"), os.NewFile(4, "held exact SETUP binding")
	defer self.Close()
	defer binding.Close()
	actual, err := os.Stat("/proc/self/exe")
	held, he := self.Stat()
	ss, sse := task0CAFileState(self)
	bs, be := task0CAFileState(binding)
	seals, _, se := syscall.Syscall(syscall.SYS_FCNTL, self.Fd(), 0x40a, 0)
	bindSeals, _, bse := syscall.Syscall(syscall.SYS_FCNTL, binding.Fd(), 0x40a, 0)
	if err != nil || he != nil || be != nil || sse != nil || ss.Uid != 0 || ss.Nlink != 0 || ss.Mode&07777 != 0500 ||
		!os.SameFile(actual, held) || !staticPreparationFile(self) || se != 0 || seals&0xf != 0xf ||
		bse != 0 || bindSeals&0xf != 0xf || bs.Uid != 0 || bs.Nlink != 0 || bs.Mode&07777 != 0400 || bs.Size < 1 || bs.Size > task0SetupBindingMaxBytes {
		return ErrRuntimeLaunch
	}
	raw, readErr := io.ReadAll(io.NewSectionReader(binding, 0, task0SetupBindingMaxBytes+1))
	defer clear(raw)
	a, err := decodeTask0Setup(raw, expectedBindingSHA)
	if readErr != nil || err != nil {
		return ErrRuntimeLaunch
	}
	socket := os.NewFile(5, "own PREP to SETUP control")
	if !task0SetupChildControl(socket) {
		socket.Close()
		return ErrRuntimeLaunch
	}
	connection, err := net.FileConn(socket)
	socket.Close()
	if err != nil {
		return ErrRuntimeLaunch
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return ErrRuntimeLaunch
	}
	defer control.Close()
	if syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "") != nil ||
		syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil ||
		task0ConvergePrivileges(task0SetupCapabilityMask) != nil || !task0SetupNoAmbientInputs(self, binding, control) || control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return ErrRuntimeLaunch
	}
	hello := task0SetupFrame{Schema: task0SetupControlSchema, Operation: "READY", BindingSHA: a.identity}
	if task0SetupWrite(control, hello, nil) != nil {
		return ErrRuntimeLaunch
	}
	admission, files, err := task0SetupRead(control)
	for _, f := range files {
		f.Close()
	}
	if err != nil || len(files) != 0 || !task0SetupFrameValid(admission, "ADMIT", a.identity, admission.Generation, admission.Nonce, 0, "") ||
		admission.Waited || admission.Joined != 0 || admission.ExitCode != 0 || len(admission.Forbidden) != 6 {
		return ErrRuntimeLaunch
	}
	for i, no := range admission.Forbidden {
		if no.Ino == 0 || slices.Contains(admission.Forbidden[:i], no) {
			return ErrRuntimeLaunch
		}
	}
	admission.Operation = "ADMITTED"
	if task0SetupWrite(control, admission, nil) != nil || control.SetDeadline(time.Time{}) != nil {
		return ErrRuntimeLaunch
	}
	ctx, cancel := context.WithTimeout(context.Background(), 31*time.Minute)
	defer cancel()
	stopClose := context.AfterFunc(ctx, func() { control.Close() })
	defer stopClose()
	owner := &task0SetupOwner{grant: a, control: control, generation: admission.Generation, forbidden: slices.Clone(admission.Forbidden),
		usedNonces: map[string]bool{admission.Nonce: true}, children: map[int]*task0SetupOwnedChild{}}
	return owner.serve(ctx)
}
