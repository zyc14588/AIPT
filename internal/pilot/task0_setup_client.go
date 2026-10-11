package pilot

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func task0SetupNonce() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrRuntimeLaunch
	}
	return hex.EncodeToString(nonce[:]), nil
}

func task0PrivateControlPair() (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrRuntimeLaunch
	}
	parent, child := os.NewFile(uintptr(fds[0]), "own control parent"), os.NewFile(uintptr(fds[1]), "own control child")
	connection, err := net.FileConn(parent)
	parent.Close()
	if err != nil {
		child.Close()
		return nil, nil, ErrRuntimeLaunch
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		child.Close()
		return nil, nil, ErrRuntimeLaunch
	}
	return control, child, nil
}

type task0SetupClient struct {
	mu          sync.Mutex
	process     *freshPreparationProcess
	grant       *acceptedTask0Setup
	generation  string
	created     int
	joined      int
	closed      bool
	invalid     bool
	abortJoined bool
	shutdownOK  bool
	self        *os.File
	binding     *os.File
	roles       map[int]*task0DelegatedProcess
	namespaces  map[string]os.FileInfo
	retirement  sync.Once
	retireError error
}

func (s *task0SetupClient) live() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.process != nil && s.grant != nil && !task0DirectJoinCompleted(s.process)
}

func (s *task0SetupClient) directJoinCompleted() bool {
	return s != nil && task0DirectJoinCompleted(s.process)
}

// Retain regular execution inputs, never child socket/pipe peers. Keeping a
// peer open would hide an early child exit. Copies have their own CLOEXEC FD.
func task0CopyHeldRoleInputs(files []*os.File) ([]*os.File, error) {
	var held []*os.File
	for _, f := range files {
		var st syscall.Stat_t
		if f == nil || syscall.Fstat(int(f.Fd()), &st) != nil {
			task0CloseInputFiles(held)
			return nil, ErrRuntimeLaunch
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			continue
		}
		fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_DUPFD_CLOEXEC, 3)
		if errno != 0 {
			task0CloseInputFiles(held)
			return nil, ErrRuntimeLaunch
		}
		held = append(held, os.NewFile(fd, "held exact selected role input"))
	}
	return held, nil
}

// The caller holds s.mu. Protocol success and actual direct Wait are separate
// facts; input retention does not make a failed generation successful.
func (s *task0SetupClient) releaseSetupInputsLocked() {
	files := []*os.File{s.self, s.binding}
	s.self, s.binding = nil, nil
	if s.directJoinCompleted() {
		task0CloseInputFiles(files)
	} else {
		task0RetainInputsUntilDirectJoin(s.process, func() { task0CloseInputFiles(files) })
	}
}

// PREP calls this before irreversible Cap0. SETUP has its own fixed USER/PID/
// MNT and shares only the already accepted remote network namespace. It gets
// no CA, original host file, evidence, DB, model asset or Parent control FD.
func launchTask0Setup(self, binding *os.File, grant *acceptedTask0Setup, generation string, forbidden []task0SetupFDIdentity) (*task0SetupClient, error) {
	if self == nil || binding == nil || grant == nil || !digest(generation) || len(forbidden) != 6 || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") || !staticPreparationFile(self) || inputSHAFileMetadata(binding) != grant.identity {
		return nil, ErrRuntimeLaunch
	}
	for _, f := range []*os.File{self, binding} {
		seals, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
		if e != 0 || seals&0xf != 0xf {
			return nil, ErrRuntimeLaunch
		}
	}
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	defer child.Close()
	held, err := task0CopyHeldRoleInputs([]*os.File{self, binding})
	if err != nil || len(held) != 2 {
		control.Close()
		task0CloseInputFiles(held)
		return nil, ErrRuntimeLaunch
	}
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = frozenEnvironment(nil)
	cmd.ExtraFiles = []*os.File{held[0], held[1], child}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	if err = cmd.Start(); err != nil {
		if pidfd >= 0 {
			syscall.Close(pidfd)
		}
		control.Close()
		task0CloseInputFiles(held)
		return nil, ErrRuntimeLaunch
	}
	child.Close() // Never retain the child's peer across a READY/ACK read.
	if pidfd >= 0 {
		syscall.Close(pidfd)
	}
	p := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exit) }()
	s := &task0SetupClient{process: p, grant: grant, generation: generation, roles: map[int]*task0DelegatedProcess{}, self: held[0], binding: held[1]}
	fail := func() (*task0SetupClient, error) {
		_ = p.retire()
		s.invalid, s.closed, s.retireError = true, true, ErrRuntimeLaunch
		s.abortJoined = task0DirectJoinCompleted(p)
		// Return the failed owner so PREP never loses its actual join state.
		return s, ErrRuntimeLaunch
	}
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return fail()
	}
	hello, rights, err := task0SetupRead(control)
	for _, f := range rights {
		f.Close()
	}
	if err != nil || len(rights) != 0 || !task0SameJSON(hello, task0SetupFrame{Schema: task0SetupControlSchema, Operation: "READY", BindingSHA: grant.identity}) ||
		verifiedPreparationChild(cmd, self) != nil {
		return fail()
	}
	if _, err = task0PrivilegeThreads("/proc/"+strconv.Itoa(cmd.Process.Pid), task0SetupCapabilityMask, 0, 0); err != nil {
		return fail()
	}
	nonce, err := task0SetupNonce()
	if err != nil {
		return fail()
	}
	admission := task0SetupFrame{Schema: task0SetupControlSchema, Operation: "ADMIT", BindingSHA: grant.identity, Generation: generation, Nonce: nonce, Forbidden: slices.Clone(forbidden)}
	if task0SetupWrite(control, admission, nil) != nil {
		return fail()
	}
	ack, rights, err := task0SetupRead(control)
	for _, f := range rights {
		f.Close()
	}
	admission.Operation = "ADMITTED"
	if err != nil || len(rights) != 0 || !task0SameJSON(ack, admission) || verifiedPreparationChild(cmd, self) != nil {
		return fail()
	}
	if _, err = task0PrivilegeThreads("/proc/"+strconv.Itoa(cmd.Process.Pid), task0SetupCapabilityMask, 0, 0); err != nil || control.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	s.namespaces = map[string]os.FileInfo{}
	for _, kind := range []string{"user", "pid", "mnt", "net"} {
		info, err := os.Stat("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/ns/" + kind)
		if err != nil {
			return fail()
		}
		s.namespaces[kind] = info
	}
	return s, nil
}

// The caller holds mu. Any protocol ambiguity permanently revokes this
// generation, closes the peer, and gives the exact server time to stop and
// directly Wait all its own children before PREP directly joins SETUP.
func (s *task0SetupClient) abortGenerationLocked() {
	if s == nil || s.invalid {
		return
	}
	s.invalid, s.closed, s.retireError = true, true, ErrRuntimeLaunch
	if s.process == nil {
		return
	}
	if s.process.control != nil {
		_ = s.process.control.Close()
	}
	select {
	case <-s.process.exit:
		s.abortJoined = true
	case <-time.After(10 * time.Second):
		// Missing cooperative join is a preserved failure. Only this directly
		// owned SETUP pidfd is signalled; no foreign/grandchild PID is polled.
		if s.process.retire() == nil {
			s.abortJoined = true
		}
	}
}

func (s *task0SetupClient) request(operation, role string, sequence int, files []*os.File, expectedRights int) (replyFrame task0SetupFrame, replyRights []*os.File, requestErr error) {
	if s == nil || s.process == nil || s.grant == nil || s.closed {
		return task0SetupFrame{}, nil, ErrRuntimeLaunch
	}
	defer func() {
		if requestErr != nil {
			s.abortGenerationLocked()
		}
	}()
	select {
	case <-s.process.exit:
		return task0SetupFrame{}, nil, ErrRuntimeLaunch
	default:
	}
	nonce, err := task0SetupNonce()
	timeout := 120 * time.Second
	if operation == "JOIN" || operation == "SHUTDOWN" {
		timeout = 10 * time.Second
	}
	if err != nil || s.process.control.SetDeadline(time.Now().Add(timeout)) != nil {
		return task0SetupFrame{}, nil, ErrRuntimeLaunch
	}
	frame := task0SetupFrame{Schema: task0SetupControlSchema, Operation: operation, BindingSHA: s.grant.identity, Generation: s.generation, Nonce: nonce, Sequence: sequence, Role: role}
	if task0SetupWrite(s.process.control, frame, files) != nil {
		return task0SetupFrame{}, nil, ErrRuntimeLaunch
	}
	reply, rights, err := task0SetupRead(s.process.control)
	expected := map[string]string{"CREATE": "CREATED", "JOIN": "JOINED", "SHUTDOWN": "SHUTDOWN_JOINED"}[operation]
	if err != nil || expected == "" || len(rights) != expectedRights || len(reply.Forbidden) != 0 ||
		!task0SetupFrameValid(reply, expected, s.grant.identity, s.generation, nonce, sequence, role) || s.process.control.SetDeadline(time.Time{}) != nil {
		for _, f := range rights {
			f.Close()
		}
		return task0SetupFrame{}, nil, ErrRuntimeLaunch
	}
	return reply, rights, nil
}

// This is an observation handle to SETUP's child, not a fabricated exec.Cmd.
// Only SETUP performs command.Wait; PREP requires its authenticated JOINED
// reply and later directly joins SETUP itself.
type task0DelegatedProcess struct {
	owner      *task0SetupClient
	process    *os.Process
	pid        int
	pidfd      *os.File
	sequence   int
	role       task0SetupRole
	retirement sync.Once
	retireErr  error
	joined     bool
	inputs     []*os.File
}

func (p *task0DelegatedProcess) joinedByOwner() bool {
	if p == nil || p.owner == nil {
		return false
	}
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	return p.joined || p.owner.shutdownOK
}

func (p *task0DelegatedProcess) releaseInputsLocked(joined bool) {
	files := p.inputs
	p.inputs = nil
	if joined || p.owner.directJoinCompleted() {
		task0CloseInputFiles(files)
	} else {
		task0RetainInputsUntilDirectJoin(p.owner.process, func() { task0CloseInputFiles(files) })
	}
}

func task0PIDFDProcess(f *os.File) (int, error) {
	if f == nil {
		return 0, ErrRuntimeLaunch
	}
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil || link != "anon_inode:[pidfd]" {
		return 0, ErrRuntimeLaunch
	}
	raw, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(f.Fd())))
	if err != nil || len(raw) > 4096 {
		return 0, ErrRuntimeLaunch
	}
	pid, found := 0, false
	for _, line := range strings.Split(string(raw), "\n") {
		if value, ok := strings.CutPrefix(line, "Pid:"); ok {
			if found {
				return 0, ErrRuntimeLaunch
			}
			found = true
			pid, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil || pid <= 1 {
				return 0, ErrRuntimeLaunch
			}
		}
	}
	if !found {
		return 0, ErrRuntimeLaunch
	}
	return pid, nil
}

func (s *task0SetupClient) create(role string, files []*os.File) (*task0DelegatedProcess, error) {
	if s == nil {
		return nil, ErrRuntimeLaunch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grant == nil || s.closed {
		return nil, ErrRuntimeLaunch
	}
	entry, ok := s.grant.roles[role]
	if !ok || s.created >= 34 {
		return nil, ErrRuntimeLaunch
	}
	held, err := task0CopyHeldRoleInputs(files)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	assigned := false
	defer func() {
		if !assigned {
			task0RetainInputsUntilDirectJoin(s.process, func() { task0CloseInputFiles(held) })
		}
	}()
	reply, rights, err := s.request("CREATE", role, s.created, files, 1)
	if err != nil || reply.Waited || reply.ExitCode != 0 || reply.Joined != 0 {
		for _, f := range rights {
			f.Close()
		}
		s.abortGenerationLocked()
		return nil, ErrRuntimeLaunch
	}
	// The slot is consumed before inspecting a returned pidfd. Any malformed
	// reply stops the generation; a failed inspection cannot create slot0 again.
	sequence := s.created
	s.created++
	pid, err := task0PIDFDProcess(rights[0])
	if err != nil {
		rights[0].Close()
		s.abortGenerationLocked()
		return nil, ErrRuntimeLaunch
	}
	process, err := os.FindProcess(pid)
	if err != nil || process.Signal(syscall.Signal(0)) != nil {
		rights[0].Close()
		if process != nil {
			process.Release()
		}
		s.abortGenerationLocked()
		return nil, ErrRuntimeLaunch
	}
	p := &task0DelegatedProcess{owner: s, process: process, pid: pid, pidfd: rights[0], sequence: sequence, role: entry, inputs: held}
	assigned = true
	s.roles[sequence] = p
	return p, nil
}

func (p *task0DelegatedProcess) retire() error {
	if p == nil || p.owner == nil {
		return ErrRuntimeLaunch
	}
	p.retirement.Do(func() {
		s := p.owner
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.shutdownOK {
			p.retireErr = nil
			p.joined = true
		} else {
			reply, _, err := s.request("JOIN", p.role.Role, p.sequence, nil, 0)
			if err != nil || !reply.Waited || reply.Joined != s.joined+1 {
				p.retireErr = ErrRuntimeLaunch
				s.abortGenerationLocked()
			} else {
				s.joined++
				p.joined = true
			}
		}
		p.releaseInputsLocked(p.joined)
		if p.pidfd != nil {
			p.pidfd.Close()
		}
		if p.process != nil {
			p.process.Release()
		}
	})
	return p.retireErr
}

func (s *task0SetupClient) retire() error {
	if s == nil {
		return ErrRuntimeLaunch
	}
	s.retirement.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		defer s.releaseSetupInputsLocked()
		if s.invalid {
			for _, role := range s.roles {
				role.releaseInputsLocked(false)
				if role.pidfd != nil {
					role.pidfd.Close()
				}
				if role.process != nil {
					role.process.Release()
				}
			}
			return
		}
		reply, _, err := s.request("SHUTDOWN", "", s.created, nil, 0)
		if err != nil || !reply.Waited || reply.Joined != s.created {
			s.retireError = ErrRuntimeLaunch
			s.abortGenerationLocked()
		} else {
			s.joined, s.shutdownOK = reply.Joined, true
		}
		s.closed = true
		s.process.control.Close()
		select {
		case <-s.process.exit:
			if s.process.waitErr != nil {
				s.retireError = ErrRuntimeLaunch
			}
		case <-time.After(5 * time.Second):
			_ = s.process.retire()
			s.retireError = ErrRuntimeLaunch
		}
		for _, role := range s.roles {
			role.releaseInputsLocked(s.shutdownOK || role.joined)
			role.pidfd.Close()
			role.process.Release()
		}
	})
	return s.retireError
}
