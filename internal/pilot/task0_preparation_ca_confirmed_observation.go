package pilot

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

const task0CAConfirmedObservationMarker = "AIPT_Q034_CA_CONFIRMED_OBSERVATION_ONLY_NOT_A_PROVIDER_CREDENTIAL"
const task0CAConfirmedRetirementSchema = "aipt.private.b007-ca-confirmed-preparation-retirement/v1"

type task0CAConfirmedSetupWait struct {
	SpawnAttempted       bool   `json:"spawn_attempted"`
	Started              bool   `json:"started"`
	NoSpawn              bool   `json:"no_spawn"`
	AdmissionNonce       string `json:"admission_nonce"`
	Admitted             bool   `json:"admitted"`
	ShutdownAttempted    bool   `json:"shutdown_attempted"`
	ShutdownNonce        string `json:"shutdown_nonce"`
	ShutdownAcknowledged bool   `json:"shutdown_acknowledged"`
	WaitCompleted        bool   `json:"actual_wait_completed"`
	ExitCode             int    `json:"exit_code"`
	WaitFailed           bool   `json:"wait_failed"`
	Created              int    `json:"business_children_created"`
	Joined               int    `json:"business_children_joined"`
}

type task0CAConfirmedRetirement struct {
	Schema          string                         `json:"schema"`
	BindingSHA      string                         `json:"preparation_binding_sha256"`
	ExecutableSHA   string                         `json:"preparation_executable_sha256"`
	Generation      string                         `json:"generation"`
	Nonce           string                         `json:"admission_nonce"`
	SetupSHA        string                         `json:"setup_executable_sha256"`
	SetupBindingSHA string                         `json:"setup_binding_sha256"`
	CA              task0SystemCABinding           `json:"system_ca"`
	Original        task0SetupFDIdentity           `json:"original"`
	Source          task0SetupFDIdentity           `json:"sealed_source"`
	Root            task0SetupFDIdentity           `json:"mountpoint_directory"`
	Materialized    task0SetupFDIdentity           `json:"materialized"`
	CAReadySent     bool                           `json:"ca_ready_sent"`
	Setup           task0CAConfirmedSetupWait      `json:"setup"`
	Handshake       task0CAConfirmedHandshakeTrace `json:"handshake"`
}

type task0PreparationCAConfirmedObservation struct {
	Schema                    string                          `json:"schema"`
	Stage                     string                          `json:"stage"`
	Outcome                   string                          `json:"outcome"`
	PreparationSpawnAttempted bool                            `json:"preparation_spawn_attempted"`
	PreparationStarted        bool                            `json:"preparation_started"`
	PreparationNoSpawn        bool                            `json:"preparation_no_spawn"`
	ReadyObserved             bool                            `json:"ready_observed"`
	AdmissionNonce            string                          `json:"admission_nonce"`
	AdmissionSent             bool                            `json:"admission_sent"`
	AdmittedObserved          bool                            `json:"admitted_observed"`
	ConfirmedSent             bool                            `json:"confirmed_sent"`
	CAReadyObserved           bool                            `json:"ca_ready_observed"`
	CAReadbackPassed          bool                            `json:"ca_readback_passed"`
	CAAdmissionSent           bool                            `json:"ca_admission_sent"`
	CAResampleSent            bool                            `json:"ca_resample_sent"`
	CAConfirmedSent           bool                            `json:"ca_confirmed_sent"`
	StopACKObserved           bool                            `json:"stop_acknowledgement_observed"`
	CAResampleCount           int                             `json:"ca_resample_count"`
	Handshake                 *task0CAConfirmedHandshakeTrace `json:"handshake"`
	Retirement                *task0CAConfirmedRetirement     `json:"preparation_retirement,omitempty"`
	DirectChildWaitCompleted  bool                            `json:"direct_child_wait_completed"`
	DirectChildExitCode       int                             `json:"direct_child_exit_code"`
	DirectChildWaitFailed     bool                            `json:"direct_child_wait_failed"`
}

type task0PreparationCAConfirmedObserver struct {
	output    io.Writer
	context   context.Context
	owner     *task0CAConfirmedCommandOwner
	pending   []byte
	proof     *task0CAProof
	handshake task0CAConfirmedHandshakeTrace
	record    task0PreparationCAConfirmedObservation
}

// The fixed Parent and PREP are separately bound images. The old production,
// prefix, READY, ADMITTED and Q028 entries continue through the old nil branch.
func RunObserveTask0PreparationCAConfirmed(expectedBindingSHA string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runTask0ParentCAConfirmedMode(expectedBindingSHA, nil, nil, nil, nil, &task0PreparationCAConfirmedObserver{output: os.Stdout, context: ctx})
}

func task0CAConfirmedObservationEnvironment() []string {
	return frozenEnvironment(map[string]string{"DEEPSEEK_API_KEY": task0CAConfirmedObservationMarker})
}

func task0CAConfirmedReadFrame(c *net.UnixConn, frame *task0CAFrame) ([]byte, error) {
	body, eof, err := task0CAConfirmedPacket(c)
	if err != nil || eof || decodeFrozenJSON(body, 8192, frame) != nil {
		return body, ErrRuntimeLaunch
	}
	return nil, nil
}

func task0CAConfirmedSetupWaitValid(w task0CAConfirmedSetupWait) bool {
	if w.Created != 0 || w.Joined != 0 || w.NoSpawn == w.Started || w.Admitted && !digest(w.AdmissionNonce) ||
		w.AdmissionNonce != "" && !digest(w.AdmissionNonce) || w.ShutdownAttempted && (!w.Admitted || !digest(w.ShutdownNonce) || w.ShutdownNonce == w.AdmissionNonce) ||
		!w.ShutdownAttempted && w.ShutdownNonce != "" || w.ShutdownAcknowledged && !w.ShutdownAttempted {
		return false
	}
	if w.NoSpawn {
		return !w.Admitted && !w.WaitCompleted && !w.WaitFailed && w.ExitCode == -1 && !w.ShutdownAttempted && w.AdmissionNonce == ""
	}
	return w.SpawnAttempted && w.WaitCompleted && w.ExitCode >= -1 && w.ExitCode <= 255 && (w.WaitFailed || w.ExitCode == 0)
}

func task0CAConfirmedRetirementValid(r task0CAConfirmedRetirement, b task0ParentBinding, setupSHA, setupBindingSHA, generation, nonce string, original, source, root task0SetupFDIdentity, proof *task0CAProof) bool {
	if r.Schema != task0CAConfirmedRetirementSchema || r.BindingSHA != b.PreparationSHA || r.ExecutableSHA != b.ExecutableSHA ||
		r.Generation != generation || r.Nonce != nonce || !digest(nonce) || r.CA != b.SystemCA || r.Original != original || r.Source != source || r.Root != root ||
		r.SetupSHA != setupSHA || r.SetupBindingSHA != setupBindingSHA || !task0CAConfirmedSetupWaitValid(r.Setup) ||
		r.CAReadySent && (!r.Setup.Admitted || r.Setup.NoSpawn || r.Materialized.Ino == 0) {
		return false
	}
	return (proof == nil || r.CAReadySent && r.Materialized == proof.Materialized) && task0CAConfirmedTraceValid(r)
}

// On unknown proof this fixed process keeps every holder reachable. Actual
// child Wait alone is not a substitute for the grandchild's typed Wait proof.
func task0CAConfirmedRetainUnknown() {
	for {
		time.Sleep(time.Hour)
	}
}

func (o *task0PreparationCAConfirmedObserver) retire(self *os.File, b task0ParentBinding, ca *task0ParentSystemCA, directory *task0CAParentDirectory) error {
	if o == nil || o.owner == nil {
		return nil // No command owner was installed and no Start was attempted.
	}
	if o.owner.noSpawn && o.owner.joinedOrNoSpawn() {
		o.record.PreparationNoSpawn = true
		o.owner.awaitRetirement()
		return nil
	}
	p := o.owner.process
	if p == nil || p.control == nil || !o.owner.startReturned || p.command == nil || p.command.Process == nil {
		task0CAConfirmedRetainUnknown()
	}
	closeErr := p.control.CloseWrite()
	// The soft handshake deadline cannot end ownership. Keep the receive half
	// open until the fixed PREP's actual SETUP retirement receipt arrives.
	if p.control.SetReadDeadline(time.Time{}) != nil {
		task0CAConfirmedRetainUnknown()
	}
	body := o.pending
	if len(body) == 0 {
		var eof bool
		var err error
		body, eof, err = task0CAConfirmedPacket(p.control)
		if err != nil || eof {
			o.owner.awaitRetirement()
			task0CAConfirmedRetainUnknown()
		}
	}
	var retirement task0CAConfirmedRetirement
	a, err := decodeTask0Preparation(b.Preparation, b.PreparationSHA)
	original, oe := task0CAIdentity(ca.original)
	source, se := task0CAIdentity(ca.snapshot)
	root, re := task0CAIdentity(directory.rootFD)
	valid := err == nil && oe == nil && se == nil && re == nil && decodeFrozenJSON(body, 8192, &retirement) == nil &&
		task0CAConfirmedRetirementValid(retirement, b, a.binding.Setup.SHA256, a.setup.identity, ca.generation, o.record.AdmissionNonce, original, source, root, o.proof) && task0CAConfirmedTraceMatchesParent(retirement.Handshake, o.handshake, o.record.StopACKObserved)
	if a != nil {
		task0ClearPreparation(a)
	}
	if !valid {
		o.owner.awaitRetirement()
		task0CAConfirmedRetainUnknown()
	}
	o.record.Retirement = &retirement
	o.owner.awaitRetirement()
	if !o.owner.joinedOrNoSpawn() || p.command.ProcessState == nil {
		task0CAConfirmedRetainUnknown()
	}
	o.record.DirectChildWaitCompleted = true
	o.record.DirectChildExitCode = p.command.ProcessState.ExitCode()
	o.record.DirectChildWaitFailed = p.waitErr != nil
	if closeErr != nil || o.record.DirectChildWaitFailed || o.record.DirectChildExitCode != 0 || !retirement.Setup.ShutdownAcknowledged {
		return ErrRuntimeLaunch
	}
	return nil
}

func (o *task0PreparationCAConfirmedObserver) publish(stage string, runErr error) error {
	if o == nil || o.output == nil {
		return ErrRuntimeLaunch
	}
	o.record.Schema = "aipt.private.b007-preparation-ca-confirmed-observation/v1"
	o.record.Stage, o.record.Outcome = stage, "REJECTED"
	o.record.Handshake = &o.handshake
	if !o.record.DirectChildWaitCompleted {
		o.record.DirectChildExitCode = -1
	}
	if runErr == nil && o.record.CAReadyObserved && o.record.CAReadbackPassed && o.record.Retirement != nil &&
		o.record.Retirement.Setup.ShutdownAcknowledged && o.record.Retirement.Setup.WaitCompleted && !o.record.Retirement.Setup.WaitFailed &&
		o.record.Retirement.Setup.ExitCode == 0 && o.record.DirectChildWaitCompleted && !o.record.DirectChildWaitFailed &&
		o.record.DirectChildExitCode == 0 && o.record.CAAdmissionSent && o.record.CAConfirmedSent && o.record.StopACKObserved && o.record.Retirement.Handshake.StoppedBeforeBusiness && task0SameJSON(o.record.Retirement.Handshake, o.handshake) {
		o.record.Outcome = "CA_CONFIRMED_STOPPED_BEFORE_BUSINESS_AND_SETUP_THEN_PREPARATION_WAITED"
	}
	if json.NewEncoder(o.output).Encode(o.record) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func observeTask0PreparationCAConfirmed(self, binding *os.File, b task0ParentBinding, ca *task0ParentSystemCA, directory *task0CAParentDirectory, process **freshPreparationProcess, o *task0PreparationCAConfirmedObserver, stage *string) error {
	if process == nil || *process != nil || o == nil || o.owner != nil || o.context == nil || o.context.Err() != nil || stage == nil ||
		os.Getuid() != 1000 || os.Getgid() != 1000 || self == nil || binding == nil || ca == nil || directory == nil ||
		!ca.stableOriginal() || !directory.stableEmpty() || !staticPreparationFile(self) || inputSHAFileMetadata(self) != b.ExecutableSHA || inputSHAFileMetadata(binding) != b.PreparationSHA {
		return ErrRuntimeLaunch
	}
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer child.Close()
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = task0CAConfirmedObservationEnvironment()
	cmd.ExtraFiles = []*os.File{self, binding, child, ca.snapshot, ca.original, directory.rootFD}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	o.owner = task0CAConfirmedCommand(cmd, control, []*os.File{self, binding, ca.snapshot, ca.original, directory.rootFD})
	*process = o.owner.process
	o.record.PreparationSpawnAttempted = true
	err = o.owner.start()
	cmd.Env = nil
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	_ = child.Close()
	o.record.PreparationStarted = cmd.Process != nil
	if err != nil {
		return ErrRuntimeLaunch
	}
	stop := context.AfterFunc(o.context, func() { _ = control.SetReadDeadline(time.Now()) })
	defer stop()
	verify := func() error {
		if o.context.Err() != nil || verifiedPreparationChild(cmd, self) != nil || !ca.stableOriginal() || !directory.stableEmpty() ||
			inputSHAFileMetadata(self) != b.ExecutableSHA || inputSHAFileMetadata(binding) != b.PreparationSHA {
			return ErrRuntimeLaunch
		}
		return nil
	}
	if control.SetDeadline(time.Now().Add(60*time.Second)) != nil || verify() != nil {
		return ErrRuntimeLaunch
	}
	read := func(frame *task0CAFrame) error {
		body, err := task0CAConfirmedReadFrame(control, frame)
		if len(body) > 0 {
			o.pending = body
		}
		return err
	}
	*stage = "READY_RECEIVE"
	var frame task0CAFrame
	if read(&frame) != nil || !task0SameJSON(frame, task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: b.PreparationSHA}) || verify() != nil {
		return ErrRuntimeLaunch
	}
	o.record.ReadyObserved = true
	nonce, err := task0SetupNonce()
	if err != nil {
		return ErrRuntimeLaunch
	}
	o.record.AdmissionNonce = nonce
	admission := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "ADMIT", BindingSHA: b.PreparationSHA, Generation: ca.generation, Nonce: nonce}
	*stage = "ADMIT_SEND"
	if task0CAPacket(control, &admission, true) != nil {
		return ErrRuntimeLaunch
	}
	o.record.AdmissionSent = true
	admission.Operation = "ADMITTED"
	*stage = "ADMITTED_RECEIVE"
	if read(&frame) != nil || !task0SameJSON(frame, admission) || verify() != nil {
		return ErrRuntimeLaunch
	}
	o.record.AdmittedObserved = true
	admission.Operation = "CONFIRMED"
	*stage = "CONFIRMED_SEND"
	if task0CAPacket(control, &admission, true) != nil {
		return ErrRuntimeLaunch
	}
	o.record.ConfirmedSent = true
	return o.completeCAHandshake(control, b, ca.generation, nonce, read, func(proof *task0CAProof) (int, error) {
		return task0ParentCAReadback(o.owner.process, self, b, ca, directory, proof)
	}, verify, stage)

}

type task0CAConfirmedSetupOwner struct {
	owner      *task0CAConfirmedCommandOwner
	grant      *acceptedTask0Setup
	generation string
	wait       task0CAConfirmedSetupWait
}

func launchTask0CAConfirmedSetup(self, binding *os.File, grant *acceptedTask0Setup, generation string, forbidden []task0SetupFDIdentity, owned **task0CAConfirmedSetupOwner) error {
	if owned == nil || *owned != nil || grant == nil || !digest(generation) || self == nil || binding == nil || len(forbidden) != 6 ||
		os.Getpid() != 1 || os.Geteuid() != 0 || !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") ||
		!staticPreparationFile(self) || inputSHAFileMetadata(binding) != grant.identity {
		return ErrRuntimeLaunch
	}
	for _, f := range []*os.File{self, binding} {
		seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
		if errno != 0 || seals&15 != 15 {
			return ErrRuntimeLaunch
		}
	}
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer child.Close()
	held, err := task0CopyHeldRoleInputs([]*os.File{self, binding})
	if err != nil || len(held) != 2 {
		_ = control.Close()
		task0CloseInputFiles(held)
		return ErrRuntimeLaunch
	}
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = frozenEnvironment(nil)
	cmd.ExtraFiles = []*os.File{held[0], held[1], child}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	s := &task0CAConfirmedSetupOwner{owner: task0CAConfirmedCommand(cmd, control, held), grant: grant, generation: generation,
		wait: task0CAConfirmedSetupWait{ExitCode: -1, SpawnAttempted: true}}
	*owned = s
	err = s.owner.start()
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	_ = child.Close()
	s.wait.Started, s.wait.NoSpawn = cmd.Process != nil, s.owner.noSpawn
	if err != nil || control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return ErrRuntimeLaunch
	}
	read := func() (task0SetupFrame, error) {
		frame, rights, err := task0SetupRead(control)
		for _, f := range rights {
			_ = f.Close()
		}
		if len(rights) != 0 {
			err = ErrRuntimeLaunch
		}
		return frame, err
	}
	hello, err := read()
	if err != nil || !task0SameJSON(hello, task0SetupFrame{Schema: task0SetupControlSchema, Operation: "READY", BindingSHA: grant.identity}) || verifiedPreparationChild(cmd, self) != nil {
		return ErrRuntimeLaunch
	}
	if _, err := task0PrivilegeThreads("/proc/"+strconv.Itoa(cmd.Process.Pid), task0SetupCapabilityMask, 0, 0); err != nil {
		return ErrRuntimeLaunch
	}
	nonce, err := task0SetupNonce()
	if err != nil {
		return ErrRuntimeLaunch
	}
	s.wait.AdmissionNonce = nonce
	admission := task0SetupFrame{Schema: task0SetupControlSchema, Operation: "ADMIT", BindingSHA: grant.identity, Generation: generation, Nonce: nonce, Forbidden: slices.Clone(forbidden)}
	if task0SetupWrite(control, admission, nil) != nil {
		return ErrRuntimeLaunch
	}
	ack, err := read()
	admission.Operation = "ADMITTED"
	if err != nil || !task0SameJSON(ack, admission) || verifiedPreparationChild(cmd, self) != nil {
		return ErrRuntimeLaunch
	}
	if _, err := task0PrivilegeThreads("/proc/"+strconv.Itoa(cmd.Process.Pid), task0SetupCapabilityMask, 0, 0); err != nil || control.SetDeadline(time.Time{}) != nil {
		return ErrRuntimeLaunch
	}
	s.wait.Admitted = true
	return nil
}

// No CREATE/JOIN request is reachable. SHUTDOWN acknowledgement is separate
// from the actual exec.Cmd.Wait below; neither can impersonate the other.
func (s *task0CAConfirmedSetupOwner) finish() error {
	if s == nil || s.owner == nil {
		return ErrRuntimeLaunch
	}
	var result error
	if s.wait.Admitted {
		nonce, err := task0SetupNonce()
		if err == nil && nonce != s.wait.AdmissionNonce {
			s.wait.ShutdownAttempted, s.wait.ShutdownNonce = true, nonce
			c := s.owner.process.control
			request := task0SetupFrame{Schema: task0SetupControlSchema, Operation: "SHUTDOWN", BindingSHA: s.grant.identity, Generation: s.generation, Nonce: nonce}
			if c.SetDeadline(time.Now().Add(10*time.Second)) == nil && task0SetupWrite(c, request, nil) == nil {
				reply, rights, readErr := task0SetupRead(c)
				for _, f := range rights {
					_ = f.Close()
				}
				request.Operation, request.Waited = "SHUTDOWN_JOINED", true
				s.wait.ShutdownAcknowledged = readErr == nil && len(rights) == 0 && task0SameJSON(reply, request)
			}
		}
		if !s.wait.ShutdownAcknowledged {
			result = ErrRuntimeLaunch
		}
	}
	s.owner.awaitRetirement() // Close only this owned control; never Kill.
	if s.owner.noSpawn {
		s.wait.NoSpawn = true
	} else {
		p := s.owner.process
		if p.command.ProcessState == nil || !task0DirectJoinCompleted(p) {
			task0CAConfirmedRetainUnknown()
		}
		s.wait.WaitCompleted = true
		s.wait.ExitCode = p.command.ProcessState.ExitCode()
		s.wait.WaitFailed = p.waitErr != nil
		if s.wait.WaitFailed || s.wait.ExitCode != 0 {
			result = ErrRuntimeLaunch
		}
	}
	if s.owner.releaseInputs() != nil || !task0CAConfirmedSetupWaitValid(s.wait) {
		result = ErrRuntimeLaunch
	}
	return result
}

// This owner is installed by the fixed caller before Start. Neither a failed
// protocol nor a timeout releases its inputs or turns a missing Wait into one.
// This separately bound Q034 entry has no native feasibility or execution grant
// until its exact source, CI, concrete input and ownership gates are accepted.
type task0CAConfirmedCommandOwner struct {
	process        *freshPreparationProcess
	inputs         []*os.File
	startAttempted bool
	startReturned  bool
	noSpawn        bool
}

func task0CAConfirmedCommand(cmd *exec.Cmd, control *net.UnixConn, inputs []*os.File) *task0CAConfirmedCommandOwner {
	return &task0CAConfirmedCommandOwner{
		process: &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})},
		inputs:  append([]*os.File(nil), inputs...),
	}
}

func (o *task0CAConfirmedCommandOwner) start() error {
	if o == nil || o.process == nil || o.process.command == nil || o.startAttempted {
		return ErrRuntimeLaunch
	}
	o.startAttempted = true
	err := o.process.command.Start()
	o.startReturned = true
	if o.process.command.Process == nil {
		o.noSpawn = err != nil
		return ErrRuntimeLaunch
	}
	// ProcessState is the actual Wait proof. A returned Wait error without it
	// leaves the exit channel open and keeps every outer holder waiting.
	go func() {
		o.process.waitErr = o.process.command.Wait()
		if o.process.command.ProcessState != nil {
			close(o.process.exit)
		}
	}()
	if err != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func (o *task0CAConfirmedCommandOwner) joinedOrNoSpawn() bool {
	return o != nil && o.startAttempted && o.startReturned &&
		(o.noSpawn || task0DirectJoinCompleted(o.process))
}

// Close only the owned control peer to request cooperative retirement. This
// mode never kills PREP or substitutes process disappearance for SETUP Wait.
func (o *task0CAConfirmedCommandOwner) awaitRetirement() {
	if o == nil || o.process == nil {
		return
	}
	if o.process.control != nil {
		_ = o.process.control.Close()
	}
	for !o.joinedOrNoSpawn() {
		if o.startReturned && o.process.command != nil && o.process.command.Process != nil {
			<-o.process.exit
		} else {
			time.Sleep(time.Second)
		}
	}
}

func (o *task0CAConfirmedCommandOwner) releaseInputs() error {
	if !o.joinedOrNoSpawn() {
		return ErrRuntimeLaunch
	}
	var result error
	for _, f := range o.inputs {
		if f != nil && f.Close() != nil {
			result = ErrRuntimeLaunch
		}
	}
	o.inputs = nil
	return result
}

// A zero-length seqpacket is not sufficient EOF evidence. Require the owned
// peer's kernel write-half closure as well. No timeout or error substitutes for
// this check. The read half remains open for the child's later Wait receipt.
func task0CAConfirmedWriteHalfClosed(c *net.UnixConn) bool {
	if c == nil {
		return false
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return false
	}
	closed := false
	err = raw.Control(func(fd uintptr) {
		p := struct {
			FD              int32
			Events, Revents int16
		}{FD: int32(fd), Events: 0x2000} // Linux POLLRDHUP.
		n, _, errno := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(&p)), 1, 0)
		closed = errno == 0 && n == 1 && p.Revents&0x2000 != 0
	})
	return err == nil && closed
}

// Both fixed observation records reject ancillary messages. Close every
// received right before rejecting it; an empty packet cannot hide an FD.
func task0CAConfirmedPacket(c *net.UnixConn) ([]byte, bool, error) {
	if c == nil {
		return nil, false, ErrRuntimeLaunch
	}
	var body [8193]byte
	ancillary := make([]byte, syscall.CmsgSpace(64*4))
	n, size, flags, _, err := c.ReadMsgUnix(body[:], ancillary)
	if size > 0 {
		messages, _ := syscall.ParseSocketControlMessage(ancillary[:size])
		for _, message := range messages {
			fds, _ := syscall.ParseUnixRights(&message)
			for _, fd := range fds {
				_ = syscall.Close(fd)
			}
		}
	}
	if size != 0 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return nil, false, ErrRuntimeLaunch
	}
	if n == 0 && (err == nil || errors.Is(err, io.EOF)) && task0CAConfirmedWriteHalfClosed(c) {
		return nil, true, nil
	}
	if err != nil || n < 1 || n > 8192 {
		return nil, false, ErrRuntimeLaunch
	}
	return append([]byte(nil), body[:n]...), false, nil
}

// Fixed receiver keeps the entry-owned runtime reachable on every failure.
func receiveTask0CAConfirmedPreparation(r *task0AcceptedPreparationRuntime, ctx context.Context, bindingSHA string) ([]byte, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || !digest(bindingSHA) || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return nil, ErrRuntimeLaunch
	}
	fail := func() ([]byte, error) {
		return nil, ErrRuntimeLaunch
	}
	slots := []**os.File{&r.self, &r.binding, &r.source, &r.original, &r.mountpoint}
	for i, fd := range []int{3, 4, 6, 7, 8} {
		syscall.CloseOnExec(fd)
		f, err := frozenBorrowFile(fd)
		if err != nil {
			return fail()
		}
		*slots[i] = f
		syscall.Close(fd)
	}
	ss, err := task0CAFileState(r.self)
	actual, ae := os.Stat("/proc/self/exe")
	held, he := r.self.Stat()
	seals, _, se := syscall.Syscall(syscall.SYS_FCNTL, r.self.Fd(), 0x40a, 0)
	if err != nil || ae != nil || he != nil || !os.SameFile(actual, held) || ss.Uid != 0 || ss.Nlink != 0 || ss.Mode&07777 != 0500 ||
		!staticPreparationFile(r.self) || se != 0 || seals&15 != 15 {
		return fail()
	}
	bs, err := task0CAFileState(r.binding)
	seals, _, se = syscall.Syscall(syscall.SYS_FCNTL, r.binding.Fd(), 0x40a, 0)
	if err != nil || bs.Uid != 0 || bs.Nlink != 0 || bs.Mode&syscall.S_IFMT != syscall.S_IFREG || bs.Mode&07777 != 0400 || bs.Size < 1 || bs.Size > task0PreparationBindingMaxBytes || se != 0 || seals&15 != 15 {
		return fail()
	}
	raw, err := io.ReadAll(io.NewSectionReader(r.binding, 0, bs.Size))
	if err != nil || inputSHA(raw) != bindingSHA {
		clear(raw)
		return fail()
	}
	peer, pe := syscall.GetsockoptUcred(5, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	kind, ke := syscall.GetsockoptInt(5, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if pe != nil || ke != nil || kind != syscall.SOCK_SEQPACKET || peer.Pid != 0 || peer.Uid != 0 || peer.Gid != 0 {
		clear(raw)
		return fail()
	}
	syscall.CloseOnExec(5)
	socket := os.NewFile(5, "own outside Parent control")
	c, err := net.FileConn(socket)
	socket.Close()
	if err != nil {
		clear(raw)
		return fail()
	}
	var ok bool
	r.control, ok = c.(*net.UnixConn)
	if !ok {
		c.Close()
		clear(raw)
		return fail()
	}
	if r.control.SetDeadline(time.Now().Add(60*time.Second)) != nil {
		clear(raw)
		return fail()
	}
	frame := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: bindingSHA}
	if task0CAPacket(r.control, &frame, true) != nil {
		clear(raw)
		return fail()
	}
	if _, packetErr := task0CAConfirmedReadFrame(r.control, &frame); packetErr != nil || !task0CAFrameValid(frame, "ADMIT", bindingSHA, frame.Generation, frame.Nonce) || frame.Proof != nil || frame.Result != nil {
		clear(raw)
		return fail()
	}
	r.proof.Generation, r.admissionNonce = frame.Generation, frame.Nonce
	frame.Operation = "ADMITTED"
	if task0CAPacket(r.control, &frame, true) != nil {
		clear(raw)
		return fail()
	}
	frame.Operation = "CONFIRMED"
	var confirmed task0CAFrame
	if _, packetErr := task0CAConfirmedReadFrame(r.control, &confirmed); packetErr != nil || !task0SameJSON(frame, confirmed) || ctx.Err() != nil {
		clear(raw)
		return fail()
	}
	if syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, "") != nil || syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "") != nil {
		clear(raw)
		return fail()
	}
	return raw, nil
}

// This dedicated PREP never opens source roots, credentials, connections,
// evidence, budgets or model data. The decoded grant supplies only fixed code
// identities. Mount and SETUP admission occur before irreversible Cap0.
func RunObserveTask0CAConfirmedPreparation(expectedBindingSHA string) (runErr error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if !digest(expectedBindingSHA) || len(os.Args) != 1 || os.Getenv("DEEPSEEK_API_KEY") != task0CAConfirmedObservationMarker {
		return ErrRuntimeLaunch
	}
	r := &task0AcceptedPreparationRuntime{}
	var a *acceptedTask0Preparation
	var setup *task0CAConfirmedSetupOwner
	var setupImage, setupBinding *os.File
	caReadySent := false
	handshake := task0CAConfirmedHandshakeTrace{}
	defer func() {
		wait := task0CAConfirmedSetupWait{NoSpawn: true, ExitCode: -1}
		if setup != nil {
			if setup.finish() != nil {
				runErr = ErrRuntimeLaunch
			}
			wait = setup.wait
		}
		// The receipt is emitted only after the actual SETUP Wait/NoSpawn.
		// Unknown ownership blocks in finish and cannot reach any close below.
		if a != nil && r.control != nil && digest(r.admissionNonce) && digest(r.proof.Generation) {
			original, oe := task0CAIdentity(r.original)
			source, se := task0CAIdentity(r.source)
			root, re := task0CAIdentity(r.mountpoint)
			receipt := task0CAConfirmedRetirement{Schema: task0CAConfirmedRetirementSchema, BindingSHA: a.identity,
				ExecutableSHA: inputSHAFileMetadata(r.self), Generation: r.proof.Generation, Nonce: r.admissionNonce,
				SetupSHA: a.binding.Setup.SHA256, SetupBindingSHA: a.setup.identity, CA: a.binding.SystemCA,
				Original: original, Source: source, Root: root, CAReadySent: caReadySent, Setup: wait, Handshake: handshake}
			if r.ca != nil {
				receipt.Materialized, _ = task0CAIdentity(r.ca.materialized)
			}
			body, err := json.Marshal(receipt)
			if oe != nil || se != nil || re != nil || !task0CAConfirmedSetupWaitValid(wait) || err != nil || len(body) > 8192 ||
				r.control.SetWriteDeadline(time.Now().Add(60*time.Second)) != nil {
				runErr = ErrRuntimeLaunch
			} else if n, err := r.control.Write(body); err != nil || n != len(body) {
				runErr = ErrRuntimeLaunch
			}
		}
		if r.control != nil {
			_ = r.control.Close()
		}
		task0CloseInputFiles([]*os.File{setupImage, setupBinding})
		if r.closeHeldInputs() != nil {
			runErr = ErrRuntimeLaunch
		}
		if a != nil {
			task0ClearPreparation(a)
		}
	}()
	raw, err := receiveTask0CAConfirmedPreparation(r, ctx, expectedBindingSHA)
	defer clear(raw)
	if err != nil {
		return ErrRuntimeLaunch
	}
	a, err = decodeTask0Preparation(raw, expectedBindingSHA)
	if err != nil || ctx.Err() != nil {
		return ErrRuntimeLaunch
	}
	r.ca, err = materializeTask0SystemCA(r.source, r.original, r.mountpoint)
	if err != nil {
		return ErrRuntimeLaunch
	}
	setupImage, err = task0HoldPreparationHelper(a.binding.Setup)
	if err != nil {
		return ErrRuntimeLaunch
	}
	setupBinding, err = task0SealedBytes(a.binding.SetupBinding)
	if err != nil {
		return ErrRuntimeLaunch
	}
	controlFD, err := r.control.SyscallConn()
	if err != nil {
		return ErrRuntimeLaunch
	}
	var controlIdentity task0SetupFDIdentity
	if controlFD.Control(func(fd uintptr) {
		var state syscall.Stat_t
		if syscall.Fstat(int(fd), &state) == nil {
			controlIdentity = task0SetupFDIdentity{state.Dev, state.Ino}
		}
	}) != nil || controlIdentity.Ino == 0 {
		return ErrRuntimeLaunch
	}
	forbidden := make([]task0SetupFDIdentity, 0, 6)
	for _, f := range []*os.File{r.self, r.binding, r.source, r.original, r.ca.materialized} {
		identity, err := task0CAIdentity(f)
		if err != nil {
			return ErrRuntimeLaunch
		}
		forbidden = append(forbidden, identity)
	}
	forbidden = append(forbidden, controlIdentity)
	if launchTask0CAConfirmedSetup(setupImage, setupBinding, a.setup, r.proof.Generation, forbidden, &setup) != nil || ctx.Err() != nil {
		return ErrRuntimeLaunch
	}
	if task0ConvergePrivileges(0) != nil || !r.ca.valid("/proc/self") {
		return ErrRuntimeLaunch
	}
	threads, err := task0PrivilegeThreads("/proc/self", 0, 0, 0)
	if err != nil {
		return ErrRuntimeLaunch
	}
	r.proof.CA, r.proof.BindingSHA = a.binding.SystemCA, a.identity
	r.proof.ExecutableSHA = inputSHAFileMetadata(r.self)
	r.proof.SetupSHA, r.proof.SetupBindingSHA = a.binding.Setup.SHA256, a.setup.identity
	r.proof.SetupAdmitted = true
	r.proof.Original, _ = task0CAIdentity(r.original)
	r.proof.Source, _ = task0CAIdentity(r.source)
	r.proof.Materialized, _ = task0CAIdentity(r.ca.materialized)
	r.proof.Bytes, r.proof.SHA256, r.proof.Threads = task0SystemCABytes, task0SystemCASHA, len(threads)
	guard := func() error {
		if ctx.Err() != nil || setup == nil || !setup.wait.Admitted || r.ca == nil || !r.ca.valid("/proc/self") || inputSHAFileMetadata(r.binding) != a.identity {
			return ErrRuntimeLaunch
		}
		_, err := task0PrivilegeThreads("/proc/self", 0, 0, 0)
		return err
	}
	if completeTask0CAConfirmedPREPHandshake(r.control, &r.proof, r.admissionNonce, &handshake, &caReadySent, guard, func() (int, error) { t, e := task0PrivilegeThreads("/proc/self", 0, 0, 0); return len(t), e }) != nil {
		return ErrRuntimeLaunch
	}

	if r.control.SetReadDeadline(time.Time{}) != nil {
		return ErrRuntimeLaunch
	}
	stopRead := context.AfterFunc(ctx, func() { _ = r.control.SetReadDeadline(time.Now()) })
	defer stopRead()
	body, eof, err := task0CAConfirmedPacket(r.control)
	if err != nil || !eof || len(body) != 0 || ctx.Err() != nil {
		return ErrRuntimeLaunch // The confirmed entry accepts only the owned Parent write-half closure here.
	}
	return nil
}

// Q034 has a separate schema and a bounded transcript. Proofs and nonces are
// values captured at the actual protocol boundary, never process-name claims.
type task0CAConfirmedHandshakeTrace struct {
	CAReadyNonces         []string       `json:"ca_ready_nonces"`
	CAReadyProofs         []task0CAProof `json:"ca_ready_proofs"`
	CAResampleNonces      []string       `json:"ca_resample_nonces"`
	CAAdmissionNonce      string         `json:"ca_admission_nonce"`
	CAAdmitted            bool           `json:"ca_admitted"`
	CAConfirmed           bool           `json:"ca_confirmed"`
	StoppedBeforeBusiness bool           `json:"stopped_before_business"`
}

type task0CAConfirmedStopACK struct {
	Schema        string                         `json:"schema"`
	BindingSHA    string                         `json:"preparation_binding_sha256"`
	ExecutableSHA string                         `json:"preparation_executable_sha256"`
	Generation    string                         `json:"generation"`
	InitialNonce  string                         `json:"initial_admission_nonce"`
	Handshake     task0CAConfirmedHandshakeTrace `json:"handshake"`
}

func task0CAConfirmedTraceValid(r task0CAConfirmedRetirement) bool {
	t := r.Handshake
	n := len(t.CAReadyProofs)
	m := len(t.CAResampleNonces)
	if n > 4 || m > 3 || len(t.CAReadyNonces) != n || m > n || n > m+1 || r.CAReadySent != (n > 0) {
		return false
	}
	used := map[string]bool{r.Nonce: true}
	for _, nonce := range t.CAResampleNonces {
		if !digest(nonce) || used[nonce] {
			return false
		}
		used[nonce] = true
	}
	for i, p := range t.CAReadyProofs {
		expected := r.Nonce
		if i > 0 {
			expected = t.CAResampleNonces[i-1]
		}
		if t.CAReadyNonces[i] != expected || !task0CAProofIdentities(&p) || p.BindingSHA != r.BindingSHA || p.ExecutableSHA != r.ExecutableSHA || p.Generation != r.Generation || p.SetupSHA != r.SetupSHA || p.SetupBindingSHA != r.SetupBindingSHA || p.CA != r.CA || p.Original != r.Original || p.Source != r.Source || p.Materialized != r.Materialized {
			return false
		}
	}
	if t.CAAdmissionNonce != "" {
		if !digest(t.CAAdmissionNonce) || used[t.CAAdmissionNonce] || n == 0 || n != m+1 {
			return false
		}
	}
	if t.CAAdmitted && t.CAAdmissionNonce == "" || t.CAConfirmed && !t.CAAdmitted || t.StoppedBeforeBusiness && !t.CAConfirmed {
		return false
	}
	return true
}

// A rejected protocol may have one sent but unread frame or one resample in
// flight. Its retirement still proves the exact fixed child's real SETUP Wait.
// A successful stop requires the complete transcript, not a partial prefix.
func task0CAConfirmedTraceMatchesParent(child, parent task0CAConfirmedHandshakeTrace, complete bool) bool {
	if complete {
		return task0SameJSON(child, parent) && child.StoppedBeforeBusiness
	}
	if len(child.CAReadyProofs) < len(parent.CAReadyProofs) || len(child.CAReadyProofs) > len(parent.CAReadyProofs)+1 || len(child.CAResampleNonces) > len(parent.CAResampleNonces) {
		return false
	}
	for i, nonce := range child.CAResampleNonces {
		if nonce != parent.CAResampleNonces[i] {
			return false
		}
	}
	for i, p := range parent.CAReadyProofs {
		if i >= len(child.CAReadyNonces) || i >= len(parent.CAReadyNonces) || child.CAReadyNonces[i] != parent.CAReadyNonces[i] || child.CAReadyProofs[i] != p {
			return false
		}
	}
	if child.CAAdmissionNonce != "" && child.CAAdmissionNonce != parent.CAAdmissionNonce {
		return false
	}
	if child.CAConfirmed && !parent.CAConfirmed {
		return false
	}
	return true
}

func (o *task0PreparationCAConfirmedObserver) completeCAHandshake(control *net.UnixConn, b task0ParentBinding, generation, initial string, read func(*task0CAFrame) error, readback func(*task0CAProof) (int, error), guard func() error, stage *string) error {
	if o == nil || control == nil || read == nil || readback == nil || guard == nil || stage == nil || !digest(initial) || !digest(generation) || len(o.handshake.CAReadyProofs) != 0 {
		return ErrRuntimeLaunch
	}
	used := map[string]bool{initial: true}
	expected := initial
	for attempt := 0; attempt < 4; attempt++ {
		*stage = "CA_READY_RECEIVE"
		var frame task0CAFrame
		if read(&frame) != nil || !task0CAFrameValid(frame, "CA_READY", b.PreparationSHA, generation, expected) || frame.Result != nil || frame.Proof == nil || guard() != nil {
			return ErrRuntimeLaunch
		}
		proof := *frame.Proof
		o.proof = &proof
		o.record.CAReadyObserved = true
		o.handshake.CAReadyNonces = append(o.handshake.CAReadyNonces, expected)
		o.handshake.CAReadyProofs = append(o.handshake.CAReadyProofs, proof)
		*stage = "CA_READY_OUTSIDE_READBACK"
		count, err := readback(&proof)
		if err != nil || guard() != nil {
			return ErrRuntimeLaunch
		}
		next, err := task0SetupNonce()
		if err != nil || used[next] {
			return ErrRuntimeLaunch
		}
		used[next] = true
		response := frame
		response.Nonce = next
		if count != proof.Threads {
			if attempt == 3 {
				return ErrRuntimeLaunch
			}
			response.Operation = "CA_RESAMPLE"
			*stage = "CA_RESAMPLE_SEND"
			if task0CAPacket(control, &response, true) != nil {
				return ErrRuntimeLaunch
			}
			o.record.CAResampleSent = true
			o.record.CAResampleCount++
			o.handshake.CAResampleNonces = append(o.handshake.CAResampleNonces, next)
			expected = next
			continue
		}
		o.record.CAReadbackPassed = true
		response.Operation = "CA_ADMIT"
		o.handshake.CAAdmissionNonce = next
		*stage = "CA_ADMIT_SEND"
		if task0CAPacket(control, &response, true) != nil {
			return ErrRuntimeLaunch
		}
		o.record.CAAdmissionSent = true
		response.Operation = "CA_ADMITTED"
		*stage = "CA_ADMITTED_RECEIVE"
		if read(&frame) != nil || !task0SameJSON(frame, response) || guard() != nil {
			return ErrRuntimeLaunch
		}
		o.handshake.CAAdmitted = true
		if _, err := readback(&proof); err != nil || guard() != nil {
			return ErrRuntimeLaunch
		}
		response.Operation = "CA_CONFIRMED"
		*stage = "CA_CONFIRMED_SEND"
		if task0CAPacket(control, &response, true) != nil {
			return ErrRuntimeLaunch
		}
		o.record.CAConfirmedSent = true
		o.handshake.CAConfirmed = true
		*stage = "CA_CONFIRMED_STOP_ACK_RECEIVE"
		body, eof, err := task0CAConfirmedPacket(control)
		if err != nil || eof {
			return ErrRuntimeLaunch
		}
		var ack task0CAConfirmedStopACK
		if decodeFrozenJSON(body, 8192, &ack) != nil {
			o.pending = body
			return ErrRuntimeLaunch
		}
		wantTrace := o.handshake
		wantTrace.StoppedBeforeBusiness = true
		want := task0CAConfirmedStopACK{Schema: "aipt.private.b007-ca-confirmed-stopped-before-business/v1", BindingSHA: b.PreparationSHA, ExecutableSHA: b.ExecutableSHA, Generation: generation, InitialNonce: initial, Handshake: wantTrace}
		if !task0SameJSON(ack, want) || guard() != nil {
			return ErrRuntimeLaunch
		}
		o.handshake = wantTrace
		o.record.StopACKObserved = true
		*stage = "CA_CONFIRMED_BEFORE_BUSINESS"
		return nil
	}
	return ErrRuntimeLaunch
}

func completeTask0CAConfirmedPREPHandshake(control *net.UnixConn, proof *task0CAProof, initial string, trace *task0CAConfirmedHandshakeTrace, readySent *bool, guard func() error, sampleThreads func() (int, error)) error {
	if control == nil || proof == nil || trace == nil || readySent == nil || guard == nil || sampleThreads == nil || !digest(initial) || len(trace.CAReadyProofs) != 0 {
		return ErrRuntimeLaunch
	}
	used := map[string]bool{initial: true}
	nonce := initial
	for attempt := 0; attempt < 4; attempt++ {
		if guard() != nil {
			return ErrRuntimeLaunch
		}
		threads, err := sampleThreads()
		if err != nil || threads < 1 || threads > 512 {
			return ErrRuntimeLaunch
		}
		proof.Threads = threads
		ready := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "CA_READY", BindingSHA: proof.BindingSHA, Generation: proof.Generation, Nonce: nonce, Proof: proof}
		if task0CAPacket(control, &ready, true) != nil {
			return ErrRuntimeLaunch
		}
		*readySent = true
		trace.CAReadyNonces = append(trace.CAReadyNonces, nonce)
		trace.CAReadyProofs = append(trace.CAReadyProofs, *proof)
		var response task0CAFrame
		if _, err := task0CAConfirmedReadFrame(control, &response); err != nil || !task0CAFrameValid(response, response.Operation, proof.BindingSHA, proof.Generation, response.Nonce) || (response.Operation != "CA_ADMIT" && response.Operation != "CA_RESAMPLE") || used[response.Nonce] || response.Result != nil || response.Proof == nil || *response.Proof != *proof || guard() != nil {
			return ErrRuntimeLaunch
		}
		used[response.Nonce] = true
		if response.Operation == "CA_RESAMPLE" {
			if attempt == 3 {
				return ErrRuntimeLaunch
			}
			trace.CAResampleNonces = append(trace.CAResampleNonces, response.Nonce)
			nonce = response.Nonce
			continue
		}
		trace.CAAdmissionNonce = response.Nonce
		response.Operation = "CA_ADMITTED"
		if task0CAPacket(control, &response, true) != nil {
			return ErrRuntimeLaunch
		}
		trace.CAAdmitted = true
		response.Operation = "CA_CONFIRMED"
		var confirmed task0CAFrame
		if _, err := task0CAConfirmedReadFrame(control, &confirmed); err != nil || !task0SameJSON(confirmed, response) || guard() != nil {
			return ErrRuntimeLaunch
		}
		trace.CAConfirmed = true
		stopTrace := *trace
		stopTrace.StoppedBeforeBusiness = true
		ack := task0CAConfirmedStopACK{Schema: "aipt.private.b007-ca-confirmed-stopped-before-business/v1", BindingSHA: proof.BindingSHA, ExecutableSHA: proof.ExecutableSHA, Generation: proof.Generation, InitialNonce: initial, Handshake: stopTrace}
		raw, err := json.Marshal(ack)
		if err != nil || len(raw) > 8192 {
			return ErrRuntimeLaunch
		}
		n, err := control.Write(raw)
		if err != nil || n != len(raw) {
			return ErrRuntimeLaunch
		}
		*trace = stopTrace
		return nil
	}
	return ErrRuntimeLaunch
}
