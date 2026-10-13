package pilot

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const task0AdmittedObservationMarker = "AIPT_Q027_ADMITTED_OBSERVATION_ONLY_NOT_A_PROVIDER_CREDENTIAL"

type task0PreparationAdmittedObservation struct {
	Schema                    string `json:"schema"`
	Stage                     string `json:"stage"`
	Outcome                   string `json:"outcome"`
	PreparationSpawnAttempted bool   `json:"preparation_spawn_attempted"`
	PreparationStarted        bool   `json:"preparation_started"`
	ReadyObserved             bool   `json:"ready_observed"`
	AdmissionSendAttempted    bool   `json:"admission_send_attempted"`
	AdmissionSent             bool   `json:"admission_sent"`
	AdmittedObserved          bool   `json:"admitted_observed"`
	ConfirmedSent             bool   `json:"confirmed_sent"`
	DirectChildWaitCompleted  bool   `json:"direct_child_wait_completed"`
	DirectChildExitCode       int    `json:"direct_child_exit_code"`
	DirectChildWaitFailed     bool   `json:"direct_child_wait_failed"`
}

type task0PreparationAdmittedObserver struct {
	output io.Writer
	record task0PreparationAdmittedObservation
}

// This fixed, separately compiled entry has a permanent max-once outer claim.
// It observes one ADMITTED response and never sends CONFIRMED or admits CA.
func RunObserveTask0PreparationAdmitted(expectedBindingSHA string) error {
	return runTask0ParentObservationMode(expectedBindingSHA, nil, nil, &task0PreparationAdmittedObserver{output: os.Stdout})
}

func task0AdmittedObservationEnvironment() []string {
	return frozenEnvironment(map[string]string{"DEEPSEEK_API_KEY": task0AdmittedObservationMarker})
}

func (o *task0PreparationAdmittedObserver) observeDirectJoin(p *freshPreparationProcess) {
	o.record.DirectChildExitCode = -1
	if p == nil || p.command == nil || !task0DirectJoinCompleted(p) || p.command.ProcessState == nil {
		return
	}
	o.record.DirectChildWaitCompleted = true
	o.record.DirectChildExitCode = p.command.ProcessState.ExitCode()
	o.record.DirectChildWaitFailed = p.waitErr != nil
}

func (o *task0PreparationAdmittedObserver) publish(stage string, runErr error) error {
	if o == nil || o.output == nil {
		return ErrRuntimeLaunch
	}
	o.record.Schema = "aipt.private.b007-preparation-admitted-observation/v1"
	o.record.Stage, o.record.Outcome = stage, "REJECTED"
	if !o.record.DirectChildWaitCompleted {
		o.record.DirectChildExitCode = -1
	}
	if runErr == nil && o.record.PreparationStarted && o.record.ReadyObserved && o.record.AdmissionSendAttempted &&
		o.record.AdmissionSent && o.record.AdmittedObserved && !o.record.ConfirmedSent && o.record.DirectChildWaitCompleted {
		o.record.Outcome = "ADMITTED_STOPPED_BEFORE_CONFIRMED"
	}
	if json.NewEncoder(o.output).Encode(o.record) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

// The verification callback is private and fixed by the caller below to the
// owned child and held inputs/CA/directory. It never supplies a protocol target.
func receiveTask0PreparationAdmitted(control *net.UnixConn, bindingSHA, generation string, verify func() error, observation *task0PreparationAdmittedObserver, stage *string) error {
	if control == nil || !digest(bindingSHA) || !digest(generation) || verify == nil || observation == nil || stage == nil {
		return ErrRuntimeLaunch
	}
	*stage = "READY_RECEIVE"
	if receiveTask0PreparationReady(control, bindingSHA) != nil {
		return ErrRuntimeLaunch
	}
	observation.record.ReadyObserved = true
	*stage = "ADMIT_PRECHECK"
	if verify() != nil {
		return ErrRuntimeLaunch
	}
	nonce, err := task0SetupNonce()
	if err != nil {
		return ErrRuntimeLaunch
	}
	admission := task0CAFrame{Schema: task0CAAdmissionSchema, Operation: "ADMIT", BindingSHA: bindingSHA, Generation: generation, Nonce: nonce}
	*stage = "ADMIT_SEND"
	observation.record.AdmissionSendAttempted = true
	if task0CAPacket(control, &admission, true) != nil {
		return ErrRuntimeLaunch
	}
	observation.record.AdmissionSent = true
	*stage = "ADMITTED_RECEIVE"
	admission.Operation = "ADMITTED"
	var frame task0CAFrame
	if task0CAPacket(control, &frame, false) != nil || !task0SameJSON(frame, admission) {
		return ErrRuntimeLaunch
	}
	observation.record.AdmittedObserved = true
	*stage = "ADMITTED_RECHECK"
	if verify() != nil {
		return ErrRuntimeLaunch
	}
	// Only the caller's direct retirement follows. No continuation is sent.
	*stage = "ADMITTED_BEFORE_CONFIRMED"
	return nil
}

// Own Cmd/control before Start and keep actual Wait reachable on every path.
// The existing Parent retains all holders if termination is still unknown.
func observeTask0PreparationAdmitted(self, binding *os.File, b task0ParentBinding, ca *task0ParentSystemCA, directory *task0CAParentDirectory, owner **freshPreparationProcess, observation *task0PreparationAdmittedObserver, stage *string) error {
	if owner == nil || *owner != nil || observation == nil || stage == nil || os.Getuid() != 1000 || os.Getgid() != 1000 ||
		self == nil || binding == nil || ca == nil || directory == nil || !ca.stableOriginal() || !directory.stableEmpty() ||
		!staticPreparationFile(self) || inputSHAFileMetadata(self) != b.ExecutableSHA || inputSHAFileMetadata(binding) != b.PreparationSHA {
		return ErrRuntimeLaunch
	}
	for _, f := range []*os.File{self, binding, ca.snapshot} {
		if f == nil {
			return ErrRuntimeLaunch
		}
		seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
		if errno != 0 || seals&0xf != 0xf {
			return ErrRuntimeLaunch
		}
	}
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer child.Close()
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = task0AdmittedObservationEnvironment()
	cmd.ExtraFiles = []*os.File{self, binding, child, ca.snapshot, ca.original, directory.rootFD}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	p := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
	*owner = p
	observation.record.PreparationSpawnAttempted = true
	err = cmd.Start()
	cmd.Env = nil
	if pidfd >= 0 {
		_ = syscall.Close(pidfd)
	}
	if cmd.Process == nil {
		if err != nil {
			*owner = nil
			_ = control.Close()
		}
		return ErrRuntimeLaunch
	}
	observation.record.PreparationStarted = true
	go func() {
		p.waitErr = cmd.Wait()
		if cmd.ProcessState != nil {
			close(p.exit)
		}
	}()
	_ = child.Close()
	verify := func() error {
		if verifiedPreparationChild(cmd, self) != nil || inputSHAFileMetadata(self) != b.ExecutableSHA || inputSHAFileMetadata(binding) != b.PreparationSHA ||
			!ca.stableOriginal() || !directory.stableEmpty() {
			return ErrRuntimeLaunch
		}
		return nil
	}
	if err != nil || control.SetDeadline(time.Now().Add(60*time.Second)) != nil || verify() != nil {
		return ErrRuntimeLaunch
	}
	return receiveTask0PreparationAdmitted(control, b.PreparationSHA, ca.generation, verify, observation, stage)
}
