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

const task0ReadyObservationMarker = "AIPT_Q026_READY_OBSERVATION_ONLY_NOT_A_PROVIDER_CREDENTIAL"

type task0PreparationReadyObservation struct {
	Schema                    string `json:"schema"`
	Stage                     string `json:"stage"`
	Outcome                   string `json:"outcome"`
	PreparationSpawnAttempted bool   `json:"preparation_spawn_attempted"`
	PreparationStarted        bool   `json:"preparation_started"`
	ReadyObserved             bool   `json:"ready_observed"`
	DirectChildWaitCompleted  bool   `json:"direct_child_wait_completed"`
	DirectChildExitCode       int    `json:"direct_child_exit_code"`
	DirectChildWaitFailed     bool   `json:"direct_child_wait_failed"`
}

type task0PreparationReadyObserver struct {
	output io.Writer
	record task0PreparationReadyObservation
}

// The separately compiled, max-once observation entry never admits PREP.
// Its fixed outer driver owns the permanent claim and all inputs through Wait.
func RunObserveTask0PreparationReady(expectedBindingSHA string) error {
	return runTask0ParentMode(expectedBindingSHA, nil, &task0PreparationReadyObserver{output: os.Stdout})
}

func task0ReadyObservationEnvironment() []string {
	return frozenEnvironment(map[string]string{"DEEPSEEK_API_KEY": task0ReadyObservationMarker})
}

func (o *task0PreparationReadyObserver) observeDirectJoin(p *freshPreparationProcess) {
	o.record.DirectChildExitCode = -1
	if p == nil || p.command == nil || !task0DirectJoinCompleted(p) || p.command.ProcessState == nil {
		return
	}
	o.record.DirectChildWaitCompleted = true
	o.record.DirectChildExitCode = p.command.ProcessState.ExitCode()
	o.record.DirectChildWaitFailed = p.waitErr != nil
}

func (o *task0PreparationReadyObserver) publish(stage string, runErr error) error {
	if o == nil || o.output == nil {
		return ErrRuntimeLaunch
	}
	o.record.Schema = "aipt.private.b007-preparation-ready-observation/v1"
	o.record.Stage, o.record.Outcome = stage, "REJECTED"
	if !o.record.DirectChildWaitCompleted {
		o.record.DirectChildExitCode = -1
	}
	if runErr == nil && o.record.PreparationStarted && o.record.ReadyObserved && o.record.DirectChildWaitCompleted {
		o.record.Outcome = "READY_STOPPED_BEFORE_ADMISSION"
	}
	if json.NewEncoder(o.output).Encode(o.record) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func task0PreparationReadyFrameValid(frame task0CAFrame, bindingSHA string) bool {
	return digest(bindingSHA) && task0SameJSON(frame, task0CAFrame{
		Schema: task0CAAdmissionSchema, Operation: "READY", BindingSHA: bindingSHA,
	})
}

func receiveTask0PreparationReady(control *net.UnixConn, bindingSHA string) error {
	var frame task0CAFrame
	if task0CAPacket(control, &frame, false) != nil || !task0PreparationReadyFrameValid(frame, bindingSHA) {
		return ErrRuntimeLaunch
	}
	return nil
}

// Unlike the complete launchers, this function never writes a control frame.
// Assign the strong owner before Start; every successful/uncertain Start keeps
// that exact Cmd, pidfd and actual Wait reachable by the Parent cleanup path.
func observeTask0PreparationReady(self, binding *os.File, b task0ParentBinding, ca *task0ParentSystemCA, directory *task0CAParentDirectory, owner **freshPreparationProcess, observation *task0PreparationReadyObserver) error {
	if owner == nil || *owner != nil || observation == nil || os.Getuid() != 1000 || os.Getgid() != 1000 ||
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
	// No CommandContext/automatic timeout kill: only the retained direct owner
	// may close control and invoke the existing retirement of its own pidfd.
	cmd := exec.Command("/proc/self/fd/3")
	cmd.Env = task0ReadyObservationEnvironment()
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
		if err != nil { // Start failed without a process; no child was created.
			*owner = nil
			_ = control.Close()
		}
		return ErrRuntimeLaunch
	}
	observation.record.PreparationStarted = true
	go func() {
		p.waitErr = cmd.Wait()
		// A failed Wait with no termination status is unknown ownership. Leave
		// exit open so the original retention path cannot close input holders.
		if cmd.ProcessState != nil {
			close(p.exit)
		}
	}()
	_ = child.Close()
	if err != nil || control.SetDeadline(time.Now().Add(60*time.Second)) != nil || verifiedPreparationChild(cmd, self) != nil {
		return ErrRuntimeLaunch
	}
	if receiveTask0PreparationReady(control, b.PreparationSHA) != nil || verifiedPreparationChild(cmd, self) != nil || !ca.stableOriginal() || !directory.stableEmpty() {
		return ErrRuntimeLaunch
	}
	observation.record.ReadyObserved = true
	// Parent's existing deferred retirement closes this control and joins the
	// child before closing its held CA/inputs or publishing the fixed record.
	return nil
}
