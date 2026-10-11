package pilot

import (
	"bufio"
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

func (p *task0DelegatedProcess) check(executable os.FileInfo) error {
	if p == nil || p.owner == nil {
		return ErrRuntimeLaunch
	}
	// Go Process.Release rewrites Process.Pid. Hold the same owner lock for
	// the entire process observation; live() alone would unlock too early.
	p.owner.mu.Lock()
	defer p.owner.mu.Unlock()
	if p.owner.closed || p.owner.process == nil || p.owner.process.command == nil || p.owner.process.command.Process == nil || p.process == nil || p.pid <= 1 || p.pidfd == nil || executable == nil || p.process.Signal(syscall.Signal(0)) != nil {
		return ErrRuntimeLaunch
	}
	pid, err := task0PIDFDProcess(p.pidfd)
	handle := false
	if err != nil || pid != p.pid || p.process.Pid != p.pid || p.process.WithHandle(func(uintptr) { handle = true }) != nil || !handle {
		return ErrRuntimeLaunch
	}
	base := "/proc/" + strconv.Itoa(pid)
	actual, err := os.Stat(base + "/exe")
	parent, pe := task0ObservedParentPID(pid)
	if err != nil || pe != nil || !os.SameFile(executable, actual) || parent != p.owner.process.command.Process.Pid {
		return ErrRuntimeLaunch
	}
	for _, name := range []string{"uid_map", "gid_map"} {
		raw, err := os.ReadFile(base + "/" + name)
		if err != nil || !singleRootIDMapping(raw) || strings.Join(strings.Fields(string(raw)), " ") != "0 0 1" {
			return ErrRuntimeLaunch
		}
	}
	groups, err := os.ReadFile(base + "/setgroups")
	if err != nil || strings.TrimSpace(string(groups)) != "deny" {
		return ErrRuntimeLaunch
	}
	for _, kind := range []string{"user", "pid", "mnt", "net"} {
		actual, err := os.Stat(base + "/ns/" + kind)
		prep, pe := os.Stat("/proc/self/ns/" + kind)
		setup := p.owner.namespaces[kind]
		shared := kind == "net" && p.role.Role != "GAME" && p.role.Role != "LOCAL"
		if err != nil || pe != nil || setup == nil || os.SameFile(actual, prep) != shared || os.SameFile(actual, setup) != shared {
			return ErrRuntimeLaunch
		}
	}
	status, err := os.ReadFile(base + "/status")
	if err != nil || len(status) > 65536 {
		return ErrRuntimeLaunch
	}
	pid1, found := false, false
	for _, line := range strings.Split(string(status), "\n") {
		v := strings.Fields(line)
		if len(v) > 1 && v[0] == "NSpid:" {
			if found {
				return ErrRuntimeLaunch
			}
			found = true
			pid1 = v[len(v)-1] == "1"
		}
	}
	if !found || !pid1 {
		return ErrRuntimeLaunch
	}
	if _, err = task0PrivilegeThreads(base, 0, 0, 0); err != nil || p.process.Signal(syscall.Signal(0)) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

type task0DelegatedPipes struct {
	input, childInput, output, childOutput *os.File
}

func task0NewDelegatedPipes() (*task0DelegatedPipes, error) {
	p := &task0DelegatedPipes{}
	var err error
	p.childInput, p.input, err = os.Pipe()
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	p.output, p.childOutput, err = os.Pipe()
	if err != nil {
		p.close()
		return nil, ErrRuntimeLaunch
	}
	return p, nil
}

func (p *task0DelegatedPipes) closePeers() {
	if p != nil {
		if p.childInput != nil {
			p.childInput.Close()
		}
		if p.childOutput != nil {
			p.childOutput.Close()
		}
	}
}

func (p *task0DelegatedPipes) close() {
	if p != nil {
		p.closePeers()
		if p.input != nil {
			p.input.Close()
		}
		if p.output != nil {
			p.output.Close()
		}
	}
}

func task0AdmitDelegatedRole(ctx context.Context, p *task0DelegatedProcess, control *net.UnixConn, executable os.FileInfo, manifestSHA string) error {
	if ctx == nil || ctx.Err() != nil || p == nil || control == nil || !digest(manifestSHA) || control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return ErrRuntimeLaunch
	}
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stop()
	var frame freshPreparationFrame
	if preparationPacket(control, &frame, false) != nil || frame != (freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: manifestSHA}) || p.check(executable) != nil {
		return ErrRuntimeLaunch
	}
	nonce, err := task0SetupNonce()
	if err != nil {
		return ErrRuntimeLaunch
	}
	admission := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "ADMIT", BindingSHA: manifestSHA, Nonce: nonce}
	if preparationPacket(control, &admission, true) != nil {
		return ErrRuntimeLaunch
	}
	admission.Operation = "ADMITTED"
	if preparationPacket(control, &frame, false) != nil || frame != admission || p.check(executable) != nil || control.SetDeadline(time.Time{}) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func launchTask0DelegatedGame(ctx context.Context, owner *task0SetupClient, helper *os.File, helperSHA, manifestSHA string) (*task0OwnedGameHelper, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || helper == nil || owner.grant == nil || owner.grant.roles["GAME"].ProgramSHA != helperSHA || owner.grant.roles["GAME"].ManifestSHA != manifestSHA {
		return nil, ErrTask0
	}
	info, err := helper.Stat()
	if err != nil {
		return nil, ErrTask0
	}
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return nil, ErrTask0
	}
	defer control.Close()
	defer child.Close()
	pipes, err := task0NewDelegatedPipes()
	if err != nil {
		return nil, ErrTask0
	}
	p, err := owner.create("GAME", []*os.File{helper, child, pipes.childInput, pipes.childOutput})
	child.Close()
	pipes.closePeers()
	if err != nil {
		pipes.close()
		return nil, ErrTask0
	}
	lifetime, cancel := context.WithCancel(ctx)
	wire := &task0PipeGame{lifetime: lifetime, cancel: cancel, input: pipes.input, output: pipes.output, serial: make(chan struct{}, 1)}
	wire.serial <- struct{}{}
	g := &task0OwnedGameHelper{wire: wire, delegated: p, executable: info}
	context.AfterFunc(lifetime, g.retire)
	if task0AdmitDelegatedRole(ctx, p, control, info, manifestSHA) != nil || wire.acceptReady(lifetime) != nil {
		g.retire()
		return nil, ErrTask0
	}
	return g, nil
}

func launchTask0DelegatedRemote(ctx context.Context, owner *task0SetupClient, helper *os.File, manifestSHA string, entry task0DispatchProfile) (*task0OwnedRemoteHelper, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || helper == nil || entry.Profile.BackendKind != modelgateway.BackendRemoteDeepSeek || modelgateway.ValidateModelProfile(entry.Profile) != nil {
		return nil, ErrRuntimeLaunch
	}
	role := string(entry.Seat)
	accepted, ok := owner.grant.roles[role]
	if !ok || accepted.ProfileBinding != entry.Profile.BindingID() || accepted.ManifestSHA != manifestSHA {
		return nil, ErrRuntimeLaunch
	}
	held, err := frozenSealedFile(int(helper.Fd()), accepted.ProgramSHA, accepted.ProgramBytes)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	broker := modelgateway.EnvironmentCredentialBroker{}
	environment, err := broker.BindChildEnvironment(ctx, *entry.Profile.CredentialReference, nil)
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	value := environment["DEEPSEEK_API_KEY"]
	if !task0PreparationCredentialValid(value) {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	credentialRaw := []byte(value)
	credential, err := task0SealedBytes(credentialRaw)
	clear(credentialRaw)
	clear(environment)
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	defer credential.Close()
	control, child, err := task0PrivateControlPair()
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	defer control.Close()
	defer child.Close()
	pipes, err := task0NewDelegatedPipes()
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	p, err := owner.create(role, []*os.File{held, child, pipes.childInput, pipes.childOutput, credential})
	child.Close()
	pipes.closePeers()
	if err != nil {
		pipes.close()
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	owned := &task0OwnedRemoteHelper{delegated: p, helper: held, input: pipes.input, output: pipes.output, reader: bufio.NewReaderSize(pipes.output, (1<<20)+1)}
	context.AfterFunc(ctx, func() { _ = owned.retire() })
	info, err := held.Stat()
	if err != nil || task0AdmitDelegatedRole(ctx, p, control, info, manifestSHA) != nil {
		owned.retire()
		return nil, ErrRuntimeLaunch
	}
	return owned, nil
}
