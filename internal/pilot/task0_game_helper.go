package pilot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/runcore"
)

const task0GameStage = "AIPT_B007_TASK0_GAME_STAGE"

type task0OwnedGameHelper struct {
	wire       *task0PipeGame
	process    *freshPreparationProcess
	delegated  *task0DelegatedProcess
	executable os.FileInfo
	retirement sync.Once
	retireErr  error
}

func verifyTask0GameChild(command *exec.Cmd, executable os.FileInfo) error {
	if command == nil || command.Process == nil || executable == nil || command.Process.Signal(syscall.Signal(0)) != nil {
		return ErrTask0
	}
	handle := false
	if command.Process.WithHandle(func(uintptr) { handle = true }) != nil || !handle {
		return ErrTask0
	}
	base := "/proc/" + strconv.Itoa(command.Process.Pid)
	actual, err := os.Stat(base + "/exe")
	if err != nil || !os.SameFile(actual, executable) {
		return ErrTask0
	}
	for _, mapping := range []struct {
		name string
		id   int
	}{{"uid_map", os.Getuid()}, {"gid_map", os.Getgid()}} {
		raw, err := os.ReadFile(base + "/" + mapping.name)
		if err != nil || !singleRootIDMapping(raw) || strings.Fields(string(raw))[1] != strconv.Itoa(mapping.id) {
			return ErrTask0
		}
	}
	for _, kind := range []string{"user", "pid", "mnt", "net"} {
		parent, err := os.Stat("/proc/self/ns/" + kind)
		child, childErr := os.Stat(base + "/ns/" + kind)
		if err != nil || childErr != nil || os.SameFile(parent, child) {
			return ErrTask0
		}
	}
	status, err := os.ReadFile(base + "/status")
	if err != nil || len(status) > 65536 {
		return ErrTask0
	}
	pid1 := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "NSpid:" && fields[len(fields)-1] == "1" {
			pid1 = true
		}
	}
	if !pid1 {
		return ErrTask0
	}
	return nil
}

// The enclosing accepted preparation binding owns both digests. It supplies
// a held sealed helper, never a caller-selected executable or game root.
// The game receives a separate closed NET namespace and no model credentials,
// database handles, seed material, model routes or host filesystem access.
func launchTask0GameHelper(ctx context.Context, helper *os.File, helperSHA, manifestSHA string) (*task0OwnedGameHelper, error) {
	if ctx == nil || ctx.Err() != nil || helper == nil || !digest(helperSHA) || !digest(manifestSHA) ||
		os.Getpid() != 1 || os.Geteuid() != 0 || !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return nil, ErrTask0
	}
	info, err := helper.Stat()
	if err != nil || info.Size() < 64 || info.Size() > 4<<30 {
		return nil, ErrTask0
	}
	held, err := frozenSealedFile(int(helper.Fd()), helperSHA, info.Size())
	if err != nil {
		return nil, ErrTask0
	}
	defer held.Close()
	capsule, err := OpenEmbeddedCodeCapsule(held, manifestSHA)
	if err != nil {
		return nil, ErrTask0
	}
	policy, policyErr := frozenTask0GamePolicy(capsule)
	validErr := validateTask0Capsule(capsule)
	capsule.Close()
	if policyErr != nil || validErr != nil || !slices.Contains(policy.Root.WorkingDirectories, "/aipt/game") {
		return nil, ErrTask0
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, ErrTask0
	}
	parent, child := os.NewFile(uintptr(fds[0]), "owned game parent admission"), os.NewFile(uintptr(fds[1]), "owned game child admission")
	defer parent.Close()
	defer child.Close()
	connection, err := net.FileConn(parent)
	if err != nil {
		return nil, ErrTask0
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return nil, ErrTask0
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3")
	cmd.Env = frozenEnvironment(map[string]string{"AIPT_TASK0_GAME_CAPSULE": "1"})
	cmd.ExtraFiles = []*os.File{held, child}
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		control.Close()
		return nil, ErrTask0
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		control.Close()
		return nil, ErrTask0
	}
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	if err = cmd.Start(); err != nil {
		if pidfd >= 0 {
			syscall.Close(pidfd)
		}
		input.Close()
		output.Close()
		control.Close()
		return nil, ErrTask0
	}
	child.Close()
	if pidfd >= 0 {
		syscall.Close(pidfd)
	}
	p := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
	go func() { p.waitErr = cmd.Wait(); close(p.exit) }()
	lifetime, cancel := context.WithCancel(ctx)
	wire := &task0PipeGame{lifetime: lifetime, cancel: cancel, input: input, output: output, serial: make(chan struct{}, 1)}
	wire.serial <- struct{}{}
	g := &task0OwnedGameHelper{wire: wire, process: p, executable: info}
	context.AfterFunc(lifetime, g.retire)
	fail := func() (*task0OwnedGameHelper, error) { g.retire(); return nil, ErrTask0 }
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil || verifyTask0GameChild(cmd, info) != nil {
		return fail()
	}
	var hello freshPreparationFrame
	if preparationPacket(control, &hello, false) != nil || hello != (freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: manifestSHA}) ||
		verifyTask0GameChild(cmd, info) != nil || verifyZeroCapabilityThreads(cmd.Process.Pid) != nil {
		return fail()
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return fail()
	}
	admission := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "ADMIT", BindingSHA: manifestSHA, Nonce: hex.EncodeToString(nonce[:])}
	if preparationPacket(control, &admission, true) != nil {
		return fail()
	}
	var ack freshPreparationFrame
	admission.Operation = "ADMITTED"
	if preparationPacket(control, &ack, false) != nil || ack != admission || verifyTask0GameChild(cmd, info) != nil || verifyZeroCapabilityThreads(cmd.Process.Pid) != nil || control.SetDeadline(time.Time{}) != nil {
		return fail()
	}
	control.Close()
	if wire.acceptReady(lifetime) != nil {
		return fail()
	}
	return g, nil
}

func (g *task0OwnedGameHelper) invoke(ctx context.Context, operation string, fields map[string]any) (json.RawMessage, error) {
	if g == nil || g.wire == nil {
		return nil, ErrTask0
	}
	if g.checkOwned() != nil {
		g.retire()
		return nil, ErrTask0
	}
	result, err := g.wire.invoke(ctx, operation, fields)
	if err != nil {
		g.retire()
		return nil, ErrTask0
	}
	return result, nil
}

func (g *task0OwnedGameHelper) retire() {
	_ = g.retireOwned()
}

func (g *task0OwnedGameHelper) checkOwned() error {
	if g == nil || g.executable == nil {
		return ErrTask0
	}
	if g.delegated != nil {
		return g.delegated.check(g.executable)
	}
	if g.process == nil {
		return ErrTask0
	}
	select {
	case <-g.process.exit:
		return ErrTask0
	default:
	}
	if verifyTask0GameChild(g.process.command, g.executable) != nil || verifyZeroCapabilityThreads(g.process.command.Process.Pid) != nil {
		return ErrTask0
	}
	return nil
}

func (g *task0OwnedGameHelper) retireOwned() error {
	if g == nil {
		return nil
	}
	g.retirement.Do(func() {
		if g.wire != nil {
			g.wire.retire()
		}
		if g.process != nil {
			g.retireErr = g.process.retire()
		}
		if g.delegated != nil {
			g.retireErr = g.delegated.retire()
		}
	})
	return g.retireErr
}

func task0RelayRequest(raw []byte) (string, map[string]any, error) {
	var object map[string]json.RawMessage
	if decodeFrozenJSON(raw, task0GameWireLimit, &object) != nil {
		return "", nil, ErrTask0
	}
	var operation string
	var source runcore.SourcePackageBinding
	if decodeFrozenJSON(object["operation"], 256, &operation) != nil || decodeFrozenJSON(object["source_binding"], 4096, &source) != nil || source != task0PrototypeSourceBinding || string(object["schema"]) != `"aipt.private.b007-task0-game-request/v1"` {
		return "", nil, ErrTask0
	}
	keys, ok := map[string][]string{"INITIAL": {}, "PROPOSE": {"state", "trusted", "frame"}, "CHECK_PROPOSAL": {"state", "seat", "proposal"}, "APPLY": {"state", "seat", "frame", "draws"}, "INVARIANT": {"state"}, "PROJECTION": {"state", "seat", "fixture_id"}}[operation]
	if !ok || len(object) != len(keys)+3 {
		return "", nil, ErrTask0
	}
	fields := map[string]any{}
	for _, key := range keys {
		value, ok := object[key]
		if !ok {
			return "", nil, ErrTask0
		}
		fields[key] = value
	}
	return operation, fields, nil
}

// This entry runs only in an externally authenticated appended helper built
// with the accepted manifest digest. Its sole executable child is the exact
// accepted game gateway; it never calls a model or writes authoritative state.
func RunFrozenTask0Game(acceptedManifestSHA string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || !digest(acceptedManifestSHA) || os.Getenv("AIPT_TASK0_GAME_CAPSULE") != "1" || len(os.Args) != 1 || os.Getpid() != 1 || os.Geteuid() != 0 {
		return ErrTask0
	}
	helper := os.NewFile(3, "externally accepted game helper")
	defer helper.Close()
	self, se := os.Stat("/proc/self/exe")
	held, he := helper.Stat()
	if se != nil || he != nil || !os.SameFile(self, held) {
		return ErrTask0
	}
	c, err := OpenEmbeddedCodeCapsule(helper, acceptedManifestSHA)
	if err != nil {
		return ErrTask0
	}
	defer c.Close()
	p, err := frozenTask0GamePolicy(c)
	if err != nil || validateTask0Capsule(c) != nil {
		return ErrTask0
	}
	stage := os.Getenv(task0GameStage)
	if stage == "" {
		for _, kind := range []string{"user", "pid", "mnt", "net"} {
			if !namespaceIsNotHost(kind) {
				return ErrTask0
			}
		}
		root, err := EnterFrozenRuntimeRoot(c, p.Root)
		if err != nil || ConstrainChildExecPrivileges(root) != nil || c.Close() != nil {
			return ErrTask0
		}
		for _, fd := range []int{3, 4} {
			if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); errno != 0 {
				return ErrTask0
			}
		}
		return syscall.Exec("/proc/self/fd/3", []string{"aipt-pilot"}, frozenEnvironment(map[string]string{"AIPT_TASK0_GAME_CAPSULE": "1", task0GameStage: "1"}))
	}
	if stage != "1" || verifyFrozenRuntimeRoot(c, p.Root) != nil || verifyZeroCapabilityThreads(1) != nil {
		return ErrTask0
	}
	for _, fd := range []int{3, 4} {
		if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC); errno != 0 {
			return ErrTask0
		}
	}
	typeValue, e := syscall.GetsockoptInt(4, syscall.SOL_SOCKET, syscall.SO_TYPE)
	peer, pe := syscall.GetsockoptUcred(4, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if e != nil || pe != nil || typeValue != syscall.SOCK_SEQPACKET || peer.Pid != 0 || peer.Uid != 0 || peer.Gid != 0 {
		return ErrTask0
	}
	f := os.NewFile(4, "own game admission socket")
	connection, e := net.FileConn(f)
	f.Close()
	if e != nil {
		return ErrTask0
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return ErrTask0
	}
	defer control.Close()
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return ErrTask0
	}
	hello := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: acceptedManifestSHA}
	if preparationPacket(control, &hello, true) != nil {
		return ErrTask0
	}
	var admission freshPreparationFrame
	if preparationPacket(control, &admission, false) != nil || admission.Schema != hello.Schema || admission.Operation != "ADMIT" || admission.BindingSHA != hello.BindingSHA || !digest(admission.Nonce) {
		return ErrTask0
	}
	admission.Operation = "ADMITTED"
	if preparationPacket(control, &admission, true) != nil {
		return ErrTask0
	}
	control.Close()
	g, err := openTask0CapsuleGame(context.Background(), c, p)
	if err != nil {
		return ErrTask0
	}
	defer g.retire()
	ready, _ := json.Marshal(map[string]any{"schema": "aipt.private.b007-task0-game-ready/v1", "source_binding": task0PrototypeSourceBinding})
	if task0WriteWire(os.Stdout, ready) != nil {
		return ErrTask0
	}
	for range 4096 {
		raw, err := task0ReadWire(os.Stdin)
		if err != nil {
			return ErrTask0
		}
		op, fields, err := task0RelayRequest(raw)
		if err != nil {
			return ErrTask0
		}
		result, err := g.invoke(context.Background(), op, fields)
		if err != nil {
			return ErrTask0
		}
		reply, _ := json.Marshal(task0GameReply{Schema: "aipt.private.b007-task0-game-reply/v1", Op: op, Source: task0PrototypeSourceBinding, Result: result})
		if task0WriteWire(os.Stdout, reply) != nil {
			return ErrTask0
		}
	}
	return ErrTask0
}
