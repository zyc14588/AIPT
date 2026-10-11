package pilot

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

func launchTask0RemoteHelper(ctx context.Context, helper *os.File, manifestSHA string, entry task0DispatchProfile) (*task0OwnedRemoteHelper, error) {
	if ctx == nil || ctx.Err() != nil || helper == nil || !digest(manifestSHA) || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") || entry.Profile.BackendKind != modelgateway.BackendRemoteDeepSeek || modelgateway.ValidateModelProfile(entry.Profile) != nil {
		return nil, ErrRuntimeLaunch
	}
	// Constructor already matched the full sealed helper digest to the
	// externally accepted role binding. Keep this held object for its lifetime.
	info, err := helper.Stat()
	if err != nil || info.Size() < 64 || info.Size() > 4<<30 {
		return nil, ErrRuntimeLaunch
	}
	seals, _, eno := syscall.Syscall(syscall.SYS_FCNTL, helper.Fd(), 0x40a, 0)
	if eno != 0 || seals&0xf != 0xf {
		return nil, ErrRuntimeLaunch
	}
	held, err := frozenBorrowFile(int(helper.Fd()))
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	c, err := OpenEmbeddedCodeCapsule(held, manifestSHA)
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	p, err := frozenTask0RemotePolicy(c)
	c.Close()
	if err != nil || !task0SameJSON(entry.Profile, p.Profile) || !task0SameJSON(entry.Sampling, p.Sampling) {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	parent, child := os.NewFile(uintptr(fds[0]), "owned remote parent admission"), os.NewFile(uintptr(fds[1]), "owned remote child admission")
	defer parent.Close()
	defer child.Close()
	connection, err := net.FileConn(parent)
	if err != nil {
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3")
	// Only this concrete, write-only broker may bind the approved credential.
	// No credential value is serialized into a binding, policy or diagnostic.
	broker := modelgateway.EnvironmentCredentialBroker{}
	env, err := broker.BindChildEnvironment(ctx, *entry.Profile.CredentialReference, map[string]string{"LANG": "C.UTF-8", "TZ": "UTC"})
	if err != nil {
		control.Close()
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	env["AIPT_TASK0_REMOTE_CAPSULE"] = "1"
	cmd.Env = frozenEnvironment(env)
	cmd.ExtraFiles = []*os.File{held, child}
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		control.Close()
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		control.Close()
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}
	if err = cmd.Start(); err != nil {
		if pidfd >= 0 {
			syscall.Close(pidfd)
		}
		input.Close()
		output.Close()
		control.Close()
		held.Close()
		return nil, ErrRuntimeLaunch
	}
	child.Close()
	if pidfd >= 0 {
		syscall.Close(pidfd)
	}
	process := &freshPreparationProcess{command: cmd, control: control, exit: make(chan struct{})}
	go func() { process.waitErr = cmd.Wait(); close(process.exit) }()
	owned := &task0OwnedRemoteHelper{process: process, helper: held, input: input, output: output, reader: bufio.NewReaderSize(output, (1<<20)+1)}
	context.AfterFunc(ctx, func() { _ = owned.retire() })
	fail := func() (*task0OwnedRemoteHelper, error) { _ = owned.retire(); return nil, ErrRuntimeLaunch }
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil || verifiedPreparationChild(cmd, held) != nil {
		return fail()
	}
	var hello freshPreparationFrame
	if preparationPacket(control, &hello, false) != nil || hello != (freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: manifestSHA}) || owned.check() != nil {
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
	if preparationPacket(control, &ack, false) != nil || ack != admission || owned.check() != nil {
		return fail()
	}
	control.Close()
	return owned, nil
}

func task0RemoteStageEnvironment(stage string) ([]string, error) {
	value, present := os.LookupEnv("DEEPSEEK_API_KEY")
	if !present || value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return nil, ErrRuntimeLaunch
	}
	return frozenEnvironment(map[string]string{"AIPT_TASK0_REMOTE_CAPSULE": "1", task0RemoteStage: stage, "DEEPSEEK_API_KEY": value}), nil
}

// Like the game helper, this self-contained entry gets only its compiled
// manifest and outside-parent admission. Its network namespace deliberately
// remains the parent's for the exact approved WAN route in the frozen Q002
// Harness. The filesystem has no game source, database, seed, model or GPU.
func RunFrozenTask0Remote(acceptedManifestSHA string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || !digest(acceptedManifestSHA) || os.Getenv("AIPT_TASK0_REMOTE_CAPSULE") != "1" || len(os.Args) != 1 || os.Getpid() != 1 || os.Geteuid() != 0 {
		return ErrRuntimeLaunch
	}
	helper := os.NewFile(3, "externally accepted remote helper")
	defer helper.Close()
	self, se := os.Stat("/proc/self/exe")
	held, he := helper.Stat()
	seals, _, eno := syscall.Syscall(syscall.SYS_FCNTL, helper.Fd(), 0x40a, 0)
	if se != nil || he != nil || !os.SameFile(self, held) || eno != 0 || seals&0xf != 0xf {
		return ErrRuntimeLaunch
	}
	c, err := OpenEmbeddedCodeCapsule(helper, acceptedManifestSHA)
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer c.Close()
	p, err := frozenTask0RemotePolicy(c)
	if err != nil {
		return ErrRuntimeLaunch
	}
	stage := os.Getenv(task0RemoteStage)
	if stage == "" {
		for _, kind := range []string{"user", "pid", "mnt"} {
			if !namespaceIsNotHost(kind) {
				return ErrRuntimeLaunch
			}
		}
		root, err := EnterFrozenRuntimeRoot(c, p.Root)
		if err != nil || ConstrainChildExecPrivileges(root) != nil || c.Close() != nil {
			return ErrRuntimeLaunch
		}
		for _, fd := range []int{3, 4} {
			if _, _, eno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); eno != 0 {
				return ErrRuntimeLaunch
			}
		}
		env, err := task0RemoteStageEnvironment("1")
		if err != nil {
			return ErrRuntimeLaunch
		}
		return syscall.Exec("/proc/self/fd/3", []string{"aipt-pilot"}, env)
	}
	if stage != "1" || verifyFrozenRuntimeRoot(c, p.Root) != nil || verifyZeroCapabilityThreads(1) != nil {
		return ErrRuntimeLaunch
	}
	for _, fd := range []int{3, 4} {
		if _, _, eno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, syscall.FD_CLOEXEC); eno != 0 {
			return ErrRuntimeLaunch
		}
	}
	typeValue, e := syscall.GetsockoptInt(4, syscall.SOL_SOCKET, syscall.SO_TYPE)
	peer, pe := syscall.GetsockoptUcred(4, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if e != nil || pe != nil || typeValue != syscall.SOCK_SEQPACKET || peer.Pid != 0 || peer.Uid != 0 || peer.Gid != 0 {
		return ErrRuntimeLaunch
	}
	f := os.NewFile(4, "own remote admission socket")
	connection, e := net.FileConn(f)
	f.Close()
	if e != nil {
		return ErrRuntimeLaunch
	}
	control, ok := connection.(*net.UnixConn)
	if !ok {
		connection.Close()
		return ErrRuntimeLaunch
	}
	defer control.Close()
	if control.SetDeadline(time.Now().Add(30*time.Second)) != nil {
		return ErrRuntimeLaunch
	}
	hello := freshPreparationFrame{Schema: freshPreparationSchema, Operation: "READY", BindingSHA: acceptedManifestSHA}
	if preparationPacket(control, &hello, true) != nil {
		return ErrRuntimeLaunch
	}
	var admission freshPreparationFrame
	if preparationPacket(control, &admission, false) != nil || admission.Schema != hello.Schema || admission.Operation != "ADMIT" || admission.BindingSHA != hello.BindingSHA || !digest(admission.Nonce) {
		return ErrRuntimeLaunch
	}
	admission.Operation = "ADMITTED"
	if preparationPacket(control, &admission, true) != nil {
		return ErrRuntimeLaunch
	}
	control.Close()
	var files []*os.File
	for _, id := range []string{p.NodeAsset, p.WorkerAsset, p.RouteAsset, p.NodeAsset, p.BundleAsset} {
		f, err := c.Descriptor(id)
		if err != nil {
			for _, f := range files {
				f.Close()
			}
			return ErrRuntimeLaunch
		}
		files = append(files, f)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	cmd := exec.Command("/proc/self/fd/3", "--no-warnings", "--input-type=module", "--eval", frozenAdapterBootstrap, "--")
	cmd.ExtraFiles = files
	cmd.Dir = "/aipt/remote"
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.Discard
	value, present := os.LookupEnv("DEEPSEEK_API_KEY")
	if !present || value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return ErrRuntimeLaunch
	}
	cmd.Env = frozenEnvironment(map[string]string{"AIPT_HARNESS_ROUTE_FD": "5", "DSH_HOME": "/aipt/private/sessions", "DEEPSEEK_API_KEY": value})
	owned, err := startFrozenProcess(cmd, files[0])
	if err != nil {
		return ErrRuntimeLaunch
	}
	defer owned.stop(time.Second)
	<-owned.exit
	owned.mu.Lock()
	waitErr := owned.waitError
	owned.mu.Unlock()
	if waitErr != nil {
		return ErrRuntimeLaunch
	}
	return nil
}
