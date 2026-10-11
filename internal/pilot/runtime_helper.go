package pilot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/protocol"
)

const frozenPolicyAsset = "b007_launch_policy"
const frozenStageEnvironment = "AIPT_B007_FROZEN_STAGE"
const frozenAdapterBootstrap = `import{fstatSync,readSync}from'node:fs';import{stripTypeScriptTypes}from'node:module';const size=fstatSync(4).size;if(size<1||size>8388608)throw Error('invalid worker size');const bytes=Buffer.allocUnsafe(size);let offset=0;while(offset<size){const count=readSync(4,bytes,offset,size-offset,offset);if(count<1)throw Error('short worker read');offset+=count}const transformed=stripTypeScriptTypes(bytes.toString('utf8'),{mode:'strip'});await import('data:text/javascript;base64,'+Buffer.from(transformed,'utf8').toString('base64'));`

func frozenEnvironment(extra map[string]string) []string {
	m := map[string]string{"LANG": "C.UTF-8", "TZ": "UTC"}
	for k, v := range extra {
		m[k] = v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+m[k])
	}
	return out
}

func frozenBorrowFile(fd int) (*os.File, error) {
	dup, _, eno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 14)
	if eno != 0 {
		return nil, ErrRuntimeLaunch
	}
	return os.NewFile(dup, "owned duplicate of frozen descriptor"), nil
}

func frozenSealedFile(fd int, expectedSHA string, expectedBytes int64) (*os.File, error) {
	f, e := frozenBorrowFile(fd)
	if e != nil {
		return nil, e
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
		}
	}()
	if f == nil || !digest(expectedSHA) || expectedBytes < 1 {
		return nil, ErrRuntimeLaunch
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() != expectedBytes {
		return nil, ErrRuntimeLaunch
	}
	seals, _, eno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x40a, 0)
	if eno != 0 || seals&0xf != 0xf {
		return nil, ErrRuntimeLaunch
	}
	h := sha256.New()
	n, e := io.Copy(h, io.NewSectionReader(f, 0, expectedBytes))
	if e != nil || n != expectedBytes || hex.EncodeToString(h.Sum(nil)) != expectedSHA {
		return nil, ErrRuntimeLaunch
	}
	keep = true
	return f, nil
}

func frozenCapsulePolicy(c *HeldCodeCapsule) (runtimeLaunchPolicy, error) {
	f, e := c.Descriptor(frozenPolicyAsset)
	if e != nil {
		return runtimeLaunchPolicy{}, ErrRuntimeLaunch
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil {
		return runtimeLaunchPolicy{}, ErrRuntimeLaunch
	}
	return decodeRuntimeLaunchPolicy(raw, c.manifest)
}

func validateFrozenInherited(c *HeldCodeCapsule, p runtimeLaunchPolicy) error {
	files := map[string]RuntimeCodeFile{}
	for _, f := range c.manifest.Files {
		files[f.AssetID] = f
	}
	for fd, id := range map[int]string{5: p.NativeAsset, 7: p.NodeAsset, 8: p.WorkerAsset, 9: p.RouteAsset, 12: p.NodeAsset, 13: p.BundleAsset} {
		f := files[id]
		held, e := frozenSealedFile(fd, f.SHA256, f.Bytes)
		if e != nil {
			return e
		}
		_ = held.Close()
	}
	gguf, e := frozenSealedFile(6, p.GGUFSHA256, p.GGUFBytes)
	if e != nil {
		return e
	}
	_ = gguf.Close()
	for _, fd := range []int{10, 11} {
		var st syscall.Stat_t
		if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
			return ErrRuntimeLaunch
		}
	}
	var sock syscall.Stat_t
	if syscall.Fstat(4, &sock) != nil || sock.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return ErrRuntimeLaunch
	}
	kind, e := syscall.GetsockoptInt(4, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if e != nil || kind != syscall.SOCK_SEQPACKET {
		return ErrRuntimeLaunch
	}
	return nil
}

func bringFrozenLoopbackUp() error {
	if !namespaceIsNotHost("net") {
		return ErrRuntimeLaunch
	}
	fd, e := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if e != nil {
		return ErrRuntimeLaunch
	}
	defer syscall.Close(fd)
	type ifreq struct {
		Name    [16]byte
		Flags   uint16
		Padding [22]byte
	}
	v := ifreq{}
	copy(v.Name[:], "lo")
	if _, _, eno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&v))); eno != 0 {
		return ErrRuntimeLaunch
	}
	v.Flags |= syscall.IFF_UP
	if _, _, eno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&v))); eno != 0 {
		return ErrRuntimeLaunch
	}
	return nil
}

// acceptedManifestSHA comes only from the separately authenticated static
// helper's build binding. cmd/aipt-pilot never reads it from a launch request.
// The unchanged manager authenticates the complete helper including its base
// executable and this appendix before this entrypoint is reachable.
func RunFrozenRuntimeIsolator(acceptedManifestSHA string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || !digest(acceptedManifestSHA) || os.Getenv("AIPT_RUNTIME_ISOLATOR") != "1" || os.Getpid() != 1 || os.Geteuid() != 0 {
		return ErrRuntimeLaunch
	}
	helper := os.NewFile(3, "externally authenticated frozen helper")
	defer helper.Close()
	self, se := os.Stat("/proc/self/exe")
	held, he := helper.Stat()
	if se != nil || he != nil || !os.SameFile(self, held) {
		return ErrRuntimeLaunch
	}
	c, e := OpenEmbeddedCodeCapsule(helper, acceptedManifestSHA)
	if e != nil {
		return ErrRuntimeLaunch
	}
	defer c.Close()
	p, e := frozenCapsulePolicy(c)
	if e != nil || validateFrozenInherited(c, p) != nil {
		return ErrRuntimeLaunch
	}
	stage := os.Getenv(frozenStageEnvironment)
	// These descriptors survive only the helper's same-file self-exec. Before
	// any later fork, restore CLOEXEC on every original; ExtraFiles alone must
	// select the native/adapter child descriptors, without cross-role pipes.
	if stage == "1" && restoreFrozenInheritedCloseOnExec() != nil {
		return ErrRuntimeLaunch
	}
	if stage == "" {
		if !namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") || bringFrozenLoopbackUp() != nil {
			return ErrRuntimeLaunch
		}
		root, e := EnterFrozenRuntimeRoot(c, p.Root)
		if e != nil {
			return ErrRuntimeLaunch
		}
		if ConstrainChildExecPrivileges(root) != nil || c.Close() != nil {
			return ErrRuntimeLaunch
		}
		// A same-file exec removes setup capabilities from every new Go thread,
		// while retaining namespace-init PID and all caller-authenticated FDs.
		for fd := 3; fd <= 13; fd++ {
			if _, _, eno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, 0); eno != 0 {
				return ErrRuntimeLaunch
			}
		}
		return syscall.Exec("/proc/self/fd/3", []string{"aipt-pilot"}, frozenEnvironment(map[string]string{"AIPT_RUNTIME_ISOLATOR": "1", frozenStageEnvironment: "1"}))
	}
	if stage != "1" || verifyFrozenRuntimeRoot(c, p.Root) != nil {
		return ErrRuntimeLaunch
	}
	if e = c.Close(); e != nil {
		return ErrRuntimeLaunch
	}
	f := os.NewFile(4, "frozen control")
	raw, e := net.FileConn(f)
	_ = f.Close()
	if e != nil {
		return ErrRuntimeLaunch
	}
	control, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return ErrRuntimeLaunch
	}
	defer control.Close()
	var incoming frozenControlRequest
	if readFrozenControl(control, &incoming) != nil || acceptFrozenControl(p.Initial, incoming, true) != nil {
		return ErrRuntimeLaunch
	}
	s := &frozenSupervisor{control: control, policy: p, proof: &frozenProofBuffer{}}
	defer s.stopAll()
	if e = s.start(); e != nil {
		_ = writeFrozenControl(control, frozenControlReply{Schema: frozenControlSchema, Operation: "START_MODEL", Result: "FAIL", Code: string(modelgateway.CodeLocalReadinessFailed), FailureStage: "FROZEN_RUNTIME_START"})
		return ErrRuntimeLaunch
	}
	if e = writeFrozenControl(control, frozenControlReply{Schema: frozenControlSchema, Operation: "START_MODEL", Result: "PASS", Port: s.proxyPort, IsolationIdentity: modelgateway.LocalIsolationIdentity}); e != nil {
		return e
	}
	return s.loop()
}

func readFrozenControl(c *net.UnixConn, p *frozenControlRequest) error {
	b := make([]byte, 65537)
	n, _, flags, _, e := c.ReadMsgUnix(b, nil)
	if e != nil || flags&syscall.MSG_TRUNC != 0 || n > 65536 {
		return ErrRuntimeLaunch
	}
	return decodeFrozenJSON(b[:n], 65536, p)
}
func writeFrozenControl(c *net.UnixConn, r frozenControlReply) error {
	b, e := json.Marshal(r)
	if e != nil {
		return ErrRuntimeLaunch
	}
	n, e := c.Write(b)
	if e != nil || n != len(b) {
		return ErrRuntimeLaunch
	}
	return nil
}

type frozenProofBuffer struct {
	mu   sync.Mutex
	body []byte
}

func (p *frozenProofBuffer) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.body)+len(b) > 16384 {
		return 0, ErrRuntimeLaunch
	}
	p.body = append(p.body, b...)
	return len(b), nil
}
func (p *frozenProofBuffer) snapshot() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.body)
}

type frozenSupervisor struct {
	control         *net.UnixConn
	policy          runtimeLaunchPolicy
	native, adapter *frozenOwnedProcess
	counter         *nativeCountProxy
	proxyPort       int
	httpServer      *http.Server
	httpExit        chan struct{}
	proof           *frozenProofBuffer
	proofListener   *net.UnixListener
	proofExit       chan struct{}
}

func reserveFrozenPort() (int, error) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return 0, ErrRuntimeLaunch
	}
	port := l.Addr().(*net.TCPAddr).Port
	e = l.Close()
	return port, e
}

func (s *frozenSupervisor) start() error {
	port, e := reserveFrozenPort()
	if e != nil {
		return e
	}
	native, e := frozenBorrowFile(5)
	if e != nil {
		return e
	}
	defer native.Close()
	model, e := frozenBorrowFile(6)
	if e != nil {
		return e
	}
	defer model.Close()
	args := append(slices.Clone(s.policy.Initial.AdditionalArguments), "--model", "/proc/self/fd/4", "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--alias", "gguf-04", "--no-webui", "--no-slots", "--jinja")
	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{native, model}
	cmd.Dir = s.policy.Initial.LlamaWorkingDirectory
	cmd.Env = frozenEnvironment(s.policy.Initial.LlamaEnvironment)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	s.native, e = startFrozenProcess(cmd, native)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.policy.Initial.StartupTimeoutMS)*time.Millisecond)
	defer cancel()
	if e = waitFrozenNativeReady(ctx, s.native, port); e != nil {
		return e
	}
	// Every count and generation dial repeats the native socket ownership gate.
	s.counter, e = newNativeCountProxy(port, b007BundleSHA, inputSHAFileMetadata(native), s.proof)
	if e != nil {
		return e
	}
	s.counter.client.Transport = s.native.guardedTransport(port)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		return ErrRuntimeLaunch
	}
	s.proxyPort = listener.Addr().(*net.TCPAddr).Port
	s.httpServer = &http.Server{Handler: s.counter, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, WriteTimeout: 160 * time.Second, MaxHeaderBytes: 16384}
	s.httpExit = make(chan struct{})
	go func() { _ = s.httpServer.Serve(listener); close(s.httpExit) }()
	if e = s.startProofServer(); e != nil {
		return e
	}
	nativeExit, counter, server := s.native.exit, s.counter, s.httpServer
	go func() { <-nativeExit; counter.Close(); _ = server.Close() }()
	return nil
}

func inputSHAFileMetadata(f *os.File) string {
	info, e := f.Stat()
	if e != nil {
		return ""
	}
	h := sha256.New()
	n, e := io.Copy(h, io.NewSectionReader(f, 0, info.Size()))
	if e != nil || n != info.Size() {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func waitFrozenNativeReady(ctx context.Context, p *frozenOwnedProcess, port int) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	transport := p.guardedTransport(port)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(route string, max int64) ([]byte, error) {
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+route, nil)
		if e != nil {
			return nil, e
		}
		resp, e := client.Do(r)
		if e != nil {
			return nil, e
		}
		defer resp.Body.Close()
		body, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
		if e != nil || resp.StatusCode != 200 || int64(len(body)) > max || p.check() != nil {
			return nil, ErrRuntimeLaunch
		}
		return body, nil
	}
	for {
		if p.check() != nil {
			return ErrRuntimeLaunch
		}
		if _, e := get("/health", 4096); e == nil {
			body, e := get("/v1/models", 65536)
			if e == nil {
				var models struct {
					Models []struct {
						Name  string `json:"name"`
						Model string `json:"model"`
					} `json:"models"`
					Object string `json:"object"`
					Data   []struct {
						ID string `json:"id"`
					} `json:"data"`
				}
				if _, e = protocol.CanonicalJSON(body); e != nil || json.Unmarshal(body, &models) != nil || models.Object != "list" || len(models.Models) != 1 || len(models.Data) != 1 || models.Models[0].Name != "gguf-04" || models.Models[0].Model != "gguf-04" || models.Data[0].ID != "gguf-04" {
					return ErrRuntimeLaunch
				}
				body, e = get("/props", 1<<20)
				if e == nil {
					var props struct {
						ChatTemplate string `json:"chat_template"`
					}
					if _, e = protocol.CanonicalJSON(body); e != nil || json.Unmarshal(body, &props) != nil || inputSHA([]byte(props.ChatTemplate)) != b007TemplateSHA {
						return ErrRuntimeLaunch
					}
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ErrRuntimeLaunch
		case <-ticker.C:
		}
	}
}

func (s *frozenSupervisor) startAdapter() error {
	if s.adapter != nil || s.native.check() != nil {
		return ErrRuntimeLaunch
	}
	node, e := frozenBorrowFile(7)
	if e != nil {
		return e
	}
	defer node.Close()
	var files []*os.File
	for _, fd := range []int{8, 9, 12, 13, 10, 11} {
		f, e := frozenBorrowFile(fd)
		if e != nil {
			for _, f := range files {
				_ = f.Close()
			}
			return e
		}
		files = append(files, f)
	}
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	cmd := exec.Command("/proc/self/fd/3", "--no-warnings", "--input-type=module", "--eval", frozenAdapterBootstrap, "--")
	cmd.ExtraFiles = []*os.File{node, files[0], files[1], files[2], files[3]}
	cmd.Dir = s.policy.Initial.AdapterWorkingDirectory
	env := map[string]string{}
	for k, v := range s.policy.Initial.AdapterEnvironment {
		env[k] = v
	}
	env[s.policy.Initial.LocalEndpointEnvironment] = "http://127.0.0.1:" + strconv.Itoa(s.proxyPort)
	env["AIPT_HARNESS_ROUTE_FD"] = "5"
	cmd.Env = frozenEnvironment(env)
	cmd.Stdin = files[4]
	cmd.Stdout = files[5]
	cmd.Stderr = io.Discard
	p, e := startFrozenProcess(cmd, node)
	if e != nil {
		return e
	}
	s.adapter = p
	return nil
}

func (s *frozenSupervisor) stopAdapter() error {
	if s.adapter != nil {
		if e := s.adapter.stop(time.Duration(s.policy.Initial.ShutdownTimeoutMS) * time.Millisecond); e != nil {
			return e
		}
		s.adapter = nil
	}
	return s.reapOthers(true)
}

func (s *frozenSupervisor) reapOthers(keepNative bool) error {
	deadline := time.Now().Add(time.Duration(s.policy.Initial.ShutdownTimeoutMS) * time.Millisecond)
	for {
		pids, e := frozenNamespacePIDs()
		if e != nil {
			return e
		}
		remaining := 0
		for _, pid := range pids {
			if pid == 1 || (keepNative && s.native != nil && pid == s.native.command.Process.Pid) {
				continue
			}
			// This procfs contains only descendants of the owned namespace init.
			p, e := os.FindProcess(pid)
			if e != nil {
				return ErrRuntimeLaunch
			}
			held := false
			e = p.WithHandle(func(uintptr) { held = true })
			if e != nil || !held {
				_ = p.Release()
				return ErrRuntimeLaunch
			}
			e = p.Kill()
			_ = p.Release()
			if e != nil && !errors.Is(e, os.ErrProcessDone) && !errors.Is(e, syscall.ESRCH) {
				return ErrRuntimeLaunch
			}
			remaining++
		}
		// The direct native/adapter command owns its Wait; reap only adopted
		// orphans. A zombie cannot retain a socket or executable process.
		for _, pid := range pids {
			if pid == 1 || (s.native != nil && pid == s.native.command.Process.Pid) || (s.adapter != nil && pid == s.adapter.command.Process.Pid) {
				continue
			}
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		}
		if remaining == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return ErrRuntimeLaunch
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *frozenSupervisor) stopAll() error {
	if s.counter != nil {
		s.counter.Close()
	}
	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.proofListener != nil {
		_ = s.proofListener.Close()
	}
	e := s.stopAdapter()
	ne := s.native.stop(time.Duration(s.policy.Initial.ShutdownTimeoutMS) * time.Millisecond)
	if ne == nil {
		s.native = nil
	}
	return errors.Join(e, ne, s.reapOthers(false))
}

func (s *frozenSupervisor) loop() error {
	requests := make(chan frozenControlRequest)
	failures := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			var r frozenControlRequest
			if e := readFrozenControl(s.control, &r); e != nil {
				select {
				case failures <- e:
				case <-done:
				}
				return
			}
			select {
			case requests <- r:
			case <-done:
				return
			}
		}
	}()
	for {
		// STOP_ADAPTER runs serially inside this loop and removes the retired
		// generation before selecting again. Any exit selected here is an
		// unexpected exit and revokes the entire runtime generation.
		var adapterExit <-chan struct{}
		if s.adapter != nil {
			adapterExit = s.adapter.exit
		}
		select {
		case <-adapterExit:
			return ErrRuntimeLaunch
		case <-s.native.exit:
			return ErrRuntimeLaunch
		case <-s.httpExit:
			return ErrRuntimeLaunch
		case <-s.proofExit:
			return ErrRuntimeLaunch
		case <-failures:
			return ErrRuntimeLaunch
		case r := <-requests:
			finished, e := s.executeFrozenControl(r, failures)
			if finished || e != nil {
				return e
			}
		}
	}
}

// executeFrozenControl is the complete request arm, kept separate so a test
// can choose that arm deterministically with already-pending exit events.
func (s *frozenSupervisor) executeFrozenControl(r frozenControlRequest, failures <-chan error) (bool, error) {
	// A ready STOP request must not mask an already observed runtime exit.
	// select has no priority: recheck the current generation before it
	// can be retired or replaced by any control operation.
	if s.pendingRuntimeFailure(failures) != nil {
		return true, ErrRuntimeLaunch
	}
	if acceptFrozenControl(s.policy.Initial, r, false) != nil {
		return true, ErrRuntimeLaunch
	}
	reply := frozenControlReply{Schema: frozenControlSchema, Operation: r.Operation, Result: "PASS"}
	var e error
	switch r.Operation {
	case "START_ADAPTER":
		e = s.startAdapter()
		if e == nil {
			reply.AdapterPID = s.adapter.command.Process.Pid
		}
	case "STOP_ADAPTER":
		// Establish a deliberate stop while the owned generation is live.
		// Cleanup still tolerates an exited child, but a control STOP cannot
		// relabel a prior unexpected exit as successful retirement.
		if s.adapter != nil && s.adapter.check() != nil {
			return true, ErrRuntimeLaunch
		}
		e = s.stopAdapter()
	case "STOP_ALL":
		e = s.stopAll()
	}
	if e != nil {
		reply.Result = "FAIL"
		reply.Code = string(modelgateway.CodeLocalShutdownFailed)
	}
	if writeFrozenControl(s.control, reply) != nil {
		return true, ErrRuntimeLaunch
	}
	if r.Operation == "STOP_ALL" {
		return true, e
	}
	return false, nil
}

// pendingRuntimeFailure also runs after the request arm wins select. In
// particular it uses the current adapter, before STOP can remove its exit
// channel. Native/counter/proof/control failures receive the same treatment.
func (s *frozenSupervisor) pendingRuntimeFailure(failures <-chan error) error {
	if s == nil || s.native == nil {
		return ErrRuntimeLaunch
	}
	var adapterExit <-chan struct{}
	if s.adapter != nil {
		adapterExit = s.adapter.exit
	}
	select {
	case <-adapterExit:
		return ErrRuntimeLaunch
	case <-s.native.exit:
		return ErrRuntimeLaunch
	case <-s.httpExit:
		return ErrRuntimeLaunch
	case <-s.proofExit:
		return ErrRuntimeLaunch
	case <-failures:
		return ErrRuntimeLaunch
	default:
		return nil
	}
}

// This socket exports only the counter's bounded digest/counter stream. No
// append, reset, start, input or evidence-mutation operation exists. Inside
// the private PID namespace Node peers have a nonzero PID and are rejected;
// the outside preparation owner is translated to PID 0 / mapped UID 0.
func (s *frozenSupervisor) startProofServer() error {
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: s.policy.ProofDirectory + "/proof.sock", Net: "unix"})
	if e != nil {
		return ErrRuntimeLaunch
	}
	s.proofListener = l
	s.proofExit = make(chan struct{})
	go func() {
		defer close(s.proofExit)
		for {
			c, e := l.AcceptUnix()
			if e != nil {
				return
			}
			func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				raw, e := c.SyscallConn()
				if e != nil {
					return
				}
				allowed := false
				_ = raw.Control(func(fd uintptr) {
					peer, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
					allowed = e == nil && peer.Pid == 0 && peer.Uid == 0 && peer.Gid == 0
				})
				if !allowed {
					return
				}
				b := s.proof.snapshot()
				_, _ = c.Write(b)
			}()
		}
	}()
	return nil
}

// Only the authenticated stage-1 entry invokes this for the fixed inherited
// descriptor set. No caller can broaden the set, retain a pipe in another
// child, or change the kernel CLOEXEC policy used by the launch operations.
func restoreFrozenInheritedCloseOnExec() error {
	for fd := 3; fd <= 13; fd++ {
		flags, _, eno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if eno != 0 {
			return ErrRuntimeLaunch
		}
		if _, _, eno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFD, flags|syscall.FD_CLOEXEC); eno != 0 {
			return ErrRuntimeLaunch
		}
	}
	return nil
}
