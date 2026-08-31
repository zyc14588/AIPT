package modelgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

const (
	AdapterProtocolVersion = "1"
	AdapterMethodProbe     = "aipt.model.probe"
	AdapterMethodInvoke    = "aipt.model.invoke"
	AdapterMethodCancel    = "aipt.model.cancel"
	maxAdapterFrameBytes   = 1 << 20
	adapterNodeBootstrap   = `import{fstatSync,readSync}from'node:fs';import{stripTypeScriptTypes}from'node:module';const size=fstatSync(4).size;if(size<1||size>8388608)throw Error('invalid worker size');const bytes=Buffer.allocUnsafe(size);let offset=0;while(offset<size){const count=readSync(4,bytes,offset,size-offset,offset);if(count<1)throw Error('short worker read');offset+=count}const transformed=stripTypeScriptTypes(bytes.toString('utf8'),{mode:'strip'});await import('data:text/javascript;base64,'+Buffer.from(transformed,'utf8').toString('base64'));`
)

// AdapterRouteSpec binds the AIPT adapter worker and its private route file.
// File paths are never included in public evidence or returned errors.
type AdapterRouteSpec struct {
	ProfileBinding          string
	ExecutablePath          string
	ExecutableSHA256        string
	AdapterEntrypointPath   string
	AdapterEntrypointSHA256 string
	RouteConfigPath         string
	RouteConfigSHA256       string
	Arguments               []string
	Environment             map[string]string
	WorkingDirectory        string
	StartupTimeout          time.Duration
	ShutdownTimeout         time.Duration
	// IsolatedLauncher is required only for LOCAL_LLAMACPP. It is a private
	// in-process capability and is never serialized into route evidence.
	IsolatedLauncher *ManagedLlama
}

type adapterRequest struct {
	JSONRPC         string `json:"jsonrpc"`
	ID              string `json:"id"`
	ProtocolVersion string `json:"protocol_version"`
	Method          string `json:"method"`
	Params          any    `json:"params"`
}

type adapterResponse struct {
	JSONRPC         string          `json:"jsonrpc"`
	ID              string          `json:"id"`
	ProtocolVersion string          `json:"protocol_version"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *struct {
		Code string `json:"code"`
	} `json:"error,omitempty"`
}

type adapterProbeParams struct {
	ProfileBinding        string `json:"profile_binding"`
	ExpectedModelID       string `json:"expected_model_id"`
	HarnessIdentity       string `json:"harness_identity"`
	ProtocolIdentity      string `json:"protocol_identity"`
	ProtocolVersion       string `json:"protocol_version"`
	CapabilityFingerprint string `json:"capability_fingerprint"`
}

type adapterRoute struct {
	profile       ModelProfile
	spec          AdapterRouteSpec
	broker        CredentialBroker
	binary        *verifiedAsset
	entry         *verifiedAsset
	config        *verifiedAsset
	harnessBinary *verifiedAsset
	harnessEntry  *verifiedAsset
	isolated      *ManagedLlama

	mu              sync.Mutex
	cmd             *exec.Cmd
	process         *managedProcessIdentity
	stdin           io.WriteCloser
	stdout          *bufio.Reader
	exit            chan error
	generation      int
	recovered       bool
	isolatedRunning bool
	failedStart     bool
}

// AdapterProcessTransport is the only production HarnessTransport. It speaks
// the additive, versioned JSON-RPC contract implemented by
// @aipt/harness-adapter/model-process-worker. That worker alone speaks ACP to
// the external DeepSeek Harness; Core has no provider or inference endpoint.
type AdapterProcessTransport struct {
	routes     map[string]*adapterRoute
	routeOrder []string
	closeMu    sync.Mutex
	opMu       sync.RWMutex
	mu         sync.Mutex
	// admissionClosed is permanent once shutdown begins. closeComplete is a
	// separate cleanup state so a failed Close remains retryable without ever
	// reopening Probe, Invoke, or Recover admission.
	admissionClosed bool
	closeComplete   bool
}

func NewAdapterProcessTransport(profiles []ModelProfile, specs []AdapterRouteSpec, broker CredentialBroker) (*AdapterProcessTransport, error) {
	byProfile := make(map[string]ModelProfile, len(profiles))
	for _, profile := range profiles {
		if err := ValidateModelProfile(profile); err != nil {
			return nil, err
		}
		if _, exists := byProfile[profile.BindingID()]; exists {
			return nil, newError(CodeInvalidProfile, "new_adapter_transport", profile.BindingID(), errors.New("duplicate profile"))
		}
		byProfile[profile.BindingID()] = profile
	}
	if len(byProfile) == 0 || len(specs) != len(byProfile) {
		return nil, newError(CodeHarnessTransport, "new_adapter_transport", "", errors.New("each profile requires exactly one route"))
	}
	transport := &AdapterProcessTransport{
		routes:     make(map[string]*adapterRoute, len(specs)),
		routeOrder: make([]string, 0, len(specs)),
	}
	for _, spec := range specs {
		profile, exists := byProfile[spec.ProfileBinding]
		if !exists || transport.routes[spec.ProfileBinding] != nil {
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "register_adapter_route", spec.ProfileBinding, errors.New("unknown or duplicate route profile"))
		}
		if err := validateAdapterRouteSpec(spec); err != nil {
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "validate_adapter_route", spec.ProfileBinding, err)
		}
		if profile.BackendKind == BackendRemoteDeepSeek && broker == nil {
			transport.closeVerifiedAssets()
			return nil, newError(CodeCredentialUnavailable, "register_adapter_route", spec.ProfileBinding, errors.New("credential broker required"))
		}
		if profile.BackendKind == BackendLocalLlamaCPP {
			if spec.IsolatedLauncher == nil || !spec.IsolatedLauncher.isolatedAdapterMatches(spec) {
				transport.closeVerifiedAssets()
				return nil, newError(CodeHarnessTransport, "register_isolated_adapter_route", spec.ProfileBinding, errors.New("local adapter is not bound to the managed isolation generation"))
			}
			transport.routes[spec.ProfileBinding] = &adapterRoute{
				profile: profile, spec: spec, broker: broker, isolated: spec.IsolatedLauncher,
			}
			transport.routeOrder = append(transport.routeOrder, spec.ProfileBinding)
			continue
		}
		if spec.IsolatedLauncher != nil {
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "register_adapter_route", spec.ProfileBinding, errors.New("remote adapter cannot use a local isolation launcher"))
		}
		binary, err := openVerifiedAsset(spec.ExecutablePath, spec.ExecutableSHA256, true)
		if err != nil {
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "open_verified_adapter_executable", spec.ProfileBinding, err)
		}
		entry, err := openVerifiedAsset(spec.AdapterEntrypointPath, spec.AdapterEntrypointSHA256, false)
		if err != nil {
			_ = binary.close()
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "open_verified_adapter_entrypoint", spec.ProfileBinding, err)
		}
		config, err := openVerifiedAsset(spec.RouteConfigPath, spec.RouteConfigSHA256, false)
		if err != nil {
			_ = binary.close()
			_ = entry.close()
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "open_verified_adapter_route", spec.ProfileBinding, err)
		}
		harnessBinary, harnessEntry, err := openVerifiedHarnessChildAssets(config)
		if err != nil {
			_ = binary.close()
			_ = entry.close()
			_ = config.close()
			transport.closeVerifiedAssets()
			return nil, newError(CodeHarnessTransport, "open_verified_harness_assets", spec.ProfileBinding, err)
		}
		transport.routes[spec.ProfileBinding] = &adapterRoute{
			profile: profile, spec: spec, broker: broker, binary: binary, entry: entry, config: config,
			harnessBinary: harnessBinary, harnessEntry: harnessEntry,
		}
		transport.routeOrder = append(transport.routeOrder, spec.ProfileBinding)
	}
	return transport, nil
}

func (t *AdapterProcessTransport) closeVerifiedAssets() {
	if t == nil {
		return
	}
	for _, route := range t.routes {
		_ = route.binary.close()
		_ = route.entry.close()
		_ = route.config.close()
		_ = route.harnessBinary.close()
		_ = route.harnessEntry.close()
	}
}

func openVerifiedHarnessChildAssets(config *verifiedAsset) (*verifiedAsset, *verifiedAsset, error) {
	raw, err := config.readAll(4 << 20)
	if err != nil {
		return nil, nil, err
	}
	var route struct {
		Child HarnessChildProcessSpec `json:"child"`
	}
	if err := json.Unmarshal(raw, &route); err != nil || route.Child.ExecutablePath == "" ||
		len(route.Child.ArgumentFileDigests) != 1 || len(route.Child.Arguments) == 0 {
		return nil, nil, errors.New("route lacks an exact verified Harness child closure")
	}
	item := route.Child.ArgumentFileDigests[0]
	if item.Index < 0 || item.Index >= len(route.Child.Arguments) ||
		item.Index != route.Child.RuntimeClosure.EntrypointArgumentIndex || item.SHA256 != route.Child.RuntimeClosure.SHA256 {
		return nil, nil, errors.New("Harness child closure binding is not exact")
	}
	binary, err := openVerifiedAsset(route.Child.ExecutablePath, route.Child.ExecutableSHA256, true)
	if err != nil {
		return nil, nil, err
	}
	entry, err := openVerifiedAsset(route.Child.Arguments[item.Index], item.SHA256, false)
	if err != nil {
		_ = binary.close()
		return nil, nil, err
	}
	return binary, entry, nil
}

func validateAdapterRouteSpec(spec AdapterRouteSpec) error {
	if spec.ProfileBinding == "" || spec.ExecutablePath == "" || spec.AdapterEntrypointPath == "" ||
		spec.RouteConfigPath == "" || spec.WorkingDirectory == "" || spec.StartupTimeout <= 0 || spec.ShutdownTimeout <= 0 {
		return errors.New("complete bounded route process specification required")
	}
	files := []struct {
		path       string
		digest     string
		executable bool
	}{
		{path: spec.ExecutablePath, digest: spec.ExecutableSHA256, executable: true},
		{path: spec.AdapterEntrypointPath, digest: spec.AdapterEntrypointSHA256},
		{path: spec.RouteConfigPath, digest: spec.RouteConfigSHA256},
	}
	for _, file := range files {
		if err := verifyRegularFileDigest(file.path, file.digest, file.executable); err != nil {
			return err
		}
	}
	if info, err := os.Stat(spec.WorkingDirectory); err != nil || !info.IsDir() {
		return errors.New("route working directory unavailable")
	}
	for _, argument := range spec.Arguments {
		if argument == "" || len(argument) > 1024 || strings.IndexByte(argument, 0) >= 0 || secretRE.MatchString(argument) {
			return errors.New("unsafe adapter argument")
		}
	}
	for key, value := range spec.Environment {
		if !isConfiguredHarnessEnvironment(key) || value == "" || len(value) > 4096 ||
			strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("unsafe adapter environment entry")
		}
	}
	return nil
}

func isConfiguredHarnessEnvironment(name string) bool {
	return name == harnessHomeEnvironment || name == harnessPersistenceEnvironment
}

func validateAdapterProcessEnvironment(environment map[string]string, backend BackendKind, localEndpointEnvironment string) error {
	for key, value := range environment {
		allowed := isBaseProcessEnvironment(key) || isConfiguredHarnessEnvironment(key) || key == harnessRouteFDEnvironment
		if backend == BackendRemoteDeepSeek {
			allowed = allowed || key == remoteCredentialEnvironment
		} else if backend == BackendLocalLlamaCPP {
			allowed = allowed || (key == localEndpointEnvironment && strings.HasPrefix(key, "AIPT_"))
		}
		if !allowed || !envNameRE.MatchString(key) || value == "" || len(value) > 64<<10 ||
			strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("adapter process environment is outside the closed allowlist")
		}
	}
	if environment[harnessRouteFDEnvironment] != "5" {
		return errors.New("adapter process route descriptor environment is not exact")
	}
	if backend == BackendRemoteDeepSeek {
		if environment[remoteCredentialEnvironment] == "" || localEndpointEnvironment != "" {
			return errors.New("remote adapter credential environment is not exact")
		}
		return nil
	}
	if backend != BackendLocalLlamaCPP || !strings.HasPrefix(localEndpointEnvironment, "AIPT_") ||
		environment[localEndpointEnvironment] == "" || environment[remoteCredentialEnvironment] != "" {
		return errors.New("local adapter endpoint environment is not exact")
	}
	return nil
}

func (t *AdapterProcessTransport) route(profile ModelProfile) (*adapterRoute, error) {
	if t == nil {
		return nil, newError(CodeHarnessTransport, "resolve_adapter_route", profile.BindingID(), errors.New("nil transport"))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.admissionClosed {
		return nil, newError(CodeHarnessTransport, "resolve_adapter_route", profile.BindingID(), errors.New("transport closed"))
	}
	route := t.routes[profile.BindingID()]
	if route == nil || route.profile.SHA256 != profile.SHA256 {
		return nil, newError(CodeSilentFallback, "resolve_adapter_route", profile.BindingID(), errors.New("exact route unavailable"))
	}
	return route, nil
}

func (t *AdapterProcessTransport) Probe(ctx context.Context, profile ModelProfile, _ SamplingProfile) (HarnessProbe, error) {
	if t != nil {
		t.opMu.RLock()
		defer t.opMu.RUnlock()
	}
	route, err := t.route(profile)
	if err != nil {
		return HarnessProbe{}, err
	}
	params := adapterProbeParams{
		ProfileBinding: profile.BindingID(), ExpectedModelID: profile.ModelID,
		HarnessIdentity: profile.Harness.BindingID(), ProtocolIdentity: profile.Harness.ProtocolIdentity,
		ProtocolVersion: profile.Harness.ProtocolVersion, CapabilityFingerprint: profile.Harness.CapabilityFingerprint,
	}
	raw, err := route.call(ctx, "probe:"+profile.BindingID(), AdapterMethodProbe, params, "")
	if err != nil {
		return HarnessProbe{}, err
	}
	var probe HarnessProbe
	if err := decodeExact(raw, &probe, maxAdapterFrameBytes); err != nil {
		return HarnessProbe{}, newError(CodeHarnessResponseInvalid, "decode_adapter_probe", profile.BindingID(), err)
	}
	return probe, nil
}

func (t *AdapterProcessTransport) Invoke(ctx context.Context, profile ModelProfile, sampling SamplingProfile, request HarnessRequest) (HarnessResult, error) {
	if t != nil {
		t.opMu.RLock()
		defer t.opMu.RUnlock()
	}
	route, err := t.route(profile)
	if err != nil {
		return HarnessResult{}, err
	}
	if err := ValidateSamplingProfile(sampling); err != nil || sampling.BindingID() != profile.SamplingProfileID ||
		request.SamplingBinding != sampling.BindingID() || request.SamplingProfile.SHA256 != sampling.SHA256 {
		return HarnessResult{}, newError(CodeSamplingDrift, "bind_adapter_sampling", request.RequestID, errors.New("exact governed sampling profile is unavailable"))
	}
	raw, err := route.call(ctx, request.RequestID, AdapterMethodInvoke, request, request.Session.SessionID)
	if err != nil {
		return HarnessResult{}, err
	}
	var result HarnessResult
	if err := decodeExact(raw, &result, maxAdapterFrameBytes); err != nil {
		return HarnessResult{}, newError(CodeHarnessResponseInvalid, "decode_adapter_result", request.RequestID, err)
	}
	route.mu.Lock()
	result.RouteRecoveryOccurred = result.RouteRecoveryOccurred || route.recovered
	route.mu.Unlock()
	return result, nil
}

func (t *AdapterProcessTransport) Recover(ctx context.Context, profile ModelProfile, _ orchestrator.Session, _ orchestrator.RecoveryRequest) error {
	if t != nil {
		t.opMu.RLock()
		defer t.opMu.RUnlock()
	}
	route, err := t.route(profile)
	if err != nil {
		return err
	}
	route.mu.Lock()
	defer route.mu.Unlock()
	if err := route.stopLocked(ctx); err != nil {
		return err
	}
	route.recovered = true
	return route.startLocked(ctx)
}

func (t *AdapterProcessTransport) Close(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t.closeMu.Lock()
	defer t.closeMu.Unlock()
	t.mu.Lock()
	if t.closeComplete {
		t.mu.Unlock()
		return nil
	}
	// Close admission before waiting for already-admitted operations. The
	// writer lock below then forms the linearization barrier: every operation
	// which resolved a route either finishes before cleanup or is rejected.
	t.admissionClosed = true
	routes := make([]*adapterRoute, 0, len(t.routeOrder))
	for index := len(t.routeOrder) - 1; index >= 0; index-- {
		routes = append(routes, t.routes[t.routeOrder[index]])
	}
	t.mu.Unlock()
	t.opMu.Lock()
	defer t.opMu.Unlock()
	var failures []error
	for _, route := range routes {
		route.mu.Lock()
		if err := route.stopLocked(ctx); err != nil {
			failures = append(failures, err)
		}
		route.mu.Unlock()
	}
	if len(failures) > 0 {
		// A route that did not settle still owns live process-generation state.
		// Keep the verified assets and make only cleanup retryable. Admission
		// remains permanently closed.
		return errors.Join(failures...)
	}
	t.closeVerifiedAssets()
	t.mu.Lock()
	t.closeComplete = true
	t.mu.Unlock()
	return nil
}

func (r *adapterRoute) call(ctx context.Context, id, method string, params any, sessionID string) (json.RawMessage, error) {
	if ctx == nil {
		return nil, newError(CodeHarnessCancelled, "adapter_call", id, errors.New("nil context"))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil && !r.isolatedRunning {
		if err := r.startLocked(ctx); err != nil {
			return nil, err
		}
	}
	request := adapterRequest{JSONRPC: "2.0", ID: id, ProtocolVersion: AdapterProtocolVersion, Method: method, Params: params}
	if err := writeAdapterFrame(r.stdin, request); err != nil {
		_ = r.stopLocked(context.Background())
		return nil, newError(CodeHarnessTransport, "write_adapter_frame", id, err)
	}
	type readResult struct {
		frame []byte
		err   error
	}
	read := make(chan readResult, 1)
	reader := r.stdout
	go func() {
		frame, err := readAdapterFrame(reader)
		read <- readResult{frame: frame, err: err}
	}()
	select {
	case result := <-read:
		if result.err != nil {
			_ = r.stopLocked(context.Background())
			return nil, newError(frameErrorCode(result.err), "read_adapter_frame", id, result.err)
		}
		return validateAdapterResponse(result.frame, id)
	case <-ctx.Done():
		if sessionID != "" {
			_ = writeAdapterFrame(r.stdin, adapterRequest{
				JSONRPC: "2.0", ID: "cancel:" + id, ProtocolVersion: AdapterProtocolVersion,
				Method: AdapterMethodCancel, Params: map[string]string{"session_id": sessionID},
			})
		}
		_ = r.stopLocked(context.Background())
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, newError(CodeHarnessTimeout, "adapter_call", id, ctx.Err())
		}
		return nil, newError(CodeHarnessCancelled, "adapter_call", id, ctx.Err())
	}
}

func (r *adapterRoute) startLocked(ctx context.Context) error {
	if r.failedStart {
		return newError(CodeHarnessBoot, "start_adapter", r.profile.BindingID(), errors.New("previous failed adapter generation still requires cleanup"))
	}
	if r.cmd != nil || r.isolatedRunning {
		return nil
	}
	if r.isolated != nil {
		stdin, stdout, err := r.isolated.startIsolatedAdapter(ctx)
		if err != nil {
			return err
		}
		r.stdin = stdin
		r.stdout = bufio.NewReaderSize(stdout, 64<<10)
		r.isolatedRunning = true
		r.generation++
		return nil
	}
	binaryFD, err := r.binary.descriptor()
	if err != nil {
		return newError(CodeHarnessTransport, "resolve_verified_adapter_executable", r.profile.BindingID(), err)
	}
	entryFD, err := r.entry.descriptor()
	if err != nil {
		return newError(CodeHarnessTransport, "resolve_verified_adapter_entrypoint", r.profile.BindingID(), err)
	}
	configFD, err := r.config.descriptor()
	if err != nil {
		return newError(CodeHarnessTransport, "resolve_verified_adapter_route", r.profile.BindingID(), err)
	}
	harnessBinaryFD, err := r.harnessBinary.descriptor()
	if err != nil {
		return newError(CodeHarnessTransport, "resolve_verified_harness_executable", r.profile.BindingID(), err)
	}
	harnessEntryFD, err := r.harnessEntry.descriptor()
	if err != nil {
		return newError(CodeHarnessTransport, "resolve_verified_harness_entrypoint", r.profile.BindingID(), err)
	}
	arguments := []string{"--input-type=module", "--eval", adapterNodeBootstrap, "--"}
	arguments = append(arguments, r.spec.Arguments...)
	command := exec.Command(inheritedAssetPath(0), arguments...)
	command.ExtraFiles = []*os.File{binaryFD, entryFD, configFD, harnessBinaryFD, harnessEntryFD}
	command.Dir = r.spec.WorkingDirectory
	environment := allowlistedBaseEnvironment(mapFromEnvironment(os.Environ()))
	for key, value := range r.spec.Environment {
		environment[key] = value
	}
	environment["AIPT_HARNESS_ROUTE_FD"] = "5"
	if r.profile.BackendKind == BackendRemoteDeepSeek {
		bound, err := r.broker.BindChildEnvironment(ctx, *r.profile.CredentialReference, environment)
		if err != nil {
			return err
		}
		environment = bound
	}
	if err := validateAdapterProcessEnvironment(environment, r.profile.BackendKind, ""); err != nil {
		return newError(CodeHarnessTransport, "validate_adapter_process_environment", r.profile.BindingID(), err)
	}
	command.Env = exactEnvironmentList(environment)
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true, PidFD: &pidfd,
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return newError(CodeHarnessTransport, "pipe_adapter_stdin", r.profile.BindingID(), err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return newError(CodeHarnessTransport, "pipe_adapter_stdout", r.profile.BindingID(), err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return newError(CodeHarnessTransport, "pipe_adapter_stderr", r.profile.BindingID(), err)
	}
	if err := command.Start(); err != nil {
		return newError(CodeHarnessTransport, "exec_adapter", r.profile.BindingID(), err)
	}
	exit := make(chan error, 1)
	go func() {
		exit <- command.Wait()
		close(exit)
	}()
	process, err := bindManagedProcessIdentity(command.Process, pidfd)
	if err != nil {
		_ = command.Process.Kill()
		go func() { _, _ = io.Copy(io.Discard, stdout) }()
		go func() { _, _ = io.Copy(io.Discard, stderr) }()
		if !waitProcessExit(exit, boundedCleanupTimeout(r.spec.ShutdownTimeout)) {
			return newError(CodeHarnessTransport, "cleanup_unbound_adapter", r.profile.BindingID(), errors.New("killed process did not settle within the cleanup bound"))
		}
		return newError(CodeLocalProcessMismatch, "bind_adapter_process_generation", r.profile.BindingID(), err)
	}
	go func() { _, _ = io.Copy(io.Discard, stderr) }()
	r.cmd = command
	r.process = process
	r.stdin = stdin
	r.stdout = bufio.NewReaderSize(stdout, 64<<10)
	r.exit = exit
	r.failedStart = true
	if err := verifyProcessExecutableAsset(command.Process.Pid, r.binary); err != nil {
		cleanupErr := r.abortFailedStartLocked("cleanup_unverified_adapter")
		return errors.Join(newError(CodeLocalProcessMismatch, "verify_adapter_process", r.profile.BindingID(), err), cleanupErr)
	}
	if !processNamespaceDiffers(command.Process.Pid, "pid") {
		cleanupErr := r.abortFailedStartLocked("cleanup_unisolated_adapter")
		return errors.Join(newError(CodeLocalProcessMismatch, "verify_adapter_pid_namespace", r.profile.BindingID(), errors.New("adapter did not enter a private PID namespace")), cleanupErr)
	}
	r.failedStart = false
	r.generation++
	return nil
}

func (r *adapterRoute) abortFailedStartLocked(operation string) error {
	if r.cmd == nil || r.process == nil || r.exit == nil {
		return newError(CodeHarnessTransport, operation, r.profile.BindingID(), errors.New("failed adapter ownership is unavailable"))
	}
	command := r.cmd
	process := r.process
	exit := r.exit
	if r.stdin != nil {
		_ = r.stdin.Close()
	}
	_ = terminateOwnedProcessGroup(process, syscall.SIGKILL)
	if !waitProcessExit(exit, boundedCleanupTimeout(r.spec.ShutdownTimeout)) {
		return newError(CodeHarnessTransport, operation, r.profile.BindingID(), errors.New("killed process did not settle within the cleanup bound; ownership retained for retry"))
	}
	if r.cmd == command {
		r.cmd = nil
		r.process = nil
		r.stdin = nil
		r.stdout = nil
		r.exit = nil
		r.failedStart = false
	}
	process.close()
	return nil
}

func exactEnvironmentList(environment map[string]string) []string {
	result := make([]string, 0, len(environment))
	for key, value := range environment {
		result = append(result, key+"="+value)
	}
	sortStrings(result)
	return result
}

func (r *adapterRoute) stopLocked(ctx context.Context) error {
	if r.isolated != nil {
		if !r.isolatedRunning {
			return nil
		}
		if err := r.isolated.stopIsolatedAdapter(ctx); err != nil {
			return err
		}
		r.isolatedRunning = false
		r.stdin = nil
		r.stdout = nil
		return nil
	}
	if r.cmd == nil {
		return nil
	}
	command := r.cmd
	process := r.process
	stdin := r.stdin
	exit := r.exit
	_ = stdin.Close()
	_ = terminateOwnedProcessGroup(process, syscall.SIGTERM)
	shutdown := r.spec.ShutdownTimeout
	if shutdown <= 0 {
		shutdown = 5 * time.Second
	}
	timer := time.NewTimer(shutdown)
	defer timer.Stop()
	var failure error
	settled := false
	select {
	case <-exit:
		settled = true
	case <-ctx.Done():
		failure = ctx.Err()
		_ = terminateOwnedProcessGroup(process, syscall.SIGKILL)
		settled = waitProcessExit(exit, boundedCleanupTimeout(shutdown))
	case <-timer.C:
		failure = errors.New("adapter shutdown timed out")
		_ = terminateOwnedProcessGroup(process, syscall.SIGKILL)
		settled = waitProcessExit(exit, boundedCleanupTimeout(shutdown))
	}
	if !settled {
		return newError(CodeHarnessTransport, "stop_adapter", r.profile.BindingID(), errors.Join(failure, errors.New("killed process did not settle within the cleanup bound")))
	}
	if r.cmd == command {
		r.cmd = nil
		r.process = nil
		r.stdin = nil
		r.stdout = nil
		r.exit = nil
		r.failedStart = false
	}
	process.close()
	if failure != nil {
		return newError(CodeHarnessTransport, "stop_adapter", r.profile.BindingID(), failure)
	}
	return nil
}

func writeAdapterFrame(writer io.Writer, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > maxAdapterFrameBytes || bytes.IndexByte(raw, '\n') >= 0 {
		return errors.New("adapter frame exceeds bound")
	}
	raw = append(raw, '\n')
	_, err = writer.Write(raw)
	return err
}

func readAdapterFrame(reader *bufio.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("adapter reader unavailable")
	}
	var frame bytes.Buffer
	for {
		part, err := reader.ReadSlice('\n')
		if frame.Len()+len(part) > maxAdapterFrameBytes+1 {
			return nil, newError(CodeHarnessFrameTooLarge, "read_frame", "", errors.New("adapter frame exceeds bound"))
		}
		frame.Write(part)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
	raw := frame.Bytes()
	if len(raw) < 2 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("partial adapter frame")
	}
	raw = raw[:len(raw)-1]
	if !json.Valid(raw) {
		return nil, errors.New("malformed adapter frame")
	}
	return append([]byte(nil), raw...), nil
}

func frameErrorCode(err error) Code {
	if CodeOf(err) == CodeHarnessFrameTooLarge {
		return CodeHarnessFrameTooLarge
	}
	return CodeHarnessResponseInvalid
}

func validateAdapterResponse(raw []byte, id string) (json.RawMessage, error) {
	var response adapterResponse
	if err := decodeExact(raw, &response, maxAdapterFrameBytes); err != nil {
		return nil, newError(CodeHarnessResponseInvalid, "decode_adapter_frame", id, err)
	}
	if response.JSONRPC != "2.0" || response.ProtocolVersion != AdapterProtocolVersion || response.ID != id ||
		(response.Error == nil) == (len(response.Result) == 0) {
		return nil, newError(CodeHarnessProtocolMismatch, "validate_adapter_frame", id, errors.New("unknown response identity/schema/version"))
	}
	if response.Error != nil {
		return nil, newError(adapterFailureCode(response.Error.Code), "adapter_result", id, errors.New("adapter returned stable failure "+strconv.Quote(response.Error.Code)))
	}
	return append(json.RawMessage(nil), response.Result...), nil
}

func adapterFailureCode(code string) Code {
	switch code {
	case "AIPT_MODEL_GATEWAY_IDENTITY_MISMATCH":
		return CodeHarnessIdentityMismatch
	case "AIPT_MODEL_GATEWAY_FRAME_INVALID", "AIPT_MODEL_GATEWAY_CONFIG_INVALID":
		return CodeHarnessResponseInvalid
	case "AIPT_MODEL_GATEWAY_HARNESS_BOOT_FAILED":
		return CodeHarnessBoot
	case "AIPT_MODEL_GATEWAY_SESSION_FAILED":
		return CodeHarnessSession
	case "AIPT_MODEL_GATEWAY_MODEL_REQUEST_FAILED":
		return CodeModelRequestFailed
	case "AIPT_MODEL_GATEWAY_TIMEOUT":
		return CodeHarnessTimeout
	case "AIPT_MODEL_GATEWAY_CANCELLED":
		return CodeHarnessCancelled
	default:
		return CodeHarnessTransport
	}
}
