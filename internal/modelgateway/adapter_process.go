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
	"path/filepath"
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
	profile ModelProfile
	spec    AdapterRouteSpec
	broker  CredentialBroker

	mu         sync.Mutex
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	stdout     *bufio.Reader
	exit       chan error
	generation int
	recovered  bool
}

// AdapterProcessTransport is the only production HarnessTransport. It speaks
// the additive, versioned JSON-RPC contract implemented by
// @aipt/harness-adapter/model-process-worker. That worker alone speaks ACP to
// the external DeepSeek Harness; Core has no provider or inference endpoint.
type AdapterProcessTransport struct {
	routes     map[string]*adapterRoute
	routeOrder []string
	mu         sync.Mutex
	closed     bool
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
			return nil, newError(CodeHarnessTransport, "register_adapter_route", spec.ProfileBinding, errors.New("unknown or duplicate route profile"))
		}
		if err := validateAdapterRouteSpec(spec); err != nil {
			return nil, newError(CodeHarnessTransport, "validate_adapter_route", spec.ProfileBinding, err)
		}
		if profile.BackendKind == BackendRemoteDeepSeek && broker == nil {
			return nil, newError(CodeCredentialUnavailable, "register_adapter_route", spec.ProfileBinding, errors.New("credential broker required"))
		}
		transport.routes[spec.ProfileBinding] = &adapterRoute{profile: profile, spec: spec, broker: broker}
		transport.routeOrder = append(transport.routeOrder, spec.ProfileBinding)
	}
	return transport, nil
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
		if !envNameRE.MatchString(key) || key == "DEEPSEEK_API_KEY" || secretRE.MatchString(key) ||
			value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("unsafe adapter environment entry")
		}
	}
	return nil
}

func (t *AdapterProcessTransport) route(profile ModelProfile) (*adapterRoute, error) {
	if t == nil {
		return nil, newError(CodeHarnessTransport, "resolve_adapter_route", profile.BindingID(), errors.New("nil transport"))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, newError(CodeHarnessTransport, "resolve_adapter_route", profile.BindingID(), errors.New("transport closed"))
	}
	route := t.routes[profile.BindingID()]
	if route == nil || route.profile.SHA256 != profile.SHA256 {
		return nil, newError(CodeSilentFallback, "resolve_adapter_route", profile.BindingID(), errors.New("exact route unavailable"))
	}
	return route, nil
}

func (t *AdapterProcessTransport) Probe(ctx context.Context, profile ModelProfile, _ SamplingProfile) (HarnessProbe, error) {
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

func (t *AdapterProcessTransport) Invoke(ctx context.Context, profile ModelProfile, _ SamplingProfile, request HarnessRequest) (HarnessResult, error) {
	route, err := t.route(profile)
	if err != nil {
		return HarnessResult{}, err
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
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	routes := make([]*adapterRoute, 0, len(t.routeOrder))
	for index := len(t.routeOrder) - 1; index >= 0; index-- {
		routes = append(routes, t.routes[t.routeOrder[index]])
	}
	t.mu.Unlock()
	var failures []error
	for _, route := range routes {
		route.mu.Lock()
		if err := route.stopLocked(ctx); err != nil {
			failures = append(failures, err)
		}
		route.mu.Unlock()
	}
	return errors.Join(failures...)
}

func (r *adapterRoute) call(ctx context.Context, id, method string, params any, sessionID string) (json.RawMessage, error) {
	if ctx == nil {
		return nil, newError(CodeHarnessCancelled, "adapter_call", id, errors.New("nil context"))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil {
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
	if r.cmd != nil {
		return nil
	}
	executable, _ := filepath.Abs(r.spec.ExecutablePath)
	entrypoint, _ := filepath.Abs(r.spec.AdapterEntrypointPath)
	arguments := append([]string{entrypoint}, r.spec.Arguments...)
	command := exec.Command(executable, arguments...)
	command.Dir = r.spec.WorkingDirectory
	environment := allowlistedBaseEnvironment(mapFromEnvironment(os.Environ()))
	for key, value := range r.spec.Environment {
		environment[key] = value
	}
	environment["AIPT_HARNESS_ROUTE_CONFIG"] = r.spec.RouteConfigPath
	if r.profile.BackendKind == BackendRemoteDeepSeek {
		bound, err := r.broker.BindChildEnvironment(ctx, *r.profile.CredentialReference, environment)
		if err != nil {
			return err
		}
		environment = bound
	}
	command.Env = exactEnvironmentList(environment)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	if err := verifyProcessExecutable(command.Process.Pid, executable); err != nil {
		_ = terminateProcessGroup(command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return newError(CodeLocalProcessMismatch, "verify_adapter_process", r.profile.BindingID(), err)
	}
	go func() { _, _ = io.Copy(io.Discard, stderr) }()
	r.cmd = command
	r.stdin = stdin
	r.stdout = bufio.NewReaderSize(stdout, 64<<10)
	r.exit = make(chan error, 1)
	r.generation++
	exit := r.exit
	go func() {
		err := command.Wait()
		exit <- err
		close(exit)
	}()
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
	if r.cmd == nil {
		return nil
	}
	command := r.cmd
	stdin := r.stdin
	exit := r.exit
	pid := command.Process.Pid
	_ = stdin.Close()
	_ = terminateProcessGroup(pid, syscall.SIGTERM)
	shutdown := r.spec.ShutdownTimeout
	if shutdown <= 0 {
		shutdown = 5 * time.Second
	}
	timer := time.NewTimer(shutdown)
	defer timer.Stop()
	var failure error
	select {
	case <-exit:
	case <-ctx.Done():
		failure = ctx.Err()
		_ = terminateProcessGroup(pid, syscall.SIGKILL)
		<-exit
	case <-timer.C:
		failure = errors.New("adapter shutdown timed out")
		_ = terminateProcessGroup(pid, syscall.SIGKILL)
		<-exit
	}
	if r.cmd == command {
		r.cmd = nil
		r.stdin = nil
		r.stdout = nil
		r.exit = nil
	}
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
