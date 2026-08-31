package modelgateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	isolationProtocolSchema = "aipt.runtime-isolation-control/v1"
	isolationMaxFrameBytes  = 256 * 1024
)

type isolationControlMessage struct {
	Schema                   string            `json:"schema"`
	Operation                string            `json:"operation"`
	ProfileBinding           string            `json:"profile_binding,omitempty"`
	ModelID                  string            `json:"model_id,omitempty"`
	TemplateSHA256           string            `json:"template_sha256,omitempty"`
	AdditionalArguments      []string          `json:"additional_arguments,omitempty"`
	LlamaEnvironment         map[string]string `json:"llama_environment,omitempty"`
	LlamaWorkingDirectory    string            `json:"llama_working_directory,omitempty"`
	AdapterEnvironment       map[string]string `json:"adapter_environment,omitempty"`
	AdapterArguments         []string          `json:"adapter_arguments,omitempty"`
	AdapterWorkingDirectory  string            `json:"adapter_working_directory,omitempty"`
	LocalEndpointEnvironment string            `json:"local_endpoint_environment,omitempty"`
	StartupTimeoutMS         int64             `json:"startup_timeout_ms,omitempty"`
	ShutdownTimeoutMS        int64             `json:"shutdown_timeout_ms,omitempty"`
}

type isolationControlResponse struct {
	Schema            string `json:"schema"`
	Operation         string `json:"operation"`
	Result            string `json:"result"`
	Code              string `json:"code,omitempty"`
	Port              int    `json:"port,omitempty"`
	AdapterPID        int    `json:"adapter_pid,omitempty"`
	IsolationIdentity string `json:"isolation_identity,omitempty"`
	FailureStage      string `json:"failure_stage,omitempty"`
}

type isolationStageError struct {
	stage string
	cause error
}

func (e *isolationStageError) Error() string { return e.stage }
func (e *isolationStageError) Unwrap() error { return e.cause }

func isolationFailure(stage string, cause error) error {
	return &isolationStageError{stage: stage, cause: cause}
}

func writeIsolationFrame(connection *net.UnixConn, value any) error {
	if connection == nil {
		return errors.New("isolation control unavailable")
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > isolationMaxFrameBytes {
		return errors.New("isolation control frame invalid")
	}
	_, err = connection.Write(raw)
	return err
}

func readIsolationFrame[T any](connection *net.UnixConn, value *T) error {
	if connection == nil || value == nil {
		return errors.New("isolation control unavailable")
	}
	buffer := make([]byte, isolationMaxFrameBytes+1)
	count, err := connection.Read(buffer)
	if err != nil {
		return err
	}
	if count == 0 || count > isolationMaxFrameBytes {
		return errors.New("isolation control frame exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(buffer[:count]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("isolation control frame has trailing data")
	}
	return nil
}

func unixSeqpacketPair() (*net.UnixConn, *os.File, error) {
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	parentFile := os.NewFile(uintptr(descriptors[0]), "aipt-isolation-control-parent")
	childFile := os.NewFile(uintptr(descriptors[1]), "aipt-isolation-control-child")
	if parentFile == nil || childFile == nil {
		if parentFile != nil {
			_ = parentFile.Close()
		}
		if childFile != nil {
			_ = childFile.Close()
		}
		return nil, nil, errors.New("isolation control descriptors unavailable")
	}
	raw, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = childFile.Close()
		return nil, nil, err
	}
	connection, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		_ = childFile.Close()
		return nil, nil, errors.New("isolation control is not a Unix seqpacket socket")
	}
	return connection, childFile, nil
}

func (m *ManagedLlama) PrepareIsolatedAdapter(spec AdapterRouteSpec, endpointEnvironment string) error {
	if m == nil {
		return errors.New("managed local runtime unavailable")
	}
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	m.mu.Lock()
	if m.retired || m.state != managedStopped || m.adapter != nil {
		m.mu.Unlock()
		return newError(CodeHarnessTransport, "prepare_isolated_adapter", m.profile.BindingID(), errors.New("adapter assets must be bound exactly once before model startup"))
	}
	m.mu.Unlock()
	if spec.ProfileBinding != m.profile.BindingID() || !envNameRE.MatchString(endpointEnvironment) {
		return newError(CodeHarnessTransport, "prepare_isolated_adapter", m.profile.BindingID(), errors.New("adapter profile or endpoint environment binding differs"))
	}
	if err := validateAdapterRouteSpec(spec); err != nil {
		return newError(CodeHarnessTransport, "prepare_isolated_adapter", m.profile.BindingID(), err)
	}
	binary, err := openVerifiedAsset(spec.ExecutablePath, spec.ExecutableSHA256, true)
	if err != nil {
		return newError(CodeHarnessTransport, "prepare_isolated_adapter_executable", m.profile.BindingID(), err)
	}
	entry, err := openVerifiedAsset(spec.AdapterEntrypointPath, spec.AdapterEntrypointSHA256, false)
	if err != nil {
		_ = binary.close()
		return newError(CodeHarnessTransport, "prepare_isolated_adapter_entrypoint", m.profile.BindingID(), err)
	}
	config, err := openVerifiedAsset(spec.RouteConfigPath, spec.RouteConfigSHA256, false)
	if err != nil {
		_ = binary.close()
		_ = entry.close()
		return newError(CodeHarnessTransport, "prepare_isolated_adapter_route", m.profile.BindingID(), err)
	}
	harnessBinary, harnessEntry, err := openVerifiedHarnessChildAssets(config)
	if err != nil {
		_ = binary.close()
		_ = entry.close()
		_ = config.close()
		return newError(CodeHarnessTransport, "prepare_isolated_harness_assets", m.profile.BindingID(), err)
	}
	m.mu.Lock()
	m.adapter = &preparedIsolatedAdapter{
		spec: spec, endpointEnv: endpointEnvironment, binary: binary, entry: entry, config: config,
		harnessBinary: harnessBinary, harnessEntry: harnessEntry,
	}
	m.mu.Unlock()
	return nil
}

func (m *ManagedLlama) isolatedAdapterMatches(spec AdapterRouteSpec) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prepared := m.adapter
	return prepared != nil && prepared.spec.ProfileBinding == spec.ProfileBinding &&
		prepared.spec.ExecutableSHA256 == spec.ExecutableSHA256 &&
		prepared.spec.AdapterEntrypointSHA256 == spec.AdapterEntrypointSHA256 &&
		prepared.spec.RouteConfigSHA256 == spec.RouteConfigSHA256 &&
		prepared.spec.ExecutablePath == spec.ExecutablePath &&
		prepared.spec.AdapterEntrypointPath == spec.AdapterEntrypointPath &&
		prepared.spec.RouteConfigPath == spec.RouteConfigPath &&
		prepared.spec.WorkingDirectory == spec.WorkingDirectory &&
		prepared.spec.StartupTimeout == spec.StartupTimeout &&
		prepared.spec.ShutdownTimeout == spec.ShutdownTimeout &&
		slices.Equal(prepared.spec.Arguments, spec.Arguments) &&
		maps.Equal(prepared.spec.Environment, spec.Environment)
}

func (m *ManagedLlama) startIsolatedLifecycle(ctx context.Context) error {
	if ctx == nil {
		return newError(CodeLocalStartupFailed, "start_isolated_llama", m.profile.BindingID(), errors.New("nil context"))
	}
	m.mu.Lock()
	if m.retired || m.state != managedStopped {
		m.mu.Unlock()
		return newError(CodeLocalStartupFailed, "start_isolated_llama", m.profile.BindingID(), errors.New("managed runtime is not startable"))
	}
	m.state = managedStarting
	prepared := m.adapter
	m.mu.Unlock()

	isolatorFD, err := m.isolator.descriptor()
	if err != nil {
		m.resetIsolatedStartFailure()
		return newError(CodeLocalBinaryMismatch, "resolve_runtime_isolator", m.profile.BindingID(), err)
	}
	binaryFD, err := m.binary.descriptor()
	if err != nil {
		m.resetIsolatedStartFailure()
		return newError(CodeLocalBinaryMismatch, "resolve_verified_llama_binary", m.profile.BindingID(), err)
	}
	ggufFD, err := m.gguf.descriptor()
	if err != nil {
		m.resetIsolatedStartFailure()
		return newError(CodeLocalGGUFMismatch, "resolve_verified_llama_gguf", m.profile.BindingID(), err)
	}
	control, childControl, err := unixSeqpacketPair()
	if err != nil {
		m.resetIsolatedStartFailure()
		return newError(CodeLocalStartupFailed, "create_isolation_control", m.profile.BindingID(), err)
	}
	inputReader, inputWriter, err := os.Pipe()
	if err != nil {
		_ = control.Close()
		_ = childControl.Close()
		m.resetIsolatedStartFailure()
		return newError(CodeLocalStartupFailed, "create_isolated_adapter_input", m.profile.BindingID(), err)
	}
	outputReader, outputWriter, err := os.Pipe()
	if err != nil {
		_ = control.Close()
		_ = childControl.Close()
		_ = inputReader.Close()
		_ = inputWriter.Close()
		m.resetIsolatedStartFailure()
		return newError(CodeLocalStartupFailed, "create_isolated_adapter_output", m.profile.BindingID(), err)
	}
	placeholder, err := os.Open(os.DevNull)
	if err != nil {
		_ = control.Close()
		_ = childControl.Close()
		_ = inputReader.Close()
		_ = inputWriter.Close()
		_ = outputReader.Close()
		_ = outputWriter.Close()
		m.resetIsolatedStartFailure()
		return newError(CodeLocalStartupFailed, "open_isolation_placeholder", m.profile.BindingID(), err)
	}
	adapterBinary, adapterEntry, adapterConfig := placeholder, placeholder, placeholder
	harnessBinary, harnessEntry := placeholder, placeholder
	if prepared != nil {
		adapterBinary, err = prepared.binary.descriptor()
		if err == nil {
			adapterEntry, err = prepared.entry.descriptor()
		}
		if err == nil {
			adapterConfig, err = prepared.config.descriptor()
		}
		if err == nil {
			harnessBinary, err = prepared.harnessBinary.descriptor()
		}
		if err == nil {
			harnessEntry, err = prepared.harnessEntry.descriptor()
		}
	}
	if err != nil {
		_ = placeholder.Close()
		_ = control.Close()
		_ = childControl.Close()
		_ = inputReader.Close()
		_ = inputWriter.Close()
		_ = outputReader.Close()
		_ = outputWriter.Close()
		m.resetIsolatedStartFailure()
		return newError(CodeHarnessTransport, "resolve_isolated_adapter_assets", m.profile.BindingID(), err)
	}
	command := exec.Command(inheritedAssetPath(0), m.spec.IsolationArguments...)
	command.ExtraFiles = []*os.File{
		isolatorFD, childControl, binaryFD, ggufFD, adapterBinary, adapterEntry, adapterConfig,
		inputReader, outputWriter, harnessBinary, harnessEntry,
	}
	command.Env = exactEnvironmentList(map[string]string{
		"LANG": "C.UTF-8", "TZ": "UTC", "AIPT_RUNTIME_ISOLATOR": "1",
	})
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Setpgid:                    true, PidFD: &pidfd,
	}
	if err := command.Start(); err != nil {
		_ = placeholder.Close()
		_ = control.Close()
		_ = childControl.Close()
		_ = inputReader.Close()
		_ = inputWriter.Close()
		_ = outputReader.Close()
		_ = outputWriter.Close()
		m.resetIsolatedStartFailure()
		return newError(CodeLocalStartupFailed, "exec_runtime_isolator", m.profile.BindingID(), err)
	}
	_ = placeholder.Close()
	_ = childControl.Close()
	_ = inputReader.Close()
	_ = outputWriter.Close()
	exit := make(chan error, 1)
	go func() {
		exit <- command.Wait()
		close(exit)
	}()
	process, err := bindManagedProcessIdentity(command.Process, pidfd)
	if err != nil {
		_ = command.Process.Kill()
		_ = waitProcessExit(exit, boundedCleanupTimeout(m.spec.ShutdownTimeout))
		_ = control.Close()
		_ = inputWriter.Close()
		_ = outputReader.Close()
		m.resetIsolatedStartFailure()
		return newError(CodeLocalProcessMismatch, "bind_runtime_isolator_generation", m.profile.BindingID(), err)
	}
	if err := verifyProcessExecutableAsset(command.Process.Pid, m.isolator); err != nil {
		cleanupErr := m.abortIsolatedStart(command, process, exit, control, inputWriter, outputReader, nil)
		return errors.Join(newError(CodeLocalProcessMismatch, "verify_runtime_isolator", m.profile.BindingID(), err), cleanupErr)
	}
	hostNetNS, hostErr := os.Stat("/proc/self/ns/net")
	childNetNS, childErr := os.Stat(fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))
	if hostErr != nil || childErr != nil || os.SameFile(hostNetNS, childNetNS) ||
		!processNamespaceDiffers(command.Process.Pid, "pid") || !processNamespaceDiffers(command.Process.Pid, "mnt") {
		cleanupErr := m.abortIsolatedStart(command, process, exit, control, inputWriter, outputReader, childNetNS)
		return errors.Join(newError(CodeLocalEndpointNotLoopback, "verify_private_network_namespace", m.profile.BindingID(), errors.New("runtime isolator did not enter distinct network and PID namespaces")), cleanupErr)
	}
	adapterEnvironment := map[string]string{}
	var adapterArguments []string
	adapterDirectory := ""
	endpointEnvironment := ""
	if prepared != nil {
		adapterEnvironment = cloneStringMap(prepared.spec.Environment)
		adapterArguments = append([]string(nil), prepared.spec.Arguments...)
		adapterDirectory = prepared.spec.WorkingDirectory
		endpointEnvironment = prepared.endpointEnv
	}
	request := isolationControlMessage{
		Schema: isolationProtocolSchema, Operation: "START_MODEL", ProfileBinding: m.profile.BindingID(),
		ModelID: m.profile.ModelID, TemplateSHA256: m.profile.LocalRuntimeIdentity.TemplateSHA256,
		AdditionalArguments: append([]string(nil), m.spec.AdditionalArguments...),
		LlamaEnvironment:    cloneStringMap(m.spec.Environment), LlamaWorkingDirectory: m.spec.WorkingDirectory,
		AdapterEnvironment: adapterEnvironment, AdapterWorkingDirectory: adapterDirectory,
		AdapterArguments:         adapterArguments,
		LocalEndpointEnvironment: endpointEnvironment,
		StartupTimeoutMS:         m.spec.StartupTimeout.Milliseconds(), ShutdownTimeoutMS: m.spec.ShutdownTimeout.Milliseconds(),
	}
	// The supervisor owns its own readiness deadline and then needs a fixed
	// cleanup/reply envelope. Give that inner owner time to report its bounded
	// failure instead of racing it with the same parent deadline.
	startupContext, cancel := context.WithTimeout(ctx, m.spec.StartupTimeout+boundedCleanupTimeout(m.spec.ShutdownTimeout)+time.Second)
	defer cancel()
	if deadline, ok := startupContext.Deadline(); ok {
		_ = control.SetDeadline(deadline)
	}
	if err := writeIsolationFrame(control, request); err != nil {
		cleanupErr := m.abortIsolatedStart(command, process, exit, control, inputWriter, outputReader, childNetNS)
		return errors.Join(newError(CodeLocalStartupFailed, "start_isolated_model", m.profile.BindingID(), err), cleanupErr)
	}
	var response isolationControlResponse
	responseErr := readIsolationFrame(control, &response)
	if responseErr != nil || response.Schema != isolationProtocolSchema ||
		response.Operation != "START_MODEL" || response.Result != "PASS" || response.Port < 1 ||
		response.IsolationIdentity != LocalIsolationIdentity {
		cause := errors.New("isolated model readiness failed")
		if responseErr != nil {
			cause = responseErr
		} else if response.Code != "" {
			cause = Sentinel(Code(response.Code))
		}
		operation := "start_isolated_model"
		if response.FailureStage != "" {
			operation += "_" + response.FailureStage
		}
		cleanupErr := m.abortIsolatedStart(command, process, exit, control, inputWriter, outputReader, childNetNS)
		return errors.Join(newError(CodeLocalReadinessFailed, operation, m.profile.BindingID(), cause), cleanupErr)
	}
	_ = control.SetDeadline(time.Time{})
	endpoint, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", response.Port))
	m.mu.Lock()
	if m.state != managedStarting {
		m.mu.Unlock()
		cleanupErr := m.abortIsolatedStart(command, process, exit, control, inputWriter, outputReader, childNetNS)
		return errors.Join(newError(CodeLocalStartupFailed, "publish_isolated_model", m.profile.BindingID(), errors.New("model generation changed during isolated startup")), cleanupErr)
	}
	m.cmd = command
	m.process = process
	m.target = endpoint
	m.endpoint = endpoint
	m.exit = exit
	m.isolationControl = control
	m.isolationInput = inputWriter
	m.isolationOutput = outputReader
	m.isolationNetNS = childNetNS
	m.state = managedRunning
	m.mu.Unlock()
	go m.observeIsolatorExit(command, exit)
	return nil
}

func (m *ManagedLlama) abortIsolatedStart(
	command *exec.Cmd,
	process *managedProcessIdentity,
	exit chan error,
	control *net.UnixConn,
	input *os.File,
	output *os.File,
	netNS os.FileInfo,
) error {
	_ = terminateOwnedProcessGroup(process, syscall.SIGKILL)
	settled := waitProcessExit(exit, boundedCleanupTimeout(m.spec.ShutdownTimeout))
	if !settled {
		m.mu.Lock()
		if m.state == managedStarting {
			m.cmd = command
			m.process = process
			m.exit = exit
			m.isolationControl = control
			m.isolationInput = input
			m.isolationOutput = output
			m.isolationNetNS = netNS
			m.state = managedCrashed
		}
		m.mu.Unlock()
		return newError(CodeLocalShutdownFailed, "cleanup_failed_isolated_start", m.profile.BindingID(), errors.New("isolation supervisor did not settle; process ownership retained for retry"))
	}
	process.close()
	_ = control.Close()
	_ = input.Close()
	_ = output.Close()
	m.resetIsolatedStartFailure()
	return nil
}

func (m *ManagedLlama) resetIsolatedStartFailure() {
	m.mu.Lock()
	if m.state == managedStarting {
		m.state = managedStopped
	}
	m.mu.Unlock()
}

func (m *ManagedLlama) observeIsolatorExit(command *exec.Cmd, exit <-chan error) {
	<-exit
	m.mu.Lock()
	if m.cmd == command && (m.state == managedRunning || m.state == managedStarting) {
		m.state = managedCrashed
	}
	m.mu.Unlock()
}

func (m *ManagedLlama) isolatedEndpoint() (*url.URL, error) {
	m.mu.Lock()
	if m.state != managedRunning || m.endpoint == nil || m.process == nil || m.isolationNetNS == nil {
		m.mu.Unlock()
		return nil, newError(CodeLocalEndpointNotLoopback, "isolated_llama_endpoint", m.profile.BindingID(), errors.New("isolated endpoint unavailable"))
	}
	endpoint := *m.endpoint
	process := m.process
	netIdentity := m.isolationNetNS
	m.mu.Unlock()
	if !IsIPv4LoopbackURL(&endpoint) || process.requireAlive() != nil {
		return nil, newError(CodeLocalEndpointNotLoopback, "isolated_llama_endpoint", m.profile.BindingID(), errors.New("isolated endpoint identity unavailable"))
	}
	observed, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", process.pid))
	if err != nil || !os.SameFile(observed, netIdentity) {
		return nil, newError(CodeLocalEndpointNotLoopback, "isolated_llama_endpoint", m.profile.BindingID(), errors.New("network namespace generation drift"))
	}
	return &endpoint, nil
}

func (m *ManagedLlama) startIsolatedAdapter(ctx context.Context) (io.WriteCloser, io.Reader, error) {
	if ctx == nil {
		return nil, nil, newError(CodeHarnessTransport, "start_isolated_adapter", m.profile.BindingID(), errors.New("context required"))
	}
	m.isolationControlMu.Lock()
	defer m.isolationControlMu.Unlock()
	m.mu.Lock()
	control := m.isolationControl
	input := m.isolationInput
	output := m.isolationOutput
	ready := m.state == managedRunning && m.adapter != nil && !m.isolationAdapterRunning
	m.mu.Unlock()
	if !ready || control == nil || input == nil || output == nil {
		return nil, nil, newError(CodeHarnessTransport, "start_isolated_adapter", m.profile.BindingID(), errors.New("isolated adapter route unavailable"))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(deadline)
	}
	if err := writeIsolationFrame(control, isolationControlMessage{Schema: isolationProtocolSchema, Operation: "START_ADAPTER"}); err != nil {
		return nil, nil, newError(CodeHarnessTransport, "start_isolated_adapter", m.profile.BindingID(), err)
	}
	var response isolationControlResponse
	responseErr := readIsolationFrame(control, &response)
	if responseErr != nil || response.Schema != isolationProtocolSchema ||
		response.Operation != "START_ADAPTER" || response.Result != "PASS" || response.AdapterPID <= 1 {
		cause := errors.New("isolated adapter spawn failed")
		if responseErr != nil {
			cause = responseErr
		} else if response.Code != "" {
			cause = Sentinel(Code(response.Code))
		}
		operation := "start_isolated_adapter"
		if response.FailureStage != "" {
			operation += "_" + response.FailureStage
		}
		return nil, nil, newError(CodeHarnessBoot, operation, m.profile.BindingID(), cause)
	}
	_ = control.SetDeadline(time.Time{})
	m.mu.Lock()
	m.isolationAdapterRunning = true
	m.mu.Unlock()
	return nopWriteCloser{Writer: input}, output, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func (m *ManagedLlama) stopIsolatedAdapter(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.isolationControlMu.Lock()
	defer m.isolationControlMu.Unlock()
	m.mu.Lock()
	running := m.isolationAdapterRunning
	control := m.isolationControl
	m.mu.Unlock()
	if !running {
		return nil
	}
	deadline := time.Now().Add(m.spec.ShutdownTimeout + time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = control.SetDeadline(deadline)
	writeErr := writeIsolationFrame(control, isolationControlMessage{Schema: isolationProtocolSchema, Operation: "STOP_ADAPTER"})
	var response isolationControlResponse
	readErr := readIsolationFrame(control, &response)
	_ = control.SetDeadline(time.Time{})
	if writeErr != nil || readErr != nil || response.Schema != isolationProtocolSchema ||
		response.Operation != "STOP_ADAPTER" || response.Result != "PASS" {
		return newError(CodeHarnessTransport, "stop_isolated_adapter", m.profile.BindingID(), errors.New("isolated adapter cleanup failed"))
	}
	m.mu.Lock()
	m.isolationAdapterRunning = false
	m.mu.Unlock()
	return nil
}

func (m *ManagedLlama) stopIsolatedLifecycle(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	adapterErr := m.stopIsolatedAdapter(ctx)
	m.isolationControlMu.Lock()
	defer m.isolationControlMu.Unlock()
	m.mu.Lock()
	command := m.cmd
	process := m.process
	exit := m.exit
	state := m.state
	control := m.isolationControl
	input := m.isolationInput
	output := m.isolationOutput
	if command == nil || m.state == managedStopped {
		m.clearIsolatedStateLocked()
		m.mu.Unlock()
		if control != nil {
			_ = control.Close()
		}
		if input != nil {
			_ = input.Close()
		}
		if output != nil {
			_ = output.Close()
		}
		if process != nil {
			process.close()
		}
		return adapterErr
	}
	m.state = managedStopping
	m.mu.Unlock()
	deadline := time.Now().Add(m.spec.ShutdownTimeout + time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = control.SetDeadline(deadline)
	var requestErr, responseErr error
	var response isolationControlResponse
	if state != managedCrashed {
		requestErr = writeIsolationFrame(control, isolationControlMessage{Schema: isolationProtocolSchema, Operation: "STOP_ALL"})
		responseErr = readIsolationFrame(control, &response)
	} else {
		response = isolationControlResponse{Schema: isolationProtocolSchema, Operation: "STOP_ALL", Result: "PASS"}
	}
	_ = control.SetDeadline(time.Time{})
	settled := waitProcessExit(exit, boundedCleanupTimeout(m.spec.ShutdownTimeout))
	if !settled {
		_ = terminateOwnedProcessGroup(process, syscall.SIGKILL)
		settled = waitProcessExit(exit, boundedCleanupTimeout(m.spec.ShutdownTimeout))
	}
	if !settled {
		m.mu.Lock()
		if m.cmd == command {
			m.state = managedCrashed
		}
		m.mu.Unlock()
		return errors.Join(adapterErr, newError(CodeLocalShutdownFailed, "stop_runtime_isolator", m.profile.BindingID(), errors.New("isolation supervisor did not settle within the cleanup bound")))
	}
	_ = control.Close()
	_ = input.Close()
	_ = output.Close()
	process.close()
	m.mu.Lock()
	if m.cmd == command {
		m.clearIsolatedStateLocked()
	}
	m.mu.Unlock()
	if requestErr != nil || responseErr != nil || response.Result != "PASS" {
		return errors.Join(adapterErr, newError(CodeLocalShutdownFailed, "stop_runtime_isolator", m.profile.BindingID(), errors.New("isolation supervisor cleanup failed")))
	}
	return adapterErr
}

func (m *ManagedLlama) clearIsolatedStateLocked() {
	m.cmd = nil
	m.process = nil
	m.target = nil
	m.endpoint = nil
	m.exit = nil
	m.isolationControl = nil
	m.isolationInput = nil
	m.isolationOutput = nil
	m.isolationNetNS = nil
	m.isolationAdapterRunning = false
	m.state = managedStopped
}

// RunRuntimeIsolator is the fixed entrypoint used by cmd/aipt-runtime-isolator
// and the synthetic test helper. The parent must create this process with a
// new user and network namespace; the helper never accepts a host TCP route.
func RunRuntimeIsolator() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if os.Getenv("AIPT_RUNTIME_ISOLATOR") != "1" {
		return errors.New("runtime isolator activation missing")
	}
	if err := mountPrivateProc(); err != nil {
		return err
	}
	if err := bringLoopbackUp(); err != nil {
		return err
	}
	controlFile := os.NewFile(4, "aipt-isolator-control")
	if controlFile == nil {
		return errors.New("runtime isolator control unavailable")
	}
	raw, err := net.FileConn(controlFile)
	_ = controlFile.Close()
	if err != nil {
		return err
	}
	control, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return errors.New("runtime isolator control is not Unix seqpacket")
	}
	defer control.Close()
	var initial isolationControlMessage
	if err := readIsolationFrame(control, &initial); err != nil {
		return err
	}
	supervisor, err := newIsolationSupervisor(control, initial)
	if err != nil {
		code := CodeOf(err)
		if code == "" {
			code = CodeLocalReadinessFailed
		}
		stage := "SUPERVISOR_START"
		var staged *isolationStageError
		if errors.As(err, &staged) {
			stage = staged.stage
		}
		_ = writeIsolationFrame(control, isolationControlResponse{
			Schema: isolationProtocolSchema, Operation: "START_MODEL", Result: "FAIL", Code: string(code), FailureStage: stage,
		})
		return err
	}
	defer func() { _ = supervisor.stopAll() }()
	if err := writeIsolationFrame(control, isolationControlResponse{
		Schema: isolationProtocolSchema, Operation: "START_MODEL", Result: "PASS", Port: supervisor.port,
		IsolationIdentity: LocalIsolationIdentity,
	}); err != nil {
		return err
	}
	return supervisor.loop()
}

type isolationSupervisor struct {
	control        *net.UnixConn
	initial        isolationControlMessage
	port           int
	llama          *exec.Cmd
	llamaProcess   *managedProcessIdentity
	llamaExit      chan error
	adapter        *exec.Cmd
	adapterProcess *managedProcessIdentity
	adapterExit    chan error
}

func newIsolationSupervisor(control *net.UnixConn, initial isolationControlMessage) (*isolationSupervisor, error) {
	if initial.Schema != isolationProtocolSchema || initial.Operation != "START_MODEL" ||
		initial.ProfileBinding == "" || initial.ModelID == "" || validSHA("template_sha256", initial.TemplateSHA256) != nil ||
		initial.LlamaWorkingDirectory == "" || initial.StartupTimeoutMS < 1 || initial.StartupTimeoutMS > 600_000 ||
		initial.ShutdownTimeoutMS < 1 || initial.ShutdownTimeoutMS > 60_000 {
		return nil, errors.New("invalid isolated model start contract")
	}
	for _, argument := range initial.AdditionalArguments {
		if unsafeLlamaArgument(argument) {
			return nil, errors.New("invalid isolated llama argument")
		}
	}
	for _, argument := range initial.AdapterArguments {
		if argument == "" || len(argument) > 1024 || strings.IndexByte(argument, 0) >= 0 || secretRE.MatchString(argument) {
			return nil, errors.New("invalid isolated adapter argument")
		}
	}
	port, err := reserveIPv4LoopbackPort()
	if err != nil {
		return nil, err
	}
	supervisor := &isolationSupervisor{control: control, initial: initial, port: port}
	if err := supervisor.startLlama(); err != nil {
		return nil, errors.Join(err, supervisor.stopAll())
	}
	return supervisor, nil
}

func inheritedFile(fd uintptr, name string) (*os.File, error) {
	file := os.NewFile(fd, name)
	if file == nil {
		return nil, errors.New("inherited runtime asset unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("inherited runtime asset is not regular")
	}
	return file, nil
}

func (s *isolationSupervisor) startLlama() error {
	binary, err := inheritedFile(5, "isolated-llama-binary")
	if err != nil {
		return isolationFailure("LLAMA_BINARY_FD", err)
	}
	gguf, err := inheritedFile(6, "isolated-llama-gguf")
	if err != nil {
		return isolationFailure("LLAMA_GGUF_FD", err)
	}
	arguments := append([]string(nil), s.initial.AdditionalArguments...)
	arguments = append(arguments,
		"--model", inheritedAssetPath(1), "--host", "127.0.0.1", "--port", strconv.Itoa(s.port),
		"--alias", s.initial.ModelID, "--no-webui", "--no-slots", "--jinja",
	)
	command := exec.Command(inheritedAssetPath(0), arguments...)
	command.ExtraFiles = []*os.File{binary, gguf}
	command.Dir = s.initial.LlamaWorkingDirectory
	command.Env = environmentList(s.initial.LlamaEnvironment)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return isolationFailure("LLAMA_STDOUT_PIPE", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return isolationFailure("LLAMA_STDERR_PIPE", err)
	}
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}
	if err := command.Start(); err != nil {
		return isolationFailure("LLAMA_EXEC", err)
	}
	go drainBounded(stdout)
	go drainBounded(stderr)
	exit := make(chan error, 1)
	go func() {
		exit <- command.Wait()
		close(exit)
	}()
	process, err := bindManagedProcessIdentity(command.Process, pidfd)
	if err != nil {
		_ = command.Process.Kill()
		settled := waitProcessExit(exit, time.Second)
		if !settled {
			return isolationFailure("LLAMA_PROCESS_IDENTITY", errors.Join(err, errors.New("unbound llama process did not settle after kill")))
		}
		return isolationFailure("LLAMA_PROCESS_IDENTITY", err)
	}
	s.llama = command
	s.llamaProcess = process
	s.llamaExit = exit
	info, _ := binary.Stat()
	if err := verifyProcessExecutableAsset(command.Process.Pid, &verifiedAsset{file: binary, info: info}); err != nil {
		return isolationFailure("LLAMA_EXECUTABLE_IDENTITY", errors.Join(err, s.stopLlama()))
	}
	readyContext, cancel := context.WithTimeout(context.Background(), time.Duration(s.initial.StartupTimeoutMS)*time.Millisecond)
	defer cancel()
	if err := waitIsolatedLlamaReady(readyContext, process, s.port, s.initial.ModelID, s.initial.TemplateSHA256); err != nil {
		return errors.Join(err, s.stopLlama())
	}
	return nil
}

func waitIsolatedLlamaReady(ctx context.Context, process *managedProcessIdentity, port int, modelID, templateSHA string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		if _, err := verifyManagedListenerOwnership(process, port); err == nil {
			if err := probeIsolatedLlama(ctx, port, modelID, templateSHA); err == nil {
				return nil
			} else {
				last = err
				if CodeOf(err) == CodeModelIdentityMismatch || CodeOf(err) == CodeLocalTemplateMismatch {
					return isolationFailure("LLAMA_IDENTITY_PROBE", err)
				}
			}
		} else {
			last = err
			var ownership *listenerOwnershipError
			if !errors.Is(err, errManagedListenerNotReady) && errors.As(err, &ownership) {
				return isolationFailure("LLAMA_LISTENER_OWNERSHIP", newError(CodeLocalProcessMismatch, "verify_isolated_listener", "", err))
			}
		}
		select {
		case <-ctx.Done():
			return isolationFailure("LLAMA_READINESS_TIMEOUT", errors.Join(ctx.Err(), last))
		case <-ticker.C:
		}
	}
}

func probeIsolatedLlama(ctx context.Context, port int, modelID, templateSHA string) error {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	get := func(path string, limit int64) ([]byte, error) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
		response, err := client.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("isolated readiness endpoint rejected")
		}
		return io.ReadAll(io.LimitReader(response.Body, limit))
	}
	if _, err := get("/health", 4<<10); err != nil {
		return err
	}
	raw, err := get("/v1/models", 64<<10)
	if err != nil {
		return err
	}
	var models struct {
		Models []json.RawMessage `json:"models"`
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	var native struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	}
	var openAI struct {
		ID string `json:"id"`
	}
	if decodeExact(raw, &models, 64<<10) != nil || models.Object != "list" || len(models.Models) != 1 ||
		len(models.Data) != 1 || json.Unmarshal(models.Models[0], &native) != nil ||
		json.Unmarshal(models.Data[0], &openAI) != nil || native.Name != modelID || native.Model != modelID ||
		openAI.ID != modelID {
		return newError(CodeModelIdentityMismatch, "probe_isolated_model", modelID, errors.New("isolated model identity mismatch"))
	}
	raw, err = get("/props", 1<<20)
	if err != nil {
		return err
	}
	var props struct {
		ChatTemplate string `json:"chat_template"`
	}
	if json.Unmarshal(raw, &props) != nil || props.ChatTemplate == "" {
		return newError(CodeLocalTemplateMismatch, "probe_isolated_template", modelID, errors.New("isolated template unavailable"))
	}
	digest := sha256.Sum256([]byte(props.ChatTemplate))
	if hex.EncodeToString(digest[:]) != templateSHA {
		return newError(CodeLocalTemplateMismatch, "probe_isolated_template", modelID, errors.New("isolated template identity mismatch"))
	}
	return nil
}

func (s *isolationSupervisor) loop() error {
	requests := make(chan isolationControlMessage)
	readFailures := make(chan error, 1)
	go func() {
		for {
			var request isolationControlMessage
			if err := readIsolationFrame(s.control, &request); err != nil {
				readFailures <- err
				return
			}
			requests <- request
		}
	}()
	for {
		select {
		case <-s.llamaExit:
			return errors.New("isolated llama exited")
		case <-s.adapterExit:
			return errors.New("isolated adapter exited")
		case err := <-readFailures:
			return err
		case request := <-requests:
			if request.Schema != isolationProtocolSchema {
				return errors.New("isolation protocol mismatch")
			}
			switch request.Operation {
			case "START_ADAPTER":
				err := s.startAdapter()
				response := isolationControlResponse{Schema: isolationProtocolSchema, Operation: request.Operation, Result: "PASS"}
				if err != nil {
					response.Result = "FAIL"
					code := CodeOf(err)
					if code == "" {
						code = CodeHarnessBoot
					}
					response.Code = string(code)
					var staged *isolationStageError
					if errors.As(err, &staged) {
						response.FailureStage = staged.stage
					}
				} else {
					response.AdapterPID = s.adapter.Process.Pid
				}
				if writeIsolationFrame(s.control, response) != nil {
					return errors.New("isolation response failed")
				}
			case "STOP_ADAPTER":
				cleanupErr := s.stopAdapter()
				response := isolationControlResponse{Schema: isolationProtocolSchema, Operation: request.Operation, Result: "PASS"}
				if cleanupErr != nil {
					response.Result = "FAIL"
					response.Code = string(CodeLocalShutdownFailed)
				}
				if writeIsolationFrame(s.control, response) != nil {
					return errors.New("isolation response failed")
				}
			case "STOP_ALL":
				cleanupErr := s.stopAll()
				response := isolationControlResponse{Schema: isolationProtocolSchema, Operation: request.Operation, Result: "PASS"}
				if cleanupErr != nil {
					response.Result = "FAIL"
					response.Code = string(CodeLocalShutdownFailed)
				}
				_ = writeIsolationFrame(s.control, response)
				return cleanupErr
			default:
				return errors.New("unknown isolation operation")
			}
		}
	}
}

func (s *isolationSupervisor) startAdapter() error {
	if s.adapter != nil {
		return errors.New("isolated adapter already running")
	}
	if s.initial.AdapterWorkingDirectory == "" || !envNameRE.MatchString(s.initial.LocalEndpointEnvironment) {
		return errors.New("isolated adapter was not prepared")
	}
	binary, err := inheritedFile(7, "isolated-adapter-binary")
	if err != nil {
		return isolationFailure("ADAPTER_BINARY_FD", err)
	}
	entry, err := inheritedFile(8, "isolated-adapter-entry")
	if err != nil {
		return isolationFailure("ADAPTER_ENTRY_FD", err)
	}
	config, err := inheritedFile(9, "isolated-adapter-config")
	if err != nil {
		return isolationFailure("ADAPTER_CONFIG_FD", err)
	}
	harnessBinary, err := inheritedFile(12, "isolated-harness-binary")
	if err != nil {
		return isolationFailure("HARNESS_BINARY_FD", err)
	}
	harnessEntry, err := inheritedFile(13, "isolated-harness-entry")
	if err != nil {
		return isolationFailure("HARNESS_ENTRY_FD", err)
	}
	input := os.NewFile(10, "isolated-adapter-input")
	output := os.NewFile(11, "isolated-adapter-output")
	if input == nil || output == nil {
		return isolationFailure("ADAPTER_STREAM_FD", errors.New("isolated adapter streams unavailable"))
	}
	arguments := []string{"--no-warnings", "--input-type=module", "--eval", adapterNodeBootstrap, "--"}
	arguments = append(arguments, s.initial.AdapterArguments...)
	command := exec.Command(inheritedAssetPath(0), arguments...)
	command.ExtraFiles = []*os.File{binary, entry, config, harnessBinary, harnessEntry}
	command.Dir = s.initial.AdapterWorkingDirectory
	environment := allowlistedBaseEnvironment(mapFromEnvironment(os.Environ()))
	for key, value := range s.initial.AdapterEnvironment {
		environment[key] = value
	}
	environment[s.initial.LocalEndpointEnvironment] = fmt.Sprintf("http://127.0.0.1:%d", s.port)
	environment[harnessRouteFDEnvironment] = "5"
	if err := validateAdapterProcessEnvironment(environment, BackendLocalLlamaCPP, s.initial.LocalEndpointEnvironment); err != nil {
		return isolationFailure("ADAPTER_ENVIRONMENT", err)
	}
	command.Env = exactEnvironmentList(environment)
	command.Stdin = input
	command.Stdout = output
	command.Stderr = io.Discard
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}
	if err := command.Start(); err != nil {
		return isolationFailure("ADAPTER_EXEC", err)
	}
	exit := make(chan error, 1)
	go func() {
		exit <- command.Wait()
		close(exit)
	}()
	process, err := bindManagedProcessIdentity(command.Process, pidfd)
	if err != nil {
		_ = command.Process.Kill()
		settled := waitProcessExit(exit, time.Second)
		if !settled {
			return isolationFailure("ADAPTER_PROCESS_IDENTITY", errors.Join(err, errors.New("unbound adapter process did not settle after kill")))
		}
		return isolationFailure("ADAPTER_PROCESS_IDENTITY", err)
	}
	s.adapter = command
	s.adapterProcess = process
	s.adapterExit = exit
	info, _ := binary.Stat()
	if err := verifyProcessExecutableAsset(command.Process.Pid, &verifiedAsset{file: binary, info: info}); err != nil {
		stage := "ADAPTER_EXECUTABLE_IDENTITY"
		if process.requireAlive() != nil {
			stage = "ADAPTER_EARLY_EXIT"
		}
		return isolationFailure(stage, errors.Join(err, s.stopAdapter()))
	}
	return nil
}

func (s *isolationSupervisor) stopAdapter() error {
	if s.adapter == nil {
		return nil
	}
	_ = terminateOwnedProcessGroup(s.adapterProcess, syscall.SIGTERM)
	settled := waitProcessExit(s.adapterExit, time.Duration(s.initial.ShutdownTimeoutMS)*time.Millisecond)
	if !settled {
		_ = terminateOwnedProcessGroup(s.adapterProcess, syscall.SIGKILL)
		settled = waitProcessExit(s.adapterExit, time.Second)
	}
	if !settled {
		return errors.New("isolated adapter did not settle after SIGKILL")
	}
	if err := s.killNonLlamaNamespaceProcesses(); err != nil {
		return err
	}
	s.adapterProcess.close()
	s.adapter = nil
	s.adapterProcess = nil
	s.adapterExit = nil
	return nil
}

func (s *isolationSupervisor) killNonLlamaNamespaceProcesses() error {
	deadline := time.Now().Add(boundedCleanupTimeout(time.Duration(s.initial.ShutdownTimeoutMS) * time.Millisecond))
	for {
		pids, err := nonLlamaNamespaceProcessIDs(os.Getpid(), s.llama)
		if err != nil {
			return errors.New("enumerate isolated adapter descendants")
		}
		if len(pids) == 0 {
			return nil
		}
		for _, pid := range pids {
			process, err := os.FindProcess(pid)
			if err != nil {
				return errors.New("bind isolated adapter descendant")
			}
			retained := false
			handleErr := process.WithHandle(func(_ uintptr) { retained = true })
			if handleErr != nil || !retained {
				_ = process.Release()
				return errors.New("bind isolated adapter descendant generation")
			}
			signalErr := process.Signal(syscall.SIGKILL)
			_ = process.Release()
			if signalErr != nil && !errors.Is(signalErr, os.ErrProcessDone) {
				return errors.New("kill isolated adapter descendant")
			}
		}
		if !time.Now().Before(deadline) {
			return errors.New("isolated adapter descendants did not settle after SIGKILL")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func nonLlamaNamespaceProcessIDs(supervisorPID int, llama *exec.Cmd) ([]int, error) {
	if supervisorPID != 1 {
		return nil, errors.New("runtime isolation supervisor is not PID namespace init")
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	type processFact struct {
		parent int
		state  byte
	}
	facts := make(map[int]processFact)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		closeIndex := bytes.LastIndexByte(raw, ')')
		if closeIndex < 0 || closeIndex+2 >= len(raw) {
			return nil, errors.New("invalid process stat record")
		}
		fields := strings.Fields(string(raw[closeIndex+1:]))
		if len(fields) < 2 || len(fields[0]) != 1 {
			return nil, errors.New("invalid process stat fields")
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, errors.New("invalid process parent identity")
		}
		facts[pid] = processFact{parent: parent, state: fields[0][0]}
	}
	llamaPID := 0
	if llama != nil && llama.Process != nil {
		llamaPID = llama.Process.Pid
	}
	isLlamaProcess := func(pid int) bool {
		for seen := 0; pid > 0 && seen <= len(facts); seen++ {
			if pid == llamaPID && llamaPID > 0 {
				return true
			}
			fact, exists := facts[pid]
			if !exists || fact.parent == pid {
				return false
			}
			pid = fact.parent
		}
		return false
	}
	result := make([]int, 0)
	for pid, fact := range facts {
		if pid == supervisorPID || fact.state == 'Z' || isLlamaProcess(pid) {
			continue
		}
		result = append(result, pid)
	}
	slices.Sort(result)
	return result, nil
}

func (s *isolationSupervisor) stopLlama() error {
	if s.llama == nil {
		return nil
	}
	_ = terminateOwnedProcessGroup(s.llamaProcess, syscall.SIGTERM)
	settled := waitProcessExit(s.llamaExit, time.Duration(s.initial.ShutdownTimeoutMS)*time.Millisecond)
	if !settled {
		_ = terminateOwnedProcessGroup(s.llamaProcess, syscall.SIGKILL)
		settled = waitProcessExit(s.llamaExit, time.Second)
	}
	if !settled {
		return errors.New("isolated llama did not settle after SIGKILL")
	}
	s.llamaProcess.close()
	s.llama = nil
	s.llamaProcess = nil
	s.llamaExit = nil
	return nil
}

func (s *isolationSupervisor) stopAll() error {
	return errors.Join(s.stopAdapter(), s.stopLlama())
}

type ifreqFlags struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

func bringLoopbackUp() error {
	descriptor, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(descriptor)
	request := ifreqFlags{}
	copy(request.Name[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(descriptor), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&request))); errno != 0 {
		return errno
	}
	request.Flags |= syscall.IFF_UP
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(descriptor), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&request))); errno != 0 {
		return errno
	}
	return nil
}

func isolatedNetNamespaceDiffers(pid int) bool {
	return processNamespaceDiffers(pid, "net")
}

func processNamespaceDiffers(pid int, namespace string) bool {
	if pid <= 1 || (namespace != "net" && namespace != "pid" && namespace != "mnt") {
		return false
	}
	host, hostErr := os.Stat(filepath.Join("/proc/self/ns", namespace))
	child, childErr := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns", namespace))
	return hostErr == nil && childErr == nil && !os.SameFile(host, child)
}

func mountPrivateProc() error {
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return err
	}
	if err := syscall.Mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return err
	}
	if os.Getpid() != 1 {
		return errors.New("runtime isolator is not PID namespace init")
	}
	return nil
}

func endpointUnreachableFromHost(ctx context.Context, endpoint *url.URL) bool {
	if !IsIPv4LoopbackURL(endpoint) {
		return false
	}
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "tcp4", endpoint.Host)
	if err != nil {
		return true
	}
	_ = connection.Close()
	return false
}

func sanitizeIsolationArguments(arguments []string) error {
	for _, argument := range arguments {
		if argument == "" || len(argument) > 1024 || strings.IndexByte(argument, 0) >= 0 ||
			secretRE.MatchString(argument) || filepathIsAbs(argument) {
			return errors.New("unsafe isolation helper argument")
		}
	}
	return nil
}

func filepathIsAbs(value string) bool {
	return strings.HasPrefix(value, "/") || (len(value) > 2 && value[1] == ':' && (value[2] == '\\' || value[2] == '/'))
}
