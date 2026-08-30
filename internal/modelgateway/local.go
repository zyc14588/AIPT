package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	DynamicPortMarker = "{DYNAMIC_IPV4_LOOPBACK_PORT}"
	GGUFPathMarker    = "{REGISTERED_GGUF}"
)

// ManagedLlamaSpec contains private, operator-selected paths. These values are
// runtime inputs only and are never copied into public evidence.
type ManagedLlamaSpec struct {
	ExecutablePath      string
	GGUFPath            string
	AdditionalArguments []string
	Environment         map[string]string
	WorkingDirectory    string
	StartupTimeout      time.Duration
	ShutdownTimeout     time.Duration
}

// GovernedLaunchParameters is the path-free identity recorded in a Model
// Profile. It deliberately includes no download/router/UI flags.
func GovernedLaunchParameters(additional []string) ([]string, error) {
	if len(additional) > 32 {
		return nil, newError(CodeLocalProcessMismatch, "govern_launch_parameters", "", errors.New("too many additional arguments"))
	}
	result := make([]string, 0, len(additional)+11)
	for _, argument := range additional {
		if unsafeLlamaArgument(argument) {
			return nil, newError(CodeLocalProcessMismatch, "govern_launch_parameters", "", errors.New("unsafe local argument"))
		}
		result = append(result, argument)
	}
	result = append(result,
		"--model", GGUFPathMarker,
		"--host", "127.0.0.1",
		"--port", DynamicPortMarker,
		"--alias", "{REGISTERED_MODEL_ID}",
		"--no-webui", "--no-slots", "--jinja",
	)
	return result, nil
}

func unsafeLlamaArgument(argument string) bool {
	if argument == "" || len(argument) > 1024 || strings.IndexByte(argument, 0) >= 0 ||
		secretRE.MatchString(argument) || absPathRE.MatchString(argument) {
		return true
	}
	lower := strings.ToLower(argument)
	for _, forbidden := range []string{
		"--model", "-m", "--model-url", "--hf-repo", "-hfr", "--hf-file",
		"--docker-repo", "--host", "--port", "--alias", "--api-key", "--api-key-file",
		"--webui", "--ui", "--models-dir", "--models-preset", "--models-autoload",
		"--chat-template", "--chat-template-file", "--no-jinja",
	} {
		if lower == forbidden || strings.HasPrefix(lower, forbidden+"=") {
			return true
		}
	}
	return false
}

type managedProcessState string

const (
	managedStopped  managedProcessState = "STOPPED"
	managedStarting managedProcessState = "STARTING"
	managedRunning  managedProcessState = "RUNNING"
	managedStopping managedProcessState = "STOPPING"
	managedCrashed  managedProcessState = "CRASHED"
)

// ManagedLlama owns exactly one registered llama.cpp process. A model switch
// requires constructing and starting another manager after stopping this one.
type ManagedLlama struct {
	profile ModelProfile
	spec    ManagedLlamaSpec

	mu        sync.Mutex
	cmd       *exec.Cmd
	process   *managedProcessIdentity
	target    *url.URL
	endpoint  *url.URL
	proxy     *http.Server
	proxyNet  net.Listener
	proxyHTTP *http.Transport
	state     managedProcessState
	recovered bool
	exit      chan error
}

func NewManagedLlama(profile ModelProfile, spec ManagedLlamaSpec) (*ManagedLlama, error) {
	if err := ValidateModelProfile(profile); err != nil {
		return nil, err
	}
	if profile.BackendKind != BackendLocalLlamaCPP || profile.LocalRuntimeIdentity == nil {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), errors.New("local profile required"))
	}
	if spec.ExecutablePath == "" || spec.GGUFPath == "" || spec.WorkingDirectory == "" ||
		spec.StartupTimeout <= 0 || spec.ShutdownTimeout <= 0 {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), errors.New("complete bounded process spec required"))
	}
	wantArgs, err := GovernedLaunchParameters(spec.AdditionalArguments)
	if err != nil {
		return nil, err
	}
	if strings.Join(wantArgs, "\x00") != strings.Join(profile.LocalRuntimeIdentity.LaunchParameters, "\x00") {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), errors.New("launch-parameter identity mismatch"))
	}
	if err := verifyRegularFileDigest(spec.ExecutablePath, profile.LocalRuntimeIdentity.BinarySHA256, true); err != nil {
		return nil, newError(CodeLocalBinaryMismatch, "verify_llama_binary", profile.BindingID(), err)
	}
	if err := verifyRegularFileDigest(spec.GGUFPath, profile.LocalRuntimeIdentity.GGUFSHA256, false); err != nil {
		return nil, newError(CodeLocalGGUFMismatch, "verify_llama_gguf", profile.BindingID(), err)
	}
	working, err := filepath.Abs(spec.WorkingDirectory)
	if err != nil {
		return nil, newError(CodeLocalProcessMismatch, "resolve_llama_workdir", profile.BindingID(), err)
	}
	info, err := os.Stat(working)
	if err != nil || !info.IsDir() {
		return nil, newError(CodeLocalProcessMismatch, "verify_llama_workdir", profile.BindingID(), errors.New("working directory unavailable"))
	}
	spec.WorkingDirectory = working
	return &ManagedLlama{profile: profile, spec: spec, state: managedStopped}, nil
}

func verifyRegularFileDigest(path, expected string, executable bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("registered asset is not a regular file")
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return errors.New("registered executable is not executable")
	}
	file, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("registered asset digest mismatch")
	}
	return nil
}

func reserveIPv4LoopbackPort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func (m *ManagedLlama) Start(ctx context.Context) error {
	if ctx == nil {
		return newError(CodeLocalStartupFailed, "start_llama", m.profile.BindingID(), errors.New("nil context"))
	}
	m.mu.Lock()
	if m.state != managedStopped {
		m.mu.Unlock()
		return newError(CodeLocalStartupFailed, "start_llama", m.profile.BindingID(), errors.New("managed runtime is not stopped"))
	}
	port, err := reserveIPv4LoopbackPort()
	if err != nil {
		m.mu.Unlock()
		return newError(CodeLocalStartupFailed, "allocate_loopback", m.profile.BindingID(), err)
	}
	executable, _ := filepath.Abs(m.spec.ExecutablePath)
	gguf, _ := filepath.Abs(m.spec.GGUFPath)
	arguments := append([]string(nil), m.spec.AdditionalArguments...)
	arguments = append(arguments,
		"--model", gguf,
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--alias", m.profile.ModelID,
		"--no-webui", "--no-slots", "--jinja",
	)
	command := exec.Command(executable, arguments...)
	command.Dir = m.spec.WorkingDirectory
	command.Env = environmentList(m.spec.Environment)
	pidfd := -1
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}
	stdout, err := command.StdoutPipe()
	if err != nil {
		m.mu.Unlock()
		return newError(CodeLocalStartupFailed, "pipe_llama_stdout", m.profile.BindingID(), err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		m.mu.Unlock()
		return newError(CodeLocalStartupFailed, "pipe_llama_stderr", m.profile.BindingID(), err)
	}
	if err := command.Start(); err != nil {
		m.mu.Unlock()
		return newError(CodeLocalStartupFailed, "exec_llama", m.profile.BindingID(), err)
	}
	process, err := bindManagedProcessIdentity(command.Process, pidfd)
	if err != nil {
		_ = terminateProcessGroup(command.Process.Pid, syscall.SIGKILL)
		_, _ = io.Copy(io.Discard, stdout)
		_, _ = io.Copy(io.Discard, stderr)
		_ = command.Wait()
		m.mu.Unlock()
		return newError(CodeLocalProcessMismatch, "bind_llama_process_generation", m.profile.BindingID(), err)
	}
	if err := verifyProcessExecutable(command.Process.Pid, executable); err != nil {
		_ = terminateProcessGroup(command.Process.Pid, syscall.SIGKILL)
		_, _ = io.Copy(io.Discard, stdout)
		_, _ = io.Copy(io.Discard, stderr)
		_ = command.Wait()
		process.close()
		m.mu.Unlock()
		return newError(CodeLocalProcessMismatch, "verify_llama_process", m.profile.BindingID(), err)
	}
	go drainBounded(stdout)
	go drainBounded(stderr)
	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	m.cmd = command
	m.process = process
	m.target = target
	m.endpoint = nil
	m.state = managedStarting
	m.exit = make(chan error, 1)
	exit := m.exit
	m.mu.Unlock()
	go func() {
		err := command.Wait()
		m.mu.Lock()
		var proxyHTTP *http.Transport
		if m.cmd == command && (m.state == managedStarting || m.state == managedRunning) {
			m.state = managedCrashed
			proxyHTTP = m.proxyHTTP
		}
		m.mu.Unlock()
		if proxyHTTP != nil {
			proxyHTTP.CloseIdleConnections()
		}
		exit <- err
		close(exit)
	}()

	startupContext, cancel := context.WithTimeout(ctx, m.spec.StartupTimeout)
	defer cancel()
	if err := m.startGuardedProxy(command, process); err != nil {
		_ = m.Stop(context.Background())
		return newError(CodeLocalReadinessFailed, "guard_llama_endpoint", m.profile.BindingID(), err)
	}
	if err := m.waitReady(startupContext); err != nil {
		_ = m.Stop(context.Background())
		return newError(CodeLocalReadinessFailed, "probe_llama", m.profile.BindingID(), err)
	}
	m.mu.Lock()
	if m.cmd != command || m.process != process || m.state != managedStarting || m.endpoint == nil || m.proxy == nil || m.proxyNet == nil {
		m.mu.Unlock()
		_ = m.Stop(context.Background())
		return newError(CodeLocalReadinessFailed, "finalize_llama_startup", m.profile.BindingID(), errors.New("managed process changed during startup"))
	}
	m.state = managedRunning
	m.mu.Unlock()
	return nil
}

func (m *ManagedLlama) startGuardedProxy(command *exec.Cmd, process *managedProcessIdentity) error {
	m.mu.Lock()
	if m.cmd != command || m.process != process || m.target == nil || m.state != managedStarting {
		m.mu.Unlock()
		return ownershipMismatch("managed target changed before proxy startup")
	}
	target := *m.target
	m.mu.Unlock()
	port, err := strconv.Atoi(target.Port())
	if err != nil {
		return ownershipMismatch("managed target port is invalid")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	front, _ := url.Parse("http://" + listener.Addr().String())
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if (network != "tcp" && network != "tcp4") || address != target.Host {
				return nil, ownershipMismatch("guarded proxy attempted an unexpected upstream")
			}
			if err := m.requireManagedGenerationActive(command, process); err != nil {
				return nil, err
			}
			return dialManagedListener(ctx, process, port)
		},
	}
	reverse := httputil.NewSingleHostReverseProxy(&target)
	reverse.Transport = transport
	reverse.ErrorLog = log.New(io.Discard, "", 0)
	reverse.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		writeGuardedProxyFailure(writer)
	}
	guardedHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := m.requireManagedGenerationActive(command, process); err != nil {
			writeGuardedProxyFailure(writer)
			return
		}
		reverse.ServeHTTP(writer, request)
	})
	server := &http.Server{
		Handler: guardedHandler, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	m.mu.Lock()
	if m.cmd != command || m.process != process || m.target == nil || m.target.String() != target.String() || m.state != managedStarting {
		m.mu.Unlock()
		_ = listener.Close()
		transport.CloseIdleConnections()
		return ownershipMismatch("managed target changed during proxy startup")
	}
	m.endpoint = front
	m.proxy = server
	m.proxyNet = listener
	m.proxyHTTP = transport
	m.mu.Unlock()
	go func() {
		err := server.Serve(listener)
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return
		}
		m.mu.Lock()
		active := m.proxy == server && (m.state == managedStarting || m.state == managedRunning)
		if active {
			m.state = managedCrashed
		}
		m.mu.Unlock()
		if active {
			_ = terminateProcessGroup(command.Process.Pid, syscall.SIGKILL)
		}
	}()
	return nil
}

func writeGuardedProxyFailure(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusBadGateway)
}

func (m *ManagedLlama) requireManagedGenerationActive(command *exec.Cmd, process *managedProcessIdentity) error {
	m.mu.Lock()
	active := m.cmd == command && m.process == process &&
		(m.state == managedStarting || m.state == managedRunning)
	m.mu.Unlock()
	if !active {
		return ownershipMismatch("managed process generation is not active")
	}
	return process.requireAlive()
}

func environmentList(values map[string]string) []string {
	base := allowlistedBaseEnvironment(mapFromEnvironment(os.Environ()))
	for key, value := range values {
		if envNameRE.MatchString(key) && value != "" && !strings.ContainsAny(value, "\r\n\x00") && !secretRE.MatchString(key) {
			base[key] = value
		}
	}
	result := make([]string, 0, len(base))
	for key, value := range base {
		result = append(result, key+"="+value)
	}
	sortStrings(result)
	return result
}

func mapFromEnvironment(entries []string) map[string]string {
	result := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, found := strings.Cut(entry, "=")
		if found {
			result[key] = value
		}
	}
	return result
}

func sortStrings(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}

func verifyProcessExecutable(pid int, expected string) error {
	observed, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	observedInfo, err := os.Stat(observed)
	if err != nil {
		return err
	}
	expectedInfo, err := os.Stat(expected)
	if err != nil {
		return err
	}
	if !os.SameFile(observedInfo, expectedInfo) {
		return errors.New("managed process executable differs from registration")
	}
	return nil
}

func drainBounded(reader io.Reader) {
	// Output is deliberately discarded, but it must be drained for the whole
	// process lifetime. Stopping after a diagnostic byte cap can fill the child
	// pipe and deadlock an otherwise healthy managed runtime.
	_, _ = io.Copy(io.Discard, reader)
}

func (m *ManagedLlama) waitReady(ctx context.Context) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.Lock()
		command := m.cmd
		process := m.process
		endpoint := m.target
		m.mu.Unlock()
		if command == nil || process == nil || endpoint == nil {
			return errors.New("managed process identity unavailable during startup")
		}
		port, portErr := strconv.Atoi(endpoint.Port())
		if portErr != nil {
			return newError(CodeLocalProcessMismatch, "verify_llama_listener", m.profile.BindingID(), errors.New("selected listener port is invalid"))
		}
		before, ownershipErr := verifyManagedListenerOwnership(process, port)
		if ownershipErr == nil {
			probeErr := m.probe(ctx, command, process)
			if probeErr == nil {
				after, afterErr := verifyManagedListenerOwnership(process, port)
				if afterErr != nil {
					if errors.Is(afterErr, errManagedListenerNotReady) {
						return newError(CodeLocalProcessMismatch, "verify_llama_listener", m.profile.BindingID(), errors.New("listener ownership changed during readiness"))
					}
					return newError(CodeLocalProcessMismatch, "verify_llama_listener", m.profile.BindingID(), afterErr)
				}
				if before.inode != after.inode {
					return newError(CodeLocalProcessMismatch, "verify_llama_listener", m.profile.BindingID(), errors.New("listener identity changed during readiness"))
				}
				return nil
			}
			ownershipErr = probeErr
		}
		if !errors.Is(ownershipErr, errManagedListenerNotReady) &&
			(errors.As(ownershipErr, new(*listenerOwnershipError)) ||
				errors.Is(ownershipErr, Sentinel(CodeLocalTemplateMismatch)) ||
				errors.Is(ownershipErr, Sentinel(CodeModelIdentityMismatch))) {
			// These are stable identity failures, not transient readiness. Waiting
			// cannot make a different registered asset become the authorized one.
			if errors.As(ownershipErr, new(*listenerOwnershipError)) {
				return newError(CodeLocalProcessMismatch, "verify_llama_listener", m.profile.BindingID(), ownershipErr)
			}
			return ownershipErr
		}
		m.mu.Lock()
		state := m.state
		m.mu.Unlock()
		if state != managedStarting {
			return errors.New("managed process exited before readiness")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *ManagedLlama) probe(ctx context.Context, command *exec.Cmd, process *managedProcessIdentity) error {
	m.mu.Lock()
	endpoint := m.endpoint
	m.mu.Unlock()
	if endpoint == nil || !IsIPv4LoopbackURL(endpoint) {
		return errors.New("endpoint is not IPv4 Loopback")
	}
	probeTransport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: false, DisableCompression: true,
		DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
			if (network != "tcp" && network != "tcp4") || address != endpoint.Host {
				return nil, ownershipMismatch("readiness probe attempted an unexpected endpoint")
			}
			if err := m.requireManagedGenerationActive(command, process); err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(dialContext, "tcp4", endpoint.Host)
		},
	}
	defer probeTransport.CloseIdleConnections()
	client := &http.Client{Timeout: 2 * time.Second, Transport: probeTransport}
	healthURL := *endpoint
	healthURL.Path = "/health"
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL.String(), nil)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("health endpoint is not ready")
	}
	modelsURL := *endpoint
	modelsURL.Path = "/v1/models"
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, modelsURL.String(), nil)
	response, err = client.Do(request)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		return errors.New("models endpoint unavailable")
	}
	// LLAMACPP-01 build 10582 returns the OpenAI-compatible `data` inventory
	// together with its native `models` inventory. Keep the top-level envelope
	// exact and require both views to identify the one frozen alias. Element
	// metadata is intentionally ignored: it is informational and build-specific,
	// while conflicting or missing identity views still fail closed.
	var models struct {
		Models []json.RawMessage `json:"models"`
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := decodeExact(raw, &models, 64<<10); err != nil ||
		models.Object != "list" || len(models.Data) != 1 || len(models.Models) != 1 {
		return newError(CodeModelIdentityMismatch, "probe_llama_model", m.profile.BindingID(), errors.New("served model identity mismatch"))
	}
	var openAIModel struct {
		ID string `json:"id"`
	}
	var nativeModel struct {
		Name  string `json:"name"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(models.Data[0], &openAIModel); err != nil ||
		openAIModel.ID != m.profile.ModelID ||
		json.Unmarshal(models.Models[0], &nativeModel) != nil ||
		nativeModel.Name != m.profile.ModelID || nativeModel.Model != m.profile.ModelID {
		return newError(CodeModelIdentityMismatch, "probe_llama_model", m.profile.BindingID(), errors.New("served model identity mismatch"))
	}
	propsURL := *endpoint
	propsURL.Path = "/props"
	request, _ = http.NewRequestWithContext(ctx, http.MethodGet, propsURL.String(), nil)
	response, err = client.Do(request)
	if err != nil {
		return err
	}
	raw, err = io.ReadAll(io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK {
		return errors.New("props endpoint unavailable")
	}
	var props struct {
		ChatTemplate string `json:"chat_template"`
	}
	if err := json.Unmarshal(raw, &props); err != nil || props.ChatTemplate == "" {
		return errors.New("chat template unavailable")
	}
	digest := sha256.Sum256([]byte(props.ChatTemplate))
	if hex.EncodeToString(digest[:]) != m.profile.LocalRuntimeIdentity.TemplateSHA256 {
		return newError(CodeLocalTemplateMismatch, "probe_llama_template", m.profile.BindingID(), errors.New("template identity mismatch"))
	}
	return nil
}

func IsIPv4LoopbackURL(endpoint *url.URL) bool {
	if endpoint == nil || endpoint.Scheme != "http" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return false
	}
	host := endpoint.Hostname()
	address := net.ParseIP(host)
	if address == nil || address.To4() == nil || !address.IsLoopback() || host != "127.0.0.1" {
		return false
	}
	port, err := strconv.Atoi(endpoint.Port())
	return err == nil && port >= 1 && port <= 65535
}

func (m *ManagedLlama) Endpoint() (*url.URL, error) {
	m.mu.Lock()
	if m.state != managedRunning || m.endpoint == nil || m.target == nil || m.proxyNet == nil || !IsIPv4LoopbackURL(m.endpoint) {
		m.mu.Unlock()
		return nil, newError(CodeLocalEndpointNotLoopback, "llama_endpoint", m.profile.BindingID(), errors.New("managed endpoint unavailable"))
	}
	command := m.cmd
	process := m.process
	endpoint := *m.endpoint
	target := *m.target
	m.mu.Unlock()
	if command == nil || process == nil {
		return nil, newError(CodeLocalProcessMismatch, "llama_endpoint", m.profile.BindingID(), errors.New("managed process unavailable"))
	}
	port, err := strconv.Atoi(target.Port())
	if err != nil {
		return nil, newError(CodeLocalProcessMismatch, "llama_endpoint", m.profile.BindingID(), errors.New("managed listener port invalid"))
	}
	if _, err := verifyManagedListenerOwnership(process, port); err != nil {
		return nil, newError(CodeLocalProcessMismatch, "llama_endpoint", m.profile.BindingID(), err)
	}
	m.mu.Lock()
	unchanged := m.state == managedRunning && m.cmd == command && m.process == process && m.endpoint != nil && m.target != nil &&
		m.endpoint.String() == endpoint.String() && m.target.String() == target.String() && m.proxyNet != nil
	m.mu.Unlock()
	if !unchanged {
		return nil, newError(CodeLocalProcessMismatch, "llama_endpoint", m.profile.BindingID(), errors.New("managed listener changed during endpoint attestation"))
	}
	return &endpoint, nil
}

func (m *ManagedLlama) CleanBaselineEligible() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state == managedRunning && !m.recovered
}

func (m *ManagedLlama) Recover(ctx context.Context) error {
	if err := m.Stop(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	m.recovered = true
	m.mu.Unlock()
	if err := m.Start(ctx); err != nil {
		return err
	}
	return nil
}

// FormalEligibilityError reports the irreversible clean-baseline transition
// separately from recovery success. Callers can keep a diagnostic route
// available after bounded recovery without ever treating it as a clean run.
func (m *ManagedLlama) FormalEligibilityError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recovered {
		return newError(CodeLocalRecoveryDisqualifies, "formal_eligibility", m.profile.BindingID(), errors.New("managed runtime recovered"))
	}
	if m.state != managedRunning {
		return newError(CodeLocalStartupFailed, "formal_eligibility", m.profile.BindingID(), errors.New("managed runtime is not ready"))
	}
	return nil
}

func (m *ManagedLlama) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	command := m.cmd
	process := m.process
	exit := m.exit
	state := m.state
	proxy := m.proxy
	proxyNet := m.proxyNet
	proxyHTTP := m.proxyHTTP
	if command == nil || state == managedStopped {
		m.cmd = nil
		m.process = nil
		m.target = nil
		m.endpoint = nil
		m.proxy = nil
		m.proxyNet = nil
		m.proxyHTTP = nil
		m.state = managedStopped
		m.mu.Unlock()
		if proxy != nil {
			_ = proxy.Close()
		} else if proxyNet != nil {
			_ = proxyNet.Close()
		}
		if proxyHTTP != nil {
			proxyHTTP.CloseIdleConnections()
		}
		process.close()
		return nil
	}
	m.state = managedStopping
	pid := command.Process.Pid
	m.mu.Unlock()
	if proxy != nil {
		_ = proxy.Close()
	} else if proxyNet != nil {
		_ = proxyNet.Close()
	}
	if proxyHTTP != nil {
		proxyHTTP.CloseIdleConnections()
	}
	_ = terminateProcessGroup(pid, syscall.SIGTERM)
	timer := time.NewTimer(m.spec.ShutdownTimeout)
	defer timer.Stop()
	var stopErr error
	select {
	case <-exit:
	case <-ctx.Done():
		_ = terminateProcessGroup(pid, syscall.SIGKILL)
		<-exit
		stopErr = newError(CodeLocalShutdownFailed, "stop_llama", m.profile.BindingID(), ctx.Err())
	case <-timer.C:
		_ = terminateProcessGroup(pid, syscall.SIGKILL)
		<-exit
		stopErr = newError(CodeLocalShutdownFailed, "stop_llama", m.profile.BindingID(), errors.New("bounded shutdown timed out"))
	}
	m.mu.Lock()
	if m.cmd == command {
		m.cmd = nil
		m.process = nil
		m.target = nil
		m.endpoint = nil
		m.proxy = nil
		m.proxyNet = nil
		m.proxyHTTP = nil
		m.state = managedStopped
	}
	m.mu.Unlock()
	process.close()
	return stopErr
}

func terminateProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, signal)
}
