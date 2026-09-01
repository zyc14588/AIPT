package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	ExecutablePath            string
	GGUFPath                  string
	AdditionalArguments       []string
	Environment               map[string]string
	WorkingDirectory          string
	StartupTimeout            time.Duration
	ShutdownTimeout           time.Duration
	IsolationExecutablePath   string
	IsolationExecutableSHA256 string
	IsolationArguments        []string
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
	profile  ModelProfile
	spec     ManagedLlamaSpec
	binary   *verifiedAsset
	gguf     *verifiedAsset
	isolator *verifiedAsset
	adapter  *preparedIsolatedAdapter

	lifecycle               sync.Mutex
	mu                      sync.Mutex
	cmd                     *exec.Cmd
	process                 *managedProcessIdentity
	target                  *url.URL
	endpoint                *url.URL
	state                   managedProcessState
	recovered               bool
	retired                 bool
	exit                    chan error
	isolationControl        *net.UnixConn
	isolationInput          *os.File
	isolationOutput         *os.File
	isolationNetNS          os.FileInfo
	isolationPlatform       runtimeIsolationPlatform
	isolationControlMu      sync.Mutex
	isolationAdapterRunning bool
}

type preparedIsolatedAdapter struct {
	spec          AdapterRouteSpec
	endpointEnv   string
	binary        *verifiedAsset
	entry         *verifiedAsset
	config        *verifiedAsset
	harnessBinary *verifiedAsset
	harnessEntry  *verifiedAsset
}

func NewManagedLlama(profile ModelProfile, spec ManagedLlamaSpec) (*ManagedLlama, error) {
	if err := ValidateModelProfile(profile); err != nil {
		return nil, err
	}
	if profile.BackendKind != BackendLocalLlamaCPP || profile.LocalRuntimeIdentity == nil {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), errors.New("local profile required"))
	}
	if spec.ExecutablePath == "" || spec.GGUFPath == "" || spec.WorkingDirectory == "" ||
		spec.IsolationExecutablePath == "" ||
		spec.StartupTimeout <= 0 || spec.ShutdownTimeout <= 0 {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), errors.New("complete bounded process spec required"))
	}
	if err := sanitizeIsolationArguments(spec.IsolationArguments); err != nil {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), err)
	}
	if err := validateManagedLlamaEnvironment(spec.Environment); err != nil {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), err)
	}
	wantArgs, err := GovernedLaunchParameters(spec.AdditionalArguments)
	if err != nil {
		return nil, err
	}
	if strings.Join(wantArgs, "\x00") != strings.Join(profile.LocalRuntimeIdentity.LaunchParameters, "\x00") {
		return nil, newError(CodeLocalProcessMismatch, "new_managed_llama", profile.BindingID(), errors.New("launch-parameter identity mismatch"))
	}
	binary, err := openVerifiedAsset(spec.ExecutablePath, profile.LocalRuntimeIdentity.BinarySHA256, true)
	if err != nil {
		return nil, newError(CodeLocalBinaryMismatch, "verify_llama_binary", profile.BindingID(), err)
	}
	gguf, err := openVerifiedAsset(spec.GGUFPath, profile.LocalRuntimeIdentity.GGUFSHA256, false)
	if err != nil {
		_ = binary.close()
		return nil, newError(CodeLocalGGUFMismatch, "verify_llama_gguf", profile.BindingID(), err)
	}
	isolator, err := openVerifiedAsset(spec.IsolationExecutablePath, profile.LocalRuntimeIdentity.IsolationHelperSHA256, true)
	if err != nil {
		_ = binary.close()
		_ = gguf.close()
		return nil, newError(CodeLocalBinaryMismatch, "verify_runtime_isolator", profile.BindingID(), err)
	}
	if spec.IsolationExecutableSHA256 != profile.LocalRuntimeIdentity.IsolationHelperSHA256 {
		_ = binary.close()
		_ = gguf.close()
		_ = isolator.close()
		return nil, newError(CodeLocalBinaryMismatch, "bind_runtime_isolator", profile.BindingID(), errors.New("isolation helper digest differs from the governed identity"))
	}
	working, err := filepath.Abs(spec.WorkingDirectory)
	if err != nil {
		_ = binary.close()
		_ = gguf.close()
		_ = isolator.close()
		return nil, newError(CodeLocalProcessMismatch, "resolve_llama_workdir", profile.BindingID(), err)
	}
	info, err := os.Stat(working)
	if err != nil || !info.IsDir() {
		_ = binary.close()
		_ = gguf.close()
		_ = isolator.close()
		return nil, newError(CodeLocalProcessMismatch, "verify_llama_workdir", profile.BindingID(), errors.New("working directory unavailable"))
	}
	spec.WorkingDirectory = working
	spec.Environment = cloneStringMap(spec.Environment)
	return &ManagedLlama{
		profile: profile, spec: spec, binary: binary, gguf: gguf, isolator: isolator,
		isolationPlatform: realLinuxRuntimeIsolator{}, state: managedStopped,
	}, nil
}

func verifyRegularFileDigest(path, expected string, executable bool) error {
	asset, err := openVerifiedAsset(path, expected, executable)
	if err != nil {
		return err
	}
	return asset.close()
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
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	return m.startIsolatedLifecycle(ctx)
}

func environmentList(values map[string]string) []string {
	base := allowlistedBaseEnvironment(mapFromEnvironment(os.Environ()))
	for key, value := range values {
		if isManagedLlamaEnvironment(key) && value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\r\n\x00") {
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

func isManagedLlamaEnvironment(name string) bool {
	switch name {
	case "CUDA_VISIBLE_DEVICES", "HIP_VISIBLE_DEVICES", "ROCR_VISIBLE_DEVICES", "ZE_AFFINITY_MASK",
		"GGML_CUDA_ENABLE_UNIFIED_MEMORY", "GGML_CUDA_FORCE_MMQ", "OMP_NUM_THREADS",
		"AIPT_LLAMA_HELPER", "AIPT_LLAMA_HELPER_MODE", "AIPT_LLAMA_HELPER_GGUF_SHA256":
		return true
	default:
		return false
	}
}

func validateManagedLlamaEnvironment(values map[string]string) error {
	for key, value := range values {
		if !isManagedLlamaEnvironment(key) || !envNameRE.MatchString(key) || value == "" || len(value) > 4096 ||
			strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("llama process environment is outside the closed allowlist")
		}
	}
	return nil
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
	return m.isolatedEndpoint()
}

func (m *ManagedLlama) CleanBaselineEligible() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state == managedRunning && !m.recovered
}

func (m *ManagedLlama) Recover(ctx context.Context) error {
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	if err := m.stopIsolatedLifecycle(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	m.recovered = true
	m.mu.Unlock()
	if err := m.startIsolatedLifecycle(ctx); err != nil {
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
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	return m.stopIsolatedLifecycle(ctx)
}

// Retire is the final lifecycle transition. Unlike Stop (which intentionally
// permits governed recovery), Retire closes every held verified file object
// and makes future starts fail closed. RuntimeCoordinator uses it whenever a
// loaded generation is discarded, including partial-start rollback.
func (m *ManagedLlama) Retire(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.lifecycle.Lock()
	defer m.lifecycle.Unlock()
	stopErr := m.stopIsolatedLifecycle(ctx)
	m.mu.Lock()
	if stopErr == nil {
		m.retired = true
	}
	m.mu.Unlock()
	if stopErr != nil {
		return stopErr
	}
	var adapterErr error
	if m.adapter != nil {
		adapterErr = errors.Join(
			m.adapter.binary.close(), m.adapter.entry.close(), m.adapter.config.close(),
			m.adapter.harnessBinary.close(), m.adapter.harnessEntry.close(),
		)
	}
	return errors.Join(m.binary.close(), m.gguf.close(), m.isolator.close(), adapterErr)
}

func terminateProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 1 {
		return ownershipMismatch("invalid numeric PID cannot be signalled")
	}
	return syscall.Kill(-pid, signal)
}
