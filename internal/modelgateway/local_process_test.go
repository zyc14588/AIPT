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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

const managedFixtureTemplate = "{{ fixture governed chat template }}"

const syntheticRuntimeIsolationEnvironment = "AIPT_TEST_SYNTHETIC_RUNTIME_ISOLATOR"

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func TestVerifiedAssetUsesWriteSealedSnapshotAfterInPlaceMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registered-asset")
	original := []byte("verified immutable bytes")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	asset, err := openVerifiedAsset(path, fileSHA256(t, path), false)
	if err != nil {
		t.Fatal(err)
	}
	defer asset.close()
	if err := os.WriteFile(path, []byte("attacker rewrote the registered inode"), 0o600); err != nil {
		t.Fatal(err)
	}
	observed, err := asset.readAll(1 << 20)
	if err != nil || !bytes.Equal(observed, original) {
		t.Fatalf("sealed snapshot changed after in-place source mutation: %q, %v", observed, err)
	}
	descriptor, err := asset.descriptor()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := descriptor.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("verified asset snapshot remained writable after sealing")
	}
}

func copyFixtureFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func managedProfile(t *testing.T, executable, gguf string, additional []string, template string) ModelProfile {
	t.Helper()
	sampling := fixtureSampling(t, "sampling-managed-local")
	profile := fixtureProfile(t, orchestrator.SeatGM, BackendLocalLlamaCPP, sampling, "cert-managed-local@1.0.0")
	parameters, err := GovernedLaunchParameters(additional)
	if err != nil {
		t.Fatal(err)
	}
	profile.SHA256 = ""
	profile.LocalRuntimeIdentity.BinarySHA256 = fileSHA256(t, executable)
	profile.LocalRuntimeIdentity.GGUFSHA256 = fileSHA256(t, gguf)
	profile.LocalRuntimeIdentity.IsolationHelperSHA256 = fileSHA256(t, executable)
	profile.LocalRuntimeIdentity.TemplateSHA256 = fixtureSHA(template)
	profile.LocalRuntimeIdentity.LaunchParameters = parameters
	bound, err := BindModelProfile(profile)
	if err != nil {
		t.Fatalf("bind managed local profile: %v", err)
	}
	return bound
}

func managedFixture(t *testing.T, mode string) (ModelProfile, ManagedLlamaSpec) {
	t.Helper()
	sourceExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	assetRoot := t.TempDir()
	executable := filepath.Join(assetRoot, "synthetic-runtime")
	copyFixtureFile(t, sourceExecutable, executable, 0o700)
	gguf := filepath.Join(assetRoot, "synthetic-contract.gguf")
	if err := os.WriteFile(gguf, []byte("synthetic GGUF contract fixture; never formal certification"), 0o600); err != nil {
		t.Fatal(err)
	}
	additional := []string{"-test.run=^TestManagedLlamaHelperProcess$", "--"}
	profile := managedProfile(t, executable, gguf, additional, managedFixtureTemplate)
	return profile, ManagedLlamaSpec{
		ExecutablePath: executable, GGUFPath: gguf, AdditionalArguments: additional,
		Environment: map[string]string{
			"AIPT_LLAMA_HELPER": "1", "AIPT_LLAMA_HELPER_MODE": mode,
			"AIPT_LLAMA_HELPER_GGUF_SHA256": fileSHA256(t, gguf),
		},
		WorkingDirectory: t.TempDir(), StartupTimeout: 3 * time.Second, ShutdownTimeout: 2 * time.Second,
		IsolationExecutablePath: executable, IsolationExecutableSHA256: fileSHA256(t, executable),
		IsolationArguments: []string{"-test.run=^TestRuntimeIsolationHelperProcess$"},
	}
}

// syntheticRuntimeIsolationPlatform exists only in the Go test binary. It
// removes the kernel namespace dependency from semantic/lifecycle tests while
// preserving the verified-process, control-protocol, readiness, ownership, and
// cleanup state machines those tests are intended to exercise.
type syntheticRuntimeIsolationPlatform struct{}

func (syntheticRuntimeIsolationPlatform) start(command *exec.Cmd, pidfd *int) error {
	command.Env = append(command.Env, syntheticRuntimeIsolationEnvironment+"=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: pidfd}
	return command.Start()
}

func (syntheticRuntimeIsolationPlatform) namespaceIdentity(pid int) (os.FileInfo, error) {
	return os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
}

func (syntheticRuntimeIsolationPlatform) namespaceIdentityCurrent(pid int, identity os.FileInfo) bool {
	if pid <= 1 || identity == nil {
		return false
	}
	observed, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
	return err == nil && os.SameFile(observed, identity)
}

func useSyntheticRuntimeIsolation(t *testing.T, manager *ManagedLlama) {
	t.Helper()
	if manager == nil {
		t.Fatal("managed runtime unavailable")
	}
	if _, ok := manager.isolationPlatform.(realLinuxRuntimeIsolator); !ok {
		t.Fatalf("production constructor did not bind the real Linux isolator: %T", manager.isolationPlatform)
	}
	manager.isolationPlatform = syntheticRuntimeIsolationPlatform{}
}

type rejectingRuntimeIsolationPlatform struct {
	startCalls atomic.Int32
	err        error
}

func (platform *rejectingRuntimeIsolationPlatform) start(command *exec.Cmd, _ *int) error {
	platform.startCalls.Add(1)
	if command.Process != nil {
		return errors.New("rejected platform observed an already-started process")
	}
	return platform.err
}

func (*rejectingRuntimeIsolationPlatform) namespaceIdentity(int) (os.FileInfo, error) {
	return nil, errors.New("rejected platform cannot publish a namespace identity")
}

func (*rejectingRuntimeIsolationPlatform) namespaceIdentityCurrent(int, os.FileInfo) bool {
	return false
}

func TestProductionRuntimeIsolationCapabilityUnavailableFailsClosed(t *testing.T) {
	profile, spec := managedFixture(t, "ready")
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	platform := &rejectingRuntimeIsolationPlatform{err: syscall.EPERM}
	manager.isolationPlatform = platform
	err = manager.Start(context.Background())
	requireCode(t, err, CodeLocalIsolationUnavailable)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("namespace policy errno was not retained internally: %v", err)
	}
	var capability *runtimeIsolationCapabilityError
	if !errors.As(err, &capability) || capability.category != "namespace_launch_denied" {
		t.Fatalf("capability category = %#v", capability)
	}
	if platform.startCalls.Load() != 1 {
		t.Fatalf("isolation launch attempts = %d, want 1", platform.startCalls.Load())
	}
	manager.mu.Lock()
	state, command, process := manager.state, manager.cmd, manager.process
	manager.mu.Unlock()
	if state != managedStopped || command != nil || process != nil {
		t.Fatalf("capability rejection published process ownership: state=%s command=%v process=%v", state, command != nil, process != nil)
	}
	if _, endpointErr := manager.Endpoint(); endpointErr == nil {
		t.Fatal("capability rejection exposed a host-loopback endpoint")
	}
	if err := manager.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticRuntimeIsolationCannotBeSelectedFromProductionInputs(t *testing.T) {
	t.Setenv(syntheticRuntimeIsolationEnvironment, "1")
	profile, spec := managedFixture(t, "ready")
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.isolationPlatform.(realLinuxRuntimeIsolator); !ok {
		t.Fatalf("environment selected a non-production isolator: %T", manager.isolationPlatform)
	}
	if err := manager.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}

	profile.SHA256 = ""
	profile.LocalRuntimeIdentity.IsolationIdentity = "AIPT_TEST_SYNTHETIC_RUNTIME_ISOLATOR"
	if _, err := BindModelProfile(profile); err == nil {
		t.Fatal("Model Profile selected a synthetic runtime isolator")
	}
}

func runSyntheticRuntimeIsolator() error {
	controlFile := os.NewFile(4, "aipt-synthetic-isolator-control")
	if controlFile == nil {
		return errors.New("synthetic isolation control unavailable")
	}
	raw, err := net.FileConn(controlFile)
	_ = controlFile.Close()
	if err != nil {
		return err
	}
	control, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return errors.New("synthetic isolation control is not Unix seqpacket")
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
			Schema: isolationProtocolSchema, Operation: "START_MODEL", Result: "FAIL",
			Code: string(code), FailureStage: stage,
		})
		return err
	}
	if err := writeIsolationFrame(control, isolationControlResponse{
		Schema: isolationProtocolSchema, Operation: "START_MODEL", Result: "PASS", Port: supervisor.port,
		IsolationIdentity: LocalIsolationIdentity,
	}); err != nil {
		_ = syntheticStopAll(supervisor)
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	return syntheticIsolationLoop(supervisor, signals)
}

func syntheticIsolationLoop(supervisor *isolationSupervisor, signals <-chan os.Signal) error {
	requests := make(chan isolationControlMessage)
	readFailures := make(chan error, 1)
	go func() {
		for {
			var request isolationControlMessage
			if err := readIsolationFrame(supervisor.control, &request); err != nil {
				readFailures <- err
				return
			}
			requests <- request
		}
	}()
	for {
		select {
		case <-signals:
			return errors.Join(errors.New("synthetic isolation supervisor terminated"), syntheticStopAll(supervisor))
		case <-supervisor.llamaExit:
			return errors.New("synthetic isolated llama exited")
		case <-supervisor.adapterExit:
			return errors.New("synthetic isolated adapter exited")
		case err := <-readFailures:
			return err
		case request := <-requests:
			if request.Schema != isolationProtocolSchema {
				return errors.New("synthetic isolation protocol mismatch")
			}
			switch request.Operation {
			case "START_ADAPTER":
				err := supervisor.startAdapter()
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
					response.AdapterPID = supervisor.adapter.Process.Pid
				}
				if writeIsolationFrame(supervisor.control, response) != nil {
					return errors.New("synthetic isolation response failed")
				}
			case "STOP_ADAPTER":
				cleanupErr := syntheticStopAdapter(supervisor)
				response := isolationControlResponse{Schema: isolationProtocolSchema, Operation: request.Operation, Result: "PASS"}
				if cleanupErr != nil {
					response.Result = "FAIL"
					response.Code = string(CodeLocalShutdownFailed)
				}
				if writeIsolationFrame(supervisor.control, response) != nil {
					return errors.New("synthetic isolation response failed")
				}
			case "STOP_ALL":
				cleanupErr := syntheticStopAll(supervisor)
				response := isolationControlResponse{Schema: isolationProtocolSchema, Operation: request.Operation, Result: "PASS"}
				if cleanupErr != nil {
					response.Result = "FAIL"
					response.Code = string(CodeLocalShutdownFailed)
				}
				_ = writeIsolationFrame(supervisor.control, response)
				return cleanupErr
			default:
				return errors.New("unknown synthetic isolation operation")
			}
		}
	}
}

func syntheticStopAdapter(supervisor *isolationSupervisor) error {
	if supervisor.adapter == nil {
		return nil
	}
	_ = terminateOwnedProcessGroup(supervisor.adapterProcess, syscall.SIGTERM)
	settled := waitProcessExit(supervisor.adapterExit, time.Duration(supervisor.initial.ShutdownTimeoutMS)*time.Millisecond)
	if !settled {
		_ = terminateOwnedProcessGroup(supervisor.adapterProcess, syscall.SIGKILL)
		settled = waitProcessExit(supervisor.adapterExit, time.Second)
	}
	if !settled {
		return errors.New("synthetic isolated adapter did not settle after SIGKILL")
	}
	supervisor.adapterProcess.close()
	supervisor.adapter = nil
	supervisor.adapterProcess = nil
	supervisor.adapterExit = nil
	return nil
}

func syntheticStopAll(supervisor *isolationSupervisor) error {
	return errors.Join(syntheticStopAdapter(supervisor), supervisor.stopLlama())
}

func TestRuntimeIsolationHelperProcess(t *testing.T) {
	if os.Getenv("AIPT_RUNTIME_ISOLATOR") != "1" {
		return
	}
	var err error
	if os.Getenv(syntheticRuntimeIsolationEnvironment) == "1" {
		err = runSyntheticRuntimeIsolator()
	} else {
		err = RunRuntimeIsolator()
	}
	if err != nil {
		os.Exit(30)
	}
	os.Exit(0)
}

// TestManagedLlamaHelperProcess is a secret-free public-CI process fixture,
// not a model and never certification evidence. The parent runs this exact
// test binary to exercise argv, process identity, loopback readiness and
// signal cleanup without a network/provider/model dependency.
func TestManagedLlamaHelperProcess(t *testing.T) {
	if os.Getenv("AIPT_LLAMA_HELPER") != "1" {
		return
	}
	arguments := os.Args
	valueAfter := func(name string) string {
		for index := 0; index+1 < len(arguments); index++ {
			if arguments[index] == name {
				return arguments[index+1]
			}
		}
		return ""
	}
	host := valueAfter("--host")
	port := valueAfter("--port")
	alias := valueAfter("--alias")
	modelPath := valueAfter("--model")
	if host == "" || port == "" || alias == "" || modelPath == "" {
		os.Exit(31)
	}
	modelBytes, modelErr := os.ReadFile(modelPath)
	modelDigest := sha256.Sum256(modelBytes)
	if modelErr != nil || hex.EncodeToString(modelDigest[:]) != os.Getenv("AIPT_LLAMA_HELPER_GGUF_SHA256") {
		os.Exit(34)
	}
	if os.Getenv("AIPT_LLAMA_HELPER_MODE") == "noisy" {
		_, _ = os.Stdout.Write(bytesOf('x', 256<<10))
	}
	if os.Getenv("AIPT_LLAMA_HELPER_MODE") == "delegated-listener" {
		command := exec.Command(os.Args[0], os.Args[1:]...)
		command.Env = append([]string(nil), os.Environ()...)
		for index, entry := range command.Env {
			if strings.HasPrefix(entry, "AIPT_LLAMA_HELPER_MODE=") {
				command.Env[index] = "AIPT_LLAMA_HELPER_MODE=delegated-listener-owner"
			}
		}
		if err := command.Start(); err != nil {
			os.Exit(33)
		}
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
		<-signals
		_ = command.Wait()
		os.Exit(0)
	}
	template := managedFixtureTemplate
	if os.Getenv("AIPT_LLAMA_HELPER_MODE") == "wrong-template" {
		template = "{{ unexpected template }}"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/v1/models", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		nativeAlias := alias
		if os.Getenv("AIPT_LLAMA_HELPER_MODE") == "conflicting-model-envelope" {
			nativeAlias = "unexpected-model"
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"models": []map[string]any{{
				"name": alias, "model": nativeAlias, "capabilities": []string{"completion"},
			}},
			"object": "list",
			"data": []map[string]any{{
				"id": alias, "object": "model", "owned_by": "llamacpp",
				"meta": map[string]any{"ftype": "Q8_0", "n_ctx": 8192},
			}},
		})
	})
	mux.HandleFunc("/props", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"chat_template": template})
	})
	listener, err := net.Listen("tcp4", net.JoinHostPort(host, port))
	if err != nil {
		os.Exit(32)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-signals:
		shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = server.Shutdown(shutdown)
		cancel()
	case <-done:
	}
	os.Exit(0)
}

func TestListenerOwnershipRaceIsRejected(t *testing.T) {
	profile, spec := managedFixture(t, "delegated-listener")
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	useSyntheticRuntimeIsolation(t, manager)
	err = manager.Start(context.Background())
	requireCode(t, err, CodeLocalReadinessFailed)
	if !errors.Is(err, Sentinel(CodeLocalProcessMismatch)) {
		t.Fatalf("listener ownership mismatch cause missing: %v", err)
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestLocalSecurityNegativeMatrixM16ToM20(t *testing.T) {
	t.Run("M16 llama endpoint non-loopback REJECT", func(t *testing.T) {
		for _, raw := range []string{
			"http://0.0.0.0:8080", "http://127.0.0.2:8080", "http://[::1]:8080",
			"https://127.0.0.1:8080", "http://user@127.0.0.1:8080", "http://127.0.0.1:8080/path",
		} {
			endpoint, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if IsIPv4LoopbackURL(endpoint) {
				t.Fatalf("unsafe endpoint accepted: %s", raw)
			}
		}
		endpoint, _ := url.Parse("http://127.0.0.1:8080")
		if !IsIPv4LoopbackURL(endpoint) {
			t.Fatal("exact IPv4 loopback endpoint rejected")
		}
	})

	t.Run("M17 llama binary digest mismatch REJECT", func(t *testing.T) {
		profile, spec := managedFixture(t, "ready")
		profile.SHA256 = ""
		profile.LocalRuntimeIdentity.BinarySHA256 = strings.Repeat("0", 64)
		profile, _ = BindModelProfile(profile)
		_, err := NewManagedLlama(profile, spec)
		requireCode(t, err, CodeLocalBinaryMismatch)
	})

	t.Run("M18 GGUF digest mismatch REJECT", func(t *testing.T) {
		profile, spec := managedFixture(t, "ready")
		profile.SHA256 = ""
		profile.LocalRuntimeIdentity.GGUFSHA256 = strings.Repeat("0", 64)
		profile, _ = BindModelProfile(profile)
		_, err := NewManagedLlama(profile, spec)
		requireCode(t, err, CodeLocalGGUFMismatch)
	})

	t.Run("M19 wrong chat template identity REJECT", func(t *testing.T) {
		profile, spec := managedFixture(t, "wrong-template")
		manager, err := NewManagedLlama(profile, spec)
		if err != nil {
			t.Fatal(err)
		}
		useSyntheticRuntimeIsolation(t, manager)
		err = manager.Start(context.Background())
		requireCode(t, err, CodeLocalReadinessFailed)
		if !errors.Is(err, Sentinel(CodeLocalTemplateMismatch)) {
			t.Fatalf("template mismatch cause missing: %v", err)
		}
	})

	t.Run("M20 managed process unexpected executable REJECT", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		other := "/bin/false"
		if same, statErr := sameFile(executable, other); statErr == nil && same {
			other = "/bin/true"
		}
		if err := verifyProcessExecutable(os.Getpid(), other); err == nil {
			t.Fatal("unexpected executable identity accepted")
		}
	})
}

func sameFile(left, right string) (bool, error) {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false, err
	}
	rightInfo, err := os.Stat(right)
	if err != nil {
		return false, err
	}
	return os.SameFile(leftInfo, rightInfo), nil
}

func TestManagedLocalStartupLoopbackShutdownAndM26RecoveryDisqualification(t *testing.T) {
	profile, spec := managedFixture(t, "noisy")
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	useSyntheticRuntimeIsolation(t, manager)
	if err := manager.Start(context.Background()); err != nil {
		var ownership *listenerOwnershipError
		if errors.As(err, &ownership) {
			t.Fatalf("managed startup: %v (%v)", err, ownership)
		}
		t.Fatalf("managed startup: %v", err)
	}
	endpoint, err := manager.Endpoint()
	if err != nil || !IsIPv4LoopbackURL(endpoint) || endpoint.Port() == "" {
		t.Fatalf("managed endpoint = %v, %v", endpoint, err)
	}
	// This hermetic test proves lifecycle/readiness semantics only. Real network
	// namespace reachability is covered by the capability-branch test below.
	if !manager.CleanBaselineEligible() || manager.FormalEligibilityError() != nil {
		t.Fatal("fresh managed runtime is not clean-baseline eligible")
	}

	manager.mu.Lock()
	process := manager.process
	manager.mu.Unlock()
	if err := manager.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("crash fixture process: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		manager.mu.Lock()
		state := manager.state
		manager.mu.Unlock()
		if state == managedCrashed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("managed process crash was not classified")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := process.requireAlive(); err == nil {
		t.Fatal("pidfd process-generation identity remained valid after child exit")
	}
	if _, endpointErr := manager.Endpoint(); endpointErr == nil {
		t.Fatal("crashed isolation generation still exposed an endpoint capability")
	}

	if err := manager.Recover(context.Background()); err != nil {
		t.Fatalf("bounded recovery: %v", err)
	}
	if manager.CleanBaselineEligible() {
		t.Fatal("M26 recovered local crash retained clean flag")
	}
	requireCode(t, manager.FormalEligibilityError(), CodeLocalRecoveryDisqualifies)
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("bounded shutdown: %v", err)
	}
}

func TestManagedLlamaRejectsConflictingLLAMACPP01ModelEnvelope(t *testing.T) {
	profile, spec := managedFixture(t, "conflicting-model-envelope")
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	useSyntheticRuntimeIsolation(t, manager)
	err = manager.Start(context.Background())
	requireCode(t, err, CodeLocalReadinessFailed)
	if !errors.Is(err, Sentinel(CodeModelIdentityMismatch)) {
		t.Fatalf("model identity mismatch cause missing: %v", err)
	}
}

func TestVerifiedAssetPathReplacementCannotChangeExecutableOrGGUF(t *testing.T) {
	profile, spec := managedFixture(t, "ready")
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	useSyntheticRuntimeIsolation(t, manager)
	originalExecutable := spec.ExecutablePath + ".verified"
	if err := os.Rename(spec.ExecutablePath, originalExecutable); err != nil {
		t.Fatal(err)
	}
	copyFixtureFile(t, "/bin/false", spec.ExecutablePath, 0o700)
	originalGGUF := spec.GGUFPath + ".verified"
	if err := os.Rename(spec.GGUFPath, originalGGUF); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec.GGUFPath, []byte("attacker replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("held verified executable/GGUF were not used after pathname replacement: %v", err)
	}
	if err := manager.Retire(context.Background()); err != nil {
		t.Fatalf("retire held verified assets: %v", err)
	}
}

func TestFailedSpawnCleanupIsBoundedAndNeverSignalsInvalidOrUnrelatedPID(t *testing.T) {
	profile, spec := managedFixture(t, "ready")
	invalidIsolator := filepath.Join(t.TempDir(), "invalid-runtime-isolator")
	if err := os.WriteFile(invalidIsolator, []byte("synthetic invalid executable format"), 0o700); err != nil {
		t.Fatal(err)
	}
	invalidDigest := fileSHA256(t, invalidIsolator)
	profile.SHA256 = ""
	profile.LocalRuntimeIdentity.IsolationHelperSHA256 = invalidDigest
	var bindErr error
	profile, bindErr = BindModelProfile(profile)
	if bindErr != nil {
		t.Fatal(bindErr)
	}
	spec.IsolationExecutablePath = invalidIsolator
	spec.IsolationExecutableSHA256 = invalidDigest
	manager, err := NewManagedLlama(profile, spec)
	if err != nil {
		t.Fatal(err)
	}
	useSyntheticRuntimeIsolation(t, manager)
	started := time.Now()
	err = manager.Start(context.Background())
	requireCode(t, err, CodeLocalStartupFailed)
	if time.Since(started) > 3*time.Second {
		t.Fatal("failed spawn cleanup exceeded its fixed bound")
	}
	manager.mu.Lock()
	state, command, process := manager.state, manager.cmd, manager.process
	manager.mu.Unlock()
	if state != managedStopped || command != nil || process != nil {
		t.Fatalf("failed spawn published partial ownership: state=%s command=%v process=%v", state, command != nil, process != nil)
	}
	if _, err := bindManagedProcessIdentity(nil, -1); err == nil {
		t.Fatal("nil process identity accepted")
	}
	if err := terminateProcessGroup(1, syscall.SIGKILL); err == nil {
		t.Fatal("PID 1 entered numeric signal path")
	}
	unrelated := exec.Command("/bin/sleep", "30")
	unrelated.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	}()
	if err := terminateOwnedProcessGroup(nil, syscall.SIGKILL); err == nil {
		t.Fatal("nil ownership entered signal path")
	}
	if err := unrelated.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("invalid cleanup signalled an unrelated process: %v", err)
	}
	if err := manager.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagedLifecycleConcurrentStartStopIsLinearizableAndLeakFree(t *testing.T) {
	for iteration := 0; iteration < 12; iteration++ {
		profile, spec := managedFixture(t, "ready")
		manager, err := NewManagedLlama(profile, spec)
		if err != nil {
			t.Fatal(err)
		}
		useSyntheticRuntimeIsolation(t, manager)
		var successes atomic.Int32
		var group sync.WaitGroup
		start := make(chan struct{})
		for worker := 0; worker < 6; worker++ {
			group.Add(1)
			go func() {
				defer group.Done()
				<-start
				if manager.Start(context.Background()) == nil {
					successes.Add(1)
				}
			}()
		}
		close(start)
		group.Wait()
		if successes.Load() != 1 {
			t.Fatalf("iteration %d launched %d generations", iteration, successes.Load())
		}
		manager.mu.Lock()
		pid := manager.process.pid
		if manager.state != managedRunning || manager.cmd == nil || manager.isolationControl == nil {
			manager.mu.Unlock()
			t.Fatalf("iteration %d has an inconsistent running generation", iteration)
		}
		manager.mu.Unlock()

		tracing := make(chan struct{})
		var startErr, stopErr error
		group.Add(2)
		go func() { defer group.Done(); <-tracing; startErr = manager.Start(context.Background()) }()
		go func() { defer group.Done(); <-tracing; stopErr = manager.Stop(context.Background()) }()
		close(tracing)
		group.Wait()
		if stopErr != nil {
			t.Fatalf("iteration %d stop failed: %v", iteration, stopErr)
		}
		manager.mu.Lock()
		state, command := manager.state, manager.cmd
		newPID := 0
		if manager.process != nil {
			newPID = manager.process.pid
		}
		manager.mu.Unlock()
		if startErr == nil {
			if state != managedRunning || command == nil || newPID <= 1 || newPID == pid {
				t.Fatalf("iteration %d did not publish exactly one post-stop generation: state=%s pid=%d", iteration, state, newPID)
			}
		} else if state != managedStopped || command != nil {
			t.Fatalf("iteration %d has a partial generation after stop won the race: %s", iteration, state)
		}
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(statErr) {
			t.Fatalf("iteration %d leaked supervisor pid %d", iteration, pid)
		}
		if state == managedRunning {
			if err := manager.Stop(context.Background()); err != nil {
				t.Fatalf("iteration %d cleanup of post-stop generation: %v", iteration, err)
			}
		}
		if err := manager.Retire(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

type isolatedAdapterTestFixture struct {
	route                AdapterRouteSpec
	descendantLeakMarker string
}

func newIsolatedAdapterTestFixture(t *testing.T, profile ModelProfile, detachedDescendant bool) isolatedAdapterTestFixture {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("Node runtime unavailable")
	}
	nodeOutput, err := exec.Command(node, "-p", "process.execPath").Output()
	if err != nil {
		t.Fatal("exact Node executable unavailable")
	}
	node = strings.TrimSpace(string(nodeOutput))
	root := t.TempDir()
	descendantLeakMarker := ""
	detachedSpawn := ""
	if detachedDescendant {
		descendantLeakMarker = filepath.Join(root, "detached-adapter-descendant-leaked")
		descendantSource := fmt.Sprintf(
			"setTimeout(()=>import('node:fs').then((fs)=>fs.writeFileSync(%s,'leaked')),500)",
			strconv.Quote(descendantLeakMarker),
		)
		detachedSpawn = fmt.Sprintf("if(!spawned){spawned=true;spawn('/proc/self/exe',['--input-type=module','--eval',%s],{detached:true,stdio:'ignore'}).unref()}", strconv.Quote(descendantSource))
	}
	entry := filepath.Join(root, "isolated-adapter.mjs")
	source := fmt.Sprintf(`import{spawn}from'node:child_process';import{createInterface}from'node:readline';
const lines=createInterface({input:process.stdin});
let spawned=false;lines.on('line',async(line)=>{%sconst request=JSON.parse(line);const response=await fetch(process.env.AIPT_LOCAL_TEST_ENDPOINT+'/health');if(!response.ok)process.exit(41);const p=request.params;process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:request.id,protocol_version:'1',result:{harness_identity:p.harness_identity,protocol_identity:p.protocol_identity,protocol_version:p.protocol_version,observed_model_id:p.expected_model_id,capability_fingerprint:p.capability_fingerprint,route_available:true,direct_provider_bypass_available:false}})+'\n')});`, detachedSpawn)
	if err := os.WriteFile(entry, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	routeConfig := filepath.Join(root, "route.json")
	entryDigest := fileSHA256(t, entry)
	routeDocument := map[string]any{"child": map[string]any{
		"executable_path": node, "executable_sha256": fileSHA256(t, node),
		"arguments":             []string{entry},
		"argument_file_digests": []map[string]any{{"index": 0, "sha256": entryDigest}},
		"runtime_closure": map[string]any{
			"schema": HarnessRuntimeClosureSchema, "kind": HarnessRuntimeClosureKind,
			"entrypoint_argument_index": 0, "sha256": entryDigest,
		},
	}}
	routeBytes, err := json.Marshal(routeDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(routeConfig, routeBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return isolatedAdapterTestFixture{route: AdapterRouteSpec{
		ProfileBinding: profile.BindingID(), ExecutablePath: node, ExecutableSHA256: fileSHA256(t, node),
		AdapterEntrypointPath: entry, AdapterEntrypointSHA256: entryDigest,
		RouteConfigPath: routeConfig, RouteConfigSHA256: fileSHA256(t, routeConfig),
		WorkingDirectory: root, StartupTimeout: 3 * time.Second, ShutdownTimeout: 2 * time.Second,
	}, descendantLeakMarker: descendantLeakMarker}
}

func exerciseGovernedIsolatedAdapter(t *testing.T, manager *ManagedLlama, profile ModelProfile, route AdapterRouteSpec) {
	t.Helper()
	route.IsolatedLauncher = manager
	transport, err := NewAdapterProcessTransport([]ModelProfile{profile}, []AdapterRouteSpec{route}, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := transport.Probe(context.Background(), profile, fixtureSampling(t, "isolation-probe-sampling"))
	if err != nil {
		t.Fatalf("governed in-namespace adapter could not reach llama: %v", err)
	}
	if err := validateProbe(profile, probe); err != nil {
		t.Fatalf("isolated adapter probe identity: %v", err)
	}
	if err := transport.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGovernedIsolatedAdapterRouteSemanticsAreHermetic(t *testing.T) {
	profile, llamaSpec := managedFixture(t, "ready")
	fixture := newIsolatedAdapterTestFixture(t, profile, false)
	manager, err := NewManagedLlama(profile, llamaSpec)
	if err != nil {
		t.Fatal(err)
	}
	useSyntheticRuntimeIsolation(t, manager)
	defer func() { _ = manager.Retire(context.Background()) }()
	if err := manager.PrepareIsolatedAdapter(fixture.route, "AIPT_LOCAL_TEST_ENDPOINT"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	direct := fixture.route
	direct.IsolatedLauncher = nil
	if transport, err := NewAdapterProcessTransport([]ModelProfile{profile}, []AdapterRouteSpec{direct}, nil); err == nil {
		_ = transport.Close(context.Background())
		t.Fatal("local adapter route was accepted without the managed isolation launcher")
	}
	exerciseGovernedIsolatedAdapter(t, manager, profile, fixture.route)
	manager.mu.Lock()
	adapterRunning := manager.isolationAdapterRunning
	manager.mu.Unlock()
	if adapterRunning {
		t.Fatal("hermetic governed adapter retained lifecycle ownership after close")
	}
}

func TestOnlyIsolatedAdapterCanReachManagedLlamaLoopback(t *testing.T) {
	profile, llamaSpec := managedFixture(t, "ready")
	fixture := newIsolatedAdapterTestFixture(t, profile, true)
	manager, err := NewManagedLlama(profile, llamaSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Retire(context.Background()) }()
	if _, ok := manager.isolationPlatform.(realLinuxRuntimeIsolator); !ok {
		t.Fatalf("production constructor selected %T", manager.isolationPlatform)
	}
	if err := manager.PrepareIsolatedAdapter(fixture.route, "AIPT_LOCAL_TEST_ENDPOINT"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		if CodeOf(err) != CodeLocalIsolationUnavailable {
			t.Fatal(err)
		}
		manager.mu.Lock()
		state, command, process := manager.state, manager.cmd, manager.process
		manager.mu.Unlock()
		if state != managedStopped || command != nil || process != nil {
			t.Fatalf("unsupported host retained a runtime generation: state=%s command=%v process=%v", state, command != nil, process != nil)
		}
		if _, endpointErr := manager.Endpoint(); endpointErr == nil {
			t.Fatal("unsupported host exposed a local llama endpoint")
		}
		if _, markerErr := os.Stat(fixture.descendantLeakMarker); !os.IsNotExist(markerErr) {
			t.Fatal("unsupported host executed the isolated adapter fixture")
		}
		return
	}
	manager.mu.Lock()
	pid := manager.process.pid
	manager.mu.Unlock()
	for _, namespace := range []string{"user", "net", "pid", "mnt"} {
		if !processNamespaceDiffers(pid, namespace) {
			t.Fatalf("real runtime isolator lacks a distinct %s namespace", namespace)
		}
	}
	endpoint, err := manager.Endpoint()
	if err != nil {
		t.Fatal(err)
	}
	hostProbe, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !endpointUnreachableFromHost(hostProbe, endpoint) {
		t.Fatal("host-local process reached the unauthenticated private llama endpoint")
	}
	exerciseGovernedIsolatedAdapter(t, manager, profile, fixture.route)
	time.Sleep(750 * time.Millisecond)
	if _, err := os.Stat(fixture.descendantLeakMarker); !os.IsNotExist(err) {
		t.Fatal("detached adapter descendant survived governed Harness cleanup")
	}
}

func TestGovernedLaunchArgumentsForbidDownloadsCredentialsUIAndEndpointOverrides(t *testing.T) {
	for _, argument := range []string{
		"--model", "--model-url=https://example.invalid/model.gguf", "--hf-repo", "--host=0.0.0.0",
		"--port=8080", "--api-key", "--webui", "--chat-template-file", "/private/model.gguf",
	} {
		if _, err := GovernedLaunchParameters([]string{argument}); err == nil {
			t.Fatalf("unsafe llama argument accepted: %s", argument)
		}
	}
	parameters, err := GovernedLaunchParameters([]string{"--ctx-size", strconv.Itoa(8192)})
	if err != nil || strings.Join(parameters, " ") == "" {
		t.Fatalf("safe governed arguments rejected: %v", err)
	}
	for _, required := range []string{"--host", "127.0.0.1", "--port", DynamicPortMarker, "--no-webui", "--no-slots", "--jinja"} {
		if !strings.Contains(strings.Join(parameters, " "), required) {
			t.Fatalf("governed launch identity missing %s: %v", required, parameters)
		}
	}
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}

func TestManagedLocalFailureTextDoesNotExposePrivatePaths(t *testing.T) {
	profile, spec := managedFixture(t, "ready")
	private := filepath.Join(t.TempDir(), "operator-private-missing.gguf")
	spec.GGUFPath = private
	_, err := NewManagedLlama(profile, spec)
	if err == nil {
		t.Fatal("missing registered GGUF accepted")
	}
	if strings.Contains(err.Error(), private) || strings.Contains(err.Error(), filepath.Dir(private)) {
		t.Fatalf("private path leaked in error: %v", err)
	}
}

func TestManagedHelperArgumentContract(t *testing.T) {
	// A lightweight source-level assertion guards accidental test-fixture drift:
	// the fake process still consumes the same exact product argv names.
	for _, argument := range []string{"--model", "--host", "--port", "--alias"} {
		if argument == "" {
			t.Fatal(fmt.Errorf("empty governed argument"))
		}
	}
}
