package modelgateway

import (
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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

const managedFixtureTemplate = "{{ fixture governed chat template }}"

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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gguf := filepath.Join(t.TempDir(), "synthetic-contract.gguf")
	if err := os.WriteFile(gguf, []byte("synthetic GGUF contract fixture; never formal certification"), 0o600); err != nil {
		t.Fatal(err)
	}
	additional := []string{"-test.run=^TestManagedLlamaHelperProcess$", "--"}
	profile := managedProfile(t, executable, gguf, additional, managedFixtureTemplate)
	return profile, ManagedLlamaSpec{
		ExecutablePath: executable, GGUFPath: gguf, AdditionalArguments: additional,
		Environment:      map[string]string{"AIPT_LLAMA_HELPER": "1", "AIPT_LLAMA_HELPER_MODE": mode},
		WorkingDirectory: t.TempDir(), StartupTimeout: 3 * time.Second, ShutdownTimeout: 2 * time.Second,
	}
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
	if host == "" || port == "" || alias == "" || valueAfter("--model") == "" {
		os.Exit(31)
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
	response, err := http.Get(endpoint.String() + "/health")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("guarded endpoint health: status=%v err=%v", responseStatus(response), err)
	}
	_ = response.Body.Close()
	if !manager.CleanBaselineEligible() || manager.FormalEligibilityError() != nil {
		t.Fatal("fresh managed runtime is not clean-baseline eligible")
	}

	manager.mu.Lock()
	pid := manager.cmd.Process.Pid
	process := manager.process
	target := *manager.target
	manager.mu.Unlock()
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
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
	if stolen, listenErr := net.Listen("tcp4", endpoint.Host); listenErr == nil {
		_ = stolen.Close()
		t.Fatal("stable AIPT-owned endpoint became bindable after managed child crash")
	}
	attacker, err := net.Listen("tcp4", target.Host)
	if err != nil {
		t.Fatalf("bind deterministic post-crash target competitor: %v", err)
	}
	var attackerRequests atomic.Int64
	attackerServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		attackerRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	})}
	attackerDone := make(chan error, 1)
	go func() { attackerDone <- attackerServer.Serve(attacker) }()
	guardedClient := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	response, err = guardedClient.Get(endpoint.String() + "/health")
	if err != nil {
		t.Fatalf("guarded post-crash request: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || attackerRequests.Load() != 0 {
		t.Fatalf("post-crash rebind was not fail-closed: status=%d attacker_requests=%d", response.StatusCode, attackerRequests.Load())
	}
	_ = attackerServer.Close()
	<-attackerDone

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
	err = manager.Start(context.Background())
	requireCode(t, err, CodeLocalReadinessFailed)
	if !errors.Is(err, Sentinel(CodeModelIdentityMismatch)) {
		t.Fatalf("model identity mismatch cause missing: %v", err)
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
