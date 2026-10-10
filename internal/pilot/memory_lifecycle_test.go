package pilot

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

func TestMemoryLifecycleRejectsUnverifiedAssetsAndRetiresFailedPreparation(t *testing.T) {
	// Public frozen profile provides a schema-valid seed only. These replacement
	// files are explicit non-canon fixtures; no runtime/server is executed.
	raw, err := os.ReadFile("../../docs/model-certification/local-llamacpp-controlled-real-02.json")
	if err != nil {
		t.Fatal(err)
	}
	var seed struct {
		Profile modelgateway.ModelProfile `json:"model_profile"`
	}
	if err = json.Unmarshal(raw, &seed); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "non-canon-executable")
	model := filepath.Join(dir, "non-canon-gguf")
	exeBody := []byte("non-canon synthetic executable, never launched")
	modelBody := []byte("non-canon synthetic model, never loaded")
	if err = os.WriteFile(exe, exeBody, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(model, modelBody, 0600); err != nil {
		t.Fatal(err)
	}
	seed.Profile.LocalRuntimeIdentity.BinarySHA256 = inputSHA(exeBody)
	seed.Profile.LocalRuntimeIdentity.GGUFSHA256 = inputSHA(modelBody)
	profile, err := modelgateway.BindModelProfile(seed.Profile)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	spec := modelgateway.ManagedLlamaSpec{ExecutablePath: exe, GGUFPath: model} // Incomplete process spec must fail before a server starts.
	guard, err := NewMemoryGuardedLocal(profile, spec, &log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = guard.RegisteredManager(); !errors.Is(err, ErrMemory) {
		t.Fatal("manager exposed before gates", err)
	}
	if err = guard.Start(context.Background()); err == nil {
		t.Fatal("incomplete runtime spec admitted")
	}
	if guard.manager != nil || !guard.retired || len(guard.assets) != 0 {
		t.Fatal("failed preparation kept handles")
	}
	if !bytes.Contains(log.Bytes(), []byte(`"phase":"AFTER_RETIRE"`)) || bytes.Contains(log.Bytes(), []byte(dir)) {
		t.Fatal("cleanup memory receipt missing or locator leaked")
	}
	if err = guard.Start(context.Background()); !errors.Is(err, ErrMemory) {
		t.Fatal("failed startup retried as a fresh generation", err)
	}
	if err = guard.Retire(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A source mutation fails authentication before cache-release or startup.
	if err = os.WriteFile(model, []byte("changed non-canon fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = NewMemoryGuardedLocal(profile, spec, &log); !errors.Is(err, ErrMemory) {
		t.Fatal("changed held asset accepted", err)
	}
}

func TestMemoryLifecycleCancellationKeepsServerUnstartedAndExplicitRetirement(t *testing.T) {
	var log bytes.Buffer
	guard := &MemoryGuardedLocal{record: &log}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := guard.Start(ctx); !errors.Is(err, ErrMemory) || guard.attempted || guard.manager != nil {
		t.Fatal("canceled construction started generation", err)
	}
	if err := guard.Retire(context.Background()); err != nil || !guard.retired {
		t.Fatal("canceled guard failed cleanup", err)
	}
	if _, err := registeredDescendantPID(0, "invalid"); !errors.Is(err, ErrMemory) {
		t.Fatal("invalid PID/hash admitted", err)
	}
}

func TestMemoryLifecycleDoesNotExposeOwnedButUnreadyGeneration(t *testing.T) {
	// This is a synthetic half-started/cleanup-failed state. It contains no
	// process handle and does not execute Start, Retire, sockets or model code.
	guard := &MemoryGuardedLocal{manager: &modelgateway.ManagedLlama{}, pid: 2, attempted: true, retired: false}
	if manager, err := guard.RegisteredManager(); manager != nil || !errors.Is(err, ErrMemory) {
		t.Fatal("cleanup ownership was mistaken for successful cache-gated startup", manager, err)
	}
}

func TestMemoryDiscoveryChildFixture(t *testing.T) {
	if os.Getenv("AIPT_B007_NON_CANON_DISCOVERY_CHILD") != "1" {
		return
	}
	// This is the test binary itself, with no model, server or native asset.
	_, _ = os.Stdout.Write([]byte("ready\n"))
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func TestMemoryDiscoveryFindsNonLeaderThreadOwnedChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	expected := hex.EncodeToString(h.Sum(nil))
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if syscall.Gettid() == os.Getpid() {
			result <- errors.New("test requires nonleader spawning thread")
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestMemoryDiscoveryChildFixture$")
		cmd.Env = append(os.Environ(), "AIPT_B007_NON_CANON_DISCOVERY_CHILD=1")
		input, err := cmd.StdinPipe()
		if err != nil {
			result <- err
			return
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			result <- err
			return
		}
		if err = cmd.Start(); err != nil {
			result <- err
			return
		}
		line, err := bufio.NewReader(output).ReadString('\n')
		if err == nil && line != "ready\n" {
			err = errors.New("child fixture not ready")
		}
		if err == nil {
			pid, findErr := registeredDescendantPID(os.Getpid(), expected)
			if findErr != nil || pid != cmd.Process.Pid {
				err = errors.New("nonleader child missing from registered descendant inventory")
			}
		}
		_ = input.Close()
		waitErr := cmd.Wait()
		if err == nil {
			err = waitErr
		}
		result <- err
	}()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestMemoryAdapterPreparationFreezesBindingAndRejectsStateChanges(t *testing.T) {
	var log bytes.Buffer
	profile := modelgateway.ModelProfile{ProfileID: "non-canon-fixture", ProfileVersion: "1.0.0"}
	seed := modelgateway.AdapterRouteSpec{ProfileBinding: profile.BindingID(), ExecutablePath: "fixture-exe", ExecutableSHA256: inputSHA([]byte("exe")), AdapterEntrypointPath: "fixture-worker", AdapterEntrypointSHA256: inputSHA([]byte("worker")), RouteConfigPath: "fixture-route", RouteConfigSHA256: inputSHA([]byte("route")), WorkingDirectory: "fixture-directory", Arguments: []string{"original"}, Environment: map[string]string{"FIXTURE": "original"}, StartupTimeout: time.Second, ShutdownTimeout: time.Second}
	for _, kind := range []string{"wrong-profile", "endpoint", "owned-launcher", "bad-digest", "timeout", "already-attempted", "retired"} {
		t.Run(kind, func(t *testing.T) {
			guard := &MemoryGuardedLocal{profile: profile, record: &log}
			candidate := seed
			endpoint := "AIPT_FIXTURE_ENDPOINT"
			switch kind {
			case "wrong-profile":
				candidate.ProfileBinding = "wrong"
			case "endpoint":
				endpoint = "INVALID-ENDPOINT"
			case "owned-launcher":
				candidate.IsolatedLauncher = &modelgateway.ManagedLlama{}
			case "bad-digest":
				candidate.RouteConfigSHA256 = "invalid"
			case "timeout":
				candidate.ShutdownTimeout = 0
			case "already-attempted":
				guard.attempted = true
			case "retired":
				guard.retired = true
			}
			if err := guard.PrepareIsolatedAdapter(candidate, endpoint); !errors.Is(err, ErrMemory) || guard.adapter != nil {
				t.Fatal("invalid binding admitted", err)
			}
		})
	}
	guard := &MemoryGuardedLocal{profile: profile, record: &log}
	if err := guard.PrepareIsolatedAdapter(seed, "AIPT_FIXTURE_ENDPOINT"); err != nil {
		t.Fatal(err)
	}
	seed.Arguments[0] = "changed"
	seed.Environment["FIXTURE"] = "changed"
	if guard.adapter.Arguments[0] != "original" || guard.adapter.Environment["FIXTURE"] != "original" {
		t.Fatal("caller mutation changed held route")
	}
	if _, err := guard.RegisteredManager(); !errors.Is(err, ErrMemory) {
		t.Fatal("preparation exposed startup capability", err)
	}
	if err := guard.PrepareIsolatedAdapter(seed, "AIPT_FIXTURE_ENDPOINT"); !errors.Is(err, ErrMemory) {
		t.Fatal("second route replaced first", err)
	}
	if err := guard.Retire(context.Background()); err != nil || guard.adapter != nil || guard.endpointEnvironment != "" {
		t.Fatal("retirement kept prepared binding", err)
	}
	if err := guard.PrepareIsolatedAdapter(seed, "AIPT_FIXTURE_ENDPOINT"); !errors.Is(err, ErrMemory) {
		t.Fatal("retired preparation restarted", err)
	}
}

func TestMemoryRetirementFailureBeforeStartPermanentlyRevokesAdmission(t *testing.T) {
	for _, kind := range []string{"canceled-context", "failed-receipt", "nil-context"} {
		t.Run(kind, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "non-canon-cache")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err = f.WriteString("non-canon, never a model"); err != nil {
				t.Fatal(err)
			}
			var record bytes.Buffer
			var writer io.Writer = &record
			ctx := context.Background()
			if kind == "failed-receipt" {
				writer = nonCanonFailWriter{}
			} else if kind == "nil-context" {
				ctx = nil
			} else {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			guard := &MemoryGuardedLocal{record: writer, assets: []CacheAsset{{AssetID: "NON_CANON_CACHE", File: f}}}
			if err = guard.Retire(ctx); err == nil {
				t.Fatal("fixture did not fail retirement")
			}
			if !guard.admissionRevoked || guard.retired || len(guard.assets) != 1 {
				t.Fatal("cleanup ownership or permanent admission state lost")
			}
			if err = guard.Start(context.Background()); !errors.Is(err, ErrMemory) || guard.attempted {
				t.Fatal("failed retirement admitted startup", err)
			}
			if err = guard.PrepareIsolatedAdapter(modelgateway.AdapterRouteSpec{}, "AIPT_TEST_ENDPOINT"); !errors.Is(err, ErrMemory) {
				t.Fatal("failed retirement admitted preparation", err)
			}
			guard.record = &record
			if err = guard.Retire(context.Background()); err != nil || !guard.retired || len(guard.assets) != 0 {
				t.Fatal("cleanup-only retry failed", err)
			}
		})
	}
}

type nonCanonFailWriter struct{}

func (nonCanonFailWriter) Write([]byte) (int, error) { return 0, errors.New("NON_CANON_RECEIPT_ERROR") }
