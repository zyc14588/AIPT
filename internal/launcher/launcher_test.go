package launcher

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/config"
)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type fakePool struct {
	log        *eventLog
	ping       func(context.Context) error
	mu         sync.Mutex
	pingCount  int
	closeCount int
}

func (p *fakePool) Ping(ctx context.Context) error {
	p.mu.Lock()
	p.pingCount++
	p.mu.Unlock()
	if p.ping != nil {
		return p.ping(ctx)
	}
	return nil
}

func (p *fakePool) Close() {
	p.mu.Lock()
	p.closeCount++
	p.mu.Unlock()
	if p.log != nil {
		p.log.add("stop:" + string(GatePostgreSQL))
	}
}

func (p *fakePool) counts() (ping, close int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pingCount, p.closeCount
}

func launcherTestConfig(t *testing.T, pingTimeoutMS int64) *config.Config {
	t.Helper()
	doc := "{" +
		"\"schema\":\"aipt.config/v1\"," +
		"\"profile\":\"development\"," +
		"\"database\":{" +
		"\"dsn\":\"postgres://aipt:test-secret@127.0.0.1:5432/aipt_development?sslmode=disable\"," +
		"\"identity\":\"aipt_development\"," +
		"\"namespace\":\"aipt_dev\"," +
		"\"ping_timeout_ms\":" + strconv.FormatInt(pingTimeoutMS, 10) + "}," +
		"\"evidence\":{\"namespace\":\"aipt.evidence.development\"}}"
	loaded, err := config.Load([]byte(doc))
	if err != nil {
		t.Fatalf("load launcher test config: %v", err)
	}
	return loaded
}

func recordingComponent(log *eventLog, gate Gate, expired *atomic.Bool) ComponentStart {
	return func(context.Context) (StopFunc, error) {
		log.add("start:" + string(gate))
		return func(ctx context.Context) error {
			if ctx.Err() != nil && expired != nil {
				expired.Store(true)
			}
			log.add("stop:" + string(gate))
			return nil
		}, nil
	}
}

func recordingWebComponent(log *eventLog, expired *atomic.Bool) WebStart {
	return func(context.Context, WebStartState) (StopFunc, error) {
		log.add("start:" + string(GateWeb))
		return func(ctx context.Context) error {
			if ctx.Err() != nil && expired != nil {
				expired.Store(true)
			}
			log.add("stop:" + string(GateWeb))
			return nil
		}, nil
	}
}

func successfulDependencies(t *testing.T, log *eventLog, timeout time.Duration) (Dependencies, *fakePool) {
	t.Helper()
	loaded := launcherTestConfig(t, 1000)
	pool := &fakePool{log: log}
	dependencies := DefaultDependencies(timeout)
	dependencies.LoadConfig = func(path string) (*config.Config, error) {
		if path != "config.json" {
			t.Errorf("config path = %q, want config.json", path)
		}
		log.add("start:" + string(GateConfig))
		return loaded, nil
	}
	dependencies.OpenPostgres = func(_ context.Context, dsn string) (PostgresPool, error) {
		if dsn != loaded.Database().DSN() {
			t.Error("postgres opener did not receive the exact validated DSN")
		}
		log.add("start:" + string(GatePostgreSQL))
		return pool, nil
	}
	dependencies.MigrateUp = func(context.Context, PostgresPool) error {
		log.add("start:" + string(GateMigrations))
		return nil
	}
	dependencies.StartModel = recordingComponent(log, GateModel, nil)
	dependencies.StartHarness = recordingComponent(log, GateHarness, nil)
	dependencies.StartCore = recordingComponent(log, GateCore, nil)
	dependencies.StartIPC = recordingComponent(log, GateIPC, nil)
	dependencies.StartWeb = recordingWebComponent(log, nil)
	return dependencies, pool
}

func mustLauncher(t *testing.T, dependencies Dependencies, timeout time.Duration) *Launcher {
	t.Helper()
	instance, err := New("config.json", Options{
		Dependencies:    dependencies,
		ShutdownTimeout: timeout,
	})
	if err != nil {
		t.Fatalf("New launcher: %v", err)
	}
	return instance
}

func TestFixedGateOrderAndPlanAreImmutable(t *testing.T) {
	want := []Gate{
		GateConfig,
		GatePostgreSQL,
		GateMigrations,
		GateModel,
		GateHarness,
		GateCore,
		GateIPC,
		GateWeb,
	}
	if got := FixedGateOrder(); !reflect.DeepEqual(got, want) {
		t.Fatalf("FixedGateOrder = %v, want %v", got, want)
	}

	mutated := FixedGateOrder()
	mutated[0] = GateWeb
	if got := FixedGateOrder(); !reflect.DeepEqual(got, want) {
		t.Fatalf("caller mutated fixed order: %v", got)
	}

	plan := Plan()
	if plan.Schema != planSchema || plan.RuntimeReady || plan.FirstBlockingGate != GateModel {
		t.Fatalf("Plan = %+v", plan)
	}
	if len(plan.Gates) != len(want) {
		t.Fatalf("plan gate count = %d, want %d", len(plan.Gates), len(want))
	}
	for index, gate := range plan.Gates {
		if gate.Position != index+1 || gate.Gate != want[index] {
			t.Errorf("plan gate %d = %+v", index, gate)
		}
		wantImplementation := NotImplemented
		if gate.Gate == GateConfig || gate.Gate == GatePostgreSQL ||
			gate.Gate == GateMigrations || gate.Gate == GateCore || gate.Gate == GateWeb {
			wantImplementation = Implemented
		}
		if gate.Implementation != wantImplementation {
			t.Errorf("%s implementation = %s, want %s", gate.Gate, gate.Implementation, wantImplementation)
		}
	}

	plan.Gates[0].Gate = GateWeb
	if Plan().Gates[0].Gate != GateConfig {
		t.Fatal("caller mutated package plan")
	}

	first, err := json.Marshal(Plan())
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(Plan())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("plan JSON is not deterministic:\n%s\n%s", first, second)
	}
	if !strings.Contains(string(first), "\"runtime_ready\":false") ||
		!strings.Contains(string(first), "\"first_blocking_gate\":\"MODEL\"") {
		t.Fatalf("plan JSON does not state fail-closed readiness: %s", first)
	}
}

func TestNewRejectsInvalidOptions(t *testing.T) {
	log := &eventLog{}
	dependencies, _ := successfulDependencies(t, log, time.Second)

	if _, err := New("", Options{Dependencies: dependencies, ShutdownTimeout: time.Second}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New(empty path) = %v, want ErrInvalidOptions", err)
	}
	if _, err := New("config.json", Options{Dependencies: dependencies}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New(zero timeout) = %v, want ErrInvalidOptions", err)
	}

	tests := []struct {
		name  string
		clear func(*Dependencies)
	}{
		{"LoadConfig", func(d *Dependencies) { d.LoadConfig = nil }},
		{"OpenPostgres", func(d *Dependencies) { d.OpenPostgres = nil }},
		{"MigrateUp", func(d *Dependencies) { d.MigrateUp = nil }},
		{"StartModel", func(d *Dependencies) { d.StartModel = nil }},
		{"StartHarness", func(d *Dependencies) { d.StartHarness = nil }},
		{"StartCore", func(d *Dependencies) { d.StartCore = nil }},
		{"StartIPC", func(d *Dependencies) { d.StartIPC = nil }},
		{"StartWeb", func(d *Dependencies) { d.StartWeb = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := dependencies
			tt.clear(&candidate)
			_, err := New("config.json", Options{Dependencies: candidate, ShutdownTimeout: time.Second})
			if !errors.Is(err, ErrInvalidOptions) || CodeOf(err) != CodeInvalidOptions {
				t.Fatalf("New with nil %s = %v", tt.name, err)
			}
		})
	}

	var nilLauncher *Launcher
	if err := nilLauncher.Run(context.Background()); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil Launcher.Run = %v", err)
	}
	instance := mustLauncher(t, dependencies, time.Second)
	if err := instance.Run(nil); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("Run(nil) = %v", err)
	}
}

func TestRunExactOrderAndReverseShutdown(t *testing.T) {
	log := &eventLog{}
	const timeout = time.Second
	dependencies, pool := successfulDependencies(t, log, timeout)
	var expired atomic.Bool
	dependencies.StartModel = recordingComponent(log, GateModel, &expired)
	dependencies.StartHarness = recordingComponent(log, GateHarness, &expired)
	dependencies.StartCore = recordingComponent(log, GateCore, &expired)
	dependencies.StartIPC = recordingComponent(log, GateIPC, &expired)

	ctx, cancel := context.WithCancel(context.Background())
	var webState WebStartState
	dependencies.StartWeb = func(_ context.Context, state WebStartState) (StopFunc, error) {
		webState = state
		state.PriorStartedGates[0] = GateWeb
		log.add("start:" + string(GateWeb))
		cancel()
		return func(stopContext context.Context) error {
			if stopContext.Err() != nil {
				expired.Store(true)
			}
			log.add("stop:" + string(GateWeb))
			return nil
		}, nil
	}

	instance := mustLauncher(t, dependencies, timeout)
	if err := instance.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want graceful cancellation", err)
	}
	if expired.Load() {
		t.Fatal("signal cancellation leaked into independent cleanup context")
	}
	if webState.Config == nil || webState.Config.Schema() != config.SchemaMarker {
		t.Fatal("WEB did not receive the validated Config")
	}
	wantPrior := []Gate{GateConfig, GatePostgreSQL, GateMigrations, GateModel, GateHarness, GateCore, GateIPC}
	if !reflect.DeepEqual(webState.PriorStartedGates, append([]Gate{GateWeb}, wantPrior[1:]...)) {
		t.Fatalf("WEB test did not observe its intentional local mutation: %v", webState.PriorStartedGates)
	}
	if got := FixedGateOrder(); !reflect.DeepEqual(got, append(wantPrior, GateWeb)) {
		t.Fatalf("WEB mutated package-owned gate order: %v", got)
	}
	want := []string{
		"start:CONFIG",
		"start:POSTGRESQL",
		"start:MIGRATIONS",
		"start:MODEL",
		"start:HARNESS",
		"start:CORE",
		"start:IPC",
		"start:WEB",
		"stop:WEB",
		"stop:IPC",
		"stop:CORE",
		"stop:HARNESS",
		"stop:MODEL",
		"stop:POSTGRESQL",
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if ping, close := pool.counts(); ping != 1 || close != 1 {
		t.Fatalf("pool counts = ping:%d close:%d, want 1/1", ping, close)
	}
}

func TestRunFailFastAtEveryImplementedBoundary(t *testing.T) {
	t.Run("config", func(t *testing.T) {
		log := &eventLog{}
		dependencies, pool := successfulDependencies(t, log, time.Second)
		root := errors.New("config-secret-cause")
		dependencies.LoadConfig = func(string) (*config.Config, error) {
			log.add("start:" + string(GateConfig))
			return nil, root
		}
		err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
		if !errors.Is(err, root) || !errors.Is(err, ErrGateFailed) ||
			CodeOf(err) != CodeGateFailed || GateOf(err) != GateConfig {
			t.Fatalf("Run = %v", err)
		}
		if strings.Contains(err.Error(), "config-secret-cause") {
			t.Fatalf("launcher error leaks provider cause: %v", err)
		}
		if got := log.snapshot(); !reflect.DeepEqual(got, []string{"start:CONFIG"}) {
			t.Fatalf("events = %v", got)
		}
		if _, close := pool.counts(); close != 0 {
			t.Fatalf("unopened pool close count = %d", close)
		}
	})

	t.Run("postgres-open-partial", func(t *testing.T) {
		log := &eventLog{}
		dependencies, pool := successfulDependencies(t, log, time.Second)
		root := errors.New("open failed")
		dependencies.OpenPostgres = func(context.Context, string) (PostgresPool, error) {
			log.add("start:" + string(GatePostgreSQL))
			return pool, root
		}
		err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
		if !errors.Is(err, root) || GateOf(err) != GatePostgreSQL {
			t.Fatalf("Run = %v", err)
		}
		want := []string{"start:CONFIG", "start:POSTGRESQL", "stop:POSTGRESQL"}
		if got := log.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("events = %v, want %v", got, want)
		}
	})

	t.Run("postgres-ping", func(t *testing.T) {
		log := &eventLog{}
		dependencies, pool := successfulDependencies(t, log, time.Second)
		root := errors.New("ping failed")
		pool.ping = func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
				t.Errorf("ping context deadline = %v, ok=%v", deadline, ok)
			}
			return root
		}
		err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
		if !errors.Is(err, root) || GateOf(err) != GatePostgreSQL {
			t.Fatalf("Run = %v", err)
		}
		want := []string{"start:CONFIG", "start:POSTGRESQL", "stop:POSTGRESQL"}
		if got := log.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("events = %v, want %v", got, want)
		}
	})

	t.Run("migrations", func(t *testing.T) {
		log := &eventLog{}
		dependencies, pool := successfulDependencies(t, log, time.Second)
		root := errors.New("migration failed")
		dependencies.MigrateUp = func(context.Context, PostgresPool) error {
			log.add("start:" + string(GateMigrations))
			return root
		}
		err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
		if !errors.Is(err, root) || GateOf(err) != GateMigrations {
			t.Fatalf("Run = %v", err)
		}
		want := []string{
			"start:CONFIG",
			"start:POSTGRESQL",
			"start:MIGRATIONS",
			"stop:POSTGRESQL",
		}
		if got := log.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("events = %v, want %v", got, want)
		}
		if ping, close := pool.counts(); ping != 1 || close != 1 {
			t.Fatalf("pool counts = %d/%d", ping, close)
		}
	})
}

func TestConfiguredPingTimeoutFailsClosed(t *testing.T) {
	log := &eventLog{}
	const pingTimeoutMS = 20
	loaded := launcherTestConfig(t, pingTimeoutMS)
	pool := &fakePool{log: log}
	pool.ping = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	dependencies, _ := successfulDependencies(t, log, time.Second)
	dependencies.LoadConfig = func(string) (*config.Config, error) {
		log.add("start:" + string(GateConfig))
		return loaded, nil
	}
	dependencies.OpenPostgres = func(context.Context, string) (PostgresPool, error) {
		log.add("start:" + string(GatePostgreSQL))
		return pool, nil
	}

	started := time.Now()
	err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrGateFailed) ||
		GateOf(err) != GatePostgreSQL {
		t.Fatalf("Run = %v", err)
	}
	if elapsed < 10*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("ping timeout elapsed = %s", elapsed)
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, []string{
		"start:CONFIG", "start:POSTGRESQL", "stop:POSTGRESQL",
	}) {
		t.Fatalf("events = %v", got)
	}
}

func TestProductionModelGateFailsClosed(t *testing.T) {
	log := &eventLog{}
	dependencies, pool := successfulDependencies(t, log, time.Second)
	production := DefaultDependencies(time.Second)
	dependencies.StartModel = production.StartModel

	instance := mustLauncher(t, dependencies, time.Second)
	if instance.Plan().RuntimeReady {
		t.Fatal("plan must not claim runtime readiness")
	}
	err := instance.Run(context.Background())
	if !errors.Is(err, ErrGateNotImplemented) ||
		CodeOf(err) != CodeGateNotImplemented || GateOf(err) != GateModel {
		t.Fatalf("Run = %v", err)
	}
	want := []string{
		"start:CONFIG",
		"start:POSTGRESQL",
		"start:MIGRATIONS",
		"stop:POSTGRESQL",
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	if _, close := pool.counts(); close != 1 {
		t.Fatalf("pool close count = %d", close)
	}
}

func TestStartupRootErrorPrecedesAndSurvivesCleanupError(t *testing.T) {
	log := &eventLog{}
	dependencies, _ := successfulDependencies(t, log, time.Second)
	root := errors.New("startup-root-secret")
	cleanup := errors.New("cleanup-secondary-secret")
	dependencies.StartModel = func(context.Context) (StopFunc, error) {
		log.add("start:" + string(GateModel))
		return func(context.Context) error {
			log.add("stop:" + string(GateModel))
			return cleanup
		}, root
	}

	err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
	if !errors.Is(err, root) || !errors.Is(err, cleanup) ||
		!errors.Is(err, ErrGateFailed) || !errors.Is(err, ErrShutdownFailed) {
		t.Fatalf("Run = %v", err)
	}
	if CodeOf(err) != CodeGateFailed || GateOf(err) != GateModel {
		t.Fatalf("root classification = %s/%s", CodeOf(err), GateOf(err))
	}
	if strings.Contains(err.Error(), "startup-root-secret") ||
		strings.Contains(err.Error(), "cleanup-secondary-secret") {
		t.Fatalf("joined error leaks a dependency cause: %v", err)
	}
	want := []string{
		"start:CONFIG",
		"start:POSTGRESQL",
		"start:MIGRATIONS",
		"start:MODEL",
		"stop:MODEL",
		"stop:POSTGRESQL",
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestCancellationDuringStartupStopsEarlierGates(t *testing.T) {
	log := &eventLog{}
	dependencies, pool := successfulDependencies(t, log, time.Second)
	entered := make(chan struct{})
	dependencies.StartModel = func(ctx context.Context) (StopFunc, error) {
		log.add("start:" + string(GateModel))
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	instance := mustLauncher(t, dependencies, time.Second)
	go func() {
		result <- instance.Run(ctx)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("MODEL gate was not entered")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, ErrCancelled) || !errors.Is(err, context.Canceled) ||
			CodeOf(err) != CodeCancelled || GateOf(err) != GateModel {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not return after cancellation")
	}
	if _, close := pool.counts(); close != 1 {
		t.Fatalf("pool close count = %d", close)
	}
}

func TestCoreGateUsesRealCoreShellThroughDependencyInjection(t *testing.T) {
	log := &eventLog{}
	dependencies, _ := successfulDependencies(t, log, time.Second)
	productionCore := DefaultDependencies(time.Second).StartCore
	dependencies.StartCore = func(ctx context.Context) (StopFunc, error) {
		log.add("start:" + string(GateCore))
		stop, err := productionCore(ctx)
		if err != nil {
			return stop, err
		}
		return func(stopContext context.Context) error {
			log.add("stop:" + string(GateCore))
			return stop(stopContext)
		}, nil
	}
	root := errors.New("ipc unavailable")
	dependencies.StartIPC = func(context.Context) (StopFunc, error) {
		log.add("start:" + string(GateIPC))
		return nil, root
	}

	err := mustLauncher(t, dependencies, time.Second).Run(context.Background())
	if !errors.Is(err, root) || GateOf(err) != GateIPC {
		t.Fatalf("Run = %v", err)
	}
	want := []string{
		"start:CONFIG",
		"start:POSTGRESQL",
		"start:MIGRATIONS",
		"start:MODEL",
		"start:HARNESS",
		"start:CORE",
		"start:IPC",
		"stop:CORE",
		"stop:HARNESS",
		"stop:MODEL",
		"stop:POSTGRESQL",
	}
	if got := log.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestShutdownTimeoutIsBoundedAndLaterStopsStillRun(t *testing.T) {
	log := &eventLog{}
	const timeout = 25 * time.Millisecond
	dependencies, _ := successfulDependencies(t, log, timeout)
	ctx, cancel := context.WithCancel(context.Background())
	dependencies.StartWeb = func(context.Context, WebStartState) (StopFunc, error) {
		log.add("start:" + string(GateWeb))
		cancel()
		return func(stopContext context.Context) error {
			log.add("stop:" + string(GateWeb))
			<-stopContext.Done()
			return stopContext.Err()
		}, nil
	}

	started := time.Now()
	err := mustLauncher(t, dependencies, timeout).Run(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrShutdownFailed) || !errors.Is(err, ErrShutdownTimeout) ||
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v", err)
	}
	if elapsed < timeout || elapsed > 500*time.Millisecond {
		t.Fatalf("bounded shutdown elapsed = %s", elapsed)
	}
	events := log.snapshot()
	if len(events) == 0 || events[len(events)-1] != "stop:POSTGRESQL" {
		t.Fatalf("later reverse stops did not run after timeout: %v", events)
	}
}

func TestPreCancelledContextStartsNothing(t *testing.T) {
	log := &eventLog{}
	dependencies, pool := successfulDependencies(t, log, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := mustLauncher(t, dependencies, time.Second).Run(ctx)
	if !errors.Is(err, ErrCancelled) || GateOf(err) != GateConfig {
		t.Fatalf("Run = %v", err)
	}
	if got := log.snapshot(); len(got) != 0 {
		t.Fatalf("pre-cancelled run started gates: %v", got)
	}
	if ping, close := pool.counts(); ping != 0 || close != 0 {
		t.Fatalf("pool counts = %d/%d", ping, close)
	}
}

func TestErrorHelpersAndNilError(t *testing.T) {
	plain := errors.New("plain")
	if CodeOf(plain) != "" || GateOf(plain) != "" {
		t.Fatal("plain error must not classify as launcher error")
	}
	if CodeOf(nil) != "" || GateOf(nil) != "" {
		t.Fatal("nil error must not classify as launcher error")
	}
	var nilGateError *GateError
	if nilGateError.Error() != "<nil>" || nilGateError.Unwrap() != nil {
		t.Fatal("nil GateError methods are not stable")
	}
}
