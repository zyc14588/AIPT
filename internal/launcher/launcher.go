package launcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zyc14588/AIPT/internal/config"
)

// Options freezes the complete implementation set and reverse-shutdown bound.
type Options struct {
	Dependencies    Dependencies
	ShutdownTimeout time.Duration
}

// Launcher is immutable after construction and always walks fixedGateOrder.
type Launcher struct {
	configPath      string
	dependencies    Dependencies
	shutdownTimeout time.Duration
}

// NewDefault constructs the production B004 launcher. With a complete private
// runtime configuration it completes MODEL/HARNESS/CORE, then fails closed at
// IPC; missing model assets or credentials fail earlier at their real gate.
func NewDefault(configPath string) (*Launcher, error) {
	return New(configPath, Options{
		Dependencies:    DefaultDependencies(DefaultShutdownTimeout),
		ShutdownTimeout: DefaultShutdownTimeout,
	})
}

// New validates a dependency set. Dependency injection can replace a gate's
// behavior for tests but cannot change the gate inventory or order.
func New(configPath string, options Options) (*Launcher, error) {
	if configPath == "" {
		return nil, newGateError(CodeInvalidOptions, "", "new", errors.New("config path is required"))
	}
	if options.ShutdownTimeout <= 0 {
		return nil, newGateError(CodeInvalidOptions, "", "new", errors.New("shutdown timeout must be positive"))
	}
	if err := validateDependencies(options.Dependencies); err != nil {
		return nil, newGateError(CodeInvalidOptions, "", "new", err)
	}
	return &Launcher{
		configPath:      configPath,
		dependencies:    options.Dependencies,
		shutdownTimeout: options.ShutdownTimeout,
	}, nil
}

func validateDependencies(dependencies Dependencies) error {
	checks := []struct {
		name string
		set  bool
	}{
		{"LoadConfig", dependencies.LoadConfig != nil},
		{"OpenPostgres", dependencies.OpenPostgres != nil},
		{"MigrateUp", dependencies.MigrateUp != nil},
		{"StartModel", dependencies.StartModel != nil},
		{"StartHarness", dependencies.StartHarness != nil},
		{"StartCore", dependencies.StartCore != nil},
		{"StartIPC", dependencies.StartIPC != nil},
		{"StartWeb", dependencies.StartWeb != nil},
	}
	for _, check := range checks {
		if !check.set {
			return fmt.Errorf("dependency %s is required", check.name)
		}
	}
	return nil
}

// Plan returns a fresh copy of the fixed production plan.
func (l *Launcher) Plan() LaunchPlan {
	return Plan()
}

type runState struct {
	config *config.Config
	pool   PostgresPool
}

type startedGate struct {
	gate Gate
	stop StopFunc
}

// Run owns the whole process lifecycle. Startup is fail-fast; a startup error
// triggers independent bounded reverse cleanup and remains the first joined
// error. A fully injected successful run waits for ctx cancellation, treats
// that cancellation as a graceful stop request, and performs the same cleanup.
func (l *Launcher) Run(ctx context.Context) error {
	if l == nil {
		return newGateError(CodeInvalidOptions, "", "run", errors.New("nil launcher"))
	}
	if ctx == nil {
		return newGateError(CodeInvalidOptions, "", "run", errors.New("nil context"))
	}

	state := &runState{}
	started := make([]startedGate, 0, len(fixedGateOrder))
	completed := make([]Gate, 0, len(fixedGateOrder))
	for _, gate := range fixedGateOrder {
		if err := ctx.Err(); err != nil {
			return l.failAndCleanup(
				newGateError(CodeCancelled, gate, "start", err),
				started,
			)
		}

		stop, err := l.startGate(ctx, gate, state, completed)
		if stop != nil {
			started = append(started, startedGate{gate: gate, stop: stop})
		}
		if err != nil {
			return l.failAndCleanup(l.normalizeStartError(ctx, gate, err), started)
		}
		completed = append(completed, gate)
	}

	<-ctx.Done()
	return l.cleanup(started)
}

func (l *Launcher) startGate(ctx context.Context, gate Gate, state *runState, completed []Gate) (StopFunc, error) {
	switch gate {
	case GateConfig:
		loaded, err := l.dependencies.LoadConfig(l.configPath)
		if err != nil {
			return nil, err
		}
		if loaded == nil {
			return nil, errors.New("config loader returned nil without an error")
		}
		state.config = loaded
		return nil, nil

	case GatePostgreSQL:
		if state.config == nil {
			return nil, errors.New("validated config is unavailable")
		}
		pool, err := l.dependencies.OpenPostgres(ctx, state.config.Database().DSN())
		var stop StopFunc
		if pool != nil {
			stop = func(context.Context) error {
				pool.Close()
				return nil
			}
		}
		if err != nil {
			return stop, err
		}
		if pool == nil {
			return nil, errors.New("postgres opener returned nil without an error")
		}

		timeout := time.Duration(state.config.Database().PingTimeoutMS()) * time.Millisecond
		pingContext, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := pool.Ping(pingContext); err != nil {
			return stop, err
		}
		state.pool = pool
		return stop, nil

	case GateMigrations:
		if state.pool == nil {
			return nil, errors.New("postgres pool is unavailable")
		}
		return nil, l.dependencies.MigrateUp(ctx, state.pool)

	case GateModel:
		return l.dependencies.StartModel(ctx)
	case GateHarness:
		return l.dependencies.StartHarness(ctx)
	case GateCore:
		return l.dependencies.StartCore(ctx)
	case GateIPC:
		return l.dependencies.StartIPC(ctx)
	case GateWeb:
		prior := append([]Gate(nil), completed...)
		return l.dependencies.StartWeb(ctx, WebStartState{
			Config:            state.config,
			PriorStartedGates: prior,
		})
	default:
		return nil, errors.New("unknown launch gate")
	}
}

func (l *Launcher) normalizeStartError(ctx context.Context, gate Gate, err error) error {
	var launcherError *GateError
	if errors.As(err, &launcherError) && launcherError != nil {
		return err
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return newGateError(CodeCancelled, gate, "start", contextErr)
	}
	return newGateError(CodeGateFailed, gate, "start", err)
}

func (l *Launcher) failAndCleanup(root error, started []startedGate) error {
	cleanupError := l.cleanup(started)
	if cleanupError == nil {
		return root
	}
	return errors.Join(root, cleanupError)
}

func (l *Launcher) cleanup(started []startedGate) error {
	shutdownContext, cancel := context.WithTimeout(context.Background(), l.shutdownTimeout)
	defer cancel()

	var cleanupErrors []error
	for index := len(started) - 1; index >= 0; index-- {
		component := started[index]
		if err := component.stop(shutdownContext); err != nil {
			cleanupErrors = append(cleanupErrors,
				newGateError(CodeShutdownFailed, component.gate, "stop", err))
		}
	}
	if err := shutdownContext.Err(); err != nil {
		cleanupErrors = append(cleanupErrors,
			newGateError(CodeShutdownTimeout, "", "stop", err))
	}
	return errors.Join(cleanupErrors...)
}
