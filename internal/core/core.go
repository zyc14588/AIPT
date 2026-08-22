package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is the explicit core lifecycle state.
type State string

const (
	StateNew      State = "NEW"
	StateStarting State = "STARTING"
	StateRunning  State = "RUNNING"
	StateStopping State = "STOPPING"
	StateStopped  State = "STOPPED"
	StateFailed   State = "FAILED"
)

// Dependency is one explicit Core-owned lifecycle dependency. Start, Ready,
// and Stop must be synchronous and context-aware. Core never creates a
// goroutine around them, preventing abandoned cleanup goroutines.
type Dependency struct {
	Name  string
	Start func(context.Context) error
	Ready func(context.Context) error
	Stop  func(context.Context) error
}

// Options freezes dependency order and bounds reverse shutdown.
type Options struct {
	Dependencies    []Dependency
	ShutdownTimeout time.Duration
}

// Snapshot is an immutable diagnostic view of lifecycle state.
type Snapshot struct {
	State               State
	Ready               bool
	StartedDependencies []string
}

// Core is the B004 lifecycle shell. opMu serializes lifecycle operations;
// mu protects observable state for concurrent readers.
type Core struct {
	opMu sync.Mutex
	mu   sync.RWMutex

	state           State
	ready           bool
	dependencies    []Dependency
	started         []int
	shutdownTimeout time.Duration
}

// New validates and copies the complete dependency contract. No dependency is
// started and no goroutine or network resource is created.
func New(options Options) (*Core, error) {
	if options.ShutdownTimeout <= 0 {
		return nil, lifecycleError(
			CodeInvalidOptions,
			"new",
			"",
			StateNew,
			errors.New("shutdown timeout must be positive"),
		)
	}
	dependencies := append([]Dependency(nil), options.Dependencies...)
	seen := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if dependency.Name == "" {
			return nil, lifecycleError(
				CodeInvalidOptions,
				"new",
				"",
				StateNew,
				errors.New("dependency name must not be empty"),
			)
		}
		if _, exists := seen[dependency.Name]; exists {
			return nil, lifecycleError(
				CodeInvalidOptions,
				"new",
				dependency.Name,
				StateNew,
				errors.New("dependency names must be unique"),
			)
		}
		seen[dependency.Name] = struct{}{}
		if dependency.Start == nil || dependency.Ready == nil || dependency.Stop == nil {
			return nil, lifecycleError(
				CodeInvalidOptions,
				"new",
				dependency.Name,
				StateNew,
				errors.New("dependency Start, Ready, and Stop functions are required"),
			)
		}
	}
	return &Core{
		state:           StateNew,
		dependencies:    dependencies,
		shutdownTimeout: options.ShutdownTimeout,
	}, nil
}

// State returns the current lifecycle state.
func (c *Core) State() State {
	if c == nil {
		return StateFailed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// Ready is true only after every Core-owned dependency has started and passed
// its readiness check, and only while the state is RUNNING.
func (c *Core) Ready() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state == StateRunning && c.ready
}

// Snapshot returns a copy safe for concurrent inspection.
func (c *Core) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{State: StateFailed}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.started))
	for _, index := range c.started {
		names = append(names, c.dependencies[index].Name)
	}
	return Snapshot{
		State:               c.state,
		Ready:               c.state == StateRunning && c.ready,
		StartedDependencies: names,
	}
}

// Start performs ordered dependency start/readiness checks. On any failure it
// marks FAILED, runs bounded reverse cleanup on an independent context, never
// starts a later dependency, and returns the original failure first.
func (c *Core) Start(ctx context.Context) error {
	if c == nil {
		return lifecycleError(
			CodeInvalidTransition,
			"start",
			"",
			StateFailed,
			errors.New("nil core"),
		)
	}
	if ctx == nil {
		return lifecycleError(
			CodeStartCancelled,
			"start",
			"",
			c.State(),
			errors.New("nil context"),
		)
	}

	c.opMu.Lock()
	defer c.opMu.Unlock()
	if err := c.transitionForStart(); err != nil {
		return err
	}

	for index, dependency := range c.dependencies {
		if err := ctx.Err(); err != nil {
			return c.failStart(
				lifecycleError(CodeStartCancelled, "start", dependency.Name, StateStarting, err),
			)
		}
		if err := dependency.Start(ctx); err != nil {
			return c.failStart(
				lifecycleError(CodeDependencyStart, "start", dependency.Name, StateStarting, err),
			)
		}
		c.mu.Lock()
		c.started = append(c.started, index)
		c.mu.Unlock()

		if err := ctx.Err(); err != nil {
			return c.failStart(
				lifecycleError(CodeStartCancelled, "ready", dependency.Name, StateStarting, err),
			)
		}
		if err := dependency.Ready(ctx); err != nil {
			return c.failStart(
				lifecycleError(CodeDependencyReady, "ready", dependency.Name, StateStarting, err),
			)
		}
	}

	c.mu.Lock()
	c.state = StateRunning
	c.ready = true
	c.mu.Unlock()
	return nil
}

func (c *Core) transitionForStart() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateNew {
		return lifecycleError(
			CodeInvalidTransition,
			"start",
			"",
			c.state,
			fmt.Errorf("start requires %s", StateNew),
		)
	}
	c.state = StateStarting
	c.ready = false
	return nil
}

func (c *Core) failStart(root error) error {
	c.mu.Lock()
	c.state = StateFailed
	c.ready = false
	c.mu.Unlock()

	cleanupContext, cancel := context.WithTimeout(context.Background(), c.shutdownTimeout)
	defer cancel()
	cleanupErrors := c.stopStarted(cleanupContext)
	if len(cleanupErrors) == 0 {
		return root
	}
	joined := make([]error, 0, len(cleanupErrors)+1)
	joined = append(joined, root)
	joined = append(joined, cleanupErrors...)
	return errors.Join(joined...)
}

// Stop is idempotent after STOPPED, turns NEW directly into STOPPED, and
// performs reverse shutdown from RUNNING or FAILED.
func (c *Core) Stop(ctx context.Context) error {
	if c == nil {
		return lifecycleError(
			CodeInvalidTransition,
			"stop",
			"",
			StateFailed,
			errors.New("nil core"),
		)
	}
	if ctx == nil {
		return lifecycleError(
			CodeShutdownTimeout,
			"stop",
			"",
			c.State(),
			errors.New("nil context"),
		)
	}

	c.opMu.Lock()
	defer c.opMu.Unlock()

	c.mu.Lock()
	switch c.state {
	case StateStopped:
		c.mu.Unlock()
		return nil
	case StateNew:
		c.state = StateStopped
		c.ready = false
		c.mu.Unlock()
		return nil
	case StateRunning, StateFailed:
		c.state = StateStopping
		c.ready = false
	default:
		state := c.state
		c.mu.Unlock()
		return lifecycleError(
			CodeInvalidTransition,
			"stop",
			"",
			state,
			errors.New("stop is not valid during a lifecycle transition"),
		)
	}
	c.mu.Unlock()

	shutdownContext, cancel := context.WithTimeout(ctx, c.shutdownTimeout)
	defer cancel()
	stopErrors := c.stopStarted(shutdownContext)
	if shutdownContext.Err() != nil {
		stopErrors = append(stopErrors, lifecycleError(
			CodeShutdownTimeout,
			"stop",
			"",
			StateStopping,
			shutdownContext.Err(),
		))
	}

	c.mu.Lock()
	if len(stopErrors) == 0 {
		c.state = StateStopped
	} else {
		c.state = StateFailed
	}
	c.ready = false
	c.mu.Unlock()
	return errors.Join(stopErrors...)
}

// stopStarted calls each currently-started dependency in reverse order. A
// dependency that reports an error remains registered for a later retry.
func (c *Core) stopStarted(ctx context.Context) []error {
	c.mu.RLock()
	pending := append([]int(nil), c.started...)
	c.mu.RUnlock()

	failed := make([]int, 0)
	var stopErrors []error
	for position := len(pending) - 1; position >= 0; position-- {
		index := pending[position]
		dependency := c.dependencies[index]
		if err := dependency.Stop(ctx); err != nil {
			failed = append(failed, index)
			stopErrors = append(stopErrors, lifecycleError(
				CodeDependencyStop,
				"stop",
				dependency.Name,
				StateStopping,
				err,
			))
		}
	}
	for left, right := 0, len(failed)-1; left < right; left, right = left+1, right-1 {
		failed[left], failed[right] = failed[right], failed[left]
	}
	c.mu.Lock()
	c.started = failed
	c.mu.Unlock()
	return stopErrors
}
