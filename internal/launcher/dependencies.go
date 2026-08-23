package launcher

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/config"
	"github.com/zyc14588/AIPT/internal/core"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/web"
)

// PostgresPool is the minimum pool surface owned by the launcher. The
// production adapter is *pgxpool.Pool; the interface keeps gate-machine unit
// tests database-free without copying the storage implementation.
type PostgresPool interface {
	Ping(context.Context) error
	Close()
}

// StopFunc synchronously stops one started component. Implementations must
// honor ctx and must not launch an abandoned cleanup goroutine.
type StopFunc func(context.Context) error

// ComponentStart starts one dependency-injected component gate.
type ComponentStart func(context.Context) (StopFunc, error)

// WebStartState is the state-aware boundary for the final WEB gate. Config is
// the same validated immutable value loaded by CONFIG. PriorStartedGates is a
// defensive snapshot of every successfully completed earlier gate, including
// non-stoppable CONFIG and MIGRATIONS.
type WebStartState struct {
	Config            *config.Config
	PriorStartedGates []Gate
}

// WebStart starts the final Web component from validated prior state.
type WebStart func(context.Context, WebStartState) (StopFunc, error)

// Dependencies are implementations only; they cannot supply, omit, or reorder
// gates. DefaultDependencies wires the real CONFIG, POSTGRESQL, MIGRATIONS,
// Core, and WEB components and installs fail-closed MODEL/HARNESS/IPC
// placeholders.
type Dependencies struct {
	LoadConfig   func(string) (*config.Config, error)
	OpenPostgres func(context.Context, string) (PostgresPool, error)
	MigrateUp    func(context.Context, PostgresPool) error
	StartModel   ComponentStart
	StartHarness ComponentStart
	StartCore    ComponentStart
	StartIPC     ComponentStart
	StartWeb     WebStart
}

// DefaultShutdownTimeout bounds both launcher reverse cleanup and the Core
// shell used by NewDefault.
const DefaultShutdownTimeout = 10 * time.Second

// DefaultDependencies returns the production B007 wiring. MODEL, HARNESS, and
// IPC remain fail-closed placeholders; WEB is real but cannot be reached by
// the production launcher until every mandatory predecessor succeeds.
func DefaultDependencies(shutdownTimeout time.Duration) Dependencies {
	if shutdownTimeout <= 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}
	return Dependencies{
		LoadConfig: config.LoadFile,
		OpenPostgres: func(ctx context.Context, dsn string) (PostgresPool, error) {
			return pgxpool.New(ctx, dsn)
		},
		MigrateUp: func(ctx context.Context, pool PostgresPool) error {
			pgxPool, ok := pool.(*pgxpool.Pool)
			if !ok || pgxPool == nil {
				return errors.New("production migration adapter requires *pgxpool.Pool")
			}
			return postgres.MigrateUp(ctx, pgxPool)
		},
		StartModel:   unimplementedComponent(GateModel),
		StartHarness: unimplementedComponent(GateHarness),
		StartCore:    coreComponent(shutdownTimeout),
		StartIPC:     unimplementedComponent(GateIPC),
		StartWeb:     webComponent(),
	}
}

func unimplementedComponent(gate Gate) ComponentStart {
	return func(context.Context) (StopFunc, error) {
		return nil, newGateError(
			CodeGateNotImplemented,
			gate,
			"start",
			fmt.Errorf("%s is mandatory but not implemented in AIPT-M0-B007", gate),
		)
	}
}

func webComponent() WebStart {
	return func(ctx context.Context, state WebStartState) (StopFunc, error) {
		if state.Config == nil {
			return nil, errors.New("validated config is unavailable at WEB")
		}
		expected := fixedGateOrder[:len(fixedGateOrder)-1]
		if len(state.PriorStartedGates) != len(expected) {
			return nil, errors.New("WEB prior gate snapshot is incomplete")
		}
		for index, gate := range expected {
			if state.PriorStartedGates[index] != gate {
				return nil, errors.New("WEB prior gate snapshot order is invalid")
			}
		}
		host, err := web.Start(ctx, state.Config)
		if err != nil {
			return nil, err
		}
		return host.Stop, nil
	}
}

func coreComponent(shutdownTimeout time.Duration) ComponentStart {
	return func(ctx context.Context) (StopFunc, error) {
		instance, err := core.New(core.Options{ShutdownTimeout: shutdownTimeout})
		if err != nil {
			return nil, err
		}
		if err := instance.Start(ctx); err != nil {
			return nil, err
		}
		return instance.Stop, nil
	}
}
