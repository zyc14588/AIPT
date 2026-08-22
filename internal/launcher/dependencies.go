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

// Dependencies are implementations only; they cannot supply, omit, or reorder
// gates. DefaultDependencies wires the real CONFIG, POSTGRESQL, MIGRATIONS,
// and Core shell and installs fail-closed placeholders elsewhere.
type Dependencies struct {
	LoadConfig   func(string) (*config.Config, error)
	OpenPostgres func(context.Context, string) (PostgresPool, error)
	MigrateUp    func(context.Context, PostgresPool) error
	StartModel   ComponentStart
	StartHarness ComponentStart
	StartCore    ComponentStart
	StartIPC     ComponentStart
	StartWeb     ComponentStart
}

// DefaultShutdownTimeout bounds both launcher reverse cleanup and the Core
// shell used by NewDefault.
const DefaultShutdownTimeout = 10 * time.Second

// DefaultDependencies returns the production B004 wiring.
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
		StartWeb:     unimplementedComponent(GateWeb),
	}
}

func unimplementedComponent(gate Gate) ComponentStart {
	return func(context.Context) (StopFunc, error) {
		return nil, newGateError(
			CodeGateNotImplemented,
			gate,
			"start",
			fmt.Errorf("%s is mandatory but not implemented in AIPT-M0-B004", gate),
		)
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
