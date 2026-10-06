// Package operational adds the B006 production wiring without rewriting the
// closed B004 launcher, its plan, or any predecessor business implementation.
package operational

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/config"
	"github.com/zyc14588/AIPT/internal/core"
	"github.com/zyc14588/AIPT/internal/launcher"
	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/web"
)

// NewProduction is the executable construction path. A real Task 0 driver is
// registered by B007, so B006 never substitutes a synthetic game executor.
func NewProduction(configPath, controlPath string, input io.ReadCloser, output io.WriteCloser, diagnostics io.Writer) (*launcher.Launcher, error) {
	if controlPath == "" || input == nil || output == nil || diagnostics == nil {
		return nil, runcontrol.ErrInvalid
	}
	var validated *config.Config
	var controlConfig runcontrol.ControlConfig
	var pool *pgxpool.Pool
	var service *runcontrol.Service
	modelRuntime := modelgateway.NewRuntimeCoordinator(os.Getenv("AIPT_MODEL_RUNTIME_CONFIG"), modelgateway.EnvironmentCredentialBroker{})
	dependencies := launcher.Dependencies{
		LoadConfig: func(path string) (*config.Config, error) {
			loaded, err := config.LoadFile(path)
			if err != nil {
				return nil, err
			}
			controlConfig, err = runcontrol.LoadControlConfig(controlPath)
			if err != nil {
				return nil, err
			}
			validated = loaded
			return loaded, nil
		},
		OpenPostgres: func(ctx context.Context, dsn string) (launcher.PostgresPool, error) {
			opened, err := pgxpool.New(ctx, dsn)
			if err == nil {
				pool = opened
			}
			return opened, err
		},
		MigrateUp: func(ctx context.Context, p launcher.PostgresPool) error {
			pg, ok := p.(*pgxpool.Pool)
			if !ok || pg == nil {
				return runcontrol.ErrUnavailable
			}
			return postgres.MigrateUp(ctx, pg)
		},
		StartModel: func(ctx context.Context) (launcher.StopFunc, error) {
			stop, err := modelRuntime.StartModel(ctx)
			return launcher.StopFunc(stop), err
		},
		StartHarness: func(ctx context.Context) (launcher.StopFunc, error) {
			stop, err := modelRuntime.StartHarness(ctx)
			return launcher.StopFunc(stop), err
		},
		StartCore: func(ctx context.Context) (launcher.StopFunc, error) {
			if pool == nil || validated == nil {
				return nil, runcontrol.ErrUnavailable
			}
			queue, err := postgres.NewQueueStore(pool, nil)
			if err != nil {
				return nil, err
			}
			reader, err := runcontrol.NewPostgresReader(pool)
			if err != nil {
				return nil, err
			}
			reports, err := runcontrol.NewFileReports(filepath.Join(controlConfig.EvidenceRoot, validated.Evidence().Namespace()))
			if err != nil {
				return nil, err
			}
			shell, err := core.New(core.Options{ShutdownTimeout: launcher.DefaultShutdownTimeout})
			if err != nil {
				return nil, err
			}
			if err := shell.Start(ctx); err != nil {
				return nil, err
			}
			shared, err := runcontrol.New(runcontrol.Options{Queue: queue, Reader: reader, Definitions: controlConfig.Definitions, Reports: reports, Lifetime: ctx, Capabilities: controlConfig.Capabilities, HolderID: controlConfig.HolderID, LeaseDuration: controlConfig.LeaseDuration})
			if err != nil {
				cleanup, cancel := context.WithTimeout(context.Background(), launcher.DefaultShutdownTimeout)
				defer cancel()
				_ = shell.Stop(cleanup)
				return nil, err
			}
			service = shared
			return func(ctx context.Context) error {
				if err := shared.Stop(ctx); err != nil {
					return err
				}
				return shell.Stop(ctx)
			}, nil
		},
		StartIPC: func(ctx context.Context) (launcher.StopFunc, error) {
			if service == nil {
				return nil, runcontrol.ErrUnavailable
			}
			rpc, err := runcontrol.StartRPC(ctx, input, output, service)
			if err != nil {
				return nil, err
			}
			return rpc.Stop, nil
		},
		StartWeb: func(ctx context.Context, state launcher.WebStartState) (launcher.StopFunc, error) {
			expected := launcher.FixedGateOrder()
			expected = expected[:len(expected)-1]
			if service == nil || state.Config == nil || len(state.PriorStartedGates) != len(expected) {
				return nil, runcontrol.ErrUnavailable
			}
			for i, gate := range expected {
				if state.PriorStartedGates[i] != gate {
					return nil, runcontrol.ErrUnavailable
				}
			}
			host, err := web.StartOperational(ctx, state.Config, service)
			if err != nil {
				return nil, err
			}
			// Diagnostics use stderr; stdout belongs exclusively to framed JSON-RPC.
			if err := json.NewEncoder(diagnostics).Encode(struct {
				Schema           string `json:"schema"`
				URL              string `json:"url"`
				RuntimeReadiness string `json:"runtime_readiness"`
			}{"aipt.web-listener/v1", host.URL(), "NOT_ASSERTED"}); err != nil {
				return host.Stop, runcontrol.ErrUnavailable
			}
			return host.Stop, nil
		},
	}
	return launcher.New(configPath, launcher.Options{Dependencies: dependencies, ShutdownTimeout: launcher.DefaultShutdownTimeout})
}

type ConstructionPlan struct {
	Schema                           string              `json:"schema"`
	Gates                            []launcher.PlanGate `json:"gates"`
	RuntimeReady                     bool                `json:"runtime_ready"`
	Readiness                        string              `json:"readiness"`
	GameDriver                       string              `json:"game_driver"`
	QualificationExecutionAuthorized bool                `json:"qualification_execution_authorized"`
}

func Plan() ConstructionPlan {
	gates := []launcher.PlanGate{}
	for i, gate := range launcher.FixedGateOrder() {
		gates = append(gates, launcher.PlanGate{Position: i + 1, Gate: gate, Implementation: launcher.Implemented})
	}
	return ConstructionPlan{Schema: "aipt.operational-plan/v1", Gates: gates, RuntimeReady: false, Readiness: "STARTUP_NOT_VERIFIED", GameDriver: "B007_CONFIGURATION_REQUIRED", QualificationExecutionAuthorized: false}
}
