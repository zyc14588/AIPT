package modelgateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

type modelAuditPGFixture struct {
	t      *testing.T
	name   string
	admin  *pgxpool.Pool
	config *pgxpool.Config
}

func newModelAuditPGFixture(t *testing.T) *modelAuditPGFixture {
	t.Helper()
	dsn := os.Getenv("AIPT_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("AIPT_REQUIRE_POSTGRES_INTEGRATION") == "1" {
			t.Fatal("AIPT_POSTGRES_DSN is required when AIPT_REQUIRE_POSTGRES_INTEGRATION=1")
		}
		t.Skip("AIPT_POSTGRES_DSN is not set")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test PostgreSQL DSN: %v", err)
	}
	if config.ConnConfig.Host != "127.0.0.1" && config.ConnConfig.Host != "localhost" {
		t.Fatalf("integration PostgreSQL must be loopback-only, host=%q", config.ConnConfig.Host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect test PostgreSQL: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping test PostgreSQL: %v", err)
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		admin.Close()
		t.Fatalf("ephemeral database identity: %v", err)
	}
	name := "aipt_mg_" + hex.EncodeToString(random)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create ephemeral database: %v", err)
	}
	eph := config.Copy()
	eph.ConnConfig.Database = name
	fixture := &modelAuditPGFixture{t: t, name: name, admin: admin, config: eph}
	t.Cleanup(fixture.cleanup)
	return fixture
}

func (f *modelAuditPGFixture) pool(ctx context.Context) *pgxpool.Pool {
	f.t.Helper()
	config := f.config.Copy()
	config.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		f.t.Fatalf("connect ephemeral database: %v", err)
	}
	return pool
}

func (f *modelAuditPGFixture) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := f.admin.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", f.name); err != nil {
		f.t.Errorf("terminate ephemeral connections: %v", err)
	}
	if _, err := f.admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{f.name}.Sanitize()); err != nil {
		f.t.Errorf("drop ephemeral database: %v", err)
	}
	f.admin.Close()
}

func postgresConsumptionFixture() BreakGlassConsumption {
	return BreakGlassConsumption{
		Schema: BreakGlassConsumptionSchema, ConsumptionID: "consume-postgres-grant-v1",
		GrantID: "postgres-grant-v1", GrantSHA256: fixtureSHA("postgres-grant"),
		AuthorizedOperation: BreakGlassRemoteEgressLocalOnlySecret,
		RunID:               "run-postgres-break-glass-v1", DiagnosticID: "diagnostic-postgres-break-glass-v1",
		ManifestSHA256: fixtureSHA("postgres-manifest"), SeatID: orchestrator.SeatGM,
		InvocationID: "invocation-postgres-break-glass-v1", ProfileBinding: "model-gm@1.0.0",
		ContextSHA256: fixtureSHA("postgres-context"), RequestSHA256: fixtureSHA("postgres-request"),
		SourceClassification: orchestrator.ClassLocalOnlySecret, DestinationBackend: BackendRemoteDeepSeek,
		IssuerAuthorityID: "owner-authority-v1", NonceSHA256: fixtureSHA("postgres-nonce"),
		ConsumedAt: breakGlassTestNow, RunDisqualified: true,
	}
}

func postgresQualificationEvidence(runID, diagnosticID, invocationID string) InvocationEvidence {
	return InvocationEvidence{
		Schema: InvocationEvidenceSchema, DiagnosticID: diagnosticID, RunID: runID,
		RunClassification: "QUALIFICATION", SeatID: orchestrator.SeatGM,
		SessionID: "session-postgres-qualification-v1", InvocationID: invocationID,
		ProfileBinding: "model-gm@1.0.0", SamplingBinding: "sampling-gm@1.0.0",
		BackendKind: BackendRemoteDeepSeek, ProviderIdentity: "deepseek-official", ModelID: "deepseek-v4-pro",
		HarnessIdentity: "harness-postgres-v1@1.0.0", StructuredOutputMode: StructuredPrompted,
		ToolCallMode: ToolCallDisabled, ContextHash: fixtureSHA("postgres-qualification-context"),
		RequestSHA256:  fixtureSHA("postgres-qualification-request-" + invocationID),
		ResponseSHA256: fixtureSHA("postgres-qualification-response-" + invocationID),
		RetryIdentity:  "ORIGINAL:1", CapabilityFingerprint: fixtureSHA("postgres-qualification-capabilities"),
		CompletedAt: breakGlassTestNow, CleanBaselineEligible: true,
	}
}

func TestPostgresIntegrationBreakGlassAtomicReplayAndRestart(t *testing.T) {
	fixture := newModelAuditPGFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := fixture.pool(ctx)
	defer pool.Close()
	if err := storagepostgres.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	var migrations int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aipt.schema_migrations").Scan(&migrations); err != nil || migrations != 2 {
		t.Fatalf("migration count=%d err=%v, want unchanged historical migrations", migrations, err)
	}

	const contenders = 16
	consumption := postgresConsumptionFixture()
	var successes atomic.Int64
	var replays atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			sink, err := NewPostgreSQLAuditSink(pool)
			if err != nil {
				t.Errorf("new sink: %v", err)
				return
			}
			err = sink.ConsumeBreakGlass(ctx, consumption)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, Sentinel(CodeBreakGlassReplay)):
				replays.Add(1)
			default:
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes.Load() != 1 || replays.Load() != contenders-1 {
		t.Fatalf("atomic results: success=%d replay=%d", successes.Load(), replays.Load())
	}

	// A fresh sink instance models process restart/resume and must recover the
	// immutable disqualification fact from the existing ledger.
	restarted, err := NewPostgreSQLAuditSink(pool)
	if err != nil {
		t.Fatal(err)
	}
	disqualified, err := restarted.BreakGlassDisqualified(ctx, consumption.RunID, consumption.DiagnosticID)
	if err != nil || !disqualified {
		t.Fatalf("restart disqualification=%t err=%v", disqualified, err)
	}
	disqualified, err = restarted.BreakGlassDisqualified(ctx, consumption.RunID, "different-diagnostic-v1")
	if err != nil || !disqualified {
		t.Fatalf("cross-diagnostic restart disqualification=%t err=%v", disqualified, err)
	}
	if err := restarted.ConsumeBreakGlass(ctx, consumption); !errors.Is(err, Sentinel(CodeBreakGlassReplay)) {
		t.Fatalf("restart replay error=%v", err)
	}
	var count int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM aipt.ledger_events WHERE event_type = $1", breakGlassConsumedEventType).Scan(&count); err != nil || count != 1 {
		t.Fatalf("consumption event count=%d err=%v", count, err)
	}
	blockedEvidence := postgresQualificationEvidence(consumption.RunID, "diagnostic-postgres-formal-v1", "invocation-postgres-formal-v1")
	if err := restarted.RecordInvocation(ctx, blockedEvidence); !errors.Is(err, Sentinel(CodeBreakGlassAudit)) {
		t.Fatalf("qualification evidence appended after durable disqualification: %v", err)
	}
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM aipt.ledger_events WHERE event_type = $1", modelInvocationAuditEventType).Scan(&count); err != nil || count != 0 {
		t.Fatalf("post-disqualification qualification event count=%d err=%v", count, err)
	}

	// Race an otherwise clean qualification append against a first consumption
	// on a fresh Run. Either the clean append linearizes first, or it fails;
	// it may never commit after the irreversible consumption event.
	raceConsumption := consumption
	raceConsumption.ConsumptionID = "consume-postgres-linearizable-v1"
	raceConsumption.GrantID = "postgres-linearizable-grant-v1"
	raceConsumption.GrantSHA256 = fixtureSHA("postgres-linearizable-grant")
	raceConsumption.RunID = "run-postgres-linearizable-v1"
	raceConsumption.DiagnosticID = "diagnostic-postgres-linearizable-consumer-v1"
	raceConsumption.InvocationID = "invocation-postgres-linearizable-consumer-v1"
	raceConsumption.ContextSHA256 = fixtureSHA("postgres-linearizable-context")
	raceConsumption.RequestSHA256 = fixtureSHA("postgres-linearizable-request")
	raceConsumption.NonceSHA256 = fixtureSHA("postgres-linearizable-nonce")
	raceEvidence := postgresQualificationEvidence(
		raceConsumption.RunID,
		"diagnostic-postgres-linearizable-formal-v1",
		"invocation-postgres-linearizable-formal-v1",
	)
	startLinearizable := make(chan struct{})
	var consumeErr, recordErr error
	var linearizable sync.WaitGroup
	linearizable.Add(2)
	go func() {
		defer linearizable.Done()
		<-startLinearizable
		consumeErr = restarted.ConsumeBreakGlass(ctx, raceConsumption)
	}()
	go func() {
		defer linearizable.Done()
		<-startLinearizable
		recordErr = restarted.RecordInvocation(ctx, raceEvidence)
	}()
	close(startLinearizable)
	linearizable.Wait()
	if consumeErr != nil {
		t.Fatalf("linearizable consumption failed: %v", consumeErr)
	}
	if recordErr != nil && !errors.Is(recordErr, Sentinel(CodeBreakGlassAudit)) {
		t.Fatalf("linearizable qualification append returned unexpected error: %v", recordErr)
	}
	streamID, err := modelAuditStreamID(raceConsumption.RunID, raceConsumption.DiagnosticID)
	if err != nil {
		t.Fatal(err)
	}
	var consumptionSequence int64
	if err := pool.QueryRow(ctx,
		"SELECT sequence FROM aipt.ledger_events WHERE stream_id = $1 AND event_type = $2",
		streamID, breakGlassConsumedEventType).Scan(&consumptionSequence); err != nil {
		t.Fatalf("read linearizable consumption sequence: %v", err)
	}
	var invocationSequence int64
	invocationErr := pool.QueryRow(ctx,
		"SELECT sequence FROM aipt.ledger_events WHERE stream_id = $1 AND event_type = $2",
		streamID, modelInvocationAuditEventType).Scan(&invocationSequence)
	switch {
	case recordErr == nil && invocationErr == nil && invocationSequence < consumptionSequence:
		// Clean evidence linearized before the disqualification.
	case recordErr != nil && errors.Is(invocationErr, pgx.ErrNoRows):
		// Disqualification linearized first and the clean append failed closed.
	default:
		t.Fatalf("clean invocation committed after disqualification: record_err=%v query_err=%v invocation_seq=%d consumption_seq=%d",
			recordErr, invocationErr, invocationSequence, consumptionSequence)
	}
}
