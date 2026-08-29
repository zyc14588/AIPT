package runcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

type runCorePGFixture struct {
	t      *testing.T
	name   string
	admin  *pgxpool.Pool
	config *pgxpool.Config
}

func newRunCorePGFixture(t *testing.T) *runCorePGFixture {
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
	name := "aipt_rc_" + hex.EncodeToString(random)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create ephemeral database: %v", err)
	}
	eph := config.Copy()
	eph.ConnConfig.Database = name
	fixture := &runCorePGFixture{t: t, name: name, admin: admin, config: eph}
	t.Cleanup(fixture.cleanup)
	return fixture
}

func (f *runCorePGFixture) pool(ctx context.Context) *pgxpool.Pool {
	f.t.Helper()
	config := f.config.Copy()
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		f.t.Fatalf("connect ephemeral database: %v", err)
	}
	return pool
}

func (f *runCorePGFixture) cleanup() {
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

func TestPostgresIntegrationRunCoreAtomicConcurrencyReplay(t *testing.T) {
	fixture := newRunCorePGFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := fixture.pool(ctx)
	defer pool.Close()

	if err := storagepostgres.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	var version string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil || !strings.HasPrefix(version, "18.4") {
		t.Fatalf("PostgreSQL version = %q, err=%v; want 18.4", version, err)
	}
	var migrations int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aipt.schema_migrations").Scan(&migrations); err != nil || migrations != 2 {
		t.Fatalf("migration count=%d err=%v, want exactly historical 000001+000002", migrations, err)
	}

	store, err := NewPostgreSQLStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	core := fixtureCore(t, store, counterHandler{}, nil, 100)
	_, startReceipt := startFixtureRun(t, core, "run-postgres-race")
	left, err := core.ResumeRun(ctx, fixtureBinding("run-postgres-race"), fixtureSeed(), startReceipt.StateHash)
	if err != nil {
		t.Fatalf("ResumeRun left: %v", err)
	}
	right, err := core.ResumeRun(ctx, fixtureBinding("run-postgres-race"), fixtureSeed(), startReceipt.StateHash)
	if err != nil {
		t.Fatalf("ResumeRun right: %v", err)
	}
	raws := [][]byte{
		proposalBytes(t, "run-postgres-race", "pg-race-left", 1, 1, []RNGRequest{{StreamID: "checks", Count: 1}}, nil),
		proposalBytes(t, "run-postgres-race", "pg-race-right", 1, 1, []RNGRequest{{StreamID: "checks", Count: 1}}, nil),
	}
	barrier := make(chan struct{})
	type result struct {
		receipt Receipt
		err     error
	}
	results := make(chan result, 2)
	for index, run := range []*Run{left, right} {
		go func(value *Run, raw []byte) {
			<-barrier
			receipt, err := value.Execute(ctx, raw)
			results <- result{receipt: receipt, err: err}
		}(run, raws[index])
	}
	close(barrier)
	var winner Receipt
	var success, conflict int
	for range 2 {
		result := <-results
		switch {
		case result.err == nil:
			success++
			winner = result.receipt
		case ErrorCode(result.err) == CodeStateConflict:
			conflict++
		default:
			t.Fatalf("concurrent Execute error: %v", result.err)
		}
	}
	if success != 1 || conflict != 1 || winner.Sequence != 2 {
		t.Fatalf("success=%d conflict=%d winner=%+v", success, conflict, winner)
	}

	verified, err := storagepostgres.VerifyStream(ctx, pool, storagepostgres.VerifyInput{StreamID: runStreamID("run-postgres-race")})
	if err != nil || verified.Sequence != 2 || verified.EventCount != 2 {
		t.Fatalf("verified stream=%+v err=%v", verified, err)
	}
	replayed, err := core.ReplayStored(ctx, fixtureBinding("run-postgres-race"), fixtureSeed(), winner.StateHash)
	if err != nil {
		t.Fatalf("ReplayStored: %v", err)
	}
	if replayed.StateHash != winner.StateHash || replayed.State.Sequence != 2 {
		t.Fatalf("replayed=%+v winner=%+v", replayed, winner)
	}

	// An invariant failure after deterministic draw calculation cannot append
	// an event or advance the persisted cursor.
	resumed, err := core.ResumeRun(ctx, fixtureBinding("run-postgres-race"), fixtureSeed(), winner.StateHash)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resumed.Execute(ctx, proposalBytes(t, "run-postgres-race", "pg-invalid", 2, 1000,
		[]RNGRequest{{StreamID: "checks", Count: 1}}, nil)); ErrorCode(err) != CodeInvariantViolation {
		t.Fatalf("invariant error = %v", err)
	}
	verifiedAfter, err := storagepostgres.VerifyStream(ctx, pool, storagepostgres.VerifyInput{StreamID: runStreamID("run-postgres-race")})
	if err != nil || verifiedAfter.Sequence != 2 || verifiedAfter.EventHash == nil || verified.EventHash == nil || *verifiedAfter.EventHash != *verified.EventHash {
		t.Fatalf("rollback changed authority: before=%+v after=%+v err=%v", verified, verifiedAfter, err)
	}

	// Direct duplicate identity remains a structured conflict and cannot create
	// a third event.
	duplicateRun, err := core.ResumeRun(ctx, fixtureBinding("run-postgres-race"), fixtureSeed(), winner.StateHash)
	if err != nil {
		t.Fatal(err)
	}
	winnerID := "pg-race-left"
	if strings.Contains(storeEventsPayload(t, ctx, store, "run-postgres-race", 1), "pg-race-right") {
		winnerID = "pg-race-right"
	}
	if _, err := duplicateRun.Execute(ctx, proposalBytes(t, "run-postgres-race", winnerID, 2, 1, nil, nil)); ErrorCode(err) != CodeStateConflict {
		t.Fatalf("duplicate identity error = %v", err)
	}
	verifiedFinal, _ := storagepostgres.VerifyStream(ctx, pool, storagepostgres.VerifyInput{StreamID: runStreamID("run-postgres-race")})
	if verifiedFinal.Sequence != 2 {
		t.Fatalf("duplicate appended event: %+v", verifiedFinal)
	}

	// A ledger cursor without a Run genesis is legal at the generic storage
	// layer but invalid for Run Core. Loading it must reject rather than index
	// an empty event slice or fabricate initial state.
	emptyRunID := "run-empty-ledger"
	if _, err := pool.Exec(ctx, "INSERT INTO aipt.ledger_streams (stream_id) VALUES ($1)", runStreamID(emptyRunID)); err != nil {
		t.Fatalf("insert empty Run stream: %v", err)
	}
	if _, err := store.Load(ctx, runStreamID(emptyRunID)); err == nil {
		t.Fatal("empty Run ledger stream was accepted")
	}

	canceled, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if _, err := duplicateRun.Execute(canceled, proposalBytes(t, "run-postgres-race", "pg-canceled", 2, 1, nil, nil)); ErrorCode(err) != CodeStateConflict || !errors.Is(canceled.Err(), context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func storeEventsPayload(t *testing.T, ctx context.Context, store EventStore, runID string, index int) string {
	t.Helper()
	events, err := store.Load(ctx, runStreamID(runID))
	if err != nil || index >= len(events) {
		t.Fatalf("load stored events: %v", err)
	}
	return events[index].PayloadCanonical
}
