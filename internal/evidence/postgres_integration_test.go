package evidence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

// evidenceIntegrationFixture owns one generated PostgreSQL database. It
// refuses every non-loopback or credential-bearing DSN, so these tests can
// never be pointed at a production database. AIPT_REQUIRE_POSTGRES_INTEGRATION
// turns a missing test DSN into a hard failure in CI.
type evidenceIntegrationFixture struct {
	t      *testing.T
	name   string
	config *pgxpool.Config
	admin  *pgxpool.Pool
}

func newEvidenceIntegrationFixture(t *testing.T) *evidenceIntegrationFixture {
	t.Helper()
	dsn := os.Getenv("AIPT_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("AIPT_REQUIRE_POSTGRES_INTEGRATION") == "1" {
			t.Fatal("AIPT_POSTGRES_DSN is required when AIPT_REQUIRE_POSTGRES_INTEGRATION=1")
		}
		t.Skip("AIPT_POSTGRES_DSN is not set; skipping PostgreSQL evidence integration")
	}
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse AIPT_POSTGRES_DSN: %v", err)
	}
	connection := adminConfig.ConnConfig
	if connection.Host != "127.0.0.1" || connection.Port != 5432 || connection.Database != "postgres" ||
		connection.User != "postgres" || connection.Password != "" || connection.TLSConfig != nil {
		t.Fatalf("AIPT_POSTGRES_DSN must be the credential-free loopback PostgreSQL test boundary; got host=%q port=%d database=%q user=%q password_present=%t tls=%t",
			connection.Host, connection.Port, connection.Database, connection.User,
			connection.Password != "", connection.TLSConfig != nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect to PostgreSQL test boundary: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping PostgreSQL test boundary: %v", err)
	}
	var version string
	if err := admin.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil {
		admin.Close()
		t.Fatalf("read PostgreSQL server_version: %v", err)
	}
	if !strings.HasPrefix(version, "18.4") {
		admin.Close()
		t.Fatalf("PostgreSQL server_version = %q, want exact 18.4 release family", version)
	}
	name := "aipt_evidence_it_" + evidenceRandomHex(t, 8)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create ephemeral evidence database: %v", err)
	}
	config := adminConfig.Copy()
	config.ConnConfig.Database = name
	fixture := &evidenceIntegrationFixture{t: t, name: name, config: config, admin: admin}
	t.Cleanup(fixture.cleanup)
	return fixture
}

func (fixture *evidenceIntegrationFixture) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := fixture.admin.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
		fixture.name); err != nil {
		fixture.t.Errorf("terminate evidence database connections: %v", err)
	}
	if _, err := fixture.admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{fixture.name}.Sanitize()); err != nil {
		fixture.t.Errorf("drop evidence database: %v", err)
	}
	var count int
	if err := fixture.admin.QueryRow(ctx, "SELECT count(*) FROM pg_database WHERE datname = $1", fixture.name).Scan(&count); err != nil {
		fixture.t.Errorf("verify evidence database cleanup: %v", err)
	} else if count != 0 {
		fixture.t.Errorf("evidence database %q remains after cleanup", fixture.name)
	}
	fixture.admin.Close()
}

func (fixture *evidenceIntegrationFixture) pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config := fixture.config.Copy()
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect to ephemeral evidence database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := storagepostgres.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp(ephemeral evidence database): %v", err)
	}
	return pool
}

func evidenceRandomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(value)
}

func appendSyntheticEvents(t *testing.T, ctx context.Context, pool *pgxpool.Pool, streamID string, count int) []storagepostgres.LedgerEvent {
	t.Helper()
	events := make([]storagepostgres.LedgerEvent, 0, count)
	for i := 1; i <= count; i++ {
		event, err := storagepostgres.Append(ctx, pool, storagepostgres.AppendInput{
			StreamID:  streamID,
			EventID:   fmt.Sprintf("synthetic-event-%04d", i),
			EventType: "fixture.advanced",
			PayloadJSON: []byte(fmt.Sprintf(
				`{"kind":"synthetic","sequence":%d}`, i)),
		})
		if err != nil {
			t.Fatalf("Append(synthetic event %d): %v", i, err)
		}
		events = append(events, event)
	}
	return events
}

func assertNoPublishedBundle(t *testing.T, parent, final string) {
	t.Helper()
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed export left a final bundle: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed export left temporary content: %v", entries)
	}
}

func TestPostgresIntegrationEvidenceExportAndVerify(t *testing.T) {
	fixture := newEvidenceIntegrationFixture(t)
	pool := fixture.pool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	appendSyntheticEvents(t, ctx, pool, "synthetic-evidence-ledger", 3)
	source := NewPostgresSource(pool)
	parent := t.TempDir()
	inputs := []ExportInput{
		{Destination: filepath.Join(parent, "first"), Source: fixtureSourceIdentity(), StreamID: "synthetic-evidence-ledger"},
		{Destination: filepath.Join(parent, "second"), Source: fixtureSourceIdentity(), StreamID: "synthetic-evidence-ledger"},
	}
	results := make([]Verification, 0, len(inputs))
	for _, input := range inputs {
		result, err := ExportRawCapture(ctx, source, input)
		if err != nil {
			t.Fatalf("ExportRawCapture(%s): %v", filepath.Base(input.Destination), err)
		}
		verified, err := VerifyRawCapture(input.Destination)
		if err != nil {
			t.Fatalf("VerifyRawCapture(%s): %v", filepath.Base(input.Destination), err)
		}
		if verified.Root != result.Root {
			t.Fatalf("self verification root = %s, export root = %s", verified.Root, result.Root)
		}
		results = append(results, result)
	}
	if results[0].Root != results[1].Root {
		t.Fatalf("same verified PostgreSQL stream produced roots %s and %s", results[0].Root, results[1].Root)
	}
	for _, name := range []string{ManifestName, EventsName, RootName} {
		first, err := os.ReadFile(filepath.Join(inputs[0].Destination, name))
		if err != nil {
			t.Fatal(err)
		}
		second, err := os.ReadFile(filepath.Join(inputs[1].Destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(second) {
			t.Errorf("PostgreSQL repeated export differs at %s", name)
		}
	}
}

func TestPostgresIntegrationEvidenceTamperLeavesNoFinal(t *testing.T) {
	fixture := newEvidenceIntegrationFixture(t)
	pool := fixture.pool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	appendSyntheticEvents(t, ctx, pool, "synthetic-tamper-ledger", 2)
	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DISABLE TRIGGER ledger_events_append_only"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DROP CONSTRAINT ledger_events_event_hash_check"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		"UPDATE aipt.ledger_events SET event_hash = decode(repeat('dd', 32), 'hex') WHERE stream_id = $1 AND sequence = 1",
		"synthetic-tamper-ledger"); err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "must-not-exist")
	_, err := ExportRawCapture(ctx, NewPostgresSource(pool), ExportInput{
		Destination: destination, Source: fixtureSourceIdentity(), StreamID: "synthetic-tamper-ledger",
	})
	if !errors.Is(err, storagepostgres.ErrLedgerEventHashMismatch) {
		t.Fatalf("tampered DB error = %v, want B003 ErrLedgerEventHashMismatch", err)
	}
	assertNoPublishedBundle(t, parent, destination)
}

type appendBeforeCursorTx struct {
	pgx.Tx
	pool      *pgxpool.Pool
	input     storagepostgres.AppendInput
	once      sync.Once
	appendErr error
}

type captureErrorRow struct{ err error }

func (row captureErrorRow) Scan(...any) error { return row.err }

func (tx *appendBeforeCursorTx) QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row {
	if strings.Contains(sql, "aipt.ledger_streams") {
		tx.once.Do(func() {
			_, tx.appendErr = storagepostgres.Append(ctx, tx.pool, tx.input)
		})
		if tx.appendErr != nil {
			return captureErrorRow{err: tx.appendErr}
		}
	}
	return tx.Tx.QueryRow(ctx, sql, arguments...)
}

func TestPostgresIntegrationEvidenceConcurrentAppendLeavesNoFinal(t *testing.T) {
	fixture := newEvidenceIntegrationFixture(t)
	pool := fixture.pool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	appendSyntheticEvents(t, ctx, pool, "synthetic-changing-ledger", 2)
	source := NewPostgresSource(pool)
	var wrapper *appendBeforeCursorTx
	source.begin = func(ctx context.Context, options pgx.TxOptions) (captureTx, error) {
		tx, err := pool.BeginTx(ctx, options)
		if err != nil {
			return nil, err
		}
		wrapper = &appendBeforeCursorTx{
			Tx: tx, pool: pool,
			input: storagepostgres.AppendInput{
				StreamID: "synthetic-changing-ledger", EventID: "synthetic-event-0003",
				EventType: "fixture.concurrent", PayloadJSON: []byte(`{"kind":"synthetic","sequence":3}`),
			},
		}
		return wrapper, nil
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, "must-not-exist")
	_, err := ExportRawCapture(ctx, source, ExportInput{
		Destination: destination, Source: fixtureSourceIdentity(), StreamID: "synthetic-changing-ledger",
	})
	if wrapper == nil {
		t.Fatal("controlled concurrent append wrapper was never installed")
	}
	if wrapper.appendErr != nil {
		t.Fatalf("controlled concurrent append failed: %v", wrapper.appendErr)
	}
	if !errors.Is(err, ErrStreamChanged) {
		t.Fatalf("concurrent append error = %v, want ErrStreamChanged", err)
	}
	assertNoPublishedBundle(t, parent, destination)
}
