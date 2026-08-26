package postgres

// migration_integration_test.go exercises the real migration runner
// (migrateUpFS and the exported MigrateUp) against uniquely generated
// ephemeral PostgreSQL databases. Every test in this file requires
// AIPT_POSTGRES_DSN to be set: when it is missing the tests skip normally,
// except that AIPT_REQUIRE_POSTGRES_INTEGRATION=1 turns the skip into a hard
// failure. The tests are parallel-safe by construction -- each creates its own
// collision-resistant aipt_* database and never touches shared state -- and
// the fixture cleanup terminates every connection to its database, drops
// exactly that database, and verifies that no aipt_* database remains.
//
// The concurrency test pins the pg_locks encoding of advisory locks: the
// bigint form used by migrateUpFS (pg_advisory_lock with advisoryLockKey)
// appears as classid = high 32 bits, objid = low 32 bits, objsubid = 1, while
// the two-int4 form used as the gate (pg_advisory_xact_lock(classid, objid))
// appears as objsubid = 2. The gate key is numerically distinct from
// advisoryLockKey.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pg_locks coordinates of the production session advisory lock taken by
// migrateUpFS: the bigint form pg_advisory_lock(advisoryLockKey) is reported
// as classid = high 32 bits, objid = low 32 bits, objsubid = 1.
const (
	advisoryLockHigh32 = int64(advisoryLockKey) >> 32
	advisoryLockLow32  = int64(advisoryLockKey) & 0xFFFFFFFF
	prodLockSubID      = 1
)

// The transaction-scoped gate used by the concurrency test: a two-int4
// advisory lock (objsubid = 2) held by the test session and requested by
// custom migration SQL. It is numerically distinct from advisoryLockKey, so
// its pg_locks coordinate (classid = gateClassID, objid = gateObjID,
// objsubid = 2) can never collide with the production lock.
const (
	gateClassID = 42
	gateObjID   = 4242
	gateSubID   = 2
)

// integrationFixture owns one uniquely generated aipt_* ephemeral database on
// the PostgreSQL server named by AIPT_POSTGRES_DSN. The fixture parses the
// administrative DSN, creates the ephemeral database, registers cleanup
// immediately after CREATE DATABASE succeeds, and exposes accessors that reach
// only the generated database; the administrative pool is used exclusively for
// lifecycle operations (create, terminate, drop, verify).
type integrationFixture struct {
	t      *testing.T
	dbName string
	ephCfg *pgxpool.Config // administrative DSN with Database replaced by dbName
	admin  *pgxpool.Pool   // administrative pool, lifecycle operations only
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()

	dsn := os.Getenv("AIPT_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("AIPT_REQUIRE_POSTGRES_INTEGRATION") == "1" {
			t.Fatalf("AIPT_POSTGRES_DSN is required when AIPT_REQUIRE_POSTGRES_INTEGRATION=1; refusing to skip")
		}
		t.Skip("AIPT_POSTGRES_DSN is not set; skipping PostgreSQL migration integration tests")
	}

	adminCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse AIPT_POSTGRES_DSN: %v", err)
	}
	if adminCfg.ConnConfig.Database == "" {
		t.Fatalf("AIPT_POSTGRES_DSN must name a database (dbname) from which to create ephemeral databases")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgxpool.NewWithConfig(ctx, adminCfg)
	if err != nil {
		t.Fatalf("connect to administrative database: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatalf("ping administrative database: %v", err)
	}

	// Collision-resistant, identifier-safe lowercase [a-z0-9_] name.
	dbName := fmt.Sprintf("aipt_it_%s", mustRandomHex(t, 8))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create ephemeral database %q: %v", dbName, err)
	}

	ephCfg := adminCfg.Copy()
	ephCfg.ConnConfig.Database = dbName

	fx := &integrationFixture{t: t, dbName: dbName, ephCfg: ephCfg, admin: admin}
	t.Cleanup(fx.cleanup) // registered immediately after CREATE DATABASE succeeds
	return fx
}

// cleanup terminates every connection to the ephemeral database, drops exactly
// that database (never a wildcard), verifies it is gone, and asserts that no
// aipt_* database remains on the server. It never calls t.Fatalf (cleanup runs
// outside the test body) and always closes the administrative pool.
func (fx *integrationFixture) cleanup() {
	t := fx.t
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := fx.admin.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
		fx.dbName); err != nil {
		t.Errorf("terminate connections to %q: %v", fx.dbName, err)
	}

	if _, err := fx.admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{fx.dbName}.Sanitize()); err != nil {
		t.Errorf("drop ephemeral database %q: %v", fx.dbName, err)
	}

	var n int
	if err := fx.admin.QueryRow(ctx, "SELECT count(*) FROM pg_database WHERE datname = $1", fx.dbName).Scan(&n); err != nil {
		t.Errorf("verify %q is gone: %v", fx.dbName, err)
	} else if n != 0 {
		t.Errorf("ephemeral database %q still exists after DROP", fx.dbName)
	}

	// Unambiguous literal aipt_ prefix: left() equality has no LIKE
	// wildcard/escape ambiguity, so only databases whose name literally starts
	// with the five characters "aipt_" are counted.
	if err := fx.admin.QueryRow(ctx, "SELECT count(*) FROM pg_database WHERE left(datname, 5) = 'aipt_'").Scan(&n); err != nil {
		t.Errorf("count remaining aipt_* databases: %v", err)
	} else if n != 0 {
		t.Errorf("cleanup left %d aipt_* database(s) on the server", n)
	}

	fx.admin.Close()
}

// pool returns a new pool whose connections reach only the ephemeral database.
// MaxConns is set explicitly so the concurrency test's two runners plus the
// test's own queries can never starve each other.
func (fx *integrationFixture) pool(ctx context.Context) *pgxpool.Pool {
	t := fx.t
	cfg := fx.ephCfg.Copy()
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to ephemeral database %q: %v", fx.dbName, err)
	}
	return pool
}

// connConfig returns a fresh copy of the ephemeral database connection config.
func (fx *integrationFixture) connConfig() *pgx.ConnConfig {
	return fx.ephCfg.ConnConfig.Copy()
}

// mustRandomHex returns n random bytes as lowercase hex, used for
// collision-resistant identifier-safe database names.
func mustRandomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(buf)
}

// waitForCondition polls cond until it reports true, bounded by both timeout
// and ctx. The poll loop is deterministic in what it asserts: it only returns
// once the observed pg_locks state proves the condition, never after a fixed
// delay.
func waitForCondition(t *testing.T, ctx context.Context, timeout time.Duration, cond func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, err := cond()
		if err != nil {
			t.Fatalf("poll condition: %v", err)
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for condition", timeout)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context done while waiting for condition: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// advisoryLockPIDs returns the session pids that hold (granted) or are waiting
// on (not granted) the advisory lock at the given pg_locks coordinate,
// restricted to the caller's current database.
func advisoryLockPIDs(ctx context.Context, pool *pgxpool.Pool, classID, objID int64, objSubID int, granted bool) ([]int, error) {
	rows, err := pool.Query(ctx, fmt.Sprintf(
		"SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid = %d AND objid = %d AND objsubid = %d AND granted = %t",
		classID, objID, objSubID, granted))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pids []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err != nil {
			return nil, err
		}
		pids = append(pids, pid)
	}
	return pids, rows.Err()
}

// countAdvisoryLocks counts every pg_locks row (granted or waiting) for the
// given advisory coordinate on the caller's current database.
func countAdvisoryLocks(ctx context.Context, pool *pgxpool.Pool, classID, objID int64, objSubID int) (int, error) {
	var n int
	err := pool.QueryRow(ctx, fmt.Sprintf(
		"SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND classid = %d AND objid = %d AND objsubid = %d",
		classID, objID, objSubID)).Scan(&n)
	return n, err
}

// countAIPTObjects counts the objects in the aipt schema: base tables,
// functions, and non-internal triggers.
func countAIPTObjects(ctx context.Context, pool *pgxpool.Pool) (tables, functions, triggers int, err error) {
	err = pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM information_schema.tables WHERE table_schema = 'aipt' AND table_type = 'BASE TABLE'),
			(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'aipt'),
			(SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'aipt' AND NOT t.tgisinternal)
	`).Scan(&tables, &functions, &triggers)
	return
}

// queryStrings returns a column of strings from a query.
func queryStrings(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) ([]string, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// queryInt64s returns a column of int64 values from a query.
func queryInt64s(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) ([]int64, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// wantStrings fails the test unless got equals want element-wise.
func wantStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s = %v, want %v", what, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s = %v, want %v", what, got, want)
			return
		}
	}
}

// TestPostgresIntegrationMigrationFreshEmbeddedApply covers a fresh apply of
// the embedded migrations through the exported MigrateUp, asserting the exact
// version/name/current-embedded checksum of the recorded row plus the full
// object inventory of the applied schema.
func TestPostgresIntegrationMigrationFreshEmbeddedApply(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	// Exact version/name/current embedded checksum of the frozen ledger row.
	var version int64
	var name string
	var checksum []byte
	var appliedAt time.Time
	if err := pool.QueryRow(ctx,
		"SELECT version, name, checksum, applied_at FROM aipt.schema_migrations ORDER BY version").Scan(
		&version, &name, &checksum, &appliedAt); err != nil {
		t.Fatalf("read aipt.schema_migrations: %v", err)
	}
	if version != 1 {
		t.Errorf("applied version = %d, want 1", version)
	}
	if name != "ledger" {
		t.Errorf("applied name = %q, want ledger", name)
	}
	embeddedSum := sha256.Sum256(mustEmbeddedMigrationBytes(t))
	if !bytes.Equal(checksum, embeddedSum[:]) {
		t.Errorf("applied checksum = %x, want embedded SHA-256 %x", checksum, embeddedSum)
	}
	if got := hex.EncodeToString(checksum); got != ledgerMigrationChecksumHex {
		t.Errorf("applied checksum hex = %s, want pinned %s", got, ledgerMigrationChecksumHex)
	}
	if appliedAt.IsZero() {
		t.Error("applied_at must be set by the database")
	}
	var queueChecksum []byte
	if err := pool.QueryRow(ctx, "SELECT checksum FROM aipt.schema_migrations WHERE version = 2 AND name = 'playtest_queue'").Scan(&queueChecksum); err != nil {
		t.Fatalf("read queue migration metadata: %v", err)
	}
	queueEmbeddedSum := sha256.Sum256(mustQueueMigrationBytes(t))
	if !bytes.Equal(queueChecksum, queueEmbeddedSum[:]) || hex.EncodeToString(queueChecksum) != queueMigrationChecksumHex {
		t.Errorf("queue migration checksum = %x, want %x", queueChecksum, queueEmbeddedSum)
	}

	// Object inventory: B003 ledger plus the exact B001 queue schema.
	tables, functions, triggers, err := countAIPTObjects(ctx, pool)
	if err != nil {
		t.Fatalf("count aipt objects: %v", err)
	}
	if tables != 12 || functions != 6 || triggers != 4 {
		t.Errorf("aipt object inventory = %d tables, %d functions, %d triggers; want 12, 6, 4",
			tables, functions, triggers)
	}
	tableNames, err := queryStrings(ctx, pool,
		"SELECT table_name FROM information_schema.tables WHERE table_schema = 'aipt' AND table_type = 'BASE TABLE' ORDER BY table_name")
	if err != nil {
		t.Fatalf("list aipt tables: %v", err)
	}
	wantStrings(t, "aipt tables", tableNames, []string{
		"ledger_events", "ledger_streams", "playtest_campaigns", "playtest_cases",
		"playtest_queue_control", "playtest_runs", "playtest_suites", "run_attempts",
		"run_dependencies", "run_leases", "run_manifests", "schema_migrations",
	})
	funcNames, err := queryStrings(ctx, pool,
		"SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'aipt' ORDER BY p.proname")
	if err != nil {
		t.Fatalf("list aipt functions: %v", err)
	}
	wantStrings(t, "aipt functions", funcNames, []string{
		"ledger_event_hash_v1", "ledger_events_append_only", "playtest_priority_rank",
		"playtest_runs_identity_immutable", "run_attempts_append_only", "run_manifests_immutable",
	})

	// The versioned hash function is live and returns a 32-byte digest.
	var hashLen int
	if err := pool.QueryRow(ctx,
		"SELECT octet_length(aipt.ledger_event_hash_v1($1, $2, $3, $4, $5, $6))",
		"stream", int64(1), "evt", "type", make([]byte, 32), nil).Scan(&hashLen); err != nil {
		t.Fatalf("call aipt.ledger_event_hash_v1: %v", err)
	}
	if hashLen != 32 {
		t.Errorf("ledger_event_hash_v1 returned %d bytes, want 32", hashLen)
	}

	// The append-only trigger rejects an UPDATE -- even one matching zero rows
	// -- with the stable code and SQLSTATE 55000.
	_, err = pool.Exec(ctx, "UPDATE aipt.ledger_events SET event_type = 'x'")
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("UPDATE aipt.ledger_events error = %v, want *pgconn.PgError", err)
	}
	if pgErr.Code != "55000" || !strings.Contains(pgErr.Message, "AIPT_LEDGER_APPEND_ONLY") {
		t.Errorf("append-only rejection = SQLSTATE %s %q, want 55000 with AIPT_LEDGER_APPEND_ONLY",
			pgErr.Code, pgErr.Message)
	}
}

// TestPostgresIntegrationMigrationSecondRunNoOp covers the clean second-run
// no-op: no error, exactly two metadata rows, an unchanged applied_at, and an
// unchanged object inventory.
func TestPostgresIntegrationMigrationSecondRunNoOp(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("first MigrateUp: %v", err)
	}

	var appliedBefore time.Time
	if err := pool.QueryRow(ctx, "SELECT applied_at FROM aipt.schema_migrations WHERE version = 1").Scan(&appliedBefore); err != nil {
		t.Fatalf("read applied_at after first run: %v", err)
	}
	tablesBefore, functionsBefore, triggersBefore, err := countAIPTObjects(ctx, pool)
	if err != nil {
		t.Fatalf("count objects after first run: %v", err)
	}

	// Give now() time to advance so an accidental re-apply would observably
	// change applied_at.
	time.Sleep(50 * time.Millisecond)

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("second MigrateUp must be a clean no-op, got: %v", err)
	}

	var appliedAfter time.Time
	if err := pool.QueryRow(ctx, "SELECT applied_at FROM aipt.schema_migrations WHERE version = 1").Scan(&appliedAfter); err != nil {
		t.Fatalf("read applied_at after second run: %v", err)
	}
	if !appliedBefore.Equal(appliedAfter) {
		t.Errorf("second run mutated applied_at: %v -> %v", appliedBefore, appliedAfter)
	}

	var rowCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM aipt.schema_migrations").Scan(&rowCount); err != nil {
		t.Fatalf("count schema_migrations rows: %v", err)
	}
	if rowCount != 2 {
		t.Errorf("second run left %d schema_migrations rows, want 2", rowCount)
	}

	tablesAfter, functionsAfter, triggersAfter, err := countAIPTObjects(ctx, pool)
	if err != nil {
		t.Fatalf("count objects after second run: %v", err)
	}
	if tablesAfter != tablesBefore || functionsAfter != functionsBefore || triggersAfter != triggersBefore {
		t.Errorf("second run changed object inventory: tables %d->%d, functions %d->%d, triggers %d->%d",
			tablesBefore, tablesAfter, functionsBefore, functionsAfter, triggersBefore, triggersAfter)
	}
}

// TestPostgresIntegrationMigrationSameVersionChecksumDrift covers same-version
// checksum drift: the run fails with errors.Is/errors.As-compatible drift
// errors carrying both checksums, and the recorded metadata row is not mutated
// in any way.
func TestPostgresIntegrationMigrationSameVersionChecksumDrift(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	sqlOriginal := "CREATE TABLE aipt.drift_marker (id bigint PRIMARY KEY);\n"
	fsysOriginal := fstest.MapFS{
		"migrations/000001_drift_marker.sql": &fstest.MapFile{Data: []byte(sqlOriginal)},
	}
	if err := migrateUpFS(ctx, pool, fsysOriginal); err != nil {
		t.Fatalf("initial migrateUpFS: %v", err)
	}

	var version int64
	var name string
	var checksum []byte
	var appliedAt time.Time
	if err := pool.QueryRow(ctx,
		"SELECT version, name, checksum, applied_at FROM aipt.schema_migrations WHERE version = 1").Scan(
		&version, &name, &checksum, &appliedAt); err != nil {
		t.Fatalf("read applied row: %v", err)
	}
	originalSum := sha256.Sum256([]byte(sqlOriginal))
	if version != 1 || name != "drift_marker" || !bytes.Equal(checksum, originalSum[:]) {
		t.Fatalf("applied row = version %d name %q checksum %x, want 1 drift_marker %x",
			version, name, checksum, originalSum)
	}

	// Same numeric version, drifted SQL bytes.
	sqlDrifted := "CREATE TABLE aipt.drift_marker (id bigint PRIMARY KEY, extra text);\n"
	fsysDrifted := fstest.MapFS{
		"migrations/000001_drift_marker.sql": &fstest.MapFile{Data: []byte(sqlDrifted)},
	}
	err := migrateUpFS(ctx, pool, fsysDrifted)
	if err == nil {
		t.Fatal("same-version checksum drift must be rejected")
	}
	if !errors.Is(err, ErrMigrationChecksumDrift) {
		t.Fatalf("drift error must match ErrMigrationChecksumDrift via errors.Is, got %v", err)
	}
	var typed *MigrationChecksumDriftError
	if !errors.As(err, &typed) {
		t.Fatalf("drift error must be recoverable via errors.As, got %v", err)
	}
	driftedSum := sha256.Sum256([]byte(sqlDrifted))
	if typed.Version != 1 || typed.Expected != originalSum || typed.Actual != driftedSum {
		t.Errorf("typed drift = version %d expected %x actual %x, want 1 %x %x",
			typed.Version, typed.Expected, typed.Actual, originalSum, driftedSum)
	}

	// No metadata mutation: the recorded row is byte-for-byte unchanged.
	var v2 int64
	var n2 string
	var c2 []byte
	var at2 time.Time
	if err := pool.QueryRow(ctx,
		"SELECT version, name, checksum, applied_at FROM aipt.schema_migrations WHERE version = 1").Scan(
		&v2, &n2, &c2, &at2); err != nil {
		t.Fatalf("re-read applied row: %v", err)
	}
	if v2 != version || n2 != name || !bytes.Equal(c2, checksum) || !at2.Equal(appliedAt) {
		t.Errorf("drifted run mutated metadata: version %d->%d name %q->%q checksum %x->%x applied_at %v->%v",
			version, v2, name, n2, checksum, c2, appliedAt, at2)
	}

	// The drifted SQL never executed: the table has no extra column.
	cols, err := queryStrings(ctx, pool,
		"SELECT column_name FROM information_schema.columns WHERE table_schema = 'aipt' AND table_name = 'drift_marker' ORDER BY column_name")
	if err != nil {
		t.Fatalf("list drift_marker columns: %v", err)
	}
	wantStrings(t, "drift_marker columns", cols, []string{"id"})

	// The original bytes still validate cleanly afterwards (no-op).
	if err := migrateUpFS(ctx, pool, fsysOriginal); err != nil {
		t.Fatalf("re-run with original bytes after drift must succeed: %v", err)
	}
}

// TestPostgresIntegrationMigrationDuplicateVersionRejectedBeforeBootstrap
// covers the fail-closed load path: duplicate numeric local versions are
// rejected before any database access, so neither the aipt schema nor any
// advisory lock ever materializes.
func TestPostgresIntegrationMigrationDuplicateVersionRejectedBeforeBootstrap(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	fsys := fstest.MapFS{
		"migrations/000001_alpha.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
		"migrations/000001_beta.sql":  &fstest.MapFile{Data: []byte("SELECT 2;\n")},
	}
	err := migrateUpFS(ctx, pool, fsys)
	if err == nil {
		t.Fatal("duplicate numeric migration versions must be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate migration version") {
		t.Errorf("error = %q, want it to report the duplicate version", err)
	}

	// loadMigrations fails before any database access: bootstrap never ran and
	// no advisory lock was ever taken.
	var schemas int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM pg_namespace WHERE nspname = 'aipt'").Scan(&schemas); err != nil {
		t.Fatalf("count aipt schema: %v", err)
	}
	if schemas != 0 {
		t.Errorf("bootstrap ran before duplicate-version rejection: aipt schema exists")
	}
	var locks int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())").Scan(&locks); err != nil {
		t.Fatalf("count advisory locks: %v", err)
	}
	if locks != 0 {
		t.Errorf("duplicate-version rejection took %d advisory lock(s), want 0", locks)
	}
}

// TestPostgresIntegrationMigrationFailingSecondMigrationRollsBack covers the
// atomic per-migration transaction: a deliberately failing second migration
// leaves migration 1 committed, drops the failed migration's objects, records
// no metadata row, and a fixed re-run applies cleanly with no partial trace.
func TestPostgresIntegrationMigrationFailingSecondMigrationRollsBack(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	sql1 := "CREATE TABLE aipt.rollback_m1 (id bigint PRIMARY KEY);\n"
	sql2 := "CREATE TABLE aipt.rollback_m2 (id bigint PRIMARY KEY);\n" +
		"INSERT INTO aipt.rollback_m2 (id) VALUES (1);\n" +
		"INSERT INTO aipt.rollback_m2 (id) VALUES (1);\n" // duplicate key: this transaction must roll back
	fsys := fstest.MapFS{
		"migrations/000001_rollback_m1.sql": &fstest.MapFile{Data: []byte(sql1)},
		"migrations/000002_rollback_m2.sql": &fstest.MapFile{Data: []byte(sql2)},
	}

	err := migrateUpFS(ctx, pool, fsys)
	if err == nil {
		t.Fatal("a run whose second migration fails must fail")
	}
	if !strings.Contains(err.Error(), "apply migration 2") {
		t.Errorf("error = %q, want it to name migration 2", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Errorf("error = %v, want the SQLSTATE 23505 duplicate-key cause preserved", err)
	}

	// Migration 1 remains committed; migration 2 left no trace.
	versions, err := queryInt64s(ctx, pool, "SELECT version FROM aipt.schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("read applied versions: %v", err)
	}
	if len(versions) != 1 || versions[0] != 1 {
		t.Errorf("applied versions = %v, want exactly [1]", versions)
	}
	tables, _, _, err := countAIPTObjects(ctx, pool)
	if err != nil {
		t.Fatalf("count aipt objects: %v", err)
	}
	// aipt.schema_migrations plus rollback_m1: 2 tables; rollback_m2 rolled back.
	if tables != 2 {
		t.Errorf("after failed run: %d aipt tables, want 2 (schema_migrations, rollback_m1)", tables)
	}
	var m2 bool
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'aipt' AND tablename = 'rollback_m2')").Scan(&m2); err != nil {
		t.Fatalf("check rollback_m2: %v", err)
	}
	if m2 {
		t.Error("rollback_m2 must not exist: the failed migration transaction was rolled back")
	}

	// Re-running with a fixed second migration applies cleanly, proving no
	// partial state remains from the failed attempt.
	sql2Fixed := "CREATE TABLE aipt.rollback_m2 (id bigint PRIMARY KEY);\n"
	fsysFixed := fstest.MapFS{
		"migrations/000001_rollback_m1.sql": &fstest.MapFile{Data: []byte(sql1)},
		"migrations/000002_rollback_m2.sql": &fstest.MapFile{Data: []byte(sql2Fixed)},
	}
	if err := migrateUpFS(ctx, pool, fsysFixed); err != nil {
		t.Fatalf("fixed second migration must apply cleanly: %v", err)
	}
	versions, err = queryInt64s(ctx, pool, "SELECT version FROM aipt.schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("re-read applied versions: %v", err)
	}
	if len(versions) != 2 || versions[0] != 1 || versions[1] != 2 {
		t.Errorf("after fixed re-run: applied versions = %v, want [1 2]", versions)
	}
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'aipt' AND tablename = 'rollback_m2')").Scan(&m2); err != nil {
		t.Fatalf("re-check rollback_m2: %v", err)
	}
	if !m2 {
		t.Error("rollback_m2 must exist after the fixed re-run")
	}
}

// runnerTracker records how many concurrent runner goroutines were started and
// how many of their results the test body has already received. The teardown
// drain uses it so success and failure paths neither double-read an
// already-consumed result nor leak a pending runner. It is only ever touched
// by the test goroutine, so it is race-safe.
type runnerTracker struct {
	started  int
	received int
}

// TestPostgresIntegrationMigrationConcurrentRunners proves the migration
// runner serializes concurrent runs on the production session advisory lock.
// The test holds a distinct transaction-scoped two-int4 gate lock that custom
// migration SQL waits on; pg_locks is then used to prove, deterministically
// (not by timing), that runner 1 waits on the gate while holding the
// production lock, that runner 2 waits on the production lock, and -- after
// the gate is released -- that both runners join into one coherent applied
// schema with no residual advisory locks. It also pins the pg_locks encoding
// of both advisory-lock forms.
func TestPostgresIntegrationMigrationConcurrentRunners(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// The gate is numerically distinct from advisoryLockKey, so its pg_locks
	// coordinate (classid = gateClassID, objid = gateObjID, objsubid = 2) can
	// never collide with the production lock (classid = high32, objid = low32,
	// objsubid = 1).
	if got := (int64(gateClassID) << 32) | int64(gateObjID); got == advisoryLockKey {
		t.Fatal("gate key must be distinct from advisoryLockKey")
	}

	gateConn, err := pgx.ConnectConfig(ctx, fx.connConfig())
	if err != nil {
		t.Fatalf("connect gate session: %v", err)
	}
	// Closing with an open transaction rolls the gate back, so even a failed
	// test releases the gate; the close itself is bounded.
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		_ = gateConn.Close(closeCtx)
	}()

	var gatePID int
	if err := gateConn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&gatePID); err != nil {
		t.Fatalf("read gate session pid: %v", err)
	}
	gateTx, err := gateConn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin gate transaction: %v", err)
	}
	if _, err := gateTx.Exec(ctx, "SELECT pg_advisory_xact_lock($1, $2)", int32(gateClassID), int32(gateObjID)); err != nil {
		t.Fatalf("acquire gate lock: %v", err)
	}

	pool := fx.pool(ctx) // migration pool: capacity for both runners plus margin
	defer pool.Close()
	vpool := fx.pool(ctx) // separate verification pool: never competes with runners
	defer vpool.Close()

	// Runner contexts are cancellable so the teardown can abort a runner that
	// is stuck waiting on the gate even after the test has already failed.
	runnerCtx, runnerCancel := context.WithCancel(ctx)

	// Custom migrations: migration 2 waits on the gate inside its own
	// transaction, so runner 1 blocks there while still holding the production
	// session advisory lock.
	sql1 := "CREATE TABLE aipt.concurrent_m1 (id bigint PRIMARY KEY);\n"
	sql2 := fmt.Sprintf("SELECT pg_advisory_xact_lock(%d, %d);\nCREATE TABLE aipt.concurrent_m2 (id bigint PRIMARY KEY);\n",
		gateClassID, gateObjID)
	fsys := fstest.MapFS{
		"migrations/000001_concurrent_setup.sql": &fstest.MapFile{Data: []byte(sql1)},
		"migrations/000002_concurrent_gate.sql":  &fstest.MapFile{Data: []byte(sql2)},
	}

	results := make(chan error, 2)
	var tracker runnerTracker
	startRunner := func() {
		tracker.started++
		go func() { results <- migrateUpFS(runnerCtx, pool, fsys) }()
	}

	// Teardown executes before vpool.Close/pool.Close (defers are LIFO): it
	// cancels every still-running runner, boundedly rolls back/releases the
	// gate on an independent background-derived context (so a canceled test
	// context can never prevent the release), and joins every started runner
	// the test body has not already received. Without it, a failure between
	// startRunner and the gate release would leave runners blocked on the gate
	// while pool.Close waits forever for their connections.
	defer func() {
		tctx, tcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer tcancel()

		runnerCancel() // abort in-flight runner work; the runner's unlock uses its own background context

		if gateTx != nil {
			// Releases the transaction-scoped gate; a no-op error once the
			// success path has already committed.
			_ = gateTx.Rollback(tctx)
		}
		if gateConn != nil {
			// Idempotent: closing the session also releases the gate at the
			// server even if the rollback above failed.
			_ = gateConn.Close(tctx)
		}

		for tracker.received < tracker.started {
			select {
			case <-results:
				tracker.received++
			case <-tctx.Done():
				t.Errorf("teardown: runner %d did not finish within %s: %v",
					tracker.received+1, 30*time.Second, tctx.Err())
				return
			}
		}
	}()

	// Runner 1 first...
	startRunner()

	// ...prove runner 1 holds the production session lock (bigint form:
	// classid = high32 = 0, objid = low32, objsubid = 1) while waiting on the
	// gate (two-int4 form: classid = gateClassID, objid = gateObjID,
	// objsubid = 2).
	var runner1PID int
	waitForCondition(t, ctx, 30*time.Second, func() (bool, error) {
		holders, err := advisoryLockPIDs(ctx, vpool, advisoryLockHigh32, advisoryLockLow32, prodLockSubID, true)
		if err != nil {
			return false, err
		}
		waiters, err := advisoryLockPIDs(ctx, vpool, gateClassID, gateObjID, gateSubID, false)
		if err != nil {
			return false, err
		}
		if len(holders) != 1 || len(waiters) != 1 {
			return false, nil
		}
		runner1PID = holders[0]
		return waiters[0] == runner1PID, nil
	})

	// The granted gate lock must be the test's own session.
	gateHolders, err := advisoryLockPIDs(ctx, vpool, gateClassID, gateObjID, gateSubID, true)
	if err != nil {
		t.Fatalf("read granted gate holders: %v", err)
	}
	if len(gateHolders) != 1 || gateHolders[0] != gatePID {
		t.Errorf("granted gate holders = %v, want exactly [%d] (the test session)", gateHolders, gatePID)
	}

	// Start runner 2 and prove it waits on the production lock: exactly one
	// session other than runner 1 and the gate holder is waiting there.
	startRunner()
	waitForCondition(t, ctx, 30*time.Second, func() (bool, error) {
		waiters, err := advisoryLockPIDs(ctx, vpool, advisoryLockHigh32, advisoryLockLow32, prodLockSubID, false)
		if err != nil {
			return false, err
		}
		if len(waiters) != 1 {
			return false, nil
		}
		return waiters[0] != runner1PID && waiters[0] != gatePID, nil
	})

	// Pin the pg_locks encodings while every lock is live: the bigint
	// production lock exists only at objsubid = 1 (one granted for runner 1,
	// one waiting for runner 2) and never at objsubid = 2 or with swapped
	// high/low halves; the two-int4 gate exists only at objsubid = 2 (one
	// granted for the test, one waiting for runner 1).
	if n, err := countAdvisoryLocks(ctx, vpool, advisoryLockHigh32, advisoryLockLow32, prodLockSubID); err != nil {
		t.Fatalf("count production lock rows: %v", err)
	} else if n != 2 {
		t.Errorf("production lock rows = %d, want 2 (1 granted, 1 waiting)", n)
	}
	if n, err := countAdvisoryLocks(ctx, vpool, advisoryLockHigh32, advisoryLockLow32, gateSubID); err != nil {
		t.Fatalf("count production lock at objsubid=2: %v", err)
	} else if n != 0 {
		t.Errorf("bigint production lock must not appear at objsubid=2, found %d row(s)", n)
	}
	if n, err := countAdvisoryLocks(ctx, vpool, gateClassID, gateObjID, gateSubID); err != nil {
		t.Fatalf("count gate lock rows: %v", err)
	} else if n != 2 {
		t.Errorf("gate lock rows = %d, want 2 (1 granted, 1 waiting)", n)
	}
	if n, err := countAdvisoryLocks(ctx, vpool, gateClassID, gateObjID, prodLockSubID); err != nil {
		t.Fatalf("count gate lock at objsubid=1: %v", err)
	} else if n != 0 {
		t.Errorf("two-int4 gate lock must not appear at objsubid=1, found %d row(s)", n)
	}
	if n, err := countAdvisoryLocks(ctx, vpool, advisoryLockLow32, advisoryLockHigh32, prodLockSubID); err != nil {
		t.Fatalf("count swapped production lock: %v", err)
	} else if n != 0 {
		t.Errorf("production lock must not appear with classid/objid swapped, found %d row(s)", n)
	}

	// Release the gate: both runners then finish deterministically.
	if err := gateTx.Commit(ctx); err != nil {
		t.Fatalf("release gate: %v", err)
	}

	// Normal two-result success assertions: join both runners and record each
	// received result so the teardown drain never double-reads it.
	for tracker.received < tracker.started {
		select {
		case err := <-results:
			tracker.received++
			if err != nil {
				t.Fatalf("concurrent runner %d failed: %v", tracker.received, err)
			}
		case <-ctx.Done():
			t.Fatalf("waiting for runner %d: %v", tracker.received+1, ctx.Err())
		}
	}

	// One coherent applied set: exactly the two migrations, in order, with the
	// checksums of the exact fs bytes.
	rows, err := pool.Query(ctx, "SELECT version, name, checksum FROM aipt.schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	type appliedRecord struct {
		version  int64
		name     string
		checksum []byte
	}
	var got []appliedRecord
	for rows.Next() {
		var a appliedRecord
		if err := rows.Scan(&a.version, &a.name, &a.checksum); err != nil {
			rows.Close()
			t.Fatalf("scan schema_migrations row: %v", err)
		}
		got = append(got, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema_migrations: %v", err)
	}
	sum1 := sha256.Sum256([]byte(sql1))
	sum2 := sha256.Sum256([]byte(sql2))
	wantApplied := []appliedRecord{
		{version: 1, name: "concurrent_setup", checksum: sum1[:]},
		{version: 2, name: "concurrent_gate", checksum: sum2[:]},
	}
	if len(got) != len(wantApplied) {
		t.Fatalf("applied rows = %d, want exactly 2", len(got))
	}
	for i := range wantApplied {
		if got[i].version != wantApplied[i].version || got[i].name != wantApplied[i].name ||
			!bytes.Equal(got[i].checksum, wantApplied[i].checksum) {
			t.Errorf("applied[%d] = version %d name %q checksum %x, want version %d name %q checksum %x",
				i, got[i].version, got[i].name, got[i].checksum,
				wantApplied[i].version, wantApplied[i].name, wantApplied[i].checksum)
		}
	}

	// Both migrations' schema objects exist.
	var m1, m2 bool
	if err := pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'aipt' AND tablename = 'concurrent_m1'), EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'aipt' AND tablename = 'concurrent_m2')").Scan(&m1, &m2); err != nil {
		t.Fatalf("check concurrent tables: %v", err)
	}
	if !m1 || !m2 {
		t.Errorf("concurrent tables exist = m1:%t m2:%t, want both", m1, m2)
	}

	// No residual advisory locks remain on this database once both runners have
	// returned: their session locks were released by migrateUpFS's deferred
	// unlock and the gate's transaction-scoped lock is gone.
	var residual int
	if err := vpool.QueryRow(ctx,
		"SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND database = (SELECT oid FROM pg_database WHERE datname = current_database())").Scan(&residual); err != nil {
		t.Fatalf("count residual advisory locks: %v", err)
	}
	if residual != 0 {
		t.Errorf("%d residual advisory lock(s) on %s", residual, fx.dbName)
	}
}
