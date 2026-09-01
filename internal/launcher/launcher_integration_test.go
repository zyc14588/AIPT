package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// launcherIntegrationFixture owns one uniquely named temporary database. Its
// b004_launcher_it_ prefix deliberately does not overlap the B003 storage
// tests' aipt_ inventory assertions when Go executes packages concurrently.
type launcherIntegrationFixture struct {
	t       *testing.T
	admin   *pgxpool.Pool
	dbName  string
	dsn     string
	dropped bool
}

func newLauncherIntegrationFixture(t *testing.T) *launcherIntegrationFixture {
	t.Helper()
	adminDSN := os.Getenv("AIPT_POSTGRES_DSN")
	if adminDSN == "" {
		if os.Getenv("AIPT_REQUIRE_POSTGRES_INTEGRATION") == "1" {
			t.Fatal("AIPT_POSTGRES_DSN is required when AIPT_REQUIRE_POSTGRES_INTEGRATION=1")
		}
		t.Skip("AIPT_POSTGRES_DSN is not set; skipping PostgreSQL launcher integration tests")
	}

	parsedURL, err := url.Parse(adminDSN)
	if err != nil || (parsedURL.Scheme != "postgres" && parsedURL.Scheme != "postgresql") ||
		parsedURL.Hostname() == "" {
		t.Fatal("AIPT_POSTGRES_DSN must be a valid URI-form PostgreSQL DSN")
	}
	adminConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatal("cannot parse AIPT_POSTGRES_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("cannot open PostgreSQL integration administrative pool")
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal("cannot ping PostgreSQL integration administrative database")
	}

	var versionNumber int
	if err := admin.QueryRow(ctx, "SELECT current_setting('server_version_num')::integer").Scan(&versionNumber); err != nil {
		admin.Close()
		t.Fatal("cannot read PostgreSQL integration server version")
	}
	if versionNumber != 180004 {
		admin.Close()
		t.Fatalf("PostgreSQL integration version = %d, want 180004 (18.4)", versionNumber)
	}

	dbName := "b004_launcher_it_" + launcherRandomHex(t, 8)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("cannot create launcher integration database %q", dbName)
	}

	databaseURL := *parsedURL
	databaseURL.Path = "/" + dbName
	databaseURL.RawPath = ""
	databaseURL.Fragment = ""
	fixture := &launcherIntegrationFixture{
		t:      t,
		admin:  admin,
		dbName: dbName,
		dsn:    databaseURL.String(),
	}
	t.Cleanup(fixture.cleanup)
	return fixture
}

func launcherRandomHex(t *testing.T, count int) string {
	t.Helper()
	buffer := make([]byte, count)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal("cannot generate launcher integration database name")
	}
	return hex.EncodeToString(buffer)
}

func (f *launcherIntegrationFixture) cleanup() {
	if !f.dropped {
		if err := f.dropDatabase(); err != nil {
			f.t.Errorf("launcher integration database cleanup failed: %v", err)
		}
	}
	f.admin.Close()
}

func (f *launcherIntegrationFixture) dropDatabase() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := f.admin.Exec(ctx,
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
		f.dbName); err != nil {
		return fmt.Errorf("terminate exact temporary database connections: %w", err)
	}
	if _, err := f.admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{f.dbName}.Sanitize()); err != nil {
		return fmt.Errorf("drop exact temporary database: %w", err)
	}
	var count int
	if err := f.admin.QueryRow(ctx, "SELECT count(*) FROM pg_database WHERE datname = $1", f.dbName).Scan(&count); err != nil {
		return fmt.Errorf("verify exact temporary database removal: %w", err)
	}
	if count != 0 {
		return errors.New("exact temporary database still exists after drop")
	}
	f.dropped = true
	return nil
}

func (f *launcherIntegrationFixture) databasePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, f.dsn)
	if err != nil {
		t.Fatal("cannot open launcher integration database")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatal("cannot ping launcher integration database")
	}
	return pool
}

func (f *launcherIntegrationFixture) configPath(t *testing.T) string {
	t.Helper()
	document := map[string]any{
		"schema":  "aipt.config/v1",
		"profile": "development",
		"database": map[string]any{
			"dsn":             f.dsn,
			"identity":        f.dbName,
			"namespace":       "b004_launcher_dev",
			"ping_timeout_ms": 10000,
		},
		"evidence": map[string]any{
			"namespace": "aipt.evidence.b004_launcher_dev",
		},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aipt-config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal("cannot write launcher integration config")
	}
	return path
}

func runDefaultLauncherExpect(t *testing.T, configPath string, code ErrorCode, gate Gate) error {
	t.Helper()
	instance, err := NewDefault(configPath)
	if err != nil {
		t.Fatalf("NewDefault = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err = instance.Run(ctx)
	if CodeOf(err) != code || GateOf(err) != gate {
		t.Fatalf("Run classification = %s/%s (%v), want %s/%s", CodeOf(err), GateOf(err), err, code, gate)
	}
	if strings.Contains(err.Error(), "postgres://") ||
		strings.Contains(err.Error(), "postgresql://") ||
		strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("launcher error leaks a DSN or credential: %v", err)
	}
	return err
}

func launcherMigrationState(t *testing.T, pool *pgxpool.Pool) (int, time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var count int
	var appliedAt time.Time
	if err := pool.QueryRow(ctx,
		"SELECT count(*), min(applied_at) FROM aipt.schema_migrations").Scan(&count, &appliedAt); err != nil {
		t.Fatal("cannot verify applied B003 migration")
	}
	return count, appliedAt
}

func TestPostgresIntegrationLauncherConnectionMigrationAndNoOp(t *testing.T) {
	t.Setenv("AIPT_MODEL_RUNTIME_CONFIG", "")
	fixture := newLauncherIntegrationFixture(t)
	configPath := fixture.configPath(t)

	first := runDefaultLauncherExpect(t, configPath, CodeGateFailed, GateModel)
	if !errors.Is(first, ErrGateFailed) {
		t.Fatalf("first Run = %v, want ErrGateFailed", first)
	}

	pool := fixture.databasePool(t)
	migrationCount, firstAppliedAt := launcherMigrationState(t, pool)
	if migrationCount != 1 {
		pool.Close()
		t.Fatalf("applied migration count = %d, want 1", migrationCount)
	}
	pool.Close()

	second := runDefaultLauncherExpect(t, configPath, CodeGateFailed, GateModel)
	if !errors.Is(second, ErrGateFailed) {
		t.Fatalf("second Run = %v, want ErrGateFailed", second)
	}

	pool = fixture.databasePool(t)
	secondCount, secondAppliedAt := launcherMigrationState(t, pool)
	if secondCount != 1 || !secondAppliedAt.Equal(firstAppliedAt) {
		pool.Close()
		t.Fatalf("second migration was not a no-op: count=%d first=%s second=%s",
			secondCount, firstAppliedAt.UTC(), secondAppliedAt.UTC())
	}

	injectContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if _, err := pool.Exec(injectContext,
		"UPDATE aipt.schema_migrations SET checksum = decode(repeat('00', 32), 'hex')"); err != nil {
		cancel()
		pool.Close()
		t.Fatal("cannot inject migration checksum drift")
	}
	cancel()
	pool.Close()

	migrationFailure := runDefaultLauncherExpect(t, configPath, CodeGateFailed, GateMigrations)
	if !errors.Is(migrationFailure, ErrGateFailed) {
		t.Fatalf("migration drift Run = %v, want ErrGateFailed", migrationFailure)
	}
}

func TestPostgresIntegrationLauncherDatabaseUnavailableFailsBeforeMigrations(t *testing.T) {
	fixture := newLauncherIntegrationFixture(t)
	configPath := fixture.configPath(t)
	if err := fixture.dropDatabase(); err != nil {
		t.Fatalf("drop temporary database before launch: %v", err)
	}

	err := runDefaultLauncherExpect(t, configPath, CodeGateFailed, GatePostgreSQL)
	if !errors.Is(err, ErrGateFailed) {
		t.Fatalf("Run = %v, want ErrGateFailed", err)
	}
}
