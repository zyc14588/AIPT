// Package postgres contains the PostgreSQL storage layer for migrations: a
// pure, database-free definition layer that parses, validates, orders, and
// checksums the SQL migration files under migrations/, plus a forward-only
// runner, migrateUpFS, that applies pending definitions to PostgreSQL through
// pgx.
//
// The definition layer has no database access and no side effects:
// loadMigrations is a pure function from an fs.FS to validated migration
// definitions, reading only the migrations/ directory and failing closed on
// anything unexpected. There are no embed directives, no filesystem writes,
// and no down/force/repair/ignore API; migrateUpFS is strictly forward-only
// and records each applied migration in aipt.schema_migrations.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisoryLockKey is the fixed session-level advisory lock key held on the
// dedicated connection for the whole migration run. It is the bigint
// interpretation of the ASCII bytes "AIPT" (0x41495054), so every process
// migrating the same database serializes on the same lock.
const advisoryLockKey int64 = 0x41495054 // "AIPT"

// unlockTimeout bounds the deferred session advisory lock release. The unlock
// runs on an independent context derived from context.Background, so it is
// still attempted when the caller's context is canceled or expired, but it can
// never block indefinitely.
const unlockTimeout = 10 * time.Second

// migration is a validated SQL migration definition. Version is the positive
// numeric migration version parsed from the filename, filename is the exact
// file name inside migrations/, name is the lowercase [a-z0-9_] part of the
// filename after the version, sql holds the exact original file bytes (never
// normalized), and checksum is the SHA-256 of those exact bytes.
type migration struct {
	version  int64
	filename string
	name     string
	sql      []byte
	checksum [32]byte
}

// appliedMigration is one recorded row of aipt.schema_migrations as read back
// from the database: the version, name, and raw checksum bytes. checksum is
// nil only if the row had no checksum value at all.
type appliedMigration struct {
	version  int64
	name     string
	checksum []byte
}

// migrateUpFS runs the forward-only migration runner against the database
// reachable through pool, loading all local migration definitions from fsys.
// It fails closed: a nil pool is rejected and all definitions are fully loaded
// and validated before any database access.
//
// A single dedicated connection is acquired and holds a stable session-level
// advisory lock across bootstrap, validation, and applies; the deferred unlock
// is registered only after pg_advisory_lock succeeds, so a failed acquisition
// never attempts an unlock. The unlock runs on an independent bounded
// background context, verifies pg_advisory_unlock returned true, and joins any
// unlock failure with the run result.
//
// Applied rows read from aipt.schema_migrations must be an exact ordered
// prefix of the local migrations; any unknown/gap/order/name/checksum-length/
// checksum drift is rejected before a single pending migration is applied.
// Each pending migration is applied in its own fresh transaction together with
// its metadata insert, so a second run is a no-op.
func migrateUpFS(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) (result error) {
	if pool == nil {
		return errors.New("migrateUpFS: nil *pgxpool.Pool")
	}

	// Load and validate every definition before touching the database.
	migs, err := loadMigrations(fsys)
	if err != nil {
		return fmt.Errorf("migrateUpFS: load migrations: %w", err)
	}

	// One dedicated connection carries the session-level advisory lock for the
	// entire run; transactions for bootstrap and applies run on this same
	// connection so the lock never leaks to another pool connection.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("migrateUpFS: acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return fmt.Errorf("migrateUpFS: acquire session advisory lock: %w", err)
	}

	// Registered only after pg_advisory_lock succeeded; a failed acquisition
	// returns above and never attempts an unlock. Defers run LIFO, so this
	// unlock runs before conn.Release() while the connection is still valid.
	defer func() {
		result = errors.Join(result, unlockAdvisoryLock(conn, advisoryLockKey))
	}()

	if err := bootstrapSchemaMigrations(ctx, conn); err != nil {
		return fmt.Errorf("migrateUpFS: bootstrap aipt.schema_migrations: %w", err)
	}

	applied, err := loadAppliedMigrations(ctx, conn)
	if err != nil {
		return fmt.Errorf("migrateUpFS: read applied migrations: %w", err)
	}

	if err := validateAppliedPrefix(migs, applied); err != nil {
		return fmt.Errorf("migrateUpFS: applied migrations are not an exact prefix of local migrations: %w", err)
	}

	for _, m := range migs[len(applied):] {
		if err := applyMigration(ctx, conn, m); err != nil {
			return fmt.Errorf("migrateUpFS: apply migration %d (%s): %w", m.version, m.filename, err)
		}
	}

	return nil
}

// bootstrapSchemaMigrations creates the aipt schema and the
// aipt.schema_migrations metadata table in one transaction on the locked
// connection. The table enforces the metadata contract at the database level:
// a positive BIGINT version primary key, a nonempty TEXT name, an exactly
// 32-byte BYTEA checksum, and a PostgreSQL-generated TIMESTAMPTZ applied_at.
// Both statements are idempotent so a second run is a no-op.
func bootstrapSchemaMigrations(ctx context.Context, conn *pgxpool.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin bootstrap transaction: %w", err)
	}
	// Rollback is a no-op after Commit and reliably rolls back on failure;
	// pgx also closes the connection if a transaction fails mid-way.
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS aipt"); err != nil {
		return fmt.Errorf("create schema aipt: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS aipt.schema_migrations (
		version    BIGINT PRIMARY KEY CHECK (version > 0),
		name       TEXT NOT NULL CHECK (name <> ''),
		checksum   BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create table aipt.schema_migrations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bootstrap transaction: %w", err)
	}
	return nil
}

// loadAppliedMigrations reads every row of aipt.schema_migrations ordered by
// version ascending.
func loadAppliedMigrations(ctx context.Context, conn *pgxpool.Conn) ([]appliedMigration, error) {
	rows, err := conn.Query(ctx, "SELECT version, name, checksum FROM aipt.schema_migrations ORDER BY version ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var applied []appliedMigration
	for rows.Next() {
		var a appliedMigration
		if err := rows.Scan(&a.version, &a.name, &a.checksum); err != nil {
			return nil, err
		}
		applied = append(applied, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return applied, nil
}

// validateAppliedPrefix verifies that the applied rows read from
// aipt.schema_migrations form an exact ordered prefix of the local migration
// definitions: every applied row must match the local migration at the same
// index in version, name, and 32-byte SHA-256 checksum, and the applied
// versions must be strictly increasing. Any violation fails closed before a
// single pending migration is applied. Checksum drift is reported as
// *MigrationChecksumDriftError with Expected set to the recorded database
// checksum and Actual set to the local file checksum.
func validateAppliedPrefix(local []migration, applied []appliedMigration) error {
	if len(applied) > len(local) {
		return fmt.Errorf("applied migration version %d has no local migration definition (%d applied rows, %d local migrations)",
			applied[len(local)].version, len(applied), len(local))
	}
	for i, a := range applied {
		l := local[i]
		if i > 0 && a.version <= applied[i-1].version {
			return fmt.Errorf("applied migration versions are not strictly increasing (%d after %d)",
				a.version, applied[i-1].version)
		}
		if a.version != l.version {
			return fmt.Errorf("applied migration version %d at index %d does not match local migration version %d: applied rows must be an exact prefix of local migrations",
				a.version, i, l.version)
		}
		if a.name != l.name {
			return fmt.Errorf("applied migration %d has name %q but local migration has name %q",
				a.version, a.name, l.name)
		}
		if len(a.checksum) != len(l.checksum) {
			return fmt.Errorf("applied migration %d checksum has length %d, want %d",
				a.version, len(a.checksum), len(l.checksum))
		}
		if !bytes.Equal(a.checksum, l.checksum[:]) {
			var expected, actual [32]byte
			copy(expected[:], a.checksum)
			copy(actual[:], l.checksum[:])
			return &MigrationChecksumDriftError{Version: a.version, Expected: expected, Actual: actual}
		}
	}
	return nil
}

// applyMigration applies one pending migration and records it in
// aipt.schema_migrations inside a single fresh transaction on the locked
// connection. The exact file bytes are executed with the explicit simple
// protocol so potentially multi-statement migration SQL is supported; the
// metadata insert shares the same transaction, so a failed apply rolls back
// everything and leaves no trace.
func applyMigration(ctx context.Context, conn *pgxpool.Conn, m migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback is a no-op after Commit and reliably rolls back on failure;
	// pgx also closes the connection if a transaction fails mid-way.
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, string(m.sql), pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("execute migration SQL: %w", err)
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO aipt.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
		pgx.QueryExecModeSimpleProtocol, m.version, m.name, m.checksum[:]); err != nil {
		return fmt.Errorf("record migration in aipt.schema_migrations: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// unlockAdvisoryLock releases the session-level advisory lock on an
// independent bounded background context so the release is attempted even when
// the caller's context is done. It verifies that pg_advisory_unlock returned
// true and reports an error otherwise.
func unlockAdvisoryLock(conn *pgxpool.Conn, key int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
	defer cancel()

	var unlocked bool
	if err := conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", key).Scan(&unlocked); err != nil {
		return fmt.Errorf("unlock session advisory lock: %w", err)
	}
	if !unlocked {
		return errors.New("unlock session advisory lock: pg_advisory_unlock returned false (lock not held by this session)")
	}
	return nil
}

// loadMigrations reads every entry under the migrations/ directory of fsys and
// returns the validated migration definitions sorted by strictly increasing
// numeric version. It reads only migrations/ and fails closed on: a missing or
// empty migrations directory, directory entries, malformed filenames, zero or
// duplicate numeric versions, read errors, and whitespace-only SQL. Each
// checksum is the SHA-256 of the exact original file bytes, without any
// normalization.
func loadMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations directory: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("migrations directory is empty: at least one migration file is required")
	}

	seen := make(map[int64]string, len(entries))
	migs := make([]migration, 0, len(entries))

	for _, entry := range entries {
		filename := entry.Name()

		if entry.IsDir() {
			return nil, fmt.Errorf("migrations: %q is a directory, expected a migration file", filename)
		}

		version, name, ok := parseMigrationFilename(filename)
		if !ok {
			return nil, fmt.Errorf("migrations: invalid migration filename %q: must be exactly six decimal digits, an underscore, a nonempty lowercase [a-z0-9_] name, and a .sql suffix", filename)
		}
		if version <= 0 {
			return nil, fmt.Errorf("migrations: %q has version %d; migration versions must be positive", filename, version)
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations: duplicate migration version %d: %q and %q", version, prev, filename)
		}
		seen[version] = filename

		body, err := fs.ReadFile(fsys, path.Join("migrations", filename))
		if err != nil {
			return nil, fmt.Errorf("migrations: read %q: %w", filename, err)
		}
		if strings.TrimSpace(string(body)) == "" {
			return nil, fmt.Errorf("migrations: %q contains no SQL (whitespace only)", filename)
		}

		migs = append(migs, migration{
			version:  version,
			filename: filename,
			name:     name,
			sql:      body,
			checksum: sha256.Sum256(body),
		})
	}

	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	// Prove that returned versions are strictly increasing; duplicates were
	// already rejected above, so this is a fail-closed invariant check.
	for i := 1; i < len(migs); i++ {
		if migs[i].version <= migs[i-1].version {
			return nil, fmt.Errorf("migrations: versions are not strictly increasing (%d after %d)",
				migs[i].version, migs[i-1].version)
		}
	}

	return migs, nil
}

// parseMigrationFilename splits a migration filename of the exact form
// <6 decimal digits>_<nonempty lowercase [a-z0-9_] name>.sql into its numeric
// version (which may be 0; positivity is checked by loadMigrations) and name.
func parseMigrationFilename(filename string) (version int64, name string, ok bool) {
	if !strings.HasSuffix(filename, ".sql") {
		return 0, "", false
	}
	stem := strings.TrimSuffix(filename, ".sql")
	if len(stem) < 7 || stem[6] != '_' {
		return 0, "", false
	}
	digits, name := stem[:6], stem[7:]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, "", false
		}
	}
	if name == "" {
		return 0, "", false
	}
	for _, c := range name {
		if !isLowerAlnumOrUnderscore(c) {
			return 0, "", false
		}
	}
	v, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, "", false
	}
	return v, name, true
}

func isLowerAlnumOrUnderscore(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
}
