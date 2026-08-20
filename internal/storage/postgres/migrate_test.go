package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestLoadMigrationsValidOutOfOrder(t *testing.T) {
	createUsers := "CREATE TABLE users (id bigint PRIMARY KEY);\r\n"
	createOrders := "CREATE TABLE orders (id bigint PRIMARY KEY, user_id bigint);\n\n  -- trailing whitespace kept\n"
	addIndexes := "CREATE INDEX idx_orders_user_id ON orders (user_id);\n"

	fsys := fstest.MapFS{
		"migrations/000003_add_indexes.sql":   &fstest.MapFile{Data: []byte(addIndexes)},
		"migrations/000001_create_users.sql":  &fstest.MapFile{Data: []byte(createUsers)},
		"migrations/000002_create_orders.sql": &fstest.MapFile{Data: []byte(createOrders)},
	}

	migs, err := loadMigrations(fsys)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) != 3 {
		t.Fatalf("got %d migrations, want 3", len(migs))
	}

	want := []struct {
		version  int64
		filename string
		name     string
		sql      string
	}{
		{1, "000001_create_users.sql", "create_users", createUsers},
		{2, "000002_create_orders.sql", "create_orders", createOrders},
		{3, "000003_add_indexes.sql", "add_indexes", addIndexes},
	}
	for i, w := range want {
		got := migs[i]
		if got.version != w.version {
			t.Errorf("migrations[%d].version = %d, want %d", i, got.version, w.version)
		}
		if got.filename != w.filename {
			t.Errorf("migrations[%d].filename = %q, want %q", i, got.filename, w.filename)
		}
		if got.name != w.name {
			t.Errorf("migrations[%d].name = %q, want %q", i, got.name, w.name)
		}
		if string(got.sql) != w.sql {
			t.Errorf("migrations[%d].sql must be the exact original bytes", i)
		}
		wantSum := sha256.Sum256([]byte(w.sql))
		if got.checksum != wantSum {
			t.Errorf("migrations[%d].checksum = %x, want %x", i, got.checksum, wantSum)
		}
	}

	// Versions must be strictly increasing after sorting.
	for i := 1; i < len(migs); i++ {
		if migs[i].version <= migs[i-1].version {
			t.Fatalf("versions not strictly increasing: %d after %d", migs[i].version, migs[i-1].version)
		}
	}
}

func TestLoadMigrationsChecksumUsesExactBytes(t *testing.T) {
	// SQL with leading and trailing whitespace: the checksum must cover the
	// exact original bytes, never a trimmed/normalized form.
	sql := "  SELECT 1;\n\n  "
	fsys := fstest.MapFS{
		"migrations/000001_padded.sql": &fstest.MapFile{Data: []byte(sql)},
	}

	migs, err := loadMigrations(fsys)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	exact := sha256.Sum256([]byte(sql))
	if migs[0].checksum != exact {
		t.Errorf("checksum = %x, want SHA-256 of exact original bytes %x", migs[0].checksum, exact)
	}
	if trimmed := sha256.Sum256(bytes.TrimSpace([]byte(sql))); migs[0].checksum == trimmed {
		t.Errorf("checksum must not be computed over normalized (trimmed) SQL bytes")
	}
}

func TestLoadMigrationsIgnoresFilesOutsideMigrations(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/000001_a.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
		"README.md":               &fstest.MapFile{Data: []byte("not a migration")},
		"migrations.sql":          &fstest.MapFile{Data: []byte("also not a migration")},
	}

	migs, err := loadMigrations(fsys)
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) != 1 || migs[0].filename != "000001_a.sql" {
		t.Fatalf("got %+v, want only the migration under migrations/", migs)
	}
}

func TestLoadMigrationsMissingDirectory(t *testing.T) {
	if _, err := loadMigrations(fstest.MapFS{}); err == nil {
		t.Fatal("missing migrations directory must be rejected")
	}
}

func TestLoadMigrationsEmptyDirectory(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations": &fstest.MapFile{Mode: fs.ModeDir},
	}
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("empty migrations directory must be rejected")
	}
}

func TestLoadMigrationsRejectsDirectoryEntry(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/000001_create_users.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
		// Directories are rejected even when the name looks like a migration.
		"migrations/000002_subdir": &fstest.MapFile{Mode: fs.ModeDir},
	}
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("directory entry inside migrations must be rejected")
	}
}

func TestLoadMigrationsRejectsInvalidFilenames(t *testing.T) {
	bad := []string{
		"000001.sql",     // missing underscore and name
		"000001_x",       // missing .sql suffix
		"00001_x.sql",    // five digits
		"0000001_x.sql",  // seven digits
		"000001_.sql",    // empty name
		"000001_X.sql",   // uppercase name
		"000001_x-y.sql", // hyphen not in [a-z0-9_]
		"000001_x y.sql", // space not in [a-z0-9_]
		"0a0001_x.sql",   // non-digit in the version field
		"000001_é.sql",   // non-ASCII name
		"_x.sql",         // no digits at all
		"000001_x.SQL",   // uppercase extension
	}
	for _, name := range bad {
		fsys := fstest.MapFS{
			"migrations/" + name: &fstest.MapFile{Data: []byte("SELECT 1;\n")},
		}
		if _, err := loadMigrations(fsys); err == nil {
			t.Errorf("filename %q must be rejected", name)
		}
	}
}

func TestLoadMigrationsRejectsZeroVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/000000_zero.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
	}
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("version 0 must be rejected")
	}
}

func TestLoadMigrationsRejectsDuplicateVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/000001_create_users.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
		"migrations/000001_create_roles.sql": &fstest.MapFile{Data: []byte("SELECT 2;\n")},
	}
	if _, err := loadMigrations(fsys); err == nil {
		t.Fatal("duplicate numeric versions must be rejected")
	}
}

func TestLoadMigrationsRejectsBlankSQL(t *testing.T) {
	for name, data := range map[string]string{
		"000001_empty.sql":  "",
		"000002_spaces.sql": "   \n\t  \r\n  ",
	} {
		fsys := fstest.MapFS{
			"migrations/" + name: &fstest.MapFile{Data: []byte(data)},
		}
		if _, err := loadMigrations(fsys); err == nil {
			t.Errorf("whitespace-only SQL in %q must be rejected", name)
		}
	}
}

// failReadFS is a minimal fs.FS whose directory listing succeeds but whose
// file reads always fail, used to prove read errors fail closed.
type failReadFS struct {
	entries []fs.DirEntry
}

func (failReadFS) Open(name string) (fs.File, error) { return nil, fs.ErrNotExist }

func (f failReadFS) ReadDir(name string) ([]fs.DirEntry, error) { return f.entries, nil }

func (failReadFS) ReadFile(name string) ([]byte, error) {
	return nil, errors.New("injected read failure")
}

func TestLoadMigrationsRejectsReadError(t *testing.T) {
	base := fstest.MapFS{
		"migrations/000001_a.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
	}
	entries, err := fs.ReadDir(base, "migrations")
	if err != nil {
		t.Fatalf("fs.ReadDir(base): %v", err)
	}

	if _, err := loadMigrations(failReadFS{entries: entries}); err == nil {
		t.Fatal("file read error must be rejected")
	}
}

func TestMigrationChecksumDriftError(t *testing.T) {
	var expected, actual [32]byte
	expected[0] = 0x01
	actual[0] = 0x02

	err := &MigrationChecksumDriftError{Version: 42, Expected: expected, Actual: actual}

	if !errors.Is(err, ErrMigrationChecksumDrift) {
		t.Fatal("typed drift error must match ErrMigrationChecksumDrift via errors.Is")
	}
	if !errors.Is(&MigrationChecksumDriftError{}, ErrMigrationChecksumDrift) {
		t.Fatal("zero-value drift error must also match the sentinel")
	}
	if errors.Is(errors.New("unrelated"), ErrMigrationChecksumDrift) {
		t.Fatal("unrelated errors must not match the sentinel")
	}

	var typed *MigrationChecksumDriftError
	if !errors.As(err, &typed) {
		t.Fatal("drift error must be recoverable via errors.As")
	}
	if typed.Version != 42 || typed.Expected != expected || typed.Actual != actual {
		t.Errorf("typed error must carry version and both checksums, got %+v", typed)
	}

	msg := err.Error()
	for _, want := range []string{"AIPT_MIGRATION_CHECKSUM_DRIFT", "42", fmt.Sprintf("%x", expected), fmt.Sprintf("%x", actual)} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}

	if got := ErrMigrationChecksumDrift.Error(); got != "AIPT_MIGRATION_CHECKSUM_DRIFT" {
		t.Errorf("sentinel text = %q, want the code itself", got)
	}
}

// ---- migrateUpFS: nil pool rejection (DB-free, fails before any access) ----

func TestMigrateUpFSNilPool(t *testing.T) {
	fsys := fstest.MapFS{
		"migrations/000001_create_users.sql": &fstest.MapFile{Data: []byte("SELECT 1;\n")},
	}
	var pool *pgxpool.Pool // nil: rejected before any database access
	err := migrateUpFS(context.Background(), pool, fsys)
	if err == nil {
		t.Fatal("nil *pgxpool.Pool must be rejected before any database access")
	}
	if !strings.Contains(err.Error(), "nil *pgxpool.Pool") {
		t.Errorf("error = %q, want it to mention the nil pool", err)
	}
}

// ---- pure helper: validateAppliedPrefix ----

// mustLocalMigrations builds local migration definitions in the given order,
// computing each checksum over its SQL exactly as loadMigrations does.
func mustLocalMigrations(t *testing.T, versions []int64, names []string, sqls []string) []migration {
	t.Helper()
	if len(versions) != len(names) || len(names) != len(sqls) {
		t.Fatalf("mismatched helper inputs: %d versions, %d names, %d sqls", len(versions), len(names), len(sqls))
	}
	migs := make([]migration, len(versions))
	for i := range versions {
		migs[i] = migration{
			version:  versions[i],
			filename: fmt.Sprintf("%06d_%s.sql", versions[i], names[i]),
			name:     names[i],
			sql:      []byte(sqls[i]),
			checksum: sha256.Sum256([]byte(sqls[i])),
		}
	}
	return migs
}

func appliedRow(version int64, name string, checksum []byte) appliedMigration {
	return appliedMigration{version: version, name: name, checksum: checksum}
}

func TestValidateAppliedPrefixEmpty(t *testing.T) {
	local := mustLocalMigrations(t, []int64{1, 2, 3}, []string{"a", "b", "c"}, []string{"s1", "s2", "s3"})
	if err := validateAppliedPrefix(local, nil); err != nil {
		t.Fatalf("empty applied prefix must be valid (everything pending), got %v", err)
	}
}

func TestValidateAppliedPrefixPartial(t *testing.T) {
	local := mustLocalMigrations(t, []int64{1, 2, 3}, []string{"a", "b", "c"}, []string{"s1", "s2", "s3"})
	applied := []appliedMigration{
		appliedRow(1, "a", local[0].checksum[:]),
		appliedRow(2, "b", local[1].checksum[:]),
	}
	if err := validateAppliedPrefix(local, applied); err != nil {
		t.Fatalf("partial applied prefix must be valid, got %v", err)
	}
}

func TestValidateAppliedPrefixFull(t *testing.T) {
	local := mustLocalMigrations(t, []int64{1, 2, 3}, []string{"a", "b", "c"}, []string{"s1", "s2", "s3"})
	applied := []appliedMigration{
		appliedRow(1, "a", local[0].checksum[:]),
		appliedRow(2, "b", local[1].checksum[:]),
		appliedRow(3, "c", local[2].checksum[:]),
	}
	if err := validateAppliedPrefix(local, applied); err != nil {
		t.Fatalf("full applied prefix must be valid (second run is a no-op), got %v", err)
	}
}

func TestValidateAppliedPrefixUnknownVersion(t *testing.T) {
	// The database recorded version 3 but the local set stops at version 2.
	local := mustLocalMigrations(t, []int64{1, 2}, []string{"a", "b"}, []string{"s1", "s2"})
	applied := []appliedMigration{
		appliedRow(1, "a", local[0].checksum[:]),
		appliedRow(2, "b", local[1].checksum[:]),
		appliedRow(3, "c", local[1].checksum[:]),
	}
	err := validateAppliedPrefix(local, applied)
	if err == nil {
		t.Fatal("an applied version with no local definition must be rejected")
	}
	if !strings.Contains(err.Error(), "has no local migration definition") {
		t.Errorf("error = %q, want it to mention the missing local definition", err)
	}
}

func TestValidateAppliedPrefixGap(t *testing.T) {
	// Version 2 was never applied: applied rows are [1,3] but local is [1,2,3].
	local := mustLocalMigrations(t, []int64{1, 2, 3}, []string{"a", "b", "c"}, []string{"s1", "s2", "s3"})
	applied := []appliedMigration{
		appliedRow(1, "a", local[0].checksum[:]),
		appliedRow(3, "c", local[2].checksum[:]),
	}
	err := validateAppliedPrefix(local, applied)
	if err == nil {
		t.Fatal("a gap in the applied versions must be rejected")
	}
	if !strings.Contains(err.Error(), "must be an exact prefix") {
		t.Errorf("error = %q, want it to mention the exact-prefix requirement", err)
	}
}

func TestValidateAppliedPrefixOrder(t *testing.T) {
	// Defensive: rows come from ORDER BY version, but the helper must still
	// fail closed on duplicate/non-increasing versions.
	local := mustLocalMigrations(t, []int64{1, 2, 3}, []string{"a", "b", "c"}, []string{"s1", "s2", "s3"})
	applied := []appliedMigration{
		appliedRow(1, "a", local[0].checksum[:]),
		appliedRow(1, "a", local[0].checksum[:]),
	}
	err := validateAppliedPrefix(local, applied)
	if err == nil {
		t.Fatal("non-strictly-increasing applied versions must be rejected")
	}
	if !strings.Contains(err.Error(), "strictly increasing") {
		t.Errorf("error = %q, want it to mention strictly increasing versions", err)
	}
}

func TestValidateAppliedPrefixNameDrift(t *testing.T) {
	local := mustLocalMigrations(t, []int64{1}, []string{"create_users"}, []string{"s1"})
	applied := []appliedMigration{
		appliedRow(1, "rename_users", local[0].checksum[:]),
	}
	err := validateAppliedPrefix(local, applied)
	if err == nil {
		t.Fatal("a recorded name differing from the local name must be rejected")
	}
	if !strings.Contains(err.Error(), "has name") {
		t.Errorf("error = %q, want it to report the name mismatch", err)
	}
}

func TestValidateAppliedPrefixChecksumLength(t *testing.T) {
	local := mustLocalMigrations(t, []int64{1}, []string{"a"}, []string{"s1"})
	applied := []appliedMigration{
		appliedRow(1, "a", []byte("too-short")),
	}
	err := validateAppliedPrefix(local, applied)
	if err == nil {
		t.Fatal("a recorded checksum that is not 32 bytes must be rejected")
	}
	if !strings.Contains(err.Error(), "checksum has length") {
		t.Errorf("error = %q, want it to report the checksum length", err)
	}
}

func TestValidateAppliedPrefixChecksumDrift(t *testing.T) {
	local := mustLocalMigrations(t, []int64{1}, []string{"a"}, []string{"s1"})
	var recorded [32]byte
	recorded[0] = 0xAB // recorded database checksum differs from the local file checksum

	err := validateAppliedPrefix(local, []appliedMigration{
		appliedRow(1, "a", recorded[:]),
	})
	if err == nil {
		t.Fatal("checksum drift must be rejected")
	}
	if !errors.Is(err, ErrMigrationChecksumDrift) {
		t.Fatalf("checksum drift must match ErrMigrationChecksumDrift via errors.Is, got %v", err)
	}
	var typed *MigrationChecksumDriftError
	if !errors.As(err, &typed) {
		t.Fatalf("checksum drift must be recoverable via errors.As, got %v", err)
	}
	if typed.Version != 1 {
		t.Errorf("typed.Version = %d, want 1", typed.Version)
	}
	if typed.Expected != recorded {
		t.Errorf("typed.Expected = %x, want the recorded database checksum %x", typed.Expected, recorded)
	}
	if typed.Actual != local[0].checksum {
		t.Errorf("typed.Actual = %x, want the local file checksum %x", typed.Actual, local[0].checksum)
	}
}
