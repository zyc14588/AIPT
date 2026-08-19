// Package postgres contains the pure, database-free definition layer for
// PostgreSQL storage: parsing, validating, ordering, and checksumming the SQL
// migration files under migrations/.
//
// The package deliberately contains no database access: no pgx or
// database/sql imports, no embed directives, no filesystem writes, and no
// down/force/repair API. loadMigrations is a pure function from an fs.FS to
// validated migration definitions, reading only the migrations/ directory and
// failing closed on anything unexpected.
package postgres

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

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
