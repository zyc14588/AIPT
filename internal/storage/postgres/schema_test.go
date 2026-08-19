package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ledgerMigrationChecksumHex is the pinned SHA-256 of the exact bytes of
// migrations/000001_ledger.sql as embedded in the binary. Any accepted change
// to the frozen migration file must update this constant in the same change.
const ledgerMigrationChecksumHex = "b050cbce44a6f38f02390cf2728f32d7c094bb4a1a03dc640e42c4c360149fb6"

// ---- embedded migration inventory and checksum ----

func mustEmbeddedMigrationBytes(t *testing.T) []byte {
	t.Helper()
	body, err := fs.ReadFile(migrationsFS, "migrations/000001_ledger.sql")
	if err != nil {
		t.Fatalf("read embedded migrations/000001_ledger.sql: %v", err)
	}
	return body
}

func mustEmbeddedMigrationSQL(t *testing.T) string {
	t.Helper()
	return string(mustEmbeddedMigrationBytes(t))
}

func TestSchemaEmbeddedMigrationsExactInventory(t *testing.T) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		t.Fatalf("fs.ReadDir(migrationsFS, migrations): %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("embedded migrations directory has %d entries, want exactly 1", len(entries))
	}
	entry := entries[0]
	if entry.Name() != "000001_ledger.sql" {
		t.Errorf("embedded migration = %q, want 000001_ledger.sql", entry.Name())
	}
	if entry.IsDir() {
		t.Error("embedded migration entry must be a file, not a directory")
	}
}

func TestSchemaEmbeddedMigrationsLoadAndChecksum(t *testing.T) {
	migs, err := loadMigrations(migrationsFS)
	if err != nil {
		t.Fatalf("loadMigrations(migrationsFS): %v", err)
	}
	if len(migs) != 1 {
		t.Fatalf("loadMigrations returned %d migrations, want 1", len(migs))
	}
	m := migs[0]
	if m.version != 1 {
		t.Errorf("migration version = %d, want 1", m.version)
	}
	if m.filename != "000001_ledger.sql" {
		t.Errorf("migration filename = %q, want 000001_ledger.sql", m.filename)
	}
	if m.name != "ledger" {
		t.Errorf("migration name = %q, want ledger", m.name)
	}

	body := mustEmbeddedMigrationBytes(t)
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != ledgerMigrationChecksumHex {
		t.Errorf("migrations/000001_ledger.sql checksum = %x, want pinned %s", sum, ledgerMigrationChecksumHex)
	}
	if m.checksum != sum {
		t.Errorf("loaded checksum %x must equal the SHA-256 of the embedded bytes %x", m.checksum, sum)
	}
}

// ---- normalized SQL structure: immune to column-alignment whitespace ----

// normalizeSQL strips SQL comments, collapses every run of whitespace to a
// single space, and spaces out parentheses and commas, so layout assertions
// never depend on column-alignment whitespace or on whether the source wrote
// "(" or "( ". Keyword case is preserved; use strings.ToLower for
// case-insensitive assertions.
func normalizeSQL(t *testing.T, sql string) string {
	t.Helper()
	var out strings.Builder
	inLineComment := false
	inBlockComment := false
	prevSpace := true
	for i := 0; i < len(sql); {
		if inLineComment {
			if sql[i] == '\n' {
				inLineComment = false
			}
			i++
			continue
		}
		if inBlockComment {
			if i+1 < len(sql) && sql[i] == '*' && sql[i+1] == '/' {
				inBlockComment = false
				i += 2
				continue
			}
			i++
			continue
		}
		if i+1 < len(sql) && sql[i] == '-' && sql[i+1] == '-' {
			inLineComment = true
			i += 2
			continue
		}
		if i+1 < len(sql) && sql[i] == '/' && sql[i+1] == '*' {
			inBlockComment = true
			i += 2
			continue
		}
		if isSQLSpace(sql[i]) {
			if !prevSpace {
				out.WriteByte(' ')
			}
			prevSpace = true
			i++
			continue
		}
		out.WriteByte(sql[i])
		prevSpace = false
		i++
	}

	// Second pass: space out parentheses and commas so "(x" and "( x" both
	// normalize to "( x", and "a,b" and "a, b" both normalize to "a , b".
	// A ')' is never followed by a space so "::" casts stay attached.
	var spaced strings.Builder
	prev := byte(0)
	compact := strings.TrimSpace(out.String())
	for i := 0; i < len(compact); i++ {
		c := compact[i]
		switch c {
		case '(':
			if prev != 0 && prev != ' ' && prev != '(' {
				spaced.WriteByte(' ')
			}
			spaced.WriteByte(c)
			spaced.WriteByte(' ')
		case ')':
			if prev != 0 && prev != ' ' && prev != '(' {
				spaced.WriteByte(' ')
			}
			spaced.WriteByte(c)
		case ',':
			if prev != 0 && prev != ' ' {
				spaced.WriteByte(' ')
			}
			spaced.WriteByte(c)
			spaced.WriteByte(' ')
		default:
			spaced.WriteByte(c)
		}
		prev = c
	}
	return strings.Join(strings.Fields(spaced.String()), " ")
}

func isSQLSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

// TestSchemaMigrationNormalizedStructure asserts every table, column,
// constraint, function, and trigger of the frozen ledger contract on the
// comment-stripped, whitespace-normalized SQL.
func TestSchemaMigrationNormalizedStructure(t *testing.T) {
	norm := normalizeSQL(t, mustEmbeddedMigrationSQL(t))
	lower := strings.ToLower(norm)

	wants := []string{
		// --- ledger_streams columns and constraints ---
		"create table aipt.ledger_streams (",
		"stream_id text primary key check ( stream_id <> '' )",
		"last_sequence bigint not null default 0 check ( last_sequence >= 0 )",
		"last_event_hash bytea check ( last_event_hash is null or octet_length ( last_event_hash ) = 32 )",
		"created_at timestamptz not null default now ( )",
		"constraint ledger_streams_cursor_invariant check ( ( last_sequence = 0 and last_event_hash is null ) or ( last_sequence > 0 and last_event_hash is not null ) )",
		// --- ledger_events columns ---
		"create table aipt.ledger_events (",
		"stream_id text not null check ( stream_id <> '' )",
		"sequence bigint not null check ( sequence > 0 )",
		"event_id text not null check ( event_id <> '' )",
		"event_type text not null check ( event_type <> '' )",
		"payload_canonical bytea not null check ( octet_length ( payload_canonical ) > 0 )",
		"payload_sha256 bytea not null check ( octet_length ( payload_sha256 ) = 32 )",
		"prev_event_hash bytea check ( prev_event_hash is null or octet_length ( prev_event_hash ) = 32 )",
		"event_hash bytea not null check ( octet_length ( event_hash ) = 32 )",
		"committed_at timestamptz not null default now ( )",
		// --- ledger_events constraints ---
		"constraint ledger_events_pkey primary key ( stream_id , sequence )",
		"constraint ledger_events_event_id_key unique ( event_id )",
		"constraint ledger_events_stream_fkey foreign key ( stream_id ) references aipt.ledger_streams ( stream_id ) on delete restrict on update restrict",
		"constraint ledger_events_chain_invariant check ( ( sequence = 1 and prev_event_hash is null ) or ( sequence > 1 and prev_event_hash is not null ) )",
		"constraint ledger_events_payload_sha256_check check ( payload_sha256 = sha256 ( payload_canonical ) )",
		"constraint ledger_events_event_hash_check check ( event_hash = aipt.ledger_event_hash_v1 ( stream_id , sequence , event_id , event_type , payload_sha256 , prev_event_hash ) )",
		// --- versioned hash function ---
		"create function aipt.ledger_event_hash_v1 ( p_stream_id text , p_sequence bigint , p_event_id text , p_event_type text , p_payload_sha256 bytea , p_prev_event_hash bytea ) returns bytea",
		"language sql immutable parallel safe return sha256 (",
		// --- append-only statement trigger ---
		"create function aipt.ledger_events_append_only ( ) returns trigger",
		"raise exception 'aipt_ledger_append_only' using errcode = '55000'",
		"create trigger ledger_events_append_only before update or delete or truncate on aipt.ledger_events for each statement execute function aipt.ledger_events_append_only ( )",
	}
	for _, want := range wants {
		if !strings.Contains(lower, want) {
			t.Errorf("normalized migration SQL must contain %q", want)
		}
	}

	// Exact object inventory: two functions, two tables, exactly one trigger.
	for what, want := range map[string]int{
		"create function":    2,
		"create table":       2,
		"create trigger":     1,
		"for each statement": 1,
	} {
		if got := strings.Count(lower, what); got != want {
			t.Errorf("migration SQL has %d %q occurrences, want %d", got, what, want)
		}
	}
}

// TestSchemaMigrationEventHashLayout pins that aipt.ledger_event_hash_v1
// builds exactly the hash.go preimage: four 4-byte big-endian length-prefixed
// UTF-8 fields, an 8-byte big-endian positive signed BIGINT sequence, the raw
// payload SHA-256, and the 0x00/0x01 previous-hash marker -- with committed_at
// excluded.
func TestSchemaMigrationEventHashLayout(t *testing.T) {
	norm := normalizeSQL(t, mustEmbeddedMigrationSQL(t))
	lower := strings.ToLower(norm)

	// The domain literal in the SQL must be the same literal hash.go pins.
	domainLiteral := "'" + strings.ToLower(HashDomain) + "'"
	if !strings.Contains(lower, "convert_to ( "+domainLiteral+" , 'utf8' )") {
		t.Errorf("normalized migration SQL must convert the domain literal %s to UTF8", domainLiteral)
	}

	// The preimage pieces must appear in the exact documented layout order.
	order := []string{
		"octet_length ( convert_to ( 'aipt_ledger_v1' , 'utf8' ) )::int4::bytea",
		"octet_length ( convert_to ( p_stream_id , 'utf8' ) )::int4::bytea",
		"p_sequence::int8::bytea",
		"octet_length ( convert_to ( p_event_id , 'utf8' ) )::int4::bytea",
		"octet_length ( convert_to ( p_event_type , 'utf8' ) )::int4::bytea",
		"|| p_payload_sha256 ||",
		"case when p_prev_event_hash is null",
	}
	last := -1
	for _, piece := range order {
		idx := strings.Index(lower, piece)
		if idx < 0 {
			t.Errorf("normalized migration SQL must contain preimage piece %q", piece)
			continue
		}
		if idx <= last {
			t.Errorf("preimage piece %q appears out of layout order", piece)
		}
		last = idx
	}

	// The RETURN expression spans from "return sha256 (" to the first ");",
	// which ends the function statement; the function is the first object in
	// the file, so the first ");" belongs to it.
	start := strings.Index(lower, "return sha256 (")
	if start < 0 {
		t.Fatal("normalized migration SQL must contain a sha256 RETURN expression")
	}
	relEnd := strings.Index(lower[start:], ");")
	if relEnd < 0 {
		t.Fatal("sha256 RETURN expression must end with );")
	}
	body := lower[start : start+relEnd]

	// Exactly four 4-byte big-endian length prefixes and one 8-byte sequence.
	if got := strings.Count(body, "::int4::bytea"); got != 4 {
		t.Errorf("preimage must use exactly 4 int4-to-bytea length prefixes, got %d", got)
	}
	if got := strings.Count(body, "::int8::bytea"); got != 1 {
		t.Errorf("preimage must use exactly 1 int8-to-bytea sequence encoding, got %d", got)
	}
	if strings.Contains(body, "committed_at") {
		t.Error("the event-hash preimage must exclude committed_at")
	}
}

// TestSchemaMigrationAbsenceOfForbiddenMachinery asserts the migration has no
// cursor-maintenance insert trigger, no row trigger, no AFTER trigger, no
// GREATEST-based cursor advance, and nothing that mutates ledger_streams.
func TestSchemaMigrationAbsenceOfForbiddenMachinery(t *testing.T) {
	norm := normalizeSQL(t, mustEmbeddedMigrationSQL(t))
	lower := strings.ToLower(norm)

	for _, forbidden := range []string{
		// No AFTER triggers and no row triggers of any kind.
		"after insert", "after update", "after delete", "after truncate", "for each row",
		// No GREATEST-based cursor advance.
		"greatest",
		// No send-function encodings and no extension (no pgcrypto digest).
		"int4send", "int8send", "create extension", "pgcrypto", "digest(",
		// No DML anywhere: the migration only defines objects.
		"insert into aipt.ledger_streams", "insert into aipt.ledger_events",
		"update aipt.ledger_streams", "update ledger_streams",
		"delete from aipt.ledger_streams", "delete from aipt.ledger_events",
		"truncate aipt.ledger_streams", "truncate table aipt.ledger_streams",
		// Every object is schema-qualified to aipt.
		"create table ledger_streams", "create table ledger_events",
		"create function ledger_event_hash_v1", "create function ledger_events_append_only",
	} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("migration SQL must not contain %q", forbidden)
		}
	}
}

// TestSchemaMigrationCommentsUseSignedInt64Semantics pins that the comments
// describe the cursor fields with positive signed int64/BIGINT semantics.
func TestSchemaMigrationCommentsUseSignedInt64Semantics(t *testing.T) {
	raw := mustEmbeddedMigrationSQL(t)
	for _, want := range []string{
		"signed BIGINT (int64)",
		"positive signed BIGINT",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("migration comments must describe the cursor fields with %q semantics", want)
		}
	}
}

// ---- MigrateUp delegation ----

// TestMigrateUpDelegatesToMigrateUpFS proves MigrateUp forwards to migrateUpFS
// with the embedded migrations filesystem: with a nil pool it must fail with
// migrateUpFS's nil-pool rejection before any database access, with no other
// error wrapping.
func TestMigrateUpDelegatesToMigrateUpFS(t *testing.T) {
	var pool *pgxpool.Pool // nil: rejected before any database access
	err := MigrateUp(context.Background(), pool)
	if err == nil {
		t.Fatal("MigrateUp with a nil *pgxpool.Pool must fail before any database access")
	}
	if !strings.Contains(err.Error(), "nil *pgxpool.Pool") {
		t.Errorf("MigrateUp error = %q, want the migrateUpFS nil-pool rejection", err)
	}
}
