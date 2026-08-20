// Database-free tests for the PostgreSQL Append path. The append transaction
// body (appendLedgerEvent) runs against the minimal ledgerTx surface, so a
// scripted fake exercises the complete cursor/tail/hash transaction without a
// database, while Append's input validation is proven to run before any pool
// access by passing a nil *pgxpool.Pool. There is no mock/test dependency.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// testCommittedAt is the fixed database-generated commit timestamp the fake
// returns through INSERT ... RETURNING committed_at. Append never uses
// time.Now, so every test can assert the exact value.
var testCommittedAt = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

// fillHash builds a 32-byte hash filled with the given byte value.
func fillHash(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// ledgerTestInput returns a valid append input whose raw payload is
// `{"b":1,"a":[3,1,2],"c":"x"}`, which canonicalizes exactly to
// `{"a":[3,1,2],"b":1,"c":"x"}`.
func ledgerTestInput() AppendInput {
	return AppendInput{
		StreamID:    "game-events",
		EventID:     "evt-0001",
		EventType:   "ledger.appended",
		PayloadJSON: []byte(`{"b":1,"a":[3,1,2],"c":"x"}`),
	}
}

// ledgerTestCanonical is the exact canonicalization of ledgerTestInput's
// payload, as returned by internal/protocol.CanonicalJSON.
const ledgerTestCanonical = `{"a":[3,1,2],"b":1,"c":"x"}`

// ---- scripted ledgerTx fake ----

// fakeRow is a scripted pgx.Row whose Scan writes the configured values into
// the destination pointers or returns the configured error.
type fakeRow struct {
	values []any
	err    error
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(r.values) != len(dest) {
		return fmt.Errorf("fakeRow: Scan got %d destinations, want %d values", len(dest), len(r.values))
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *int64:
			v, ok := r.values[i].(int64)
			if !ok {
				return fmt.Errorf("fakeRow: value %d is %T, want int64", i, r.values[i])
			}
			*d = v
		case *[]byte:
			v, ok := r.values[i].([]byte)
			if !ok {
				return fmt.Errorf("fakeRow: value %d is %T, want []byte", i, r.values[i])
			}
			*d = v
		case *time.Time:
			v, ok := r.values[i].(time.Time)
			if !ok {
				return fmt.Errorf("fakeRow: value %d is %T, want time.Time", i, r.values[i])
			}
			*d = v
		default:
			return fmt.Errorf("fakeRow: unsupported scan destination %T", dest[i])
		}
	}
	return nil
}

type execCall struct {
	sql  string
	args []any
}

type queryRowCall struct {
	sql  string
	args []any
}

// fakeTx is a scripted ledgerTx recording every call so tests can assert the
// exact SQL, arguments, and lifecycle of the append transaction. By default
// the stream is empty: the cursor is (0, NULL) and the tail query reports
// pgx.ErrNoRows.
type fakeTx struct {
	// Programmable results.
	cursorSeq  int64
	cursorHash []byte
	cursorErr  error

	tailSeq  int64
	tailHash []byte
	tailErr  error

	committedAt time.Time
	insertErr   error

	upsertErr          error
	updateErr          error
	updateRowsAffected int64

	commitErr error

	// Recorded calls.
	execs         []execCall
	queryRows     []queryRowCall
	commitCalled  bool
	rollbackCalls int
}

func newFakeTx() *fakeTx {
	return &fakeTx{tailErr: pgx.ErrNoRows, updateRowsAffected: 1}
}

func (f *fakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, execCall{sql: sql, args: args})
	switch {
	case strings.Contains(sql, "INSERT INTO aipt.ledger_streams"):
		if f.upsertErr != nil {
			return pgconn.CommandTag{}, f.upsertErr
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case strings.Contains(sql, "UPDATE aipt.ledger_streams"):
		if f.updateErr != nil {
			return pgconn.CommandTag{}, f.updateErr
		}
		return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", f.updateRowsAffected)), nil
	default:
		return pgconn.CommandTag{}, fmt.Errorf("fakeTx: unexpected Exec SQL %q", sql)
	}
}

func (f *fakeTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	f.queryRows = append(f.queryRows, queryRowCall{sql: sql, args: args})
	switch {
	case strings.Contains(sql, "FOR UPDATE"):
		return &fakeRow{values: []any{f.cursorSeq, f.cursorHash}, err: f.cursorErr}
	case strings.Contains(sql, "ORDER BY sequence DESC"):
		return &fakeRow{values: []any{f.tailSeq, f.tailHash}, err: f.tailErr}
	case strings.Contains(sql, "RETURNING committed_at"):
		return &fakeRow{values: []any{f.committedAt}, err: f.insertErr}
	default:
		return &fakeRow{err: fmt.Errorf("fakeTx: unexpected QueryRow SQL %q", sql)}
	}
}

func (f *fakeTx) Commit(ctx context.Context) error {
	f.commitCalled = true
	return f.commitErr
}

func (f *fakeTx) Rollback(ctx context.Context) error {
	f.rollbackCalls++
	return nil
}

// mustPrepare canonicalizes the ledger test input and fails the test on error.
func mustPrepare(t *testing.T) (AppendInput, string, [32]byte) {
	t.Helper()
	in := ledgerTestInput()
	canonical, payloadHash, err := prepareAppendInput(in)
	if err != nil {
		t.Fatalf("prepareAppendInput: %v", err)
	}
	return in, canonical, payloadHash
}

// ---- input validation before any pool access ----

func TestAppendPrepareInputCanonicalizationAndDigest(t *testing.T) {
	in, canonical, payloadHash := mustPrepare(t)

	if canonical != ledgerTestCanonical {
		t.Errorf("canonical = %q, want %q", canonical, ledgerTestCanonical)
	}
	// The payload digest must be the SHA-256 of the exact canonical string.
	if want := sha256.Sum256([]byte(canonical)); payloadHash != want {
		t.Errorf("payloadHash = %x, want sha256(canonical) %x", payloadHash, want)
	}

	// The exact returned string must be byte-identical to the protocol package
	// and to its documented hex digest oracle.
	wantCanonical, err := protocol.CanonicalJSON(in.PayloadJSON)
	if err != nil {
		t.Fatalf("protocol.CanonicalJSON: %v", err)
	}
	if canonical != wantCanonical {
		t.Errorf("canonical must equal protocol.CanonicalJSON output, got %q want %q", canonical, wantCanonical)
	}
	wantDigest, err := protocol.CanonicalSHA256(in.PayloadJSON)
	if err != nil {
		t.Fatalf("protocol.CanonicalSHA256: %v", err)
	}
	if got := fmt.Sprintf("%x", payloadHash); got != wantDigest {
		t.Errorf("payloadHash hex = %s, want protocol.CanonicalSHA256 %s", got, wantDigest)
	}

	// Whitespace, key sorting, and number normalization are the protocol
	// package's exact output for every input.
	for _, tc := range []struct{ raw, want string }{
		{`{ "z" : 1 , "a" : 2 }`, `{"a":2,"z":1}`},
		{`[ 1 , 2 , 3 ]`, `[1,2,3]`},
		{`{"s":"x\n\u0001"}`, `{"s":"x\n\u0001"}`},
		{`{"n":1.50}`, `{"n":1.5}`},
		{`{"b":false,"n":null,"t":true}`, `{"b":false,"n":null,"t":true}`},
	} {
		got, _, err := prepareAppendInput(AppendInput{
			StreamID:    "s",
			EventID:     "e",
			EventType:   "t",
			PayloadJSON: []byte(tc.raw),
		})
		if err != nil {
			t.Errorf("prepareAppendInput(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("prepareAppendInput(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestAppendRejectsBadPayloadBeforeNilPool proves strict canonicalization runs
// before any pool or transaction access: every rejected payload returns the
// protocol package's typed reason even for a nil pool, never the nil-pool
// error.
func TestAppendRejectsBadPayloadBeforeNilPool(t *testing.T) {
	var pool *pgxpool.Pool // nil: any database access would fail here
	cases := []struct {
		name   string
		raw    string
		reason string
	}{
		{"malformed", `{"a":`, protocol.ReasonJSONMalformed},
		{"empty input", ``, protocol.ReasonJSONMalformed},
		{"trailing input", `{"a":1} extra`, protocol.ReasonJSONTrailing},
		{"duplicate key", `{"a":1,"a":2}`, protocol.ReasonJSONDuplicateKey},
		{"unsafe integer", `{"n":9007199254740993}`, protocol.ReasonJSONUnsafeInteger},
		{"negative zero", `{"n":-0}`, protocol.ReasonJSONNegativeZero},
		{"non-finite number", `{"n":1e400}`, protocol.ReasonJSONNonFiniteNumber},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ledgerTestInput()
			in.PayloadJSON = []byte(tc.raw)
			ev, err := Append(context.Background(), pool, in)
			if err == nil {
				t.Fatal("invalid payload must be rejected before any pool access")
			}
			if ev != (LedgerEvent{}) {
				t.Errorf("rejected append must return the zero event, got %+v", ev)
			}
			if reason := protocol.ContractReason(err); reason != tc.reason {
				t.Errorf("reason = %q, want %q (err = %v)", reason, tc.reason, err)
			}
			if strings.Contains(err.Error(), "nil *pgxpool.Pool") {
				t.Errorf("payload rejection must precede the nil-pool check, got %v", err)
			}
		})
	}
}

// TestAppendRejectsInvalidIdentifiersBeforeNilPool proves identifier validation
// runs before any pool or transaction access: empty and non-UTF-8 identifiers
// are rejected with the hash chain's typed input error even for a nil pool.
func TestAppendRejectsInvalidIdentifiersBeforeNilPool(t *testing.T) {
	var pool *pgxpool.Pool // nil: any database access would fail here
	cases := []struct {
		name  string
		field string
		value string
	}{
		{"empty stream_id", "stream_id", ""},
		{"empty event_id", "event_id", ""},
		{"empty event_type", "event_type", ""},
		{"non-UTF8 stream_id", "stream_id", "\xff\xfe"},
		{"non-UTF8 event_id", "event_id", "\xff\xfe"},
		{"non-UTF8 event_type", "event_type", "\xff\xfe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ledgerTestInput()
			switch tc.field {
			case "stream_id":
				in.StreamID = tc.value
			case "event_id":
				in.EventID = tc.value
			case "event_type":
				in.EventType = tc.value
			}
			_, err := Append(context.Background(), pool, in)
			if err == nil {
				t.Fatal("invalid identifier must be rejected before any pool access")
			}
			if !errors.Is(err, ErrInvalidLedgerHashInput) {
				t.Errorf("error = %v, want errors.Is(ErrInvalidLedgerHashInput)", err)
			}
			var typed *LedgerHashInputError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.Field != tc.field {
				t.Errorf("typed.Field = %q, want %q", typed.Field, tc.field)
			}
			if strings.Contains(err.Error(), "nil *pgxpool.Pool") {
				t.Errorf("identifier rejection must precede the nil-pool check, got %v", err)
			}
		})
	}
}

func TestAppendNilPoolRejected(t *testing.T) {
	var pool *pgxpool.Pool
	_, err := Append(context.Background(), pool, ledgerTestInput())
	if err == nil {
		t.Fatal("valid append with a nil *pgxpool.Pool must be rejected")
	}
	if !strings.Contains(err.Error(), "nil *pgxpool.Pool") {
		t.Errorf("error = %q, want it to mention the nil pool", err)
	}
}

// ---- append transaction body: empty and matching cursor-tail states ----

// TestAppendLedgerEventGenesis drives the full genesis append: empty cursor
// (0, NULL), no tail, sequence 1, no previous hash, and the exact statement
// sequence with the exact arguments.
func TestAppendLedgerEventGenesis(t *testing.T) {
	f := newFakeTx()
	f.committedAt = testCommittedAt

	in, canonical, payloadHash := mustPrepare(t)
	ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
	if err != nil {
		t.Fatalf("appendLedgerEvent: %v", err)
	}

	if ev.StreamID != in.StreamID || ev.EventID != in.EventID || ev.EventType != in.EventType {
		t.Errorf("event identifiers = (%q,%q,%q), want (%q,%q,%q)",
			ev.StreamID, ev.EventID, ev.EventType, in.StreamID, in.EventID, in.EventType)
	}
	if ev.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", ev.Sequence)
	}
	if ev.PrevEventHash != nil {
		t.Errorf("genesis PrevEventHash = %x, want nil", ev.PrevEventHash)
	}
	if ev.PayloadCanonical != canonical {
		t.Errorf("PayloadCanonical = %q, want %q", ev.PayloadCanonical, canonical)
	}
	if ev.PayloadHash != payloadHash {
		t.Errorf("PayloadHash = %x, want %x", ev.PayloadHash, payloadHash)
	}
	wantEventHash, err := hashLedgerBlock(ledgerHashInput{
		StreamID:    in.StreamID,
		Sequence:    1,
		EventID:     in.EventID,
		EventType:   in.EventType,
		PayloadHash: payloadHash,
	})
	if err != nil {
		t.Fatalf("hashLedgerBlock: %v", err)
	}
	if ev.EventHash != wantEventHash {
		t.Errorf("EventHash = %x, want versioned hash %x", ev.EventHash, wantEventHash)
	}
	if !ev.CommittedAt.Equal(testCommittedAt) {
		t.Errorf("CommittedAt = %v, want the database-returned %v", ev.CommittedAt, testCommittedAt)
	}

	// Exact statement sequence: stream upsert, then FOR UPDATE cursor read,
	// then tail query, then INSERT RETURNING, then guarded cursor update.
	if len(f.execs) != 2 {
		t.Fatalf("Exec calls = %d, want 2 (upsert + guarded update)", len(f.execs))
	}
	if !strings.Contains(f.execs[0].sql, "ON CONFLICT DO NOTHING") {
		t.Errorf("first Exec must be the stream upsert, got %q", f.execs[0].sql)
	}
	if len(f.queryRows) != 3 {
		t.Fatalf("QueryRow calls = %d, want 3 (cursor + tail + insert)", len(f.queryRows))
	}
	if !strings.Contains(f.queryRows[0].sql, "FOR UPDATE") {
		t.Errorf("first QueryRow must lock the cursor, got %q", f.queryRows[0].sql)
	}
	if !strings.Contains(f.queryRows[1].sql, "ORDER BY sequence DESC") {
		t.Errorf("second QueryRow must query the tail, got %q", f.queryRows[1].sql)
	}

	// The INSERT carries the exact committed data: stream, sequence, event
	// identifiers, canonical payload, payload hash, NULL previous hash, and the
	// computed event hash.
	ins := f.queryRows[2]
	if !strings.Contains(ins.sql, "RETURNING committed_at") {
		t.Errorf("third QueryRow must be the INSERT RETURNING committed_at, got %q", ins.sql)
	}
	if len(ins.args) != 8 {
		t.Fatalf("INSERT args = %d, want 8", len(ins.args))
	}
	if ins.args[0] != in.StreamID || ins.args[2] != in.EventID || ins.args[3] != in.EventType {
		t.Errorf("INSERT identifier args = (%v,%v,%v), want (%q,%q,%q)", ins.args[0], ins.args[2], ins.args[3], in.StreamID, in.EventID, in.EventType)
	}
	if ins.args[1] != int64(1) {
		t.Errorf("INSERT sequence arg = %v, want 1", ins.args[1])
	}
	if ins.args[4] != canonical {
		t.Errorf("INSERT canonical arg = %v, want %q", ins.args[4], canonical)
	}
	if !bytes.Equal(ins.args[5].([]byte), payloadHash[:]) {
		t.Errorf("INSERT payload hash arg = %x, want %x", ins.args[5], payloadHash)
	}
	if b, ok := ins.args[6].([]byte); !ok || b != nil {
		t.Errorf("INSERT prev hash arg = %#v, want nil []byte for genesis", ins.args[6])
	}
	if !bytes.Equal(ins.args[7].([]byte), ev.EventHash[:]) {
		t.Errorf("INSERT event hash arg = %x, want %x", ins.args[7], ev.EventHash)
	}

	// The guarded cursor update must move (0, NULL) to (1, event_hash) and
	// re-verify the old cursor values in the WHERE clause.
	upd := f.execs[1]
	if !strings.Contains(upd.sql, "UPDATE aipt.ledger_streams") ||
		!strings.Contains(upd.sql, "IS NOT DISTINCT FROM") {
		t.Errorf("second Exec must be the guarded cursor update, got %q", upd.sql)
	}
	if len(upd.args) != 5 {
		t.Fatalf("UPDATE args = %d, want 5", len(upd.args))
	}
	if upd.args[0] != in.StreamID || upd.args[1] != int64(1) {
		t.Errorf("UPDATE identity args = (%v,%v), want (%q,1)", upd.args[0], upd.args[1], in.StreamID)
	}
	if !bytes.Equal(upd.args[2].([]byte), ev.EventHash[:]) {
		t.Errorf("UPDATE new cursor hash arg = %x, want %x", upd.args[2], ev.EventHash)
	}
	if upd.args[3] != int64(0) {
		t.Errorf("UPDATE old cursor sequence arg = %v, want 0", upd.args[3])
	}
	if b, ok := upd.args[4].([]byte); !ok || b != nil {
		t.Errorf("UPDATE old cursor hash arg = %#v, want nil []byte", upd.args[4])
	}
}

// TestAppendLedgerEventChained drives a chained append whose locked cursor and
// actual tail agree: sequence 8 after a tail of 7, previous hash equal to the
// tail hash, and the guarded update re-verifying both old cursor values.
func TestAppendLedgerEventChained(t *testing.T) {
	f := newFakeTx()
	tailHash := fillHash(0xAB)
	f.cursorSeq = 7
	f.cursorHash = tailHash[:]
	f.tailSeq = 7
	f.tailHash = tailHash[:]
	f.tailErr = nil
	f.committedAt = testCommittedAt

	in, canonical, payloadHash := mustPrepare(t)
	ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
	if err != nil {
		t.Fatalf("appendLedgerEvent: %v", err)
	}

	if ev.Sequence != 8 {
		t.Errorf("Sequence = %d, want 8", ev.Sequence)
	}
	if ev.PrevEventHash == nil {
		t.Fatal("chained append must carry the previous event hash")
	}
	if *ev.PrevEventHash != tailHash {
		t.Errorf("PrevEventHash = %x, want tail hash %x", *ev.PrevEventHash, tailHash)
	}
	wantEventHash, err := hashLedgerBlock(ledgerHashInput{
		StreamID:    in.StreamID,
		Sequence:    8,
		EventID:     in.EventID,
		EventType:   in.EventType,
		PayloadHash: payloadHash,
		PrevHash:    &tailHash,
	})
	if err != nil {
		t.Fatalf("hashLedgerBlock: %v", err)
	}
	if ev.EventHash != wantEventHash {
		t.Errorf("EventHash = %x, want chained versioned hash %x", ev.EventHash, wantEventHash)
	}

	if len(f.queryRows) != 3 || len(f.execs) != 2 {
		t.Fatalf("statement counts: %d QueryRows, %d Execs, want 3 and 2", len(f.queryRows), len(f.execs))
	}
	ins := f.queryRows[2]
	if !bytes.Equal(ins.args[6].([]byte), tailHash[:]) {
		t.Errorf("INSERT prev hash arg = %x, want %x", ins.args[6], tailHash)
	}
	upd := f.execs[1]
	if upd.args[3] != int64(7) {
		t.Errorf("UPDATE old cursor sequence arg = %v, want 7", upd.args[3])
	}
	if !bytes.Equal(upd.args[4].([]byte), tailHash[:]) {
		t.Errorf("UPDATE old cursor hash arg = %x, want %x", upd.args[4], tailHash)
	}
}

// ---- cursor/tail mismatches ----

// TestAppendLedgerEventCursorMismatch covers every cursor/tail disagreement:
// an empty cursor with a tail present, a nonempty cursor with no tail,
// sequence drift, hash drift, and a corrupted cursor (hash without sequence).
// Each must fail closed with the typed AIPT_LEDGER_CURSOR_MISMATCH error
// before any event insert or cursor update.
func TestAppendLedgerEventCursorMismatch(t *testing.T) {
	h1 := fillHash(0x01)
	h2 := fillHash(0x02)
	cases := []struct {
		name string

		cursorSeq  int64
		cursorHash []byte
		tailSeq    int64
		tailHash   []byte
		tailErr    error

		wantCursorSeq   int64
		wantTailSeq     int64
		cursorHashNil   bool
		tailHashNil     bool
		wantTailPresent bool
	}{
		{
			name:      "empty cursor but tail exists",
			cursorSeq: 0, cursorHash: nil,
			tailSeq: 1, tailHash: h1[:], tailErr: nil,
			wantCursorSeq: 0, wantTailSeq: 1,
			cursorHashNil: true, tailHashNil: false, wantTailPresent: true,
		},
		{
			name:      "cursor but no tail",
			cursorSeq: 5, cursorHash: h1[:],
			tailSeq: 0, tailHash: nil, tailErr: pgx.ErrNoRows,
			wantCursorSeq: 5, wantTailSeq: 0,
			cursorHashNil: false, tailHashNil: true, wantTailPresent: false,
		},
		{
			name:      "sequence mismatch",
			cursorSeq: 5, cursorHash: h1[:],
			tailSeq: 6, tailHash: h1[:], tailErr: nil,
			wantCursorSeq: 5, wantTailSeq: 6,
			cursorHashNil: false, tailHashNil: false, wantTailPresent: true,
		},
		{
			name:      "hash mismatch",
			cursorSeq: 5, cursorHash: h1[:],
			tailSeq: 5, tailHash: h2[:], tailErr: nil,
			wantCursorSeq: 5, wantTailSeq: 5,
			cursorHashNil: false, tailHashNil: false, wantTailPresent: true,
		},
		{
			name:      "corrupt cursor hash without sequence",
			cursorSeq: 0, cursorHash: h1[:],
			tailSeq: 0, tailHash: nil, tailErr: pgx.ErrNoRows,
			wantCursorSeq: 0, wantTailSeq: 0,
			cursorHashNil: false, tailHashNil: true, wantTailPresent: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTx()
			f.cursorSeq = tc.cursorSeq
			f.cursorHash = tc.cursorHash
			f.tailSeq = tc.tailSeq
			f.tailHash = tc.tailHash
			f.tailErr = tc.tailErr

			in, canonical, payloadHash := mustPrepare(t)
			ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
			if err == nil {
				t.Fatal("a cursor/tail mismatch must fail closed")
			}
			if ev != (LedgerEvent{}) {
				t.Errorf("failed append must return the zero event, got %+v", ev)
			}
			if !errors.Is(err, ErrLedgerCursorMismatch) {
				t.Fatalf("error = %v, want errors.Is(ErrLedgerCursorMismatch)", err)
			}
			var typed *LedgerCursorMismatchError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.StreamID != in.StreamID {
				t.Errorf("typed.StreamID = %q, want %q", typed.StreamID, in.StreamID)
			}
			if typed.CursorSequence != tc.wantCursorSeq {
				t.Errorf("typed.CursorSequence = %d, want %d", typed.CursorSequence, tc.wantCursorSeq)
			}
			if typed.TailSequence != tc.wantTailSeq {
				t.Errorf("typed.TailSequence = %d, want %d", typed.TailSequence, tc.wantTailSeq)
			}
			if (typed.CursorHash == nil) != tc.cursorHashNil {
				t.Errorf("typed.CursorHash nil = %t, want %t", typed.CursorHash == nil, tc.cursorHashNil)
			}
			if (typed.TailHash == nil) != tc.tailHashNil {
				t.Errorf("typed.TailHash nil = %t, want %t", typed.TailHash == nil, tc.tailHashNil)
			}
			if typed.TailPresent != tc.wantTailPresent {
				t.Errorf("typed.TailPresent = %t, want %t", typed.TailPresent, tc.wantTailPresent)
			}
			if !strings.Contains(err.Error(), "AIPT_LEDGER_CURSOR_MISMATCH") {
				t.Errorf("error text = %q, want it to embed the stable mismatch code", err)
			}

			// No event insert and no cursor update may run after a mismatch.
			if len(f.queryRows) != 2 {
				t.Errorf("QueryRow calls = %d, want 2 (no INSERT RETURNING after a mismatch)", len(f.queryRows))
			}
			if len(f.execs) != 1 {
				t.Errorf("Exec calls = %d, want 1 (no cursor update after a mismatch)", len(f.execs))
			}
		})
	}
}

// ---- sequence exhaustion ----

// TestAppendLedgerEventSequenceExhausted proves a cursor at math.MaxInt64 with
// a matching tail is rejected with the typed AIPT_LEDGER_SEQUENCE_EXHAUSTED
// error before any event insert or cursor update.
func TestAppendLedgerEventSequenceExhausted(t *testing.T) {
	f := newFakeTx()
	tailHash := fillHash(0xEE)
	f.cursorSeq = math.MaxInt64
	f.cursorHash = tailHash[:]
	f.tailSeq = math.MaxInt64
	f.tailHash = tailHash[:]
	f.tailErr = nil

	in, canonical, payloadHash := mustPrepare(t)
	ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
	if err == nil {
		t.Fatal("sequence exhaustion must be rejected")
	}
	if ev != (LedgerEvent{}) {
		t.Errorf("failed append must return the zero event, got %+v", ev)
	}
	if !errors.Is(err, ErrLedgerSequenceExhausted) {
		t.Fatalf("error = %v, want errors.Is(ErrLedgerSequenceExhausted)", err)
	}
	var typed *LedgerSequenceExhaustedError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != in.StreamID {
		t.Errorf("typed.StreamID = %q, want %q", typed.StreamID, in.StreamID)
	}
	if typed.Sequence != math.MaxInt64 {
		t.Errorf("typed.Sequence = %d, want %d", typed.Sequence, int64(math.MaxInt64))
	}
	if !strings.Contains(err.Error(), "AIPT_LEDGER_SEQUENCE_EXHAUSTED") {
		t.Errorf("error text = %q, want it to embed the stable exhaustion code", err)
	}
	if len(f.queryRows) != 2 {
		t.Errorf("QueryRow calls = %d, want 2 (no INSERT RETURNING after exhaustion)", len(f.queryRows))
	}
	if len(f.execs) != 1 {
		t.Errorf("Exec calls = %d, want 1 (no cursor update after exhaustion)", len(f.execs))
	}
}

// ---- database hash byte-length validation ----

// TestAppendLedgerEventHashLengthRejected proves database hash values are
// validated for the exact 32-byte length and never truncated or padded.
func TestAppendLedgerEventHashLengthRejected(t *testing.T) {
	short := []byte{0x01, 0x02} // 2 bytes: neither NULL nor 32
	good := fillHash(0xAA)
	cases := []struct {
		name string

		cursorSeq  int64
		cursorHash []byte
		tailSeq    int64
		tailHash   []byte
		tailErr    error

		wantText string
	}{
		{
			name:      "cursor hash length",
			cursorSeq: 3, cursorHash: short,
			tailSeq: 0, tailHash: nil, tailErr: pgx.ErrNoRows,
			wantText: "last_event_hash has byte length 2",
		},
		{
			name:      "tail hash length",
			cursorSeq: 3, cursorHash: good[:],
			tailSeq: 3, tailHash: short, tailErr: nil,
			wantText: "tail event_hash has byte length 2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTx()
			f.cursorSeq = tc.cursorSeq
			f.cursorHash = tc.cursorHash
			f.tailSeq = tc.tailSeq
			f.tailHash = tc.tailHash
			f.tailErr = tc.tailErr

			in, canonical, payloadHash := mustPrepare(t)
			_, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
			if err == nil {
				t.Fatal("a malformed database hash length must fail closed")
			}
			if errors.Is(err, ErrLedgerCursorMismatch) {
				t.Errorf("a hash length violation is not a cursor mismatch, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantText)
			}
			if len(f.queryRows) != 2 {
				t.Errorf("QueryRow calls = %d, want 2 (no INSERT RETURNING)", len(f.queryRows))
			}
			if len(f.execs) != 1 {
				t.Errorf("Exec calls = %d, want 1 (no cursor update)", len(f.execs))
			}
		})
	}
}

// ---- guarded cursor update and DB failure rollback ----

// TestAppendLedgerEventGuardedUpdateRequiresOneRow proves the guarded cursor
// update must affect exactly one row; anything else fails closed after the
// event insert, so the cursor never advances.
func TestAppendLedgerEventGuardedUpdateRequiresOneRow(t *testing.T) {
	for _, n := range []int64{0, 2} {
		t.Run(fmt.Sprintf("affected %d", n), func(t *testing.T) {
			f := newFakeTx()
			f.updateRowsAffected = n
			f.committedAt = testCommittedAt

			in, canonical, payloadHash := mustPrepare(t)
			ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
			if err == nil {
				t.Fatal("a cursor update affecting != 1 row must fail closed")
			}
			if ev != (LedgerEvent{}) {
				t.Errorf("failed append must return the zero event, got %+v", ev)
			}
			if !strings.Contains(err.Error(), "exactly 1") {
				t.Errorf("error = %q, want it to require exactly one affected row", err)
			}
			// The event insert ran (3 QueryRows) but the guarded update was
			// rejected, so nothing advanced.
			if len(f.queryRows) != 3 {
				t.Errorf("QueryRow calls = %d, want 3 (INSERT RETURNING ran)", len(f.queryRows))
			}
		})
	}
}

// TestAppendLedgerEventDuplicateEventID preserves the database error (a
// duplicate event_id surfaces as a PostgreSQL unique-violation) and proves no
// cursor update runs after a failed insert.
func TestAppendLedgerEventDuplicateEventID(t *testing.T) {
	f := newFakeTx()
	f.insertErr = &pgconn.PgError{
		Code:    "23505",
		Message: `duplicate key value violates unique constraint "ledger_events_event_id_key"`,
	}

	in, canonical, payloadHash := mustPrepare(t)
	ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
	if err == nil {
		t.Fatal("a duplicate event_id must fail closed")
	}
	if ev != (LedgerEvent{}) {
		t.Errorf("failed append must return the zero event, got %+v", ev)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("error = %v, want the wrapped database error preserved", err)
	}
	if pgErr.Code != "23505" {
		t.Errorf("preserved SQLSTATE = %q, want 23505", pgErr.Code)
	}
	// Only the stream upsert ran; no cursor update may follow a failed insert.
	if len(f.execs) != 1 {
		t.Errorf("Exec calls = %d, want 1 (upsert only; no cursor update after a failed insert)", len(f.execs))
	}
}

// TestAppendLedgerEventDBFailurePreservesCause covers the remaining DB failure
// points (stream upsert, cursor read, tail read, cursor update) and proves
// every wrapped error preserves its cause through errors.Is.
func TestAppendLedgerEventDBFailurePreservesCause(t *testing.T) {
	sentinel := errors.New("injected database failure")
	in, canonical, payloadHash := mustPrepare(t)

	t.Run("upsert", func(t *testing.T) {
		f := newFakeTx()
		f.upsertErr = sentinel
		if _, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash); !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the upsert cause preserved", err)
		}
	})
	t.Run("cursor read", func(t *testing.T) {
		f := newFakeTx()
		f.cursorErr = sentinel
		if _, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash); !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the cursor-read cause preserved", err)
		}
	})
	t.Run("tail read", func(t *testing.T) {
		f := newFakeTx()
		f.tailErr = sentinel
		if _, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash); !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the tail-read cause preserved", err)
		}
	})
	t.Run("cursor update", func(t *testing.T) {
		f := newFakeTx()
		f.updateErr = sentinel
		if _, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash); !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the update cause preserved", err)
		}
	})
}

// ---- defensive returned-value behavior ----

// TestAppendLedgerEventReturnedValuesMatchCommittedData proves the returned
// event is exactly the data committed in the transaction statements, that the
// returned previous hash is an independent copy of the database bytes, and
// that appendLedgerEvent never commits or rolls back (the caller owns the
// transaction lifecycle, so the cursor advances only on a caller commit).
func TestAppendLedgerEventReturnedValuesMatchCommittedData(t *testing.T) {
	f := newFakeTx()
	tailHash := fillHash(0x5A)
	f.cursorSeq = 2
	f.cursorHash = tailHash[:]
	f.tailSeq = 2
	f.tailHash = tailHash[:]
	f.tailErr = nil
	f.committedAt = testCommittedAt

	in, canonical, payloadHash := mustPrepare(t)
	ev, err := appendLedgerEvent(context.Background(), f, in, canonical, payloadHash)
	if err != nil {
		t.Fatalf("appendLedgerEvent: %v", err)
	}

	// The returned values must be exactly what was written by the INSERT.
	ins := f.queryRows[2]
	if ev.PayloadCanonical != ins.args[4].(string) {
		t.Errorf("returned canonical %q must equal the INSERT arg %v", ev.PayloadCanonical, ins.args[4])
	}
	if !bytes.Equal(ev.PayloadHash[:], ins.args[5].([]byte)) {
		t.Errorf("returned payload hash %x must equal the INSERT arg %x", ev.PayloadHash, ins.args[5])
	}
	if !bytes.Equal(ev.EventHash[:], ins.args[7].([]byte)) {
		t.Errorf("returned event hash %x must equal the INSERT arg %x", ev.EventHash, ins.args[7])
	}
	if ev.PrevEventHash == nil || !bytes.Equal(ev.PrevEventHash[:], ins.args[6].([]byte)) {
		t.Errorf("returned prev hash %v must equal the INSERT arg %x", ev.PrevEventHash, ins.args[6])
	}
	if !ev.CommittedAt.Equal(f.committedAt) {
		t.Errorf("returned CommittedAt %v must equal the database value %v", ev.CommittedAt, f.committedAt)
	}

	// The guarded update wrote the same event hash as the new cursor hash.
	upd := f.execs[1]
	if !bytes.Equal(upd.args[2].([]byte), ev.EventHash[:]) {
		t.Errorf("new cursor hash %x must equal the returned event hash %x", upd.args[2], ev.EventHash)
	}

	// The returned previous hash must be an independent copy: mutating the
	// database-provided bytes afterwards must not change the returned value.
	wantPrev := tailHash // copy taken before the mutation
	f.tailHash[0] ^= 0xFF
	if *ev.PrevEventHash != wantPrev {
		t.Errorf("returned PrevEventHash %x must be an independent copy of the tail hash %x", *ev.PrevEventHash, wantPrev)
	}

	// appendLedgerEvent must never commit or roll back: the caller commits only
	// after a successful append, so the cursor can never advance on failure.
	if f.commitCalled {
		t.Error("appendLedgerEvent must never call Commit")
	}
	if f.rollbackCalls != 0 {
		t.Errorf("appendLedgerEvent must never call Rollback, got %d calls", f.rollbackCalls)
	}
}

// ---- typed error contracts ----

func TestLedgerCursorMismatchErrorContract(t *testing.T) {
	h := fillHash(0x07)
	err := &LedgerCursorMismatchError{
		StreamID:       "game-events",
		CursorSequence: 3,
		CursorHash:     &h,
		TailSequence:   4,
		TailHash:       &h,
		TailPresent:    true,
	}
	if !errors.Is(err, ErrLedgerCursorMismatch) {
		t.Fatal("typed mismatch error must match ErrLedgerCursorMismatch via errors.Is")
	}
	if !errors.Is(&LedgerCursorMismatchError{}, ErrLedgerCursorMismatch) {
		t.Fatal("zero-value mismatch error must also match the sentinel")
	}
	if errors.Is(errors.New("unrelated"), ErrLedgerCursorMismatch) {
		t.Fatal("unrelated errors must not match the sentinel")
	}
	var typed *LedgerCursorMismatchError
	if !errors.As(err, &typed) {
		t.Fatal("mismatch error must be recoverable via errors.As")
	}
	if typed.StreamID != "game-events" || typed.CursorSequence != 3 || typed.TailSequence != 4 || !typed.TailPresent {
		t.Errorf("typed error must carry the stream, sequences, and tail presence, got %+v", typed)
	}
	msg := err.Error()
	for _, want := range []string{"AIPT_LEDGER_CURSOR_MISMATCH", "game-events", "3", "4"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}
	if got := ErrLedgerCursorMismatch.Error(); got != "AIPT_LEDGER_CURSOR_MISMATCH" {
		t.Errorf("sentinel text = %q, want the code itself", got)
	}
	if got := (*LedgerCursorMismatchError)(nil).Error(); got != "<nil>" {
		t.Errorf("nil typed error text = %q, want <nil>", got)
	}
}

func TestLedgerSequenceExhaustedErrorContract(t *testing.T) {
	err := &LedgerSequenceExhaustedError{StreamID: "game-events", Sequence: math.MaxInt64}
	if !errors.Is(err, ErrLedgerSequenceExhausted) {
		t.Fatal("typed exhaustion error must match ErrLedgerSequenceExhausted via errors.Is")
	}
	if !errors.Is(&LedgerSequenceExhaustedError{}, ErrLedgerSequenceExhausted) {
		t.Fatal("zero-value exhaustion error must also match the sentinel")
	}
	if errors.Is(errors.New("unrelated"), ErrLedgerSequenceExhausted) {
		t.Fatal("unrelated errors must not match the sentinel")
	}
	var typed *LedgerSequenceExhaustedError
	if !errors.As(err, &typed) {
		t.Fatal("exhaustion error must be recoverable via errors.As")
	}
	if typed.StreamID != "game-events" || typed.Sequence != math.MaxInt64 {
		t.Errorf("typed error must carry the stream and sequence, got %+v", typed)
	}
	msg := err.Error()
	for _, want := range []string{"AIPT_LEDGER_SEQUENCE_EXHAUSTED", "game-events", "9223372036854775807"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}
	if got := ErrLedgerSequenceExhausted.Error(); got != "AIPT_LEDGER_SEQUENCE_EXHAUSTED" {
		t.Errorf("sentinel text = %q, want the code itself", got)
	}
}

// ---- identifier length bound ----

// TestAppendIdentifierLengthBound proves the identifier path of Append uses
// the same uint32 length-prefix bound as the hash chain. The pure guard is
// exercised at the boundary value instead of allocating a >4GiB string.
func TestAppendIdentifierLengthBound(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("uint32 overflow bound requires a 64-bit int")
	}
	tooLong := int(int64(math.MaxUint32) + 1)
	if err := validateByteLength("stream_id", tooLong); err == nil {
		t.Fatal("identifier byte length beyond MaxUint32 must be rejected")
	} else if !errors.Is(err, ErrInvalidLedgerHashInput) {
		t.Errorf("error = %v, want errors.Is(ErrInvalidLedgerHashInput)", err)
	}
	if err := validateByteLength("stream_id", math.MaxUint32); err != nil {
		t.Errorf("byte length exactly MaxUint32 must be accepted, got %v", err)
	}
}
