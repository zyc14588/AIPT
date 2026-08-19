// Database-free tests for the PostgreSQL Verify path. The verification
// transaction body (verifyStreamTx) runs against the minimal verifyTx surface
// (QueryRow for the stream cursor, Query for the ordered events), so a
// scripted fake exercises the complete cursor/chain/hash verification without
// a database, while VerifyStream's input validation is proven to run before
// any pool access by passing a nil *pgxpool.Pool. There is no mock/test
// dependency; package test helpers (fillHash, ledgerTestInput,
// ledgerTestCanonical) are reused where safe.
package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// verifyEvent is one scripted ledger event: the textual fields and the exact
// stored canonical payload TEXT that verification must hash byte-for-byte.
type verifyEvent struct {
	eventID          string
	eventType        string
	payloadCanonical string
}

// verifyChain is a fully consistent scripted stream: the cursor values and the
// event rows in ascending sequence order, together with the independently
// computed event hashes (through hashLedgerBlock, the implementation under
// test, whose digest contract is pinned by hash_test.go's independent vectors).
type verifyChain struct {
	cursorSeq  int64
	cursorHash []byte
	rows       [][]any
	hashes     [][32]byte
}

// buildVerifyChain builds a consistent chain for streamID: every event carries
// the SHA-256 of its exact stored payload TEXT, genesis carries a NULL
// previous hash, each later event carries the verified hash of the preceding
// one, every event hash is the versioned hashLedgerBlock digest, and the
// cursor is the actual tail (0, NULL for an empty stream). Every returned byte
// slice is an owned copy, so tests can corrupt one row without aliasing
// another.
func buildVerifyChain(streamID string, events []verifyEvent) verifyChain {
	ch := verifyChain{cursorSeq: int64(len(events))}
	var prior [32]byte
	for i, ev := range events {
		seq := int64(i + 1)
		payloadHash := sha256.Sum256([]byte(ev.payloadCanonical))
		var prevPtr *[32]byte
		if i > 0 {
			prevPtr = &prior
		}
		h, err := hashLedgerBlock(ledgerHashInput{
			StreamID:    streamID,
			Sequence:    seq,
			EventID:     ev.eventID,
			EventType:   ev.eventType,
			PayloadHash: payloadHash,
			PrevHash:    prevPtr,
		})
		if err != nil {
			panic(fmt.Sprintf("buildVerifyChain: hashLedgerBlock(sequence %d): %v", seq, err))
		}
		var prev []byte
		if i > 0 {
			prev = append([]byte(nil), prior[:]...)
		}
		ch.rows = append(ch.rows, []any{
			seq, ev.eventID, ev.eventType, ev.payloadCanonical,
			payloadHash[:], prev, h[:],
		})
		ch.hashes = append(ch.hashes, h)
		prior = h
	}
	if len(ch.hashes) > 0 {
		ch.cursorHash = append([]byte(nil), ch.hashes[len(ch.hashes)-1][:]...)
	}
	return ch
}

// ---- scripted verifyTx / pgx.Rows fake ----

// scanVerifyValue writes one scripted value into a Scan destination, matching
// the scan types verifyStreamTx uses: int64, string, and []byte (nil included).
func scanVerifyValue(dest any, value any) error {
	switch d := dest.(type) {
	case *int64:
		v, ok := value.(int64)
		if !ok {
			return fmt.Errorf("verify fake: value is %T, want int64", value)
		}
		*d = v
	case *string:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("verify fake: value is %T, want string", value)
		}
		*d = v
	case *[]byte:
		v, ok := value.([]byte)
		if !ok {
			return fmt.Errorf("verify fake: value is %T, want []byte", value)
		}
		*d = v
	default:
		return fmt.Errorf("verify fake: unsupported scan destination %T", dest)
	}
	return nil
}

// fakeVerifyRow is a scripted pgx.Row for the single cursor QueryRow: Scan
// writes the configured cursor values or returns the configured error.
type fakeVerifyRow struct {
	values []any
	err    error
}

func (r *fakeVerifyRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(r.values) != len(dest) {
		return fmt.Errorf("fakeVerifyRow: Scan got %d destinations, want %d values", len(dest), len(r.values))
	}
	for i := range dest {
		if err := scanVerifyValue(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

// fakeVerifyRows is a scripted pgx.Rows for the event query: each entry of
// rows is one event row's seven values, scanned in order. scanErr is returned
// by Scan, err is returned by Err after Next is exhausted, and Close records
// that verifyStreamTx released the result set.
type fakeVerifyRows struct {
	rows    [][]any
	idx     int
	err     error
	scanErr error
	closed  bool
}

func (r *fakeVerifyRows) Close() { r.closed = true }
func (r *fakeVerifyRows) Err() error {
	return r.err
}
func (r *fakeVerifyRows) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}
func (r *fakeVerifyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

// Values, RawValues, and Conn complete the pgx.Rows interface; the
// verification body never calls them, so they return zero values.
func (r *fakeVerifyRows) Values() ([]any, error) {
	return nil, nil
}
func (r *fakeVerifyRows) RawValues() [][]byte { return nil }
func (r *fakeVerifyRows) Conn() *pgx.Conn     { return nil }

func (r *fakeVerifyRows) Next() bool {
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeVerifyRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	if r.idx == 0 || r.idx > len(r.rows) {
		return fmt.Errorf("fakeVerifyRows: Scan called without a current row")
	}
	row := r.rows[r.idx-1]
	if len(row) != len(dest) {
		return fmt.Errorf("fakeVerifyRows: Scan got %d destinations, want %d values", len(dest), len(row))
	}
	for i := range dest {
		if err := scanVerifyValue(dest[i], row[i]); err != nil {
			return err
		}
	}
	return nil
}

// verifyCall records one statement the verification body issued: its exact SQL
// and arguments.
type verifyCall struct {
	sql  string
	args []any
}

// fakeVerifyTx is a scripted verifyTx. The cursor QueryRow returns
// cursorSeq/cursorHash (or cursorErr), and the events Query returns rows (or
// queryErr). Every statement is recorded so tests can assert the exact
// SELECT-only SQL shape, the arguments, and that the body never commits or
// rolls back.
type fakeVerifyTx struct {
	cursorSeq  int64
	cursorHash []byte
	cursorErr  error

	queryErr error
	rows     *fakeVerifyRows

	commitErr error

	queryCalls    []verifyCall
	commitCalled  bool
	rollbackCalls int
}

func newFakeVerifyTx() *fakeVerifyTx {
	return &fakeVerifyTx{rows: &fakeVerifyRows{}}
}

func (f *fakeVerifyTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.queryCalls = append(f.queryCalls, verifyCall{sql: sql, args: args})
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.rows, nil
}

func (f *fakeVerifyTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	f.queryCalls = append(f.queryCalls, verifyCall{sql: sql, args: args})
	return &fakeVerifyRow{values: []any{f.cursorSeq, f.cursorHash}, err: f.cursorErr}
}

func (f *fakeVerifyTx) Commit(ctx context.Context) error {
	f.commitCalled = true
	return f.commitErr
}

func (f *fakeVerifyTx) Rollback(ctx context.Context) error {
	f.rollbackCalls++
	return nil
}

// newVerifyChainTx builds a consistent chain for streamID and wires it into a
// fresh fake transaction.
func newVerifyChainTx(streamID string, events []verifyEvent) (*fakeVerifyTx, verifyChain) {
	ch := buildVerifyChain(streamID, events)
	f := newFakeVerifyTx()
	f.cursorSeq = ch.cursorSeq
	f.cursorHash = ch.cursorHash
	f.rows = &fakeVerifyRows{rows: ch.rows}
	return f, ch
}

// assertVerifyFailed fails the test unless err is non-nil and matches the
// expected sentinel through errors.Is.
func assertVerifyFailed(t *testing.T, err error, want error) {
	t.Helper()
	if err == nil {
		t.Fatal("a corrupted chain must fail closed")
	}
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want errors.Is(%v)", err, want)
	}
}

// assertErrorCode fails the test unless err's message embeds the stable code.
func assertErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	if !strings.Contains(err.Error(), code) {
		t.Errorf("error text = %q, want it to embed the stable code %q", err, code)
	}
}

// ---- valid chains ----

// TestVerifyStreamValid drives the valid verification table: the empty stream
// (cursor (0, NULL), no events), a genesis stream, and a multi-event chain,
// asserting the exact returned tail sequence, tail hash, and event count.
func TestVerifyStreamValid(t *testing.T) {
	cases := []struct {
		name     string
		streamID string
		events   []verifyEvent
	}{
		{"empty", "game-events", nil},
		{"genesis", "game-events", []verifyEvent{
			{"evt-0001", "ledger.appended", `{"a":1}`},
		}},
		{"multi-event", "game-events", []verifyEvent{
			{"evt-0001", "ledger.appended", `{"n":1}`},
			{"evt-0002", "state.applied", `{"n":2}`},
			{"evt-0003", "ledger.appended", `{"n":3}`},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, ch := newVerifyChainTx(tc.streamID, tc.events)
			vs, err := verifyStreamTx(context.Background(), f, tc.streamID)
			if err != nil {
				t.Fatalf("verifyStreamTx: %v", err)
			}
			if vs.StreamID != tc.streamID {
				t.Errorf("StreamID = %q, want %q", vs.StreamID, tc.streamID)
			}
			wantSeq := int64(len(tc.events))
			if vs.Sequence != wantSeq {
				t.Errorf("Sequence = %d, want %d", vs.Sequence, wantSeq)
			}
			if vs.EventCount != wantSeq {
				t.Errorf("EventCount = %d, want %d", vs.EventCount, wantSeq)
			}
			if wantSeq == 0 {
				if vs.EventHash != nil {
					t.Errorf("empty stream EventHash = %x, want nil", *vs.EventHash)
				}
			} else {
				if vs.EventHash == nil {
					t.Fatal("nonempty stream must return the tail event hash")
				}
				if *vs.EventHash != ch.hashes[wantSeq-1] {
					t.Errorf("EventHash = %x, want tail hash %x", *vs.EventHash, ch.hashes[wantSeq-1])
				}
			}
			if !f.rows.closed {
				t.Error("event rows must be closed after a successful verification")
			}
		})
	}
}

// TestVerifyStreamStoredNoncanonicalText proves verification hashes the exact
// stored canonical payload TEXT and never re-canonicalizes: the stored text is
// ledgerTestInput's non-canonical JSON (its canonical form ledgerTestCanonical
// differs), yet the chain built on the exact stored bytes verifies. A body
// that re-canonicalized before hashing would fail with a payload hash
// mismatch, because the recorded hash is the digest of the exact stored bytes.
func TestVerifyStreamStoredNoncanonicalText(t *testing.T) {
	stored := string(ledgerTestInput().PayloadJSON)
	if stored == ledgerTestCanonical {
		t.Fatal("test input must be non-canonical TEXT for the no-re-canonicalization property to be exercised")
	}
	if sha256.Sum256([]byte(stored)) == sha256.Sum256([]byte(ledgerTestCanonical)) {
		t.Fatal("stored and canonical text must hash differently for this test to be meaningful")
	}

	f, ch := newVerifyChainTx("game-events", []verifyEvent{
		{"evt-0001", "ledger.appended", stored},
	})
	vs, err := verifyStreamTx(context.Background(), f, "game-events")
	if err != nil {
		t.Fatalf("verifyStreamTx on the exact stored non-canonical TEXT: %v", err)
	}
	if vs.Sequence != 1 || vs.EventCount != 1 {
		t.Errorf("tail = (%d, %d), want (1, 1)", vs.Sequence, vs.EventCount)
	}
	if *vs.EventHash != ch.hashes[0] {
		t.Errorf("EventHash = %x, want the chain digest of the exact stored TEXT %x", *vs.EventHash, ch.hashes[0])
	}
}

// TestVerifyStreamIndependentStreams verifies two streams with independent
// data in separate runs and proves each returns only its own tail: stream A
// and stream B have different event sets and different tail hashes.
func TestVerifyStreamIndependentStreams(t *testing.T) {
	evsA := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"stream":"a","n":1}`},
		{"evt-0002", "state.applied", `{"stream":"a","n":2}`},
	}
	evsB := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"stream":"b","n":1}`},
	}
	fA, chA := newVerifyChainTx("game-events", evsA)
	vsA, err := verifyStreamTx(context.Background(), fA, "game-events")
	if err != nil {
		t.Fatalf("verifyStreamTx(stream A): %v", err)
	}
	fB, chB := newVerifyChainTx("audit-log", evsB)
	vsB, err := verifyStreamTx(context.Background(), fB, "audit-log")
	if err != nil {
		t.Fatalf("verifyStreamTx(stream B): %v", err)
	}

	if vsA.StreamID != "game-events" || vsA.Sequence != 2 || vsA.EventCount != 2 {
		t.Errorf("stream A result = %+v, want stream game-events tail 2/2", vsA)
	}
	if *vsA.EventHash != chA.hashes[1] {
		t.Errorf("stream A tail hash = %x, want %x", *vsA.EventHash, chA.hashes[1])
	}
	if vsB.StreamID != "audit-log" || vsB.Sequence != 1 || vsB.EventCount != 1 {
		t.Errorf("stream B result = %+v, want stream audit-log tail 1/1", vsB)
	}
	if *vsB.EventHash != chB.hashes[0] {
		t.Errorf("stream B tail hash = %x, want %x", *vsB.EventHash, chB.hashes[0])
	}
	if *vsA.EventHash == *vsB.EventHash {
		t.Error("independent streams must carry independent data and hashes")
	}
}

// ---- missing stream / input validation ----

// TestVerifyStreamMissingStream proves a stream with no cursor row fails
// closed with the typed AIPT_LEDGER_STREAM_NOT_FOUND error before any event
// query runs.
func TestVerifyStreamMissingStream(t *testing.T) {
	f := newFakeVerifyTx()
	f.cursorErr = pgx.ErrNoRows
	_, err := verifyStreamTx(context.Background(), f, "game-events")
	assertVerifyFailed(t, err, ErrLedgerStreamNotFound)
	var typed *LedgerStreamNotFoundError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" {
		t.Errorf("typed.StreamID = %q, want %q", typed.StreamID, "game-events")
	}
	assertErrorCode(t, err, "AIPT_LEDGER_STREAM_NOT_FOUND")
	if len(f.queryCalls) != 1 {
		t.Errorf("query calls = %d, want 1 (cursor only; no event query for a missing stream)", len(f.queryCalls))
	}
}

// TestVerifyStreamInputValidationBeforeNilPool proves stream identifier
// validation runs before any pool or transaction access: empty and non-UTF-8
// stream IDs are rejected with the hash chain's typed input error even for a
// nil pool.
func TestVerifyStreamInputValidationBeforeNilPool(t *testing.T) {
	var pool *pgxpool.Pool // nil: any database access would fail here
	for _, tc := range []struct {
		name     string
		streamID string
	}{
		{"empty stream_id", ""},
		{"non-UTF8 stream_id", "\xff\xfe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vs, err := VerifyStream(context.Background(), pool, VerifyInput{StreamID: tc.streamID})
			if err == nil {
				t.Fatal("invalid stream ID must be rejected before any pool access")
			}
			if vs != (VerifiedStream{}) {
				t.Errorf("rejected verification must return the zero result, got %+v", vs)
			}
			if !errors.Is(err, ErrInvalidLedgerHashInput) {
				t.Errorf("error = %v, want errors.Is(ErrInvalidLedgerHashInput)", err)
			}
			var typed *LedgerHashInputError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.Field != "stream_id" {
				t.Errorf("typed.Field = %q, want %q", typed.Field, "stream_id")
			}
			if strings.Contains(err.Error(), "nil *pgxpool.Pool") {
				t.Errorf("identifier rejection must precede the nil-pool check, got %v", err)
			}
		})
	}
}

// TestVerifyStreamNilPoolRejected proves a valid stream ID with a nil pool is
// rejected by the pool guard, after input validation.
func TestVerifyStreamNilPoolRejected(t *testing.T) {
	var pool *pgxpool.Pool
	_, err := VerifyStream(context.Background(), pool, VerifyInput{StreamID: "game-events"})
	if err == nil {
		t.Fatal("valid stream ID with a nil *pgxpool.Pool must be rejected")
	}
	if !strings.Contains(err.Error(), "nil *pgxpool.Pool") {
		t.Errorf("error = %q, want it to mention the nil pool", err)
	}
}

// ---- chain corruption ----

// TestVerifyStreamSequenceGap covers both gap shapes — the first event not at
// sequence 1 and a later event skipping a sequence — each failing closed with
// the typed AIPT_LEDGER_SEQUENCE_GAP error carrying the expected and actual
// sequences.
func TestVerifyStreamSequenceGap(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	cases := []struct {
		name         string
		mutate       func(*verifyChain)
		wantExpected int64
		wantActual   int64
	}{
		{"first sequence gap", func(c *verifyChain) { c.rows[0][0] = int64(2) }, 1, 2},
		{"internal sequence gap", func(c *verifyChain) { c.rows[1][0] = int64(3) }, 2, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := buildVerifyChain("game-events", evs)
			tc.mutate(&ch)
			f := newFakeVerifyTx()
			f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
			f.rows = &fakeVerifyRows{rows: ch.rows}
			_, err := verifyStreamTx(context.Background(), f, "game-events")
			assertVerifyFailed(t, err, ErrLedgerSequenceGap)
			var typed *LedgerSequenceGapError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.StreamID != "game-events" || typed.Expected != tc.wantExpected || typed.Actual != tc.wantActual {
				t.Errorf("typed = %+v, want stream game-events expected %d actual %d", typed, tc.wantExpected, tc.wantActual)
			}
			assertErrorCode(t, err, "AIPT_LEDGER_SEQUENCE_GAP")
		})
	}
}

// TestVerifyStreamPrevHashMismatch covers every previous-hash corruption: a
// genesis event carrying a non-NULL previous hash, a later event carrying a
// wrong previous hash, and a later event carrying SQL NULL. Each fails closed
// with the typed AIPT_LEDGER_PREV_HASH_MISMATCH error. A NULL previous hash on
// a later event is a prev-hash mismatch, not a malformed hash: the body
// reports the missing predecessor first.
func TestVerifyStreamPrevHashMismatch(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	w11 := fillHash(0x11)
	w22 := fillHash(0x22)
	cases := []struct {
		name            string
		mutate          func(*verifyChain)
		wantSeq         int64
		wantExpectedNil bool
		wantActual      *[32]byte // nil means expect a nil Actual
	}{
		{"genesis non-NULL prev", func(c *verifyChain) { c.rows[0][5] = w11[:] }, 1, true, &w11},
		{"later wrong prev", func(c *verifyChain) { c.rows[1][5] = w22[:] }, 2, false, &w22},
		{"later NULL prev", func(c *verifyChain) { c.rows[1][5] = []byte(nil) }, 2, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := buildVerifyChain("game-events", evs)
			tc.mutate(&ch)
			f := newFakeVerifyTx()
			f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
			f.rows = &fakeVerifyRows{rows: ch.rows}
			_, err := verifyStreamTx(context.Background(), f, "game-events")
			assertVerifyFailed(t, err, ErrLedgerPrevHashMismatch)
			var typed *LedgerPrevHashMismatchError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.StreamID != "game-events" || typed.Sequence != tc.wantSeq {
				t.Errorf("typed = %+v, want stream game-events sequence %d", typed, tc.wantSeq)
			}
			if (typed.Expected == nil) != tc.wantExpectedNil {
				t.Errorf("typed.Expected nil = %t, want %t", typed.Expected == nil, tc.wantExpectedNil)
			}
			// The expected side of a later-event mismatch is the verified hash
			// of the preceding event.
			if !tc.wantExpectedNil && *typed.Expected != ch.hashes[0] {
				t.Errorf("typed.Expected = %x, want verified predecessor %x", *typed.Expected, ch.hashes[0])
			}
			if tc.wantActual == nil {
				if typed.Actual != nil {
					t.Errorf("typed.Actual = %x, want nil", *typed.Actual)
				}
			} else if typed.Actual == nil || *typed.Actual != *tc.wantActual {
				t.Errorf("typed.Actual = %v, want the recorded hash %x", typed.Actual, *tc.wantActual)
			}
			assertErrorCode(t, err, "AIPT_LEDGER_PREV_HASH_MISMATCH")
		})
	}
}

// TestVerifyStreamPayloadHashMismatch proves a recorded payload_sha256 that
// differs from the SHA-256 of the exact stored payload TEXT fails closed with
// the typed AIPT_LEDGER_PAYLOAD_HASH_MISMATCH error carrying the digest of the
// stored text as Expected and the recorded bytes as Actual.
func TestVerifyStreamPayloadHashMismatch(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	recorded := fillHash(0x99)
	ch := buildVerifyChain("game-events", evs)
	ch.rows[1][4] = recorded[:]
	f := newFakeVerifyTx()
	f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
	f.rows = &fakeVerifyRows{rows: ch.rows}

	_, err := verifyStreamTx(context.Background(), f, "game-events")
	assertVerifyFailed(t, err, ErrLedgerPayloadHashMismatch)
	var typed *LedgerPayloadHashMismatchError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" || typed.Sequence != 2 {
		t.Errorf("typed = %+v, want stream game-events sequence 2", typed)
	}
	if want := sha256.Sum256([]byte(evs[1].payloadCanonical)); typed.Expected == nil || *typed.Expected != want {
		t.Errorf("typed.Expected = %v, want the digest of the stored TEXT %x", typed.Expected, want)
	}
	if typed.Actual == nil || *typed.Actual != recorded {
		t.Errorf("typed.Actual = %v, want the recorded payload hash %x", typed.Actual, recorded)
	}
	assertErrorCode(t, err, "AIPT_LEDGER_PAYLOAD_HASH_MISMATCH")
}

// TestVerifyStreamEventHashMismatch proves a recorded event_hash that differs
// from the versioned hashLedgerBlock digest of the event's own fields fails
// closed with the typed AIPT_LEDGER_EVENT_HASH_MISMATCH error carrying the
// recomputed digest as Expected and the recorded bytes as Actual.
func TestVerifyStreamEventHashMismatch(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	recorded := fillHash(0x77)
	ch := buildVerifyChain("game-events", evs)
	ch.rows[0][6] = recorded[:]
	f := newFakeVerifyTx()
	f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
	f.rows = &fakeVerifyRows{rows: ch.rows}

	_, err := verifyStreamTx(context.Background(), f, "game-events")
	assertVerifyFailed(t, err, ErrLedgerEventHashMismatch)
	var typed *LedgerEventHashMismatchError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" || typed.Sequence != 1 {
		t.Errorf("typed = %+v, want stream game-events sequence 1", typed)
	}
	if typed.Expected == nil || *typed.Expected != ch.hashes[0] {
		t.Errorf("typed.Expected = %v, want the recomputed digest %x", typed.Expected, ch.hashes[0])
	}
	if typed.Actual == nil || *typed.Actual != recorded {
		t.Errorf("typed.Actual = %v, want the recorded event hash %x", typed.Actual, recorded)
	}
	assertErrorCode(t, err, "AIPT_LEDGER_EVENT_HASH_MISMATCH")
}

// TestVerifyStreamMalformedHash covers the nil-versus-empty malformed hash
// boundary for every hash column: SQL NULL where the hash is required and
// non-NULL values whose byte length is not 32 (short and zero-length), for
// payload_sha256, event_hash, prev_event_hash, and the cursor's
// last_event_hash. Every case fails closed with the typed
// AIPT_LEDGER_MALFORMED_HASH error carrying the field, NULL-ness, and byte
// length. Two boundaries are intentionally classified elsewhere: a SQL NULL
// previous hash on a later event is a prev-hash mismatch (the body reports the
// missing predecessor first, see TestVerifyStreamPrevHashMismatch), and a SQL
// NULL cursor hash is the legal empty cursor (see TestVerifyStreamValid).
func TestVerifyStreamMalformedHash(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	cases := []struct {
		name       string
		row        int // event row to corrupt, -1 for the cursor
		col        int
		value      any
		wantSeq    int64
		wantField  string
		wantIsNull bool
		wantLen    int
	}{
		{"payload NULL", 0, 4, []byte(nil), 1, "payload_sha256", true, 0},
		{"payload short", 0, 4, []byte{0x01}, 1, "payload_sha256", false, 1},
		{"payload empty", 0, 4, []byte{}, 1, "payload_sha256", false, 0},
		{"event NULL", 0, 6, []byte(nil), 1, "event_hash", true, 0},
		{"event short", 0, 6, []byte{0x01, 0x02}, 1, "event_hash", false, 2},
		{"event empty", 0, 6, []byte{}, 1, "event_hash", false, 0},
		{"prev short", 1, 5, []byte{0x01}, 2, "prev_event_hash", false, 1},
		{"prev empty", 1, 5, []byte{}, 2, "prev_event_hash", false, 0},
		{"genesis prev short", 0, 5, []byte{0x01}, 1, "prev_event_hash", false, 1},
		{"cursor short", -1, -1, []byte{0x01}, 2, "last_event_hash", false, 1},
		{"cursor empty", -1, -1, []byte{}, 2, "last_event_hash", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := buildVerifyChain("game-events", evs)
			f := newFakeVerifyTx()
			f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
			f.rows = &fakeVerifyRows{rows: ch.rows}
			if tc.row >= 0 {
				ch.rows[tc.row][tc.col] = tc.value
			} else {
				f.cursorHash = tc.value.([]byte)
			}
			_, err := verifyStreamTx(context.Background(), f, "game-events")
			assertVerifyFailed(t, err, ErrLedgerMalformedHash)
			var typed *LedgerMalformedHashError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.StreamID != "game-events" || typed.Sequence != tc.wantSeq ||
				typed.Field != tc.wantField || typed.IsNull != tc.wantIsNull || typed.ByteLength != tc.wantLen {
				t.Errorf("typed = %+v, want stream game-events sequence %d field %s is null %t byte length %d",
					typed, tc.wantSeq, tc.wantField, tc.wantIsNull, tc.wantLen)
			}
			assertErrorCode(t, err, "AIPT_LEDGER_MALFORMED_HASH")
		})
	}
}

// TestVerifyStreamCursorMismatch covers every cursor-versus-tail disagreement:
// an empty cursor with a nonempty tail, a nonempty cursor with an empty tail,
// cursor sequence drift, and cursor hash drift. Each fails closed with the
// typed AIPT_LEDGER_CURSOR_MISMATCH error carrying the stored cursor and the
// actual verified tail. The sequence-drift case stores the actual verified
// tail hash so only the cursor sequence is wrong, and the hash-drift case
// keeps the correct tail sequence so only the cursor hash is wrong: each
// drift axis is isolated from the other.
func TestVerifyStreamCursorMismatch(t *testing.T) {
	streamID := "game-events"
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	other := fillHash(0x0B)
	cases := []struct {
		name                 string
		cursorSeq            int64
		cursorHash           []byte
		cursorHashIsTail     bool // use the actual verified tail hash as the stored cursor hash
		events               []verifyEvent
		wantCursorSeq        int64
		wantCursorHashNil    bool
		wantCursorHashIsTail bool // reported cursor hash must equal the verified tail hash
		wantTailSeq          int64
		wantTailHashNil      bool
		wantTailPresent      bool
	}{
		{"empty cursor, nonempty tail", 0, nil, false, evs, 0, true, false, 2, false, true},
		{"nonempty cursor, empty tail", 2, other[:], false, nil, 2, false, false, 0, true, false},
		{"cursor sequence drift", 1, nil, true, evs, 1, false, true, 2, false, true},
		{"cursor hash drift", 2, other[:], false, evs, 2, false, false, 2, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := buildVerifyChain(streamID, tc.events)
			f := newFakeVerifyTx()
			f.cursorSeq = tc.cursorSeq
			if tc.cursorHashIsTail {
				f.cursorHash = append([]byte(nil), ch.hashes[len(ch.hashes)-1][:]...)
			} else {
				f.cursorHash = tc.cursorHash
			}
			f.rows = &fakeVerifyRows{rows: ch.rows}
			_, err := verifyStreamTx(context.Background(), f, streamID)
			assertVerifyFailed(t, err, ErrLedgerCursorMismatch)
			var typed *LedgerCursorMismatchError
			if !errors.As(err, &typed) {
				t.Fatalf("error = %v, want recoverable via errors.As", err)
			}
			if typed.StreamID != streamID ||
				typed.CursorSequence != tc.wantCursorSeq ||
				typed.TailSequence != tc.wantTailSeq ||
				typed.TailPresent != tc.wantTailPresent {
				t.Errorf("typed = %+v, want stream %s cursor %d tail %d present %t",
					typed, streamID, tc.wantCursorSeq, tc.wantTailSeq, tc.wantTailPresent)
			}
			if (typed.CursorHash == nil) != tc.wantCursorHashNil {
				t.Errorf("typed.CursorHash nil = %t, want %t", typed.CursorHash == nil, tc.wantCursorHashNil)
			}
			if (typed.TailHash == nil) != tc.wantTailHashNil {
				t.Errorf("typed.TailHash nil = %t, want %t", typed.TailHash == nil, tc.wantTailHashNil)
			}
			// The stored cursor hash and the verified tail hash are reported
			// exactly as read.
			if !tc.wantCursorHashNil {
				if tc.wantCursorHashIsTail {
					want := ch.hashes[len(ch.hashes)-1]
					if typed.CursorHash == nil || *typed.CursorHash != want {
						t.Errorf("typed.CursorHash = %v, want the verified tail hash %x", typed.CursorHash, want)
					}
				} else if *typed.CursorHash != other {
					t.Errorf("typed.CursorHash = %x, want stored %x", *typed.CursorHash, other)
				}
			}
			if tc.events != nil {
				if want := ch.hashes[len(ch.hashes)-1]; typed.TailHash == nil || *typed.TailHash != want {
					t.Errorf("typed.TailHash = %v, want verified tail %x", typed.TailHash, want)
				}
			}
			assertErrorCode(t, err, "AIPT_LEDGER_CURSOR_MISMATCH")
		})
	}
}

// ---- database failure handling ----

// TestVerifyStreamDBErrorsPreserveCause covers every database failure point of
// the verification body — the cursor QueryRow, the events Query, the event
// Scan, and rows.Err — and proves each wrapped error preserves its cause
// through errors.Is.
func TestVerifyStreamDBErrorsPreserveCause(t *testing.T) {
	sentinel := errors.New("injected database failure")
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}

	t.Run("cursor read", func(t *testing.T) {
		f := newFakeVerifyTx()
		f.cursorErr = sentinel
		_, err := verifyStreamTx(context.Background(), f, "game-events")
		if !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the cursor-read cause preserved", err)
		}
		if len(f.queryCalls) != 1 {
			t.Errorf("query calls = %d, want 1 (cursor only)", len(f.queryCalls))
		}
	})
	t.Run("event query", func(t *testing.T) {
		f := newFakeVerifyTx()
		f.queryErr = sentinel
		_, err := verifyStreamTx(context.Background(), f, "game-events")
		if !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the event-query cause preserved", err)
		}
	})
	t.Run("event scan", func(t *testing.T) {
		ch := buildVerifyChain("game-events", evs)
		f := newFakeVerifyTx()
		f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
		f.rows = &fakeVerifyRows{rows: ch.rows, scanErr: sentinel}
		_, err := verifyStreamTx(context.Background(), f, "game-events")
		if !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the scan cause preserved", err)
		}
		if !f.rows.closed {
			t.Error("rows must be closed after a scan failure")
		}
	})
	t.Run("rows Err", func(t *testing.T) {
		ch := buildVerifyChain("game-events", evs)
		f := newFakeVerifyTx()
		f.cursorSeq, f.cursorHash = ch.cursorSeq, ch.cursorHash
		f.rows = &fakeVerifyRows{rows: ch.rows, err: sentinel}
		_, err := verifyStreamTx(context.Background(), f, "game-events")
		if !errors.Is(err, sentinel) {
			t.Errorf("error = %v, want the rows.Err cause preserved", err)
		}
		if !f.rows.closed {
			t.Error("rows must be closed after rows.Err")
		}
	})
}

// TestVerifyStreamClosesRows proves the event result set is always released:
// after a successful verification and after every failure shape (chain
// violation, scan error, rows.Err).
func TestVerifyStreamClosesRows(t *testing.T) {
	sentinel := errors.New("injected database failure")
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	cases := []struct {
		name    string
		corrupt func(*fakeVerifyTx)
	}{
		{"success", func(f *fakeVerifyTx) {}},
		{"verify failure", func(f *fakeVerifyTx) { f.rows.rows[0][4] = []byte{0x01} }},
		{"scan failure", func(f *fakeVerifyTx) { f.rows.scanErr = sentinel }},
		{"rows.Err", func(f *fakeVerifyTx) { f.rows.err = sentinel }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newVerifyChainTx("game-events", evs)
			tc.corrupt(f)
			_, _ = verifyStreamTx(context.Background(), f, "game-events")
			if !f.rows.closed {
				t.Error("event rows must be closed on every verification outcome")
			}
		})
	}
}

// ---- SQL shape and returned values ----

// TestVerifyStreamSQLShape pins the read-only SQL contract of the verification
// body: exactly two statements — the cursor SELECT on aipt.ledger_streams and
// the event SELECT on aipt.ledger_events ordered by sequence ASC — both bound
// to the stream ID, with no mutation SQL anywhere, and the body never commits
// or rolls back (the caller owns the transaction lifecycle).
func TestVerifyStreamSQLShape(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	f, _ := newVerifyChainTx("game-events", evs)
	if _, err := verifyStreamTx(context.Background(), f, "game-events"); err != nil {
		t.Fatalf("verifyStreamTx: %v", err)
	}

	if len(f.queryCalls) != 2 {
		t.Fatalf("statements = %d, want 2 (cursor + events)", len(f.queryCalls))
	}
	cursor, events := f.queryCalls[0], f.queryCalls[1]

	if !strings.Contains(cursor.sql, "SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1") {
		t.Errorf("cursor statement = %q, want the ledger_streams cursor SELECT", cursor.sql)
	}
	for _, want := range []string{
		"SELECT sequence, event_id, event_type, payload_canonical, payload_sha256, prev_event_hash, event_hash",
		"FROM aipt.ledger_events",
		"WHERE stream_id = $1",
		"ORDER BY sequence ASC",
	} {
		if !strings.Contains(events.sql, want) {
			t.Errorf("event statement = %q, want it to contain %q", events.sql, want)
		}
	}
	if len(cursor.args) != 1 || cursor.args[0] != "game-events" {
		t.Errorf("cursor args = %v, want [game-events]", cursor.args)
	}
	if len(events.args) != 1 || events.args[0] != "game-events" {
		t.Errorf("event args = %v, want [game-events]", events.args)
	}
	for _, c := range f.queryCalls {
		up := strings.ToUpper(c.sql)
		for _, keyword := range []string{"INSERT", "UPDATE", "DELETE", "UPSERT"} {
			if strings.Contains(up, keyword) {
				t.Errorf("statement %q must not contain mutation keyword %s", c.sql, keyword)
			}
		}
	}
	if f.commitCalled {
		t.Error("verifyStreamTx must never call Commit")
	}
	if f.rollbackCalls != 0 {
		t.Errorf("verifyStreamTx must never call Rollback, got %d calls", f.rollbackCalls)
	}
}

// TestVerifyStreamReturnedHashOwnedCopy proves the returned tail hash is an
// owned copy: mutating the database-provided cursor bytes and event-row bytes
// after verification must not change the returned value.
func TestVerifyStreamReturnedHashOwnedCopy(t *testing.T) {
	evs := []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	}
	f, ch := newVerifyChainTx("game-events", evs)
	vs, err := verifyStreamTx(context.Background(), f, "game-events")
	if err != nil {
		t.Fatalf("verifyStreamTx: %v", err)
	}
	want := *vs.EventHash // snapshot before the mutation

	// Corrupt the fake's storage the verification read from: the cursor hash
	// and the last event row's recorded event hash.
	f.cursorHash[0] ^= 0xFF
	f.rows.rows[len(evs)-1][6].([]byte)[0] ^= 0xFF

	if *vs.EventHash != want {
		t.Errorf("returned EventHash %x must be an owned copy of the tail hash %x", *vs.EventHash, want)
	}
	if *vs.EventHash != ch.hashes[len(ch.hashes)-1] {
		t.Errorf("returned EventHash %x must equal the verified tail hash %x", *vs.EventHash, ch.hashes[len(ch.hashes)-1])
	}
}

// ---- stable codes ----

// TestVerifyStreamSentinelCodes pins the exact stable code strings of every
// verification sentinel, so callers can match failures without parsing
// messages.
func TestVerifyStreamSentinelCodes(t *testing.T) {
	cases := []struct {
		sentinel error
		code     string
	}{
		{ErrLedgerCursorMismatch, "AIPT_LEDGER_CURSOR_MISMATCH"},
		{ErrLedgerStreamNotFound, "AIPT_LEDGER_STREAM_NOT_FOUND"},
		{ErrLedgerSequenceGap, "AIPT_LEDGER_SEQUENCE_GAP"},
		{ErrLedgerPrevHashMismatch, "AIPT_LEDGER_PREV_HASH_MISMATCH"},
		{ErrLedgerPayloadHashMismatch, "AIPT_LEDGER_PAYLOAD_HASH_MISMATCH"},
		{ErrLedgerEventHashMismatch, "AIPT_LEDGER_EVENT_HASH_MISMATCH"},
		{ErrLedgerMalformedHash, "AIPT_LEDGER_MALFORMED_HASH"},
		{ErrInvalidLedgerHashInput, "AIPT_INVALID_LEDGER_HASH_INPUT"},
	}
	for _, tc := range cases {
		if got := tc.sentinel.Error(); got != tc.code {
			t.Errorf("sentinel text = %q, want the stable code %q", got, tc.code)
		}
	}
}
