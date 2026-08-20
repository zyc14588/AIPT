// ledger_integration_test.go exercises the production Append, VerifyStream,
// and MigrateUp APIs against uniquely generated ephemeral PostgreSQL databases,
// covering the happy-path chain, duplicate-event_id atomicity, invalid payload
// rejection before any database access, deterministic same-stream concurrency,
// independent multi-stream isolation, the append-only DML gates, and five
// isolated tamper cases. Every test in this file requires AIPT_POSTGRES_DSN to
// be set: when it is missing the tests skip normally, except that
// AIPT_REQUIRE_POSTGRES_INTEGRATION=1 turns the skip into a hard failure. The
// tests are parallel-safe by construction -- each creates its own
// collision-resistant aipt_* database and never touches shared state -- and
// the fixture cleanup terminates every connection to its database, drops
// exactly that database, and verifies that no aipt_* database remains.
//
// The concurrency test starts at least 16 Append goroutines behind a channel
// barrier, registers a teardown that cancels and boundedly drains every
// started-but-not-yet-received appender before the pool closes, joins every
// started goroutine under a bounded context, and asserts only deterministic
// final-state invariants (exact 1..N sequences, unique event IDs, coherent
// prev-hash links, cursor at N, exact VerifyStream tail), never a timing-based
// interleaving assumption.
//
// The tamper tests disable the append-only trigger and drop only the single
// check constraint that the specific event-row tamper would otherwise violate
// (ledger_events_payload_sha256_check for a payload_canonical change,
// ledger_events_event_hash_check for a prev_event_hash or event_hash change),
// in the ephemeral test database only; the production migration SQL is never
// modified. The ledger_streams cursor tamper needs no trigger or constraint
// change because the cursor invariant still holds after the tamper. Tamper
// values use valid 32-byte hashes wherever the target column is a hash, so
// VerifyStream reaches the intended semantic typed failure instead of a
// malformed-hash error, and every failed verification returns the zero
// VerifiedStream.

package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// ledgerAppendInput builds a valid append input with the standard event type.
func ledgerAppendInput(streamID, eventID, payload string) AppendInput {
	return AppendInput{
		StreamID:    streamID,
		EventID:     eventID,
		EventType:   "ledger.appended",
		PayloadJSON: []byte(payload),
	}
}

// ledgerAppendLive appends through the production API and fails the test on
// any error, also asserting that the database returned a real committed_at.
func ledgerAppendLive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, in AppendInput) LedgerEvent {
	t.Helper()
	ev, err := Append(ctx, pool, in)
	if err != nil {
		t.Fatalf("Append(stream %q, event %q): %v", in.StreamID, in.EventID, err)
	}
	if ev.CommittedAt.IsZero() {
		t.Errorf("Append(stream %q, event %q) returned a zero committed_at", in.StreamID, in.EventID)
	}
	return ev
}

// ledgerVerifyLive verifies through the production API and fails the test on
// any error.
func ledgerVerifyLive(t *testing.T, ctx context.Context, pool *pgxpool.Pool, streamID string) VerifiedStream {
	t.Helper()
	vs, err := VerifyStream(ctx, pool, VerifyInput{StreamID: streamID})
	if err != nil {
		t.Fatalf("VerifyStream(%q): %v", streamID, err)
	}
	return vs
}

// ledgerEventRow is one committed row of aipt.ledger_events as read back from
// the ephemeral database, ordered by sequence ASC.
type ledgerEventRow struct {
	sequence         int64
	eventID          string
	eventType        string
	payloadCanonical string
	payloadSHA       []byte
	prevEventHash    []byte // nil for SQL NULL
	eventHash        []byte
}

// queryLedgerEvents reads every committed event row of one stream in sequence
// order.
func queryLedgerEvents(ctx context.Context, pool *pgxpool.Pool, streamID string) ([]ledgerEventRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT sequence, event_id, event_type, payload_canonical, payload_sha256, prev_event_hash, event_hash
		FROM aipt.ledger_events
		WHERE stream_id = $1
		ORDER BY sequence ASC`, streamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ledgerEventRow
	for rows.Next() {
		var r ledgerEventRow
		if err := rows.Scan(&r.sequence, &r.eventID, &r.eventType, &r.payloadCanonical,
			&r.payloadSHA, &r.prevEventHash, &r.eventHash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ledgerCursor mirrors the aipt.ledger_streams cursor row.
type ledgerCursor struct {
	lastSequence  int64
	lastEventHash []byte // nil for SQL NULL
}

// queryLedgerCursor reads the stream cursor row.
func queryLedgerCursor(ctx context.Context, pool *pgxpool.Pool, streamID string) (ledgerCursor, error) {
	var c ledgerCursor
	err := pool.QueryRow(ctx,
		"SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1",
		streamID).Scan(&c.lastSequence, &c.lastEventHash)
	return c, err
}

// assertLedgerAppendOnlyRejected fails the test unless the statement was
// rejected by the append-only trigger with SQLSTATE 55000 and the stable code
// AIPT_LEDGER_APPEND_ONLY.
func assertLedgerAppendOnlyRejected(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	_, err := pool.Exec(ctx, sql, args...)
	if err == nil {
		t.Fatalf("statement %q must be rejected by the append-only trigger", sql)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("statement %q error = %v, want *pgconn.PgError", sql, err)
	}
	if pgErr.Code != "55000" || !strings.Contains(pgErr.Message, "AIPT_LEDGER_APPEND_ONLY") {
		t.Errorf("append-only rejection = SQLSTATE %s %q, want 55000 with AIPT_LEDGER_APPEND_ONLY",
			pgErr.Code, pgErr.Message)
	}
}

// ledgerNewPool returns a pool to the fixture's ephemeral database with the
// requested connection cap, used by the concurrency test so every Append
// goroutine can hold its own connection.
func ledgerNewPool(ctx context.Context, t *testing.T, fx *integrationFixture, maxConns int32) *pgxpool.Pool {
	t.Helper()
	cfg := fx.ephCfg.Copy()
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect to ephemeral database %q: %v", fx.dbName, err)
	}
	return pool
}

// assertRowMatchesEvent fails the test unless the database row carries exactly
// the committed event returned by Append.
func assertRowMatchesEvent(t *testing.T, what string, r ledgerEventRow, ev LedgerEvent) {
	t.Helper()
	if r.sequence != ev.Sequence {
		t.Errorf("%s: stored sequence = %d, want %d", what, r.sequence, ev.Sequence)
	}
	if r.eventID != ev.EventID {
		t.Errorf("%s: stored event_id = %q, want %q", what, r.eventID, ev.EventID)
	}
	if r.eventType != ev.EventType {
		t.Errorf("%s: stored event_type = %q, want %q", what, r.eventType, ev.EventType)
	}
	if r.payloadCanonical != ev.PayloadCanonical {
		t.Errorf("%s: stored payload_canonical = %q, want %q", what, r.payloadCanonical, ev.PayloadCanonical)
	}
	if !bytes.Equal(r.payloadSHA, ev.PayloadHash[:]) {
		t.Errorf("%s: stored payload_sha256 = %x, want %x", what, r.payloadSHA, ev.PayloadHash)
	}
	if !bytes.Equal(r.eventHash, ev.EventHash[:]) {
		t.Errorf("%s: stored event_hash = %x, want %x", what, r.eventHash, ev.EventHash)
	}
	if ev.PrevEventHash == nil {
		if r.prevEventHash != nil {
			t.Errorf("%s: stored prev_event_hash = %x, want SQL NULL", what, r.prevEventHash)
		}
	} else if !bytes.Equal(r.prevEventHash, ev.PrevEventHash[:]) {
		t.Errorf("%s: stored prev_event_hash = %x, want %x", what, r.prevEventHash, *ev.PrevEventHash)
	}
}

// TestPostgresIntegrationLedgerHappyPath covers the live happy path: a
// genesis and a chained second event on one stream plus an independent genesis
// event on another stream, asserting exact sequences, canonical
// payload/payload-hash/prev-hash/event-hash links, the database rows and
// cursors, the live SQL hash function agreement, and VerifyStream's exact
// independent tails and counts with no cross-stream chain.
func TestPostgresIntegrationLedgerHappyPath(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	// Stream A: genesis, then a chained second event.
	rawA1 := `{"b":1,"a":[3,1,2],"c":"x"}` // canonicalizes exactly to ledgerTestCanonical
	evA1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-a-0001", rawA1))
	evA2 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-a-0002", `{"n":2}`))
	// Stream B: one independent genesis event.
	evB1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("audit-log", "evt-b-0001", `{"audit":true}`))

	// Exact sequences.
	if evA1.Sequence != 1 || evA2.Sequence != 2 || evB1.Sequence != 1 {
		t.Errorf("returned sequences = (%d, %d, %d), want (1, 2, 1)",
			evA1.Sequence, evA2.Sequence, evB1.Sequence)
	}

	// Canonical payload and its digest, byte-for-byte the protocol package.
	canonicalA1, err := protocol.CanonicalJSON([]byte(rawA1))
	if err != nil {
		t.Fatalf("protocol.CanonicalJSON: %v", err)
	}
	if canonicalA1 != ledgerTestCanonical {
		t.Fatalf("canonicalA1 = %q, want pinned %q", canonicalA1, ledgerTestCanonical)
	}
	if evA1.PayloadCanonical != canonicalA1 {
		t.Errorf("evA1 PayloadCanonical = %q, want %q", evA1.PayloadCanonical, canonicalA1)
	}
	if want := sha256.Sum256([]byte(canonicalA1)); evA1.PayloadHash != want {
		t.Errorf("evA1 PayloadHash = %x, want sha256(canonical) %x", evA1.PayloadHash, want)
	}
	wantCanonicalA2, err := protocol.CanonicalJSON([]byte(`{"n":2}`))
	if err != nil {
		t.Fatalf("protocol.CanonicalJSON(n=2): %v", err)
	}
	if evA2.PayloadCanonical != wantCanonicalA2 {
		t.Errorf("evA2 PayloadCanonical = %q, want %q", evA2.PayloadCanonical, wantCanonicalA2)
	}

	// Prev-hash links: genesis is NULL, the chained event carries the verified
	// hash of the preceding event.
	if evA1.PrevEventHash != nil {
		t.Errorf("genesis PrevEventHash = %x, want nil", *evA1.PrevEventHash)
	}
	if evA2.PrevEventHash == nil || *evA2.PrevEventHash != evA1.EventHash {
		t.Errorf("evA2 PrevEventHash = %v, want the verified predecessor hash %x", evA2.PrevEventHash, evA1.EventHash)
	}
	if evB1.PrevEventHash != nil {
		t.Errorf("stream B genesis PrevEventHash = %x, want nil", *evB1.PrevEventHash)
	}

	// Versioned event hashes recomputed independently with hashLedgerBlock.
	wantA1, err := hashLedgerBlock(ledgerHashInput{
		StreamID: "game-events", Sequence: 1, EventID: "evt-a-0001", EventType: "ledger.appended",
		PayloadHash: evA1.PayloadHash,
	})
	if err != nil {
		t.Fatalf("hashLedgerBlock(evt-a-0001): %v", err)
	}
	if evA1.EventHash != wantA1 {
		t.Errorf("evA1 EventHash = %x, want %x", evA1.EventHash, wantA1)
	}
	wantA2, err := hashLedgerBlock(ledgerHashInput{
		StreamID: "game-events", Sequence: 2, EventID: "evt-a-0002", EventType: "ledger.appended",
		PayloadHash: evA2.PayloadHash, PrevHash: &evA1.EventHash,
	})
	if err != nil {
		t.Fatalf("hashLedgerBlock(evt-a-0002): %v", err)
	}
	if evA2.EventHash != wantA2 {
		t.Errorf("evA2 EventHash = %x, want %x", evA2.EventHash, wantA2)
	}

	// The live SQL hash function agrees with the Go digest for the chained event.
	var sqlHash []byte
	if err := pool.QueryRow(ctx,
		"SELECT aipt.ledger_event_hash_v1($1, $2, $3, $4, $5, $6)",
		"game-events", int64(2), "evt-a-0002", "ledger.appended", evA2.PayloadHash[:], evA1.EventHash[:]).
		Scan(&sqlHash); err != nil {
		t.Fatalf("call aipt.ledger_event_hash_v1: %v", err)
	}
	if !bytes.Equal(sqlHash, evA2.EventHash[:]) {
		t.Errorf("SQL hash function = %x, want Go digest %x", sqlHash, evA2.EventHash)
	}

	// Database rows carry exactly the committed data.
	rowsA, err := queryLedgerEvents(ctx, pool, "game-events")
	if err != nil {
		t.Fatalf("read stream A events: %v", err)
	}
	if len(rowsA) != 2 {
		t.Fatalf("stream A rows = %d, want 2", len(rowsA))
	}
	assertRowMatchesEvent(t, "stream A genesis", rowsA[0], evA1)
	assertRowMatchesEvent(t, "stream A second", rowsA[1], evA2)
	rowsB, err := queryLedgerEvents(ctx, pool, "audit-log")
	if err != nil {
		t.Fatalf("read stream B events: %v", err)
	}
	if len(rowsB) != 1 {
		t.Fatalf("stream B rows = %d, want 1", len(rowsB))
	}
	assertRowMatchesEvent(t, "stream B genesis", rowsB[0], evB1)

	// Cursors advance to the exact committed tail.
	curA, err := queryLedgerCursor(ctx, pool, "game-events")
	if err != nil {
		t.Fatalf("read stream A cursor: %v", err)
	}
	if curA.lastSequence != 2 || !bytes.Equal(curA.lastEventHash, evA2.EventHash[:]) {
		t.Errorf("stream A cursor = (%d, %x), want (2, %x)", curA.lastSequence, curA.lastEventHash, evA2.EventHash)
	}
	curB, err := queryLedgerCursor(ctx, pool, "audit-log")
	if err != nil {
		t.Fatalf("read stream B cursor: %v", err)
	}
	if curB.lastSequence != 1 || !bytes.Equal(curB.lastEventHash, evB1.EventHash[:]) {
		t.Errorf("stream B cursor = (%d, %x), want (1, %x)", curB.lastSequence, curB.lastEventHash, evB1.EventHash)
	}

	// VerifyStream returns the exact independent tails and counts: no
	// cross-stream chain (A's count is 2, never 3) and distinct tails.
	vsA := ledgerVerifyLive(t, ctx, pool, "game-events")
	if vsA.Sequence != 2 || vsA.EventCount != 2 {
		t.Errorf("stream A verified = (%d, %d), want (2, 2)", vsA.Sequence, vsA.EventCount)
	}
	if vsA.EventHash == nil || *vsA.EventHash != evA2.EventHash {
		t.Errorf("stream A verified tail = %v, want %x", vsA.EventHash, evA2.EventHash)
	}
	vsB := ledgerVerifyLive(t, ctx, pool, "audit-log")
	if vsB.Sequence != 1 || vsB.EventCount != 1 {
		t.Errorf("stream B verified = (%d, %d), want (1, 1)", vsB.Sequence, vsB.EventCount)
	}
	if vsB.EventHash == nil || *vsB.EventHash != evB1.EventHash {
		t.Errorf("stream B verified tail = %v, want %x", vsB.EventHash, evB1.EventHash)
	}
	if vsA.EventHash == nil || vsB.EventHash == nil || *vsA.EventHash == *vsB.EventHash {
		t.Error("independent streams must verify to distinct tails")
	}
}

// TestPostgresIntegrationLedgerDuplicateEventIDPreservesUniqueViolation covers
// a live duplicate event_id: the database unique violation (SQLSTATE 23505) is
// preserved, the failed transaction inserts no event and neither advances nor
// alters the locked stream cursor, and VerifyStream still succeeds on the
// preexisting chain.
func TestPostgresIntegrationLedgerDuplicateEventIDPreservesUniqueViolation(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	genesis := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-dup-0001", `{"n":1}`))

	// Same event_id with a different payload and event type: valid input, so
	// the append reaches the database and must fail on the UNIQUE (event_id)
	// constraint.
	dupIn := AppendInput{
		StreamID:    "game-events",
		EventID:     "evt-dup-0001",
		EventType:   "other.type",
		PayloadJSON: []byte(`{"n":2}`),
	}
	ev, err := Append(ctx, pool, dupIn)
	if err == nil {
		t.Fatal("duplicate event_id must be rejected")
	}
	if ev != (LedgerEvent{}) {
		t.Errorf("failed append must return the zero event, got %+v", ev)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("duplicate error = %v, want the database unique violation preserved", err)
	}
	if pgErr.Code != "23505" {
		t.Errorf("preserved SQLSTATE = %q, want 23505", pgErr.Code)
	}
	if pgErr.ConstraintName != "ledger_events_event_id_key" {
		t.Errorf("violated constraint = %q, want ledger_events_event_id_key", pgErr.ConstraintName)
	}

	// The failed transaction inserted no event.
	rows, err := queryLedgerEvents(ctx, pool, "game-events")
	if err != nil {
		t.Fatalf("read stream events: %v", err)
	}
	if len(rows) != 1 || rows[0].sequence != 1 || rows[0].eventID != "evt-dup-0001" {
		t.Errorf("after duplicate append: %d rows (first %+v), want exactly the single genesis row", len(rows), rows)
	}

	// The locked stream cursor was neither advanced nor altered.
	cur, err := queryLedgerCursor(ctx, pool, "game-events")
	if err != nil {
		t.Fatalf("read stream cursor: %v", err)
	}
	if cur.lastSequence != 1 || !bytes.Equal(cur.lastEventHash, genesis.EventHash[:]) {
		t.Errorf("cursor after duplicate append = (%d, %x), want (1, %x)",
			cur.lastSequence, cur.lastEventHash, genesis.EventHash)
	}

	// VerifyStream still succeeds on the preexisting chain.
	vs := ledgerVerifyLive(t, ctx, pool, "game-events")
	if vs.Sequence != 1 || vs.EventCount != 1 {
		t.Errorf("verified = (%d, %d), want (1, 1)", vs.Sequence, vs.EventCount)
	}
	if vs.EventHash == nil || *vs.EventHash != genesis.EventHash {
		t.Errorf("verified tail = %v, want %x", vs.EventHash, genesis.EventHash)
	}
}

// TestPostgresIntegrationLedgerInvalidPayloadRejectedBeforeDatabase proves
// strict payload canonicalization runs before any pool or transaction access:
// every rejected payload returns the protocol package's typed reason even for
// a nil pool, never the nil-pool error, with a zero event result.
func TestPostgresIntegrationLedgerInvalidPayloadRejectedBeforeDatabase(t *testing.T) {
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
			in := ledgerAppendInput("game-events", "evt-invalid-0001", tc.raw)
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

// TestPostgresIntegrationLedgerConcurrentSameStreamAppends releases at least
// 16 unique Append goroutines from a barrier, registers the teardown cleanup
// before any goroutine starts (after the pool-close defer, so it runs first
// via LIFO and cancels plus boundedly drains every started-but-not-yet-
// received appender under an independent background timeout before the pool
// closes, without double-draining on success), joins every started goroutine
// under a bounded context, requires every Append to succeed, and proves the
// returned and stored sequences are exactly 1..N with unique event IDs (no
// loss, no fork, no duplicates), coherent prev_hash links, a cursor at N, and
// an exact VerifyStream count/tail. It never assumes goroutine-to-sequence
// ordering: the assertions hold for every interleaving.
func TestPostgresIntegrationLedgerConcurrentSameStreamAppends(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const n = 16
	// One connection per appender plus margin for the test's own queries, so
	// every goroutine can hold its transaction connection concurrently.
	pool := ledgerNewPool(ctx, t, fx, n+2)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	const streamID = "concurrent-stream"
	// Appender work runs on its own cancellable context so the teardown can
	// abort an appender that is stuck even after the test context has already
	// failed.
	appendCtx, appendCancel := context.WithCancel(ctx)

	start := make(chan struct{}) // barrier: release all appenders at once
	type appendOutcome struct {
		idx int
		ev  LedgerEvent
		err error
	}
	// Buffered to n: every started appender can always hand off its single
	// result without blocking, so the teardown drain can never deadlock on a
	// send.
	results := make(chan appendOutcome, n)
	// started/received are only ever touched by the test goroutine (the
	// appenders never see them), so they are race-safe.
	var started, received int

	// Cleanup is registered before any goroutine starts but after the
	// pool-close defer, so LIFO runs it first, before pool.Close: it cancels
	// every still-running appender and then drains every started-but-not-yet-
	// received result under an independent bounded background timeout (never
	// the already-canceled test context), so pool.Close can never wait forever
	// for a stuck appender's connection. On the success path the test body has
	// already received all n results, so the drain is a no-op and no result is
	// double-read.
	defer func() {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer drainCancel()
		appendCancel() // abort in-flight appender work
		for received < started {
			select {
			case <-results:
				received++
			case <-drainCtx.Done():
				t.Errorf("teardown: concurrent append %d did not finish within 30s: %v",
					received+1, drainCtx.Err())
				return
			}
		}
	}()

	for i := 0; i < n; i++ {
		started++
		go func(idx int) {
			<-start
			ev, err := Append(appendCtx, pool, ledgerAppendInput(
				streamID,
				fmt.Sprintf("evt-concurrent-%02d", idx),
				fmt.Sprintf(`{"i":%d}`, idx),
			))
			results <- appendOutcome{idx: idx, ev: ev, err: err}
		}(i)
	}
	close(start)

	// Join every started goroutine under the bounded context.
	outcomes := make([]appendOutcome, 0, n)
	for received < started {
		select {
		case out := <-results:
			received++
			outcomes = append(outcomes, out)
		case <-ctx.Done():
			t.Fatalf("waiting for concurrent append %d of %d: %v", received+1, n, ctx.Err())
		}
	}

	// Every Append must succeed.
	for _, out := range outcomes {
		if out.err != nil {
			t.Errorf("concurrent append %d (evt-concurrent-%02d) failed: %v", out.idx, out.idx, out.err)
		}
	}

	// Returned sequences are exactly 1..N, independent of goroutine order.
	seqs := make([]int64, 0, n)
	seenSeq := make(map[int64]bool, n)
	for _, out := range outcomes {
		if out.err != nil {
			continue
		}
		seqs = append(seqs, out.ev.Sequence)
		seenSeq[out.ev.Sequence] = true
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	if len(seqs) != n {
		t.Fatalf("successful appends = %d, want exactly %d", len(seqs), n)
	}
	for i, s := range seqs {
		if s != int64(i+1) {
			t.Errorf("returned sequences = %v, want exactly 1..%d", seqs, n)
			break
		}
	}
	if len(seenSeq) != n {
		t.Errorf("returned sequences contain %d distinct values, want %d (no fork/duplicate)", len(seenSeq), n)
	}

	// Stored rows: sequences exactly 1..N with coherent prev-hash links.
	rows, err := queryLedgerEvents(ctx, pool, streamID)
	if err != nil {
		t.Fatalf("read concurrent stream events: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("stored rows = %d, want %d", len(rows), n)
	}
	storedIDs := make(map[string]bool, n)
	for i, r := range rows {
		if r.sequence != int64(i+1) {
			t.Errorf("stored row %d sequence = %d, want %d (no loss/gap)", i, r.sequence, i+1)
		}
		if storedIDs[r.eventID] {
			t.Errorf("duplicate stored event_id %q", r.eventID)
		}
		storedIDs[r.eventID] = true
		if i == 0 {
			if r.prevEventHash != nil {
				t.Errorf("genesis prev_event_hash = %x, want SQL NULL", r.prevEventHash)
			}
		} else if !bytes.Equal(r.prevEventHash, rows[i-1].eventHash) {
			t.Errorf("row %d prev_event_hash %x does not link to row %d event_hash %x",
				i+1, r.prevEventHash, i, rows[i-1].eventHash)
		}
	}

	// Every returned event matches its stored row by event_id: the stored
	// sequence and hashes are exactly what Append returned.
	byID := make(map[string]ledgerEventRow, n)
	for _, r := range rows {
		byID[r.eventID] = r
	}
	for _, out := range outcomes {
		if out.err != nil {
			continue
		}
		r, ok := byID[out.ev.EventID]
		if !ok {
			t.Errorf("stored row for returned event %q not found", out.ev.EventID)
			continue
		}
		if r.sequence != out.ev.Sequence {
			t.Errorf("stored sequence %d for event %q, want returned %d", r.sequence, out.ev.EventID, out.ev.Sequence)
		}
		if !bytes.Equal(r.eventHash, out.ev.EventHash[:]) {
			t.Errorf("stored event_hash %x for event %q, want returned %x", r.eventHash, out.ev.EventID, out.ev.EventHash)
		}
		if r.payloadCanonical != out.ev.PayloadCanonical {
			t.Errorf("stored payload_canonical %q for event %q, want returned %q",
				r.payloadCanonical, out.ev.EventID, out.ev.PayloadCanonical)
		}
	}

	// Cursor at N with the tail hash.
	cur, err := queryLedgerCursor(ctx, pool, streamID)
	if err != nil {
		t.Fatalf("read concurrent stream cursor: %v", err)
	}
	if cur.lastSequence != n || !bytes.Equal(cur.lastEventHash, rows[n-1].eventHash) {
		t.Errorf("cursor = (%d, %x), want (%d, %x)", cur.lastSequence, cur.lastEventHash, n, rows[n-1].eventHash)
	}

	// VerifyStream count and tail are exact.
	vs := ledgerVerifyLive(t, ctx, pool, streamID)
	if vs.Sequence != n || vs.EventCount != n {
		t.Errorf("verified = (%d, %d), want (%d, %d)", vs.Sequence, vs.EventCount, n, n)
	}
	if vs.EventHash == nil || !bytes.Equal(vs.EventHash[:], rows[n-1].eventHash) {
		t.Errorf("verified tail = %v, want %x", vs.EventHash, rows[n-1].eventHash)
	}
}

// TestPostgresIntegrationLedgerMultiStreamIsolation interleaves appends across
// three independent streams and proves each genesis previous hash is NULL,
// every subsequent previous hash links only to that stream's own prior event,
// the cursors/counts/tails are isolated per stream, and VerifyStream succeeds
// independently for each stream with exact results.
func TestPostgresIntegrationLedgerMultiStreamIsolation(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	// Interleaved appends: no stream's chain depends on another stream's rows.
	evA1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("alpha", "alpha-0001", `{"s":"alpha","n":1}`))
	evB1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("beta", "beta-0001", `{"s":"beta","n":1}`))
	evA2 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("alpha", "alpha-0002", `{"s":"alpha","n":2}`))
	evC1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("gamma", "gamma-0001", `{"s":"gamma","n":1}`))
	evB2 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("beta", "beta-0002", `{"s":"beta","n":2}`))
	evA3 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("alpha", "alpha-0003", `{"s":"alpha","n":3}`))

	// Exact per-stream sequences.
	if evA1.Sequence != 1 || evA2.Sequence != 2 || evA3.Sequence != 3 {
		t.Errorf("alpha sequences = (%d, %d, %d), want (1, 2, 3)", evA1.Sequence, evA2.Sequence, evA3.Sequence)
	}
	if evB1.Sequence != 1 || evB2.Sequence != 2 {
		t.Errorf("beta sequences = (%d, %d), want (1, 2)", evB1.Sequence, evB2.Sequence)
	}
	if evC1.Sequence != 1 {
		t.Errorf("gamma sequence = %d, want 1", evC1.Sequence)
	}

	// Every genesis previous hash is NULL.
	if evA1.PrevEventHash != nil || evB1.PrevEventHash != nil || evC1.PrevEventHash != nil {
		t.Error("every genesis event must have a nil PrevEventHash")
	}

	// Subsequent previous hashes link only to that stream's own prior event.
	if evA2.PrevEventHash == nil || *evA2.PrevEventHash != evA1.EventHash {
		t.Errorf("alpha-0002 prev = %v, want alpha-0001 hash %x", evA2.PrevEventHash, evA1.EventHash)
	}
	if evA3.PrevEventHash == nil || *evA3.PrevEventHash != evA2.EventHash {
		t.Errorf("alpha-0003 prev = %v, want alpha-0002 hash %x", evA3.PrevEventHash, evA2.EventHash)
	}
	if evB2.PrevEventHash == nil || *evB2.PrevEventHash != evB1.EventHash {
		t.Errorf("beta-0002 prev = %v, want beta-0001 hash %x", evB2.PrevEventHash, evB1.EventHash)
	}

	// Per-stream database rows, cursors, and independent VerifyStream results.
	streams := []struct {
		streamID string
		events   []LedgerEvent
	}{
		{"alpha", []LedgerEvent{evA1, evA2, evA3}},
		{"beta", []LedgerEvent{evB1, evB2}},
		{"gamma", []LedgerEvent{evC1}},
	}
	tails := make(map[string][32]byte, len(streams))
	for _, sc := range streams {
		rows, err := queryLedgerEvents(ctx, pool, sc.streamID)
		if err != nil {
			t.Fatalf("read %s events: %v", sc.streamID, err)
		}
		if len(rows) != len(sc.events) {
			t.Errorf("%s rows = %d, want %d", sc.streamID, len(rows), len(sc.events))
			continue
		}
		for i, r := range rows {
			assertRowMatchesEvent(t, sc.streamID+" row "+fmt.Sprint(i), r, sc.events[i])
			if i == 0 {
				if r.prevEventHash != nil {
					t.Errorf("%s genesis prev_event_hash = %x, want SQL NULL", sc.streamID, r.prevEventHash)
				}
			} else if !bytes.Equal(r.prevEventHash, sc.events[i-1].EventHash[:]) {
				t.Errorf("%s row %d prev_event_hash %x does not link to its own prior event %x",
					sc.streamID, i+1, r.prevEventHash, sc.events[i-1].EventHash)
			}
		}
		cur, err := queryLedgerCursor(ctx, pool, sc.streamID)
		if err != nil {
			t.Fatalf("read %s cursor: %v", sc.streamID, err)
		}
		tail := sc.events[len(sc.events)-1]
		if cur.lastSequence != int64(len(sc.events)) || !bytes.Equal(cur.lastEventHash, tail.EventHash[:]) {
			t.Errorf("%s cursor = (%d, %x), want (%d, %x)",
				sc.streamID, cur.lastSequence, cur.lastEventHash, len(sc.events), tail.EventHash)
		}
		vs := ledgerVerifyLive(t, ctx, pool, sc.streamID)
		if vs.Sequence != int64(len(sc.events)) || vs.EventCount != int64(len(sc.events)) {
			t.Errorf("%s verified = (%d, %d), want (%d, %d)",
				sc.streamID, vs.Sequence, vs.EventCount, len(sc.events), len(sc.events))
		}
		if vs.EventHash == nil || *vs.EventHash != tail.EventHash {
			t.Errorf("%s verified tail = %v, want %x", sc.streamID, vs.EventHash, tail.EventHash)
		}
		tails[sc.streamID] = tail.EventHash
	}

	// No cross-stream chain: every stream verifies to a distinct [32]byte tail
	// hash. A collision would mean two streams ended on the same verified tail
	// -- e.g. verification served one stream's chain for another -- so the
	// uniqueness is asserted keyed by the exact tail hash bytes and tied back
	// to the stream IDs that produced them.
	seenTail := make(map[[32]byte]string, len(streams))
	for streamID, h := range tails {
		if other, dup := seenTail[h]; dup {
			t.Errorf("streams %q and %q verify to the same tail hash %x", other, streamID, h)
		}
		seenTail[h] = streamID
	}
	if len(seenTail) != len(streams) {
		t.Errorf("distinct verified tail hashes = %d, want %d", len(seenTail), len(streams))
	}
}

// TestPostgresIntegrationLedgerAppendOnlyDMLGates proves the append-only
// statement trigger rejects every UPDATE, DELETE, and TRUNCATE of
// aipt.ledger_events -- including zero-row statements and statements matching
// committed rows -- with SQLSTATE 55000 and the stable code
// AIPT_LEDGER_APPEND_ONLY, and that the rejected statements change nothing.
func TestPostgresIntegrationLedgerAppendOnlyDMLGates(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	// Zero-row statements against the empty table are still rejected at the
	// statement level.
	assertLedgerAppendOnlyRejected(t, ctx, pool, "UPDATE aipt.ledger_events SET event_type = 'x'")
	assertLedgerAppendOnlyRejected(t, ctx, pool, "UPDATE aipt.ledger_events SET event_type = 'x' WHERE event_id = $1", "missing")
	assertLedgerAppendOnlyRejected(t, ctx, pool, "DELETE FROM aipt.ledger_events")
	assertLedgerAppendOnlyRejected(t, ctx, pool, "DELETE FROM aipt.ledger_events WHERE event_id = $1", "missing")
	assertLedgerAppendOnlyRejected(t, ctx, pool, "TRUNCATE aipt.ledger_events")

	// Statements matching a committed row are rejected identically.
	ev := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-gate-0001", `{"n":1}`))
	assertLedgerAppendOnlyRejected(t, ctx, pool, "UPDATE aipt.ledger_events SET event_type = 'x' WHERE event_id = $1", "evt-gate-0001")
	assertLedgerAppendOnlyRejected(t, ctx, pool, "DELETE FROM aipt.ledger_events WHERE event_id = $1", "evt-gate-0001")
	assertLedgerAppendOnlyRejected(t, ctx, pool, "TRUNCATE aipt.ledger_events")

	// The rejected statements changed nothing: the event row and cursor remain.
	rows, err := queryLedgerEvents(ctx, pool, "game-events")
	if err != nil {
		t.Fatalf("read stream events: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("after rejected DML: %d rows, want exactly 1", len(rows))
	}
	assertRowMatchesEvent(t, "surviving row", rows[0], ev)
	cur, err := queryLedgerCursor(ctx, pool, "game-events")
	if err != nil {
		t.Fatalf("read stream cursor: %v", err)
	}
	if cur.lastSequence != 1 || !bytes.Equal(cur.lastEventHash, ev.EventHash[:]) {
		t.Errorf("cursor after rejected DML = (%d, %x), want (1, %x)", cur.lastSequence, cur.lastEventHash, ev.EventHash)
	}
}

// TestPostgresIntegrationLedgerTamperPayloadCanonical replaces the stored
// canonical payload TEXT of a committed event in the ephemeral database and
// proves VerifyStream fails with the typed AIPT_LEDGER_PAYLOAD_HASH_MISMATCH
// error and a zero VerifiedStream. The append-only trigger is disabled and
// only the payload digest check constraint is dropped: every other migration
// constraint stays intact.
func TestPostgresIntegrationLedgerTamperPayloadCanonical(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0001", `{"n":1}`))
	ev2 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0002", `{"n":2}`))

	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DISABLE TRIGGER ledger_events_append_only"); err != nil {
		t.Fatalf("disable append-only trigger: %v", err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DROP CONSTRAINT ledger_events_payload_sha256_check"); err != nil {
		t.Fatalf("drop payload digest check: %v", err)
	}

	// Replace the stored TEXT of the second event; the recorded 32-byte
	// payload_sha256 is unchanged, so verification reaches the semantic
	// payload-hash mismatch rather than a malformed-hash error.
	const tampered = `{"tampered":true}`
	if _, err := pool.Exec(ctx,
		"UPDATE aipt.ledger_events SET payload_canonical = $1 WHERE stream_id = $2 AND sequence = 2",
		tampered, "game-events"); err != nil {
		t.Fatalf("tamper payload_canonical: %v", err)
	}

	vs, err := VerifyStream(ctx, pool, VerifyInput{StreamID: "game-events"})
	if err == nil {
		t.Fatal("tampered payload must fail verification")
	}
	if vs != (VerifiedStream{}) {
		t.Errorf("failed verification must return the zero result, got %+v", vs)
	}
	if !errors.Is(err, ErrLedgerPayloadHashMismatch) {
		t.Fatalf("error = %v, want errors.Is(ErrLedgerPayloadHashMismatch)", err)
	}
	var typed *LedgerPayloadHashMismatchError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" || typed.Sequence != 2 {
		t.Errorf("typed = %+v, want stream game-events sequence 2", typed)
	}
	if want := sha256.Sum256([]byte(tampered)); typed.Expected == nil || *typed.Expected != want {
		t.Errorf("typed.Expected = %v, want the digest of the stored tampered text %x", typed.Expected, want)
	}
	if typed.Actual == nil || !bytes.Equal(typed.Actual[:], ev2.PayloadHash[:]) {
		t.Errorf("typed.Actual = %v, want the recorded payload hash %x", typed.Actual, ev2.PayloadHash)
	}
}

// TestPostgresIntegrationLedgerTamperPrevEventHash replaces the recorded
// prev_event_hash of a chained event with a valid 32-byte hash and proves
// VerifyStream fails with the typed AIPT_LEDGER_PREV_HASH_MISMATCH error and a
// zero VerifiedStream. The append-only trigger is disabled and only the
// versioned event-hash check constraint is dropped.
func TestPostgresIntegrationLedgerTamperPrevEventHash(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	ev1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0001", `{"n":1}`))
	ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0002", `{"n":2}`))

	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DISABLE TRIGGER ledger_events_append_only"); err != nil {
		t.Fatalf("disable append-only trigger: %v", err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DROP CONSTRAINT ledger_events_event_hash_check"); err != nil {
		t.Fatalf("drop event hash check: %v", err)
	}

	// A valid 32-byte replacement previous hash, distinct from the real
	// predecessor, so verification reports the prev-hash mismatch (checked
	// before the event-hash recomputation) instead of a malformed hash.
	var tampered [32]byte = fillHash(0xA5)
	if tampered == ev1.EventHash {
		t.Fatal("tamper hash must differ from the real predecessor hash")
	}
	if _, err := pool.Exec(ctx,
		"UPDATE aipt.ledger_events SET prev_event_hash = $1 WHERE stream_id = $2 AND sequence = 2",
		tampered[:], "game-events"); err != nil {
		t.Fatalf("tamper prev_event_hash: %v", err)
	}

	vs, err := VerifyStream(ctx, pool, VerifyInput{StreamID: "game-events"})
	if err == nil {
		t.Fatal("tampered prev_event_hash must fail verification")
	}
	if vs != (VerifiedStream{}) {
		t.Errorf("failed verification must return the zero result, got %+v", vs)
	}
	if !errors.Is(err, ErrLedgerPrevHashMismatch) {
		t.Fatalf("error = %v, want errors.Is(ErrLedgerPrevHashMismatch)", err)
	}
	var typed *LedgerPrevHashMismatchError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" || typed.Sequence != 2 {
		t.Errorf("typed = %+v, want stream game-events sequence 2", typed)
	}
	if typed.Expected == nil || *typed.Expected != ev1.EventHash {
		t.Errorf("typed.Expected = %v, want the verified predecessor hash %x", typed.Expected, ev1.EventHash)
	}
	if typed.Actual == nil || *typed.Actual != tampered {
		t.Errorf("typed.Actual = %v, want the recorded tampered hash %x", typed.Actual, tampered)
	}
}

// TestPostgresIntegrationLedgerTamperEventHash replaces the recorded event_hash
// of the genesis event with a valid 32-byte hash and proves VerifyStream fails
// with the typed AIPT_LEDGER_EVENT_HASH_MISMATCH error and a zero
// VerifiedStream. The append-only trigger is disabled and only the versioned
// event-hash check constraint is dropped.
func TestPostgresIntegrationLedgerTamperEventHash(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	ev1 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0001", `{"n":1}`))
	ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0002", `{"n":2}`))

	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DISABLE TRIGGER ledger_events_append_only"); err != nil {
		t.Fatalf("disable append-only trigger: %v", err)
	}
	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DROP CONSTRAINT ledger_events_event_hash_check"); err != nil {
		t.Fatalf("drop event hash check: %v", err)
	}

	// A valid 32-byte replacement event hash, distinct from the real digest,
	// so verification reports the event-hash mismatch (payload and prev checks
	// pass first) instead of a malformed hash.
	var tampered [32]byte = fillHash(0xB6)
	if tampered == ev1.EventHash {
		t.Fatal("tamper hash must differ from the real event hash")
	}
	if _, err := pool.Exec(ctx,
		"UPDATE aipt.ledger_events SET event_hash = $1 WHERE stream_id = $2 AND sequence = 1",
		tampered[:], "game-events"); err != nil {
		t.Fatalf("tamper event_hash: %v", err)
	}

	vs, err := VerifyStream(ctx, pool, VerifyInput{StreamID: "game-events"})
	if err == nil {
		t.Fatal("tampered event_hash must fail verification")
	}
	if vs != (VerifiedStream{}) {
		t.Errorf("failed verification must return the zero result, got %+v", vs)
	}
	if !errors.Is(err, ErrLedgerEventHashMismatch) {
		t.Fatalf("error = %v, want errors.Is(ErrLedgerEventHashMismatch)", err)
	}
	var typed *LedgerEventHashMismatchError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" || typed.Sequence != 1 {
		t.Errorf("typed = %+v, want stream game-events sequence 1", typed)
	}
	if typed.Expected == nil || *typed.Expected != ev1.EventHash {
		t.Errorf("typed.Expected = %v, want the recomputed digest %x", typed.Expected, ev1.EventHash)
	}
	if typed.Actual == nil || *typed.Actual != tampered {
		t.Errorf("typed.Actual = %v, want the recorded tampered hash %x", typed.Actual, tampered)
	}
}

// TestPostgresIntegrationLedgerTamperCursor rewinds the ledger_streams cursor
// of a two-event stream and proves VerifyStream fails with the typed
// AIPT_LEDGER_CURSOR_MISMATCH error and a zero VerifiedStream. No trigger
// disabling or constraint drop is needed: ledger_streams carries no
// append-only trigger and the cursor invariant still holds after the tamper
// (the stored tail hash is retained, only the sequence drifts).
func TestPostgresIntegrationLedgerTamperCursor(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0001", `{"n":1}`))
	ev2 := ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0002", `{"n":2}`))

	// Rewind only the cursor sequence; the cursor hash stays the verified tail
	// hash, so the cursor invariant (sequence > 0 with non-NULL 32-byte hash)
	// still holds and no constraint change is required.
	if _, err := pool.Exec(ctx,
		"UPDATE aipt.ledger_streams SET last_sequence = 1 WHERE stream_id = $1",
		"game-events"); err != nil {
		t.Fatalf("tamper ledger_streams cursor: %v", err)
	}

	vs, err := VerifyStream(ctx, pool, VerifyInput{StreamID: "game-events"})
	if err == nil {
		t.Fatal("tampered cursor must fail verification")
	}
	if vs != (VerifiedStream{}) {
		t.Errorf("failed verification must return the zero result, got %+v", vs)
	}
	if !errors.Is(err, ErrLedgerCursorMismatch) {
		t.Fatalf("error = %v, want errors.Is(ErrLedgerCursorMismatch)", err)
	}
	var typed *LedgerCursorMismatchError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" {
		t.Errorf("typed.StreamID = %q, want game-events", typed.StreamID)
	}
	if typed.CursorSequence != 1 {
		t.Errorf("typed.CursorSequence = %d, want the tampered 1", typed.CursorSequence)
	}
	if typed.TailSequence != 2 || !typed.TailPresent {
		t.Errorf("typed tail = (sequence %d, present %t), want (2, true)", typed.TailSequence, typed.TailPresent)
	}
	// The stored cursor hash and the verified tail hash are both the real tail
	// hash: only the sequence drifted.
	if typed.CursorHash == nil || *typed.CursorHash != ev2.EventHash {
		t.Errorf("typed.CursorHash = %v, want the retained tail hash %x", typed.CursorHash, ev2.EventHash)
	}
	if typed.TailHash == nil || *typed.TailHash != ev2.EventHash {
		t.Errorf("typed.TailHash = %v, want the verified tail hash %x", typed.TailHash, ev2.EventHash)
	}
}

// TestPostgresIntegrationLedgerTamperSequenceGap deletes the genesis event row
// and proves VerifyStream fails with the typed AIPT_LEDGER_SEQUENCE_GAP error
// and a zero VerifiedStream. The append-only trigger is disabled (the only
// gate on DELETE); no constraint is dropped.
func TestPostgresIntegrationLedgerTamperSequenceGap(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool := fx.pool(ctx)
	defer pool.Close()

	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp on fresh ephemeral database: %v", err)
	}

	ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0001", `{"n":1}`))
	ledgerAppendLive(t, ctx, pool, ledgerAppendInput("game-events", "evt-tamper-0002", `{"n":2}`))

	if _, err := pool.Exec(ctx, "ALTER TABLE aipt.ledger_events DISABLE TRIGGER ledger_events_append_only"); err != nil {
		t.Fatalf("disable append-only trigger: %v", err)
	}

	// Delete the genesis row: the stream then starts at sequence 2, so the
	// first verified event is a gap from the expected sequence 1.
	if _, err := pool.Exec(ctx,
		"DELETE FROM aipt.ledger_events WHERE stream_id = $1 AND sequence = 1",
		"game-events"); err != nil {
		t.Fatalf("tamper sequence gap: %v", err)
	}

	vs, err := VerifyStream(ctx, pool, VerifyInput{StreamID: "game-events"})
	if err == nil {
		t.Fatal("a sequence gap must fail verification")
	}
	if vs != (VerifiedStream{}) {
		t.Errorf("failed verification must return the zero result, got %+v", vs)
	}
	if !errors.Is(err, ErrLedgerSequenceGap) {
		t.Fatalf("error = %v, want errors.Is(ErrLedgerSequenceGap)", err)
	}
	var typed *LedgerSequenceGapError
	if !errors.As(err, &typed) {
		t.Fatalf("error = %v, want recoverable via errors.As", err)
	}
	if typed.StreamID != "game-events" || typed.Expected != 1 || typed.Actual != 2 {
		t.Errorf("typed = %+v, want stream game-events expected 1 actual 2", typed)
	}
}
