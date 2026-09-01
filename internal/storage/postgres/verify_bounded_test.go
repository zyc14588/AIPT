package postgres

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

const (
	testMaxEventPayloadBytes = int64(1 << 20)
	testMaxTotalPayloadBytes = int64(64 << 20)
)

type boundedVerifyFakeTx struct {
	*fakeVerifyTx
	maxPayloadBytes   int64
	totalPayloadBytes int64
	sizeErr           error
}

func (tx *boundedVerifyFakeTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if strings.Contains(sql, "MAX(payload_bytes)") {
		tx.queryCalls = append(tx.queryCalls, verifyCall{sql: sql, args: args})
		return &fakeVerifyRow{values: []any{tx.maxPayloadBytes, tx.totalPayloadBytes}, err: tx.sizeErr}
	}
	return tx.fakeVerifyTx.QueryRow(ctx, sql, args...)
}

func newBoundedVerifyChainTx(streamID string, events []verifyEvent) *boundedVerifyFakeTx {
	tx, _ := newVerifyChainTx(streamID, events)
	bounded := &boundedVerifyFakeTx{fakeVerifyTx: tx}
	for _, event := range events {
		bytes := int64(len(event.payloadCanonical))
		if bytes > bounded.maxPayloadBytes {
			bounded.maxPayloadBytes = bytes
		}
		bounded.totalPayloadBytes += bytes
	}
	return bounded
}

func boundedVerifyInput(streamID string, maxEvents int64) BoundedVerifyInput {
	return BoundedVerifyInput{
		StreamID: streamID, MaxEvents: maxEvents,
		MaxEventPayloadBytes: testMaxEventPayloadBytes,
		MaxTotalPayloadBytes: testMaxTotalPayloadBytes,
	}
}

func TestVerifyStreamBoundedRejectsCursorBeforeEventQuery(t *testing.T) {
	tx := newBoundedVerifyChainTx("game-events", []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	})
	result, err := verifyStreamTxAtMost(context.Background(), tx, boundedVerifyInput("game-events", 1))
	if err == nil || !strings.Contains(err.Error(), "exceeds configured bound 1") {
		t.Fatalf("bounded verification error = %v", err)
	}
	if result != (VerifiedStream{}) {
		t.Fatalf("bounded verification returned nonzero result: %+v", result)
	}
	if len(tx.queryCalls) != 1 {
		t.Fatalf("statements = %d, want cursor SELECT only", len(tx.queryCalls))
	}
}

func TestVerifyStreamBoundedDelegatesFrozenVerificationWithDefensiveLimit(t *testing.T) {
	tx := newBoundedVerifyChainTx("game-events", []verifyEvent{
		{"evt-0001", "ledger.appended", `{"a":1}`},
		{"evt-0002", "state.applied", `{"b":2}`},
	})
	result, err := verifyStreamTxAtMost(context.Background(), tx, boundedVerifyInput("game-events", 2))
	if err != nil {
		t.Fatalf("verifyStreamTxAtMost: %v", err)
	}
	if result.EventCount != 2 || result.Sequence != 2 {
		t.Fatalf("bounded result = %+v, want verified two-event tail", result)
	}
	if len(tx.queryCalls) != 4 {
		t.Fatalf("statements = %d, want cursor + payload-size preflight + frozen cursor + events", len(tx.queryCalls))
	}
	sizes := tx.queryCalls[1]
	if !strings.Contains(sizes.sql, "octet_length(payload_canonical)") || !strings.Contains(sizes.sql, "LIMIT $2") ||
		len(sizes.args) != 2 || sizes.args[0] != "game-events" || sizes.args[1] != int64(3) {
		t.Fatalf("payload-size preflight = %#v", sizes)
	}
	events := tx.queryCalls[3]
	if !strings.Contains(events.sql, "FROM aipt.ledger_events") || !strings.Contains(events.sql, "LIMIT $2") {
		t.Fatalf("bounded event query = %q", events.sql)
	}
	if len(events.args) != 2 || events.args[0] != "game-events" || events.args[1] != int64(3) {
		t.Fatalf("bounded event args = %#v, want [game-events 3]", events.args)
	}
}

func TestVerifyStreamBoundedRejectsNonpositiveLimitWithoutDatabaseWork(t *testing.T) {
	tx := newBoundedVerifyChainTx("game-events", nil)
	cases := []BoundedVerifyInput{
		boundedVerifyInput("game-events", 0),
		boundedVerifyInput("game-events", -1),
		boundedVerifyInput("game-events", math.MaxInt64),
		{StreamID: "game-events", MaxEvents: 1, MaxEventPayloadBytes: 0, MaxTotalPayloadBytes: 1},
		{StreamID: "game-events", MaxEvents: 1, MaxEventPayloadBytes: 1, MaxTotalPayloadBytes: 0},
		{StreamID: "game-events", MaxEvents: 1, MaxEventPayloadBytes: 2, MaxTotalPayloadBytes: 1},
	}
	for _, input := range cases {
		result, err := verifyStreamTxAtMost(context.Background(), tx, input)
		if err == nil || result != (VerifiedStream{}) {
			t.Fatalf("input %+v result=%+v error=%v", input, result, err)
		}
	}
	if len(tx.queryCalls) != 0 {
		t.Fatalf("invalid limits performed %d database statements", len(tx.queryCalls))
	}
}

func TestVerifyStreamBoundedRejectsPayloadBytesBeforeFullEventQuery(t *testing.T) {
	tx := newBoundedVerifyChainTx("game-events", []verifyEvent{
		{"evt-0001", "ledger.appended", strings.Repeat("x", 11)},
	})
	input := boundedVerifyInput("game-events", 1)
	input.MaxEventPayloadBytes = 10
	input.MaxTotalPayloadBytes = 100
	result, err := verifyStreamTxAtMost(context.Background(), tx, input)
	if err == nil || !strings.Contains(err.Error(), "per-event bound 10") || result != (VerifiedStream{}) {
		t.Fatalf("oversized payload result=%+v error=%v", result, err)
	}
	if len(tx.queryCalls) != 2 {
		t.Fatalf("statements = %d, want cursor and payload-size preflight only", len(tx.queryCalls))
	}
	for _, call := range tx.queryCalls {
		if strings.Contains(call.sql, "SELECT sequence, event_id, event_type, payload_canonical") {
			t.Fatalf("oversized payload reached full event query: %q", call.sql)
		}
	}
}

func TestVerifyStreamBoundedRejectsAggregatePayloadBytesBeforeFullEventQuery(t *testing.T) {
	tx := newBoundedVerifyChainTx("game-events", []verifyEvent{
		{"evt-0001", "ledger.appended", "123456"},
		{"evt-0002", "state.applied", "12345"},
	})
	input := boundedVerifyInput("game-events", 2)
	input.MaxEventPayloadBytes = 6
	input.MaxTotalPayloadBytes = 10
	result, err := verifyStreamTxAtMost(context.Background(), tx, input)
	if err == nil || !strings.Contains(err.Error(), "aggregate bound 10") || result != (VerifiedStream{}) {
		t.Fatalf("oversized aggregate result=%+v error=%v", result, err)
	}
	if len(tx.queryCalls) != 2 {
		t.Fatalf("statements = %d, want cursor and payload-size preflight only", len(tx.queryCalls))
	}
}

func TestVerifyStreamBoundedAcceptsExactPayloadBoundaries(t *testing.T) {
	tx := newBoundedVerifyChainTx("game-events", []verifyEvent{
		{"evt-0001", "ledger.appended", "12345"},
		{"evt-0002", "state.applied", "67890"},
	})
	input := boundedVerifyInput("game-events", 2)
	input.MaxEventPayloadBytes = 5
	input.MaxTotalPayloadBytes = 10
	result, err := verifyStreamTxAtMost(context.Background(), tx, input)
	if err != nil || result.EventCount != 2 {
		t.Fatalf("exact-boundary result=%+v error=%v", result, err)
	}
}
