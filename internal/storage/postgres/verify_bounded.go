package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BoundedVerifyInput is an additive caller-scoped guard around the frozen
// complete-stream VerifyStream contract. It is used by materializers which
// must reject an oversized stream before reading its event rows.
type BoundedVerifyInput struct {
	StreamID             string
	MaxEvents            int64
	MaxEventPayloadBytes int64
	MaxTotalPayloadBytes int64
}

// VerifyStreamBounded preserves VerifyStream's chain semantics while adding a
// deterministic event-count and payload-byte ceiling. The cursor/payload
// preflights and the frozen verifier run in the same RepeatableRead, read-only
// snapshot, so an append cannot race between either size decision and chain
// verification. The event query is additionally limited to MaxEvents+1 and
// its Rows iterator is capped at that same boundary.
func VerifyStreamBounded(ctx context.Context, pool *pgxpool.Pool, in BoundedVerifyInput) (VerifiedStream, error) {
	if err := validateTextField("stream_id", in.StreamID); err != nil {
		return VerifiedStream{}, err
	}
	if err := validateBoundedVerifyLimits(in); err != nil {
		return VerifiedStream{}, err
	}
	if pool == nil {
		return VerifiedStream{}, errors.New("VerifyStreamBounded: nil *pgxpool.Pool")
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	verified, err := verifyStreamTxAtMost(ctx, tx, in)
	if err != nil {
		return VerifiedStream{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: commit transaction: %w", err)
	}
	return verified, nil
}

func validateBoundedVerifyLimits(in BoundedVerifyInput) error {
	if in.MaxEvents <= 0 || in.MaxEvents == math.MaxInt64 {
		return errors.New("VerifyStreamBounded: max_events must be positive and leave room for a sentinel row")
	}
	if in.MaxEventPayloadBytes <= 0 {
		return errors.New("VerifyStreamBounded: max_event_payload_bytes must be positive")
	}
	if in.MaxTotalPayloadBytes <= 0 {
		return errors.New("VerifyStreamBounded: max_total_payload_bytes must be positive")
	}
	if in.MaxEventPayloadBytes > in.MaxTotalPayloadBytes {
		return errors.New("VerifyStreamBounded: max_event_payload_bytes must not exceed max_total_payload_bytes")
	}
	return nil
}

func verifyStreamTxAtMost(ctx context.Context, tx verifyTx, in BoundedVerifyInput) (VerifiedStream, error) {
	if err := validateBoundedVerifyLimits(in); err != nil {
		return VerifiedStream{}, err
	}
	var cursorSequence int64
	var cursorHash []byte
	switch err := tx.QueryRow(ctx,
		"SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1",
		in.StreamID).Scan(&cursorSequence, &cursorHash); {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: read ledger stream cursor: %w", &LedgerStreamNotFoundError{StreamID: in.StreamID})
	default:
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: read ledger stream cursor: %w", err)
	}
	if cursorSequence > in.MaxEvents {
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: ledger event count %d exceeds configured bound %d", cursorSequence, in.MaxEvents)
	}

	// Ask PostgreSQL for sizes only; no payload text crosses the client
	// boundary until both the per-event and aggregate budgets pass. LIMIT N+1
	// keeps this preflight bounded even when a corrupt cursor understates the
	// actual row count, and the frozen verifier subsequently detects that
	// cursor/row disagreement in the same RepeatableRead snapshot.
	var maxPayloadBytes int64
	var totalPayloadBytes int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(MAX(payload_bytes), 0)::bigint,
		       COALESCE(SUM(payload_bytes), 0)::bigint
		FROM (
			SELECT octet_length(payload_canonical) AS payload_bytes
			FROM aipt.ledger_events
			WHERE stream_id = $1
			ORDER BY sequence ASC
			LIMIT $2
		) AS bounded_events`, in.StreamID, in.MaxEvents+1).Scan(&maxPayloadBytes, &totalPayloadBytes); err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: preflight ledger payload sizes: %w", err)
	}
	if maxPayloadBytes < 0 || maxPayloadBytes > in.MaxEventPayloadBytes {
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: ledger event payload bytes %d exceed configured per-event bound %d", maxPayloadBytes, in.MaxEventPayloadBytes)
	}
	if totalPayloadBytes < 0 || totalPayloadBytes > in.MaxTotalPayloadBytes {
		return VerifiedStream{}, fmt.Errorf("VerifyStreamBounded: ledger payload bytes %d exceed configured aggregate bound %d", totalPayloadBytes, in.MaxTotalPayloadBytes)
	}

	// Delegate every chain, payload, hash, sequence, and cursor invariant to
	// the frozen B003 verifier. This wrapper changes only the event-row query
	// budget; it does not copy or fork any ledger verification semantics.
	return verifyStreamTx(ctx, boundedVerifyTx{verifyTx: tx, maxEvents: in.MaxEvents}, in.StreamID)
}

type boundedVerifyTx struct {
	verifyTx
	maxEvents int64
}

func (tx boundedVerifyTx) Query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	rows, err := tx.verifyTx.Query(ctx, query+"\n\t\tLIMIT $2", append(args, tx.maxEvents+1)...)
	if err != nil {
		return nil, err
	}
	return &boundedVerifyRows{Rows: rows, remaining: tx.maxEvents + 1}, nil
}

type boundedVerifyRows struct {
	pgx.Rows
	remaining int64
}

func (rows *boundedVerifyRows) Next() bool {
	if rows.remaining <= 0 || !rows.Rows.Next() {
		return false
	}
	rows.remaining--
	return true
}
