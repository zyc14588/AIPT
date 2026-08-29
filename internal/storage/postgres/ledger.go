// This file implements the public Go PostgreSQL Append path of the AIPT
// ledger contract. Append accepts raw JSON, canonicalizes it with the existing
// internal/protocol package before any database access, and then performs the
// complete cursor/tail/hash append transaction: it ensures the stream row
// exists, locks the stream cursor, verifies the cursor against the actual
// ledger_events tail (never trusting the cursor alone), rejects sequence
// exhaustion, computes the versioned event hash, inserts the event (obtaining
// committed_at from the database, never from time.Now), advances the cursor in
// a guarded update that must affect exactly one row, and commits. Every
// failure rolls the transaction back so the cursor can never advance
// independently of a successful event insert. VerifyStream and integration
// tests are out of scope for this file.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// AppendInput is the raw input of a ledger append. StreamID, EventID, and
// EventType are the nonempty valid-UTF-8 identifiers of the stream, the event,
// and the event type; PayloadJSON is the raw JSON payload, which Append
// canonicalizes with internal/protocol.CanonicalJSON before any database
// access.
type AppendInput struct {
	StreamID    string
	EventID     string
	EventType   string
	PayloadJSON []byte
	// ExpectedSequence, when non-nil, is the exact locked stream cursor that
	// must precede this append. The comparison happens after the cursor row is
	// locked and reconciled with the event tail, in the same transaction as
	// the insert and cursor advance. It is therefore an optimistic-concurrency
	// precondition, not a best-effort read performed by the caller.
	ExpectedSequence *int64
}

// LedgerEvent is the committed result of a successful append. StreamID,
// Sequence, EventID, and EventType are the identifiers of the committed event;
// PayloadCanonical is the exact canonical JSON string stored by the database
// (the exact string returned by internal/protocol.CanonicalJSON); PayloadHash
// is the SHA-256 of that canonical string's UTF-8 bytes; EventHash is the
// versioned AIPT_LEDGER_V1 event hash; PrevEventHash is the previous event's
// hash (nil for the genesis event); and CommittedAt is the database-generated
// commit timestamp returned by the INSERT.
type LedgerEvent struct {
	StreamID         string
	Sequence         int64
	EventID          string
	EventType        string
	PayloadCanonical string
	PayloadHash      [32]byte
	EventHash        [32]byte
	PrevEventHash    *[32]byte
	CommittedAt      time.Time
}

// ledgerTx is the minimal transactional surface the append transaction body
// needs. pgx.Tx satisfies it, and tests inject a scripted fake, so the whole
// transaction body is exercised without a database. Commit and Rollback are
// part of the surface so the helper can be driven exactly like a real
// transaction, but appendLedgerEvent itself never commits and never rolls
// back: the caller owns the transaction lifecycle, so the cursor can only
// advance when the caller commits after a successful append.
type ledgerTx interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Append commits one ledger event for the stream identified by in and returns
// the committed event. All input validation (nonempty valid-UTF-8 identifiers
// and strict canonicalization of the raw JSON payload through the existing
// internal/protocol package) happens before any pool or transaction access, so
// invalid input is rejected even for a nil pool. The append runs in one
// transaction: the stream row is ensured, the cursor is locked and verified
// against the actual ledger_events tail, the event is inserted, and the cursor
// is advanced in a guarded update; Commit is the last step, so any failure
// rolls everything back and the cursor cannot advance independently.
func Append(ctx context.Context, pool *pgxpool.Pool, in AppendInput) (LedgerEvent, error) {
	canonical, payloadHash, err := prepareAppendInput(in)
	if err != nil {
		return LedgerEvent{}, err
	}
	if pool == nil {
		return LedgerEvent{}, errors.New("Append: nil *pgxpool.Pool")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: begin transaction: %w", err)
	}
	// Rollback is a no-op after Commit and reliably rolls back on failure;
	// pgx also closes the connection if a transaction fails mid-way.
	defer tx.Rollback(ctx)

	ev, err := appendLedgerEvent(ctx, tx, in, canonical, payloadHash)
	if err != nil {
		return LedgerEvent{}, err
	}
	// The cursor is advanced only inside the same transaction as the event
	// insert; committing is the last step, so a failed commit rolls everything
	// back and the cursor cannot advance independently.
	if err := tx.Commit(ctx); err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: commit transaction: %w", err)
	}
	return ev, nil
}

// prepareAppendInput validates every identifier and canonicalizes the payload
// strictly before any pool or transaction access. Identifiers are validated
// with the same fail-closed guard the hash chain uses (validateTextField), so
// anything that cannot be encoded into a versioned preimage is rejected here.
// The payload is canonicalized with the existing internal/protocol.CanonicalJSON
// (never copied or reimplemented), and the exact returned string is stored;
// payloadHash is the SHA-256 of that canonical string's UTF-8 bytes. Input
// validation errors are returned verbatim so callers can match
// protocol.ContractReason and *LedgerHashInputError directly.
func prepareAppendInput(in AppendInput) (canonical string, payloadHash [32]byte, err error) {
	for _, f := range []struct{ name, value string }{
		{"stream_id", in.StreamID},
		{"event_id", in.EventID},
		{"event_type", in.EventType},
	} {
		if err := validateTextField(f.name, f.value); err != nil {
			return "", [32]byte{}, err
		}
	}
	if in.ExpectedSequence != nil && *in.ExpectedSequence < 0 {
		return "", [32]byte{}, &LedgerExpectedSequenceError{
			StreamID: in.StreamID,
			Expected: *in.ExpectedSequence,
			Actual:   0,
		}
	}
	canonical, err = protocol.CanonicalJSON(in.PayloadJSON)
	if err != nil {
		return "", [32]byte{}, err
	}
	return canonical, sha256.Sum256([]byte(canonical)), nil
}

// appendLedgerEvent runs the complete cursor/tail/hash append transaction body
// against tx. It verifies the locked stream cursor against the actual
// ledger_events tail (never trusting the cursor alone), fails closed with
// AIPT_LEDGER_CURSOR_MISMATCH on any disagreement, rejects cursor exhaustion at
// the maximum positive BIGINT sequence, computes the versioned event hash with
// hashLedgerBlock, inserts the event, and advances the cursor in a guarded
// update that must affect exactly one row. It never commits: the caller
// commits only after this returns nil and rolls back on any error, so a failed
// insert/check/update/commit can never advance the cursor.
func appendLedgerEvent(ctx context.Context, tx ledgerTx, in AppendInput, canonical string, payloadHash [32]byte) (LedgerEvent, error) {
	// Ensure the stream row exists (idempotent; a concurrent first append may
	// have created it already).
	if _, err := tx.Exec(ctx,
		"INSERT INTO aipt.ledger_streams (stream_id) VALUES ($1) ON CONFLICT DO NOTHING",
		in.StreamID); err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: ensure ledger stream: %w", err)
	}

	// Lock the stream row and read the cursor under the transaction.
	var cursorSeq int64
	var cursorHash []byte
	if err := tx.QueryRow(ctx,
		"SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1 FOR UPDATE",
		in.StreamID).Scan(&cursorSeq, &cursorHash); err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: read ledger stream cursor: %w", err)
	}

	// Query the actual ledger_events tail ordered by sequence DESC, never
	// trusting the cursor alone.
	var tailSeq int64
	var tailHash []byte
	tailPresent := true
	switch err := tx.QueryRow(ctx,
		"SELECT sequence, event_hash FROM aipt.ledger_events WHERE stream_id = $1 ORDER BY sequence DESC LIMIT 1",
		in.StreamID).Scan(&tailSeq, &tailHash); {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		tailPresent = false
	default:
		return LedgerEvent{}, fmt.Errorf("Append: read ledger tail: %w", err)
	}

	// Validate database hash byte lengths instead of truncating or padding.
	if len(cursorHash) != 0 && len(cursorHash) != 32 {
		return LedgerEvent{}, fmt.Errorf("Append: ledger stream cursor last_event_hash has byte length %d, want 0 (NULL) or 32", len(cursorHash))
	}
	if tailPresent && len(tailHash) != 32 {
		return LedgerEvent{}, fmt.Errorf("Append: ledger tail event_hash has byte length %d, want 32", len(tailHash))
	}

	// Fail closed unless the empty cursor matches no tail, or both the tail
	// sequence and hash match the cursor.
	cursorEmpty := cursorSeq == 0 && cursorHash == nil
	switch {
	case cursorEmpty && !tailPresent:
		// Genesis append: sequence 1 with no previous hash.
	case !cursorEmpty && tailPresent && tailSeq == cursorSeq && bytes.Equal(tailHash, cursorHash):
		// Chained append: the actual tail and the locked cursor agree.
	default:
		return LedgerEvent{}, fmt.Errorf("Append: verify ledger cursor: %w", &LedgerCursorMismatchError{
			StreamID:       in.StreamID,
			CursorSequence: cursorSeq,
			CursorHash:     ledgerHashPtr(cursorHash),
			TailSequence:   tailSeq,
			TailHash:       ledgerHashPtr(tailHash),
			TailPresent:    tailPresent,
		})
	}

	// A caller that binds an action to an authoritative state sequence must
	// compare it while holding the same row lock used by the append. This is
	// deliberately after cursor/tail reconciliation: a corrupt cursor is an
	// integrity failure, never misclassified as an ordinary stale action.
	if in.ExpectedSequence != nil && cursorSeq != *in.ExpectedSequence {
		return LedgerEvent{}, fmt.Errorf("Append: verify expected sequence: %w", &LedgerExpectedSequenceError{
			StreamID: in.StreamID,
			Expected: *in.ExpectedSequence,
			Actual:   cursorSeq,
		})
	}

	// Reject sequence exhaustion: the next sequence must remain a representable
	// positive signed int64/BIGINT value.
	if cursorSeq == math.MaxInt64 {
		return LedgerEvent{}, fmt.Errorf("Append: verify ledger cursor: %w", &LedgerSequenceExhaustedError{
			StreamID: in.StreamID,
			Sequence: cursorSeq,
		})
	}
	sequence := cursorSeq + 1

	// Compute the previous, payload, and versioned event hash. hashLedgerBlock
	// validates the input fields again, failing closed before any hashing.
	var prevHash *[32]byte
	var prevHashBytes []byte
	if !cursorEmpty {
		prev := ledgerHashPtr(tailHash)
		prevHash = prev
		prevHashBytes = prev[:]
	}
	eventHash, err := hashLedgerBlock(ledgerHashInput{
		StreamID:    in.StreamID,
		Sequence:    sequence,
		EventID:     in.EventID,
		EventType:   in.EventType,
		PayloadHash: payloadHash,
		PrevHash:    prevHash,
	})
	if err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: hash ledger event: %w", err)
	}

	// Insert the event and obtain committed_at from the database via RETURNING
	// (never from time.Now). A duplicate event_id fails here and rolls the
	// transaction back before any cursor change.
	var committedAt time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO aipt.ledger_events
			(stream_id, sequence, event_id, event_type, payload_canonical, payload_sha256, prev_event_hash, event_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING committed_at`,
		in.StreamID, sequence, in.EventID, in.EventType, canonical, payloadHash[:], prevHashBytes, eventHash[:],
	).Scan(&committedAt); err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: insert ledger event: %w", err)
	}

	// Advance the cursor only after the event insert succeeded, in a guarded
	// update that requires exactly one affected row: both last_sequence and
	// last_event_hash must still equal the locked cursor values.
	ct, err := tx.Exec(ctx, `
		UPDATE aipt.ledger_streams
		SET last_sequence = $2, last_event_hash = $3
		WHERE stream_id = $1 AND last_sequence = $4 AND last_event_hash IS NOT DISTINCT FROM $5`,
		in.StreamID, sequence, eventHash[:], cursorSeq, cursorHash)
	if err != nil {
		return LedgerEvent{}, fmt.Errorf("Append: advance ledger stream cursor: %w", err)
	}
	if n := ct.RowsAffected(); n != 1 {
		return LedgerEvent{}, fmt.Errorf("Append: advance ledger stream cursor: update affected %d rows, want exactly 1", n)
	}

	// Build the returned event with cloned hash values.
	ev := LedgerEvent{
		StreamID:         in.StreamID,
		Sequence:         sequence,
		EventID:          in.EventID,
		EventType:        in.EventType,
		PayloadCanonical: canonical,
		PayloadHash:      payloadHash,
		EventHash:        eventHash,
		CommittedAt:      committedAt,
	}
	if prevHash != nil {
		prev := *prevHash
		ev.PrevEventHash = &prev
	}
	return ev, nil
}

// ledgerHashPtr copies a validated 32-byte database hash into a fresh [32]byte
// and returns a pointer to the copy; a nil or empty slice yields nil. It never
// truncates or pads: callers must validate the byte length first.
func ledgerHashPtr(b []byte) *[32]byte {
	if len(b) != 32 {
		return nil
	}
	var h [32]byte
	copy(h[:], b)
	return &h
}
