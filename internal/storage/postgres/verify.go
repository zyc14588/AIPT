// This file implements the public Go PostgreSQL Verify path of the AIPT
// ledger contract. VerifyStream validates the stream identifier with the same
// fail-closed guard the hash chain uses before any pool access, opens one
// RepeatableRead ReadOnly transaction, and reads the stream cursor and every
// event of the stream ordered by sequence ASC in that single snapshot. The
// body fails closed on any violation of the chain, payload, event-hash, or
// cursor invariants: sequences must be exactly 1..N, the genesis event must
// carry a SQL NULL previous hash, every later previous hash must equal the
// verified hash of the preceding event, the recorded payload SHA-256 must
// equal the SHA-256 of the exact stored canonical payload TEXT (never
// re-canonicalized), the recorded event hash must equal the versioned
// hashLedgerBlock digest, and the stored cursor must equal the actual verified
// tail with 0/NULL empty-stream semantics. The transaction is read-only and
// every statement is a SELECT, so verification never mutates data. Missing
// streams and every integrity failure use the typed errors in errors.go.
package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyInput is the input of a ledger verification run. StreamID is the
// nonempty valid-UTF-8 identifier of the stream whose chain is verified; it is
// validated with the same fail-closed guard the hash chain uses
// (validateTextField) before any pool or transaction access.
type VerifyInput struct {
	StreamID string
}

// VerifiedStream is the committed result of a successful verification run.
// StreamID is the verified stream, Sequence is the verified tail sequence (0
// for an empty stream), EventHash is the verified tail event hash (nil for an
// empty stream), and EventCount is the number of verified events.
type VerifiedStream struct {
	StreamID   string
	Sequence   int64
	EventHash  *[32]byte
	EventCount int64
}

// verifyTx is the minimal read-only transactional surface the verification
// transaction body needs. pgx.Tx satisfies it, and tests inject a scripted
// fake, so the whole transaction body is exercised without a database. Only
// query statements are exposed because verification never mutates data. Commit
// and Rollback are part of the surface so the helper can be driven exactly
// like a real transaction, but verifyStreamTx itself never commits and never
// rolls back: the caller owns the transaction lifecycle.
type verifyTx interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// VerifyStream verifies the complete ledger chain of the stream identified by
// in and returns the verified tail. Input validation (a nonempty valid-UTF-8
// stream_id through the same guard the hash chain uses) happens before any
// pool or transaction access, so invalid input is rejected even for a nil
// pool. The verification runs in one RepeatableRead ReadOnly transaction so
// the cursor read and every event read observe the same snapshot, and the
// transaction commits only after the body returns nil, so any failure rolls
// the read-only transaction back. Every failure returns the zero result.
func VerifyStream(ctx context.Context, pool *pgxpool.Pool, in VerifyInput) (VerifiedStream, error) {
	if err := validateTextField("stream_id", in.StreamID); err != nil {
		return VerifiedStream{}, err
	}
	if pool == nil {
		return VerifiedStream{}, errors.New("VerifyStream: nil *pgxpool.Pool")
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStream: begin transaction: %w", err)
	}
	// Rollback is a no-op after Commit and reliably rolls back on failure; the
	// read-only transaction can never mutate data.
	defer tx.Rollback(ctx)

	vs, err := verifyStreamTx(ctx, tx, in.StreamID)
	if err != nil {
		return VerifiedStream{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStream: commit transaction: %w", err)
	}
	return vs, nil
}

// verifyStreamTx runs the complete verification transaction body against tx:
// it reads the stream cursor and every event ordered by sequence ASC, verifies
// each event's chain position (exactly 1..N), previous hash (SQL NULL genesis,
// then the verified hash of the preceding event), payload hash (SHA-256 of the
// exact stored canonical payload TEXT, never re-canonicalized), and versioned
// event hash (hashLedgerBlock), and finally verifies that the stored cursor
// equals the actual verified tail (0/NULL for an empty stream). It fails
// closed through the typed errors in errors.go and never mutates data: only
// QueryRow and Query statements run. It never commits: the caller commits only
// after this returns nil and rolls back on any error.
func verifyStreamTx(ctx context.Context, tx verifyTx, streamID string) (VerifiedStream, error) {
	// Read the stream cursor under the transaction snapshot. A missing stream
	// row means there is no chain to verify.
	var cursorSeq int64
	var cursorHash []byte
	switch err := tx.QueryRow(ctx,
		"SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1",
		streamID).Scan(&cursorSeq, &cursorHash); {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows):
		return VerifiedStream{}, fmt.Errorf("VerifyStream: read ledger stream cursor: %w", &LedgerStreamNotFoundError{StreamID: streamID})
	default:
		return VerifiedStream{}, fmt.Errorf("VerifyStream: read ledger stream cursor: %w", err)
	}

	// A non-NULL cursor hash must be exactly 32 bytes; SQL NULL is the legal
	// empty-cursor value and is never confused with a non-NULL zero-length
	// bytea.
	if cursorHash != nil && len(cursorHash) != 32 {
		return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger cursor: %w", &LedgerMalformedHashError{
			StreamID:   streamID,
			Sequence:   cursorSeq,
			Field:      "last_event_hash",
			IsNull:     false,
			ByteLength: len(cursorHash),
		})
	}

	// Read every event of the stream ordered by sequence ASC in the same
	// snapshot.
	rows, err := tx.Query(ctx, `
		SELECT sequence, event_id, event_type, payload_canonical, payload_sha256, prev_event_hash, event_hash
		FROM aipt.ledger_events
		WHERE stream_id = $1
		ORDER BY sequence ASC`,
		streamID)
	if err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStream: read ledger events: %w", err)
	}
	defer rows.Close()

	// The previous verified hash lives in owned [32]byte storage, never in a
	// row-buffer slice, so a reused or mutated scan buffer can never corrupt
	// the chain walk.
	var priorHash [32]byte
	expectedSeq := int64(1)
	eventCount := int64(0)
	var tailSeq int64
	var tailHash [32]byte

	for rows.Next() {
		var (
			seq              int64
			eventID          string
			eventType        string
			payloadCanonical string
			payloadSHA       []byte
			prevHash         []byte
			eventHash        []byte
		)
		if err := rows.Scan(&seq, &eventID, &eventType, &payloadCanonical, &payloadSHA, &prevHash, &eventHash); err != nil {
			return VerifiedStream{}, fmt.Errorf("VerifyStream: scan ledger event: %w", err)
		}

		// The sequence must be exactly the next expected one, starting at 1.
		if seq != expectedSeq {
			return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerSequenceGapError{
				StreamID: streamID,
				Expected: expectedSeq,
				Actual:   seq,
			})
		}

		// Verify the previous hash: the genesis event must be SQL NULL, every
		// later event must carry the verified hash of the preceding event, and
		// any non-NULL hash must be exactly 32 bytes.
		if seq == 1 {
			if prevHash != nil {
				if len(prevHash) != 32 {
					return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerMalformedHashError{
						StreamID:   streamID,
						Sequence:   seq,
						Field:      "prev_event_hash",
						IsNull:     false,
						ByteLength: len(prevHash),
					})
				}
				return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerPrevHashMismatchError{
					StreamID: streamID,
					Sequence: seq,
					Expected: nil,
					Actual:   ledgerHashPtr(prevHash),
				})
			}
		} else {
			if prevHash == nil {
				expected := priorHash
				return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerPrevHashMismatchError{
					StreamID: streamID,
					Sequence: seq,
					Expected: &expected,
					Actual:   nil,
				})
			}
			if len(prevHash) != 32 {
				return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerMalformedHashError{
					StreamID:   streamID,
					Sequence:   seq,
					Field:      "prev_event_hash",
					IsNull:     false,
					ByteLength: len(prevHash),
				})
			}
			if !bytes.Equal(prevHash, priorHash[:]) {
				expected := priorHash
				return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerPrevHashMismatchError{
					StreamID: streamID,
					Sequence: seq,
					Expected: &expected,
					Actual:   ledgerHashPtr(prevHash),
				})
			}
		}

		// Verify the payload hash against the exact stored canonical TEXT
		// bytes: the digest of the stored payload (never re-canonicalized)
		// must equal the recorded payload_sha256 exactly.
		if len(payloadSHA) != 32 {
			return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerMalformedHashError{
				StreamID:   streamID,
				Sequence:   seq,
				Field:      "payload_sha256",
				IsNull:     payloadSHA == nil,
				ByteLength: len(payloadSHA),
			})
		}
		payloadHash := sha256.Sum256([]byte(payloadCanonical))
		if !bytes.Equal(payloadHash[:], payloadSHA) {
			expected := payloadHash
			return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerPayloadHashMismatchError{
				StreamID: streamID,
				Sequence: seq,
				Expected: &expected,
				Actual:   ledgerHashPtr(payloadSHA),
			})
		}

		// Verify the versioned event hash with the existing hashLedgerBlock,
		// using the recorded payload hash and the verified previous hash (nil
		// for the genesis event).
		if len(eventHash) != 32 {
			return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerMalformedHashError{
				StreamID:   streamID,
				Sequence:   seq,
				Field:      "event_hash",
				IsNull:     eventHash == nil,
				ByteLength: len(eventHash),
			})
		}
		var prevPtr *[32]byte
		if seq > 1 {
			prevPtr = &priorHash
		}
		recomputed, err := hashLedgerBlock(ledgerHashInput{
			StreamID:    streamID,
			Sequence:    seq,
			EventID:     eventID,
			EventType:   eventType,
			PayloadHash: payloadHash,
			PrevHash:    prevPtr,
		})
		if err != nil {
			return VerifiedStream{}, fmt.Errorf("VerifyStream: hash ledger event: %w", err)
		}
		if !bytes.Equal(recomputed[:], eventHash) {
			expected := recomputed
			return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger event: %w", &LedgerEventHashMismatchError{
				StreamID: streamID,
				Sequence: seq,
				Expected: &expected,
				Actual:   ledgerHashPtr(eventHash),
			})
		}

		// The event verified: keep the verified hash as the owned previous
		// hash for the next event and track the verified tail.
		priorHash = recomputed
		tailSeq = seq
		tailHash = recomputed
		eventCount++
		expectedSeq++
	}

	if err := rows.Err(); err != nil {
		return VerifiedStream{}, fmt.Errorf("VerifyStream: iterate ledger events: %w", err)
	}

	// The stored cursor must equal the actual verified tail: an empty stream
	// has cursor (0, NULL) with no events, and a nonempty stream has cursor
	// (eventCount, verified tail hash).
	cursorEmpty := cursorSeq == 0 && cursorHash == nil
	tailPresent := eventCount > 0
	var tailHashPtr *[32]byte
	if tailPresent {
		h := tailHash
		tailHashPtr = &h
	}
	switch {
	case cursorEmpty && !tailPresent:
		// Empty stream: cursor (0, NULL) matches the empty tail.
	case !cursorEmpty && tailPresent && cursorSeq == tailSeq && bytes.Equal(cursorHash, tailHash[:]):
		// Nonempty stream: cursor and verified tail agree.
	default:
		return VerifiedStream{}, fmt.Errorf("VerifyStream: verify ledger cursor: %w", &LedgerCursorMismatchError{
			StreamID:       streamID,
			CursorSequence: cursorSeq,
			CursorHash:     ledgerHashPtr(cursorHash),
			TailSequence:   tailSeq,
			TailHash:       tailHashPtr,
			TailPresent:    tailPresent,
		})
	}

	vs := VerifiedStream{
		StreamID:   streamID,
		Sequence:   tailSeq,
		EventCount: eventCount,
	}
	if tailPresent {
		h := tailHash
		vs.EventHash = &h
	}
	return vs, nil
}
