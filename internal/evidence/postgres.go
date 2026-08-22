package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

type captureTx interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

// PostgresSource is the B006 read-only adapter over the frozen B003 ledger.
// NewPostgresSource must construct it; the unexported seams exist solely for
// dependency-free tests of the SELECT-only transaction and change detector.
type PostgresSource struct {
	pool   *pgxpool.Pool
	verify func(context.Context, *pgxpool.Pool, storagepostgres.VerifyInput) (storagepostgres.VerifiedStream, error)
	begin  func(context.Context, pgx.TxOptions) (captureTx, error)
}

// NewPostgresSource binds a PostgreSQL pool without copying any B003 chain or
// hash logic. Capture always calls storage/postgres.VerifyStream first.
func NewPostgresSource(pool *pgxpool.Pool) *PostgresSource {
	source := &PostgresSource{pool: pool, verify: storagepostgres.VerifyStream}
	source.begin = func(ctx context.Context, options pgx.TxOptions) (captureTx, error) {
		if pool == nil {
			return nil, errors.New("nil *pgxpool.Pool")
		}
		return pool.BeginTx(ctx, options)
	}
	return source
}

// Capture verifies the complete B003 hash chain, then reads exactly the
// verified 1..N prefix in a read-only ReadCommitted transaction. Every SQL
// statement issued here is SELECT. A final cursor reread detects a committed
// append since verification and returns AIPT_EVIDENCE_STREAM_CHANGED instead
// of silently emitting a capture under a stale tail identity.
func (source *PostgresSource) Capture(ctx context.Context, streamID string) (LedgerSnapshot, error) {
	if err := validateLedgerText("stream_id", streamID); err != nil {
		return LedgerSnapshot{}, err
	}
	if source == nil || source.verify == nil || source.begin == nil {
		return LedgerSnapshot{}, fmt.Errorf("%w: uninitialized PostgreSQL source", ErrInvalidInput)
	}
	verified, err := source.verify(ctx, source.pool, storagepostgres.VerifyInput{StreamID: streamID})
	if err != nil {
		return LedgerSnapshot{}, classifyError(ErrLedgerVerify, "verify PostgreSQL ledger stream", err)
	}
	if verified.StreamID != streamID || verified.Sequence < 0 || verified.EventCount < 0 ||
		verified.Sequence != verified.EventCount || (verified.EventCount == 0) != (verified.EventHash == nil) {
		return LedgerSnapshot{}, fmt.Errorf("%w: VerifyStream returned an inconsistent identity", ErrInvalidInput)
	}

	tx, err := source.begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return LedgerSnapshot{}, fmt.Errorf("begin read-only evidence transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		SELECT sequence, event_id, event_type, payload_canonical, payload_sha256,
		       prev_event_hash, event_hash, committed_at
		FROM aipt.ledger_events
		WHERE stream_id = $1 AND sequence <= $2
		ORDER BY sequence ASC`, streamID, verified.Sequence)
	if err != nil {
		return LedgerSnapshot{}, fmt.Errorf("read verified ledger prefix: %w", err)
	}
	events := make([]LedgerEvent, 0)
	for rows.Next() {
		var (
			sequence         int64
			eventID          string
			eventType        string
			payloadCanonical string
			payloadHash      []byte
			previousHash     []byte
			eventHash        []byte
			committedAt      time.Time
		)
		if err := rows.Scan(&sequence, &eventID, &eventType, &payloadCanonical, &payloadHash,
			&previousHash, &eventHash, &committedAt); err != nil {
			rows.Close()
			return LedgerSnapshot{}, fmt.Errorf("scan verified ledger prefix: %w", err)
		}
		payload, err := requiredDatabaseHash("payload_sha256", payloadHash)
		if err != nil {
			rows.Close()
			return LedgerSnapshot{}, err
		}
		hash, err := requiredDatabaseHash("event_hash", eventHash)
		if err != nil {
			rows.Close()
			return LedgerSnapshot{}, err
		}
		previous, err := nullableDatabaseHash("prev_event_hash", previousHash)
		if err != nil {
			rows.Close()
			return LedgerSnapshot{}, err
		}
		events = append(events, LedgerEvent{
			StreamID: streamID, Sequence: sequence, EventID: eventID, EventType: eventType,
			PayloadCanonical: payloadCanonical, PayloadSHA256: payload,
			PrevEventHash: previous, EventHash: hash, CommittedAt: committedAt,
		})
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return LedgerSnapshot{}, fmt.Errorf("read verified ledger prefix: %w", rowsErr)
	}
	if int64(len(events)) != verified.EventCount {
		return LedgerSnapshot{}, fmt.Errorf("%w: verified count %d but SELECT returned %d events",
			ErrStreamChanged, verified.EventCount, len(events))
	}
	if len(events) > 0 && (events[len(events)-1].Sequence != verified.Sequence ||
		verified.EventHash == nil || events[len(events)-1].EventHash != *verified.EventHash) {
		return LedgerSnapshot{}, fmt.Errorf("%w: selected tail differs from VerifyStream", ErrStreamChanged)
	}

	var cursorSequence int64
	var cursorHash []byte
	if err := tx.QueryRow(ctx,
		"SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1",
		streamID).Scan(&cursorSequence, &cursorHash); err != nil {
		return LedgerSnapshot{}, fmt.Errorf("reread ledger cursor: %w", err)
	}
	if cursorSequence != verified.Sequence || !databaseHashMatches(cursorHash, verified.EventHash) {
		return LedgerSnapshot{}, fmt.Errorf("%w: verified cursor changed before export", ErrStreamChanged)
	}
	if err := tx.Commit(ctx); err != nil {
		return LedgerSnapshot{}, fmt.Errorf("commit read-only evidence transaction: %w", err)
	}

	var tail *[32]byte
	if verified.EventHash != nil {
		value := *verified.EventHash
		tail = &value
	}
	return LedgerSnapshot{
		StreamID: streamID, EventCount: verified.EventCount, TailSequence: verified.Sequence,
		TailHash: tail, Events: events,
	}, nil
}

func requiredDatabaseHash(field string, value []byte) ([32]byte, error) {
	if len(value) != sha256Size {
		return [32]byte{}, fmt.Errorf("%w: database %s byte length %d, want 32", ErrInvalidInput, field, len(value))
	}
	var out [32]byte
	copy(out[:], value)
	return out, nil
}

func nullableDatabaseHash(field string, value []byte) (*[32]byte, error) {
	if value == nil {
		return nil, nil
	}
	hash, err := requiredDatabaseHash(field, value)
	if err != nil {
		return nil, err
	}
	return &hash, nil
}

func databaseHashMatches(value []byte, expected *[32]byte) bool {
	if expected == nil {
		return value == nil
	}
	return len(value) == sha256Size && bytes.Equal(value, expected[:])
}

const sha256Size = 32
