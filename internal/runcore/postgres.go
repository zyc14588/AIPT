package runcore

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

var errStoreConflict = errors.New("AIPT_RUN_EVENT_STORE_CONFLICT")

// PostgreSQLStore adapts the accepted append-only hash-chain ledger. It adds
// no table, snapshot, cache, or second persistence authority.
type PostgreSQLStore struct {
	pool *pgxpool.Pool
}

func NewPostgreSQLStore(pool *pgxpool.Pool) (*PostgreSQLStore, error) {
	if pool == nil {
		return nil, errors.New("nil PostgreSQL pool")
	}
	return &PostgreSQLStore{pool: pool}, nil
}

func (s *PostgreSQLStore) Append(ctx context.Context, request AppendRequest) (storagepostgres.LedgerEvent, error) {
	if s == nil || s.pool == nil {
		return storagepostgres.LedgerEvent{}, errors.New("nil PostgreSQL store")
	}
	expected := request.ExpectedSequence
	event, err := storagepostgres.Append(ctx, s.pool, storagepostgres.AppendInput{
		StreamID: request.StreamID, EventID: request.EventID, EventType: request.EventType,
		PayloadJSON: request.Payload, ExpectedSequence: &expected,
	})
	if errors.Is(err, storagepostgres.ErrLedgerExpectedSequence) {
		return storagepostgres.LedgerEvent{}, errStoreConflict
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return storagepostgres.LedgerEvent{}, errStoreConflict
	}
	return event, err
}

// Load reads cursor and events in one repeatable-read snapshot, verifies the
// copied chain, and requires the cursor to equal its exact tail.
func (s *PostgreSQLStore) Load(ctx context.Context, streamID string) ([]storagepostgres.LedgerEvent, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return nil, errors.New("nil PostgreSQL store or context")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var cursorSequence int64
	var cursorHash []byte
	if err := tx.QueryRow(ctx,
		"SELECT last_sequence, last_event_hash FROM aipt.ledger_streams WHERE stream_id = $1",
		streamID).Scan(&cursorSequence, &cursorHash); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `
		SELECT sequence, event_id, event_type, payload_canonical, payload_sha256,
		       prev_event_hash, event_hash, committed_at
		FROM aipt.ledger_events
		WHERE stream_id = $1
		ORDER BY sequence ASC`, streamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []storagepostgres.LedgerEvent
	for rows.Next() {
		var event storagepostgres.LedgerEvent
		var payloadHash, previousHash, eventHash []byte
		event.StreamID = streamID
		if err := rows.Scan(&event.Sequence, &event.EventID, &event.EventType, &event.PayloadCanonical,
			&payloadHash, &previousHash, &eventHash, &event.CommittedAt); err != nil {
			return nil, err
		}
		if len(payloadHash) != 32 || len(eventHash) != 32 || (previousHash != nil && len(previousHash) != 32) {
			return nil, errors.New("malformed ledger hash")
		}
		copy(event.PayloadHash[:], payloadHash)
		copy(event.EventHash[:], eventHash)
		if previousHash != nil {
			var previous [32]byte
			copy(previous[:], previousHash)
			event.PrevEventHash = &previous
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errors.New("Run Core ledger stream has no genesis event")
	}
	if err := storagepostgres.VerifyLedgerEvents(events); err != nil {
		return nil, err
	}
	tail := events[len(events)-1]
	if cursorSequence != tail.Sequence || len(cursorHash) != 32 || !bytes.Equal(cursorHash, tail.EventHash[:]) {
		return nil, fmt.Errorf("ledger cursor does not match verified tail")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return events, nil
}
