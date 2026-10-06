package runcontrol

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
)

// PostgresReader adds a bounded, repeatable-read projection only. Every write
// still goes through the frozen B001 QueueStore, with no new migration.
type PostgresReader struct{ pool *pgxpool.Pool }

func NewPostgresReader(pool *pgxpool.Pool) (*PostgresReader, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresReader{pool: pool}, nil
}
func (r *PostgresReader) Snapshot(ctx context.Context, limit int) (QueueSnapshot, error) {
	if limit < 1 || limit > 100 {
		return QueueSnapshot{}, ErrInvalid
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return QueueSnapshot{}, ErrUnavailable
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	result := QueueSnapshot{Records: []postgres.RunRecord{}}
	if err := tx.QueryRow(ctx, `SELECT paused FROM aipt.playtest_queue_control WHERE control_id='GLOBAL'`).Scan(&result.Paused); err != nil {
		return QueueSnapshot{}, ErrUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT r.run_id,r.manifest_id,r.case_id,r.run_type,r.classification,
 r.qualification_eligible,r.priority_class,r.status,r.queued_at,r.eligible_after,m.canonical_sha256
 FROM aipt.playtest_runs r JOIN aipt.run_manifests m USING(manifest_id,run_id)
 ORDER BY (r.status='LEASED') DESC,aipt.playtest_priority_rank(r.priority_class),r.queued_at,r.run_id COLLATE "C" LIMIT $1`, limit+1)
	if err != nil {
		return QueueSnapshot{}, ErrUnavailable
	}
	for rows.Next() {
		var item postgres.RunRecord
		var digest []byte
		if err := rows.Scan(&item.RunID, &item.ManifestID, &item.CaseID, &item.RunType, &item.Classification, &item.QualificationEligible, &item.Priority, &item.Status, &item.QueuedAt, &item.EligibleAfter, &digest); err != nil || len(digest) != 32 {
			rows.Close()
			return QueueSnapshot{}, ErrUnavailable
		}
		copy(item.ManifestSHA256[:], digest)
		result.Records = append(result.Records, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return QueueSnapshot{}, ErrUnavailable
	}
	if len(result.Records) > limit {
		result.Truncated = true
		result.Records = result.Records[:limit]
	}
	if err := tx.Commit(ctx); err != nil {
		return QueueSnapshot{}, ErrUnavailable
	}
	return result, nil
}
