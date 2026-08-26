package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zyc14588/AIPT/internal/testplan"
)

var queueIdentityRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/\-]{0,127}$`)

var validPriorities = map[PriorityClass]struct{}{
	PriorityRelease: {}, PriorityHotfix: {}, PriorityMilestone: {}, PrioritySystem: {},
	PriorityCalibration: {}, PriorityExploratory: {}, PriorityBackground: {},
}

const eligibleRunsSQL = `
	FROM aipt.playtest_runs r
	WHERE r.status = 'QUEUED'
	  AND r.eligible_after <= statement_timestamp()
	  AND r.required_resource_id = ANY($1::text[])
	  AND r.required_model_id = ANY($2::text[])
	  AND r.required_certification_id = ANY($3::text[])
	  AND r.required_labels <@ $4::text[]
	  AND NOT EXISTS (
	      SELECT 1 FROM aipt.run_dependencies d
	      JOIN aipt.playtest_runs predecessor ON predecessor.run_id = d.depends_on_run_id
	      WHERE d.run_id = r.run_id AND predecessor.status <> 'COMPLETED'
	  )
	  AND (
	      r.classification <> 'QUALIFICATION'
	      OR NOT EXISTS (
	          SELECT 1 FROM aipt.run_leases active_formal
	          WHERE active_formal.status = 'ACTIVE' AND active_formal.formal_slot = 1
	      )
	  )
	ORDER BY aipt.playtest_priority_rank(r.priority_class) ASC,
	         r.queued_at ASC,
	         r.run_id COLLATE "C" ASC`

// EnqueueRun creates the complete Campaign/Suite/Case/Run ancestry and its
// immutable Manifest in one transaction. Existing ancestry may be reused only
// when every parent, name and task type is identical; any later failure rolls
// the entire transaction back.
func (s *QueueStore) EnqueueRun(ctx context.Context, in EnqueueRunInput) (RunRecord, error) {
	const op = "EnqueueRun"
	if err := mutationContext(ctx, op, ""); err != nil {
		return RunRecord{}, err
	}
	frozen, err := testplan.DecodeRunManifest(in.ManifestBytes)
	if err != nil {
		return RunRecord{}, queueError(ErrQueueInvalidInput, op, "", err)
	}
	runID := frozen.Manifest.RunID
	if err := validateEnqueueInput(in, frozen.Manifest); err != nil {
		return RunRecord{}, queueError(ErrQueueInvalidInput, op, runID, err)
	}
	labels, err := normalizedIdentities(in.RequiredLabels, true)
	if err != nil {
		return RunRecord{}, queueError(ErrQueueInvalidInput, op, runID, err)
	}
	dependencies, err := normalizedIdentities(in.DependencyRunIDs, true)
	if err != nil {
		return RunRecord{}, queueError(ErrQueueInvalidInput, op, runID, err)
	}
	for _, dependency := range dependencies {
		if dependency == runID {
			return RunRecord{}, queueError(ErrQueueInvalidInput, op, runID, errors.New("self dependency"))
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RunRecord{}, queueError(ErrQueueStorage, op, runID, err)
	}
	defer tx.Rollback(ctx)
	if err := ensureAncestry(ctx, tx, frozen.Manifest, in); err != nil {
		return RunRecord{}, queueError(ErrQueueStateConflict, op, runID, err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aipt.run_manifests
			(manifest_id, run_id, schema_identity, manifest_bytes, canonical_sha256)
		VALUES ($1, $2, $3, $4, $5)`,
		frozen.Manifest.ManifestID, runID, frozen.Manifest.Schema, frozen.Canonical, frozen.Digest[:]); err != nil {
		return RunRecord{}, queueDBError(op, runID, err, ErrQueueRunExists)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO aipt.playtest_runs
			(run_id, manifest_id, case_id, run_type, classification,
			 qualification_eligible, priority_class, required_resource_id,
			 required_model_id, required_certification_id, required_labels,
			 eligible_after)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
		        COALESCE($12::timestamptz, statement_timestamp()))`,
		runID, frozen.Manifest.ManifestID, frozen.Manifest.Ancestry.CaseID,
		string(frozen.Manifest.RunType), frozen.Manifest.Classification,
		frozen.Manifest.QualificationEligible, string(in.Priority),
		in.RequiredResourceID, in.RequiredModelID, in.RequiredCertificationID,
		labels, in.EligibleAfter); err != nil {
		return RunRecord{}, queueDBError(op, runID, err, ErrQueueRunExists)
	}
	for _, dependency := range dependencies {
		if _, err := tx.Exec(ctx, `INSERT INTO aipt.run_dependencies (run_id, depends_on_run_id) VALUES ($1, $2)`, runID, dependency); err != nil {
			return RunRecord{}, queueDBError(op, runID, err, ErrQueueStateConflict)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return RunRecord{}, queueError(ErrQueueStorage, op, runID, err)
	}
	return s.GetRun(ctx, runID)
}

func ensureAncestry(ctx context.Context, tx pgx.Tx, manifest testplan.RunManifest, in EnqueueRunInput) error {
	var identity string
	if err := tx.QueryRow(ctx, `
		INSERT INTO aipt.playtest_campaigns (campaign_id, name) VALUES ($1, $2)
		ON CONFLICT (campaign_id) DO UPDATE SET campaign_id = EXCLUDED.campaign_id
		WHERE aipt.playtest_campaigns.name = EXCLUDED.name
		RETURNING campaign_id`, manifest.Ancestry.CampaignID, in.CampaignName).Scan(&identity); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO aipt.playtest_suites (suite_id, campaign_id, name) VALUES ($1, $2, $3)
		ON CONFLICT (suite_id) DO UPDATE SET suite_id = EXCLUDED.suite_id
		WHERE aipt.playtest_suites.campaign_id = EXCLUDED.campaign_id
		  AND aipt.playtest_suites.name = EXCLUDED.name
		RETURNING suite_id`, manifest.Ancestry.SuiteID, manifest.Ancestry.CampaignID, in.SuiteName).Scan(&identity); err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO aipt.playtest_cases (case_id, suite_id, name, task_type) VALUES ($1, $2, $3, $4)
		ON CONFLICT (case_id) DO UPDATE SET case_id = EXCLUDED.case_id
		WHERE aipt.playtest_cases.suite_id = EXCLUDED.suite_id
		  AND aipt.playtest_cases.name = EXCLUDED.name
		  AND aipt.playtest_cases.task_type = EXCLUDED.task_type
		RETURNING case_id`, manifest.Ancestry.CaseID, manifest.Ancestry.SuiteID, in.CaseName, string(manifest.RunType)).Scan(&identity); err != nil {
		return err
	}
	return nil
}

func (s *QueueStore) GetRun(ctx context.Context, runID string) (RunRecord, error) {
	if err := validQueueIdentity(runID); err != nil {
		return RunRecord{}, queueError(ErrQueueInvalidInput, "GetRun", runID, err)
	}
	row := s.pool.QueryRow(ctx, `
		SELECT r.run_id, r.manifest_id, r.case_id, r.run_type, r.classification,
		       r.qualification_eligible, r.priority_class, r.required_resource_id,
		       r.required_model_id, r.required_certification_id, r.required_labels,
		       r.status, r.eligible_after, r.queued_at,
		       m.manifest_bytes, m.canonical_sha256
		FROM aipt.playtest_runs r
		JOIN aipt.run_manifests m ON m.manifest_id = r.manifest_id AND m.run_id = r.run_id
		WHERE r.run_id = $1`, runID)
	record, err := scanRunRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return RunRecord{}, queueError(ErrQueueRunNotFound, "GetRun", runID, err)
	}
	if err != nil {
		return RunRecord{}, queueError(ErrQueueStorage, "GetRun", runID, err)
	}
	return record, nil
}

func (s *QueueStore) ListEligibleRuns(ctx context.Context, capabilities CapabilitySet, limit int) ([]RunRecord, error) {
	if limit < 1 || limit > 100 {
		return nil, queueError(ErrQueueInvalidInput, "ListEligibleRuns", "", errors.New("invalid limit"))
	}
	resources, models, certifications, labels, err := normalizeCapabilities(capabilities)
	if err != nil {
		return nil, queueError(ErrQueueInvalidInput, "ListEligibleRuns", "", err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT r.run_id, r.manifest_id, r.case_id, r.run_type, r.classification,
		       r.qualification_eligible, r.priority_class, r.required_resource_id,
		       r.required_model_id, r.required_certification_id, r.required_labels,
		       r.status, r.eligible_after, r.queued_at,
		       NULL::bytea, NULL::bytea
	`+eligibleRunsSQL+`
	LIMIT $5`, resources, models, certifications, labels, limit)
	if err != nil {
		return nil, queueError(ErrQueueStorage, "ListEligibleRuns", "", err)
	}
	defer rows.Close()
	var records []RunRecord
	for rows.Next() {
		record, err := scanRunRecord(rows)
		if err != nil {
			return nil, queueError(ErrQueueStorage, "ListEligibleRuns", "", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, queueError(ErrQueueStorage, "ListEligibleRuns", "", err)
	}
	return records, nil
}

func (s *QueueStore) CancelQueuedRun(ctx context.Context, runID, reason string) error {
	const op = "CancelQueuedRun"
	if err := mutationContext(ctx, op, runID); err != nil {
		return err
	}
	if err := validQueueIdentity(runID); err != nil || strings.TrimSpace(reason) == "" || len(reason) > 500 {
		return queueError(ErrQueueInvalidInput, op, runID, err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return queueError(ErrQueueStorage, op, runID, err)
	}
	defer tx.Rollback(ctx)
	command, err := tx.Exec(ctx, `
		UPDATE aipt.playtest_runs
		SET status = 'CANCELED', canceled_at = statement_timestamp(), cancel_reason = $2
		WHERE run_id = $1 AND status = 'QUEUED'`, runID, reason)
	if err != nil {
		return queueError(ErrQueueStorage, op, runID, err)
	}
	if command.RowsAffected() != 1 {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM aipt.playtest_runs WHERE run_id = $1`, runID).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
			return queueError(ErrQueueRunNotFound, op, runID, err)
		} else if err != nil {
			return queueError(ErrQueueStorage, op, runID, err)
		}
		return queueError(ErrQueueStateConflict, op, runID, errors.New("not queued"))
	}
	if err := tx.Commit(ctx); err != nil {
		return queueError(ErrQueueStorage, op, runID, err)
	}
	return nil
}

// SetQueuePaused controls new acquisition only. There is deliberately no API
// for pausing or resuming an active formal Run.
func (s *QueueStore) SetQueuePaused(ctx context.Context, paused bool, reason string) error {
	const op = "SetQueuePaused"
	if err := mutationContext(ctx, op, ""); err != nil {
		return err
	}
	if len(reason) > 500 {
		return queueError(ErrQueueInvalidInput, op, "", errors.New("reason too long"))
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE aipt.playtest_queue_control
		SET paused = $1, reason = NULLIF($2, ''), updated_at = statement_timestamp()
		WHERE control_id = 'GLOBAL'`, paused, reason); err != nil {
		return queueError(ErrQueueStorage, op, "", err)
	}
	return nil
}

func (s *QueueStore) AcquireLease(ctx context.Context, in AcquireLeaseInput) (Lease, error) {
	const op = "AcquireLease"
	if err := mutationContext(ctx, op, ""); err != nil {
		return Lease{}, err
	}
	if err := validQueueIdentity(in.HolderID); err != nil || in.LeaseDuration < time.Second || in.LeaseDuration > 24*time.Hour {
		return Lease{}, queueError(ErrQueueInvalidInput, op, "", err)
	}
	resources, models, certifications, labels, err := normalizeCapabilities(in.Capabilities)
	if err != nil {
		return Lease{}, queueError(ErrQueueInvalidInput, op, "", err)
	}
	rawToken, err := s.tokens.NewToken(ctx)
	if err != nil || len(rawToken) < 32 || len(rawToken) > 128 {
		return Lease{}, queueError(ErrLeaseTokenSource, op, "", err)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256([]byte(token))

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Lease{}, queueError(ErrQueueStorage, op, "", err)
	}
	defer tx.Rollback(ctx)
	var paused bool
	if err := tx.QueryRow(ctx, `SELECT paused FROM aipt.playtest_queue_control WHERE control_id = 'GLOBAL' FOR UPDATE`).Scan(&paused); err != nil {
		return Lease{}, queueError(ErrQueueStorage, op, "", err)
	}
	if paused {
		return Lease{}, queueError(ErrQueuePaused, op, "", nil)
	}
	if _, err := recoverExpiredTx(ctx, tx); err != nil {
		return Lease{}, queueError(ErrQueueStorage, op, "", err)
	}

	var runID, classification string
	if err := tx.QueryRow(ctx, `
		SELECT r.run_id, r.classification
	`+eligibleRunsSQL+`
	LIMIT 1
	FOR UPDATE OF r SKIP LOCKED`, resources, models, certifications, labels).Scan(&runID, &classification); errors.Is(err, pgx.ErrNoRows) {
		return Lease{}, queueError(ErrQueueNoEligibleRun, op, "", err)
	} else if err != nil {
		return Lease{}, queueError(ErrQueueStorage, op, "", err)
	}

	var generation int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(generation), 0) + 1 FROM aipt.run_leases WHERE run_id = $1`, runID).Scan(&generation); err != nil {
		return Lease{}, queueError(ErrQueueStorage, op, runID, err)
	}
	var formalSlot any
	formal := classification == "QUALIFICATION"
	if formal {
		formalSlot = int16(1)
	}
	lease := Lease{RunID: runID, Generation: generation, HolderID: in.HolderID, Token: token, Formal: formal}
	microseconds := in.LeaseDuration.Microseconds()
	if err := tx.QueryRow(ctx, `
		INSERT INTO aipt.run_leases
			(run_id, generation, holder_id, token_sha256, formal_slot, status, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE',
		        statement_timestamp() + ($6::bigint * interval '1 microsecond'))
		RETURNING lease_id, acquired_at, heartbeat_at, expires_at`,
		runID, generation, in.HolderID, tokenHash[:], formalSlot, microseconds).
		Scan(&lease.LeaseID, &lease.AcquiredAt, &lease.HeartbeatAt, &lease.ExpiresAt); err != nil {
		return Lease{}, queueDBError(op, runID, err, ErrQueueStateConflict)
	}
	command, err := tx.Exec(ctx, `UPDATE aipt.playtest_runs SET status = 'LEASED' WHERE run_id = $1 AND status = 'QUEUED'`, runID)
	if err != nil || command.RowsAffected() != 1 {
		return Lease{}, queueError(ErrQueueStateConflict, op, runID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Lease{}, queueError(ErrQueueStorage, op, runID, err)
	}
	return lease, nil
}

func (s *QueueStore) RenewLease(ctx context.Context, leaseID int64, token string, duration time.Duration) (time.Time, error) {
	const op = "RenewLease"
	if err := mutationContext(ctx, op, ""); err != nil {
		return time.Time{}, err
	}
	if leaseID < 1 || token == "" || duration < time.Second || duration > 24*time.Hour {
		return time.Time{}, queueError(ErrQueueInvalidInput, op, "", nil)
	}
	hash := sha256.Sum256([]byte(token))
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, queueError(ErrQueueStorage, op, "", err)
	}
	defer tx.Rollback(ctx)
	var expires time.Time
	err = tx.QueryRow(ctx, `
		UPDATE aipt.run_leases
		SET heartbeat_at = statement_timestamp(),
		    expires_at = statement_timestamp() + ($3::bigint * interval '1 microsecond')
		WHERE lease_id = $1 AND token_sha256 = $2 AND status = 'ACTIVE'
		  AND expires_at > statement_timestamp()
		RETURNING expires_at`, leaseID, hash[:], duration.Microseconds()).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, classifyLeaseFailure(ctx, tx, op, leaseID, hash[:])
	}
	if err != nil {
		return time.Time{}, queueError(ErrQueueStorage, op, "", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, queueError(ErrQueueStorage, op, "", err)
	}
	return expires, nil
}

func (s *QueueStore) ReleaseLease(ctx context.Context, leaseID int64, token string, disposition ReleaseDisposition) error {
	const op = "ReleaseLease"
	if err := mutationContext(ctx, op, ""); err != nil {
		return err
	}
	if leaseID < 1 || token == "" || (disposition != ReleaseRequeue && disposition != ReleaseComplete) {
		return queueError(ErrQueueInvalidInput, op, "", nil)
	}
	hash := sha256.Sum256([]byte(token))
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return queueError(ErrQueueStorage, op, "", err)
	}
	defer tx.Rollback(ctx)
	var runID, status string
	var tokenMatches, unexpired bool
	if err := tx.QueryRow(ctx, `
		SELECT run_id, status, token_sha256 = $2, expires_at > statement_timestamp()
		FROM aipt.run_leases WHERE lease_id = $1 FOR UPDATE`, leaseID, hash[:]).
		Scan(&runID, &status, &tokenMatches, &unexpired); errors.Is(err, pgx.ErrNoRows) {
		return queueError(ErrLeaseStale, op, "", err)
	} else if err != nil {
		return queueError(ErrQueueStorage, op, "", err)
	}
	if !tokenMatches || status != "ACTIVE" {
		return queueError(ErrLeaseStale, op, runID, nil)
	}
	if !unexpired {
		return queueError(ErrLeaseExpired, op, runID, nil)
	}
	leaseStatus, runStatus := "RELEASED", "QUEUED"
	if disposition == ReleaseComplete {
		leaseStatus, runStatus = "COMPLETED", "COMPLETED"
	}
	leaseCommand, err := tx.Exec(ctx, `UPDATE aipt.run_leases SET status = $2, ended_at = statement_timestamp() WHERE lease_id = $1 AND status = 'ACTIVE'`, leaseID, leaseStatus)
	if err != nil || leaseCommand.RowsAffected() != 1 {
		return queueError(ErrQueueStorage, op, runID, err)
	}
	var runCommand pgconn.CommandTag
	if runStatus == "COMPLETED" {
		runCommand, err = tx.Exec(ctx, `UPDATE aipt.playtest_runs SET status = 'COMPLETED', completed_at = statement_timestamp() WHERE run_id = $1 AND status = 'LEASED'`, runID)
	} else {
		runCommand, err = tx.Exec(ctx, `UPDATE aipt.playtest_runs SET status = 'QUEUED' WHERE run_id = $1 AND status = 'LEASED'`, runID)
	}
	if err != nil || runCommand.RowsAffected() != 1 {
		return queueError(ErrQueueStorage, op, runID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return queueError(ErrQueueStorage, op, runID, err)
	}
	return nil
}

func (s *QueueStore) RecoverExpiredLeases(ctx context.Context) ([]string, error) {
	const op = "RecoverExpiredLeases"
	if err := mutationContext(ctx, op, ""); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, queueError(ErrQueueStorage, op, "", err)
	}
	defer tx.Rollback(ctx)
	var ignored bool
	if err := tx.QueryRow(ctx, `SELECT paused FROM aipt.playtest_queue_control WHERE control_id = 'GLOBAL' FOR UPDATE`).Scan(&ignored); err != nil {
		return nil, queueError(ErrQueueStorage, op, "", err)
	}
	recovered, err := recoverExpiredTx(ctx, tx)
	if err != nil {
		return nil, queueError(ErrQueueStorage, op, "", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, queueError(ErrQueueStorage, op, "", err)
	}
	return recovered, nil
}

func recoverExpiredTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `
		WITH expired AS (
			UPDATE aipt.run_leases
			SET status = 'EXPIRED', ended_at = statement_timestamp()
			WHERE status = 'ACTIVE' AND expires_at <= statement_timestamp()
			RETURNING run_id
		)
		UPDATE aipt.playtest_runs r
		SET status = 'QUEUED'
		FROM expired e
		WHERE r.run_id = e.run_id AND r.status = 'LEASED'
		RETURNING r.run_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recovered []string
	for rows.Next() {
		var runID string
		if err := rows.Scan(&runID); err != nil {
			return nil, err
		}
		recovered = append(recovered, runID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(recovered)
	return recovered, nil
}

func classifyLeaseFailure(ctx context.Context, tx pgx.Tx, op string, leaseID int64, tokenHash []byte) error {
	var status string
	var tokenMatches, expired bool
	if err := tx.QueryRow(ctx, `
		SELECT status, token_sha256 = $2, expires_at <= statement_timestamp()
		FROM aipt.run_leases WHERE lease_id = $1`, leaseID, tokenHash).Scan(&status, &tokenMatches, &expired); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return queueError(ErrLeaseStale, op, "", err)
		}
		return queueError(ErrQueueStorage, op, "", err)
	}
	if tokenMatches && status == "ACTIVE" && expired {
		return queueError(ErrLeaseExpired, op, "", nil)
	}
	return queueError(ErrLeaseStale, op, "", nil)
}

func (s *QueueStore) AppendAttempt(ctx context.Context, runID, attemptID string, kind AttemptKind, outcome AttemptOutcome, evidence *[32]byte) (AttemptRecordValue, error) {
	const op = "AppendAttempt"
	if err := mutationContext(ctx, op, runID); err != nil {
		return AttemptRecordValue{}, err
	}
	if err := validQueueIdentity(runID); err != nil {
		return AttemptRecordValue{}, queueError(ErrQueueInvalidInput, op, runID, err)
	}
	if err := validQueueIdentity(attemptID); err != nil || !validAttemptKind(kind) || !validAttemptOutcome(outcome) {
		return AttemptRecordValue{}, queueError(ErrQueueInvalidInput, op, runID, err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AttemptRecordValue{}, queueError(ErrQueueStorage, op, runID, err)
	}
	defer tx.Rollback(ctx)
	var locked string
	if err := tx.QueryRow(ctx, `SELECT run_id FROM aipt.playtest_runs WHERE run_id = $1 FOR UPDATE`, runID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return AttemptRecordValue{}, queueError(ErrQueueRunNotFound, op, runID, err)
	} else if err != nil {
		return AttemptRecordValue{}, queueError(ErrQueueStorage, op, runID, err)
	}
	var number int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(attempt_number), 0) + 1 FROM aipt.run_attempts WHERE run_id = $1`, runID).Scan(&number); err != nil {
		return AttemptRecordValue{}, queueError(ErrQueueStorage, op, runID, err)
	}
	var evidenceBytes []byte
	if evidence != nil {
		evidenceBytes = evidence[:]
	}
	record := AttemptRecordValue{RunID: runID, AttemptNumber: number, AttemptID: attemptID, Kind: kind, Outcome: outcome, EvidenceSHA256: evidence}
	if err := tx.QueryRow(ctx, `
		INSERT INTO aipt.run_attempts (run_id, attempt_number, attempt_id, attempt_kind, outcome, evidence_sha256)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING recorded_at`, runID, number, attemptID, string(kind), string(outcome), evidenceBytes).Scan(&record.RecordedAt); err != nil {
		return AttemptRecordValue{}, queueDBError(op, runID, err, ErrAttemptConflict)
	}
	if err := tx.Commit(ctx); err != nil {
		return AttemptRecordValue{}, queueError(ErrQueueStorage, op, runID, err)
	}
	return record, nil
}

func (s *QueueStore) ReadAttempts(ctx context.Context, runID string) ([]AttemptRecordValue, error) {
	if err := validQueueIdentity(runID); err != nil {
		return nil, queueError(ErrQueueInvalidInput, "ReadAttempts", runID, err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT run_id, attempt_number, attempt_id, attempt_kind, outcome, evidence_sha256, recorded_at
		FROM aipt.run_attempts WHERE run_id = $1 ORDER BY attempt_number ASC`, runID)
	if err != nil {
		return nil, queueError(ErrQueueStorage, "ReadAttempts", runID, err)
	}
	defer rows.Close()
	var records []AttemptRecordValue
	for rows.Next() {
		var record AttemptRecordValue
		var kind, outcome string
		var evidence []byte
		if err := rows.Scan(&record.RunID, &record.AttemptNumber, &record.AttemptID, &kind, &outcome, &evidence, &record.RecordedAt); err != nil {
			return nil, queueError(ErrQueueStorage, "ReadAttempts", runID, err)
		}
		record.Kind, record.Outcome = AttemptKind(kind), AttemptOutcome(outcome)
		if len(evidence) != 0 {
			if len(evidence) != 32 {
				return nil, queueError(ErrQueueStorage, "ReadAttempts", runID, errors.New("invalid digest"))
			}
			var digest [32]byte
			copy(digest[:], evidence)
			record.EvidenceSHA256 = &digest
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, queueError(ErrQueueStorage, "ReadAttempts", runID, err)
	}
	return records, nil
}

type rowScanner interface{ Scan(dest ...any) error }

func scanRunRecord(row rowScanner) (RunRecord, error) {
	var record RunRecord
	var priority, status string
	var digest []byte
	err := row.Scan(&record.RunID, &record.ManifestID, &record.CaseID, &record.RunType,
		&record.Classification, &record.QualificationEligible, &priority,
		&record.RequiredResourceID, &record.RequiredModelID, &record.RequiredCertificationID,
		&record.RequiredLabels, &status, &record.EligibleAfter, &record.QueuedAt,
		&record.ManifestCanonical, &digest)
	if err != nil {
		return RunRecord{}, err
	}
	record.Priority, record.Status = PriorityClass(priority), RunStatus(status)
	if len(digest) != 0 {
		if len(digest) != 32 {
			return RunRecord{}, errors.New("manifest digest length")
		}
		copy(record.ManifestSHA256[:], digest)
	}
	record.ManifestCanonical = append([]byte(nil), record.ManifestCanonical...)
	return record, nil
}

func validateEnqueueInput(in EnqueueRunInput, manifest testplan.RunManifest) error {
	for _, name := range []string{in.CampaignName, in.SuiteName, in.CaseName} {
		if !utf8.ValidString(name) || strings.TrimSpace(name) == "" || len([]rune(name)) > 200 {
			return errors.New("invalid ancestry name")
		}
	}
	if _, ok := validPriorities[in.Priority]; !ok {
		return errors.New("invalid priority")
	}
	for _, identity := range []string{in.RequiredResourceID, in.RequiredModelID, in.RequiredCertificationID} {
		if err := validQueueIdentity(identity); err != nil {
			return err
		}
	}
	if manifest.ManifestID == "" || manifest.RunID == "" || manifest.Ancestry.CampaignID == "" || manifest.Ancestry.SuiteID == "" || manifest.Ancestry.CaseID == "" {
		return errors.New("incomplete manifest identity")
	}
	return nil
}

func normalizeCapabilities(in CapabilitySet) ([]string, []string, []string, []string, error) {
	resources, err := normalizedIdentities(in.ResourceIDs, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	models, err := normalizedIdentities(in.ModelIDs, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	certifications, err := normalizedIdentities(in.CertificationIDs, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	labels, err := normalizedIdentities(in.Labels, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return resources, models, certifications, labels, nil
}

func normalizedIdentities(values []string, allowEmpty bool) ([]string, error) {
	if !allowEmpty && len(values) == 0 {
		return nil, errors.New("empty identity set")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if err := validQueueIdentity(value); err != nil {
			return nil, err
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validQueueIdentity(value string) error {
	if !utf8.ValidString(value) || !queueIdentityRE.MatchString(value) {
		return errors.New("invalid bounded identity")
	}
	return nil
}

func validAttemptKind(value AttemptKind) bool {
	return value == AttemptNewRun || value == AttemptSameRunRecovery || value == AttemptRecord
}
func validAttemptOutcome(value AttemptOutcome) bool {
	return value == AttemptStarted || value == AttemptFailed || value == AttemptSucceeded || value == AttemptCanceled
}

func mutationContext(ctx context.Context, operation, runID string) error {
	if ctx == nil {
		return queueError(ErrQueueInvalidInput, operation, runID, errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return queueError(ErrQueueStateConflict, operation, runID, err)
	}
	return nil
}

func queueDBError(operation, runID string, err error, conflictCode error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "23503" || pgErr.Code == "23514" || pgErr.Code == "55000") {
		return queueError(conflictCode, operation, runID, err)
	}
	return queueError(ErrQueueStorage, operation, runID, err)
}
