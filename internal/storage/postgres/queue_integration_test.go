package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/testplan"
)

type deterministicTokenSource struct{ next atomic.Uint64 }

func (s *deterministicTokenSource) NewToken(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("AIPT-B001-FIXED-TEST-TOKEN-%020d", s.next.Add(1))))
	return sum[:], nil
}

func queueTestStore(t *testing.T, pool *pgxpool.Pool) *QueueStore {
	t.Helper()
	store, err := NewQueueStore(pool, &deterministicTokenSource{})
	if err != nil {
		t.Fatalf("NewQueueStore: %v", err)
	}
	return store
}

func queueTestManifest(t *testing.T, runID, classification string) []byte {
	t.Helper()
	manifest := testplan.RunManifest{
		Schema: testplan.RunManifestSchema, ManifestID: "manifest-" + runID, RunID: runID,
		Ancestry: testplan.Ancestry{CampaignID: "campaign-" + runID, SuiteID: "suite-" + runID, CaseID: "case-" + runID},
		RunType:  testplan.TaskRule,
		Source: testplan.SourceBinding{
			AIPT: testplan.RepositorySource{Repository: "zyc14588/AIPT", Commit: "64b5692971bbe687884ec34bd6417fe803987ae9", Tree: "1a6feabb1796af9f66fd78fc842f249ec03a5251"},
			Game: testplan.RepositorySource{Repository: "fixture/game", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)},
		},
		ModelAssignments:    []testplan.ModelAssignment{{AssignmentID: "assignment-1", ModelProfileID: "model-profile-v1"}},
		PromptAssets:        []testplan.PromptAsset{{AssetID: "prompt-asset-v1", SHA256: strings.Repeat("3", 64)}},
		SeatRoster:          []testplan.Seat{{SeatID: "gm", RoleID: "GM", ModelAssignmentID: "assignment-1"}},
		Budget:              testplan.BudgetBinding{PolicyID: "budget-policy-v1", LimitsID: "budget-limits-v1", MaxInputTokens: 10000, MaxOutputTokens: 2000, MaxDurationSeconds: 300},
		Evidence:            testplan.EvidenceBinding{ProfileID: "evidence-profile-v1", ConfigID: "evidence-config-v1"},
		VisibilityProfileID: "AIPT_VISIBILITY_STANDARD_V1", SafetyApplicable: false, SafetyProfileID: "NOT_APPLICABLE",
		Classification: classification, QualificationEligible: classification == "QUALIFICATION",
	}
	frozen, err := testplan.BindRunManifest(manifest)
	if err != nil {
		t.Fatalf("BindRunManifest(%s): %v", runID, err)
	}
	return frozen.Canonical
}

func enqueueQueueTestRun(t *testing.T, ctx context.Context, store *QueueStore, runID string, classification string, priority PriorityClass, dependencies ...string) RunRecord {
	t.Helper()
	record, err := store.EnqueueRun(ctx, EnqueueRunInput{
		ManifestBytes: queueTestManifest(t, runID, classification),
		CampaignName:  "Campaign " + runID, SuiteName: "Suite " + runID, CaseName: "Case " + runID,
		Priority:           priority,
		RequiredResourceID: "resource-fixture-v1", RequiredModelID: "model-fixture-v1",
		RequiredCertificationID: "certification-fixture-v1", RequiredLabels: []string{"linux", "playtest"},
		DependencyRunIDs: dependencies,
	})
	if err != nil {
		t.Fatalf("EnqueueRun(%s): %v", runID, err)
	}
	return record
}

func queueCapabilities() CapabilitySet {
	return CapabilitySet{
		ResourceIDs: []string{"resource-fixture-v1"}, ModelIDs: []string{"model-fixture-v1"},
		CertificationIDs: []string{"certification-fixture-v1"}, Labels: []string{"playtest", "linux", "extra"},
	}
}

func assertPGCode(t *testing.T, err error, code, marker string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("error = %v, want *pgconn.PgError", err)
	}
	if pgErr.Code != code || !strings.Contains(pgErr.Message, marker) {
		t.Fatalf("error = SQLSTATE %s %q, want %s/%s", pgErr.Code, pgErr.Message, code, marker)
	}
}

func TestPostgresIntegrationQueueUpgradeFromB003(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := fx.pool(ctx)
	defer pool.Close()
	ledgerBytes, err := fs.ReadFile(migrationsFS, "migrations/000001_ledger.sql")
	if err != nil {
		t.Fatal(err)
	}
	ledgerOnly := fstest.MapFS{"migrations/000001_ledger.sql": &fstest.MapFile{Data: ledgerBytes}}
	if err := migrateUpFS(ctx, pool, ledgerOnly); err != nil {
		t.Fatalf("B003-only MigrateUp: %v", err)
	}
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("upgrade to B001: %v", err)
	}
	versions, err := queryInt64s(ctx, pool, "SELECT version FROM aipt.schema_migrations ORDER BY version")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0] != 1 || versions[1] != 2 {
		t.Fatalf("migration versions = %v, want [1 2]", versions)
	}
	var ledgerChecksum, queueChecksum []byte
	if err := pool.QueryRow(ctx, `SELECT checksum FROM aipt.schema_migrations WHERE version = 1`).Scan(&ledgerChecksum); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT checksum FROM aipt.schema_migrations WHERE version = 2`).Scan(&queueChecksum); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", ledgerChecksum) != ledgerMigrationChecksumHex || fmt.Sprintf("%x", queueChecksum) != queueMigrationChecksumHex {
		t.Fatal("migration checksum binding drifted")
	}
}

func TestPostgresIntegrationQueueManifestImmutableEnqueueCancelNewRunAndRollback(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := fx.pool(ctx)
	defer pool.Close()
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := queueTestStore(t, pool)
	old := enqueueQueueTestRun(t, ctx, store, "run-old", "QUALIFICATION", PrioritySystem)
	read, err := store.GetRun(ctx, old.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if read.ManifestID != old.ManifestID || !strings.Contains(string(read.ManifestCanonical), `"run_id":"run-old"`) {
		t.Fatal("enqueue/read binding drifted")
	}

	for label, sql := range map[string]string{
		"update":   `UPDATE aipt.run_manifests SET manifest_bytes = '\x7b7d' WHERE run_id = 'run-old'`,
		"delete":   `DELETE FROM aipt.run_manifests WHERE run_id = 'run-old'`,
		"truncate": `TRUNCATE aipt.run_manifests`,
	} {
		t.Run(label, func(t *testing.T) {
			_, err := pool.Exec(ctx, sql)
			assertPGCode(t, err, "55000", "AIPT_RUN_MANIFEST_IMMUTABLE")
		})
	}
	if err := store.CancelQueuedRun(ctx, "run-old", "superseded by immutable new Run"); err != nil {
		t.Fatal(err)
	}
	newRun := enqueueQueueTestRun(t, ctx, store, "run-new", "QUALIFICATION", PrioritySystem)
	if newRun.RunID == old.RunID || newRun.ManifestSHA256 == old.ManifestSHA256 {
		t.Fatal("cancel+new semantics did not create distinct identities")
	}
	oldRead, err := store.GetRun(ctx, "run-old")
	if err != nil || oldRead.Status != RunCanceled {
		t.Fatalf("old Run = %+v, %v", oldRead, err)
	}

	_, err = store.EnqueueRun(ctx, EnqueueRunInput{
		ManifestBytes: queueTestManifest(t, "run-rollback", "QUALIFICATION"),
		CampaignName:  "Rollback Campaign", SuiteName: "Rollback Suite", CaseName: "Rollback Case",
		Priority: PrioritySystem, RequiredResourceID: "resource-fixture-v1", RequiredModelID: "model-fixture-v1",
		RequiredCertificationID: "certification-fixture-v1", RequiredLabels: []string{"playtest"},
		DependencyRunIDs: []string{"missing-predecessor"},
	})
	if !errors.Is(err, ErrQueueStateConflict) {
		t.Fatalf("rollback enqueue error = %v", err)
	}
	for table, column := range map[string]string{
		"playtest_campaigns": "campaign_id", "playtest_suites": "suite_id", "playtest_cases": "case_id",
		"run_manifests": "run_id", "playtest_runs": "run_id",
	} {
		var count int
		identity := map[string]string{"playtest_campaigns": "campaign-run-rollback", "playtest_suites": "suite-run-rollback", "playtest_cases": "case-run-rollback", "run_manifests": "run-rollback", "playtest_runs": "run-rollback"}[table]
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM aipt.%s WHERE %s = $1`, table, column), identity).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rollback left %s row: count=%d err=%v", table, count, err)
		}
	}
}

func TestPostgresIntegrationQueueDeterministicEligibilityPauseAndDependencies(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := fx.pool(ctx)
	defer pool.Close()
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := queueTestStore(t, pool)
	enqueueQueueTestRun(t, ctx, store, "run-background", "QUALIFICATION", PriorityBackground)
	enqueueQueueTestRun(t, ctx, store, "run-release", "QUALIFICATION", PriorityRelease)
	enqueueQueueTestRun(t, ctx, store, "run-blocked", "QUALIFICATION", PriorityHotfix, "run-background")

	missing, err := store.ListEligibleRuns(ctx, CapabilitySet{}, 10)
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing capability fail-closed = %v, %v", missing, err)
	}
	eligible, err := store.ListEligibleRuns(ctx, queueCapabilities(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(eligible) != 2 || eligible[0].RunID != "run-release" || eligible[1].RunID != "run-background" {
		t.Fatalf("eligible order = %+v", eligible)
	}
	if err := store.SetQueuePaused(ctx, true, "operator queue boundary"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcquireLease(ctx, AcquireLeaseInput{HolderID: "worker-1", LeaseDuration: time.Minute, Capabilities: queueCapabilities()}); !errors.Is(err, ErrQueuePaused) {
		t.Fatalf("paused acquire error = %v", err)
	}
	if err := store.SetQueuePaused(ctx, false, ""); err != nil {
		t.Fatal(err)
	}
	lease, err := store.AcquireLease(ctx, AcquireLeaseInput{HolderID: "worker-1", LeaseDuration: time.Minute, Capabilities: queueCapabilities()})
	if err != nil || lease.RunID != "run-release" {
		t.Fatalf("lease = %+v, %v", lease, err)
	}
	if err := store.ReleaseLease(ctx, lease.LeaseID, lease.Token, ReleaseComplete); err != nil {
		t.Fatal(err)
	}
	eligible, err = store.ListEligibleRuns(ctx, queueCapabilities(), 10)
	if err != nil || len(eligible) != 1 || eligible[0].RunID != "run-background" {
		t.Fatalf("post-dependency eligible = %+v, %v", eligible, err)
	}
}

func TestPostgresIntegrationQueueConcurrentFormalClaimsWIP1(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := ledgerNewPool(ctx, t, fx, 24)
	defer pool.Close()
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := queueTestStore(t, pool)
	enqueueQueueTestRun(t, ctx, store, "run-formal-a", "QUALIFICATION", PrioritySystem)
	enqueueQueueTestRun(t, ctx, store, "run-formal-b", "QUALIFICATION", PrioritySystem)

	const claimers = 16
	start := make(chan struct{})
	results := make(chan struct {
		lease Lease
		err   error
	}, claimers)
	var wg sync.WaitGroup
	for i := 0; i < claimers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			lease, err := store.AcquireLease(ctx, AcquireLeaseInput{HolderID: fmt.Sprintf("worker-%02d", index), LeaseDuration: time.Minute, Capabilities: queueCapabilities()})
			results <- struct {
				lease Lease
				err   error
			}{lease, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var successes int
	var winner Lease
	for result := range results {
		if result.err == nil {
			successes++
			winner = result.lease
			continue
		}
		if !errors.Is(result.err, ErrQueueNoEligibleRun) {
			t.Errorf("claim error = %v", result.err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful formal claims = %d, want 1", successes)
	}
	var active, leased int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM aipt.run_leases WHERE status = 'ACTIVE' AND formal_slot = 1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM aipt.playtest_runs WHERE status = 'LEASED' AND classification = 'QUALIFICATION'`).Scan(&leased); err != nil {
		t.Fatal(err)
	}
	if active != 1 || leased != 1 {
		t.Fatalf("authority state active=%d leased=%d", active, leased)
	}
	other := "run-formal-a"
	if winner.RunID == other {
		other = "run-formal-b"
	}
	duplicateHash := sha256.Sum256([]byte("duplicate-formal-slot"))
	_, err := pool.Exec(ctx, `
		INSERT INTO aipt.run_leases (run_id, generation, holder_id, token_sha256, formal_slot, status, expires_at)
		VALUES ($1, 1, 'bypass-worker', $2, 1, 'ACTIVE', statement_timestamp() + interval '1 minute')`, other, duplicateHash[:])
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "run_leases_one_active_formal_slot" {
		t.Fatalf("duplicate formal lease error = %v", err)
	}
}

func TestPostgresIntegrationQueueLeaseHeartbeatExpiryRecoveryAndStaleHolder(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool := fx.pool(ctx)
	defer pool.Close()
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := queueTestStore(t, pool)
	enqueueQueueTestRun(t, ctx, store, "run-recovery", "QUALIFICATION", PrioritySystem)
	lease, err := store.AcquireLease(ctx, AcquireLeaseInput{HolderID: "worker-old", LeaseDuration: time.Second, Capabilities: queueCapabilities()})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := store.RenewLease(ctx, lease.LeaseID, lease.Token, 2*time.Second)
	if err != nil || !renewed.After(lease.ExpiresAt) {
		t.Fatalf("renewed=%v err=%v original=%v", renewed, err, lease.ExpiresAt)
	}
	if _, err := store.RenewLease(ctx, lease.LeaseID, lease.Token+"stale", 2*time.Second); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("stale token error = %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(2.1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RenewLease(ctx, lease.LeaseID, lease.Token, time.Minute); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expired renew error = %v", err)
	}
	recovered, err := store.RecoverExpiredLeases(ctx)
	if err != nil || len(recovered) != 1 || recovered[0] != "run-recovery" {
		t.Fatalf("recovered=%v err=%v", recovered, err)
	}
	newLease, err := store.AcquireLease(ctx, AcquireLeaseInput{HolderID: "worker-new", LeaseDuration: time.Minute, Capabilities: queueCapabilities()})
	if err != nil || newLease.Generation != lease.Generation+1 || newLease.Token == lease.Token {
		t.Fatalf("new lease=%+v err=%v", newLease, err)
	}
	if _, err := store.RenewLease(ctx, lease.LeaseID, lease.Token, time.Minute); !errors.Is(err, ErrLeaseStale) {
		t.Fatalf("old holder renewal error = %v", err)
	}
	if err := store.ReleaseLease(ctx, newLease.LeaseID, newLease.Token, ReleaseComplete); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresIntegrationQueueAttemptAppendHistory(t *testing.T) {
	fx := newIntegrationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := fx.pool(ctx)
	defer pool.Close()
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := queueTestStore(t, pool)
	enqueueQueueTestRun(t, ctx, store, "run-attempts", "DIAGNOSTIC", PriorityExploratory)
	digest := sha256.Sum256([]byte("failed-attempt-evidence"))
	if _, err := store.AppendAttempt(ctx, "run-attempts", "attempt-1", AttemptNewRun, AttemptFailed, &digest); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendAttempt(ctx, "run-attempts", "attempt-2", AttemptSameRunRecovery, AttemptFailed, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendAttempt(ctx, "run-attempts", "attempt-3", AttemptRecord, AttemptSucceeded, nil); err != nil {
		t.Fatal(err)
	}
	records, err := store.ReadAttempts(ctx, "run-attempts")
	if err != nil || len(records) != 3 {
		t.Fatalf("attempts=%+v err=%v", records, err)
	}
	for index, record := range records {
		if record.AttemptNumber != int64(index+1) {
			t.Fatalf("attempt numbering = %+v", records)
		}
	}
	if records[0].Outcome != AttemptFailed || records[2].Outcome != AttemptSucceeded {
		t.Fatal("failed history was hidden")
	}
	for label, sql := range map[string]string{
		"update":   `UPDATE aipt.run_attempts SET outcome = 'SUCCEEDED' WHERE attempt_id = 'attempt-1'`,
		"delete":   `DELETE FROM aipt.run_attempts WHERE attempt_id = 'attempt-1'`,
		"truncate": `TRUNCATE aipt.run_attempts`,
	} {
		t.Run(label, func(t *testing.T) {
			_, err := pool.Exec(ctx, sql)
			assertPGCode(t, err, "55000", "AIPT_RUN_ATTEMPT_APPEND_ONLY")
		})
	}
}
