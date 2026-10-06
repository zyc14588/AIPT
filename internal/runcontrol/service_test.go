package runcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// This in-memory queue is test-only. PostgreSQL authority is separately tested
// in internal/storage/postgres/b006_control_integration_test.go.
type testQueue struct {
	mu         sync.Mutex
	records    map[string]postgres.RunRecord
	attempts   map[string][]postgres.AttemptRecordValue
	paused     bool
	leases     int
	renewals   int
	renewError error
}

func newTestQueue() *testQueue {
	return &testQueue{records: map[string]postgres.RunRecord{}, attempts: map[string][]postgres.AttemptRecordValue{}}
}
func (q *testQueue) EnqueueRun(ctx context.Context, input postgres.EnqueueRunInput) (postgres.RunRecord, error) {
	f, err := testplan.DecodeRunManifest(input.ManifestBytes)
	if err != nil {
		return postgres.RunRecord{}, err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, exists := q.records[f.Manifest.RunID]; exists {
		return postgres.RunRecord{}, postgres.ErrQueueRunExists
	}
	r := postgres.RunRecord{RunID: f.Manifest.RunID, ManifestID: f.Manifest.ManifestID, CaseID: f.Manifest.Ancestry.CaseID, RunType: string(f.Manifest.RunType), Classification: f.Manifest.Classification, QualificationEligible: f.Manifest.QualificationEligible, Priority: input.Priority, Status: postgres.RunQueued, ManifestCanonical: f.Canonical, ManifestSHA256: f.Digest, RequiredResourceID: input.RequiredResourceID, RequiredModelID: input.RequiredModelID, RequiredCertificationID: input.RequiredCertificationID}
	q.records[r.RunID] = r
	return r, nil
}
func (q *testQueue) GetRun(ctx context.Context, id string) (postgres.RunRecord, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.records[id]
	if !ok {
		return r, postgres.ErrQueueRunNotFound
	}
	r.ManifestCanonical = append([]byte(nil), r.ManifestCanonical...)
	return r, nil
}
func (q *testQueue) SetQueuePaused(ctx context.Context, paused bool, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.paused = paused
	return nil
}
func (q *testQueue) CancelQueuedRun(ctx context.Context, id, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.records[id]
	if !ok {
		return postgres.ErrQueueRunNotFound
	}
	if r.Status != postgres.RunQueued {
		return postgres.ErrQueueStateConflict
	}
	r.Status = postgres.RunCanceled
	q.records[id] = r
	return nil
}
func (q *testQueue) RecoverExpiredLeases(context.Context) ([]string, error) { return []string{}, nil }
func (q *testQueue) AcquireLease(ctx context.Context, in postgres.AcquireLeaseInput) (postgres.Lease, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.paused {
		return postgres.Lease{}, postgres.ErrQueuePaused
	}
	for id, r := range q.records {
		if r.Status == postgres.RunQueued {
			q.leases++
			r.Status = postgres.RunLeased
			q.records[id] = r
			return postgres.Lease{LeaseID: int64(q.leases), RunID: id, Token: "PRIVATE_LEASE_TOKEN_SENTINEL", Formal: r.QualificationEligible}, nil
		}
	}
	return postgres.Lease{}, postgres.ErrQueueNoEligibleRun
}
func (q *testQueue) RenewLease(ctx context.Context, id int64, token string, duration time.Duration) (time.Time, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.renewals++
	return time.Now().Add(duration), q.renewError
}
func (q *testQueue) ReleaseLease(ctx context.Context, id int64, token string, disposition postgres.ReleaseDisposition) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for run, r := range q.records {
		if r.Status == postgres.RunLeased {
			r.Status = postgres.RunQueued
			if disposition == postgres.ReleaseComplete {
				r.Status = postgres.RunCompleted
			}
			q.records[run] = r
		}
	}
	return nil
}
func (q *testQueue) AppendAttempt(ctx context.Context, id, attempt string, kind postgres.AttemptKind, outcome postgres.AttemptOutcome, evidence *[32]byte) (postgres.AttemptRecordValue, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	v := postgres.AttemptRecordValue{RunID: id, AttemptID: attempt, AttemptNumber: int64(len(q.attempts[id]) + 1), Kind: kind, Outcome: outcome, EvidenceSHA256: evidence}
	q.attempts[id] = append(q.attempts[id], v)
	return v, nil
}
func (q *testQueue) ReadAttempts(ctx context.Context, id string) ([]postgres.AttemptRecordValue, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]postgres.AttemptRecordValue(nil), q.attempts[id]...), nil
}
func (q *testQueue) Snapshot(ctx context.Context, limit int) (QueueSnapshot, error) {
	if limit < 1 || limit > 100 {
		return QueueSnapshot{}, ErrInvalid
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	v := QueueSnapshot{Paused: q.paused, Records: []postgres.RunRecord{}}
	for _, r := range q.records {
		v.Records = append(v.Records, r)
	}
	return v, nil
}

func definition(t *testing.T, id string, qual bool) Definition {
	t.Helper()
	classification := "DIAGNOSTIC"
	if qual {
		classification = "QUALIFICATION"
	}
	manifest := testplan.RunManifest{Schema: testplan.RunManifestSchema, RunID: id, ManifestID: "manifest-" + id, Ancestry: testplan.Ancestry{CampaignID: "campaign-" + id, SuiteID: "suite-" + id, CaseID: "case-" + id}, RunType: testplan.TaskRule, Source: testplan.SourceBinding{AIPT: testplan.RepositorySource{Repository: "zyc14588/AIPT", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}, Game: testplan.RepositorySource{Repository: "fixture/game", Commit: strings.Repeat("3", 40), Tree: strings.Repeat("4", 40)}}, ModelAssignments: []testplan.ModelAssignment{{AssignmentID: "model-a", ModelProfileID: "profile-a"}}, PromptAssets: []testplan.PromptAsset{{AssetID: "prompt-a", SHA256: strings.Repeat("5", 64)}}, SeatRoster: []testplan.Seat{{SeatID: "gm", RoleID: "GM", ModelAssignmentID: "model-a"}, {SeatID: "p1", RoleID: "PLAYER", ModelAssignmentID: "model-a"}, {SeatID: "p2", RoleID: "PLAYER", ModelAssignmentID: "model-a"}, {SeatID: "p3", RoleID: "PLAYER", ModelAssignmentID: "model-a"}, {SeatID: "p4", RoleID: "PLAYER", ModelAssignmentID: "model-a"}}, Budget: testplan.BudgetBinding{PolicyID: "policy-a", LimitsID: "limits-a", MaxInputTokens: 100, MaxOutputTokens: 100, MaxDurationSeconds: 30}, Evidence: testplan.EvidenceBinding{ProfileID: "evidence-a", ConfigID: "config-a"}, VisibilityProfileID: "AIPT_VISIBILITY_STANDARD_V1", SafetyApplicable: false, SafetyProfileID: "NOT_APPLICABLE", Classification: classification, QualificationEligible: qual}
	frozen, err := testplan.BindRunManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return Definition{ID: id, Input: postgres.EnqueueRunInput{ManifestBytes: frozen.Canonical, CampaignName: "protocol fixture", SuiteName: "control fixture", CaseName: "counter fixture", Priority: postgres.PrioritySystem, RequiredResourceID: "resource-a", RequiredModelID: "model-a", RequiredCertificationID: "cert-a", RequiredLabels: []string{}, DependencyRunIDs: []string{}}}
}
func testService(t *testing.T, q *testQueue, executor Executor, reports Reports, definitions ...Definition) *Service {
	t.Helper()
	s, err := New(Options{Queue: q, Reader: q, Definitions: definitions, Executor: executor, Reports: reports, Lifetime: context.Background(), HolderID: "test-holder", LeaseDuration: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	return s
}

type executorFunc func(context.Context, Execution) (Completion, error)

func (f executorFunc) Execute(ctx context.Context, input Execution) (Completion, error) {
	return f(ctx, input)
}

type testReports struct {
	root [32]byte
	err  error
}

func (r testReports) Inspect(ctx context.Context, record postgres.RunRecord) (ReportView, error) {
	return ReportView{RunID: record.RunID, Root: fmt.Sprintf("%x", r.root), ExecutionStatus: "COMPLETED", QualificationEligible: false}, r.err
}
func (r testReports) Export(context.Context, postgres.RunRecord, string) (Download, error) {
	return Download{}, ErrReportUnavailable
}

func waitWorker(t *testing.T, s *Service) {
	t.Helper()
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()
	if active == nil {
		return
	}
	select {
	case <-active.done:
	case <-time.After(4 * time.Second):
		t.Fatal("worker not joined")
	}
}

func TestSharedCommandsDoNotExposeManifestOrLease(t *testing.T) {
	q := newTestQueue()
	s := testService(t, q, nil, nil, definition(t, "run-a", false))
	ctx := context.Background()
	if _, err := s.Invoke(ctx, "aipt.v1.queue.enqueue", json.RawMessage(`{"registration_id":"run-a"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunNext(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unconfigured executor: %v", err)
	}
	q.mu.Lock()
	claims := q.leases
	q.mu.Unlock()
	if claims != 0 {
		t.Fatal("unconfigured start claimed a lease")
	}
	detail, err := s.Run(ctx, "run-a")
	if err != nil || len(detail.Seats) != 5 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	snapshot, err := s.Snapshot(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(struct {
		Snapshot Snapshot
		Detail   RunDetail
	}{snapshot, detail})
	for _, secret := range []string{"PRIVATE_LEASE_TOKEN_SENTINEL", "manifest_canonical", "prompt_assets", "domain_state", "seed", "dsn", "source", "token"} {
		if bytes.Contains(bytes.ToLower(data), []byte(strings.ToLower(secret))) {
			t.Fatalf("public view leaked %q", secret)
		}
	}
	if _, err := s.Invoke(ctx, "aipt.v1.queue.pause", json.RawMessage(`{"paused":true}`)); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = s.Snapshot(ctx, 100)
	if !snapshot.Paused || snapshot.Items[0].Status != postgres.RunQueued {
		t.Fatal("pause mutated active run state")
	}
	if _, err := s.Invoke(ctx, "aipt.v1.queue.cancel", json.RawMessage(`{"run_id":"run-a"}`)); err != nil {
		t.Fatal(err)
	}
	detail, _ = s.Run(ctx, "run-a")
	if detail.Run.Status != postgres.RunCanceled {
		t.Fatal("cancel lost authoritative state")
	}
}

func TestStrictRequestMutationsAndNoCallerExecutionKnobs(t *testing.T) {
	q := newTestQueue()
	s := testService(t, q, nil, nil, definition(t, "run-a", false))
	valid := `{"jsonrpc":"2.0","protocol_version":1,"id":"req-a","method":"aipt.v1.queue.enqueue","params":{"registration_id":"run-a"}}`
	cases := []string{strings.Replace(valid, `"params"`, `"Params"`, 1), strings.Replace(valid, `"protocol_version":1`, `"protocol_version":2`, 1), strings.Replace(valid, `"id":"req-a"`, `"id":null`, 1), strings.Replace(valid, `"registration_id":"run-a"`, `"Registration_id":"run-a"`, 1), strings.Replace(valid, `"registration_id":"run-a"`, `"registration_id":"run-a","registration_id":"run-a"`, 1), strings.Replace(valid, `"registration_id":"run-a"`, `"registration_id":"run-a","lease_token":"private"`, 1), strings.Replace(valid, `"registration_id":"run-a"`, `"registration_id":"run-a","executor":"fake"`, 1), strings.Replace(valid, `"registration_id":"run-a"`, `"registration_id":"run-a","manifest":{}`, 1), valid + `{}`, `[` + valid + `]`, strings.Replace(valid, `"params":{"registration_id":"run-a"}`, `"params":null`, 1), strings.Replace(valid, `"id":"req-a"`, `"id":"req-a","id":"req-b"`, 1)}
	for i, raw := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			response := s.Respond(context.Background(), []byte(raw))
			if response.Error == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	q.mu.Lock()
	count := len(q.records)
	q.mu.Unlock()
	if count != 0 {
		t.Fatal("rejected requests changed queue")
	}
	if response := s.Respond(context.Background(), []byte(valid)); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := s.Respond(context.Background(), []byte(strings.Replace(valid, "queue.enqueue", "lease.release", 1))); response.Error == nil || response.Error.Code != -32601 {
		t.Fatal("unknown authority method accepted")
	}
}

func TestWorkerCompletionRequiresVerifiedReportAndCurrentLease(t *testing.T) {
	for _, mode := range []string{"valid", "zero-root", "wrong-root", "report-fails", "lease-expired"} {
		t.Run(mode, func(t *testing.T) {
			q := newTestQueue()
			root := sha256.Sum256([]byte("test-only-report"))
			completion := root
			reports := testReports{root: root}
			if mode == "zero-root" {
				completion = [32]byte{}
			}
			if mode == "wrong-root" {
				reports.root = sha256.Sum256([]byte("other-report"))
			}
			if mode == "report-fails" {
				reports.err = ErrReportUnavailable
			}
			if mode == "lease-expired" {
				q.renewError = postgres.ErrLeaseExpired
			}
			s := testService(t, q, executorFunc(func(context.Context, Execution) (Completion, error) {
				return Completion{AuditReadyRoot: completion}, nil
			}), reports, definition(t, "run-a", false))
			if _, err := s.Enqueue(context.Background(), "run-a"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RunNext(context.Background()); err != nil {
				t.Fatal(err)
			}
			waitWorker(t, s)
			detail, err := s.Run(context.Background(), "run-a")
			if err != nil {
				t.Fatal(err)
			}
			success := mode == "valid"
			if (detail.Run.Status == postgres.RunCompleted) != success || len(detail.Attempts) != 2 || (detail.Attempts[1].Outcome == postgres.AttemptSucceeded) != success {
				t.Fatalf("unsafe completion %+v", detail)
			}
			if !success && detail.Attempts[1].EvidenceSHA256 != nil {
				t.Fatal("failure carried completion evidence")
			}
		})
	}
}

func TestWorkerCancellationAndSingleProcessWIP(t *testing.T) {
	q := newTestQueue()
	started := make(chan struct{})
	root := sha256.Sum256([]byte("test-report"))
	s := testService(t, q, executorFunc(func(ctx context.Context, input Execution) (Completion, error) {
		close(started)
		<-ctx.Done()
		return Completion{AuditReadyRoot: root}, nil
	}), testReports{root: root}, definition(t, "run-a", false))
	_, _ = s.Enqueue(context.Background(), "run-a")
	request, cancel := context.WithCancel(context.Background())
	_, err := s.RunNext(request)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	<-started
	if _, err := s.RunNext(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatalf("parallel worker accepted: %v", err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	record, _ := q.GetRun(context.Background(), "run-a")
	if record.Status == postgres.RunCompleted {
		t.Fatal("canceled executor's success result completed a Run")
	}
	if _, err := s.Enqueue(context.Background(), "run-a"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("stopped service accepted command")
	}
}

func TestQualificationIsNeverExecutedOrEnqueuedByB006(t *testing.T) {
	q := newTestQueue()
	calls := 0
	d := definition(t, "formal-a", true)
	s := testService(t, q, executorFunc(func(context.Context, Execution) (Completion, error) { calls++; return Completion{}, nil }), testReports{}, d)
	if _, err := s.Enqueue(context.Background(), "formal-a"); !errors.Is(err, ErrNotAuthorized) {
		t.Fatal("qualification enqueue accepted")
	}
	if _, err := q.EnqueueRun(context.Background(), d.Input); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunNext(context.Background()); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("qualification execution accepted: %v", err)
	}
	if calls != 0 {
		t.Fatal("executor invoked for formal Run")
	}
}

func TestServiceCopiesRegistrationAndRejectsManifestCasingAlias(t *testing.T) {
	q := newTestQueue()
	d := definition(t, "run-a", false)
	s := testService(t, q, nil, nil, d)
	d.Input.ManifestBytes[0] = 'x'
	if _, err := s.Enqueue(context.Background(), "run-a"); err != nil {
		t.Fatal("caller mutated registered manifest")
	}
	alias := definition(t, "run-b", false)
	alias.Input.ManifestBytes = bytes.Replace(alias.Input.ManifestBytes, []byte(`"run_id"`), []byte(`"Run_id"`), 1)
	if _, err := New(Options{Queue: q, Reader: q, Definitions: []Definition{alias}, Lifetime: context.Background(), HolderID: "holder", LeaseDuration: 3 * time.Second}); !errors.Is(err, ErrInvalid) {
		t.Fatal("Manifest case alias accepted")
	}
}

func TestRegisteredRunSelfDependencyIsRejectedBeforeServiceStarts(t *testing.T) {
	q := newTestQueue()
	d := definition(t, "run-self-dependent", false)
	d.Input.DependencyRunIDs = []string{"run-self-dependent"}
	if _, err := New(Options{Queue: q, Reader: q, Definitions: []Definition{d}, Lifetime: context.Background(), HolderID: "holder", LeaseDuration: 3 * time.Second}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self-dependent service accepted: %v", err)
	}
	if len(q.records) != 0 || q.leases != 0 {
		t.Fatal("invalid registry reached queue authority")
	}
}

type reportFunc func(context.Context, postgres.RunRecord) (ReportView, error)

func (f reportFunc) Inspect(ctx context.Context, r postgres.RunRecord) (ReportView, error) {
	return f(ctx, r)
}
func (f reportFunc) Export(context.Context, postgres.RunRecord, string) (Download, error) {
	return Download{}, ErrReportUnavailable
}
func TestWorkerCanceledDuringReportVerificationNeverCompletes(t *testing.T) {
	q := newTestQueue()
	root := [32]byte{7}
	entered := make(chan struct{})
	release := make(chan struct{})
	reports := reportFunc(func(_ context.Context, r postgres.RunRecord) (ReportView, error) {
		close(entered)
		<-release
		return ReportView{RunID: r.RunID, Root: fmt.Sprintf("%x", root), ExecutionStatus: "COMPLETED", QualificationEligible: false}, nil
	})
	executor := executorFunc(func(context.Context, Execution) (Completion, error) { return Completion{AuditReadyRoot: root}, nil })
	s := testService(t, q, executor, reports, definition(t, "run-canceled-report", false))
	if _, err := s.Enqueue(context.Background(), "run-canceled-report"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("verification never started")
	}
	stopped := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stopped <- s.Stop(ctx)
	}()
	select {
	case <-s.lifetime.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("stop did not cancel run")
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	record, err := q.GetRun(context.Background(), "run-canceled-report")
	if err != nil {
		t.Fatal(err)
	}
	if record.Status == postgres.RunCompleted {
		t.Fatal("canceled verification completed Run")
	}
	attempts, _ := q.ReadAttempts(context.Background(), record.RunID)
	for _, a := range attempts {
		if a.Outcome == postgres.AttemptSucceeded {
			t.Fatal("canceled verification appended SUCCEEDED")
		}
	}
}
