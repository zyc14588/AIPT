package postgres_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/config"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/runcore"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
	"github.com/zyc14588/AIPT/internal/web"
)

func b006Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AIPT_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("AIPT_REQUIRE_POSTGRES_INTEGRATION") == "1" {
			t.Fatal("PostgreSQL DSN is required")
		}
		t.Skip("PostgreSQL DSN not configured")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test DSN")
	}
	if cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost" {
		t.Fatal("test database must be loopback-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("administrative pool unavailable")
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal("administrative database unavailable")
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	name := "aipt_b006_" + hex.EncodeToString(random)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal("cannot create isolated database")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		defer admin.Close()
		_, _ = admin.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()", name)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("isolated database cleanup failed")
		}
	})
	isolated := cfg.Copy()
	isolated.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, isolated)
	if err != nil {
		t.Fatal("isolated pool unavailable")
	}
	t.Cleanup(pool.Close)
	if err := postgres.MigrateUp(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&version); err != nil || !strings.HasPrefix(version, "18.4") {
		t.Fatalf("expected PostgreSQL 18.4, got %s", version)
	}
	return pool
}
func b006Definition(t *testing.T, id string, formal bool) runcontrol.Definition {
	t.Helper()
	classification := "DIAGNOSTIC"
	if formal {
		classification = "QUALIFICATION"
	}
	m := testplan.RunManifest{Schema: testplan.RunManifestSchema, ManifestID: "manifest-" + id, RunID: id, Ancestry: testplan.Ancestry{CampaignID: "campaign-" + id, SuiteID: "suite-" + id, CaseID: "case-" + id}, RunType: testplan.TaskRule, Source: testplan.SourceBinding{AIPT: testplan.RepositorySource{Repository: "zyc14588/AIPT", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}, Game: testplan.RepositorySource{Repository: "fixture/game", Commit: strings.Repeat("3", 40), Tree: strings.Repeat("4", 40)}}, ModelAssignments: []testplan.ModelAssignment{{AssignmentID: "model-a", ModelProfileID: "profile-a"}}, PromptAssets: []testplan.PromptAsset{{AssetID: "prompt-a", SHA256: strings.Repeat("5", 64)}}, SeatRoster: []testplan.Seat{{SeatID: "gm", RoleID: "GM", ModelAssignmentID: "model-a"}, {SeatID: "p1", RoleID: "PLAYER", ModelAssignmentID: "model-a"}, {SeatID: "p2", RoleID: "PLAYER", ModelAssignmentID: "model-a"}, {SeatID: "p3", RoleID: "PLAYER", ModelAssignmentID: "model-a"}, {SeatID: "p4", RoleID: "PLAYER", ModelAssignmentID: "model-a"}}, Budget: testplan.BudgetBinding{PolicyID: "policy-a", LimitsID: "limits-a", MaxInputTokens: 100, MaxOutputTokens: 100, MaxDurationSeconds: 30}, Evidence: testplan.EvidenceBinding{ProfileID: "evidence-a", ConfigID: "config-a"}, VisibilityProfileID: "AIPT_VISIBILITY_STANDARD_V1", SafetyApplicable: false, SafetyProfileID: "NOT_APPLICABLE", Classification: classification, QualificationEligible: formal}
	frozen, err := testplan.BindRunManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return runcontrol.Definition{ID: id, Input: postgres.EnqueueRunInput{ManifestBytes: frozen.Canonical, CampaignName: "NON_CANON_PROTOCOL_FIXTURE", SuiteName: "control", CaseName: "counter", Priority: postgres.PrioritySystem, RequiredResourceID: "resource-a", RequiredModelID: "model-a", RequiredCertificationID: "cert-a", RequiredLabels: []string{}, DependencyRunIDs: []string{}}}
}
func b006Service(t *testing.T, pool *pgxpool.Pool, executor runcontrol.Executor, reports runcontrol.Reports, defs ...runcontrol.Definition) *runcontrol.Service {
	t.Helper()
	queue, err := postgres.NewQueueStore(pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := runcontrol.NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := runcontrol.New(runcontrol.Options{Queue: queue, Reader: reader, Definitions: defs, Executor: executor, Reports: reports, Lifetime: context.Background(), HolderID: "b006-test-holder", LeaseDuration: 3 * time.Second, Capabilities: postgres.CapabilitySet{ResourceIDs: []string{"resource-a"}, ModelIDs: []string{"model-a"}, CertificationIDs: []string{"cert-a"}, Labels: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := service.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	return service
}

func TestPostgresIntegrationB006WebAndRPCShareQueueAndImmutableManifest(t *testing.T) {
	pool := b006Pool(t)
	service := b006Service(t, pool, nil, nil, b006Definition(t, "run-a", false), b006Definition(t, "formal-a", true))
	ctx := context.Background()
	cfg, err := config.Load([]byte(`{"schema":"aipt.config/v1","profile":"development","database":{"identity":"control_dev","namespace":"control_dev","dsn":"postgresql://127.0.0.1/control_dev","ping_timeout_ms":1000},"evidence":{"namespace":"control-dev"}}`))
	if err != nil {
		t.Fatal(err)
	}
	host, err := web.StartOperational(ctx, cfg, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = host.Stop(ctx)
	})
	response, err := http.Get(host.URL() + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	var session struct {
		Token string `json:"csrf_token"`
	}
	err = json.NewDecoder(response.Body).Decode(&session)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"jsonrpc":"2.0","protocol_version":1,"id":"web-a","method":"aipt.v1.queue.enqueue","params":{"registration_id":"run-a"}}`
	request, _ := http.NewRequest("POST", host.URL()+"/api/v1/control", strings.NewReader(raw))
	request.Header.Set("Origin", host.URL())
	request.Header.Set("X-AIPT-CSRF", session.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("enqueue: %s", data)
	}
	var stored []byte
	if err := pool.QueryRow(ctx, "SELECT manifest_bytes FROM aipt.run_manifests WHERE run_id='run-a'").Scan(&stored); err != nil || !bytes.Equal(stored, b006Definition(t, "run-a", false).Input.ManifestBytes) {
		t.Fatal("Web did not preserve exact immutable Manifest")
	}
	if _, err := service.Enqueue(ctx, "formal-a"); !errors.Is(err, runcontrol.ErrNotAuthorized) {
		t.Fatal("formal Run enqueued without authorization")
	}
	input, send := io.Pipe()
	receive, output := io.Pipe()
	defer send.Close()
	defer receive.Close()
	rpc, err := runcontrol.StartRPC(ctx, input, output, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = rpc.Stop(ctx)
	})
	frame := `{"jsonrpc":"2.0","protocol_version":1,"id":"rpc-a","method":"aipt.v1.queue.pause","params":{"paused":true}}`
	sent := make(chan error, 1)
	go func() { _, err := fmt.Fprintf(send, "Content-Length: %d\r\n\r\n%s", len(frame), frame); sent <- err }()
	reader := bufio.NewReader(receive)
	header, _ := reader.ReadString('\n')
	var size int
	_, _ = fmt.Sscanf(header, "Content-Length: %d", &size)
	_, _ = reader.ReadString('\n')
	reply := make([]byte, size)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	var paused bool
	if err := pool.QueryRow(ctx, "SELECT paused FROM aipt.playtest_queue_control WHERE control_id='GLOBAL'").Scan(&paused); err != nil || !paused {
		t.Fatal("RPC not persisted in authoritative queue")
	}
	response, err = http.Get(host.URL() + "/api/v1/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	var dashboard web.OperationalDashboard
	err = json.NewDecoder(response.Body).Decode(&dashboard)
	_ = response.Body.Close()
	if err != nil || !dashboard.Control.Paused || len(dashboard.Control.Items) != 1 {
		t.Fatal("HTTP did not observe RPC's database mutation")
	}
	detail, err := service.Run(ctx, "run-a")
	if err != nil || len(detail.Seats) != 5 {
		t.Fatal("Status/Table not derived from the held Manifest")
	}
	// B006 creates no migration or side-channel writer for any prior authority.
	if _, err := pool.Exec(ctx, "UPDATE aipt.run_manifests SET manifest_bytes=$1 WHERE run_id='run-a'", []byte("tamper")); err == nil {
		t.Fatal("Manifest append-only gate bypassed")
	}
	if _, err := service.Invoke(ctx, "aipt.v1.queue.cancel", json.RawMessage(`{"run_id":"run-a"}`)); err != nil {
		t.Fatal(err)
	}
	detail, err = service.Run(ctx, "run-a")
	if err != nil || detail.Run.Status != postgres.RunCanceled {
		t.Fatal("queue cancel was not authoritative")
	}
}

type b006Seed struct{}

func (b006Seed) RootSeed(context.Context, runcore.RunBinding) ([]byte, error) {
	return bytes.Repeat([]byte{0x42}, 32), nil
}

type b006Counter struct{}

func (b006Counter) ValidatePayload(runcore.ActionProposal) error { return nil }
func (b006Counter) ValidatePrecondition(ctx context.Context, state runcore.RunState, p runcore.ActionProposal) error {
	return ctx.Err()
}
func (b006Counter) Apply(ctx context.Context, state runcore.RunState, p runcore.ActionProposal, draws []runcore.RNGDraw) (json.RawMessage, error) {
	return json.RawMessage(`{"counter":1,"private":"HIDDEN_DOMAIN_SENTINEL"}`), ctx.Err()
}

// This non-narrative executor uses the real B002 PostgreSQL Core and replay.
// Its report adapter is test-only and does not claim production AUDIT_READY,
// real-model playtesting, game canon or qualification acceptance.
type b006CoreExecutor struct {
	pool    *pgxpool.Pool
	reports *b006TestReports
	started chan struct{}
	allow   chan struct{}
	errout  chan error
}

func (e *b006CoreExecutor) Execute(ctx context.Context, input runcontrol.Execution) (completion runcontrol.Completion, executionErr error) {
	defer func() {
		if executionErr != nil {
			e.errout <- executionErr
		}
	}()
	close(e.started)
	select {
	case <-e.allow:
	case <-ctx.Done():
		return runcontrol.Completion{}, ctx.Err()
	}
	store, err := runcore.NewPostgreSQLStore(e.pool)
	if err != nil {
		return runcontrol.Completion{}, err
	}
	core, err := runcore.New(runcore.Config{Store: store, SeedSource: b006Seed{}, Authorizer: runcore.AuthorizerFunc(func(ctx context.Context, state runcore.RunState, p runcore.ActionProposal) error { return ctx.Err() }), Rules: runcore.RuleValidatorFunc(func(ctx context.Context, state runcore.RunState, p runcore.ActionProposal) error { return ctx.Err() }), Handlers: map[string]runcore.ActionHandler{"counter.increment": b006Counter{}}})
	if err != nil {
		return runcontrol.Completion{}, err
	}
	m := input.Manifest.Manifest
	binding := runcore.RunBinding{Schema: runcore.RunBindingSchema, RunID: m.RunID, Manifest: runcore.ArtifactBinding{ID: m.ManifestID, Schema: testplan.RunManifestSchema, CanonicalSHA256: hex.EncodeToString(input.Manifest.Digest[:])}, RuntimeAdapterInput: runcore.ArtifactBinding{ID: "NON_CANON_CONTROL_ADAPTER", Schema: "aipt.runtime-adapter-input/v1", CanonicalSHA256: strings.Repeat("6", 64)}, SourcePackage: runcore.SourcePackageBinding{PackageID: "NON_CANON_PROTOCOL_FIXTURE", Schema: "aipt.playtest-package/v1", Repository: m.Source.Game.Repository, Commit: m.Source.Game.Commit, Tree: m.Source.Game.Tree, CanonicalSHA256: strings.Repeat("7", 64)}}
	run, _, err := core.StartRun(ctx, runcore.StartRunInput{Binding: binding, InitialState: json.RawMessage(`{"counter":0,"private":"HIDDEN_DOMAIN_SENTINEL"}`)})
	if err != nil {
		return runcontrol.Completion{}, err
	}
	proposal := runcore.ActionProposal{Schema: runcore.ActionProposalSchema, ActionID: "counter-a", RunID: m.RunID, ActorID: "gm", ActionType: "counter.increment", ExpectedSequence: 1, Source: runcore.RuleSource{Kind: "RULE_ID", Reference: "FIXTURE_RULE"}, Payload: json.RawMessage(`{}`), RNGRequests: []runcore.RNGRequest{}}
	encoded, _ := json.Marshal(proposal)
	canonical, err := protocol.CanonicalJSON(encoded)
	if err != nil {
		return runcontrol.Completion{}, err
	}
	receipt, err := run.Execute(ctx, []byte(canonical))
	if err != nil {
		return runcontrol.Completion{}, err
	}
	events, err := store.Load(ctx, "aipt.run-core:"+m.RunID)
	if err != nil {
		return runcontrol.Completion{}, err
	}
	replay, err := core.Replay(ctx, runcore.ReplayInput{Binding: binding, Seed: bytes.Repeat([]byte{0x42}, 32), Events: events, ExpectedFinalStateHash: receipt.StateHash})
	if err != nil || replay.EventCount != 2 {
		return runcontrol.Completion{}, fmt.Errorf("real replay failed: %v", err)
	}
	root := events[len(events)-1].EventHash
	e.reports.mu.Lock()
	e.reports.roots[m.RunID] = root
	e.reports.mu.Unlock()
	return runcontrol.Completion{AuditReadyRoot: root}, nil
}

type b006TestReports struct {
	mu    sync.Mutex
	roots map[string][32]byte
}

func (r *b006TestReports) Inspect(ctx context.Context, record postgres.RunRecord) (runcontrol.ReportView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	root, ok := r.roots[record.RunID]
	if !ok {
		return runcontrol.ReportView{}, runcontrol.ErrReportUnavailable
	}
	return runcontrol.ReportView{RunID: record.RunID, Root: hex.EncodeToString(root[:]), ExecutionStatus: "COMPLETED", QualificationEligible: false}, nil
}
func (r *b006TestReports) Export(context.Context, postgres.RunRecord, string) (runcontrol.Download, error) {
	return runcontrol.Download{}, runcontrol.ErrReportUnavailable
}

func TestPostgresIntegrationB006RunCoreReplayAndWorkerWIP(t *testing.T) {
	pool := b006Pool(t)
	reports := &b006TestReports{roots: map[string][32]byte{}}
	executor := &b006CoreExecutor{pool: pool, reports: reports, started: make(chan struct{}), allow: make(chan struct{}), errout: make(chan error, 1)}
	service := b006Service(t, pool, executor, reports, b006Definition(t, "run-a", false))
	ctx := context.Background()
	if _, err := service.Enqueue(ctx, "run-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RunNext(ctx); err != nil {
		t.Fatal(err)
	}
	<-executor.started
	if _, err := service.RunNext(ctx); !errors.Is(err, runcontrol.ErrConflict) {
		t.Fatal("parallel worker accepted")
	}
	close(executor.allow)
	deadline := time.After(4 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("worker not finalized")
		case <-ticker.C:
			snapshot, err := service.Snapshot(ctx, 100)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.WorkerRunID != nil {
				continue
			}
			detail, err := service.Run(ctx, "run-a")
			if err != nil {
				t.Fatal(err)
			}
			if detail.Run.Status != postgres.RunCompleted || len(detail.Attempts) != 2 || detail.Attempts[1].Outcome != postgres.AttemptSucceeded || detail.Run.QualificationEligible {
				select {
				case executionErr := <-executor.errout:
					t.Fatalf("synthetic driver failed: %v", executionErr)
				default:
				}
				t.Fatalf("final state %+v, snapshot %+v", detail, snapshot)
			}
			public, _ := json.Marshal(detail)
			if bytes.Contains(public, []byte("HIDDEN_DOMAIN_SENTINEL")) || bytes.Contains(public, []byte("seed")) {
				t.Fatal("private Core state entered Status/Table")
			}
			var active int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM aipt.run_leases WHERE status='ACTIVE'").Scan(&active); err != nil || active != 0 {
				t.Fatal("worker leaked active database lease")
			}
			return
		}
	}
}
