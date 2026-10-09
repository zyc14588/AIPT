package pilot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

// These are isolated non-canon protocol fixtures. They perform no model or
// GitHub requests, never create the actual Owner diagnostic claim, and exercise
// the real database rather than a replacement budget or queue implementation.
func pilotPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AIPT_POSTGRES_DSN")
	if dsn == "" {
		if os.Getenv("AIPT_REQUIRE_POSTGRES_INTEGRATION") == "1" {
			t.Fatal("PostgreSQL DSN is required")
		}
		t.Skip("PostgreSQL integration not configured")
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal("invalid test DSN")
	}
	if cfg.ConnConfig.Host != "127.0.0.1" && cfg.ConnConfig.Host != "localhost" {
		t.Fatal("test database must be loopback-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal("administrative pool unavailable")
	}
	if e = admin.Ping(ctx); e != nil {
		admin.Close()
		t.Fatal("administrative database unavailable")
	}
	nonce := make([]byte, 8)
	if _, e = rand.Read(nonce); e != nil {
		admin.Close()
		t.Fatal(e)
	}
	name := "aipt_b007_" + hex.EncodeToString(nonce)
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		admin.Close()
		t.Fatal("isolated database creation failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		defer admin.Close()
		_, _ = admin.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()", name)
		if _, e := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error("isolated database cleanup failed")
		}
	})
	isolated := cfg.Copy()
	isolated.ConnConfig.Database = name
	pool, e := pgxpool.NewWithConfig(ctx, isolated)
	if e != nil {
		t.Fatal("isolated pool unavailable")
	}
	t.Cleanup(pool.Close)
	if e = postgres.MigrateUp(ctx, pool); e != nil {
		t.Fatal(e)
	}
	var version string
	if e = pool.QueryRow(ctx, "SHOW server_version").Scan(&version); e != nil || !strings.HasPrefix(version, "18.4") {
		t.Fatalf("expected PostgreSQL 18.4, got %s", version)
	}
	return pool
}
func pilotManifest(t *testing.T, id string) testplan.FrozenManifest {
	t.Helper()
	m := testplan.RunManifest{Schema: testplan.RunManifestSchema, ManifestID: "manifest-" + id, RunID: id, Ancestry: testplan.Ancestry{CampaignID: "campaign-" + id, SuiteID: "suite-" + id, CaseID: "case-" + id}, RunType: testplan.TaskHumanSimulation, Source: testplan.SourceBinding{AIPT: testplan.RepositorySource{Repository: "zyc14588/AIPT", Commit: "5f3f6353d744f6674de7cb610a8d8e9b9220c02a", Tree: "d91062ddb99d781a825e272a6365ed4effe97350"}, Game: testplan.RepositorySource{Repository: "fixture/game", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40)}}, ModelAssignments: []testplan.ModelAssignment{{AssignmentID: "model-a", ModelProfileID: "NON-CANON-PROTOCOL-FIXTURE"}}, PromptAssets: []testplan.PromptAsset{{AssetID: "fixture-asset", SHA256: strings.Repeat("3", 64)}}, SeatRoster: []testplan.Seat{{SeatID: "gm", RoleID: "GM", ModelAssignmentID: "model-a"}}, Budget: testplan.BudgetBinding{PolicyID: "budget-Q001", LimitsID: "B007-CAPS", MaxInputTokens: MaxInputTokens, MaxOutputTokens: MaxOutputTokens, MaxDurationSeconds: 1800}, Evidence: testplan.EvidenceBinding{ProfileID: "fixture-evidence", ConfigID: "fixture-config"}, VisibilityProfileID: "AIPT_VISIBILITY_STANDARD_V1", SafetyApplicable: false, SafetyProfileID: "NOT_APPLICABLE", Classification: "DIAGNOSTIC", QualificationEligible: false}
	f, e := testplan.BindRunManifest(m)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func pilotEnqueue(t *testing.T, pool *pgxpool.Pool, f testplan.FrozenManifest) {
	t.Helper()
	queue, e := postgres.NewQueueStore(pool, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = queue.EnqueueRun(context.Background(), postgres.EnqueueRunInput{ManifestBytes: f.Canonical, CampaignName: "NON_CANON_PROTOCOL_FIXTURE", SuiteName: "pilot-budget", CaseName: "budget-only", Priority: postgres.PrioritySystem, RequiredResourceID: "fixture-resource", RequiredModelID: "fixture-model", RequiredCertificationID: "fixture-cert", RequiredLabels: []string{}, DependencyRunIDs: []string{}})
	if e != nil {
		t.Fatal(e)
	}
}
func privateRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	return root
}
func globalFixture(t *testing.T) (*GlobalBudget, testplan.FrozenManifest, Pricing, WireProof) {
	t.Helper()
	pool := pilotPool(t)
	manifest := pilotManifest(t, "B007-SYNTHETIC-NO-NETWORK")
	pilotEnqueue(t, pool, manifest)
	p := Pricing{"deepseek-v4-pro", 1320, 3960, strings.Repeat("1", 64), time.Now().UTC()}
	proof := WireProof{"141eb6fef83422698aef7a981029e843e8161534", strings.Repeat("2", 64), strings.Repeat("3", 64), 8192, 1024, 1, true}
	g, e := OpenGlobalBudget(context.Background(), pool, privateRoot(t), manifest, p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { g.Close() })
	return g, manifest, p, proof
}
func TestPostgresPilotOneAuthorityCannotEnrollAnotherRunOrRoot(t *testing.T) {
	g, f, p, proof := globalFixture(t)
	ctx := context.Background()
	if e := g.ReserveRemote(ctx, "initial-certification", proof); e != nil {
		t.Fatal(e)
	}
	if other, e := OpenGlobalBudget(ctx, g.pool, privateRoot(t), f, p); e == nil {
		other.Close()
		t.Fatal("a new root granted a second authorization")
	}
	changed := pilotManifest(t, "DIFFERENT-DIAGNOSTIC-RUN")
	pilotEnqueue(t, g.pool, changed)
	if other, e := OpenGlobalBudget(ctx, g.pool, g.rootPath, changed, p); e == nil {
		other.Close()
		t.Fatal("a new run granted a second authorization")
	}
	p.ReceiptSHA = strings.Repeat("4", 64)
	if other, e := OpenGlobalBudget(ctx, g.pool, g.rootPath, f, p); e == nil {
		other.Close()
		t.Fatal("changed pricing identity accepted")
	}
	totals, e := g.Totals(ctx)
	if e != nil || totals.RemoteAttempts != 1 {
		t.Fatalf("totals changed: %+v %v", totals, e)
	}
}
func TestPostgresPilotConcurrentReservationsAndRestartCannotReset(t *testing.T) {
	g, f, p, proof := globalFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.ReserveRemote(ctx, fmt.Sprintf("concurrent-%02d", i), proof) == nil {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := success.Load(); got != 32 {
		t.Fatalf("authorized %d attempts", got)
	}
	again, e := OpenGlobalBudget(ctx, g.pool, g.rootPath, f, p)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	if again.ReserveRemote(ctx, "restart-extra", proof) == nil {
		t.Fatal("restart increased cap")
	}
	totals, e := again.Totals(ctx)
	if e != nil || totals.RemoteAttempts != 32 || totals.InputTokens != 262144 || totals.OutputTokens != 32768 || totals.ReservedNanodollars != 475791360 {
		t.Fatalf("wrong aggregate: %+v %v", totals, e)
	}
	var count int
	if e = g.pool.QueryRow(ctx, "SELECT count(*) FROM aipt.b007_budget_reservations").Scan(&count); e != nil || count != 32 {
		t.Fatalf("reservations=%d err=%v", count, e)
	}
}
func TestPostgresPilotLocalCallConsumesSharedTokenCeilings(t *testing.T) {
	g, _, _, proof := globalFixture(t)
	ctx := context.Background()
	if e := g.ReserveLocal(ctx, "local-minimum", proof); e != nil {
		t.Fatal(e)
	}
	if g.ReserveLocal(ctx, "second-local", proof) == nil {
		t.Fatal("local cap increased")
	}
	for i := range 31 {
		if e := g.ReserveRemote(ctx, fmt.Sprintf("remote-%02d", i), proof); e != nil {
			t.Fatal(e)
		}
	}
	if g.ReserveRemote(ctx, "overflow-after-local", proof) == nil {
		t.Fatal("local tokens excluded from total cap")
	}
	totals, e := g.Totals(ctx)
	if e != nil || totals.LocalCalls != 1 || totals.RemoteAttempts != 31 || totals.InputTokens != 262144 || totals.OutputTokens != 32768 {
		t.Fatalf("incorrect totals: %+v %v", totals, e)
	}
}
func TestPostgresPilotUnknownOutcomeDuplicateAndCancellationNeverRefund(t *testing.T) {
	g, _, _, proof := globalFixture(t)
	ctx := context.Background()
	if e := g.ReserveRemote(ctx, "unknown-outcome", proof); e != nil {
		t.Fatal(e)
	}
	if g.ReserveRemote(ctx, "unknown-outcome", proof) == nil {
		t.Fatal("duplicate replay authorized")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if g.ReserveRemote(cancelled, "cancelled-before-reservation", proof) == nil {
		t.Fatal("cancelled context authorized")
	}
	if e := g.ReserveRemote(ctx, "explicit-retry", proof); e != nil {
		t.Fatal(e)
	}
	totals, e := g.Totals(ctx)
	if e != nil || totals.RemoteAttempts != 2 {
		t.Fatalf("unknown attempt refunded: %+v %v", totals, e)
	}
}
func TestPostgresPilotRootReplacementRevokesHeldBudget(t *testing.T) {
	g, f, p, proof := globalFixture(t)
	ctx := context.Background()
	old := g.rootPath + ".held"
	if e := os.Rename(g.rootPath, old); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(old) })
	if e := os.Mkdir(g.rootPath, 0700); e != nil {
		t.Fatal(e)
	}
	if g.ReserveRemote(ctx, "held-after-replacement", proof) == nil {
		t.Fatal("held budget accepted replaced root")
	}
	if other, e := OpenGlobalBudget(ctx, g.pool, g.rootPath, f, p); e == nil {
		other.Close()
		t.Fatal("new root recreated budget")
	}
	if other, e := OpenGlobalBudget(ctx, g.pool, old, f, p); e == nil {
		other.Close()
		t.Fatal("renaming original root reset path binding")
	}
	if _, e := g.Totals(ctx); e == nil {
		t.Fatal("totals trusted replaced root")
	}
}
func TestPostgresPilotRejectsUnqueuedManifestAndUnprovenWire(t *testing.T) {
	g, _, p, proof := globalFixture(t)
	ctx := context.Background()
	missing := pilotManifest(t, "UNQUEUED-DIAGNOSTIC")
	if other, e := OpenGlobalBudget(ctx, g.pool, privateRoot(t), missing, p); e == nil {
		other.Close()
		t.Fatal("an unqueued manifest created a claim")
	}
	proof.BeforeEveryWireSend = false
	if g.ReserveRemote(ctx, "unproven-boundary", proof) == nil {
		t.Fatal("missing wire proof accepted")
	}
	totals, e := g.Totals(ctx)
	if e != nil || totals.RemoteAttempts != 0 {
		t.Fatalf("bad proof consumed authorization: %+v %v", totals, e)
	}
}
func TestPostgresPilotDatabaseHistoryCannotResetOrRefund(t *testing.T) {
	g, _, _, proof := globalFixture(t)
	ctx := context.Background()
	if e := g.ReserveRemote(ctx, "durable-reservation", proof); e != nil {
		t.Fatal(e)
	}
	statements := []string{
		"DELETE FROM aipt.b007_budget_claims", "TRUNCATE aipt.b007_budget_claims CASCADE",
		"UPDATE aipt.b007_budget_claims SET remote_attempts=0,input_tokens=0,output_tokens=0,nanodollars=0",
		"UPDATE aipt.b007_budget_claims SET started_at=statement_timestamp()",
		"UPDATE aipt.b007_budget_claims SET root_inode=root_inode+1",
		"DELETE FROM aipt.b007_budget_reservations", "TRUNCATE aipt.b007_budget_reservations",
		"UPDATE aipt.b007_budget_reservations SET input_tokens=1",
	}
	for _, sql := range statements {
		if _, e := g.pool.Exec(ctx, sql); e == nil {
			t.Fatalf("budget mutation accepted: %s", sql)
		}
	}
	totals, e := g.Totals(ctx)
	if e != nil || totals.RemoteAttempts != 1 || totals.InputTokens != 8192 {
		t.Fatalf("history refunded: %+v %v", totals, e)
	}
}
