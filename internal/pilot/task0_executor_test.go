package pilot

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
)

func TestTask0ExecutorRejectsMissingAuthorityWithoutOpeningRuntime(t *testing.T) {
	for _, execution := range []runcontrol.Execution{{}, {AttemptID: "caller-selected"}, {AttemptID: "b006-" + strings.Repeat("a", 32)}} {
		e := &task0Executor{}
		if _, err := e.Execute(context.Background(), execution); err == nil || e.consumed {
			t.Fatal("unbound executor granted runtime access")
		}
	}
}

// Real isolated PostgreSQL + unchanged B001 lease/attempt APIs, but only the
// pre-model original-intent claim is exercised. No Executor Execute call,
// registered runtime, cache file, Core RNG, network/model or DIAG is started.
func TestPostgresTask0ExecutorRequiresOriginalLeaseAndCannotRestart(t *testing.T) {
	ctx := context.Background()
	pool := pilotPool(t)
	b, f := task0DispatchBindingFixture(t)
	raw, _ := json.Marshal(b)
	g, err := decodeTask0DispatchGrant(raw, inputSHA(raw), f)
	if err != nil {
		t.Fatal(err)
	}
	pilotEnqueue(t, pool, f)
	price := Pricing{"deepseek-v4-pro", 1320, 3960, strings.Repeat("1", 64), time.Now().UTC()}
	budget, err := OpenGlobalBudget(ctx, pool, privateRoot(t), f, price)
	if err != nil {
		t.Fatal(err)
	}
	defer budget.Close()
	queue, err := postgres.NewQueueStore(pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &task0Executor{budget: budget, grant: g, queue: queue}
	execution := runcontrol.Execution{Manifest: f, AttemptID: "b006-" + strings.Repeat("a", 32)}
	if e.claimExecution(ctx, execution) == nil {
		t.Fatal("unleased queue accepted")
	}
	lease, err := queue.AcquireLease(ctx, postgres.AcquireLeaseInput{HolderID: "NON-CANON-TASK0", LeaseDuration: time.Minute, Capabilities: postgres.CapabilitySet{ResourceIDs: []string{"fixture-resource"}, ModelIDs: []string{"fixture-model"}, CertificationIDs: []string{"fixture-cert"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.ReleaseLease(ctx, lease.LeaseID, lease.Token, postgres.ReleaseRequeue)
	if e.claimExecution(ctx, execution) == nil {
		t.Fatal("missing original queue attempt accepted")
	}
	if _, err := queue.AppendAttempt(ctx, f.Manifest.RunID, execution.AttemptID+"-start", postgres.AttemptNewRun, postgres.AttemptStarted, nil); err != nil {
		t.Fatal(err)
	}
	wrong := execution
	wrong.AttemptID = "b006-" + strings.Repeat("b", 32)
	if e.claimExecution(ctx, wrong) == nil {
		t.Fatal("foreign attempt accepted")
	}
	if e.claimExecution(ctx, execution) != nil || !e.consumed {
		t.Fatal("exact original leased intent rejected")
	}
	if e.claimExecution(ctx, execution) == nil {
		t.Fatal("same object restarted")
	}
	restored := &task0Executor{budget: budget, grant: g, queue: queue}
	if restored.claimExecution(ctx, execution) == nil {
		t.Fatal("fresh object replaced durable original intent")
	}
	if totals, err := budget.Totals(ctx); err != nil || totals != (BudgetTotals{}) {
		t.Fatal("claim performed a model reservation")
	}
}
