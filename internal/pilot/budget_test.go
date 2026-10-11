package pilot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func budgetFixture(t *testing.T) (*Budget, Pricing, WireProof) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	dir := filepath.Join(root, "budget")
	os.Mkdir(dir, 0700)
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	// Synthetic unit facts only. This fixture cannot certify a real closure.
	price := Pricing{"deepseek-v4-pro", 1320, 3960, strings.Repeat("1", 64), time.Now().UTC()}
	proof := WireProof{"141eb6fef83422698aef7a981029e843e8161534", strings.Repeat("2", 64), strings.Repeat("3", 64), 8192, 1024, 1, true}
	b, e := InitializeBudget(dir, "B007-SYNTHETIC-NO-NETWORK", price)
	if e != nil {
		t.Fatal(e)
	}
	return b, price, proof
}
func TestBudgetConcurrencyAndRestartCannotResetCeilings(t *testing.T) {
	b, price, proof := budgetFixture(t)
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.ReserveRemote(fmt.Sprintf("attempt-%02d", i), proof) == nil {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := success.Load(); got != 32 {
		t.Fatalf("authorized %d attempts", got)
	}
	reopened, e := OpenBudget(b.directory, b.runID, price)
	if e != nil {
		t.Fatal(e)
	}
	if reopened.ReserveRemote("restart-extra", proof) == nil {
		t.Fatal("restart increased budget")
	}
	totals, e := reopened.Totals()
	if e != nil {
		t.Fatal(e)
	}
	if totals.RemoteAttempts != 32 || totals.InputTokens != 262144 || totals.OutputTokens != 32768 || totals.ReservedNanodollars != 475791360 {
		t.Fatalf("wrong totals: %+v", totals)
	}
	if _, e = OpenBudget(b.directory, "DIFFERENT-RUN-ID", price); e == nil {
		t.Fatal("different run reset shared ledger")
	}
}
func TestBudgetDuplicateRetryAndUnknownOutcomeRetainReservation(t *testing.T) {
	b, _, proof := budgetFixture(t)
	if e := b.ReserveRemote("certification-attempt-1", proof); e != nil {
		t.Fatal(e)
	}
	if b.ReserveRemote("certification-attempt-1", proof) == nil {
		t.Fatal("duplicate reuse authorized")
	}
	if e := b.ReserveRemote("certification-retry-2", proof); e != nil {
		t.Fatal(e)
	}
	total, e := b.Totals()
	if e != nil || total.RemoteAttempts != 2 {
		t.Fatalf("unknown/failed/retried call released reservation: %+v %v", total, e)
	}
}
func TestBudgetRejectsAbsentOrOuterOnlyWireProof(t *testing.T) {
	b, _, proof := budgetFixture(t)
	mutations := []func(*WireProof){func(p *WireProof) { p.BeforeEveryWireSend = false }, func(p *WireProof) { p.MaxWireAttemptsPerInvocation = 0 }, func(p *WireProof) { p.MaxWireAttemptsPerInvocation = 2 }, func(p *WireProof) { p.UpstreamOutputCeiling = 2048 }, func(p *WireProof) { p.CompleteInputCeiling = 8193 }, func(p *WireProof) { p.ReportSHA = "" }, func(p *WireProof) { p.SourceCommit = strings.Repeat("0", 40) }}
	for i, mutate := range mutations {
		bad := proof
		mutate(&bad)
		if b.ReserveRemote(fmt.Sprintf("bad-%d", i), bad) == nil {
			t.Fatalf("invalid proof %d accepted", i)
		}
	}
	total, e := b.Totals()
	if e != nil || total.RemoteAttempts != 0 {
		t.Fatalf("invalid proof changed budget: %+v %v", total, e)
	}
}
func TestBudgetElapsedAndLocalCallCeilingsPersist(t *testing.T) {
	b, _, proof := budgetFixture(t)
	if e := b.ReserveLocal("local-minimum-1"); e != nil {
		t.Fatal(e)
	}
	if b.ReserveLocal("local-minimum-2") == nil {
		t.Fatal("second local call authorized")
	}
	b.now = func() time.Time { return time.Now().UTC().Add(MaxElapsed) }
	if b.ReserveRemote("expired", proof) == nil {
		t.Fatal("expired budget authorized")
	}
}
func TestBudgetDollarReservationRejectsBeforeSending(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	dir := filepath.Join(root, "budget")
	os.Mkdir(dir, 0700)
	os.Chmod(dir, 0700)
	price := Pricing{"deepseek-v4-pro", 1000000, 1000000, strings.Repeat("1", 64), time.Now().UTC()}
	b, e := InitializeBudget(dir, "EXPENSIVE-SYNTHETIC", price)
	if e != nil {
		t.Fatal(e)
	}
	_, _, proof := budgetFixture(t)
	if b.ReserveRemote("over-five-dollars", proof) == nil {
		t.Fatal("over-budget attempt authorized")
	}
	total, e := b.Totals()
	if e != nil || total.RemoteAttempts != 0 {
		t.Fatal(total, e)
	}
}
func TestBudgetLedgerDamageDeletionAndRollbackFailClosed(t *testing.T) {
	for _, mode := range []string{"partial", "canonical-prefix-rollback", "deletion", "head-damage", "symlink", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			b, price, proof := budgetFixture(t)
			if e := b.ReserveRemote("first", proof); e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(b.directory, "b007-budget.jsonl")
			switch mode {
			case "partial":
				f, e := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
				if e != nil {
					t.Fatal(e)
				}
				f.WriteString("{\"unfinished\"")
				f.Close()
			case "canonical-prefix-rollback":
				data, e := os.ReadFile(p)
				if e != nil {
					t.Fatal(e)
				}
				os.WriteFile(p, []byte(strings.Split(string(data), "\n")[0]+"\n"), 0600)
			case "deletion":
				os.Remove(p)
			case "head-damage":
				os.WriteFile(filepath.Join(b.directory, "b007-budget-head.json"), []byte("{}\n"), 0600)
			case "symlink":
				os.Remove(p)
				os.Symlink("/dev/null", p)
			case "hardlink":
				os.Link(p, filepath.Join(b.directory, "extra-link"))
			}
			if _, e := OpenBudget(b.directory, b.runID, price); e == nil {
				t.Fatal("damaged ledger reauthorized")
			}
		})
	}
}
func TestBudgetStalePricingAndSharedDirectoryRejected(t *testing.T) {
	_, price, _ := budgetFixture(t)
	root := t.TempDir()
	os.Chmod(root, 0700)
	dir := filepath.Join(root, "budget")
	os.Mkdir(dir, 0700)
	os.Chmod(dir, 0700)
	price.VerifiedAt = price.VerifiedAt.Add(-25 * time.Hour)
	if _, e := OpenBudget(dir, "STALE", price); e == nil {
		t.Fatal("stale price accepted")
	}
	dir = t.TempDir()
	os.Chmod(dir, 0755)
	price.VerifiedAt = time.Now().UTC()
	if _, e := OpenBudget(dir, "SHARED", price); e == nil {
		t.Fatal("shared directory accepted")
	}
}

func TestBudgetWholeLedgerLossOrDirectoryReplacementCannotReenroll(t *testing.T) {
	for _, mode := range []string{"both-files-deleted", "directory-replaced"} {
		t.Run(mode, func(t *testing.T) {
			b, price, proof := budgetFixture(t)
			if e := b.ReserveRemote("reserved-before-loss", proof); e != nil {
				t.Fatal(e)
			}
			if mode == "both-files-deleted" {
				os.Remove(filepath.Join(b.directory, "b007-budget.jsonl"))
				os.Remove(filepath.Join(b.directory, "b007-budget-head.json"))
			} else {
				// Rename to keep the original inode allocated and avoid inode reuse.
				if e := os.Rename(b.directory, b.directory+".lost"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(b.directory, 0700); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := OpenBudget(b.directory, b.runID, price); e == nil {
				t.Fatal("resume reinitialized lost state")
			}
			if _, e := InitializeBudget(b.directory, b.runID, price); e == nil {
				t.Fatal("explicit reenrollment reset budget")
			}
			if b.ReserveRemote("after-loss", proof) == nil {
				t.Fatal("held Budget authorized after state loss")
			}
		})
	}
}

func TestBudgetLocalInvocationReservesSharedTokenAllowance(t *testing.T) {
	b, _, proof := budgetFixture(t)
	if e := b.ReserveLocal("local-role"); e != nil {
		t.Fatal(e)
	}
	for i := range 31 {
		if e := b.ReserveRemote(fmt.Sprintf("remote-%02d", i), proof); e != nil {
			t.Fatal(e)
		}
	}
	if b.ReserveRemote("aggregate-overflow", proof) == nil {
		t.Fatal("local call escaped aggregate token ceilings")
	}
	totals, e := b.Totals()
	if e != nil || totals.LocalCalls != 1 || totals.RemoteAttempts != 31 || totals.InputTokens != MaxInputTokens || totals.OutputTokens != MaxOutputTokens {
		t.Fatalf("wrong aggregate: %+v %v", totals, e)
	}
}
