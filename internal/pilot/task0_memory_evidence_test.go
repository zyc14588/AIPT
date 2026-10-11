package pilot

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
)

// Numeric memory receipts below are NON_CANON. No cache asset, model binary,
// GGUF, memory guard, source FD or registered runtime is opened by these tests.
func task0MemoryEvidenceFixture(t *testing.T) (modelgateway.ModelProfile, []MemoryGateReceipt) {
	t.Helper()
	p := task0DispatchProfileFixture(t, orchestrator.SeatPlayer1, true).Profile
	receipts := make([]MemoryGateReceipt, 3)
	start := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	for i := range receipts {
		before := MemorySnapshot{ObservedAt: start.Add(time.Duration(2*i) * time.Second), TotalBytes: 128 << 30, AvailableBytes: 80 << 30, FreeBytes: 20 << 30}
		after := before
		after.ObservedAt = before.ObservedAt.Add(time.Second)
		receipts[i] = MemoryGateReceipt{Schema: "aipt.private.b007-local-memory-gate/v1", Phase: task0MemoryPhases[i], Before: before, After: after,
			Scope: "HELD_REGISTERED_LOCAL_MODEL_AND_EXECUTABLE_FILE_PAGE_CACHE", Assets: []CacheReleaseResult{
				{AssetID: p.LocalRuntimeIdentity.ExecutableReference, Bytes: 1 << 20, HintAccepted: true, ReleaseObserved: true},
				{AssetID: p.LocalRuntimeIdentity.GGUFReference, Bytes: b007GGUFBytes, HintAccepted: true, ReleaseObserved: true}}}
	}
	return p, receipts
}

func task0MemoryLines(t *testing.T, receipts []MemoryGateReceipt) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, r := range receipts {
		if json.NewEncoder(&b).Encode(r) != nil {
			t.Fatal("fixture encoding")
		}
	}
	return b.Bytes()
}

func TestTask0MemoryEvidenceRequiresThreePhasesExactAssetsAndHonestRetention(t *testing.T) {
	for _, scenario := range []string{"valid", "honest_kernel_retention", "missing_phase", "extra_phase", "wrong_order", "repeated_phase", "global_cache_claim", "scope", "time_reversal", "zero_memory", "false_memory", "foreign_asset", "duplicate_asset", "GGUF_size", "missing_hint", "false_release", "unexplained_retention", "impossible_residency", "case_alias", "unknown_field", "missing_newline"} {
		t.Run(scenario, func(t *testing.T) {
			p, receipts := task0MemoryEvidenceFixture(t)
			r := &receipts[1]
			a := &r.Assets[1]
			switch scenario {
			case "honest_kernel_retention":
				a.ResidentBeforeBytes = 4096
				a.ResidentAfterBytes = 4096
				a.ReleaseObserved = false
				a.RemainingExplanation = "PAGES_STILL_REFERENCED_OR_KERNEL_RETENTION_HINT_IS_NOT_GLOBAL_CACHE_CLEAR"
			case "missing_phase":
				receipts = receipts[:2]
			case "extra_phase":
				receipts = append(receipts, receipts[2])
			case "wrong_order":
				receipts[0], receipts[1] = receipts[1], receipts[0]
			case "repeated_phase":
				r.Phase = "BEFORE_START"
			case "global_cache_claim":
				r.SystemGlobalCacheCleared = true
			case "scope":
				r.Scope = "ALL_HOST_CACHE"
			case "time_reversal":
				r.Before.ObservedAt = receipts[0].Before.ObservedAt
			case "zero_memory":
				r.Before.TotalBytes = 0
			case "false_memory":
				r.After.AvailableBytes = r.After.TotalBytes + 1
			case "foreign_asset":
				a.AssetID = "FOREIGN-MODEL"
			case "duplicate_asset":
				a.AssetID = r.Assets[0].AssetID
			case "GGUF_size":
				a.Bytes--
			case "missing_hint":
				a.HintAccepted = false
			case "false_release":
				a.ReleaseObserved = false
			case "unexplained_retention":
				a.ResidentAfterBytes = 4096
			case "impossible_residency":
				a.ResidentBeforeBytes = uint64(a.Bytes) + 1
			}
			raw := task0MemoryLines(t, receipts)
			switch scenario {
			case "case_alias":
				raw = bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "unknown_field":
				raw = bytes.Replace(raw, []byte(`"phase":`), []byte(`"seed":"NON_CANON","phase":`), 1)
			case "missing_newline":
				raw = raw[:len(raw)-1]
			}
			_, err := task0DecodeMemoryHistory(raw, p)
			if (err == nil) != (scenario == "valid" || scenario == "honest_kernel_retention") {
				t.Fatal("memory evidence acceptance differs", scenario, err)
			}
		})
	}
}

func TestTask0MemoryEvidenceExclusiveDurableHistoryAndPartialFailure(t *testing.T) {
	for _, scenario := range []string{"complete", "partial", "invalid_record"} {
		t.Run(scenario, func(t *testing.T) {
			budget, _ := task0SeedFixture(t)
			p, receipts := task0MemoryEvidenceFixture(t)
			local := &acceptedPilotLocalGrant{binding: pilotLocalBinding{Profile: p}}
			w, err := newTask0MemoryReceiptWriter(budget, local)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newTask0MemoryReceiptWriter(budget, local); err == nil {
				t.Fatal("exclusive memory history overwritten")
			}
			count := 3
			if scenario == "partial" {
				count = 1
			}
			if scenario == "invalid_record" {
				if _, err := w.Write([]byte("invalid")); err == nil {
					t.Fatal("bad record accepted")
				}
				if _, err := w.Write(task0MemoryLines(t, receipts[:1])); err == nil {
					t.Fatal("failed writer recovered")
				}
				count = 0
			}
			for _, receipt := range receipts[:count] {
				if _, err := w.Write(task0MemoryLines(t, []MemoryGateReceipt{receipt})); err != nil {
					t.Fatal(err)
				}
			}
			if w.Close() != nil || w.Close() != nil {
				t.Fatal("seal failed")
			}
			if _, err := w.Write(task0MemoryLines(t, receipts[:1])); err == nil {
				t.Fatal("sealed writer reopened")
			}
			path := filepath.Join(budget.rootPath, task0MemoryRecordName)
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != 0400 {
				t.Fatal("private history not sealed")
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			_, decodeErr := task0DecodeMemoryHistory(raw, p)
			if (decodeErr == nil) != (scenario == "complete") {
				t.Fatal("partial history produced full acceptance")
			}
		})
	}
}
