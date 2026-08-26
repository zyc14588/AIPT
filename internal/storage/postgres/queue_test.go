package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestQueueDeterministicSelectionContract(t *testing.T) {
	priority := strings.Index(eligibleRunsSQL, "playtest_priority_rank")
	waitingAge := strings.Index(eligibleRunsSQL, "r.queued_at ASC")
	tie := strings.Index(eligibleRunsSQL, `r.run_id COLLATE "C" ASC`)
	if priority < 0 || waitingAge <= priority || tie <= waitingAge {
		t.Fatalf("selection order is not priority -> waiting age -> C-collated run ID: %q", eligibleRunsSQL)
	}
	for _, required := range []string{
		"required_resource_id = ANY", "required_model_id = ANY",
		"required_certification_id = ANY", "required_labels <@",
		"run_dependencies", "predecessor.status <> 'COMPLETED'",
		"active_formal.formal_slot = 1",
	} {
		if !strings.Contains(eligibleRunsSQL, required) {
			t.Errorf("selection contract misses %q", required)
		}
	}
}

func TestQueueIdentitySetsAreSortedAndDeduplicated(t *testing.T) {
	got, err := normalizedIdentities([]string{"z", "a", "z", "m"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a", "m", "z"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if _, err := normalizedIdentities([]string{"bad value"}, true); err == nil {
		t.Fatal("invalid identity accepted")
	}
}

func TestQueueErrorNeverRendersPrivateCause(t *testing.T) {
	private := errors.New("postgres://user:password@private.example/production")
	err := queueError(ErrQueueStorage, "EnqueueRun", "run-1", private)
	if !errors.Is(err, ErrQueueStorage) {
		t.Fatal("stable code does not unwrap")
	}
	if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "postgres://") || strings.Contains(err.Error(), "private.example") {
		t.Fatalf("QueueError leaked its private cause: %q", err)
	}
}

func TestPrioritySetIsExactAndClosed(t *testing.T) {
	want := []PriorityClass{PriorityRelease, PriorityHotfix, PriorityMilestone, PrioritySystem, PriorityCalibration, PriorityExploratory, PriorityBackground}
	if len(validPriorities) != len(want) {
		t.Fatalf("priority count = %d, want 7", len(validPriorities))
	}
	for _, value := range want {
		if _, ok := validPriorities[value]; !ok {
			t.Errorf("priority %q missing", value)
		}
	}
	if _, ok := validPriorities["UNKNOWN"]; ok {
		t.Fatal("unknown priority accepted")
	}
}
