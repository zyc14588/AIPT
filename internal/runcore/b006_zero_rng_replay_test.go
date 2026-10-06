package runcore

import (
	"context"
	"encoding/json"
	"testing"
)

// No model, game canon or qualification is involved. Both forms are already
// accepted by B002 and must remain distinct in the committed proposal digest.
func TestB006ClosedCoreZeroRNGProposalReplayRegression(t *testing.T) {
	for _, caseValue := range []struct {
		name     string
		requests []RNGRequest
	}{{"nil", nil}, {"empty-array", []RNGRequest{}}} {
		t.Run(caseValue.name, func(t *testing.T) {
			store := newMemoryStore()
			core := fixtureCore(t, store, counterHandler{}, nil, 10)
			id := "run-zero-rng-" + caseValue.name
			run, _ := startFixtureRun(t, core, id)
			raw := proposalBytes(t, id, "counter-a", 1, 1, caseValue.requests, nil)
			receipt, err := run.Execute(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			events := store.events(id)
			var action struct {
				Action struct {
					Proposal json.RawMessage `json:"proposal"`
					SHA      string          `json:"proposal_sha256"`
				} `json:"action"`
			}
			if err := json.Unmarshal([]byte(events[1].PayloadCanonical), &action); err != nil {
				t.Fatal(err)
			}
			t.Logf("committed proposal=%s stored_proposal_sha256=%s", action.Action.Proposal, action.Action.SHA)
			result, err := core.Replay(context.Background(), ReplayInput{Binding: fixtureBinding(id), Seed: fixtureSeed(), Events: events, ExpectedFinalStateHash: receipt.StateHash})
			if err != nil || result.StateHash != receipt.StateHash || result.EventCount != 2 {
				t.Fatalf("accepted action committed but could not replay: %v", err)
			}
		})
	}
}
