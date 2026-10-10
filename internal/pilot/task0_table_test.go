package pilot

import (
	"encoding/json"
	"testing"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

// NON_CANON scheduling fixtures invoke no game mutation, model or Core RNG.
func TestTask0FloorKeepsGMOnlyWhileCommittedGMRestWorkRemains(t *testing.T) {
	for _, scenario := range []string{"before_rest_roll", "pending_risk", "pending_note", "rest_complete", "unsigned_player", "unspent_rest", "open_mission", "unsettled"} {
		t.Run(scenario, func(t *testing.T) {
			actors := map[string]any{}
			for _, player := range orchestrator.BaselineSeats()[1:] {
				actor, _ := task0Actor(player)
				actors[actor] = map[string]any{"signed": true, "rest_points": 0, "pollution_notes": []any{}}
			}
			state := map[string]any{"schema": "unregistered.task0-state/v2", "mission": "WITHDREW_NOT_DELIVERED", "ledger": map[string]any{"NON_CANON": true}, "rest_event": map[string]any{"kind": "RISK"}, "risk_queue": []string{}, "actors": actors}
			first := actors["UNR-CHAR-0001"].(map[string]any)
			switch scenario {
			case "before_rest_roll":
				state["rest_event"] = nil
			case "pending_risk":
				state["risk_queue"] = []string{"UNR-CHAR-0001"}
			case "pending_note":
				first["pollution_notes"] = []any{map[string]any{"text": nil}}
			case "unsigned_player":
				first["signed"] = false
				state["rest_event"] = nil
			case "unspent_rest":
				first["rest_points"] = 1
				state["rest_event"] = nil
			case "open_mission":
				state["mission"] = "OPEN"
				state["rest_event"] = nil
			case "unsettled":
				state["ledger"] = nil
				state["rest_event"] = nil
			}
			domain, _ := json.Marshal(state)
			floor, err := orchestrator.NewFloorController("NON-CANON-floor", task0TablePolicy())
			if err != nil || floor.OpenDiscussion() != nil {
				t.Fatal("floor fixture")
			}
			before := len(floor.Events())
			if task0AdvanceTableFloor(floor, orchestrator.SeatGM, domain) != nil {
				t.Fatal("valid floor transition rejected")
			}
			_, owner := floor.State()
			keep := scenario == "before_rest_roll" || scenario == "pending_risk" || scenario == "pending_note"
			if (owner == orchestrator.SeatGM) != keep {
				t.Fatal("wrong floor owner", owner)
			}
			if keep && len(floor.Events()) != before {
				t.Fatal("manufactured a floor transfer")
			}
			if !keep && owner != orchestrator.SeatPlayer1 {
				t.Fatal("serial player order changed")
			}
			if task0AdvanceTableFloor(floor, orchestrator.SeatPlayer2, domain) == nil {
				t.Fatal("non-owner moved floor")
			}
		})
	}
}
