package pilot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
)

func nonCanonActorState(t *testing.T) json.RawMessage {
	t.Helper()
	actors := map[string]any{}
	for i, seat := range orchestrator.BaselineSeats()[1:] {
		id, _ := task0Actor(seat)
		actors[id] = map[string]any{"actor_id": id, "non_canon": true, "shared_data": strings.Repeat("NON_CANON_SHARED_DATA_", 12), "pressure": i,
			"knowledge": []any{map[string]any{"NON_CANON_PRIVATE": fmt.Sprintf("actor-%d", i)}}}
	}
	raw, _ := json.Marshal(map[string]any{"NON_CANON": true, "actors": actors, "ledger": map[string]any{"opaque": "NON_CANON_LEDGER_DATA"}})
	return raw
}

func TestTask0GMContextEncodingIsLosslessAndNeverAddsDefaults(t *testing.T) {
	raw := nonCanonActorState(t)
	original, _ := protocol.CanonicalJSON(raw)
	encoded, err := task0EncodeGMState(raw)
	if err != nil || len(encoded) >= len(original) {
		t.Fatal("shared state was not reversibly compacted", err)
	}
	decoded, err := task0DecodeGMState(encoded)
	if err != nil || !bytes.Equal(decoded, []byte(original)) {
		t.Fatal("common or private actor values changed")
	}
	var p task0EncodedGMState
	json.Unmarshal(encoded, &p)
	if len(p.Shared) != 2 || p.Shared["pressure"] != nil || p.Shared["knowledge"] != nil || p.Shared["actor_id"] != nil {
		t.Fatal("unequal actor data entered shared values")
	}
	// An absent key is distinct from null; only values present in all four
	// maps are eligible for inheritance.
	var state map[string]json.RawMessage
	json.Unmarshal(raw, &state)
	var actors map[string]map[string]json.RawMessage
	json.Unmarshal(state["actors"], &actors)
	delete(actors["UNR-CHAR-0004"], "non_canon")
	state["actors"], _ = json.Marshal(actors)
	raw, _ = json.Marshal(state)
	encoded, err = task0EncodeGMState(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = task0DecodeGMState(encoded)
	original, _ = protocol.CanonicalJSON(raw)
	if err != nil || !bytes.Equal(decoded, []byte(original)) {
		t.Fatal("absent value was defaulted into an actor")
	}
}

func TestTask0GMContextModalInheritanceRetainsEveryOverrideAndAbsence(t *testing.T) {
	for _, scenario := range []string{"three_shared_one_private", "null_is_not_absence", "empty_is_not_null", "tie_is_deterministic"} {
		t.Run(scenario, func(t *testing.T) {
			var state map[string]json.RawMessage
			json.Unmarshal(nonCanonActorState(t), &state)
			var actors map[string]map[string]json.RawMessage
			json.Unmarshal(state["actors"], &actors)
			ids := []string{"UNR-CHAR-0001", "UNR-CHAR-0002", "UNR-CHAR-0003", "UNR-CHAR-0004"}
			for _, id := range ids {
				actors[id]["modal_private"] = json.RawMessage(`"NON_CANON_COMMON_LONG_VALUE_NON_CANON_COMMON_LONG_VALUE"`)
			}
			actors[ids[0]]["modal_private"] = json.RawMessage(`"NON_CANON_ONLY_ACTOR_ONE_PRIVATE"`)
			switch scenario {
			case "null_is_not_absence":
				delete(actors[ids[0]], "modal_private")
				actors[ids[1]]["modal_private"] = json.RawMessage(`null`)
			case "empty_is_not_null":
				actors[ids[0]]["modal_private"] = json.RawMessage(`null`)
				actors[ids[1]]["modal_private"] = json.RawMessage(`""`)
			case "tie_is_deterministic":
				actors[ids[1]]["modal_private"] = actors[ids[0]]["modal_private"]
			}
			state["actors"], _ = json.Marshal(actors)
			raw, _ := json.Marshal(state)
			canonical, _ := protocol.CanonicalJSON(raw)
			first, err := task0EncodeGMState(raw)
			decoded, decodeErr := task0DecodeGMState(first)
			if err != nil || decodeErr != nil || !bytes.Equal(decoded, []byte(canonical)) {
				t.Fatal("modal encoding changed private/absent/null/empty actor state", err, decodeErr)
			}
			for i := 0; i < 20; i++ {
				next, e := task0EncodeGMState(raw)
				if e != nil || !bytes.Equal(first, next) {
					t.Fatal("modal tie depends on map iteration")
				}
			}
			if scenario == "three_shared_one_private" {
				var compact task0EncodedGMState
				json.Unmarshal(first, &compact)
				if compact.Encoding != task0ModalActorEncoding || len(compact.Shared["modal_private"]) == 0 || !bytes.Equal(compact.Actors[ids[0]]["modal_private"], actors[ids[0]]["modal_private"]) {
					t.Fatal("private override discarded")
				}
			}
		})
	}
}

func TestTask0GMContextEncodingRejectsAmbiguousOrForeignActors(t *testing.T) {
	for _, scenario := range []string{"missing_actor", "wrong_actor", "encoding_selector", "malformed", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			raw := nonCanonActorState(t)
			var state map[string]json.RawMessage
			json.Unmarshal(raw, &state)
			var actors map[string]map[string]json.RawMessage
			json.Unmarshal(state["actors"], &actors)
			switch scenario {
			case "missing_actor":
				delete(actors, "UNR-CHAR-0004")
			case "wrong_actor":
				actors["FOREIGN"] = actors["UNR-CHAR-0004"]
				delete(actors, "UNR-CHAR-0004")
			case "encoding_selector":
				state["encoding"] = json.RawMessage(`"FOREIGN"`)
			}
			state["actors"], _ = json.Marshal(actors)
			raw, _ = json.Marshal(state)
			if scenario == "malformed" {
				raw = json.RawMessage(`{"actors":`)
			}
			if scenario == "oversize" {
				raw = json.RawMessage(strings.Repeat(" ", 1<<20+1))
			}
			if task0, err := task0EncodeGMState(raw); err == nil || task0 != nil {
				t.Fatal("ambiguous state entered compact context")
			}
		})
	}
	for _, scenario := range []string{"encoding", "unknown", "duplicate", "override_shared", "missing", "foreign"} {
		t.Run("decode_"+scenario, func(t *testing.T) {
			raw, _ := task0EncodeGMState(nonCanonActorState(t))
			var p task0EncodedGMState
			json.Unmarshal(raw, &p)
			switch scenario {
			case "encoding":
				p.Encoding = "FOREIGN"
			case "override_shared":
				p.Actors["UNR-CHAR-0001"]["non_canon"] = json.RawMessage(`false`)
			case "missing":
				delete(p.Actors, "UNR-CHAR-0004")
			case "foreign":
				p.Actors["FOREIGN"] = p.Actors["UNR-CHAR-0004"]
				delete(p.Actors, "UNR-CHAR-0004")
			}
			raw, _ = json.Marshal(p)
			if scenario == "unknown" {
				raw = append(raw[:len(raw)-1], []byte(`,"untrusted_selector":true}`)...)
			}
			if scenario == "duplicate" {
				raw = append(raw[:len(raw)-1], []byte(`,"encoding":"ACTORS_INHERIT_SHARED_THEN_OVERRIDE_V1"}`)...)
			}
			if _, err := task0DecodeGMState(raw); err == nil {
				t.Fatal("ambiguous compact context decoded")
			}
		})
	}
}

func TestTask0GMProcedureUsesLiteralCommittedPhaseWithoutChoosingActions(t *testing.T) {
	text := "# NON_CANON\n\n## Procedure / Rule Text\n\n"
	for i := 1; i <= 12; i++ {
		text += fmt.Sprintf("%d. NON_CANON_PROCEDURE_%02d\n", i, i)
	}
	text += "\n## OTHER_NON_CANON_DATA\n"
	for _, sample := range []struct {
		name, state string
		want        []int
	}{
		{"opening", `{"mission":"OPEN","ledger":null,"actors":{}}`, []int{1, 2, 12}},
		{"settle", `{"mission":"NON_CANON_WITHDREW","ledger":null,"actors":{}}`, []int{2, 9, 12}},
		{"rest", `{"ledger":{},"rest_event":null,"actors":{"NON_CANON":{"rest_points":2}}}`, []int{2, 10, 12}},
		{"event", `{"ledger":{},"rest_event":null,"actors":{"NON_CANON":{"rest_points":0}}}`, []int{2, 10, 11, 12}},
		{"melee", `{"mission":"OPEN","actors":{"NON_CANON":{"melee_target":"NON_CANON_NPC"}}}`, []int{1, 2, 6, 12}},
	} {
		t.Run(sample.name, func(t *testing.T) {
			values, _, err := task0GMProcedure(text, json.RawMessage(sample.state))
			if err != nil || len(values) != len(sample.want) {
				t.Fatal("phase-selected procedure differs")
			}
			for i, n := range sample.want {
				literal := fmt.Sprintf("%d. NON_CANON_PROCEDURE_%02d\n", n, n)
				if n == 12 {
					literal += "\n"
				}
				if values[i] != literal || !strings.Contains(text, values[i]) {
					t.Fatal("reference text was rewritten")
				}
			}
		})
	}
}

func TestTask0OwnPublicCardCannotSelectOtherPlayer(t *testing.T) {
	raw := json.RawMessage(`[{"character_id":"UNR-CHAR-0001","NON_CANON":"OWN"},{"character_id":"UNR-CHAR-0002","NON_CANON":"FOREIGN"}]`)
	card, err := task0OwnPublicCard(raw, orchestrator.SeatPlayer1)
	if err != nil || !bytes.Contains(card, []byte("OWN")) || bytes.Contains(card, []byte("FOREIGN")) {
		t.Fatal("card selection crossed authenticated actor")
	}
	if _, err := task0OwnPublicCard(raw, orchestrator.SeatPlayer3); err == nil {
		t.Fatal("missing actor defaulted")
	}
	if _, err := task0OwnPublicCard(raw, orchestrator.SeatGM); err == nil {
		t.Fatal("GM received player-only selection")
	}
	raw = json.RawMessage(`[{"character_id":"UNR-CHAR-0001"},{"character_id":"UNR-CHAR-0001"}]`)
	if _, err := task0OwnPublicCard(raw, orchestrator.SeatPlayer1); err == nil {
		t.Fatal("duplicate actor silently selected")
	}
}
