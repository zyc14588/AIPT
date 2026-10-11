package pilot

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
)

const task0ActorEncoding = "ACTORS_INHERIT_SHARED_THEN_OVERRIDE_V1"
const task0ModalActorEncoding = "ACTORS_INHERIT_MODAL_THEN_OVERRIDE_V2"

type task0EncodedGMState struct {
	Encoding string                                `json:"encoding"`
	State    map[string]json.RawMessage            `json:"state"`
	Shared   map[string]json.RawMessage            `json:"actors_shared"`
	Actors   map[string]map[string]json.RawMessage `json:"actors"`
}

// Common actor fields occur once. Each actor inherits all shared fields and
// then overrides with its own map. This is a reversible representation of the
// already authorized GM projection, with no removed/defaulted state values.
// It is never used to create a player view or alter the authoritative Core.
func task0EncodeGMState(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) < 2 || len(raw) > 1<<20 {
		return nil, ErrTask0
	}
	canonical, err := protocol.CanonicalJSON(raw)
	var state map[string]json.RawMessage
	if err != nil || json.Unmarshal([]byte(canonical), &state) != nil || state == nil {
		return nil, ErrTask0
	}
	if _, exists := state["encoding"]; exists {
		return nil, ErrTask0
	}
	actorRaw, exists := state["actors"]
	if !exists {
		return json.RawMessage(canonical), nil
	}
	var actors map[string]map[string]json.RawMessage
	if json.Unmarshal(actorRaw, &actors) != nil || len(actors) != 4 {
		return nil, ErrTask0
	}
	ids := make([]string, 0, 4)
	for _, seat := range orchestrator.BaselineSeats()[1:] {
		id, _ := task0Actor(seat)
		if actors[id] == nil {
			return nil, ErrTask0
		}
		ids = append(ids, id)
	}
	shared := map[string]json.RawMessage{}
	modal := false
	for key, value := range actors[ids[0]] {
		counts := map[string]int{}
		present := true
		for _, id := range ids {
			v, ok := actors[id][key]
			if !ok {
				present = false
				break
			}
			counts[string(v)]++
		}
		if !present {
			continue
		}
		best, count := string(value), counts[string(value)]
		for candidate, n := range counts {
			if n > count || n == count && candidate < best {
				best, count = candidate, n
			}
		}
		// A shared value is an explicit existing value, never a default. It
		// must already occur in at least two actors and its key in all four.
		// Different actors retain exact overrides, including null/empty/zero.
		if count >= 2 {
			shared[key] = json.RawMessage(best)
			modal = modal || count != 4
		}
	}
	for _, id := range ids {
		for key, value := range shared {
			if bytes.Equal(actors[id][key], value) {
				delete(actors[id], key)
			}
		}
	}
	delete(state, "actors")
	encoding := task0ActorEncoding
	if modal {
		encoding = task0ModalActorEncoding
	}
	encoded, err := json.Marshal(task0EncodedGMState{Encoding: encoding, State: state, Shared: shared, Actors: actors})
	compact, canonicalErr := protocol.CanonicalJSON(encoded)
	if err != nil || canonicalErr != nil {
		return nil, ErrTask0
	}
	decoded, err := task0DecodeGMState(json.RawMessage(compact))
	if err != nil || !bytes.Equal(decoded, []byte(canonical)) {
		return nil, ErrTask0
	}
	if len(compact) >= len(canonical) {
		return json.RawMessage(canonical), nil
	}
	return json.RawMessage(compact), nil
}

// The encoder checks this exact round trip on every production context, not
// just in fixtures. The decoder is private control code; model output cannot
// use this representation as a state patch.
func task0DecodeGMState(raw json.RawMessage) (json.RawMessage, error) {
	var p task0EncodedGMState
	if decodeFrozenJSON(raw, 1<<20, &p) != nil || (p.Encoding != task0ActorEncoding && p.Encoding != task0ModalActorEncoding) || p.State == nil || p.Shared == nil || len(p.Actors) != 4 || p.State["actors"] != nil {
		return nil, ErrTask0
	}
	for _, seat := range orchestrator.BaselineSeats()[1:] {
		id, _ := task0Actor(seat)
		values, exists := p.Actors[id]
		if !exists || values == nil {
			return nil, ErrTask0
		}
		for key, value := range p.Shared {
			if override, duplicate := values[key]; duplicate {
				if p.Encoding == task0ActorEncoding || bytes.Equal(override, value) {
					return nil, ErrTask0
				}
				continue
			}
			values[key] = value
		}
	}
	if p.Encoding == task0ModalActorEncoding {
		for key, value := range p.Shared {
			matches := 0
			for _, actor := range p.Actors {
				if bytes.Equal(actor[key], value) {
					matches++
				}
			}
			if matches < 2 {
				return nil, ErrTask0
			}
		}
	}
	actorRaw, err := json.Marshal(p.Actors)
	if err != nil {
		return nil, ErrTask0
	}
	p.State["actors"] = actorRaw
	decoded, err := json.Marshal(p.State)
	canonical, ce := protocol.CanonicalJSON(decoded)
	if err != nil || ce != nil || len(canonical) > 1<<20 {
		return nil, ErrTask0
	}
	return json.RawMessage(canonical), nil
}

func task0OwnPublicCard(raw json.RawMessage, seat orchestrator.SeatID) (json.RawMessage, error) {
	var cards []json.RawMessage
	if json.Unmarshal(raw, &cards) != nil {
		return nil, ErrTask0
	}
	actor, ok := task0Actor(seat)
	if !ok || seat == orchestrator.SeatGM {
		return nil, ErrTask0
	}
	var result json.RawMessage
	for _, card := range cards {
		var identity struct {
			ID string `json:"character_id"`
		}
		if json.Unmarshal(card, &identity) != nil {
			return nil, ErrTask0
		}
		if identity.ID == actor {
			if result != nil {
				return nil, ErrTask0
			}
			result = slices.Clone(card)
		}
	}
	// The actual held source contains exactly one card per authenticated actor.
	if result == nil {
		return nil, ErrTask0
	}
	return result, nil
}

type task0ContextPhase struct {
	Mission string          `json:"mission"`
	Ledger  json.RawMessage `json:"ledger"`
	Rest    json.RawMessage `json:"rest_event"`
	Risk    []string        `json:"risk_queue"`
	Combat  bool            `json:"combat_active"`
	Actors  map[string]struct {
		Rest      int             `json:"rest_points"`
		Melee     json.RawMessage `json:"melee_target"`
		Knowledge []struct {
			FactID string `json:"fact_id"`
			Status string `json:"status"`
		} `json:"knowledge"`
		Pollution int `json:"pollution"`
		Notes     int `json:"pollution_note_count"`
	} `json:"actors"`
}

func task0Null(raw json.RawMessage) bool { return len(raw) == 0 || bytes.Equal(raw, []byte("null")) }

// Select literal numbered runbook paragraphs by committed phase. These are
// mandatory world data, never trusted instructions, and do not select the
// next action or force a mission outcome. Other authorized references remain
// available to the unchanged B004 reduction policy.
func task0GMProcedure(text string, domain json.RawMessage) ([]string, task0ContextPhase, error) {
	var phase task0ContextPhase
	if json.Unmarshal(domain, &phase) != nil {
		return nil, phase, ErrTask0
	}
	const heading = "## Procedure / Rule Text\n"
	start := strings.Index(text, heading)
	if start < 0 {
		return []string{text}, phase, nil
	}
	if strings.Count(text, heading) != 1 {
		return nil, phase, ErrTask0
	}
	body := text[start+len(heading):]
	if end := strings.Index(body, "\n## "); end >= 0 {
		body = body[:end+1]
	}
	spans := regexp.MustCompile(`(?m)^([0-9]{1,2})\. `).FindAllStringSubmatchIndex(body, -1)
	if len(spans) != 12 {
		return nil, phase, ErrTask0
	}
	items := map[int]string{}
	for i, span := range spans {
		want := string([]byte{byte('1' + i)})
		if i >= 9 {
			want = []string{"10", "11", "12"}[i-9]
		}
		if body[span[2]:span[3]] != want {
			return nil, phase, ErrTask0
		}
		end := len(body)
		if i+1 < len(spans) {
			end = spans[i+1][0]
		}
		items[i+1] = body[span[0]:end]
	}
	selected := []int{2, 12}
	if task0Null(phase.Ledger) {
		if phase.Mission == "OPEN" {
			selected = append(selected, 1)
		} else {
			selected = append(selected, 9)
		}
	} else {
		selected = append(selected, 10)
		allRestDone := true
		for _, actor := range phase.Actors {
			allRestDone = allRestDone && actor.Rest == 0
		}
		if allRestDone && task0Null(phase.Rest) || len(phase.Risk) > 0 {
			selected = append(selected, 11)
		}
	}
	melee := phase.Combat
	for _, actor := range phase.Actors {
		melee = melee || !task0Null(actor.Melee)
	}
	if melee {
		selected = append(selected, 6)
	}
	slices.Sort(selected)
	result := make([]string, 0, len(selected))
	for _, item := range selected {
		result = append(result, items[item])
	}
	return result, phase, nil
}
