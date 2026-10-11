package pilot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
	"github.com/zyc14588/AIPT/internal/runcore"
)

const task0FixtureID = "b007-task0-diagnostic"

type task0Syntax struct {
	bySeat map[orchestrator.SeatID]json.RawMessage
}

// Syntax is transport metadata derived from the held, accepted contract and
// its fixed parameter-key registry. It contains no world text, numerical
// resolution, source locator or model-selected mutation authority.
func task0HeldSyntax(s *Task0PrototypeSources) (*task0Syntax, error) {
	if s == nil || s.binding != task0PrototypeSourceBinding || s.identity != Task0PrototypeAnnexSHA {
		return nil, ErrTask0
	}
	raw, err := s.copyHeldSource("aipt/task0-v2/action-contract.json")
	if err != nil || inputSHA(raw) != "6fa75e95fd1508958c551aaa507a07deffeb8d8ccf8485de1c98478f2d20c7d9" {
		return nil, ErrTask0
	}
	var contract struct {
		ActionTypes map[string]struct {
			Actor       string   `json:"actor"`
			Requires    []string `json:"requires"`
			IntentKinds []string `json:"intent_kinds"`
		} `json:"action_types"`
		TextLimit    int `json:"text_limit_utf8_bytes"`
		PayloadLimit int `json:"nested_payload_limit_bytes"`
	}
	if json.Unmarshal(raw, &contract) != nil || len(contract.ActionTypes) != 12 || contract.TextLimit != 320 || contract.PayloadLimit != 1024 {
		return nil, ErrTask0
	}
	script, err := s.copyHeldSource("scripts/aipt/task0-prototype.mjs")
	if err != nil {
		return nil, ErrTask0
	}
	start := bytes.Index(script, []byte("const PARAM_KEYS = {\n"))
	if start < 0 || bytes.Count(script, []byte("const PARAM_KEYS = {\n")) != 1 {
		return nil, ErrTask0
	}
	registry := script[start+len("const PARAM_KEYS = {\n"):]
	end := bytes.Index(registry, []byte("\n};"))
	if end < 0 || end > 4096 {
		return nil, ErrTask0
	}
	keys, err := task0ParameterRegistry(string(registry[:end]))
	if err != nil || len(keys) != len(contract.ActionTypes["PLAYER_INTENT"].IntentKinds) {
		return nil, ErrTask0
	}
	for _, kind := range contract.ActionTypes["PLAYER_INTENT"].IntentKinds {
		if _, ok := keys[kind]; !ok {
			return nil, ErrTask0
		}
	}
	if !bytes.Contains(script, []byte("['exposure', 'time', 'resource', 'pressure'].includes(cost)")) {
		return nil, ErrTask0
	}
	syntax := &task0Syntax{bySeat: map[orchestrator.SeatID]json.RawMessage{}}
	for _, seat := range orchestrator.BaselineSeats() {
		actor, _ := task0Actor(seat)
		types := map[string][]string{}
		for kind, spec := range contract.ActionTypes {
			allowed := false
			switch spec.Actor {
			case "GM", "GM_AFTER_ALL_SEATS_RECONSENT":
				allowed = seat == orchestrator.SeatGM
			case "OWN_CHARACTER":
				allowed = seat != orchestrator.SeatGM
			case "ANY_REGISTERED_SEAT":
				allowed = true
			default:
				return nil, ErrTask0
			}
			if allowed {
				types[kind] = append([]string{}, spec.Requires...)
			}
		}
		value := map[string]any{
			"outer_schema": orchestrator.AgentResponseSchema, "speech_encoding": "JSON_STRING_CONTAINING_ONE_TASK0_FRAME",
			"speech_frame_keys": []string{"actor_id", "action_type", "payload"}, "actor_id": actor,
			"action_payload_keys": types, "provider_action": nil, "world_text_is_data": true,
			"text_limit_utf8_bytes": contract.TextLimit, "payload_limit_bytes": contract.PayloadLimit,
			"outcome_and_rng_authority": "FIXED_GAME_KERNEL_AND_AIPT_RUN_CORE",
		}
		if seat != orchestrator.SeatGM {
			value["intent_parameter_keys"] = keys
			value["cost_choices"] = []string{"exposure", "time", "resource", "pressure"}
		}
		encoded, _ := json.Marshal(value)
		canonical, err := protocol.CanonicalJSON(encoded)
		if err != nil {
			return nil, ErrTask0
		}
		syntax.bySeat[seat] = json.RawMessage(canonical)
	}
	return syntax, nil
}

func task0ParameterRegistry(body string) (map[string][]string, error) {
	pattern := regexp.MustCompile(`([A-Z][A-Z_]*): \[((?:'[a-z_]+'(?:, )?)*)\]`)
	spans := pattern.FindAllStringSubmatchIndex(body, -1)
	keys := map[string][]string{}
	last := 0
	for _, span := range spans {
		separator := strings.TrimSpace(body[last:span[0]])
		if last == 0 && separator != "" || last != 0 && separator != "," {
			return nil, ErrTask0
		}
		name := body[span[2]:span[3]]
		if _, duplicate := keys[name]; duplicate {
			return nil, ErrTask0
		}
		items := []string{}
		if list := body[span[4]:span[5]]; list != "" {
			for _, item := range strings.Split(list, ", ") {
				if len(item) < 3 || item[0] != '\'' || item[len(item)-1] != '\'' {
					return nil, ErrTask0
				}
				key := item[1 : len(item)-1]
				if slices.Contains(items, key) {
					return nil, ErrTask0
				}
				items = append(items, key)
			}
		}
		keys[name], last = items, span[1]
	}
	if len(keys) == 0 || strings.TrimSpace(body[last:]) != "," {
		return nil, ErrTask0
	}
	return keys, nil
}

type task0References struct {
	contents map[string]orchestrator.RetrievedContent
	turn     task0AuthenticatedTurn
}

func (r *task0References) Retrieve(ctx context.Context, sources []orchestrator.AuthorizedSource) ([]orchestrator.RetrievedContent, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrTask0
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	if !ok || turn != r.turn {
		return nil, ErrTask0
	}
	result := make([]orchestrator.RetrievedContent, 0, len(sources))
	seen := map[string]bool{}
	for _, source := range sources {
		value, ok := r.contents[source.SourceID]
		if !ok || seen[source.SourceID] || value.Classification != source.Classification || value.ContentSHA256 != source.ExpectedSHA256 {
			return nil, ErrTask0
		}
		seen[source.SourceID] = true
		result = append(result, value)
	}
	return result, nil
}

// One synchronous B003 invocation owns this reference set. Identifiers from
// an earlier turn or a different seat cannot select another private view.
type task0ReferenceSlot struct {
	mu      sync.RWMutex
	current *task0References
}

func (s *task0ReferenceSlot) activate(ctx context.Context, refs *task0References) error {
	if s == nil || ctx == nil || ctx.Err() != nil || refs == nil {
		return ErrTask0
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	if !ok || turn != refs.turn {
		return ErrTask0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		return ErrTask0
	}
	s.current = refs
	return nil
}

func (s *task0ReferenceSlot) retire(refs *task0References) error {
	if s == nil || refs == nil {
		return ErrTask0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != refs {
		return ErrTask0
	}
	s.current = nil
	return nil
}

func (s *task0ReferenceSlot) Retrieve(ctx context.Context, sources []orchestrator.AuthorizedSource) ([]orchestrator.RetrievedContent, error) {
	if s == nil {
		return nil, ErrTask0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.Retrieve(ctx, sources)
}

func task0WireSeat(seat orchestrator.SeatID) string {
	switch seat {
	case orchestrator.SeatGM:
		return "seat-gm"
	case orchestrator.SeatPlayer1:
		return "seat-01"
	case orchestrator.SeatPlayer2:
		return "seat-02"
	case orchestrator.SeatPlayer3:
		return "seat-03"
	case orchestrator.SeatPlayer4:
		return "seat-04"
	default:
		return ""
	}
}

type task0PublicView struct {
	Characters json.RawMessage `json:"public_characters"`
	Reference  string          `json:"player_reference"`
	Situation  json.RawMessage `json:"situation"`
	Handouts   json.RawMessage `json:"handouts"`
	Ledger     json.RawMessage `json:"ledger"`
	Data       bool            `json:"world_text_is_data"`
}

type task0GMView struct {
	Schema          string          `json:"schema"`
	Principal       string          `json:"principal"`
	Characters      json.RawMessage `json:"public_characters"`
	Reference       string          `json:"player_reference"`
	Situation       json.RawMessage `json:"situation"`
	Handouts        json.RawMessage `json:"handouts"`
	Data            bool            `json:"world_text_is_data"`
	GM              json.RawMessage `json:"gm"`
	GMReference     string          `json:"gm_reference"`
	SafetyReference string          `json:"gm_safety_reference"`
	Private         json.RawMessage `json:"character_private"`
	AllHandouts     json.RawMessage `json:"all_handouts"`
	Domain          json.RawMessage `json:"domain_state"`
}

type task0OwnView struct {
	State   json.RawMessage `json:"own_state"`
	Private json.RawMessage `json:"own_private"`
}

// All authoritative state is retained in one role-scoped fact. Static world
// references are separately cited data and may be reduced by the unchanged
// gateway context policy. No full-state back door is passed to the Retriever.
func (k *task0KernelCore) turnContextInput(ctx context.Context, state runcore.RunState, syntax *task0Syntax) (orchestrator.ContextInput, *task0References, error) {
	fail := func() (orchestrator.ContextInput, *task0References, error) {
		return orchestrator.ContextInput{}, nil, ErrTask0
	}
	if k == nil || k.game == nil || syntax == nil || ctx == nil || ctx.Err() != nil || state.Binding != k.binding {
		return fail()
	}
	turn, ok := ctx.Value(task0TurnKey{}).(task0AuthenticatedTurn)
	wire := task0WireSeat(turn.seat)
	if !ok || wire == "" || turn.runID != state.Binding.RunID || turn.sequence != state.Sequence || syntax.bySeat[turn.seat] == nil {
		return fail()
	}
	raw, err := k.game.invoke(ctx, "PROJECTION", map[string]any{"state": state.DomainState, "seat": turn.seat, "fixture_id": task0FixtureID})
	p, errDecode := protocol.DecodeProjection(raw)
	stateCanonical, errState := protocol.CanonicalJSON(state.DomainState)
	if err != nil || errDecode != nil || errState != nil || p.ProtocolVersion != "1.0.0" || p.SchemaVersion != "1.0.0" ||
		p.FixtureID != task0FixtureID || p.SeatID != wire || p.ProjectionID != "task0-projection-"+wire+"-"+inputSHA([]byte(stateCanonical))[8:24] {
		return fail()
	}
	fields := map[string]protocol.StateField{}
	known := []string{"seat-gm", "seat-01", "seat-02", "seat-03", "seat-04"}
	for _, field := range p.Fields {
		var expected []string
		label := "TABLE_HIDDEN_REMOTE_ALLOWED"
		switch field.FieldID {
		case "task0-public":
			label, expected = "PUBLIC", known
		case "task0-gm":
			expected = []string{"seat-gm"}
		case "task0-seat-01", "task0-seat-02", "task0-seat-03", "task0-seat-04":
			expected = []string{"seat-gm", strings.TrimPrefix(field.FieldID, "task0-")}
		default:
			return fail()
		}
		actual := slices.Clone(field.Visibility.AuthorizedSeatIDs)
		want := slices.Clone(expected)
		slices.Sort(actual)
		slices.Sort(want)
		if fields[field.FieldID].FieldID != "" || !slices.Equal(actual, want) || field.Visibility.Label != label || !slices.Contains(expected, wire) {
			return fail()
		}
		fields[field.FieldID] = field
	}
	wanted := 2
	if turn.seat == orchestrator.SeatGM {
		wanted = 6
	}
	if len(fields) != wanted || fields["task0-public"].FieldID == "" {
		return fail()
	}
	var public task0PublicView
	if decodeFrozenJSON(fields["task0-public"].Value, 1<<20, &public) != nil || !public.Data || len(public.Characters) < 2 || len(public.Situation) < 2 || len(public.Handouts) < 2 || len(public.Ledger) == 0 {
		return fail()
	}
	refs := &task0References{contents: map[string]orchestrator.RetrievedContent{}, turn: turn}
	input := orchestrator.ContextInput{}
	allowed := []orchestrator.SeatID{orchestrator.SeatGM, turn.seat}
	scope := orchestrator.ScopeSeatPrivate
	if turn.seat == orchestrator.SeatGM {
		// B003 GM_ONLY is authorized by the role, with an empty explicit
		// recipient list. Explicit recipients belong only to SEAT_PRIVATE.
		allowed, scope = nil, orchestrator.ScopeGMOnly
	}
	add := func(priority int, content string, class orchestrator.DataClassification, refScope orchestrator.VisibilityScope, seats []orchestrator.SeatID) {
		if content == "" {
			return
		}
		identity := inputSHA([]byte(p.ProjectionID + "\x00" + content))
		id := fmt.Sprintf("task0-ref-%02d-%s", priority, identity[:24])
		if _, exists := refs.contents[id]; exists {
			return
		}
		hash := inputSHA([]byte(content))
		refs.contents[id] = orchestrator.RetrievedContent{SourceID: id, Classification: class, Content: content, ContentSHA256: hash}
		input.RequestedSources = append(input.RequestedSources, orchestrator.SourceDescriptor{SourceID: id, Classification: class, Scope: refScope, AllowedSeats: slices.Clone(seats), ExpectedSHA256: hash})
	}
	parts := func(priority int, text string, class orchestrator.DataClassification, refScope orchestrator.VisibilityScope, seats []orchestrator.SeatID) {
		// Preserve complete Markdown sections. Each returned byte is from an
		// already authorized projection; no neighboring source is reopened.
		start := 0
		for {
			next := strings.Index(text[start:], "\n## ")
			if next < 0 {
				add(priority, text[start:], class, refScope, seats)
				break
			}
			end := start + next + 1
			add(priority, text[start:end], class, refScope, seats)
			start = end
		}
	}
	view := map[string]any{"sequence": state.Sequence, "situation": public.Situation, "ledger": public.Ledger, "output_contract": syntax.bySeat[turn.seat]}
	var handouts map[string]json.RawMessage
	if json.Unmarshal(public.Handouts, &handouts) != nil {
		return fail()
	}
	handoutIDs := make([]string, 0, len(handouts))
	for id, body := range handouts {
		handoutIDs = append(handoutIDs, id)
		add(10, string(body), orchestrator.ClassPublic, orchestrator.ScopePublic, nil)
	}
	slices.Sort(handoutIDs)
	view["released_handout_ids"] = handoutIDs
	add(15, string(public.Characters), orchestrator.ClassPublic, orchestrator.ScopePublic, nil)
	parts(30, public.Reference, orchestrator.ClassPublic, orchestrator.ScopePublic, nil)
	if turn.seat == orchestrator.SeatGM {
		var gm task0GMView
		if decodeFrozenJSON(fields["task0-gm"].Value, 1<<20, &gm) != nil || gm.Schema != "unregistered.task0-role-projection/v2" || gm.Principal != "GM" || !gm.Data ||
			!bytes.Equal(gm.Domain, []byte(stateCanonical)) {
			return fail()
		}
		compact, compactErr := task0EncodeGMState(gm.Domain)
		procedure, phase, procedureErr := task0GMProcedure(gm.GMReference, gm.Domain)
		if compactErr != nil || procedureErr != nil {
			return fail()
		}
		view["domain_state"] = compact
		view["gm_procedure_data"] = procedure
		// These public values already occur exactly in the losslessly retained
		// GM state. Keep their projected identity in the original Context hash,
		// without sending duplicate values as a second mandatory view.
		delete(view, "situation")
		delete(view, "ledger")
		// The accepted GM projection already authorizes unpublished handout
		// bodies. Keep each body with its source handout identity; players still
		// receive only the release-filtered public.Handouts above.
		var allHandouts map[string]json.RawMessage
		if decodeFrozenJSON(gm.AllHandouts, 1<<20, &allHandouts) != nil {
			return fail()
		}
		for id, body := range allHandouts {
			if _, released := handouts[id]; released {
				continue
			}
			encoded, err := json.Marshal(map[string]any{"handout_id": id, "body": body})
			if err != nil {
				return fail()
			}
			add(9, string(encoded), orchestrator.ClassTableHiddenRemoteAllowed, scope, allowed)
		}
		var world map[string]json.RawMessage
		if json.Unmarshal(gm.GM, &world) != nil {
			return fail()
		}
		requiredWorld := map[string]json.RawMessage{}
		neededKnowledge := map[string]json.RawMessage{}
		for _, actor := range phase.Actors {
			if actor.Pollution > actor.Notes {
				requiredWorld["pollution_note_templates"] = world["pollution_note_templates"]
			}
			for _, knowledge := range actor.Knowledge {
				if knowledge.Status == "SEEN" {
					// VERIFY_KNOWLEDGE requires this exact actor's existing
					// SEEN fact and a source knowledge_facts entry. Pollution
					// notes remain exact actor data; they are not that action's
					// source truth registry. The complete registry still occurs
					// in the original authorized reference below.
					fact, err := task0NeededKnowledgeFact(world["knowledge_facts"], knowledge.FactID)
					if err != nil {
						return fail()
					}
					if fact != nil {
						neededKnowledge[knowledge.FactID] = fact
					}
				}
			}
		}
		if len(neededKnowledge) > 0 {
			body, err := json.Marshal(neededKnowledge)
			if err != nil {
				return fail()
			}
			requiredWorld["knowledge_facts"] = json.RawMessage(body)
		}
		if phase.Combat {
			requiredWorld["npcs"] = world["npcs"]
		}
		if len(requiredWorld) > 0 {
			for _, value := range requiredWorld {
				if len(value) < 2 {
					return fail()
				}
			}
			view["gm_required_world_data"] = requiredWorld
		}
		for key, value := range world {
			encoded, _ := json.Marshal(map[string]json.RawMessage{key: value})
			add(20, string(encoded), orchestrator.ClassTableHiddenRemoteAllowed, scope, allowed)
		}
		add(25, string(gm.Private), orchestrator.ClassTableHiddenRemoteAllowed, scope, allowed)
		parts(35, gm.GMReference, orchestrator.ClassTableHiddenRemoteAllowed, scope, allowed)
		parts(40, gm.SafetyReference, orchestrator.ClassTableHiddenRemoteAllowed, scope, allowed)
	} else {
		var own task0OwnView
		if decodeFrozenJSON(fields["task0-"+wire].Value, 1<<20, &own) != nil || len(own.State) < 2 || len(own.Private) < 2 {
			return fail()
		}
		view["own_state"] = own.State
		card, err := task0OwnPublicCard(public.Characters, turn.seat)
		if err != nil {
			return fail()
		}
		view["own_public_card"] = card
		add(5, string(own.Private), orchestrator.ClassTableHiddenRemoteAllowed, scope, allowed)
	}
	encoded, err := json.Marshal(view)
	canonical, errCanonical := protocol.CanonicalJSON(encoded)
	if err != nil || errCanonical != nil {
		return fail()
	}
	if turn.seat == orchestrator.SeatGM {
		packed, err := task0EncodeGMView(json.RawMessage(canonical))
		if err != nil {
			return fail()
		}
		canonical = string(packed)
	}
	fact := orchestrator.StateFact{FactID: "task0-turn-state", Classification: orchestrator.ClassTableHiddenRemoteAllowed, Scope: scope, AllowedSeats: allowed,
		Value: json.RawMessage(canonical), ValueSHA256: inputSHA([]byte(canonical))}
	input.StateFacts = []orchestrator.StateFact{fact}
	// There is no summarized prior event history here. Current state already
	// occurs in its complete authenticated fact above; copying its hash into
	// MemorySummary adds no history or authorization. Keep the original B003
	// empty-summary representation rather than a second current-state copy.
	input.Summary, err = orchestrator.NewMemorySummary("t0-"+string(turn.seat), "v1", turn.runID, turn.seat, nil, nil, nil)
	if err != nil || len(input.RequestedSources) > 128 {
		return fail()
	}
	return input, refs, nil
}
