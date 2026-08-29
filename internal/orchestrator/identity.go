package orchestrator

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

type BaselineIdentitySet struct {
	SessionIDs map[SeatID]string
	Personas   map[SeatID]PersonaBaseline
	Characters map[SeatID]Character
	GMProfile  GMProfile
}

func NewPersonaBaseline(personaID, version string, traits []PersonaTrait) (PersonaBaseline, error) {
	if err := validIdentity("persona_id", personaID); err != nil {
		return PersonaBaseline{}, err
	}
	if err := validIdentity("persona.version", version); err != nil {
		return PersonaBaseline{}, err
	}
	copy := append([]PersonaTrait(nil), traits...)
	sort.Slice(copy, func(i, j int) bool { return copy[i].Name < copy[j].Name })
	if len(copy) == 0 || len(copy) > 32 {
		return PersonaBaseline{}, errors.New("persona traits must be nonempty and bounded")
	}
	for index, trait := range copy {
		if err := validIdentity("persona.trait.name", trait.Name); err != nil {
			return PersonaBaseline{}, err
		}
		if trait.Value < 0 || trait.Value > 100 {
			return PersonaBaseline{}, errors.New("persona trait value is outside 0..100")
		}
		if index > 0 && copy[index-1].Name == trait.Name {
			return PersonaBaseline{}, errors.New("duplicate persona trait")
		}
	}
	identity := struct {
		PersonaID string         `json:"persona_id"`
		Version   string         `json:"version"`
		Traits    []PersonaTrait `json:"traits"`
	}{PersonaID: personaID, Version: version, Traits: copy}
	canonical, err := canonicalValue(identity)
	if err != nil {
		return PersonaBaseline{}, err
	}
	return PersonaBaseline{PersonaID: personaID, Version: version, Traits: copy, SHA256: sha256Bytes(canonical)}, nil
}

func NewCharacter(characterID, version string, projection []byte) (Character, error) {
	if err := validIdentity("character_id", characterID); err != nil {
		return Character{}, err
	}
	if err := validIdentity("character.version", version); err != nil {
		return Character{}, err
	}
	canonical, err := canonicalRaw(projection)
	if err != nil {
		return Character{}, err
	}
	return Character{
		CharacterID: characterID, Version: version,
		Projection: canonical, ProjectionSHA256: sha256Bytes(canonical),
	}, nil
}

func NewBaselineSeats(runID string, identities BaselineIdentitySet) ([]Seat, error) {
	if err := validIdentity("run_id", runID); err != nil {
		return nil, err
	}
	if identities.GMProfile != GMProfileNeutral && identities.GMProfile != GMProfileSkilled &&
		identities.GMProfile != GMProfileRulesFaithful {
		return nil, errors.New("unknown GM profile")
	}
	baseline := baselineSeatIDs()
	seats := make([]Seat, 0, len(baseline))
	for _, seatID := range baseline {
		sessionID, exists := identities.SessionIDs[seatID]
		if !exists {
			return nil, fmt.Errorf("missing session identity for %s", seatID)
		}
		persona, exists := identities.Personas[seatID]
		if !exists {
			return nil, fmt.Errorf("missing persona identity for %s", seatID)
		}
		role := RolePlayer
		roleContract := "AIPT_PLAYER_ROLE_CONTRACT_V1"
		var character *Character
		profile := GMProfile("")
		if seatID == SeatGM {
			role = RoleGM
			roleContract = "AIPT_GM_ROLE_CONTRACT_V1"
			profile = identities.GMProfile
		} else {
			value, ok := identities.Characters[seatID]
			if !ok {
				return nil, fmt.Errorf("missing Character identity for %s", seatID)
			}
			value.Projection = cloneRaw(value.Projection)
			character = &value
		}
		seats = append(seats, Seat{
			SeatID: seatID, RunID: runID, Role: role, RoleContractID: roleContract,
			VisibilityID: "visibility:" + string(seatID),
			Session:      Session{Schema: SessionSchema, SessionID: sessionID, RunID: runID, SeatID: seatID, Generation: 1},
			Persona:      clonePersona(persona), Character: character, GMProfile: profile,
		})
	}
	if err := validateSeatPlan(runID, seats); err != nil {
		return nil, err
	}
	return seats, nil
}

func validatePolicy(policy OrchestrationPolicy) error {
	if policy.Schema != PolicySchema {
		return errors.New("unknown orchestration policy schema")
	}
	if err := validIdentity("policy_id", policy.PolicyID); err != nil {
		return err
	}
	baseline := baselineSeatIDs()
	if !sameSeatSet(policy.SeatOrder, baseline) || !sameSeatSet(policy.InterruptionOrder, baseline) {
		return errors.New("seat and interruption orders must each contain the baseline seats exactly once")
	}
	if policy.SemanticRepairBudget < 0 || policy.SemanticRepairBudget > 64 ||
		policy.TransportRetryBudget < 0 || policy.TransportRetryBudget > 64 ||
		policy.SessionRecoveryBudget < 0 || policy.SessionRecoveryBudget > 64 {
		return errors.New("retry and recovery budgets must be explicit non-negative bounds")
	}
	if policy.InvocationTimeoutMillis <= 0 || policy.InvocationTimeoutMillis > 3_600_000 {
		return errors.New("invocation timeout must be an explicit positive bounded duration")
	}
	if policy.MaxContextSources < 0 || policy.MaxContextSources > 1024 || policy.MaxEventWindow < 0 || policy.MaxEventWindow > 4096 {
		return errors.New("context bounds are invalid")
	}
	return nil
}

func sameSeatSet(left, right []SeatID) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[SeatID]struct{}, len(left))
	for _, value := range left {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := seen[value]; !exists {
			return false
		}
	}
	return true
}

func validateSeatPlan(runID string, seats []Seat) error {
	if len(seats) != len(baselineSeatIDs()) {
		return errors.New("baseline requires exactly one GM and four Player seats")
	}
	seatIDs := map[SeatID]struct{}{}
	sessionIDs := map[string]struct{}{}
	personaIDs := map[string]struct{}{}
	characterIDs := map[string]struct{}{}
	gmCount, playerCount := 0, 0
	for _, seat := range seats {
		if !containsSeat(baselineSeatIDs(), seat.SeatID) {
			return errors.New("unknown baseline seat identity")
		}
		if _, exists := seatIDs[seat.SeatID]; exists {
			return errors.New("duplicate seat identity")
		}
		seatIDs[seat.SeatID] = struct{}{}
		if seat.RunID != runID || seat.Session.RunID != runID || seat.Session.SeatID != seat.SeatID {
			return errors.New("seat or Session Run binding mismatch")
		}
		if err := validateSession(seat.Session); err != nil {
			return err
		}
		if _, exists := sessionIDs[seat.Session.SessionID]; exists {
			return errors.New("Session aliasing across seats")
		}
		sessionIDs[seat.Session.SessionID] = struct{}{}
		if err := validatePersona(seat.Persona); err != nil {
			return err
		}
		if _, exists := personaIDs[seat.Persona.PersonaID]; exists {
			return errors.New("persona identity aliasing across seats")
		}
		personaIDs[seat.Persona.PersonaID] = struct{}{}
		switch seat.Role {
		case RoleGM:
			gmCount++
			if seat.SeatID != SeatGM || seat.Character != nil ||
				(seat.GMProfile != GMProfileNeutral && seat.GMProfile != GMProfileSkilled && seat.GMProfile != GMProfileRulesFaithful) ||
				seat.RoleContractID != "AIPT_GM_ROLE_CONTRACT_V1" {
				return errors.New("GM seat contract mismatch")
			}
		case RolePlayer:
			playerCount++
			if seat.SeatID == SeatGM || seat.Character == nil || seat.GMProfile != "" ||
				seat.RoleContractID != "AIPT_PLAYER_ROLE_CONTRACT_V1" {
				return errors.New("Player seat contract mismatch")
			}
			if err := validateCharacter(*seat.Character); err != nil {
				return err
			}
			if _, exists := characterIDs[seat.Character.CharacterID]; exists {
				return errors.New("character identity aliasing across Player seats")
			}
			characterIDs[seat.Character.CharacterID] = struct{}{}
		default:
			return errors.New("unknown seat role")
		}
		if seat.VisibilityID != "visibility:"+string(seat.SeatID) {
			return errors.New("seat visibility identity mismatch")
		}
	}
	if gmCount != 1 || playerCount != 4 {
		return errors.New("baseline requires exactly one GM and four Players")
	}
	return nil
}

func validateSession(session Session) error {
	if session.Schema != SessionSchema {
		return errors.New("unknown Session schema")
	}
	for _, item := range []struct {
		field string
		value string
	}{
		{field: "session_id", value: session.SessionID},
		{field: "run_id", value: session.RunID},
		{field: "seat_id", value: string(session.SeatID)},
	} {
		if err := validIdentity(item.field, item.value); err != nil {
			return err
		}
	}
	if session.Generation < 1 || session.Generation > 1024 {
		return errors.New("Session generation is outside the bound")
	}
	if session.Generation == 1 && session.ParentSessionID != "" {
		return errors.New("initial Session cannot have a parent")
	}
	if session.Generation > 1 {
		if err := validIdentity("parent_session_id", session.ParentSessionID); err != nil {
			return err
		}
		if session.ParentSessionID == session.SessionID {
			return errors.New("Session cannot recover to itself")
		}
	}
	return nil
}

func validatePersona(persona PersonaBaseline) error {
	rebuilt, err := NewPersonaBaseline(persona.PersonaID, persona.Version, persona.Traits)
	if err != nil {
		return err
	}
	if rebuilt.SHA256 != persona.SHA256 {
		return errors.New("Persona baseline hash mismatch")
	}
	return nil
}

func validatePersonaState(state PersonaState) error {
	if state.Version != "v1" || validIdentity("persona_state.persona_id", state.PersonaID) != nil ||
		validIdentity("persona_state.run_id", state.RunID) != nil || !containsSeat(baselineSeatIDs(), state.SeatID) ||
		state.Misunderstanding < 0 || state.Misunderstanding > 100 || state.Forgetting < 0 || state.Forgetting > 100 ||
		state.Stress < 0 || state.Stress > 100 || state.SuboptimalDecisionBias < 0 || state.SuboptimalDecisionBias > 100 ||
		state.LastPersonaEventSequence < 0 || state.LastPersonaEventSequence > 9_007_199_254_740_991 {
		return errors.New("Persona state is invalid or outside its bounds")
	}
	return nil
}

func validateCharacter(character Character) error {
	rebuilt, err := NewCharacter(character.CharacterID, character.Version, character.Projection)
	if err != nil {
		return err
	}
	if rebuilt.ProjectionSHA256 != character.ProjectionSHA256 {
		return errors.New("Character projection hash mismatch")
	}
	return nil
}

func clonePersona(value PersonaBaseline) PersonaBaseline {
	copy := value
	copy.Traits = append([]PersonaTrait(nil), value.Traits...)
	return copy
}

func cloneCharacter(value *Character) *Character {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Projection = cloneRaw(value.Projection)
	return &copy
}

type sessionRegistry struct {
	mu        sync.Mutex
	runID     string
	bySeat    map[SeatID]Session
	allIDs    map[string]struct{}
	authority *SessionAuthority
}

type sessionBinding struct {
	runID  string
	seatID SeatID
}

// SessionAuthority is a derived binding registry. It prevents an operational
// Session identity from being replayed across Runs or seats; it does not store
// gameplay facts and is reconstructable from authoritative lifecycle events.
type SessionAuthority struct {
	mu       sync.Mutex
	bindings map[string]sessionBinding
}

func NewSessionAuthority() *SessionAuthority {
	return &SessionAuthority{bindings: map[string]sessionBinding{}}
}

func (a *SessionAuthority) bind(session Session) error {
	return a.bindAll([]Session{session})
}

func (a *SessionAuthority) bindAll(sessions []Session) error {
	if a == nil {
		return errors.New("Session authority is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	pending := make(map[string]sessionBinding, len(sessions))
	for _, session := range sessions {
		binding := sessionBinding{runID: session.RunID, seatID: session.SeatID}
		if current, exists := a.bindings[session.SessionID]; exists && current != binding {
			return errors.New("Session identity is already bound to another Run or seat")
		}
		if current, exists := pending[session.SessionID]; exists && current != binding {
			return errors.New("Session identity is aliased inside one binding set")
		}
		pending[session.SessionID] = binding
	}
	for _, session := range sessions {
		a.bindings[session.SessionID] = pending[session.SessionID]
	}
	return nil
}

func newSessionRegistry(runID string, seats []Seat, authority *SessionAuthority) (*sessionRegistry, error) {
	registry := &sessionRegistry{runID: runID, bySeat: map[SeatID]Session{}, allIDs: map[string]struct{}{}, authority: authority}
	sessions := make([]Session, 0, len(seats))
	for _, seat := range seats {
		sessions = append(sessions, seat.Session)
	}
	if err := authority.bindAll(sessions); err != nil {
		return nil, err
	}
	for _, seat := range seats {
		registry.bySeat[seat.SeatID] = seat.Session
		registry.allIDs[seat.Session.SessionID] = struct{}{}
	}
	return registry, nil
}

func (r *sessionRegistry) get(seatID SeatID) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, exists := r.bySeat[seatID]
	return value, exists
}

func (r *sessionRegistry) recover(old, next Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.bySeat[old.SeatID]
	if !exists || current != old {
		return errors.New("old Session is not the current immutable seat binding")
	}
	if err := validateSession(next); err != nil {
		return err
	}
	if next.RunID != r.runID || next.RunID != old.RunID || next.SeatID != old.SeatID {
		return errors.New("recovered Session changed Run or seat identity")
	}
	if next.Generation != old.Generation+1 || next.ParentSessionID != old.SessionID {
		return errors.New("recovered Session generation or parent is invalid")
	}
	if _, exists := r.allIDs[next.SessionID]; exists {
		return errors.New("recovered Session reuses an existing identity")
	}
	if err := r.authority.bind(next); err != nil {
		return err
	}
	r.bySeat[next.SeatID] = next
	r.allIDs[next.SessionID] = struct{}{}
	return nil
}

type PersonaTracker struct {
	mu       sync.Mutex
	runID    string
	baseline map[SeatID]PersonaBaseline
	states   map[SeatID]PersonaState
	eventIDs map[string]struct{}
}

func NewPersonaTracker(runID string, seats []Seat) (*PersonaTracker, error) {
	if err := validateSeatPlan(runID, seats); err != nil {
		return nil, err
	}
	tracker := &PersonaTracker{
		runID: runID, baseline: map[SeatID]PersonaBaseline{}, states: map[SeatID]PersonaState{},
		eventIDs: map[string]struct{}{},
	}
	for _, seat := range seats {
		tracker.baseline[seat.SeatID] = clonePersona(seat.Persona)
		tracker.states[seat.SeatID] = PersonaState{
			Version: "v1", PersonaID: seat.Persona.PersonaID, RunID: runID, SeatID: seat.SeatID,
		}
	}
	return tracker, nil
}

func (t *PersonaTracker) Baseline(seatID SeatID) (PersonaBaseline, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	value, exists := t.baseline[seatID]
	return clonePersona(value), exists
}

func (t *PersonaTracker) State(seatID SeatID) (PersonaState, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	value, exists := t.states[seatID]
	return value, exists
}

func (t *PersonaTracker) Apply(event PersonaEvent) (PersonaState, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if event.Schema != PersonaEventSchema {
		return PersonaState{}, errors.New("unknown Persona event schema")
	}
	if err := validIdentity("persona_event.event_id", event.EventID); err != nil {
		return PersonaState{}, err
	}
	if _, exists := t.eventIDs[event.EventID]; exists {
		return PersonaState{}, errors.New("duplicate Persona event identity")
	}
	state, exists := t.states[event.SeatID]
	if !exists || event.RunID != t.runID || event.RunID != state.RunID || event.PersonaID != state.PersonaID {
		return PersonaState{}, errors.New("Persona event binding mismatch")
	}
	if event.Sequence != state.LastPersonaEventSequence+1 || event.Delta < -100 || event.Delta > 100 {
		return PersonaState{}, errors.New("Persona event sequence or delta is invalid")
	}
	apply := func(value *int) error {
		next := *value + event.Delta
		if next < 0 || next > 100 {
			return errors.New("Persona state would exceed the bounded range")
		}
		*value = next
		return nil
	}
	var err error
	switch event.Kind {
	case PersonaMisunderstanding:
		err = apply(&state.Misunderstanding)
	case PersonaForgetting:
		err = apply(&state.Forgetting)
	case PersonaStress:
		err = apply(&state.Stress)
	case PersonaSuboptimalDecisionBias:
		err = apply(&state.SuboptimalDecisionBias)
	default:
		err = errors.New("unknown Persona event kind")
	}
	if err != nil {
		return PersonaState{}, err
	}
	state.LastPersonaEventSequence = event.Sequence
	t.states[event.SeatID] = state
	t.eventIDs[event.EventID] = struct{}{}
	return state, nil
}
