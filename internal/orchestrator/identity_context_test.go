package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBaselineSeatSessionAndPersonaContracts(t *testing.T) {
	runID := "run-seat-contract"
	seats := fixtureSeats(t, runID)
	if len(seats) != 5 {
		t.Fatalf("seat count = %d", len(seats))
	}
	gm, players := 0, 0
	sessions := map[string]struct{}{}
	for _, seat := range seats {
		if seat.Role == RoleGM {
			gm++
			if seat.Character != nil || seat.GMProfile != GMProfileRulesFaithful {
				t.Fatalf("GM contract = %+v", seat)
			}
		} else {
			players++
			if seat.Character == nil {
				t.Fatalf("Player lacks Character: %s", seat.SeatID)
			}
		}
		if _, exists := sessions[seat.Session.SessionID]; exists {
			t.Fatalf("duplicate Session %s", seat.Session.SessionID)
		}
		sessions[seat.Session.SessionID] = struct{}{}
	}
	if gm != 1 || players != 4 {
		t.Fatalf("roles gm=%d players=%d", gm, players)
	}

	aliased := append([]Seat(nil), seats...)
	aliased[2].Session.SessionID = aliased[1].Session.SessionID
	if err := validateSeatPlan(runID, aliased); err == nil {
		t.Fatal("Session aliasing accepted")
	}

	contractMutations := []struct {
		name   string
		mutate func([]Seat)
	}{
		{"gm-profile", func(values []Seat) { values[0].GMProfile = "provider-profile" }},
		{"gm-role-contract", func(values []Seat) { values[0].RoleContractID = "ATTACKER_ROLE" }},
		{"player-role-contract", func(values []Seat) { values[1].RoleContractID = "ATTACKER_ROLE" }},
		{"visibility-binding", func(values []Seat) { values[1].VisibilityID = "visibility:PLAYER_2" }},
	}
	for _, probe := range contractMutations {
		t.Run(probe.name, func(t *testing.T) {
			copy := append([]Seat(nil), seats...)
			probe.mutate(copy)
			if err := validateSeatPlan(runID, copy); err == nil {
				t.Fatal("mutated seat contract accepted")
			}
		})
	}

	authority := NewSessionAuthority()
	for _, seat := range seats {
		if err := authority.bind(seat.Session); err != nil {
			t.Fatalf("bind: %v", err)
		}
	}
	crossRun := seats[1].Session
	crossRun.RunID = "run-other"
	if err := authority.bind(crossRun); err == nil {
		t.Fatal("cross-Run Session replay accepted")
	}
	crossSeat := seats[1].Session
	crossSeat.SeatID = SeatPlayer2
	if err := authority.bind(crossSeat); err == nil {
		t.Fatal("cross-seat Session replay accepted")
	}

	atomicAuthority := NewSessionAuthority()
	conflict := seats[2].Session
	conflict.RunID = "other-run"
	if err := atomicAuthority.bind(conflict); err != nil {
		t.Fatalf("seed conflict: %v", err)
	}
	if err := atomicAuthority.bindAll([]Session{seats[1].Session, seats[2].Session}); err == nil {
		t.Fatal("conflicting Session set accepted")
	}
	if _, exists := atomicAuthority.bindings[seats[1].Session.SessionID]; exists {
		t.Fatal("failed Session set partially mutated authority")
	}
}

func TestPersonaBaselineImmutableEventStateAndCharacterSeparation(t *testing.T) {
	runID := "run-persona"
	seats := fixtureSeats(t, runID)
	tracker, err := NewPersonaTracker(runID, seats)
	if err != nil {
		t.Fatalf("NewPersonaTracker: %v", err)
	}
	beforeCharacter := cloneRaw(seatByID(t, seats, SeatPlayer1).Character.Projection)
	baseline, _ := tracker.Baseline(SeatPlayer1)
	originalHash := baseline.SHA256
	baseline.Traits[0].Value = 99
	reloaded, _ := tracker.Baseline(SeatPlayer1)
	if reloaded.SHA256 != originalHash || reloaded.Traits[0].Value == 99 {
		t.Fatal("Persona baseline was mutable through a returned copy")
	}
	state, err := tracker.Apply(PersonaEvent{
		Schema: PersonaEventSchema, EventID: "persona-event-1", RunID: runID, SeatID: SeatPlayer1,
		PersonaID: reloaded.PersonaID, Sequence: 1, Kind: PersonaStress, Delta: 25,
	})
	if err != nil || state.Stress != 25 || state.LastPersonaEventSequence != 1 {
		t.Fatalf("Persona Apply = %+v, %v", state, err)
	}
	if !reflect.DeepEqual(beforeCharacter, seatByID(t, seats, SeatPlayer1).Character.Projection) {
		t.Fatal("Persona state changed Character projection")
	}
	if _, err := tracker.Apply(PersonaEvent{
		Schema: PersonaEventSchema, EventID: "persona-event-gap", RunID: runID, SeatID: SeatPlayer1,
		PersonaID: reloaded.PersonaID, Sequence: 3, Kind: PersonaForgetting, Delta: 1,
	}); err == nil {
		t.Fatal("Persona event sequence gap accepted")
	}
	if _, err := tracker.Apply(PersonaEvent{
		Schema: PersonaEventSchema, EventID: "persona-event-cross", RunID: "run-other", SeatID: SeatPlayer1,
		PersonaID: reloaded.PersonaID, Sequence: 2, Kind: PersonaStress, Delta: 1,
	}); err == nil {
		t.Fatal("cross-Run Persona event accepted")
	}
	if _, err := tracker.Apply(PersonaEvent{
		Schema: PersonaEventSchema, EventID: "persona-event-1", RunID: runID, SeatID: SeatPlayer1,
		PersonaID: reloaded.PersonaID, Sequence: 2, Kind: PersonaStress, Delta: 1,
	}); err == nil {
		t.Fatal("duplicate Persona event identity accepted")
	}
}

func TestSeatAuthorizedViewFailClosedVisibilityMatrix(t *testing.T) {
	runID := "run-visibility"
	seats := fixtureSeats(t, runID)
	facts := []StateFact{
		fact(t, "public", ClassPublic, ScopePublic, nil, `{"v":"public"}`),
		fact(t, "gm-only", ClassTableHiddenRemoteAllowed, ScopeGMOnly, nil, `{"v":"gm-secret"}`),
		fact(t, "p1-private", ClassTableHiddenRemoteAllowed, ScopeSeatPrivate, []SeatID{SeatPlayer1}, `{"v":"p1-secret"}`),
		fact(t, "system", ClassSystemInternal, ScopeSystemInternal, nil, `{"v":"internal"}`),
		fact(t, "credential", ClassCredentialSecret, ScopeSeatPrivate, []SeatID{SeatPlayer1}, `{"v":"credential-secret"}`),
		fact(t, "human-private", ClassHumanPrivateData, ScopeSeatPrivate, []SeatID{SeatPlayer1}, `{"v":"human-private"}`),
	}
	viewP1, err := BuildAuthorizedView(runID, seatByID(t, seats, SeatPlayer1), facts)
	if err != nil {
		t.Fatalf("P1 view: %v", err)
	}
	if got := factIDs(viewP1.Facts); !reflect.DeepEqual(got, []string{"p1-private", "public"}) {
		t.Fatalf("P1 facts = %v", got)
	}
	viewP2, err := BuildAuthorizedView(runID, seatByID(t, seats, SeatPlayer2), facts)
	if err != nil {
		t.Fatalf("P2 view: %v", err)
	}
	if got := factIDs(viewP2.Facts); !reflect.DeepEqual(got, []string{"public"}) {
		t.Fatalf("P2 facts = %v", got)
	}
	viewGM, err := BuildAuthorizedView(runID, seatByID(t, seats, SeatGM), facts)
	if err != nil {
		t.Fatalf("GM view: %v", err)
	}
	if got := factIDs(viewGM.Facts); !reflect.DeepEqual(got, []string{"gm-only", "public"}) {
		t.Fatalf("GM facts = %v", got)
	}
	unlabelled := append([]StateFact(nil), facts...)
	unlabelled = append(unlabelled, StateFact{FactID: "missing-label", Scope: ScopePublic, Value: json.RawMessage(`{"x":1}`)})
	_, err = BuildAuthorizedView(runID, seatByID(t, seats, SeatPlayer1), unlabelled)
	if !errors.Is(err, Sentinel(CodeVisibilityDenied)) {
		t.Fatalf("unlabelled fact error = %v", err)
	}
}

func factIDs(facts []StateFact) []string {
	result := make([]string, len(facts))
	for index, fact := range facts {
		result[index] = fact.FactID
	}
	return result
}

func TestACLBeforeRetrievalCitationVerificationAndNoSecretErrorLeak(t *testing.T) {
	runID := "run-retrieval"
	seat := seatByID(t, fixtureSeats(t, runID), SeatPlayer1)
	secretPayload := "postgres://user:password@host/database root-seed=deadbeef"
	secret := SourceDescriptor{
		SourceID: "gm-source", Classification: ClassTableHiddenRemoteAllowed, Scope: ScopeGMOnly,
		ExpectedSHA256: sha256String(secretPayload),
	}
	retriever := &recordingRetriever{content: map[string]RetrievedContent{}}
	_, err := authorizeSources(runID, seat, []SourceDescriptor{secret}, 10)
	if !errors.Is(err, Sentinel(CodeVisibilityDenied)) || retriever.callCount() != 0 {
		t.Fatalf("ACL did not reject before retrieval: err=%v calls=%d", err, retriever.callCount())
	}
	if strings.Contains(err.Error(), secretPayload) || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "root-seed") {
		t.Fatalf("error leaked hidden payload: %v", err)
	}

	publicText := "allowed source"
	public := SourceDescriptor{SourceID: "public-source", Classification: ClassPublic, Scope: ScopePublic, ExpectedSHA256: sha256String(publicText)}
	authorized, err := authorizeSources(runID, seat, []SourceDescriptor{public}, 10)
	if err != nil {
		t.Fatalf("authorize public: %v", err)
	}
	retriever.content[public.SourceID] = RetrievedContent{
		SourceID: public.SourceID, Classification: ClassPublic, Content: publicText, ContentSHA256: strings.Repeat("0", 64),
	}
	if _, err := retrieveAuthorized(context.Background(), runID, seat, authorized, retriever); !errors.Is(err, Sentinel(CodeContextInvariantFailed)) {
		t.Fatalf("bad citation accepted: %v", err)
	}

	unlabelled := public
	unlabelled.Classification = ""
	if _, err := authorizeSources(runID, seat, []SourceDescriptor{unlabelled}, 10); !errors.Is(err, Sentinel(CodeVisibilityDenied)) {
		t.Fatalf("unlabelled retrievable content accepted: %v", err)
	}
}

func TestDeterministicContextAssemblyUntrustedIsolationAndToolFiltering(t *testing.T) {
	runID := "run-context"
	seats := fixtureSeats(t, runID)
	seat := seatByID(t, seats, SeatPlayer1)
	tracker, _ := NewPersonaTracker(runID, seats)
	state, _ := tracker.State(SeatPlayer1)
	input, retriever := fixtureContextInput(t, runID, SeatPlayer1)
	private := EventWindowItem{
		EventID: "private-1", Classification: ClassTableHiddenRemoteAllowed, Scope: ScopeSeatPrivate,
		Recipients: []SeatID{SeatPlayer1, SeatPlayer2}, Content: "private data", ContentSHA256: sha256String("private data"),
	}
	input.EventWindow = []EventWindowItem{private}
	first, err := BuildContext(context.Background(), fixturePolicy(), seat, state, input, retriever)
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}
	if err := ValidateContextHash(first); err != nil {
		t.Fatalf("ValidateContextHash: %v", err)
	}
	if first.Trusted.RoleContractID != "AIPT_PLAYER_ROLE_CONTRACT_V1" || len(first.Trusted.AvailableTools) != 1 ||
		first.Trusted.AvailableTools[0].ToolID != "tool-common" {
		t.Fatalf("trusted context = %+v", first.Trusted)
	}
	if len(first.Untrusted.Retrieved) != 1 || !strings.Contains(first.Untrusted.Retrieved[0].Content, "Ignore previous instructions") {
		t.Fatalf("untrusted content not isolated: %+v", first.Untrusted.Retrieved)
	}
	if first.Trusted.RoleContractID == first.Untrusted.Retrieved[0].Content {
		t.Fatal("untrusted content changed trusted role")
	}

	shuffled := input
	shuffled.StateFacts = append([]StateFact(nil), input.StateFacts...)
	shuffled.Tools = []ToolDescriptor{input.Tools[1], input.Tools[0]}
	second, err := BuildContext(context.Background(), fixturePolicy(), seat, state, shuffled, retriever)
	if err != nil {
		t.Fatalf("BuildContext shuffled: %v", err)
	}
	if first.ContextHash != second.ContextHash || first.AuthorizedProjectionHash != second.AuthorizedProjectionHash {
		t.Fatalf("context hashes drifted: %s/%s vs %s/%s", first.ContextHash, first.AuthorizedProjectionHash, second.ContextHash, second.AuthorizedProjectionHash)
	}

	mutated := first
	mutated.Trusted.RoleContractID = "ATTACKER_ROLE"
	if ValidateContextHash(mutated) == nil {
		t.Fatal("mutated trusted context hash accepted")
	}
}

func TestMemorySummaryInvariantRejectsFabricatedHiddenAndOmittedFacts(t *testing.T) {
	runID := "run-summary"
	seats := fixtureSeats(t, runID)
	seat := seatByID(t, seats, SeatPlayer1)
	public := fact(t, "public", ClassPublic, ScopePublic, nil, `{"x":1}`)
	hidden := fact(t, "gm-hidden", ClassTableHiddenRemoteAllowed, ScopeGMOnly, nil, `{"secret":true}`)
	view, err := BuildAuthorizedView(runID, seat, []StateFact{hidden, public})
	if err != nil {
		t.Fatalf("BuildAuthorizedView: %v", err)
	}
	valid, _ := NewMemorySummary("summary-valid", "v1", runID, SeatPlayer1,
		[]SummaryFact{{FactID: public.FactID, ValueSHA256: public.ValueSHA256}}, []string{public.FactID}, nil)
	if err := validateSummary(runID, seat, valid, view, nil); err != nil {
		t.Fatalf("valid summary rejected: %v", err)
	}
	duplicateRequired, _ := NewMemorySummary("summary-duplicate-required", "v1", runID, SeatPlayer1,
		[]SummaryFact{{FactID: public.FactID, ValueSHA256: public.ValueSHA256}},
		[]string{public.FactID, public.FactID}, nil)
	if err := validateSummary(runID, seat, duplicateRequired, view, nil); !errors.Is(err, Sentinel(CodeContextInvariantFailed)) {
		t.Fatalf("duplicate required fact accepted: %v", err)
	}

	probes := []struct {
		name     string
		facts    []SummaryFact
		required []string
	}{
		{"fabricated", []SummaryFact{{FactID: "fabricated", ValueSHA256: strings.Repeat("a", 64)}}, nil},
		{"hidden", []SummaryFact{{FactID: hidden.FactID, ValueSHA256: hidden.ValueSHA256}}, nil},
		{"stale", []SummaryFact{{FactID: public.FactID, ValueSHA256: strings.Repeat("b", 64)}}, nil},
		{"required-omitted", nil, []string{public.FactID}},
	}
	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			summary, _ := NewMemorySummary("summary-"+probe.name, "v1", runID, SeatPlayer1, probe.facts, probe.required, nil)
			if err := validateSummary(runID, seat, summary, view, nil); !errors.Is(err, Sentinel(CodeContextInvariantFailed)) {
				t.Fatalf("probe accepted: %v", err)
			}
		})
	}
}

func TestContextCanonicalizesSummaryAndRejectsInvalidACLAndTools(t *testing.T) {
	runID := "run-context-canonical-inputs"
	seats := fixtureSeats(t, runID)
	seat := seatByID(t, seats, SeatPlayer1)
	tracker, _ := NewPersonaTracker(runID, seats)
	state, _ := tracker.State(SeatPlayer1)
	input, retriever := fixtureContextInput(t, runID, SeatPlayer1)
	second := fact(t, "fact-second", ClassPublic, ScopePublic, nil, `{"round":2}`)
	input.StateFacts = append(input.StateFacts, second)
	input.Summary, _ = NewMemorySummary("summary-canonical", "v1", runID, SeatPlayer1,
		[]SummaryFact{
			{FactID: second.FactID, ValueSHA256: second.ValueSHA256},
			{FactID: input.StateFacts[0].FactID, ValueSHA256: input.StateFacts[0].ValueSHA256},
		}, []string{second.FactID, input.StateFacts[0].FactID}, []string{"source-public"})
	// Preserve the canonical hash while deliberately presenting the lists in
	// a different order. BuildContext must normalize the embedded summary.
	input.Summary.Facts[0], input.Summary.Facts[1] = input.Summary.Facts[1], input.Summary.Facts[0]
	input.Summary.RequiredFactIDs[0], input.Summary.RequiredFactIDs[1] = input.Summary.RequiredFactIDs[1], input.Summary.RequiredFactIDs[0]
	bundle, err := BuildContext(context.Background(), fixturePolicy(), seat, state, input, retriever)
	if err != nil {
		t.Fatalf("BuildContext unordered summary: %v", err)
	}
	if bundle.Untrusted.MemorySummary.Facts[0].FactID != "fact-public" ||
		bundle.Untrusted.MemorySummary.RequiredFactIDs[0] != "fact-public" {
		t.Fatalf("summary was not canonicalized: %+v", bundle.Untrusted.MemorySummary)
	}

	badACL := input
	badACL.StateFacts = append([]StateFact(nil), input.StateFacts...)
	badACL.StateFacts[0].AllowedSeats = []SeatID{"PLAYER_99"}
	if _, err := BuildContext(context.Background(), fixturePolicy(), seat, state, badACL, retriever); !errors.Is(err, Sentinel(CodeVisibilityDenied)) {
		t.Fatalf("invalid ACL seat accepted: %v", err)
	}

	badTool := input
	badTool.Tools = []ToolDescriptor{{ToolID: "tool-invalid", Version: "v1", AllowedRoles: []Role{"ORACLE"}}}
	if _, err := BuildContext(context.Background(), fixturePolicy(), seat, state, badTool, retriever); !errors.Is(err, Sentinel(CodeContextInvariantFailed)) {
		t.Fatalf("invalid tool grant accepted: %v", err)
	}
}

func TestSerializedArrayContractsNeverEmitNull(t *testing.T) {
	runID := "run-json-array-contracts"
	seats := fixtureSeats(t, runID)
	tracker, _ := NewPersonaTracker(runID, seats)
	state, _ := tracker.State(SeatPlayer1)
	input, retriever := fixtureContextInput(t, runID, SeatPlayer1)
	bundle, err := BuildContext(context.Background(), fixturePolicy(), seatByID(t, seats, SeatPlayer1), state, input, retriever)
	if err != nil {
		t.Fatalf("BuildContext: %v", err)
	}
	contextJSON, _ := json.Marshal(bundle)
	for _, forbidden := range []string{
		`"allowed_seats":null`, `"event_window":null`, `"facts":null`,
		`"required_fact_ids":null`, `"source_ids":null`, `"available_tools":null`, `"retrieved":null`,
	} {
		if strings.Contains(string(contextJSON), forbidden) {
			t.Fatalf("context violates strict array schema with %s: %s", forbidden, contextJSON)
		}
	}
	floor, _ := NewFloorController(runID, fixturePolicy())
	_ = floor.OpenDiscussion()
	eventJSON, _ := json.Marshal(floor.Events()[0])
	if strings.Contains(string(eventJSON), `"recipients":null`) || !strings.Contains(string(eventJSON), `"recipients":[]`) {
		t.Fatalf("event recipients are not a JSON array: %s", eventJSON)
	}
	empty, _ := NewMemorySummary("summary-empty", "v1", runID, SeatPlayer1, nil, nil, nil)
	emptyJSON, _ := json.Marshal(empty)
	for _, required := range []string{`"facts":[]`, `"required_fact_ids":[]`, `"source_ids":[]`} {
		if !strings.Contains(string(emptyJSON), required) {
			t.Fatalf("empty summary lacks %s: %s", required, emptyJSON)
		}
	}
}
