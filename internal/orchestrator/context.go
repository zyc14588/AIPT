package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"unicode/utf8"
)

func BuildAuthorizedView(runID string, seat Seat, facts []StateFact) (AuthorizedView, error) {
	const operation = "build_authorized_view"
	if seat.RunID != runID {
		return AuthorizedView{}, orchestrationError(CodeSeatUnauthorized, operation, runID, seat.SeatID, "", errors.New("seat Run mismatch"))
	}
	seen := map[string]struct{}{}
	authorized := make([]StateFact, 0, len(facts))
	for _, fact := range facts {
		if err := validIdentity("fact_id", fact.FactID); err != nil || !validClassification(fact.Classification) ||
			!validScope(fact.Scope) || !validScopedSeatList(fact.Scope, fact.AllowedSeats) {
			return AuthorizedView{}, orchestrationError(CodeVisibilityDenied, operation, runID, seat.SeatID, "", errors.New("unlabelled or invalid fact"))
		}
		if _, exists := seen[fact.FactID]; exists {
			return AuthorizedView{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate fact identity"))
		}
		seen[fact.FactID] = struct{}{}
		canonical, err := canonicalRaw(fact.Value)
		if err != nil || fact.ValueSHA256 != sha256Bytes(canonical) {
			return AuthorizedView{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("fact value/hash invalid"))
		}
		if !seatMayReceive(seat, fact.Classification, fact.Scope, fact.AllowedSeats) {
			continue
		}
		copy := fact
		copy.Value = canonical
		copy.AllowedSeats = sortSeatIDs(fact.AllowedSeats, baselineSeatIDs())
		authorized = append(authorized, copy)
	}
	sort.Slice(authorized, func(i, j int) bool { return authorized[i].FactID < authorized[j].FactID })
	identity := struct {
		RunID  string      `json:"run_id"`
		SeatID SeatID      `json:"seat_id"`
		Facts  []StateFact `json:"facts"`
	}{RunID: runID, SeatID: seat.SeatID, Facts: authorized}
	canonical, err := canonicalValue(identity)
	if err != nil {
		return AuthorizedView{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", err)
	}
	return AuthorizedView{RunID: runID, SeatID: seat.SeatID, Facts: authorized, SHA256: sha256Bytes(canonical)}, nil
}

func seatMayReceive(seat Seat, classification DataClassification, scope VisibilityScope, allowed []SeatID) bool {
	switch classification {
	case ClassLocalOnlySecret, ClassHumanPrivateData, ClassCredentialSecret, ClassSystemInternal:
		return false
	case ClassPublic, ClassUnreleasedRemoteAllowed, ClassTableHiddenRemoteAllowed:
	default:
		return false
	}
	switch scope {
	case ScopePublic:
		return true
	case ScopeGMOnly:
		return seat.Role == RoleGM && seat.SeatID == SeatGM
	case ScopeSeatPrivate:
		return containsSeat(allowed, seat.SeatID)
	case ScopeSystemInternal:
		return false
	default:
		return false
	}
}

func authorizeSources(runID string, seat Seat, requested []SourceDescriptor, maximum int) ([]AuthorizedSource, error) {
	const operation = "authorize_sources"
	if len(requested) > maximum {
		return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("source bound exceeded"))
	}
	seen := map[string]struct{}{}
	authorized := make([]AuthorizedSource, 0, len(requested))
	for _, source := range requested {
		if err := validIdentity("source_id", source.SourceID); err != nil || !validClassification(source.Classification) ||
			!validScope(source.Scope) || !validScopedSeatList(source.Scope, source.AllowedSeats) {
			return nil, orchestrationError(CodeVisibilityDenied, operation, runID, seat.SeatID, "", errors.New("unlabelled or invalid retrievable source"))
		}
		if err := validSHA256("source.expected_sha256", source.ExpectedSHA256); err != nil {
			return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", err)
		}
		if _, exists := seen[source.SourceID]; exists {
			return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate source identity"))
		}
		seen[source.SourceID] = struct{}{}
		if !seatMayReceive(seat, source.Classification, source.Scope, source.AllowedSeats) {
			return nil, orchestrationError(CodeVisibilityDenied, operation, runID, seat.SeatID, "", errors.New("requested source is not authorized"))
		}
		authorized = append(authorized, AuthorizedSource{
			SourceID: source.SourceID, Classification: source.Classification, ExpectedSHA256: source.ExpectedSHA256,
		})
	}
	sort.Slice(authorized, func(i, j int) bool { return authorized[i].SourceID < authorized[j].SourceID })
	return authorized, nil
}

func retrieveAuthorized(ctx context.Context, runID string, seat Seat, sources []AuthorizedSource, retriever Retriever) ([]RetrievedContent, error) {
	const operation = "retrieve_authorized"
	if len(sources) == 0 {
		return []RetrievedContent{}, nil
	}
	if retriever == nil {
		return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("Retriever is required"))
	}
	results, err := retriever.Retrieve(ctx, append([]AuthorizedSource(nil), sources...))
	if err != nil {
		return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", err)
	}
	if len(results) != len(sources) {
		return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("Retriever result set differs from authorized request"))
	}
	byID := make(map[string]AuthorizedSource, len(sources))
	for _, source := range sources {
		byID[source.SourceID] = source
	}
	seen := map[string]struct{}{}
	verified := make([]RetrievedContent, 0, len(results))
	for _, result := range results {
		source, exists := byID[result.SourceID]
		if !exists {
			return nil, orchestrationError(CodeVisibilityDenied, operation, runID, seat.SeatID, "", errors.New("Retriever returned an unauthorized source"))
		}
		if _, duplicate := seen[result.SourceID]; duplicate {
			return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate retrieved source"))
		}
		seen[result.SourceID] = struct{}{}
		if !utf8.ValidString(result.Content) || result.Classification != source.Classification || result.ContentSHA256 != sha256String(result.Content) ||
			result.ContentSHA256 != source.ExpectedSHA256 {
			return nil, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("retrieval citation/classification verification failed"))
		}
		verified = append(verified, result)
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].SourceID < verified[j].SourceID })
	return verified, nil
}

func authorizeEventWindow(runID string, seat Seat, items []EventWindowItem, maximum int) ([]EventWindowItem, string, error) {
	const operation = "authorize_event_window"
	if len(items) > maximum {
		return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("event window bound exceeded"))
	}
	seen := map[string]struct{}{}
	authorized := make([]EventWindowItem, 0, len(items))
	for _, item := range items {
		if err := validIdentity("event_window.event_id", item.EventID); err != nil || !validClassification(item.Classification) ||
			!validScope(item.Scope) || !validScopedSeatList(item.Scope, item.Recipients) || !utf8.ValidString(item.Content) ||
			len([]rune(item.Content)) > 20_000 {
			return nil, "", orchestrationError(CodeVisibilityDenied, operation, runID, seat.SeatID, "", errors.New("unlabelled event-window item"))
		}
		if _, exists := seen[item.EventID]; exists {
			return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate event-window identity"))
		}
		seen[item.EventID] = struct{}{}
		if item.ContentSHA256 != sha256String(item.Content) {
			return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("event-window content hash mismatch"))
		}
		if !seatMayReceive(seat, item.Classification, item.Scope, item.Recipients) {
			continue
		}
		copy := item
		copy.Recipients = sortSeatIDs(item.Recipients, baselineSeatIDs())
		authorized = append(authorized, copy)
	}
	sort.Slice(authorized, func(i, j int) bool { return authorized[i].EventID < authorized[j].EventID })
	canonical, err := canonicalValue(authorized)
	if err != nil {
		return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", err)
	}
	return authorized, "event-window:" + sha256Bytes(canonical), nil
}

func NewMemorySummary(summaryID, version, runID string, seatID SeatID, facts []SummaryFact, requiredFactIDs, sourceIDs []string) (MemorySummary, error) {
	summary := MemorySummary{
		SummaryID: summaryID, Version: version, RunID: runID, SeatID: seatID,
		Facts: append([]SummaryFact{}, facts...), RequiredFactIDs: append([]string{}, requiredFactIDs...),
		SourceIDs: append([]string{}, sourceIDs...),
	}
	sort.Slice(summary.Facts, func(i, j int) bool { return summary.Facts[i].FactID < summary.Facts[j].FactID })
	sort.Strings(summary.RequiredFactIDs)
	sort.Strings(summary.SourceIDs)
	identity := summary
	identity.SHA256 = ""
	canonical, err := canonicalValue(identity)
	if err != nil {
		return MemorySummary{}, err
	}
	summary.SHA256 = sha256Bytes(canonical)
	return summary, nil
}

func validatedSummary(runID string, seat Seat, summary MemorySummary, view AuthorizedView, retrieved []RetrievedContent) (MemorySummary, error) {
	const operation = "validate_memory_summary"
	if err := validIdentity("summary_id", summary.SummaryID); err != nil || validIdentity("summary.version", summary.Version) != nil ||
		summary.RunID != runID || summary.SeatID != seat.SeatID {
		return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary identity binding invalid"))
	}
	rebuilt, err := NewMemorySummary(summary.SummaryID, summary.Version, summary.RunID, summary.SeatID, summary.Facts, summary.RequiredFactIDs, summary.SourceIDs)
	if err != nil || rebuilt.SHA256 != summary.SHA256 {
		return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary canonical identity invalid"))
	}
	authorizedFacts := make(map[string]string, len(view.Facts))
	for _, fact := range view.Facts {
		authorizedFacts[fact.FactID] = fact.ValueSHA256
	}
	seenFacts := map[string]struct{}{}
	for _, fact := range summary.Facts {
		if err := validIdentity("summary.fact_id", fact.FactID); err != nil || validSHA256("summary.fact.value_sha256", fact.ValueSHA256) != nil {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary fact identity invalid"))
		}
		if _, exists := seenFacts[fact.FactID]; exists || authorizedFacts[fact.FactID] != fact.ValueSHA256 {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary fabricated, stale, or hidden fact"))
		}
		seenFacts[fact.FactID] = struct{}{}
	}
	seenRequired := map[string]struct{}{}
	for _, required := range rebuilt.RequiredFactIDs {
		if _, exists := seenRequired[required]; exists {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate required summary fact"))
		}
		seenRequired[required] = struct{}{}
		if _, authorized := authorizedFacts[required]; !authorized {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary requires a hidden or missing fact"))
		}
		if _, present := seenFacts[required]; !present {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary omitted a required persistent fact"))
		}
	}
	authorizedSources := make(map[string]struct{}, len(retrieved))
	for _, source := range retrieved {
		authorizedSources[source.SourceID] = struct{}{}
	}
	seenSources := map[string]struct{}{}
	for _, sourceID := range rebuilt.SourceIDs {
		if err := validIdentity("summary.source_id", sourceID); err != nil {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", err)
		}
		if _, exists := seenSources[sourceID]; exists {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate summary source"))
		}
		seenSources[sourceID] = struct{}{}
		if _, authorized := authorizedSources[sourceID]; !authorized {
			return MemorySummary{}, orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("summary references an unauthorized source"))
		}
	}
	return rebuilt, nil
}

func validateSummary(runID string, seat Seat, summary MemorySummary, view AuthorizedView, retrieved []RetrievedContent) error {
	_, err := validatedSummary(runID, seat, summary, view, retrieved)
	return err
}

func authorizeTools(runID string, seat Seat, tools []ToolDescriptor) ([]AvailableTool, string, error) {
	const operation = "authorize_tools"
	seen := map[string]struct{}{}
	available := make([]AvailableTool, 0, len(tools))
	for _, tool := range tools {
		if err := validIdentity("tool_id", tool.ToolID); err != nil || validIdentity("tool.version", tool.Version) != nil ||
			!validRoleList(tool.AllowedRoles) || !validSeatList(tool.AllowedSeats) {
			return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("invalid tool identity"))
		}
		if _, exists := seen[tool.ToolID]; exists {
			return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", errors.New("duplicate tool identity"))
		}
		seen[tool.ToolID] = struct{}{}
		roleAllowed := len(tool.AllowedRoles) == 0
		for _, role := range tool.AllowedRoles {
			if role == seat.Role {
				roleAllowed = true
			}
		}
		seatAllowed := len(tool.AllowedSeats) == 0 || containsSeat(tool.AllowedSeats, seat.SeatID)
		if roleAllowed && seatAllowed {
			available = append(available, AvailableTool{ToolID: tool.ToolID, Version: tool.Version})
		}
	}
	sort.Slice(available, func(i, j int) bool { return available[i].ToolID < available[j].ToolID })
	canonical, err := canonicalValue(available)
	if err != nil {
		return nil, "", orchestrationError(CodeContextInvariantFailed, operation, runID, seat.SeatID, "", err)
	}
	return available, "tool-capabilities:" + sha256Bytes(canonical), nil
}

func BuildContext(ctx context.Context, policy OrchestrationPolicy, seat Seat, personaState PersonaState, input ContextInput, retriever Retriever) (ContextBundle, error) {
	const operation = "build_context"
	if err := validatePolicy(policy); err != nil {
		return ContextBundle{}, orchestrationError(CodeInvalidPolicy, operation, seat.RunID, seat.SeatID, "", err)
	}
	if err := validatePersonaState(personaState); err != nil || personaState.RunID != seat.RunID ||
		personaState.SeatID != seat.SeatID || personaState.PersonaID != seat.Persona.PersonaID {
		return ContextBundle{}, orchestrationError(CodeContextInvariantFailed, operation, seat.RunID, seat.SeatID, "", errors.New("Persona state binding mismatch"))
	}
	view, err := BuildAuthorizedView(seat.RunID, seat, input.StateFacts)
	if err != nil {
		return ContextBundle{}, err
	}
	sources, err := authorizeSources(seat.RunID, seat, input.RequestedSources, policy.MaxContextSources)
	if err != nil {
		return ContextBundle{}, err
	}
	retrieved, err := retrieveAuthorized(ctx, seat.RunID, seat, sources, retriever)
	if err != nil {
		return ContextBundle{}, err
	}
	window, windowID, err := authorizeEventWindow(seat.RunID, seat, input.EventWindow, policy.MaxEventWindow)
	if err != nil {
		return ContextBundle{}, err
	}
	summary, err := validatedSummary(seat.RunID, seat, input.Summary, view, retrieved)
	if err != nil {
		return ContextBundle{}, err
	}
	tools, toolID, err := authorizeTools(seat.RunID, seat, input.Tools)
	if err != nil {
		return ContextBundle{}, err
	}
	characterID := ""
	if seat.Character != nil {
		characterID = seat.Character.CharacterID
	}
	bundle := ContextBundle{
		Schema: ContextSchema, ContextVersion: "v1", RunID: seat.RunID, SeatID: seat.SeatID,
		SessionID: seat.Session.SessionID, AuthorizedProjectionHash: view.SHA256,
		PersonaID: seat.Persona.PersonaID, CharacterID: characterID, EventWindowID: windowID,
		SummaryID: summary.SummaryID, ToolCapabilityID: toolID,
		Trusted: TrustedContext{
			RoleContractID: seat.RoleContractID, PolicyID: policy.PolicyID,
			Persona: clonePersona(seat.Persona), PersonaState: personaState,
			Character: cloneCharacter(seat.Character), GMProfile: seat.GMProfile, AvailableTools: tools,
		},
		Untrusted: UntrustedContext{
			AuthorizedState: view, EventWindow: window, MemorySummary: summary, Retrieved: retrieved,
		},
	}
	hash, err := contextHashFor(bundle)
	if err != nil {
		return ContextBundle{}, orchestrationError(CodeContextInvariantFailed, operation, seat.RunID, seat.SeatID, "", err)
	}
	bundle.ContextHash = hash
	return bundle, nil
}

func contextHashFor(bundle ContextBundle) (string, error) {
	hashInput := struct {
		Schema                   string           `json:"schema"`
		ContextVersion           string           `json:"context_version"`
		RunID                    string           `json:"run_id"`
		SeatID                   SeatID           `json:"seat_id"`
		SessionID                string           `json:"session_id"`
		AuthorizedProjectionHash string           `json:"authorized_projection_hash"`
		PersonaID                string           `json:"persona_id"`
		CharacterID              string           `json:"character_id,omitempty"`
		EventWindowID            string           `json:"event_window_id"`
		SummaryID                string           `json:"summary_id"`
		ToolCapabilityID         string           `json:"tool_capability_id"`
		Trusted                  TrustedContext   `json:"trusted"`
		Untrusted                UntrustedContext `json:"untrusted"`
	}{
		bundle.Schema, bundle.ContextVersion, bundle.RunID, bundle.SeatID, bundle.SessionID,
		bundle.AuthorizedProjectionHash, bundle.PersonaID, bundle.CharacterID, bundle.EventWindowID,
		bundle.SummaryID, bundle.ToolCapabilityID, bundle.Trusted, bundle.Untrusted,
	}
	canonical, err := canonicalValue(hashInput)
	if err != nil {
		return "", err
	}
	hash := sha256Bytes(canonical)
	if err := validSHA256("context_hash", hash); err != nil {
		return "", err
	}
	return hash, nil
}

func ValidateContextHash(bundle ContextBundle) error {
	if bundle.Schema != ContextSchema {
		return errors.New("unknown context schema")
	}
	hash := bundle.ContextHash
	computed, err := contextHashFor(bundle)
	if err != nil || computed != hash {
		return fmt.Errorf("context canonical hash mismatch")
	}
	return nil
}

func rebindContextSession(bundle ContextBundle, session Session) (ContextBundle, error) {
	if bundle.RunID != session.RunID || bundle.SeatID != session.SeatID {
		return ContextBundle{}, errors.New("context Session rebind changed Run or seat")
	}
	bundle.SessionID = session.SessionID
	hash, err := contextHashFor(bundle)
	if err != nil {
		return ContextBundle{}, err
	}
	bundle.ContextHash = hash
	return bundle, nil
}
