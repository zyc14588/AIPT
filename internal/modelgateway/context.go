package modelgateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

const PreparedContextSchema = "aipt.prepared-context/v1"

const maxPreparedContextElementsV1 = 10_000

type preparedContext struct {
	Schema              string                          `json:"schema"`
	OriginalContextHash string                          `json:"original_context_hash"`
	RunID               string                          `json:"run_id"`
	SeatID              orchestrator.SeatID             `json:"seat_id"`
	SessionID           string                          `json:"session_id"`
	Trusted             orchestrator.TrustedContext     `json:"trusted"`
	AuthorizedState     orchestrator.AuthorizedView     `json:"authorized_state"`
	MemorySummary       orchestrator.MemorySummary      `json:"memory_summary"`
	EventWindow         []orchestrator.EventWindowItem  `json:"event_window"`
	Retrieved           []orchestrator.RetrievedContent `json:"retrieved"`
}

func clonePrepared(bundle orchestrator.ContextBundle) preparedContext {
	prepared := preparedContext{
		Schema: PreparedContextSchema, OriginalContextHash: bundle.ContextHash,
		RunID: bundle.RunID, SeatID: bundle.SeatID, SessionID: bundle.SessionID,
		Trusted: bundle.Trusted, AuthorizedState: bundle.Untrusted.AuthorizedState,
		MemorySummary: bundle.Untrusted.MemorySummary,
		EventWindow:   cloneSlice(bundle.Untrusted.EventWindow),
		Retrieved:     cloneSlice(bundle.Untrusted.Retrieved),
	}
	prepared.Trusted.AvailableTools = cloneSlice(bundle.Trusted.AvailableTools)
	prepared.AuthorizedState.Facts = cloneSlice(bundle.Untrusted.AuthorizedState.Facts)
	prepared.MemorySummary.Facts = cloneSlice(bundle.Untrusted.MemorySummary.Facts)
	prepared.MemorySummary.RequiredFactIDs = cloneSlice(bundle.Untrusted.MemorySummary.RequiredFactIDs)
	prepared.MemorySummary.SourceIDs = cloneSlice(bundle.Untrusted.MemorySummary.SourceIDs)
	return prepared
}

func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append(make([]T, 0, len(values)), values...)
}

type EgressDecision struct {
	CleanBaselineEligible bool
	BreakGlassRequired    bool
}

// ValidateEgress is the adapter-side half of dual enforcement. B003 has
// already produced a seat-authorized Context Bundle; this check never reaches
// back into full state and cannot widen visibility.
func ValidateEgress(profile ModelProfile, bundle orchestrator.ContextBundle) (EgressDecision, error) {
	if err := ValidateModelProfile(profile); err != nil {
		return EgressDecision{}, err
	}
	if err := orchestrator.ValidateContextHash(bundle); err != nil {
		return EgressDecision{}, newError(CodeEgressDenied, "validate_context_hash", profile.BindingID(), err)
	}
	allowed := make(map[orchestrator.DataClassification]bool, len(profile.DataEgressPolicy.AllowedClassifications))
	for _, classification := range profile.DataEgressPolicy.AllowedClassifications {
		allowed[classification] = true
	}
	decision := EgressDecision{CleanBaselineEligible: true}
	check := func(classification orchestrator.DataClassification) error {
		if classification == orchestrator.ClassCredentialSecret || classification == orchestrator.ClassHumanPrivateData {
			return errors.New("strict secret classification denied")
		}
		if profile.BackendKind == BackendRemoteDeepSeek && classification == orchestrator.ClassLocalOnlySecret {
			if !profile.DataEgressPolicy.BreakGlassAllowed {
				return errors.New("LOCAL_ONLY_SECRET denied on remote route")
			}
			decision.CleanBaselineEligible = false
			decision.BreakGlassRequired = true
			return nil
		}
		if !allowed[classification] {
			return errors.New("classification absent from profile allowlist")
		}
		return nil
	}
	for _, fact := range bundle.Untrusted.AuthorizedState.Facts {
		if err := check(fact.Classification); err != nil {
			return EgressDecision{}, newError(CodeEgressDenied, "authorize_state_egress", profile.BindingID(), err)
		}
	}
	for _, event := range bundle.Untrusted.EventWindow {
		if err := check(event.Classification); err != nil {
			return EgressDecision{}, newError(CodeEgressDenied, "authorize_event_egress", profile.BindingID(), err)
		}
	}
	for _, content := range bundle.Untrusted.Retrieved {
		if err := check(content.Classification); err != nil {
			return EgressDecision{}, newError(CodeEgressDenied, "authorize_retrieval_egress", profile.BindingID(), err)
		}
	}
	return decision, nil
}

// PrepareContext applies AIPT_CONTEXT_BUDGET_REDUCE_V1. It preserves every
// trusted identity, authoritative state fact, summary invariant, and tool
// authorization. Only retrieved documents (from the end) and then oldest
// event-window entries are removed until the byte bound fits.
func PrepareContext(bundle orchestrator.ContextBundle, policy ContextPolicy) ([]byte, ContextReduction, error) {
	if !boundedPreparedContextInput(bundle, policy.MaxRequestBytes) {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context_preflight", bundle.ContextHash, errors.New("context input exceeds the bounded preparation budget"))
	}
	if err := orchestrator.ValidateContextHash(bundle); err != nil {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, err)
	}
	if policy.ReductionPolicyID != "AIPT_CONTEXT_BUDGET_REDUCE_V1" || policy.MaxContextBytes < 1024 {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, errors.New("unknown reduction policy"))
	}
	prepared := clonePrepared(bundle)
	original, err := json.Marshal(prepared)
	if err != nil {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, err)
	}
	if len(original) > policy.MaxRequestBytes {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, errors.New("serialized context exceeds max_request_bytes"))
	}
	reduction := ContextReduction{
		Schema: ContextReductionSchema, PolicyID: policy.ReductionPolicyID,
		OriginalContextHash: bundle.ContextHash, OriginalBytes: len(original),
	}
	encoded := original
	if len(encoded) > policy.MaxContextBytes {
		allRetrieved := prepared.Retrieved
		prepared.Retrieved = nil
		withoutRetrieved, marshalErr := json.Marshal(prepared)
		if marshalErr != nil {
			return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, marshalErr)
		}
		if len(withoutRetrieved) <= policy.MaxContextBytes {
			encoded = withoutRetrieved
			low, high := 0, len(allRetrieved)
			for low < high {
				mid := low + (high-low+1)/2
				prepared.Retrieved = allRetrieved[:mid]
				candidate, marshalErr := json.Marshal(prepared)
				if marshalErr != nil {
					return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, marshalErr)
				}
				if len(candidate) <= policy.MaxContextBytes {
					low = mid
					encoded = candidate
				} else {
					high = mid - 1
				}
			}
			prepared.Retrieved = allRetrieved[:low]
			for index := len(allRetrieved) - 1; index >= low; index-- {
				reduction.RemovedSourceIDs = append(reduction.RemovedSourceIDs, allRetrieved[index].SourceID)
			}
		} else {
			prepared.Retrieved = nil
			encoded = withoutRetrieved
			for index := len(allRetrieved) - 1; index >= 0; index-- {
				reduction.RemovedSourceIDs = append(reduction.RemovedSourceIDs, allRetrieved[index].SourceID)
			}
		}
	}
	if len(encoded) > policy.MaxContextBytes && len(prepared.EventWindow) > 0 {
		allEvents := prepared.EventWindow
		low, high := 0, len(allEvents)
		for low < high {
			mid := low + (high-low)/2
			prepared.EventWindow = allEvents[mid:]
			candidate, marshalErr := json.Marshal(prepared)
			if marshalErr != nil {
				return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, marshalErr)
			}
			if len(candidate) <= policy.MaxContextBytes {
				high = mid
				encoded = candidate
			} else {
				low = mid + 1
			}
		}
		prepared.EventWindow = allEvents[low:]
		for index := 0; index < low; index++ {
			reduction.RemovedEventIDs = append(reduction.RemovedEventIDs, allEvents[index].EventID)
		}
		encoded, err = json.Marshal(prepared)
		if err != nil {
			return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, err)
		}
	}
	if len(encoded) > policy.MaxContextBytes {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, errors.New("required context exceeds bound"))
	}
	if err := verifyPreparedSubset(bundle, prepared); err != nil {
		return nil, ContextReduction{}, newError(CodeContextBudgetExceeded, "prepare_context", bundle.ContextHash, err)
	}
	digest := sha256.Sum256(encoded)
	reduction.PreparedContextSHA256 = hex.EncodeToString(digest[:])
	reduction.PreparedBytes = len(encoded)
	return encoded, reduction, nil
}

func boundedPreparedContextInput(bundle orchestrator.ContextBundle, maximum int) bool {
	if maximum < 1024 || maximum > 16<<20 {
		return false
	}
	bytes := 0
	elements := 0
	add := func(size int) bool {
		if size < 0 || size > maximum-bytes {
			return false
		}
		bytes += size
		return true
	}
	stack := []reflect.Value{reflect.ValueOf(bundle)}
	for len(stack) > 0 {
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
			if value.IsNil() {
				value = reflect.Value{}
				break
			}
			value = value.Elem()
		}
		if !value.IsValid() {
			continue
		}
		elements++
		if elements > maxPreparedContextElementsV1 {
			return false
		}
		switch value.Kind() {
		case reflect.String:
			if !add(value.Len()) {
				return false
			}
		case reflect.Slice:
			if value.Type().Elem().Kind() == reflect.Uint8 {
				if !add(value.Len()) {
					return false
				}
				continue
			}
			if value.Len() > maxPreparedContextElementsV1-elements {
				return false
			}
			for index := 0; index < value.Len(); index++ {
				stack = append(stack, value.Index(index))
			}
		case reflect.Array:
			for index := 0; index < value.Len(); index++ {
				stack = append(stack, value.Index(index))
			}
		case reflect.Struct:
			for index := 0; index < value.NumField(); index++ {
				stack = append(stack, value.Field(index))
			}
		case reflect.Map:
			if value.Len() > maxPreparedContextElementsV1-elements {
				return false
			}
			iterator := value.MapRange()
			for iterator.Next() {
				stack = append(stack, iterator.Key(), iterator.Value())
			}
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			if !add(32) {
				return false
			}
		}
	}
	return true
}

func verifyPreparedSubset(bundle orchestrator.ContextBundle, prepared preparedContext) error {
	if prepared.OriginalContextHash != bundle.ContextHash || prepared.RunID != bundle.RunID ||
		prepared.SeatID != bundle.SeatID || prepared.SessionID != bundle.SessionID {
		return errors.New("prepared context identity drift")
	}
	criticalOriginal := struct {
		Trusted         orchestrator.TrustedContext
		AuthorizedState orchestrator.AuthorizedView
		MemorySummary   orchestrator.MemorySummary
	}{bundle.Trusted, bundle.Untrusted.AuthorizedState, bundle.Untrusted.MemorySummary}
	criticalPrepared := struct {
		Trusted         orchestrator.TrustedContext
		AuthorizedState orchestrator.AuthorizedView
		MemorySummary   orchestrator.MemorySummary
	}{prepared.Trusted, prepared.AuthorizedState, prepared.MemorySummary}
	left, _ := canonicalDigest(criticalOriginal)
	right, _ := canonicalDigest(criticalPrepared)
	if left != right {
		return errors.New("critical context changed during reduction")
	}
	events := map[string]string{}
	for _, event := range bundle.Untrusted.EventWindow {
		digest, _ := canonicalDigest(event)
		events[event.EventID] = digest
	}
	for _, event := range prepared.EventWindow {
		digest, _ := canonicalDigest(event)
		if events[event.EventID] != digest {
			return errors.New("event data was added or changed during reduction")
		}
	}
	sources := map[string]string{}
	for _, source := range bundle.Untrusted.Retrieved {
		digest, _ := canonicalDigest(source)
		sources[source.SourceID] = digest
	}
	for _, source := range prepared.Retrieved {
		digest, _ := canonicalDigest(source)
		if sources[source.SourceID] != digest {
			return errors.New("retrieved data was added or changed during reduction")
		}
	}
	return nil
}

func sortedClassifications(values []orchestrator.DataClassification) []orchestrator.DataClassification {
	copy := append([]orchestrator.DataClassification(nil), values...)
	sort.Slice(copy, func(i, j int) bool { return copy[i] < copy[j] })
	return copy
}
