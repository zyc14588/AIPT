package pilot

import (
	"encoding/json"
	"regexp"
	"slices"
)

var task0PollutionFactID = regexp.MustCompile(`^T0-NOTE-[1-9][0-9]?$`)

// Select a source registry entry only for an existing SEEN fact that can be
// verified by the accepted Game contract. This does not change the full state,
// actor note text, source registry, or optional authorized world reference.
func task0NeededKnowledgeFact(raw json.RawMessage, id string) (json.RawMessage, error) {
	if id == "" {
		return nil, ErrTask0
	}
	var facts map[string]json.RawMessage
	if json.Unmarshal(raw, &facts) != nil || facts == nil {
		return nil, ErrTask0
	}
	if value, ok := facts[id]; ok {
		if len(value) < 2 || task0Null(value) {
			return nil, ErrTask0
		}
		return slices.Clone(value), nil
	}
	if task0PollutionFactID.MatchString(id) {
		return nil, nil
	}
	return nil, ErrTask0
}
