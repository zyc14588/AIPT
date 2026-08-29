package runcore

import "encoding/json"

type projectionEnvelope struct {
	Schema      string          `json:"schema"`
	RunID       string          `json:"run_id"`
	ManifestID  string          `json:"manifest_id"`
	Sequence    int64           `json:"sequence"`
	StateSHA256 string          `json:"state_sha256"`
	DomainState json.RawMessage `json:"domain_state"`
}

// Project deterministically derives a non-authoritative canonical view. The
// projection has no mutation method, no seed field, no database table, and no
// effect on the ledger or Run state.
func Project(state RunState) (Projection, error) {
	if err := validateState(state); err != nil {
		return Projection{}, err
	}
	hash, err := stateHash(state)
	if err != nil {
		return Projection{}, err
	}
	canonical, err := canonicalValue(projectionEnvelope{
		Schema: RunProjectionSchema, RunID: state.Binding.RunID,
		ManifestID: state.Binding.Manifest.ID, Sequence: state.Sequence,
		StateSHA256: hash, DomainState: append(json.RawMessage(nil), state.DomainState...),
	})
	if err != nil {
		return Projection{}, err
	}
	return Projection{Canonical: canonical, SHA256: hashBytes(canonical)}, nil
}
