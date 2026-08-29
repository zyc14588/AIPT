package runcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

var (
	identityRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/\-]{0,127}$`)
	repositoryRE = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	gitOIDRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex64RE      = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

func validIdentity(field, value string) error {
	if !utf8.ValidString(value) || !identityRE.MatchString(value) {
		return fmt.Errorf("%s is not a bounded identity", field)
	}
	return nil
}

func validSHA256(field, value string) error {
	if !sha256RE.MatchString(value) {
		return fmt.Errorf("%s is not lowercase SHA-256", field)
	}
	return nil
}

func validateBinding(binding RunBinding) error {
	if binding.Schema != RunBindingSchema {
		return errors.New("unknown run binding schema")
	}
	if err := validIdentity("run_id", binding.RunID); err != nil {
		return err
	}
	artifacts := []struct {
		field string
		value ArtifactBinding
	}{
		{"manifest", binding.Manifest},
		{"runtime_adapter_input", binding.RuntimeAdapterInput},
	}
	for _, item := range artifacts {
		if err := validIdentity(item.field+".id", item.value.ID); err != nil {
			return err
		}
		if err := validIdentity(item.field+".schema", item.value.Schema); err != nil {
			return err
		}
		if err := validSHA256(item.field+".canonical_sha256", item.value.CanonicalSHA256); err != nil {
			return err
		}
	}
	source := binding.SourcePackage
	if err := validIdentity("source_package.package_id", source.PackageID); err != nil {
		return err
	}
	if err := validIdentity("source_package.schema", source.Schema); err != nil {
		return err
	}
	if !repositoryRE.MatchString(source.Repository) {
		return errors.New("source_package.repository must be owner/name")
	}
	if !gitOIDRE.MatchString(source.Commit) || !gitOIDRE.MatchString(source.Tree) {
		return errors.New("source_package commit/tree must be lowercase 40-hex")
	}
	return validSHA256("source_package.canonical_sha256", source.CanonicalSHA256)
}

func validateRuleSource(source RuleSource) error {
	if source.Kind != RuleSourceRuleID && source.Kind != RuleSourceExplicit {
		return errors.New("unknown rule source kind")
	}
	return validIdentity("source.reference", source.Reference)
}

func validateProposal(proposal ActionProposal) error {
	if proposal.Schema != ActionProposalSchema {
		return errors.New("unknown action proposal schema")
	}
	for _, item := range []struct{ field, value string }{
		{"action_id", proposal.ActionID},
		{"run_id", proposal.RunID},
		{"actor_id", proposal.ActorID},
		{"action_type", proposal.ActionType},
	} {
		if err := validIdentity(item.field, item.value); err != nil {
			return err
		}
	}
	if proposal.ExpectedSequence < 1 || proposal.ExpectedSequence >= maxSafeJSONInteger {
		return errors.New("expected_sequence is outside the safe positive range")
	}
	if _, err := canonicalRaw(proposal.Payload); err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	if ruling := proposal.TemporaryRuling; ruling != nil {
		for _, item := range []struct{ field, value string }{
			{"temporary_ruling.ruling_id", ruling.RulingID},
			{"temporary_ruling.scope", ruling.Scope},
		} {
			if err := validIdentity(item.field, item.value); err != nil {
				return err
			}
		}
		if strings.TrimSpace(ruling.Reason) == "" || !utf8.ValidString(ruling.Reason) || len([]rune(ruling.Reason)) > 500 {
			return errors.New("temporary ruling reason must be nonempty and bounded")
		}
		if ruling.ValidThroughSequence <= proposal.ExpectedSequence || ruling.ValidThroughSequence > maxSafeJSONInteger {
			return errors.New("temporary ruling validity boundary must be a future safe sequence")
		}
	}
	return nil
}

func validateRNGRequests(requests []RNGRequest) error {
	seenStreams := make(map[string]struct{}, len(requests))
	total := 0
	for _, request := range requests {
		if err := validIdentity("rng_requests.stream_id", request.StreamID); err != nil {
			return err
		}
		if _, exists := seenStreams[request.StreamID]; exists {
			return errors.New("duplicate RNG stream request")
		}
		seenStreams[request.StreamID] = struct{}{}
		if request.Count < 1 || request.Count > maxRNGDrawsPerAction {
			return errors.New("RNG request count is outside the bounded range")
		}
		total += request.Count
		if total > maxRNGDrawsPerAction {
			return errors.New("total RNG draw count exceeds the action bound")
		}
	}
	return nil
}

func validateState(state RunState) error {
	if state.Schema != RunStateSchema {
		return errors.New("unknown Run state schema")
	}
	if err := validateBinding(state.Binding); err != nil {
		return err
	}
	if state.Sequence < 1 || state.Sequence > maxSafeJSONInteger {
		return errors.New("state sequence is outside the safe positive range")
	}
	if state.RNGVersion != RNGVersionV1 || state.CommitmentVersion != SeedCommitmentV1 {
		return errors.New("unknown RNG or commitment version")
	}
	if err := validSHA256("seed_commitment", state.SeedCommitment); err != nil {
		return err
	}
	canonical, err := canonicalRaw(state.DomainState)
	if err != nil || !bytes.Equal(canonical, state.DomainState) {
		return errors.New("domain state must be canonical JSON")
	}
	if len(state.RNGCursors) > maxRNGDrawsPerAction {
		return errors.New("RNG cursor stream count exceeds the Run bound")
	}
	for streamID, cursor := range state.RNGCursors {
		if err := validIdentity("rng_cursors stream", streamID); err != nil {
			return err
		}
		if cursor < 1 || cursor > maxSafeJSONInteger {
			return errors.New("RNG cursor is outside the safe positive range")
		}
	}
	return nil
}

func validateDraw(draw RNGDraw) error {
	if draw.Version != RNGVersionV1 {
		return errors.New("unknown RNG version")
	}
	if err := validIdentity("rng draw stream_id", draw.StreamID); err != nil {
		return err
	}
	if draw.DrawIndex < 1 || draw.DrawIndex > maxSafeJSONInteger || !hex64RE.MatchString(draw.ValueHex) {
		return errors.New("invalid RNG draw evidence")
	}
	return nil
}

func decodeProposal(raw []byte) (ActionProposal, []byte, error) {
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return ActionProposal{}, nil, err
	}
	var proposal ActionProposal
	decoder := json.NewDecoder(bytes.NewReader([]byte(canonical)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proposal); err != nil {
		return ActionProposal{}, nil, err
	}
	if err := validateProposal(proposal); err != nil {
		return ActionProposal{}, nil, err
	}
	payload, err := canonicalRaw(proposal.Payload)
	if err != nil {
		return ActionProposal{}, nil, err
	}
	proposal.Payload = payload
	normalized, err := canonicalValue(proposal)
	if err != nil {
		return ActionProposal{}, nil, err
	}
	return proposal, normalized, nil
}

func canonicalRaw(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing JSON value")
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func canonicalValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func stateHash(state RunState) (string, error) {
	canonical, err := canonicalValue(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func cloneState(state RunState) RunState {
	copy := state
	copy.DomainState = append(json.RawMessage(nil), state.DomainState...)
	copy.RNGCursors = make(map[string]int64, len(state.RNGCursors))
	for key, value := range state.RNGCursors {
		copy.RNGCursors[key] = value
	}
	return copy
}

func equalCanonical(left, right any) bool {
	l, err := canonicalValue(left)
	if err != nil {
		return false
	}
	r, err := canonicalValue(right)
	return err == nil && bytes.Equal(l, r)
}

func decodedHex(value string) ([]byte, error) {
	if !sha256RE.MatchString(value) {
		return nil, errors.New("invalid SHA-256")
	}
	return hex.DecodeString(value)
}
