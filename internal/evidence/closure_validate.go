package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	ErrAuditReadyInvalid   = errors.New("AIPT_AUDIT_READY_INVALID")
	ErrSourceUnverified    = errors.New("AIPT_SOURCE_IDENTITY_UNVERIFIED")
	ErrReplayMismatch      = errors.New("AIPT_REPLAY_FINAL_STATE_MISMATCH")
	ErrDefectInvalid       = errors.New("AIPT_DEFECT_CONTRACT_INVALID")
	ErrReportInvalid       = errors.New("AIPT_REPORT_CONTRACT_INVALID")
	ErrReportTransition    = errors.New("AIPT_REPORT_TRANSITION_INVALID")
	ErrEncryptionRequired  = errors.New("ENCRYPTION_REQUIRED_BUT_UNAVAILABLE")
	ErrDisclosureViolation = errors.New("AIPT_DISCLOSURE_POLICY_VIOLATION")
	ErrChunkInvalid        = errors.New("AIPT_CONTENT_CHUNK_INVALID")
)

const (
	maxContractItems      = 10_000
	maxActionReceipts     = 100_000
	maxGateFacts          = 1_000
	maxDefectStates       = 256
	maxDefectTransitions  = 4_096
	maxLifecycleRevisions = 100_000
	maxCoverageItems      = 1_000_000
)

var (
	contractIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,255}$`)
	logicalPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`)
	mediaTypePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$`)
)

func validContractIdentifier(field, value string) error {
	if !utf8.ValidString(value) || !contractIdentifier.MatchString(value) || strings.Contains(value, "//") ||
		strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.Contains(value, "../") || value == ".." {
		return fmt.Errorf("%s must be a stable identifier", field)
	}
	return nil
}

func validLogicalPath(field, value string) error {
	if !utf8.ValidString(value) || !logicalPathPattern.MatchString(value) || strings.Contains(value, "//") ||
		strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.Contains(value, "../") || value == ".." ||
		strings.ContainsRune(value, '\\') || strings.ContainsRune(value, 0) {
		return fmt.Errorf("%s is not a portable relative path", field)
	}
	return nil
}

func validSHA(field, value string) error {
	if !lowerSHA256.MatchString(value) {
		return fmt.Errorf("%s must be lowercase SHA-256", field)
	}
	return nil
}

func validateArtifactIdentity(field string, identity ArtifactIdentity) error {
	if err := validContractIdentifier(field+".id", identity.ID); err != nil {
		return err
	}
	if err := validContractIdentifier(field+".schema", identity.Schema); err != nil {
		return err
	}
	return validSHA(field+".canonical_sha256", identity.CanonicalSHA256)
}

func normalizeStringSet(field string, values []string, allowEmpty bool) ([]string, error) {
	if (!allowEmpty && len(values) == 0) || len(values) > maxContractItems {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	out := append([]string(nil), values...)
	for index, value := range out {
		if err := validContractIdentifier(fmt.Sprintf("%s[%d]", field, index), value); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	for index := 1; index < len(out); index++ {
		if out[index] == out[index-1] {
			return nil, fmt.Errorf("%s contains a duplicate", field)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

func normalizeEvidenceReferences(field string, references []EvidenceReference, allowEmpty bool) ([]EvidenceReference, error) {
	if (!allowEmpty && len(references) == 0) || len(references) > maxContractItems {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	out := append([]EvidenceReference(nil), references...)
	for index, reference := range out {
		prefix := fmt.Sprintf("%s[%d]", field, index)
		if err := validContractIdentifier(prefix+".id", reference.ID); err != nil {
			return nil, err
		}
		if err := validLogicalPath(prefix+".path", reference.Path); err != nil {
			return nil, err
		}
		if err := validSHA(prefix+".sha256", reference.SHA256); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Path < out[j].Path
	})
	ids := map[string]struct{}{}
	paths := map[string]struct{}{}
	for _, reference := range out {
		if _, exists := ids[reference.ID]; exists {
			return nil, fmt.Errorf("%s contains a duplicate id", field)
		}
		if _, exists := paths[reference.Path]; exists {
			return nil, fmt.Errorf("%s contains a duplicate path", field)
		}
		ids[reference.ID] = struct{}{}
		paths[reference.Path] = struct{}{}
	}
	if out == nil {
		out = []EvidenceReference{}
	}
	return out, nil
}

func validateRNG(field string, evidence RNGEvidence) error {
	if evidence.Used {
		if err := validContractIdentifier(field+".version", evidence.Version); err != nil {
			return err
		}
		if err := validSHA(field+".seed_commitment", evidence.SeedCommitment); err != nil {
			return err
		}
		if evidence.SeedDisclosureStatus != "COMMITTED_NOT_DISCLOSED" && evidence.SeedDisclosureStatus != "DISCLOSED_AS_EVIDENCE" {
			return fmt.Errorf("%s.seed_disclosure_status is invalid", field)
		}
		return nil
	}
	if evidence.Version != "NONE" || evidence.SeedCommitment != "" || evidence.SeedDisclosureStatus != "NOT_APPLICABLE" {
		return fmt.Errorf("%s must use the exact no-RNG representation", field)
	}
	return nil
}

func normalizeReplay(replay ReplayEvidence) (ReplayEvidence, error) {
	if replay.Schema != ReplayEvidenceSchema || replay.Version != ContractVersion {
		return ReplayEvidence{}, errors.New("replay schema/version is invalid")
	}
	if err := validContractIdentifier("replay.run_id", replay.RunID); err != nil {
		return ReplayEvidence{}, err
	}
	if err := validSHA("replay.run_manifest_sha256", replay.RunManifestSHA256); err != nil {
		return ReplayEvidence{}, err
	}
	if err := validateLedgerText("replay.ledger_stream_id", replay.LedgerStreamID); err != nil {
		return ReplayEvidence{}, err
	}
	if replay.LedgerTailSequence < 0 {
		return ReplayEvidence{}, errors.New("replay ledger tail sequence is negative")
	}
	if replay.LedgerTailSequence == 0 {
		if replay.LedgerTailHash != nil {
			return ReplayEvidence{}, errors.New("empty replay ledger has a tail hash")
		}
	} else if replay.LedgerTailHash == nil || validSHA("replay.ledger_tail_hash", *replay.LedgerTailHash) != nil {
		return ReplayEvidence{}, errors.New("nonempty replay ledger tail hash is invalid")
	}
	if err := validSHA("replay.live_final_state_hash", replay.LiveFinalStateHash); err != nil {
		return ReplayEvidence{}, err
	}
	if err := validSHA("replay.replayed_final_state_hash", replay.ReplayedFinalStateHash); err != nil {
		return ReplayEvidence{}, err
	}
	if !replay.HashMatch || replay.LiveFinalStateHash != replay.ReplayedFinalStateHash {
		return ReplayEvidence{}, ErrReplayMismatch
	}
	if err := validContractIdentifier("replay.implementation.id", replay.Implementation.ID); err != nil {
		return ReplayEvidence{}, err
	}
	if err := validContractIdentifier("replay.implementation.version", replay.Implementation.Version); err != nil {
		return ReplayEvidence{}, err
	}
	if err := validSHA("replay.implementation.sha256", replay.Implementation.SHA256); err != nil {
		return ReplayEvidence{}, err
	}
	if err := validateRNG("replay.rng", replay.RNG); err != nil {
		return ReplayEvidence{}, err
	}
	return replay, nil
}

func normalizeGateFacts(field string, facts []GateEligibilityFact, allowEmpty bool) ([]GateEligibilityFact, error) {
	if (!allowEmpty && len(facts) == 0) || len(facts) > maxGateFacts {
		return nil, fmt.Errorf("%s must not be empty", field)
	}
	out := append([]GateEligibilityFact(nil), facts...)
	for index, fact := range out {
		if err := validContractIdentifier(fmt.Sprintf("%s[%d].gate", field, index), fact.Gate); err != nil {
			return nil, err
		}
		if err := validContractIdentifier(fmt.Sprintf("%s[%d].reason_code", field, index), fact.ReasonCode); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Gate < out[j].Gate })
	for index := 1; index < len(out); index++ {
		if out[index].Gate == out[index-1].Gate {
			return nil, fmt.Errorf("%s contains a duplicate gate", field)
		}
	}
	if out == nil {
		out = []GateEligibilityFact{}
	}
	return out, nil
}

func NormalizeRunEvidenceClosure(closure RunEvidenceClosure) (RunEvidenceClosure, error) {
	if closure.Schema != RunClosureSchema || closure.Version != ContractVersion {
		return RunEvidenceClosure{}, fmt.Errorf("%w: schema/version", ErrAuditReadyInvalid)
	}
	if err := validContractIdentifier("run_id", closure.RunID); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: %v", ErrAuditReadyInvalid, err)
	}
	if err := validateArtifactIdentity("run_manifest", closure.RunManifest); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: %v", ErrAuditReadyInvalid, err)
	}
	if err := validateAuditReadySourceIdentity(closure.Source); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: source", ErrAuditReadyInvalid)
	}
	if closure.StateAuthority != "POSTGRESQL_APPEND_ONLY_HASH_CHAIN" {
		return RunEvidenceClosure{}, fmt.Errorf("%w: state authority", ErrAuditReadyInvalid)
	}
	if err := validateLedgerText("ledger.stream_id", closure.Ledger.StreamID); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: ledger", ErrAuditReadyInvalid)
	}
	if closure.Ledger.EventCount < 0 || closure.Ledger.EventCount > maxRawCaptureEventCount || closure.Ledger.TailSequence != closure.Ledger.EventCount {
		return RunEvidenceClosure{}, fmt.Errorf("%w: ledger count/tail", ErrAuditReadyInvalid)
	}
	if closure.Ledger.EventCount == 0 {
		if closure.Ledger.TailEventHash != nil {
			return RunEvidenceClosure{}, fmt.Errorf("%w: empty ledger tail", ErrAuditReadyInvalid)
		}
	} else if closure.Ledger.TailEventHash == nil || validSHA("ledger.tail_event_hash", *closure.Ledger.TailEventHash) != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: ledger tail hash", ErrAuditReadyInvalid)
	}
	receipts := append([]ActionReceiptEvidence(nil), closure.ActionReceipts...)
	if len(receipts) == 0 || len(receipts) > maxActionReceipts || int64(len(receipts)) != closure.Ledger.EventCount {
		return RunEvidenceClosure{}, fmt.Errorf("%w: action receipts must cover the complete ledger", ErrAuditReadyInvalid)
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].Sequence != receipts[j].Sequence {
			return receipts[i].Sequence < receipts[j].Sequence
		}
		return receipts[i].ActionID < receipts[j].ActionID
	})
	seenActions := map[string]struct{}{}
	for index, receipt := range receipts {
		prefix := fmt.Sprintf("action_receipts[%d]", index)
		if err := validContractIdentifier(prefix+".action_id", receipt.ActionID); err != nil || receipt.Sequence != int64(index+1) {
			return RunEvidenceClosure{}, fmt.Errorf("%w: invalid action receipt identity", ErrAuditReadyInvalid)
		}
		if _, exists := seenActions[receipt.ActionID]; exists {
			return RunEvidenceClosure{}, fmt.Errorf("%w: duplicate action receipt", ErrAuditReadyInvalid)
		}
		seenActions[receipt.ActionID] = struct{}{}
		for name, value := range map[string]string{"event_hash": receipt.EventHash, "state_hash": receipt.StateHash, "projection_hash": receipt.ProjectionHash} {
			if err := validSHA(prefix+"."+name, value); err != nil {
				return RunEvidenceClosure{}, fmt.Errorf("%w: action receipt hash", ErrAuditReadyInvalid)
			}
		}
		if _, err := normalizeEvidenceReferences(prefix+".evidence", []EvidenceReference{receipt.Evidence}, false); err != nil {
			return RunEvidenceClosure{}, fmt.Errorf("%w: action receipt evidence", ErrAuditReadyInvalid)
		}
	}
	closure.ActionReceipts = receipts
	if err := validContractIdentifier("projection.schema", closure.Projection.Schema); err != nil ||
		validSHA("projection.canonical_sha256", closure.Projection.CanonicalSHA256) != nil ||
		validSHA("projection.final_state_hash", closure.Projection.FinalStateHash) != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: projection", ErrAuditReadyInvalid)
	}
	finalReceipt := receipts[len(receipts)-1]
	if finalReceipt.StateHash != closure.Projection.FinalStateHash || finalReceipt.ProjectionHash != closure.Projection.CanonicalSHA256 {
		return RunEvidenceClosure{}, fmt.Errorf("%w: final action receipt projection binding", ErrAuditReadyInvalid)
	}
	rules := append([]RuleCitation(nil), closure.RuleCitations...)
	if len(rules) == 0 || len(rules) > maxContractItems {
		return RunEvidenceClosure{}, fmt.Errorf("%w: missing rule citations", ErrAuditReadyInvalid)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].RuleID < rules[j].RuleID })
	for index, citation := range rules {
		if err := validContractIdentifier(fmt.Sprintf("rule_citations[%d].rule_id", index), citation.RuleID); err != nil ||
			validSHA("rule source", citation.SourceSHA256) != nil || (index > 0 && citation.RuleID == rules[index-1].RuleID) {
			return RunEvidenceClosure{}, fmt.Errorf("%w: rule citation", ErrAuditReadyInvalid)
		}
	}
	closure.RuleCitations = rules
	if err := validateRNG("rng", closure.RNG); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: rng", ErrAuditReadyInvalid)
	}
	replay, err := normalizeReplay(closure.Replay)
	if err != nil {
		return RunEvidenceClosure{}, err
	}
	closure.Replay = replay
	if replay.RunID != closure.RunID || replay.RunManifestSHA256 != closure.RunManifest.CanonicalSHA256 ||
		replay.LedgerStreamID != closure.Ledger.StreamID || replay.LedgerTailSequence != closure.Ledger.TailSequence ||
		!equalStringPointers(replay.LedgerTailHash, closure.Ledger.TailEventHash) ||
		replay.LiveFinalStateHash != closure.Projection.FinalStateHash || !equalRNG(replay.RNG, closure.RNG) {
		return RunEvidenceClosure{}, fmt.Errorf("%w: replay binding", ErrAuditReadyInvalid)
	}
	closure.CoverageReferences, err = normalizeEvidenceReferences("coverage_references", closure.CoverageReferences, false)
	if err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: coverage references", ErrAuditReadyInvalid)
	}
	if closure.DefectOccurrenceIDs, err = normalizeStringSet("defect_occurrence_ids", closure.DefectOccurrenceIDs, true); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: defect occurrences", ErrAuditReadyInvalid)
	}
	if closure.AnomalyCodes, err = normalizeStringSet("anomaly_codes", closure.AnomalyCodes, true); err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: anomalies", ErrAuditReadyInvalid)
	}
	closure.GateEligibilityFacts, err = normalizeGateFacts("gate_eligibility_facts", closure.GateEligibilityFacts, false)
	if err != nil {
		return RunEvidenceClosure{}, fmt.Errorf("%w: gate facts", ErrAuditReadyInvalid)
	}
	models := append([]ModelExecutionReference(nil), closure.ModelExecutionReferences...)
	if len(models) > maxContractItems {
		return RunEvidenceClosure{}, fmt.Errorf("%w: model execution reference count", ErrAuditReadyInvalid)
	}
	sort.Slice(models, func(i, j int) bool { return models[i].ExecutionID < models[j].ExecutionID })
	for index, model := range models {
		if err := validContractIdentifier(fmt.Sprintf("model_execution_references[%d].execution_id", index), model.ExecutionID); err != nil ||
			validContractIdentifier("model profile", model.ModelProfile) != nil ||
			validContractIdentifier("harness identity", model.HarnessIdentity) != nil ||
			validSHA("model evidence", model.EvidenceSHA256) != nil ||
			(index > 0 && model.ExecutionID == models[index-1].ExecutionID) {
			return RunEvidenceClosure{}, fmt.Errorf("%w: model execution reference", ErrAuditReadyInvalid)
		}
	}
	if models == nil {
		models = []ModelExecutionReference{}
	}
	closure.ModelExecutionReferences = models
	return closure, nil
}

func equalStringPointers(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func equalRNG(left, right RNGEvidence) bool { return left == right }

func validRootCause(domain RootCauseDomain) bool {
	switch domain {
	case RootCauseRuleProse, RootCauseMachineRule, RootCauseModule, RootCauseAdapter, RootCauseAIPT, RootCauseModel:
		return true
	default:
		return false
	}
}

func normalizeFingerprintProjection(projection DefectFingerprintProjection) (DefectFingerprintProjection, error) {
	if projection.Version != DefectFingerprintVersion || !validRootCause(projection.RootCauseDomain) {
		return DefectFingerprintProjection{}, errors.New("fingerprint version or root cause is invalid")
	}
	if err := validContractIdentifier("semantic_key", projection.SemanticKey); err != nil {
		return DefectFingerprintProjection{}, err
	}
	var err error
	projection.RuleIDs, err = normalizeStringSet("rule_ids", projection.RuleIDs, true)
	if err != nil {
		return DefectFingerprintProjection{}, err
	}
	projection.InvariantIDs, err = normalizeStringSet("invariant_ids", projection.InvariantIDs, true)
	if err != nil {
		return DefectFingerprintProjection{}, err
	}
	if len(projection.RuleIDs) == 0 && len(projection.InvariantIDs) == 0 {
		return DefectFingerprintProjection{}, errors.New("fingerprint must bind a Rule or invariant")
	}
	return projection, nil
}

func DefectFingerprint(projection DefectFingerprintProjection) (string, DefectFingerprintProjection, error) {
	projection, err := normalizeFingerprintProjection(projection)
	if err != nil {
		return "", DefectFingerprintProjection{}, err
	}
	line, err := canonicalLine(projection)
	if err != nil {
		return "", DefectFingerprintProjection{}, err
	}
	digest := sha256.Sum256(line[:len(line)-1])
	return hex.EncodeToString(digest[:]), projection, nil
}

func normalizeDefectDimensions(prefix string, domain RootCauseDomain, severity, confidence, reproducibility string, scope []string, priority string) ([]string, error) {
	if !validRootCause(domain) {
		return nil, fmt.Errorf("%s.root_cause_domain is invalid", prefix)
	}
	for name, value := range map[string]string{"severity": severity, "confidence": confidence, "reproducibility": reproducibility, "priority": priority} {
		if err := validContractIdentifier(prefix+"."+name, value); err != nil {
			return nil, err
		}
	}
	return normalizeStringSet(prefix+".scope", scope, false)
}

func NormalizeDefectFamily(family DefectFamily) (DefectFamily, error) {
	if family.Schema != DefectFamilySchema || family.Version != ContractVersion || family.FingerprintVersion != DefectFingerprintVersion {
		return DefectFamily{}, fmt.Errorf("%w: family schema/version", ErrDefectInvalid)
	}
	if err := validContractIdentifier("family_id", family.FamilyID); err != nil {
		return DefectFamily{}, fmt.Errorf("%w: family id", ErrDefectInvalid)
	}
	fingerprint, projection, err := DefectFingerprint(family.Projection)
	if err != nil || fingerprint != family.Fingerprint || projection.RootCauseDomain != family.RootCauseDomain {
		return DefectFamily{}, fmt.Errorf("%w: fingerprint", ErrDefectInvalid)
	}
	family.Projection = projection
	family.Scope, err = normalizeDefectDimensions("family", family.RootCauseDomain, family.Severity, family.Confidence, family.Reproducibility, family.Scope, family.Priority)
	if err != nil {
		return DefectFamily{}, fmt.Errorf("%w: dimensions", ErrDefectInvalid)
	}
	return family, nil
}

func NormalizeDefectOccurrence(occurrence DefectOccurrence) (DefectOccurrence, error) {
	if occurrence.Schema != DefectOccurrenceSchema || occurrence.Version != ContractVersion {
		return DefectOccurrence{}, fmt.Errorf("%w: occurrence schema/version", ErrDefectInvalid)
	}
	if err := validContractIdentifier("occurrence_id", occurrence.OccurrenceID); err != nil ||
		validContractIdentifier("occurrence.run_id", occurrence.RunID) != nil ||
		validSHA("occurrence.family_fingerprint", occurrence.FamilyFingerprint) != nil ||
		validSHA("occurrence.observed_context_sha256", occurrence.ObservedContextSHA256) != nil ||
		validateAuditReadySourceIdentity(occurrence.Source) != nil {
		return DefectOccurrence{}, fmt.Errorf("%w: occurrence identity", ErrDefectInvalid)
	}
	var err error
	occurrence.Scope, err = normalizeDefectDimensions("occurrence", occurrence.RootCauseDomain, occurrence.Severity, occurrence.Confidence, occurrence.Reproducibility, occurrence.Scope, occurrence.Priority)
	if err != nil {
		return DefectOccurrence{}, fmt.Errorf("%w: occurrence dimensions", ErrDefectInvalid)
	}
	occurrence.EvidenceReferences, err = normalizeEvidenceReferences("occurrence.evidence_references", occurrence.EvidenceReferences, false)
	if err != nil {
		return DefectOccurrence{}, fmt.Errorf("%w: occurrence evidence", ErrDefectInvalid)
	}
	if _, err := normalizeEvidenceReferences("occurrence.reproduction_reference", []EvidenceReference{occurrence.ReproductionReference}, false); err != nil {
		return DefectOccurrence{}, fmt.Errorf("%w: reproduction evidence", ErrDefectInvalid)
	}
	return occurrence, nil
}

func NormalizeDefects(families []DefectFamily, occurrences []DefectOccurrence) ([]DefectFamily, []DefectOccurrence, error) {
	if len(families) > maxContractItems || len(occurrences) > maxContractItems {
		return nil, nil, fmt.Errorf("%w: defect collection exceeds bound", ErrDefectInvalid)
	}
	normalizedFamilies := append([]DefectFamily(nil), families...)
	for index := range normalizedFamilies {
		family, err := NormalizeDefectFamily(normalizedFamilies[index])
		if err != nil {
			return nil, nil, err
		}
		normalizedFamilies[index] = family
	}
	sort.Slice(normalizedFamilies, func(i, j int) bool { return normalizedFamilies[i].Fingerprint < normalizedFamilies[j].Fingerprint })
	familyByFingerprint := map[string]DefectFamily{}
	familyIDs := map[string]struct{}{}
	for _, family := range normalizedFamilies {
		if _, exists := familyByFingerprint[family.Fingerprint]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate family fingerprint", ErrDefectInvalid)
		}
		if _, exists := familyIDs[family.FamilyID]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate family id", ErrDefectInvalid)
		}
		familyByFingerprint[family.Fingerprint] = family
		familyIDs[family.FamilyID] = struct{}{}
	}
	normalizedOccurrences := append([]DefectOccurrence(nil), occurrences...)
	for index := range normalizedOccurrences {
		occurrence, err := NormalizeDefectOccurrence(normalizedOccurrences[index])
		if err != nil {
			return nil, nil, err
		}
		family, exists := familyByFingerprint[occurrence.FamilyFingerprint]
		if !exists || family.RootCauseDomain != occurrence.RootCauseDomain {
			return nil, nil, fmt.Errorf("%w: occurrence family binding", ErrDefectInvalid)
		}
		normalizedOccurrences[index] = occurrence
	}
	sort.Slice(normalizedOccurrences, func(i, j int) bool {
		return normalizedOccurrences[i].OccurrenceID < normalizedOccurrences[j].OccurrenceID
	})
	for index := 1; index < len(normalizedOccurrences); index++ {
		if normalizedOccurrences[index].OccurrenceID == normalizedOccurrences[index-1].OccurrenceID {
			return nil, nil, fmt.Errorf("%w: duplicate occurrence id", ErrDefectInvalid)
		}
	}
	if normalizedFamilies == nil {
		normalizedFamilies = []DefectFamily{}
	}
	if normalizedOccurrences == nil {
		normalizedOccurrences = []DefectOccurrence{}
	}
	return normalizedFamilies, normalizedOccurrences, nil
}

func ClassifyDefectGrouping(occurrence DefectOccurrence, families []DefectFamily) (DefectGrouping, error) {
	occurrence, err := NormalizeDefectOccurrence(occurrence)
	if err != nil {
		return DefectGrouping{}, err
	}
	for _, candidate := range families {
		family, familyErr := NormalizeDefectFamily(candidate)
		if familyErr != nil {
			return DefectGrouping{}, familyErr
		}
		if family.Fingerprint == occurrence.FamilyFingerprint {
			return DefectGrouping{OccurrenceID: occurrence.OccurrenceID, Disposition: "EXACT_FINGERPRINT_MATCH", FamilyID: family.FamilyID}, nil
		}
	}
	return DefectGrouping{OccurrenceID: occurrence.OccurrenceID, Disposition: "SEMANTIC_DUPLICATE_CANDIDATE", FamilyID: ""}, nil
}

func NormalizeDefectStatePolicy(policy DefectStatePolicy) (DefectStatePolicy, error) {
	if policy.Schema != DefectStatePolicySchema || policy.Version != ContractVersion {
		return DefectStatePolicy{}, fmt.Errorf("%w: state policy schema/version", ErrDefectInvalid)
	}
	if err := validContractIdentifier("policy_id", policy.PolicyID); err != nil {
		return DefectStatePolicy{}, fmt.Errorf("%w: policy id", ErrDefectInvalid)
	}
	if len(policy.States) > maxDefectStates || len(policy.TerminalStates) > maxDefectStates || len(policy.Transitions) > maxDefectTransitions {
		return DefectStatePolicy{}, fmt.Errorf("%w: state graph exceeds bound", ErrDefectInvalid)
	}
	var err error
	policy.States, err = normalizeStringSet("states", policy.States, false)
	if err != nil {
		return DefectStatePolicy{}, fmt.Errorf("%w: states", ErrDefectInvalid)
	}
	policy.TerminalStates, err = normalizeStringSet("terminal_states", policy.TerminalStates, false)
	if err != nil {
		return DefectStatePolicy{}, fmt.Errorf("%w: terminal states", ErrDefectInvalid)
	}
	stateSet := map[string]struct{}{}
	for _, state := range policy.States {
		stateSet[state] = struct{}{}
	}
	if _, exists := stateSet[policy.InitialState]; !exists {
		return DefectStatePolicy{}, fmt.Errorf("%w: initial state not declared", ErrDefectInvalid)
	}
	for _, state := range policy.TerminalStates {
		if _, exists := stateSet[state]; !exists {
			return DefectStatePolicy{}, fmt.Errorf("%w: terminal state not declared", ErrDefectInvalid)
		}
	}
	transitions := append([]DefectStateTransition(nil), policy.Transitions...)
	sort.Slice(transitions, func(i, j int) bool {
		if transitions[i].From != transitions[j].From {
			return transitions[i].From < transitions[j].From
		}
		return transitions[i].To < transitions[j].To
	})
	for index, transition := range transitions {
		if _, exists := stateSet[transition.From]; !exists {
			return DefectStatePolicy{}, fmt.Errorf("%w: transition source not declared", ErrDefectInvalid)
		}
		if _, exists := stateSet[transition.To]; !exists || transition.From == transition.To {
			return DefectStatePolicy{}, fmt.Errorf("%w: transition target invalid", ErrDefectInvalid)
		}
		if index > 0 && transition == transitions[index-1] {
			return DefectStatePolicy{}, fmt.Errorf("%w: duplicate transition", ErrDefectInvalid)
		}
		if containsString(policy.TerminalStates, transition.From) {
			return DefectStatePolicy{}, fmt.Errorf("%w: terminal state has outgoing transition", ErrDefectInvalid)
		}
	}
	policy.Transitions = transitions
	return policy, nil
}

func ResolveDefectDecisionChain(policy DefectStatePolicy, familyFingerprint string, decisions []DefectDecision) (string, error) {
	policy, err := NormalizeDefectStatePolicy(policy)
	if err != nil {
		return "", err
	}
	if err := validSHA("family_fingerprint", familyFingerprint); err != nil {
		return "", fmt.Errorf("%w: family fingerprint", ErrDefectInvalid)
	}
	current := policy.InitialState
	var predecessor *string
	if len(decisions) > maxLifecycleRevisions {
		return "", fmt.Errorf("%w: decision chain exceeds bound", ErrDefectInvalid)
	}
	seenDecisionIDs := make(map[string]struct{}, len(decisions))
	for index, decision := range decisions {
		if decision.Schema != DefectDecisionSchema || decision.Version != ContractVersion || decision.Sequence != int64(index+1) ||
			decision.FamilyFingerprint != familyFingerprint || decision.FromState != current ||
			!equalStringPointers(decision.PredecessorDecisionHash, predecessor) {
			return "", fmt.Errorf("%w: decision chain identity", ErrDefectInvalid)
		}
		if err := validContractIdentifier("decision_id", decision.DecisionID); err != nil ||
			validContractIdentifier("authority_id", decision.AuthorityID) != nil || validSHA("rationale_sha256", decision.RationaleSHA256) != nil {
			return "", fmt.Errorf("%w: decision fields", ErrDefectInvalid)
		}
		if _, exists := seenDecisionIDs[decision.DecisionID]; exists {
			return "", fmt.Errorf("%w: duplicate decision id", ErrDefectInvalid)
		}
		seenDecisionIDs[decision.DecisionID] = struct{}{}
		allowed := false
		for _, transition := range policy.Transitions {
			if transition.From == decision.FromState && transition.To == decision.ToState {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("%w: transition not authorized by policy", ErrDefectInvalid)
		}
		line, marshalErr := canonicalLine(decision)
		if marshalErr != nil {
			return "", fmt.Errorf("%w: decision canonicalization", ErrDefectInvalid)
		}
		digest := sha256.Sum256(line)
		value := hex.EncodeToString(digest[:])
		predecessor = &value
		current = decision.ToState
	}
	return current, nil
}

func NormalizeRunReport(report RunReport) (RunReport, error) {
	if report.Schema != RunReportSchema || report.Version != ContractVersion || report.Revision < 1 || report.Revision > maxLifecycleRevisions {
		return RunReport{}, fmt.Errorf("%w: schema/version/revision", ErrReportInvalid)
	}
	if err := validContractIdentifier("report_id", report.ReportID); err != nil || validContractIdentifier("report.run_id", report.RunID) != nil ||
		validateAuditReadySourceIdentity(report.Source) != nil || validateArtifactIdentity("report.run_manifest", report.RunManifest) != nil ||
		validContractIdentifier("execution_status", report.ExecutionStatus) != nil {
		return RunReport{}, fmt.Errorf("%w: identity", ErrReportInvalid)
	}
	if report.Revision == 1 && report.PredecessorReportSHA256 != nil {
		return RunReport{}, fmt.Errorf("%w: initial predecessor", ErrReportInvalid)
	}
	if report.Revision > 1 && (report.PredecessorReportSHA256 == nil || validSHA("predecessor_report_sha256", *report.PredecessorReportSHA256) != nil) {
		return RunReport{}, fmt.Errorf("%w: successor predecessor", ErrReportInvalid)
	}
	if report.Lifecycle != ReportProvisional && report.Lifecycle != ReportFinalizing && report.Lifecycle != ReportSealed {
		return RunReport{}, fmt.Errorf("%w: lifecycle", ErrReportInvalid)
	}
	if (report.Lifecycle == ReportProvisional && report.Revision != 1) ||
		(report.Lifecycle == ReportFinalizing && report.Revision != 2) ||
		(report.Lifecycle == ReportSealed && report.Revision != 3) {
		return RunReport{}, fmt.Errorf("%w: lifecycle revision", ErrReportInvalid)
	}
	var err error
	report.Coverage.References, err = normalizeEvidenceReferences("report.coverage.references", report.Coverage.References, false)
	if err != nil || report.Coverage.Total < 0 || report.Coverage.Total > maxCoverageItems || report.Coverage.Covered < 0 || report.Coverage.Covered > report.Coverage.Total {
		return RunReport{}, fmt.Errorf("%w: coverage", ErrReportInvalid)
	}
	report.Replay, err = normalizeReplay(report.Replay)
	if err != nil || report.Replay.RunID != report.RunID || report.Replay.RunManifestSHA256 != report.RunManifest.CanonicalSHA256 {
		return RunReport{}, fmt.Errorf("%w: replay", ErrReportInvalid)
	}
	if report.DefectFamilyReferences, err = normalizeStringSet("report.defect_family_references", report.DefectFamilyReferences, true); err != nil {
		return RunReport{}, fmt.Errorf("%w: defect family references", ErrReportInvalid)
	}
	if report.DefectOccurrenceReferences, err = normalizeStringSet("report.defect_occurrence_references", report.DefectOccurrenceReferences, true); err != nil {
		return RunReport{}, fmt.Errorf("%w: defect occurrence references", ErrReportInvalid)
	}
	if report.AnomalyCodes, err = normalizeStringSet("report.anomaly_codes", report.AnomalyCodes, true); err != nil {
		return RunReport{}, fmt.Errorf("%w: anomalies", ErrReportInvalid)
	}
	if report.SecurityFindings, err = normalizeFindingReferences("security_findings", report.SecurityFindings); err != nil {
		return RunReport{}, fmt.Errorf("%w: security findings", ErrReportInvalid)
	}
	if report.VisibilityFindings, err = normalizeFindingReferences("visibility_findings", report.VisibilityFindings); err != nil {
		return RunReport{}, fmt.Errorf("%w: visibility findings", ErrReportInvalid)
	}
	if report.ModelExecution.RemoteDeepSeekRealCalls < 0 || report.ModelExecution.LocalLlamaCPPRealCalls < 0 || report.ModelExecution.ProviderModelNetworkCalls < 0 {
		return RunReport{}, fmt.Errorf("%w: model counts", ErrReportInvalid)
	}
	if report.ModelExecution.ReferenceIDs, err = normalizeStringSet("model_execution.reference_ids", report.ModelExecution.ReferenceIDs, true); err != nil {
		return RunReport{}, fmt.Errorf("%w: model references", ErrReportInvalid)
	}
	report.GateEligibilityFacts, err = normalizeGateFacts("report.gate_eligibility_facts", report.GateEligibilityFacts, false)
	if err != nil {
		return RunReport{}, fmt.Errorf("%w: gate facts", ErrReportInvalid)
	}
	roots := append([]EvidenceRootIdentity(nil), report.EvidenceRoots...)
	if len(roots) == 0 || len(roots) > maxContractItems {
		return RunReport{}, fmt.Errorf("%w: evidence roots", ErrReportInvalid)
	}
	sort.Slice(roots, func(i, j int) bool { return roots[i].Kind < roots[j].Kind })
	for index, root := range roots {
		if err := validContractIdentifier("evidence root kind", root.Kind); err != nil || validSHA("evidence root hash", root.SHA256) != nil ||
			(index > 0 && root.Kind == roots[index-1].Kind) {
			return RunReport{}, fmt.Errorf("%w: evidence root identity", ErrReportInvalid)
		}
	}
	report.EvidenceRoots = roots
	if report.AuditorVerdictClaimed {
		if report.AuditResult == nil || validLogicalPath("audit_result.asset_path", report.AuditResult.AssetPath) != nil ||
			validSHA("audit_result.sha256", report.AuditResult.SHA256) != nil ||
			(report.AuditResult.Verdict != "PASS" && report.AuditResult.Verdict != "FAIL" && report.AuditResult.Verdict != "BLOCKED") {
			return RunReport{}, fmt.Errorf("%w: auditor claim lacks AUDIT_RESULT", ErrReportInvalid)
		}
	} else if report.AuditResult != nil {
		return RunReport{}, fmt.Errorf("%w: unclaimed AUDIT_RESULT must be null", ErrReportInvalid)
	}
	return report, nil
}

func normalizeFindingReferences(field string, findings []FindingReference) ([]FindingReference, error) {
	if len(findings) > maxContractItems {
		return nil, errors.New("finding reference count exceeds bound")
	}
	out := append([]FindingReference(nil), findings...)
	sort.Slice(out, func(i, j int) bool { return out[i].FindingID < out[j].FindingID })
	for index, finding := range out {
		if err := validContractIdentifier(field+".finding_id", finding.FindingID); err != nil ||
			validContractIdentifier(field+".evidence_id", finding.EvidenceID) != nil ||
			validContractIdentifier(field+".severity", finding.Severity) != nil ||
			(index > 0 && finding.FindingID == out[index-1].FindingID) {
			return nil, errors.New("invalid or duplicate finding reference")
		}
	}
	if out == nil {
		out = []FindingReference{}
	}
	return out, nil
}

func ValidateReportTransition(previous, next RunReport) error {
	previous, err := NormalizeRunReport(previous)
	if err != nil {
		return fmt.Errorf("%w: previous report contract", ErrReportTransition)
	}
	next, err = NormalizeRunReport(next)
	if err != nil {
		return fmt.Errorf("%w: successor report contract", ErrReportTransition)
	}
	if previous.Lifecycle == ReportSealed || previous.ReportID != next.ReportID || previous.RunID != next.RunID ||
		previous.Source != next.Source || previous.RunManifest != next.RunManifest || next.Revision != previous.Revision+1 {
		return ErrReportTransition
	}
	allowed := (previous.Lifecycle == ReportProvisional && next.Lifecycle == ReportFinalizing) ||
		(previous.Lifecycle == ReportFinalizing && next.Lifecycle == ReportSealed)
	if !allowed {
		return ErrReportTransition
	}
	digest, err := canonicalDigest(previous)
	if err != nil || next.PredecessorReportSHA256 == nil || *next.PredecessorReportSHA256 != digest {
		return ErrReportTransition
	}
	return nil
}

func NormalizeReportAddendum(addendum ReportAddendum) (ReportAddendum, error) {
	if addendum.Schema != ReportAddendumSchema || addendum.Version != ContractVersion || addendum.Sequence < 1 ||
		addendum.Sequence > maxLifecycleRevisions ||
		validContractIdentifier("addendum_id", addendum.AddendumID) != nil || validSHA("sealed_report_sha256", addendum.SealedReportSHA256) != nil ||
		validSHA("content_sha256", addendum.ContentSHA256) != nil {
		return ReportAddendum{}, ErrReportInvalid
	}
	if addendum.Sequence == 1 && addendum.PredecessorAddendumHash != nil {
		return ReportAddendum{}, ErrReportInvalid
	}
	if addendum.Sequence > 1 && (addendum.PredecessorAddendumHash == nil || validSHA("predecessor_addendum_sha256", *addendum.PredecessorAddendumHash) != nil) {
		return ReportAddendum{}, ErrReportInvalid
	}
	var err error
	if addendum.EvidenceReferences, err = normalizeEvidenceReferences("addendum.evidence_references", addendum.EvidenceReferences, false); err != nil {
		return ReportAddendum{}, ErrReportInvalid
	}
	return addendum, nil
}

func ValidateReportAddendum(addendum ReportAddendum) error {
	_, err := NormalizeReportAddendum(addendum)
	return err
}

// ValidateReportAddendumChain verifies the only permitted post-seal report
// evolution: an append-only, hash-linked addendum chain bound to the immutable
// canonical SEALED report. The report itself is never reopened or rewritten.
func ValidateReportAddendumChain(sealed RunReport, addenda []ReportAddendum) error {
	sealed, err := NormalizeRunReport(sealed)
	if err != nil || sealed.Lifecycle != ReportSealed {
		return ErrReportTransition
	}
	sealedHash, err := canonicalDigest(sealed)
	if err != nil {
		return ErrReportTransition
	}
	if len(addenda) > maxLifecycleRevisions {
		return ErrReportTransition
	}
	var predecessor *string
	seenIDs := make(map[string]struct{}, len(addenda))
	for index, candidate := range addenda {
		addendum, normalizeErr := NormalizeReportAddendum(candidate)
		if normalizeErr != nil || addendum.Sequence != int64(index+1) ||
			addendum.SealedReportSHA256 != sealedHash || !equalOptionalString(addendum.PredecessorAddendumHash, predecessor) {
			return ErrReportTransition
		}
		if _, exists := seenIDs[addendum.AddendumID]; exists {
			return ErrReportTransition
		}
		seenIDs[addendum.AddendumID] = struct{}{}
		digest, err := canonicalDigest(addendum)
		if err != nil {
			return ErrReportTransition
		}
		predecessor = &digest
	}
	return nil
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func canonicalDigest(value any) (string, error) {
	line, err := canonicalLine(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(line)
	return hex.EncodeToString(digest[:]), nil
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(values, wanted)
	return index < len(values) && values[index] == wanted
}

func canonicalEqual(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}
