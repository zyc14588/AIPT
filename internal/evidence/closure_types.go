package evidence

import (
	"context"
	"encoding/json"
)

const (
	AuditReadyStage                = "AUDIT_READY"
	AuditReadyNormalizationVersion = "aipt.audit-ready/v1"
	RunClosureSchema               = "aipt.run-evidence-closure/v1"
	ReplayEvidenceSchema           = "aipt.replay-evidence/v1"
	DefectFamilySchema             = "aipt.defect-family/v1"
	DefectOccurrenceSchema         = "aipt.defect-occurrence/v1"
	DefectFingerprintVersion       = "aipt.defect-fingerprint/v1"
	DefectStatePolicySchema        = "aipt.defect-state-policy/v1"
	DefectDecisionSchema           = "aipt.defect-adjudication/v1"
	RunReportSchema                = "aipt.run-report/v1"
	ReportAddendumSchema           = "aipt.run-report-addendum/v1"
	BundleIndexSchema              = "aipt.audit-ready.bundle-index/v1"
	CoreClassificationSchema       = "aipt.core-evidence-classification/v1"
	ContractVersion                = "1.0.0"

	BundleIndexName       = "bundle-index.json"
	RunClosureName        = "run-evidence-closure.json"
	ReplayEvidenceName    = "replay-evidence.json"
	DefectFamiliesName    = "defect-families.json"
	DefectOccurrencesName = "defect-occurrences.json"
	RunReportName         = "run-report.json"
	RunReportMarkdownName = "run-report.md"
	RunReportCSVName      = "run-report.csv"
	RunReportJUnitName    = "run-report.junit.xml"
	RunReportHTMLName     = "run-report.html"
	RawManifestAssetName  = "raw-capture-manifest.json"
	RawEventsAssetName    = "raw-capture-events.ndjson"
	RawRootAssetName      = "raw-capture-root.sha256"
)

// DisclosureProfile is the authority-frozen evidence disclosure boundary.
type DisclosureProfile string

const (
	DisclosurePublic          DisclosureProfile = "PUBLIC"
	DisclosureExternalAuditor DisclosureProfile = "EXTERNAL_AUDITOR"
	DisclosurePrivateFull     DisclosureProfile = "PRIVATE_FULL"
)

type EncryptionStatus string

const (
	EncryptionUnencrypted EncryptionStatus = "UNENCRYPTED"
	EncryptionEncrypted   EncryptionStatus = "ENCRYPTED"
)

type Encryption struct {
	Status       EncryptionStatus `json:"status"`
	Scheme       string           `json:"scheme,omitempty"`
	KeyReference string           `json:"key_reference,omitempty"`
}

type Disclosure struct {
	Profile                    DisclosureProfile `json:"profile"`
	ContainsUnpublishedContent bool              `json:"contains_unpublished_content"`
	Encryption                 Encryption        `json:"encryption"`
}

type RemoteVerification struct {
	Remote string `json:"remote"`
	Commit string `json:"commit"`
	Status string `json:"status"`
}

// SourceVerifier validates an immutable commit against a local, already
// fetched source mirror. Implementations must not perform network access.
type SourceVerifier interface {
	Verify(context.Context, SourceIdentity) (RemoteVerification, error)
}

type AuditReadyManifest struct {
	Schema               string             `json:"schema"`
	Version              string             `json:"version"`
	Stage                string             `json:"stage"`
	RawCaptureRoot       string             `json:"raw_capture_root"`
	Source               SourceIdentity     `json:"source"`
	RemoteVerification   RemoteVerification `json:"remote_verification"`
	Disclosure           Disclosure         `json:"disclosure"`
	NormalizationVersion string             `json:"normalization_version"`
	NormalizedAssets     []Asset            `json:"normalized_assets"`
}

type ArtifactIdentity struct {
	ID              string `json:"id"`
	Schema          string `json:"schema"`
	CanonicalSHA256 string `json:"canonical_sha256"`
}

type LedgerIdentity struct {
	StreamID      string  `json:"stream_id"`
	EventCount    int64   `json:"event_count"`
	TailSequence  int64   `json:"tail_sequence"`
	TailEventHash *string `json:"tail_event_hash"`
}

type EvidenceReference struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ActionReceiptEvidence struct {
	ActionID       string            `json:"action_id"`
	Sequence       int64             `json:"sequence"`
	EventHash      string            `json:"event_hash"`
	StateHash      string            `json:"state_hash"`
	ProjectionHash string            `json:"projection_hash"`
	Evidence       EvidenceReference `json:"evidence"`
}

type ProjectionEvidence struct {
	Schema          string `json:"schema"`
	CanonicalSHA256 string `json:"canonical_sha256"`
	FinalStateHash  string `json:"final_state_hash"`
}

type RuleCitation struct {
	RuleID       string `json:"rule_id"`
	SourceSHA256 string `json:"source_sha256"`
}

type RNGEvidence struct {
	Used                 bool   `json:"used"`
	Version              string `json:"version"`
	SeedCommitment       string `json:"seed_commitment"`
	SeedDisclosureStatus string `json:"seed_disclosure_status"`
}

type ReplayImplementation struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type ReplayEvidence struct {
	Schema                 string               `json:"schema"`
	Version                string               `json:"version"`
	RunID                  string               `json:"run_id"`
	RunManifestSHA256      string               `json:"run_manifest_sha256"`
	LedgerStreamID         string               `json:"ledger_stream_id"`
	LedgerTailSequence     int64                `json:"ledger_tail_sequence"`
	LedgerTailHash         *string              `json:"ledger_tail_hash"`
	LiveFinalStateHash     string               `json:"live_final_state_hash"`
	ReplayedFinalStateHash string               `json:"replayed_final_state_hash"`
	HashMatch              bool                 `json:"hash_match"`
	Implementation         ReplayImplementation `json:"implementation"`
	RNG                    RNGEvidence          `json:"rng"`
}

type GateEligibilityFact struct {
	Gate       string `json:"gate"`
	Eligible   bool   `json:"eligible"`
	ReasonCode string `json:"reason_code"`
}

type ModelExecutionReference struct {
	ExecutionID     string `json:"execution_id"`
	ModelProfile    string `json:"model_profile"`
	HarnessIdentity string `json:"harness_identity"`
	EvidenceSHA256  string `json:"evidence_sha256"`
}

type RunEvidenceClosure struct {
	Schema                   string                    `json:"schema"`
	Version                  string                    `json:"version"`
	RunID                    string                    `json:"run_id"`
	RunManifest              ArtifactIdentity          `json:"run_manifest"`
	Source                   SourceIdentity            `json:"source"`
	StateAuthority           string                    `json:"state_authority"`
	Ledger                   LedgerIdentity            `json:"ledger"`
	ActionReceipts           []ActionReceiptEvidence   `json:"action_receipts"`
	Projection               ProjectionEvidence        `json:"projection"`
	RuleCitations            []RuleCitation            `json:"rule_citations"`
	RNG                      RNGEvidence               `json:"rng"`
	Replay                   ReplayEvidence            `json:"replay"`
	CoverageReferences       []EvidenceReference       `json:"coverage_references"`
	DefectOccurrenceIDs      []string                  `json:"defect_occurrence_ids"`
	AnomalyCodes             []string                  `json:"anomaly_codes"`
	GateEligibilityFacts     []GateEligibilityFact     `json:"gate_eligibility_facts"`
	ModelExecutionReferences []ModelExecutionReference `json:"model_execution_references"`
}

type RootCauseDomain string

const (
	RootCauseRuleProse   RootCauseDomain = "RULE_PROSE"
	RootCauseMachineRule RootCauseDomain = "MACHINE_RULE"
	RootCauseModule      RootCauseDomain = "MODULE"
	RootCauseAdapter     RootCauseDomain = "ADAPTER"
	RootCauseAIPT        RootCauseDomain = "AIPT"
	RootCauseModel       RootCauseDomain = "MODEL"
)

type DefectFingerprintProjection struct {
	Version         string          `json:"version"`
	RootCauseDomain RootCauseDomain `json:"root_cause_domain"`
	SemanticKey     string          `json:"semantic_key"`
	RuleIDs         []string        `json:"rule_ids"`
	InvariantIDs    []string        `json:"invariant_ids"`
}

type DefectFamily struct {
	Schema             string                      `json:"schema"`
	Version            string                      `json:"version"`
	FamilyID           string                      `json:"family_id"`
	FingerprintVersion string                      `json:"fingerprint_version"`
	Fingerprint        string                      `json:"fingerprint"`
	Projection         DefectFingerprintProjection `json:"fingerprint_projection"`
	RootCauseDomain    RootCauseDomain             `json:"root_cause_domain"`
	Severity           string                      `json:"severity"`
	Confidence         string                      `json:"confidence"`
	Reproducibility    string                      `json:"reproducibility"`
	Scope              []string                    `json:"scope"`
	Priority           string                      `json:"priority"`
}

type DefectOccurrence struct {
	Schema                string              `json:"schema"`
	Version               string              `json:"version"`
	OccurrenceID          string              `json:"occurrence_id"`
	FamilyFingerprint     string              `json:"family_fingerprint"`
	RunID                 string              `json:"run_id"`
	Source                SourceIdentity      `json:"source"`
	RootCauseDomain       RootCauseDomain     `json:"root_cause_domain"`
	Severity              string              `json:"severity"`
	Confidence            string              `json:"confidence"`
	Reproducibility       string              `json:"reproducibility"`
	Scope                 []string            `json:"scope"`
	Priority              string              `json:"priority"`
	EvidenceReferences    []EvidenceReference `json:"evidence_references"`
	ReproductionReference EvidenceReference   `json:"reproduction_reference"`
	ObservedContextSHA256 string              `json:"observed_context_sha256"`
}

type DefectGrouping struct {
	OccurrenceID string `json:"occurrence_id"`
	Disposition  string `json:"disposition"`
	FamilyID     string `json:"family_id"`
}

// DefectStatePolicy deliberately contains no built-in governance state names.
// A versioned Authority policy must supply the explicit state graph.
type DefectStatePolicy struct {
	Schema         string                  `json:"schema"`
	Version        string                  `json:"version"`
	PolicyID       string                  `json:"policy_id"`
	States         []string                `json:"states"`
	InitialState   string                  `json:"initial_state"`
	TerminalStates []string                `json:"terminal_states"`
	Transitions    []DefectStateTransition `json:"transitions"`
}

type DefectStateTransition struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type DefectDecision struct {
	Schema                  string  `json:"schema"`
	Version                 string  `json:"version"`
	DecisionID              string  `json:"decision_id"`
	Sequence                int64   `json:"sequence"`
	PredecessorDecisionHash *string `json:"predecessor_decision_sha256"`
	FamilyFingerprint       string  `json:"family_fingerprint"`
	FromState               string  `json:"from_state"`
	ToState                 string  `json:"to_state"`
	AuthorityID             string  `json:"authority_id"`
	RationaleSHA256         string  `json:"rationale_sha256"`
}

type CoverageSummary struct {
	References []EvidenceReference `json:"references"`
	Total      int64               `json:"total"`
	Covered    int64               `json:"covered"`
}

type FindingReference struct {
	FindingID  string `json:"finding_id"`
	EvidenceID string `json:"evidence_id"`
	Severity   string `json:"severity"`
}

type ModelExecutionFacts struct {
	RemoteDeepSeekRealCalls   int64    `json:"remote_deepseek_real_calls"`
	LocalLlamaCPPRealCalls    int64    `json:"local_llamacpp_real_calls"`
	ProviderModelNetworkCalls int64    `json:"provider_model_network_calls"`
	ReferenceIDs              []string `json:"reference_ids"`
}

type EvidenceRootIdentity struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type AuditResultReference struct {
	AssetPath string `json:"asset_path"`
	SHA256    string `json:"sha256"`
	Verdict   string `json:"verdict"`
}

type ReportLifecycle string

const (
	ReportProvisional ReportLifecycle = "PROVISIONAL"
	ReportFinalizing  ReportLifecycle = "FINALIZING"
	ReportSealed      ReportLifecycle = "SEALED"
)

type RunReport struct {
	Schema                     string                 `json:"schema"`
	Version                    string                 `json:"version"`
	ReportID                   string                 `json:"report_id"`
	Revision                   int64                  `json:"revision"`
	PredecessorReportSHA256    *string                `json:"predecessor_report_sha256"`
	Lifecycle                  ReportLifecycle        `json:"lifecycle"`
	RunID                      string                 `json:"run_id"`
	Source                     SourceIdentity         `json:"source"`
	RunManifest                ArtifactIdentity       `json:"run_manifest"`
	ExecutionStatus            string                 `json:"execution_status"`
	Coverage                   CoverageSummary        `json:"coverage"`
	Replay                     ReplayEvidence         `json:"replay"`
	DefectFamilyReferences     []string               `json:"defect_family_references"`
	DefectOccurrenceReferences []string               `json:"defect_occurrence_references"`
	AnomalyCodes               []string               `json:"anomaly_codes"`
	SecurityFindings           []FindingReference     `json:"security_findings"`
	VisibilityFindings         []FindingReference     `json:"visibility_findings"`
	ModelExecution             ModelExecutionFacts    `json:"model_execution"`
	GateEligibilityFacts       []GateEligibilityFact  `json:"gate_eligibility_facts"`
	QualificationEligible      bool                   `json:"qualification_eligible"`
	EvidenceRoots              []EvidenceRootIdentity `json:"evidence_roots"`
	AuditorVerdictClaimed      bool                   `json:"auditor_verdict_claimed"`
	AuditResult                *AuditResultReference  `json:"audit_result"`
}

type ReportAddendum struct {
	Schema                  string              `json:"schema"`
	Version                 string              `json:"version"`
	AddendumID              string              `json:"addendum_id"`
	SealedReportSHA256      string              `json:"sealed_report_sha256"`
	Sequence                int64               `json:"sequence"`
	PredecessorAddendumHash *string             `json:"predecessor_addendum_sha256"`
	ContentSHA256           string              `json:"content_sha256"`
	EvidenceReferences      []EvidenceReference `json:"evidence_references"`
}

type ContentClassification string

const (
	ContentPublic            ContentClassification = "PUBLIC"
	ContentUnreleasedRemote  ContentClassification = "UNRELEASED_REMOTE_ALLOWED"
	ContentTableHiddenRemote ContentClassification = "TABLE_HIDDEN_REMOTE_ALLOWED"
	ContentLocalOnlySecret   ContentClassification = "LOCAL_ONLY_SECRET"
	ContentHumanPrivateData  ContentClassification = "HUMAN_PRIVATE_DATA"
	ContentCredentialSecret  ContentClassification = "CREDENTIAL_SECRET"
)

type ContentKind string

const (
	ContentKindContract            ContentKind = "CONTRACT"
	ContentKindRawCapture          ContentKind = "RAW_CAPTURE"
	ContentKindReportDerivative    ContentKind = "REPORT_DERIVATIVE"
	ContentKindSupplemental        ContentKind = "SUPPLEMENTAL"
	ContentKindPrivatePrompt       ContentKind = "PRIVATE_PROMPT"
	ContentKindCredential          ContentKind = "CREDENTIAL"
	ContentKindPrivateAssetLocator ContentKind = "PRIVATE_ASSET_LOCATOR"
	ContentKindGameBody            ContentKind = "GAME_BODY"
)

type LogicalAssetInput struct {
	Path           string                `json:"path"`
	MediaType      string                `json:"media_type"`
	Classification ContentClassification `json:"classification"`
	ContentKind    ContentKind           `json:"content_kind"`
	Data           []byte                `json:"-"`
}

// CoreEvidenceClassifications is the explicit B005 classification authority
// for every required AUDIT_READY core evidence category. ReportDerivatives is
// declared separately so the machine contract can enforce its deterministic
// inheritance from RunReport instead of trusting individual asset labels.
type CoreEvidenceClassifications struct {
	Schema             string                `json:"schema"`
	Version            string                `json:"version"`
	RawCapture         ContentClassification `json:"raw_capture"`
	RunEvidenceClosure ContentClassification `json:"run_evidence_closure"`
	ReplayEvidence     ContentClassification `json:"replay_evidence"`
	DefectFamily       ContentClassification `json:"defect_family"`
	DefectOccurrence   ContentClassification `json:"defect_occurrence"`
	RunReport          ContentClassification `json:"run_report"`
	ReportDerivatives  ContentClassification `json:"report_derivatives"`
}

type ExportProfile struct {
	ProfileID       string `json:"profile_id"`
	InlineThreshold int64  `json:"inline_threshold"`
	ChunkSize       int64  `json:"chunk_size"`
	MaxAssetBytes   int64  `json:"max_asset_bytes"`
	MaxTotalBytes   int64  `json:"max_total_bytes"`
	MaxAssets       int    `json:"max_assets"`
	MaxChunks       int    `json:"max_chunks"`
}

type ChunkReference struct {
	Ordinal int64  `json:"ordinal"`
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
}

type AssetStorage struct {
	Kind   string           `json:"kind"`
	Path   string           `json:"path,omitempty"`
	Chunks []ChunkReference `json:"chunks,omitempty"`
}

type LogicalAsset struct {
	Path           string                `json:"path"`
	MediaType      string                `json:"media_type"`
	Bytes          int64                 `json:"bytes"`
	SHA256         string                `json:"sha256"`
	Classification ContentClassification `json:"classification"`
	ContentKind    ContentKind           `json:"content_kind"`
	Storage        AssetStorage          `json:"storage"`
}

type BundleIndex struct {
	Schema                      string                      `json:"schema"`
	Version                     string                      `json:"version"`
	CoreEvidenceClassifications CoreEvidenceClassifications `json:"core_evidence_classifications"`
	ExportProfile               ExportProfile               `json:"export_profile"`
	LogicalAssets               []LogicalAsset              `json:"logical_assets"`
}

type GenerateAuditReadyInput struct {
	Destination         string
	RawCapture          string
	SourceVerifier      SourceVerifier
	Disclosure          Disclosure
	CoreClassifications CoreEvidenceClassifications
	Closure             RunEvidenceClosure
	DefectFamilies      []DefectFamily
	DefectOccurrences   []DefectOccurrence
	Report              RunReport
	Supplemental        []LogicalAssetInput
	ExportProfile       ExportProfile
}

type AuditReadyVerification struct {
	Root          string
	Manifest      AuditReadyManifest
	BundleIndex   BundleIndex
	Closure       RunEvidenceClosure
	Report        RunReport
	LogicalAssets map[string][]byte
}

type defectFamilyEnvelope struct {
	Schema   string         `json:"schema"`
	Version  string         `json:"version"`
	Families []DefectFamily `json:"families"`
}

type defectOccurrenceEnvelope struct {
	Schema      string             `json:"schema"`
	Version     string             `json:"version"`
	Occurrences []DefectOccurrence `json:"occurrences"`
}

// CanonicalJSONAsset exists for callers that already hold validated JSON and
// need a typed supplemental asset without exposing a filesystem path.
func CanonicalJSONAsset(path, mediaType string, classification ContentClassification, kind ContentKind, value any) (LogicalAssetInput, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return LogicalAssetInput{}, err
	}
	canonical, err := canonicalLine(json.RawMessage(raw))
	if err != nil {
		return LogicalAssetInput{}, err
	}
	return LogicalAssetInput{Path: path, MediaType: mediaType, Classification: classification, ContentKind: kind, Data: canonical}, nil
}
