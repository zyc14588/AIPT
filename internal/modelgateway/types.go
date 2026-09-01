package modelgateway

import (
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

const (
	ModelProfileSchema          = "aipt.model-profile/v1"
	SamplingProfileSchema       = "aipt.sampling-profile/v1"
	CertificationSchema         = "aipt.model-certification/v1"
	ExecutionTupleSchema        = "aipt.model-execution-tuple/v1"
	HarnessRequestSchema        = "aipt.harness-agent-request/v1"
	HarnessResponseSchema       = "aipt.harness-agent-response/v1"
	InvocationEvidenceSchema    = "aipt.model-invocation-evidence/v1"
	BreakGlassGrantSchema       = "aipt.break-glass-grant/v1"
	BreakGlassConsumptionSchema = "aipt.break-glass-consumption/v1"
	ManifestBindingSchema       = "aipt.model-manifest-binding/v1"
	ReplacementEventSchema      = "aipt.model-replacement-event/v1"
	ContextReductionSchema      = "aipt.context-reduction/v1"
	EffectiveSamplingSchema     = "aipt.effective-sampling-projection/v1"
	SamplingEnforcementIdentity = "AIPT_ACP_CONSERVATIVE_UTF8_BYTE_BUDGET_V1"
	LocalIsolationIdentity      = "AIPT_LINUX_USER_NETNS_SUPERVISOR_V1"

	HarnessProtocolACP        = "agent-client-protocol"
	HarnessProtocolVersionACP = "1"
	RemoteDeepSeekModelID     = "deepseek-v4-pro"
)

// BackendKind is the B004 closed backend registry.
type BackendKind string

const (
	BackendRemoteDeepSeek BackendKind = "REMOTE_DEEPSEEK"
	BackendLocalLlamaCPP  BackendKind = "LOCAL_LLAMACPP"
)

type StructuredOutputMode string

const (
	StructuredNative   StructuredOutputMode = "NATIVE_SCHEMA"
	StructuredPrompted StructuredOutputMode = "PROMPTED"
	StructuredRepair   StructuredOutputMode = "BOUNDED_REPAIR"
)

type ToolCallMode string

const (
	ToolCallDisabled ToolCallMode = "DISABLED"
	ToolCallNative   ToolCallMode = "NATIVE"
	ToolCallEmulated ToolCallMode = "EMULATED"
)

type CredentialReferenceKind string

const (
	CredentialEnvironment   CredentialReferenceKind = "ENVIRONMENT_VARIABLE"
	CredentialEncryptedFile CredentialReferenceKind = "ENCRYPTED_LOCAL_FILE"
)

type CapabilityName string

const (
	CapabilityBasicCompletion                   CapabilityName = "basic_completion"
	CapabilityStructuredOutputNative            CapabilityName = "structured_output_native"
	CapabilityStructuredOutputPrompted          CapabilityName = "structured_output_prompted"
	CapabilityStructuredOutputRepair            CapabilityName = "structured_output_repair"
	CapabilityToolCallNative                    CapabilityName = "tool_call_native"
	CapabilityToolCallEmulated                  CapabilityName = "tool_call_emulated"
	CapabilityContextBudget                     CapabilityName = "context_budget"
	CapabilityRoleInvocation                    CapabilityName = "role_invocation"
	CapabilityTransportStability                CapabilityName = "transport_stability"
	CapabilityVisibilityPolicyCompatible        CapabilityName = "visibility_policy_compatible"
	CapabilityPromptInjectionBoundaryCompatible CapabilityName = "prompt_injection_boundary_compatible"
)

type ClaimStatus string

const (
	ClaimCertified    ClaimStatus = "CERTIFIED"
	ClaimNotCertified ClaimStatus = "NOT_CERTIFIED"
	ClaimUntested     ClaimStatus = "UNTESTED"
)

type CertificationKind string

const (
	CertificationControlledReal CertificationKind = "CONTROLLED_REAL"
	CertificationSyntheticCI    CertificationKind = "SYNTHETIC_PUBLIC_CI"
)

type CapabilityClaim struct {
	Name   CapabilityName `json:"name"`
	Status ClaimStatus    `json:"status"`
}

type SamplingProfile struct {
	Schema                string   `json:"schema"`
	SamplingID            string   `json:"sampling_id"`
	SamplingVersion       string   `json:"sampling_version"`
	Temperature           float64  `json:"temperature"`
	TopP                  float64  `json:"top_p"`
	MaxOutputTokens       int      `json:"max_output_tokens"`
	MaxContextTokens      int      `json:"max_context_tokens"`
	Seed                  *int64   `json:"seed,omitempty"`
	AppliedParameters     []string `json:"applied_parameters"`
	UnsupportedParameters []string `json:"unsupported_parameters"`
	SHA256                string   `json:"sha256"`
}

func (p SamplingProfile) BindingID() string { return p.SamplingID + "@" + p.SamplingVersion }

// EffectiveSamplingProjection records the exact controls the ACP v1 route
// can enforce. UTF-8 bytes are a conservative upper bound on tokenizer units:
// every token consumes at least one input byte, so these ceilings can reject
// early but cannot admit more than the governed token count.
type EffectiveSamplingProjection struct {
	Schema                 string   `json:"schema"`
	EnforcementIdentity    string   `json:"enforcement_identity"`
	AppliedParameters      []string `json:"applied_parameters"`
	UnsupportedParameters  []string `json:"unsupported_parameters"`
	MaxContextTokens       int      `json:"max_context_tokens"`
	MaxOutputTokens        int      `json:"max_output_tokens"`
	ContextUTF8ByteCeiling int      `json:"context_utf8_byte_ceiling"`
	OutputUTF8ByteCeiling  int      `json:"output_utf8_byte_ceiling"`
}

type HarnessIdentity struct {
	Implementation        string `json:"implementation"`
	Version               string `json:"version"`
	Commit                string `json:"commit"`
	PackageSHA256         string `json:"package_sha256"`
	ProtocolIdentity      string `json:"protocol_identity"`
	ProtocolVersion       string `json:"protocol_version"`
	CapabilityFingerprint string `json:"capability_fingerprint"`
	RuntimeClosureKind    string `json:"runtime_closure_kind"`
	RuntimeClosureSHA256  string `json:"runtime_closure_sha256"`
}

func (h HarnessIdentity) BindingID() string {
	return h.Implementation + "@" + h.Version + "+" + h.Commit
}

type ContextPolicy struct {
	PolicyID          string `json:"policy_id"`
	PolicyVersion     string `json:"policy_version"`
	MaxRequestBytes   int    `json:"max_request_bytes"`
	MaxContextBytes   int    `json:"max_context_bytes"`
	ReductionPolicyID string `json:"reduction_policy_id"`
}

type DataEgressPolicy struct {
	PolicyID               string                            `json:"policy_id"`
	PolicyVersion          string                            `json:"policy_version"`
	AllowedClassifications []orchestrator.DataClassification `json:"allowed_classifications"`
	BreakGlassAllowed      bool                              `json:"break_glass_allowed"`
}

type CredentialReference struct {
	ReferenceID string                  `json:"reference_id"`
	Kind        CredentialReferenceKind `json:"kind"`
	Locator     string                  `json:"locator"`
}

type HardwareIdentity struct {
	Architecture string `json:"architecture"`
	CPUClass     string `json:"cpu_class"`
	GPUBackend   string `json:"gpu_backend"`
	MemoryClass  string `json:"memory_class"`
}

type LocalRuntimeIdentity struct {
	ExecutableReference      string           `json:"executable_reference"`
	BinarySHA256             string           `json:"binary_sha256"`
	Version                  string           `json:"version"`
	Commit                   string           `json:"commit"`
	GGUFReference            string           `json:"gguf_reference"`
	GGUFSHA256               string           `json:"gguf_sha256"`
	GGUFModelIdentity        string           `json:"gguf_model_identity"`
	QuantizationIdentity     string           `json:"quantization_identity"`
	TemplateIdentity         string           `json:"template_identity"`
	TemplateSHA256           string           `json:"template_sha256"`
	IsolationIdentity        string           `json:"isolation_identity"`
	IsolationHelperReference string           `json:"isolation_helper_reference"`
	IsolationHelperSHA256    string           `json:"isolation_helper_sha256"`
	LaunchParameters         []string         `json:"launch_parameters"`
	Hardware                 HardwareIdentity `json:"hardware"`
}

type ModelProfile struct {
	Schema                 string                `json:"schema"`
	ProfileID              string                `json:"profile_id"`
	ProfileVersion         string                `json:"profile_version"`
	BackendKind            BackendKind           `json:"backend_kind"`
	ProviderIdentity       string                `json:"provider_identity"`
	ModelID                string                `json:"model_id"`
	Harness                HarnessIdentity       `json:"harness_identity"`
	SamplingProfileID      string                `json:"sampling_profile_id"`
	StructuredOutputMode   StructuredOutputMode  `json:"structured_output_mode"`
	ToolCallMode           ToolCallMode          `json:"tool_call_mode"`
	ContextPolicy          ContextPolicy         `json:"context_policy"`
	DataEgressPolicy       DataEgressPolicy      `json:"data_egress_policy"`
	CredentialReference    *CredentialReference  `json:"credential_reference,omitempty"`
	LocalRuntimeIdentity   *LocalRuntimeIdentity `json:"local_runtime_identity,omitempty"`
	CapabilityRequirements []CapabilityName      `json:"capability_requirements"`
	CertificationIdentity  string                `json:"certification_identity"`
	SHA256                 string                `json:"sha256"`
}

func (p ModelProfile) BindingID() string { return p.ProfileID + "@" + p.ProfileVersion }

type ExecutionTuple struct {
	Schema                         string                      `json:"schema"`
	BackendKind                    BackendKind                 `json:"backend_kind"`
	ProviderIdentity               string                      `json:"provider_identity"`
	ModelID                        string                      `json:"model_id"`
	ModelProfileBinding            string                      `json:"model_profile_binding"`
	SamplingProfileBinding         string                      `json:"sampling_profile_binding"`
	RequestedSamplingSHA256        string                      `json:"requested_sampling_sha256"`
	EffectiveSampling              EffectiveSamplingProjection `json:"effective_sampling_projection"`
	UnsupportedSamplingParameters  []string                    `json:"unsupported_sampling_parameters"`
	BackendSerializedRequestSHA256 string                      `json:"backend_serialized_request_sha256"`
	HarnessIdentity                string                      `json:"harness_identity"`
	HarnessProtocolIdentity        string                      `json:"harness_protocol_identity"`
	HarnessProtocolVersion         string                      `json:"harness_protocol_version"`
	StructuredOutputMode           StructuredOutputMode        `json:"structured_output_mode"`
	ToolCallMode                   ToolCallMode                `json:"tool_call_mode"`
	RequestContractVersion         string                      `json:"request_contract_version"`
	CapabilityFingerprint          string                      `json:"capability_fingerprint"`
	EnvironmentIdentity            string                      `json:"environment_identity"`
	LocalRuntimeIdentity           *LocalRuntimeIdentity       `json:"local_runtime_identity,omitempty"`
	SHA256                         string                      `json:"sha256"`
}

type Certification struct {
	Schema                    string            `json:"schema"`
	CertificationID           string            `json:"certification_id"`
	CertificationVersion      string            `json:"certification_version"`
	ProfileBinding            string            `json:"profile_binding"`
	SamplingBinding           string            `json:"sampling_binding"`
	Result                    string            `json:"result"`
	Kind                      CertificationKind `json:"kind"`
	MinimumCertification      bool              `json:"minimum_certification"`
	RealModelCalls            int               `json:"real_model_calls"`
	EvidenceIdentity          string            `json:"evidence_identity"`
	ProductionRoleEligibility string            `json:"production_role_eligibility"`
	Claims                    []CapabilityClaim `json:"claims"`
	ExecutionTuple            ExecutionTuple    `json:"execution_tuple"`
	ObservedAt                time.Time         `json:"observed_at"`
	SHA256                    string            `json:"sha256"`
}

func (c Certification) BindingID() string {
	return c.CertificationID + "@" + c.CertificationVersion
}

type RoleAssignment struct {
	AssignmentID          string              `json:"assignment_id"`
	SeatID                orchestrator.SeatID `json:"seat_id"`
	RoleID                string              `json:"role_id"`
	ProfileBinding        string              `json:"profile_binding"`
	SamplingBinding       string              `json:"sampling_binding"`
	BackendKind           BackendKind         `json:"backend_kind"`
	CertificationIdentity string              `json:"certification_identity"`
}

type ManifestBinding struct {
	Schema                string           `json:"schema"`
	ManifestID            string           `json:"manifest_id"`
	RunID                 string           `json:"run_id"`
	ManifestSHA256        string           `json:"manifest_sha256"`
	RunClassification     string           `json:"run_classification"`
	QualificationEligible bool             `json:"qualification_eligible"`
	Assignments           []RoleAssignment `json:"assignments"`
	CleanBaselineEligible bool             `json:"clean_baseline_eligible"`
	SHA256                string           `json:"sha256"`
}

type ReplacementEvent struct {
	Schema                string              `json:"schema"`
	EventID               string              `json:"event_id"`
	ManifestSHA256        string              `json:"manifest_sha256"`
	SeatID                orchestrator.SeatID `json:"seat_id"`
	PreviousProfile       string              `json:"previous_profile"`
	ReplacementProfile    string              `json:"replacement_profile"`
	ReasonCode            string              `json:"reason_code"`
	CleanBaselineEligible bool                `json:"clean_baseline_eligible"`
}

type ContextReduction struct {
	Schema                string   `json:"schema"`
	PolicyID              string   `json:"policy_id"`
	OriginalContextHash   string   `json:"original_context_hash"`
	PreparedContextSHA256 string   `json:"prepared_context_sha256"`
	OriginalBytes         int      `json:"original_bytes"`
	PreparedBytes         int      `json:"prepared_bytes"`
	RemovedEventIDs       []string `json:"removed_event_ids"`
	RemovedSourceIDs      []string `json:"removed_source_ids"`
}

type GatewayMode string

const (
	GatewayModeFormal     GatewayMode = "FORMAL"
	GatewayModeDiagnostic GatewayMode = "DIAGNOSTIC"
)

type BreakGlassOperation string

const BreakGlassRemoteEgressLocalOnlySecret BreakGlassOperation = "REMOTE_EGRESS_LOCAL_ONLY_SECRET"

type BreakGlassGrant struct {
	Schema               string                          `json:"schema"`
	GrantID              string                          `json:"grant_id"`
	OneTime              bool                            `json:"one_time"`
	DiagnosticOnly       bool                            `json:"diagnostic_only"`
	AuthorizedOperation  BreakGlassOperation             `json:"authorized_operation"`
	RunID                string                          `json:"run_id"`
	DiagnosticID         string                          `json:"diagnostic_id"`
	ManifestSHA256       string                          `json:"manifest_sha256"`
	SeatID               orchestrator.SeatID             `json:"seat_id"`
	InvocationID         string                          `json:"invocation_id"`
	ProfileBinding       string                          `json:"profile_binding"`
	ContextSHA256        string                          `json:"context_sha256"`
	RequestSHA256        string                          `json:"request_sha256"`
	SourceClassification orchestrator.DataClassification `json:"source_classification"`
	DestinationBackend   BackendKind                     `json:"destination_backend"`
	IssuerAuthorityID    string                          `json:"issuer_authority_id"`
	IssuedAt             time.Time                       `json:"issued_at"`
	ExpiresAt            time.Time                       `json:"expires_at"`
	Nonce                string                          `json:"nonce"`
	SignatureEd25519     string                          `json:"signature_ed25519"`
}

type BreakGlassConsumption struct {
	Schema               string                          `json:"schema"`
	ConsumptionID        string                          `json:"consumption_id"`
	GrantID              string                          `json:"grant_id"`
	GrantSHA256          string                          `json:"grant_sha256"`
	AuthorizedOperation  BreakGlassOperation             `json:"authorized_operation"`
	RunID                string                          `json:"run_id"`
	DiagnosticID         string                          `json:"diagnostic_id"`
	ManifestSHA256       string                          `json:"manifest_sha256"`
	SeatID               orchestrator.SeatID             `json:"seat_id"`
	InvocationID         string                          `json:"invocation_id"`
	ProfileBinding       string                          `json:"profile_binding"`
	ContextSHA256        string                          `json:"context_sha256"`
	RequestSHA256        string                          `json:"request_sha256"`
	SourceClassification orchestrator.DataClassification `json:"source_classification"`
	DestinationBackend   BackendKind                     `json:"destination_backend"`
	IssuerAuthorityID    string                          `json:"issuer_authority_id"`
	NonceSHA256          string                          `json:"nonce_sha256"`
	ConsumedAt           time.Time                       `json:"consumed_at"`
	RunDisqualified      bool                            `json:"run_disqualified"`
}

type CredentialValidation struct {
	ReferenceID string                  `json:"reference_id"`
	Kind        CredentialReferenceKind `json:"kind"`
	State       string                  `json:"state"`
	Metadata    map[string]string       `json:"metadata"`
}

type HarnessRequest struct {
	Schema           string                         `json:"schema"`
	ProtocolVersion  string                         `json:"protocol_version"`
	RequestID        string                         `json:"request_id"`
	ProfileBinding   string                         `json:"profile_binding"`
	SamplingBinding  string                         `json:"sampling_binding"`
	ExpectedModelID  string                         `json:"expected_model_id"`
	HarnessIdentity  string                         `json:"harness_identity"`
	BackendKind      BackendKind                    `json:"backend_kind"`
	ProviderIdentity string                         `json:"provider_identity"`
	StructuredMode   StructuredOutputMode           `json:"structured_output_mode"`
	ToolMode         ToolCallMode                   `json:"tool_call_mode"`
	SamplingProfile  SamplingProfile                `json:"sampling_profile"`
	Session          orchestrator.Session           `json:"session"`
	Invocation       orchestrator.InvocationRequest `json:"invocation"`
	PreparedContext  []byte                         `json:"prepared_context"`
	ContextReduction ContextReduction               `json:"context_reduction"`
	RequestSHA256    string                         `json:"request_sha256"`
}

type HarnessResult struct {
	Schema                         string                      `json:"schema"`
	ProtocolVersion                string                      `json:"protocol_version"`
	RequestID                      string                      `json:"request_id"`
	HarnessIdentity                string                      `json:"harness_identity"`
	ObservedModelID                string                      `json:"observed_model_id"`
	CapabilityFingerprint          string                      `json:"capability_fingerprint"`
	RawResponse                    []byte                      `json:"raw_response"`
	StructuredResponse             []byte                      `json:"structured_response"`
	ResponseSHA256                 string                      `json:"response_sha256"`
	CompletedAt                    time.Time                   `json:"completed_at"`
	RouteRecoveryOccurred          bool                        `json:"route_recovery_occurred"`
	RequestedSamplingSHA256        string                      `json:"requested_sampling_sha256"`
	EffectiveSampling              EffectiveSamplingProjection `json:"effective_sampling_projection"`
	UnsupportedSamplingParameters  []string                    `json:"unsupported_sampling_parameters"`
	BackendSerializedRequestSHA256 string                      `json:"backend_serialized_request_sha256"`
}

type HarnessProbe struct {
	HarnessIdentity               string `json:"harness_identity"`
	ProtocolIdentity              string `json:"protocol_identity"`
	ProtocolVersion               string `json:"protocol_version"`
	ObservedModelID               string `json:"observed_model_id"`
	CapabilityFingerprint         string `json:"capability_fingerprint"`
	RouteAvailable                bool   `json:"route_available"`
	DirectProviderBypassAvailable bool   `json:"direct_provider_bypass_available"`
}

type InvocationEvidence struct {
	Schema                string               `json:"schema"`
	DiagnosticID          string               `json:"diagnostic_id"`
	RunID                 string               `json:"run_id"`
	RunClassification     string               `json:"run_classification"`
	SeatID                orchestrator.SeatID  `json:"seat_id"`
	SessionID             string               `json:"session_id"`
	InvocationID          string               `json:"invocation_id"`
	ProfileBinding        string               `json:"profile_binding"`
	SamplingBinding       string               `json:"sampling_binding"`
	BackendKind           BackendKind          `json:"backend_kind"`
	ProviderIdentity      string               `json:"provider_identity"`
	ModelID               string               `json:"model_id"`
	HarnessIdentity       string               `json:"harness_identity"`
	StructuredOutputMode  StructuredOutputMode `json:"structured_output_mode"`
	ToolCallMode          ToolCallMode         `json:"tool_call_mode"`
	ContextHash           string               `json:"context_hash"`
	RequestSHA256         string               `json:"request_sha256"`
	ResponseSHA256        string               `json:"response_sha256"`
	RetryIdentity         string               `json:"retry_identity"`
	CapabilityFingerprint string               `json:"capability_fingerprint"`
	CompletedAt           time.Time            `json:"completed_at"`
	CleanBaselineEligible bool                 `json:"clean_baseline_eligible"`
	BreakGlassUsed        bool                 `json:"break_glass_used"`
	BreakGlassGrantSHA256 string               `json:"break_glass_grant_sha256"`
}
