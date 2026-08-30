package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

const (
	ControlledCertificationSpecSchema   = "aipt.controlled-model-certification-spec/v1"
	ControlledCertificationResultSchema = "aipt.public.controlled-model-certification-result/v1"
	controlledLocalEndpointEnvironment  = "AIPT_LOCAL_LLAMACPP_ENDPOINT"
	controlledHarnessHomeEnvironment    = "DSH_HOME"
	controlledPersistenceEnvironment    = "AIPT_HARNESS_PERSISTENCE_ROOT"
	controlledCredentialLocator         = "DEEPSEEK_API_KEY"
	controlledHarnessImplementation     = "deepseek-harness"
	controlledHarnessVersion            = "0.1.0-rc.8"
	controlledHarnessCommit             = "141eb6fef83422698aef7a981029e843e8161534"
	controlledGGUFReference             = "GGUF-04"
	controlledGGUFSHA256                = "31756fca94beca71ea4b8706d6fdc896dab2a3c6376ab0c1863b98512a24f8d6"
	ACPOutputBudgetSchema               = "aipt.acp-output-budget/v1"
)

type ACPOutputBudget struct {
	Schema                          string `json:"schema"`
	MaxStdoutProtocolBytes          int64  `json:"max_stdout_protocol_bytes"`
	MaxNotificationBytes            int64  `json:"max_notification_bytes"`
	MaxResponseAndNotificationBytes int64  `json:"max_response_and_notification_bytes"`
	MaxStderrBytes                  int64  `json:"max_stderr_bytes"`
}

// HarnessChildArgumentDigest binds every private file argument consumed by
// the frozen Harness process. Paths remain private runtime input; only their
// digests can reach the public certification result.
type HarnessChildArgumentDigest struct {
	Index  int    `json:"index"`
	SHA256 string `json:"sha256"`
}

// HarnessChildProcessSpec is the private, exact ACP child process selected by
// an operator for one controlled certification attempt.
type HarnessChildProcessSpec struct {
	ExecutablePath       string                       `json:"executable_path"`
	ExecutableSHA256     string                       `json:"executable_sha256"`
	Arguments            []string                     `json:"arguments"`
	ArgumentFileDigests  []HarnessChildArgumentDigest `json:"argument_file_digests"`
	WorkingDirectory     string                       `json:"working_directory"`
	EnvironmentAllowlist []string                     `json:"environment_allowlist"`
	StartupTimeoutMS     int64                        `json:"startup_timeout_ms"`
	RequestTimeoutMS     int64                        `json:"request_timeout_ms"`
	ShutdownTimeoutMS    int64                        `json:"shutdown_timeout_ms"`
	OutputBudget         ACPOutputBudget              `json:"output_budget"`
}

// ControlledCertificationSpec is a private operator input. It contains local
// process paths but no credential value. The credential locator is carried only
// by ModelProfile.CredentialReference and is resolved write-only by the broker.
type ControlledCertificationSpec struct {
	Schema                   string                  `json:"schema"`
	CertificationID          string                  `json:"certification_id"`
	CertificationVersion     string                  `json:"certification_version"`
	EvidenceIdentity         string                  `json:"evidence_identity"`
	EnvironmentIdentity      string                  `json:"environment_identity"`
	Sampling                 SamplingProfile         `json:"sampling_profile"`
	Profile                  ModelProfile            `json:"model_profile"`
	AdapterExecutablePath    string                  `json:"adapter_executable_path"`
	AdapterExecutableSHA256  string                  `json:"adapter_executable_sha256"`
	AdapterEntrypointPath    string                  `json:"adapter_entrypoint_path"`
	AdapterEntrypointSHA256  string                  `json:"adapter_entrypoint_sha256"`
	AdapterWorkingDirectory  string                  `json:"adapter_working_directory"`
	AdapterStartupTimeoutMS  int64                   `json:"adapter_startup_timeout_ms"`
	AdapterShutdownTimeoutMS int64                   `json:"adapter_shutdown_timeout_ms"`
	HarnessChild             HarnessChildProcessSpec `json:"harness_child"`
	LocalRuntime             *LocalRuntimeConfig     `json:"local_runtime,omitempty"`
}

// ControlledCertificationResult is the only serializable output of a real
// certification attempt. It deliberately has no process paths, prompt or
// response bodies, environment snapshot, or credential-bearing field.
type ControlledCertificationResult struct {
	Schema                   string                `json:"schema"`
	Result                   string                `json:"result"`
	BackendKind              BackendKind           `json:"backend_kind"`
	Profile                  ModelProfile          `json:"model_profile"`
	Sampling                 SamplingProfile       `json:"sampling_profile"`
	Certification            Certification         `json:"certification"`
	Probe                    HarnessProbe          `json:"harness_probe"`
	CredentialValidation     *CredentialValidation `json:"credential_validation,omitempty"`
	RequestSHA256            string                `json:"request_sha256"`
	ResponseSHA256           string                `json:"response_sha256"`
	ResponseProtocolVersion  string                `json:"response_protocol_version"`
	RouteRecoveryOccurred    bool                  `json:"route_recovery_occurred"`
	CredentialValuesRecorded bool                  `json:"credential_values_recorded"`
	PrivatePathsRecorded     bool                  `json:"private_paths_recorded"`
}

type privateHarnessRoute struct {
	Schema                  string                  `json:"schema"`
	ProfileBinding          string                  `json:"profile_binding"`
	SamplingBinding         string                  `json:"sampling_binding"`
	BackendKind             BackendKind             `json:"backend_kind"`
	ProviderIdentity        string                  `json:"provider_identity"`
	ModelID                 string                  `json:"model_id"`
	HarnessIdentity         string                  `json:"harness_identity"`
	HarnessProtocolIdentity string                  `json:"harness_protocol_identity"`
	HarnessProtocolVersion  string                  `json:"harness_protocol_version"`
	CapabilityFingerprint   string                  `json:"capability_fingerprint"`
	StructuredOutputMode    StructuredOutputMode    `json:"structured_output_mode"`
	ToolCallMode            ToolCallMode            `json:"tool_call_mode"`
	SessionWorkingDirectory string                  `json:"session_working_directory"`
	Child                   HarnessChildProcessSpec `json:"child"`
}

func normalizeControlledProfiles(spec ControlledCertificationSpec) (ControlledCertificationSpec, error) {
	if spec.Schema != ControlledCertificationSpecSchema {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("unknown controlled-certification schema"))
	}
	if err := validIdentity("certification_id", spec.CertificationID); err != nil {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", "", err)
	}
	if err := validVersion("certification_version", spec.CertificationVersion); err != nil {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, err)
	}
	if err := validIdentity("evidence_identity", spec.EvidenceIdentity); err != nil {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, err)
	}
	if err := validIdentity("environment_identity", spec.EnvironmentIdentity); err != nil {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, err)
	}
	var err error
	if spec.Sampling.SHA256 == "" {
		spec.Sampling, err = BindSamplingProfile(spec.Sampling)
	} else {
		err = ValidateSamplingProfile(spec.Sampling)
	}
	if err != nil {
		return ControlledCertificationSpec{}, err
	}
	if spec.Profile.SHA256 == "" {
		spec.Profile, err = BindModelProfile(spec.Profile)
	} else {
		err = ValidateModelProfile(spec.Profile)
	}
	if err != nil {
		return ControlledCertificationSpec{}, err
	}
	if spec.Profile.SamplingProfileID != spec.Sampling.BindingID() ||
		spec.Profile.CertificationIdentity != spec.CertificationID+"@"+spec.CertificationVersion {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("profile, sampling, and certification bindings differ"))
	}
	if spec.Profile.StructuredOutputMode != StructuredPrompted || spec.Profile.ToolCallMode != ToolCallDisabled {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("minimum certification requires prompted structured output with tools disabled"))
	}
	required := append([]CapabilityName(nil), spec.Profile.CapabilityRequirements...)
	sort.Slice(required, func(i, j int) bool { return required[i] < required[j] })
	want := []CapabilityName{CapabilityBasicCompletion, CapabilityRoleInvocation, CapabilityStructuredOutputPrompted}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !slices.Equal(required, want) {
		return ControlledCertificationSpec{}, newError(CodeCertificationMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("minimum certification capability set is not exact"))
	}
	if spec.Profile.Harness.Implementation != controlledHarnessImplementation ||
		spec.Profile.Harness.Version != controlledHarnessVersion ||
		spec.Profile.Harness.Commit != controlledHarnessCommit {
		return ControlledCertificationSpec{}, newError(CodeHarnessIdentityMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("controlled Harness identity differs from the Owner-approved freeze"))
	}
	if spec.AdapterStartupTimeoutMS < 1 || spec.AdapterStartupTimeoutMS > 600_000 ||
		spec.AdapterShutdownTimeoutMS < 1 || spec.AdapterShutdownTimeoutMS > 60_000 {
		return ControlledCertificationSpec{}, newError(CodeHarnessTransport, "validate_controlled_spec", spec.CertificationID, errors.New("adapter timeouts are invalid"))
	}
	if err := verifyRegularFileDigest(spec.AdapterExecutablePath, spec.AdapterExecutableSHA256, true); err != nil {
		return ControlledCertificationSpec{}, newError(CodeHarnessTransport, "verify_adapter_executable", spec.CertificationID, err)
	}
	if err := verifyRegularFileDigest(spec.AdapterEntrypointPath, spec.AdapterEntrypointSHA256, false); err != nil {
		return ControlledCertificationSpec{}, newError(CodeHarnessTransport, "verify_adapter_entrypoint", spec.CertificationID, err)
	}
	if info, statErr := os.Stat(spec.AdapterWorkingDirectory); statErr != nil || !info.IsDir() {
		return ControlledCertificationSpec{}, newError(CodeHarnessTransport, "verify_adapter_workdir", spec.CertificationID, errors.New("adapter working directory unavailable"))
	}
	if err := validateHarnessChild(spec.Profile, spec.HarnessChild); err != nil {
		return ControlledCertificationSpec{}, err
	}
	if spec.AdapterShutdownTimeoutMS < spec.HarnessChild.ShutdownTimeoutMS+1_000 {
		return ControlledCertificationSpec{}, newError(CodeHarnessTransport, "validate_controlled_spec", spec.CertificationID, errors.New("adapter shutdown bound must contain Harness child shutdown"))
	}
	if spec.Profile.BackendKind == BackendRemoteDeepSeek {
		if spec.LocalRuntime != nil {
			return ControlledCertificationSpec{}, newError(CodeLocalProcessMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("remote certification has a local runtime"))
		}
		if spec.Profile.CredentialReference == nil ||
			spec.Profile.CredentialReference.Kind != CredentialEnvironment ||
			spec.Profile.CredentialReference.Locator != controlledCredentialLocator {
			return ControlledCertificationSpec{}, newError(CodeCredentialPolicy, "validate_controlled_spec", spec.CertificationID, errors.New("remote certification credential reference differs from the Owner-approved binding"))
		}
	} else if spec.LocalRuntime == nil || spec.LocalRuntime.ProfileBinding != spec.Profile.BindingID() ||
		spec.Profile.LocalRuntimeIdentity == nil ||
		spec.Profile.LocalRuntimeIdentity.GGUFReference != controlledGGUFReference ||
		spec.Profile.LocalRuntimeIdentity.GGUFSHA256 != controlledGGUFSHA256 {
		return ControlledCertificationSpec{}, newError(CodeLocalProcessMismatch, "validate_controlled_spec", spec.CertificationID, errors.New("local certification lacks its exact runtime binding"))
	}
	return spec, nil
}

func validateHarnessChild(profile ModelProfile, child HarnessChildProcessSpec) error {
	if child.ExecutablePath == "" || child.WorkingDirectory == "" || len(child.Arguments) == 0 ||
		child.StartupTimeoutMS < 1 || child.StartupTimeoutMS > 600_000 ||
		child.RequestTimeoutMS < 1 || child.RequestTimeoutMS > 3_600_000 ||
		child.ShutdownTimeoutMS < 1 || child.ShutdownTimeoutMS > 60_000 {
		return newError(CodeHarnessTransport, "validate_harness_child", profile.BindingID(), errors.New("complete bounded Harness child specification required"))
	}
	if child.OutputBudget.Schema != ACPOutputBudgetSchema ||
		child.OutputBudget.MaxStdoutProtocolBytes < 1 || child.OutputBudget.MaxStdoutProtocolBytes > 1_073_741_824 ||
		child.OutputBudget.MaxNotificationBytes < 1 || child.OutputBudget.MaxNotificationBytes > 1_073_741_824 ||
		child.OutputBudget.MaxResponseAndNotificationBytes < 1 || child.OutputBudget.MaxResponseAndNotificationBytes > 1_073_741_824 ||
		child.OutputBudget.MaxStderrBytes < 1 || child.OutputBudget.MaxStderrBytes > 1_073_741_824 {
		return newError(CodeHarnessTransport, "validate_harness_output_budget", profile.BindingID(), errors.New("explicit versioned ACP output budget required"))
	}
	if err := verifyRegularFileDigest(child.ExecutablePath, child.ExecutableSHA256, true); err != nil {
		return newError(CodeHarnessTransport, "verify_harness_executable", profile.BindingID(), err)
	}
	seenIndexes := map[int]bool{}
	for _, item := range child.ArgumentFileDigests {
		if item.Index < 0 || item.Index >= len(child.Arguments) || seenIndexes[item.Index] {
			return newError(CodeHarnessTransport, "validate_harness_argument_digest", profile.BindingID(), errors.New("Harness argument digest index is invalid"))
		}
		seenIndexes[item.Index] = true
		if err := verifyRegularFileDigest(child.Arguments[item.Index], item.SHA256, false); err != nil {
			return newError(CodeHarnessTransport, "verify_harness_argument_file", profile.BindingID(), err)
		}
	}
	for index, argument := range child.Arguments {
		if argument == "" || len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 || secretRE.MatchString(argument) {
			return newError(CodeHarnessTransport, "validate_harness_argument", profile.BindingID(), errors.New("unsafe Harness argument"))
		}
		if filepath.IsAbs(argument) && !seenIndexes[index] {
			return newError(CodeHarnessTransport, "validate_harness_argument", profile.BindingID(), errors.New("private Harness file argument lacks a digest"))
		}
	}
	if info, err := os.Stat(child.WorkingDirectory); err != nil || !info.IsDir() {
		return newError(CodeHarnessTransport, "verify_harness_workdir", profile.BindingID(), errors.New("Harness working directory unavailable"))
	}
	seenEnvironment := map[string]bool{}
	for _, name := range child.EnvironmentAllowlist {
		if !envNameRE.MatchString(name) || seenEnvironment[name] {
			return newError(CodeHarnessTransport, "validate_harness_environment", profile.BindingID(), errors.New("Harness environment allowlist is invalid"))
		}
		seenEnvironment[name] = true
	}
	for name := range seenEnvironment {
		allowed := name == "LANG" || name == "LC_ALL" || name == "TZ" || name == "PATH" ||
			name == controlledHarnessHomeEnvironment || name == controlledPersistenceEnvironment
		if profile.BackendKind == BackendRemoteDeepSeek {
			allowed = allowed || name == controlledCredentialLocator
		} else {
			allowed = allowed || name == controlledLocalEndpointEnvironment
		}
		if !allowed {
			return newError(CodeHarnessTransport, "validate_harness_environment", profile.BindingID(), errors.New("Harness environment name is outside the closed allowlist"))
		}
	}
	if !seenEnvironment[controlledHarnessHomeEnvironment] || !seenEnvironment[controlledPersistenceEnvironment] {
		return newError(CodeHarnessTransport, "validate_harness_environment", profile.BindingID(), errors.New("controlled Harness private roots are not bound"))
	}
	if profile.BackendKind == BackendRemoteDeepSeek {
		if !seenEnvironment[controlledCredentialLocator] || seenEnvironment[controlledLocalEndpointEnvironment] {
			return newError(CodeCredentialPolicy, "validate_harness_environment", profile.BindingID(), errors.New("remote Harness credential binding is not exact"))
		}
	} else if !seenEnvironment[controlledLocalEndpointEnvironment] || seenEnvironment[controlledCredentialLocator] {
		return newError(CodeHarnessTransport, "validate_harness_environment", profile.BindingID(), errors.New("local Harness endpoint binding is not exact"))
	}
	return nil
}

func writePrivateHarnessRoute(spec ControlledCertificationSpec) (string, string, func(), error) {
	directory, err := os.MkdirTemp("", "aipt-controlled-certification-")
	if err != nil {
		return "", "", func() {}, newError(CodeHarnessTransport, "create_private_route", spec.CertificationID, err)
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	route := privateHarnessRoute{
		Schema: "aipt.harness-route/v1", ProfileBinding: spec.Profile.BindingID(),
		SamplingBinding: spec.Sampling.BindingID(), BackendKind: spec.Profile.BackendKind,
		ProviderIdentity: spec.Profile.ProviderIdentity, ModelID: spec.Profile.ModelID,
		HarnessIdentity:         spec.Profile.Harness.BindingID(),
		HarnessProtocolIdentity: spec.Profile.Harness.ProtocolIdentity,
		HarnessProtocolVersion:  spec.Profile.Harness.ProtocolVersion,
		CapabilityFingerprint:   spec.Profile.Harness.CapabilityFingerprint,
		StructuredOutputMode:    spec.Profile.StructuredOutputMode, ToolCallMode: spec.Profile.ToolCallMode,
		SessionWorkingDirectory: spec.HarnessChild.WorkingDirectory, Child: spec.HarnessChild,
	}
	raw, err := json.Marshal(route)
	if err != nil {
		cleanup()
		return "", "", func() {}, newError(CodeHarnessTransport, "encode_private_route", spec.CertificationID, err)
	}
	path := filepath.Join(directory, "route.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		cleanup()
		return "", "", func() {}, newError(CodeHarnessTransport, "write_private_route", spec.CertificationID, err)
	}
	digest := sha256.Sum256(raw)
	return path, hex.EncodeToString(digest[:]), cleanup, nil
}

func controlledClaims() []CapabilityClaim {
	return []CapabilityClaim{
		{Name: CapabilityBasicCompletion, Status: ClaimCertified},
		{Name: CapabilityStructuredOutputNative, Status: ClaimNotCertified},
		{Name: CapabilityStructuredOutputPrompted, Status: ClaimCertified},
		{Name: CapabilityStructuredOutputRepair, Status: ClaimUntested},
		{Name: CapabilityToolCallNative, Status: ClaimNotCertified},
		{Name: CapabilityToolCallEmulated, Status: ClaimUntested},
		{Name: CapabilityContextBudget, Status: ClaimUntested},
		{Name: CapabilityRoleInvocation, Status: ClaimCertified},
		{Name: CapabilityTransportStability, Status: ClaimUntested},
		{Name: CapabilityVisibilityPolicyCompatible, Status: ClaimUntested},
		{Name: CapabilityPromptInjectionBoundaryCompatible, Status: ClaimUntested},
	}
}

func certificationRequest(profile ModelProfile, sampling SamplingProfile) (HarnessRequest, error) {
	seat := orchestrator.SeatGM
	if profile.BackendKind == BackendLocalLlamaCPP {
		seat = orchestrator.SeatPlayer1
	}
	runID := "b004-controlled-certification"
	sessionID := "session-b004-" + strings.ToLower(strings.ReplaceAll(string(profile.BackendKind), "_", "-"))
	requestID := "invoke-b004-" + strings.ToLower(strings.ReplaceAll(string(profile.BackendKind), "_", "-"))
	prepared, err := json.Marshal(map[string]any{
		"schema":          "aipt.controlled-certification-context/v1",
		"classification":  "PUBLIC",
		"probe":           "Return a speech-only acknowledgement bound to this invocation.",
		"available_tools": []string{},
	})
	if err != nil {
		return HarnessRequest{}, err
	}
	preparedDigest := sha256.Sum256(prepared)
	request := HarnessRequest{
		Schema: HarnessRequestSchema, ProtocolVersion: "1", RequestID: requestID,
		ProfileBinding: profile.BindingID(), SamplingBinding: sampling.BindingID(),
		ExpectedModelID: profile.ModelID, HarnessIdentity: profile.Harness.BindingID(),
		BackendKind: profile.BackendKind, ProviderIdentity: profile.ProviderIdentity,
		StructuredMode: profile.StructuredOutputMode, ToolMode: profile.ToolCallMode,
		SamplingProfile: sampling,
		Session: orchestrator.Session{
			Schema: orchestrator.SessionSchema, SessionID: sessionID, RunID: runID,
			SeatID: seat, Generation: 1,
		},
		Invocation: orchestrator.InvocationRequest{
			InvocationID: requestID, RunID: runID, SeatID: seat, SessionID: sessionID,
			Kind: orchestrator.InvocationOriginal, Attempt: 1,
		},
		PreparedContext: prepared,
		ContextReduction: ContextReduction{
			Schema: ContextReductionSchema, PolicyID: profile.ContextPolicy.ReductionPolicyID,
			OriginalContextHash:   hex.EncodeToString(preparedDigest[:]),
			PreparedContextSHA256: hex.EncodeToString(preparedDigest[:]),
			OriginalBytes:         len(prepared), PreparedBytes: len(prepared),
			RemovedEventIDs: []string{}, RemovedSourceIDs: []string{},
		},
	}
	request.RequestSHA256, err = requestDigest(request)
	if err != nil {
		return HarnessRequest{}, err
	}
	return request, nil
}

func observeControlledCertification(
	ctx context.Context,
	spec ControlledCertificationSpec,
	transport HarnessTransport,
	credential *CredentialValidation,
	clock func() time.Time,
) (ControlledCertificationResult, error) {
	probe, err := transport.Probe(ctx, spec.Profile, spec.Sampling)
	if err != nil {
		return ControlledCertificationResult{}, err
	}
	if err := validateProbe(spec.Profile, probe); err != nil {
		return ControlledCertificationResult{}, err
	}
	request, err := certificationRequest(spec.Profile, spec.Sampling)
	if err != nil {
		return ControlledCertificationResult{}, newError(CodeCertificationMismatch, "build_certification_request", spec.CertificationID, err)
	}
	result, err := transport.Invoke(ctx, spec.Profile, spec.Sampling, request)
	if err != nil {
		return ControlledCertificationResult{}, err
	}
	responseRaw, err := validateHarnessResult(spec.Profile, request, result)
	if err != nil {
		return ControlledCertificationResult{}, err
	}
	var response orchestrator.AgentResponse
	if err := decodeExact(responseRaw, &response, 1<<20); err != nil {
		return ControlledCertificationResult{}, newError(CodeHarnessResponseInvalid, "decode_certification_response", request.RequestID, err)
	}
	if response.Schema != orchestrator.AgentResponseSchema || response.InvocationID != request.RequestID ||
		response.RunID != request.Invocation.RunID || response.SeatID != request.Invocation.SeatID ||
		response.SessionID != request.Session.SessionID || response.Metadata.ProtocolVersion != "v1" ||
		response.Speech == "" || len([]rune(response.Speech)) > 20_000 || response.Action != nil ||
		response.Metadata.SpeechActionClaim != nil || result.RouteRecoveryOccurred {
		return ControlledCertificationResult{}, newError(CodeHarnessResponseInvalid, "validate_certification_response", request.RequestID, errors.New("controlled response is not an exact speech-only v1 result"))
	}
	tuple, err := BindExecutionTuple(ExecutionTuple{
		Schema: ExecutionTupleSchema, BackendKind: spec.Profile.BackendKind,
		ProviderIdentity: spec.Profile.ProviderIdentity, ModelID: spec.Profile.ModelID,
		ModelProfileBinding: spec.Profile.BindingID(), SamplingProfileBinding: spec.Sampling.BindingID(),
		HarnessIdentity: spec.Profile.Harness.BindingID(), HarnessProtocolIdentity: spec.Profile.Harness.ProtocolIdentity,
		HarnessProtocolVersion: spec.Profile.Harness.ProtocolVersion,
		StructuredOutputMode:   spec.Profile.StructuredOutputMode, ToolCallMode: spec.Profile.ToolCallMode,
		RequestContractVersion: "1", CapabilityFingerprint: spec.Profile.Harness.CapabilityFingerprint,
		EnvironmentIdentity: spec.EnvironmentIdentity, LocalRuntimeIdentity: spec.Profile.LocalRuntimeIdentity,
	})
	if err != nil {
		return ControlledCertificationResult{}, err
	}
	observedAt := result.CompletedAt.UTC()
	if observedAt.IsZero() {
		observedAt = clock().UTC()
	}
	eligibility := "NOT_CLAIMED"
	if spec.Profile.BackendKind == BackendLocalLlamaCPP {
		eligibility = "NOT_GRANTED_DEFER_003"
	}
	certification, err := BindCertification(Certification{
		Schema: CertificationSchema, CertificationID: spec.CertificationID,
		CertificationVersion: spec.CertificationVersion, ProfileBinding: spec.Profile.BindingID(),
		SamplingBinding: spec.Sampling.BindingID(), Result: "PASS", Kind: CertificationControlledReal,
		MinimumCertification: true, RealModelCalls: 1, EvidenceIdentity: spec.EvidenceIdentity,
		ProductionRoleEligibility: eligibility, Claims: controlledClaims(), ExecutionTuple: tuple,
		ObservedAt: observedAt,
	}, spec.Profile, spec.Sampling)
	if err != nil {
		return ControlledCertificationResult{}, err
	}
	return ControlledCertificationResult{
		Schema: ControlledCertificationResultSchema, Result: "PASS", BackendKind: spec.Profile.BackendKind,
		Profile: spec.Profile, Sampling: spec.Sampling, Certification: certification, Probe: probe,
		CredentialValidation: credential, RequestSHA256: request.RequestSHA256,
		ResponseSHA256: result.ResponseSHA256, ResponseProtocolVersion: response.Metadata.ProtocolVersion,
		RouteRecoveryOccurred:    result.RouteRecoveryOccurred,
		CredentialValuesRecorded: false, PrivatePathsRecorded: false,
	}, nil
}

// RunControlledCertification performs exactly one real, non-qualification
// model call through the governed AIPT adapter and frozen ACP Harness route.
// It returns only the secret-free public result and always closes every child.
func RunControlledCertification(
	ctx context.Context,
	input ControlledCertificationSpec,
	broker CredentialBroker,
	clock func() time.Time,
) (ControlledCertificationResult, error) {
	if ctx == nil {
		return ControlledCertificationResult{}, newError(CodeCertificationMismatch, "controlled_certification", input.CertificationID, errors.New("context required"))
	}
	spec, err := normalizeControlledProfiles(input)
	if err != nil {
		return ControlledCertificationResult{}, err
	}
	if clock == nil {
		clock = time.Now
	}
	var credential *CredentialValidation
	if spec.Profile.BackendKind == BackendRemoteDeepSeek {
		if broker == nil {
			return ControlledCertificationResult{}, newError(CodeCredentialUnavailable, "controlled_certification", spec.CertificationID, errors.New("credential broker required"))
		}
		validation, validateErr := broker.Validate(ctx, *spec.Profile.CredentialReference)
		if validateErr != nil {
			return ControlledCertificationResult{}, validateErr
		}
		if validation.ReferenceID != spec.Profile.CredentialReference.ReferenceID ||
			validation.Kind != spec.Profile.CredentialReference.Kind || validation.State != "VALID" ||
			len(validation.Metadata) != 2 || validation.Metadata["source"] != "environment" ||
			validation.Metadata["exposure"] != "write-only" {
			return ControlledCertificationResult{}, newError(CodeCredentialPolicy, "controlled_certification", spec.CertificationID, errors.New("credential broker returned non-canonical public validation metadata"))
		}
		credential = &CredentialValidation{
			ReferenceID: validation.ReferenceID,
			Kind:        validation.Kind,
			State:       "VALID",
			Metadata:    map[string]string{"source": "environment", "exposure": "write-only"},
		}
	}

	var manager *ManagedLlama
	adapterEnvironment := map[string]string{}
	if spec.Profile.BackendKind == BackendLocalLlamaCPP {
		local := spec.LocalRuntime
		manager, err = NewManagedLlama(spec.Profile, ManagedLlamaSpec{
			ExecutablePath: local.ExecutablePath, GGUFPath: local.GGUFPath,
			AdditionalArguments: append([]string(nil), local.AdditionalArguments...),
			Environment:         cloneStringMap(local.Environment), WorkingDirectory: local.WorkingDirectory,
			StartupTimeout:  time.Duration(local.StartupTimeoutMS) * time.Millisecond,
			ShutdownTimeout: time.Duration(local.ShutdownTimeoutMS) * time.Millisecond,
		})
		if err != nil {
			return ControlledCertificationResult{}, err
		}
		if err = manager.Start(ctx); err != nil {
			return ControlledCertificationResult{}, err
		}
		endpoint, endpointErr := manager.Endpoint()
		if endpointErr != nil {
			_ = manager.Stop(context.Background())
			return ControlledCertificationResult{}, endpointErr
		}
		adapterEnvironment[controlledLocalEndpointEnvironment] = endpoint.String()
	}

	routePath, routeDigest, cleanupRoute, err := writePrivateHarnessRoute(spec)
	if err != nil {
		if manager != nil {
			_ = manager.Stop(context.Background())
		}
		return ControlledCertificationResult{}, err
	}
	defer cleanupRoute()
	privateRoot := filepath.Dir(routePath)
	harnessHome := filepath.Join(privateRoot, "harness-home")
	persistenceRoot := filepath.Join(privateRoot, "sessions")
	if err := os.Mkdir(harnessHome, 0o700); err != nil {
		if manager != nil {
			_ = manager.Stop(context.Background())
		}
		return ControlledCertificationResult{}, newError(CodeHarnessTransport, "create_private_harness_home", spec.CertificationID, err)
	}
	if err := os.Mkdir(persistenceRoot, 0o700); err != nil {
		if manager != nil {
			_ = manager.Stop(context.Background())
		}
		return ControlledCertificationResult{}, newError(CodeHarnessTransport, "create_private_persistence", spec.CertificationID, err)
	}
	adapterEnvironment[controlledHarnessHomeEnvironment] = harnessHome
	adapterEnvironment[controlledPersistenceEnvironment] = persistenceRoot
	transport, err := NewAdapterProcessTransport([]ModelProfile{spec.Profile}, []AdapterRouteSpec{{
		ProfileBinding: spec.Profile.BindingID(), ExecutablePath: spec.AdapterExecutablePath,
		ExecutableSHA256: spec.AdapterExecutableSHA256, AdapterEntrypointPath: spec.AdapterEntrypointPath,
		AdapterEntrypointSHA256: spec.AdapterEntrypointSHA256,
		RouteConfigPath:         routePath, RouteConfigSHA256: routeDigest,
		Environment: adapterEnvironment, WorkingDirectory: spec.AdapterWorkingDirectory,
		StartupTimeout:  time.Duration(spec.AdapterStartupTimeoutMS) * time.Millisecond,
		ShutdownTimeout: time.Duration(spec.AdapterShutdownTimeoutMS) * time.Millisecond,
	}}, broker)
	if err != nil {
		if manager != nil {
			_ = manager.Stop(context.Background())
		}
		return ControlledCertificationResult{}, err
	}
	result, runErr := observeControlledCertification(ctx, spec, transport, credential, clock)
	closeErr := transport.Close(context.Background())
	var stopErr error
	if manager != nil {
		if eligibilityErr := manager.FormalEligibilityError(); eligibilityErr != nil && runErr == nil {
			runErr = eligibilityErr
		}
		stopErr = manager.Stop(context.Background())
	}
	if runErr != nil {
		return ControlledCertificationResult{}, runErr
	}
	if closeErr != nil {
		return ControlledCertificationResult{}, newError(CodeHarnessTransport, "close_controlled_harness", spec.CertificationID, closeErr)
	}
	if stopErr != nil {
		return ControlledCertificationResult{}, stopErr
	}
	return result, nil
}
