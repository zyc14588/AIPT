package modelgateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

var (
	identityRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,127}$`)
	versionRE  = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`)
	sha256RE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gitOIDRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	envNameRE  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	secretRE   = regexp.MustCompile(`(?i)(authorization|bearer|api[_-]?key|credential[_-]?(value|secret)|password|(^|[^a-z])(sk|dsk)-[a-z0-9_-]{8,})`)
	absPathRE  = regexp.MustCompile(`(^/)|(^[A-Za-z]:[\\/])`)
)

func validIdentity(field, value string) error {
	if !identityRE.MatchString(value) {
		return fmt.Errorf("%s must be a bounded identity", field)
	}
	return nil
}

func validVersion(field, value string) error {
	if !versionRE.MatchString(value) {
		return fmt.Errorf("%s must be a numeric version", field)
	}
	return nil
}

func validSHA(field, value string) error {
	if !sha256RE.MatchString(value) {
		return fmt.Errorf("%s must be lowercase SHA-256", field)
	}
	return nil
}

func canonicalDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func verifySamplingDigest(profile SamplingProfile) error {
	want := profile.SHA256
	profile.SHA256 = ""
	got, err := canonicalDigest(profile)
	if err != nil {
		return err
	}
	if want == "" || got != want {
		return errors.New("sampling digest mismatch")
	}
	return nil
}

func BindSamplingProfile(profile SamplingProfile) (SamplingProfile, error) {
	profile.SHA256 = ""
	if err := validateSamplingProfile(profile, false); err != nil {
		return SamplingProfile{}, newError(CodeInvalidProfile, "bind_sampling", profile.BindingID(), err)
	}
	digest, err := canonicalDigest(profile)
	if err != nil {
		return SamplingProfile{}, newError(CodeInvalidProfile, "bind_sampling", profile.BindingID(), err)
	}
	profile.SHA256 = digest
	return profile, nil
}

func ValidateSamplingProfile(profile SamplingProfile) error {
	if err := validateSamplingProfile(profile, true); err != nil {
		code := CodeInvalidProfile
		if strings.Contains(err.Error(), "digest") {
			code = CodeSamplingDrift
		}
		return newError(code, "validate_sampling", profile.BindingID(), err)
	}
	return nil
}

func validateSamplingProfile(profile SamplingProfile, requireDigest bool) error {
	if profile.Schema != SamplingProfileSchema {
		return errors.New("unknown sampling schema")
	}
	if err := validIdentity("sampling_id", profile.SamplingID); err != nil {
		return err
	}
	if err := validVersion("sampling_version", profile.SamplingVersion); err != nil {
		return err
	}
	if profile.Temperature < 0 || profile.Temperature > 2 {
		return errors.New("temperature outside governed range")
	}
	if profile.TopP <= 0 || profile.TopP > 1 {
		return errors.New("top_p outside governed range")
	}
	// The frozen B004 Harness closure serializes exactly these two provider
	// limits. A different otherwise-well-formed profile is unsupported until a
	// separately identified closure is certified; accepting it here would
	// falsely claim provider-side enforcement.
	if profile.MaxOutputTokens != 1024 || profile.MaxContextTokens != 8192 {
		return errors.New("token controls differ from the frozen Harness backend serialization")
	}
	got := append([]string(nil), profile.AppliedParameters...)
	sort.Strings(got)
	known := map[string]bool{
		"max_context_tokens": true, "max_output_tokens": true,
		"temperature": true, "top_p": true, "seed": true,
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			return errors.New("duplicate applied parameter")
		}
	}
	seen := map[string]bool{}
	for _, parameter := range got {
		if !known[parameter] {
			return errors.New("unknown applied parameter")
		}
		seen[parameter] = true
	}
	if strings.Join(profile.AppliedParameters, "\x00") != "max_context_tokens\x00max_output_tokens" {
		return errors.New("ACP v1 applies exactly the context and output byte-equivalent controls")
	}
	unsupported := append([]string(nil), profile.UnsupportedParameters...)
	sort.Strings(unsupported)
	wantUnsupported := []string{"temperature", "top_p"}
	if profile.Seed != nil {
		wantUnsupported = append(wantUnsupported, "seed")
		sort.Strings(wantUnsupported)
	}
	for index := 1; index < len(unsupported); index++ {
		if unsupported[index] == unsupported[index-1] {
			return errors.New("duplicate unsupported parameter")
		}
	}
	for _, parameter := range unsupported {
		if !known[parameter] || seen[parameter] {
			return errors.New("unknown or conflicting unsupported parameter")
		}
	}
	if strings.Join(profile.UnsupportedParameters, "\x00") != strings.Join(wantUnsupported, "\x00") {
		return errors.New("ACP v1 unsupported sampling parameters must be explicit and complete")
	}
	if requireDigest {
		return verifySamplingDigest(profile)
	}
	if profile.SHA256 != "" {
		return errors.New("sampling digest is computed by BindSamplingProfile")
	}
	return nil
}

func effectiveSamplingProjection(profile SamplingProfile) EffectiveSamplingProjection {
	return EffectiveSamplingProjection{
		Schema: EffectiveSamplingSchema, EnforcementIdentity: SamplingEnforcementIdentity,
		AppliedParameters:     append([]string(nil), profile.AppliedParameters...),
		UnsupportedParameters: append([]string(nil), profile.UnsupportedParameters...),
		MaxContextTokens:      profile.MaxContextTokens, MaxOutputTokens: profile.MaxOutputTokens,
		ContextUTF8ByteCeiling: profile.MaxContextTokens,
		OutputUTF8ByteCeiling:  profile.MaxOutputTokens,
	}
}

func validateEffectiveSampling(profile SamplingProfile, projection EffectiveSamplingProjection) error {
	want := effectiveSamplingProjection(profile)
	left, err := canonicalDigest(want)
	if err != nil {
		return err
	}
	right, err := canonicalDigest(projection)
	if err != nil {
		return err
	}
	if left != right {
		return errors.New("effective sampling projection drift")
	}
	return nil
}

func BindModelProfile(profile ModelProfile) (ModelProfile, error) {
	profile.SHA256 = ""
	if err := validateModelProfile(profile, false); err != nil {
		return ModelProfile{}, newError(profileValidationCode(err), "bind_profile", profile.BindingID(), err)
	}
	digest, err := canonicalDigest(profile)
	if err != nil {
		return ModelProfile{}, newError(CodeInvalidProfile, "bind_profile", profile.BindingID(), err)
	}
	profile.SHA256 = digest
	return profile, nil
}

func ValidateModelProfile(profile ModelProfile) error {
	if err := validateModelProfile(profile, true); err != nil {
		return newError(profileValidationCode(err), "validate_profile", profile.BindingID(), err)
	}
	return nil
}

func profileValidationCode(err error) Code {
	if err == nil {
		return ""
	}
	message := err.Error()
	if strings.Contains(message, "backend") {
		return CodeUnknownBackend
	}
	if strings.Contains(message, "credential") {
		return CodeCredentialPolicy
	}
	return CodeInvalidProfile
}

func validateModelProfile(profile ModelProfile, requireDigest bool) error {
	if profile.Schema != ModelProfileSchema {
		return errors.New("unknown model profile schema")
	}
	if err := validIdentity("profile_id", profile.ProfileID); err != nil {
		return err
	}
	if err := validVersion("profile_version", profile.ProfileVersion); err != nil {
		return err
	}
	switch profile.BackendKind {
	case BackendRemoteDeepSeek, BackendLocalLlamaCPP:
	default:
		return errors.New("unknown backend kind")
	}
	fields := []struct{ name, value string }{
		{name: "provider_identity", value: profile.ProviderIdentity},
		{name: "model_id", value: profile.ModelID},
		{name: "sampling_profile_id", value: profile.SamplingProfileID},
		{name: "certification_identity", value: profile.CertificationIdentity},
		{name: "context_policy.policy_id", value: profile.ContextPolicy.PolicyID},
		{name: "context_policy.reduction_policy_id", value: profile.ContextPolicy.ReductionPolicyID},
		{name: "data_egress_policy.policy_id", value: profile.DataEgressPolicy.PolicyID},
	}
	for _, field := range fields {
		if err := validIdentity(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validVersion("context_policy.policy_version", profile.ContextPolicy.PolicyVersion); err != nil {
		return err
	}
	if err := validVersion("data_egress_policy.policy_version", profile.DataEgressPolicy.PolicyVersion); err != nil {
		return err
	}
	if profile.ContextPolicy.MaxRequestBytes < 1024 || profile.ContextPolicy.MaxRequestBytes > 16<<20 ||
		profile.ContextPolicy.MaxContextBytes < 1024 || profile.ContextPolicy.MaxContextBytes > profile.ContextPolicy.MaxRequestBytes {
		return errors.New("context/request byte bounds are invalid")
	}
	if err := validateHarnessIdentity(profile.Harness); err != nil {
		return err
	}
	switch profile.StructuredOutputMode {
	case StructuredNative, StructuredPrompted, StructuredRepair:
	default:
		return errors.New("unknown structured-output mode")
	}
	switch profile.ToolCallMode {
	case ToolCallDisabled, ToolCallNative, ToolCallEmulated:
	default:
		return errors.New("unknown tool-call mode")
	}
	if len(profile.CapabilityRequirements) == 0 || len(profile.CapabilityRequirements) > 32 {
		return errors.New("capability requirements must be independent and bounded")
	}
	seenCapabilities := map[CapabilityName]bool{}
	for _, capability := range profile.CapabilityRequirements {
		if !knownCapability(capability) || seenCapabilities[capability] {
			return errors.New("unknown or duplicate capability requirement")
		}
		seenCapabilities[capability] = true
	}
	if err := validateEgressPolicy(profile.DataEgressPolicy); err != nil {
		return err
	}
	if profile.BackendKind == BackendRemoteDeepSeek {
		if profile.ProviderIdentity != "deepseek-official" || profile.ModelID != RemoteDeepSeekModelID {
			return errors.New("REMOTE_DEEPSEEK must bind the exact governed provider/model identity")
		}
		if profile.CredentialReference == nil || profile.LocalRuntimeIdentity != nil {
			return errors.New("remote credential reference is required and local runtime identity is forbidden")
		}
		if err := validateCredentialReference(*profile.CredentialReference); err != nil {
			return err
		}
		for _, classification := range profile.DataEgressPolicy.AllowedClassifications {
			if classification == orchestrator.ClassLocalOnlySecret || classification == orchestrator.ClassSystemInternal {
				return errors.New("remote profile cannot normally allowlist local-only or system-internal data")
			}
		}
	} else {
		if profile.ProviderIdentity != "llama.cpp" || profile.CredentialReference != nil || profile.LocalRuntimeIdentity == nil {
			return errors.New("LOCAL_LLAMACPP must bind llama.cpp and only a local runtime identity")
		}
		if err := validateLocalIdentity(*profile.LocalRuntimeIdentity); err != nil {
			return err
		}
	}
	if requireDigest {
		want := profile.SHA256
		profile.SHA256 = ""
		got, err := canonicalDigest(profile)
		if err != nil {
			return err
		}
		if want == "" || got != want {
			return errors.New("model profile digest mismatch")
		}
	} else if profile.SHA256 != "" {
		return errors.New("profile digest is computed by BindModelProfile")
	}
	return nil
}

func validateHarnessIdentity(identity HarnessIdentity) error {
	fields := []struct{ name, value string }{
		{name: "harness implementation", value: identity.Implementation},
		{name: "harness version", value: identity.Version},
		{name: "harness package digest", value: identity.PackageSHA256},
		{name: "harness protocol identity", value: identity.ProtocolIdentity},
		{name: "harness protocol version", value: identity.ProtocolVersion},
		{name: "harness capability fingerprint", value: identity.CapabilityFingerprint},
		{name: "harness runtime closure kind", value: identity.RuntimeClosureKind},
		{name: "harness runtime closure digest", value: identity.RuntimeClosureSHA256},
	}
	for _, field := range fields {
		if field.value == "" || !utf8.ValidString(field.value) || len(field.value) > 256 {
			return fmt.Errorf("%s is invalid", field.name)
		}
	}
	if !gitOIDRE.MatchString(identity.Commit) {
		return errors.New("harness commit must be exact lowercase git OID")
	}
	if err := validSHA("harness package_sha256", identity.PackageSHA256); err != nil {
		return err
	}
	if err := validSHA("harness capability_fingerprint", identity.CapabilityFingerprint); err != nil {
		return err
	}
	if identity.RuntimeClosureKind != HarnessRuntimeClosureKind {
		return errors.New("unrecognized Harness runtime closure kind")
	}
	if err := validSHA("harness runtime_closure_sha256", identity.RuntimeClosureSHA256); err != nil {
		return err
	}
	if identity.ProtocolIdentity != HarnessProtocolACP || identity.ProtocolVersion != HarnessProtocolVersionACP {
		return errors.New("unrecognized Harness protocol identity/version")
	}
	return nil
}

func validateCredentialReference(reference CredentialReference) error {
	if err := validIdentity("credential reference_id", reference.ReferenceID); err != nil {
		return err
	}
	switch reference.Kind {
	case CredentialEnvironment:
		if !envNameRE.MatchString(reference.Locator) {
			return errors.New("credential environment locator is invalid")
		}
	case CredentialEncryptedFile:
		if err := validIdentity("encrypted credential locator", reference.Locator); err != nil {
			return errors.New("encrypted credential locator must be an opaque reference, not a path")
		}
	default:
		return errors.New("unknown credential reference kind")
	}
	return nil
}

func validateLocalIdentity(identity LocalRuntimeIdentity) error {
	fields := []struct{ name, value string }{
		{name: "executable_reference", value: identity.ExecutableReference},
		{name: "version", value: identity.Version},
		{name: "gguf_reference", value: identity.GGUFReference},
		{name: "gguf_model_identity", value: identity.GGUFModelIdentity},
		{name: "quantization_identity", value: identity.QuantizationIdentity},
		{name: "template_identity", value: identity.TemplateIdentity},
		{name: "isolation_helper_reference", value: identity.IsolationHelperReference},
		{name: "hardware.architecture", value: identity.Hardware.Architecture},
		{name: "hardware.cpu_class", value: identity.Hardware.CPUClass},
		{name: "hardware.gpu_backend", value: identity.Hardware.GPUBackend},
		{name: "hardware.memory_class", value: identity.Hardware.MemoryClass},
	}
	for _, field := range fields {
		if err := validIdentity(field.name, field.value); err != nil {
			return err
		}
	}
	if err := validSHA("binary_sha256", identity.BinarySHA256); err != nil {
		return err
	}
	if err := validSHA("gguf_sha256", identity.GGUFSHA256); err != nil {
		return err
	}
	if err := validSHA("template_sha256", identity.TemplateSHA256); err != nil {
		return err
	}
	if identity.IsolationIdentity != LocalIsolationIdentity {
		return errors.New("local runtime requires the frozen Linux user/network namespace isolation identity")
	}
	if err := validSHA("isolation_helper_sha256", identity.IsolationHelperSHA256); err != nil {
		return err
	}
	if identity.Commit != "" && !gitOIDRE.MatchString(identity.Commit) {
		return errors.New("llama.cpp commit must be exact lowercase git OID when present")
	}
	if len(identity.LaunchParameters) == 0 || len(identity.LaunchParameters) > 64 {
		return errors.New("local launch parameters are missing or unbounded")
	}
	for _, argument := range identity.LaunchParameters {
		if argument == "" || len(argument) > 1024 || strings.IndexByte(argument, 0) >= 0 ||
			secretRE.MatchString(argument) || absPathRE.MatchString(argument) {
			return errors.New("local launch parameter is unsafe or contains a private path")
		}
	}
	return nil
}

func validateEgressPolicy(policy DataEgressPolicy) error {
	if len(policy.AllowedClassifications) == 0 || len(policy.AllowedClassifications) > 8 {
		return errors.New("egress classification allowlist is missing or unbounded")
	}
	seen := map[orchestrator.DataClassification]bool{}
	for _, classification := range policy.AllowedClassifications {
		if !knownClassification(classification) || seen[classification] {
			return errors.New("unknown or duplicate egress classification")
		}
		seen[classification] = true
	}
	if seen[orchestrator.ClassCredentialSecret] || seen[orchestrator.ClassHumanPrivateData] {
		return errors.New("credential and human-private classifications can never be allowlisted")
	}
	return nil
}

func knownClassification(value orchestrator.DataClassification) bool {
	switch value {
	case orchestrator.ClassPublic, orchestrator.ClassUnreleasedRemoteAllowed,
		orchestrator.ClassTableHiddenRemoteAllowed, orchestrator.ClassLocalOnlySecret,
		orchestrator.ClassHumanPrivateData, orchestrator.ClassCredentialSecret,
		orchestrator.ClassSystemInternal:
		return true
	default:
		return false
	}
}

func knownCapability(value CapabilityName) bool {
	switch value {
	case CapabilityBasicCompletion, CapabilityStructuredOutputNative,
		CapabilityStructuredOutputPrompted, CapabilityStructuredOutputRepair,
		CapabilityToolCallNative, CapabilityToolCallEmulated, CapabilityContextBudget,
		CapabilityRoleInvocation, CapabilityTransportStability,
		CapabilityVisibilityPolicyCompatible, CapabilityPromptInjectionBoundaryCompatible:
		return true
	default:
		return false
	}
}

func decodeExact(raw []byte, target any, limit int64) error {
	if len(raw) == 0 || int64(len(raw)) > limit {
		return errors.New("document is empty or exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("document contains trailing content")
	}
	return nil
}

// EvidenceSafe rejects common secret values and private absolute paths. It is
// intentionally applied after marshaling the exact public evidence object.
func EvidenceSafe(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return newError(CodeEvidenceUnsafe, "marshal_evidence", "", err)
	}
	text := string(raw)
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return newError(CodeEvidenceUnsafe, "decode_evidence", "", err)
	}
	if secretRE.MatchString(text) || evidenceContainsPrivatePath(decoded) {
		return newError(CodeEvidenceUnsafe, "validate_evidence", "", errors.New("unsafe evidence content"))
	}
	return nil
}

func evidenceContainsPrivatePath(value any) bool {
	switch typed := value.(type) {
	case string:
		return absPathRE.MatchString(typed) || strings.Contains(typed, `:\\`)
	case []any:
		for _, item := range typed {
			if evidenceContainsPrivatePath(item) {
				return true
			}
		}
	case map[string]any:
		for key, item := range typed {
			if evidenceContainsPrivatePath(key) || evidenceContainsPrivatePath(item) {
				return true
			}
		}
	}
	return false
}
