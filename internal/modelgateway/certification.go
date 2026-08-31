package modelgateway

import (
	"errors"
	"strings"
)

func BindExecutionTuple(tuple ExecutionTuple) (ExecutionTuple, error) {
	tuple.SHA256 = ""
	if err := validateExecutionTuple(tuple, nil, nil, false); err != nil {
		return ExecutionTuple{}, newError(CodeCertificationMismatch, "bind_execution_tuple", tuple.ModelProfileBinding, err)
	}
	digest, err := canonicalDigest(tuple)
	if err != nil {
		return ExecutionTuple{}, newError(CodeCertificationMismatch, "bind_execution_tuple", tuple.ModelProfileBinding, err)
	}
	tuple.SHA256 = digest
	return tuple, nil
}

func validateExecutionTuple(tuple ExecutionTuple, profile *ModelProfile, sampling *SamplingProfile, requireDigest bool) error {
	if tuple.Schema != ExecutionTupleSchema {
		return errors.New("unknown execution tuple schema")
	}
	fields := []struct{ name, value string }{
		{name: "provider_identity", value: tuple.ProviderIdentity},
		{name: "model_id", value: tuple.ModelID},
		{name: "model_profile_binding", value: tuple.ModelProfileBinding},
		{name: "sampling_profile_binding", value: tuple.SamplingProfileBinding},
		{name: "harness_identity", value: tuple.HarnessIdentity},
		{name: "harness_protocol_identity", value: tuple.HarnessProtocolIdentity},
		{name: "harness_protocol_version", value: tuple.HarnessProtocolVersion},
		{name: "request_contract_version", value: tuple.RequestContractVersion},
		{name: "environment_identity", value: tuple.EnvironmentIdentity},
	}
	for _, field := range fields {
		if err := validIdentity(field.name, field.value); err != nil {
			return err
		}
	}
	if tuple.RequestContractVersion != "1" {
		return errors.New("unknown request contract version")
	}
	switch tuple.StructuredOutputMode {
	case StructuredNative, StructuredPrompted, StructuredRepair:
	default:
		return errors.New("unknown structured-output mode")
	}
	switch tuple.ToolCallMode {
	case ToolCallDisabled, ToolCallNative, ToolCallEmulated:
	default:
		return errors.New("unknown tool-call mode")
	}
	if err := validSHA("capability_fingerprint", tuple.CapabilityFingerprint); err != nil {
		return err
	}
	if err := validSHA("requested_sampling_sha256", tuple.RequestedSamplingSHA256); err != nil {
		return err
	}
	if err := validSHA("backend_serialized_request_sha256", tuple.BackendSerializedRequestSHA256); err != nil {
		return err
	}
	projection := tuple.EffectiveSampling
	if projection.Schema != EffectiveSamplingSchema || projection.EnforcementIdentity != SamplingEnforcementIdentity ||
		projection.MaxContextTokens < 1 || projection.MaxOutputTokens < 1 ||
		projection.ContextUTF8ByteCeiling != projection.MaxContextTokens ||
		projection.OutputUTF8ByteCeiling != projection.MaxOutputTokens ||
		strings.Join(projection.AppliedParameters, "\x00") != "max_context_tokens\x00max_output_tokens" ||
		strings.Join(projection.UnsupportedParameters, "\x00") != strings.Join(tuple.UnsupportedSamplingParameters, "\x00") {
		return errors.New("execution tuple effective sampling projection is invalid")
	}
	switch tuple.BackendKind {
	case BackendRemoteDeepSeek:
		if tuple.ProviderIdentity != "deepseek-official" || tuple.ModelID != RemoteDeepSeekModelID || tuple.LocalRuntimeIdentity != nil {
			return errors.New("remote execution tuple cannot contain a local runtime identity")
		}
	case BackendLocalLlamaCPP:
		if tuple.ProviderIdentity != "llama.cpp" || tuple.LocalRuntimeIdentity == nil {
			return errors.New("local execution tuple requires full local runtime identity")
		}
		if err := validateLocalIdentity(*tuple.LocalRuntimeIdentity); err != nil {
			return err
		}
	default:
		return errors.New("unknown backend kind")
	}
	if profile != nil {
		if tuple.BackendKind != profile.BackendKind || tuple.ProviderIdentity != profile.ProviderIdentity ||
			tuple.ModelID != profile.ModelID || tuple.ModelProfileBinding != profile.BindingID() ||
			tuple.SamplingProfileBinding != profile.SamplingProfileID ||
			tuple.HarnessIdentity != profile.Harness.BindingID() ||
			tuple.HarnessProtocolIdentity != profile.Harness.ProtocolIdentity ||
			tuple.HarnessProtocolVersion != profile.Harness.ProtocolVersion ||
			tuple.StructuredOutputMode != profile.StructuredOutputMode ||
			tuple.ToolCallMode != profile.ToolCallMode ||
			tuple.CapabilityFingerprint != profile.Harness.CapabilityFingerprint {
			return errors.New("execution tuple does not exactly bind the model profile")
		}
		if profile.BackendKind == BackendLocalLlamaCPP && !equalLocalIdentity(tuple.LocalRuntimeIdentity, profile.LocalRuntimeIdentity) {
			return errors.New("execution tuple local runtime identity drift")
		}
	}
	if sampling != nil {
		if tuple.SamplingProfileBinding != sampling.BindingID() || tuple.RequestedSamplingSHA256 != sampling.SHA256 ||
			strings.Join(tuple.UnsupportedSamplingParameters, "\x00") != strings.Join(sampling.UnsupportedParameters, "\x00") {
			return errors.New("execution tuple sampling profile drift")
		}
		if err := validateEffectiveSampling(*sampling, tuple.EffectiveSampling); err != nil {
			return err
		}
	}
	if requireDigest {
		want := tuple.SHA256
		tuple.SHA256 = ""
		got, err := canonicalDigest(tuple)
		if err != nil {
			return err
		}
		if want == "" || got != want {
			return errors.New("execution tuple digest mismatch")
		}
	} else if tuple.SHA256 != "" {
		return errors.New("execution tuple digest must be computed")
	}
	return nil
}

func equalLocalIdentity(left, right *LocalRuntimeIdentity) bool {
	if left == nil || right == nil {
		return left == right
	}
	ld, _ := canonicalDigest(left)
	rd, _ := canonicalDigest(right)
	return ld == rd
}

func BindCertification(certification Certification, profile ModelProfile, sampling SamplingProfile) (Certification, error) {
	certification.SHA256 = ""
	if certification.ExecutionTuple.SHA256 == "" {
		return Certification{}, newError(CodeCertificationMismatch, "bind_certification", certification.BindingID(), errors.New("execution tuple must already be bound"))
	}
	if err := validateCertification(certification, profile, sampling, false); err != nil {
		return Certification{}, newError(CodeCertificationMismatch, "bind_certification", certification.BindingID(), err)
	}
	digest, err := canonicalDigest(certification)
	if err != nil {
		return Certification{}, newError(CodeCertificationMismatch, "bind_certification", certification.BindingID(), err)
	}
	certification.SHA256 = digest
	return certification, nil
}

func ValidateCertification(certification Certification, registry *Registry) error {
	if registry == nil {
		return newError(CodeCertificationMissing, "validate_certification", certification.BindingID(), errors.New("registry required"))
	}
	profile, exists := registry.profiles[certification.ProfileBinding]
	if !exists {
		return newError(CodeCertificationMismatch, "validate_certification", certification.BindingID(), errors.New("profile binding is absent"))
	}
	sampling, exists := registry.samplings[certification.SamplingBinding]
	if !exists {
		return newError(CodeCertificationMismatch, "validate_certification", certification.BindingID(), errors.New("sampling binding is absent"))
	}
	if err := validateCertification(certification, profile, sampling, true); err != nil {
		return newError(CodeCertificationMismatch, "validate_certification", certification.BindingID(), err)
	}
	return nil
}

func validateCertification(certification Certification, profile ModelProfile, sampling SamplingProfile, requireDigest bool) error {
	if certification.Schema != CertificationSchema {
		return errors.New("unknown certification schema")
	}
	if err := validIdentity("certification_id", certification.CertificationID); err != nil {
		return err
	}
	if err := validVersion("certification_version", certification.CertificationVersion); err != nil {
		return err
	}
	if certification.ProfileBinding != profile.BindingID() || certification.SamplingBinding != sampling.BindingID() {
		return errors.New("certification profile/sampling binding mismatch")
	}
	if certification.Result != "PASS" || !certification.MinimumCertification {
		return errors.New("minimum certification result must be PASS")
	}
	if err := validIdentity("evidence_identity", certification.EvidenceIdentity); err != nil {
		return err
	}
	switch certification.Kind {
	case CertificationControlledReal:
		if certification.RealModelCalls < 1 {
			return errors.New("controlled-real certification requires an observed real model call")
		}
	case CertificationSyntheticCI:
		if certification.RealModelCalls != 0 {
			return errors.New("synthetic public-CI certification must record zero real model calls")
		}
	default:
		return errors.New("unknown certification kind")
	}
	if profile.BackendKind == BackendLocalLlamaCPP && certification.ProductionRoleEligibility != "NOT_GRANTED_DEFER_003" {
		return errors.New("local production role eligibility falsely granted while DEFER-003 is open")
	}
	if profile.BackendKind == BackendRemoteDeepSeek && certification.ProductionRoleEligibility != "NOT_CLAIMED" {
		return errors.New("remote minimum certification cannot grant production role eligibility")
	}
	if certification.ObservedAt.IsZero() {
		return errors.New("certification observation time is required")
	}
	seen := map[CapabilityName]ClaimStatus{}
	for _, claim := range certification.Claims {
		if !knownCapability(claim.Name) || (claim.Status != ClaimCertified && claim.Status != ClaimNotCertified && claim.Status != ClaimUntested) {
			return errors.New("unknown capability claim")
		}
		if _, exists := seen[claim.Name]; exists {
			return errors.New("duplicate capability claim")
		}
		seen[claim.Name] = claim.Status
	}
	for _, requirement := range profile.CapabilityRequirements {
		if seen[requirement] != ClaimCertified {
			return errors.New("required capability is not independently certified")
		}
	}
	if profile.StructuredOutputMode == StructuredNative && seen[CapabilityStructuredOutputNative] != ClaimCertified {
		return errors.New("native structured-output claim is not certified")
	}
	if profile.StructuredOutputMode == StructuredPrompted && seen[CapabilityStructuredOutputPrompted] != ClaimCertified {
		return errors.New("prompted structured-output claim is not certified")
	}
	if profile.ToolCallMode == ToolCallNative && seen[CapabilityToolCallNative] != ClaimCertified {
		return errors.New("native tool-call claim is not certified")
	}
	if err := validateExecutionTuple(certification.ExecutionTuple, &profile, &sampling, true); err != nil {
		return err
	}
	if requireDigest {
		want := certification.SHA256
		certification.SHA256 = ""
		got, err := canonicalDigest(certification)
		if err != nil {
			return err
		}
		if want == "" || got != want {
			return errors.New("certification digest mismatch")
		}
	} else if certification.SHA256 != "" {
		return errors.New("certification digest must be computed")
	}
	return nil
}

// ValidateFormalCertification rejects synthetic contract evidence even when
// all of its protocol assertions pass. Public-CI fixtures can exercise the
// gateway, but they can never make a production route formally eligible.
func ValidateFormalCertification(certification Certification, registry *Registry) error {
	if err := ValidateCertification(certification, registry); err != nil {
		return err
	}
	if certification.Kind != CertificationControlledReal || certification.RealModelCalls < 1 {
		return newError(CodeCertificationMissing, "validate_formal_certification", certification.BindingID(), errors.New("controlled-real certification is required"))
	}
	return nil
}
