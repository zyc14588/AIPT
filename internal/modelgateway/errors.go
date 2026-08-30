package modelgateway

import (
	"errors"
	"fmt"
)

// Code is a stable, redacted B004 failure classification. Error strings never
// include provider text, prompts, credentials, or private paths.
type Code string

const (
	CodeInvalidProfile            Code = "AIPT_MODEL_PROFILE_INVALID"
	CodeUnknownProfileVersion     Code = "AIPT_MODEL_PROFILE_VERSION_UNKNOWN"
	CodeUnknownBackend            Code = "AIPT_MODEL_BACKEND_UNKNOWN"
	CodeSamplingDrift             Code = "AIPT_MODEL_SAMPLING_DRIFT"
	CodeCertificationMissing      Code = "AIPT_MODEL_CERTIFICATION_MISSING"
	CodeCertificationMismatch     Code = "AIPT_MODEL_CERTIFICATION_MISMATCH"
	CodeManifestBindingInvalid    Code = "AIPT_MODEL_MANIFEST_BINDING_INVALID"
	CodeManifestImmutable         Code = "AIPT_MODEL_MANIFEST_IMMUTABLE"
	CodeSilentFallback            Code = "AIPT_MODEL_SILENT_FALLBACK_FORBIDDEN"
	CodeCredentialUnavailable     Code = "AIPT_MODEL_CREDENTIAL_UNAVAILABLE"
	CodeCredentialPolicy          Code = "AIPT_MODEL_CREDENTIAL_POLICY_VIOLATION"
	CodeEgressDenied              Code = "AIPT_MODEL_EGRESS_DENIED"
	CodeBreakGlassInvalid         Code = "AIPT_BREAK_GLASS_GRANT_INVALID"
	CodeBreakGlassReplay          Code = "AIPT_BREAK_GLASS_GRANT_REPLAYED"
	CodeBreakGlassAudit           Code = "AIPT_BREAK_GLASS_AUDIT_FAILED"
	CodeContextBudgetExceeded     Code = "AIPT_MODEL_CONTEXT_BUDGET_EXCEEDED"
	CodeHarnessIdentityMismatch   Code = "AIPT_HARNESS_IDENTITY_MISMATCH"
	CodeHarnessProtocolMismatch   Code = "AIPT_HARNESS_PROTOCOL_MISMATCH"
	CodeHarnessResponseInvalid    Code = "AIPT_HARNESS_RESPONSE_INVALID"
	CodeHarnessFrameTooLarge      Code = "AIPT_HARNESS_FRAME_TOO_LARGE"
	CodeHarnessBoot               Code = "AIPT_HARNESS_BOOT_FAILED"
	CodeHarnessTimeout            Code = "AIPT_HARNESS_TIMEOUT"
	CodeHarnessCancelled          Code = "AIPT_HARNESS_CANCELLED"
	CodeHarnessTransport          Code = "AIPT_HARNESS_TRANSPORT_FAILED"
	CodeHarnessSession            Code = "AIPT_HARNESS_SESSION_FAILED"
	CodeModelRequestFailed        Code = "AIPT_MODEL_REQUEST_FAILED"
	CodeModelIdentityMismatch     Code = "AIPT_MODEL_IDENTITY_MISMATCH"
	CodeLocalEndpointNotLoopback  Code = "AIPT_LLAMA_ENDPOINT_NOT_LOOPBACK"
	CodeLocalBinaryMismatch       Code = "AIPT_LLAMA_BINARY_IDENTITY_MISMATCH"
	CodeLocalGGUFMismatch         Code = "AIPT_LLAMA_GGUF_IDENTITY_MISMATCH"
	CodeLocalTemplateMismatch     Code = "AIPT_LLAMA_TEMPLATE_IDENTITY_MISMATCH"
	CodeLocalProcessMismatch      Code = "AIPT_LLAMA_PROCESS_IDENTITY_MISMATCH"
	CodeLocalStartupFailed        Code = "AIPT_LLAMA_STARTUP_FAILED"
	CodeLocalReadinessFailed      Code = "AIPT_LLAMA_READINESS_FAILED"
	CodeLocalShutdownFailed       Code = "AIPT_LLAMA_SHUTDOWN_FAILED"
	CodeLocalRecoveryDisqualifies Code = "AIPT_LLAMA_RECOVERY_DISQUALIFIES_CLEAN_BASELINE"
	CodeEvidenceUnsafe            Code = "AIPT_MODEL_EVIDENCE_UNSAFE"
	CodeDirectProviderBypass      Code = "AIPT_MODEL_DIRECT_PROVIDER_BYPASS_FORBIDDEN"
)

var sentinels = map[Code]error{}

func init() {
	for _, code := range []Code{
		CodeInvalidProfile, CodeUnknownProfileVersion, CodeUnknownBackend,
		CodeSamplingDrift, CodeCertificationMissing, CodeCertificationMismatch,
		CodeManifestBindingInvalid, CodeManifestImmutable, CodeSilentFallback,
		CodeCredentialUnavailable, CodeCredentialPolicy, CodeEgressDenied,
		CodeBreakGlassInvalid, CodeBreakGlassReplay, CodeBreakGlassAudit,
		CodeContextBudgetExceeded, CodeHarnessIdentityMismatch,
		CodeHarnessProtocolMismatch, CodeHarnessResponseInvalid,
		CodeHarnessFrameTooLarge, CodeHarnessBoot, CodeHarnessTimeout, CodeHarnessCancelled,
		CodeHarnessTransport, CodeHarnessSession, CodeModelRequestFailed, CodeModelIdentityMismatch,
		CodeLocalEndpointNotLoopback, CodeLocalBinaryMismatch, CodeLocalGGUFMismatch,
		CodeLocalTemplateMismatch, CodeLocalProcessMismatch, CodeLocalStartupFailed,
		CodeLocalReadinessFailed, CodeLocalShutdownFailed,
		CodeLocalRecoveryDisqualifies, CodeEvidenceUnsafe, CodeDirectProviderBypass,
	} {
		sentinels[code] = errors.New(string(code))
	}
}

// Error preserves an internal cause for errors.Is/errors.As while exposing
// only stable non-secret identifiers in Error().
type Error struct {
	Code      Code
	Operation string
	Identity  string
	cause     error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := string(e.Code)
	if e.Operation != "" {
		message += ": operation=" + e.Operation
	}
	if e.Identity != "" {
		message += " identity=" + e.Identity
	}
	return message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *Error) Is(target error) bool {
	return e != nil && target == sentinels[e.Code]
}

func newError(code Code, operation, identity string, cause error) error {
	if cause == nil {
		cause = fmt.Errorf("%s", operation)
	}
	return &Error{Code: code, Operation: operation, Identity: identity, cause: cause}
}

// Sentinel returns the stable sentinel for code.
func Sentinel(code Code) error { return sentinels[code] }

// CodeOf returns the first model-gateway code in err's unwrap tree.
func CodeOf(err error) Code {
	var structured *Error
	if errors.As(err, &structured) && structured != nil {
		return structured.Code
	}
	return ""
}
