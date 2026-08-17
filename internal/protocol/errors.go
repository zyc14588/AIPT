package protocol

import "fmt"

// Stable AIPT reason codes carried by ContractError. Every rejection path in
// this package returns a typed ContractError with one of these reasons, so
// tests (and consumers) can distinguish failure modes instead of matching
// free-form messages. The semantic/visibility reasons below are the exact
// stable reasons of the accepted protocol-assets validator.
const (
	// --- strict JSON layer ---
	ReasonJSONMalformed       = "AIPT_JSON_MALFORMED"
	ReasonJSONTrailing        = "AIPT_JSON_TRAILING"
	ReasonJSONDuplicateKey    = "AIPT_JSON_DUPLICATE_KEY"
	ReasonJSONUnsafeInteger   = "AIPT_JSON_UNSAFE_INTEGER"
	ReasonJSONNegativeZero    = "AIPT_JSON_NEGATIVE_ZERO"
	ReasonJSONNonFiniteNumber = "AIPT_JSON_NON_FINITE_NUMBER"
	ReasonJSONUnknownMember   = "AIPT_JSON_UNKNOWN_MEMBER"
	ReasonJSONMissingMember   = "AIPT_JSON_MISSING_MEMBER"
	ReasonJSONNullMember      = "AIPT_JSON_NULL_MEMBER"
	ReasonJSONInvalidType     = "AIPT_JSON_INVALID_TYPE"

	// --- envelope / identity layer ---
	ReasonEnvelopeUnknownRoot            = "AIPT_ENVELOPE_UNKNOWN_ROOT"
	ReasonJSONRPCVersionInvalid          = "AIPT_JSONRPC_VERSION_INVALID"
	ReasonProtocolVersionInvalid         = "AIPT_PROTOCOL_VERSION_INVALID"
	ReasonSchemaVersionInvalid           = "AIPT_SCHEMA_VERSION_INVALID"
	ReasonFixtureIDInvalid               = "AIPT_FIXTURE_ID_INVALID"
	ReasonIdentifierInvalid              = "AIPT_IDENTIFIER_INVALID"
	ReasonIDInvalid                      = "AIPT_ID_INVALID"
	ReasonMethodInvalid                  = "AIPT_METHOD_INVALID"
	ReasonParamsInvalid                  = "AIPT_PARAMS_INVALID"
	ReasonResponseResultErrorBoth        = "AIPT_RESPONSE_RESULT_ERROR_BOTH"
	ReasonResponseResultErrorNeither     = "AIPT_RESPONSE_RESULT_ERROR_NEITHER"
	ReasonErrorCodeInvalid               = "AIPT_ERROR_CODE_INVALID"
	ReasonErrorDataInvalid               = "AIPT_ERROR_DATA_INVALID"
	ReasonApplyResultInvalid             = "AIPT_APPLY_RESULT_INVALID"
	ReasonVisibilityLabelInvalid         = "AIPT_VISIBILITY_LABEL_INVALID"
	ReasonVisibilityAuthorizationInvalid = "AIPT_VISIBILITY_AUTHORIZATION_INVALID"
	ReasonSeatSetInvalid                 = "AIPT_SEAT_SET_INVALID"
	ReasonManifestPathUnsafe             = "AIPT_MANIFEST_PATH_UNSAFE"
	ReasonManifestInvalid                = "AIPT_MANIFEST_INVALID"
	ReasonReplayAssertionInvalid         = "AIPT_REPLAY_ASSERTION_INVALID"
	ReasonMutantSpecimenInvalid          = "AIPT_MUTANT_SPECIMEN_INVALID"
	ReasonStateEventInvalid              = "AIPT_STATE_EVENT_INVALID"
	ReasonCheckInvalid                   = "AIPT_DETERMINISTIC_CHECK_INVALID"
	ReasonCheckOutputMismatch            = "AIPT_DETERMINISTIC_CHECK_MISMATCH"

	// --- semantic layer (exact stable oracle reasons) ---
	ReasonVisibilityUnauthorizedField      = "AIPT_VISIBILITY_UNAUTHORIZED_FIELD"
	ReasonProjectionUnknownSeat            = "AIPT_PROJECTION_UNKNOWN_SEAT"
	ReasonProjectionDuplicateFieldID       = "AIPT_PROJECTION_DUPLICATE_FIELD_ID"
	ReasonProjectionUnknownField           = "AIPT_PROJECTION_UNKNOWN_FIELD"
	ReasonProjectionValueDrift             = "AIPT_PROJECTION_VALUE_DRIFT"
	ReasonVisibilityReclassified           = "AIPT_VISIBILITY_RECLASSIFIED"
	ReasonVisibilityAuthorizationDrift     = "AIPT_VISIBILITY_AUTHORIZATION_DRIFT"
	ReasonProjectionMissingAuthorizedField = "AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD"
	ReasonStateDuplicateFieldID            = "AIPT_STATE_DUPLICATE_FIELD_ID"
	ReasonStateMissingFields               = "AIPT_STATE_MISSING_FIELDS"
	ReasonVisibilityUnknownSeat            = "AIPT_VISIBILITY_UNKNOWN_SEAT"
	ReasonProjectionInvalid                = "AIPT_PROJECTION_INVALID"
	ReasonFixtureIdentityMismatch          = "AIPT_FIXTURE_IDENTITY_MISMATCH"
	ReasonFixtureMutantSemanticDrift       = "AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT"
	ReasonProtocolErrorMismatchedCode      = "AIPT_PROTOCOL_ERROR_MISMATCHED_ERROR_CODE"
)

// ContractError is the deterministic typed error returned by every
// fail-closed rejection in this package. Reason is a stable AIPT reason code,
// Path is the JSON path of the offending value when practical ("" when not
// applicable), and Detail is a deterministic human-readable explanation.
type ContractError struct {
	Reason string
	Path   string
	Detail string
}

func (e *ContractError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Path != "" {
		return fmt.Sprintf("%s at %s: %s", e.Reason, e.Path, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
}

// newContractError builds a ContractError.
func newContractError(reason, path, detail string) error {
	return &ContractError{Reason: reason, Path: path, Detail: detail}
}

// ContractReason returns the stable AIPT reason code of err when err is a
// *ContractError, and "" otherwise. It never inspects message text.
func ContractReason(err error) string {
	ce, ok := err.(*ContractError)
	if !ok || ce == nil {
		return ""
	}
	return ce.Reason
}

// ContractPath returns the JSON path of err when err is a *ContractError.
func ContractPath(err error) string {
	ce, ok := err.(*ContractError)
	if !ok || ce == nil {
		return ""
	}
	return ce.Path
}
