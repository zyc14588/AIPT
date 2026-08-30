package modelgateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/zyc14588/AIPT/internal/orchestrator"
)

type BreakGlassVerifier interface {
	Verify(BreakGlassGrant) error
}

type breakGlassGrantAuthority interface {
	BreakGlassVerifier
	trustedBreakGlassVerifier()
}

type ed25519BreakGlassVerifier struct {
	authorities map[string]ed25519.PublicKey
}

func (*ed25519BreakGlassVerifier) trustedBreakGlassVerifier() {}

// NewEd25519BreakGlassVerifier returns a public verification interface backed
// by an unexported trusted implementation. External wrappers cannot embed the
// concrete authority and override Verify while inheriting its private marker.
func NewEd25519BreakGlassVerifier(authorities map[string]ed25519.PublicKey) (BreakGlassVerifier, error) {
	if len(authorities) == 0 || len(authorities) > 32 {
		return nil, newError(CodeBreakGlassInvalid, "new_break_glass_verifier", "", errors.New("trusted break-glass authority required"))
	}
	copy := make(map[string]ed25519.PublicKey, len(authorities))
	for identity, key := range authorities {
		if validIdentity("issuer_authority_id", identity) != nil || len(key) != ed25519.PublicKeySize {
			return nil, newError(CodeBreakGlassInvalid, "new_break_glass_verifier", "", errors.New("invalid trusted break-glass authority"))
		}
		copy[identity] = append(ed25519.PublicKey(nil), key...)
	}
	return &ed25519BreakGlassVerifier{authorities: copy}, nil
}

func (v *ed25519BreakGlassVerifier) Verify(grant BreakGlassGrant) error {
	if v == nil {
		return newError(CodeBreakGlassInvalid, "verify_break_glass_grant", grant.GrantID, errors.New("grant verifier unavailable"))
	}
	if err := validateBreakGlassGrant(grant); err != nil {
		return newError(CodeBreakGlassInvalid, "verify_break_glass_grant", grant.GrantID, err)
	}
	key := v.authorities[grant.IssuerAuthorityID]
	if len(key) != ed25519.PublicKeySize {
		return newError(CodeBreakGlassInvalid, "verify_break_glass_grant", grant.GrantID, errors.New("untrusted grant issuer"))
	}
	signature, err := hex.DecodeString(grant.SignatureEd25519)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return newError(CodeBreakGlassInvalid, "verify_break_glass_grant", grant.GrantID, errors.New("invalid grant signature encoding"))
	}
	payload, err := breakGlassSigningPayload(grant)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return newError(CodeBreakGlassInvalid, "verify_break_glass_grant", grant.GrantID, errors.New("grant signature mismatch"))
	}
	return nil
}

func validateBreakGlassGrant(grant BreakGlassGrant) error {
	if grant.Schema != BreakGlassGrantSchema || !grant.OneTime || !grant.DiagnosticOnly ||
		grant.AuthorizedOperation != BreakGlassRemoteEgressLocalOnlySecret ||
		grant.SourceClassification != orchestrator.ClassLocalOnlySecret ||
		grant.DestinationBackend != BackendRemoteDeepSeek {
		return errors.New("grant schema or fixed diagnostic scope is invalid")
	}
	for field, value := range map[string]string{
		"grant_id": grant.GrantID, "run_id": grant.RunID, "diagnostic_id": grant.DiagnosticID,
		"invocation_id": grant.InvocationID, "profile_binding": grant.ProfileBinding,
		"issuer_authority_id": grant.IssuerAuthorityID, "nonce": grant.Nonce,
	} {
		if err := validIdentity(field, value); err != nil {
			return err
		}
	}
	if grant.SeatID == "" || validSHA("manifest_sha256", grant.ManifestSHA256) != nil ||
		validSHA("context_sha256", grant.ContextSHA256) != nil ||
		validSHA("request_sha256", grant.RequestSHA256) != nil || grant.IssuedAt.IsZero() ||
		grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(grant.IssuedAt) {
		return errors.New("grant identity, digest, or validity window is invalid")
	}
	return nil
}

func breakGlassSigningPayload(grant BreakGlassGrant) ([]byte, error) {
	grant.SignatureEd25519 = ""
	return json.Marshal(grant)
}

func signBreakGlassGrant(grant BreakGlassGrant, key ed25519.PrivateKey) (BreakGlassGrant, error) {
	if len(key) != ed25519.PrivateKeySize {
		return BreakGlassGrant{}, errors.New("invalid Ed25519 private key")
	}
	payload, err := breakGlassSigningPayload(grant)
	if err != nil {
		return BreakGlassGrant{}, err
	}
	grant.SignatureEd25519 = hex.EncodeToString(ed25519.Sign(key, payload))
	return grant, nil
}

func breakGlassGrantDigest(grant BreakGlassGrant) (string, error) {
	return canonicalDigest(grant)
}

func (g *Gateway) consumeBreakGlass(
	ctx context.Context,
	profile ModelProfile,
	invocation orchestrator.InvocationRequest,
	request HarnessRequest,
	now time.Time,
) (string, error) {
	if g.mode != GatewayModeDiagnostic || g.breakGlass == nil || g.breakGlassVerifier == nil {
		return "", newError(CodeBreakGlassInvalid, "consume_break_glass", invocation.InvocationID, errors.New("diagnostic grant unavailable"))
	}
	grant := *g.breakGlass
	if err := g.breakGlassVerifier.Verify(grant); err != nil {
		return "", err
	}
	if grant.RunID != g.runID || grant.DiagnosticID != g.diagnosticID ||
		grant.ManifestSHA256 != g.binding.ManifestSHA256 || grant.SeatID != invocation.SeatID ||
		grant.InvocationID != invocation.InvocationID || grant.ProfileBinding != profile.BindingID() ||
		grant.ContextSHA256 != invocation.Context.ContextHash ||
		grant.RequestSHA256 != request.RequestSHA256 ||
		now.Before(grant.IssuedAt) || !now.Before(grant.ExpiresAt) {
		return "", newError(CodeBreakGlassInvalid, "consume_break_glass", invocation.InvocationID, errors.New("grant scope or validity mismatch"))
	}
	grantDigest, err := breakGlassGrantDigest(grant)
	if err != nil {
		return "", newError(CodeBreakGlassInvalid, "consume_break_glass", invocation.InvocationID, err)
	}
	nonceDigest := sha256.Sum256([]byte(grant.Nonce))
	consumption := BreakGlassConsumption{
		Schema: BreakGlassConsumptionSchema, ConsumptionID: "consume-" + grant.GrantID,
		GrantID: grant.GrantID, GrantSHA256: grantDigest, AuthorizedOperation: grant.AuthorizedOperation,
		RunID: grant.RunID, DiagnosticID: grant.DiagnosticID, ManifestSHA256: grant.ManifestSHA256,
		SeatID: grant.SeatID, InvocationID: grant.InvocationID, ProfileBinding: grant.ProfileBinding,
		ContextSHA256: grant.ContextSHA256, RequestSHA256: request.RequestSHA256,
		SourceClassification: grant.SourceClassification, DestinationBackend: grant.DestinationBackend,
		IssuerAuthorityID: grant.IssuerAuthorityID, NonceSHA256: hex.EncodeToString(nonceDigest[:]),
		ConsumedAt: now, RunDisqualified: true,
	}
	if err := EvidenceSafe(consumption); err != nil {
		return "", err
	}
	if err := g.audit.ConsumeBreakGlass(ctx, consumption); err != nil {
		return "", err
	}
	return grantDigest, nil
}
