package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zyc14588/AIPT/internal/orchestrator"
	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

const maxModelAuditAppendRetries = 32

const (
	modelInvocationAuditEventType = "AIPT_MODEL_INVOCATION_V1"
	breakGlassConsumedEventType   = "AIPT_BREAK_GLASS_CONSUMED_V1"
)

// AuditSink is the single B004 auditable-state boundary. Break-glass
// consumption and invocation evidence must share this sink so a model call can
// never race ahead of the authoritative one-time consumption fact.
type AuditSink interface {
	RecordInvocation(context.Context, InvocationEvidence) error
	ConsumeBreakGlass(context.Context, BreakGlassConsumption) error
	BreakGlassDisqualified(context.Context, string, string) (bool, error)
}

type breakGlassConsumptionAuthority interface {
	AuditSink
	authoritativeBreakGlassConsumption()
}

// postgresqlAuditSink reuses the accepted append-only ledger and its globally
// unique event IDs. Its concrete type stays unexported so an external wrapper
// cannot override audit methods while inheriting the private authority marker.
// It adds no table, migration, cursor, cache, or second authority, and it never
// inserts B004 audit events into a B002 Run stream.
type postgresqlAuditSink struct {
	pool *pgxpool.Pool
}

func (*postgresqlAuditSink) authoritativeBreakGlassConsumption() {}

func NewPostgreSQLAuditSink(pool *pgxpool.Pool) (AuditSink, error) {
	if pool == nil {
		return nil, newError(CodeBreakGlassAudit, "new_model_audit_sink", "", errors.New("nil PostgreSQL pool"))
	}
	return &postgresqlAuditSink{pool: pool}, nil
}

func modelAuditStreamID(runID, diagnosticID string) (string, error) {
	if err := validIdentity("run_id", runID); err != nil {
		return "", err
	}
	if err := validIdentity("diagnostic_id", diagnosticID); err != nil {
		return "", err
	}
	// Break-glass disqualification belongs to the entire Run. DiagnosticID is
	// validated and retained in each event payload, but must never partition
	// the authoritative run-level stream or allow a fresh diagnostic identity
	// to appear clean after restart.
	digest := sha256.Sum256([]byte(runID))
	return "aipt-model-run-audit-v1-" + hex.EncodeToString(digest[:]), nil
}

func auditEventID(domain string, identities ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	for _, identity := range identities {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(identity))
	}
	return domain + "-" + hex.EncodeToString(hash.Sum(nil))
}

func (s *postgresqlAuditSink) append(
	ctx context.Context,
	runID, diagnosticID, eventID, eventType string,
	payload any,
	expectedSequence *int64,
) error {
	if s == nil || s.pool == nil || ctx == nil {
		return newError(CodeBreakGlassAudit, "append_model_audit", eventID, errors.New("audit sink unavailable"))
	}
	streamID, err := modelAuditStreamID(runID, diagnosticID)
	if err != nil {
		return newError(CodeBreakGlassAudit, "append_model_audit", eventID, err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return newError(CodeBreakGlassAudit, "append_model_audit", eventID, err)
	}
	_, err = storagepostgres.Append(ctx, s.pool, storagepostgres.AppendInput{
		StreamID: streamID, EventID: eventID, EventType: eventType, PayloadJSON: raw,
		ExpectedSequence: expectedSequence,
	})
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if eventType == breakGlassConsumedEventType && errors.As(err, &pgErr) &&
		pgErr.Code == "23505" && pgErr.ConstraintName == "ledger_events_event_id_key" {
		return newError(CodeBreakGlassReplay, "consume_break_glass", eventID, errors.New("grant already consumed"))
	}
	return newError(CodeBreakGlassAudit, "append_model_audit", eventID, err)
}

func (s *postgresqlAuditSink) RecordInvocation(ctx context.Context, value InvocationEvidence) error {
	if value.Schema != InvocationEvidenceSchema ||
		(value.RunClassification != "QUALIFICATION" && value.RunClassification != "DIAGNOSTIC") ||
		(value.RunClassification == "DIAGNOSTIC" && value.CleanBaselineEligible) ||
		(value.RunClassification == "QUALIFICATION" && value.BreakGlassUsed) {
		return newError(CodeBreakGlassAudit, "record_model_invocation", value.InvocationID, errors.New("invalid Run-classified invocation evidence"))
	}
	if err := EvidenceSafe(value); err != nil {
		return err
	}
	eventID := auditEventID("model-invocation-v1", value.RunID, value.DiagnosticID, value.InvocationID, value.RequestSHA256)
	if value.RunClassification != "QUALIFICATION" {
		return s.append(ctx, value.RunID, value.DiagnosticID, eventID, modelInvocationAuditEventType, value, nil)
	}
	streamID, err := modelAuditStreamID(value.RunID, value.DiagnosticID)
	if err != nil {
		return newError(CodeBreakGlassAudit, "record_model_invocation", value.InvocationID, err)
	}
	for range maxModelAuditAppendRetries {
		sequence, disqualified, err := s.readRunAuditState(ctx, streamID)
		if err != nil {
			return newError(CodeBreakGlassAudit, "record_model_invocation", value.InvocationID, err)
		}
		if disqualified {
			return newError(CodeBreakGlassAudit, "record_model_invocation", value.InvocationID, errors.New("Run is irreversibly disqualified"))
		}
		err = s.append(ctx, value.RunID, value.DiagnosticID, eventID, modelInvocationAuditEventType, value, &sequence)
		if err == nil {
			return nil
		}
		if !errors.Is(err, storagepostgres.ErrLedgerExpectedSequence) {
			return err
		}
	}
	return newError(CodeBreakGlassAudit, "record_model_invocation", value.InvocationID, errors.New("concurrent Run audit state did not stabilize"))
}

func (s *postgresqlAuditSink) readRunAuditState(ctx context.Context, streamID string) (int64, bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return 0, false, errors.New("audit sink unavailable")
	}
	var sequence int64
	var disqualified bool
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE((
			SELECT last_sequence FROM aipt.ledger_streams WHERE stream_id = $1
		), 0), EXISTS (
			SELECT 1 FROM aipt.ledger_events
			WHERE stream_id = $1 AND event_type = $2
		)`, streamID, breakGlassConsumedEventType).Scan(&sequence, &disqualified)
	return sequence, disqualified, err
}

func (s *postgresqlAuditSink) ConsumeBreakGlass(ctx context.Context, value BreakGlassConsumption) error {
	if value.Schema != BreakGlassConsumptionSchema || !value.RunDisqualified ||
		value.AuthorizedOperation != BreakGlassRemoteEgressLocalOnlySecret ||
		value.SourceClassification != orchestrator.ClassLocalOnlySecret || value.DestinationBackend != BackendRemoteDeepSeek ||
		validIdentity("consumption_id", value.ConsumptionID) != nil || validIdentity("grant_id", value.GrantID) != nil ||
		validIdentity("run_id", value.RunID) != nil || validIdentity("diagnostic_id", value.DiagnosticID) != nil ||
		validIdentity("invocation_id", value.InvocationID) != nil || validIdentity("profile_binding", value.ProfileBinding) != nil ||
		validIdentity("issuer_authority_id", value.IssuerAuthorityID) != nil || value.SeatID == "" || value.ConsumedAt.IsZero() ||
		validSHA("grant_sha256", value.GrantSHA256) != nil || validSHA("manifest_sha256", value.ManifestSHA256) != nil ||
		validSHA("context_sha256", value.ContextSHA256) != nil || validSHA("request_sha256", value.RequestSHA256) != nil ||
		validSHA("nonce_sha256", value.NonceSHA256) != nil {
		return newError(CodeBreakGlassInvalid, "consume_break_glass", value.GrantID, errors.New("invalid consumption fact"))
	}
	if err := EvidenceSafe(value); err != nil {
		return err
	}
	// GrantID alone defines global one-time identity. The ledger's global UNIQUE
	// event_id constraint makes cross-run and concurrent reuse fail atomically.
	eventID := auditEventID("break-glass-consumed-v1", value.GrantID)
	return s.append(ctx, value.RunID, value.DiagnosticID, eventID, breakGlassConsumedEventType, value, nil)
}

func (s *postgresqlAuditSink) BreakGlassDisqualified(ctx context.Context, runID, diagnosticID string) (bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return false, newError(CodeBreakGlassAudit, "read_break_glass_state", diagnosticID, errors.New("audit sink unavailable"))
	}
	streamID, err := modelAuditStreamID(runID, diagnosticID)
	if err != nil {
		return false, newError(CodeBreakGlassAudit, "read_break_glass_state", diagnosticID, err)
	}
	var consumed bool
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM aipt.ledger_events
			WHERE stream_id = $1 AND event_type = $2
		)`, streamID, breakGlassConsumedEventType).Scan(&consumed)
	if err != nil {
		return false, newError(CodeBreakGlassAudit, "read_break_glass_state", diagnosticID, err)
	}
	return consumed, nil
}
