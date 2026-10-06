// Package runcontrol provides one transport-neutral command service over the
// frozen B001 PostgreSQL queue. No transport is an authority or a game engine.
package runcontrol

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/zyc14588/AIPT/internal/storage/postgres"
	"github.com/zyc14588/AIPT/internal/testplan"
)

const Schema = "aipt.run-control/v1"
const MaxRequestBytes = 1 << 20
const MaxExportBytes = 2 << 20

var (
	ErrInvalid           = errors.New("AIPT_RUN_CONTROL_INVALID_REQUEST")
	ErrUnavailable       = errors.New("AIPT_RUN_CONTROL_UNAVAILABLE")
	ErrNotFound          = errors.New("AIPT_RUN_CONTROL_NOT_FOUND")
	ErrConflict          = errors.New("AIPT_RUN_CONTROL_CONFLICT")
	ErrNotConfigured     = errors.New("AIPT_RUN_CONTROL_EXECUTOR_NOT_CONFIGURED")
	ErrNotAuthorized     = errors.New("AIPT_RUN_CONTROL_RUN_NOT_AUTHORIZED")
	ErrReportUnavailable = errors.New("AIPT_RUN_CONTROL_REPORT_UNAVAILABLE")
	ErrDisclosure        = errors.New("AIPT_RUN_CONTROL_REPORT_NOT_PUBLIC")
	ErrUnknownMethod     = errors.New("AIPT_RUN_CONTROL_UNKNOWN_METHOD")
	identityPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@+/\-]{0,127}$`)
)

// PublicCode deliberately excludes database causes, paths and caller strings.
func PublicCode(err error) string {
	for _, code := range []error{ErrInvalid, ErrUnavailable, ErrNotFound, ErrConflict, ErrNotConfigured, ErrNotAuthorized, ErrReportUnavailable, ErrDisclosure, ErrUnknownMethod} {
		if errors.Is(err, code) {
			return code.Error()
		}
	}
	switch {
	case errors.Is(err, postgres.ErrQueueInvalidInput):
		return ErrInvalid.Error()
	case errors.Is(err, postgres.ErrQueueRunNotFound):
		return ErrNotFound.Error()
	case errors.Is(err, postgres.ErrQueueStateConflict), errors.Is(err, postgres.ErrQueueRunExists), errors.Is(err, postgres.ErrQueuePaused), errors.Is(err, postgres.ErrQueueNoEligibleRun), errors.Is(err, postgres.ErrLeaseExpired), errors.Is(err, postgres.ErrLeaseStale):
		return ErrConflict.Error()
	default:
		return ErrUnavailable.Error()
	}
}

// Queue is the accepted B001 API, including its database clock and WIP=1 gate.
// Implementations used in production are always *postgres.QueueStore.
type Queue interface {
	EnqueueRun(context.Context, postgres.EnqueueRunInput) (postgres.RunRecord, error)
	GetRun(context.Context, string) (postgres.RunRecord, error)
	SetQueuePaused(context.Context, bool, string) error
	CancelQueuedRun(context.Context, string, string) error
	RecoverExpiredLeases(context.Context) ([]string, error)
	AcquireLease(context.Context, postgres.AcquireLeaseInput) (postgres.Lease, error)
	RenewLease(context.Context, int64, string, time.Duration) (time.Time, error)
	ReleaseLease(context.Context, int64, string, postgres.ReleaseDisposition) error
	AppendAttempt(context.Context, string, string, postgres.AttemptKind, postgres.AttemptOutcome, *[32]byte) (postgres.AttemptRecordValue, error)
	ReadAttempts(context.Context, string) ([]postgres.AttemptRecordValue, error)
}

type QueueSnapshot struct {
	Paused    bool
	Records   []postgres.RunRecord
	Truncated bool
}

type Reader interface {
	Snapshot(context.Context, int) (QueueSnapshot, error)
}

// Definition is trusted server input. Web/RPC accepts its ID only, never any
// Manifest, resource capability, credential, execution code or evidence path.
type Definition struct {
	ID    string
	Input postgres.EnqueueRunInput
}

type Registration struct {
	ID             string `json:"registration_id"`
	RunID          string `json:"run_id"`
	ManifestID     string `json:"manifest_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Classification string `json:"classification"`
}

type RunView struct {
	RunID                 string                 `json:"run_id"`
	ManifestID            string                 `json:"manifest_id"`
	ManifestSHA256        string                 `json:"manifest_sha256"`
	CaseID                string                 `json:"case_id"`
	RunType               string                 `json:"run_type"`
	Classification        string                 `json:"classification"`
	QualificationEligible bool                   `json:"qualification_eligible"`
	Priority              postgres.PriorityClass `json:"priority"`
	Status                postgres.RunStatus     `json:"status"`
	QueuedAt              time.Time              `json:"queued_at"`
	EligibleAfter         time.Time              `json:"eligible_after"`
}

func publicRun(r postgres.RunRecord) RunView {
	return RunView{RunID: r.RunID, ManifestID: r.ManifestID, ManifestSHA256: hex.EncodeToString(r.ManifestSHA256[:]), CaseID: r.CaseID, RunType: r.RunType, Classification: r.Classification, QualificationEligible: r.QualificationEligible, Priority: r.Priority, Status: r.Status, QueuedAt: r.QueuedAt, EligibleAfter: r.EligibleAfter}
}

type SeatView struct {
	SeatID            string `json:"seat_id"`
	RoleID            string `json:"role_id"`
	ModelAssignmentID string `json:"model_assignment_id"`
	AssignmentStatus  string `json:"assignment_status"`
}

type AttemptView struct {
	Number         int64                   `json:"number"`
	Kind           postgres.AttemptKind    `json:"kind"`
	Outcome        postgres.AttemptOutcome `json:"outcome"`
	EvidenceSHA256 *string                 `json:"evidence_sha256"`
	RecordedAt     time.Time               `json:"recorded_at"`
}

type RunDetail struct {
	Run      RunView       `json:"run"`
	Seats    []SeatView    `json:"seats"`
	Attempts []AttemptView `json:"attempts"`
}

type Snapshot struct {
	Schema                           string         `json:"schema"`
	QueueAuthority                   string         `json:"queue_authority"`
	GameplayAuthority                string         `json:"gameplay_authority"`
	Paused                           bool           `json:"paused"`
	Truncated                        bool           `json:"truncated"`
	Items                            []RunView      `json:"items"`
	Registrations                    []Registration `json:"registrations"`
	ExecutorConfigured               bool           `json:"executor_configured"`
	QualificationExecutionAuthorized bool           `json:"qualification_execution_authorized"`
	WorkerRunID                      *string        `json:"worker_run_id"`
	WorkerLastError                  *string        `json:"worker_last_error"`
}

type ReportView struct {
	RunID                 string   `json:"run_id"`
	ReportID              string   `json:"report_id"`
	Root                  string   `json:"root"`
	ExecutionStatus       string   `json:"execution_status"`
	QualificationEligible bool     `json:"qualification_eligible"`
	Formats               []string `json:"formats"`
}

type Download struct {
	Filename  string `json:"filename"`
	MediaType string `json:"media_type"`
	SHA256    string `json:"sha256"`
	Data      []byte `json:"data_base64"`
}

type Reports interface {
	Inspect(context.Context, postgres.RunRecord) (ReportView, error)
	Export(context.Context, postgres.RunRecord, string) (Download, error)
}

// Execution belongs to a trusted game driver, installed by the next pilot
// batch. It receives the immutable Manifest, never the private lease token.
// A driver must honor cancellation and use B002/B003 for gameplay mutations.
type Execution struct {
	Manifest  testplan.FrozenManifest
	AttemptID string
}

type Completion struct{ AuditReadyRoot [32]byte }
type Executor interface {
	Execute(context.Context, Execution) (Completion, error)
}
