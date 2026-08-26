package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PriorityClass string

const (
	PriorityRelease     PriorityClass = "RELEASE"
	PriorityHotfix      PriorityClass = "HOTFIX"
	PriorityMilestone   PriorityClass = "MILESTONE"
	PrioritySystem      PriorityClass = "SYSTEM"
	PriorityCalibration PriorityClass = "CALIBRATION"
	PriorityExploratory PriorityClass = "EXPLORATORY"
	PriorityBackground  PriorityClass = "BACKGROUND"
)

type RunStatus string

const (
	RunQueued    RunStatus = "QUEUED"
	RunLeased    RunStatus = "LEASED"
	RunCompleted RunStatus = "COMPLETED"
	RunCanceled  RunStatus = "CANCELED"
)

type AttemptKind string

const (
	AttemptNewRun          AttemptKind = "NEW_RUN"
	AttemptSameRunRecovery AttemptKind = "SAME_RUN_RECOVERY"
	AttemptRecord          AttemptKind = "ATTEMPT"
)

type AttemptOutcome string

const (
	AttemptStarted   AttemptOutcome = "STARTED"
	AttemptFailed    AttemptOutcome = "FAILED"
	AttemptSucceeded AttemptOutcome = "SUCCEEDED"
	AttemptCanceled  AttemptOutcome = "CANCELED"
)

type ReleaseDisposition string

const (
	ReleaseRequeue  ReleaseDisposition = "REQUEUE"
	ReleaseComplete ReleaseDisposition = "COMPLETE"
)

type TokenSource interface {
	NewToken(context.Context) ([]byte, error)
}

type CryptoTokenSource struct{}

func (CryptoTokenSource) NewToken(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return token, nil
}

type QueueStore struct {
	pool   *pgxpool.Pool
	tokens TokenSource
}

func NewQueueStore(pool *pgxpool.Pool, tokens TokenSource) (*QueueStore, error) {
	if pool == nil {
		return nil, queueError(ErrQueueInvalidInput, "NewQueueStore", "", errors.New("nil pool"))
	}
	if tokens == nil {
		tokens = CryptoTokenSource{}
	}
	return &QueueStore{pool: pool, tokens: tokens}, nil
}

type EnqueueRunInput struct {
	ManifestBytes           []byte
	CampaignName            string
	SuiteName               string
	CaseName                string
	Priority                PriorityClass
	RequiredResourceID      string
	RequiredModelID         string
	RequiredCertificationID string
	RequiredLabels          []string
	DependencyRunIDs        []string
	EligibleAfter           *time.Time
}

type CapabilitySet struct {
	ResourceIDs      []string
	ModelIDs         []string
	CertificationIDs []string
	Labels           []string
}

type RunRecord struct {
	RunID                   string
	ManifestID              string
	CaseID                  string
	RunType                 string
	Classification          string
	QualificationEligible   bool
	Priority                PriorityClass
	RequiredResourceID      string
	RequiredModelID         string
	RequiredCertificationID string
	RequiredLabels          []string
	Status                  RunStatus
	EligibleAfter           time.Time
	QueuedAt                time.Time
	ManifestCanonical       []byte
	ManifestSHA256          [32]byte
}

type AcquireLeaseInput struct {
	HolderID      string
	LeaseDuration time.Duration
	Capabilities  CapabilitySet
}

type Lease struct {
	LeaseID     int64
	RunID       string
	Generation  int64
	HolderID    string
	Token       string
	Formal      bool
	AcquiredAt  time.Time
	HeartbeatAt time.Time
	ExpiresAt   time.Time
}

type AttemptRecordValue struct {
	RunID          string
	AttemptNumber  int64
	AttemptID      string
	Kind           AttemptKind
	Outcome        AttemptOutcome
	EvidenceSHA256 *[32]byte
	RecordedAt     time.Time
}
