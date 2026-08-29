package runcore

import (
	"context"
	"encoding/json"

	storagepostgres "github.com/zyc14588/AIPT/internal/storage/postgres"
)

const (
	ActionProposalSchema = "aipt.action-proposal/v1"
	RunBindingSchema     = "aipt.run-binding/v1"
	RunStateSchema       = "aipt.run-state/v1"
	RunEventSchema       = "aipt.run-event/v1"
	RunProjectionSchema  = "aipt.run-projection/v1"
	ActionReceiptSchema  = "aipt.action-receipt/v1"

	RNGVersionV1        = "AIPT_RNG_HMAC_SHA256_V1"
	SeedCommitmentV1    = "AIPT_SEED_COMMITMENT_SHA256_V1"
	RunStartedEventType = "AIPT_RUN_STARTED_V1"
	ActionEventType     = "AIPT_RUN_ACTION_COMMITTED_V1"

	RuleSourceRuleID   = "RULE_ID"
	RuleSourceExplicit = "EXPLICIT_SOURCE"

	maxSafeJSONInteger   int64 = 9_007_199_254_740_991
	maxRNGDrawsPerAction       = 4096
)

// ArtifactBinding identifies an immutable, versioned canonical artifact.
type ArtifactBinding struct {
	ID              string `json:"id"`
	Schema          string `json:"schema"`
	CanonicalSHA256 string `json:"canonical_sha256"`
}

// SourcePackageBinding binds the read-only game/source package identity.
type SourcePackageBinding struct {
	PackageID       string `json:"package_id"`
	Schema          string `json:"schema"`
	Repository      string `json:"repository"`
	Commit          string `json:"commit"`
	Tree            string `json:"tree"`
	CanonicalSHA256 string `json:"canonical_sha256"`
}

// RunBinding joins the accepted B001 Manifest identity with the immutable
// runtime-adapter input and source-package identities. It is copied into every
// authoritative Run event and cannot be changed by an action handler.
type RunBinding struct {
	Schema              string               `json:"schema"`
	RunID               string               `json:"run_id"`
	Manifest            ArtifactBinding      `json:"manifest"`
	RuntimeAdapterInput ArtifactBinding      `json:"runtime_adapter_input"`
	SourcePackage       SourcePackageBinding `json:"source_package"`
}

type RuleSource struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
}

// TemporaryRuling is a deterministic storage contract only. B002 does not
// start or emulate a GM; a future GM can submit this metadata with an intent.
type TemporaryRuling struct {
	RulingID             string `json:"ruling_id"`
	Scope                string `json:"scope"`
	Reason               string `json:"reason"`
	Reversible           bool   `json:"reversible"`
	ValidThroughSequence int64  `json:"valid_through_sequence"`
}

type RNGRequest struct {
	StreamID string `json:"stream_id"`
	Count    int    `json:"count"`
}

// ActionProposal is the only caller-controlled mutation input.
type ActionProposal struct {
	Schema           string           `json:"schema"`
	ActionID         string           `json:"action_id"`
	RunID            string           `json:"run_id"`
	ActorID          string           `json:"actor_id"`
	ActionType       string           `json:"action_type"`
	ExpectedSequence int64            `json:"expected_sequence"`
	Source           RuleSource       `json:"source"`
	Payload          json.RawMessage  `json:"payload"`
	RNGRequests      []RNGRequest     `json:"rng_requests"`
	TemporaryRuling  *TemporaryRuling `json:"temporary_ruling,omitempty"`
}

type RNGDraw struct {
	Version   string `json:"version"`
	StreamID  string `json:"stream_id"`
	DrawIndex int64  `json:"draw_index"`
	ValueHex  string `json:"value_hex"`
}

// RunState is an immutable value at the API boundary. DomainState is
// canonical JSON. Root seed material is deliberately absent.
type RunState struct {
	Schema            string           `json:"schema"`
	Binding           RunBinding       `json:"binding"`
	Sequence          int64            `json:"sequence"`
	RNGVersion        string           `json:"rng_version"`
	CommitmentVersion string           `json:"commitment_version"`
	SeedCommitment    string           `json:"seed_commitment"`
	RNGCursors        map[string]int64 `json:"rng_cursors"`
	DomainState       json.RawMessage  `json:"domain_state"`
}

type Receipt struct {
	Schema         string    `json:"schema"`
	RunID          string    `json:"run_id"`
	ActionID       string    `json:"action_id"`
	Sequence       int64     `json:"sequence"`
	EventHash      string    `json:"event_hash"`
	StateHash      string    `json:"state_hash"`
	ProjectionHash string    `json:"projection_hash"`
	RNGDraws       []RNGDraw `json:"rng_draws"`
}

type Projection struct {
	Canonical []byte
	SHA256    string
}

type ReplayInput struct {
	Binding                RunBinding
	Seed                   []byte
	Events                 []storagepostgres.LedgerEvent
	ExpectedFinalStateHash string
}

type ReplayResult struct {
	State          RunState
	StateHash      string
	EventCount     int
	ProjectionHash string
}

type AppendRequest struct {
	StreamID         string
	ExpectedSequence int64
	EventID          string
	EventType        string
	Payload          []byte
}

// EventStore is the only authoritative persistence boundary used by Core.
// Production uses PostgreSQLStore; tests may use an in-memory implementation.
type EventStore interface {
	Append(context.Context, AppendRequest) (storagepostgres.LedgerEvent, error)
	Load(context.Context, string) ([]storagepostgres.LedgerEvent, error)
}

type SeedSource interface {
	RootSeed(context.Context, RunBinding) ([]byte, error)
}

type Authorizer interface {
	Authorize(context.Context, RunState, ActionProposal) error
}

type RuleValidator interface {
	ValidateRuleSource(context.Context, RunState, ActionProposal) error
}

// ActionHandler is deterministic application logic registered by action type.
// It receives a copied state/proposal and exact Core-produced draws. It can
// return only the next domain JSON, so it cannot mutate identities, sequence,
// RNG cursors, projection, or the ledger directly.
type ActionHandler interface {
	ValidatePayload(ActionProposal) error
	ValidatePrecondition(context.Context, RunState, ActionProposal) error
	Apply(context.Context, RunState, ActionProposal, []RNGDraw) (json.RawMessage, error)
}

type AuthorizerFunc func(context.Context, RunState, ActionProposal) error

func (f AuthorizerFunc) Authorize(ctx context.Context, state RunState, proposal ActionProposal) error {
	return f(ctx, state, proposal)
}

type RuleValidatorFunc func(context.Context, RunState, ActionProposal) error

func (f RuleValidatorFunc) ValidateRuleSource(ctx context.Context, state RunState, proposal ActionProposal) error {
	return f(ctx, state, proposal)
}

type Invariant interface {
	Validate(RunState) error
}

type InvariantFunc func(RunState) error

func (f InvariantFunc) Validate(state RunState) error { return f(state) }

type Config struct {
	Store      EventStore
	SeedSource SeedSource
	Authorizer Authorizer
	Rules      RuleValidator
	Handlers   map[string]ActionHandler
	Invariants []Invariant
}

type StartRunInput struct {
	Binding      RunBinding
	InitialState json.RawMessage
}
