// Package evidence implements the frozen AIPT-M0-B006 native RAW_CAPTURE
// exporter/verifier and the additive AIPT-MVP-B005 AUDIT_READY closure. This
// file remains the legacy RAW_CAPTURE contract; B005 types live separately.
// AUDIT_RESULT generation, signing, and encryption remain outside the package.
package evidence

import (
	"context"
	"errors"
	"time"
)

const (
	SchemaID             = "aipt.evidence/v1"
	SchemaVersion        = "1.0.0"
	RawEventSchemaID     = "aipt.evidence.raw-event/v1"
	RawCaptureStage      = "RAW_CAPTURE"
	LedgerStreamKind     = "LEDGER_STREAM"
	NormalizationVersion = "aipt.raw-capture/v1"
	ManifestName         = "manifest.json"
	EventsName           = "events.ndjson"
	RootName             = "ROOT.sha256"
)

var (
	ErrInvalidInput  = errors.New("AIPT_EVIDENCE_INVALID_INPUT")
	ErrUnsafePath    = errors.New("AIPT_EVIDENCE_UNSAFE_PATH")
	ErrBundleInvalid = errors.New("AIPT_EVIDENCE_BUNDLE_INVALID")
	ErrTargetExists  = errors.New("AIPT_EVIDENCE_TARGET_EXISTS")
	ErrLedgerVerify  = errors.New("AIPT_EVIDENCE_LEDGER_VERIFY_FAILED")
	ErrStreamChanged = errors.New("AIPT_EVIDENCE_STREAM_CHANGED")
	ErrWriteFailed   = errors.New("AIPT_EVIDENCE_WRITE_FAILED")
)

// classifiedError preserves errors.Is classification and the original cause
// without rendering the cause text. Ledger/source errors are an untrusted
// diagnostic boundary and may contain payload material; public errors expose
// only a stable category and a fixed operation name.
type classifiedError struct {
	category  error
	operation string
	cause     error
}

func (err *classifiedError) Error() string {
	return err.category.Error() + ": " + err.operation
}

func (err *classifiedError) Unwrap() []error {
	return []error{err.category, err.cause}
}

func classifyError(category error, operation string, cause error) error {
	return &classifiedError{category: category, operation: operation, cause: cause}
}

// SourceIdentity binds a capture to an immutable repository commit and tree.
// It intentionally carries no workstation, process, credential, or database
// locator metadata.
type SourceIdentity struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
}

// LedgerEvent is one already-verified ledger row supplied to the exporter.
// PayloadCanonical is the exact TEXT read from PostgreSQL, not reconstructed
// JSON. EventHash is an opaque B003 ledger hash: B006 verifies syntax and
// linkage but never duplicates the frozen B003 hash preimage implementation.
type LedgerEvent struct {
	StreamID         string
	Sequence         int64
	EventID          string
	EventType        string
	PayloadCanonical string
	PayloadSHA256    [32]byte
	PrevEventHash    *[32]byte
	EventHash        [32]byte
	CommittedAt      time.Time
}

// LedgerSnapshot is one complete, verified stream at a stable tail.
type LedgerSnapshot struct {
	StreamID     string
	EventCount   int64
	TailSequence int64
	TailHash     *[32]byte
	Events       []LedgerEvent
}

// LedgerSource returns a complete stream snapshot or fails. Implementations
// must never return a silently truncated prefix.
type LedgerSource interface {
	Capture(context.Context, string) (LedgerSnapshot, error)
}

// ExportInput selects the final directory and immutable source identity.
// Destination is operational input only and is never written into evidence.
type ExportInput struct {
	Destination string
	Source      SourceIdentity
	StreamID    string
}

// Asset describes one content-addressed bundle asset.
type Asset struct {
	Path      string `json:"path"`
	MediaType string `json:"media_type"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
}

// RawCaptureManifest is the exact B006-generated manifest shape.
type RawCaptureManifest struct {
	Schema               string         `json:"schema"`
	Version              string         `json:"version"`
	Stage                string         `json:"stage"`
	Source               SourceIdentity `json:"source"`
	CaptureKind          string         `json:"capture_kind"`
	StreamID             string         `json:"stream_id"`
	EventCount           int64          `json:"event_count"`
	TailSequence         int64          `json:"tail_sequence"`
	TailEventHash        *string        `json:"tail_event_hash"`
	NormalizationVersion string         `json:"normalization_version"`
	Assets               []Asset        `json:"assets"`
}

// Verification is the verified public identity of a RAW_CAPTURE directory.
type Verification struct {
	Root     string
	Manifest RawCaptureManifest
}

type rawEventRecord struct {
	Schema           string  `json:"schema"`
	Version          string  `json:"version"`
	StreamID         string  `json:"stream_id"`
	Sequence         int64   `json:"sequence"`
	EventID          string  `json:"event_id"`
	EventType        string  `json:"event_type"`
	PayloadCanonical string  `json:"payload_canonical"`
	PayloadSHA256    string  `json:"payload_sha256"`
	PrevEventHash    *string `json:"prev_event_hash"`
	EventHash        string  `json:"event_hash"`
	CommittedAt      string  `json:"committed_at"`
}
