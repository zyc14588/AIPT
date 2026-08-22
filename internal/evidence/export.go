package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zyc14588/AIPT/internal/protocol"
)

// ExportRawCapture materializes one complete RAW_CAPTURE directory. It first
// captures and validates the whole verified stream, writes into a private
// temporary sibling, fsyncs and self-verifies every byte, then atomically
// renames the sibling into an absent final path. Any failure removes the
// temporary directory and leaves no partial final bundle.
func ExportRawCapture(ctx context.Context, source LedgerSource, in ExportInput) (Verification, error) {
	if source == nil {
		return Verification{}, fmt.Errorf("%w: nil ledger source", ErrInvalidInput)
	}
	if err := validateExportInput(in); err != nil {
		return Verification{}, err
	}
	finalPath, parent, err := validateAbsentDestination(in.Destination)
	if err != nil {
		return Verification{}, err
	}
	snapshot, err := source.Capture(ctx, in.StreamID)
	if err != nil {
		if errors.Is(err, ErrStreamChanged) {
			return Verification{}, classifyError(ErrStreamChanged, "capture verified ledger stream", err)
		}
		return Verification{}, classifyError(ErrLedgerVerify, "capture verified ledger stream", err)
	}
	if err := validateSnapshot(snapshot, in.StreamID); err != nil {
		return Verification{}, err
	}

	tempPath, err := os.MkdirTemp(parent, ".aipt-raw-capture-tmp-")
	if err != nil {
		return Verification{}, fmt.Errorf("%w: create private temporary bundle: %v", ErrWriteFailed, err)
	}
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.RemoveAll(tempPath)
		}
	}()
	if err := os.Chmod(tempPath, 0o700); err != nil {
		return Verification{}, fmt.Errorf("%w: set temporary bundle permissions: %v", ErrWriteFailed, err)
	}

	eventsBytes, err := encodeEvents(snapshot.Events)
	if err != nil {
		return Verification{}, err
	}
	if err := writePrivateFile(tempPath, EventsName, eventsBytes); err != nil {
		return Verification{}, err
	}
	eventsHash := sha256.Sum256(eventsBytes)
	manifest := newRawCaptureManifest(in.Source, snapshot, int64(len(eventsBytes)), eventsHash)
	manifestBytes, err := canonicalLine(manifest)
	if err != nil {
		return Verification{}, fmt.Errorf("canonicalize manifest: %w", err)
	}
	if err := writePrivateFile(tempPath, ManifestName, manifestBytes); err != nil {
		return Verification{}, err
	}
	manifestHash := sha256.Sum256(manifestBytes)
	rootBytes := []byte(hex.EncodeToString(manifestHash[:]) + "\n")
	if err := writePrivateFile(tempPath, RootName, rootBytes); err != nil {
		return Verification{}, err
	}
	if err := syncDirectory(tempPath); err != nil {
		return Verification{}, fmt.Errorf("%w: sync temporary bundle: %v", ErrWriteFailed, err)
	}

	verification, err := VerifyRawCapture(tempPath)
	if err != nil {
		return Verification{}, fmt.Errorf("self-verify temporary bundle: %w", err)
	}
	// Recheck immediately before rename so an existing file, directory, or
	// symlink is always rejected rather than intentionally replaced.
	if _, err := os.Lstat(finalPath); err == nil {
		return Verification{}, fmt.Errorf("%w: final path appeared before rename", ErrTargetExists)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Verification{}, fmt.Errorf("lstat final path before rename: %w", err)
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		return Verification{}, fmt.Errorf("%w: atomically publish verified bundle: %v", ErrWriteFailed, err)
	}
	keepTemp = false
	return verification, nil
}

func validateExportInput(in ExportInput) error {
	if in.Destination == "" {
		return fmt.Errorf("%w: empty destination", ErrInvalidInput)
	}
	if err := validateSourceIdentity(in.Source); err != nil {
		return err
	}
	if err := validateLedgerText("stream_id", in.StreamID); err != nil {
		return err
	}
	return nil
}

func validateAbsentDestination(destination string) (finalPath string, parent string, err error) {
	finalPath, err = filepath.Abs(destination)
	if err != nil {
		return "", "", fmt.Errorf("%w: resolve destination: %v", ErrUnsafePath, err)
	}
	finalPath = filepath.Clean(finalPath)
	if filepath.Base(finalPath) == "." || filepath.Base(finalPath) == string(filepath.Separator) {
		return "", "", fmt.Errorf("%w: destination must name a child directory", ErrUnsafePath)
	}
	if _, statErr := os.Lstat(finalPath); statErr == nil {
		return "", "", fmt.Errorf("%w: destination already exists", ErrTargetExists)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("%w: lstat destination: %v", ErrUnsafePath, statErr)
	}
	parent = filepath.Dir(finalPath)
	st, statErr := os.Lstat(parent)
	if statErr != nil {
		return "", "", fmt.Errorf("%w: destination parent: %v", ErrUnsafePath, statErr)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return "", "", fmt.Errorf("%w: destination parent must be a real directory", ErrUnsafePath)
	}
	return finalPath, parent, nil
}

func newRawCaptureManifest(source SourceIdentity, snapshot LedgerSnapshot, size int64, digest [32]byte) RawCaptureManifest {
	var tail *string
	if snapshot.TailHash != nil {
		value := hex.EncodeToString(snapshot.TailHash[:])
		tail = &value
	}
	return RawCaptureManifest{
		Schema:               SchemaID,
		Version:              SchemaVersion,
		Stage:                RawCaptureStage,
		Source:               source,
		CaptureKind:          LedgerStreamKind,
		StreamID:             snapshot.StreamID,
		EventCount:           snapshot.EventCount,
		TailSequence:         snapshot.TailSequence,
		TailEventHash:        tail,
		NormalizationVersion: NormalizationVersion,
		Assets: []Asset{{
			Path: EventsName, MediaType: "application/x-ndjson", Bytes: size,
			SHA256: hex.EncodeToString(digest[:]),
		}},
	}
}

func encodeEvents(events []LedgerEvent) ([]byte, error) {
	var out []byte
	for i, event := range events {
		var previous *string
		if event.PrevEventHash != nil {
			value := hex.EncodeToString(event.PrevEventHash[:])
			previous = &value
		}
		record := rawEventRecord{
			Schema:           RawEventSchemaID,
			Version:          SchemaVersion,
			StreamID:         event.StreamID,
			Sequence:         event.Sequence,
			EventID:          event.EventID,
			EventType:        event.EventType,
			PayloadCanonical: event.PayloadCanonical,
			PayloadSHA256:    hex.EncodeToString(event.PayloadSHA256[:]),
			PrevEventHash:    previous,
			EventHash:        hex.EncodeToString(event.EventHash[:]),
			CommittedAt:      event.CommittedAt.UTC().Format(timeFormat),
		}
		line, err := canonicalLine(record)
		if err != nil {
			return nil, fmt.Errorf("canonicalize event %d: %w", i+1, err)
		}
		out = append(out, line...)
	}
	return out, nil
}

func canonicalLine(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	return append([]byte(canonical), '\n'), nil
}

func writePrivateFile(directory, name string, data []byte) error {
	file, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create %s: %v", ErrWriteFailed, name, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("%w: chmod %s: %v", ErrWriteFailed, name, err)
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("%w: write %s: %v", ErrWriteFailed, name, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("%w: sync %s: %v", ErrWriteFailed, name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("%w: close %s: %v", ErrWriteFailed, name, err)
	}
	closed = true
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
