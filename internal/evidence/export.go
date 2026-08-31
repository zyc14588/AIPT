package evidence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

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
	parentFile, parentState, err := openPrivateExportParent(parent)
	if err != nil {
		return Verification{}, err
	}
	defer parentFile.Close()
	finalName := filepath.Base(finalPath)
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

	tempName, tempDirectory, tempState, err := createPrivateStagingDirectory(parentFile)
	if err != nil {
		return Verification{}, fmt.Errorf("%w: create private temporary bundle: %v", ErrWriteFailed, err)
	}
	defer tempDirectory.Close()
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.RemoveAll(filepath.Join(parent, tempName))
		}
	}()

	eventsBytes, err := encodeEvents(snapshot.Events)
	if err != nil {
		return Verification{}, err
	}
	if err := writePrivateFileAt(tempDirectory, EventsName, eventsBytes); err != nil {
		return Verification{}, err
	}
	eventsHash := sha256.Sum256(eventsBytes)
	manifest := newRawCaptureManifest(in.Source, snapshot, int64(len(eventsBytes)), eventsHash)
	manifestBytes, err := canonicalLine(manifest)
	if err != nil {
		return Verification{}, fmt.Errorf("canonicalize manifest: %w", err)
	}
	if err := writePrivateFileAt(tempDirectory, ManifestName, manifestBytes); err != nil {
		return Verification{}, err
	}
	manifestHash := sha256.Sum256(manifestBytes)
	rootBytes := []byte(hex.EncodeToString(manifestHash[:]) + "\n")
	if err := writePrivateFileAt(tempDirectory, RootName, rootBytes); err != nil {
		return Verification{}, err
	}
	if err := tempDirectory.Sync(); err != nil {
		return Verification{}, fmt.Errorf("%w: sync temporary bundle: %v", ErrWriteFailed, err)
	}
	if err := syscall.Fstat(int(tempDirectory.Fd()), &tempState); err != nil {
		return Verification{}, fmt.Errorf("%w: retain completed staging identity: %v", ErrWriteFailed, err)
	}

	verification, err := verifyHeldRawCapture(tempDirectory, tempState)
	if err != nil {
		return Verification{}, fmt.Errorf("self-verify temporary bundle: %w", err)
	}
	if !pathMatchesHeldDirectory(parent, parentState) {
		return Verification{}, fmt.Errorf("%w: destination parent identity changed", ErrUnsafePath)
	}
	if err := renameat2NoReplace(int(parentFile.Fd()), tempName, int(parentFile.Fd()), finalName); err != nil {
		if errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOTEMPTY) {
			return Verification{}, fmt.Errorf("%w: final path appeared before publication", ErrTargetExists)
		}
		return Verification{}, fmt.Errorf("%w: atomically publish verified bundle: %v", ErrWriteFailed, err)
	}
	keepTemp = false
	if err := parentFile.Sync(); err != nil {
		return Verification{}, fmt.Errorf("%w: sync destination parent: %v", ErrWriteFailed, err)
	}
	finalDirectory, finalState, err := openPrivateDirectoryAt(parentFile, finalName)
	if err != nil {
		return Verification{}, fmt.Errorf("%w: open published bundle: %v", ErrWriteFailed, err)
	}
	defer finalDirectory.Close()
	if !samePrivateBundleDirectory(tempState, finalState) {
		return Verification{}, fmt.Errorf("%w: published object differs from verified staging identity", ErrWriteFailed)
	}
	published, err := verifyHeldRawCapture(finalDirectory, finalState)
	if err != nil || published.Root != verification.Root {
		return Verification{}, fmt.Errorf("%w: published object failed exact post-publication verification", ErrWriteFailed)
	}
	if !pathMatchesHeldDirectory(parent, parentState) {
		return Verification{}, fmt.Errorf("%w: destination parent identity changed during publication", ErrUnsafePath)
	}
	return published, nil
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

func openPrivateExportParent(parent string) (*os.File, syscall.Stat_t, error) {
	fd, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, fmt.Errorf("%w: open destination parent: %v", ErrUnsafePath, err)
	}
	file := os.NewFile(uintptr(fd), parent)
	if file == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, fmt.Errorf("%w: construct destination parent handle", ErrUnsafePath)
	}
	var state syscall.Stat_t
	if err := syscall.Fstat(fd, &state); err != nil || state.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		state.Mode&0o022 != 0 {
		file.Close()
		if err != nil {
			return nil, syscall.Stat_t{}, fmt.Errorf("%w: inspect destination parent: %v", ErrUnsafePath, err)
		}
		return nil, syscall.Stat_t{}, fmt.Errorf("%w: destination parent must be an owner-controlled non-group/world-writable real directory (mode %#o)", ErrUnsafePath, state.Mode&0o777)
	}
	return file, state, nil
}

func pathMatchesHeldDirectory(path string, held syscall.Stat_t) bool {
	var current syscall.Stat_t
	if err := syscall.Lstat(path, &current); err != nil {
		return false
	}
	return sameDirectoryIdentity(held, current) && current.Mode&0o022 == 0 && current.Uid == held.Uid
}

func sameDirectoryIdentity(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Mode&syscall.S_IFMT == syscall.S_IFDIR && right.Mode&syscall.S_IFMT == syscall.S_IFDIR
}

func samePrivateBundleDirectory(left, right syscall.Stat_t) bool {
	return sameDirectoryIdentity(left, right) && left.Mode&0o777 == 0o700 && right.Mode&0o777 == 0o700 &&
		left.Uid == right.Uid
}

func createPrivateStagingDirectory(parent *os.File) (string, *os.File, syscall.Stat_t, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return "", nil, syscall.Stat_t{}, err
		}
		name := ".aipt-raw-capture-tmp-" + hex.EncodeToString(entropy[:])
		if err := syscall.Mkdirat(int(parent.Fd()), name, 0o700); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return "", nil, syscall.Stat_t{}, err
		}
		file, state, err := openPrivateDirectoryAt(parent, name)
		if err != nil {
			return name, nil, syscall.Stat_t{}, err
		}
		return name, file, state, nil
	}
	return "", nil, syscall.Stat_t{}, errors.New("exhausted private staging name attempts")
}

func openPrivateDirectoryAt(parent *os.File, name string) (*os.File, syscall.Stat_t, error) {
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, errors.New("construct held directory")
	}
	var state syscall.Stat_t
	if err := syscall.Fstat(fd, &state); err != nil ||
		state.Mode&syscall.S_IFMT != syscall.S_IFDIR || state.Mode&0o777 != 0o700 {
		file.Close()
		if err != nil {
			return nil, syscall.Stat_t{}, err
		}
		return nil, syscall.Stat_t{}, errors.New("held directory identity or permissions are invalid")
	}
	return file, state, nil
}

func renameat2NoReplace(oldDirectory int, oldName string, newDirectory int, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	syscallNumber, err := renameat2SyscallNumber()
	if err != nil {
		return err
	}
	// Linux renameat2(2), RENAME_NOREPLACE. An unavailable kernel primitive
	// fails closed instead of falling back to replacement-capable Rename.
	const renameNoReplace = uintptr(1)
	_, _, errno := syscall.Syscall6(
		syscallNumber,
		uintptr(oldDirectory), uintptr(unsafe.Pointer(oldPointer)),
		uintptr(newDirectory), uintptr(unsafe.Pointer(newPointer)),
		renameNoReplace, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func renameat2SyscallNumber() (uintptr, error) {
	switch runtime.GOARCH {
	case "amd64":
		return 316, nil
	case "386":
		return 353, nil
	case "arm":
		return 382, nil
	case "arm64", "riscv64", "loong64":
		return 276, nil
	case "ppc64", "ppc64le":
		return 357, nil
	case "s390x":
		return 347, nil
	case "mips64", "mips64le":
		return 5311, nil
	default:
		return 0, errors.New("no-replace RAW_CAPTURE publication is unsupported on this architecture")
	}
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
	if int64(len(events)) > maxRawCaptureEventCount {
		return nil, fmt.Errorf("%w: event count exceeds bound %d", ErrInvalidInput, maxRawCaptureEventCount)
	}
	var out []byte
	for i, event := range events {
		line, err := encodeEventLine(event)
		if err != nil {
			return nil, fmt.Errorf("canonicalize event %d: %w", i+1, err)
		}
		if len(line) > maxRawCaptureEventLineBytes {
			return nil, fmt.Errorf("%w: event %d encoded line exceeds bound %d", ErrInvalidInput, i+1, maxRawCaptureEventLineBytes)
		}
		if int64(len(out))+int64(len(line)) > maxRawCaptureEventsBytes {
			return nil, fmt.Errorf("%w: encoded events exceed bound %d", ErrInvalidInput, maxRawCaptureEventsBytes)
		}
		out = append(out, line...)
	}
	return out, nil
}

func encodeEventLine(event LedgerEvent) ([]byte, error) {
	var previous *string
	if event.PrevEventHash != nil {
		value := hex.EncodeToString(event.PrevEventHash[:])
		previous = &value
	}
	return canonicalLine(rawEventRecord{
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
	})
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

func writePrivateFileAt(directory *os.File, name string, data []byte) error {
	fd, err := syscall.Openat(int(directory.Fd()), name,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create %s: %v", ErrWriteFailed, name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return fmt.Errorf("%w: construct %s", ErrWriteFailed, name)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
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
