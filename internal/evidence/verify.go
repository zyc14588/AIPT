package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const (
	timeFormat                  = time.RFC3339Nano
	maxRawCaptureManifestBytes  = int64(1 << 20)
	maxRawCaptureRootBytes      = int64(65)
	maxRawCaptureEventsBytes    = int64(64 << 20)
	maxRawCaptureEventCount     = int64(100_000)
	maxRawCaptureEventLineBytes = 1 << 20
)

var (
	lowerSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerGitOID = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// VerifyRawCapture verifies an already materialized RAW_CAPTURE directory.
// It requires an exact three-file inventory, private modes, no symlinks,
// canonical JSON+LF, exact hashes and root, a complete ordered stream, exact
// payload hashes/canonical text, and the opaque B003 hash linkage.
func VerifyRawCapture(directory string) (Verification, error) {
	fail := func(format string, args ...any) (Verification, error) {
		return Verification{}, fmt.Errorf("%w: %s", ErrBundleInvalid, fmt.Sprintf(format, args...))
	}
	directoryFile, directoryStat, err := openRawCaptureDirectory(directory)
	if err != nil {
		return fail("open bundle directory: %v", err)
	}
	defer directoryFile.Close()
	return verifyHeldRawCapture(directoryFile, directoryStat)
}

// verifyHeldRawCapture verifies the exact directory object already held by
// the caller. Export uses this form so the self-verified staging object is
// never reopened through a mutable pathname before publication.
func verifyHeldRawCapture(directoryFile *os.File, directoryStat syscall.Stat_t) (Verification, error) {
	fail := func(format string, args ...any) (Verification, error) {
		return Verification{}, fmt.Errorf("%w: %s", ErrBundleInvalid, fmt.Sprintf(format, args...))
	}
	entries, err := directoryFile.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return fail("read bundle directory: %v", err)
	}
	if len(entries) > 3 {
		return fail("bundle contains more than three members")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{EventsName, ManifestName, RootName}
	sort.Strings(wantNames)
	if !equalStrings(names, wantNames) {
		return fail("file inventory is %v, want exactly %v", names, wantNames)
	}

	manifestFile, manifestStat, err := openHeldPrivateFile(directoryFile, ManifestName, maxRawCaptureManifestBytes)
	if err != nil {
		return fail("open manifest: %v", err)
	}
	defer manifestFile.Close()
	rootFile, rootStat, err := openHeldPrivateFile(directoryFile, RootName, maxRawCaptureRootBytes)
	if err != nil {
		return fail("open root: %v", err)
	}
	defer rootFile.Close()
	eventsFile, eventsStat, err := openHeldPrivateFile(directoryFile, EventsName, maxRawCaptureEventsBytes)
	if err != nil {
		return fail("open events: %v", err)
	}
	defer eventsFile.Close()

	manifestBytes, err := readHeldPrivateFile(manifestFile, manifestStat, maxRawCaptureManifestBytes)
	if err != nil {
		return fail("read manifest: %v", err)
	}
	manifestBody, err := canonicalBody(manifestBytes)
	if err != nil {
		return fail("manifest: %v", err)
	}
	var manifest RawCaptureManifest
	if err := strictDecode(manifestBody, &manifest); err != nil {
		return fail("decode manifest: %v", err)
	}
	if err := validateManifest(manifest); err != nil {
		return fail("manifest semantics: %v", err)
	}

	rootBytes, err := readHeldPrivateFile(rootFile, rootStat, maxRawCaptureRootBytes)
	if err != nil {
		return fail("read root: %v", err)
	}
	if len(rootBytes) != 65 || rootBytes[64] != '\n' || !lowerSHA256.Match(rootBytes[:64]) {
		return fail("ROOT.sha256 must be one lowercase SHA-256 plus LF")
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	root := hex.EncodeToString(manifestDigest[:])
	if string(rootBytes[:64]) != root {
		return fail("root digest does not match exact manifest bytes")
	}

	eventsBytes, err := readHeldPrivateFile(eventsFile, eventsStat, maxRawCaptureEventsBytes)
	if err != nil {
		return fail("read events: %v", err)
	}
	asset := manifest.Assets[0]
	if asset.Bytes != int64(len(eventsBytes)) {
		return fail("events byte count is %d, manifest says %d", len(eventsBytes), asset.Bytes)
	}
	eventsDigest := sha256.Sum256(eventsBytes)
	if asset.SHA256 != hex.EncodeToString(eventsDigest[:]) {
		return fail("events digest does not match manifest")
	}
	events, err := decodeAndVerifyEvents(eventsBytes, manifest.StreamID)
	if err != nil {
		return fail("events: %v", err)
	}
	if events.Count != manifest.EventCount || manifest.TailSequence != manifest.EventCount {
		return fail("event count/tail mismatch: decoded=%d manifest_count=%d tail_sequence=%d",
			events.Count, manifest.EventCount, manifest.TailSequence)
	}
	if events.Count == 0 {
		if manifest.TailEventHash != nil {
			return fail("empty stream carries a tail hash")
		}
	} else if manifest.TailEventHash == nil || *manifest.TailEventHash != events.TailHash {
		return fail("tail event hash does not match final event")
	}
	var finalDirectoryStat syscall.Stat_t
	if err := syscall.Fstat(int(directoryFile.Fd()), &finalDirectoryStat); err != nil || !sameFileState(directoryStat, finalDirectoryStat) {
		return fail("bundle directory changed during verification")
	}
	return Verification{Root: root, Manifest: manifest}, nil
}

func openRawCaptureDirectory(directory string) (*os.File, syscall.Stat_t, error) {
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), directory)
	if file == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, errors.New("construct directory handle")
	}
	var state syscall.Stat_t
	if err := syscall.Fstat(fd, &state); err != nil {
		file.Close()
		return nil, syscall.Stat_t{}, err
	}
	if state.Mode&syscall.S_IFMT != syscall.S_IFDIR || state.Mode&0o777 != 0o700 {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("bundle root must be a real mode-0700 directory")
	}
	return file, state, nil
}

func openHeldPrivateFile(directory *os.File, name string, maximumBytes int64) (*os.File, syscall.Stat_t, error) {
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, errors.New("construct file handle")
	}
	var state syscall.Stat_t
	if err := syscall.Fstat(fd, &state); err != nil {
		file.Close()
		return nil, syscall.Stat_t{}, err
	}
	if state.Mode&syscall.S_IFMT != syscall.S_IFREG || state.Mode&0o777 != 0o600 {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("member must be a regular non-symlink mode-0600 file")
	}
	if state.Size < 0 || state.Size > maximumBytes {
		file.Close()
		return nil, syscall.Stat_t{}, fmt.Errorf("member size %d exceeds bound %d", state.Size, maximumBytes)
	}
	return file, state, nil
}

func readHeldPrivateFile(file *os.File, before syscall.Stat_t, maximumBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, maximumBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximumBytes {
		return nil, fmt.Errorf("member exceeds bound %d", maximumBytes)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &after); err != nil {
		return nil, err
	}
	if !sameFileState(before, after) || int64(len(data)) != before.Size {
		return nil, errors.New("member changed during verification")
	}
	return data, nil
}

func sameFileState(left, right syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func validateSnapshot(snapshot LedgerSnapshot, streamID string) error {
	if snapshot.StreamID != streamID {
		return fmt.Errorf("%w: source returned stream_id %q, want %q", ErrInvalidInput, snapshot.StreamID, streamID)
	}
	if snapshot.EventCount < 0 || snapshot.TailSequence < 0 ||
		snapshot.EventCount != int64(len(snapshot.Events)) || snapshot.TailSequence != snapshot.EventCount {
		return fmt.Errorf("%w: source returned an inconsistent event count/tail", ErrInvalidInput)
	}
	if snapshot.EventCount > maxRawCaptureEventCount {
		return fmt.Errorf("%w: source event count %d exceeds bound %d", ErrInvalidInput, snapshot.EventCount, maxRawCaptureEventCount)
	}
	if len(snapshot.Events) == 0 {
		if snapshot.TailHash != nil {
			return fmt.Errorf("%w: empty snapshot carries a tail hash", ErrInvalidInput)
		}
		return nil
	}
	if snapshot.TailHash == nil {
		return fmt.Errorf("%w: nonempty snapshot has no tail hash", ErrInvalidInput)
	}
	var previous *[32]byte
	var encodedBytes int64
	for i := range snapshot.Events {
		event := snapshot.Events[i]
		if event.StreamID != streamID || event.Sequence != int64(i+1) {
			return fmt.Errorf("%w: event %d stream/sequence mismatch", ErrInvalidInput, i+1)
		}
		if err := validateLedgerText("event_id", event.EventID); err != nil {
			return err
		}
		if err := validateLedgerText("event_type", event.EventType); err != nil {
			return err
		}
		canonical, err := protocol.CanonicalJSON([]byte(event.PayloadCanonical))
		if err != nil || canonical != event.PayloadCanonical {
			return fmt.Errorf("%w: event %d payload_canonical is not exact canonical JSON", ErrInvalidInput, i+1)
		}
		payloadHash := sha256.Sum256([]byte(event.PayloadCanonical))
		if payloadHash != event.PayloadSHA256 {
			return fmt.Errorf("%w: event %d payload SHA-256 mismatch", ErrInvalidInput, i+1)
		}
		if event.CommittedAt.IsZero() {
			return fmt.Errorf("%w: event %d has a zero committed_at", ErrInvalidInput, i+1)
		}
		if !equalHashes(event.PrevEventHash, previous) {
			return fmt.Errorf("%w: event %d previous hash mismatch", ErrInvalidInput, i+1)
		}
		line, err := encodeEventLine(event)
		if err != nil {
			return fmt.Errorf("%w: event %d encoding is invalid: %v", ErrInvalidInput, i+1, err)
		}
		if len(line) > maxRawCaptureEventLineBytes {
			return fmt.Errorf("%w: event %d encoded line exceeds bound %d", ErrInvalidInput, i+1, maxRawCaptureEventLineBytes)
		}
		encodedBytes += int64(len(line))
		if encodedBytes > maxRawCaptureEventsBytes {
			return fmt.Errorf("%w: encoded events exceed bound %d", ErrInvalidInput, maxRawCaptureEventsBytes)
		}
		hash := event.EventHash
		previous = &hash
	}
	if previous == nil || *previous != *snapshot.TailHash {
		return fmt.Errorf("%w: snapshot tail hash mismatch", ErrInvalidInput)
	}
	return nil
}

func validateManifest(manifest RawCaptureManifest) error {
	if manifest.Schema != SchemaID || manifest.Version != SchemaVersion || manifest.Stage != RawCaptureStage ||
		manifest.CaptureKind != LedgerStreamKind || manifest.NormalizationVersion != NormalizationVersion {
		return errors.New("schema/version/stage/capture_kind/normalization_version drifted")
	}
	if err := validateSourceIdentity(manifest.Source); err != nil {
		return err
	}
	if err := validateLedgerText("stream_id", manifest.StreamID); err != nil {
		return err
	}
	if manifest.EventCount < 0 || manifest.TailSequence < 0 {
		return errors.New("negative event count/tail sequence")
	}
	if manifest.EventCount > maxRawCaptureEventCount {
		return fmt.Errorf("event count exceeds bound %d", maxRawCaptureEventCount)
	}
	if manifest.EventCount == 0 {
		if manifest.TailSequence != 0 || manifest.TailEventHash != nil {
			return errors.New("empty stream tail must be sequence 0 and null hash")
		}
	} else if manifest.TailSequence != manifest.EventCount || manifest.TailEventHash == nil ||
		!lowerSHA256.MatchString(*manifest.TailEventHash) {
		return errors.New("nonempty stream count/tail invariant failed")
	}
	if len(manifest.Assets) != 1 {
		return errors.New("asset inventory must contain exactly events.ndjson")
	}
	asset := manifest.Assets[0]
	if asset.Path != EventsName || asset.MediaType != "application/x-ndjson" || asset.Bytes < 0 ||
		asset.Bytes > maxRawCaptureEventsBytes ||
		!lowerSHA256.MatchString(asset.SHA256) {
		return errors.New("events asset metadata is invalid")
	}
	return nil
}

type verifiedEventSummary struct {
	Count    int64
	TailHash string
}

func decodeAndVerifyEvents(data []byte, streamID string) (verifiedEventSummary, error) {
	if len(data) == 0 {
		return verifiedEventSummary{}, nil
	}
	if data[len(data)-1] != '\n' {
		return verifiedEventSummary{}, errors.New("events.ndjson must end in LF")
	}
	body := data[:len(data)-1]
	start := 0
	lineNumber := int64(0)
	var previous *string
	for {
		lineNumber++
		if lineNumber > maxRawCaptureEventCount {
			return verifiedEventSummary{}, fmt.Errorf("event count exceeds bound %d", maxRawCaptureEventCount)
		}
		relativeEnd := bytes.IndexByte(body[start:], '\n')
		end := len(body)
		if relativeEnd >= 0 {
			end = start + relativeEnd
		}
		line := body[start:end]
		if len(line) > maxRawCaptureEventLineBytes {
			return verifiedEventSummary{}, fmt.Errorf("line %d exceeds byte bound %d", lineNumber, maxRawCaptureEventLineBytes)
		}
		if len(line) == 0 || bytes.ContainsRune(line, '\r') {
			return verifiedEventSummary{}, fmt.Errorf("line %d is empty or contains CR", lineNumber)
		}
		body, err := canonicalJSONBody(line)
		if err != nil {
			return verifiedEventSummary{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		var event rawEventRecord
		if err := strictDecode(body, &event); err != nil {
			return verifiedEventSummary{}, fmt.Errorf("line %d decode: %w", lineNumber, err)
		}
		if event.Schema != RawEventSchemaID || event.Version != SchemaVersion ||
			event.StreamID != streamID || event.Sequence != lineNumber {
			return verifiedEventSummary{}, fmt.Errorf("line %d schema/version/stream/sequence mismatch", lineNumber)
		}
		if err := validateLedgerText("event_id", event.EventID); err != nil {
			return verifiedEventSummary{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if err := validateLedgerText("event_type", event.EventType); err != nil {
			return verifiedEventSummary{}, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		canonical, err := protocol.CanonicalJSON([]byte(event.PayloadCanonical))
		if err != nil || canonical != event.PayloadCanonical {
			return verifiedEventSummary{}, fmt.Errorf("line %d payload_canonical is not exact canonical JSON", lineNumber)
		}
		payloadHash := sha256.Sum256([]byte(event.PayloadCanonical))
		if event.PayloadSHA256 != hex.EncodeToString(payloadHash[:]) {
			return verifiedEventSummary{}, fmt.Errorf("line %d payload SHA-256 mismatch", lineNumber)
		}
		if !lowerSHA256.MatchString(event.EventHash) {
			return verifiedEventSummary{}, fmt.Errorf("line %d event hash syntax is invalid", lineNumber)
		}
		if (previous == nil && event.PrevEventHash != nil) ||
			(previous != nil && (event.PrevEventHash == nil || *event.PrevEventHash != *previous)) {
			return verifiedEventSummary{}, fmt.Errorf("line %d previous hash linkage mismatch", lineNumber)
		}
		parsedTime, err := time.Parse(timeFormat, event.CommittedAt)
		if err != nil || !strings.HasSuffix(event.CommittedAt, "Z") ||
			parsedTime.UTC().Format(timeFormat) != event.CommittedAt {
			return verifiedEventSummary{}, fmt.Errorf("line %d committed_at is not canonical UTC RFC3339Nano", lineNumber)
		}
		value := event.EventHash
		previous = &value
		if relativeEnd < 0 {
			break
		}
		start = end + 1
	}
	return verifiedEventSummary{Count: lineNumber, TailHash: *previous}, nil
}

func canonicalBody(file []byte) ([]byte, error) {
	if len(file) < 2 || file[len(file)-1] != '\n' || bytes.ContainsAny(file[:len(file)-1], "\r\n") {
		return nil, errors.New("must be one canonical JSON document followed by exactly one LF")
	}
	return canonicalJSONBody(file[:len(file)-1])
}

func canonicalJSONBody(body []byte) ([]byte, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("invalid UTF-8")
	}
	canonical, err := protocol.CanonicalJSON(body)
	if err != nil {
		return nil, err
	}
	if canonical != string(body) {
		return nil, errors.New("JSON is not canonical")
	}
	return body, nil
}

func strictDecode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateSourceIdentity(source SourceIdentity) error {
	if !utf8.ValidString(source.Repository) || len(source.Repository) <= len("https://") ||
		utf8.RuneCountInString(source.Repository) > 512 || !strings.HasPrefix(source.Repository, "https://") ||
		strings.ContainsAny(source.Repository, "\r\n\t ") {
		return fmt.Errorf("%w: source repository must be a nonempty HTTPS URL without whitespace", ErrInvalidInput)
	}
	if !lowerGitOID.MatchString(source.Commit) || !lowerGitOID.MatchString(source.Tree) {
		return fmt.Errorf("%w: source commit/tree must be lowercase 40-hex Git object IDs", ErrInvalidInput)
	}
	return nil
}

func validateLedgerText(field, value string) error {
	if value == "" || !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s must be nonempty valid UTF-8", ErrInvalidInput, field)
	}
	return nil
}

func equalHashes(a, b *[32]byte) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
