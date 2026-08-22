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
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const timeFormat = time.RFC3339Nano

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
	st, err := os.Lstat(directory)
	if err != nil {
		return fail("lstat bundle: %v", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return fail("bundle root must be a real directory")
	}
	if st.Mode().Perm() != 0o700 {
		return fail("bundle root mode is %04o, want 0700", st.Mode().Perm())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fail("read bundle directory: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fail("inspect %q: %v", entry.Name(), infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fail("%q must be a regular non-symlink file", entry.Name())
		}
		if info.Mode().Perm() != 0o600 {
			return fail("%q mode is %04o, want 0600", entry.Name(), info.Mode().Perm())
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{EventsName, ManifestName, RootName}
	sort.Strings(wantNames)
	if !equalStrings(names, wantNames) {
		return fail("file inventory is %v, want exactly %v", names, wantNames)
	}

	manifestBytes, err := os.ReadFile(filepath.Join(directory, ManifestName))
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

	rootBytes, err := os.ReadFile(filepath.Join(directory, RootName))
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

	eventsBytes, err := os.ReadFile(filepath.Join(directory, EventsName))
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
	if int64(len(events)) != manifest.EventCount || manifest.TailSequence != manifest.EventCount {
		return fail("event count/tail mismatch: decoded=%d manifest_count=%d tail_sequence=%d",
			len(events), manifest.EventCount, manifest.TailSequence)
	}
	if len(events) == 0 {
		if manifest.TailEventHash != nil {
			return fail("empty stream carries a tail hash")
		}
	} else if manifest.TailEventHash == nil || *manifest.TailEventHash != events[len(events)-1].EventHash {
		return fail("tail event hash does not match final event")
	}
	return Verification{Root: root, Manifest: manifest}, nil
}

func validateSnapshot(snapshot LedgerSnapshot, streamID string) error {
	if snapshot.StreamID != streamID {
		return fmt.Errorf("%w: source returned stream_id %q, want %q", ErrInvalidInput, snapshot.StreamID, streamID)
	}
	if snapshot.EventCount < 0 || snapshot.TailSequence < 0 ||
		snapshot.EventCount != int64(len(snapshot.Events)) || snapshot.TailSequence != snapshot.EventCount {
		return fmt.Errorf("%w: source returned an inconsistent event count/tail", ErrInvalidInput)
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
		!lowerSHA256.MatchString(asset.SHA256) {
		return errors.New("events asset metadata is invalid")
	}
	return nil
}

func decodeAndVerifyEvents(data []byte, streamID string) ([]rawEventRecord, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, errors.New("events.ndjson must end in LF")
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})
	out := make([]rawEventRecord, 0, len(lines))
	var previous *string
	for i, line := range lines {
		if len(line) == 0 || bytes.ContainsRune(line, '\r') {
			return nil, fmt.Errorf("line %d is empty or contains CR", i+1)
		}
		body, err := canonicalJSONBody(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		var event rawEventRecord
		if err := strictDecode(body, &event); err != nil {
			return nil, fmt.Errorf("line %d decode: %w", i+1, err)
		}
		if event.Schema != RawEventSchemaID || event.Version != SchemaVersion ||
			event.StreamID != streamID || event.Sequence != int64(i+1) {
			return nil, fmt.Errorf("line %d schema/version/stream/sequence mismatch", i+1)
		}
		if err := validateLedgerText("event_id", event.EventID); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if err := validateLedgerText("event_type", event.EventType); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		canonical, err := protocol.CanonicalJSON([]byte(event.PayloadCanonical))
		if err != nil || canonical != event.PayloadCanonical {
			return nil, fmt.Errorf("line %d payload_canonical is not exact canonical JSON", i+1)
		}
		payloadHash := sha256.Sum256([]byte(event.PayloadCanonical))
		if event.PayloadSHA256 != hex.EncodeToString(payloadHash[:]) {
			return nil, fmt.Errorf("line %d payload SHA-256 mismatch", i+1)
		}
		if !lowerSHA256.MatchString(event.EventHash) {
			return nil, fmt.Errorf("line %d event hash syntax is invalid", i+1)
		}
		if (previous == nil && event.PrevEventHash != nil) ||
			(previous != nil && (event.PrevEventHash == nil || *event.PrevEventHash != *previous)) {
			return nil, fmt.Errorf("line %d previous hash linkage mismatch", i+1)
		}
		parsedTime, err := time.Parse(timeFormat, event.CommittedAt)
		if err != nil || !strings.HasSuffix(event.CommittedAt, "Z") ||
			parsedTime.UTC().Format(timeFormat) != event.CommittedAt {
			return nil, fmt.Errorf("line %d committed_at is not canonical UTC RFC3339Nano", i+1)
		}
		value := event.EventHash
		previous = &value
		out = append(out, event)
	}
	return out, nil
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
