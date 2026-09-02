package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type rawCaptureMaterial struct {
	Verification  Verification
	ManifestBytes []byte
	EventsBytes   []byte
	RootBytes     []byte
}

type heldRawCapture struct {
	path      string
	directory *os.File
	state     syscall.Stat_t
	members   []heldRawMember
	material  rawCaptureMaterial
}

type heldRawMember struct {
	file  *os.File
	state syscall.Stat_t
}

// holdVerifiedRawCapture invokes the independent public verifier first, then
// opens and verifies every selected byte through held descriptors. A swap to
// another valid bundle is detected by the initial/final root comparison.
func holdVerifiedRawCapture(directory string) (*heldRawCapture, error) {
	initial, err := VerifyRawCapture(directory)
	if err != nil {
		return nil, err
	}
	directoryFile, directoryState, err := openPrivateDirectoryPath(directory)
	if err != nil {
		return nil, fmt.Errorf("%w: hold verified RAW_CAPTURE", ErrBundleInvalid)
	}
	heldMembers := make([]heldRawMember, 0, 3)
	failed := true
	defer func() {
		if failed {
			for _, member := range heldMembers {
				member.file.Close()
			}
			directoryFile.Close()
		}
	}()

	entries, err := directoryFile.ReadDir(4)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: read held RAW_CAPTURE inventory", ErrBundleInvalid)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wanted := []string{EventsName, ManifestName, RootName}
	sort.Strings(wanted)
	if !equalStrings(names, wanted) {
		return nil, fmt.Errorf("%w: held RAW_CAPTURE inventory", ErrBundleInvalid)
	}

	read := func(name string, maximum int64) ([]byte, error) {
		file, state, openErr := openHeldPrivateFile(directoryFile, name, maximum)
		if openErr != nil {
			return nil, openErr
		}
		data, readErr := readHeldPrivateFile(file, state, maximum)
		if readErr != nil {
			file.Close()
			return nil, readErr
		}
		heldMembers = append(heldMembers, heldRawMember{file: file, state: state})
		return data, nil
	}
	manifestBytes, err := read(ManifestName, maxRawCaptureManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: held RAW_CAPTURE manifest", ErrBundleInvalid)
	}
	rootBytes, err := read(RootName, maxRawCaptureRootBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: held RAW_CAPTURE root", ErrBundleInvalid)
	}
	eventsBytes, err := read(EventsName, maxRawCaptureEventsBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: held RAW_CAPTURE events", ErrBundleInvalid)
	}
	verification, err := verifyRawCaptureBytes(manifestBytes, eventsBytes, rootBytes)
	if err != nil {
		return nil, err
	}
	if verification.Root != initial.Root || !canonicalEqual(verification.Manifest, initial.Manifest) {
		return nil, fmt.Errorf("%w: RAW_CAPTURE changed while acquiring held input", ErrStreamChanged)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(int(directoryFile.Fd()), &after); err != nil || !sameFileState(directoryState, after) ||
		!directoryPathMatchesNoSymlinks(directory, directoryState, true) {
		return nil, fmt.Errorf("%w: RAW_CAPTURE directory changed while acquiring held input", ErrStreamChanged)
	}
	failed = false
	return &heldRawCapture{
		path: directory, directory: directoryFile, state: directoryState, members: heldMembers,
		material: rawCaptureMaterial{
			Verification: verification, ManifestBytes: manifestBytes, EventsBytes: eventsBytes, RootBytes: rootBytes,
		},
	}, nil
}

func (held *heldRawCapture) Close() error {
	if held == nil || held.directory == nil {
		return nil
	}
	var result error
	for _, member := range held.members {
		if err := member.file.Close(); err != nil && result == nil {
			result = err
		}
	}
	if err := held.directory.Close(); err != nil && result == nil {
		result = err
	}
	return result
}

func (held *heldRawCapture) Stable() bool {
	if held == nil || held.directory == nil {
		return false
	}
	var after syscall.Stat_t
	if syscall.Fstat(int(held.directory.Fd()), &after) != nil || !sameFileState(held.state, after) ||
		!directoryPathMatchesNoSymlinks(held.path, held.state, true) {
		return false
	}
	for _, member := range held.members {
		if syscall.Fstat(int(member.file.Fd()), &after) != nil || !sameFileState(member.state, after) {
			return false
		}
	}
	return true
}

// openDirectoryNoSymlinkComponents resolves an absolute directory one held
// component at a time. O_NOFOLLOW on a single full-path open protects only the
// final component; this traversal also rejects symlinks in every ancestor.
func openDirectoryNoSymlinkComponents(directory string) (*os.File, syscall.Stat_t, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, syscall.Stat_t{}, errors.New("resolve directory path")
	}
	absolute = filepath.Clean(absolute)
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(string(filepath.Separator), flags, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, errors.New("open filesystem root")
	}
	for _, component := range strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		next, openErr := syscall.Openat(fd, component, flags, 0)
		_ = syscall.Close(fd)
		if openErr != nil {
			return nil, syscall.Stat_t{}, errors.New("directory path contains an unavailable or symlink component")
		}
		fd = next
	}
	file := os.NewFile(uintptr(fd), "held-directory")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, syscall.Stat_t{}, errors.New("construct held directory")
	}
	var state syscall.Stat_t
	if err := syscall.Fstat(fd, &state); err != nil || state.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = file.Close()
		return nil, syscall.Stat_t{}, errors.New("inspect held directory")
	}
	return file, state, nil
}

func openPrivateDirectoryPath(directory string) (*os.File, syscall.Stat_t, error) {
	file, state, err := openDirectoryNoSymlinkComponents(directory)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	if state.Mode&0o777 != 0o700 || state.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, syscall.Stat_t{}, errors.New("bundle root must be an owner-controlled mode-0700 real directory")
	}
	return file, state, nil
}

func openOwnerControlledDirectoryPath(directory string) (*os.File, syscall.Stat_t, error) {
	file, state, err := openDirectoryNoSymlinkComponents(directory)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	if state.Mode&0o022 != 0 || state.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, syscall.Stat_t{}, errors.New("directory must be owner-controlled and non-group/world-writable")
	}
	return file, state, nil
}

func directoryPathMatchesNoSymlinks(directory string, held syscall.Stat_t, requirePrivate bool) bool {
	file, current, err := openDirectoryNoSymlinkComponents(directory)
	if err != nil {
		return false
	}
	defer file.Close()
	if !sameDirectoryIdentity(held, current) || current.Uid != held.Uid || current.Uid != uint32(os.Geteuid()) {
		return false
	}
	if requirePrivate {
		return current.Mode&0o777 == 0o700
	}
	return current.Mode&0o022 == 0
}

// verifiedRawEventHashes returns the authoritative sequence-to-event-hash map
// from bytes that must already satisfy the independent RAW_CAPTURE verifier.
// It deliberately revalidates the event stream before exposing the mapping.
func verifiedRawEventHashes(data []byte, streamID string) (map[int64]string, error) {
	summary, err := decodeAndVerifyEvents(data, streamID)
	if err != nil {
		return nil, err
	}
	hashes := make(map[int64]string, summary.Count)
	if summary.Count == 0 {
		return hashes, nil
	}
	for _, line := range bytes.Split(data[:len(data)-1], []byte{'\n'}) {
		body, canonicalErr := canonicalJSONBody(line)
		if canonicalErr != nil {
			return nil, canonicalErr
		}
		var event rawEventRecord
		if decodeErr := strictDecode(body, &event); decodeErr != nil {
			return nil, decodeErr
		}
		if _, duplicate := hashes[event.Sequence]; duplicate {
			return nil, errors.New("duplicate RAW_CAPTURE event sequence")
		}
		hashes[event.Sequence] = event.EventHash
	}
	if int64(len(hashes)) != summary.Count {
		return nil, errors.New("RAW_CAPTURE event hash inventory mismatch")
	}
	return hashes, nil
}

func verifyRawCaptureBytes(manifestBytes, eventsBytes, rootBytes []byte) (Verification, error) {
	fail := func() (Verification, error) {
		return Verification{}, fmt.Errorf("%w: embedded RAW_CAPTURE is invalid", ErrBundleInvalid)
	}
	manifestBody, err := canonicalBody(manifestBytes)
	if err != nil {
		return fail()
	}
	var manifest RawCaptureManifest
	if err := strictDecode(manifestBody, &manifest); err != nil || validateManifest(manifest) != nil {
		return fail()
	}
	if len(rootBytes) != 65 || rootBytes[64] != '\n' || !lowerSHA256.Match(rootBytes[:64]) {
		return fail()
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	root := hex.EncodeToString(manifestDigest[:])
	if string(rootBytes[:64]) != root {
		return fail()
	}
	asset := manifest.Assets[0]
	if asset.Bytes != int64(len(eventsBytes)) {
		return fail()
	}
	eventsDigest := sha256.Sum256(eventsBytes)
	if asset.SHA256 != hex.EncodeToString(eventsDigest[:]) {
		return fail()
	}
	events, err := decodeAndVerifyEvents(eventsBytes, manifest.StreamID)
	if err != nil || events.Count != manifest.EventCount || manifest.TailSequence != manifest.EventCount {
		return fail()
	}
	if events.Count == 0 {
		if manifest.TailEventHash != nil {
			return fail()
		}
	} else if manifest.TailEventHash == nil || *manifest.TailEventHash != events.TailHash {
		return fail()
	}
	return Verification{Root: root, Manifest: manifest}, nil
}
