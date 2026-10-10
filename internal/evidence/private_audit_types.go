package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

const (
	PrivateAuditSchema        = "aipt.private-audit-ready/v1"
	PrivateAuditNormalization = "aipt.audit-ready.private/v1"
	PrivateAuditEncryption    = "AES_256_GCM_V1"
)

// This is an additive Q011 contract. The original B005 public entry and its
// encryption-required refusal remain unchanged.
var ErrPrivateAudit = errors.New("AIPT_PRIVATE_AUDIT_REJECTED")

type PrivateCipherMember struct {
	Ordinal   int64  `json:"ordinal"`
	Path      string `json:"path"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Nonce     string `json:"nonce"`
	Plaintext Asset  `json:"plaintext"`
}

type PrivateAuditManifest struct {
	Schema               string                `json:"schema"`
	Version              string                `json:"version"`
	Stage                string                `json:"stage"`
	NormalizationVersion string                `json:"normalization_version"`
	Source               SourceIdentity        `json:"source"`
	RunID                string                `json:"run_id"`
	RunManifest          ArtifactIdentity      `json:"run_manifest"`
	Ledger               LedgerIdentity        `json:"ledger"`
	RawCaptureRoot       string                `json:"raw_capture_root"`
	PlaintextRoot        string                `json:"plaintext_root"`
	Disclosure           Disclosure            `json:"disclosure"`
	RemoteVerification   RemoteVerification    `json:"remote_verification"`
	Members              []PrivateCipherMember `json:"members"`
}

type PrivateAuditReadyVerification struct {
	Root        string
	Manifest    PrivateAuditManifest
	BundleIndex BundleIndex
	Closure     RunEvidenceClosure
	Report      RunReport
	// Held plaintext is returned only to trusted local evidence preparation.
	// A Web/RPC report adapter must construct its explicit public projection.
	LogicalAssets map[string][]byte
}

// The key is an Owner-only descriptor, never a bundle member or an exported
// field. Only a newly created handle can generate one bundle; loaded handles
// are verification-only. Failure consumes generation authority as well.
type PrivateAuditKey struct {
	mu             sync.Mutex
	directory      *os.File
	file           *os.File
	directoryPath  string
	directoryState syscall.Stat_t
	fileState      syscall.Stat_t
	reference      string
	fresh          bool
	used           bool
}

func CreatePrivateAuditKey(directory string) (*PrivateAuditKey, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrPrivateAudit
	}
	dir, state, err := openPrivateDirectoryPath(directory)
	if err != nil {
		return nil, ErrPrivateAudit
	}
	defer dir.Close()
	var identity [16]byte
	var material [32]byte
	defer clear(material[:])
	if _, err = rand.Read(identity[:]); err != nil {
		return nil, ErrPrivateAudit
	}
	if _, err = rand.Read(material[:]); err != nil {
		return nil, ErrPrivateAudit
	}
	reference := "key-" + hex.EncodeToString(identity[:])
	fd, err := syscall.Openat(int(dir.Fd()), reference+".key", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrPrivateAudit
	}
	f := os.NewFile(uintptr(fd), "private evidence key")
	if f == nil {
		syscall.Close(fd)
		return nil, ErrPrivateAudit
	}
	n, writeErr := f.Write(material[:])
	modeErr := f.Chmod(0400)
	syncErr := f.Sync()
	closeErr := f.Close()
	if n != 32 || writeErr != nil || modeErr != nil || syncErr != nil || closeErr != nil || dir.Sync() != nil || !directoryPathMatchesNoSymlinks(directory, state, true) {
		return nil, ErrPrivateAudit
	}
	key, err := LoadPrivateAuditKey(directory, reference)
	if err == nil {
		key.fresh = true
	}
	return key, err
}

func LoadPrivateAuditKey(directory, reference string) (*PrivateAuditKey, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || !privateKeyReference(reference) {
		return nil, ErrPrivateAudit
	}
	dir, state, err := openPrivateDirectoryPath(directory)
	if err != nil {
		return nil, ErrPrivateAudit
	}
	return loadPrivateAuditKeyDirectory(dir, state, directory, reference)
}

// LoadPrivateAuditKeyAt retains its own descriptor. It never resolves a
// mutable directory pathname, and its returned handle is verification-only.
func LoadPrivateAuditKeyAt(directory *os.File, reference string) (*PrivateAuditKey, error) {
	if !privateKeyReference(reference) {
		return nil, ErrPrivateAudit
	}
	dir, state, err := copyPrivateAuditDirectory(directory)
	if err != nil {
		return nil, ErrPrivateAudit
	}
	return loadPrivateAuditKeyDirectory(dir, state, "", reference)
}

func loadPrivateAuditKeyDirectory(dir *os.File, state syscall.Stat_t, path, reference string) (*PrivateAuditKey, error) {
	f, fs, err := openPrivateAuditFile(dir, reference+".key", 32)
	if err != nil {
		dir.Close()
		return nil, ErrPrivateAudit
	}
	if fs.Size != 32 || fs.Mode&0777 != 0400 || fs.Nlink != 1 || fs.Uid != uint32(os.Geteuid()) {
		f.Close()
		dir.Close()
		return nil, ErrPrivateAudit
	}
	return &PrivateAuditKey{directory: dir, file: f, directoryPath: path, directoryState: state, fileState: fs, reference: reference}, nil
}

// Openat(".") creates a separate directory stream as well as retaining the
// inode. Dup would share ReadDir's offset with a concurrent report request.
func copyPrivateAuditDirectory(directory *os.File) (*os.File, syscall.Stat_t, error) {
	if directory == nil {
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	var before syscall.Stat_t
	if syscall.Fstat(int(directory.Fd()), &before) != nil || !privateAuditDirectoryState(before) {
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	fd, err := syscall.Openat(int(directory.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	f := os.NewFile(uintptr(fd), "held private evidence directory")
	if f == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	var after syscall.Stat_t
	if syscall.Fstat(fd, &after) != nil || !privateAuditDirectoryState(after) || !sameFileState(before, after) {
		f.Close()
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	return f, after, nil
}

func privateAuditDirectoryState(s syscall.Stat_t) bool {
	return s.Mode&syscall.S_IFMT == syscall.S_IFDIR && s.Mode&0777 == 0700 && s.Uid == uint32(os.Geteuid())
}

func privateKeyReference(s string) bool {
	if len(s) != 36 || !strings.HasPrefix(s, "key-") {
		return false
	}
	decoded, err := hex.DecodeString(s[4:])
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == s[4:]
}

func openPrivateAuditFile(directory *os.File, name string, maximum int64) (*os.File, syscall.Stat_t, error) {
	if directory == nil || !safeBundleMember.MatchString(name) || maximum < 0 {
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	f := os.NewFile(uintptr(fd), "held private evidence member")
	if f == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	var state syscall.Stat_t
	if syscall.Fstat(fd, &state) != nil || state.Mode&syscall.S_IFMT != syscall.S_IFREG || state.Mode&0777 != 0400 || state.Size < 0 || state.Size > maximum || state.Nlink != 1 || state.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, syscall.Stat_t{}, ErrPrivateAudit
	}
	return f, state, nil
}

func (k *PrivateAuditKey) Reference() string {
	if k == nil {
		return ""
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.file == nil {
		return ""
	}
	return k.reference
}

func (k *PrivateAuditKey) read(consume bool) ([]byte, error) {
	if k == nil {
		return nil, ErrPrivateAudit
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.file == nil || k.directory == nil || !privateKeyReference(k.reference) || !k.directoryStable() {
		return nil, ErrPrivateAudit
	}
	if consume {
		if !k.fresh || k.used {
			return nil, ErrPrivateAudit
		}
		k.used = true
	}
	var fs syscall.Stat_t
	if syscall.Fstat(int(k.file.Fd()), &fs) != nil || !sameFileState(k.fileState, fs) || fs.Size != 32 || fs.Mode&0777 != 0400 || fs.Nlink != 1 || fs.Uid != uint32(os.Geteuid()) {
		return nil, ErrPrivateAudit
	}
	named, namedState, err := openPrivateAuditFile(k.directory, k.reference+".key", 32)
	if err != nil {
		return nil, ErrPrivateAudit
	}
	named.Close()
	if !sameFileState(k.fileState, namedState) {
		return nil, ErrPrivateAudit
	}
	body, err := io.ReadAll(io.NewSectionReader(k.file, 0, 33))
	if err != nil || len(body) != 32 || syscall.Fstat(int(k.file.Fd()), &fs) != nil || !sameFileState(k.fileState, fs) {
		clear(body)
		return nil, ErrPrivateAudit
	}
	return body, nil
}

// Caller holds k.mu. Path-based handles also retain the original pathname
// identity; At handles validate their retained directory and named key only.
func (k *PrivateAuditKey) directoryStable() bool {
	var current syscall.Stat_t
	return k.directory != nil && syscall.Fstat(int(k.directory.Fd()), &current) == nil && privateAuditDirectoryState(current) &&
		sameDirectoryIdentity(k.directoryState, current) &&
		(k.directoryPath == "" || directoryPathMatchesNoSymlinks(k.directoryPath, k.directoryState, true))
}

func (k *PrivateAuditKey) separateDirectory(state syscall.Stat_t) bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.file != nil && k.directoryStable() && !sameDirectoryIdentity(k.directoryState, state)
}

// Descriptor generation rejects a key directory that is equal to, contains,
// or is contained by either evidence directory. Walk held directory objects,
// including aliases, rather than using a serialized local pathname.
func (k *PrivateAuditKey) separateHeldDirectory(directory *os.File) bool {
	if k == nil || directory == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.file != nil && k.directoryStable() && privateDirectoryNotAncestor(k.directory, directory) && privateDirectoryNotAncestor(directory, k.directory)
}

func privateDirectoryNotAncestor(ancestor, descendant *os.File) bool {
	if ancestor == nil || descendant == nil {
		return false
	}
	var wanted syscall.Stat_t
	if syscall.Fstat(int(ancestor.Fd()), &wanted) != nil || wanted.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return false
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Openat(int(descendant.Fd()), ".", flags, 0)
	if err != nil {
		return false
	}
	defer func() { syscall.Close(fd) }()
	for range 1024 {
		var here, parent syscall.Stat_t
		if syscall.Fstat(fd, &here) != nil || sameDirectoryIdentity(wanted, here) {
			return false
		}
		next, e := syscall.Openat(fd, "..", flags, 0)
		if e != nil {
			return false
		}
		if syscall.Fstat(next, &parent) != nil {
			syscall.Close(next)
			return false
		}
		if sameDirectoryIdentity(here, parent) {
			syscall.Close(next)
			return true
		}
		syscall.Close(fd)
		fd = next
	}
	return false
}

func (k *PrivateAuditKey) Close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var err error
	if k.file != nil {
		err = k.file.Close()
		k.file = nil
	}
	if k.directory != nil {
		err = errors.Join(err, k.directory.Close())
		k.directory = nil
	}
	return err
}

func (k *PrivateAuditKey) separateFrom(path string) bool {
	if k == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	dir := k.directoryPath
	return dir != "" && path != dir && !strings.HasPrefix(path, dir+string(os.PathSeparator)) && !strings.HasPrefix(dir, path+string(os.PathSeparator))
}
