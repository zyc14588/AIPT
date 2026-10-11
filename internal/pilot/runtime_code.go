package pilot

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const LocalClosureAuthoritySHA = "a7c7495cd97e950a9c9112df089bff6dfae913fadc9c3c751ce4c63e913277a5"

var ErrCodeCapsule = errors.New("B007 held runtime code identity rejected")
var codeID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)

type CodeDependency struct {
	Name    string `json:"name"`
	AssetID string `json:"asset_id"`
}

// GuestPaths are private capsule locators, never public source or model
// evidence. A digest of a provenance receipt is only a reference: its source
// and package authenticity must be independently accepted by the launcher.
type RuntimeCodeFile struct {
	AssetID          string           `json:"asset_id"`
	Kind             string           `json:"kind"`
	SHA256           string           `json:"sha256"`
	Bytes            int64            `json:"bytes"`
	Executable       bool             `json:"executable"`
	GuestPaths       []string         `json:"guest_paths"`
	ProvenanceSHA256 string           `json:"provenance_sha256"`
	Interpreter      string           `json:"interpreter"`
	Needed           []CodeDependency `json:"needed"`
}

type RuntimeCodeManifest struct {
	Schema             string            `json:"schema"`
	AuthoritySHA256    string            `json:"authority_sha256"`
	SourceCommit       string            `json:"source_commit"`
	SourceTree         string            `json:"source_tree"`
	BuildReceiptSHA256 string            `json:"build_receipt_sha256"`
	Files              []RuntimeCodeFile `json:"files"`
	LaunchRoots        []string          `json:"launch_roots"`
	DynamicAssets      []string          `json:"dynamic_assets"`
}

// HeldCodeCapsule has no Start, certification or readiness operation. It
// checks exact accepted manifest/file bytes and declared ELF edges, then owns
// write-sealed file objects. It does not authenticate provenance references,
// prove every dlopen edge, or establish actual namespace/loader acceptance.
// expectedSHA must originate in the separately accepted run/launch binding,
// never merely be recomputed from an untrusted caller-supplied manifest.
type HeldCodeCapsule struct {
	mu       sync.Mutex
	identity string
	manifest RuntimeCodeManifest
	files    map[string]*os.File
	closed   bool
}

func validGuestCodePath(p string) bool {
	if p == "" || len(p) > 1024 || !strings.HasPrefix(p, "/") || p == "/" || p != path.Clean(p) || strings.ContainsAny(p, "\\\x00\r\n") {
		return false
	}
	for _, reserved := range []string{"/proc", "/sys", "/dev", "/tmp"} {
		if p == reserved || strings.HasPrefix(p, reserved+"/") {
			return false
		}
	}
	return true
}

func decodeCodeManifest(raw []byte, expectedSHA string) (RuntimeCodeManifest, error) {
	var m RuntimeCodeManifest
	if len(raw) == 0 || len(raw) > 4<<20 || !digest(expectedSHA) || inputSHA(raw) != expectedSHA {
		return m, ErrCodeCapsule
	}
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil {
		return m, ErrCodeCapsule
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.Schema != "aipt.private.b007-runtime-code-manifest/v1" || m.AuthoritySHA256 != LocalClosureAuthoritySHA || m.SourceCommit != "e85caa81ea2b65797396018c179b87ad61fa38ab" || m.SourceTree != "85d6c1d06c249f1cdeecaf27ad1cb9fa3d48727f" || !digest(m.BuildReceiptSHA256) || len(m.Files) == 0 || len(m.Files) > 2048 || len(m.LaunchRoots) == 0 || len(m.LaunchRoots) > 16 || len(m.DynamicAssets) > 2048 {
		return m, ErrCodeCapsule
	}
	roundtrip, err := json.Marshal(m)
	if err != nil {
		return m, ErrCodeCapsule
	}
	canonicalRoundtrip, err := protocol.CanonicalJSON(roundtrip)
	if err != nil || canonical != canonicalRoundtrip {
		return m, ErrCodeCapsule
	}
	ids := map[string]RuntimeCodeFile{}
	paths := map[string]bool{}
	var total int64
	previous := ""
	for _, f := range m.Files {
		if !codeID.MatchString(f.AssetID) || f.AssetID <= previous || !digest(f.SHA256) || !digest(f.ProvenanceSHA256) || f.Bytes <= 0 || f.Bytes > 4<<30 || total > (32<<30)-f.Bytes || !slices.Contains([]string{"ELF", "JAVASCRIPT", "DEVICE_CODE", "DATA"}, f.Kind) || len(f.GuestPaths) == 0 || len(f.GuestPaths) > 32 || len(f.Needed) > 128 {
			return m, ErrCodeCapsule
		}
		if f.Kind != "ELF" && (f.Executable || f.Interpreter != "" || len(f.Needed) != 0) {
			return m, ErrCodeCapsule
		}
		previous = f.AssetID
		total += f.Bytes
		ids[f.AssetID] = f
		for _, p := range f.GuestPaths {
			if !validGuestCodePath(p) || paths[p] {
				return m, ErrCodeCapsule
			}
			paths[p] = true
		}
	}
	for p := range paths {
		for parent := path.Dir(p); parent != "/"; parent = path.Dir(parent) {
			if paths[parent] {
				return m, ErrCodeCapsule
			}
		}
	}
	roots := map[string]bool{}
	for _, id := range m.LaunchRoots {
		f, ok := ids[id]
		if !ok || !f.Executable || f.Kind != "ELF" || roots[id] {
			return m, ErrCodeCapsule
		}
		roots[id] = true
	}
	for _, id := range m.DynamicAssets {
		if _, ok := ids[id]; !ok || roots[id] {
			return m, ErrCodeCapsule
		}
		roots[id] = true
	}
	for _, f := range m.Files {
		seen := map[string]bool{}
		for _, edge := range f.Needed {
			target, ok := ids[edge.AssetID]
			if edge.Name == "" || len(edge.Name) > 1024 || strings.ContainsAny(edge.Name, "\x00\r\n\\") || !ok || target.Kind != "ELF" || seen[edge.Name] {
				return m, ErrCodeCapsule
			}
			seen[edge.Name] = true
		}
	}
	return m, nil
}

func sealedCodeSnapshot(source *os.File, size int64, executable bool) (*os.File, error) {
	return sealedCodeSnapshotAt(source, size, executable, 0)
}

func sealedCodeSnapshotAt(source *os.File, size int64, executable bool, offset int64) (*os.File, error) {
	if source == nil || size <= 0 || size > 4<<30 || offset < 0 {
		return nil, ErrCodeCapsule
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || offset > info.Size() || size > info.Size()-offset {
		return nil, ErrCodeCapsule
	}
	// This B007 native closure is explicitly the registered Linux amd64 class.
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, ErrCodeCapsule
	}
	name, err := syscall.BytePtrFromString("aipt-b007-held-code")
	if err != nil {
		return nil, ErrCodeCapsule
	}
	fd, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(name)), 3, 0) // memfd_create, CLOEXEC | ALLOW_SEALING
	if errno != 0 {
		return nil, ErrCodeCapsule
	}
	f := os.NewFile(fd, "sealed B007 code asset")
	fail := func() (*os.File, error) { _ = f.Close(); return nil, ErrCodeCapsule }
	if n, err := io.Copy(f, io.NewSectionReader(source, offset, size)); err != nil || n != size {
		return fail()
	}
	mode := os.FileMode(0400)
	if executable {
		mode = 0500
	}
	if f.Chmod(mode) != nil {
		return fail()
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x409, 0xf); errno != 0 {
		return fail()
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	return f, nil
}

func openPrivateCode(rootFD int, id string, spec RuntimeCodeFile) (*os.File, error) {
	fd, err := syscall.Openat(rootFD, id, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrCodeCapsule
	}
	source := os.NewFile(uintptr(fd), "private B007 captured code")
	defer source.Close()
	var before syscall.Stat_t
	if syscall.Fstat(fd, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Mode&0777 != 0600 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size != spec.Bytes {
		return nil, ErrCodeCapsule
	}
	f, err := sealedCodeSnapshot(source, spec.Bytes, spec.Executable)
	if err != nil {
		return nil, err
	}
	fail := func() (*os.File, error) { _ = f.Close(); return nil, ErrCodeCapsule }
	var after syscall.Stat_t
	if syscall.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return fail()
	}
	h := sha256.New()
	if n, err := io.Copy(h, io.NewSectionReader(f, 0, spec.Bytes)); err != nil || n != spec.Bytes || hex.EncodeToString(h.Sum(nil)) != spec.SHA256 {
		return fail()
	}
	return f, nil
}

func OpenHeldCodeCapsule(raw []byte, expectedSHA, privateRoot string) (*HeldCodeCapsule, error) {
	m, err := decodeCodeManifest(raw, expectedSHA)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(privateRoot, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrCodeCapsule
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&0777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return nil, ErrCodeCapsule
	}
	c := &HeldCodeCapsule{identity: expectedSHA, manifest: m, files: map[string]*os.File{}}
	fail := func() (*HeldCodeCapsule, error) { _ = c.Close(); return nil, ErrCodeCapsule }
	for _, spec := range m.Files {
		f, err := openPrivateCode(fd, spec.AssetID, spec)
		if err != nil {
			return fail()
		}
		c.files[spec.AssetID] = f
	}
	if c.validateELFEdges() != nil {
		return fail()
	}
	return c, nil
}

func (c *HeldCodeCapsule) validateELFEdges() error {
	guest := map[string]string{}
	assets := map[string]RuntimeCodeFile{}
	for _, f := range c.manifest.Files {
		assets[f.AssetID] = f
		for _, p := range f.GuestPaths {
			guest[p] = f.AssetID
		}
	}
	for _, spec := range c.manifest.Files {
		if spec.Kind != "ELF" {
			continue
		}
		e, err := elf.NewFile(io.NewSectionReader(c.files[spec.AssetID], 0, spec.Bytes))
		if err != nil {
			return ErrCodeCapsule
		}
		if e.Class != elf.ELFCLASS64 || e.Data != elf.ELFDATA2LSB || e.Machine != elf.EM_X86_64 || (e.Type != elf.ET_EXEC && e.Type != elf.ET_DYN) {
			return ErrCodeCapsule
		}
		interpreter := ""
		for _, p := range e.Progs {
			if p.Type != elf.PT_INTERP {
				continue
			}
			if interpreter != "" || p.Filesz < 2 || p.Filesz > 4096 {
				return ErrCodeCapsule
			}
			raw, err := io.ReadAll(io.LimitReader(p.Open(), 4097))
			if err != nil || uint64(len(raw)) != p.Filesz || raw[len(raw)-1] != 0 || bytes.IndexByte(raw[:len(raw)-1], 0) >= 0 {
				return ErrCodeCapsule
			}
			interpreter = string(raw[:len(raw)-1])
		}
		if interpreter != spec.Interpreter {
			return ErrCodeCapsule
		}
		if interpreter != "" {
			target, ok := assets[guest[interpreter]]
			if !validGuestCodePath(interpreter) || !ok || target.Kind != "ELF" || !target.Executable {
				return ErrCodeCapsule
			}
		}
		dynamic, err := readNativeDynamic(e, spec.Bytes)
		if err != nil || len(dynamic.needed) != len(spec.Needed) {
			return ErrCodeCapsule
		}
		declared := map[string]string{}
		for _, edge := range spec.Needed {
			declared[edge.Name] = edge.AssetID
		}
		for _, name := range dynamic.needed {
			id, ok := declared[name]
			if !ok {
				return ErrCodeCapsule
			}
			target, err := elf.NewFile(c.files[id])
			if err != nil {
				return ErrCodeCapsule
			}
			targetInfo, err := readNativeDynamic(target, assets[id].Bytes)
			if err != nil {
				return ErrCodeCapsule
			}
			if len(targetInfo.soname) == 1 && targetInfo.soname[0] != name && !strings.Contains(name, "/") {
				return ErrCodeCapsule
			}
			matched := false
			for p, owner := range guest {
				if owner == id && (p == name || !strings.Contains(name, "/") && path.Base(p) == name) {
					matched = true
				}
			}
			if !matched {
				return ErrCodeCapsule
			}
		}
	}
	return nil
}

func (c *HeldCodeCapsule) Identity() string {
	if c == nil {
		return ""
	}
	return c.identity
}

// Descriptor duplicates a sealed object. The caller owns that duplicate and
// must retire all children and close their duplicates before closing capsule.
func (c *HeldCodeCapsule) Descriptor(id string) (*os.File, error) {
	if c == nil {
		return nil, ErrCodeCapsule
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	f := c.files[id]
	if c.closed || f == nil {
		return nil, ErrCodeCapsule
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, ErrCodeCapsule
	}
	return os.NewFile(fd, "inherited sealed B007 code"), nil
}

func (c *HeldCodeCapsule) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	var result error
	for id, f := range c.files {
		result = errors.Join(result, f.Close())
		delete(c.files, id)
	}
	return result
}
