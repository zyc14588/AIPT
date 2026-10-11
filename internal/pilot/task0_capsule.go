package pilot

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"github.com/zyc14588/AIPT/internal/protocol"
)

const task0ManifestPath = "aipt/task0-v2/package-manifest.json"
const task0GatewayAsset = "b007_task0_game_gateway"
const task0GatewayPath = "/aipt/task0-game-gateway.mjs"

func task0SourceAsset(name string) string { return "b007_game_" + inputSHA([]byte(name)) }

func task0AssetSpec(name string, body []byte) RuntimeCodeFile {
	kind := "DATA"
	if strings.HasSuffix(name, ".mjs") {
		kind = "JAVASCRIPT"
	}
	return RuntimeCodeFile{AssetID: task0SourceAsset(name), Kind: kind, SHA256: inputSHA(body), Bytes: int64(len(body)),
		GuestPaths: []string{"/aipt/game/" + name}, ProvenanceSHA256: Task0PrototypeAnnexSHA, Needed: []CodeDependency{}}
}

func task0PinnedManifest(raw []byte) (prototypeSourceManifest, error) {
	var m prototypeSourceManifest
	canonical, err := protocol.CanonicalJSON(raw)
	if err != nil || canonical != string(raw) || inputSHA(raw) != task0PrototypeSourceBinding.CanonicalSHA256 ||
		decodeFrozenJSON(raw, 1<<20, &m) != nil || len(m.Entries) != 45 || m.Schema != task0PrototypeSourceBinding.Schema ||
		m.PackageID != task0PrototypeSourceBinding.PackageID || m.Canonical || m.Lifecycle != "PROTOTYPE" {
		return m, ErrTask0
	}
	return m, nil
}

// This cold assembly returns private file objects, not public game bodies.
// A complete runtime/launch grant must separately accept the containing
// capsule, Node closure, build origins, review and exact implementation CI.
func task0CapsuleAssets(s *Task0PrototypeSources, gateway []byte) ([]RuntimeCodeFile, map[string]*os.File, error) {
	if s == nil || s.identity != Task0PrototypeAnnexSHA || s.binding != task0PrototypeSourceBinding || inputSHA(gateway) != Task0GameGatewaySHA {
		return nil, nil, ErrTask0
	}
	manifest, err := s.copyHeldManifest()
	if err != nil {
		return nil, nil, ErrTask0
	}
	m, err := task0PinnedManifest(manifest)
	if err != nil || len(s.files) != len(m.Entries) {
		return nil, nil, ErrTask0
	}
	contents := map[string][]byte{task0ManifestPath: manifest}
	for _, row := range m.Entries {
		body, err := s.copyHeldSource(row.Path)
		if err != nil || !validInputPath(row.Path) || len(body) != row.Bytes || inputSHA(body) != row.SHA256 || contents[row.Path] != nil {
			return nil, nil, ErrTask0
		}
		contents[row.Path] = body
	}
	files := map[string]*os.File{}
	var specs []RuntimeCodeFile
	fail := func() ([]RuntimeCodeFile, map[string]*os.File, error) {
		for _, f := range files {
			_ = f.Close()
		}
		return nil, nil, ErrTask0
	}
	for name, body := range contents {
		spec := task0AssetSpec(name, body)
		f, err := task0SealedBytes(body)
		if err != nil {
			return fail()
		}
		files[spec.AssetID], specs = f, append(specs, spec)
	}
	f, err := task0SealedBytes(gateway)
	if err != nil {
		return fail()
	}
	files[task0GatewayAsset] = f
	specs = append(specs, RuntimeCodeFile{AssetID: task0GatewayAsset, Kind: "JAVASCRIPT", SHA256: Task0GameGatewaySHA, Bytes: int64(len(gateway)),
		GuestPaths: []string{task0GatewayPath}, ProvenanceSHA256: Task0RuntimeAdapterSHA, Needed: []CodeDependency{}})
	slices.SortFunc(specs, func(a, b RuntimeCodeFile) int { return strings.Compare(a.AssetID, b.AssetID) })
	return specs, files, nil
}

func task0SealedBytes(body []byte) (*os.File, error) {
	if len(body) < 1 || len(body) > 4<<20 || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, ErrTask0
	}
	name, err := syscall.BytePtrFromString("aipt-b007-task0-private-source")
	if err != nil {
		return nil, ErrTask0
	}
	fd, _, errno := syscall.Syscall(319, uintptr(unsafe.Pointer(name)), 3, 0)
	if errno != 0 {
		return nil, ErrTask0
	}
	f := os.NewFile(fd, "sealed private Task0 source")
	fail := func() (*os.File, error) { _ = f.Close(); return nil, ErrTask0 }
	if n, err := f.Write(body); err != nil || n != len(body) || f.Chmod(0400) != nil {
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

// Verify the game subtree has exactly the accepted closure and no extra
// aliases or files. Reading held descriptors never reopens a host path.
func validateTask0Capsule(c *HeldCodeCapsule) error {
	if c == nil || !digest(c.Identity()) {
		return ErrTask0
	}
	f, err := c.Descriptor(task0SourceAsset(task0ManifestPath))
	if err != nil {
		return ErrTask0
	}
	// A duplicated descriptor shares its cursor with the held object. ReadAt
	// keeps verification independent of prior readers and leaves that cursor
	// untouched, including when the same capsule is admitted repeatedly.
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, (1<<20)+1))
	_ = f.Close()
	if err != nil {
		return ErrTask0
	}
	m, err := task0PinnedManifest(raw)
	if err != nil {
		return ErrTask0
	}
	wanted := map[string]RuntimeCodeFile{}
	for _, row := range m.Entries {
		wanted[task0SourceAsset(row.Path)] = RuntimeCodeFile{AssetID: task0SourceAsset(row.Path), Kind: "DATA", SHA256: row.SHA256, Bytes: int64(row.Bytes),
			GuestPaths: []string{"/aipt/game/" + row.Path}, ProvenanceSHA256: Task0PrototypeAnnexSHA, Needed: []CodeDependency{}}
		if strings.HasSuffix(row.Path, ".mjs") {
			v := wanted[task0SourceAsset(row.Path)]
			v.Kind = "JAVASCRIPT"
			wanted[v.AssetID] = v
		}
	}
	wanted[task0SourceAsset(task0ManifestPath)] = task0AssetSpec(task0ManifestPath, raw)
	seen := map[string]bool{}
	for _, spec := range c.manifest.Files {
		if spec.AssetID == task0GatewayAsset {
			if seen[spec.AssetID] || spec.Kind != "JAVASCRIPT" || spec.SHA256 != Task0GameGatewaySHA || spec.Bytes < 1 || spec.Executable ||
				!slices.Equal(spec.GuestPaths, []string{task0GatewayPath}) || spec.ProvenanceSHA256 != Task0RuntimeAdapterSHA || spec.Interpreter != "" || len(spec.Needed) != 0 {
				return ErrTask0
			}
			seen[spec.AssetID] = true
		} else if expected, ok := wanted[spec.AssetID]; ok {
			a, _ := json.Marshal(spec)
			b, _ := json.Marshal(expected)
			if seen[spec.AssetID] || !bytes.Equal(a, b) {
				return ErrTask0
			}
			seen[spec.AssetID] = true
		} else {
			for _, p := range spec.GuestPaths {
				if p == task0GatewayPath || p == "/aipt/game" || strings.HasPrefix(p, "/aipt/game/") || path.Dir(p) == "/aipt/game" {
					return ErrTask0
				}
			}
			continue
		}
		held, err := c.Descriptor(spec.AssetID)
		if err != nil {
			return ErrTask0
		}
		info, err := held.Stat()
		identity := inputSHAFileMetadata(held)
		_ = held.Close()
		if err != nil || info.Size() != spec.Bytes || identity != spec.SHA256 {
			return ErrTask0
		}
	}
	if len(seen) != len(wanted)+1 {
		return ErrTask0
	}
	return nil
}
