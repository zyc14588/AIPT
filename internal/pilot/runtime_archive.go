package pilot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"syscall"
)

const capsuleTrailerBytes = 80
const maxEmbeddedCapsuleBytes = (32 << 30) + (132 << 20) + capsuleTrailerBytes
const capsuleTrailerMagic = "AIPT_B007_CODE_CAPSULE_V1"

// OpenEmbeddedCodeCapsule reads the flat, bounded append-only capsule in an
// already-held, write-sealed helper file. expectedManifestSHA must be fixed
// in the separately authenticated helper build/launch binding. The caller
// must also authenticate the complete helper executable, including its base
// ELF: a self-reported footer or manifest digest never grants that authority.
// This function has no launch, readiness or provenance-acceptance operation.
func OpenEmbeddedCodeCapsule(source *os.File, expectedManifestSHA string) (*HeldCodeCapsule, error) {
	if source == nil || !digest(expectedManifestSHA) {
		return nil, ErrCodeCapsule
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 64+capsuleTrailerBytes || info.Size() > maxEmbeddedCapsuleBytes {
		return nil, ErrCodeCapsule
	}
	seals, _, errno := syscall.Syscall(syscall.SYS_FCNTL, source.Fd(), 0x40a, 0)
	if errno != 0 || seals&0xf != 0xf {
		return nil, ErrCodeCapsule
	}
	var trailer [capsuleTrailerBytes]byte
	if _, err := source.ReadAt(trailer[:], info.Size()-capsuleTrailerBytes); err != nil {
		return nil, ErrCodeCapsule
	}
	var magic [32]byte
	copy(magic[:], capsuleTrailerMagic)
	if !bytes.Equal(magic[:], trailer[:32]) || hex.EncodeToString(trailer[48:]) != expectedManifestSHA {
		return nil, ErrCodeCapsule
	}
	baseEnd, manifestBytes := binary.LittleEndian.Uint64(trailer[32:40]), binary.LittleEndian.Uint64(trailer[40:48])
	end := uint64(info.Size() - capsuleTrailerBytes)
	if baseEnd < 64 || baseEnd > 128<<20 || manifestBytes == 0 || manifestBytes > 4<<20 || baseEnd > end || manifestBytes > end-baseEnd {
		return nil, ErrCodeCapsule
	}
	raw := make([]byte, int(manifestBytes))
	if _, err := source.ReadAt(raw, int64(baseEnd)); err != nil {
		return nil, ErrCodeCapsule
	}
	m, err := decodeCodeManifest(raw, expectedManifestSHA)
	if err != nil {
		return nil, err
	}
	c := &HeldCodeCapsule{identity: expectedManifestSHA, manifest: m, files: map[string]*os.File{}}
	fail := func() (*HeldCodeCapsule, error) { _ = c.Close(); return nil, ErrCodeCapsule }
	offset := baseEnd + manifestBytes
	for _, spec := range m.Files {
		if offset > end || uint64(spec.Bytes) > end-offset {
			return fail()
		}
		f, err := sealedCodeSnapshotAt(source, spec.Bytes, spec.Executable, int64(offset))
		if err != nil {
			return fail()
		}
		c.files[spec.AssetID] = f
		h := sha256.New()
		if n, err := io.Copy(h, io.NewSectionReader(f, 0, spec.Bytes)); err != nil || n != spec.Bytes || hex.EncodeToString(h.Sum(nil)) != spec.SHA256 {
			return fail()
		}
		offset += uint64(spec.Bytes)
	}
	if offset != end || c.validateELFEdges() != nil {
		return fail()
	}
	return c, nil
}
