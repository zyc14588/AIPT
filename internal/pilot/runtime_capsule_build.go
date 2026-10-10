package pilot

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
)

// This cold artifact operation has no runtime, model, certification or budget
// admission. The caller must independently authenticate the Go build and all
// source/package origins before an output digest can enter an accepted launch
// binding. A receipt or digest supplied here never grants that authority.
type PreparedCapsuleBuild struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	BaseSHA256     string `json:"base_sha256"`
	HelperSHA256   string `json:"helper_sha256"`
	HelperBytes    int64  `json:"helper_bytes"`
	AssetCount     int    `json:"asset_count"`
}

func BuildPreparedRuntimeCapsule(ctx context.Context, base *os.File, baseSHA string, manifestRaw []byte, manifestSHA string, sources map[string]*os.File, out io.Writer) (PreparedCapsuleBuild, error) {
	var result PreparedCapsuleBuild
	if ctx == nil || ctx.Err() != nil || base == nil || out == nil || !digest(baseSHA) {
		return result, ErrCodeCapsule
	}
	m, e := decodeCodeManifest(manifestRaw, manifestSHA)
	if e != nil || len(sources) != len(m.Files) {
		return result, ErrCodeCapsule
	}
	info, e := base.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > 128<<20 {
		return result, ErrCodeCapsule
	}
	b, e := sealedCodeSnapshot(base, info.Size(), true)
	if e != nil {
		return result, ErrCodeCapsule
	}
	defer b.Close()
	if inputSHAFileMetadata(b) != baseSHA {
		return result, ErrCodeCapsule
	}
	image, e := elf.NewFile(io.NewSectionReader(b, 0, info.Size()))
	if e != nil {
		return result, ErrCodeCapsule
	}
	if image.Class != elf.ELFCLASS64 || image.Data != elf.ELFDATA2LSB || image.Machine != elf.EM_X86_64 || (image.Type != elf.ET_EXEC && image.Type != elf.ET_DYN) {
		return result, ErrCodeCapsule
	}
	for _, p := range image.Progs {
		if p.Type == elf.PT_INTERP {
			return result, ErrCodeCapsule
		}
	}
	d, e := readNativeDynamic(image, info.Size())
	if e != nil || len(d.needed) != 0 {
		return result, ErrCodeCapsule
	}
	c := &HeldCodeCapsule{identity: manifestSHA, manifest: m, files: map[string]*os.File{}}
	defer c.Close()
	for _, spec := range m.Files {
		if ctx.Err() != nil || sources[spec.AssetID] == nil {
			return result, ErrCodeCapsule
		}
		f, e := sealedCodeSnapshot(sources[spec.AssetID], spec.Bytes, spec.Executable)
		if e != nil {
			return result, ErrCodeCapsule
		}
		c.files[spec.AssetID] = f
		sourceInfo, e := sources[spec.AssetID].Stat()
		if e != nil || sourceInfo.Size() != spec.Bytes || inputSHAFileMetadata(f) != spec.SHA256 {
			return result, ErrCodeCapsule
		}
	}
	if c.validateELFEdges() != nil || ctx.Err() != nil {
		return result, ErrCodeCapsule
	}
	h := sha256.New()
	writer := io.MultiWriter(out, h)
	var total int64
	copy := func(source io.Reader, size int64) error {
		if ctx.Err() != nil {
			return ErrCodeCapsule
		}
		n, e := io.Copy(writer, io.LimitReader(source, size))
		total += n
		if e != nil || n != size || ctx.Err() != nil {
			return ErrCodeCapsule
		}
		return nil
	}
	if e = copy(io.NewSectionReader(b, 0, info.Size()), info.Size()); e != nil {
		return result, e
	}
	if n, e := writer.Write(manifestRaw); e != nil || n != len(manifestRaw) {
		return result, ErrCodeCapsule
	} else {
		total += int64(n)
	}
	for _, spec := range m.Files {
		if e = copy(io.NewSectionReader(c.files[spec.AssetID], 0, spec.Bytes), spec.Bytes); e != nil {
			return result, e
		}
	}
	var trailer [capsuleTrailerBytes]byte
	copyMagic := []byte(capsuleTrailerMagic)
	for i := range copyMagic {
		trailer[i] = copyMagic[i]
	}
	binary.LittleEndian.PutUint64(trailer[32:40], uint64(info.Size()))
	binary.LittleEndian.PutUint64(trailer[40:48], uint64(len(manifestRaw)))
	digestBytes, e := hex.DecodeString(manifestSHA)
	if e != nil {
		return result, ErrCodeCapsule
	}
	for i := range digestBytes {
		trailer[48+i] = digestBytes[i]
	}
	if n, e := writer.Write(trailer[:]); e != nil || n != len(trailer) || ctx.Err() != nil {
		return result, ErrCodeCapsule
	} else {
		total += int64(n)
	}
	return PreparedCapsuleBuild{ManifestSHA256: manifestSHA, BaseSHA256: baseSHA, HelperSHA256: hex.EncodeToString(h.Sum(nil)), HelperBytes: total, AssetCount: len(m.Files)}, nil
}
