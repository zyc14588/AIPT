package pilot

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"slices"
	"strings"
)

type nativeDynamicInfo struct {
	needed []string
	soname []string
}

// The kernel/ELF loader uses program headers, not section headers. In
// particular, removing the section table must not hide a DT_NEEDED edge.
// This validates file-backed dynamic strings; it is not an execution test or
// proof that an accepted launcher has closed every runtime dlopen search.
func readNativeDynamic(e *elf.File, fileBytes int64) (nativeDynamicInfo, error) {
	var out nativeDynamicInfo
	if e == nil || fileBytes <= 0 || len(e.Progs) == 0 || len(e.Progs) > 128 {
		return out, ErrCodeCapsule
	}
	var loads []*elf.Prog
	var dynamic *elf.Prog
	for _, p := range e.Progs {
		if p.Off > uint64(fileBytes) || p.Filesz > uint64(fileBytes)-p.Off {
			return out, ErrCodeCapsule
		}
		switch p.Type {
		case elf.PT_LOAD:
			// This capsule accepts the fixed Linux amd64 4 KiB mapping class.
			// A later LOAD can replace an earlier *page*, including bytes
			// outside its logical range or zero-filled BSS. Reject overlapping
			// page ranges even when two mappings claim identical file bytes.
			const pageBytes uint64 = 4096
			if p.Memsz < p.Filesz || p.Vaddr > ^uint64(0)-p.Memsz || p.Vaddr%pageBytes != p.Off%pageBytes || (p.Align > 1 && (p.Align&(p.Align-1) != 0 || p.Vaddr%p.Align != p.Off%p.Align)) {
				return out, ErrCodeCapsule
			}
			if p.Memsz == 0 {
				continue
			}
			end := p.Vaddr + p.Memsz
			if end > ^uint64(0)-(pageBytes-1) {
				return out, ErrCodeCapsule
			}
			startPage, endPage := p.Vaddr&^(pageBytes-1), (end+pageBytes-1)&^(pageBytes-1)
			for _, previous := range loads {
				previousStart := previous.Vaddr & ^(pageBytes - 1)
				previousEnd := (previous.Vaddr + previous.Memsz + pageBytes - 1) & ^(pageBytes - 1)
				if startPage < previousEnd && previousStart < endPage {
					return out, ErrCodeCapsule
				}
			}
			loads = append(loads, p)
		case elf.PT_DYNAMIC:
			if dynamic != nil || p.Filesz == 0 || p.Filesz > 1<<20 || p.Filesz%16 != 0 {
				return out, ErrCodeCapsule
			}
			dynamic = p
		}
	}
	if len(loads) == 0 {
		return out, ErrCodeCapsule
	}
	if dynamic == nil {
		for _, s := range e.Sections {
			if s.Type == elf.SHT_DYNAMIC {
				return out, ErrCodeCapsule
			}
		}
		return out, nil
	}
	// The entire dynamic table itself must be mapped from the same file bytes.
	mapRegion := func(addr, size uint64) (*elf.Prog, uint64, error) {
		var selected *elf.Prog
		var offset uint64
		for _, p := range loads {
			if addr < p.Vaddr {
				continue
			}
			delta := addr - p.Vaddr
			if delta > p.Filesz || size > p.Filesz-delta {
				continue
			}
			if selected != nil {
				return nil, 0, ErrCodeCapsule
			}
			selected, offset = p, delta
		}
		if selected == nil {
			return nil, 0, ErrCodeCapsule
		}
		return selected, offset, nil
	}
	load, delta, err := mapRegion(dynamic.Vaddr, dynamic.Filesz)
	if err != nil || load.Off+delta != dynamic.Off {
		return out, ErrCodeCapsule
	}
	raw := make([]byte, int(dynamic.Filesz))
	if _, err := io.ReadFull(dynamic.Open(), raw); err != nil {
		return out, ErrCodeCapsule
	}
	var strtab, strsz uint64
	var hasStrtab, hasStrsz, terminated bool
	var needed, soname []uint64
	for i := 0; i < len(raw); i += 16 {
		tag, val := elf.DynTag(binary.LittleEndian.Uint64(raw[i:i+8])), binary.LittleEndian.Uint64(raw[i+8:i+16])
		if tag == elf.DT_NULL {
			terminated = true
			break
		}
		switch tag {
		case elf.DT_STRTAB:
			if hasStrtab {
				return out, ErrCodeCapsule
			}
			strtab, hasStrtab = val, true
		case elf.DT_STRSZ:
			if hasStrsz {
				return out, ErrCodeCapsule
			}
			strsz, hasStrsz = val, true
		case elf.DT_NEEDED:
			needed = append(needed, val)
		case elf.DT_SONAME:
			soname = append(soname, val)
		}
	}
	if !terminated || len(needed) > 128 || len(soname) > 1 {
		return out, ErrCodeCapsule
	}
	if !hasStrtab || !hasStrsz || strsz == 0 || strsz > 16<<20 {
		return out, ErrCodeCapsule
	}
	load, delta, err = mapRegion(strtab, strsz)
	if err != nil {
		return out, ErrCodeCapsule
	}
	reader := load.Open()
	if _, err := reader.Seek(int64(delta), io.SeekStart); err != nil {
		return out, ErrCodeCapsule
	}
	strs := make([]byte, int(strsz))
	if _, err := io.ReadFull(reader, strs); err != nil {
		return out, ErrCodeCapsule
	}
	readNames := func(offsets []uint64) ([]string, error) {
		names := make([]string, 0, len(offsets))
		seen := map[string]bool{}
		for _, off := range offsets {
			if off >= uint64(len(strs)) {
				return nil, ErrCodeCapsule
			}
			end := bytes.IndexByte(strs[off:], 0)
			if end < 1 || end > 1024 {
				return nil, ErrCodeCapsule
			}
			name := string(strs[off : off+uint64(end)])
			if seen[name] || strings.ContainsAny(name, "\r\n\\") {
				return nil, ErrCodeCapsule
			}
			seen[name] = true
			names = append(names, name)
		}
		return names, nil
	}
	out.needed, err = readNames(needed)
	if err != nil {
		return out, err
	}
	out.soname, err = readNames(soname)
	if err != nil {
		return out, err
	}
	// When section metadata is present, reject a contradictory second view.
	for _, s := range e.Sections {
		if s.Type != elf.SHT_DYNAMIC {
			continue
		}
		sectionNames, err := e.ImportedLibraries()
		if err != nil || !slices.Equal(sectionNames, out.needed) {
			return out, ErrCodeCapsule
		}
		sectionSONAME, err := e.DynString(elf.DT_SONAME)
		if err != nil || !slices.Equal(sectionSONAME, out.soname) {
			return out, ErrCodeCapsule
		}
		break
	}
	return out, nil
}
