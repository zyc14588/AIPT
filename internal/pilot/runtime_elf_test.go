package pilot

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"testing"
)

// Only ELF-shaped data, never executed. The first file page has no needed
// dependency; a later overlapping LOAD page has an unregistered dependency.
// The declared graph of the first view is complete, so rejection must result
// from ambiguous mappings, not an already-missing declared dependency.
func nonCanonOverlayELF(kind string) []byte {
	body := make([]byte, 8192)
	put := func(off int, v any) {
		var z bytes.Buffer
		_ = binary.Write(&z, binary.LittleEndian, v)
		copy(body[off:], z.Bytes())
	}
	h := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Phoff: 64, Phentsize: 56, Phnum: 3, Shentsize: 64}
	copy(h.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	put(0, h)
	firstSize := uint64(4096)
	if kind == "disjoint_same_page" {
		firstSize = 1024
	}
	put(64, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R), Vaddr: 0x400000, Filesz: firstSize, Memsz: firstSize, Align: 4096})
	put(120, elf.Prog64{Type: uint32(elf.PT_DYNAMIC), Off: 512, Vaddr: 0x400200, Filesz: 64, Memsz: 64, Align: 8})
	second := elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R), Off: 4096, Vaddr: 0x400000, Filesz: 528, Memsz: 528, Align: 4096}
	switch kind {
	case "partial_strings":
		second.Off = 0x1301
		second.Vaddr = 0x400301
		second.Filesz = 8
		second.Memsz = 8
	case "zero_fill":
		second.Filesz = 0
		second.Memsz = 4096
	case "disjoint_same_page":
		second.Off = 0x1800
		second.Vaddr = 0x400800
		second.Filesz = 16
		second.Memsz = 16
	case "separate_page":
		second.Off = 4096
		second.Vaddr = 0x401000
		second.Filesz = 4096
		second.Memsz = 4096
	case "no_dynamic_overlap":
		put(120, elf.Prog64{Type: uint32(elf.PT_NULL)})
	}
	put(176, second)
	put(512, elf.Dyn64{Tag: int64(elf.DT_DEBUG)})
	put(528, elf.Dyn64{Tag: int64(elf.DT_STRTAB), Val: 0x400300})
	name := "lib_non_canon_unlisted_overlay.so"
	put(544, elf.Dyn64{Tag: int64(elf.DT_STRSZ), Val: uint64(len(name) + 2)})
	put(560, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	copy(body[768:], append(append([]byte{0}, []byte(name)...), 0))
	copy(body[4096:], body[:4096])
	put(4096+512, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: 1})
	return body
}

func TestCodeCapsuleRejectsPartialBSSAndSharedLoadPages(t *testing.T) {
	for _, kind := range []string{"partial_dynamic", "partial_strings", "zero_fill", "disjoint_same_page", "no_dynamic_overlap", "separate_page"} {
		t.Run(kind, func(t *testing.T) {
			body := nonCanonOverlayELF(kind)
			m := nonCanonCodeManifest(body)
			root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
			c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
			if c != nil {
				defer c.Close()
			}
			if kind == "separate_page" {
				if err != nil {
					t.Fatal("nonoverlapping synthetic mapping rejected", err)
				}
				return
			}
			if c != nil || !errors.Is(err, ErrCodeCapsule) {
				t.Fatal("ambiguous LOAD memory admitted", err)
			}
		})
	}
}

func TestCodeCapsuleRejectsInvalidLoadAlignmentAndPageArithmetic(t *testing.T) {
	for _, kind := range []string{"offset_alignment", "invalid_align", "page_end_overflow", "memory_end_overflow"} {
		t.Run(kind, func(t *testing.T) {
			body := nonCanonCodeELF("")
			switch kind {
			case "offset_alignment":
				binary.LittleEndian.PutUint64(body[64+16:64+24], 0x10001)
			case "invalid_align":
				binary.LittleEndian.PutUint64(body[64+48:64+56], 3)
			case "page_end_overflow":
				binary.LittleEndian.PutUint64(body[64+16:64+24], ^uint64(0)-4095)
				binary.LittleEndian.PutUint64(body[64+40:64+48], 4095)
			case "memory_end_overflow":
				binary.LittleEndian.PutUint64(body[64+16:64+24], ^uint64(0)-4095)
				binary.LittleEndian.PutUint64(body[64+40:64+48], 4096)
			}
			m := nonCanonCodeManifest(body)
			root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
			c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
			if c != nil {
				defer c.Close()
			}
			if c != nil || !errors.Is(err, ErrCodeCapsule) {
				t.Fatal("invalid native LOAD admitted", err)
			}
		})
	}
}
