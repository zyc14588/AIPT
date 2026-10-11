package pilot

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// These ELF-shaped fixtures are data, not loadable runtime programs. They are
// never executed and their provenance labels explicitly have no acceptance.
func nonCanonCodeELF(needed string) []byte {
	h := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Phoff: 64, Phentsize: 56, Phnum: 1, Shentsize: 64}
	copy(h.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	size := 192
	if needed != "" {
		h.Phnum = 2
		h.Shoff = 0x200
		h.Shnum = 3
		size = 0x200 + 3*64
	}
	b := make([]byte, size)
	put := func(off int, v any) {
		var out bytes.Buffer
		_ = binary.Write(&out, binary.LittleEndian, v)
		copy(b[off:], out.Bytes())
	}
	put(0, h)
	put(64, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: 0, Vaddr: 0x10000, Filesz: uint64(size), Memsz: uint64(size), Align: 0x1000})
	if needed != "" {
		put(120, elf.Prog64{Type: uint32(elf.PT_DYNAMIC), Off: 0x100, Vaddr: 0x10100, Filesz: 64, Memsz: 64})
		put(0x100, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: 1})
		put(0x110, elf.Dyn64{Tag: int64(elf.DT_STRTAB), Val: 0x10180})
		put(0x120, elf.Dyn64{Tag: int64(elf.DT_STRSZ), Val: uint64(len(needed) + 2)})
		put(0x130, elf.Dyn64{Tag: int64(elf.DT_NULL)})
		copy(b[0x180:], append(append([]byte{0}, []byte(needed)...), 0))
		put(0x200+64, elf.Section64{Type: uint32(elf.SHT_DYNAMIC), Off: 0x100, Size: 64, Link: 2, Addralign: 8, Entsize: 16})
		put(0x200+128, elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: 0x180, Size: uint64(len(needed) + 2), Addralign: 1})
	}
	return b
}

func nonCanonCodeManifest(body []byte) RuntimeCodeManifest {
	return RuntimeCodeManifest{
		Schema: "aipt.private.b007-runtime-code-manifest/v1", AuthoritySHA256: LocalClosureAuthoritySHA,
		SourceCommit: "e85caa81ea2b65797396018c179b87ad61fa38ab", SourceTree: "85d6c1d06c249f1cdeecaf27ad1cb9fa3d48727f",
		BuildReceiptSHA256: inputSHA([]byte("NON_CANON_NO_BUILD_OR_PACKAGE_PROVENANCE_ACCEPTANCE")),
		Files:              []RuntimeCodeFile{{AssetID: "server_fixture", Kind: "ELF", SHA256: inputSHA(body), Bytes: int64(len(body)), Executable: true, GuestPaths: []string{"/app/non_canon_server"}, ProvenanceSHA256: inputSHA([]byte("NON_CANON_NO_SOURCE_ACCEPTANCE")), Needed: []CodeDependency{}}},
		LaunchRoots:        []string{"server_fixture"}, DynamicAssets: []string{},
	}
}

func prepareNonCanonCode(t *testing.T, m RuntimeCodeManifest, contents map[string][]byte) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for id, body := range contents {
		if err := os.WriteFile(filepath.Join(root, id), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return root, raw
}

func TestCodeCapsuleSealsExactBytesAgainstInPlaceAndPathSwap(t *testing.T) {
	body := nonCanonCodeELF("")
	m := nonCanonCodeManifest(body)
	root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
	c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Identity() != inputSHA(raw) {
		t.Fatal("manifest binding lost")
	}
	name := filepath.Join(root, "server_fixture")
	if err = os.WriteFile(name, []byte("changed mutable source"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, []byte("replacement inode"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := c.Descriptor("server_fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	observed, err := io.ReadAll(io.NewSectionReader(f, 0, int64(len(body))))
	if err != nil || !bytes.Equal(observed, body) {
		t.Fatal("held bytes followed source mutation", err)
	}
	if _, err := f.WriteAt([]byte("mutation"), 0); !errors.Is(err, syscall.EPERM) {
		t.Fatal("sealed snapshot remained writable", err)
	}
	if err := f.Truncate(0); !errors.Is(err, syscall.EPERM) {
		t.Fatal("sealed snapshot remained shrinkable", err)
	}
	if _, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); !errors.Is(err, ErrCodeCapsule) {
		t.Fatal("new preparation accepted changed source", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Descriptor("server_fixture"); !errors.Is(err, ErrCodeCapsule) {
		t.Fatal("retired capsule exposed a new descriptor", err)
	}
}

func TestCodeCapsuleRejectsMissingChangedAndUnsafeFileObjects(t *testing.T) {
	for _, mutation := range []string{"missing", "changed", "symlink", "hardlink", "permissive_file", "permissive_root"} {
		t.Run(mutation, func(t *testing.T) {
			body := nonCanonCodeELF("")
			m := nonCanonCodeManifest(body)
			root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
			name := filepath.Join(root, "server_fixture")
			switch mutation {
			case "missing":
				_ = os.Remove(name)
			case "changed":
				_ = os.WriteFile(name, bytes.Repeat([]byte{1}, len(body)), 0600)
			case "symlink":
				_ = os.Rename(name, name+"_target")
				_ = os.Symlink(name+"_target", name)
			case "hardlink":
				_ = os.Link(name, name+"_alias")
			case "permissive_file":
				_ = os.Chmod(name, 0644)
			case "permissive_root":
				_ = os.Chmod(root, 0755)
			}
			if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
				if c != nil {
					_ = c.Close()
				}
				t.Fatal("unsafe captured object admitted", err)
			}
		})
	}
}

func TestCodeCapsuleSameEntryCannotHideAnOmittedELFDependency(t *testing.T) {
	body := nonCanonCodeELF("lib_non_canon.so")
	m := nonCanonCodeManifest(body)
	root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
	if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatal("entry digest hid undeclared native library", err)
	}
	lib := nonCanonCodeELF("")
	m.Files = append([]RuntimeCodeFile{{AssetID: "library_fixture", Kind: "ELF", SHA256: inputSHA(lib), Bytes: int64(len(lib)), GuestPaths: []string{"/app/lib_non_canon.so"}, ProvenanceSHA256: inputSHA([]byte("NON_CANON_LIBRARY_NO_PACKAGE_ACCEPTANCE")), Needed: []CodeDependency{}}}, m.Files...)
	m.Files[1].Needed = []CodeDependency{{Name: "lib_non_canon.so", AssetID: "library_fixture"}}
	root, raw = prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body, "library_fixture": lib})
	c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
	if err != nil {
		t.Fatal("complete fixture graph rejected", err)
	}
	_ = c.Close()
	// Neither a present host library nor an unchanged entry hash is a fallback
	// for the missing exact captured library file.
	_ = os.Remove(filepath.Join(root, "library_fixture"))
	if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatal("unlisted fallback accepted", err)
	}
}

func TestCodeCapsuleRejectsBindingPromotionAndAmbiguousNamespacePaths(t *testing.T) {
	for _, mutation := range []string{"wrong_authority", "wrong_source", "missing_provenance", "unlisted_dynamic", "duplicate_guest", "ancestor_file", "proc_guest", "noncanonical_guest", "unknown_field", "duplicate_json_field", "wrong_expected_digest"} {
		t.Run(mutation, func(t *testing.T) {
			body := nonCanonCodeELF("")
			m := nonCanonCodeManifest(body)
			switch mutation {
			case "wrong_authority":
				m.AuthoritySHA256 = strings.Repeat("0", 64)
			case "wrong_source":
				m.SourceCommit = strings.Repeat("0", 40)
			case "missing_provenance":
				m.Files[0].ProvenanceSHA256 = ""
			case "unlisted_dynamic":
				m.DynamicAssets = []string{"unlisted_library"}
			case "duplicate_guest":
				m.Files[0].GuestPaths = append(m.Files[0].GuestPaths, m.Files[0].GuestPaths[0])
			case "ancestor_file":
				m.Files[0].GuestPaths = append(m.Files[0].GuestPaths, "/app")
			case "proc_guest":
				m.Files[0].GuestPaths = []string{"/proc/self/exe"}
			case "noncanonical_guest":
				m.Files[0].GuestPaths = []string{"/app/../host/executable"}
			}
			root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
			if mutation == "unknown_field" {
				raw = append([]byte(`{"unknown":true,`), raw[1:]...)
			}
			if mutation == "duplicate_json_field" {
				raw = append([]byte(`{"schema":"wrong",`), raw[1:]...)
			}
			expected := inputSHA(raw)
			if mutation == "wrong_expected_digest" {
				expected = strings.Repeat("0", 64)
			}
			if c, err := OpenHeldCodeCapsule(raw, expected, root); c != nil || !errors.Is(err, ErrCodeCapsule) {
				if c != nil {
					_ = c.Close()
				}
				t.Fatal("ambiguous/unbound identity admitted", err)
			}
		})
	}
}

func TestCodeCapsuleConcurrentClosureCannotReopenAdmission(t *testing.T) {
	body := nonCanonCodeELF("")
	m := nonCanonCodeManifest(body)
	root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
	c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
	if err != nil {
		t.Fatal(err)
	}
	var w sync.WaitGroup
	for i := 0; i < 100; i++ {
		w.Go(func() {
			f, err := c.Descriptor("server_fixture")
			if err == nil {
				_ = f.Close()
			} else if !errors.Is(err, ErrCodeCapsule) {
				t.Error(err)
			}
		})
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	w.Wait()
	if _, err := c.Descriptor("server_fixture"); !errors.Is(err, ErrCodeCapsule) {
		t.Fatal("closed capsule admitted file", err)
	}
}

func nonCanonInterpreterELF(interpreter string) []byte {
	size := 176 + len(interpreter) + 1
	h := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT), Ehsize: 64, Phoff: 64, Phentsize: 56, Phnum: 2, Shentsize: 64}
	copy(h.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, h)
	_ = binary.Write(&out, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Off: 0, Vaddr: 0x10000, Filesz: uint64(size), Memsz: uint64(size), Align: 0x1000})
	_ = binary.Write(&out, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_INTERP), Off: 176, Vaddr: 0x100b0, Filesz: uint64(len(interpreter) + 1), Memsz: uint64(len(interpreter) + 1)})
	out.WriteString(interpreter)
	out.WriteByte(0)
	return out.Bytes()
}

func TestCodeCapsuleRequiresCapturedExecutableELFInterpreter(t *testing.T) {
	for _, mode := range []string{"missing", "data", "non_executable", "exact_elf"} {
		t.Run(mode, func(t *testing.T) {
			body := nonCanonInterpreterELF("/lib64/non_canon_loader")
			m := nonCanonCodeManifest(body)
			m.Files[0].Interpreter = "/lib64/non_canon_loader"
			contents := map[string][]byte{"server_fixture": body}
			if mode != "missing" {
				loader := nonCanonCodeELF("")
				kind := "ELF"
				if mode == "data" {
					loader = []byte("NON_CANON_NOT_AN_ELF_LOADER")
					kind = "DATA"
				}
				m.Files = append([]RuntimeCodeFile{{AssetID: "loader_fixture", Kind: kind, SHA256: inputSHA(loader), Bytes: int64(len(loader)), Executable: mode == "exact_elf", GuestPaths: []string{"/lib64/non_canon_loader"}, ProvenanceSHA256: inputSHA([]byte("NON_CANON_NO_PACKAGE_OR_RUNTIME_ACCEPTANCE")), Needed: []CodeDependency{}}}, m.Files...)
				contents["loader_fixture"] = loader
			}
			root, raw := prepareNonCanonCode(t, m, contents)
			c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
			if mode == "exact_elf" {
				if err != nil {
					t.Fatal("exact captured loader edge rejected", err)
				}
				_ = c.Close()
			} else if c != nil || !errors.Is(err, ErrCodeCapsule) {
				if c != nil {
					_ = c.Close()
				}
				t.Fatal("missing or non-executable native interpreter admitted", err)
			}
		})
	}
}

func TestCodeCapsuleDoesNotLoseLoaderDependenciesWithoutSectionHeaders(t *testing.T) {
	body := nonCanonCodeELF("lib_non_canon.so")
	// Strip the optional section table while preserving both loader program headers.
	binary.LittleEndian.PutUint64(body[40:48], 0)
	binary.LittleEndian.PutUint16(body[60:62], 0)
	m := nonCanonCodeManifest(body)
	root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
	if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
		if c != nil {
			_ = c.Close()
		}
		t.Fatal("sectionless unlisted PT_DYNAMIC dependency admitted", err)
	}
	lib := nonCanonCodeELF("")
	m.Files = append([]RuntimeCodeFile{{AssetID: "library_fixture", Kind: "ELF", SHA256: inputSHA(lib), Bytes: int64(len(lib)), GuestPaths: []string{"/app/lib_non_canon.so"}, ProvenanceSHA256: inputSHA([]byte("NON_CANON_NOT_PACKAGE_ACCEPTANCE")), Needed: []CodeDependency{}}}, m.Files...)
	m.Files[1].Needed = []CodeDependency{{Name: "lib_non_canon.so", AssetID: "library_fixture"}}
	root, raw = prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body, "library_fixture": lib})
	c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
	if err != nil {
		t.Fatal("complete sectionless loader graph rejected", err)
	}
	_ = c.Close()
}

func TestCodeCapsuleRejectsCaseFoldedJSONBindings(t *testing.T) {
	fields := []string{"schema", "authority_sha256", "source_commit", "source_tree", "build_receipt_sha256", "files", "launch_roots", "dynamic_assets", "asset_id", "kind", "sha256", "bytes", "executable", "guest_paths", "provenance_sha256", "interpreter", "needed"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			body := nonCanonCodeELF("")
			m := nonCanonCodeManifest(body)
			root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
			raw = bytes.Replace(raw, []byte(`"`+field+`":`), []byte(`"`+strings.ToUpper(field)+`":`), 1)
			if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
				if c != nil {
					_ = c.Close()
				}
				t.Fatal("case-folded contract key admitted", err)
			}
		})
	}
	t.Run("conflicting_schema_alias", func(t *testing.T) {
		body := nonCanonCodeELF("")
		m := nonCanonCodeManifest(body)
		root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
		raw = bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"unapproved","SCHEMA":`), 1)
		if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
			if c != nil {
				_ = c.Close()
			}
			t.Fatal("conflicting folded schema admitted", err)
		}
	})
}

func TestCodeCapsuleRejectsAmbiguousDynamicFileMappings(t *testing.T) {
	for _, mutation := range []string{"unmapped_strings", "missing_terminator", "dynamic_not_file_backed", "duplicate_strtab", "contradictory_section_needed", "no_load_segment"} {
		t.Run(mutation, func(t *testing.T) {
			body := nonCanonCodeELF("lib_non_canon.so")
			switch mutation {
			case "unmapped_strings":
				binary.LittleEndian.PutUint64(body[0x118:0x120], 0x9999999999)
			case "missing_terminator":
				binary.LittleEndian.PutUint64(body[0x130:0x138], uint64(elf.DT_DEBUG))
			case "dynamic_not_file_backed":
				binary.LittleEndian.PutUint64(body[120+16:120+24], 0x10200)
			case "duplicate_strtab":
				binary.LittleEndian.PutUint64(body[0x120:0x128], uint64(elf.DT_STRTAB))
			case "contradictory_section_needed":
				binary.LittleEndian.PutUint64(body[0x200+64+24:0x200+64+32], 0x110)
				binary.LittleEndian.PutUint64(body[0x200+64+32:0x200+64+40], 48)
			case "no_load_segment":
				binary.LittleEndian.PutUint32(body[64:68], uint32(elf.PT_NULL))
			}
			m := nonCanonCodeManifest(body)
			lib := nonCanonCodeELF("")
			m.Files = append([]RuntimeCodeFile{{AssetID: "library_fixture", Kind: "ELF", SHA256: inputSHA(lib), Bytes: int64(len(lib)), GuestPaths: []string{"/app/lib_non_canon.so"}, ProvenanceSHA256: inputSHA([]byte("NON_CANON_NOT_PACKAGE_ACCEPTANCE")), Needed: []CodeDependency{}}}, m.Files...)
			m.Files[1].Needed = []CodeDependency{{Name: "lib_non_canon.so", AssetID: "library_fixture"}}
			root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body, "library_fixture": lib})
			if c, err := OpenHeldCodeCapsule(raw, inputSHA(raw), root); c != nil || !errors.Is(err, ErrCodeCapsule) {
				if c != nil {
					_ = c.Close()
				}
				t.Fatal("ambiguous runtime dynamic mapping admitted", err)
			}
		})
	}
}
