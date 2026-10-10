package pilot

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func nonCanonFrozenPlan() FrozenRootPlan {
	return FrozenRootPlan{Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/work"}, WritableDirectories: []string{"/aipt/private/session"}, AMDDevices: []FrozenDevice{}}
}

func TestFrozenRootPlanRejectsFallbackAndWritableCode(t *testing.T) {
	for _, kind := range []string{"valid", "wrong_schema", "no_work", "relative_work", "dirty_work", "reserved_work", "duplicate_work", "work_below_code", "write_outside_private", "write_above_code", "overlapping_writable", "gpu_without_sysfs", "unlisted_device", "duplicate_device", "invalid_gpu_number", "zero_major", "valid_explicit_gpu"} {
		t.Run(kind, func(t *testing.T) {
			p := nonCanonFrozenPlan()
			m := nonCanonCodeManifest(nonCanonCodeELF(""))
			switch kind {
			case "wrong_schema":
				p.Schema = "untrusted"
			case "no_work":
				p.WorkingDirectories = nil
			case "relative_work":
				p.WorkingDirectories = []string{"relative"}
			case "dirty_work":
				p.WorkingDirectories = []string{"/aipt/../host"}
			case "reserved_work":
				p.WorkingDirectories = []string{"/proc/self"}
			case "duplicate_work":
				p.WorkingDirectories = append(p.WorkingDirectories, p.WorkingDirectories[0])
			case "work_below_code":
				p.WorkingDirectories = []string{"/app/non_canon_server/escape"}
			case "write_outside_private":
				p.WritableDirectories = []string{"/usr/lib"}
			case "write_above_code":
				p.WritableDirectories = []string{"/aipt/private/session"}
				m.Files[0].GuestPaths = []string{"/aipt/private/session/code"}
			case "overlapping_writable":
				p.WritableDirectories = append(p.WritableDirectories, "/aipt/private/session/nested")
			case "gpu_without_sysfs":
				p.AMDDevices = []FrozenDevice{{Path: "/dev/kfd", Major: 1, Minor: 1}}
			case "unlisted_device":
				p.HardwareSysfs = true
				p.AMDDevices = []FrozenDevice{{Path: "/dev/sda", Major: 8}}
			case "duplicate_device":
				p.HardwareSysfs = true
				p.AMDDevices = []FrozenDevice{{Path: "/dev/kfd", Major: 1, Minor: 1}, {Path: "/dev/kfd", Major: 1, Minor: 1}}
			case "invalid_gpu_number":
				p.HardwareSysfs = true
				p.AMDDevices = []FrozenDevice{{Path: "/dev/dri/renderD00128", Major: 226, Minor: 128}}
			case "zero_major":
				p.HardwareSysfs = true
				p.AMDDevices = []FrozenDevice{{Path: "/dev/kfd"}}
			case "valid_explicit_gpu":
				p.HardwareSysfs = true
				p.AMDDevices = []FrozenDevice{{Path: "/dev/kfd", Major: 235}, {Path: "/dev/dri/renderD128", Major: 226, Minor: 128}}
			}
			e := validateFrozenRootPlan(p, m)
			valid := kind == "valid" || kind == "valid_explicit_gpu"
			if valid && e != nil {
				t.Fatal("valid explicit plan rejected", e)
			}
			if !valid && !errors.Is(e, ErrFrozenRoot) {
				t.Fatal("unsafe filesystem plan admitted", e)
			}
		})
	}
}

func TestFrozenRootRequiresDistinctDedicatedNamespaces(t *testing.T) {
	if c, e := EnterFrozenRuntimeRoot(nil, nonCanonFrozenPlan()); c != nil || !errors.Is(e, ErrFrozenRoot) {
		t.Fatal("missing held capsule admitted", e)
	}
	if e := ConstrainChildExecPrivileges(nil); !errors.Is(e, ErrFrozenRoot) {
		t.Fatal("missing root granted child exec", e)
	}
	if e := ConstrainChildExecPrivileges(&FrozenRuntimeRoot{pid: os.Getpid() + 1, entered: true}); !errors.Is(e, ErrFrozenRoot) {
		t.Fatal("foreign process root granted child exec", e)
	}
}

// This fixture is test-only and uses the test binary itself, built CGO=0. It
// never launches registered Node, llama.cpp, a GGUF or any network service.
// Run the dedicated required check with AIPT_REQUIRE_FROZEN_ROOT_FIXTURE=1;
// ordinary race checks skip the fixture because the race binary needs libc.
func TestFrozenRootNamespaceFixture(t *testing.T) {
	role := os.Getenv("AIPT_NONCANON_ROOT_FIXTURE")
	if role == "verify" {
		status, e := os.ReadFile("/proc/self/status")
		if e != nil {
			t.Fatal(e)
		}
		for _, k := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
			found := false
			for _, line := range strings.Split(string(status), "\n") {
				if strings.HasPrefix(line, k) {
					found = true
					if strings.TrimSpace(strings.TrimPrefix(line, k)) != "0000000000000000" {
						t.Fatal("child retained capability", k)
					}
				}
			}
			if !found {
				t.Fatal("child status missing capability", k)
			}
		}
		if !bytes.Contains(status, []byte("NoNewPrivs:\t1")) {
			t.Fatal("child exec lacks NoNewPrivs")
		}
		if _, e = os.ReadFile(os.Getenv("AIPT_NONCANON_HOST_SENTINEL")); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("host fallback visible", e)
		}
		data, e := os.ReadFile("/aipt/held_data")
		if e != nil || string(data) != "NON_CANON_ORIGINAL_HELD_BYTES" {
			t.Fatal("bind followed replaced/in-place source", e)
		}
		if e = os.WriteFile("/aipt/held_data", []byte("mutation"), 0600); e == nil {
			t.Fatal("held code/data root writable")
		}
		if e = os.WriteFile("/aipt/host_write", []byte("mutation"), 0600); e == nil {
			t.Fatal("immutable root writable")
		}
		if e = os.WriteFile("/aipt/private/session/record", []byte("NON_CANON_PRIVATE_RECORD"), 0600); e != nil {
			t.Fatal("bounded private data mount unavailable", e)
		}
		self, e := os.ReadFile("/aipt/noncanon_fixture")
		if e != nil {
			t.Fatal(e)
		}
		for _, writable := range []string{"/tmp", "/dev/shm", "/aipt/private/session"} {
			name := writable + "/noncanon_noexec_check"
			if e = os.WriteFile(name, self, 0700); e != nil {
				t.Fatal("private data mount write failed", e)
			}
			if e = exec.Command(name, "-test.run=^TestFrozenRootNamespaceFixture$").Run(); !errors.Is(e, syscall.EACCES) {
				t.Fatal("private data mount admits native execution", e)
			}
		}
		if e = syscall.Mount("tmpfs", "/tmp", "tmpfs", 0, ""); !errors.Is(e, syscall.EPERM) {
			t.Fatal("child can mount host fallback", e)
		}
		if e = syscall.Chroot("/tmp"); !errors.Is(e, syscall.EPERM) {
			t.Fatal("child retained chroot privilege", e)
		}
		return
	}
	if role == "prepare" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		body, e := os.ReadFile("/proc/self/exe")
		if e != nil {
			t.Fatal(e)
		}
		m := nonCanonCodeManifest(body)
		m.Files[0].GuestPaths = []string{"/aipt/noncanon_fixture"}
		data := []byte("NON_CANON_ORIGINAL_HELD_BYTES")
		m.Files = append([]RuntimeCodeFile{{AssetID: "data_fixture", Kind: "DATA", SHA256: inputSHA(data), Bytes: int64(len(data)), GuestPaths: []string{"/aipt/held_data"}, ProvenanceSHA256: inputSHA([]byte("NON_CANON_ONLY_NO_ACCEPTANCE")), Needed: []CodeDependency{}}}, m.Files...)
		root, raw := prepareNonCanonCode(t, m, map[string][]byte{"data_fixture": data, "server_fixture": body})
		c, e := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		if e = os.WriteFile(filepath.Join(root, "data_fixture"), []byte("NON_CANON_IN_PLACE_CHANGED"), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(filepath.Join(root, "data_fixture"), filepath.Join(root, "data_fixture.old")); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, "data_fixture"), []byte("NON_CANON_REPLACEMENT"), 0600); e != nil {
			t.Fatal(e)
		}
		frozen, e := EnterFrozenRuntimeRoot(c, nonCanonFrozenPlan())
		if e != nil {
			t.Fatal(e)
		}
		if e = ConstrainChildExecPrivileges(frozen); e != nil {
			t.Fatal(e)
		}
		child := exec.Command("/aipt/noncanon_fixture", "-test.run=^TestFrozenRootNamespaceFixture$")
		child.Env = []string{"AIPT_NONCANON_ROOT_FIXTURE=verify", "AIPT_NONCANON_HOST_SENTINEL=" + os.Getenv("AIPT_NONCANON_HOST_SENTINEL")}
		out, e := child.CombinedOutput()
		if e != nil {
			t.Fatalf("constrained child check: %v %s", e, out)
		}
		// The read-only root hides t.TempDir, so parent-owned fixture cleanup occurs
		// only when this owned namespace exits; no inaccessible-host cleanup error
		// is treated as a runtime failure or as authority to remove host files.
		return
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	f, e := elf.Open(exe)
	if e != nil {
		t.Fatal(e)
	}
	dynamic := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			dynamic = true
		}
	}
	f.Close()
	if dynamic {
		if os.Getenv("AIPT_REQUIRE_FROZEN_ROOT_FIXTURE") == "1" {
			t.Fatal("required root fixture must be statically built CGO_ENABLED=0")
		}
		t.Skip("dedicated static namespace check required")
	}
	sentinel := filepath.Join(t.TempDir(), "host_only")
	if e = os.WriteFile(sentinel, []byte("NON_CANON_HOST_FALLBACK"), 0600); e != nil {
		t.Fatal(e)
	}
	child := exec.Command(exe, "-test.run=^TestFrozenRootNamespaceFixture$")
	child.Env = []string{"AIPT_NONCANON_ROOT_FIXTURE=prepare", "AIPT_NONCANON_HOST_SENTINEL=" + sentinel}
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	out, e := child.CombinedOutput()
	if e != nil {
		if errors.Is(e, syscall.EPERM) && os.Getenv("AIPT_REQUIRE_FROZEN_ROOT_FIXTURE") != "1" {
			t.Skip("namespace unavailable in default sandbox")
		}
		t.Fatalf("private root fixture: %v %s", e, out)
	}
}
