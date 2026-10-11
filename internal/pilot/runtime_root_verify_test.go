package pilot

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func nonCanonHardwareRootPlan() FrozenRootPlan {
	return FrozenRootPlan{Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/fixture_work"}, WritableDirectories: []string{"/aipt/private/home", "/aipt/private/proof", "/aipt/private/sessions"}, HardwareSysfs: true, AMDDevices: []FrozenDevice{{Path: "/dev/kfd", Major: 509, Minor: 0}, {Path: "/dev/dri/renderD128", Major: 226, Minor: 128}}}
}

// The only executable here is this statically built test binary. It reads
// kernel device metadata, without invoking a GPU library, driver ioctl,
// registered helper/native binary, GGUF, counter or model request.
func TestFrozenHardwareRootNamespaceFixture(t *testing.T) {
	role := os.Getenv("AIPT_NONCANON_HARDWARE_ROOT_FIXTURE")
	if role == "verify" {
		body, e := os.ReadFile("/proc/self/exe")
		if e != nil {
			t.Fatal(e)
		}
		m := nonCanonCodeManifest(body)
		m.Files[0].GuestPaths = []string{"/aipt/noncanon_fixture"}
		raw, _ := json.Marshal(m)
		c := &HeldCodeCapsule{identity: inputSHA(raw), manifest: m}
		if e = verifyFrozenRuntimeRoot(c, nonCanonHardwareRootPlan()); e != nil {
			t.Fatal("complete frozen root verification", e)
		}
		vendor, e := os.ReadFile("/sys/class/drm/renderD128/device/vendor")
		if e != nil || strings.TrimSpace(string(vendor)) != "0x1002" {
			t.Fatal("AMD kernel metadata", e)
		}
		device, e := os.ReadFile("/sys/class/drm/renderD128/device/device")
		if e != nil || strings.TrimSpace(string(device)) != "0x1586" {
			t.Fatal("registered hardware class metadata", e)
		}
		// A post-verification private data file must not become executable.
		if e = os.WriteFile("/aipt/private/home/NON_CANON_DATA", []byte("NON_CANON_DATA_ONLY"), 0600); e != nil {
			t.Fatal(e)
		}
		if e = verifyRuntimeMount("/aipt/private/home", 0x01021994, true); e == nil {
			t.Fatal("writable data mount mistaken for immutable code")
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
		root, raw := prepareNonCanonCode(t, m, map[string][]byte{"server_fixture": body})
		c, e := OpenHeldCodeCapsule(raw, inputSHA(raw), root)
		if e != nil {
			t.Fatal(e)
		}
		frozen, e := EnterFrozenRuntimeRoot(c, nonCanonHardwareRootPlan())
		if e != nil {
			t.Fatal("hardware root preparation", e)
		}
		if e = ConstrainChildExecPrivileges(frozen); e != nil {
			t.Fatal(e)
		}
		if e = c.Close(); e != nil {
			t.Fatal(e)
		}
		// Same namespace-init PID; all newly created Go threads inherit the
		// zero capability sets after this exec, not the setup helper's sets.
		if e = syscall.Exec("/aipt/noncanon_fixture", []string{"/aipt/noncanon_fixture", "-test.run=^TestFrozenHardwareRootNamespaceFixture$"}, []string{"AIPT_NONCANON_HARDWARE_ROOT_FIXTURE=verify"}); e != nil {
			t.Fatal(e)
		}
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
	required := os.Getenv("AIPT_REQUIRE_FROZEN_HARDWARE_FIXTURE") == "1"
	if dynamic {
		if required {
			t.Fatal("required hardware fixture needs static CGO_ENABLED=0 test binary")
		}
		t.Skip("dedicated static local hardware fixture required")
	}
	if _, e = os.Stat("/dev/kfd"); e != nil && !required {
		t.Skip("registered local AMD hardware absent")
	}
	child := exec.Command(exe, "-test.run=^TestFrozenHardwareRootNamespaceFixture$")
	child.Env = []string{"AIPT_NONCANON_HARDWARE_ROOT_FIXTURE=prepare"}
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	out, e := child.CombinedOutput()
	if e != nil {
		if errors.Is(e, syscall.EPERM) && !required {
			t.Skip("local namespaces unavailable")
		}
		t.Fatalf("private hardware root fixture: %v %s", e, out)
	}
}
