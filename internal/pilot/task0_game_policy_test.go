package pilot

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func nonCanonGamePolicyMetadata() (task0GameRootPolicy, RuntimeCodeManifest) {
	p := task0GameRootPolicy{Schema: "aipt.private.b007-task0-game-root-policy/v1", NodeAsset: "node_fixture", Root: FrozenRootPlan{
		Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/game"}, WritableDirectories: []string{}, AMDDevices: []FrozenDevice{}}}
	m := nonCanonCodeManifest(nonCanonCodeELF(""))
	m.Files[0].AssetID, m.Files[0].SHA256, m.Files[0].GuestPaths = p.NodeAsset, b007NodeSHA, []string{"/aipt/node-fixture"}
	m.LaunchRoots, m.DynamicAssets = []string{p.NodeAsset}, []string{}
	m.Files = append(m.Files, RuntimeCodeFile{AssetID: task0GamePolicyAsset, Kind: "DATA", GuestPaths: []string{"/aipt/policy/task0-game-root.json"}},
		RuntimeCodeFile{AssetID: task0GatewayAsset, Kind: "JAVASCRIPT", SHA256: Task0GameGatewaySHA})
	for n := range 46 {
		m.Files = append(m.Files, RuntimeCodeFile{AssetID: fmt.Sprintf("b007_game_noncanon_%02d", n), Kind: "DATA", GuestPaths: []string{fmt.Sprintf("/aipt/game/NON_CANON_%02d", n)}})
	}
	return p, m
}

// Metadata-only fixtures do not authenticate bytes or produce launch grants.
func TestTask0GamePolicyRejectsModelHardwareAndExtraCode(t *testing.T) {
	for _, scenario := range []string{"valid", "schema", "gpu", "sysfs", "writable", "workdir", "extra_root", "native_elf", "credential_data", "route_data", "missing_source", "wrong_node", "bad_gateway", "policy_alias", "unresolved_interpreter"} {
		t.Run(scenario, func(t *testing.T) {
			p, m := nonCanonGamePolicyMetadata()
			switch scenario {
			case "schema":
				p.Schema = "NON_CANON_OTHER_SCHEMA"
			case "gpu":
				p.Root.AMDDevices = []FrozenDevice{{Path: "/dev/kfd", Major: 509}}
			case "sysfs":
				p.Root.HardwareSysfs = true
			case "writable":
				p.Root.WritableDirectories = []string{"/aipt/private/home"}
			case "workdir":
				p.Root.WorkingDirectories = []string{"/aipt/native"}
			case "extra_root":
				m.LaunchRoots = append(m.LaunchRoots, "llama_fixture")
			case "native_elf", "credential_data", "route_data":
				kind := "DATA"
				if scenario == "native_elf" {
					kind = "ELF"
				}
				m.Files = append(m.Files, RuntimeCodeFile{AssetID: scenario, Kind: kind, GuestPaths: []string{"/aipt/extra"}})
			case "missing_source":
				m.Files = m.Files[:len(m.Files)-1]
			case "wrong_node":
				m.Files[0].SHA256 = strings.Repeat("0", 64)
			case "bad_gateway":
				m.Files[2].SHA256 = strings.Repeat("0", 64)
			case "policy_alias":
				m.Files[1].GuestPaths = append(m.Files[1].GuestPaths, "/aipt/alternate-policy")
			case "unresolved_interpreter":
				m.Files[0].Interpreter = "/lib/unlisted-loader"
			}
			if (validateTask0GameRootPolicy(p, m) == nil) != (scenario == "valid") {
				t.Fatal("game policy admission differs", scenario)
			}
		})
	}
	if _, err := frozenTask0GamePolicy(nil); err == nil {
		t.Fatal("missing capsule admitted")
	}
	if verifyFrozenSysfs(FrozenRootPlan{}) == nil {
		t.Fatal("host sysfs accepted with hardware disabled")
	}
}

// This static fixture executes only its own unregistered test binary. It
// checks the exact immutable-root verifier with hardware disabled and never
// runs Node, a registered helper, native/GPU code, a model or a token counter.
func TestTask0MinimalRuntimeRootNamespaceFixture(t *testing.T) {
	const key = "AIPT_NONCANON_TASK0_MINIMAL_ROOT_FIXTURE"
	plan := FrozenRootPlan{Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/game"}, WritableDirectories: []string{}, AMDDevices: []FrozenDevice{}}
	role := os.Getenv(key)
	if role == "verify" {
		body, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		m := nonCanonCodeManifest(body)
		m.Files[0].GuestPaths = []string{"/aipt/noncanon-fixture"}
		raw, _ := json.Marshal(m)
		c := &HeldCodeCapsule{identity: inputSHA(raw), manifest: m}
		if verifyFrozenRuntimeRoot(c, plan) != nil {
			t.Fatal("hardware-disabled immutable root rejected")
		}
		for _, name := range []string{"/dev/kfd", "/dev/dri/renderD128", "/aipt/native", "/etc/resolv.conf"} {
			if _, err := os.Stat(name); !os.IsNotExist(err) {
				t.Fatal("unlisted runtime asset visible", name, err)
			}
		}
		return
	}
	if role == "prepare" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		body, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		m := nonCanonCodeManifest(body)
		m.Files[0].GuestPaths = []string{"/aipt/noncanon-fixture"}
		raw, _ := json.Marshal(m)
		self, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := sealedCodeSnapshot(self, int64(len(body)), true)
		self.Close()
		if err != nil {
			t.Fatal(err)
		}
		c := &HeldCodeCapsule{identity: inputSHA(raw), manifest: m, files: map[string]*os.File{"server_fixture": sealed}}
		if c.validateELFEdges() != nil {
			t.Fatal("static fixture ELF closure rejected")
		}
		frozen, err := EnterFrozenRuntimeRoot(c, plan)
		if err != nil || ConstrainChildExecPrivileges(frozen) != nil || c.Close() != nil {
			t.Fatal("minimal immutable root setup failed", err)
		}
		if err = syscall.Exec("/aipt/noncanon-fixture", []string{"/aipt/noncanon-fixture", "-test.run=^TestTask0MinimalRuntimeRootNamespaceFixture$"}, []string{key + "=verify"}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("AIPT_REQUIRE_TASK0_MINIMAL_ROOT_FIXTURE") != "1" {
		t.Skip("dedicated static model-free root fixture")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	static := staticPreparationFile(f)
	f.Close()
	if !static {
		t.Fatal("required fixture needs CGO_ENABLED=0 static test binary")
	}
	command := exec.Command(exe, "-test.run=^TestTask0MinimalRuntimeRootNamespaceFixture$")
	command.Env = []string{key + "=prepare"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("minimal immutable root fixture: %v %s", err, output)
	}
}
