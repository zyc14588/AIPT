package pilot

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
)

func nonCanonRemotePolicyMetadata(t *testing.T) (task0RemoteRootPolicy, RuntimeCodeManifest) {
	t.Helper()
	entry := task0DispatchProfileFixture(t, orchestrator.SeatGM, false)
	p := task0RemoteRootPolicy{Schema: "aipt.private.b007-task0-remote-root-policy/v1", Profile: entry.Profile, Sampling: entry.Sampling,
		NodeAsset: "node_fixture", WorkerAsset: "worker_fixture", RouteAsset: "route_fixture", BundleAsset: "bundle_fixture",
		Root: FrozenRootPlan{Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/remote"}, WritableDirectories: []string{"/aipt/private/sessions"}, AMDDevices: []FrozenDevice{}}}
	m := nonCanonCodeManifest(nonCanonCodeELF(""))
	m.Files[0].AssetID, m.Files[0].SHA256, m.Files[0].GuestPaths = p.NodeAsset, b007NodeSHA, []string{"/aipt/node"}
	m.LaunchRoots, m.DynamicAssets = []string{p.NodeAsset}, []string{}
	for _, spec := range []RuntimeCodeFile{
		{AssetID: task0RemotePolicyAsset, Kind: "DATA", GuestPaths: []string{"/aipt/policy/remote-root.json"}},
		{AssetID: p.WorkerAsset, Kind: "JAVASCRIPT", SHA256: task0ModelWorkerSHA, GuestPaths: []string{"/aipt/model-worker-b007.ts"}},
		{AssetID: p.RouteAsset, Kind: "DATA", GuestPaths: []string{"/aipt/remote-route.json"}},
		{AssetID: p.BundleAsset, Kind: "JAVASCRIPT", SHA256: b007BundleSHA, GuestPaths: []string{"/aipt/harness-b007.mjs"}},
		{AssetID: "b007_remote_resolver", Kind: "DATA", GuestPaths: []string{"/etc/resolv.conf"}},
		{AssetID: "b007_remote_nss", Kind: "DATA", GuestPaths: []string{"/etc/nsswitch.conf"}},
	} {
		m.Files = append(m.Files, spec)
	}
	return p, m
}

// This validates metadata only; synthetic digests do not admit any process.
func TestTask0RemotePolicyRejectsNativeGameAndRouteDrift(t *testing.T) {
	for _, scenario := range []string{"valid", "schema", "gpu", "sysfs", "game_workdir", "extra_write", "alternate_node", "alternate_worker", "alternate_bundle", "alternate_route_alias", "unlisted_native", "unlisted_game_source", "unlisted_ca", "missing_resolver", "asset_collision", "sampling", "credential", "backend"} {
		t.Run(scenario, func(t *testing.T) {
			p, m := nonCanonRemotePolicyMetadata(t)
			switch scenario {
			case "schema":
				p.Schema = "NON_CANON_OTHER_SCHEMA"
			case "gpu":
				p.Root.AMDDevices = []FrozenDevice{{Path: "/dev/kfd", Major: 509}}
			case "sysfs":
				p.Root.HardwareSysfs = true
			case "game_workdir":
				p.Root.WorkingDirectories = []string{"/aipt/game"}
			case "extra_write":
				p.Root.WritableDirectories = append(p.Root.WritableDirectories, "/aipt/private/home")
			case "alternate_node":
				m.Files[0].GuestPaths = []string{"/aipt/other-node"}
			case "alternate_worker":
				m.Files[2].SHA256 = strings.Repeat("0", 64)
			case "alternate_bundle":
				m.Files[4].SHA256 = strings.Repeat("0", 64)
			case "alternate_route_alias":
				m.Files[3].GuestPaths = append(m.Files[3].GuestPaths, "/aipt/another-route")
			case "unlisted_native", "unlisted_game_source", "unlisted_ca":
				m.Files = append(m.Files, RuntimeCodeFile{AssetID: scenario, Kind: "DATA", GuestPaths: []string{"/aipt/unlisted"}})
			case "missing_resolver":
				m.Files = append(m.Files[:5], m.Files[6:]...)
			case "asset_collision":
				p.RouteAsset = p.WorkerAsset
			case "sampling":
				p.Sampling.MaxContextTokens = 16384
			case "credential":
				p.Profile.CredentialReference.Locator = "NON_CANON_FOREIGN"
			case "backend":
				p.Profile.BackendKind = modelgateway.BackendLocalLlamaCPP
			}
			if (validateTask0RemoteRootPolicy(p, m) == nil) != (scenario == "valid") {
				t.Fatal("remote root admission differs", scenario)
			}
		})
	}
}

func TestTask0RemoteWireReplyRejectsForeignNullAndAliases(t *testing.T) {
	for _, scenario := range []string{"valid", "id", "version", "jsonrpc", "case", "duplicate", "error", "null", "unknown", "trailing", "oversized"} {
		t.Run(scenario, func(t *testing.T) {
			value := map[string]any{"jsonrpc": "2.0", "id": "owned-1", "protocol_version": "1", "result": map[string]bool{"NON_CANON": true}}
			switch scenario {
			case "id":
				value["id"] = "foreign"
			case "version":
				value["protocol_version"] = "2"
			case "jsonrpc":
				value["jsonrpc"] = "1.0"
			case "case":
				value["ID"] = value["id"]
				delete(value, "id")
			case "error":
				value["error"] = map[string]string{"code": "AIPT_MODEL_GATEWAY_HARNESS_FAILED"}
			case "null":
				value["result"] = nil
			case "unknown":
				value["stdout_path"] = "NON_CANON_SELECTOR"
			case "oversized":
				value["result"] = strings.Repeat("x", 1<<20)
			}
			raw, _ := json.Marshal(value)
			if scenario == "duplicate" {
				raw = append(raw[:len(raw)-1], []byte(`,"id":"owned-1"}`)...)
			}
			if scenario == "trailing" {
				raw = append(raw, []byte(`{}`)...)
			}
			if (func() error { _, err := task0RemoteDecodeReply(raw, "owned-1"); return err }() == nil) != (scenario == "valid") {
				t.Fatal("remote reply admission differs", scenario)
			}
		})
	}
}

func TestTask0RemoteRejectsUnboundHostAndRecoveryBeforeCredentialUse(t *testing.T) {
	if value, err := newTask0FrozenRemoteTransport(context.Background(), nil, "", nil, map[string]*os.File{}); err == nil || value != nil {
		t.Fatal("unbound remote transport admitted")
	}
	if value, err := launchTask0RemoteHelper(context.Background(), nil, "", task0DispatchProfile{}); err == nil || value != nil {
		t.Fatal("unbound helper launched")
	}
	if RunFrozenTask0Remote("") == nil {
		t.Fatal("host entry admitted")
	}
	transport := &task0FrozenRemoteTransport{}
	if transport.Recover(context.Background(), modelgateway.ModelProfile{}, orchestrator.Session{}, orchestrator.RecoveryRequest{}) == nil {
		t.Fatal("remote recovery admitted")
	}
	if _, err := transport.Probe(context.Background(), modelgateway.ModelProfile{}, modelgateway.SamplingProfile{}); err == nil {
		t.Fatal("missing role admitted")
	}
	if _, err := transport.Invoke(context.Background(), modelgateway.ModelProfile{}, modelgateway.SamplingProfile{}, modelgateway.HarnessRequest{}); err == nil {
		t.Fatal("missing role invoked")
	}
	if transport.Close(context.Background()) != nil || transport.Close(context.Background()) != nil {
		t.Fatal("empty retirement not idempotent")
	}
	if (&task0OwnedRemoteHelper{}).check() == nil {
		t.Fatal("unowned helper passed")
	}
}

func TestTask0RemoteResolverRejectsHostSearchAndNSSPlugins(t *testing.T) {
	for _, sample := range []struct {
		name, resolver, nss string
		valid               bool
	}{
		{"stub", "nameserver 127.0.0.53\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", true},
		{"ipv6", "nameserver ::1\nnameserver 192.0.2.1\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", true},
		{"search", "nameserver 127.0.0.53\nsearch host-private.example\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"files", "nameserver 127.0.0.53\noptions timeout:2 attempts:1 ndots:1\n", "hosts: files dns\n", false},
		{"plugin", "nameserver 127.0.0.53\noptions timeout:2 attempts:1 ndots:1\n", "hosts: myhostname dns\n", false},
		{"unset", "nameserver 0.0.0.0\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"multicast", "nameserver ff02::1\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"zone", "nameserver fe80::1%eth0\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"mapped", "nameserver ::ffff:192.0.2.1\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"duplicate", "nameserver ::1\nnameserver ::1\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"unterminated", "nameserver ::1\noptions timeout:2 attempts:1 ndots:1", "hosts: dns\n", false},
		{"format", "nameserver  ::1\noptions timeout:2 attempts:1 ndots:1\n", "hosts: dns\n", false},
		{"retry", "nameserver ::1\noptions timeout:2 attempts:2 ndots:1\n", "hosts: dns\n", false},
		{"oversize", strings.Repeat("x", 1025), "hosts: dns\n", false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if (validateTask0RemoteResolver([]byte(sample.resolver), []byte(sample.nss)) == nil) != sample.valid {
				t.Fatal("resolver data admission differs")
			}
		})
	}
}
