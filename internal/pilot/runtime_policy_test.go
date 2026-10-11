package pilot

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// Metadata fixtures only: no body with these registered digests is opened,
// no runtime capsule is accepted, and no helper, native code or model runs.
func nonCanonRuntimePolicy() (runtimeLaunchPolicy, RuntimeCodeManifest) {
	p := runtimeLaunchPolicy{
		Schema: "aipt.private.b007-frozen-runtime-launch-policy/v1",
		Initial: frozenControlRequest{Schema: frozenControlSchema, Operation: "START_MODEL", ProfileBinding: "NON_CANON_METADATA@1.0.0", ModelID: "gguf-04", TemplateSHA256: b007TemplateSHA,
			AdditionalArguments: slices.Clone(b007NativeArguments), LlamaEnvironment: map[string]string{"HIP_VISIBLE_DEVICES": "0", "ROCR_VISIBLE_DEVICES": "0", "OMP_NUM_THREADS": "8"}, LlamaWorkingDirectory: "/aipt/fixture_work",
			AdapterEnvironment: map[string]string{"DSH_HOME": "/aipt/private/home", "AIPT_HARNESS_PERSISTENCE_ROOT": "/aipt/private/sessions"}, AdapterWorkingDirectory: "/aipt/fixture_work", LocalEndpointEnvironment: "AIPT_LOCAL_LLAMACPP_ENDPOINT", StartupTimeoutMS: 300000, ShutdownTimeoutMS: 30000},
		Root:        FrozenRootPlan{Schema: "aipt.private.b007-frozen-runtime-root-plan/v1", WorkingDirectories: []string{"/aipt/fixture_work"}, WritableDirectories: []string{"/aipt/private/home", "/aipt/private/proof", "/aipt/private/sessions"}, HardwareSysfs: true, AMDDevices: []FrozenDevice{{Path: "/dev/kfd", Major: 509, Minor: 0}, {Path: "/dev/dri/renderD128", Major: 226, Minor: 128}}},
		NativeAsset: "native_fixture", NodeAsset: "node_fixture", WorkerAsset: "worker_fixture", RouteAsset: "route_fixture", BundleAsset: "bundle_fixture", GGUFSHA256: b007GGUFSHA, GGUFBytes: b007GGUFBytes, ProofDirectory: "/aipt/private/proof",
	}
	m := RuntimeCodeManifest{LaunchRoots: []string{"native_fixture", "node_fixture"}}
	for _, v := range []struct {
		id, kind, sha string
		size          int64
	}{{"bundle_fixture", "JAVASCRIPT", b007BundleSHA, 591429}, {"native_fixture", "ELF", inputSHA([]byte("NON_CANON_METADATA_ONLY")), 17904}, {"node_fixture", "ELF", b007NodeSHA, 125989464}, {"route_fixture", "DATA", inputSHA([]byte("NON_CANON_ROUTE_METADATA")), 1}, {"worker_fixture", "JAVASCRIPT", inputSHA([]byte("NON_CANON_WORKER_METADATA")), 1}} {
		m.Files = append(m.Files, RuntimeCodeFile{AssetID: v.id, Kind: v.kind, SHA256: v.sha, Bytes: v.size, Executable: v.kind == "ELF", GuestPaths: []string{"/aipt/code/" + v.id}})
	}
	return p, m
}

func TestFrozenLaunchPolicyRejectsCallerSelectedRuntime(t *testing.T) {
	p, m := nonCanonRuntimePolicy()
	raw, _ := json.Marshal(p)
	if _, e := decodeRuntimeLaunchPolicy(raw, m); e != nil {
		t.Fatal("metadata-only governed contract", e)
	}
	for _, kind := range []string{"model", "template", "gguf", "gguf-bytes", "context", "output", "reasoning", "template-override", "native-environment", "adapter-environment", "endpoint", "startup", "shutdown", "proof", "working-directory", "writable-directory", "device", "extra-device", "asset-alias", "node-digest", "bundle-digest", "node-launch-root", "worker-kind"} {
		t.Run(kind, func(t *testing.T) {
			p, m := nonCanonRuntimePolicy()
			switch kind {
			case "model":
				p.Initial.ModelID = "other"
			case "template":
				p.Initial.TemplateSHA256 = inputSHA([]byte("other"))
			case "gguf":
				p.GGUFSHA256 = inputSHA([]byte("other"))
			case "gguf-bytes":
				p.GGUFBytes++
			case "context":
				p.Initial.AdditionalArguments[1] = "8192"
			case "output":
				p.Initial.AdditionalArguments[3] = "1025"
			case "reasoning":
				p.Initial.AdditionalArguments[9] = "on"
			case "template-override":
				p.Initial.AdditionalArguments = append(p.Initial.AdditionalArguments, "--chat-template", "other")
			case "native-environment":
				p.Initial.LlamaEnvironment["LD_PRELOAD"] = "unlisted"
			case "adapter-environment":
				p.Initial.AdapterEnvironment["NODE_OPTIONS"] = "unlisted"
			case "endpoint":
				p.Initial.LocalEndpointEnvironment = "DIRECT_NATIVE"
			case "startup":
				p.Initial.StartupTimeoutMS = 600001
			case "shutdown":
				p.Initial.ShutdownTimeoutMS = 30001
			case "proof":
				p.ProofDirectory = "/aipt/private/home"
			case "working-directory":
				p.Initial.AdapterWorkingDirectory = "/unlisted"
			case "writable-directory":
				p.Root.WritableDirectories = append(p.Root.WritableDirectories, "/aipt/private/unlisted")
			case "device":
				p.Root.AMDDevices[1].Minor = 129
			case "extra-device":
				p.Root.AMDDevices = append(p.Root.AMDDevices, FrozenDevice{Path: "/dev/dri/renderD129", Major: 226, Minor: 129})
			case "asset-alias":
				p.NodeAsset = p.NativeAsset
			case "node-digest":
				m.Files[2].SHA256 = inputSHA([]byte("other"))
			case "bundle-digest":
				m.Files[0].SHA256 = inputSHA([]byte("other"))
			case "node-launch-root":
				m.LaunchRoots = []string{p.NativeAsset}
			case "worker-kind":
				m.Files[4].Kind = "DATA"
			}
			raw, _ := json.Marshal(p)
			if _, e := decodeRuntimeLaunchPolicy(raw, m); e == nil {
				t.Fatal("caller-selected contract admitted")
			}
		})
	}
}

func TestFrozenLaunchPolicyStrictFieldIdentity(t *testing.T) {
	p, m := nonCanonRuntimePolicy()
	raw, _ := json.Marshal(p)
	for name, body := range map[string]string{
		"case-alias":    strings.Replace(string(raw), `"gguf_bytes":`, `"GGUF_BYTES":`, 1),
		"duplicate":     strings.Replace(string(raw), `"gguf_bytes":`, `"gguf_bytes":1,"gguf_bytes":`, 1),
		"null-required": strings.Replace(string(raw), `"gguf_bytes":29047084416`, `"gguf_bytes":null`, 1),
		"unlisted":      strings.Replace(string(raw), `"schema":`, `"execution_mode":"unlisted","schema":`, 1),
		"trailing":      string(raw) + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeRuntimeLaunchPolicy([]byte(body), m); e == nil {
				t.Fatal("non-exact policy accepted")
			}
		})
	}
}

func TestFrozenControlRequiresAcceptedInitialAndBareLaterOperations(t *testing.T) {
	p, _ := nonCanonRuntimePolicy()
	if acceptFrozenControl(p.Initial, p.Initial, true) != nil {
		t.Fatal("fixed initial rejected")
	}
	changed := p.Initial
	changed.ModelID = "other"
	if acceptFrozenControl(p.Initial, changed, true) == nil {
		t.Fatal("changed initial accepted")
	}
	for _, op := range []string{"START_ADAPTER", "STOP_ADAPTER", "STOP_ALL"} {
		request := frozenControlRequest{Schema: frozenControlSchema, Operation: op}
		if acceptFrozenControl(p.Initial, request, false) != nil {
			t.Fatal("bare operation rejected", op)
		}
		request.ProfileBinding = p.Initial.ProfileBinding
		if acceptFrozenControl(p.Initial, request, false) == nil {
			t.Fatal("later operation with startup data accepted", op)
		}
	}
	if acceptFrozenControl(p.Initial, frozenControlRequest{Schema: frozenControlSchema, Operation: "DIRECT_NATIVE"}, false) == nil {
		t.Fatal("unknown operation accepted")
	}
}
