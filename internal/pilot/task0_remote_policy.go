package pilot

import (
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/protocol"
)

const task0RemotePolicyAsset = "b007_task0_remote_root_policy"
const task0RemoteStage = "AIPT_B007_TASK0_REMOTE_STAGE"

type task0RemoteRootPolicy struct {
	Schema      string                       `json:"schema"`
	Root        FrozenRootPlan               `json:"root"`
	Profile     modelgateway.ModelProfile    `json:"model_profile"`
	Sampling    modelgateway.SamplingProfile `json:"sampling_profile"`
	NodeAsset   string                       `json:"node_asset"`
	WorkerAsset string                       `json:"worker_asset"`
	RouteAsset  string                       `json:"route_asset"`
	BundleAsset string                       `json:"bundle_asset"`
}

func task0RemoteExpectedRoute(p task0RemoteRootPolicy) map[string]any {
	return map[string]any{
		"schema": "aipt.harness-route/v1", "profile_binding": p.Profile.BindingID(), "sampling_binding": p.Sampling.BindingID(),
		"backend_kind": p.Profile.BackendKind, "provider_identity": p.Profile.ProviderIdentity, "model_id": p.Profile.ModelID,
		"harness_identity": p.Profile.Harness.BindingID(), "harness_protocol_identity": p.Profile.Harness.ProtocolIdentity,
		"harness_protocol_version": p.Profile.Harness.ProtocolVersion, "capability_fingerprint": p.Profile.Harness.CapabilityFingerprint,
		"structured_output_mode": p.Profile.StructuredOutputMode, "tool_call_mode": p.Profile.ToolCallMode,
		"session_working_directory": "/aipt/remote", "sampling_profile": p.Sampling,
		"child": map[string]any{
			"executable_path": "/aipt/node", "executable_sha256": b007NodeSHA,
			"arguments":             []string{"/aipt/harness-b007.mjs"},
			"argument_file_digests": []map[string]any{{"index": 0, "sha256": b007BundleSHA}},
			"runtime_closure":       map[string]any{"schema": "aipt.harness-runtime-closure/v1", "kind": "VERIFIED_SINGLE_FILE_DATA_URL_V1", "entrypoint_argument_index": 0, "sha256": b007BundleSHA},
			"working_directory":     "/aipt/remote", "environment_allowlist": []string{"LANG", "TZ", "DEEPSEEK_API_KEY", "DSH_HOME"},
			"startup_timeout_ms": 10000, "request_timeout_ms": 90000, "shutdown_timeout_ms": 1000,
			"output_budget": map[string]any{"schema": "aipt.acp-output-budget/v1", "max_stdout_protocol_bytes": 8 << 20,
				"max_notification_bytes": 4 << 20, "max_response_and_notification_bytes": 8 << 20, "max_stderr_bytes": 1 << 20},
		},
	}
}

func validateTask0RemoteRootPolicy(p task0RemoteRootPolicy, m RuntimeCodeManifest) error {
	profile, sampling := p.Profile, p.Sampling
	if p.Schema != "aipt.private.b007-task0-remote-root-policy/v1" || validateFrozenRootPlan(p.Root, m) != nil ||
		!slices.Equal(p.Root.WorkingDirectories, []string{"/aipt/remote"}) || !slices.Equal(p.Root.WritableDirectories, []string{"/aipt/private/sessions"}) ||
		p.Root.HardwareSysfs || len(p.Root.AMDDevices) != 0 || modelgateway.ValidateModelProfile(profile) != nil || modelgateway.ValidateSamplingProfile(sampling) != nil ||
		profile.BackendKind != modelgateway.BackendRemoteDeepSeek || profile.ModelID != modelgateway.RemoteDeepSeekModelID ||
		profile.CredentialReference == nil || profile.CredentialReference.Kind != modelgateway.CredentialEnvironment || profile.CredentialReference.Locator != "DEEPSEEK_API_KEY" ||
		profile.Harness.RuntimeClosureSHA256 != b007BundleSHA || profile.SamplingProfileID != sampling.BindingID() || sampling.MaxContextTokens != 8192 || sampling.MaxOutputTokens != 1024 ||
		profile.StructuredOutputMode != modelgateway.StructuredPrompted || profile.ToolCallMode != modelgateway.ToolCallDisabled {
		return ErrRuntimeLaunch
	}
	elfs, err := task0NodeClosure(m, p.NodeAsset)
	if err != nil {
		return ErrRuntimeLaunch
	}
	wanted := map[string]struct {
		kind, sha, path string
	}{
		task0RemotePolicyAsset: {"DATA", "", "/aipt/policy/remote-root.json"},
		p.WorkerAsset:          {"JAVASCRIPT", task0ModelWorkerSHA, "/aipt/model-worker-b007.ts"},
		p.RouteAsset:           {"DATA", "", "/aipt/remote-route.json"},
		p.BundleAsset:          {"JAVASCRIPT", b007BundleSHA, "/aipt/harness-b007.mjs"},
		"b007_remote_resolver": {"DATA", "", "/etc/resolv.conf"},
		"b007_remote_nss":      {"DATA", "", "/etc/nsswitch.conf"},
	}
	if len(wanted) != 6 {
		return ErrRuntimeLaunch
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if elfs[f.AssetID] {
			if f.AssetID == p.NodeAsset && !slices.Equal(f.GuestPaths, []string{"/aipt/node"}) {
				return ErrRuntimeLaunch
			}
			continue
		}
		spec, exists := wanted[f.AssetID]
		if !exists || f.Kind != spec.kind || !slices.Equal(f.GuestPaths, []string{spec.path}) || spec.sha != "" && f.SHA256 != spec.sha || f.Executable || f.Interpreter != "" || len(f.Needed) != 0 {
			return ErrRuntimeLaunch
		}
		seen[f.AssetID] = true
	}
	if len(seen) != len(wanted) {
		return ErrRuntimeLaunch
	}
	return nil
}

func task0ReadCapsuleData(c *HeldCodeCapsule, asset string, max int64) ([]byte, error) {
	f, err := c.Descriptor(asset)
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	defer f.Close()
	body, err := io.ReadAll(io.NewSectionReader(f, 0, max+1))
	if err != nil || len(body) < 1 || int64(len(body)) > max {
		return nil, ErrRuntimeLaunch
	}
	return body, nil
}

func frozenTask0RemotePolicy(c *HeldCodeCapsule) (task0RemoteRootPolicy, error) {
	var p task0RemoteRootPolicy
	if c == nil || !digest(c.Identity()) {
		return p, ErrRuntimeLaunch
	}
	raw, err := task0ReadCapsuleData(c, task0RemotePolicyAsset, 64<<10)
	if err != nil || decodeFrozenJSON(raw, 64<<10, &p) != nil || validateTask0RemoteRootPolicy(p, c.manifest) != nil {
		return p, ErrRuntimeLaunch
	}
	// The model cannot select a second route, configuration, plugin, child
	// environment or filesystem path through data fields in this exact route.
	route, err := task0ReadCapsuleData(c, p.RouteAsset, 64<<10)
	want, marshalErr := json.Marshal(task0RemoteExpectedRoute(p))
	a, ae := protocol.CanonicalJSON(route)
	b, be := protocol.CanonicalJSON(want)
	if err != nil || marshalErr != nil || ae != nil || be != nil || a != b {
		return p, ErrRuntimeLaunch
	}
	resolver, err := task0ReadCapsuleData(c, "b007_remote_resolver", 1024)
	nss, nssErr := task0ReadCapsuleData(c, "b007_remote_nss", 1024)
	if err != nil || nssErr != nil || validateTask0RemoteResolver(resolver, nss) != nil {
		return p, ErrRuntimeLaunch
	}
	return p, nil
}

// These two immutable data files are part of the accepted capsule digest.
// No host search suffix, hosts file, NSS plugin or model-selected resolver is
// consulted. Loopback DNS is allowed because this helper deliberately retains
// the parent's network namespace and may use its already configured DNS stub.
func validateTask0RemoteResolver(resolver, nss []byte) error {
	if string(nss) != "hosts: dns\n" || len(resolver) < 1 || len(resolver) > 1024 || !strings.HasSuffix(string(resolver), "\n") {
		return ErrRuntimeLaunch
	}
	lines := strings.Split(strings.TrimSuffix(string(resolver), "\n"), "\n")
	if len(lines) < 2 || len(lines) > 4 || lines[len(lines)-1] != "options timeout:2 attempts:1 ndots:1" {
		return ErrRuntimeLaunch
	}
	seen := map[netip.Addr]bool{}
	for _, line := range lines[:len(lines)-1] {
		if !strings.HasPrefix(line, "nameserver ") {
			return ErrRuntimeLaunch
		}
		text := strings.TrimPrefix(line, "nameserver ")
		ip, err := netip.ParseAddr(text)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.String() != text || seen[ip] {
			return ErrRuntimeLaunch
		}
		seen[ip] = true
	}
	return nil
}
