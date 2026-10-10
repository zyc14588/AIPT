package pilot

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/zyc14588/AIPT/internal/protocol"
)

var ErrRuntimeLaunch = errors.New("B007 accepted frozen runtime launch rejected")

const frozenControlSchema = "aipt.runtime-isolation-control/v1"
const b007GGUFSHA = "31756fca94beca71ea4b8706d6fdc896dab2a3c6376ab0c1863b98512a24f8d6"
const b007GGUFBytes int64 = 29047084416
const b007TemplateSHA = "c3cf9e34abf4f9e36c2d72165aa9c132d3e2a725b6c2586aaa3a8af9d7a81041"
const b007NodeSHA = "bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12"
const b007BundleSHA = "d4d1d6d7558d0190caf192f6db77d04eacd6573280fef4041589ea2ba09fec70"

// These frames preserve the already accepted manager's control protocol.
// The new helper accepts only the exact START_MODEL in its authenticated DATA
// policy, and only schema/operation for later commands. There is no caller
// selector for an executable, unlisted environment, or direct native route.
type frozenControlRequest struct {
	Schema                   string            `json:"schema"`
	Operation                string            `json:"operation"`
	ProfileBinding           string            `json:"profile_binding,omitempty"`
	ModelID                  string            `json:"model_id,omitempty"`
	TemplateSHA256           string            `json:"template_sha256,omitempty"`
	AdditionalArguments      []string          `json:"additional_arguments,omitempty"`
	LlamaEnvironment         map[string]string `json:"llama_environment,omitempty"`
	LlamaWorkingDirectory    string            `json:"llama_working_directory,omitempty"`
	AdapterEnvironment       map[string]string `json:"adapter_environment,omitempty"`
	AdapterArguments         []string          `json:"adapter_arguments,omitempty"`
	AdapterWorkingDirectory  string            `json:"adapter_working_directory,omitempty"`
	LocalEndpointEnvironment string            `json:"local_endpoint_environment,omitempty"`
	StartupTimeoutMS         int64             `json:"startup_timeout_ms,omitempty"`
	ShutdownTimeoutMS        int64             `json:"shutdown_timeout_ms,omitempty"`
}
type frozenControlReply struct {
	Schema            string `json:"schema"`
	Operation         string `json:"operation"`
	Result            string `json:"result"`
	Code              string `json:"code,omitempty"`
	Port              int    `json:"port,omitempty"`
	AdapterPID        int    `json:"adapter_pid,omitempty"`
	IsolationIdentity string `json:"isolation_identity,omitempty"`
	FailureStage      string `json:"failure_stage,omitempty"`
}

// Private paths name only the new guest filesystem. The whole policy is a
// DATA member of the externally accepted, write-sealed executable capsule.
// This structure alone cannot authenticate its own capsule or code origins.
type runtimeLaunchPolicy struct {
	Schema         string               `json:"schema"`
	Initial        frozenControlRequest `json:"initial"`
	Root           FrozenRootPlan       `json:"root"`
	NativeAsset    string               `json:"native_asset"`
	NodeAsset      string               `json:"node_asset"`
	WorkerAsset    string               `json:"worker_asset"`
	RouteAsset     string               `json:"route_asset"`
	BundleAsset    string               `json:"bundle_asset"`
	GGUFSHA256     string               `json:"gguf_sha256"`
	GGUFBytes      int64                `json:"gguf_bytes"`
	ProofDirectory string               `json:"proof_directory"`
}

var b007NativeArguments = []string{
	"--ctx-size", "9216", "--n-predict", "1024", "--n-gpu-layers", "99", "--parallel", "1",
	"--reasoning", "off", "--chat-template-kwargs", `{"enable_thinking":false}`,
	"--no-context-shift", "--no-warmup",
}

func decodeFrozenJSON[T any](raw []byte, maximum int, value *T) error {
	if value == nil || len(raw) == 0 || len(raw) > maximum {
		return ErrRuntimeLaunch
	}
	canonical, e := protocol.CanonicalJSON(raw)
	if e != nil {
		return ErrRuntimeLaunch
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return ErrRuntimeLaunch
	}
	roundtrip, e := json.Marshal(value)
	if e != nil {
		return ErrRuntimeLaunch
	}
	check, e := protocol.CanonicalJSON(roundtrip)
	if e != nil || canonical != check {
		return ErrRuntimeLaunch
	}
	return nil
}

func decodeRuntimeLaunchPolicy(raw []byte, manifest RuntimeCodeManifest) (runtimeLaunchPolicy, error) {
	var p runtimeLaunchPolicy
	if decodeFrozenJSON(raw, 64<<10, &p) != nil || validateRuntimeLaunchPolicy(p, manifest) != nil {
		return p, ErrRuntimeLaunch
	}
	return p, nil
}

func validateRuntimeLaunchPolicy(p runtimeLaunchPolicy, m RuntimeCodeManifest) error {
	i := p.Initial
	if p.Schema != "aipt.private.b007-frozen-runtime-launch-policy/v1" ||
		i.Schema != frozenControlSchema || i.Operation != "START_MODEL" ||
		len(i.ProfileBinding) < 5 || len(i.ProfileBinding) > 128 || !strings.Contains(i.ProfileBinding, "@") || strings.ContainsAny(i.ProfileBinding, "/\\\x00\r\n ") ||
		i.ModelID != "gguf-04" || i.TemplateSHA256 != b007TemplateSHA ||
		p.GGUFSHA256 != b007GGUFSHA || p.GGUFBytes != b007GGUFBytes ||
		!slices.Equal(i.AdditionalArguments, b007NativeArguments) || len(i.AdapterArguments) != 0 ||
		i.LocalEndpointEnvironment != "AIPT_LOCAL_LLAMACPP_ENDPOINT" ||
		i.StartupTimeoutMS < 1 || i.StartupTimeoutMS > 600000 || i.ShutdownTimeoutMS < 1 || i.ShutdownTimeoutMS > 30000 ||
		p.ProofDirectory != "/aipt/private/proof" ||
		validateFrozenRootPlan(p.Root, m) != nil || !p.Root.HardwareSysfs ||
		!slices.Contains(p.Root.WorkingDirectories, i.LlamaWorkingDirectory) || !slices.Contains(p.Root.WorkingDirectories, i.AdapterWorkingDirectory) {
		return ErrRuntimeLaunch
	}
	if !maps.Equal(i.LlamaEnvironment, map[string]string{"HIP_VISIBLE_DEVICES": "0", "ROCR_VISIBLE_DEVICES": "0", "OMP_NUM_THREADS": "8"}) ||
		!maps.Equal(i.AdapterEnvironment, map[string]string{"DSH_HOME": "/aipt/private/home", "AIPT_HARNESS_PERSISTENCE_ROOT": "/aipt/private/sessions"}) ||
		!slices.Equal(p.Root.WritableDirectories, []string{"/aipt/private/home", "/aipt/private/proof", "/aipt/private/sessions"}) ||
		len(p.Root.AMDDevices) != 2 || p.Root.AMDDevices[0] != (FrozenDevice{Path: "/dev/kfd", Major: 509, Minor: 0}) || p.Root.AMDDevices[1] != (FrozenDevice{Path: "/dev/dri/renderD128", Major: 226, Minor: 128}) {
		return ErrRuntimeLaunch
	}
	files := map[string]RuntimeCodeFile{}
	for _, f := range m.Files {
		files[f.AssetID] = f
	}
	ids := map[string]bool{}
	for id, kind := range map[string]string{p.NativeAsset: "ELF", p.NodeAsset: "ELF", p.WorkerAsset: "JAVASCRIPT", p.RouteAsset: "DATA", p.BundleAsset: "JAVASCRIPT"} {
		f, exists := files[id]
		if !exists || ids[id] || f.Kind != kind || (kind == "ELF" && (!f.Executable || !slices.Contains(m.LaunchRoots, id))) {
			return ErrRuntimeLaunch
		}
		ids[id] = true
	}
	if len(ids) != 5 || files[p.NativeAsset].Bytes != 17904 || files[p.NodeAsset].SHA256 != b007NodeSHA || files[p.BundleAsset].SHA256 != b007BundleSHA {
		return ErrRuntimeLaunch
	}
	return nil
}

func acceptFrozenControl(initial frozenControlRequest, incoming frozenControlRequest, start bool) error {
	var want frozenControlRequest
	if start {
		want = initial
	} else {
		if incoming.Operation != "START_ADAPTER" && incoming.Operation != "STOP_ADAPTER" && incoming.Operation != "STOP_ALL" {
			return ErrRuntimeLaunch
		}
		want = frozenControlRequest{Schema: frozenControlSchema, Operation: incoming.Operation}
	}
	a, ae := json.Marshal(incoming)
	b, be := json.Marshal(want)
	if ae != nil || be != nil || !bytes.Equal(a, b) {
		return ErrRuntimeLaunch
	}
	return nil
}
