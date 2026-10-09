package pilot

import (
	"io"
	"slices"
	"strings"
)

const task0GamePolicyAsset = "b007_task0_game_root_policy"

// The game owns a closed network namespace, immutable source and the Node
// loader closure. Model/native assets and hardware are not game capabilities.
type task0GameRootPolicy struct {
	Schema    string         `json:"schema"`
	Root      FrozenRootPlan `json:"root"`
	NodeAsset string         `json:"node_asset"`
}

// Every ELF in a non-native capsule must be reachable from the exact Node's
// declared interpreter/NEEDED closure. Actual ELF bytes are checked separately
// by HeldCodeCapsule; names and metadata cannot authenticate themselves.
func task0NodeClosure(m RuntimeCodeManifest, nodeID string) (map[string]bool, error) {
	files, guest := map[string]RuntimeCodeFile{}, map[string]string{}
	for _, f := range m.Files {
		if files[f.AssetID].AssetID != "" {
			return nil, ErrRuntimeLaunch
		}
		files[f.AssetID] = f
		for _, name := range f.GuestPaths {
			if guest[name] != "" {
				return nil, ErrRuntimeLaunch
			}
			guest[name] = f.AssetID
		}
	}
	node := files[nodeID]
	if node.Kind != "ELF" || !node.Executable || node.SHA256 != b007NodeSHA || !slices.Equal(m.LaunchRoots, []string{nodeID}) {
		return nil, ErrRuntimeLaunch
	}
	used := map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		f, exists := files[id]
		if !exists || f.Kind != "ELF" {
			return ErrRuntimeLaunch
		}
		if used[id] {
			return nil
		}
		used[id] = true
		if f.Interpreter != "" {
			if visit(guest[f.Interpreter]) != nil {
				return ErrRuntimeLaunch
			}
		}
		for _, edge := range f.Needed {
			if visit(edge.AssetID) != nil {
				return ErrRuntimeLaunch
			}
		}
		return nil
	}
	if visit(nodeID) != nil {
		return nil, ErrRuntimeLaunch
	}
	return used, nil
}

func validateTask0GameRootPolicy(p task0GameRootPolicy, m RuntimeCodeManifest) error {
	if p.Schema != "aipt.private.b007-task0-game-root-policy/v1" ||
		!slices.Equal(p.Root.WorkingDirectories, []string{"/aipt/game"}) || len(p.Root.WritableDirectories) != 0 ||
		p.Root.HardwareSysfs || len(p.Root.AMDDevices) != 0 || validateFrozenRootPlan(p.Root, m) != nil {
		return ErrTask0
	}
	elfs, err := task0NodeClosure(m, p.NodeAsset)
	if err != nil {
		return ErrTask0
	}
	policy, gateway, sources := false, false, 0
	for _, f := range m.Files {
		switch {
		case elfs[f.AssetID]:
		case f.AssetID == task0GamePolicyAsset:
			if f.Kind != "DATA" || !slices.Equal(f.GuestPaths, []string{"/aipt/policy/task0-game-root.json"}) {
				return ErrTask0
			}
			policy = true
		case f.AssetID == task0GatewayAsset:
			if f.Kind != "JAVASCRIPT" || f.SHA256 != Task0GameGatewaySHA {
				return ErrTask0
			}
			gateway = true
		case strings.HasPrefix(f.AssetID, "b007_game_"):
			// validateTask0Capsule checks every one of these exact 46 assets,
			// source digest, bytes and guest alias against the held source manifest.
			if f.Kind != "DATA" && f.Kind != "JAVASCRIPT" {
				return ErrTask0
			}
			sources++
		default:
			return ErrTask0
		}
	}
	if !policy || !gateway || sources != 46 {
		return ErrTask0
	}
	return nil
}

func frozenTask0GamePolicy(c *HeldCodeCapsule) (task0GameRootPolicy, error) {
	var p task0GameRootPolicy
	if c == nil || !digest(c.Identity()) || validateTask0Capsule(c) != nil {
		return p, ErrTask0
	}
	f, err := c.Descriptor(task0GamePolicyAsset)
	if err != nil {
		return p, ErrTask0
	}
	defer f.Close()
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, (64<<10)+1))
	if err != nil || decodeFrozenJSON(raw, 64<<10, &p) != nil || validateTask0GameRootPolicy(p, c.manifest) != nil {
		return p, ErrTask0
	}
	return p, nil
}
