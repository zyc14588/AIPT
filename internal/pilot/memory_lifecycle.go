package pilot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

// MemoryGuardedLocal adds the Owner-selected file-cache gate around the
// unchanged managed local runtime. It owns its registered cache FDs; a failed
// start is retired and cannot be retried as a fresh model generation.
// Construction does not start a server, create a model snapshot or infer.
type MemoryGuardedLocal struct {
	mu                  sync.Mutex
	profile             modelgateway.ModelProfile
	spec                modelgateway.ManagedLlamaSpec
	record              io.Writer
	assets              []CacheAsset
	manager             *modelgateway.ManagedLlama
	adapter             *modelgateway.AdapterRouteSpec
	endpointEnvironment string
	attempted, retired  bool
	admissionRevoked    bool
	sources             *heldMemorySources
	ready               bool
	pid                 int
}

func holdCacheAsset(name, locator, expected string) (CacheAsset, error) {
	canonical, err := filepath.EvalSymlinks(locator)
	if err != nil || !filepath.IsAbs(canonical) || !digest(expected) {
		return CacheAsset{}, ErrMemory
	}
	fd, err := syscall.Open(canonical, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return CacheAsset{}, ErrMemory
	}
	f := os.NewFile(uintptr(fd), "held registered local cache asset")
	fail := func() (CacheAsset, error) { _ = f.Close(); return CacheAsset{}, ErrMemory }
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 {
		return fail()
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
		return fail()
	}
	after, err := f.Stat()
	current, pathErr := os.Stat(canonical)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(after, current) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return fail()
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	return CacheAsset{AssetID: name, File: f}, nil
}

func NewMemoryGuardedLocal(profile modelgateway.ModelProfile, spec modelgateway.ManagedLlamaSpec, record io.Writer) (*MemoryGuardedLocal, error) {
	if modelgateway.ValidateModelProfile(profile) != nil || profile.BackendKind != modelgateway.BackendLocalLlamaCPP || profile.LocalRuntimeIdentity == nil || record == nil {
		return nil, ErrMemory
	}
	// Freeze caller-owned slices, maps, and nested profile identities before
	// holding assets. Later caller mutation cannot change the startup binding.
	raw, err := json.Marshal(profile)
	if err != nil {
		return nil, ErrMemory
	}
	var frozen modelgateway.ModelProfile
	if json.Unmarshal(raw, &frozen) != nil || modelgateway.ValidateModelProfile(frozen) != nil {
		return nil, ErrMemory
	}
	spec.AdditionalArguments = slices.Clone(spec.AdditionalArguments)
	spec.IsolationArguments = slices.Clone(spec.IsolationArguments)
	spec.Environment = maps.Clone(spec.Environment)
	result := &MemoryGuardedLocal{profile: frozen, spec: spec, record: record}
	runtime := frozen.LocalRuntimeIdentity
	for _, item := range []struct{ id, path, sha string }{
		{runtime.ExecutableReference, spec.ExecutablePath, runtime.BinarySHA256},
		{runtime.GGUFReference, spec.GGUFPath, runtime.GGUFSHA256},
	} {
		asset, err := holdCacheAsset(item.id, item.path, item.sha)
		if err != nil {
			result.closeAssets()
			return nil, err
		}
		result.assets = append(result.assets, asset)
	}
	return result, nil
}

// PrepareIsolatedAdapter records a single adapter binding before Start. The
// unchanged manager performs full route validation and sealed asset capture
// during Start, before the BEFORE_START cache gate or any process launch.
// Construction exposes no manager or model-use capability.
func (m *MemoryGuardedLocal) PrepareIsolatedAdapter(spec modelgateway.AdapterRouteSpec, endpointEnvironment string) error {
	if m == nil {
		return ErrMemory
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.admissionRevoked || m.attempted || m.retired || m.adapter != nil || spec.IsolatedLauncher != nil ||
		spec.ProfileBinding != m.profile.BindingID() || !regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`).MatchString(endpointEnvironment) ||
		spec.ExecutablePath == "" || spec.AdapterEntrypointPath == "" || spec.RouteConfigPath == "" || spec.WorkingDirectory == "" ||
		!digest(spec.ExecutableSHA256) || !digest(spec.AdapterEntrypointSHA256) || !digest(spec.RouteConfigSHA256) ||
		spec.StartupTimeout <= 0 || spec.ShutdownTimeout <= 0 {
		return ErrMemory
	}
	spec.Arguments = slices.Clone(spec.Arguments)
	spec.Environment = maps.Clone(spec.Environment)
	m.adapter = &spec
	m.endpointEnvironment = endpointEnvironment
	return nil
}

func (m *MemoryGuardedLocal) closeAssets() {
	for _, asset := range m.assets {
		_ = asset.File.Close()
	}
	m.assets = nil
}

func (m *MemoryGuardedLocal) Start(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrMemory
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.admissionRevoked || m.attempted || m.retired || ctx.Err() != nil {
		return ErrMemory
	}
	m.attempted = true
	// The dedicated preparation child owns a private user/mount namespace.
	// Bind the held source objects there before the unchanged manager opens
	// its paths. A host rename, including an equal-digest replacement and
	// later swap-back, cannot change which inode is read and cache-released.
	if len(m.assets) != 2 || m.spec.IsolationExecutablePath == "" {
		return m.retireFailure(ErrMemory)
	}
	helper, err := holdCacheAsset(m.profile.LocalRuntimeIdentity.IsolationHelperReference, m.spec.IsolationExecutablePath, m.profile.LocalRuntimeIdentity.IsolationHelperSHA256)
	if err != nil {
		return m.retireFailure(err)
	}
	m.sources, err = bindHeldMemorySources([]*os.File{m.assets[0].File, m.assets[1].File, helper.File})
	_ = helper.File.Close()
	if err != nil {
		return m.retireFailure(err)
	}
	m.spec.ExecutablePath = m.sources.paths[0]
	m.spec.GGUFPath = m.sources.paths[1]
	m.spec.IsolationExecutablePath = m.sources.paths[2]
	manager, err := modelgateway.NewManagedLlama(m.profile, m.spec)
	if err != nil {
		return m.retireFailure(err)
	}
	m.manager = manager
	if m.adapter != nil {
		if err = manager.PrepareIsolatedAdapter(*m.adapter, m.endpointEnvironment); err != nil {
			return m.retireFailure(err)
		}
	}
	// Preparation copies and hashes the sealed GGUF. Release the original file
	// cache after that read and immediately before launching the local process.
	if _, err = CheckAndReleaseModelCache(ctx, "BEFORE_START", 0, m.assets, m.record); err != nil {
		return m.retireFailure(err)
	}
	if err = manager.Start(ctx); err != nil {
		return m.retireFailure(err)
	}
	m.pid, err = registeredDescendantPID(os.Getpid(), m.profile.LocalRuntimeIdentity.BinarySHA256)
	if err != nil {
		return m.retireFailure(err)
	}
	if _, err = CheckAndReleaseModelCache(ctx, "AFTER_START", m.pid, m.assets, m.record); err != nil {
		return m.retireFailure(err)
	}
	m.ready = true
	return nil
}

// RegisteredManager is available only after successful startup and both
// memory gates. It supplies the unchanged namespace-isolated Harness route.
func (m *MemoryGuardedLocal) RegisteredManager() (*modelgateway.ManagedLlama, error) {
	if m == nil {
		return nil, ErrMemory
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.manager == nil || m.pid <= 1 || m.retired || !m.ready {
		return nil, ErrMemory
	}
	return m.manager, nil
}

func (m *MemoryGuardedLocal) retireFailure(cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return errors.Join(cause, m.retire(cleanupCtx))
}
func (m *MemoryGuardedLocal) Retire(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.admissionRevoked = true
	m.ready = false
	if ctx == nil {
		return ErrMemory
	}
	return m.retire(ctx)
}
func (m *MemoryGuardedLocal) retire(ctx context.Context) error {
	// Revocation precedes cleanup. Ownership may remain reachable after a
	// cleanup failure, but that never reopens model use or bypasses a gate.
	m.admissionRevoked = true
	m.ready = false
	if m.retired {
		return nil
	}
	if m.manager != nil {
		if err := m.manager.Retire(ctx); err != nil {
			return err
		} // Keep ownership reachable for bounded cleanup.
	}
	m.pid = 0
	if len(m.assets) > 0 {
		if _, err := CheckAndReleaseModelCache(ctx, "AFTER_RETIRE", 0, m.assets, m.record); err != nil {
			return err
		}
	}
	if m.sources != nil {
		if err := m.sources.close(); err != nil {
			return err
		}
		m.sources = nil
	}
	m.closeAssets()
	m.manager = nil
	m.adapter = nil
	m.endpointEnvironment = ""
	m.retired = true
	return nil
}

// Only direct descendants of the calling pilot process are considered. This
// reads process state; it neither attaches to nor signals an unrelated model.
// The manager itself retains the kernel pidfd authority for all retirement.
func registeredDescendantPID(rootPID int, executableSHA string) (int, error) {
	if rootPID <= 1 || !digest(executableSHA) {
		return 0, ErrMemory
	}
	todo := []int{rootPID}
	seen := map[int]bool{}
	found := 0
	for len(todo) > 0 {
		pid := todo[0]
		todo = todo[1:]
		if seen[pid] {
			continue
		}
		if len(seen) >= 256 {
			return 0, ErrMemory
		}
		seen[pid] = true
		children, err := taskChildren(pid)
		if err != nil {
			return 0, ErrMemory
		}
		for _, child := range children {
			todo = append(todo, child)
			f, err := os.Open("/proc/" + strconv.Itoa(child) + "/exe")
			if err != nil {
				return 0, ErrMemory
			}
			info, err := f.Stat()
			if err != nil {
				_ = f.Close()
				return 0, ErrMemory
			}
			// Registered launchers are small; avoid reading a 100MB Node binary just
			// to discard it. There is no fixed executable size assumption for a match.
			if info.Size() > 0 && info.Size() <= 32<<20 {
				hash := sha256.New()
				_, err = io.Copy(hash, io.LimitReader(f, 32<<20+1))
				if err == nil && hex.EncodeToString(hash.Sum(nil)) == executableSHA {
					if found != 0 {
						_ = f.Close()
						return 0, ErrMemory
					}
					found = child
				}
			}
			_ = f.Close()
		}
	}
	if found <= 1 {
		return 0, ErrMemory
	}
	return found, nil
}

// Forked children are owned by the thread which spawned them. Reading only
// task/<leader>/children can miss a valid model launched by Go's exec on a
// different OS thread. Union every task's bounded inventory, then deduplicate.
func taskChildren(pid int) ([]int, error) {
	if pid <= 1 {
		return nil, ErrMemory
	}
	taskRoot := "/proc/" + strconv.Itoa(pid) + "/task"
	tasks, err := os.ReadDir(taskRoot)
	if err != nil || len(tasks) == 0 || len(tasks) > 512 {
		return nil, ErrMemory
	}
	children := []int{}
	seen := map[int]bool{}
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil || tid <= 1 || !task.IsDir() {
			return nil, ErrMemory
		}
		raw, err := os.ReadFile(taskRoot + "/" + task.Name() + "/children")
		if os.IsNotExist(err) {
			continue
		} // A nonleader task may retire during inspection.
		if err != nil || len(raw) > 64<<10 {
			return nil, ErrMemory
		}
		for _, value := range strings.Fields(string(raw)) {
			child, err := strconv.Atoi(value)
			if err != nil || child <= 1 {
				return nil, ErrMemory
			}
			if !seen[child] {
				seen[child] = true
				children = append(children, child)
			}
			if len(children) > 256 {
				return nil, ErrMemory
			}
		}
	}
	slices.Sort(children)
	return children, nil
}
