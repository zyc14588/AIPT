package pilot

import (
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
)

// This private binding is compiled into the separately accepted preparation
// executable. The caller cannot select its digest, bypass a missing full
// review or CI receipt, or expose a manager before both memory gates succeed.
// Receipt digests alone are references; the Owner's local online acceptance
// authenticates their origins before building the exact preparation binary.
type pilotLocalBinding struct {
	Schema                         string                           `json:"schema"`
	AuthoritySHA256                string                           `json:"authority_sha256"`
	AcceptedImplementationCommit   string                           `json:"accepted_implementation_commit"`
	FullIndependentReviewSHA256    string                           `json:"full_independent_review_sha256"`
	ImmutableOnlineCIReceiptSHA256 string                           `json:"immutable_online_ci_receipt_sha256"`
	RuntimeManifestSHA256          string                           `json:"runtime_manifest_sha256"`
	RuntimePolicySHA256            string                           `json:"runtime_policy_sha256"`
	Profile                        modelgateway.ModelProfile        `json:"model_profile"`
	Sampling                       modelgateway.SamplingProfile     `json:"sampling_profile"`
	Local                          modelgateway.LocalRuntimeConfig  `json:"local_runtime"`
	Adapter                        modelgateway.AdapterRuntimeRoute `json:"adapter_route"`
}

type acceptedPilotLocalGrant struct {
	binding  pilotLocalBinding
	identity string
}

func decodeAcceptedPilotLocalGrant(raw []byte, expectedBindingSHA, expectedManifestSHA string, manifestRaw, policyRaw []byte) (*acceptedPilotLocalGrant, error) {
	if !digest(expectedBindingSHA) || !digest(expectedManifestSHA) || inputSHA(raw) != expectedBindingSHA {
		return nil, ErrRuntimeLaunch
	}
	var b pilotLocalBinding
	if decodeFrozenJSON(raw, 1<<20, &b) != nil || b.Schema != "aipt.private.b007-accepted-local-launch-binding/v1" || b.AuthoritySHA256 != LocalClosureAuthoritySHA || b.RuntimeManifestSHA256 != expectedManifestSHA || !digest(b.FullIndependentReviewSHA256) || !digest(b.ImmutableOnlineCIReceiptSHA256) || !digest(b.RuntimePolicySHA256) || len(b.AcceptedImplementationCommit) != 40 {
		return nil, ErrRuntimeLaunch
	}
	for _, c := range b.AcceptedImplementationCommit {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return nil, ErrRuntimeLaunch
		}
	}
	if modelgateway.ValidateModelProfile(b.Profile) != nil || modelgateway.ValidateSamplingProfile(b.Sampling) != nil || b.Profile.BackendKind != modelgateway.BackendLocalLlamaCPP || b.Profile.ModelID != "gguf-04" || b.Profile.LocalRuntimeIdentity == nil || b.Profile.Harness.RuntimeClosureSHA256 != b007BundleSHA || b.Profile.SamplingProfileID != b.Sampling.BindingID() || b.Sampling.MaxOutputTokens != 1024 || b.Sampling.MaxContextTokens > 8192 {
		return nil, ErrRuntimeLaunch
	}
	r, l, a := b.Profile.LocalRuntimeIdentity, b.Local, b.Adapter
	if r.GGUFSHA256 != b007GGUFSHA || r.TemplateSHA256 != b007TemplateSHA || l.ProfileBinding != b.Profile.BindingID() || a.ProfileBinding != l.ProfileBinding || l.IsolationExecutableSHA256 != r.IsolationHelperSHA256 || !slices.Equal(l.AdditionalArguments, b007NativeArguments) || len(l.IsolationArguments) != 0 || len(a.Arguments) != 0 || a.LocalEndpointEnv != "AIPT_LOCAL_LLAMACPP_ENDPOINT" || a.ExecutableSHA256 != b007NodeSHA || !digest(a.AdapterEntrypointSHA256) || !digest(a.RouteConfigSHA256) || !maps.Equal(l.Environment, map[string]string{"HIP_VISIBLE_DEVICES": "0", "ROCR_VISIBLE_DEVICES": "0", "OMP_NUM_THREADS": "8"}) || !maps.Equal(a.Environment, map[string]string{"DSH_HOME": "/aipt/private/home", "AIPT_HARNESS_PERSISTENCE_ROOT": "/aipt/private/sessions"}) || l.StartupTimeoutMS < 1 || l.StartupTimeoutMS > 600000 || l.ShutdownTimeoutMS < 1 || l.ShutdownTimeoutMS > 30000 || a.StartupTimeoutMS < 1 || a.StartupTimeoutMS > 600000 || a.ShutdownTimeoutMS < 1 || a.ShutdownTimeoutMS > 30000 {
		return nil, ErrRuntimeLaunch
	}
	m, e := decodeCodeManifest(manifestRaw, expectedManifestSHA)
	if e != nil || inputSHA(policyRaw) != b.RuntimePolicySHA256 {
		return nil, ErrRuntimeLaunch
	}
	p, e := decodeRuntimeLaunchPolicy(policyRaw, m)
	if e != nil || validatePilotLocalPolicy(b, p, m) != nil {
		return nil, ErrRuntimeLaunch
	}
	return &acceptedPilotLocalGrant{binding: b, identity: expectedBindingSHA}, nil
}

func validatePilotLocalPolicy(b pilotLocalBinding, p runtimeLaunchPolicy, m RuntimeCodeManifest) error {
	l, a, r, i := b.Local, b.Adapter, b.Profile.LocalRuntimeIdentity, p.Initial
	if r == nil || validateRuntimeLaunchPolicy(p, m) != nil || i.ProfileBinding != b.Profile.BindingID() || i.LlamaWorkingDirectory != l.WorkingDirectory || i.AdapterWorkingDirectory != a.WorkingDirectory || i.StartupTimeoutMS != l.StartupTimeoutMS || i.ShutdownTimeoutMS != l.ShutdownTimeoutMS || a.StartupTimeoutMS != l.StartupTimeoutMS || a.ShutdownTimeoutMS != l.ShutdownTimeoutMS || !slices.Equal(i.AdditionalArguments, l.AdditionalArguments) || !maps.Equal(i.LlamaEnvironment, l.Environment) || !maps.Equal(i.AdapterEnvironment, a.Environment) || i.LocalEndpointEnvironment != a.LocalEndpointEnv {
		return ErrRuntimeLaunch
	}
	args, e := modelgateway.GovernedLaunchParameters(b007NativeArguments)
	if e != nil || !slices.Equal(r.LaunchParameters, args) {
		return ErrRuntimeLaunch
	}
	files := map[string]RuntimeCodeFile{}
	for _, f := range m.Files {
		files[f.AssetID] = f
	}
	if files[p.NativeAsset].SHA256 != r.BinarySHA256 || files[p.NodeAsset].SHA256 != a.ExecutableSHA256 || files[p.WorkerAsset].SHA256 != a.AdapterEntrypointSHA256 || files[p.RouteAsset].SHA256 != a.RouteConfigSHA256 || files[p.BundleAsset].SHA256 != b.Profile.Harness.RuntimeClosureSHA256 || files[frozenPolicyAsset].SHA256 != b.RuntimePolicySHA256 {
		return ErrRuntimeLaunch
	}
	return nil
}

type preparedPilotLocal struct {
	mu        sync.Mutex
	grant     *acceptedPilotLocalGrant
	memory    *MemoryGuardedLocal
	transport modelgateway.HarnessTransport
	delegated *task0DelegatedLocal
	revoked   bool
}

// The enclosing driver is freshly exec'd into its own user/mount namespace
// before this constructor. Native/GGUF/cache source FDs are opened here, not
// passed from the parent's mount namespace. No runtime test selector exists.
func openPreparedPilotLocal(ctx context.Context, grant *acceptedPilotLocalGrant, memoryReceipts io.Writer) (*preparedPilotLocal, error) {
	if ctx == nil || ctx.Err() != nil || grant == nil || !digest(grant.identity) || memoryReceipts == nil || os.Geteuid() != 0 || !namespaceIsNotHost("user") || !namespaceIsNotHost("mnt") {
		return nil, ErrRuntimeLaunch
	}
	b := grant.binding
	l, a := b.Local, b.Adapter
	m, e := NewMemoryGuardedLocal(b.Profile, modelgateway.ManagedLlamaSpec{ExecutablePath: l.ExecutablePath, GGUFPath: l.GGUFPath, AdditionalArguments: slices.Clone(l.AdditionalArguments), Environment: maps.Clone(l.Environment), WorkingDirectory: l.WorkingDirectory, StartupTimeout: time.Duration(l.StartupTimeoutMS) * time.Millisecond, ShutdownTimeout: time.Duration(l.ShutdownTimeoutMS) * time.Millisecond, IsolationExecutablePath: l.IsolationExecutablePath, IsolationExecutableSHA256: l.IsolationExecutableSHA256}, memoryReceipts)
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	s := &preparedPilotLocal{grant: grant, memory: m}
	fail := func(cause error) (*preparedPilotLocal, error) { return nil, errors.Join(cause, s.retire()) }
	route := modelgateway.AdapterRouteSpec{ProfileBinding: a.ProfileBinding, ExecutablePath: a.ExecutablePath, ExecutableSHA256: a.ExecutableSHA256, AdapterEntrypointPath: a.AdapterEntrypointPath, AdapterEntrypointSHA256: a.AdapterEntrypointSHA256, RouteConfigPath: a.RouteConfigPath, RouteConfigSHA256: a.RouteConfigSHA256, Arguments: slices.Clone(a.Arguments), Environment: maps.Clone(a.Environment), WorkingDirectory: a.WorkingDirectory, StartupTimeout: time.Duration(a.StartupTimeoutMS) * time.Millisecond, ShutdownTimeout: time.Duration(a.ShutdownTimeoutMS) * time.Millisecond}
	if e = m.PrepareIsolatedAdapter(route, a.LocalEndpointEnv); e != nil {
		return fail(ErrRuntimeLaunch)
	}
	if e = m.Start(ctx); e != nil {
		return fail(ErrRuntimeLaunch)
	}
	manager, e := m.RegisteredManager()
	if e != nil {
		return fail(ErrRuntimeLaunch)
	}
	route.IsolatedLauncher = manager
	s.transport, e = modelgateway.NewAdapterProcessTransport([]modelgateway.ModelProfile{b.Profile}, []modelgateway.AdapterRouteSpec{route}, nil)
	if e != nil {
		return fail(ErrRuntimeLaunch)
	}
	return s, nil
}

func (s *preparedPilotLocal) retire() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var transportErr, memoryErr error
	if s.transport != nil {
		transportErr = s.transport.Close(ctx)
	}
	if s.memory != nil {
		memoryErr = s.memory.Retire(ctx)
	}
	if s.delegated != nil {
		memoryErr = errors.Join(memoryErr, s.delegated.retire())
	}
	return errors.Join(transportErr, memoryErr)
}

func processParentPID(pid int) (int, error) {
	raw, e := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if e != nil || len(raw) > 65536 {
		return 0, ErrRuntimeLaunch
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, ErrRuntimeLaunch
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 2 {
		return 0, ErrRuntimeLaunch
	}
	parent, e := strconv.Atoi(fields[1])
	if e != nil || parent <= 1 {
		return 0, ErrRuntimeLaunch
	}
	return parent, nil
}

// The stream is read before retirement from the exact accepted helper's
// read-only Unix service. Kernel peer credentials, a retained pidfd, the
// complete sealed helper digest and stable namespace identities authenticate
// its origin; self-reported receipt fields do not provide that authority.
func (s *preparedPilotLocal) readNativeProof(ctx context.Context) ([]byte, error) {
	if s == nil || ctx == nil {
		return nil, ErrRuntimeLaunch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || (s.memory == nil && s.delegated == nil) || s.transport == nil {
		return nil, ErrRuntimeLaunch
	}
	var nativePID int
	var ready bool
	if s.delegated != nil {
		l := s.delegated
		l.mu.Lock()
		nativePID, ready = l.nativePID, l.ready && l.check() == nil
		l.mu.Unlock()
	} else {
		m := s.memory
		m.mu.Lock()
		nativePID, ready = m.pid, m.ready
		m.mu.Unlock()
	}
	if !ready || nativePID <= 1 {
		return nil, ErrRuntimeLaunch
	}
	pid, e := processParentPID(nativePID)
	if e != nil {
		return nil, e
	}
	if s.delegated != nil && (s.delegated.process == nil || s.delegated.process.process == nil || pid != s.delegated.process.pid) {
		return nil, ErrRuntimeLaunch
	}
	p, e := os.FindProcess(pid)
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	defer p.Release()
	held := false
	if p.WithHandle(func(uintptr) { held = true }) != nil || !held || p.Signal(syscall.Signal(0)) != nil {
		return nil, ErrRuntimeLaunch
	}
	base := "/proc/" + strconv.Itoa(pid)
	executable, e := os.Open(base + "/exe")
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	defer executable.Close()
	info, e := executable.Stat()
	if e != nil || info.Size() < 64 || info.Size() > 4<<30 {
		return nil, ErrRuntimeLaunch
	}
	seal, _, eno := syscall.Syscall(syscall.SYS_FCNTL, executable.Fd(), 0x40a, 0)
	if eno != 0 || seal&0xf != 0xf || inputSHAFileMetadata(executable) != s.grant.binding.Profile.LocalRuntimeIdentity.IsolationHelperSHA256 {
		return nil, ErrRuntimeLaunch
	}
	ns := map[string]os.FileInfo{}
	for _, kind := range []string{"user", "pid", "mnt", "net"} {
		a, e := os.Stat(base + "/ns/" + kind)
		b, be := os.Stat("/proc/self/ns/" + kind)
		if e != nil || be != nil || os.SameFile(a, b) {
			return nil, ErrRuntimeLaunch
		}
		ns[kind] = a
	}
	// This is the owned child's proc root and fixed guest socket, never an
	// Owner home locator supplied by a model or public caller.
	address := filepath.Join(base, "root", "aipt", "private", "proof", "proof.sock")
	c, e := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", address)
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	defer c.Close()
	deadline := time.Now().Add(time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	unix, ok := c.(*net.UnixConn)
	if !ok {
		return nil, ErrRuntimeLaunch
	}
	raw, e := unix.SyscallConn()
	if e != nil {
		return nil, ErrRuntimeLaunch
	}
	peerOK := false
	if e = raw.Control(func(fd uintptr) {
		peer, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		peerOK = e == nil && int(peer.Pid) == pid && peer.Uid == uint32(os.Geteuid()) && peer.Gid == uint32(os.Getegid())
	}); e != nil || !peerOK {
		return nil, ErrRuntimeLaunch
	}
	body, e := io.ReadAll(io.LimitReader(c, 16385))
	if e != nil || len(body) > 16384 || p.Signal(syscall.Signal(0)) != nil {
		return nil, ErrRuntimeLaunch
	}
	a, e := os.Stat(base + "/exe")
	if e != nil || !os.SameFile(a, info) {
		return nil, ErrRuntimeLaunch
	}
	parent, e := processParentPID(nativePID)
	if e != nil || parent != pid {
		return nil, ErrRuntimeLaunch
	}
	for kind, a := range ns {
		b, e := os.Stat(base + "/ns/" + kind)
		if e != nil || !os.SameFile(a, b) {
			return nil, ErrRuntimeLaunch
		}
	}
	return body, nil
}

func validateCompletedNativeProof(raw []byte, closureSHA, nativeSHA, requestSHA string) error {
	if len(raw) == 0 || len(raw) > 16384 || raw[len(raw)-1] != '\n' || !digest(closureSHA) || !digest(nativeSHA) || !digest(requestSHA) {
		return ErrNativeInputProof
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 3 {
		return ErrNativeInputProof
	}
	previous := strings.Repeat("0", 64)
	input, requestBytes := 0, 0
	for i, line := range lines {
		var r NativeInputReceipt
		if decodeFrozenJSON([]byte(line), 4096, &r) != nil || r.Schema != "aipt.private.b007-final-native-input-proof/v1" || r.Sequence != i+1 || r.PreviousSHA256 != previous || r.ClosureSHA256 != closureSHA || r.NativeSHA256 != nativeSHA || r.RequestSHA256 != requestSHA || r.RequestBytes < 1 || r.RequestBytes > 8192 {
			return ErrNativeInputProof
		}
		if i == 0 {
			if r.Event != "COUNT_REQUEST_INTENT" || r.InputTokens != 0 || r.OutputTokens != 0 || r.ResponseSHA256 != inputSHA(nil) {
				return ErrNativeInputProof
			}
			requestBytes = r.RequestBytes
		}
		if r.RequestBytes != requestBytes {
			return ErrNativeInputProof
		}
		if i == 1 {
			if r.Event != "COUNT_PASS_GENERATION_INTENT" || r.InputTokens < 1 || r.InputTokens > 8192 || r.OutputTokens != 0 || r.ResponseSHA256 != inputSHA(nil) {
				return ErrNativeInputProof
			}
			input = r.InputTokens
		}
		if i == 2 {
			if r.Event != "GENERATION_COMPLETED_WITH_BOUNDED_USAGE" || r.InputTokens != input || r.OutputTokens < 0 || r.OutputTokens > 1024 || !digest(r.ResponseSHA256) || r.ResponseSHA256 == inputSHA(nil) {
				return ErrNativeInputProof
			}
		}
		previous = inputSHA(append([]byte(line), '\n'))
	}
	return nil
}
