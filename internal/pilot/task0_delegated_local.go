package pilot

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
)

// This adapter delegates the existing frozen LOCAL helper and its unchanged
// 3..13 ABI to the single accepted SETUP owner. It creates no new role,
// provider route, model, profile, sampling policy or attempt budget.
type task0DelegatedLocal struct {
	mu                      sync.Mutex
	owner                   *task0SetupClient
	createAttempted         bool
	process                 *task0DelegatedProcess
	helper                  *os.File
	control                 *net.UnixConn
	pipes                   *task0DelegatedPipes
	reader                  *bufio.Reader
	grant                   *acceptedPilotLocalGrant
	assets                  []CacheAsset
	record                  io.Writer
	nativePID               int
	ready, adapter, revoked bool
	serial                  uint64
	retirement              sync.Once
	retireErr               error
}

func task0RegisteredGGUFSnapshot(ctx context.Context, source *os.File) (*os.File, error) {
	if ctx == nil || ctx.Err() != nil || source == nil || os.Getpid() != 1 || os.Geteuid() != 0 {
		return nil, ErrRuntimeLaunch
	}
	before, err := task0CAFileState(source)
	if err != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG || before.Nlink != 1 || before.Size != b007GGUFBytes {
		return nil, ErrRuntimeLaunch
	}
	name, err := syscall.BytePtrFromString("aipt-b007-fixed-registered-gguf")
	if err != nil {
		return nil, ErrRuntimeLaunch
	}
	fd, _, e := syscall.Syscall(319, uintptr(unsafe.Pointer(name)), 3, 0)
	if e != 0 {
		return nil, ErrRuntimeLaunch
	}
	f := os.NewFile(fd, "held sealed registered GGUF")
	fail := func() (*os.File, error) { f.Close(); return nil, ErrRuntimeLaunch }
	hash := sha256.New()
	buffer := make([]byte, 256<<10)
	defer clear(buffer)
	for offset := int64(0); offset < b007GGUFBytes; {
		if ctx.Err() != nil {
			return fail()
		}
		want := min(int64(len(buffer)), b007GGUFBytes-offset)
		n, err := source.ReadAt(buffer[:want], offset)
		if int64(n) != want || err != nil {
			return fail()
		}
		written, err := f.Write(buffer[:n])
		if err != nil || written != n {
			return fail()
		}
		if _, err = hash.Write(buffer[:n]); err != nil {
			return fail()
		}
		offset += int64(n)
	}
	after, err := task0CAFileState(source)
	if err != nil || !task0SamePrivateRecordState(before, after) || hex.EncodeToString(hash.Sum(nil)) != b007GGUFSHA || ctx.Err() != nil || f.Chmod(0400) != nil {
		return fail()
	}
	_, _, e = syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 0x409, 15)
	if e != 0 {
		return fail()
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail()
	}
	return f, nil
}

func openTask0DelegatedLocal(ctx context.Context, owner *task0SetupClient, grant *acceptedPilotLocalGrant, memoryReceipts io.Writer) (*preparedPilotLocal, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || !owner.live() || owner.grant == nil || grant == nil || memoryReceipts == nil ||
		!task0SameJSON(owner.grant.local.binding, grant.binding) || os.Getpid() != 1 || os.Geteuid() != 0 {
		return nil, ErrRuntimeLaunch
	}
	l := &task0DelegatedLocal{owner: owner, grant: grant, record: memoryReceipts}
	fail := func() (*preparedPilotLocal, error) { _ = l.retire(); return nil, ErrRuntimeLaunch }
	b := grant.binding
	for _, item := range []struct{ id, path, sha string }{{b.Profile.LocalRuntimeIdentity.ExecutableReference, b.Local.ExecutablePath, b.Profile.LocalRuntimeIdentity.BinarySHA256}, {b.Profile.LocalRuntimeIdentity.GGUFReference, b.Local.GGUFPath, b007GGUFSHA}} {
		asset, err := holdCacheAsset(item.id, item.path, item.sha)
		if err != nil {
			return fail()
		}
		l.assets = append(l.assets, asset)
	}
	role := owner.grant.roles["LOCAL"]
	l.helper, _ = task0HoldPreparationHelper(task0PreparationFile{Path: b.Local.IsolationExecutablePath, SHA256: role.ProgramSHA, Bytes: role.ProgramBytes})
	if l.helper == nil {
		return fail()
	}
	c, err := OpenEmbeddedCodeCapsule(l.helper, role.ManifestSHA)
	if err != nil {
		return fail()
	}
	defer c.Close()
	policy, err := frozenCapsulePolicy(c)
	if err != nil || !task0SameJSON(policy, owner.grant.policy) || !task0SameJSON(c.manifest, owner.grant.manifest) {
		return fail()
	}
	gguf, err := task0RegisteredGGUFSnapshot(ctx, l.assets[1].File)
	if err != nil {
		return fail()
	}
	defer gguf.Close()
	control, child, err := task0PrivateControlPair()
	if err != nil {
		return fail()
	}
	l.control = control
	defer child.Close()
	l.pipes, err = task0NewDelegatedPipes()
	if err != nil {
		return fail()
	}
	files := make([]*os.File, 11)
	files[0], files[1], files[3], files[7], files[8] = l.helper, child, gguf, l.pipes.childInput, l.pipes.childOutput
	defer func() {
		for _, index := range []int{2, 4, 5, 6, 9, 10} {
			if files[index] != nil {
				files[index].Close()
			}
		}
	}()
	for index, id := range map[int]string{2: policy.NativeAsset, 4: policy.NodeAsset, 5: policy.WorkerAsset, 6: policy.RouteAsset, 9: policy.NodeAsset, 10: policy.BundleAsset} {
		files[index], err = c.Descriptor(id)
		if err != nil {
			return fail()
		}
	}
	// Copy/hash completes before the same two held original cache objects are
	// released. This never remounts paths in active, zero-capability PREP.
	if _, err = CheckAndReleaseModelCache(ctx, "BEFORE_START", 0, l.assets, l.record); err != nil {
		return fail()
	}
	l.createAttempted = true
	l.process, err = owner.create("LOCAL", files)
	child.Close()
	l.pipes.closePeers()
	if err != nil {
		return fail()
	}
	if _, err = l.exchangeControl(ctx, policy.Initial, time.Duration(b.Local.StartupTimeoutMS)*time.Millisecond); err != nil {
		return fail()
	}
	info, err := l.helper.Stat()
	if err != nil || l.process.check(info) != nil {
		return fail()
	}
	l.nativePID, err = registeredDescendantPID(l.process.pid, b.Profile.LocalRuntimeIdentity.BinarySHA256)
	if err != nil {
		return fail()
	}
	if _, err = CheckAndReleaseModelCache(ctx, "AFTER_START", l.nativePID, l.assets, l.record); err != nil {
		return fail()
	}
	l.ready = true
	l.reader = bufio.NewReaderSize(l.pipes.output, (1<<20)+1)
	context.AfterFunc(ctx, func() { _ = l.retire() })
	return &preparedPilotLocal{grant: grant, transport: l, delegated: l}, nil
}

func (l *task0DelegatedLocal) check() error {
	if l == nil || !l.ready || l.revoked || l.process == nil || l.helper == nil {
		return ErrRuntimeLaunch
	}
	info, err := l.helper.Stat()
	if err != nil {
		return ErrRuntimeLaunch
	}
	return l.process.check(info)
}

func (l *task0DelegatedLocal) exchangeControl(ctx context.Context, request frozenControlRequest, timeout time.Duration) (frozenControlReply, error) {
	var reply frozenControlReply
	if ctx == nil || ctx.Err() != nil || l == nil || l.control == nil || timeout <= 0 {
		return reply, ErrRuntimeLaunch
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if l.control.SetDeadline(deadline) != nil {
		return reply, ErrRuntimeLaunch
	}
	stop := context.AfterFunc(ctx, func() { _ = l.control.Close() })
	defer stop()
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > 65536 {
		return reply, ErrRuntimeLaunch
	}
	n, err := l.control.Write(raw)
	if err != nil || n != len(raw) {
		return reply, ErrRuntimeLaunch
	}
	var response [4097]byte
	n, _, flags, _, err := l.control.ReadMsgUnix(response[:], nil)
	if err != nil || flags&syscall.MSG_TRUNC != 0 || n < 1 || n > 4096 || decodeFrozenJSON(response[:n], 4096, &reply) != nil ||
		reply.Schema != frozenControlSchema || reply.Operation != request.Operation || reply.Result != "PASS" || reply.Code != "" || reply.FailureStage != "" {
		return reply, ErrRuntimeLaunch
	}
	if request.Operation == "START_MODEL" {
		if reply.IsolationIdentity != modelgateway.LocalIsolationIdentity || reply.Port < 1 || reply.Port > 65535 || reply.AdapterPID != 0 {
			return reply, ErrRuntimeLaunch
		}
	} else if request.Operation == "START_ADAPTER" {
		if reply.AdapterPID < 2 || reply.Port != 0 || reply.IsolationIdentity != "" {
			return reply, ErrRuntimeLaunch
		}
	} else if reply.AdapterPID != 0 || reply.Port != 0 || reply.IsolationIdentity != "" {
		return reply, ErrRuntimeLaunch
	}
	if l.control.SetDeadline(time.Time{}) != nil {
		return reply, ErrRuntimeLaunch
	}
	return reply, nil
}

func (l *task0DelegatedLocal) adapterExchange(ctx context.Context, profile modelgateway.ModelProfile, sampling modelgateway.SamplingProfile, method string, params any) (json.RawMessage, error) {
	if l.check() != nil || ctx == nil || ctx.Err() != nil || !task0SameJSON(profile, l.grant.binding.Profile) || !task0SameJSON(sampling, l.grant.binding.Sampling) {
		return nil, ErrRuntimeLaunch
	}
	if !l.adapter {
		if _, err := l.exchangeControl(ctx, frozenControlRequest{Schema: frozenControlSchema, Operation: "START_ADAPTER"}, time.Duration(l.grant.binding.Adapter.StartupTimeoutMS)*time.Millisecond); err != nil {
			return nil, ErrRuntimeLaunch
		}
		l.adapter = true
	}
	l.serial++
	id := "b007-owned-local-" + strconv.FormatUint(l.serial, 10)
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "protocol_version": "1", "method": method, "params": params})
	if err != nil || len(body) > 1<<20 {
		return nil, ErrRuntimeLaunch
	}
	callCtx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		data := append(body, '\n')
		for len(data) > 0 {
			n, e := l.pipes.input.Write(data)
			if e != nil || n < 1 || n > len(data) {
				done <- result{err: ErrRuntimeLaunch}
				return
			}
			data = data[n:]
		}
		raw, e := l.reader.ReadSlice('\n')
		if e != nil || len(raw) > (1<<20)+1 {
			done <- result{err: ErrRuntimeLaunch}
			return
		}
		done <- result{raw: bytes.Clone(raw)}
	}()
	select {
	case <-callCtx.Done():
		l.revoked = true
		l.pipes.close()
		return nil, ErrRuntimeLaunch
	case v := <-done:
		if v.err != nil || ctx.Err() != nil || l.check() != nil {
			l.revoked = true
			return nil, ErrRuntimeLaunch
		}
		return task0RemoteDecodeReply(v.raw, id)
	}
}

func (l *task0DelegatedLocal) Probe(ctx context.Context, p modelgateway.ModelProfile, s modelgateway.SamplingProfile) (modelgateway.HarnessProbe, error) {
	var value modelgateway.HarnessProbe
	if l == nil {
		return value, ErrRuntimeLaunch
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := l.adapterExchange(ctx, p, s, modelgateway.AdapterMethodProbe, map[string]string{"profile_binding": p.BindingID(), "expected_model_id": p.ModelID, "harness_identity": p.Harness.BindingID(), "protocol_identity": p.Harness.ProtocolIdentity, "protocol_version": p.Harness.ProtocolVersion, "capability_fingerprint": p.Harness.CapabilityFingerprint})
	if err != nil || decodeFrozenJSON(raw, 4096, &value) != nil || value.HarnessIdentity != p.Harness.BindingID() || value.ObservedModelID != p.ModelID || value.ProtocolIdentity != p.Harness.ProtocolIdentity || value.ProtocolVersion != p.Harness.ProtocolVersion || value.CapabilityFingerprint != p.Harness.CapabilityFingerprint || !value.RouteAvailable || value.DirectProviderBypassAvailable {
		return modelgateway.HarnessProbe{}, ErrRuntimeLaunch
	}
	return value, nil
}

func (l *task0DelegatedLocal) Invoke(ctx context.Context, p modelgateway.ModelProfile, s modelgateway.SamplingProfile, r modelgateway.HarnessRequest) (modelgateway.HarnessResult, error) {
	var value modelgateway.HarnessResult
	if l == nil {
		return value, ErrRuntimeLaunch
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	raw, err := l.adapterExchange(ctx, p, s, modelgateway.AdapterMethodInvoke, r)
	if err != nil || decodeFrozenJSON(raw, 1<<20, &value) != nil {
		return value, ErrRuntimeLaunch
	}
	return value, nil
}

func (*task0DelegatedLocal) Recover(context.Context, modelgateway.ModelProfile, orchestrator.Session, orchestrator.RecoveryRequest) error {
	return ErrRuntimeLaunch
}
func (l *task0DelegatedLocal) Close(context.Context) error { return l.retire() }

func (l *task0DelegatedLocal) retire() error {
	if l == nil {
		return nil
	}
	l.retirement.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.revoked = true
		l.ready = false
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if l.process != nil {
			if l.control != nil {
				if _, err := l.exchangeControl(ctx, frozenControlRequest{Schema: frozenControlSchema, Operation: "STOP_ALL"}, time.Duration(l.grant.binding.Local.ShutdownTimeoutMS)*time.Millisecond); err != nil {
					l.retireErr = ErrRuntimeLaunch
				}
			}
			if l.process.retire() != nil {
				l.retireErr = ErrRuntimeLaunch
			}
		}
		if l.control != nil {
			l.control.Close()
		}
		if l.pipes != nil {
			l.pipes.close()
		}
		joined := l.process != nil && l.process.joinedByOwner()
		// CREATE may have succeeded even if its reply never supplied a usable
		// handle. Keep this partial LOCAL owner reachable until SETUP's actual
		// direct Wait. A failed protocol never emits an AFTER_RETIRE receipt.
		if l.createAttempted && !joined {
			l.retireErr = ErrRuntimeLaunch
			if l.owner.directJoinCompleted() {
				l.closeHeldInputs()
				return
			}
			task0RetainInputsUntilDirectJoin(l.owner.process, func() {
				l.mu.Lock()
				defer l.mu.Unlock()
				l.closeHeldInputs()
			})
			return
		}
		if joined && len(l.assets) > 0 {
			if _, err := CheckAndReleaseModelCache(ctx, "AFTER_RETIRE", 0, l.assets, l.record); err != nil {
				l.retireErr = ErrRuntimeLaunch
			}
		}
		l.closeHeldInputs()
	})
	return l.retireErr
}

// The caller holds l.mu. This closure supplies no successful cache receipt.
func (l *task0DelegatedLocal) closeHeldInputs() {
	for _, asset := range l.assets {
		if asset.File != nil {
			_ = asset.File.Close()
		}
	}
	l.assets = nil
	if l.helper != nil {
		_ = l.helper.Close()
		l.helper = nil
	}
}
