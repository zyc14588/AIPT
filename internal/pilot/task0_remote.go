package pilot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/testplan"
)

type task0RemoteRoleBinding struct {
	ProfileBinding string `json:"profile_binding"`
	HelperSHA      string `json:"helper_sha256"`
	ManifestSHA    string `json:"runtime_manifest_sha256"`
}

type task0RemoteBinding struct {
	Schema       string                    `json:"schema"`
	AuthoritySHA string                    `json:"authority_sha256"`
	DispatchSHA  string                    `json:"dispatch_binding_sha256"`
	ManifestSHA  string                    `json:"frozen_manifest_sha256"`
	ReviewSHA    string                    `json:"full_independent_review_sha256"`
	CIReceiptSHA string                    `json:"immutable_online_ci_receipt_sha256"`
	Source       testplan.RepositorySource `json:"accepted_implementation"`
	Roles        []task0RemoteRoleBinding  `json:"role_helpers"`
}

type task0FrozenRemoteRoute struct {
	helper   *os.File
	manifest string
	profile  task0DispatchProfile
	owned    *task0OwnedRemoteHelper
	serial   uint64
}

// The only production constructor requires the exact private preparation
// binding and five externally accepted sealed role helpers. It never exposes
// a host adapter, arbitrary CredentialBroker, provider endpoint or CLI route.
type task0FrozenRemoteTransport struct {
	mu       sync.Mutex
	lifetime context.Context
	grant    *acceptedTask0DispatchGrant
	routes   map[string]*task0FrozenRemoteRoute
	closed   bool
	setup    *task0SetupClient
}

func newTask0DelegatedRemoteTransport(ctx context.Context, owner *task0SetupClient, raw []byte, expectedSHA string, grant *acceptedTask0DispatchGrant, helpers map[string]*os.File) (*task0FrozenRemoteTransport, error) {
	if owner == nil || !owner.live() || owner.grant == nil || grant == nil || owner.grant.dispatch.identity != grant.identity {
		return nil, ErrRuntimeLaunch
	}
	t, err := newTask0FrozenRemoteTransport(ctx, raw, expectedSHA, grant, helpers)
	if err != nil {
		return nil, err
	}
	t.setup = owner
	return t, nil
}

func newTask0FrozenRemoteTransport(ctx context.Context, raw []byte, expectedSHA string, grant *acceptedTask0DispatchGrant, helpers map[string]*os.File) (*task0FrozenRemoteTransport, error) {
	var b task0RemoteBinding
	if ctx == nil || ctx.Err() != nil || grant == nil || !digest(grant.identity) || !digest(expectedSHA) || inputSHA(raw) != expectedSHA ||
		decodeFrozenJSON(raw, 1<<20, &b) != nil || b.Schema != "aipt.private.b007-task0-accepted-remote-launch/v1" ||
		b.AuthoritySHA != BudgetAuthority || b.DispatchSHA != grant.identity || b.ManifestSHA != grant.binding.ManifestSHA ||
		b.ReviewSHA != grant.binding.FullReviewSHA || b.CIReceiptSHA != grant.binding.OnlineCIReceiptSHA || b.Source != grant.binding.Implementation ||
		len(b.Roles) != 5 || len(helpers) != 5 || os.Getpid() != 1 || os.Geteuid() != 0 ||
		!namespaceIsNotHost("user") || !namespaceIsNotHost("pid") || !namespaceIsNotHost("mnt") {
		return nil, ErrRuntimeLaunch
	}
	t := &task0FrozenRemoteTransport{grant: grant, lifetime: ctx, routes: map[string]*task0FrozenRemoteRoute{}}
	fail := func() (*task0FrozenRemoteTransport, error) {
		_ = t.Close(context.Background())
		return nil, ErrRuntimeLaunch
	}
	for _, role := range b.Roles {
		entry, exists := grant.profiles[role.ProfileBinding]
		f := helpers[role.ProfileBinding]
		if !exists || entry.Profile.BackendKind != modelgateway.BackendRemoteDeepSeek || f == nil || t.routes[role.ProfileBinding] != nil || !digest(role.HelperSHA) || !digest(role.ManifestSHA) {
			return fail()
		}
		info, err := f.Stat()
		if err != nil || info.Size() < 64 || info.Size() > 4<<30 {
			return fail()
		}
		held, err := frozenSealedFile(int(f.Fd()), role.HelperSHA, info.Size())
		if err != nil {
			return fail()
		}
		c, err := OpenEmbeddedCodeCapsule(held, role.ManifestSHA)
		if err != nil {
			held.Close()
			return fail()
		}
		policy, policyErr := frozenTask0RemotePolicy(c)
		c.Close()
		if policyErr != nil || !task0SameJSON(entry.Profile, policy.Profile) || !task0SameJSON(entry.Sampling, policy.Sampling) {
			held.Close()
			return fail()
		}
		t.routes[role.ProfileBinding] = &task0FrozenRemoteRoute{helper: held, manifest: role.ManifestSHA, profile: entry}
	}
	return t, nil
}

func (t *task0FrozenRemoteTransport) route(p modelgateway.ModelProfile, s modelgateway.SamplingProfile) (*task0FrozenRemoteRoute, error) {
	if t == nil || t.closed || t.grant == nil || t.lifetime == nil || t.lifetime.Err() != nil {
		return nil, ErrRuntimeLaunch
	}
	r := t.routes[p.BindingID()]
	if r == nil || !task0SameJSON(r.profile.Profile, p) || !task0SameJSON(r.profile.Sampling, s) {
		return nil, ErrRuntimeLaunch
	}
	return r, nil
}

type task0RemoteAdapterReply struct {
	JSONRPC         string          `json:"jsonrpc"`
	ID              string          `json:"id"`
	ProtocolVersion string          `json:"protocol_version"`
	Result          json.RawMessage `json:"result,omitempty"`
	Error           *struct {
		Code string `json:"code"`
	} `json:"error,omitempty"`
}

func task0RemoteDecodeReply(raw []byte, id string) (json.RawMessage, error) {
	var r task0RemoteAdapterReply
	if decodeFrozenJSON(bytes.TrimSuffix(raw, []byte{'\n'}), 1<<20, &r) != nil || r.JSONRPC != "2.0" || r.ID != id || r.ProtocolVersion != "1" ||
		r.Error != nil || len(r.Result) < 2 || bytes.Equal(r.Result, []byte("null")) {
		return nil, ErrRuntimeLaunch
	}
	return r.Result, nil
}

func (t *task0FrozenRemoteTransport) exchange(ctx context.Context, r *task0FrozenRemoteRoute, method string, params any) (json.RawMessage, error) {
	if ctx == nil || ctx.Err() != nil || r == nil || r.helper == nil || t.closed {
		return nil, ErrRuntimeLaunch
	}
	if r.owned == nil {
		// Accepted production never falls back to cloning from Cap0 PREP.
		if t.setup == nil {
			return nil, ErrRuntimeLaunch
		}
		owned, err := launchTask0DelegatedRemote(t.lifetime, t.setup, r.helper, r.manifest, r.profile)
		if err != nil {
			t.closed = true
			return nil, ErrRuntimeLaunch
		}
		r.owned = owned
	}
	if r.owned.check() != nil {
		t.closed = true
		r.owned.retire()
		return nil, ErrRuntimeLaunch
	}
	r.serial++
	id := fmt.Sprintf("b007-owned-remote-%d", r.serial)
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
			n, e := r.owned.input.Write(data)
			if e != nil || n < 1 || n > len(data) {
				done <- result{err: ErrRuntimeLaunch}
				return
			}
			data = data[n:]
		}
		raw, e := r.owned.reader.ReadSlice('\n')
		if e != nil || len(raw) > (1<<20)+1 {
			done <- result{err: ErrRuntimeLaunch}
			return
		}
		done <- result{raw: bytes.Clone(raw)}
	}()
	select {
	case <-callCtx.Done():
		t.closed = true
		r.owned.retire()
		return nil, ErrRuntimeLaunch
	case v := <-done:
		if v.err != nil || ctx.Err() != nil || r.owned.check() != nil {
			t.closed = true
			r.owned.retire()
			return nil, ErrRuntimeLaunch
		}
		decoded, e := task0RemoteDecodeReply(v.raw, id)
		if e != nil {
			t.closed = true
			r.owned.retire()
			return nil, ErrRuntimeLaunch
		}
		return decoded, nil
	}
}

func (t *task0FrozenRemoteTransport) Probe(ctx context.Context, p modelgateway.ModelProfile, s modelgateway.SamplingProfile) (modelgateway.HarnessProbe, error) {
	var probe modelgateway.HarnessProbe
	if t == nil {
		return probe, ErrRuntimeLaunch
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	r, err := t.route(p, s)
	if err != nil {
		return probe, err
	}
	raw, err := t.exchange(ctx, r, modelgateway.AdapterMethodProbe, map[string]string{"profile_binding": p.BindingID(), "expected_model_id": p.ModelID, "harness_identity": p.Harness.BindingID(), "protocol_identity": p.Harness.ProtocolIdentity, "protocol_version": p.Harness.ProtocolVersion, "capability_fingerprint": p.Harness.CapabilityFingerprint})
	if err != nil || decodeFrozenJSON(raw, 4096, &probe) != nil || probe.HarnessIdentity != p.Harness.BindingID() || probe.ObservedModelID != p.ModelID || probe.ProtocolIdentity != p.Harness.ProtocolIdentity || probe.ProtocolVersion != p.Harness.ProtocolVersion || probe.CapabilityFingerprint != p.Harness.CapabilityFingerprint || !probe.RouteAvailable || probe.DirectProviderBypassAvailable {
		return modelgateway.HarnessProbe{}, ErrRuntimeLaunch
	}
	return probe, nil
}

func (t *task0FrozenRemoteTransport) Invoke(ctx context.Context, p modelgateway.ModelProfile, s modelgateway.SamplingProfile, req modelgateway.HarnessRequest) (modelgateway.HarnessResult, error) {
	var value modelgateway.HarnessResult
	if t == nil {
		return value, ErrRuntimeLaunch
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	r, err := t.route(p, s)
	if err != nil || req.Schema != modelgateway.HarnessRequestSchema || req.ProfileBinding != p.BindingID() || req.SamplingBinding != s.BindingID() || req.ExpectedModelID != p.ModelID || req.HarnessIdentity != p.Harness.BindingID() || req.BackendKind != modelgateway.BackendRemoteDeepSeek || !task0SameJSON(req.SamplingProfile, s) {
		return value, ErrRuntimeLaunch
	}
	raw, err := t.exchange(ctx, r, modelgateway.AdapterMethodInvoke, req)
	if err != nil || decodeFrozenJSON(raw, 1<<20, &value) != nil {
		return modelgateway.HarnessResult{}, ErrRuntimeLaunch
	}
	return value, nil
}

func (*task0FrozenRemoteTransport) Recover(context.Context, modelgateway.ModelProfile, orchestrator.Session, orchestrator.RecoveryRequest) error {
	return ErrRuntimeLaunch
}

func (t *task0FrozenRemoteTransport) Close(context.Context) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	var failure error
	for _, r := range t.routes {
		if r.owned != nil {
			if r.owned.retire() != nil {
				failure = ErrRuntimeLaunch
			}
		}
		if r.helper != nil {
			if r.helper.Close() != nil {
				failure = ErrRuntimeLaunch
			}
			r.helper = nil
		}
	}
	return failure
}

type task0OwnedRemoteHelper struct {
	process    *freshPreparationProcess
	delegated  *task0DelegatedProcess
	helper     *os.File
	input      io.WriteCloser
	output     io.ReadCloser
	reader     *bufio.Reader
	retirement sync.Once
	retireErr  error
}

func (p *task0OwnedRemoteHelper) check() error {
	if p == nil || p.helper == nil {
		return ErrRuntimeLaunch
	}
	if p.delegated != nil {
		info, err := p.helper.Stat()
		if err != nil {
			return ErrRuntimeLaunch
		}
		return p.delegated.check(info)
	}
	if p.process == nil {
		return ErrRuntimeLaunch
	}
	select {
	case <-p.process.exit:
		return ErrRuntimeLaunch
	default:
	}
	if verifiedPreparationChild(p.process.command, p.helper) != nil || verifyZeroCapabilityThreads(p.process.command.Process.Pid) != nil {
		return ErrRuntimeLaunch
	}
	return nil
}

func (p *task0OwnedRemoteHelper) retire() error {
	if p == nil {
		return nil
	}
	p.retirement.Do(func() {
		if p.input != nil {
			_ = p.input.Close()
		}
		if p.output != nil {
			_ = p.output.Close()
		}
		if p.process != nil {
			p.retireErr = p.process.retire()
		}
		if p.delegated != nil {
			p.retireErr = p.delegated.retire()
		}
		if p.helper != nil {
			_ = p.helper.Close()
		}
	})
	return p.retireErr
}
