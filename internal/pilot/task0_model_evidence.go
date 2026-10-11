package pilot

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"syscall"

	"github.com/zyc14588/AIPT/internal/modelgateway"
	"github.com/zyc14588/AIPT/internal/orchestrator"
	"github.com/zyc14588/AIPT/internal/protocol"
)

// Body-bearing execution records stay under the held private budget root.
// They are staging input for Q011 encryption, never a PUBLIC export, public
// repository asset, worker authority or a substitute for the full Core RAW.
type task0ModelIntent struct {
	Schema       string                      `json:"schema"`
	AuthoritySHA string                      `json:"authority_sha256"`
	ManifestSHA  string                      `json:"manifest_sha256"`
	GrantSHA     string                      `json:"dispatch_grant_sha256"`
	Request      modelgateway.HarnessRequest `json:"request"`
}
type task0ModelTerminal struct {
	Schema       string                      `json:"schema"`
	AuthoritySHA string                      `json:"authority_sha256"`
	ManifestSHA  string                      `json:"manifest_sha256"`
	GrantSHA     string                      `json:"dispatch_grant_sha256"`
	RequestID    string                      `json:"request_id"`
	RequestSHA   string                      `json:"request_sha256"`
	Status       string                      `json:"status"`
	Result       *modelgateway.HarnessResult `json:"result"`
}

func task0ModelEvidenceNames(requestID string) (string, string, error) {
	if !runPattern.MatchString(requestID) {
		return "", "", ErrTask0
	}
	id := inputSHA([]byte(requestID))
	return "task0-model-" + id + ".request.json", "task0-model-" + id + ".result.json", nil
}

func task0PrivateCanonicalLine(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrTask0
	}
	c, err := protocol.CanonicalJSON(raw)
	if err != nil || len(c) < 2 || len(c) > 1<<20-1 {
		return nil, ErrTask0
	}
	return append([]byte(c), '\n'), nil
}

func task0ValidateModelEvidenceRequest(grant *acceptedTask0DispatchGrant, request modelgateway.HarnessRequest) bool {
	if grant == nil {
		return false
	}
	entry, ok := grant.profiles[request.ProfileBinding]
	if !ok {
		return false
	}
	p, s := entry.Profile, entry.Sampling
	if request.Schema != modelgateway.HarnessRequestSchema || request.ProtocolVersion != "1" || !runPattern.MatchString(request.RequestID) || request.ExpectedModelID != p.ModelID ||
		request.SamplingBinding != s.BindingID() || request.HarnessIdentity != p.Harness.BindingID() || request.BackendKind != p.BackendKind || request.ProviderIdentity != p.ProviderIdentity ||
		request.StructuredMode != p.StructuredOutputMode || request.ToolMode != p.ToolCallMode || !task0SameJSON(request.SamplingProfile, s) ||
		request.Session.Schema != orchestrator.SessionSchema || request.Session.Generation != 1 || request.Session.ParentSessionID != "" || request.Session.RunID != grant.manifest.Manifest.RunID || request.Session.SeatID != entry.Seat ||
		request.Invocation.Kind != orchestrator.InvocationOriginal || request.Invocation.Attempt != 1 || request.Invocation.InvocationID != request.RequestID || request.Invocation.SessionID != request.Session.SessionID ||
		request.Invocation.RunID != request.Session.RunID || request.Invocation.SeatID != entry.Seat || request.Invocation.Context.RunID != request.Session.RunID ||
		request.Invocation.Context.SessionID != request.Session.SessionID || request.Invocation.Context.SeatID != entry.Seat || orchestrator.ValidateContextHash(request.Invocation.Context) != nil {
		return false
	}
	if _, err := modelgateway.ValidateEgress(p, request.Invocation.Context); err != nil {
		return false
	}
	prepared, reduction, err := modelgateway.PrepareContext(request.Invocation.Context, p.ContextPolicy)
	if err != nil || len(prepared) > task0RoleContextCeiling(entry.Seat) || !bytes.Equal(prepared, request.PreparedContext) || !task0SameJSON(reduction, request.ContextReduction) {
		return false
	}
	want := request.RequestSHA256
	request.RequestSHA256 = ""
	raw, err := json.Marshal(request)
	return err == nil && len(raw) <= p.ContextPolicy.MaxRequestBytes && digest(want) && inputSHA(raw) == want
}

func task0CaptureModelIntent(budget *GlobalBudget, grant *acceptedTask0DispatchGrant, request modelgateway.HarnessRequest) error {
	if budget == nil || grant == nil || grant.manifest.Digest != budget.manifest.Digest || !task0ValidateModelEvidenceRequest(grant, request) {
		return ErrTask0
	}
	name, _, err := task0ModelEvidenceNames(request.RequestID)
	if err != nil {
		return err
	}
	body, err := task0PrivateCanonicalLine(task0ModelIntent{"aipt.private.b007-model-intent/v1", BudgetAuthority, hex.EncodeToString(budget.manifest.Digest[:]), grant.identity, request})
	if err != nil || persistTask0PrivateRecord(budget, name, body) != nil {
		return ErrTask0
	}
	return nil
}

func task0CaptureModelTerminal(budget *GlobalBudget, grant *acceptedTask0DispatchGrant, request modelgateway.HarnessRequest, result *modelgateway.HarnessResult) error {
	if budget == nil || grant == nil || grant.manifest.Digest != budget.manifest.Digest {
		return ErrTask0
	}
	_, name, err := task0ModelEvidenceNames(request.RequestID)
	if err != nil {
		return err
	}
	status := "FAILED_NO_RETRY"
	if result != nil {
		if len(result.RawResponse) < 1 || len(result.RawResponse) > 1024 || len(result.StructuredResponse) > 1024 || result.RequestID != request.RequestID || result.ResponseSHA256 != inputSHA(result.RawResponse) {
			return ErrTask0
		}
		status = "HARNESS_RESPONSE_RECEIVED"
	}
	body, err := task0PrivateCanonicalLine(task0ModelTerminal{"aipt.private.b007-model-terminal/v1", BudgetAuthority, hex.EncodeToString(budget.manifest.Digest[:]), grant.identity, request.RequestID, request.RequestSHA256, status, result})
	if err != nil || persistTask0PrivateRecord(budget, name, body) != nil {
		return ErrTask0
	}
	return nil
}

func task0SamePrivateRecordState(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Size == b.Size && a.Nlink == 1 && b.Nlink == 1 && a.Uid == b.Uid && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func task0ReadPrivateRecord(budget *GlobalBudget, name string) ([]byte, error) {
	if budget == nil || budget.checkRoot() != nil || !runPattern.MatchString(name) {
		return nil, ErrTask0
	}
	open := func() (*os.File, syscall.Stat_t, error) {
		fd, err := syscall.Openat(int(budget.root.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, syscall.Stat_t{}, ErrTask0
		}
		f := os.NewFile(uintptr(fd), "held private model execution evidence")
		var s syscall.Stat_t
		if f == nil || syscall.Fstat(fd, &s) != nil || s.Mode&syscall.S_IFMT != syscall.S_IFREG || s.Mode&0777 != 0400 || s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 || s.Size < 1 || s.Size > 1<<20 {
			if f != nil {
				f.Close()
			} else {
				syscall.Close(fd)
			}
			return nil, syscall.Stat_t{}, ErrTask0
		}
		return f, s, nil
	}
	f, before, err := open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.NewSectionReader(f, 0, before.Size+1))
	var after syscall.Stat_t
	if err != nil || int64(len(body)) != before.Size || syscall.Fstat(int(f.Fd()), &after) != nil || !task0SamePrivateRecordState(before, after) || budget.checkRoot() != nil {
		clear(body)
		return nil, ErrTask0
	}
	named, ns, err := open()
	if err != nil {
		clear(body)
		return nil, ErrTask0
	}
	named.Close()
	if !task0SamePrivateRecordState(before, ns) {
		clear(body)
		return nil, ErrTask0
	}
	return body, nil
}

func task0ReadModelEvidence(budget *GlobalBudget, grant *acceptedTask0DispatchGrant, requestID string) (task0ModelIntent, task0ModelTerminal, []byte, []byte, error) {
	fail := func() (task0ModelIntent, task0ModelTerminal, []byte, []byte, error) {
		return task0ModelIntent{}, task0ModelTerminal{}, nil, nil, ErrTask0
	}
	if budget == nil || grant == nil || grant.manifest.Digest != budget.manifest.Digest {
		return fail()
	}
	inName, outName, err := task0ModelEvidenceNames(requestID)
	if err != nil {
		return fail()
	}
	inRaw, err := task0ReadPrivateRecord(budget, inName)
	if err != nil {
		return fail()
	}
	outRaw, err := task0ReadPrivateRecord(budget, outName)
	if err != nil {
		clear(inRaw)
		return fail()
	}
	var intent task0ModelIntent
	var terminal task0ModelTerminal
	if decodeFrozenJSON(inRaw, 1<<20, &intent) != nil || decodeFrozenJSON(outRaw, 1<<20, &terminal) != nil ||
		intent.Schema != "aipt.private.b007-model-intent/v1" || terminal.Schema != "aipt.private.b007-model-terminal/v1" ||
		intent.AuthoritySHA != BudgetAuthority || terminal.AuthoritySHA != BudgetAuthority || intent.GrantSHA != grant.identity || terminal.GrantSHA != grant.identity ||
		intent.ManifestSHA != hex.EncodeToString(grant.manifest.Digest[:]) || terminal.ManifestSHA != intent.ManifestSHA ||
		intent.Request.RequestID != requestID || !task0ValidateModelEvidenceRequest(grant, intent.Request) || terminal.RequestID != requestID || terminal.RequestSHA != intent.Request.RequestSHA256 ||
		terminal.Status != "HARNESS_RESPONSE_RECEIVED" || terminal.Result == nil || terminal.Result.RequestID != requestID || terminal.Result.ResponseSHA256 != inputSHA(terminal.Result.RawResponse) ||
		len(terminal.Result.RawResponse) < 1 || len(terminal.Result.RawResponse) > 1024 || len(terminal.Result.StructuredResponse) > 1024 {
		clear(inRaw)
		clear(outRaw)
		return fail()
	}
	entry := grant.profiles[intent.Request.ProfileBinding]
	result := terminal.Result
	if result.Schema != modelgateway.HarnessResponseSchema || result.ProtocolVersion != "1" || result.HarnessIdentity != entry.Profile.Harness.BindingID() || result.ObservedModelID != entry.Profile.ModelID ||
		result.CapabilityFingerprint != entry.Profile.Harness.CapabilityFingerprint || result.RequestedSamplingSHA256 != entry.Sampling.SHA256 ||
		!task0SameJSON(result.UnsupportedSamplingParameters, entry.Sampling.UnsupportedParameters) || !task0ExactEffectiveSampling(entry.Sampling, result.EffectiveSampling) ||
		result.CompletedAt.IsZero() || result.RouteRecoveryOccurred || !digest(result.BackendSerializedRequestSHA256) {
		clear(inRaw)
		clear(outRaw)
		return fail()
	}
	canonicalIn, e1 := task0PrivateCanonicalLine(intent)
	canonicalOut, e2 := task0PrivateCanonicalLine(terminal)
	if e1 != nil || e2 != nil || !bytes.Equal(canonicalIn, inRaw) || !bytes.Equal(canonicalOut, outRaw) {
		clear(inRaw)
		clear(outRaw)
		return fail()
	}
	return intent, terminal, inRaw, outRaw, nil
}

// Compare the complete projection against the accepted sampling profile. The
// private terminal is evidence, so a valid body digest cannot authorize a
// different byte ceiling or enforcement identity recorded alongside it.
func task0ExactEffectiveSampling(s modelgateway.SamplingProfile, got modelgateway.EffectiveSamplingProjection) bool {
	want := modelgateway.EffectiveSamplingProjection{
		Schema: modelgateway.EffectiveSamplingSchema, EnforcementIdentity: modelgateway.SamplingEnforcementIdentity,
		AppliedParameters: s.AppliedParameters, UnsupportedParameters: s.UnsupportedParameters,
		MaxContextTokens: s.MaxContextTokens, MaxOutputTokens: s.MaxOutputTokens,
		ContextUTF8ByteCeiling: s.MaxContextTokens, OutputUTF8ByteCeiling: s.MaxOutputTokens,
	}
	return task0SameJSON(want, got)
}
