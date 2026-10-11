package pilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zyc14588/AIPT/internal/protocol"
)

var ErrNativeInputProof = errors.New("B007 authenticated final native input proof rejected")

// Counter proof contains only identities, digests and counters; no prompt,
// response text, credential or locator is serializable through this type.
type NativeInputReceipt struct {
	Schema         string `json:"schema"`
	Sequence       int    `json:"sequence"`
	PreviousSHA256 string `json:"previous_sha256"`
	Event          string `json:"event"`
	ClosureSHA256  string `json:"closure_sha256"`
	NativeSHA256   string `json:"native_sha256"`
	RequestSHA256  string `json:"request_sha256"`
	RequestBytes   int    `json:"request_bytes"`
	InputTokens    int    `json:"input_tokens"`
	OutputTokens   int    `json:"output_tokens"`
	ResponseSHA256 string `json:"response_sha256"`
}

type nativeCountProxy struct {
	mu                                  sync.Mutex
	nativeOrigin, closureSHA, nativeSHA string
	client                              *http.Client
	proof                               io.Writer
	sequence, attempts                  int
	previous                            string
	poisoned                            bool
	lifetime                            context.Context
	cancel                              context.CancelFunc
}

// Only the fixed helper calls this after binding the native executable,
// template, private network namespace, launch arguments and readiness. Digests
// supplied to this constructor do not themselves prove source authenticity.
// Its HTTP client makes no redirect or idempotent POST retry and sees only the
// already-authenticated native listener in that same private namespace.
func newNativeCountProxy(port int, closureSHA, nativeSHA string, proof io.Writer) (*nativeCountProxy, error) {
	if port < 1 || port > 65535 || !digest(closureSHA) || !digest(nativeSHA) || proof == nil {
		return nil, ErrNativeInputProof
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16384, ResponseHeaderTimeout: 30 * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	lifetime, cancel := context.WithCancel(context.Background())
	return &nativeCountProxy{nativeOrigin: "http://127.0.0.1:" + strconv.Itoa(port), closureSHA: closureSHA, nativeSHA: nativeSHA, client: client, proof: proof, previous: strings.Repeat("0", 64), lifetime: lifetime, cancel: cancel}, nil
}

func exactJSONObject(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, ErrNativeInputProof
	}
	if _, e := protocol.CanonicalJSON(raw); e != nil {
		return nil, ErrNativeInputProof
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, ErrNativeInputProof
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return nil, ErrNativeInputProof
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, ErrNativeInputProof
		}
	}
	return m, nil
}

func finalNativeRequest(raw []byte) error {
	if len(raw) == 0 || len(raw) > 8192 || !utf8.Valid(raw) {
		return ErrNativeInputProof
	}
	m, e := exactJSONObject(raw, []string{"model", "messages", "stream", "stream_options", "thinking", "max_tokens"}, []string{"temperature", "stop"})
	if e != nil {
		return e
	}
	var model string
	var maximum int
	var stream bool
	if json.Unmarshal(m["model"], &model) != nil || model != "gguf-04" || json.Unmarshal(m["max_tokens"], &maximum) != nil || maximum != 1024 || json.Unmarshal(m["stream"], &stream) != nil || !stream {
		return ErrNativeInputProof
	}
	options, e := exactJSONObject(m["stream_options"], []string{"include_usage"}, nil)
	if e != nil || !bytes.Equal(options["include_usage"], []byte("true")) {
		return ErrNativeInputProof
	}
	thinking, e := exactJSONObject(m["thinking"], []string{"type"}, nil)
	if e != nil || !bytes.Equal(thinking["type"], []byte(`"disabled"`)) {
		return ErrNativeInputProof
	}
	var messages []json.RawMessage
	if json.Unmarshal(m["messages"], &messages) != nil || len(messages) == 0 || len(messages) > 8192 {
		return ErrNativeInputProof
	}
	for _, rawMessage := range messages {
		message, e := exactJSONObject(rawMessage, []string{"role", "content"}, nil)
		if e != nil {
			return e
		}
		var role, content string
		if json.Unmarshal(message["role"], &role) != nil || (role != "system" && role != "user" && role != "assistant") || json.Unmarshal(message["content"], &content) != nil || bytes.Equal(message["content"], []byte("null")) {
			return ErrNativeInputProof
		}
	}
	if rawT, ok := m["temperature"]; ok {
		var t float64
		if json.Unmarshal(rawT, &t) != nil || bytes.Equal(rawT, []byte("null")) || math.IsNaN(t) || math.IsInf(t, 0) || t < 0 || t > 2 {
			return ErrNativeInputProof
		}
	}
	if stop, ok := m["stop"]; ok {
		if bytes.Equal(stop, []byte("null")) {
			return ErrNativeInputProof
		}
		var s string
		if json.Unmarshal(stop, &s) != nil {
			var all []json.RawMessage
			if json.Unmarshal(stop, &all) != nil || len(all) > 16 {
				return ErrNativeInputProof
			}
			for _, v := range all {
				if json.Unmarshal(v, &s) != nil || bytes.Equal(v, []byte("null")) {
					return ErrNativeInputProof
				}
			}
		}
	}
	return nil
}

func (p *nativeCountProxy) appendProof(event string, raw []byte, input, output int, response []byte) error {
	r := NativeInputReceipt{Schema: "aipt.private.b007-final-native-input-proof/v1", Sequence: p.sequence + 1, PreviousSHA256: p.previous, Event: event, ClosureSHA256: p.closureSHA, NativeSHA256: p.nativeSHA, RequestSHA256: inputSHA(raw), RequestBytes: len(raw), InputTokens: input, OutputTokens: output, ResponseSHA256: inputSHA(response)}
	b, e := json.Marshal(r)
	if e != nil {
		p.poisoned = true
		return ErrNativeInputProof
	}
	b = append(b, '\n')
	if n, e := p.proof.Write(b); e != nil || n != len(b) {
		p.poisoned = true
		return ErrNativeInputProof
	}
	p.sequence++
	p.previous = inputSHA(b)
	return nil
}

func (p *nativeCountProxy) nativePOST(ctx context.Context, route string, raw []byte) (*http.Response, error) {
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, p.nativeOrigin+route, bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	request.Header.Set("Content-Type", "application/json")
	return p.client.Do(request)
}

func nativeCountResponse(raw []byte) (int, error) {
	m, e := exactJSONObject(raw, []string{"input_tokens", "object"}, nil)
	if e != nil {
		return 0, e
	}
	var n int
	var object string
	if json.Unmarshal(m["input_tokens"], &n) != nil || n <= 0 || json.Unmarshal(m["object"], &object) != nil || object != "response.input_tokens" {
		return 0, ErrNativeInputProof
	}
	return n, nil
}

func nativeStreamUsage(raw []byte, input int) (int, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) {
		return 0, ErrNativeInputProof
	}
	usageFound, done := false, false
	output := 0
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 || bytes.HasPrefix(line, []byte(":")) {
			continue
		}
		if !bytes.HasPrefix(line, []byte("data: ")) || done {
			return 0, ErrNativeInputProof
		}
		data := line[6:]
		if bytes.Equal(data, []byte("[DONE]")) {
			done = true
			continue
		}
		if usageFound {
			return 0, ErrNativeInputProof
		}
		if _, e := protocol.CanonicalJSON(data); e != nil {
			return 0, ErrNativeInputProof
		}
		var frame map[string]json.RawMessage
		if json.Unmarshal(data, &frame) != nil || frame == nil {
			return 0, ErrNativeInputProof
		}
		if _, ok := frame["error"]; ok {
			return 0, ErrNativeInputProof
		}
		usage, ok := frame["usage"]
		if !ok || bytes.Equal(usage, []byte("null")) {
			continue
		}
		if usageFound {
			return 0, ErrNativeInputProof
		}
		m, e := exactJSONObject(usage, []string{"prompt_tokens", "completion_tokens", "total_tokens"}, []string{"prompt_tokens_details", "completion_tokens_details"})
		if e != nil {
			return 0, e
		}
		var prompt, total int
		for _, key := range []string{"prompt_tokens", "completion_tokens", "total_tokens"} {
			if bytes.Equal(bytes.TrimSpace(m[key]), []byte("null")) {
				return 0, ErrNativeInputProof
			}
		}
		if json.Unmarshal(m["prompt_tokens"], &prompt) != nil || prompt != input || json.Unmarshal(m["completion_tokens"], &output) != nil || output < 0 || output > 1024 || json.Unmarshal(m["total_tokens"], &total) != nil || total != prompt+output {
			return 0, ErrNativeInputProof
		}
		if details, ok := m["completion_tokens_details"]; ok && !bytes.Equal(details, []byte("null")) {
			var d map[string]json.RawMessage
			if json.Unmarshal(details, &d) != nil {
				return 0, ErrNativeInputProof
			}
			if r, ok := d["reasoning_tokens"]; ok {
				var n int
				if bytes.Equal(bytes.TrimSpace(r), []byte("null")) || json.Unmarshal(r, &n) != nil || n != 0 {
					return 0, ErrNativeInputProof
				}
			}
		}
		usageFound = true
	}
	if !done || !usageFound {
		return 0, ErrNativeInputProof
	}
	return output, nil
}

func (p *nativeCountProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	fail := func(status int) {
		// A rejected partial upload must not be drained without a deadline by
		// net/http after this handler returns, even before hooks are registered.
		_ = controller.SetReadDeadline(time.Now())
		if r.Body != nil {
			_ = r.Body.Close()
		}
		http.Error(w, "B007 final native input proof rejected", status)
	}
	if p.lifetime.Err() != nil {
		fail(http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/chat/completions" && r.URL.Path != "/v1/chat/completions") || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.Fragment != "" || r.ContentLength > 8192 {
		fail(http.StatusBadRequest)
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		fail(http.StatusBadRequest)
		return
	}
	// Body.Read and Close may run concurrently by the HTTP request contract.
	// Do not hold the dispatch lock while waiting for an upload. Retirement
	// cancels this reader before it waits for an owned native dispatch.
	bodyContext, cancelBody := context.WithTimeout(p.lifetime, 30*time.Second)
	defer cancelBody()
	// Initialize before registering any cancellation callback. A cancelled
	// upload must never have its expired deadline moved into the future.
	_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	stopRequestCancel := context.AfterFunc(r.Context(), cancelBody)
	defer stopRequestCancel()
	bodyCallbackDone := make(chan struct{})
	stopBodyClose := context.AfterFunc(bodyContext, func() {
		defer close(bodyCallbackDone)
		// A server request body can be waiting inside a socket read while its
		// Close waits for that read's lock. Wake the socket read first.
		_ = controller.SetReadDeadline(time.Now())
		_ = r.Body.Close()
	})
	var joinBodyOnce sync.Once
	joinBodyCallback := func() {
		joinBodyOnce.Do(func() {
			// stop(false) does not wait for a started callback. Every return
			// must join it before the ResponseController leaves handler scope.
			if !stopBodyClose() {
				<-bodyCallbackDone
			}
		})
	}
	defer joinBodyCallback()
	if bodyContext.Err() != nil || r.Context().Err() != nil {
		fail(http.StatusForbidden)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 8193))
	// Keep the read deadline in force for a truncated body. Clearing it here
	// could let the HTTP server's later body cleanup drain block again.
	if e != nil || finalNativeRequest(raw) != nil {
		fail(http.StatusBadRequest)
		return
	}
	// A valid bounded request reached the actual body EOF. Stop the upload
	// cancellation callback before restoring the socket read deadline, so the
	// HTTP server's background disconnect reader does not cancel a legitimate
	// longer generation. If the callback already fired, keep its deadline and
	// reject this upload; never race an active callback by clearing it.
	joinBodyCallback()
	if bodyContext.Err() != nil || r.Context().Err() != nil {
		fail(http.StatusForbidden)
		return
	}
	stopRequestCancel()
	cancelBody()
	_ = controller.SetReadDeadline(time.Time{})
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.poisoned || p.lifetime.Err() != nil || r.Context().Err() != nil || p.attempts >= MaxLocalCalls {
		fail(http.StatusForbidden)
		return
	}
	p.attempts++ // consumed even if counting, generation or evidence later fails
	if p.appendProof("COUNT_REQUEST_INTENT", raw, 0, 0, nil) != nil {
		fail(http.StatusInternalServerError)
		return
	}
	countContext, cancel := context.WithTimeout(p.lifetime, 30*time.Second)
	stopCancel := context.AfterFunc(r.Context(), cancel)
	defer stopCancel()
	if r.Context().Err() != nil {
		cancel()
		fail(http.StatusBadGateway)
		return
	}
	count, e := p.nativePOST(countContext, "/v1/chat/completions/input_tokens", raw)
	if e != nil {
		cancel()
		fail(http.StatusBadGateway)
		return
	}
	body, e := io.ReadAll(io.LimitReader(count.Body, 16385))
	count.Body.Close()
	cancel()
	tokens, countError := nativeCountResponse(body)
	if e != nil || len(body) > 16384 || count.StatusCode != http.StatusOK || countError != nil {
		fail(http.StatusBadGateway)
		return
	}
	if tokens > 8192 {
		_ = p.appendProof("COUNT_OVER_LIMIT_NO_GENERATION", raw, tokens, 0, nil)
		fail(http.StatusRequestEntityTooLarge)
		return
	}
	if p.appendProof("COUNT_PASS_GENERATION_INTENT", raw, tokens, 0, nil) != nil {
		fail(http.StatusInternalServerError)
		return
	}
	generationContext, cancel := context.WithTimeout(p.lifetime, 120*time.Second)
	defer cancel()
	stopGenerationCancel := context.AfterFunc(r.Context(), cancel)
	defer stopGenerationCancel()
	if r.Context().Err() != nil {
		cancel()
		fail(http.StatusBadGateway)
		return
	}
	generation, e := p.nativePOST(generationContext, "/v1/chat/completions", raw)
	if e != nil {
		fail(http.StatusBadGateway)
		return
	}
	defer generation.Body.Close()
	response, e := io.ReadAll(io.LimitReader(generation.Body, (1<<20)+1))
	media, _, mediaError := mime.ParseMediaType(generation.Header.Get("Content-Type"))
	output, usageError := nativeStreamUsage(response, tokens)
	if e != nil || len(response) > 1<<20 || generation.StatusCode != http.StatusOK || mediaError != nil || media != "text/event-stream" || usageError != nil {
		fail(http.StatusBadGateway)
		return
	}
	if p.appendProof("GENERATION_COMPLETED_WITH_BOUNDED_USAGE", raw, tokens, output, response) != nil {
		fail(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if _, e = w.Write(response); e != nil {
		p.poisoned = true
	}
}

func (p *nativeCountProxy) Close() {
	p.cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.poisoned = true
	p.client.CloseIdleConnections()
}

var _ http.Handler = (*nativeCountProxy)(nil)
