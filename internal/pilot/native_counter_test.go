package pilot

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const nonCanonFinalBody = `{"model":"gguf-04","messages":[{"role":"user","content":"NON_CANON_PRIVATE_COUNTER_TEST_TEXT"}],"stream":true,"stream_options":{"include_usage":true},"thinking":{"type":"disabled"},"max_tokens":1024}`

func nonCanonSSE(input, output int) string {
	return fmt.Sprintf("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":%d,\"completion_tokens\":%d,\"total_tokens\":%d}}\n\ndata: [DONE]\n\n", input, output, input+output)
}

func nonCanonCounter(t *testing.T, fn http.HandlerFunc, proof io.Writer) (*nativeCountProxy, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	counts, generations := &atomic.Int32{}, &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions/input_tokens" {
			counts.Add(1)
		} else if r.URL.Path == "/v1/chat/completions" {
			generations.Add(1)
		} else {
			t.Error("unregistered fixture route", r.URL.Path)
		}
		fn(w, r)
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	proxy, e := newNativeCountProxy(port, inputSHA([]byte("NON_CANON_NO_CLOSURE_ACCEPTANCE")), inputSHA([]byte("NON_CANON_NO_NATIVE_ACCEPTANCE")), proof)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(proxy.Close)
	return proxy, counts, generations
}

func nonCanonProxyRequest(p *nativeCountProxy, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	p.ServeHTTP(out, req)
	return out
}

func TestNativeCounterUsesExactFinalBodyForCountAndGeneration(t *testing.T) {
	var proof bytes.Buffer
	p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
		body, e := io.ReadAll(r.Body)
		if e != nil || string(body) != nonCanonFinalBody {
			t.Error("final body changed between count and generation", e)
		}
		if r.Method != http.MethodPost {
			t.Error("unexpected counter method")
		}
		if r.URL.Path == "/v1/chat/completions/input_tokens" {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"input_tokens":37,"object":"response.input_tokens"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, nonCanonSSE(37, 3))
	}, &proof)
	out := nonCanonProxyRequest(p, nonCanonFinalBody)
	if out.Code != 200 || counts.Load() != 1 || generations.Load() != 1 || out.Body.String() != nonCanonSSE(37, 3) {
		t.Fatal("bounded fixture dispatch failed", out.Code, counts.Load(), generations.Load())
	}
	if bytes.Contains(proof.Bytes(), []byte("NON_CANON_PRIVATE_COUNTER_TEST_TEXT")) {
		t.Fatal("proof exported private request text")
	}
	previous := strings.Repeat("0", 64)
	events := []string{}
	for i, line := range bytes.Split(bytes.TrimSpace(proof.Bytes()), []byte("\n")) {
		var r NativeInputReceipt
		if e := json.Unmarshal(line, &r); e != nil {
			t.Fatal(e)
		}
		if r.Sequence != i+1 || r.PreviousSHA256 != previous || r.RequestSHA256 != inputSHA([]byte(nonCanonFinalBody)) || r.RequestBytes != len(nonCanonFinalBody) {
			t.Fatal("counter proof binding lost")
		}
		previous = inputSHA(append(bytes.Clone(line), '\n'))
		events = append(events, r.Event)
	}
	if strings.Join(events, ",") != "COUNT_REQUEST_INTENT,COUNT_PASS_GENERATION_INTENT,GENERATION_COMPLETED_WITH_BOUNDED_USAGE" {
		t.Fatal("missing proof stages", events)
	}
}

func TestNativeCounterRejectsInputBeforeAnyNativeSend(t *testing.T) {
	for _, kind := range []string{"unknown_field", "case_alias", "duplicate_model", "tools", "wrong_model", "output_cap", "thinking_on", "stream_false", "missing_usage", "message_tool", "message_null", "temperature_null", "stop_null", "stop_type", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			body := nonCanonFinalBody
			switch kind {
			case "unknown_field":
				body = strings.Replace(body, `"model":`, `"unused":true,"model":`, 1)
			case "case_alias":
				body = strings.Replace(body, `"model":`, `"MODEL":`, 1)
			case "duplicate_model":
				body = strings.Replace(body, `"model":`, `"model":"other","model":`, 1)
			case "tools":
				body = strings.Replace(body, `"model":`, `"tools":[],"model":`, 1)
			case "wrong_model":
				body = strings.Replace(body, "gguf-04", "other", 1)
			case "output_cap":
				body = strings.Replace(body, "1024", "1025", 1)
			case "thinking_on":
				body = strings.Replace(body, "disabled", "enabled", 1)
			case "stream_false":
				body = strings.Replace(body, `"stream":true`, `"stream":false`, 1)
			case "missing_usage":
				body = strings.Replace(body, `"include_usage":true`, `"include_usage":false`, 1)
			case "message_tool":
				body = strings.Replace(body, `"role":"user"`, `"role":"tool"`, 1)
			case "message_null":
				body = strings.Replace(body, `"content":"NON_CANON_PRIVATE_COUNTER_TEST_TEXT"`, `"content":null`, 1)
			case "temperature_null":
				body = strings.Replace(body, `"model":`, `"temperature":null,"model":`, 1)
			case "stop_null":
				body = strings.Replace(body, `"model":`, `"stop":null,"model":`, 1)
			case "stop_type":
				body = strings.Replace(body, `"model":`, `"stop":[null],"model":`, 1)
			case "oversize":
				body = strings.Replace(body, "NON_CANON_PRIVATE_COUNTER_TEST_TEXT", strings.Repeat("x", 8193), 1)
			}
			var proof bytes.Buffer
			p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
				t.Error("unsafe request reached simulated native endpoint")
			}, &proof)
			out := nonCanonProxyRequest(p, body)
			if out.Code != 400 || counts.Load() != 0 || generations.Load() != 0 {
				t.Fatal("unsafe input dispatch admitted", out.Code)
			}
		})
	}
}

func TestNativeCounterCannotGenerateAfterUnprovenCount(t *testing.T) {
	for _, kind := range []string{"over_limit", "negative", "zero", "case_alias", "duplicate", "wrong_object", "unknown_field", "wrong_status", "oversize_response", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			var proof bytes.Buffer
			p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/chat/completions/input_tokens" {
					t.Error("generation sent after invalid count")
				}
				body := `{"input_tokens":37,"object":"response.input_tokens"}`
				switch kind {
				case "over_limit":
					body = strings.Replace(body, "37", "8193", 1)
				case "negative":
					body = strings.Replace(body, "37", "-1", 1)
				case "zero":
					body = strings.Replace(body, "37", "0", 1)
				case "case_alias":
					body = strings.Replace(body, "input_tokens", "INPUT_TOKENS", 1)
				case "duplicate":
					body = strings.Replace(body, `"input_tokens":`, `"input_tokens":10000,"input_tokens":`, 1)
				case "wrong_object":
					body = strings.Replace(body, "response.input_tokens", "response.other", 1)
				case "unknown_field":
					body = strings.Replace(body, `"input_tokens":`, `"unaccepted":0,"input_tokens":`, 1)
				case "wrong_status":
					w.WriteHeader(500)
				case "oversize_response":
					body = strings.Repeat(" ", 16385) + body
				case "redirect":
					w.Header().Set("Location", "/v1/chat/completions")
					w.WriteHeader(307)
					return
				}
				io.WriteString(w, body)
			}, &proof)
			out := nonCanonProxyRequest(p, nonCanonFinalBody)
			if out.Code == 200 || counts.Load() != 1 || generations.Load() != 0 {
				t.Fatal("invalid native count authorized generation", out.Code, counts.Load(), generations.Load())
			}
		})
	}
}

type nonCanonFailProof struct{ writes, failAt int }

func (w *nonCanonFailProof) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errors.New("NON_CANON_PROOF_WRITE_FAILURE")
	}
	return len(p), nil
}

func TestNativeCounterEvidenceFailureCannotExposeGenerationResult(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			proof := &nonCanonFailProof{failAt: failAt}
			p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/chat/completions/input_tokens" {
					io.WriteString(w, `{"input_tokens":37,"object":"response.input_tokens"}`)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, nonCanonSSE(37, 3))
			}, proof)
			out := nonCanonProxyRequest(p, nonCanonFinalBody)
			if out.Code != 500 || !p.poisoned {
				t.Fatal("evidence failure did not revoke dispatch", out.Code)
			}
			expectedCounts, expectedGenerations := int32(0), int32(0)
			if failAt >= 2 {
				expectedCounts = 1
			}
			if failAt == 3 {
				expectedGenerations = 1
			}
			if counts.Load() != expectedCounts || generations.Load() != expectedGenerations {
				t.Fatal("evidence failure dispatch count wrong")
			}
			if again := nonCanonProxyRequest(p, nonCanonFinalBody); again.Code != 403 {
				t.Fatal("poisoned proof allowed later dispatch")
			}
		})
	}
}

func TestNativeCounterRejectsUnboundedOrMissingStreamUsage(t *testing.T) {
	for _, kind := range []string{"completion_null", "prompt_null", "total_null", "reasoning_null", "over_output", "prompt_mismatch", "total_mismatch", "no_usage", "no_done", "duplicate_usage", "reasoning", "post_usage_data", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			var proof bytes.Buffer
			p, _, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/chat/completions/input_tokens" {
					io.WriteString(w, `{"input_tokens":37,"object":"response.input_tokens"}`)
					return
				}
				response := nonCanonSSE(37, 3)
				switch kind {
				case "completion_null":
					response = nonCanonSSE(37, 0)
					response = strings.Replace(response, `"completion_tokens":0`, `"completion_tokens":null`, 1)
				case "prompt_null":
					response = strings.Replace(response, `"prompt_tokens":37`, `"prompt_tokens":null`, 1)
				case "total_null":
					response = strings.Replace(response, `"total_tokens":40`, `"total_tokens":null`, 1)
				case "reasoning_null":
					response = strings.Replace(response, `"total_tokens":40`, `"total_tokens":40,"completion_tokens_details":{"reasoning_tokens":null}`, 1)
				case "over_output":
					response = nonCanonSSE(37, 1025)
				case "prompt_mismatch":
					response = nonCanonSSE(38, 3)
				case "total_mismatch":
					response = strings.Replace(response, `"total_tokens":40`, `"total_tokens":41`, 1)
				case "no_usage":
					response = "data: {\"choices\":[]}\n\ndata: [DONE]\n\n"
				case "no_done":
					response = strings.TrimSuffix(response, "data: [DONE]\n\n")
				case "duplicate_usage":
					response = strings.Replace(response, "data: [DONE]", strings.TrimSuffix(response, "data: [DONE]\n\n")+"data: [DONE]", 1)
				case "reasoning":
					response = strings.Replace(response, `"total_tokens":40`, `"total_tokens":40,"completion_tokens_details":{"reasoning_tokens":1}`, 1)
				case "post_usage_data":
					response = strings.Replace(response, "data: [DONE]", "data: {\"choices\":[]}\n\ndata: [DONE]", 1)
				case "oversize":
					response = strings.Repeat("x", (1<<20)+1)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, response)
			}, &proof)
			out := nonCanonProxyRequest(p, nonCanonFinalBody)
			if out.Code != 502 || generations.Load() != 1 || strings.Contains(proof.String(), "GENERATION_COMPLETED") {
				t.Fatal("unproven output was accepted", out.Code)
			}
		})
	}
}

func TestNativeCounterConcurrentRequestsKeepOneGenerationCeiling(t *testing.T) {
	var proof bytes.Buffer
	p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions/input_tokens" {
			io.WriteString(w, `{"input_tokens":37,"object":"response.input_tokens"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, nonCanonSSE(37, 3))
	}, &proof)
	var wg sync.WaitGroup
	var success atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			if nonCanonProxyRequest(p, nonCanonFinalBody).Code == 200 {
				success.Add(1)
			}
		})
	}
	wg.Wait()
	if success.Load() != MaxLocalCalls || counts.Load() != MaxLocalCalls || generations.Load() != MaxLocalCalls {
		t.Fatal("concurrent requests escaped local generation ceiling", success.Load(), counts.Load(), generations.Load())
	}
}

func TestNativeCounterRetirementCancelsOwnedInFlightGeneration(t *testing.T) {
	var proof bytes.Buffer
	started := make(chan struct{})
	release := make(chan struct{})
	p, _, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions/input_tokens" {
			io.WriteString(w, `{"input_tokens":37,"object":"response.input_tokens"}`)
			return
		}
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}, &proof)
	finished := make(chan int, 1)
	go func() { finished <- nonCanonProxyRequest(p, nonCanonFinalBody).Code }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("simulated generation did not start")
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("retirement waited for full generation deadline")
	}
	select {
	case status := <-finished:
		if status != 502 {
			t.Fatal("retired generation returned success", status)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("retired dispatch did not settle")
	}
	close(release)
	if generations.Load() != 1 || bytes.Contains(proof.Bytes(), []byte("GENERATION_COMPLETED")) {
		t.Fatal("uncertain retirement manufactured completion")
	}
	if nonCanonProxyRequest(p, nonCanonFinalBody).Code != 403 {
		t.Fatal("retired proxy allowed a new dispatch")
	}
}

func TestNativeCounterRetirementCancelsPartialIncomingBody(t *testing.T) {
	var proof bytes.Buffer
	p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("partial body reached simulated native endpoint")
	}, &proof)
	reader, writer := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", reader)
	req.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() { p.ServeHTTP(out, req); close(finished) }()
	written := make(chan error, 1)
	go func() { _, err := writer.Write([]byte(`{"model":`)); written <- err }()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("fixture reader did not begin")
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("retirement blocked on partial upload")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		_ = writer.Close()
		t.Fatal("partial upload not canceled")
	}
	_ = writer.Close()
	if counts.Load() != 0 || generations.Load() != 0 || proof.Len() != 0 || out.Code == 200 {
		t.Fatal("retired partial upload manufactured dispatch or completion")
	}
}

type nonCanonSignalingBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (b *nonCanonSignalingBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}

func TestNativeCounterRetirementCancelsPartialActualHTTPUpload(t *testing.T) {
	var proof bytes.Buffer
	p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) { t.Error("partial HTTP body reached native fixture") }, &proof)
	started := make(chan struct{})
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = &nonCanonSignalingBody{ReadCloser: r.Body, started: started}
		defer close(finished)
		p.ServeHTTP(w, r)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	conn, err := net.DialTimeout("tcp4", u.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = io.WriteString(conn, "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"model\":"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("HTTP body reader did not begin")
	}
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("retirement blocked on socket upload")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("socket body reader or body cleanup was not canceled")
	}
	if counts.Load() != 0 || generations.Load() != 0 || proof.Len() != 0 {
		t.Fatal("partial socket upload admitted native request")
	}
}

func TestNativeCounterFinishedHTTPUploadDoesNotCancelLaterGeneration(t *testing.T) {
	var proof bytes.Buffer
	p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions/input_tokens" {
			io.WriteString(w, `{"input_tokens":37,"object":"response.input_tokens"}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// Beyond the fixed 30s upload timer, inside the fixed 120s generation
		// timer. Flush headers first so response-header timeout is not involved.
		timer := time.NewTimer(31 * time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		io.WriteString(w, nonCanonSSE(37, 3))
	}, &proof)
	server := httptest.NewServer(p)
	defer server.Close()
	client := &http.Client{Timeout: 38 * time.Second}
	response, err := client.Post(server.URL+"/v1/chat/completions", "application/json", strings.NewReader(nonCanonFinalBody))
	if err != nil {
		t.Fatal("completed HTTP upload canceled during valid generation", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != nonCanonSSE(37, 3) || counts.Load() != 1 || generations.Load() != 1 {
		t.Fatal("upload and generation deadlines overlapped", response.StatusCode, err)
	}
	p.Close()
	if !bytes.Contains(proof.Bytes(), []byte("GENERATION_COMPLETED_WITH_BOUNDED_USAGE")) {
		t.Fatal("accepted delayed generation has no complete usage proof")
	}
}

type nonCanonEOFBarrierBody struct {
	reader                 *strings.Reader
	eofReached, eofRelease chan struct{}
	reached, release       sync.Once
}

func (b *nonCanonEOFBarrierBody) Read(p []byte) (int, error) {
	n, e := b.reader.Read(p)
	if e == io.EOF {
		b.reached.Do(func() { close(b.eofReached) })
		<-b.eofRelease
	}
	return n, e
}
func (b *nonCanonEOFBarrierBody) Close() error {
	b.release.Do(func() { close(b.eofRelease) })
	return nil
}

type nonCanonCallbackBarrierWriter struct {
	*httptest.ResponseRecorder
	callbackEntered, callbackRelease   chan struct{}
	once                               sync.Once
	handlerReturned, lateControllerUse atomic.Bool
}

func (w *nonCanonCallbackBarrierWriter) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() && deadline.Before(time.Now().Add(time.Second)) {
		w.once.Do(func() { close(w.callbackEntered) })
		<-w.callbackRelease
		if w.handlerReturned.Load() {
			w.lateControllerUse.Store(true)
		}
	}
	return nil
}

func TestNativeCounterJoinsStartedUploadCancellationBeforeReturning(t *testing.T) {
	var proof bytes.Buffer
	p, counts, generations := nonCanonCounter(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled upload reached native fixture") }, &proof)
	body := &nonCanonEOFBarrierBody{reader: strings.NewReader(nonCanonFinalBody), eofReached: make(chan struct{}), eofRelease: make(chan struct{})}
	defer body.Close()
	w := &nonCanonCallbackBarrierWriter{ResponseRecorder: httptest.NewRecorder(), callbackEntered: make(chan struct{}), callbackRelease: make(chan struct{})}
	var releaseOnce sync.Once
	releaseCallback := func() { releaseOnce.Do(func() { close(w.callbackRelease) }) }
	defer releaseCallback()
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", body)
	r.Header.Set("Content-Type", "application/json")
	finished := make(chan struct{})
	go func() { p.ServeHTTP(w, r); w.handlerReturned.Store(true); close(finished) }()
	select {
	case <-body.eofReached:
	case <-time.After(time.Second):
		t.Fatal("EOF reader did not begin")
	}
	p.Close()
	select {
	case <-w.callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback did not begin")
	}
	// EOF settles while the already-started callback is delayed. The handler
	// must reject the canceled upload but cannot leave its controller behind.
	body.Close()
	select {
	case <-finished:
		t.Fatal("handler returned with its controller callback still running")
	case <-time.After(100 * time.Millisecond):
	}
	releaseCallback()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("handler did not settle after callback joined")
	}
	if w.lateControllerUse.Load() || w.Code == http.StatusOK || counts.Load() != 0 || generations.Load() != 0 || proof.Len() != 0 {
		t.Fatal("callback lifetime or canceled admission failed")
	}
}

type earlyCancelDeadlineWriter struct {
	*httptest.ResponseRecorder
	futureEntered, releaseFuture, pastApplied chan struct{}
	mu                                        sync.Mutex
	last                                      time.Time
	futureOnce, pastOnce                      sync.Once
}

func (w *earlyCancelDeadlineWriter) SetReadDeadline(deadline time.Time) error {
	if time.Until(deadline) > 20*time.Second {
		w.futureOnce.Do(func() { close(w.futureEntered) })
		<-w.releaseFuture
	} else {
		w.pastOnce.Do(func() { close(w.pastApplied) })
	}
	w.mu.Lock()
	w.last = deadline
	w.mu.Unlock()
	return nil
}

type earlyCancelUnreadBody struct {
	closed chan struct{}
	once   sync.Once
}

func (b *earlyCancelUnreadBody) Read([]byte) (int, error) { <-b.closed; return 0, io.ErrClosedPipe }
func (b *earlyCancelUnreadBody) Close() error             { b.once.Do(func() { close(b.closed) }); return nil }

func TestNativeCounterInitialDeadlineCannotOverwriteCancellation(t *testing.T) {
	var proof bytes.Buffer
	p, e := newNativeCountProxy(12345, strings.Repeat("a", 64), strings.Repeat("b", 64), &proof)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	w := &earlyCancelDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), futureEntered: make(chan struct{}), releaseFuture: make(chan struct{}), pastApplied: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(w.releaseFuture) }) }
	defer release()
	body := &earlyCancelUnreadBody{closed: make(chan struct{})}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/chat/completions", body)
	r.ContentLength = 200
	r.Header.Set("Content-Type", "application/json")
	done := make(chan struct{})
	go func() { p.ServeHTTP(w, r); close(done) }()
	select {
	case <-w.futureEntered:
	case <-time.After(time.Second):
		t.Fatal("initial deadline not entered")
	}
	p.Close()
	// The callback must not exist while initialization remains paused. Before
	// the repair it could apply an expired deadline, later overwritten below.
	select {
	case <-w.pastApplied:
		t.Error("cancellation callback raced deadline initialization")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("early cancellation did not settle")
	}
	select {
	case <-w.pastApplied:
	case <-time.After(time.Second):
		t.Fatal("expired deadline was not applied")
	}
	w.mu.Lock()
	last := w.last
	w.mu.Unlock()
	if time.Until(last) > 0 {
		t.Fatal("future deadline survived cancellation")
	}
	if w.Code != http.StatusForbidden || proof.Len() != 0 {
		t.Fatal("cancelled upload admitted or proof written", w.Code)
	}
}

func TestNativeCounterRejectedPartialUploadsCannotDrainIndefinitely(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(strconv.FormatBool(closed), func(t *testing.T) {
			var proof bytes.Buffer
			p, e := newNativeCountProxy(12345, strings.Repeat("a", 64), strings.Repeat("b", 64), &proof)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			if closed {
				p.Close()
			}
			server := httptest.NewServer(p)
			defer server.Close()
			connection, e := net.DialTimeout("tcp4", strings.TrimPrefix(server.URL, "http://"), time.Second)
			if e != nil {
				t.Fatal(e)
			}
			defer connection.Close()
			path, want := "/unlisted", "400"
			if closed {
				path = "/v1/chat/completions"
				want = "403"
			}
			_, e = io.WriteString(connection, "POST "+path+" HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\nx")
			if e != nil {
				t.Fatal(e)
			}
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			status, e := bufio.NewReader(connection).ReadString('\n')
			if e != nil || !strings.Contains(status, want) {
				t.Fatal("rejected partial upload did not settle", status, e)
			}
			if proof.Len() != 0 {
				t.Fatal("rejected upload emitted native intent")
			}
		})
	}
}
